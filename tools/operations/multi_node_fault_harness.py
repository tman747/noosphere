#!/usr/bin/env python3
"""Run a loopback MindChain cluster through partition, crash, and indexer faults."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


class HarnessError(RuntimeError):
    pass


def reserve_port(sock_type: int) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get_json(address: str, path: str, token: str | None = None, timeout: float = 1.5) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"http://{address}{path}", headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except (OSError, HTTPError, URLError, json.JSONDecodeError) as error:
        raise HarnessError(f"{address}{path} unavailable: {error}") from error
    if not isinstance(value, dict):
        raise HarnessError(f"{address}{path} returned non-object JSON")
    return value


class UdpRelay:
    """Single-client UDP relay whose forwarding can be disabled atomically."""

    def __init__(self, listen_port: int, upstream_port: int) -> None:
        self.listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen.bind(("127.0.0.1", listen_port))
        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upstream.connect(("127.0.0.1", upstream_port))
        self.listen.setblocking(False)
        self.upstream.setblocking(False)
        self._enabled = threading.Event()
        self._enabled.set()
        self._stop = threading.Event()
        self._client: tuple[str, int] | None = None
        self._thread = threading.Thread(target=self._run, name=f"udp-relay-{listen_port}", daemon=True)
        self._thread.start()

    def partition(self) -> None:
        self._enabled.clear()

    def heal(self) -> None:
        self._enabled.set()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.listen.close()
        self.upstream.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([self.listen, self.upstream], [], [], 0.05)
                for sock in readable:
                    if sock is self.listen:
                        payload, client = self.listen.recvfrom(65535)
                        self._client = client
                        if self._enabled.is_set():
                            self.upstream.send(payload)
                    else:
                        payload = self.upstream.recv(65535)
                        if self._enabled.is_set() and self._client is not None:
                            self.listen.sendto(payload, self._client)
            except OSError:
                if not self._stop.is_set():
                    time.sleep(0.02)


class ManagedProcess:
    def __init__(self, name: str, command: list[str], env: dict[str, str], log_dir: Path) -> None:
        self.name = name
        self.command = command
        self.env = env
        self.log_dir = log_dir
        self.process: subprocess.Popen[bytes] | None = None
        self.log = None

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            raise HarnessError(f"{self.name} is already running")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log = (self.log_dir / f"{self.name}.log").open("ab", buffering=0)
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.process = subprocess.Popen(
            self.command,
            cwd=ROOT,
            env=self.env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )

    def stop(self, timeout: float = 8.0) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def assert_running(self) -> None:
        if self.process is None or self.process.poll() is not None:
            code = None if self.process is None else self.process.returncode
            raise HarnessError(f"{self.name} exited unexpectedly with {code}")


class ClusterHarness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = args.root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.logs = self.root / "logs"
        self.token = secrets.token_urlsafe(24)
        self.genesis_time_ms = int(time.time() * 1000) - 30_000
        self.producer_p2p = reserve_port(socket.SOCK_DGRAM)
        self.producer_rpc = reserve_port(socket.SOCK_STREAM)
        self.observer_ports = [reserve_port(socket.SOCK_STREAM) for _ in range(3)]
        self.observer_p2p = [reserve_port(socket.SOCK_DGRAM) for _ in range(3)]
        self.relay_ports = [reserve_port(socket.SOCK_DGRAM) for _ in range(3)]
        self.indexer_port = reserve_port(socket.SOCK_STREAM)
        self.relays: list[UdpRelay] = []
        self.processes: dict[str, ManagedProcess] = {}
        self.identity: tuple[str, str] | None = None
        self.last_heads: dict[str, int] = {}
        self.last_finalized: dict[str, int] = {}
        self.phases: list[dict[str, Any]] = []

    def node_common(self, data_dir: Path) -> list[str]:
        return [
            str(self.args.noosd),
            "--params", str(self.args.params),
            "--data-dir", str(data_dir),
            "--genesis-time", str(self.genesis_time_ms),
            "--rpc-token", self.token,
            "--devnet-contract-fixture",
        ]

    def configure(self) -> None:
        producer = self.node_common(self.root / "producer") + [
            "--rpc", f"127.0.0.1:{self.producer_rpc}",
            "--p2p-listen", f"/ip4/127.0.0.1/udp/{self.producer_p2p}/quic-v1",
            "--validator",
            "--produce-interval-ms", str(self.args.produce_interval_ms),
        ]
        self.processes["producer"] = ManagedProcess("producer", producer, os.environ.copy(), self.logs)
        for index in range(3):
            observer = self.node_common(self.root / f"observer-{index + 1}") + [
                "--rpc", f"127.0.0.1:{self.observer_ports[index]}",
                "--p2p-listen", f"/ip4/127.0.0.1/udp/{self.observer_p2p[index]}/quic-v1",
                "--peer", f"/ip4/127.0.0.1/udp/{self.relay_ports[index]}/quic-v1",
                "--observer",
            ]
            self.processes[f"observer-{index + 1}"] = ManagedProcess(
                f"observer-{index + 1}", observer, os.environ.copy(), self.logs
            )

    def status(self, name: str) -> dict[str, Any]:
        if name == "producer":
            port = self.producer_rpc
        else:
            port = self.observer_ports[int(name.rsplit("-", 1)[1]) - 1]
        return get_json(f"127.0.0.1:{port}", "/status", self.token)

    def indexer_status(self) -> dict[str, Any]:
        return get_json(f"127.0.0.1:{self.indexer_port}", "/api/status")

    def cluster_status(self, names: list[str] | None = None) -> dict[str, dict[str, Any]]:
        selected = names or ["producer", "observer-1", "observer-2", "observer-3"]
        return {name: self.status(name) for name in selected}

    def validate_cluster(self, statuses: dict[str, dict[str, Any]], allow_lag: int) -> dict[str, int]:
        identities = {(value.get("chain_id"), value.get("genesis_hash")) for value in statuses.values()}
        if len(identities) != 1:
            raise HarnessError(f"protocol identity divergence: {identities}")
        identity = next(iter(identities))
        if self.identity is None:
            self.identity = (str(identity[0]), str(identity[1]))
        elif identity != self.identity:
            raise HarnessError("cluster identity changed during fault run")
        heads: dict[str, int] = {}
        for name, value in statuses.items():
            try:
                head = int(value["unsafe_head"]["height"])
                finalized = int(value["finalized"]["epoch"])
            except (KeyError, TypeError, ValueError) as error:
                raise HarnessError(f"malformed status from {name}") from error
            if head < self.last_heads.get(name, 0):
                raise HarnessError(f"head regressed on {name}")
            if finalized < self.last_finalized.get(name, 0):
                raise HarnessError(f"finality regressed on {name}")
            self.last_heads[name] = head
            self.last_finalized[name] = finalized
            heads[name] = head
        if max(heads.values()) - min(heads.values()) > allow_lag:
            raise HarnessError(f"cluster lag exceeds {allow_lag}: {heads}")
        return heads

    def wait_until(self, label: str, predicate: Callable[[], Any], timeout: float | None = None) -> Any:
        deadline = time.monotonic() + (timeout or self.args.timeout)
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (HarnessError, OSError) as error:
                last_error = error
            time.sleep(0.25)
        raise HarnessError(f"timeout waiting for {label}: {last_error}")

    def record_phase(self, name: str, started: float, details: dict[str, Any]) -> None:
        self.phases.append({
            "phase": name,
            "duration_ms": int((time.monotonic() - started) * 1000),
            **details,
        })

    def start_cluster(self) -> None:
        self.configure()
        self.processes["producer"].start()
        self.wait_until("producer RPC", lambda: self.status("producer"))
        self.relays = [UdpRelay(relay, self.producer_p2p) for relay in self.relay_ports]
        for name in ("observer-1", "observer-2", "observer-3"):
            self.processes[name].start()
        self.wait_until("all observer RPCs", lambda: self.cluster_status())
        baseline = self.wait_until(
            "initial synchronization",
            lambda: self._caught_up(self.args.warmup_blocks, self.args.max_lag),
        )
        self.validate_cluster(baseline, self.args.max_lag)

    def _caught_up(self, minimum_height: int, lag: int, names: list[str] | None = None) -> dict[str, dict[str, Any]] | None:
        statuses = self.cluster_status(names)
        heights = [int(value["unsafe_head"]["height"]) for value in statuses.values()]
        if min(heights) >= minimum_height and max(heights) - min(heights) <= lag:
            return statuses
        return None

    def partition_fault(self) -> None:
        started = time.monotonic()
        before = self.status("observer-2")
        before_height = int(before["unsafe_head"]["height"])
        self.relays[1].partition()
        producer_target = before_height + self.args.fault_blocks
        self.wait_until(
            "producer progress during partition",
            lambda: self.status("producer") if int(self.status("producer")["unsafe_head"]["height"]) >= producer_target else None,
        )
        isolated = self.status("observer-2")
        isolated_height = int(isolated["unsafe_head"]["height"])
        if isolated_height >= producer_target:
            raise HarnessError("partitioned observer continued importing producer blocks")
        self.relays[1].heal()
        healed = self.wait_until(
            "partitioned observer catch-up",
            lambda: self._caught_up(producer_target, self.args.max_lag),
        )
        heads = self.validate_cluster(healed, self.args.max_lag)
        self.record_phase("network_partition", started, {"isolated_height": isolated_height, "heads": heads})

    def crash_fault(self) -> None:
        started = time.monotonic()
        crashed = "observer-3"
        before = int(self.status(crashed)["unsafe_head"]["height"])
        self.processes[crashed].stop()
        target = before + self.args.fault_blocks
        self.wait_until(
            "producer progress during observer crash",
            lambda: self.status("producer") if int(self.status("producer")["unsafe_head"]["height"]) >= target else None,
        )
        self.processes[crashed].start()
        recovered = self.wait_until(
            "crashed observer recovery",
            lambda: self._caught_up(target, self.args.max_lag),
        )
        heads = self.validate_cluster(recovered, self.args.max_lag)
        self.record_phase("observer_crash_restart", started, {"restart_from_height": before, "heads": heads})

    def start_indexer(self) -> None:
        if self.identity is None:
            raise HarnessError("cluster identity is unavailable")
        environment = os.environ.copy()
        environment.update({
            "NOOS_CHAIN_ID": self.identity[0],
            "NOOS_GENESIS_HASH": self.identity[1],
            "NOOS_NODE_RPC": f"127.0.0.1:{self.producer_rpc}",
            "NOOS_NODE_TOKEN": self.token,
            "NOOS_INDEXER_LISTEN": f"127.0.0.1:{self.indexer_port}",
            "NOOS_INDEXER_ROOT": str(self.root / "indexer"),
        })
        self.processes["indexer"] = ManagedProcess(
            "indexer", [str(self.args.indexer)], environment, self.logs
        )
        self.processes["indexer"].start()

    def indexer_fault(self) -> None:
        started = time.monotonic()
        self.start_indexer()
        initial = self.wait_until(
            "indexer readiness",
            lambda: self._indexer_caught_up(),
        )
        initial_height = int(initial["unsafe_head"]["height"])
        self.processes["indexer"].stop()
        target = initial_height + self.args.fault_blocks
        self.wait_until(
            "producer progress during indexer outage",
            lambda: self.status("producer") if int(self.status("producer")["unsafe_head"]["height"]) >= target else None,
        )
        self.processes["indexer"].start()
        recovered = self.wait_until("indexer recovery", lambda: self._indexer_caught_up(minimum=target))
        self.record_phase(
            "indexer_crash_restart",
            started,
            {"restart_from_height": initial_height, "recovered_height": int(recovered["unsafe_head"]["height"])},
        )

    def _indexer_caught_up(self, minimum: int = 0) -> dict[str, Any] | None:
        indexer = self.indexer_status()
        producer = self.status("producer")
        if indexer.get("chain_id") != producer.get("chain_id") or indexer.get("genesis_hash") != producer.get("genesis_hash"):
            raise HarnessError("indexer identity differs from producer")
        index_height = int(indexer["unsafe_head"]["height"])
        producer_height = int(producer["unsafe_head"]["height"])
        if indexer.get("ready") is True and index_height >= minimum and producer_height - index_height <= self.args.max_lag:
            return indexer
        return None

    def run(self) -> dict[str, Any]:
        started = time.monotonic()
        try:
            self.start_cluster()
            self.partition_fault()
            self.crash_fault()
            self.indexer_fault()
            final_statuses = self.cluster_status()
            heads = self.validate_cluster(final_statuses, self.args.max_lag)
            report = {
                "schema": "noos/multi-node-fault-report/v1",
                "verdict": "PASS",
                "chain_id": self.identity[0] if self.identity else None,
                "genesis_hash": self.identity[1] if self.identity else None,
                "nodes": 4,
                "faults": self.phases,
                "final_heads": heads,
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
            return report
        finally:
            self.close()

    def close(self) -> None:
        for process in reversed(list(self.processes.values())):
            process.stop()
        for relay in self.relays:
            relay.close()


def locate_binary(directory: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    path = directory / f"{name}{suffix}"
    if not path.is_file():
        raise HarnessError(f"missing binary: {path}")
    return path.resolve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--params", type=Path, default=ROOT / "protocol" / "genesis" / "devnet-parameters.toml")
    parser.add_argument("--root", type=Path, default=Path(tempfile.gettempdir()) / "noosphere-fault-harness")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--produce-interval-ms", type=int, default=500)
    parser.add_argument("--warmup-blocks", type=int, default=4)
    parser.add_argument("--fault-blocks", type=int, default=3)
    parser.add_argument("--max-lag", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args(argv)
    if min(args.produce_interval_ms, args.warmup_blocks, args.fault_blocks, args.max_lag + 1) < 1 or args.timeout <= 0:
        print("RESULT multi_node_fault_harness=FAIL reason=invalid numeric option", file=sys.stderr)
        return 1
    try:
        args.noosd = locate_binary(args.binary_dir, "noosd")
        args.indexer = locate_binary(args.binary_dir, "noos-indexer")
        args.params = args.params.resolve()
        if not args.params.is_file():
            raise HarnessError(f"missing genesis parameters: {args.params}")
        if args.root.exists():
            shutil.rmtree(args.root)
        report = ClusterHarness(args).run()
    except (HarnessError, OSError, subprocess.SubprocessError) as error:
        report = {"schema": "noos/multi-node-fault-report/v1", "verdict": "FAIL", "reason": str(error)}
        code = 1
    else:
        code = 0
    output = args.out or args.root.with_suffix(".report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(json.dumps(report, sort_keys=True, separators=(",", ":")).encode())
    print(f"RESULT multi_node_fault_harness={report['verdict']} out={output}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
