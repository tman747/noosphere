#!/usr/bin/env python3
"""Soak a MindChain cluster through NAT, WAN, bootstrap, sync, and process faults."""
from __future__ import annotations

import argparse
import hashlib
import heapq
import ipaddress
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
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import bootstrap_registry


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

def expect_http_status(address: str, path: str, expected: int, timeout: float = 1.5) -> None:
    request = Request(f"http://{address}{path}", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
    except HTTPError as error:
        status = error.code
    except (OSError, URLError) as error:
        raise HarnessError(f"{address}{path} unavailable: {error}") from error
    if status != expected:
        raise HarnessError(f"{address}{path} returned HTTP {status}, expected {expected}")


class UdpRelay:
    """Multi-client UDP NAT relay with deterministic loss and latency."""

    COUNTERS = ("received", "forwarded", "dropped", "delayed")

    def __init__(self, listen_port: int, upstream_port: int) -> None:
        self.listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen.bind(("127.0.0.1", listen_port))
        self.listen.setblocking(False)
        self.upstream_address = ("127.0.0.1", upstream_port)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._profiles: dict[int | None, tuple[int, int]] = {}
        self._loss_accumulator: dict[int, int] = {}
        self._metrics: dict[int, dict[str, int]] = {}
        self._known_clients: set[int] = set()
        self._mappings: dict[tuple[str, int], socket.socket] = {}
        self._reverse: dict[socket.socket, tuple[str, int]] = {}
        self._delayed: list[tuple[float, int, bool, socket.socket, tuple[str, int], bytes]] = []
        self._delivery_sequence = 0
        self._thread = threading.Thread(target=self._run, name=f"udp-relay-{listen_port}", daemon=True)
        self._thread.start()

    def impair(
        self,
        *,
        loss_permille: int,
        latency_ms: int,
        client_ports: set[int] | None = None,
    ) -> None:
        if not 0 <= loss_permille <= 1000 or latency_ms < 0:
            raise HarnessError("relay impairment is outside its bounds")
        if client_ports is not None and not client_ports:
            raise HarnessError("relay impairment requires at least one client port")
        with self._lock:
            keys: set[int | None] = {None} if client_ports is None else set(client_ports)
            for key in keys:
                self._profiles[key] = (loss_permille, latency_ms)
                if key is not None:
                    self._loss_accumulator[key] = 0

    def partition(self, client_ports: set[int] | None = None) -> None:
        self.impair(loss_permille=1000, latency_ms=0, client_ports=client_ports)

    def heal(self, client_ports: set[int] | None = None) -> None:
        with self._lock:
            if client_ports is None:
                self._profiles.clear()
                self._loss_accumulator.clear()
            else:
                for port in client_ports:
                    self._profiles.pop(port, None)
                    self._loss_accumulator.pop(port, None)

    def metrics(self, client_ports: set[int] | None = None) -> dict[str, Any]:
        with self._lock:
            selected = self._known_clients if client_ports is None else client_ports
            totals = {
                counter: sum(self._metrics.get(port, {}).get(counter, 0) for port in selected)
                for counter in self.COUNTERS
            }
            return {
                **totals,
                "mapping_count": len(selected & self._known_clients),
                "client_ports": sorted(selected & self._known_clients),
            }

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.listen.close()
        for upstream in self._mappings.values():
            upstream.close()

    def _mapping(self, client: tuple[str, int]) -> socket.socket:
        upstream = self._mappings.get(client)
        if upstream is not None:
            return upstream
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.connect(self.upstream_address)
        upstream.setblocking(False)
        self._mappings[client] = upstream
        self._reverse[upstream] = client
        with self._lock:
            self._known_clients.add(client[1])
            self._metrics.setdefault(client[1], {counter: 0 for counter in self.COUNTERS})
        return upstream

    def _profile_and_account(self, client_port: int) -> tuple[int, int, bool]:
        with self._lock:
            counters = self._metrics.setdefault(
                client_port, {counter: 0 for counter in self.COUNTERS}
            )
            counters["received"] += 1
            loss_permille, latency_ms = self._profiles.get(
                client_port, self._profiles.get(None, (0, 0))
            )
            accumulator = self._loss_accumulator.get(client_port, 0) + loss_permille
            dropped = accumulator >= 1000
            if dropped:
                accumulator -= 1000
                counters["dropped"] += 1
            elif latency_ms:
                counters["delayed"] += 1
            self._loss_accumulator[client_port] = accumulator
            return loss_permille, latency_ms, dropped

    def _deliver(
        self,
        outbound: bool,
        upstream: socket.socket,
        client: tuple[str, int],
        payload: bytes,
    ) -> None:
        try:
            if outbound:
                upstream.send(payload)
            else:
                self.listen.sendto(payload, client)
        except (BlockingIOError, OSError):
            with self._lock:
                self._metrics[client[1]]["dropped"] += 1
            return
        with self._lock:
            self._metrics[client[1]]["forwarded"] += 1

    def _forward(
        self,
        outbound: bool,
        upstream: socket.socket,
        client: tuple[str, int],
        payload: bytes,
    ) -> None:
        _, latency_ms, dropped = self._profile_and_account(client[1])
        if dropped:
            return
        if latency_ms:
            self._delivery_sequence += 1
            heapq.heappush(
                self._delayed,
                (
                    time.monotonic() + latency_ms / 1000,
                    self._delivery_sequence,
                    outbound,
                    upstream,
                    client,
                    payload,
                ),
            )
            return
        self._deliver(outbound, upstream, client, payload)

    def _flush_delayed(self) -> None:
        now = time.monotonic()
        while self._delayed and self._delayed[0][0] <= now:
            _, _, outbound, upstream, client, payload = heapq.heappop(self._delayed)
            self._deliver(outbound, upstream, client, payload)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._flush_delayed()
                timeout = 0.05
                if self._delayed:
                    timeout = max(0.0, min(timeout, self._delayed[0][0] - time.monotonic()))
                readable, _, _ = select.select(
                    [self.listen, *self._reverse.keys()], [], [], timeout
                )
                for source in readable:
                    if source is self.listen:
                        payload, client = self.listen.recvfrom(65535)
                        upstream = self._mapping(client)
                        self._forward(True, upstream, client, payload)
                    else:
                        payload = source.recv(65535)
                        client = self._reverse[source]
                        self._forward(False, source, client, payload)
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
    BOOTSTRAP_RELAYS_V1 = ("producer-v1", "observer-1")

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = args.root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.logs = self.root / "logs"
        self.token = secrets.token_urlsafe(24)
        self.token_path = self.root / "operator-rpc.token"
        self._write_private(self.token_path, f"{self.token}\n".encode())
        self.genesis_time_ms = int(time.time() * 1000) - 30_000
        self.producer_p2p = reserve_port(socket.SOCK_DGRAM)
        self.producer_rpc = reserve_port(socket.SOCK_STREAM)
        self.observer_ports = [reserve_port(socket.SOCK_STREAM) for _ in range(3)]
        self.observer_p2p = [reserve_port(socket.SOCK_DGRAM) for _ in range(3)]
        self.producer_relay_v1 = reserve_port(socket.SOCK_DGRAM)
        self.observer_relay = reserve_port(socket.SOCK_DGRAM)
        self.producer_relay_v2 = reserve_port(socket.SOCK_DGRAM)
        self.indexer_port = reserve_port(socket.SOCK_STREAM)
        self.relays: dict[str, UdpRelay] = {}
        self.processes: dict[str, ManagedProcess] = {}
        self.identity: tuple[str, str] | None = None
        self.last_heads: dict[str, int] = {}
        self.last_finalized: dict[str, int] = {}
        self.phases: list[dict[str, Any]] = []
        self.registry_path = self.root / "bootstrap-registry.json"
        self.registry_private_seed = secrets.token_bytes(32)
        self.registry_public_key = bootstrap_registry.public_from_seed(
            self.registry_private_seed
        )
        self.registry_envelopes: dict[int, dict[str, Any]] = {}
        now_ms = int(time.time() * 1000)
        self.registry_valid_from = now_ms - 60_000
        self.registry_expires = now_ms + 3_600_000
        self.node_seeds = {
            name: secrets.token_bytes(32)
            for name in ("producer", "observer-1", "observer-2", "observer-3")
        }
        self.node_ids = {
            name: bootstrap_registry.peer_id_from_seed(seed)
            for name, seed in self.node_seeds.items()
        }
        self.nat_clients: dict[str, dict[str, set[int]]] = {}
        self._prepare_node_data()

    @staticmethod
    def _write_private(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _prepare_node_data(self) -> None:
        for name, seed in self.node_seeds.items():
            self._write_private(self.root / name / "p2p-key", seed)

    def node_common(self, data_dir: Path) -> list[str]:
        return [
            str(self.args.noosd),
            "--params",
            str(self.args.params),
            "--data-dir",
            str(data_dir),
            "--genesis-time",
            str(self.genesis_time_ms),
            "--rpc-token-file",
            str(self.token_path),
            "--devnet-contract-fixture",
            "--devnet-witness-fixture",
        ]

    def configure_producer(self) -> None:
        producer = self.node_common(self.root / "producer") + [
            "--rpc",
            f"127.0.0.1:{self.producer_rpc}",
            "--p2p-listen",
            f"/ip4/127.0.0.1/udp/{self.producer_p2p}/quic-v1",
            "--validator",
            "--produce-interval-ms",
            str(self.args.produce_interval_ms),
        ]
        self.processes["producer"] = ManagedProcess(
            "producer", producer, os.environ.copy(), self.logs
        )

    def configure_observers(self) -> None:
        for index in range(3):
            observer = self.node_common(self.root / f"observer-{index + 1}") + [
                "--rpc",
                f"127.0.0.1:{self.observer_ports[index]}",
                "--p2p-listen",
                f"/ip4/127.0.0.1/udp/{self.observer_p2p[index]}/quic-v1",
                "--bootstrap-registry",
                str(self.registry_path),
                "--bootstrap-public-key",
                self.registry_public_key.hex(),
                "--observer",
            ]
            name = f"observer-{index + 1}"
            self.processes[name] = ManagedProcess(
                name, observer, os.environ.copy(), self.logs
            )

    def _start_relay(self, name: str, listen_port: int, upstream_port: int) -> None:
        if name in self.relays:
            raise HarnessError(f"relay {name} already exists")
        self.relays[name] = UdpRelay(listen_port, upstream_port)

    def publish_registry(
        self, sequence: int, producer_relay_port: int, previous_registry_id: str | None
    ) -> dict[str, Any]:
        if self.identity is None:
            raise HarnessError("cannot publish bootstrap snapshot before chain identity")
        producer_id = self.node_ids["producer"]
        observer_id = self.node_ids["observer-1"]
        nodes = [
            bootstrap_registry.make_node(
                producer_id,
                [
                    f"/ip4/127.0.0.1/udp/{producer_relay_port}/quic-v1/p2p/{producer_id}"
                ],
                self.registry_valid_from,
                self.registry_expires,
            ),
            bootstrap_registry.make_node(
                observer_id,
                [
                    f"/ip4/127.0.0.1/udp/{self.observer_relay}/quic-v1/p2p/{observer_id}"
                ],
                self.registry_valid_from,
                self.registry_expires,
            ),
        ]
        envelope = bootstrap_registry.sign_registry(
            chain_id=self.identity[0],
            genesis_hash=self.identity[1],
            sequence=sequence,
            previous_registry_id=previous_registry_id,
            valid_from_unix_ms=self.registry_valid_from,
            expires_unix_ms=self.registry_expires,
            nodes=nodes,
            private_seed=self.registry_private_seed,
        )
        bootstrap_registry.verify_registry(
            envelope,
            trusted_public_key=self.registry_public_key,
            expected_chain_id=self.identity[0],
            expected_genesis_hash=self.identity[1],
            now_unix_ms=int(time.time() * 1000),
        )
        payload = bootstrap_registry.canonical_file(envelope)
        version_path = self.root / f"bootstrap-registry-v{sequence}.json"
        version_path.write_bytes(payload)
        temporary = self.registry_path.with_suffix(".tmp")
        temporary.write_bytes(payload)
        os.replace(temporary, self.registry_path)
        self.registry_envelopes[sequence] = envelope
        return envelope

    def accepted_snapshot(self, name: str, sequence: int) -> dict[str, Any]:
        directory = self.root / name / "accepted-bootstrap-registries"
        matches = sorted(directory.glob(f"{sequence:020d}-*.json"))
        if len(matches) != 1:
            raise HarnessError(
                f"{name} has {len(matches)} accepted bootstrap snapshots at sequence {sequence}"
            )
        payload = matches[0].read_bytes()
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as error:
            raise HarnessError(f"{name} accepted malformed bootstrap JSON") from error
        expected = self.registry_envelopes.get(sequence)
        if value != expected:
            raise HarnessError(f"{name} accepted snapshot differs from published sequence {sequence}")
        return {
            "sequence": sequence,
            "registry_id": value["body"]["registry_id"],
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def status_port(self, name: str) -> int:
        if name == "producer":
            return self.producer_rpc
        return self.observer_ports[int(name.rsplit("-", 1)[1]) - 1]

    def status(self, name: str) -> dict[str, Any]:
        return get_json(f"127.0.0.1:{self.status_port(name)}", "/status", self.token)

    def indexer_status(self) -> dict[str, Any]:
        return get_json(f"127.0.0.1:{self.indexer_port}", "/api/status")

    def cluster_status(
        self, names: list[str] | None = None
    ) -> dict[str, dict[str, Any]]:
        selected = names or ["producer", "observer-1", "observer-2", "observer-3"]
        return {name: self.status(name) for name in selected}

    def validate_cluster(
        self, statuses: dict[str, dict[str, Any]], allow_lag: int
    ) -> dict[str, int]:
        identities = {
            (value.get("chain_id"), value.get("genesis_hash"))
            for value in statuses.values()
        }
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

    def wait_until(
        self, label: str, predicate: Callable[[], Any], timeout: float | None = None
    ) -> Any:
        deadline = time.monotonic() + (timeout or self.args.timeout)
        last_error: Exception | None = None
        last_value: Any = None
        while time.monotonic() < deadline:
            try:
                last_value = predicate()
                if last_value:
                    return last_value
            except (HarnessError, OSError) as error:
                last_error = error
            time.sleep(0.25)
        raise HarnessError(
            f"timeout waiting for {label}: error={last_error} last={last_value}"
        )

    def record_phase(
        self, name: str, started: float, details: dict[str, Any]
    ) -> None:
        self.phases.append(
            {
                "phase": name,
                "duration_ms": int((time.monotonic() - started) * 1000),
                **details,
            }
        )

    def _new_nat_mappings(
        self, before: dict[str, set[int]], required: tuple[str, ...]
    ) -> dict[str, set[int]] | None:
        additions = {
            name: set(self.relays[name].metrics()["client_ports"]) - ports
            for name, ports in before.items()
        }
        if all(additions[name] for name in required):
            return additions
        return None

    def _caught_up(
        self, minimum_height: int, lag: int, names: list[str] | None = None
    ) -> dict[str, dict[str, Any]] | None:
        statuses = self.cluster_status(names)
        heights = {
            name: int(value["unsafe_head"]["height"])
            for name, value in statuses.items()
        }
        if min(heights.values()) >= minimum_height and max(heights.values()) - min(
            heights.values()
        ) <= lag:
            return statuses
        raise HarnessError(
            f"cluster not converged: minimum={minimum_height} lag={lag} heads={heights}"
        )

    def _producer_reached(self, minimum_height: int) -> dict[str, Any] | None:
        status = self.status("producer")
        return status if int(status["unsafe_head"]["height"]) >= minimum_height else None

    def assert_rpc_private(self) -> dict[str, Any]:
        bindings: dict[str, str] = {}
        for name in ("producer", "observer-1", "observer-2", "observer-3"):
            command = self.processes[name].command
            if "--rpc-token" in command or "--rpc-token-file" not in command:
                raise HarnessError(f"{name} exposes its operator token in the process command")
            try:
                bind = command[command.index("--rpc") + 1]
                host, port = bind.rsplit(":", 1)
                if not ipaddress.ip_address(host).is_loopback or not port.isdigit():
                    raise ValueError
            except (ValueError, IndexError) as error:
                raise HarnessError(f"{name} operator RPC is not loopback-bound") from error
            expect_http_status(bind, "/status", 401)
            bindings[name] = bind
        return {
            "bindings": bindings,
            "unauthenticated_status": 401,
            "token_source": "private_file",
        }

    def _target_metrics(self, name: str) -> dict[str, dict[str, Any]]:
        return {
            relay_name: self.relays[relay_name].metrics(ports)
            for relay_name, ports in self.nat_clients[name].items()
        }

    @staticmethod
    def _metric_delta(
        before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, int]]:
        return {
            relay_name: {
                counter: int(after[relay_name][counter]) - int(metrics[counter])
                for counter in UdpRelay.COUNTERS
            }
            for relay_name, metrics in before.items()
        }

    def _impair_target(self, name: str, loss_permille: int, latency_ms: int) -> None:
        mappings = self.nat_clients.get(name)
        if not mappings or any(not mappings.get(relay) for relay in self.BOOTSTRAP_RELAYS_V1):
            raise HarnessError(f"missing NAT mappings for {name}")
        for relay_name in self.BOOTSTRAP_RELAYS_V1:
            self.relays[relay_name].impair(
                loss_permille=loss_permille,
                latency_ms=latency_ms,
                client_ports=mappings[relay_name],
            )

    def _heal_target(self, name: str) -> None:
        for relay_name, ports in self.nat_clients[name].items():
            self.relays[relay_name].heal(ports)

    def _shared_block(self, name: str) -> dict[str, Any]:
        observer = self.status(name)
        producer = self.status("producer")
        height = min(
            int(observer["unsafe_head"]["height"]),
            int(producer["unsafe_head"]["height"]),
        )
        producer_block = get_json(
            f"127.0.0.1:{self.producer_rpc}", f"/block/{height}", self.token
        )
        observer_block = get_json(
            f"127.0.0.1:{self.status_port(name)}", f"/block/{height}", self.token
        )
        if observer_block != producer_block:
            raise HarnessError(f"{name} state-sync block differs at height {height}")
        return {"height": height, "hash": producer_block["hash"]}

    def start_cluster(self) -> None:
        started = time.monotonic()
        self.configure_producer()
        self.processes["producer"].start()
        producer_status = self.wait_until(
            "producer RPC", lambda: self.status("producer")
        )
        self.identity = (
            str(producer_status["chain_id"]),
            str(producer_status["genesis_hash"]),
        )
        self._start_relay(
            "producer-v1", self.producer_relay_v1, self.producer_p2p
        )
        self._start_relay(
            "observer-1", self.observer_relay, self.observer_p2p[0]
        )
        registry = self.publish_registry(1, self.producer_relay_v1, None)
        self.configure_observers()
        for index, name in enumerate(
            ("observer-1", "observer-2", "observer-3")
        ):
            before = {
                relay_name: set(self.relays[relay_name].metrics()["client_ports"])
                for relay_name in self.BOOTSTRAP_RELAYS_V1
            }
            self.processes[name].start()
            self.wait_until(f"{name} RPC", lambda name=name: self.status(name))
            required = (
                ("producer-v1",)
                if index == 0
                else self.BOOTSTRAP_RELAYS_V1
            )
            additions = self.wait_until(
                f"{name} NAT mappings",
                lambda before=before, required=required: self._new_nat_mappings(
                    before, required
                ),
            )
            self.nat_clients[name] = additions
            self.wait_until(
                f"{name} initial sync",
                lambda name=name: self._caught_up(
                    1, self.args.max_lag, ["producer", name]
                ),
            )
        baseline = self.wait_until(
            "initial synchronization",
            lambda: self._caught_up(
                self.args.warmup_blocks, self.args.max_lag
            ),
        )
        heads = self.validate_cluster(baseline, self.args.max_lag)
        accepted = {
            name: self.accepted_snapshot(name, 1)
            for name in ("observer-1", "observer-2", "observer-3")
        }
        self.record_phase(
            "nat_bootstrap_snapshot",
            started,
            {
                "registry_id": registry["body"]["registry_id"],
                "registry_sequence": 1,
                "bootstrap_nodes": [
                    node["node_id"] for node in registry["body"]["nodes"]
                ],
                "nat_clients": {
                    node: {
                        relay: sorted(ports)
                        for relay, ports in mappings.items()
                    }
                    for node, mappings in self.nat_clients.items()
                },
                "accepted_snapshots": accepted,
                "operator_rpc": self.assert_rpc_private(),
                "heads": heads,
            },
        )

    def wan_fault(self) -> None:
        started = time.monotonic()
        target_name = "observer-2"
        before_metrics = self._target_metrics(target_name)
        start_height = int(self.status("producer")["unsafe_head"]["height"])
        target_height = start_height + self.args.fault_blocks
        self._impair_target(
            target_name,
            self.args.wan_loss_permille,
            self.args.wan_latency_ms,
        )
        try:
            self.wait_until(
                "producer progress under WAN impairment",
                lambda: self._producer_reached(target_height),
            )
            recovered = self.wait_until(
                "WAN-impaired observer convergence",
                lambda: self._caught_up(target_height, self.args.max_lag),
            )
        finally:
            self._heal_target(target_name)
        heads = self.validate_cluster(recovered, self.args.max_lag)
        deltas = self._metric_delta(
            before_metrics, self._target_metrics(target_name)
        )
        if sum(item["dropped"] for item in deltas.values()) == 0:
            raise HarnessError("WAN loss profile did not drop a packet")
        if sum(item["delayed"] for item in deltas.values()) == 0:
            raise HarnessError("WAN latency profile did not delay a packet")
        self.record_phase(
            "wan_loss_latency",
            started,
            {
                "target": target_name,
                "loss_permille": self.args.wan_loss_permille,
                "latency_ms": self.args.wan_latency_ms,
                "packet_deltas": deltas,
                "state_sync": self._shared_block(target_name),
                "heads": heads,
            },
        )

    def partition_fault(self) -> None:
        started = time.monotonic()
        target_name = "observer-2"
        before_metrics = {
            name: self.relays[name].metrics()
            for name in self.BOOTSTRAP_RELAYS_V1
        }
        before_height = int(self.status(target_name)["unsafe_head"]["height"])
        target_height = (
            int(self.status("producer")["unsafe_head"]["height"])
            + self.args.fault_blocks
        )
        for relay_name in self.BOOTSTRAP_RELAYS_V1:
            self.relays[relay_name].partition()

        def intercepted() -> dict[str, dict[str, int]] | None:
            current = {
                name: self.relays[name].metrics()
                for name in self.BOOTSTRAP_RELAYS_V1
            }
            delta = self._metric_delta(before_metrics, current)
            return (
                delta
                if sum(item["dropped"] for item in delta.values()) > 0
                else None
            )

        try:
            self.wait_until(
                "producer progress during partition",
                lambda: self._producer_reached(target_height),
            )
            deltas = self.wait_until(
                "partition packet interception", intercepted
            )
            isolated_height = int(
                self.status(target_name)["unsafe_head"]["height"]
            )
            if isolated_height >= target_height:
                raise HarnessError(
                    "partitioned observer continued importing producer blocks"
                )
        finally:
            for relay_name in self.BOOTSTRAP_RELAYS_V1:
                self.relays[relay_name].heal()
        healed = self.wait_until(
            "partitioned observer catch-up",
            lambda: self._caught_up(target_height, self.args.max_lag),
        )
        heads = self.validate_cluster(healed, self.args.max_lag)
        self.record_phase(
            "network_partition_reconnect",
            started,
            {
                "scope": "all_bootstrap_routes",
                "target": target_name,
                "before_height": before_height,
                "isolated_height": isolated_height,
                "packet_deltas": deltas,
                "state_sync": self._shared_block(target_name),
                "heads": heads,
            },
        )

    def bootstrap_outage_fault(self) -> None:
        started = time.monotonic()
        target_name = "observer-2"
        before_height = int(self.status(target_name)["unsafe_head"]["height"])
        self.processes[target_name].stop()
        before_metrics = {
            name: self.relays[name].metrics()
            for name in self.BOOTSTRAP_RELAYS_V1
        }
        for relay_name in self.BOOTSTRAP_RELAYS_V1:
            self.relays[relay_name].partition()
        try:
            self.processes[target_name].start()
            self.wait_until(
                "observer RPC during bootstrap outage",
                lambda: self.status(target_name),
            )
            target_height = before_height + self.args.fault_blocks
            self.wait_until(
                "producer progress during bootstrap outage",
                lambda: self._producer_reached(target_height),
            )
            isolated_height = int(
                self.status(target_name)["unsafe_head"]["height"]
            )
            if isolated_height > before_height:
                raise HarnessError(
                    "observer advanced while every bootstrap route was unavailable"
                )
        finally:
            for relay_name in self.BOOTSTRAP_RELAYS_V1:
                self.relays[relay_name].heal()
        recovered = self.wait_until(
            "bootstrap reconnect and state sync",
            lambda: self._caught_up(target_height, self.args.max_lag),
        )
        heads = self.validate_cluster(recovered, self.args.max_lag)
        after_metrics = {
            name: self.relays[name].metrics()
            for name in self.BOOTSTRAP_RELAYS_V1
        }
        deltas = self._metric_delta(before_metrics, after_metrics)
        if sum(item["dropped"] for item in deltas.values()) == 0:
            raise HarnessError("bootstrap outage did not intercept a dial packet")
        self.record_phase(
            "bootstrap_outage_reconnect",
            started,
            {
                "target": target_name,
                "restart_from_height": before_height,
                "isolated_height": isolated_height,
                "packet_deltas": deltas,
                "state_sync": self._shared_block(target_name),
                "heads": heads,
            },
        )

    def rotation_state_sync_fault(self) -> None:
        started = time.monotonic()
        target_name = "observer-3"
        before_height = int(self.status(target_name)["unsafe_head"]["height"])
        self.processes[target_name].stop()
        target_height = before_height + self.args.fault_blocks
        self.wait_until(
            "producer progress before peer rotation",
            lambda: self._producer_reached(target_height),
        )
        self._start_relay(
            "producer-v2", self.producer_relay_v2, self.producer_p2p
        )
        previous = self.registry_envelopes[1]["body"]["registry_id"]
        registry = self.publish_registry(
            2, self.producer_relay_v2, previous
        )
        self.relays["observer-1"].partition()
        before_metrics = self.relays["producer-v2"].metrics()
        try:
            self.processes[target_name].start()
            self.wait_until(
                "rotated observer RPC", lambda: self.status(target_name)
            )
            recovered = self.wait_until(
                "rotated bootstrap state sync",
                lambda: self._caught_up(target_height, self.args.max_lag),
            )
        finally:
            self.relays["observer-1"].heal()
        heads = self.validate_cluster(recovered, self.args.max_lag)
        after_metrics = self.relays["producer-v2"].metrics()
        if (
            after_metrics["received"] <= before_metrics["received"]
            or after_metrics["forwarded"] <= before_metrics["forwarded"]
        ):
            raise HarnessError("rotated producer relay carried no observer traffic")
        accepted = self.accepted_snapshot(target_name, 2)
        self.record_phase(
            "signed_peer_rotation_state_sync",
            started,
            {
                "target": target_name,
                "stable_peer_id": self.node_ids["producer"],
                "previous_registry_id": previous,
                "registry_id": registry["body"]["registry_id"],
                "registry_sequence": 2,
                "accepted_snapshot": accepted,
                "old_relay_port": self.producer_relay_v1,
                "new_relay_port": self.producer_relay_v2,
                "new_relay_metrics": after_metrics,
                "state_sync": self._shared_block(target_name),
                "heads": heads,
            },
        )

    def crash_fault(self) -> None:
        started = time.monotonic()
        crashed = "observer-3"
        before = int(self.status(crashed)["unsafe_head"]["height"])
        self.processes[crashed].stop()
        target = before + self.args.fault_blocks
        self.wait_until(
            "producer progress during observer crash",
            lambda: self._producer_reached(target),
        )
        self.processes[crashed].start()
        recovered = self.wait_until(
            "crashed observer recovery",
            lambda: self._caught_up(target, self.args.max_lag),
        )
        heads = self.validate_cluster(recovered, self.args.max_lag)
        self.record_phase(
            "observer_crash_restart",
            started,
            {
                "restart_from_height": before,
                "state_sync": self._shared_block(crashed),
                "heads": heads,
            },
        )

    def start_indexer(self) -> None:
        if self.identity is None:
            raise HarnessError("cluster identity is unavailable")
        environment = os.environ.copy()
        environment.update(
            {
                "NOOS_CHAIN_ID": self.identity[0],
                "NOOS_GENESIS_HASH": self.identity[1],
                "NOOS_NODE_RPC": f"127.0.0.1:{self.producer_rpc}",
                "NOOS_NODE_TOKEN": self.token,
                "NOOS_INDEXER_LISTEN": f"127.0.0.1:{self.indexer_port}",
                "NOOS_INDEXER_ROOT": str(self.root / "indexer"),
            }
        )
        bind = environment["NOOS_INDEXER_LISTEN"]
        if not ipaddress.ip_address(bind.rsplit(":", 1)[0]).is_loopback:
            raise HarnessError("indexer HTTP API is not loopback-bound")
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
            lambda: self._producer_reached(target),
        )
        self.processes["indexer"].start()
        recovered = self.wait_until(
            "indexer recovery",
            lambda: self._indexer_caught_up(minimum=target),
        )
        self.record_phase(
            "indexer_crash_restart",
            started,
            {
                "restart_from_height": initial_height,
                "recovered_height": int(recovered["unsafe_head"]["height"]),
                "listen": f"127.0.0.1:{self.indexer_port}",
            },
        )

    def _indexer_caught_up(self, minimum: int = 0) -> dict[str, Any] | None:
        indexer = self.indexer_status()
        producer = self.status("producer")
        if (
            indexer.get("chain_id") != producer.get("chain_id")
            or indexer.get("genesis_hash") != producer.get("genesis_hash")
        ):
            raise HarnessError("indexer identity differs from producer")
        index_height = int(indexer["unsafe_head"]["height"])
        producer_height = int(producer["unsafe_head"]["height"])
        if (
            indexer.get("ready") is True
            and index_height >= minimum
            and producer_height - index_height <= self.args.max_lag
        ):
            return indexer
        return None

    def run(self) -> dict[str, Any]:
        started = time.monotonic()
        try:
            self.start_cluster()
            self.wan_fault()
            self.partition_fault()
            self.bootstrap_outage_fault()
            self.rotation_state_sync_fault()
            self.crash_fault()
            self.indexer_fault()
            final_statuses = self.cluster_status()
            heads = self.validate_cluster(final_statuses, self.args.max_lag)
            final_blocks = {
                name: self._shared_block(name)
                for name in ("observer-1", "observer-2", "observer-3")
            }
            return {
                "schema": "noos/multi-node-network-soak-report/v2",
                "verdict": "PASS",
                "chain_id": self.identity[0] if self.identity else None,
                "genesis_hash": self.identity[1] if self.identity else None,
                "nodes": 4,
                "bootstrap_public_key": self.registry_public_key.hex(),
                "faults": self.phases,
                "final_heads": heads,
                "final_shared_blocks": final_blocks,
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
        finally:
            self.close()

    def close(self) -> None:
        for process in reversed(list(self.processes.values())):
            process.stop()
        for relay in self.relays.values():
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
    parser.add_argument(
        "--params",
        type=Path,
        default=ROOT / "protocol" / "genesis" / "devnet-parameters.toml",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(tempfile.gettempdir()) / "noosphere-network-soak",
    )
    parser.add_argument("--out", type=Path)
    parser.add_argument("--produce-interval-ms", type=int, default=500)
    parser.add_argument("--warmup-blocks", type=int, default=4)
    parser.add_argument("--fault-blocks", type=int, default=3)
    parser.add_argument("--max-lag", type=int, default=12)
    parser.add_argument("--wan-loss-permille", type=int, default=100)
    parser.add_argument("--wan-latency-ms", type=int, default=25)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args(argv)
    numeric = (
        args.produce_interval_ms,
        args.warmup_blocks,
        args.fault_blocks,
        args.max_lag + 1,
        args.wan_latency_ms,
    )
    if (
        min(numeric) < 1
        or not 1 <= args.wan_loss_permille <= 999
        or args.timeout <= 0
    ):
        print(
            "RESULT multi_node_fault_harness=FAIL reason=invalid numeric option",
            file=sys.stderr,
        )
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
    except (
        HarnessError,
        OSError,
        subprocess.SubprocessError,
        bootstrap_registry.BootstrapRegistryError,
    ) as error:
        report = {
            "schema": "noos/multi-node-network-soak-report/v2",
            "verdict": "FAIL",
            "reason": str(error),
        }
        code = 1
    else:
        code = 0
    output = args.out or args.root.with_suffix(".report.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    )
    print(
        f"RESULT multi_node_fault_harness={report['verdict']} out={output}"
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
