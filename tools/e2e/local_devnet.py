#!/usr/bin/env python3
"""Run or inspect a persistent local NOOSPHERE developer network.

The foreground ``run`` command owns a validator, QUIC-peered observer, and
indexer. Runtime state stays under --runtime-dir, so stopping and rerunning the
command exercises durable node/indexer recovery with the same chain identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_smoke import (  # noqa: E402
    FAUCET_KEY,
    FAUCET_PUB,
    INDEXER,
    P2P_A,
    RPC_A,
    RPC_B,
    TOKEN,
    Proc,
    build_binaries,
    cli,
    enc_intent,
    enc_witnesses,
    http_json,
    sign_txid,
    transfer_actions,
)

DEFAULT_RUNTIME = Path(os.environ.get("NOOS_LOCAL_DEVNET_DIR", "C:/tmp/noosphere-local-devnet"))
DEFAULT_GENESIS_TIME_MS = 1_783_834_564_049
PRODUCE_INTERVAL_MS = 6000
RECIPIENT_SEED = hashlib.blake2b(
    b"noos-local-devnet/developer-account", digest_size=32
).hexdigest()

MAX_OBSERVER_LAG = 8
MAX_INDEXER_LAG = 16
DEVNET_CONTRACT_CODE_HASH = "c0" * 32
DEVELOPER_FUNDING_MICRO = 100_000_000


def head_height(status_value: object) -> int:
    if not isinstance(status_value, dict):
        raise ValueError("status is not an object")
    head = status_value.get("unsafe_head")
    if not isinstance(head, dict):
        raise ValueError("status.unsafe_head is not an object")
    return int(head["height"])


def readiness(expected: dict, checks: dict[str, object]) -> tuple[list[str], dict[str, int]]:
    issues: list[str] = []
    identities = ("chain_id", "genesis_hash")
    for name in ("validator", "observer", "indexer"):
        value = checks.get(name)
        if not isinstance(value, dict) or "error" in value:
            issues.append(f"{name} unavailable")
            continue
        for field in identities:
            if value.get(field) != expected.get(field):
                issues.append(f"{name} {field} mismatch")
    lags: dict[str, int] = {}
    try:
        validator_height = head_height(checks["validator"])
        for name, maximum in (
            ("observer", MAX_OBSERVER_LAG),
            ("indexer", MAX_INDEXER_LAG),
        ):
            lag = max(0, validator_height - head_height(checks[name]))
            lags[name] = lag
            if lag > maximum:
                issues.append(f"{name} head lag {lag} exceeds {maximum}")
    except (KeyError, TypeError, ValueError) as exc:
        issues.append(f"invalid head status: {exc}")
    return issues, lags


def wait_devnet_ready(expected: dict, deadline_s: float) -> dict[str, object]:
    deadline = time.monotonic() + deadline_s
    last_issues: list[str] = ["services not queried"]
    last_checks: dict[str, object] = {}
    while time.monotonic() < deadline:
        checks: dict[str, object] = {}
        for name, addr, path, auth in (
            ("validator", RPC_A, "/status", TOKEN),
            ("observer", RPC_B, "/status", TOKEN),
            ("indexer", INDEXER, "/api/status", None),
        ):
            try:
                checks[name] = http_json(addr, path, auth, 2)
            except Exception as exc:
                checks[name] = {"error": str(exc)}
        last_issues, lags = readiness(expected, checks)
        checks["head_lag"] = lags
        last_checks = checks
        if not last_issues:
            return checks
        time.sleep(0.5)
    raise RuntimeError(
        f"devnet did not become coherent within {deadline_s}s: "
        f"{last_issues}; last={last_checks}"
    )

def wait_http(addr: str, path: str, token: str | None, deadline_s: float) -> dict:
    deadline = time.monotonic() + deadline_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = http_json(addr, path, token, 2)
            if isinstance(value, dict):
                return value
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            last = exc
        time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for http://{addr}{path}: {last}")


def runtime_metadata(runtime: Path) -> dict:
    path = runtime / "local-devnet.json"
    if not path.is_file():
        raise SystemExit(f"local devnet metadata not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def status(runtime: Path) -> int:
    metadata = runtime_metadata(runtime)
    token = metadata["rpc_token"]
    checks: dict[str, object] = {"metadata": metadata}
    for name, addr, path, auth in (
        ("validator", metadata["validator_rpc"], "/status", token),
        ("observer", metadata["observer_rpc"], "/status", token),
        ("indexer", metadata["indexer"], "/api/status", None),
    ):
        try:
            checks[name] = http_json(addr, path, auth, 2)
        except Exception as exc:  # status must report every unavailable surface
            checks[name] = {"error": str(exc)}
    issues, lags = readiness(metadata, checks)
    checks["ready"] = not issues
    checks["issues"] = issues
    checks["head_lag"] = lags
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if not issues else 1


def derive_recipient(exe: Path) -> str:
    derived = cli(
        exe,
        "keygen",
        "--seed",
        RECIPIENT_SEED,
        "--purpose",
        "sign",
        "--account",
        "0",
        "--index",
        "0",
    )
    verifying_key = str(derived["verifying_key"])
    if re.fullmatch(r"[0-9a-f]{64}", verifying_key) is None:
        raise RuntimeError("developer account derivation returned a noncanonical verifying key")
    return verifying_key


def ensure_developer_funded(
    exe: Path,
    prior: dict,
    chain_id: str,
    genesis_hash: str,
    recipient: str,
) -> str:
    prior_txid = prior.get("developer_funding_txid")
    if isinstance(prior_txid, str):
        try:
            receipt = http_json(RPC_A, f"/receipt/{prior_txid}", TOKEN, 2)
            if isinstance(receipt.get("state"), dict):
                return prior_txid
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
    current = http_json(RPC_A, "/status", TOKEN, 2)
    spec = {
        "chain_id": chain_id,
        "expiry_height": head_height(current) + 1000,
        "fee_payer": FAUCET_PUB.hex(),
        "resource_limits": {
            "bytes": 4096,
            "grain_steps": 0,
            "proof_units": 0,
            "blob_bytes": 0,
            "state_reads": 64,
            "state_writes": 64,
        },
        "account_inputs": [FAUCET_PUB.hex()],
        "actions": transfer_actions(
            FAUCET_PUB,
            bytes.fromhex(recipient),
            DEVELOPER_FUNDING_MICRO,
        ),
    }
    built = cli(exe, "tx", "build", "--spec", json.dumps(spec))
    txid = str(built["txid"])
    signature = sign_txid(FAUCET_KEY, bytes.fromhex(txid))
    witnesses = enc_witnesses([enc_intent(bytes.fromhex(txid), signature)]).hex()
    submitted = cli(
        exe,
        "tx",
        "submit",
        "--node",
        RPC_A,
        "--token",
        TOKEN,
        "--chain-id",
        chain_id,
        "--genesis-hash",
        genesis_hash,
        "--tx",
        str(built["tx"]),
        "--witnesses",
        witnesses,
    )
    if submitted.get("txid") != txid:
        raise RuntimeError("developer funding submission returned the wrong txid")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        receipt = http_json(RPC_A, f"/receipt/{txid}", TOKEN, 2)
        state = receipt.get("state")
        if isinstance(state, dict):
            if state.get("status_code") != 0:
                raise RuntimeError(f"developer funding failed: {receipt}")
            return txid
        time.sleep(0.5)
    raise RuntimeError("developer funding did not settle within 60s")


def run(runtime: Path, *, build: bool) -> int:
    runtime.mkdir(parents=True, exist_ok=True)
    logs = runtime / "logs"
    logs.mkdir(exist_ok=True)
    env = os.environ.copy()
    if build:
        exes = build_binaries(env)
    else:
        import subprocess

        metadata = json.loads(
            subprocess.check_output(
                ["cargo", "metadata", "--format-version", "1", "--no-deps"],
                cwd=ROOT,
                env=env,
                text=True,
            )
        )
        suffix = ".exe" if os.name == "nt" else ""
        debug = Path(metadata["target_directory"]) / "debug"
        exes = {name: debug / (name + suffix) for name in ("noosd", "noos-indexer", "noos-cli")}
        missing = [str(path) for path in exes.values() if not path.is_file()]
        if missing:
            raise SystemExit(f"missing developer binaries; omit --no-build: {missing}")

    metadata_path = runtime / "local-devnet.json"
    prior = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else {}
    genesis_time_ms = int(prior.get("genesis_time_ms", DEFAULT_GENESIS_TIME_MS))
    recipient = derive_recipient(exes["noos-cli"])
    procs: list[Proc] = []
    try:
        validator = Proc(
            "noosd-validator",
            [
                str(exes["noosd"]),
                "--data-dir",
                str(runtime / "validator"),
                "--genesis-time",
                str(genesis_time_ms),
                "--rpc",
                RPC_A,
                "--rpc-token",
                TOKEN,
                "--p2p-listen",
                P2P_A,
                "--validator",
                "--produce-interval-ms",
                str(PRODUCE_INTERVAL_MS),
                "--devnet-account",
                recipient,
                "--devnet-contract-fixture",
            ],
            env,
            logs,
        )
        procs.append(validator)
        up = validator.wait_line(
            r"noosd up: chain_id=([0-9a-f]{64}) genesis_hash=([0-9a-f]{64})", 300
        )
        match = re.search(
            r"chain_id=([0-9a-f]{64}) genesis_hash=([0-9a-f]{64})", up
        )
        if match is None:
            raise RuntimeError("validator did not report canonical identity")
        chain_id, genesis_hash = match.group(1), match.group(2)
        validator.wait_line(r"operator RPC ready", 30)
        p2p_line = validator.wait_line(r"p2p ready at (\S+)", 30)
        peer_addr = p2p_line.rsplit(" ", 1)[-1]

        observer = Proc(
            "noosd-observer",
            [
                str(exes["noosd"]),
                "--data-dir",
                str(runtime / "observer"),
                "--genesis-time",
                str(genesis_time_ms),
                "--rpc",
                RPC_B,
                "--rpc-token",
                TOKEN,
                "--peer",
                peer_addr,
                "--observer",
                "--devnet-account",
                recipient,
                "--devnet-contract-fixture",
                "--devnet-witness-fixture",
            ],
            env,
            logs,
        )
        procs.append(observer)
        observer.wait_line(r"noosd up: chain_id=" + chain_id, 300)

        indexer_root = runtime / "indexer"
        indexer_root.mkdir(exist_ok=True)
        checkpoint_path = indexer_root / "ingest-checkpoint-v1.json"
        # The current indexer keeps query state in memory and a durable ingest
        # cursor on disk. Rebuild the local query view deterministically on
        # every process start so the cursor never skips data after a restart.
        first = wait_http(RPC_A, "/block/1", TOKEN, 30)
        parent_hash = first.get("parent_hash")
        if first.get("height") != 1 or not isinstance(parent_hash, str):
            raise RuntimeError("validator block 1 cannot seed the indexer checkpoint")
        checkpoint = {
            "schema": "noos-ingest-checkpoint-v1",
            "identity": {
                "chain_id": chain_id,
                "genesis_hash": genesis_hash,
                "api_version": "v1",
            },
            "next_height": "1",
            "recent": [{"height": "0", "hash": parent_hash}],
        }
        checkpoint_path.write_text(
            json.dumps(checkpoint, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

        indexer_env = dict(
            env,
            NOOS_CHAIN_ID=chain_id,
            NOOS_GENESIS_HASH=genesis_hash,
            NOOS_NODE_RPC=RPC_A,
            NOOS_NODE_TOKEN=TOKEN,
            NOOS_INDEXER_LISTEN=INDEXER,
            NOOS_INDEXER_ROOT=str(indexer_root),
        )
        indexer = Proc("noos-indexer", [str(exes["noos-indexer"])], indexer_env, logs)
        procs.append(indexer)
        coherent = wait_devnet_ready(
            {"chain_id": chain_id, "genesis_hash": genesis_hash},
            300,
        )
        developer_funding_txid = ensure_developer_funded(
            exes["noos-cli"],
            prior,
            chain_id,
            genesis_hash,
            recipient,
        )
        coherent = wait_devnet_ready(
            {"chain_id": chain_id, "genesis_hash": genesis_hash},
            60,
        )
        validator_status = coherent["validator"]
        observer_status = coherent["observer"]
        indexer_status = coherent["indexer"]

        metadata = {
            "schema": "noos/local-devnet/v1",
            "runtime_dir": str(runtime.resolve()),
            "genesis_time_ms": genesis_time_ms,
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "developer_seed_hex": RECIPIENT_SEED,
            "developer_public_id": recipient,
            "developer_funding_micro": DEVELOPER_FUNDING_MICRO,
            "developer_funding_txid": developer_funding_txid,
            "devnet_contract_code_hash": DEVNET_CONTRACT_CODE_HASH,
            "validator_rpc": RPC_A,
            "observer_rpc": RPC_B,
            "indexer": INDEXER,
            "p2p": peer_addr,
            "rpc_token": TOKEN,
            "produce_interval_ms": PRODUCE_INTERVAL_MS,
        }
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print("RESULT local_devnet=READY", flush=True)
        print(json.dumps(metadata, indent=2, sort_keys=True), flush=True)
        print(
            json.dumps(
                {
                    "validator_head": validator_status.get("unsafe_head"),
                    "observer_head": observer_status.get("unsafe_head"),
                    "indexer_status": indexer_status,
                },
                indent=2,
                sort_keys=True,
            ),
            flush=True,
        )
        while True:
            for proc in procs:
                if proc.p.poll() is not None:
                    raise RuntimeError(f"{proc.name} exited with code {proc.p.returncode}; see {proc.log_path}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("RESULT local_devnet=STOPPING", flush=True)
        return 0
    finally:
        for proc in reversed(procs):
            proc.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("run", "status"), default="run")
    parser.add_argument("--runtime-dir", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    if args.command == "status":
        return status(args.runtime_dir)
    return run(args.runtime_dir, build=not args.no_build)


if __name__ == "__main__":
    raise SystemExit(main())
