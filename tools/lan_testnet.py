#!/usr/bin/env python3
"""Provision and run a three-machine MindChain engineering LAN.

The generated public bundle contains only immutable chain identity inputs and
wallet public keys. Operator RPC credentials stay in a mode-restricted local
file. Run one foreground role per terminal/device; never expose operator RPC.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEX32 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_ROOT = Path(os.environ.get("NOOS_LAN_ROOT", str(Path.home() / ".mindchain-lan")))


def atomic_json(path: Path, value: dict, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    if private and os.name != "nt":
        tmp.chmod(0o600)
    os.replace(tmp, path)


def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def binary(name: str) -> Path:
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT, text=True
    ))
    suffix = ".exe" if os.name == "nt" else ""
    target = Path(metadata["target_directory"])
    candidates = [
        target / "debug" / f"{name}{suffix}",
        target / "release" / f"{name}{suffix}",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise SystemExit(f"missing {name}; build the LAN binaries first")


def load_manifest(path: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"schema", "genesis_time_ms", "params", "params_sha256", "wallet_accounts", "ports"}
    if not isinstance(value, dict) or value.get("schema") != "noos/lan-testnet/v1" or not required.issubset(value):
        raise SystemExit("invalid LAN manifest")
    params = Path(value["params"])
    if not params.is_absolute():
        params = ROOT / params
    if hashlib.sha256(params.read_bytes()).hexdigest() != value["params_sha256"]:
        raise SystemExit("genesis parameters checksum mismatch")
    for account in value["wallet_accounts"]:
        if HEX32.fullmatch(str(account)) is None:
            raise SystemExit("manifest contains malformed wallet account")
    return value


def init(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    params = Path(args.params).resolve()
    if not params.is_file():
        raise SystemExit(f"parameters not found: {params}")
    accounts = list(dict.fromkeys(args.wallet_account))
    if any(HEX32.fullmatch(item) is None for item in accounts):
        raise SystemExit("--wallet-account values must be lowercase 32-byte hex public keys")
    genesis_time = args.genesis_time_ms or int(time.time() * 1000) + 15_000
    manifest = {
        "schema": "noos/lan-testnet/v1",
        "created_unix_ms": int(time.time() * 1000),
        "genesis_time_ms": genesis_time,
        "params": str(params),
        "params_sha256": hashlib.sha256(params.read_bytes()).hexdigest(),
        "wallet_accounts": accounts,
        "ports": {"p2p": args.p2p_port, "operator_rpc": args.rpc_port, "indexer": args.indexer_port},
        "produce_interval_ms": args.produce_interval_ms,
    }
    secret = {"schema": "noos/lan-operator-secret/v1", "rpc_token": secrets.token_urlsafe(32)}
    atomic_json(root / "lan-manifest.json", manifest)
    atomic_json(root / "operator-secret.json", secret, private=True)
    print(json.dumps({
        "manifest": str(root / "lan-manifest.json"),
        "operator_secret": str(root / "operator-secret.json"),
        "copy_to_other_nodes": [str(root / "lan-manifest.json"), str(params)],
        "keep_private": str(root / "operator-secret.json"),
        "validator_lan_ip": local_ip(),
        "next": "run-validator on computer A; run-observer on computers B and C",
    }, indent=2))


def params_path(manifest: dict) -> str:
    path = Path(manifest["params"])
    return str(path if path.is_absolute() else ROOT / path)


def common_node(manifest: dict, data_dir: Path) -> list[str]:
    args = [
        str(binary("noosd")), "--params", params_path(manifest), "--data-dir", str(data_dir),
        "--genesis-time", str(manifest["genesis_time_ms"]),
    ]
    for account in manifest["wallet_accounts"]:
        args.extend(["--devnet-account", account])
    return args


def run_validator(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    secret = json.loads(Path(args.operator_secret).read_text(encoding="utf-8"))
    port = int(manifest["ports"]["p2p"])
    rpc = int(manifest["ports"]["operator_rpc"])
    command = common_node(manifest, Path(args.data_dir)) + [
        "--rpc", f"127.0.0.1:{rpc}", "--rpc-token", secret["rpc_token"],
        "--p2p-listen", f"/ip4/0.0.0.0/udp/{port}/quic-v1",
        "--devnet-producer", "--devnet-witness", "0",
        "--produce-interval-ms", str(manifest["produce_interval_ms"]),
        "--devnet-contract-fixture",
    ]
    print(f"validator peer address: /ip4/{local_ip()}/udp/{port}/quic-v1", flush=True)
    raise SystemExit(subprocess.call(command))


def run_observer(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    p2p_port = int(manifest["ports"]["p2p"])
    own_port = args.p2p_port
    peer = f"/ip4/{args.validator_host}/udp/{p2p_port}/quic-v1"
    command = common_node(manifest, Path(args.data_dir)) + [
        "--p2p-listen", f"/ip4/0.0.0.0/udp/{own_port}/quic-v1", "--peer", peer,
        "--observer", "--devnet-contract-fixture", "--devnet-witness", str(args.witness_index),
    ]
    if args.operator_secret and args.rpc_port:
        secret = json.loads(Path(args.operator_secret).read_text(encoding="utf-8"))
        command.extend([
            "--rpc", f"127.0.0.1:{args.rpc_port}",
            "--rpc-token", secret["rpc_token"],
        ])
    if args.light:
        command.append("--light")
    print(f"joining validator at {peer}", flush=True)
    raise SystemExit(subprocess.call(command))


def run_indexer(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    secret = json.loads(Path(args.operator_secret).read_text(encoding="utf-8"))
    rpc_port = int(manifest["ports"]["operator_rpc"])
    indexer_port = int(manifest["ports"]["indexer"])
    # Identity is learned once from the authenticated local node and then bound
    # into the public process environment.
    request = urllib.request.Request(f"http://127.0.0.1:{rpc_port}/status")
    request.add_header("Authorization", f"Bearer {secret['rpc_token']}")
    with urllib.request.urlopen(request, timeout=5) as response:
        status = json.load(response)
    env = os.environ.copy()
    env.update({
        "NOOS_CHAIN_ID": status["chain_id"],
        "NOOS_GENESIS_HASH": status["genesis_hash"],
        "NOOS_NODE_RPC": f"127.0.0.1:{rpc_port}",
        "NOOS_NODE_TOKEN": secret["rpc_token"],
        "NOOS_INDEXER_LISTEN": f"0.0.0.0:{indexer_port}",
        "NOOS_INDEXER_ROOT": str(Path(args.data_dir).resolve()),
    })
    profile = {
        "schema": "noos-wallet-lan-profile-v1",
        "chain_id": status["chain_id"], "genesis_hash": status["genesis_hash"],
        "api_version": "v1", "api_base_url": f"http://{args.public_host}:{indexer_port}",
        "test_network": True,
    }
    atomic_json(Path(args.profile_out), profile)
    print(json.dumps({"public_profile": str(Path(args.profile_out).resolve()), "api": profile["api_base_url"]}, indent=2), flush=True)
    raise SystemExit(subprocess.call([str(binary("noos-indexer"))], env=env))


def status(args: argparse.Namespace) -> None:
    profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    with urllib.request.urlopen(profile["api_base_url"].rstrip("/") + "/api/status", timeout=5) as response:
        value = json.load(response)
    if value.get("chain_id") != profile.get("chain_id") or value.get("genesis_hash") != profile.get("genesis_hash"):
        raise SystemExit("wrong_protocol_identity")
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("init")
    create.add_argument("--root", default=str(DEFAULT_ROOT))
    create.add_argument("--params", default=str(ROOT / "protocol/genesis/devnet-parameters.toml"))
    create.add_argument("--wallet-account", action="append", default=[])
    create.add_argument("--genesis-time-ms", type=int)
    create.add_argument("--p2p-port", type=int, default=19701)
    create.add_argument("--rpc-port", type=int, default=18632)
    create.add_argument("--indexer-port", type=int, default=18080)
    create.add_argument("--produce-interval-ms", type=int, default=6000)
    validator = sub.add_parser("run-validator")
    validator.add_argument("--manifest", required=True)
    validator.add_argument("--operator-secret", required=True)
    validator.add_argument("--data-dir", default=str(DEFAULT_ROOT / "validator"))
    observer = sub.add_parser("run-observer")
    observer.add_argument("--manifest", required=True)
    observer.add_argument("--validator-host", required=True)
    observer.add_argument("--data-dir", default=str(DEFAULT_ROOT / "observer"))
    observer.add_argument("--p2p-port", type=int, default=19702)
    observer.add_argument("--witness-index", type=int, choices=(1, 2, 3), required=True)
    observer.add_argument("--operator-secret")
    observer.add_argument("--rpc-port", type=int)
    observer.add_argument("--light", action="store_true")
    indexer = sub.add_parser("run-indexer")
    indexer.add_argument("--manifest", required=True)
    indexer.add_argument("--operator-secret", required=True)
    indexer.add_argument("--public-host", required=True)
    indexer.add_argument("--data-dir", default=str(DEFAULT_ROOT / "indexer"))
    indexer.add_argument("--profile-out", default=str(DEFAULT_ROOT / "wallet-profile.json"))
    inspect = sub.add_parser("status")
    inspect.add_argument("--profile", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    {"init": init, "run-validator": run_validator, "run-observer": run_observer,
     "run-indexer": run_indexer, "status": status}[args.command](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
