#!/usr/bin/env python3
"""Cross-device MindChain engineering-wallet transfers.

Seeds are read from a permission-restricted file or an interactive hidden prompt;
they are never accepted on the command line. Every send verifies chain identity,
builds canonical bytes with noos-cli, signs locally, submits the exact envelope,
and waits for a settled receipt from the public indexer.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZERO_ASSET = "00" * 32
HEX32 = re.compile(r"^[0-9a-f]{64}$")


def cargo_binary(name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    packaged = [
        ROOT / "target" / "release" / f"{name}{suffix}",
        ROOT / "target" / "debug" / f"{name}{suffix}",
    ]
    for path in packaged:
        if path.is_file():
            return path

    try:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            cwd=ROOT, text=True,
        ))
    except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"missing packaged {name}{suffix} and unable to inspect a Cargo workspace"
        ) from exc
    target = Path(metadata["target_directory"])
    for profile in ("release", "debug"):
        path = target / profile / f"{name}{suffix}"
        if path.is_file():
            return path
    raise SystemExit(
        f"missing {name}{suffix}; run cargo build -p noos-cli --bin noos-cli --release --locked"
    )


def api_json(base: str, path: str, *, body: dict | None = None, timeout: float = 10) -> dict:
    url = base.rstrip("/") + path
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(url, data=data)
    request.add_header("Accept", "application/vnd.noos.v1+json, application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read(1_048_577))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SystemExit(f"request failed: {url}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"malformed response from {url}")
    return value


def cli_json(exe: Path, *args: str) -> dict:
    completed = subprocess.run([str(exe), *args], cwd=ROOT, text=True, capture_output=True)
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or completed.stdout.strip() or "noos-cli failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit("noos-cli returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise SystemExit("noos-cli returned a non-object")
    return value


def read_seed(path: str | None) -> str:
    if path is None:
        seed = getpass.getpass("Wallet seed hex: ").strip()
    else:
        seed_path = Path(path)
        if not seed_path.is_file():
            raise SystemExit(f"seed file not found: {seed_path}")
        if os.name != "nt":
            mode = stat.S_IMODE(seed_path.stat().st_mode)
            if mode & 0o077:
                raise SystemExit("seed file must not be readable or writable by group/other")
        seed = seed_path.read_text(encoding="utf-8").strip()
    if HEX32.fullmatch(seed) is None:
        raise SystemExit("seed must be exactly 32 lowercase hex bytes")
    return seed


def load_profile(path: str) -> dict:
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"chain_id", "genesis_hash", "api_base_url"}
    if not isinstance(profile, dict) or not required.issubset(profile):
        raise SystemExit("profile must contain chain_id, genesis_hash, and api_base_url")
    if HEX32.fullmatch(str(profile["chain_id"])) is None or HEX32.fullmatch(str(profile["genesis_hash"])) is None:
        raise SystemExit("profile identity is malformed")
    if not str(profile["api_base_url"]).startswith(("https://", "http://127.0.0.1:", "http://localhost:", "http://10.", "http://192.168.")):
        raise SystemExit("plain HTTP is restricted to loopback or RFC1918 engineering LAN addresses")
    return profile


def checked_status(profile: dict) -> dict:
    status = api_json(str(profile["api_base_url"]), "/api/status")
    if status.get("chain_id") != profile["chain_id"] or status.get("genesis_hash") != profile["genesis_hash"]:
        raise SystemExit("wrong_protocol_identity")
    if status.get("api_version") != "v1" or status.get("protocol_version") != "v1":
        raise SystemExit("unsupported protocol/API version")
    return status


def derive(exe: Path, seed: str, account: int, index: int) -> dict:
    return cli_json(exe, "keygen", "--seed", seed, "--purpose", "sign", "--account", str(account), "--index", str(index))


def action(discriminant: int, account: str, asset: str, amount: int) -> str:
    return (discriminant.to_bytes(2, "little") + bytes.fromhex(account) + bytes.fromhex(asset) + amount.to_bytes(16, "little")).hex()


def balance(profile: dict, account: str, asset: str) -> dict:
    if HEX32.fullmatch(account) is None or HEX32.fullmatch(asset) is None:
        raise SystemExit("account and asset must be lowercase 32-byte hex values")
    return api_json(str(profile["api_base_url"]), f"/api/v1/balances/{account}/{asset}")


def send(args: argparse.Namespace, exe: Path, profile: dict) -> dict:
    if HEX32.fullmatch(args.to) is None or HEX32.fullmatch(args.asset) is None:
        raise SystemExit("recipient and asset must be lowercase 32-byte hex values")
    amount = int(args.amount)
    if amount <= 0:
        raise SystemExit("amount must be positive")
    seed = read_seed(args.seed_file)
    sender = str(derive(exe, seed, args.account, args.index)["verifying_key"])
    before = checked_status(profile)
    unsafe_height = int(before["unsafe_head"]["height"])
    balance_record = balance(profile, sender, args.asset)
    available = int(balance_record.get("unsafe_amount", balance_record.get("balance", "0")))
    if available < amount:
        raise SystemExit(f"insufficient balance: have {available}, requested {amount} plus fee")
    spec = {
        "chain_id": profile["chain_id"],
        "format_version": 1,
        "expiry_height": unsafe_height + 1000,
        "fee_payer": sender,
        "fee_authorization": None,
        "resource_limits": {
            "bytes": 4096,
            "grain_steps": 0,
            "proof_units": 0,
            "blob_bytes": 0,
            "state_reads": 64,
            "state_writes": 64,
        },
        "note_inputs": [],
        "account_inputs": [sender],
        "object_access_list": [],
        "actions": [action(3, sender, args.asset, amount), action(2, args.to, args.asset, amount)],
        "outputs": [],
        "evidence_refs": [],
        "lock_reveals": [],
    }
    built = cli_json(exe, "tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
    signed = cli_json(
        exe, "tx", "sign", "--tx", str(built["tx"]), "--seed", seed,
        "--account", str(args.account), "--index", str(args.index),
        "--chain-id", str(profile["chain_id"]), "--genesis-hash", str(profile["genesis_hash"]),
        "--scope", "0",
    )
    if signed.get("txid") != built.get("txid") or signed.get("verifying_key") != sender:
        raise SystemExit("local signature binding failed")
    checked_status(profile)
    accepted = api_json(str(profile["api_base_url"]), "/api/v1/transactions", body={"tx": built["tx"], "witnesses": signed["witnesses"]})
    if accepted.get("txid") != built["txid"]:
        raise SystemExit("submission txid mismatch")
    deadline = time.monotonic() + args.wait
    txid = str(built["txid"])
    while time.monotonic() < deadline:
        try:
            record = api_json(str(profile["api_base_url"]), f"/api/v1/transactions/{txid}")
        except SystemExit as error:
            if "HTTP Error 404" in str(error):
                time.sleep(0.25)
                continue
            raise
        state = record.get("state")
        if state in {"INCLUDED", "JUSTIFIED", "FINALIZED"}:
            return {"txid": txid, "state": state, "from": sender, "to": args.to, "asset": args.asset, "amount": str(amount)}
        if state in {"REJECTED", "REVERTED"}:
            raise SystemExit(f"transaction {state.lower()}: {record}")
        time.sleep(0.5)
    raise SystemExit(f"transaction did not settle within {args.wait}s: {txid}")


def parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(description=__doc__)
    out.add_argument("--profile", required=True, help="LAN/public chain profile JSON")
    sub = out.add_subparsers(dest="command", required=True)
    key = sub.add_parser("derive", help="derive a wallet public account")
    key.add_argument("--seed-file")
    key.add_argument("--account", type=int, default=0)
    key.add_argument("--index", type=int, default=0)
    bal = sub.add_parser("balance", help="read an account balance")
    bal.add_argument("--account-id", required=True)
    bal.add_argument("--asset", default=ZERO_ASSET)
    pay = sub.add_parser("send", help="sign and submit an account transfer")
    pay.add_argument("--seed-file")
    pay.add_argument("--account", type=int, default=0)
    pay.add_argument("--index", type=int, default=0)
    pay.add_argument("--to", required=True)
    pay.add_argument("--asset", default=ZERO_ASSET)
    pay.add_argument("--amount", required=True, help="integer base units")
    pay.add_argument("--wait", type=float, default=60)
    return out


def main() -> int:
    args = parser().parse_args()
    profile = load_profile(args.profile)
    exe = cargo_binary("noos-cli")
    if args.command == "derive":
        print(json.dumps(derive(exe, read_seed(args.seed_file), args.account, args.index), indent=2))
    elif args.command == "balance":
        checked_status(profile)
        print(json.dumps(balance(profile, args.account_id, args.asset), indent=2))
    else:
        print(json.dumps(send(args, exe, profile), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
