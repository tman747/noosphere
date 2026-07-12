#!/usr/bin/env python3
"""Sign and verify replay-protected MindChain fleet telemetry reports."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "noos/fleet-telemetry/v1"
DOMAIN = b"NOOS/FLEET/TELEMETRY/V1\0"
HEX32 = 64


def canonical(report: dict) -> bytes:
    value = dict(report)
    value.pop("signature", None)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_seed(path: Path) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError as error:
        raise ValueError("telemetry seed is malformed") from error
    if len(seed) != 32 or text != seed.hex():
        raise ValueError("telemetry seed must be exactly 32 lowercase bytes")
    return seed


def public_hex(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def node_id(public_key: str) -> str:
    return hashlib.sha256(b"NOOS/FLEET/NODE/V1\0" + bytes.fromhex(public_key)).hexdigest()


def keygen(path: Path) -> dict:
    if path.exists():
        raise ValueError(f"refusing to overwrite telemetry seed: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(secrets.token_hex(32) + "\n", encoding="ascii", newline="\n")
    if os.name != "nt":
        temporary.chmod(0o600)
    os.replace(temporary, path)
    public = public_hex(read_seed(path))
    return {"node_id": node_id(public), "public_key": public}


def sign_report(seed_path: Path, sequence: int, status: dict, *, observed_ms: int | None = None) -> dict:
    if sequence < 1:
        raise ValueError("telemetry sequence must be positive")
    seed = read_seed(seed_path)
    public = public_hex(seed)
    chain_id = str(status.get("chain_id", ""))
    genesis_hash = str(status.get("genesis_hash", ""))
    if len(chain_id) != HEX32 or len(genesis_hash) != HEX32:
        raise ValueError("status protocol identity is malformed")
    report = {
        "schema": SCHEMA,
        "node_id": node_id(public),
        "public_key": public,
        "sequence": sequence,
        "observed_unix_ms": int(time.time() * 1000) if observed_ms is None else observed_ms,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "version": str(status.get("version", "unknown"))[:64],
        "architecture": platform.machine()[:64],
        "sync": status.get("sync", {}),
        "peers": int(status.get("peers", 0)),
        "bootstrap": str(status.get("bootstrap", "unknown"))[:256],
        "capacity": status.get("capacity", {}),
        "worker_policy": status.get("worker_policy", {}),
    }
    report["signature"] = Ed25519PrivateKey.from_private_bytes(seed).sign(
        DOMAIN + canonical(report)
    ).hex()
    return report


def load_roster(path: Path) -> dict[str, str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "noos/fleet-roster/v1" or not isinstance(value.get("nodes"), list):
        raise ValueError("fleet roster is malformed")
    roster: dict[str, str] = {}
    for entry in value["nodes"]:
        identity, public = str(entry.get("node_id", "")), str(entry.get("public_key", ""))
        if len(identity) != HEX32 or len(public) != HEX32 or node_id(public) != identity:
            raise ValueError("fleet roster identity is malformed")
        if identity in roster:
            raise ValueError("fleet roster contains a duplicate node")
        roster[identity] = public
    return roster


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS fleet_reports(node_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, observed_ms INTEGER NOT NULL, report_json TEXT NOT NULL)")
    db.commit()
    return db


def verify_report(report: dict, roster: dict[str, str], database: Path, *, now_ms: int | None = None, freshness_ms: int = 120_000) -> None:
    if report.get("schema") != SCHEMA:
        raise ValueError("telemetry schema is unsupported")
    identity = str(report.get("node_id", ""))
    public = str(report.get("public_key", ""))
    if roster.get(identity) != public or node_id(public) != identity:
        raise ValueError("telemetry node is not in the trusted roster")
    sequence = report.get("sequence")
    observed = report.get("observed_unix_ms")
    if type(sequence) is not int or sequence < 1 or type(observed) is not int:
        raise ValueError("telemetry sequence or timestamp is malformed")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if observed > now + 30_000 or now - observed > freshness_ms:
        raise ValueError("telemetry report is stale or future-dated")
    try:
        signature = bytes.fromhex(str(report["signature"]))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(signature, DOMAIN + canonical(report))
    except Exception as error:
        raise ValueError("telemetry signature verification failed") from error
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    with open_db(database) as db:
        db.execute("BEGIN IMMEDIATE")
        prior = db.execute("SELECT sequence FROM fleet_reports WHERE node_id=?", (identity,)).fetchone()
        if prior is not None and sequence <= int(prior[0]):
            raise ValueError("telemetry sequence was replayed or regressed")
        db.execute(
            "INSERT INTO fleet_reports VALUES(?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET sequence=excluded.sequence,observed_ms=excluded.observed_ms,report_json=excluded.report_json",
            (identity, sequence, observed, encoded),
        )
        db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    key = sub.add_parser("keygen"); key.add_argument("--seed-file", required=True)
    sign = sub.add_parser("sign"); sign.add_argument("--seed-file", required=True); sign.add_argument("--sequence", type=int, required=True); sign.add_argument("--status", required=True); sign.add_argument("--output", required=True)
    verify = sub.add_parser("verify"); verify.add_argument("--report", required=True); verify.add_argument("--roster", required=True); verify.add_argument("--database", required=True); verify.add_argument("--freshness-ms", type=int, default=120_000)
    args = parser.parse_args()
    if args.command == "keygen":
        print(json.dumps(keygen(Path(args.seed_file)), indent=2))
    elif args.command == "sign":
        status = json.loads(Path(args.status).read_text(encoding="utf-8"))
        report = sign_report(Path(args.seed_file), args.sequence, status)
        Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"node_id": report["node_id"], "sequence": report["sequence"]}, indent=2))
    else:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        verify_report(report, load_roster(Path(args.roster)), Path(args.database), freshness_ms=args.freshness_ms)
        print(json.dumps({"verified": True, "node_id": report["node_id"], "sequence": report["sequence"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
