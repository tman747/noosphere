#!/usr/bin/env python3
"""Issue, verify, list, and revoke signed MindChain invitation role leases."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "noos/invitation-lease/v2"
DOMAIN = b"NOOS/INVITATION/LEASE/V2\0"
ROLES = {"observer", "witness-1", "witness-2", "witness-3"}


def canonical_payload(invite: dict) -> bytes:
    payload = dict(invite)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_seed(path: Path) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError as error:
        raise SystemExit("invitation seed must contain lowercase hexadecimal bytes") from error
    if len(seed) != 32 or text != seed.hex():
        raise SystemExit("invitation seed must contain exactly 32 lowercase bytes")
    return seed


def keygen(path: Path) -> str:
    if path.exists():
        raise SystemExit(f"refusing to overwrite invitation seed: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(seed.hex() + "\n", encoding="ascii", newline="\n")
    if os.name != "nt":
        temporary.chmod(0o600)
    os.replace(temporary, path)
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute(
        """CREATE TABLE IF NOT EXISTS invitation_leases (
            lease_id TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            platform TEXT NOT NULL,
            issued_ms INTEGER NOT NULL,
            expires_ms INTEGER NOT NULL,
            revoked_ms INTEGER,
            invite_json TEXT NOT NULL
        )"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS invitation_role_active ON invitation_leases(role, expires_ms, revoked_ms)"
    )
    db.commit()
    return db


def issue_lease(
    database: Path,
    seed_path: Path,
    invite: dict,
    role: str,
    platform: str,
    ttl_seconds: int,
    now_ms: int | None = None,
) -> dict:
    if role not in ROLES:
        raise ValueError(f"unsupported invitation role: {role}")
    if platform not in {"windows", "macos", "linux"}:
        raise ValueError(f"unsupported invitation platform: {platform}")
    if not 60 <= ttl_seconds <= 30 * 24 * 60 * 60:
        raise ValueError("invitation TTL must be between 60 seconds and 30 days")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    expires = now + ttl_seconds * 1000
    private = Ed25519PrivateKey.from_private_bytes(read_seed(seed_path))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    lease_id = secrets.token_hex(16)
    signed = dict(invite)
    signed.update(
        {
            "schema": SCHEMA,
            "lease_id": lease_id,
            "role": role,
            "platform": platform,
            "issued_unix_ms": now,
            "expires_unix_ms": expires,
            "signing_key": public,
        }
    )
    signed["signature"] = private.sign(DOMAIN + canonical_payload(signed)).hex()
    encoded = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with open_db(database) as db:
        db.execute("BEGIN IMMEDIATE")
        active = db.execute(
            "SELECT lease_id FROM invitation_leases WHERE role=? AND revoked_ms IS NULL AND expires_ms>?",
            (role, now),
        ).fetchone()
        if active is not None and role != "observer":
            raise ValueError(f"role {role} is already leased by {active[0]}")
        db.execute(
            "INSERT INTO invitation_leases VALUES (?,?,?,?,?,?,?)",
            (lease_id, role, platform, now, expires, None, encoded),
        )
        db.commit()
    return signed


def verify_lease(invite: dict, database: Path | None = None, now_ms: int | None = None) -> None:
    if invite.get("schema") != SCHEMA:
        raise ValueError("unsupported invitation lease schema")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    issued = int(invite.get("issued_unix_ms", 0))
    expires = int(invite.get("expires_unix_ms", 0))
    if issued <= 0 or expires <= issued or now < issued or now >= expires:
        raise ValueError("invitation lease is not currently valid")
    try:
        public = bytes.fromhex(str(invite["signing_key"]))
        signature = bytes.fromhex(str(invite["signature"]))
    except (KeyError, ValueError) as error:
        raise ValueError("invitation lease signature is malformed") from error
    if len(public) != 32 or len(signature) != 64:
        raise ValueError("invitation lease signature has the wrong length")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, DOMAIN + canonical_payload(invite)
        )
    except Exception as error:
        raise ValueError("invitation lease signature verification failed") from error
    if database is not None:
        with open_db(database) as db:
            row = db.execute(
                "SELECT expires_ms,revoked_ms,invite_json FROM invitation_leases WHERE lease_id=?",
                (str(invite.get("lease_id", "")),),
            ).fetchone()
        if row is None or row[1] is not None or int(row[0]) != expires:
            raise ValueError("invitation lease is unknown or revoked")
        if json.loads(row[2]) != invite:
            raise ValueError("invitation lease differs from the issued record")


def revoke_lease(database: Path, lease_id: str, now_ms: int | None = None) -> bool:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    with open_db(database) as db:
        changed = db.execute(
            "UPDATE invitation_leases SET revoked_ms=? WHERE lease_id=? AND revoked_ms IS NULL",
            (now, lease_id),
        ).rowcount
        db.commit()
    return changed == 1


def lease_rows(database: Path) -> list[dict]:
    with open_db(database) as db:
        rows = db.execute(
            "SELECT lease_id,role,platform,issued_ms,expires_ms,revoked_ms FROM invitation_leases ORDER BY issued_ms DESC"
        ).fetchall()
    keys = ("lease_id", "role", "platform", "issued_unix_ms", "expires_unix_ms", "revoked_unix_ms")
    return [dict(zip(keys, row)) for row in rows]


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("keygen")
    generate.add_argument("--seed-file", required=True)
    issue = sub.add_parser("issue")
    issue.add_argument("--database", required=True)
    issue.add_argument("--seed-file", required=True)
    issue.add_argument("--invite", required=True)
    issue.add_argument("--role", choices=sorted(ROLES), required=True)
    issue.add_argument("--platform", choices=("windows", "macos", "linux"), required=True)
    issue.add_argument("--ttl-seconds", type=int, default=86400)
    issue.add_argument("--output", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--invite", required=True)
    verify.add_argument("--database")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--database", required=True)
    revoke.add_argument("--lease-id", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--database", required=True)
    args = parser.parse_args()
    if args.command == "keygen":
        print(json.dumps({"signing_key": keygen(Path(args.seed_file))}, indent=2))
    elif args.command == "issue":
        invite = json.loads(Path(args.invite).read_text(encoding="utf-8"))
        signed = issue_lease(
            Path(args.database), Path(args.seed_file), invite, args.role, args.platform, args.ttl_seconds
        )
        atomic_json(Path(args.output), signed)
        print(json.dumps({"lease_id": signed["lease_id"], "expires_unix_ms": signed["expires_unix_ms"]}, indent=2))
    elif args.command == "verify":
        invite = json.loads(Path(args.invite).read_text(encoding="utf-8"))
        verify_lease(invite, Path(args.database) if args.database else None)
        print(json.dumps({"valid": True, "lease_id": invite["lease_id"]}, indent=2))
    elif args.command == "revoke":
        if not revoke_lease(Path(args.database), args.lease_id):
            raise SystemExit("unknown or already revoked invitation lease")
        print(json.dumps({"revoked": True, "lease_id": args.lease_id}, indent=2))
    else:
        print(json.dumps({"items": lease_rows(Path(args.database))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
