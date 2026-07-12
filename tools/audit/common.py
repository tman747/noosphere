#!/usr/bin/env python3
"""Shared fail-closed helpers for the independent-audit handoff."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROOT = Path(__file__).resolve().parents[2]


class AuditError(ValueError):
    """A deterministic validation failure suitable for a gate result."""


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AuditError(f"{field} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def safe_member(name: str) -> PurePosixPath:
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts or "" in candidate.parts:
        raise AuditError(f"unsafe package path: {name}")
    return candidate


def read_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"{label} must be a JSON object")
    return value


def git(*args: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def resolve_revision(revision: str) -> str:
    resolved = str(git("rev-parse", f"{revision}^{{commit}}"))
    if not HEX40.fullmatch(resolved):
        raise AuditError("git did not resolve a full commit revision")
    return resolved


def git_paths(revision: str) -> list[str]:
    raw = str(git("ls-tree", "-r", "--name-only", revision))
    return [line for line in raw.splitlines() if line]


def git_blob(revision: str, path: str) -> bytes:
    safe_member(path)
    return bytes(git("show", f"{revision}:{path}", binary=True))


def verify_ed25519(public_key_base64: str, signature_base64: str, payload: bytes) -> str:
    try:
        public_key = base64.b64decode(public_key_base64, validate=True)
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise AuditError("signature or public key is not strict base64") from exc
    if len(public_key) != 32 or len(signature) != 64:
        raise AuditError("Ed25519 public key/signature has the wrong length")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (ValueError, InvalidSignature) as exc:
        raise AuditError("detached Ed25519 signature verification failed") from exc
    return sha256_bytes(public_key)


def _verify_file_map(root: Path, files: dict[str, str]) -> None:
    if not files:
        raise AuditError("bundle file map is empty")
    for relative, expected in sorted(files.items()):
        safe_member(relative)
        if not HEX64.fullmatch(str(expected)):
            raise AuditError(f"invalid bundle hash for {relative}")
        path = root / Path(*PurePosixPath(relative).parts)
        if not path.is_file():
            raise AuditError(f"bundle file missing: {relative}")
        if sha256_file(path) != expected:
            raise AuditError(f"bundle file hash mismatch: {relative}")


def verify_bundle_dir(root: Path) -> dict:
    manifest_path = root / "bundle-manifest.json"
    manifest = read_json(manifest_path, "bundle manifest")
    if manifest.get("schema_version") != 1 or manifest.get("bundle_kind") != "noosphere-independent-audit-handoff":
        raise AuditError("wrong audit bundle schema or kind")
    if manifest.get("external_audit_complete") is not False or manifest.get("promotion_effect") != "none":
        raise AuditError("bundle makes an unauthorized completion or promotion claim")
    revision = manifest.get("source_revision")
    if not isinstance(revision, str) or not HEX40.fullmatch(revision):
        raise AuditError("bundle source revision is not an exact Git commit")
    _verify_file_map(root, manifest.get("files", {}))
    listed = set(manifest["files"])
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "bundle-manifest.json"
    }
    if actual != listed:
        raise AuditError(
            f"bundle file set mismatch missing={sorted(listed - actual)} unbound={sorted(actual - listed)}"
        )
    binding = manifest.get("binding", {})
    for key, relative in {
        "scope_sha256": "audit-scope.json",
        "source_manifest_sha256": "source-manifest.json",
        "threat_inventory_sha256": "threat-model-inventory.json",
    }.items():
        expected = binding.get(key)
        if expected != manifest["files"].get(relative):
            raise AuditError(f"bundle binding mismatch: {key}")
    identity = {
        "source_revision": revision,
        "scope_sha256": binding.get("scope_sha256"),
        "source_manifest_sha256": binding.get("source_manifest_sha256"),
        "threat_inventory_sha256": binding.get("threat_inventory_sha256"),
    }
    if manifest.get("bundle_id") != "sha256:" + sha256_bytes(canonical_bytes(identity)):
        raise AuditError("bundle_id does not match its binding identity")
    return manifest


@contextmanager
def materialize_bundle(path: Path) -> Iterator[tuple[Path, dict]]:
    if path.is_dir():
        yield path, verify_bundle_dir(path)
        return
    if not path.is_file() or path.suffix.lower() != ".zip":
        raise AuditError("bundle must be a directory or .zip file")
    with tempfile.TemporaryDirectory(prefix="noos-audit-bundle-") as temporary:
        root = Path(temporary)
        try:
            with zipfile.ZipFile(path, "r") as archive:
                names = archive.namelist()
                if len(names) != len(set(names)):
                    raise AuditError("duplicate paths in audit bundle")
                for name in names:
                    safe_member(name)
                archive.extractall(root)
        except (OSError, zipfile.BadZipFile) as exc:
            raise AuditError(f"cannot extract audit bundle: {exc}") from exc
        yield root, verify_bundle_dir(root)


def atomic_append_only_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o644)
    except FileExistsError as exc:
        raise AuditError(f"append-only record already exists: {path.name}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
