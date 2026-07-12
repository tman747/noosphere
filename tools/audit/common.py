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
    if "\\" in name or "\x00" in name or "//" in name:
        raise AuditError(f"unsafe package path: {name}")
    candidate = PurePosixPath(name)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or ".." in candidate.parts
        or "." in candidate.parts
        or "" in candidate.parts
        or any(part.endswith(":") for part in candidate.parts)
    ):
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


def git(*args: str, binary: bool = False, repo: Path = ROOT) -> bytes | str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def resolve_revision(revision: str, repo: Path = ROOT) -> str:
    resolved = str(git("rev-parse", f"{revision}^{{commit}}", repo=repo))
    if not HEX40.fullmatch(resolved):
        raise AuditError("git did not resolve a full commit revision")
    return resolved


def git_paths(revision: str, repo: Path = ROOT) -> list[str]:
    raw = str(git("ls-tree", "-r", "--name-only", revision, repo=repo))
    return [line for line in raw.splitlines() if line]


def git_blob(revision: str, path: str, repo: Path = ROOT) -> bytes:
    safe_member(path)
    return bytes(git("show", f"{revision}:{path}", binary=True, repo=repo))


def git_tree(revision: str, repo: Path = ROOT) -> str:
    tree = str(git("rev-parse", f"{revision}^{{tree}}", repo=repo))
    if not HEX40.fullmatch(tree):
        raise AuditError("git did not resolve a full tree id")
    return tree


def git_entry(revision: str, path: str, repo: Path = ROOT) -> tuple[str, str, str]:
    safe_member(path)
    raw = str(git("ls-tree", revision, "--", path, repo=repo))
    lines = raw.splitlines()
    if len(lines) != 1:
        raise AuditError(f"source manifest path is missing or ambiguous in Git: {path}")
    try:
        metadata, listed_path = lines[0].split("\t", 1)
        mode, object_type, object_id = metadata.split(" ", 2)
    except ValueError as exc:
        raise AuditError(f"cannot parse Git tree entry for {path}") from exc
    if listed_path != path:
        raise AuditError(f"Git tree returned a different path for {path}")
    return mode, object_type, object_id


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
    if not isinstance(manifest.get("source_tree"), str) or not HEX40.fullmatch(manifest["source_tree"]):
        raise AuditError("bundle source tree is not an exact Git tree")
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


def verify_bundle_against_git(root: Path, manifest: dict, repo: Path, revision: str) -> str:
    """Bind a self-consistent bundle to an independently supplied Git object database."""
    if not repo.is_dir():
        raise AuditError("trusted repository/worktree does not exist")
    resolved = resolve_revision(revision, repo)
    if manifest.get("source_revision") != resolved:
        raise AuditError(
            f"bundle revision mismatch: bundle={manifest.get('source_revision')} trusted={resolved}"
        )
    trusted_tree = git_tree(resolved, repo)
    if manifest.get("source_tree") != trusted_tree:
        raise AuditError("bundle source tree does not match the trusted Git revision")

    source_manifest = read_json(root / "source-manifest.json", "source manifest")
    if (
        source_manifest.get("schema_version") != 2
        or source_manifest.get("manifest_kind") != "noosphere-audit-source-manifest"
        or source_manifest.get("source_revision") != resolved
        or source_manifest.get("source_tree") != trusted_tree
        or source_manifest.get("hash_algorithm") != "sha256"
    ):
        raise AuditError("source manifest is not bound to the trusted revision/tree")
    entries = source_manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise AuditError("source manifest entries must be a non-empty list")

    seen_paths: set[str] = set()
    seen_archive_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path", "archive_path", "git_mode", "git_type", "git_blob", "sha256", "bytes", "role", "workstreams"
        }:
            raise AuditError("source manifest entry has missing or unknown fields")
        path = entry["path"]
        archive_path = entry["archive_path"]
        if not isinstance(path, str) or not isinstance(archive_path, str):
            raise AuditError("source manifest paths must be strings")
        safe_member(path)
        safe_member(archive_path)
        if path in seen_paths or archive_path in seen_archive_paths:
            raise AuditError("source manifest contains duplicate paths")
        seen_paths.add(path)
        seen_archive_paths.add(archive_path)
        if not isinstance(entry["bytes"], int) or isinstance(entry["bytes"], bool) or entry["bytes"] < 0:
            raise AuditError(f"invalid source byte count: {path}")
        if entry["role"] not in {"audited_source", "normative_or_tooling_reference"}:
            raise AuditError(f"invalid source role/workstreams: {path}")
        if (
            not isinstance(entry["workstreams"], list)
            or any(not isinstance(item, str) or not item for item in entry["workstreams"])
            or len(entry["workstreams"]) != len(set(entry["workstreams"]))
        ):
            raise AuditError(f"invalid source role/workstreams: {path}")
        expected_prefix = "source/" if entry["role"] == "audited_source" else "reference/"
        if not archive_path.startswith(expected_prefix):
            raise AuditError(f"source archive role/path mismatch: {path}")
        mode, object_type, object_id = git_entry(resolved, path, repo)
        if object_type != "blob":
            raise AuditError(f"source path is not a Git blob: {path}")
        if (entry["git_mode"], entry["git_type"], entry["git_blob"]) != (mode, object_type, object_id):
            raise AuditError(f"source Git identity/type mismatch: {path}")
        data = git_blob(resolved, path, repo)
        if entry["bytes"] != len(data) or entry["sha256"] != sha256_bytes(data):
            raise AuditError(f"source size/hash differs from trusted Git: {path}")
        packaged = root / Path(*PurePosixPath(archive_path).parts)
        if not packaged.is_file() or packaged.read_bytes() != data:
            raise AuditError(f"packaged source bytes differ from trusted Git: {path}")

    packaged_sources = {
        path.relative_to(root).as_posix()
        for prefix in (root / "source", root / "reference")
        if prefix.exists()
        for path in prefix.rglob("*")
        if path.is_file()
    }
    if packaged_sources != seen_archive_paths:
        raise AuditError(
            f"packaged source set mismatch missing={sorted(seen_archive_paths - packaged_sources)} "
            f"extra={sorted(packaged_sources - seen_archive_paths)}"
        )
    return resolved


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
                infos = archive.infolist()
                names = [info.filename for info in infos]
                if len(names) != len(set(names)):
                    raise AuditError("duplicate paths in audit bundle")
                for info in infos:
                    safe_member(info.filename.rstrip("/") if info.is_dir() else info.filename)
                    unix_type = (info.external_attr >> 16) & 0o170000
                    if unix_type not in {0, 0o040000 if info.is_dir() else 0o100000}:
                        raise AuditError(f"non-regular path in audit bundle: {info.filename}")
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
