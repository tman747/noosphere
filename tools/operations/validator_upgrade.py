#!/usr/bin/env python3
"""Fail-closed validator binary upgrade orchestration with automatic rollback."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"NOOS/VALIDATOR/UPGRADE/V1\x00"
MANIFEST_SCHEMA = "noos/validator-upgrade/v1"
KEYRING_SCHEMA = "noos/validator-upgrade-keyring/v1"
JOURNAL_SCHEMA = "noos/validator-upgrade-journal/v1"
HEX32_LENGTH = 64


class UpgradeError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise UpgradeError(f"path escapes managed root: {relative}")
    return candidate


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UpgradeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise UpgradeError(f"{path} must contain a JSON object")
    return value


def validate_hex32(value: Any, field: str) -> str:
    text = str(value)
    if len(text) != HEX32_LENGTH or any(char not in "0123456789abcdef" for char in text):
        raise UpgradeError(f"{field} must be 32-byte lowercase hex")
    return text


def unsigned_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    value = dict(manifest)
    value["signatures"] = []
    return value


def verify_manifest(manifest: dict[str, Any], keyring: dict[str, Any]) -> None:
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise UpgradeError("unsupported upgrade manifest schema")
    if keyring.get("schema") != KEYRING_SCHEMA:
        raise UpgradeError("unsupported validator upgrade keyring schema")
    validate_hex32(manifest.get("chain_id"), "chain_id")
    validate_hex32(manifest.get("genesis_hash"), "genesis_hash")
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not release_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in release_id):
        raise UpgradeError("release_id contains unsafe characters")
    for field in ("activation_height", "restart_buffer_blocks"):
        if not isinstance(manifest.get(field), int) or manifest[field] < 1:
            raise UpgradeError(f"{field} must be a positive integer")
    throughput = manifest.get("throughput")
    required_throughput = {
        "produce_interval_ms",
        "template_byte_budget",
        "template_max_transactions",
    }
    if not isinstance(throughput, dict) or set(throughput) != required_throughput:
        raise UpgradeError("throughput must bind cadence, byte budget, and transaction cap")
    if not isinstance(throughput["produce_interval_ms"], int) or throughput["produce_interval_ms"] < 1:
        raise UpgradeError("throughput produce_interval_ms must be positive")
    if (
        not isinstance(throughput["template_byte_budget"], int)
        or not 1 <= throughput["template_byte_budget"] <= 983_040
    ):
        raise UpgradeError("throughput template_byte_budget must be 1..=983040")
    if (
        not isinstance(throughput["template_max_transactions"], int)
        or not 1 <= throughput["template_max_transactions"] <= 16_384
    ):
        raise UpgradeError("throughput template_max_transactions must be 1..=16384")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise UpgradeError("artifacts must be a non-empty path-to-sha256 map")
    for relative, digest in artifacts.items():
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise UpgradeError("artifact paths must be relative")
        validate_hex32(digest, f"artifact digest for {relative}")
    binary = manifest.get("binary")
    if not isinstance(binary, dict) or set(binary) != {"artifact", "install_path"}:
        raise UpgradeError("binary must contain exactly artifact and install_path")
    if binary["artifact"] not in artifacts:
        raise UpgradeError("binary artifact is absent from artifacts")
    for command_name in ("drain_command", "stop_command", "start_command", "version_command"):
        command = manifest.get(command_name)
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            raise UpgradeError(f"{command_name} must be a non-empty argument array")
    signatures = manifest.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise UpgradeError("manifest requires exactly one release-operator signature")
    signature = signatures[0]
    if not isinstance(signature, dict) or set(signature) != {"role", "key_id", "signature_ed25519_hex"}:
        raise UpgradeError("manifest signature fields are invalid")
    if signature["role"] != "release-operator":
        raise UpgradeError("manifest signature role must be release-operator")
    keys = keyring.get("keys")
    if not isinstance(keys, dict) or signature["key_id"] not in keys:
        raise UpgradeError("manifest signing key is not pinned")
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(validate_hex32(keys[signature["key_id"]], "public key")))
        signature_bytes = bytes.fromhex(signature["signature_ed25519_hex"])
        if len(signature_bytes) != 64:
            raise ValueError("signature length")
        public.verify(signature_bytes, DOMAIN + canonical_json(unsigned_manifest(manifest)))
    except (ValueError, InvalidSignature) as error:
        raise UpgradeError("manifest signature verification failed") from error


def node_status(rpc: str, token: str, timeout: float = 3.0) -> dict[str, Any]:
    request = Request(f"http://{rpc}/status", headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except (OSError, URLError, json.JSONDecodeError) as error:
        raise UpgradeError(f"validator status unavailable: {error}") from error
    if not isinstance(value, dict):
        raise UpgradeError("validator status response is not an object")
    return value


def require_identity(status: dict[str, Any], manifest: dict[str, Any]) -> int:
    if status.get("chain_id") != manifest["chain_id"] or status.get("genesis_hash") != manifest["genesis_hash"]:
        raise UpgradeError("validator chain identity differs from signed upgrade manifest")
    try:
        return int(status["unsafe_head"]["height"])
    except (KeyError, TypeError, ValueError) as error:
        raise UpgradeError("validator status lacks unsafe head height") from error


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as stream:
        stream.write(canonical_json(value))
        temporary = Path(stream.name)
    os.replace(temporary, path)


def journal_path(state_root: Path, release_id: str) -> Path:
    return state_root / "journals" / f"{release_id}.json"


def update_journal(path: Path, journal: dict[str, Any], phase: str, **details: Any) -> None:
    journal["phase"] = phase
    journal["updated_unix_ms"] = int(time.time() * 1000)
    journal.update(details)
    atomic_json(path, journal)


def expand_command(command: list[str], values: dict[str, str]) -> list[str]:
    expanded: list[str] = []
    for argument in command:
        try:
            expanded.append(argument.format_map(values))
        except KeyError as error:
            raise UpgradeError(f"unknown command placeholder {error.args[0]}") from error
    return expanded


def run_command(name: str, command: list[str], values: dict[str, str]) -> None:
    completed = subprocess.run(expand_command(command, values), capture_output=True, text=True, timeout=120)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise UpgradeError(f"{name} failed: {detail}")


def prepare(manifest: dict[str, Any], source_root: Path, install_root: Path, state_root: Path, rpc: str, token: str) -> dict[str, Any]:
    status = node_status(rpc, token)
    head = require_identity(status, manifest)
    lead = manifest["activation_height"] - head
    if lead < manifest["restart_buffer_blocks"]:
        raise UpgradeError(f"activation height has only {lead} blocks of lead; {manifest['restart_buffer_blocks']} required")
    release_dir = state_root / "releases" / manifest["release_id"]
    if release_dir.exists():
        shutil.rmtree(release_dir)
    release_dir.mkdir(parents=True)
    staged_hashes: dict[str, str] = {}
    for relative, expected in sorted(manifest["artifacts"].items()):
        source = safe_path(source_root, relative)
        if not source.is_file() or sha256_file(source) != expected:
            raise UpgradeError(f"artifact missing or hash mismatch: {relative}")
        destination = safe_path(release_dir, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        actual = sha256_file(destination)
        if actual != expected:
            raise UpgradeError(f"staged artifact hash mismatch: {relative}")
        staged_hashes[relative] = actual
    install_path = safe_path(install_root, manifest["binary"]["install_path"])
    if not install_path.is_file():
        raise UpgradeError("installed validator binary is missing; rollback cannot be guaranteed")
    journal = {
        "schema": JOURNAL_SCHEMA,
        "release_id": manifest["release_id"],
        "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
        "chain_id": manifest["chain_id"],
        "genesis_hash": manifest["genesis_hash"],
        "activation_height": manifest["activation_height"],
        "throughput": manifest["throughput"],
        "prepared_at_height": head,
        "release_dir": str(release_dir.resolve()),
        "install_path": str(install_path),
        "staged_hashes": staged_hashes,
    }
    path = journal_path(state_root, manifest["release_id"])
    update_journal(path, journal, "PREPARED")
    return journal


def load_prepared(manifest: dict[str, Any], state_root: Path) -> tuple[Path, dict[str, Any]]:
    path = journal_path(state_root, manifest["release_id"])
    journal = read_json(path)
    if journal.get("schema") != JOURNAL_SCHEMA or journal.get("phase") not in {"PREPARED", "ROLLED_BACK"}:
        raise UpgradeError("upgrade is not in a preparable activation state")
    if journal.get("manifest_sha256") != hashlib.sha256(canonical_json(manifest)).hexdigest():
        raise UpgradeError("prepared journal binds different manifest bytes")
    for relative, expected in manifest["artifacts"].items():
        staged = safe_path(Path(journal["release_dir"]), relative)
        if not staged.is_file() or sha256_file(staged) != expected:
            raise UpgradeError(f"prepared artifact changed: {relative}")
    return path, journal


def make_snapshot(data_dir: Path, state_root: Path, release_id: str) -> Path:
    if not data_dir.is_dir():
        raise UpgradeError(f"validator data directory is missing: {data_dir}")
    destination = state_root / "snapshots" / release_id
    destination.mkdir(parents=True, exist_ok=True)
    archive_base = destination / f"validator-{int(time.time() * 1000)}"
    archive = Path(shutil.make_archive(str(archive_base), "zip", root_dir=data_dir))
    if not archive.is_file() or archive.stat().st_size == 0:
        raise UpgradeError("validator snapshot was not created")
    return archive


def wait_healthy(rpc: str, token: str, manifest: dict[str, Any], timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status = node_status(rpc, token)
            require_identity(status, manifest)
            return status
        except UpgradeError as error:
            last_error = error
            time.sleep(0.5)
    raise UpgradeError(f"upgraded validator did not become healthy: {last_error}")


def restore_backup(manifest: dict[str, Any], journal: dict[str, Any], values: dict[str, str], rpc: str, token: str, timeout: float) -> None:
    install_path = Path(journal["install_path"])
    backup = Path(journal["backup_path"]) if journal.get("backup_path") else None
    if backup and backup.is_file():
        install_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, install_path)
    run_command("rollback start command", manifest["start_command"], values)
    wait_healthy(rpc, token, manifest, timeout)


def activate(manifest: dict[str, Any], install_root: Path, data_dir: Path, state_root: Path, rpc: str, token: str, health_timeout: float) -> dict[str, Any]:
    path, journal = load_prepared(manifest, state_root)
    status = node_status(rpc, token)
    head = require_identity(status, manifest)
    lead = manifest["activation_height"] - head
    if lead < manifest["restart_buffer_blocks"]:
        raise UpgradeError(f"refusing restart with only {lead} blocks before activation")
    release_dir = Path(journal["release_dir"])
    install_path = safe_path(install_root, manifest["binary"]["install_path"])
    staged_binary = safe_path(release_dir, manifest["binary"]["artifact"])
    backup = state_root / "backups" / manifest["release_id"] / install_path.name
    values = {
        "install_path": str(install_path),
        "release_dir": str(release_dir),
        "data_dir": str(data_dir.resolve()),
        "activation_height": str(manifest["activation_height"]),
        "produce_interval_ms": str(manifest["throughput"]["produce_interval_ms"]),
        "template_byte_budget": str(manifest["throughput"]["template_byte_budget"]),
        "template_max_transactions": str(
            manifest["throughput"]["template_max_transactions"]
        ),
    }
    stopped = False
    try:
        run_command("drain command", manifest["drain_command"], values)
        update_journal(path, journal, "DRAINED", drained_at_height=head)
        run_command("stop command", manifest["stop_command"], values)
        stopped = True
        snapshot = make_snapshot(data_dir, state_root, manifest["release_id"])
        update_journal(path, journal, "SNAPSHOTTED", snapshot_path=str(snapshot.resolve()))
        backup.parent.mkdir(parents=True, exist_ok=True)
        if install_path.is_file():
            shutil.copy2(install_path, backup)
            journal["backup_path"] = str(backup.resolve())
        else:
            journal["backup_path"] = None
        install_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = install_path.with_suffix(install_path.suffix + ".upgrade")
        shutil.copy2(staged_binary, temporary)
        os.replace(temporary, install_path)
        expected = manifest["artifacts"][manifest["binary"]["artifact"]]
        if sha256_file(install_path) != expected:
            raise UpgradeError("installed validator binary hash mismatch")
        update_journal(path, journal, "INSTALLED", installed_sha256=expected)
        run_command("start command", manifest["start_command"], values)
        stopped = False
        wait_healthy(rpc, token, manifest, health_timeout)
        version = subprocess.run(expand_command(manifest["version_command"], values), capture_output=True, text=True, timeout=30)
        if version.returncode != 0 or manifest["release_version"] not in (version.stdout + version.stderr):
            raise UpgradeError("installed validator version does not match signed release version")
        update_journal(path, journal, "ACTIVE", activated_at_height=head)
        return journal
    except Exception as error:
        update_journal(path, journal, "ROLLBACK_REQUIRED", failure=str(error))
        if stopped or journal.get("phase") in {"INSTALLED", "ROLLBACK_REQUIRED"}:
            try:
                restore_backup(manifest, journal, values, rpc, token, health_timeout)
                update_journal(path, journal, "ROLLED_BACK", rollback_reason=str(error))
            except Exception as rollback_error:
                update_journal(path, journal, "ROLLBACK_FAILED", rollback_failure=str(rollback_error))
                raise UpgradeError(f"upgrade failed ({error}); rollback failed ({rollback_error})") from rollback_error
        raise UpgradeError(f"upgrade failed and was rolled back: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage and activate a signed validator upgrade")
    parser.add_argument("command", choices=("prepare", "activate"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--health-timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    try:
        manifest = read_json(args.manifest)
        verify_manifest(manifest, read_json(args.keyring))
        if args.command == "prepare":
            journal = prepare(manifest, args.source_root, args.install_root, args.state_root, args.rpc, args.token)
        else:
            if args.data_dir is None:
                raise UpgradeError("--data-dir is required for activation")
            journal = activate(manifest, args.install_root, args.data_dir, args.state_root, args.rpc, args.token, args.health_timeout)
    except (UpgradeError, OSError, subprocess.SubprocessError) as error:
        print(f"RESULT validator_upgrade=FAIL reason={error}", file=sys.stderr)
        return 1
    print(f"RESULT validator_upgrade=PASS release={manifest['release_id']} phase={journal['phase']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
