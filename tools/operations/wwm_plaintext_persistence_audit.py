#!/usr/bin/env python3
"""Signed, bounded prompt/output persistence audit for the public WWM gateway.

The scanner never emits canary plaintext. It scans raw files and bounded archive
members, then signs a report that binds the exact release, deployment, lifecycle
phase, target categories, canary digests, and every inspected byte count. A
matrix seals only after success, cancellation, timeout, crash, and reboot scans
all pass for database, cache, logs, crash artifacts, and telemetry.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCAN_SCHEMA = "noos/wwm-inference-plaintext-scan/v1"
MATRIX_SCHEMA = "noos/wwm-inference-plaintext-matrix/v1"
MANIFEST_SCHEMA = "noos/wwm-inference-plaintext-targets/v1"
SCAN_DOMAIN = b"NOOS/SIG/WWM-INFERENCE-PLAINTEXT-SCAN/V1\0"
MATRIX_DOMAIN = b"NOOS/SIG/WWM-INFERENCE-PLAINTEXT-MATRIX/V1\0"
SCAN_ID_DOMAIN = b"NOOS/WWM-INFERENCE-PLAINTEXT-SCAN-ID/V1\0"
MATRIX_ID_DOMAIN = b"NOOS/WWM-INFERENCE-PLAINTEXT-MATRIX-ID/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PHASES = frozenset({"success", "cancellation", "timeout", "crash", "reboot"})
CATEGORIES = frozenset({"database", "cache", "logs", "crash_artifacts", "telemetry"})
MAX_CANARIES = 64
MAX_CANARY_BYTES = 512
MIN_CANARY_BYTES = 8
MAX_FILES = 100_000
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_EXPANDED_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class AuditError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(canonical_json(value) + b"\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def load_json(path: Path, maximum: int = 8 * 1024 * 1024) -> dict[str, Any]:
    try:
        if path.stat().st_size > maximum:
            raise AuditError(f"JSON input exceeds {maximum} bytes")
        value = json.loads(path.read_text(encoding="utf-8"))
    except AuditError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot load JSON input: {error}") from error
    if not isinstance(value, dict):
        raise AuditError("JSON input must be an object")
    return value


def load_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise AuditError(f"cannot read signing seed: {error}") from error
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeError, ValueError) as error:
            raise AuditError("signing seed must be 32 raw bytes or lowercase hex64") from error
    elif len(raw) == 32:
        seed = raw
    else:
        raise AuditError("signing seed must be 32 raw bytes or lowercase hex64")
    if seed == bytes(32):
        raise AuditError("all-zero signing seed is forbidden")
    return seed


def _decode_public(value: Any, key_id: Any) -> bytes:
    if not isinstance(value, str) or not isinstance(key_id, str) or not HEX64.fullmatch(key_id):
        raise AuditError("signer public key or key id is malformed")
    try:
        public = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise AuditError("signer public key is not canonical base64") from error
    if len(public) != 32 or sha256(public) != key_id:
        raise AuditError("signer key id does not bind its Ed25519 public key")
    return public


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise AuditError("signature is missing")
    try:
        signature = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise AuditError("signature is not canonical base64") from error
    if len(signature) != 64:
        raise AuditError("signature must contain 64 bytes")
    return signature


def sign_body(schema: str, domain: bytes, body: dict[str, Any], seed: bytes) -> dict[str, Any]:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes_raw()
    signature = private.sign(domain + canonical_json(body))
    return {
        "schema": schema,
        "body": body,
        "signer": {
            "key_id": sha256(public),
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_envelope(value: Any, schema: str, domain: bytes) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "body", "signer"} or value.get("schema") != schema:
        raise AuditError("signed audit envelope is malformed")
    body = value["body"]
    signer = value["signer"]
    if not isinstance(body, dict) or not isinstance(signer, dict) or set(signer) != {
        "key_id",
        "public_key_base64",
        "signature_base64",
    }:
        raise AuditError("signed audit body or signer is malformed")
    public = _decode_public(signer["public_key_base64"], signer["key_id"])
    signature = _decode_signature(signer["signature_base64"])
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, domain + canonical_json(body))
    except InvalidSignature as error:
        raise AuditError("audit signature is invalid") from error
    return body


def load_canaries(path: Path) -> list[bytes]:
    value = load_json(path, maximum=MAX_CANARIES * (MAX_CANARY_BYTES + 64))
    if set(value) != {"schema", "canaries"} or value.get("schema") != "noos/wwm-inference-plaintext-canaries/v1":
        raise AuditError("canary file has the wrong closed schema")
    rows = value["canaries"]
    if not isinstance(rows, list) or not rows or len(rows) > MAX_CANARIES:
        raise AuditError("canary count is outside the bound")
    canaries: list[bytes] = []
    for row in rows:
        if not isinstance(row, str):
            raise AuditError("canaries must be text")
        try:
            encoded = row.encode("ascii")
        except UnicodeEncodeError as error:
            raise AuditError("canaries must be ASCII for exact and case-folded raw scanning") from error
        if not MIN_CANARY_BYTES <= len(encoded) <= MAX_CANARY_BYTES:
            raise AuditError("canary byte length is outside the bound")
        canaries.append(encoded)
    if len(set(canaries)) != len(canaries):
        raise AuditError("canaries must be distinct")
    return canaries


def validate_manifest(value: Any) -> dict[str, Any]:
    fields = {"schema", "source_revision", "deployment_sha256", "phase", "production", "promotion_effect", "targets"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != MANIFEST_SCHEMA:
        raise AuditError("plaintext target manifest has the wrong closed schema")
    if not HEX40.fullmatch(str(value["source_revision"])) or not HEX64.fullmatch(str(value["deployment_sha256"])):
        raise AuditError("target manifest release identity is malformed")
    if value["phase"] not in PHASES or value["production"] is not False or value["promotion_effect"] != "NONE":
        raise AuditError("target manifest phase or nonproduction boundary is invalid")
    targets = value["targets"]
    if not isinstance(targets, list) or len(targets) != len(CATEGORIES):
        raise AuditError("target manifest must declare every exact persistence category once")
    observed: set[str] = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"category", "path"}:
            raise AuditError("target entry is malformed")
        category = target["category"]
        path = target["path"]
        if category not in CATEGORIES or category in observed:
            raise AuditError("target categories are duplicated or unknown")
        if not isinstance(path, str) or not path or "\x00" in path:
            raise AuditError("target path is invalid")
        observed.add(category)
    if observed != CATEGORIES:
        raise AuditError("target manifest does not cover every persistence category")
    return value


def _portable_member(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AuditError("archive contains an unsafe member path")
    return value


def _scan_stream(stream: BinaryIO, canaries: list[bytes], maximum: int) -> tuple[int, set[int]]:
    longest = max(len(canary) for canary in canaries)
    carry = b""
    total = 0
    found: set[int] = set()
    while chunk := stream.read(CHUNK_BYTES):
        total += len(chunk)
        if total > maximum:
            raise AuditError("scanned stream exceeds its declared byte bound")
        window = carry + chunk
        folded = window.lower()
        for index, canary in enumerate(canaries):
            if canary in window or canary.lower() in folded:
                found.add(index)
        carry = window[-(longest - 1) :] if longest > 1 else b""
    return total, found


def _scan_file(path: Path, canaries: list[bytes]) -> tuple[int, list[dict[str, Any]], int, int]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AuditError("target file exceeds the per-file scan bound")
    findings: list[dict[str, Any]] = []
    with path.open("rb") as source:
        raw_bytes, found = _scan_stream(source, canaries, MAX_FILE_BYTES)
    for index in sorted(found):
        findings.append({"canary_sha256": sha256(canaries[index]), "location": "raw"})
    expanded_bytes = 0
    member_count = 0
    suffix = path.name.lower()
    if suffix.endswith(".zip"):
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise AuditError("zip member count exceeds the bound")
                for member in members:
                    if member.is_dir():
                        continue
                    name = _portable_member(member.filename)
                    if member.file_size > MAX_FILE_BYTES:
                        raise AuditError("zip member exceeds the per-member bound")
                    with archive.open(member, "r") as source:
                        count, member_found = _scan_stream(source, canaries, MAX_FILE_BYTES)
                    expanded_bytes += count
                    member_count += 1
                    if expanded_bytes > MAX_EXPANDED_ARCHIVE_BYTES:
                        raise AuditError("expanded archive bytes exceed the bound")
                    for index in sorted(member_found):
                        findings.append({"canary_sha256": sha256(canaries[index]), "location": f"zip:{name}"})
        except (OSError, zipfile.BadZipFile, RuntimeError) as error:
            raise AuditError(f"cannot inspect zip target: {error}") from error
    elif suffix.endswith(".gz"):
        try:
            with gzip.open(path, "rb") as source:
                expanded_bytes, member_found = _scan_stream(source, canaries, MAX_EXPANDED_ARCHIVE_BYTES)
            member_count = 1
            for index in sorted(member_found):
                findings.append({"canary_sha256": sha256(canaries[index]), "location": "gzip:payload"})
        except (OSError, EOFError) as error:
            raise AuditError(f"cannot inspect gzip target: {error}") from error
    return raw_bytes, findings, expanded_bytes, member_count


def _target_files(path: Path) -> list[Path]:
    if not path.exists():
        raise AuditError("declared persistence target does not exist")
    if path.is_symlink():
        raise AuditError("persistence target may not be a symlink")
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise AuditError("persistence target is neither a file nor directory")
    files: list[Path] = []
    for candidate in sorted(path.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.is_symlink():
            raise AuditError("persistence target tree contains a symlink")
        if candidate.is_file():
            files.append(candidate)
            if len(files) > MAX_FILES:
                raise AuditError("persistence target exceeds the file-count bound")
    return files


def perform_scan(manifest: dict[str, Any], canaries: list[bytes]) -> dict[str, Any]:
    manifest = validate_manifest(manifest)
    started = utc_now()
    target_results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    total_files = 0
    total_raw_bytes = 0
    total_expanded_bytes = 0
    total_archive_members = 0
    for target in sorted(manifest["targets"], key=lambda row: row["category"]):
        declared_root = Path(target["path"])
        if declared_root.is_symlink():
            raise AuditError("persistence target may not be a symlink")
        root = declared_root.resolve(strict=True)
        files = _target_files(root)
        category_raw = 0
        category_expanded = 0
        category_members = 0
        for path in files:
            raw_bytes, file_findings, expanded_bytes, member_count = _scan_file(path, canaries)
            category_raw += raw_bytes
            category_expanded += expanded_bytes
            category_members += member_count
            total_files += 1
            total_raw_bytes += raw_bytes
            total_expanded_bytes += expanded_bytes
            total_archive_members += member_count
            if total_files > MAX_FILES or total_raw_bytes + total_expanded_bytes > MAX_TOTAL_BYTES:
                raise AuditError("persistence scan exceeds its global bounds")
            relative = path.relative_to(root).as_posix() if root.is_dir() else path.name
            for finding in file_findings:
                findings.append({"category": target["category"], "path": relative, **finding})
        target_results.append(
            {
                "category": target["category"],
                "root_sha256": sha256(str(root).encode("utf-8")),
                "file_count": len(files),
                "raw_bytes": category_raw,
                "expanded_archive_bytes": category_expanded,
                "archive_member_count": category_members,
            }
        )
    body: dict[str, Any] = {
        "scan_id": "",
        "source_revision": manifest["source_revision"],
        "deployment_sha256": manifest["deployment_sha256"],
        "phase": manifest["phase"],
        "started_at_utc": started,
        "completed_at_utc": utc_now(),
        "canary_sha256": sorted(sha256(canary) for canary in canaries),
        "targets": target_results,
        "total_file_count": total_files,
        "total_raw_bytes": total_raw_bytes,
        "total_expanded_archive_bytes": total_expanded_bytes,
        "total_archive_member_count": total_archive_members,
        "findings": findings,
        "verdict": "PASS" if not findings else "FAIL",
        "production": False,
        "promotion_effect": "NONE",
    }
    body["scan_id"] = sha256(SCAN_ID_DOMAIN + canonical_json({**body, "scan_id": ""}))
    return body


def validate_scan_body(body: Any) -> dict[str, Any]:
    fields = {
        "scan_id", "source_revision", "deployment_sha256", "phase", "started_at_utc", "completed_at_utc",
        "canary_sha256", "targets", "total_file_count", "total_raw_bytes", "total_expanded_archive_bytes",
        "total_archive_member_count", "findings", "verdict", "production", "promotion_effect",
    }
    if not isinstance(body, dict) or set(body) != fields:
        raise AuditError("plaintext scan body has the wrong closed schema")
    expected_id = sha256(SCAN_ID_DOMAIN + canonical_json({**body, "scan_id": ""}))
    if body["scan_id"] != expected_id or not HEX64.fullmatch(str(body["scan_id"])):
        raise AuditError("plaintext scan id mismatch")
    if not HEX40.fullmatch(str(body["source_revision"])) or not HEX64.fullmatch(str(body["deployment_sha256"])):
        raise AuditError("plaintext scan release identity is malformed")
    if body["phase"] not in PHASES or body["production"] is not False or body["promotion_effect"] != "NONE":
        raise AuditError("plaintext scan phase or nonproduction boundary is invalid")
    digests = body["canary_sha256"]
    if not isinstance(digests, list) or not digests or digests != sorted(set(digests)) or any(not HEX64.fullmatch(str(item)) for item in digests):
        raise AuditError("plaintext scan canary digest set is malformed")
    targets = body["targets"]
    if not isinstance(targets, list) or {row.get("category") for row in targets if isinstance(row, dict)} != CATEGORIES:
        raise AuditError("plaintext scan target category coverage is incomplete")
    target_fields = {"category", "root_sha256", "file_count", "raw_bytes", "expanded_archive_bytes", "archive_member_count"}
    target_numeric_fields = ("file_count", "raw_bytes", "expanded_archive_bytes", "archive_member_count")
    if any(
        not isinstance(row, dict)
        or set(row) != target_fields
        or not HEX64.fullmatch(str(row["root_sha256"]))
        or any(
            not isinstance(row[field], int) or isinstance(row[field], bool) or row[field] < 0
            for field in target_numeric_fields
        )
        for row in targets
    ):
        raise AuditError("plaintext scan target evidence is malformed")
    numeric_fields = ("total_file_count", "total_raw_bytes", "total_expanded_archive_bytes", "total_archive_member_count")
    if any(not isinstance(body[field], int) or isinstance(body[field], bool) or body[field] < 0 for field in numeric_fields):
        raise AuditError("plaintext scan totals are malformed")
    total_pairs = (
        ("total_file_count", "file_count"),
        ("total_raw_bytes", "raw_bytes"),
        ("total_expanded_archive_bytes", "expanded_archive_bytes"),
        ("total_archive_member_count", "archive_member_count"),
    )
    if any(body[total] != sum(row[component] for row in targets) for total, component in total_pairs):
        raise AuditError("plaintext scan totals do not equal target evidence")
    findings = body["findings"]
    if not isinstance(findings, list) or body["verdict"] not in {"PASS", "FAIL"} or (body["verdict"] == "PASS") != (not findings):
        raise AuditError("plaintext scan verdict does not match findings")
    if findings:
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != {"category", "path", "canary_sha256", "location"}:
                raise AuditError("plaintext scan finding is malformed")
    return body


def validate_scan_envelope(value: Any) -> dict[str, Any]:
    return validate_scan_body(verify_envelope(value, SCAN_SCHEMA, SCAN_DOMAIN))


def seal_matrix(scans: list[dict[str, Any]], seed: bytes) -> dict[str, Any]:
    bodies = [validate_scan_envelope(scan) for scan in scans]
    if {body["phase"] for body in bodies} != PHASES or len(bodies) != len(PHASES):
        raise AuditError("plaintext matrix requires exactly one signed scan for every lifecycle phase")
    identities = {(body["source_revision"], body["deployment_sha256"]) for body in bodies}
    if len(identities) != 1:
        raise AuditError("plaintext matrix scans do not bind one exact release")
    if any(body["verdict"] != "PASS" for body in bodies):
        raise AuditError("plaintext matrix includes a failing persistence scan")
    source_revision, deployment_sha256 = identities.pop()
    ordered = sorted(scans, key=lambda scan: scan["body"]["phase"])
    body: dict[str, Any] = {
        "matrix_id": "",
        "source_revision": source_revision,
        "deployment_sha256": deployment_sha256,
        "phases": sorted(PHASES),
        "scan_ids": [scan["body"]["scan_id"] for scan in ordered],
        "scan_sha256": [sha256(canonical_json(scan)) for scan in ordered],
        "scans": ordered,
        "verdict": "PASS",
        "production": False,
        "promotion_effect": "NONE",
    }
    body["matrix_id"] = sha256(MATRIX_ID_DOMAIN + canonical_json({**body, "matrix_id": ""}))
    return sign_body(MATRIX_SCHEMA, MATRIX_DOMAIN, body, seed)


def validate_matrix(value: Any) -> dict[str, Any]:
    body = verify_envelope(value, MATRIX_SCHEMA, MATRIX_DOMAIN)
    fields = {"matrix_id", "source_revision", "deployment_sha256", "phases", "scan_ids", "scan_sha256", "scans", "verdict", "production", "promotion_effect"}
    if set(body) != fields:
        raise AuditError("plaintext matrix body has the wrong closed schema")
    expected_id = sha256(MATRIX_ID_DOMAIN + canonical_json({**body, "matrix_id": ""}))
    if body["matrix_id"] != expected_id or body["phases"] != sorted(PHASES) or body["verdict"] != "PASS":
        raise AuditError("plaintext matrix identity, phases, or verdict is invalid")
    if body["production"] is not False or body["promotion_effect"] != "NONE":
        raise AuditError("plaintext matrix violates the nonproduction boundary")
    scans = body["scans"]
    if not isinstance(scans, list) or len(scans) != len(PHASES):
        raise AuditError("plaintext matrix signed scan set is incomplete")
    rebuilt = seal_matrix(scans, bytes.fromhex("01" * 32))["body"]
    for field in fields - {"matrix_id"}:
        if body[field] != rebuilt[field]:
            raise AuditError("plaintext matrix content is inconsistent with embedded scans")
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan and seal WWM prompt/output plaintext persistence evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--manifest", type=Path, required=True)
    scan_parser.add_argument("--canaries", type=Path, required=True)
    scan_parser.add_argument("--signing-seed", type=Path, required=True)
    scan_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--input", type=Path, required=True)
    matrix_parser = subparsers.add_parser("seal-matrix")
    matrix_parser.add_argument("--scan", action="append", type=Path, required=True)
    matrix_parser.add_argument("--signing-seed", type=Path, required=True)
    matrix_parser.add_argument("--output", type=Path, required=True)
    matrix_verify_parser = subparsers.add_parser("verify-matrix")
    matrix_verify_parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            manifest = validate_manifest(load_json(args.manifest))
            canaries = load_canaries(args.canaries)
            report = sign_body(SCAN_SCHEMA, SCAN_DOMAIN, perform_scan(manifest, canaries), load_seed(args.signing_seed))
            validate_scan_envelope(report)
            atomic_write(args.output, report)
            result = report["body"]
        elif args.command == "verify":
            result = validate_scan_envelope(load_json(args.input))
        elif args.command == "seal-matrix":
            report = seal_matrix([load_json(path) for path in args.scan], load_seed(args.signing_seed))
            validate_matrix(report)
            atomic_write(args.output, report)
            result = report["body"]
        else:
            result = validate_matrix(load_json(args.input))
    except AuditError as error:
        print(f"plaintext persistence audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"id": result.get("scan_id", result.get("matrix_id")), "verdict": result["verdict"]}, sort_keys=True, separators=(",", ":")))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
