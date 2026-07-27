#!/usr/bin/env python3
"""Authorize, execute, and verify fail-closed E-WWM-23 resilience drills."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PLAN_SCHEMA = "noos/e-wwm-23-resilience-plan/v1"
RESULT_SCHEMA = "noos/e-wwm-23-resilience-result/v1"
OBSERVATION_SCHEMA = "noos/e-wwm-23-resilience-observation/v1"
AUTH_DOMAIN = b"NOOS/SIG/E-WWM-23-RESILIENCE-AUTHORIZATION/V1\0"
EVIDENCE_DOMAIN = b"NOOS/SIG/E-WWM-23-RESILIENCE-EVIDENCE/V1\0"
REQUIRED_DRILLS = (
    "queue_saturation",
    "key_rotation",
    "backup",
    "restore",
    "retention_deletion",
    "telemetry_outage",
    "incident_recovery",
)
NON_PROMOTING_POLICY = {
    "availability_certificate_effect": False,
    "production_custody": False,
    "promotion_authorized": False,
    "rewards": False,
    "schedulability_effect": False,
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
PLAN_KEYS = {
    "plan_id",
    "source_revision",
    "deployment_sha256",
    "evidence_scope",
    "authorized_at_utc",
    "expires_at_utc",
    "consent_version",
    "authorization_signer_key_id",
    "evidence_signer_key_id",
    "non_promoting_policy",
    "drills",
}
DRILL_KEYS = {"drill_id", "adapter_path", "adapter_sha256", "argv", "timeout_seconds"}
OBSERVATION_KEYS = {
    "schema",
    "drill_id",
    "source_revision",
    "deployment_sha256",
    "started_at_utc",
    "ended_at_utc",
    "verdict",
    "before_data_root",
    "after_data_root",
    "automatic_recovery",
    "manual_repair",
    "non_promoting_policy",
    "metrics",
}
ENVELOPE_KEYS = {"schema", "body", "authorization"}
RESULT_KEYS = {"schema", "body", "attestation"}
SIGNATURE_KEYS = {"suite", "domain", "key_id", "public_key_base64", "signature_base64"}


class ResilienceError(RuntimeError):
    """A plan, drill observation, or signed result is unsafe or malformed."""


@dataclass(frozen=True)
class RunnerResult:
    returncode: int
    stdout: bytes
    stderr: bytes


Runner = Callable[[Sequence[str], int], RunnerResult]


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        if path.stat().st_size > maximum_bytes:
            raise ResilienceError(f"{path} exceeds the bounded document size")
        value = json.loads(path.read_text(encoding="utf-8"))
    except ResilienceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ResilienceError(f"cannot load JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise ResilienceError(f"{path} must contain a JSON object")
    return value


def atomic_create(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise ResilienceError(f"refusing to overwrite evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ResilienceError(f"refusing to overwrite evidence: {path}") from error
        except OSError as error:
            raise ResilienceError(f"cannot publish insert-once evidence {path}: {error}") from error
        temporary.unlink()
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise ResilienceError(f"{label} must be canonical UTC with second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ResilienceError(f"{label} is not a valid UTC timestamp") from error


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_seed(path: Path) -> bytes:
    try:
        encoded = path.read_bytes()
        raw = encoded if len(encoded) == 32 else base64.b64decode(encoded.strip(), validate=True)
    except (OSError, ValueError, TypeError) as error:
        raise ResilienceError("Ed25519 seed must be 32 raw bytes or canonical base64") from error
    if len(raw) != 32:
        raise ResilienceError("Ed25519 seed must contain exactly 32 bytes")
    return raw


def public_identity(private: Ed25519PrivateKey) -> tuple[str, str]:
    public = private.public_key().public_bytes_raw()
    return base64.b64encode(public).decode("ascii"), sha256_bytes(public)


def decode_public(value: Any) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise ResilienceError("public key is not canonical base64") from error
    if len(decoded) != 32:
        raise ResilienceError("public key must contain exactly 32 bytes")
    return decoded


def decode_signature(value: Any) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise ResilienceError("signature is not canonical base64") from error
    if len(decoded) != 64:
        raise ResilienceError("signature must contain exactly 64 bytes")
    return decoded


def plan_id(body: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json({key: value for key, value in body.items() if key != "plan_id"}))


def validate_plan_body(body: Any, *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != PLAN_KEYS:
        raise ResilienceError("resilience plan body fields do not match the closed contract")
    if body["plan_id"] != plan_id(body):
        raise ResilienceError("resilience plan ID does not bind its complete body")
    if HEX40.fullmatch(str(body["source_revision"])) is None or HEX64.fullmatch(str(body["deployment_sha256"])) is None:
        raise ResilienceError("resilience plan release identity is invalid")
    if body["evidence_scope"] != "OWNER_CONTROLLED_NONPRODUCTION_DEVNET":
        raise ResilienceError("resilience drills are restricted to the owner-controlled nonproduction devnet")
    if body["non_promoting_policy"] != NON_PROMOTING_POLICY:
        raise ResilienceError("resilience plan weakens the non-promoting policy")
    if TOKEN.fullmatch(str(body["consent_version"])) is None:
        raise ResilienceError("resilience plan consent version is invalid")
    for field in ("authorization_signer_key_id", "evidence_signer_key_id"):
        if HEX64.fullmatch(str(body[field])) is None:
            raise ResilienceError(f"{field} is invalid")
    authorized = parse_utc(body["authorized_at_utc"], "authorized_at_utc")
    expires = parse_utc(body["expires_at_utc"], "expires_at_utc")
    observed_now = now or datetime.now(timezone.utc)
    if expires <= authorized or authorized > observed_now or expires < observed_now:
        raise ResilienceError("resilience plan authorization is future-dated, expired, or inverted")
    drills = body["drills"]
    if not isinstance(drills, list) or tuple(row.get("drill_id") for row in drills if isinstance(row, dict)) != REQUIRED_DRILLS:
        raise ResilienceError("resilience plan must contain every required drill exactly once and in order")
    for row in drills:
        if not isinstance(row, dict) or set(row) != DRILL_KEYS:
            raise ResilienceError("resilience drill fields do not match the closed contract")
        if not isinstance(row["adapter_path"], str) or not row["adapter_path"] or "\x00" in row["adapter_path"]:
            raise ResilienceError("resilience adapter path is invalid")
        if HEX64.fullmatch(str(row["adapter_sha256"])) is None:
            raise ResilienceError("resilience adapter digest is invalid")
        if not isinstance(row["argv"], list) or len(row["argv"]) > 32 or not all(isinstance(arg, str) and arg and "\x00" not in arg for arg in row["argv"]):
            raise ResilienceError("resilience adapter argv is invalid or unbounded")
        if not isinstance(row["timeout_seconds"], int) or isinstance(row["timeout_seconds"], bool) or not 1 <= row["timeout_seconds"] <= 3600:
            raise ResilienceError("resilience adapter timeout is invalid")
    return body


def signature_record(private: Ed25519PrivateKey, domain: bytes, body: Mapping[str, Any]) -> dict[str, str]:
    public, key_id = public_identity(private)
    return {
        "suite": "Ed25519",
        "domain": domain.rstrip(b"\0").decode("ascii"),
        "key_id": key_id,
        "public_key_base64": public,
        "signature_base64": base64.b64encode(private.sign(domain + canonical_json(body))).decode("ascii"),
    }


def verify_signature(record: Any, domain: bytes, body: Mapping[str, Any], expected_key_id: str) -> None:
    if not isinstance(record, dict) or set(record) != SIGNATURE_KEYS:
        raise ResilienceError("signature record fields do not match the closed contract")
    public = decode_public(record["public_key_base64"])
    if (
        record["suite"] != "Ed25519"
        or record["domain"] != domain.rstrip(b"\0").decode("ascii")
        or record["key_id"] != expected_key_id
        or sha256_bytes(public) != expected_key_id
    ):
        raise ResilienceError("signature identity differs from the registered signer")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(record["signature_base64"]),
            domain + canonical_json(body),
        )
    except (ValueError, InvalidSignature) as error:
        raise ResilienceError("Ed25519 signature is forged or invalid") from error


def authorize(unsigned_path: Path, seed_path: Path, output: Path, *, now: datetime | None = None) -> dict[str, Any]:
    unsigned = load_object(unsigned_path)
    if set(unsigned) != {"schema", "body"} or unsigned.get("schema") != PLAN_SCHEMA:
        raise ResilienceError("unsigned resilience plan fields do not match the closed contract")
    body = validate_plan_body(unsigned["body"], now=now)
    private = Ed25519PrivateKey.from_private_bytes(load_seed(seed_path))
    _, key_id = public_identity(private)
    if key_id != body["authorization_signer_key_id"]:
        raise ResilienceError("authorization seed does not match the registered signer")
    document = {"schema": PLAN_SCHEMA, "body": body, "authorization": signature_record(private, AUTH_DOMAIN, body)}
    atomic_create(output, document)
    return document


def verify_plan(document: Any, expected_key_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != ENVELOPE_KEYS or document.get("schema") != PLAN_SCHEMA:
        raise ResilienceError("signed resilience plan fields do not match the closed contract")
    body = validate_plan_body(document["body"], now=now)
    if body["authorization_signer_key_id"] != expected_key_id:
        raise ResilienceError("resilience plan is not authorized by the expected trust anchor")
    verify_signature(document["authorization"], AUTH_DOMAIN, body, expected_key_id)
    return body


def positive_int(metrics: Mapping[str, Any], field: str, *, allow_zero: bool = False) -> int:
    value = metrics.get(field)
    minimum = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ResilienceError(f"{field} must be an integer >= {minimum}")
    return value


def require_true(metrics: Mapping[str, Any], *fields: str) -> None:
    for field in fields:
        if metrics.get(field) is not True:
            raise ResilienceError(f"{field} must be observed true")


def validate_metrics(drill_id: str, metrics: Any, before: str, after: str) -> None:
    if not isinstance(metrics, dict):
        raise ResilienceError(f"{drill_id} metrics must be an object")
    if drill_id == "queue_saturation":
        required = {"queue_limit", "max_queue_depth", "rejected_requests", "lost_records", "duplicate_records", "drained"}
        if set(metrics) != required:
            raise ResilienceError("queue saturation metrics do not match the closed contract")
        limit = positive_int(metrics, "queue_limit")
        maximum = positive_int(metrics, "max_queue_depth", allow_zero=True)
        positive_int(metrics, "rejected_requests")
        if maximum > limit or metrics["lost_records"] != 0 or metrics["duplicate_records"] != 0 or metrics["drained"] is not True or before != after:
            raise ResilienceError("queue saturation exceeded bounds, lost state, duplicated state, or failed to drain")
    elif drill_id == "key_rotation":
        required = {"previous_key_id", "new_key_id", "overlap_verified", "stale_key_rejected", "new_key_accepted", "old_key_disabled"}
        if set(metrics) != required:
            raise ResilienceError("key rotation metrics do not match the closed contract")
        if HEX64.fullmatch(str(metrics["previous_key_id"])) is None or HEX64.fullmatch(str(metrics["new_key_id"])) is None or metrics["previous_key_id"] == metrics["new_key_id"]:
            raise ResilienceError("key rotation identities are invalid or unchanged")
        require_true(metrics, "overlap_verified", "stale_key_rejected", "new_key_accepted", "old_key_disabled")
        if before != after:
            raise ResilienceError("key rotation changed durable participant data")
    elif drill_id == "backup":
        required = {"backup_sha256", "source_state_root", "backup_state_root", "consistent_snapshot"}
        if set(metrics) != required or any(HEX64.fullmatch(str(metrics.get(field))) is None for field in ("backup_sha256", "source_state_root", "backup_state_root")):
            raise ResilienceError("backup metrics or identities are invalid")
        if metrics["source_state_root"] != metrics["backup_state_root"] or metrics["source_state_root"] != before or before != after or metrics["consistent_snapshot"] is not True:
            raise ResilienceError("backup is not a consistent snapshot of the observed source state")
    elif drill_id == "restore":
        required = {"backup_sha256", "source_state_root", "restored_state_root", "empty_destination", "stale_state_records"}
        if set(metrics) != required or any(HEX64.fullmatch(str(metrics.get(field))) is None for field in ("backup_sha256", "source_state_root", "restored_state_root")):
            raise ResilienceError("restore metrics or identities are invalid")
        if metrics["source_state_root"] != metrics["restored_state_root"] or metrics["restored_state_root"] != after or metrics["empty_destination"] is not True or metrics["stale_state_records"] != 0:
            raise ResilienceError("restore did not reproduce the backup into an empty destination")
    elif drill_id == "retention_deletion":
        required = {"expired_candidates", "deleted_records", "remaining_expired_records", "retained_unexpired_records", "raw_identity_fields"}
        if set(metrics) != required:
            raise ResilienceError("retention deletion metrics do not match the closed contract")
        expired = positive_int(metrics, "expired_candidates")
        deleted = positive_int(metrics, "deleted_records")
        positive_int(metrics, "retained_unexpired_records")
        if expired != deleted or metrics["remaining_expired_records"] != 0 or metrics["raw_identity_fields"] != 0 or before == after:
            raise ResilienceError("retention deletion was incomplete, overbroad, or identity-bearing")
    elif drill_id == "telemetry_outage":
        required = {"successful_core_requests", "telemetry_deliveries_during_outage", "telemetry_queue_limit", "max_telemetry_queue", "recovery_flush_complete", "raw_identity_fields"}
        if set(metrics) != required:
            raise ResilienceError("telemetry outage metrics do not match the closed contract")
        positive_int(metrics, "successful_core_requests")
        limit = positive_int(metrics, "telemetry_queue_limit")
        maximum = positive_int(metrics, "max_telemetry_queue", allow_zero=True)
        if metrics["telemetry_deliveries_during_outage"] != 0 or maximum > limit or metrics["recovery_flush_complete"] is not True or metrics["raw_identity_fields"] != 0 or before != after:
            raise ResilienceError("telemetry outage affected core state, exceeded bounds, leaked identity, or failed recovery")
    elif drill_id == "incident_recovery":
        required = {"recovery_seconds", "recovery_limit_seconds", "health_restored", "replay_equal", "manual_intervention_count"}
        if set(metrics) != required:
            raise ResilienceError("incident recovery metrics do not match the closed contract")
        elapsed = metrics["recovery_seconds"]
        limit = metrics["recovery_limit_seconds"]
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed < 0 or not isinstance(limit, (int, float)) or isinstance(limit, bool) or limit <= 0:
            raise ResilienceError("incident recovery duration bounds are invalid")
        if elapsed > limit or metrics["health_restored"] is not True or metrics["replay_equal"] is not True or metrics["manual_intervention_count"] != 0 or before != after:
            raise ResilienceError("incident recovery exceeded its bound or required repair")
    else:
        raise ResilienceError(f"unregistered resilience drill: {drill_id}")


def validate_observation(value: Any, plan: Mapping[str, Any], drill: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS or value.get("schema") != OBSERVATION_SCHEMA:
        raise ResilienceError("resilience observation fields do not match the closed contract")
    if value["drill_id"] != drill["drill_id"] or value["source_revision"] != plan["source_revision"] or value["deployment_sha256"] != plan["deployment_sha256"]:
        raise ResilienceError("resilience observation is stale or belongs to another drill")
    if value["verdict"] != "PASS" or value["non_promoting_policy"] != NON_PROMOTING_POLICY or value["automatic_recovery"] is not True or value["manual_repair"] is not False:
        raise ResilienceError("resilience observation failed, promoted behavior, or required manual repair")
    before = str(value["before_data_root"])
    after = str(value["after_data_root"])
    if HEX64.fullmatch(before) is None or HEX64.fullmatch(after) is None:
        raise ResilienceError("resilience observation data roots are invalid")
    started = parse_utc(value["started_at_utc"], "started_at_utc")
    ended = parse_utc(value["ended_at_utc"], "ended_at_utc")
    observed_now = now or datetime.now(timezone.utc)
    if ended < started or (ended - started).total_seconds() > drill["timeout_seconds"] or ended > observed_now:
        raise ResilienceError("resilience observation timing is inverted, future-dated, or over timeout")
    validate_metrics(value["drill_id"], value["metrics"], before, after)
    return value


def run_adapter(command: Sequence[str], timeout_seconds: int) -> RunnerResult:
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout_seconds, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ResilienceError(f"resilience adapter failed to execute: {error}") from error
    return RunnerResult(completed.returncode, completed.stdout, completed.stderr)


def decode_adapter_output(result: RunnerResult, drill_id: str) -> dict[str, Any]:
    if result.returncode != 0:
        detail = result.stderr[:512].decode("utf-8", "replace")
        raise ResilienceError(f"{drill_id} adapter exited {result.returncode}: {detail}")
    if len(result.stdout) > MAX_OUTPUT_BYTES:
        raise ResilienceError(f"{drill_id} adapter output exceeds the bounded size")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ResilienceError(f"{drill_id} adapter did not emit one JSON object") from error
    if not isinstance(value, dict):
        raise ResilienceError(f"{drill_id} adapter output must be a JSON object")
    return value


def execute(
    document: Mapping[str, Any],
    expected_authorization_key_id: str,
    evidence_seed_path: Path,
    output: Path,
    *,
    runner: Runner = run_adapter,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    plan = verify_plan(document, expected_authorization_key_id, now=observed_now)
    private = Ed25519PrivateKey.from_private_bytes(load_seed(evidence_seed_path))
    _, evidence_key_id = public_identity(private)
    if evidence_key_id != plan["evidence_signer_key_id"]:
        raise ResilienceError("evidence seed does not match the signer authorized by the plan")
    steps: list[dict[str, Any]] = []
    for drill in plan["drills"]:
        adapter = Path(drill["adapter_path"])
        try:
            observed_digest = sha256_file(adapter)
        except OSError as error:
            raise ResilienceError(f"cannot hash resilience adapter {adapter}: {error}") from error
        if observed_digest != drill["adapter_sha256"]:
            raise ResilienceError(f"{drill['drill_id']} adapter digest differs from the authorized plan")
        result = runner([str(adapter), *drill["argv"]], drill["timeout_seconds"])
        raw = decode_adapter_output(result, drill["drill_id"])
        observation = validate_observation(raw, plan, drill, now=observed_now)
        steps.append(
            {
                "drill_id": drill["drill_id"],
                "adapter_sha256": observed_digest,
                "stdout_sha256": sha256_bytes(result.stdout),
                "stderr_sha256": sha256_bytes(result.stderr),
                "observation": observation,
            }
        )
    backup = steps[REQUIRED_DRILLS.index("backup")]["observation"]["metrics"]
    restore = steps[REQUIRED_DRILLS.index("restore")]["observation"]["metrics"]
    if restore["backup_sha256"] != backup["backup_sha256"] or restore["source_state_root"] != backup["source_state_root"]:
        raise ResilienceError("restore evidence does not bind the backup created by this drill run")
    body = {
        "plan_id": plan["plan_id"],
        "source_revision": plan["source_revision"],
        "deployment_sha256": plan["deployment_sha256"],
        "evidence_scope": plan["evidence_scope"],
        "executed_at_utc": format_utc(observed_now),
        "consent_version": plan["consent_version"],
        "non_promoting_policy": NON_PROMOTING_POLICY,
        "steps": steps,
        "verdict": "PASS",
    }
    envelope = {"schema": RESULT_SCHEMA, "body": body, "attestation": signature_record(private, EVIDENCE_DOMAIN, body)}
    atomic_create(output, envelope)
    return envelope


def verify_result(
    document: Any,
    plan_document: Any,
    expected_authorization_key_id: str,
    expected_evidence_key_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    plan = verify_plan(plan_document, expected_authorization_key_id, now=observed_now)
    if not isinstance(document, dict) or set(document) != RESULT_KEYS or document.get("schema") != RESULT_SCHEMA:
        raise ResilienceError("resilience result fields do not match the closed contract")
    body = document["body"]
    expected_body_keys = {"plan_id", "source_revision", "deployment_sha256", "evidence_scope", "executed_at_utc", "consent_version", "non_promoting_policy", "steps", "verdict"}
    if not isinstance(body, dict) or set(body) != expected_body_keys:
        raise ResilienceError("resilience result body fields do not match the closed contract")
    if any(body[field] != plan[field] for field in ("plan_id", "source_revision", "deployment_sha256", "evidence_scope", "consent_version", "non_promoting_policy")) or body["verdict"] != "PASS":
        raise ResilienceError("resilience result does not bind the authorized plan or passing policy")
    executed = parse_utc(body["executed_at_utc"], "executed_at_utc")
    if executed > observed_now:
        raise ResilienceError("resilience result is future-dated")
    steps = body["steps"]
    if not isinstance(steps, list) or len(steps) != len(REQUIRED_DRILLS):
        raise ResilienceError("resilience result does not contain every required drill")
    for step, drill in zip(steps, plan["drills"], strict=True):
        if not isinstance(step, dict) or set(step) != {"drill_id", "adapter_sha256", "stdout_sha256", "stderr_sha256", "observation"}:
            raise ResilienceError("resilience result step fields do not match the closed contract")
        if step["drill_id"] != drill["drill_id"] or step["adapter_sha256"] != drill["adapter_sha256"] or HEX64.fullmatch(str(step["stdout_sha256"])) is None or HEX64.fullmatch(str(step["stderr_sha256"])) is None:
            raise ResilienceError("resilience result step is stale or lacks bounded output commitments")
        validate_observation(step["observation"], plan, drill, now=observed_now)
    backup = steps[REQUIRED_DRILLS.index("backup")]["observation"]["metrics"]
    restore = steps[REQUIRED_DRILLS.index("restore")]["observation"]["metrics"]
    if restore["backup_sha256"] != backup["backup_sha256"] or restore["source_state_root"] != backup["source_state_root"]:
        raise ResilienceError("verified restore does not bind this result's backup")
    if plan["evidence_signer_key_id"] != expected_evidence_key_id:
        raise ResilienceError("resilience evidence signer differs from the expected trust anchor")
    verify_signature(document["attestation"], EVIDENCE_DOMAIN, body, expected_evidence_key_id)
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    authorize_command = commands.add_parser("authorize")
    authorize_command.add_argument("--unsigned", type=Path, required=True)
    authorize_command.add_argument("--seed", type=Path, required=True)
    authorize_command.add_argument("--output", type=Path, required=True)
    execute_command = commands.add_parser("execute")
    execute_command.add_argument("--plan", type=Path, required=True)
    execute_command.add_argument("--authorization-key-id", required=True)
    execute_command.add_argument("--evidence-seed", type=Path, required=True)
    execute_command.add_argument("--output", type=Path, required=True)
    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--plan", type=Path, required=True)
    verify_command.add_argument("--result", type=Path, required=True)
    verify_command.add_argument("--authorization-key-id", required=True)
    verify_command.add_argument("--evidence-key-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "authorize":
            result = authorize(args.unsigned, args.seed, args.output)
            summary = {"verdict": "AUTHORIZED", "plan_id": result["body"]["plan_id"]}
        elif args.command == "execute":
            result = execute(load_object(args.plan), args.authorization_key_id, args.evidence_seed, args.output)
            summary = {"verdict": "PASS", "plan_id": result["body"]["plan_id"], "drill_count": len(result["body"]["steps"]), "promotion_authorized": False}
        else:
            body = verify_result(load_object(args.result), load_object(args.plan), args.authorization_key_id, args.evidence_key_id)
            summary = {"verdict": body["verdict"], "plan_id": body["plan_id"], "drill_count": len(body["steps"]), "promotion_authorized": False}
        sys.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except ResilienceError as error:
        sys.stdout.write(json.dumps({"verdict": "INVALID_EVIDENCE", "error": str(error), "promotion_authorized": False}, sort_keys=True, separators=(",", ":")) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
