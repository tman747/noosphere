#!/usr/bin/env python3
"""Authorize, execute, and verify operator-independence fault drills."""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PLAN_SCHEMA = "noos/operator-independence-drill-plan/v1"
OBSERVATION_SCHEMA = "noos/operator-independence-drill-observation/v1"
RESULT_SCHEMA = "noos/operator-independence-drill-result/v1"
AUTH_DOMAIN = b"NOOS/SIG/OPERATOR-INDEPENDENCE-DRILL-AUTHORIZATION/V1\0"
EVIDENCE_DOMAIN = b"NOOS/SIG/OPERATOR-INDEPENDENCE-DRILL-EVIDENCE/V1\0"
PLAN_ID_DOMAIN = b"NOOS/OPERATOR-INDEPENDENCE-DRILL-PLAN-ID/V1\0"
RESULT_ID_DOMAIN = b"NOOS/OPERATOR-INDEPENDENCE-DRILL-RESULT-ID/V1\0"
REQUIRED_DRILLS = (
    "largest_provider_loss",
    "largest_region_loss",
    "model_share_poison",
    "model_share_replay_withhold",
)
NON_PROMOTING_POLICY = {
    "production_admission": False,
    "production_custody": False,
    "promotion_authorized": False,
    "rewards": False,
}
PLAN_BODY_FIELDS = {
    "plan_id",
    "source_revision",
    "deployment_sha256",
    "cohort_id",
    "evidence_scope",
    "authorized_at_utc",
    "expires_at_utc",
    "authorization_signer_key_id",
    "evidence_signer_key_id",
    "non_promoting_policy",
    "drills",
}
DRILL_FIELDS = {"drill_id", "adapter_path", "adapter_sha256", "argv", "timeout_seconds"}
OBSERVATION_FIELDS = {
    "schema",
    "drill_id",
    "source_revision",
    "deployment_sha256",
    "cohort_id",
    "started_at_utc",
    "ended_at_utc",
    "verdict",
    "before_content_root",
    "after_content_root",
    "automatic_recovery",
    "manual_repair",
    "non_promoting_policy",
    "metrics",
}
SIGNATURE_FIELDS = {
    "suite",
    "domain",
    "key_id",
    "public_key_base64",
    "signature_base64",
}
RESULT_BODY_FIELDS = {
    "result_id",
    "plan_id",
    "source_revision",
    "deployment_sha256",
    "cohort_id",
    "observed_at_utc",
    "verdict",
    "non_promoting_policy",
    "steps",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_ADAPTER_OUTPUT_BYTES = 2 * 1024 * 1024


class IndependenceDrillError(RuntimeError):
    """A drill plan, observation, or attestation is unsafe or malformed."""


@dataclass(frozen=True)
class RunnerResult:
    returncode: int
    stdout: bytes
    stderr: bytes


Runner = Callable[[Sequence[str], int], RunnerResult]


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise IndependenceDrillError(f"cannot hash adapter {path}: {error}") from error
    return digest.hexdigest()


def load_object(path: Path, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise IndependenceDrillError(f"cannot read {path}: {error}") from error
    if not payload or len(payload) > maximum_bytes:
        raise IndependenceDrillError(f"document size is outside 1..{maximum_bytes} bytes")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndependenceDrillError(f"{path} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise IndependenceDrillError(f"{path} must contain one JSON object")
    return value


def atomic_create(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise IndependenceDrillError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except OSError as link_error:
            try:
                placeholder = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
            except FileExistsError as error:
                raise IndependenceDrillError(f"refusing to overwrite {path}") from error
            except OSError as error:
                raise IndependenceDrillError(
                    f"cannot reserve evidence path {path}: {error}"
                ) from link_error
            else:
                os.close(placeholder)
            os.replace(temporary, path)
        else:
            temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise IndependenceDrillError(f"{label} must be UTC text with second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise IndependenceDrillError(f"{label} is not a valid UTC timestamp") from error


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_seed(path: Path) -> bytes:
    try:
        seed = path.read_bytes()
    except OSError as error:
        raise IndependenceDrillError(f"cannot read Ed25519 seed: {error}") from error
    if len(seed) != 32 or seed == bytes(32):
        raise IndependenceDrillError("Ed25519 seed must contain 32 nonzero raw bytes")
    return seed


def public_identity(private: Ed25519PrivateKey) -> tuple[str, str]:
    public = private.public_key().public_bytes_raw()
    return base64.b64encode(public).decode("ascii"), sha256_bytes(public)


def decode_public(value: Any) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise IndependenceDrillError("signature public key is not canonical base64") from error
    if len(decoded) != 32:
        raise IndependenceDrillError("signature public key must contain 32 bytes")
    return decoded


def decode_signature(value: Any) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise IndependenceDrillError("signature is not canonical base64") from error
    if len(decoded) != 64:
        raise IndependenceDrillError("Ed25519 signature must contain 64 bytes")
    return decoded


def plan_id(body: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in body.items() if key != "plan_id"}
    return sha256_bytes(PLAN_ID_DOMAIN + canonical_json(unsigned))


def result_id(body: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in body.items() if key != "result_id"}
    return sha256_bytes(RESULT_ID_DOMAIN + canonical_json(unsigned))


def signature_record(
    private: Ed25519PrivateKey, domain: bytes, body: Mapping[str, Any]
) -> dict[str, str]:
    public, key_id = public_identity(private)
    return {
        "suite": "ed25519",
        "domain": domain[:-1].decode("ascii"),
        "key_id": key_id,
        "public_key_base64": public,
        "signature_base64": base64.b64encode(
            private.sign(domain + canonical_json(body))
        ).decode("ascii"),
    }


def verify_signature(
    record: Any, domain: bytes, body: Mapping[str, Any], expected_key_id: str
) -> None:
    if not isinstance(record, dict) or set(record) != SIGNATURE_FIELDS:
        raise IndependenceDrillError("signature record fields are malformed")
    if record.get("suite") != "ed25519" or record.get("domain") != domain[:-1].decode(
        "ascii"
    ):
        raise IndependenceDrillError("signature suite or domain is invalid")
    public = decode_public(record.get("public_key_base64"))
    if sha256_bytes(public) != expected_key_id or record.get("key_id") != expected_key_id:
        raise IndependenceDrillError("signature does not match the expected trust anchor")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(record.get("signature_base64")),
            domain + canonical_json(body),
        )
    except InvalidSignature as error:
        raise IndependenceDrillError("Ed25519 signature is forged or invalid") from error


def _validate_adapter(row: Any) -> None:
    if not isinstance(row, dict) or set(row) != DRILL_FIELDS:
        raise IndependenceDrillError("drill adapter fields are malformed")
    if row.get("drill_id") not in REQUIRED_DRILLS:
        raise IndependenceDrillError("drill id is not registered")
    path = row.get("adapter_path")
    if not isinstance(path, str) or not path or "\x00" in path or not Path(path).is_absolute():
        raise IndependenceDrillError("adapter path must be absolute text")
    if not isinstance(row.get("adapter_sha256"), str) or HEX64.fullmatch(
        row["adapter_sha256"]
    ) is None:
        raise IndependenceDrillError("adapter digest must be lowercase SHA-256")
    argv = row.get("argv")
    if (
        not isinstance(argv, list)
        or len(argv) > 64
        or any(not isinstance(item, str) or not item or "\x00" in item for item in argv)
    ):
        raise IndependenceDrillError("adapter argv is malformed or unbounded")
    timeout = row.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600:
        raise IndependenceDrillError("adapter timeout must be within 1..3600 seconds")


def validate_plan_body(
    body: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != PLAN_BODY_FIELDS:
        raise IndependenceDrillError("plan body fields are malformed")
    for field in ("deployment_sha256", "cohort_id", "authorization_signer_key_id", "evidence_signer_key_id"):
        if not isinstance(body.get(field), str) or HEX64.fullmatch(body[field]) is None:
            raise IndependenceDrillError(f"{field} must be lowercase hex64")
    if not isinstance(body.get("source_revision"), str) or HEX40.fullmatch(
        body["source_revision"]
    ) is None:
        raise IndependenceDrillError("source_revision must be lowercase Git hex40")
    if body.get("evidence_scope") != "OWNER_CONTROLLED_NONPRODUCTION_DEVNET":
        raise IndependenceDrillError("only the nonproduction owner-controlled scope is authorized")
    if body.get("non_promoting_policy") != NON_PROMOTING_POLICY:
        raise IndependenceDrillError("non-promoting policy differs from the frozen contract")
    authorized = parse_utc(body.get("authorized_at_utc"), "authorized_at_utc")
    expires = parse_utc(body.get("expires_at_utc"), "expires_at_utc")
    observed_now = now or datetime.now(timezone.utc)
    if authorized >= expires or observed_now < authorized or observed_now > expires:
        raise IndependenceDrillError("drill authorization is not currently valid")
    drills = body.get("drills")
    if (
        not isinstance(drills, list)
        or tuple(
            row.get("drill_id") for row in drills if isinstance(row, dict)
        )
        != REQUIRED_DRILLS
    ):
        raise IndependenceDrillError(
            "plan must contain every registered independence drill exactly once and in order"
        )
    for row in drills:
        _validate_adapter(row)
    if body.get("plan_id") != plan_id(body):
        raise IndependenceDrillError("plan_id does not match the canonical plan body")
    return body


def authorize(
    unsigned_path: Path,
    seed_path: Path,
    output: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    unsigned = load_object(unsigned_path)
    if set(unsigned) != {"schema", "body"} or unsigned.get("schema") != PLAN_SCHEMA:
        raise IndependenceDrillError("unsigned plan envelope is malformed")
    body = validate_plan_body(unsigned.get("body"), now=now)
    private = Ed25519PrivateKey.from_private_bytes(load_seed(seed_path))
    _, key_id = public_identity(private)
    if body["authorization_signer_key_id"] != key_id:
        raise IndependenceDrillError("authorization seed differs from the plan trust anchor")
    document = {
        "schema": PLAN_SCHEMA,
        "body": body,
        "authorization": signature_record(private, AUTH_DOMAIN, body),
    }
    atomic_create(output, document)
    return document


def verify_plan(
    document: Any, expected_key_id: str, *, now: datetime | None = None
) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "body", "authorization"}
        or document.get("schema") != PLAN_SCHEMA
    ):
        raise IndependenceDrillError("signed plan envelope is malformed")
    body = validate_plan_body(document.get("body"), now=now)
    verify_signature(document.get("authorization"), AUTH_DOMAIN, body, expected_key_id)
    if body["authorization_signer_key_id"] != expected_key_id:
        raise IndependenceDrillError("plan embeds a different authorization trust anchor")
    return body


def positive_int(metrics: Mapping[str, Any], field: str, *, allow_zero: bool = False) -> int:
    value = metrics.get(field)
    minimum = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise IndependenceDrillError(f"{field} must be an integer >= {minimum}")
    return value


def require_true(metrics: Mapping[str, Any], *fields: str) -> None:
    for field in fields:
        if metrics.get(field) is not True:
            raise IndependenceDrillError(f"{field} must be observed true")


def validate_metrics(
    drill_id: str, metrics: Any, before: str, after: str
) -> None:
    if not isinstance(metrics, dict):
        raise IndependenceDrillError(f"{drill_id} metrics must be an object")
    if before != after:
        raise IndependenceDrillError(f"{drill_id} changed the committed content root")
    if drill_id in {"largest_provider_loss", "largest_region_loss"}:
        scope_field = "lost_provider" if drill_id == "largest_provider_loss" else "lost_region"
        remaining_field = (
            "remaining_providers" if drill_id == "largest_provider_loss" else "remaining_regions"
        )
        required = {
            scope_field,
            "lost_scope_rank",
            "lost_operators",
            remaining_field,
            "base_finality_advanced",
            "executor_quorum_preserved",
            "read_quorum_preserved",
            "reconstruction_admitted",
            "repair_receipts",
            "unrelated_job_failures",
        }
        if set(metrics) != required:
            raise IndependenceDrillError(f"{drill_id} metrics differ from the closed contract")
        scope = metrics[scope_field]
        if not isinstance(scope, str) or TOKEN.fullmatch(scope) is None:
            raise IndependenceDrillError(f"{scope_field} is malformed")
        if metrics["lost_scope_rank"] != 1:
            raise IndependenceDrillError("the drill did not remove the largest registered scope")
        positive_int(metrics, "lost_operators")
        if positive_int(metrics, remaining_field) < 2:
            raise IndependenceDrillError("too few independent failure domains remained")
        positive_int(metrics, "repair_receipts")
        if metrics["unrelated_job_failures"] != 0:
            raise IndependenceDrillError("provider or region loss interrupted unrelated work")
        require_true(
            metrics,
            "base_finality_advanced",
            "executor_quorum_preserved",
            "read_quorum_preserved",
            "reconstruction_admitted",
        )
    elif drill_id == "model_share_poison":
        required = {
            "injected_corrupt_shares",
            "rejected_corrupt_shares",
            "accepted_corrupt_shares",
            "quarantine_activated",
            "repair_receipts",
            "reconstructed_content_root",
            "jobs_scheduled_below_threshold",
            "unrelated_job_failures",
        }
        if set(metrics) != required:
            raise IndependenceDrillError("model poison metrics differ from the closed contract")
        injected = positive_int(metrics, "injected_corrupt_shares")
        if metrics["rejected_corrupt_shares"] != injected or metrics["accepted_corrupt_shares"] != 0:
            raise IndependenceDrillError("a corrupt model share was not rejected exactly once")
        if metrics["reconstructed_content_root"] != after or HEX64.fullmatch(str(after)) is None:
            raise IndependenceDrillError("poison repair reconstructed the wrong content root")
        positive_int(metrics, "repair_receipts")
        if metrics["jobs_scheduled_below_threshold"] != 0 or metrics["unrelated_job_failures"] != 0:
            raise IndependenceDrillError("poison handling scheduled unsafe or unrelated work")
        require_true(metrics, "quarantine_activated")
    elif drill_id == "model_share_replay_withhold":
        required = {
            "replayed_shares",
            "accepted_replays",
            "stale_shares",
            "accepted_stale_shares",
            "withheld_positions",
            "threshold_unschedulable_observed",
            "restored_schedulability",
            "repair_receipts",
            "unrelated_job_failures",
        }
        if set(metrics) != required:
            raise IndependenceDrillError("model replay metrics differ from the closed contract")
        positive_int(metrics, "replayed_shares")
        positive_int(metrics, "stale_shares")
        positive_int(metrics, "withheld_positions")
        positive_int(metrics, "repair_receipts")
        if (
            metrics["accepted_replays"] != 0
            or metrics["accepted_stale_shares"] != 0
            or metrics["unrelated_job_failures"] != 0
        ):
            raise IndependenceDrillError("replayed/stale shares were accepted or unrelated work failed")
        require_true(
            metrics,
            "threshold_unschedulable_observed",
            "restored_schedulability",
        )
    else:
        raise IndependenceDrillError(f"unregistered independence drill: {drill_id}")


def validate_observation(
    value: Any,
    plan: Mapping[str, Any],
    drill: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != OBSERVATION_FIELDS
        or value.get("schema") != OBSERVATION_SCHEMA
    ):
        raise IndependenceDrillError("drill observation fields are malformed")
    for field in ("drill_id", "source_revision", "deployment_sha256", "cohort_id"):
        expected = drill["drill_id"] if field == "drill_id" else plan[field]
        if value.get(field) != expected:
            raise IndependenceDrillError(f"observation {field} differs from its signed plan")
    started = parse_utc(value.get("started_at_utc"), "started_at_utc")
    ended = parse_utc(value.get("ended_at_utc"), "ended_at_utc")
    observed_now = now or datetime.now(timezone.utc)
    if started > ended or ended > observed_now:
        raise IndependenceDrillError("observation time interval is invalid or future-dated")
    if value.get("verdict") != "PASS":
        raise IndependenceDrillError("drill adapter did not report PASS")
    if value.get("automatic_recovery") is not True or value.get("manual_repair") is not False:
        raise IndependenceDrillError("drill required manual repair or lacked automatic recovery")
    if value.get("non_promoting_policy") != NON_PROMOTING_POLICY:
        raise IndependenceDrillError("observation changed the non-promoting policy")
    before = value.get("before_content_root")
    after = value.get("after_content_root")
    if not isinstance(before, str) or HEX64.fullmatch(before) is None or not isinstance(
        after, str
    ) or HEX64.fullmatch(after) is None:
        raise IndependenceDrillError("observation content roots must be lowercase hex64")
    validate_metrics(drill["drill_id"], value.get("metrics"), before, after)
    return value


def run_adapter(command: Sequence[str], timeout_seconds: int) -> RunnerResult:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IndependenceDrillError(f"drill adapter failed to execute: {error}") from error
    return RunnerResult(completed.returncode, completed.stdout, completed.stderr)


def adapter_command(path: Path, argv: Sequence[str]) -> list[str]:
    if path.suffix.lower() == ".py":
        return [sys.executable, str(path), *argv]
    return [str(path), *argv]


def decode_adapter_output(result: RunnerResult, drill_id: str) -> dict[str, Any]:
    if result.returncode != 0:
        raise IndependenceDrillError(f"{drill_id} adapter exited with {result.returncode}")
    if not result.stdout or len(result.stdout) > MAX_ADAPTER_OUTPUT_BYTES:
        raise IndependenceDrillError(f"{drill_id} stdout is empty or over the output bound")
    if len(result.stderr) > MAX_ADAPTER_OUTPUT_BYTES:
        raise IndependenceDrillError(f"{drill_id} stderr exceeds the output bound")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndependenceDrillError(f"{drill_id} adapter did not emit one JSON object") from error
    if not isinstance(value, dict):
        raise IndependenceDrillError(f"{drill_id} adapter output must be an object")
    return value


def execute(
    signed_plan: Mapping[str, Any],
    expected_authorization_key_id: str,
    evidence_seed_path: Path,
    output: Path,
    *,
    runner: Runner = run_adapter,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    plan = verify_plan(signed_plan, expected_authorization_key_id, now=observed_now)
    private = Ed25519PrivateKey.from_private_bytes(load_seed(evidence_seed_path))
    _, evidence_key_id = public_identity(private)
    if evidence_key_id != plan["evidence_signer_key_id"]:
        raise IndependenceDrillError("evidence seed differs from the plan trust anchor")
    steps: list[dict[str, Any]] = []
    for drill in plan["drills"]:
        adapter = Path(drill["adapter_path"])
        if not adapter.is_file() or sha256_file(adapter) != drill["adapter_sha256"]:
            raise IndependenceDrillError(
                f"{drill['drill_id']} adapter is missing or its digest differs from the plan"
            )
        result = runner(
            adapter_command(adapter, drill["argv"]), drill["timeout_seconds"]
        )
        observation = decode_adapter_output(result, drill["drill_id"])
        validate_observation(observation, plan, drill, now=observed_now)
        steps.append(
            {
                "drill_id": drill["drill_id"],
                "adapter_sha256": drill["adapter_sha256"],
                "stdout_sha256": sha256_bytes(result.stdout),
                "stderr_sha256": sha256_bytes(result.stderr),
                "observation": observation,
            }
        )
    body: dict[str, Any] = {
        "result_id": "",
        "plan_id": plan["plan_id"],
        "source_revision": plan["source_revision"],
        "deployment_sha256": plan["deployment_sha256"],
        "cohort_id": plan["cohort_id"],
        "observed_at_utc": format_utc(observed_now),
        "verdict": "PASS",
        "non_promoting_policy": NON_PROMOTING_POLICY,
        "steps": steps,
    }
    body["result_id"] = result_id(body)
    envelope = {
        "schema": RESULT_SCHEMA,
        "body": body,
        "attestation": signature_record(private, EVIDENCE_DOMAIN, body),
    }
    atomic_create(output, envelope)
    return envelope


def verify_result(
    document: Any,
    signed_plan: Mapping[str, Any],
    expected_authorization_key_id: str,
    expected_evidence_key_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    plan = verify_plan(signed_plan, expected_authorization_key_id, now=observed_now)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "body", "attestation"}
        or document.get("schema") != RESULT_SCHEMA
    ):
        raise IndependenceDrillError("result envelope fields are malformed")
    body = document.get("body")
    if not isinstance(body, dict) or set(body) != RESULT_BODY_FIELDS:
        raise IndependenceDrillError("result body fields are malformed")
    for field in ("plan_id", "source_revision", "deployment_sha256", "cohort_id"):
        if body.get(field) != plan[field]:
            raise IndependenceDrillError(f"result {field} differs from the signed plan")
    if body.get("verdict") != "PASS" or body.get("non_promoting_policy") != NON_PROMOTING_POLICY:
        raise IndependenceDrillError("result is not a passing non-promoting drill run")
    if body.get("result_id") != result_id(body):
        raise IndependenceDrillError("result_id does not match the canonical result body")
    if parse_utc(body.get("observed_at_utc"), "observed_at_utc") > observed_now:
        raise IndependenceDrillError("result observation time is future-dated")
    steps = body.get("steps")
    if not isinstance(steps, list) or len(steps) != len(REQUIRED_DRILLS):
        raise IndependenceDrillError("result does not contain every registered drill")
    for step, drill in zip(steps, plan["drills"], strict=True):
        required = {
            "drill_id",
            "adapter_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "observation",
        }
        if not isinstance(step, dict) or set(step) != required:
            raise IndependenceDrillError("result step fields are malformed")
        if step["drill_id"] != drill["drill_id"] or step["adapter_sha256"] != drill["adapter_sha256"]:
            raise IndependenceDrillError("result step differs from its registered adapter")
        if any(
            not isinstance(step[field], str) or HEX64.fullmatch(step[field]) is None
            for field in ("stdout_sha256", "stderr_sha256")
        ):
            raise IndependenceDrillError("result stream digest is malformed")
        validate_observation(step["observation"], plan, drill, now=observed_now)
    if plan["evidence_signer_key_id"] != expected_evidence_key_id:
        raise IndependenceDrillError("plan embeds a different evidence trust anchor")
    verify_signature(
        document.get("attestation"),
        EVIDENCE_DOMAIN,
        body,
        expected_evidence_key_id,
    )
    return body


def keygen(path: Path) -> dict[str, str]:
    if path.exists():
        raise IndependenceDrillError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(private.private_bytes_raw())
        stream.flush()
        os.fsync(stream.fileno())
    public, key_id = public_identity(private)
    return {"key_id": key_id, "public_key_base64": public}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("keygen")
    generate.add_argument("--out", type=Path, required=True)
    authorize_parser = subparsers.add_parser("authorize")
    authorize_parser.add_argument("--unsigned", type=Path, required=True)
    authorize_parser.add_argument("--seed", type=Path, required=True)
    authorize_parser.add_argument("--out", type=Path, required=True)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--plan", type=Path, required=True)
    execute_parser.add_argument("--authorization-key-id", required=True)
    execute_parser.add_argument("--evidence-seed", type=Path, required=True)
    execute_parser.add_argument("--out", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--plan", type=Path, required=True)
    verify_parser.add_argument("--result", type=Path, required=True)
    verify_parser.add_argument("--authorization-key-id", required=True)
    verify_parser.add_argument("--evidence-key-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            result = keygen(args.out)
        elif args.command == "authorize":
            result = authorize(args.unsigned, args.seed, args.out)
        elif args.command == "execute":
            plan = load_object(args.plan)
            result = execute(
                plan,
                args.authorization_key_id,
                args.evidence_seed,
                args.out,
            )
        else:
            plan = load_object(args.plan)
            result = verify_result(
                load_object(args.result),
                plan,
                args.authorization_key_id,
                args.evidence_key_id,
            )
    except IndependenceDrillError as error:
        print(f"RESULT operator_independence_drills=FAIL reason={error}", file=sys.stderr)
        return 1
    print(canonical_json(result).decode("utf-8"))
    print(f"RESULT operator_independence_drills=PASS command={args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
