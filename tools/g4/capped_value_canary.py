#!/usr/bin/env python3
"""Sign and verify fail-closed G4 capped-value canary control evidence.

The tool proves only the machine-checkable control contract: aggregate exposure
never exceeds ten basis points, incidents disable the affected target within
one finalized-checkpoint interval, recovery is target-scoped and separately
authorized, checkpoints are append-only and threshold signed, and the required
fault/exit drills are present. It never turns local clocks, organization labels,
or signatures into proof of independence, elapsed public time, or promotion.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MANIFEST_SCHEMA = "noos/g4-capped-value-canary-manifest/v1"
CHECKPOINT_SCHEMA = "noos/g4-capped-value-canary-checkpoint/v1"
RESULT_SCHEMA = "noos/g4-capped-value-canary-result/v1"
MANIFEST_DOMAIN = b"NOOS/SIG/G4/CAPPED-VALUE-CANARY/MANIFEST/V1\0"
CHECKPOINT_DOMAIN = b"NOOS/SIG/G4/CAPPED-VALUE-CANARY/CHECKPOINT/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
STATES = {"ACTIVE", "DISABLED", "RECOVERING"}
DRILL_KINDS = {
    "one_checkpoint_disable",
    "target_recovery",
    "wan",
    "blackout",
    "saturation",
    "exit",
}
MAX_CAP_BPS = 10
REQUIRED_REAL_DAYS = 180
MAX_OPERATORS = 64
MAX_TARGETS = 32
MAX_CHECKPOINTS = 100_000
MAX_FILE_BYTES = 16 * 1024 * 1024


class CanaryError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CanaryError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path, maximum: int = MAX_FILE_BYTES) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > maximum:
            raise CanaryError(f"{path} exceeds {maximum} bytes")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CanaryError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise CanaryError(f"{path} must contain one JSON object")
    return value


def load_ledger(path: Path) -> list[dict[str, Any]]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise CanaryError(f"{path} exceeds {MAX_FILE_BYTES} bytes")
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CanaryError(f"cannot read {path}: {error}") from error
    if len(lines) > MAX_CHECKPOINTS:
        raise CanaryError(f"ledger exceeds {MAX_CHECKPOINTS} checkpoints")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line, object_pairs_hook=reject_duplicates)
        except (json.JSONDecodeError, CanaryError) as error:
            raise CanaryError(f"ledger line {line_number} is invalid: {error}") from error
        if not isinstance(value, dict):
            raise CanaryError(f"ledger line {line_number} is not an object")
        records.append(value)
    return records


def exact_fields(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        present = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise CanaryError(f"{context} fields mismatch: {present}")
    return value


def token(value: Any, context: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise CanaryError(f"{context} must be a canonical identifier")
    return value


def hex40(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX40.fullmatch(value):
        raise CanaryError(f"{context} must be a lowercase Git revision")
    return value


def hex64(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise CanaryError(f"{context} must be a lowercase hash32")
    return value


def integer(value: Any, context: str, minimum: int, maximum: int = (1 << 127) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CanaryError(f"{context} must be an integer in {minimum}..{maximum}")
    return value


def parse_time(value: Any, context: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CanaryError(f"{context} must be canonical UTC")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CanaryError(f"{context} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise CanaryError(f"{context} must be UTC")
    return parsed


def decode_public_key(value: Any, context: str) -> Ed25519PublicKey:
    if not isinstance(value, str):
        raise CanaryError(f"{context} must be base64")
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32:
            raise ValueError("wrong key length")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as error:
        raise CanaryError(f"{context} is not an Ed25519 public key") from error


def unsigned(document: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "signatures"}


def signature_message(document: Mapping[str, Any], schema: str) -> bytes:
    if schema == MANIFEST_SCHEMA:
        return MANIFEST_DOMAIN + canonical_json(unsigned(document))
    if schema == CHECKPOINT_SCHEMA:
        return CHECKPOINT_DOMAIN + canonical_json(unsigned(document))
    raise CanaryError("unsupported signed schema")


def validate_operator(operator: Any, index: int) -> tuple[str, dict[str, Any]]:
    row = exact_fields(
        operator,
        {"operator_id", "organization_id", "provider_id", "region_id", "key_id", "public_key_base64"},
        f"operators[{index}]",
    )
    operator_id = token(row["operator_id"], f"operators[{index}].operator_id")
    for field in ("organization_id", "provider_id", "region_id", "key_id"):
        token(row[field], f"operators[{index}].{field}")
    decode_public_key(row["public_key_base64"], f"operators[{index}].public_key_base64")
    return operator_id, row


def validate_signature_set(
    document: Mapping[str, Any],
    operators: Mapping[str, Mapping[str, Any]],
    threshold: int,
) -> set[str]:
    signatures = document.get("signatures")
    if not isinstance(signatures, list) or not threshold <= len(signatures) <= len(operators):
        raise CanaryError("signature count does not meet the manifest threshold")
    ids = [row.get("operator_id") for row in signatures if isinstance(row, dict)]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise CanaryError("signatures must be unique and sorted by operator_id")
    message = signature_message(document, str(document.get("schema")))
    organizations: set[str] = set()
    for index, raw in enumerate(signatures):
        row = exact_fields(raw, {"operator_id", "key_id", "signature_base64"}, f"signatures[{index}]")
        operator_id = token(row["operator_id"], f"signatures[{index}].operator_id")
        operator = operators.get(operator_id)
        if operator is None or row["key_id"] != operator["key_id"]:
            raise CanaryError("signature identity is not registered by the manifest")
        try:
            signature = base64.b64decode(row["signature_base64"], validate=True)
            if len(signature) != 64:
                raise ValueError("wrong signature length")
            decode_public_key(operator["public_key_base64"], "operator public key").verify(signature, message)
        except (ValueError, TypeError, InvalidSignature) as error:
            raise CanaryError(f"invalid signature for {operator_id}") from error
        organizations.add(str(operator["organization_id"]))
    if len(organizations) < threshold:
        raise CanaryError("signature threshold lacks distinct declared organizations")
    return organizations


def validate_manifest(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    exact_fields(
        manifest,
        {
            "schema", "manifest_state", "canary_id", "source_revision", "chain_id", "genesis_hash",
            "eligible_value_atoms", "value_unit", "cap_bps", "checkpoint_interval_blocks",
            "required_real_days", "target_ids", "operators", "signature_threshold",
            "observer_organization_ids", "independence_limit", "production_authorized",
            "promotion_effect", "signatures",
        },
        "manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise CanaryError("wrong manifest schema")
    if manifest["manifest_state"] not in {"EXTERNAL_COLLECTION", "TEST_FIXTURE_NOT_EVIDENCE"}:
        raise CanaryError("manifest state is invalid")
    token(manifest["canary_id"], "canary_id")
    hex40(manifest["source_revision"], "source_revision")
    hex64(manifest["chain_id"], "chain_id")
    hex64(manifest["genesis_hash"], "genesis_hash")
    integer(manifest["eligible_value_atoms"], "eligible_value_atoms", 1)
    token(manifest["value_unit"], "value_unit")
    integer(manifest["cap_bps"], "cap_bps", 1, MAX_CAP_BPS)
    integer(manifest["checkpoint_interval_blocks"], "checkpoint_interval_blocks", 1, 1_000_000)
    if manifest["required_real_days"] != REQUIRED_REAL_DAYS:
        raise CanaryError(f"required_real_days must remain {REQUIRED_REAL_DAYS}")
    targets = manifest["target_ids"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise CanaryError("target_ids count is outside the bound")
    checked_targets = [token(value, "target_id") for value in targets]
    if checked_targets != sorted(set(checked_targets)):
        raise CanaryError("target_ids must be unique and sorted")
    raw_operators = manifest["operators"]
    if not isinstance(raw_operators, list) or not 3 <= len(raw_operators) <= MAX_OPERATORS:
        raise CanaryError("operators must contain 3..64 entries")
    operators: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(raw_operators):
        operator_id, row = validate_operator(raw, index)
        if operator_id in operators:
            raise CanaryError("operator_id values must be unique")
        operators[operator_id] = row
    if list(operators) != sorted(operators):
        raise CanaryError("operators must be sorted by operator_id")
    threshold = integer(manifest["signature_threshold"], "signature_threshold", 2, len(operators))
    observers = manifest["observer_organization_ids"]
    if not isinstance(observers, list) or len(observers) < 2:
        raise CanaryError("at least two observer organizations are required")
    checked_observers = [token(value, "observer organization") for value in observers]
    if checked_observers != sorted(set(checked_observers)):
        raise CanaryError("observer organizations must be unique and sorted")
    operator_organizations = {str(row["organization_id"]) for row in operators.values()}
    if operator_organizations & set(checked_observers):
        raise CanaryError("observer and operator organizations must be declared separately")
    if not isinstance(manifest["independence_limit"], str) or "does not prove" not in manifest["independence_limit"]:
        raise CanaryError("manifest must disclose the machine-verification independence limit")
    if manifest["production_authorized"] is not False or manifest["promotion_effect"] != "NONE":
        raise CanaryError("canary manifest cannot authorize production or promotion")
    validate_signature_set(manifest, operators, threshold)
    return operators


def checkpoint_hash(checkpoint: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json(checkpoint))


def validate_target_observation(
    raw: Any,
    index: int,
    checkpoint_height: int,
    interval: int,
) -> dict[str, Any]:
    row = exact_fields(
        raw,
        {
            "target_id", "state", "exposure_atoms", "new_risk_value_atoms",
            "disable_request_height", "disabled_height", "recovery_authorization_id",
            "recovery_evidence_root",
        },
        f"target_observations[{index}]",
    )
    token(row["target_id"], f"target_observations[{index}].target_id")
    if row["state"] not in STATES:
        raise CanaryError("target state is invalid")
    exposure = integer(row["exposure_atoms"], "exposure_atoms", 0)
    new_risk = integer(row["new_risk_value_atoms"], "new_risk_value_atoms", 0)
    if row["state"] == "ACTIVE":
        if any(row[field] is not None for field in (
            "disable_request_height", "disabled_height", "recovery_authorization_id", "recovery_evidence_root"
        )):
            raise CanaryError("ACTIVE target carries terminal or recovery fields")
    else:
        request_height = integer(row["disable_request_height"], "disable_request_height", 0, checkpoint_height)
        disabled_height = integer(row["disabled_height"], "disabled_height", request_height, checkpoint_height)
        if disabled_height > request_height + interval:
            raise CanaryError("target was not disabled within one checkpoint interval")
        if exposure != 0 or new_risk != 0:
            raise CanaryError("DISABLED/RECOVERING target must have zero exposure and new risk")
        if row["state"] == "DISABLED":
            if row["recovery_authorization_id"] is not None or row["recovery_evidence_root"] is not None:
                raise CanaryError("DISABLED target carries recovery authority")
        else:
            hex64(row["recovery_authorization_id"], "recovery_authorization_id")
            hex64(row["recovery_evidence_root"], "recovery_evidence_root")
    return row


def validate_checkpoint(
    manifest: Mapping[str, Any],
    operators: Mapping[str, Mapping[str, Any]],
    checkpoint: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    exact_fields(
        checkpoint,
        {
            "schema", "canary_id", "source_revision", "chain_id", "genesis_hash", "sequence",
            "previous_checkpoint_sha256", "observed_at_utc", "finalized_height",
            "target_observations", "incidents", "drills", "production_authorized",
            "promotion_effect", "signatures",
        },
        "checkpoint",
    )
    if checkpoint["schema"] != CHECKPOINT_SCHEMA:
        raise CanaryError("wrong checkpoint schema")
    for field in ("canary_id", "source_revision", "chain_id", "genesis_hash"):
        if checkpoint[field] != manifest[field]:
            raise CanaryError(f"checkpoint {field} changed")
    sequence = integer(checkpoint["sequence"], "sequence", 0, MAX_CHECKPOINTS - 1)
    expected_sequence = 0 if previous is None else int(previous["sequence"]) + 1
    expected_previous = "0" * 64 if previous is None else checkpoint_hash(previous)
    if sequence != expected_sequence or checkpoint["previous_checkpoint_sha256"] != expected_previous:
        raise CanaryError("checkpoint sequence or predecessor hash is discontinuous")
    observed = parse_time(checkpoint["observed_at_utc"], "observed_at_utc")
    height = integer(checkpoint["finalized_height"], "finalized_height", 0)
    if previous is not None:
        if observed <= parse_time(previous["observed_at_utc"], "previous observed_at_utc"):
            raise CanaryError("checkpoint wall clock is not strictly increasing")
        if height <= int(previous["finalized_height"]):
            raise CanaryError("finalized height is not strictly increasing")
    if checkpoint["production_authorized"] is not False or checkpoint["promotion_effect"] != "NONE":
        raise CanaryError("checkpoint cannot authorize production or promotion")
    validate_signature_set(checkpoint, operators, int(manifest["signature_threshold"]))

    raw_targets = checkpoint["target_observations"]
    if not isinstance(raw_targets, list):
        raise CanaryError("target_observations must be a list")
    rows = [
        validate_target_observation(raw, index, height, int(manifest["checkpoint_interval_blocks"]))
        for index, raw in enumerate(raw_targets)
    ]
    ids = [row["target_id"] for row in rows]
    if ids != manifest["target_ids"]:
        raise CanaryError("checkpoint target set/order differs from manifest")
    by_target = {str(row["target_id"]): row for row in rows}
    total_exposure = sum(int(row["exposure_atoms"]) for row in rows)
    if total_exposure * 10_000 > int(manifest["eligible_value_atoms"]) * int(manifest["cap_bps"]):
        raise CanaryError("aggregate canary exposure exceeds the basis-point cap")

    incidents_raw = checkpoint["incidents"]
    if not isinstance(incidents_raw, list):
        raise CanaryError("incidents must be a list")
    incidents: list[dict[str, Any]] = []
    incident_targets: set[str] = set()
    incident_ids: set[str] = set()
    for index, raw in enumerate(incidents_raw):
        row = exact_fields(
            raw,
            {"incident_id", "target_id", "detected_height", "disable_requested_height"},
            f"incidents[{index}]",
        )
        incident_id = token(row["incident_id"], "incident_id")
        target_id = token(row["target_id"], "incident target_id")
        if target_id not in by_target or incident_id in incident_ids or target_id in incident_targets:
            raise CanaryError("incident identity or target is duplicate/unknown")
        detected = integer(row["detected_height"], "incident detected_height", 0, height)
        requested = integer(row["disable_requested_height"], "incident disable_requested_height", detected, height)
        incident_ids.add(incident_id)
        incident_targets.add(target_id)
        incidents.append(row)
        target = by_target[target_id]
        if target["state"] != "ACTIVE" and target["disable_request_height"] != requested:
            raise CanaryError("incident disable request does not bind the affected target")

    drills_raw = checkpoint["drills"]
    if not isinstance(drills_raw, list):
        raise CanaryError("drills must be a list")
    drills: list[dict[str, Any]] = []
    drill_ids: set[str] = set()
    observer_set = set(manifest["observer_organization_ids"])
    for index, raw in enumerate(drills_raw):
        row = exact_fields(
            raw,
            {"drill_id", "kind", "target_id", "observer_organization_ids", "verdict"},
            f"drills[{index}]",
        )
        drill_id = token(row["drill_id"], "drill_id")
        if drill_id in drill_ids or row["kind"] not in DRILL_KINDS or row["target_id"] not in by_target:
            raise CanaryError("drill identity, kind, or target is invalid")
        observers = row["observer_organization_ids"]
        if not isinstance(observers, list) or observers != sorted(set(observers)) or len(observers) < 2:
            raise CanaryError("each drill requires two sorted distinct observer organizations")
        if not set(observers) <= observer_set or row["verdict"] != "PASS":
            raise CanaryError("drill observer or verdict is invalid")
        drill_ids.add(drill_id)
        drills.append(row)

    if previous is not None:
        prior_targets = {str(row["target_id"]): row for row in previous["target_observations"]}
        prior_incidents = {str(row["target_id"]): row for row in previous["incidents"]}
        for target_id, current in by_target.items():
            prior = prior_targets[target_id]
            transition = (prior["state"], current["state"])
            if transition not in {
                ("ACTIVE", "ACTIVE"), ("ACTIVE", "DISABLED"),
                ("DISABLED", "DISABLED"), ("DISABLED", "RECOVERING"),
                ("RECOVERING", "RECOVERING"), ("RECOVERING", "ACTIVE"),
                ("RECOVERING", "DISABLED"),
            }:
                raise CanaryError(f"illegal target state transition for {target_id}: {transition}")
            pending = prior_incidents.get(target_id)
            if pending is not None:
                if current["state"] != "DISABLED":
                    raise CanaryError("incident target was not disabled by the next checkpoint")
                if current["disable_request_height"] != pending["disable_requested_height"]:
                    raise CanaryError("incident disable request changed across checkpoints")
            if transition == ("DISABLED", "RECOVERING"):
                if (
                    current["disable_request_height"] != prior["disable_request_height"]
                    or current["disabled_height"] != prior["disabled_height"]
                ):
                    raise CanaryError("target recovery changed the disable lineage")
            if transition == ("RECOVERING", "ACTIVE") and (
                prior["recovery_authorization_id"] is None or prior["recovery_evidence_root"] is None
            ):
                raise CanaryError("target recovery lacks prior authorization/evidence")
    return by_target, incidents, drills


def verify_evidence(manifest: Mapping[str, Any], checkpoints: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    operators = validate_manifest(manifest)
    if not checkpoints:
        blockers = ["no signed canary checkpoints exist"]
        return result(manifest, 0, 0, 0, [], blockers, False)
    previous: Mapping[str, Any] | None = None
    maximum_exposure = 0
    completed_drills: list[dict[str, Any]] = []
    disable_observed = False
    recovery_observed = False
    for checkpoint in checkpoints:
        targets, _, drills = validate_checkpoint(manifest, operators, checkpoint, previous)
        maximum_exposure = max(maximum_exposure, sum(int(row["exposure_atoms"]) for row in targets.values()))
        completed_drills.extend(drills)
        if previous is not None:
            prior_targets = {str(row["target_id"]): row for row in previous["target_observations"]}
            for target_id, current in targets.items():
                transition = (prior_targets[target_id]["state"], current["state"])
                disable_observed |= transition == ("ACTIVE", "DISABLED")
                recovery_observed |= transition == ("RECOVERING", "ACTIVE")
        previous = checkpoint
    assert previous is not None
    first_time = parse_time(checkpoints[0]["observed_at_utc"], "first observed_at_utc")
    last_time = parse_time(checkpoints[-1]["observed_at_utc"], "last observed_at_utc")
    elapsed_seconds = max(0, int((last_time - first_time).total_seconds()))
    kinds = {str(row["kind"]) for row in completed_drills}
    exit_drills = {str(row["drill_id"]) for row in completed_drills if row["kind"] == "exit"}
    blockers: list[str] = []
    missing = sorted(DRILL_KINDS - kinds)
    if missing:
        blockers.append("missing drills: " + ",".join(missing))
    if len(exit_drills) < 2:
        blockers.append("fewer than two independently observed exit drills")
    if not disable_observed:
        blockers.append("no active-to-disabled transition was observed")
    if not recovery_observed:
        blockers.append("no authorized target recovery completed")
    pending_incidents = [str(row["target_id"]) for row in previous["incidents"]]
    if pending_incidents:
        blockers.append("final checkpoint has pending incidents: " + ",".join(sorted(pending_incidents)))
    controls_passed = not blockers
    return result(
        manifest,
        len(checkpoints),
        maximum_exposure,
        elapsed_seconds,
        sorted(kinds),
        blockers,
        controls_passed,
    )


def result(
    manifest: Mapping[str, Any],
    checkpoint_count: int,
    maximum_exposure: int,
    elapsed_seconds: int,
    completed_drills: list[str],
    blockers: list[str],
    controls_passed: bool,
) -> dict[str, Any]:
    eligible = int(manifest["eligible_value_atoms"])
    maximum_bps_ceil = (maximum_exposure * 10_000 + eligible - 1) // eligible
    body = {
        "schema": RESULT_SCHEMA,
        "canary_id": manifest["canary_id"],
        "source_revision": manifest["source_revision"],
        "checkpoint_count": checkpoint_count,
        "maximum_exposure_atoms": maximum_exposure,
        "maximum_exposure_bps_ceil": maximum_bps_ceil,
        "cap_bps": manifest["cap_bps"],
        "elapsed_wall_clock_seconds": elapsed_seconds,
        "required_real_days": REQUIRED_REAL_DAYS,
        "duration_gate": "EXTERNAL_PUBLIC_TIME_VERIFICATION_REQUIRED",
        "completed_drill_kinds": completed_drills,
        "control_contract_passed": controls_passed,
        "blockers": blockers,
        "evidence_mode": manifest["manifest_state"],
        "independent_control_established": False,
        "production_authorized": False,
        "promotion_effect": "NONE",
    }
    return {**body, "result_id": sha256_bytes(canonical_json(body))}


def load_seed(path: Path) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes().strip()
    except OSError as error:
        raise CanaryError(f"cannot read signing seed: {error}") from error
    try:
        seed = bytes.fromhex(raw.decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise CanaryError("signing seed must contain exactly 32 bytes as lowercase hex") from error
    if len(seed) != 32 or raw.decode("ascii") != seed.hex():
        raise CanaryError("signing seed must contain exactly 32 bytes as lowercase hex")
    return Ed25519PrivateKey.from_private_bytes(seed)


def add_signature(
    document: Mapping[str, Any],
    manifest: Mapping[str, Any],
    operator_id: str,
    seed_path: Path,
) -> dict[str, Any]:
    operators = {str(row["operator_id"]): row for row in manifest.get("operators", []) if isinstance(row, dict)}
    operator = operators.get(operator_id)
    if operator is None:
        raise CanaryError("operator_id is not registered by the manifest")
    private = load_seed(seed_path)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    registered = base64.b64decode(operator["public_key_base64"], validate=True)
    if public != registered:
        raise CanaryError("private seed does not match the registered operator public key")
    output = copy.deepcopy(document)
    signatures = output.get("signatures")
    if not isinstance(signatures, list):
        raise CanaryError("document signatures must be a list")
    if any(row.get("operator_id") == operator_id for row in signatures if isinstance(row, dict)):
        raise CanaryError("operator has already signed this document")
    signature = private.sign(signature_message(output, str(output.get("schema"))))
    signatures.append({
        "operator_id": operator_id,
        "key_id": operator["key_id"],
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    })
    signatures.sort(key=lambda row: row["operator_id"])
    return output


def write_new(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except FileExistsError as error:
        raise CanaryError(f"refusing to overwrite {path}") from error
    except OSError as error:
        raise CanaryError(f"cannot create {path}: {error}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    sign_manifest = sub.add_parser("sign-manifest")
    sign_manifest.add_argument("--input", type=Path, required=True)
    sign_manifest.add_argument("--operator-id", required=True)
    sign_manifest.add_argument("--seed", type=Path, required=True)
    sign_manifest.add_argument("--output", type=Path, required=True)
    sign_checkpoint = sub.add_parser("sign-checkpoint")
    sign_checkpoint.add_argument("--manifest", type=Path, required=True)
    sign_checkpoint.add_argument("--input", type=Path, required=True)
    sign_checkpoint.add_argument("--operator-id", required=True)
    sign_checkpoint.add_argument("--seed", type=Path, required=True)
    sign_checkpoint.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "verify":
            manifest = load_json(args.manifest)
            summary = verify_evidence(manifest, load_ledger(args.ledger))
            if args.output is not None:
                write_new(args.output, summary)
            print(json.dumps(summary, sort_keys=True))
            return 0
        if args.command == "sign-manifest":
            document = load_json(args.input)
            if document.get("schema") != MANIFEST_SCHEMA:
                raise CanaryError("sign-manifest input has the wrong schema")
            output = add_signature(document, document, args.operator_id, args.seed)
            write_new(args.output, output)
            return 0
        manifest = load_json(args.manifest)
        validate_manifest(manifest)
        document = load_json(args.input)
        if document.get("schema") != CHECKPOINT_SCHEMA:
            raise CanaryError("sign-checkpoint input has the wrong schema")
        output = add_signature(document, manifest, args.operator_id, args.seed)
        write_new(args.output, output)
        return 0
    except (CanaryError, OSError, ValueError) as error:
        print(f"G4_CANARY_REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
