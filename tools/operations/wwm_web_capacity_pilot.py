#!/usr/bin/env python3
"""Append-only real-duration evidence collector for E-WWM-23.

This collector never enables WWM controls or authorizes production.  A sealed PASS
means only that the exact registered experimental evidence contract validated.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from datetime import date, datetime, time, timedelta, timezone
from itertools import product
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.gates import wwm_evidence_bundle as gate

EXPERIMENT_MANIFEST = ROOT / "experiments" / "wwm-web-capacity" / "experiment.json"
LEDGER_SCHEMA = "noos/e-wwm-23-pilot-ledger/v1"
ENVELOPE_SCHEMA = "noos/e-wwm-23-daily-observation/v1"
SUMMARY_SCHEMA = "noos/e-wwm-23-evidence-summary/v1"
ENVELOPE_DOMAIN = b"NOOS/SIG/WWM/V1\0E-WWM-23-DAILY-OBSERVATION\0"
SUMMARY_DOMAIN = b"NOOS/SIG/WWM/V1\0E-WWM-23-EVIDENCE-SUMMARY\0"
MINIMUM_DURATION = timedelta(days=30)
MAX_FUTURE_SKEW = timedelta(0)
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_OBSERVATIONS = 4096
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ARTIFACT_KIND_PATTERN = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

SPECIAL_ARTIFACT_KINDS = {
    "daily_observation",
    "dependency_receipt",
    "reproduction",
    "second_client_vector",
    "reproducible_build",
    "red_team_engagement",
    "drill",
    "cohort_cell",
    "promotion_hold_record",
    "promotion_hold_evidence",
    "supporting_evidence",
}
ALLOWED_ARTIFACT_KINDS = gate.E23_REQUIRED_ARTIFACT_KINDS | SPECIAL_ARTIFACT_KINDS
REQUIRED_DEPENDENCIES = {"E-WWM-03", "E-WWM-15"}
REQUIRED_PRIVACY = {
    "raw_participant_token": False,
    "raw_ip": False,
    "raw_user_agent": False,
    "summary_only": True,
}
CONFIG_KEYS = {
    "schema",
    "experiment_id",
    "model_id",
    "model_source_sha256",
    "source_revision",
    "evidence_scope",
    "pilot_start_utc",
    "initialized_at_utc",
    "controls_enabled",
    "production_claim",
    "promotion_authorized",
    "trusted_observers",
    "summary_signer_key_id",
}
OBSERVER_KEYS = {
    "observer_id",
    "role",
    "control_cluster_id",
    "public_key_base64",
    "key_id",
}
ENVELOPE_KEYS = {
    "schema",
    "envelope_id",
    "sequence",
    "experiment_id",
    "model_id",
    "source_revision",
    "observed_start_utc",
    "observed_end_utc",
    "submitted_at_utc",
    "artifact_kind",
    "content_path",
    "content_sha256",
    "content_bytes",
    "observer_id",
    "observer_role",
    "control_cluster_id",
    "public_key_base64",
    "key_id",
    "privacy",
    "signature_base64",
}
FORBIDDEN_IDENTITY_KEYS = {
    "participant_token",
    "raw_participant_token",
    "raw_ip",
    "ip_address",
    "raw_user_agent",
    "user_agent",
}
LAB_MARKERS = {
    gate.E23_LAB_REPORT_SCHEMA,
    gate.E23_LAB_STATUS,
    gate.E23_LAB_SCOPE,
    "MEASURED_LAB",
    "TEST_ONLY",
}


class PilotError(ValueError):
    """Pilot evidence is malformed, mutable, untrusted, or incomplete."""


def canonical_json(value: Any) -> bytes:
    return gate.canonical_json(value)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_PATTERN.fullmatch(value):
        raise PilotError(f"{field} must be canonical UTC with second precision")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise PilotError(f"{field} is not a valid UTC timestamp") from error
    return parsed


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_object(path: Path, *, maximum_bytes: int | None = None) -> dict[str, Any]:
    try:
        if maximum_bytes is not None and path.stat().st_size > maximum_bytes:
            raise PilotError(f"{path} exceeds the bounded JSON size")
        value = json.loads(path.read_text(encoding="utf-8"))
    except PilotError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PilotError(f"cannot load JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise PilotError(f"{path} must contain a JSON object")
    return value


def _decode_public(value: Any, key_id: Any) -> bytes:
    try:
        public = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise PilotError("observer public key is not canonical base64") from error
    if len(public) != 32 or not isinstance(key_id, str) or not HEX64.fullmatch(key_id):
        raise PilotError("observer key length or key ID is invalid")
    if sha256_bytes(public) != key_id:
        raise PilotError("observer key ID does not bind its public key")
    return public


def _manifest_contract() -> tuple[dict[str, Any], set[str]]:
    manifest = load_object(EXPERIMENT_MANIFEST)
    if (
        manifest.get("schema") != "noos/registered-experiment/v1"
        or manifest.get("experiment_id") != "E-WWM-23"
        or manifest.get("status") != "EXPERIMENTAL_OFF_CHAIN"
        or manifest.get("duration_days") != 30
    ):
        raise PilotError("registered E-WWM-23 manifest is missing or weakened")
    drills = set(manifest.get("required_drills", []))
    if drills != gate.E23_REQUIRED_DRILLS:
        raise PilotError("registered E-WWM-23 drills differ from the evidence gate")
    required_cells = {
        f"{browser.lower()}_{device}_{storage.lower()}"
        for browser, device, storage in product(
            manifest["required_browsers"],
            manifest["required_device_modes"],
            manifest["required_storage_modes"],
        )
    }
    return manifest, required_cells


def validate_config(config: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    if set(config) != CONFIG_KEYS or config.get("schema") != LEDGER_SCHEMA:
        raise PilotError("pilot ledger fields do not match the closed contract")
    manifest, _ = _manifest_contract()
    model = manifest["model_binding"]
    if (
        config["experiment_id"] != "E-WWM-23"
        or config["model_id"] != model["artifact_id"]
        or config["model_source_sha256"] != model["source_sha256"]
        or not HEX40.fullmatch(str(config["source_revision"]))
    ):
        raise PilotError("pilot experiment, model, or source revision is not exact")
    if config["evidence_scope"] not in {"REAL_PUBLIC_PILOT", "TEST_FIXTURE"}:
        raise PilotError("pilot evidence scope is invalid")
    if (
        config["controls_enabled"] is not False
        or config["production_claim"] is not False
        or config["promotion_authorized"] is not False
    ):
        raise PilotError("pilot configuration cannot enable controls, production, or promotion")
    start = parse_utc(config["pilot_start_utc"], "pilot_start_utc")
    initialized = parse_utc(config["initialized_at_utc"], "initialized_at_utc")
    observed_now = now or datetime.now(timezone.utc)
    if start > initialized or initialized > observed_now + MAX_FUTURE_SKEW:
        raise PilotError("pilot initialization timestamps are impossible or future-dated")
    observers = config["trusted_observers"]
    if not isinstance(observers, list) or not (3 <= len(observers) <= 32):
        raise PilotError("pilot requires a bounded trusted observer allowlist")
    observer_ids: set[str] = set()
    key_ids: set[str] = set()
    roles: set[str] = set()
    for observer in observers:
        if not isinstance(observer, dict) or set(observer) != OBSERVER_KEYS:
            raise PilotError("trusted observer fields are invalid")
        observer_id = observer["observer_id"]
        if not isinstance(observer_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", observer_id):
            raise PilotError("trusted observer ID is invalid")
        if observer["role"] not in gate.ATTESTATION_ROLES:
            raise PilotError("trusted observer role is invalid")
        if not HEX64.fullmatch(str(observer["control_cluster_id"])):
            raise PilotError("trusted observer control cluster is invalid")
        _decode_public(observer["public_key_base64"], observer["key_id"])
        if observer_id in observer_ids or observer["key_id"] in key_ids:
            raise PilotError("trusted observer identity or key is duplicated")
        observer_ids.add(observer_id)
        key_ids.add(observer["key_id"])
        roles.add(observer["role"])
    if roles != gate.ATTESTATION_ROLES:
        raise PilotError("trusted observer allowlist lacks every independent role")
    if config["summary_signer_key_id"] not in key_ids:
        raise PilotError("summary signer is not a trusted observer key")
    return config


def initialize_ledger(ledger: Path, config_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    if ledger.exists():
        raise PilotError("pilot ledger path already exists; initialization is insert-once")
    config = validate_config(load_object(config_path, maximum_bytes=MAX_ENVELOPE_BYTES), now=now)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    staging = ledger.parent / f".{ledger.name}.init-{uuid.uuid4().hex}"
    try:
        staging.mkdir()
        (staging / "observations").mkdir()
        (staging / "artifacts").mkdir()
        with (staging / "ledger.json").open("xb") as handle:
            handle.write(canonical_json(config))
        os.replace(staging, ledger)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return config


def envelope_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in envelope.items() if key not in {"envelope_id", "signature_base64"}}


def envelope_message(envelope: dict[str, Any]) -> bytes:
    return ENVELOPE_DOMAIN + canonical_json(envelope_payload(envelope))


def envelope_id(envelope: dict[str, Any]) -> str:
    return sha256_bytes(envelope_message(envelope))


def _observer_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["key_id"]: row for row in config["trusted_observers"]}


def _safe_content_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or "\\" in value:
        raise PilotError("content_path must be a bounded portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PilotError("content_path must not escape its observation submission")
    return value


def _walk_json(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield None, child
            yield from _walk_json(child)


def _validate_artifact_privacy_and_scope(path: Path, scope: str) -> None:
    disallowed = {
        *(f'"{key}"'.encode("ascii") for key in FORBIDDEN_IDENTITY_KEYS),
        *(marker.lower().encode("utf-8") for marker in LAB_MARKERS),
        b'"real_duration":false',
        b'"real-duration":false',
        b'"controls_enabled":true',
        b'"production_claim":true',
        b'"promotion_authorized":true',
    }
    if scope == "REAL_PUBLIC_PILOT":
        disallowed.update({b'"test_fixture":true', b'"fixture":true'})
    carry = b""
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            compact = b"".join((carry + chunk).lower().split())
            if any(marker in compact for marker in disallowed):
                raise PilotError(
                    "artifact contains raw identity, lab-scope, fixture, or enabled-production data"
                )
            carry = compact[-128:]
    if path.stat().st_size > MAX_ENVELOPE_BYTES:
        return
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return
    for key, value in _walk_json(record):
        if key is not None and key.lower() in FORBIDDEN_IDENTITY_KEYS:
            raise PilotError("artifact contains a raw participant token, IP, or user-agent field")
        if isinstance(value, str) and value in LAB_MARKERS:
            raise PilotError("deterministic/lab-scope artifacts cannot enter the real-duration ledger")
        if key in {"real_duration", "real-duration"} and value is False:
            raise PilotError("non-real-duration artifacts cannot enter the pilot ledger")
        if key in {"controls_enabled", "production_claim", "promotion_authorized"} and value is not False:
            raise PilotError("artifact attempts production, promotion, or control enablement")
        if scope == "REAL_PUBLIC_PILOT" and key in {"test_fixture", "fixture"} and value is True:
            raise PilotError("test fixture artifact cannot enter a real public pilot")


def _artifact_digest(path: Path) -> tuple[int, str]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise PilotError(f"cannot stat observation artifact: {error}") from error
    if size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise PilotError("observation artifact size is outside the bounded contract")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return size, digest.hexdigest()


def _verify_envelope(
    envelope: dict[str, Any],
    config: dict[str, Any],
    *,
    expected_sequence: int,
    now: datetime,
) -> tuple[datetime, datetime, datetime]:
    if set(envelope) != ENVELOPE_KEYS or envelope.get("schema") != ENVELOPE_SCHEMA:
        raise PilotError("observation envelope fields do not match the closed contract")
    if envelope["sequence"] != expected_sequence or not isinstance(envelope["sequence"], int):
        raise PilotError("observation sequence is not the next insert-once value")
    if (
        envelope["experiment_id"] != config["experiment_id"]
        or envelope["model_id"] != config["model_id"]
        or envelope["source_revision"] != config["source_revision"]
    ):
        raise PilotError("observation experiment, model, or source revision is stale")
    kind = envelope["artifact_kind"]
    if kind not in ALLOWED_ARTIFACT_KINDS or not ARTIFACT_KIND_PATTERN.fullmatch(str(kind)):
        raise PilotError("observation artifact kind is not registered and bounded")
    _safe_content_path(envelope["content_path"])
    if not HEX64.fullmatch(str(envelope["content_sha256"])):
        raise PilotError("observation content digest is invalid")
    if not isinstance(envelope["content_bytes"], int) or not (0 < envelope["content_bytes"] <= MAX_ARTIFACT_BYTES):
        raise PilotError("observation content length is invalid")
    if envelope["privacy"] != REQUIRED_PRIVACY:
        raise PilotError("observation does not attest summary-only participant privacy")
    start = parse_utc(envelope["observed_start_utc"], "observed_start_utc")
    end = parse_utc(envelope["observed_end_utc"], "observed_end_utc")
    submitted = parse_utc(envelope["submitted_at_utc"], "submitted_at_utc")
    pilot_start = parse_utc(config["pilot_start_utc"], "pilot_start_utc")
    if start < pilot_start or end <= start or end - start > timedelta(days=1):
        raise PilotError("daily observed interval is invalid or exceeds 24 hours")
    if end > submitted or end > now + MAX_FUTURE_SKEW or submitted > now + MAX_FUTURE_SKEW:
        raise PilotError("observation interval or submission timestamp is future-dated")
    observers = _observer_map(config)
    trusted = observers.get(envelope["key_id"])
    if trusted is None:
        raise PilotError("observation key is not allowlisted")
    if any(
        envelope[field] != trusted[trusted_field]
        for field, trusted_field in (
            ("observer_id", "observer_id"),
            ("observer_role", "role"),
            ("control_cluster_id", "control_cluster_id"),
            ("public_key_base64", "public_key_base64"),
        )
    ):
        raise PilotError("observation signer identity differs from the trusted allowlist")
    if envelope["envelope_id"] != envelope_id(envelope):
        raise PilotError("observation envelope ID does not bind its signed payload")
    try:
        signature = base64.b64decode(envelope["signature_base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise PilotError("observation signature is missing or not canonical base64") from error
    if len(signature) != 64:
        raise PilotError("observation signature is missing or has the wrong length")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(
            _decode_public(envelope["public_key_base64"], envelope["key_id"])
        ).verify(signature, envelope_message(envelope))
    except ImportError as error:
        raise PilotError("cryptography with Ed25519 support is required") from error
    except (ValueError, InvalidSignature) as error:
        raise PilotError("observation Ed25519 signature is forged or invalid") from error
    return start, end, submitted


def _observation_files(ledger: Path) -> list[Path]:
    observations = ledger / "observations"
    if not observations.is_dir():
        raise PilotError("pilot ledger observations directory is missing")
    entries = list(observations.iterdir())
    if any(not path.is_file() for path in entries):
        raise PilotError("pilot ledger contains an unexpected observation entry")
    files = sorted(entries)
    if len(files) > MAX_OBSERVATIONS:
        raise PilotError("pilot ledger exceeds the bounded observation count")
    return files


def load_ledger(
    ledger: Path, *, now: datetime | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    config = validate_config(load_object(ledger / "ledger.json", maximum_bytes=MAX_ENVELOPE_BYTES), now=now)
    observed_now = now or datetime.now(timezone.utc)
    envelopes: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_artifacts: set[tuple[str, str]] = set()
    last_submitted: datetime | None = None
    for sequence, path in enumerate(_observation_files(ledger), start=1):
        envelope = load_object(path, maximum_bytes=MAX_ENVELOPE_BYTES)
        _, _, submitted = _verify_envelope(
            envelope, config, expected_sequence=sequence, now=observed_now
        )
        expected_name = f"{sequence:08d}-{envelope['envelope_id']}.json"
        if path.name != expected_name:
            raise PilotError("observation filename does not bind sequence and envelope ID")
        identity = (envelope["observer_id"], envelope["content_sha256"])
        if envelope["envelope_id"] in seen_ids or identity in seen_artifacts:
            raise PilotError("replayed observer/artifact envelope is present")
        if last_submitted is not None and submitted < last_submitted:
            raise PilotError("observation submission timestamp rolled back")
        artifact = ledger / "artifacts" / envelope["content_sha256"]
        size, digest = _artifact_digest(artifact)
        if size != envelope["content_bytes"] or digest != envelope["content_sha256"]:
            raise PilotError("append-only observation artifact integrity mismatch")
        seen_ids.add(envelope["envelope_id"])
        seen_artifacts.add(identity)
        last_submitted = submitted
        envelopes.append(envelope)
    artifact_dir = ledger / "artifacts"
    if not artifact_dir.is_dir():
        raise PilotError("pilot ledger artifacts directory is missing")
    artifact_entries = list(artifact_dir.iterdir())
    if any(not path.is_file() for path in artifact_entries):
        raise PilotError("pilot ledger contains an unexpected artifact entry")
    if {path.name for path in artifact_entries} != {
        envelope["content_sha256"] for envelope in envelopes
    }:
        raise PilotError("pilot ledger contains missing or unreferenced artifact bytes")
    return config, envelopes


def append_observation(
    ledger: Path,
    envelope_path: Path,
    artifact_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    config, existing = load_ledger(ledger, now=now)
    if len(existing) >= MAX_OBSERVATIONS:
        raise PilotError("pilot ledger has reached its bounded observation count")
    envelope = load_object(envelope_path, maximum_bytes=MAX_ENVELOPE_BYTES)
    observed_now = now or datetime.now(timezone.utc)
    _, _, submitted = _verify_envelope(
        envelope, config, expected_sequence=len(existing) + 1, now=observed_now
    )
    if existing:
        previous = parse_utc(existing[-1]["submitted_at_utc"], "submitted_at_utc")
        if submitted < previous:
            raise PilotError("observation submission timestamp rolled back")
    if any(row["envelope_id"] == envelope["envelope_id"] for row in existing):
        raise PilotError("replayed observation envelope is rejected")
    if any(
        row["content_sha256"] == envelope["content_sha256"]
        or row["content_path"] == envelope["content_path"]
        or (
            row["observer_id"] == envelope["observer_id"]
            and row["content_sha256"] == envelope["content_sha256"]
        )
        for row in existing
    ):
        raise PilotError("duplicate observer/artifact evidence is rejected")
    size, digest = _artifact_digest(artifact_path)
    if size != envelope["content_bytes"] or digest != envelope["content_sha256"]:
        raise PilotError("observation envelope does not bind the supplied artifact bytes")
    _validate_artifact_privacy_and_scope(artifact_path, config["evidence_scope"])
    stored_artifact = ledger / "artifacts" / digest
    if stored_artifact.exists():
        raise PilotError("artifact digest is already present; append-only replay rejected")
    observation_name = f"{envelope['sequence']:08d}-{envelope['envelope_id']}.json"
    stored_envelope = ledger / "observations" / observation_name
    if stored_envelope.exists():
        raise PilotError("observation slot already exists; overwrite rejected")
    try:
        with artifact_path.open("rb") as source, stored_artifact.open("xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        with stored_envelope.open("xb") as target:
            target.write(canonical_json(envelope))
    except Exception:
        if stored_envelope.exists():
            stored_envelope.unlink()
        if stored_artifact.exists():
            stored_artifact.unlink()
        raise
    return envelope


def _artifact_record(ledger: Path, envelope: dict[str, Any]) -> dict[str, Any]:
    return load_object(
        ledger / "artifacts" / envelope["content_sha256"],
        maximum_bytes=MAX_ENVELOPE_BYTES,
    )


def _validate_daily_coverage(ledger: Path, envelopes: list[dict[str, Any]]) -> tuple[datetime, datetime, list[str]]:
    daily = [row for row in envelopes if row["artifact_kind"] == "daily_observation"]
    if not daily:
        raise PilotError("pilot ledger has no signed daily observations")
    days: dict[date, tuple[datetime, datetime]] = {}
    for envelope in daily:
        record = _artifact_record(ledger, envelope)
        if set(record) != {"day_utc", "verdict"} or record.get("verdict") != "PASS":
            raise PilotError("daily observation artifact is malformed or not PASS")
        try:
            record_day = date.fromisoformat(record["day_utc"])
        except (TypeError, ValueError) as error:
            raise PilotError("daily observation day is invalid") from error
        start = parse_utc(envelope["observed_start_utc"], "observed_start_utc")
        end = parse_utc(envelope["observed_end_utc"], "observed_end_utc")
        midnight = datetime.combine(record_day, time.min, tzinfo=timezone.utc)
        if start != midnight or end > midnight + timedelta(days=1):
            raise PilotError("daily observation does not bind its exact UTC day")
        if record_day in days:
            raise PilotError("duplicate signed daily observation")
        days[record_day] = (start, end)
    first = min(start for start, _ in days.values())
    last = max(end for _, end in days.values())
    if last - first < MINIMUM_DURATION:
        raise PilotError("real pilot interval is under 30 elapsed days")
    if any(end != start + timedelta(days=1) for start, end in days.values()):
        raise PilotError("signed daily observations do not provide continuous full-day coverage")
    required_day_count = (last.date() - first.date()).days
    required_days = {first.date() + timedelta(days=index) for index in range(required_day_count)}
    if set(days) != required_days:
        raise PilotError("real pilot ledger has missing UTC observation days")
    return first, last, sorted(day.isoformat() for day in days)


def _validate_complete_contract(
    ledger: Path,
    config: dict[str, Any],
    envelopes: list[dict[str, Any]],
) -> dict[str, Any]:
    first, last, days = _validate_daily_coverage(ledger, envelopes)
    kinds = [row["artifact_kind"] for row in envelopes]
    for kind in gate.E23_REQUIRED_ARTIFACT_KINDS:
        if kinds.count(kind) != 1:
            raise PilotError(f"pilot requires exactly one real observation artifact for {kind}")
    if "second_client_vector" not in kinds:
        raise PilotError("pilot lacks a required second-client vector")
    roles = {row["observer_role"] for row in envelopes}
    clusters = {row["control_cluster_id"] for row in envelopes}
    if roles != gate.ATTESTATION_ROLES or len(clusters) < 3:
        raise PilotError("pilot observations lack independent roles or control clusters")
    records: dict[str, list[dict[str, Any]]] = {}
    for kind in {
        "dependency_receipt",
        "reproduction",
        "reproducible_build",
        "red_team_engagement",
        "drill",
        "cohort_cell",
        "promotion_hold_record",
    }:
        records[kind] = [_artifact_record(ledger, row) for row in envelopes if row["artifact_kind"] == kind]
    dependency_ids = {row.get("requirement_id") for row in records["dependency_receipt"]}
    if dependency_ids != REQUIRED_DEPENDENCIES:
        raise PilotError("pilot lacks every exact dependency receipt")
    successful_reproduction_clusters = {
        row.get("control_cluster_id")
        for row in records["reproduction"]
        if row.get("verdict") == "PASS" and row.get("source_revision") == config["source_revision"]
    }
    if len(successful_reproduction_clusters) < 2:
        raise PilotError("pilot lacks two independent PASS reproductions")
    builder_clusters = {
        row.get("control_cluster_id")
        for row in records["reproducible_build"]
        if row.get("bit_identical") is True and row.get("source_revision") == config["source_revision"]
    }
    if len(builder_clusters) < 2:
        raise PilotError("pilot lacks two independent bit-identical builders")
    if not records["red_team_engagement"]:
        raise PilotError("pilot lacks a funded red-team engagement")
    drills = {row.get("kind"): row.get("verdict") for row in records["drill"]}
    if drills != {kind: "PASS" for kind in gate.E23_REQUIRED_DRILLS}:
        raise PilotError("pilot lacks every exact passing drill")
    _, required_cells = _manifest_contract()
    cells = {row.get("cell_id"): row.get("verdict") for row in records["cohort_cell"]}
    if cells != {cell: "PASS" for cell in required_cells}:
        raise PilotError("pilot lacks every browser/device/storage cohort cell")
    promotion = records["promotion_hold_record"]
    if len(promotion) != 1 or promotion[0].get("decision") != "HOLD":
        raise PilotError("pilot requires one explicit non-promoting HOLD record")
    if config["controls_enabled"] or config["production_claim"] or config["promotion_authorized"]:
        raise PilotError("pilot evidence cannot enable production or controls")
    return {
        "first": first,
        "last": last,
        "days": days,
        "records": records,
        "roles": sorted(roles),
        "clusters": sorted(clusters),
    }


def _copy_submission_artifacts(
    ledger: Path,
    envelopes: list[dict[str, Any]],
    submission: Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    raw: list[dict[str, str]] = []
    vectors: list[dict[str, str]] = []
    for envelope in envelopes:
        digest = envelope["content_sha256"]
        name = f"{envelope['sequence']:04d}-{envelope['artifact_kind']}-{digest}.bin"
        destination = submission / name
        shutil.copyfile(ledger / "artifacts" / digest, destination)
        spec = {"kind": envelope["artifact_kind"], "path": name}
        if envelope["artifact_kind"] == "second_client_vector":
            vectors.append(spec)
        else:
            raw.append(spec)
    return raw, vectors


def prepare_candidate_bundle(
    ledger: Path,
    output: Path,
    *,
    registry_path: Path = gate.DEFAULT_REGISTRY,
    experiments_path: Path = gate.DEFAULT_EXPERIMENTS,
    now: datetime | None = None,
) -> dict[str, Any]:
    if output.exists():
        raise PilotError("candidate bundle output already exists; overwrite rejected")
    config, envelopes = load_ledger(ledger, now=now)
    contract = _validate_complete_contract(ledger, config, envelopes)
    with tempfile.TemporaryDirectory(dir=str(output.parent)) as temporary:
        submission = Path(temporary) / "submission"
        submission.mkdir()
        raw, vectors = _copy_submission_artifacts(ledger, envelopes, submission)
        records = contract["records"]
        environment = {
            "experiment_id": "E-WWM-23",
            "model_id": config["model_id"],
            "model_source_sha256": config["model_source_sha256"],
            "source_revision": config["source_revision"],
            "evidence_scope": config["evidence_scope"],
            "pilot_start_utc": format_utc(contract["first"]),
            "pilot_end_utc": format_utc(contract["last"]),
            "observation_ledger_root": sha256_bytes(
                canonical_json([row["envelope_id"] for row in envelopes])
            ),
        }
        measured = {
            "evidence_scope": config["evidence_scope"],
            "elapsed_seconds": int((contract["last"] - contract["first"]).total_seconds()),
            "observed_utc_days": len(contract["days"]),
            "signed_observation_envelopes": len(envelopes),
            "production_claim": False,
            "promotion_authorized": False,
            "controls_enabled": False,
            "claim_scope": "EXPERIMENTAL_EVIDENCE_ONLY",
        }
        (submission / "environment.json").write_bytes(canonical_json(environment))
        (submission / "measured.json").write_bytes(canonical_json(measured))
        metadata = {
            "verdict": "PASS",
            "raw_artifacts": raw,
            "dependency_receipts": records["dependency_receipt"],
            "reproductions": records["reproduction"],
            "second_client_vectors": vectors,
            "reproducible_builds": records["reproducible_build"],
            "red_team_engagements": records["red_team_engagement"],
            "drills": records["drill"],
            "promotion_record": records["promotion_hold_record"][0],
            "severity1_open_findings": 0,
        }
        (submission / "metadata.json").write_bytes(canonical_json(metadata))
        try:
            return gate.prepare_bundle(
                "E-WWM-23",
                submission,
                output,
                config["source_revision"],
                registry_path,
                experiments_path,
            )
        except gate.EvidenceError as error:
            raise PilotError(f"generic E-WWM-23 evidence validator rejected candidate: {error}") from error


def write_candidate_attestation_payload(
    ledger: Path,
    output: Path,
    *,
    registry_path: Path = gate.DEFAULT_REGISTRY,
    experiments_path: Path = gate.DEFAULT_EXPERIMENTS,
    now: datetime | None = None,
) -> dict[str, Any]:
    if output.exists():
        raise PilotError("attestation payload output already exists; overwrite rejected")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(output.parent)) as temporary:
        candidate = Path(temporary) / "candidate"
        bundle = prepare_candidate_bundle(
            ledger,
            candidate,
            registry_path=registry_path,
            experiments_path=experiments_path,
            now=now,
        )
        message = gate.attestation_message(bundle)
    with output.open("xb") as handle:
        handle.write(message)
    return {"path": str(output), "bytes": len(message), "payload_sha256": sha256_bytes(message)}


def _load_private_key(path: Path):
    try:
        encoded = path.read_bytes()
        raw = encoded if len(encoded) == 32 else base64.b64decode(encoded.strip(), validate=True)
        if len(raw) != 32:
            raise ValueError("wrong length")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return Ed25519PrivateKey.from_private_bytes(raw)
    except (OSError, ValueError, TypeError, ImportError) as error:
        raise PilotError("summary private key must be 32 raw bytes or canonical base64") from error


def _trusted_bundle_attestations(
    candidate: Path,
    config: dict[str, Any],
    attestation_paths: list[Path],
) -> None:
    trusted = _observer_map(config)
    if len(attestation_paths) < 3:
        raise PilotError("candidate seal requires all independent bundle attestations")
    seen: set[str] = set()
    for path in attestation_paths:
        attestation = load_object(path, maximum_bytes=MAX_ENVELOPE_BYTES)
        observer = trusted.get(attestation.get("key_id"))
        if observer is None:
            raise PilotError("bundle attestation key is not on the pilot allowlist")
        if any(
            attestation.get(field) != observer[observer_field]
            for field, observer_field in (
                ("operator_id", "observer_id"),
                ("role", "role"),
                ("control_cluster_id", "control_cluster_id"),
                ("public_key_base64", "public_key_base64"),
            )
        ):
            raise PilotError("bundle attestation identity differs from the pilot allowlist")
        if attestation["key_id"] in seen:
            raise PilotError("duplicate bundle attestation key")
        seen.add(attestation["key_id"])
        try:
            gate.attach_attestation(candidate, path)
        except gate.EvidenceError as error:
            raise PilotError(f"generic bundle attestation rejected: {error}") from error


def _sign_summary(
    summary: dict[str, Any],
    private_key_path: Path,
    config: dict[str, Any],
) -> dict[str, Any]:
    private = _load_private_key(private_key_path)
    from cryptography.hazmat.primitives import serialization

    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = sha256_bytes(public)
    if key_id != config["summary_signer_key_id"]:
        raise PilotError("summary private key is not the configured trusted signer")
    trusted = _observer_map(config)[key_id]
    signed = dict(summary)
    signed["signer_key_id"] = key_id
    signed["signer_public_key_base64"] = trusted["public_key_base64"]
    message = SUMMARY_DOMAIN + canonical_json(signed)
    signed["signature_base64"] = base64.b64encode(private.sign(message)).decode("ascii")
    return signed


def seal_candidate(
    ledger: Path,
    output: Path,
    attestation_paths: list[Path],
    summary_private_key: Path,
    *,
    registry_path: Path = gate.DEFAULT_REGISTRY,
    experiments_path: Path = gate.DEFAULT_EXPERIMENTS,
    now: datetime | None = None,
) -> dict[str, Any]:
    if output.exists():
        raise PilotError("sealed candidate output already exists; overwrite rejected")
    observed_now = now or datetime.now(timezone.utc)
    config, envelopes = load_ledger(ledger, now=observed_now)
    contract = _validate_complete_contract(ledger, config, envelopes)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.parent / f".{output.name}.seal-{uuid.uuid4().hex}"
    try:
        prepare_candidate_bundle(
            ledger,
            staging,
            registry_path=registry_path,
            experiments_path=experiments_path,
            now=observed_now,
        )
        _trusted_bundle_attestations(staging, config, attestation_paths)
        try:
            sealed = gate.seal_bundle(staging, registry_path, experiments_path)
            verified = gate.verify_bundle_directory(
                staging,
                registry_path=registry_path,
                experiments_path=experiments_path,
                expected_revision=config["source_revision"],
                require_sealed=True,
                enforce_pass_policy=True,
            )
        except gate.EvidenceError as error:
            raise PilotError(f"generic 23-claim evidence validator rejected seal: {error}") from error
        if verified["result"]["verdict"] != "PASS":
            raise PilotError("generic 23-claim evidence validator did not return PASS")
        summary = {
            "schema": SUMMARY_SCHEMA,
            "fixture_label": (
                "TEST_FIXTURE"
                if config["evidence_scope"] == "TEST_FIXTURE"
                else "REAL_PUBLIC_PILOT_CANDIDATE"
            ),
            "experiment_id": "E-WWM-23",
            "model_id": config["model_id"],
            "source_revision": config["source_revision"],
            "evidence_scope": config["evidence_scope"],
            "pilot_start_utc": format_utc(contract["first"]),
            "pilot_end_utc": format_utc(contract["last"]),
            "elapsed_seconds": int((contract["last"] - contract["first"]).total_seconds()),
            "observed_utc_days": len(contract["days"]),
            "bundle_id": sealed["bundle_id"],
            "verdict": "PASS",
            "claim_scope": "EXPERIMENTAL_EVIDENCE_ONLY",
            "promotion_authorized": False,
            "production_claim": False,
            "controls_enabled": False,
            "generated_at_utc": format_utc(observed_now),
        }
        signed_summary = _sign_summary(summary, summary_private_key, config)
        with (staging / "EvidenceSummary.json").open("xb") as handle:
            handle.write(canonical_json(signed_summary))
        os.replace(staging, output)
        return signed_summary
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=gate.DEFAULT_REGISTRY)
    parser.add_argument("--experiments", type=Path, default=gate.DEFAULT_EXPERIMENTS)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init")
    initialize.add_argument("--ledger", type=Path, required=True)
    initialize.add_argument("--config", type=Path, required=True)

    append = commands.add_parser("append")
    append.add_argument("--ledger", type=Path, required=True)
    append.add_argument("--envelope", type=Path, required=True)
    append.add_argument("--artifact", type=Path, required=True)

    payload = commands.add_parser("candidate-payload")
    payload.add_argument("--ledger", type=Path, required=True)
    payload.add_argument("--output", type=Path, required=True)

    seal = commands.add_parser("seal")
    seal.add_argument("--ledger", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    seal.add_argument("--attestation", type=Path, action="append", required=True)
    seal.add_argument("--summary-private-key", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "init":
            config = initialize_ledger(args.ledger, args.config)
            emit(
                {
                    "verdict": "INITIALIZED",
                    "experiment_id": config["experiment_id"],
                    "evidence_scope": config["evidence_scope"],
                    "promotion_authorized": False,
                    "production_claim": False,
                }
            )
        elif args.command == "append":
            envelope = append_observation(args.ledger, args.envelope, args.artifact)
            emit(
                {
                    "verdict": "APPENDED",
                    "sequence": envelope["sequence"],
                    "envelope_id": envelope["envelope_id"],
                    "promotion_authorized": False,
                }
            )
        elif args.command == "candidate-payload":
            emit(
                write_candidate_attestation_payload(
                    args.ledger,
                    args.output,
                    registry_path=args.registry,
                    experiments_path=args.experiments,
                )
            )
        else:
            emit(
                seal_candidate(
                    args.ledger,
                    args.output,
                    args.attestation,
                    args.summary_private_key,
                    registry_path=args.registry,
                    experiments_path=args.experiments,
                )
            )
        return 0
    except (PilotError, gate.EvidenceError) as error:
        emit(
            {
                "verdict": "INVALID_EVIDENCE",
                "error": str(error),
                "promotion_authorized": False,
                "production_claim": False,
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
