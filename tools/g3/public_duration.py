#!/usr/bin/env python3
"""Create and verify append-only G3 public-duration evidence.

This tool records what operator-controlled systems report.  It does not represent an
operator as a person, turn simulated time into public time, or treat fixture/test keys
as production evidence.  A completed evidence record is not a G3 promotion verdict.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

HEX_REVISION = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REQUIRED_DRILLS = {"restart", "partition", "ai-off", "blackout", "wan"}
LANE_DAYS = {"application": 30, "cryptographic_economic": 90}
MAX_CHECKPOINT_GAP_SECONDS = 26 * 60 * 60
MAX_TELEMETRY_GAP_SECONDS = 5 * 60
MAX_SIGN_DELAY_SECONDS = 2 * 60 * 60
FRESH_APPEND_SKEW_SECONDS = 5 * 60
PLACEHOLDERS = ("REPLACE_", "OWNER_BLOCKED", "EXTERNAL_BLOCKED", "PENDING_")


class EvidenceError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise EvidenceError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one JSON object")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def format_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_utc(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceError(f"{field} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError(f"{field} is not a valid timestamp") from exc
    return parsed.astimezone(dt.timezone.utc)


def has_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return any(marker in value for marker in PLACEHOLDERS)
    if isinstance(value, list):
        return any(has_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(has_placeholder(item) for item in value.values())
    return False


def public_url(value: Any, field: str, resolve_dns: bool = False) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{field} must be a URL")
    parsed = urllib.parse.urlsplit(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise EvidenceError(f"{field} must be an unauthenticated public https URL")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")):
        raise EvidenceError(f"{field} uses a private-only host")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if "." not in host:
            raise EvidenceError(f"{field} host is not publicly qualified")
    else:
        if not address.is_global:
            raise EvidenceError(f"{field} uses a non-public IP address")
    if resolve_dns:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise EvidenceError(f"{field} public DNS resolution failed: {exc}") from exc
        if not addresses or any(not ipaddress.ip_address(item).is_global for item in addresses):
            raise EvidenceError(f"{field} resolves to a non-public address")
    return value


def exact_fields(value: Any, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        missing = expected - set(value) if isinstance(value, dict) else expected
        extra = set(value) - expected if isinstance(value, dict) else set()
        raise EvidenceError(f"{field} fields mismatch (missing={sorted(missing)}, extra={sorted(extra)})")
    return value


def unsigned_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "manifest_signatures"}


def manifest_hash(manifest: dict[str, Any]) -> str:
    return sha256_bytes(canonical(unsigned_manifest(manifest)))


def checkpoint_payload(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in checkpoint.items() if key != "signatures"}


def payload_hash(checkpoint: dict[str, Any]) -> str:
    return sha256_bytes(canonical(checkpoint_payload(checkpoint)))


def checkpoint_hash(checkpoint: dict[str, Any]) -> str:
    return sha256_bytes(canonical(checkpoint))


def signature_message(payload_sha256: str, operator_id: str, signed_at_utc: str, artifact_kind: str = "daily-checkpoint") -> bytes:
    # This is a release-style detached signature over an exact canonical envelope,
    # not a new protocol signature domain. New NOOS/* crypto contexts may only enter
    # through the frozen crypto-domain registry and its review process.
    return canonical({"artifact_kind": artifact_kind, "operator_id": operator_id, "payload_sha256": payload_sha256, "signed_at_utc": signed_at_utc})


def openssl(args: list[str], *, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(["openssl", *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except FileNotFoundError as exc:
        raise EvidenceError("OpenSSL is required for Ed25519 signing and verification") from exc


def sign_ed25519(private_key: Path, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="noos-g3-sign-") as tmp:
        message_path = Path(tmp) / "message.bin"
        message_path.write_bytes(message)
        completed = openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(private_key), "-in", str(message_path)])
    if completed.returncode != 0 or len(completed.stdout) != 64:
        raise EvidenceError("Ed25519 signing failed: " + completed.stderr.decode(errors="replace").strip())
    return completed.stdout


def verify_ed25519(public_key_pem: str, message: bytes, signature: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="noos-g3-verify-") as tmp:
        public_path = Path(tmp) / "public.pem"
        signature_path = Path(tmp) / "signature.bin"
        message_path = Path(tmp) / "message.bin"
        public_path.write_text(public_key_pem, encoding="ascii")
        signature_path.write_bytes(signature)
        message_path.write_bytes(message)
        completed = openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_path), "-sigfile", str(signature_path), "-in", str(message_path)])
    if completed.returncode != 0:
        raise EvidenceError("invalid Ed25519 operator signature")


def operator_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["operator_id"]: item for item in manifest["operators"]}


def validate_manifest(manifest: dict[str, Any], *, live_dns: bool = False, require_signatures: bool = True) -> None:
    expected = {"schema_version", "manifest_kind", "manifest_state", "network", "release_binding", "evidence_policy", "operators", "lanes", "topology", "drill_schedule", "public_ledger_urls", "manifest_signatures"}
    exact_fields(manifest, expected, "manifest")
    if manifest["schema_version"] != 1 or manifest["manifest_kind"] != "noos-g3-public-duration":
        raise EvidenceError("manifest schema/kind mismatch")
    if manifest["manifest_state"] not in {"TEMPLATE_NOT_STARTED", "TEST_FIXTURE_NOT_EVIDENCE", "ACTIVE"}:
        raise EvidenceError("manifest_state must be TEMPLATE_NOT_STARTED, TEST_FIXTURE_NOT_EVIDENCE, or ACTIVE")
    network = exact_fields(manifest["network"], {"network_id", "chain_id", "genesis_hash", "is_test_network", "asset_label"}, "network")
    if network["is_test_network"] is not True or network["asset_label"] != "NOOS_TEST":
        raise EvidenceError("G3 manifest must bind a valueless NOOS_TEST network")
    release = exact_fields(manifest["release_binding"], {"exact_revision", "release_manifest_path", "release_manifest_sha256", "protocol_version", "api_version"}, "release_binding")
    policy = exact_fields(manifest["evidence_policy"], {"minimum_operators", "minimum_independent_signatures", "checkpoint_period_seconds", "maximum_checkpoint_gap_seconds", "maximum_telemetry_gap_seconds", "maximum_sign_delay_seconds", "simulated_time_accepted", "test_keys_accepted", "promotion_effect"}, "evidence_policy")
    if policy["minimum_operators"] < 3 or policy["minimum_independent_signatures"] < 2 or policy["minimum_independent_signatures"] > policy["minimum_operators"]:
        raise EvidenceError("operator/signature thresholds are too weak")
    if policy["checkpoint_period_seconds"] != 86400 or policy["maximum_checkpoint_gap_seconds"] > MAX_CHECKPOINT_GAP_SECONDS or policy["maximum_telemetry_gap_seconds"] > MAX_TELEMETRY_GAP_SECONDS or policy["maximum_sign_delay_seconds"] > MAX_SIGN_DELAY_SECONDS:
        raise EvidenceError("duration/telemetry/signature policy exceeds hard limits")
    if policy["simulated_time_accepted"] is not False or policy["test_keys_accepted"] is not False or policy["promotion_effect"] != "NONE":
        raise EvidenceError("manifest must reject simulated time/test keys and confer no promotion")
    operators = manifest["operators"]
    if not isinstance(operators, list) or len(operators) < policy["minimum_operators"]:
        raise EvidenceError("manifest lacks the minimum operator topology")
    seen_ids: set[str] = set()
    seen_domains: set[str] = set()
    for index, operator in enumerate(operators):
        exact_fields(operator, {"operator_id", "organization", "control_domain", "region", "infrastructure_provider", "network_carrier", "client_family", "key_id", "key_usage", "public_key_pem", "rpc_url", "telemetry_url", "checkpoint_url"}, f"operators[{index}]")
        if not ID.fullmatch(str(operator["operator_id"])) or operator["operator_id"] in seen_ids:
            raise EvidenceError("operator IDs must be unique stable identifiers")
        control = str(operator["control_domain"]).lower()
        if "." not in control or control in seen_domains:
            raise EvidenceError("operators must declare distinct public control domains")
        seen_ids.add(operator["operator_id"]); seen_domains.add(control)
        for key in ("rpc_url", "telemetry_url", "checkpoint_url"):
            public_url(operator[key], f"operators[{index}].{key}", live_dns and manifest["manifest_state"] == "ACTIVE")
        if operator["key_usage"] not in {"production-evidence", "TEST_ONLY"}:
            raise EvidenceError("operator key_usage must be production-evidence or TEST_ONLY")
        if not isinstance(operator["public_key_pem"], str) or "BEGIN PUBLIC KEY" not in operator["public_key_pem"]:
            raise EvidenceError("operator public key must be an Ed25519 SubjectPublicKeyInfo PEM")
    lanes = manifest["lanes"]
    if not isinstance(lanes, list) or not lanes:
        raise EvidenceError("at least one lane is required")
    classes: set[str] = set()
    for index, lane in enumerate(lanes):
        exact_fields(lane, {"lane_id", "classification", "required_real_days", "authoritative", "telemetry_metric"}, f"lanes[{index}]")
        classification = lane["classification"]
        if classification not in LANE_DAYS or lane["required_real_days"] != LANE_DAYS[classification]:
            raise EvidenceError("lane duration does not match the frozen 30/90-day classification")
        classes.add(classification)
    if classes != set(LANE_DAYS):
        raise EvidenceError("manifest must expose both 30-day application and 90-day cryptographic/economic classes")
    topology = exact_fields(manifest["topology"], {"minimum_regions", "minimum_infrastructure_providers", "minimum_network_carriers", "minimum_client_families"}, "topology")
    for field in topology:
        if not isinstance(topology[field], int) or topology[field] < 2:
            raise EvidenceError(f"topology.{field} must require at least two")
    diversity_fields = {
        "minimum_regions": "region",
        "minimum_infrastructure_providers": "infrastructure_provider",
        "minimum_network_carriers": "network_carrier",
        "minimum_client_families": "client_family",
    }
    for minimum_field, operator_field in diversity_fields.items():
        if len({str(item[operator_field]).strip().lower() for item in operators}) < topology[minimum_field]:
            raise EvidenceError(f"operator topology does not meet {minimum_field}")
    schedule = manifest["drill_schedule"]
    if not isinstance(schedule, list) or len(schedule) != len(REQUIRED_DRILLS) or {item.get("drill_type") for item in schedule if isinstance(item, dict)} != REQUIRED_DRILLS:
        raise EvidenceError("drill schedule must contain exactly restart/partition/ai-off/blackout/wan types")
    drill_ids: set[str] = set()
    for index, drill in enumerate(schedule):
        exact_fields(drill, {"drill_id", "drill_type", "start_after_real_days", "duration_seconds", "required_observers", "instructions"}, f"drill_schedule[{index}]")
        if not ID.fullmatch(str(drill["drill_id"])) or drill["drill_id"] in drill_ids or drill["start_after_real_days"] < 0 or drill["duration_seconds"] <= 0 or drill["required_observers"] < 2:
            raise EvidenceError("invalid drill schedule entry")
        drill_ids.add(drill["drill_id"])
        if drill["drill_type"] == "ai-off" and drill["duration_seconds"] < 7 * 86400:
            raise EvidenceError("AI-off drill must schedule seven uninterrupted real days")
    if not isinstance(manifest["public_ledger_urls"], list) or len(manifest["public_ledger_urls"]) < 2:
        raise EvidenceError("at least two public ledger mirrors are required")
    for index, url in enumerate(manifest["public_ledger_urls"]):
        public_url(url, f"public_ledger_urls[{index}]", live_dns and manifest["manifest_state"] == "ACTIVE")
    if not isinstance(manifest["manifest_signatures"], list):
        raise EvidenceError("manifest_signatures must be an array")
    if manifest["manifest_state"] == "ACTIVE":
        if has_placeholder(manifest):
            raise EvidenceError("active manifest contains blocked/pending placeholders")
        if not HEX_REVISION.fullmatch(str(release["exact_revision"])) or not HEX64.fullmatch(str(release["release_manifest_sha256"])):
            raise EvidenceError("active manifest lacks an exact revision/release-manifest hash")
        if not HEX64.fullmatch(str(network["chain_id"])) or not HEX64.fullmatch(str(network["genesis_hash"])):
            raise EvidenceError("active manifest lacks exact public-testnet identity hashes")
        release_path = Path(release["release_manifest_path"])
        if not release_path.is_file() or sha256_file(release_path) != release["release_manifest_sha256"]:
            raise EvidenceError("release manifest path/hash binding failed")
        release_doc = load_json(release_path)
        release_source = release_doc.get("source", {})
        release_identity = release_doc.get("identity", {})
        release_versions = release_doc.get("release", {})
        if release_source.get("repo_revision") != release["exact_revision"] or release_identity.get("chain_id") != network["chain_id"] or release_identity.get("genesis_hash") != network["genesis_hash"]:
            raise EvidenceError("release manifest does not bind the same revision/network identity")
        if release_versions.get("protocol_version") != release["protocol_version"] or release_versions.get("api_version") != release["api_version"]:
            raise EvidenceError("release manifest protocol/API binding changed")
        if any(operator["key_usage"] != "production-evidence" for operator in operators):
            raise EvidenceError("active manifest contains test-only keys")
        if require_signatures:
            digest = manifest_hash(manifest)
            signed: set[str] = set()
            for index, signature in enumerate(manifest["manifest_signatures"]):
                exact_fields(signature, {"operator_id", "key_id", "algorithm", "payload_sha256", "signed_at_utc", "signature_base64"}, f"manifest_signatures[{index}]")
                operator_id = signature["operator_id"]
                if operator_id in signed or operator_id not in seen_ids:
                    raise EvidenceError("duplicate or unknown manifest signer")
                signed.add(operator_id)
                operator = next(item for item in operators if item["operator_id"] == operator_id)
                parse_utc(signature["signed_at_utc"], "manifest signature time")
                if signature["key_id"] != operator["key_id"] or signature["algorithm"] != "ed25519" or signature["payload_sha256"] != digest:
                    raise EvidenceError("manifest signature binding is invalid")
                try:
                    raw_signature = base64.b64decode(signature["signature_base64"], validate=True)
                except (ValueError, TypeError) as exc:
                    raise EvidenceError("manifest signature is not canonical base64") from exc
                verify_ed25519(operator["public_key_pem"], signature_message(digest, operator_id, signature["signed_at_utc"], "exact-revision-manifest"), raw_signature)
            if len(signed) < policy["minimum_independent_signatures"]:
                raise EvidenceError("active exact-revision manifest lacks independent operator signatures")


def read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                raise EvidenceError(f"ledger line {number} is blank")
            item = json.loads(line, object_pairs_hook=reject_duplicates)
            if not isinstance(item, dict):
                raise EvidenceError(f"ledger line {number} is not an object")
            if canonical(item).decode("utf-8") != line:
                raise EvidenceError(f"ledger line {number} is not canonical JSON")
            records.append(item)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot parse ledger {path}: {exc}") from exc
    return records


def verify_checkpoint(manifest: dict[str, Any], checkpoint: dict[str, Any], previous: dict[str, Any] | None, *, now: dt.datetime) -> None:
    expected = {"schema_version", "record_kind", "network_id", "manifest_sha256", "exact_revision", "sequence", "previous_checkpoint_sha256", "wall_clock", "lane_observations", "operator_observations", "drill_observations", "signatures"}
    exact_fields(checkpoint, expected, "checkpoint")
    if checkpoint["schema_version"] != 1 or checkpoint["record_kind"] != "noos-g3-daily-checkpoint":
        raise EvidenceError("checkpoint schema/kind mismatch")
    if checkpoint["network_id"] != manifest["network"]["network_id"] or checkpoint["manifest_sha256"] != manifest_hash(manifest) or checkpoint["exact_revision"] != manifest["release_binding"]["exact_revision"]:
        raise EvidenceError("checkpoint network/manifest/revision binding changed")
    expected_sequence = 0 if previous is None else previous["sequence"] + 1
    expected_previous = "0" * 64 if previous is None else checkpoint_hash(previous)
    if checkpoint["sequence"] != expected_sequence or checkpoint["previous_checkpoint_sha256"] != expected_previous:
        raise EvidenceError("checkpoint append-only sequence/hash chain is broken")
    wall = exact_fields(checkpoint["wall_clock"], {"observed_at_utc", "unix_time_ns", "monotonic_time_ns", "clock_id", "clock_source", "time_mode"}, "wall_clock")
    observed = parse_utc(wall["observed_at_utc"], "wall_clock.observed_at_utc")
    if wall["time_mode"] != "REAL_WALL_CLOCK" or wall["clock_source"] != "system_utc_plus_monotonic" or not isinstance(wall["unix_time_ns"], int) or not isinstance(wall["monotonic_time_ns"], int):
        raise EvidenceError("simulated or malformed wall-clock record rejected")
    if abs(wall["unix_time_ns"] / 1_000_000_000 - observed.timestamp()) > 1:
        raise EvidenceError("wall-clock timestamp representations disagree")
    if observed > now + dt.timedelta(seconds=FRESH_APPEND_SKEW_SECONDS):
        raise EvidenceError("checkpoint is future-dated")
    if previous is not None:
        prior_wall = previous["wall_clock"]
        prior_time = parse_utc(prior_wall["observed_at_utc"], "previous.wall_clock.observed_at_utc")
        elapsed = (observed - prior_time).total_seconds()
        if elapsed <= 0:
            raise EvidenceError("wall clock rolled back or checkpoint was backdated")
        if elapsed > manifest["evidence_policy"]["maximum_checkpoint_gap_seconds"]:
            raise EvidenceError("daily checkpoint gap exceeds policy")
        if wall["clock_id"] == prior_wall["clock_id"] and wall["monotonic_time_ns"] <= prior_wall["monotonic_time_ns"]:
            raise EvidenceError("monotonic clock rolled back")
        if wall["clock_id"] != prior_wall["clock_id"] and not any(item.get("drill_type") == "restart" and item.get("outcome") == "COMPLETED" for item in checkpoint["drill_observations"]):
            raise EvidenceError("clock/boot identity changed without a signed restart observation")
    lanes = checkpoint["lane_observations"]
    expected_lanes = {item["lane_id"] for item in manifest["lanes"]}
    if not isinstance(lanes, list) or {item.get("lane_id") for item in lanes if isinstance(item, dict)} != expected_lanes:
        raise EvidenceError("checkpoint lane set changed")
    for index, lane in enumerate(lanes):
        exact_fields(lane, {"lane_id", "state", "telemetry_sequence", "sample_count", "window_start_utc", "window_end_utc", "maximum_sample_gap_seconds", "discontinuities"}, f"lane_observations[{index}]")
        if lane["state"] not in {"ACTIVE", "DISABLED_BY_SCHEDULED_DRILL"} or lane["sample_count"] <= 0 or lane["maximum_sample_gap_seconds"] > manifest["evidence_policy"]["maximum_telemetry_gap_seconds"] or lane["discontinuities"] != 0:
            raise EvidenceError("telemetry discontinuity or invalid lane state")
        start = parse_utc(lane["window_start_utc"], "lane.window_start_utc"); end = parse_utc(lane["window_end_utc"], "lane.window_end_utc")
        if start >= end or end > observed + dt.timedelta(minutes=5) or end < observed - dt.timedelta(minutes=10):
            raise EvidenceError("lane telemetry window does not cover checkpoint time")
        if previous is not None:
            prior_lane = next(item for item in previous["lane_observations"] if item["lane_id"] == lane["lane_id"])
            if lane["telemetry_sequence"] <= prior_lane["telemetry_sequence"] or start > parse_utc(prior_lane["window_end_utc"], "prior lane end") + dt.timedelta(seconds=manifest["evidence_policy"]["maximum_telemetry_gap_seconds"]):
                raise EvidenceError("lane telemetry sequence/window is discontinuous")
    observations = checkpoint["operator_observations"]
    operators = operator_map(manifest)
    if not isinstance(observations, list) or {item.get("operator_id") for item in observations if isinstance(item, dict)} != set(operators):
        raise EvidenceError("checkpoint lacks observations from the exact operator topology")
    for index, item in enumerate(observations):
        exact_fields(item, {"operator_id", "telemetry_url", "observed_at_utc", "telemetry_sequence", "chain_height", "finalized_height", "telemetry_sha256", "ai_processes_enabled"}, f"operator_observations[{index}]")
        operator = operators[item["operator_id"]]
        if item["telemetry_url"] != operator["telemetry_url"] or not HEX64.fullmatch(str(item["telemetry_sha256"])):
            raise EvidenceError("operator telemetry source/hash mismatch")
        item_time = parse_utc(item["observed_at_utc"], "operator observation time")
        if abs((item_time - observed).total_seconds()) > 10 * 60 or item["chain_height"] < item["finalized_height"] or min(item["chain_height"], item["finalized_height"], item["telemetry_sequence"]) < 0:
            raise EvidenceError("operator observation is stale or internally inconsistent")
        if previous is not None:
            prior = next(old for old in previous["operator_observations"] if old["operator_id"] == item["operator_id"])
            if item["telemetry_sequence"] <= prior["telemetry_sequence"] or item["chain_height"] < prior["chain_height"] or item["finalized_height"] < prior["finalized_height"]:
                raise EvidenceError("operator telemetry counter rolled back")
    drills = checkpoint["drill_observations"]
    if not isinstance(drills, list):
        raise EvidenceError("drill_observations must be an array")
    scheduled_drills = {item["drill_id"]: item for item in manifest["drill_schedule"]}
    for index, drill in enumerate(drills):
        exact_fields(drill, {"drill_id", "drill_type", "started_at_utc", "ended_at_utc", "outcome", "observer_operator_ids", "raw_evidence_sha256"}, f"drill_observations[{index}]")
        scheduled = scheduled_drills.get(drill["drill_id"])
        if scheduled is None or drill["drill_type"] != scheduled["drill_type"] or drill["outcome"] not in {"IN_PROGRESS", "COMPLETED", "FAILED"} or not HEX64.fullmatch(str(drill["raw_evidence_sha256"])):
            raise EvidenceError("invalid drill observation")
        if len(set(drill["observer_operator_ids"])) < scheduled["required_observers"] or not set(drill["observer_operator_ids"]) <= set(operators):
            raise EvidenceError("drill lacks independent operator observers")
        drill_duration = (parse_utc(drill["ended_at_utc"], "drill end") - parse_utc(drill["started_at_utc"], "drill start")).total_seconds()
        if drill_duration < 0:
            raise EvidenceError("drill ends before it starts")
        if drill["outcome"] == "COMPLETED" and drill_duration < scheduled["duration_seconds"]:
            raise EvidenceError("completed drill did not run for its scheduled real duration")
    signatures = checkpoint["signatures"]
    if not isinstance(signatures, list):
        raise EvidenceError("signatures must be an array")
    seen_signers: set[str] = set()
    digest = payload_hash(checkpoint)
    for index, signature in enumerate(signatures):
        exact_fields(signature, {"operator_id", "key_id", "algorithm", "payload_sha256", "signed_at_utc", "signature_base64"}, f"signatures[{index}]")
        operator_id = signature["operator_id"]
        if operator_id in seen_signers or operator_id not in operators:
            raise EvidenceError("duplicate or unknown checkpoint signer")
        seen_signers.add(operator_id)
        operator = operators[operator_id]
        signed_at = parse_utc(signature["signed_at_utc"], "signature.signed_at_utc")
        delay = (signed_at - observed).total_seconds()
        if signature["key_id"] != operator["key_id"] or signature["algorithm"] != "ed25519" or signature["payload_sha256"] != digest or delay < 0 or delay > manifest["evidence_policy"]["maximum_sign_delay_seconds"] or signed_at > now + dt.timedelta(seconds=FRESH_APPEND_SKEW_SECONDS):
            raise EvidenceError("signature binding/time is invalid or backdated")
        try:
            raw_signature = base64.b64decode(signature["signature_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise EvidenceError("operator signature is not canonical base64") from exc
        if len(raw_signature) != 64:
            raise EvidenceError("operator signature length is invalid")
        verify_ed25519(operator["public_key_pem"], signature_message(digest, operator_id, signature["signed_at_utc"]), raw_signature)
    if len(seen_signers) < manifest["evidence_policy"]["minimum_independent_signatures"]:
        raise EvidenceError("checkpoint lacks independent operator signatures")


def verify_evidence(manifest: dict[str, Any], records: list[dict[str, Any]], *, now: dt.datetime) -> dict[str, Any]:
    validate_manifest(manifest)
    if manifest["manifest_state"] != "ACTIVE":
        return {"status": "NOT_STARTED", "qualifying_real_days": 0, "ai_off_real_days": 0, "lane_status": {}, "blockers": ["exact active G2-revision manifest and production-evidence keys have not been supplied"], "promotion_effect": "NONE"}
    if not records:
        return {"status": "NOT_STARTED", "qualifying_real_days": 0, "ai_off_real_days": 0, "lane_status": {}, "blockers": ["no signed public daily checkpoint exists"], "promotion_effect": "NONE"}
    previous = None
    for record in records:
        verify_checkpoint(manifest, record, previous, now=now)
        previous = record
    first_time = parse_utc(records[0]["wall_clock"]["observed_at_utc"], "first checkpoint time")
    last_time = parse_utc(records[-1]["wall_clock"]["observed_at_utc"], "last checkpoint time")
    real_days = max(0.0, (last_time - first_time).total_seconds() / 86400)
    minimum_signatures = manifest["evidence_policy"]["minimum_independent_signatures"]
    blockers: list[str] = []
    if any(len(record["signatures"]) < minimum_signatures for record in records):
        blockers.append("independent operator signatures are still missing")
    lane_status: dict[str, dict[str, Any]] = {}
    for lane in manifest["lanes"]:
        required = lane["required_real_days"]
        lane_status[lane["lane_id"]] = {"classification": lane["classification"], "required_real_days": required, "observed_real_days": round(real_days, 6), "complete": real_days >= required}
        if real_days < required:
            blockers.append(f"{lane['lane_id']} requires {required - real_days:.6f} more uninterrupted real days")
    ai_off_current_seconds = 0.0
    ai_off_max_seconds = 0.0
    for earlier, later in zip(records, records[1:]):
        if all(not item["ai_processes_enabled"] for item in earlier["operator_observations"]) and all(not item["ai_processes_enabled"] for item in later["operator_observations"]):
            ai_off_current_seconds += (parse_utc(later["wall_clock"]["observed_at_utc"], "AI-off end") - parse_utc(earlier["wall_clock"]["observed_at_utc"], "AI-off start")).total_seconds()
            ai_off_max_seconds = max(ai_off_max_seconds, ai_off_current_seconds)
        else:
            ai_off_current_seconds = 0.0
    ai_off_days = max(0.0, ai_off_max_seconds / 86400)
    if ai_off_days < 7:
        blockers.append(f"AI-off run requires {7 - ai_off_days:.6f} more uninterrupted real public days")
    completed_drills: set[str] = set()
    for record in records:
        for item in record["drill_observations"]:
            if item["outcome"] != "COMPLETED":
                continue
            scheduled = next(entry for entry in manifest["drill_schedule"] if entry["drill_id"] == item["drill_id"])
            scheduled_start = first_time + dt.timedelta(days=scheduled["start_after_real_days"])
            if parse_utc(item["started_at_utc"], "scheduled drill start") >= scheduled_start:
                completed_drills.add(item["drill_type"])
            else:
                blockers.append(f"{item['drill_id']} ran before its preregistered real-time schedule")
    missing_drills = sorted(REQUIRED_DRILLS - completed_drills)
    if missing_drills:
        blockers.append("completed signed drill evidence missing: " + ", ".join(missing_drills))
    status = "EVIDENCE_COMPLETE" if not blockers else "IN_PROGRESS"
    return {"status": status, "qualifying_real_days": round(real_days, 6), "ai_off_real_days": round(ai_off_days, 6), "lane_status": lane_status, "blockers": blockers, "promotion_effect": "NONE"}


def clock_id() -> str:
    boot_id = Path("/proc/sys/kernel/random/boot_id")
    if boot_id.is_file():
        return boot_id.read_text(encoding="ascii").strip()
    approximate_boot = round(time.time() - time.monotonic(), -1)
    return sha256_bytes(f"{platform.node()}:{approximate_boot}".encode())[:32]


def load_json_array(path: Path, label: str) -> list[Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be a JSON array")
    return value


def create_checkpoint(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest)
    validate_manifest(manifest)
    if manifest["manifest_state"] != "ACTIVE":
        raise EvidenceError("cannot create evidence from a template/not-started manifest")
    records = read_ledger(args.ledger)
    now = utc_now()
    checkpoint = {
        "schema_version": 1,
        "record_kind": "noos-g3-daily-checkpoint",
        "network_id": manifest["network"]["network_id"],
        "manifest_sha256": manifest_hash(manifest),
        "exact_revision": manifest["release_binding"]["exact_revision"],
        "sequence": len(records),
        "previous_checkpoint_sha256": "0" * 64 if not records else checkpoint_hash(records[-1]),
        "wall_clock": {"observed_at_utc": format_utc(now), "unix_time_ns": time.time_ns(), "monotonic_time_ns": time.monotonic_ns(), "clock_id": clock_id(), "clock_source": "system_utc_plus_monotonic", "time_mode": "REAL_WALL_CLOCK"},
        "lane_observations": load_json_array(args.lanes, "lane observations"),
        "operator_observations": load_json_array(args.operators, "operator observations"),
        "drill_observations": load_json_array(args.drills, "drill observations"),
        "signatures": [],
    }
    args.output.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Unsigned operator-automation checkpoint created: {args.output}")
    print("status=IN_PROGRESS (independent signatures not yet supplied)")


def sign_checkpoint(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest); checkpoint = load_json(args.checkpoint)
    validate_manifest(manifest)
    operators = operator_map(manifest)
    if args.operator_id not in operators:
        raise EvidenceError("signing operator is not in the manifest")
    if any(item.get("operator_id") == args.operator_id for item in checkpoint.get("signatures", [])):
        raise EvidenceError("operator has already signed this checkpoint")
    operator = operators[args.operator_id]
    signed_at = format_utc(utc_now())
    digest = payload_hash(checkpoint)
    raw = sign_ed25519(args.private_key, signature_message(digest, args.operator_id, signed_at))
    signed = json.loads(json.dumps(checkpoint))
    signed["signatures"].append({"operator_id": args.operator_id, "key_id": operator["key_id"], "algorithm": "ed25519", "payload_sha256": digest, "signed_at_utc": signed_at, "signature_base64": base64.b64encode(raw).decode("ascii")})
    args.output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Checkpoint signed by configured operator key: {args.output}")
    print("A valid signature proves key control; it does not prove a human or organizational independence.")


def sign_manifest(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest)
    validate_manifest(manifest, require_signatures=False)
    operators = operator_map(manifest)
    if args.operator_id not in operators:
        raise EvidenceError("signing operator is not in the manifest")
    if any(item.get("operator_id") == args.operator_id for item in manifest["manifest_signatures"]):
        raise EvidenceError("operator has already signed this manifest")
    operator = operators[args.operator_id]
    signed_at = format_utc(utc_now())
    digest = manifest_hash(manifest)
    raw = sign_ed25519(args.private_key, signature_message(digest, args.operator_id, signed_at, "exact-revision-manifest"))
    signed = json.loads(json.dumps(manifest))
    signed["manifest_signatures"].append({"operator_id": args.operator_id, "key_id": operator["key_id"], "algorithm": "ed25519", "payload_sha256": digest, "signed_at_utc": signed_at, "signature_base64": base64.b64encode(raw).decode("ascii")})
    args.output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Exact-revision manifest signed by configured operator key: {args.output}")
    print("A valid signature proves key control; organizational independence remains external evidence.")


def append_checkpoint(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest); checkpoint = load_json(args.checkpoint)
    validate_manifest(manifest)
    now = utc_now()
    observed = parse_utc(checkpoint["wall_clock"]["observed_at_utc"], "checkpoint time")
    if abs((now - observed).total_seconds()) > FRESH_APPEND_SKEW_SECONDS:
        raise EvidenceError("append refused: checkpoint was not created from the current real wall clock")
    if len(checkpoint["signatures"]) < manifest["evidence_policy"]["minimum_independent_signatures"]:
        raise EvidenceError("append refused: independent operator signature threshold not met")
    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    lock_path = args.ledger.with_name(args.ledger.name + ".append.lock")
    try:
        lock_descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise EvidenceError("another checkpoint append is active (or a stale lock requires operator review)") from exc
    try:
        os.close(lock_descriptor)
        records = read_ledger(args.ledger)
        verify_checkpoint(manifest, checkpoint, records[-1] if records else None, now=now)
        line = canonical(checkpoint) + b"\n"
        descriptor = os.open(args.ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o644)
        try:
            written = os.write(descriptor, line)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if written != len(line):
            raise EvidenceError("short append while writing checkpoint ledger")
    finally:
        lock_path.unlink(missing_ok=True)
    print(f"Append-only checkpoint recorded: sequence={checkpoint['sequence']} sha256={checkpoint_hash(checkpoint)}")
    print("status=IN_PROGRESS (elapsed time and future signatures/drills remain externally supplied)")


def live_probe(manifest: dict[str, Any]) -> None:
    validate_manifest(manifest, live_dns=True)
    for operator in manifest["operators"]:
        request = urllib.request.Request(operator["telemetry_url"], headers={"User-Agent": "noos-g3-verifier/1"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                public_url(response.geturl(), f"redirected telemetry URL for {operator['operator_id']}", resolve_dns=True)
                if response.status != 200 or not response.read(1024):
                    raise EvidenceError(f"public telemetry probe failed for {operator['operator_id']}")
        except (OSError, urllib.error.URLError) as exc:
            raise EvidenceError(f"public telemetry probe failed for {operator['operator_id']}: {exc}") from exc


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__)
    sub = top.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify manifest and append-only duration ledger")
    verify.add_argument("--manifest", type=Path, required=True); verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--live", action="store_true", help="also resolve and probe every public telemetry endpoint")
    verify.add_argument("--json", action="store_true")
    create = sub.add_parser("create-checkpoint", help="create an unsigned checkpoint using only the current clocks")
    create.add_argument("--manifest", type=Path, required=True); create.add_argument("--ledger", type=Path, required=True)
    create.add_argument("--lanes", type=Path, required=True); create.add_argument("--operators", type=Path, required=True); create.add_argument("--drills", type=Path, required=True); create.add_argument("--output", type=Path, required=True)
    sign = sub.add_parser("sign-checkpoint", help="add one configured operator signature to a new file")
    sign.add_argument("--manifest", type=Path, required=True); sign.add_argument("--checkpoint", type=Path, required=True); sign.add_argument("--operator-id", required=True); sign.add_argument("--private-key", type=Path, required=True); sign.add_argument("--output", type=Path, required=True)
    sign_manifest_parser = sub.add_parser("sign-manifest", help="add one configured operator signature to an exact-revision manifest")
    sign_manifest_parser.add_argument("--manifest", type=Path, required=True); sign_manifest_parser.add_argument("--operator-id", required=True); sign_manifest_parser.add_argument("--private-key", type=Path, required=True); sign_manifest_parser.add_argument("--output", type=Path, required=True)
    append = sub.add_parser("append-checkpoint", help="verify and atomically append a freshly created threshold-signed checkpoint")
    append.add_argument("--manifest", type=Path, required=True); append.add_argument("--checkpoint", type=Path, required=True); append.add_argument("--ledger", type=Path, required=True)
    return top


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "create-checkpoint": create_checkpoint(args); return 0
        if args.command == "sign-checkpoint": sign_checkpoint(args); return 0
        if args.command == "sign-manifest": sign_manifest(args); return 0
        if args.command == "append-checkpoint": append_checkpoint(args); return 0
        manifest = load_json(args.manifest); records = read_ledger(args.ledger)
        if args.live and manifest.get("manifest_state") == "ACTIVE": live_probe(manifest)
        result = verify_evidence(manifest, records, now=utc_now())
        if args.json: print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"status={result['status']}")
            print(f"qualifying_real_days={result['qualifying_real_days']}")
            print(f"ai_off_real_days={result['ai_off_real_days']}")
            print("promotion_effect=NONE")
            for blocker in result["blockers"]: print(f"BLOCKER: {blocker}")
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        print("status=IN_PROGRESS")
        print(f"REJECTED: {exc}")
        print("promotion_effect=NONE")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
