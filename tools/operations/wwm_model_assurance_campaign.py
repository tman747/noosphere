from __future__ import annotations

import argparse
import base64
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


CAMPAIGN_SCHEMA = "noos/wwm-model-assurance-campaign/v1"
REPORT_SCHEMA = "noos/wwm-model-assurance-report/v1"
RESULT_SCHEMA = "noos/wwm-model-assurance-result/v1"
CAMPAIGN_DOMAIN = b"NOOS/SIG/WWM-MODEL-ASSURANCE-CAMPAIGN/V1\0"
REPORT_DOMAIN = b"NOOS/SIG/WWM-MODEL-ASSURANCE-REPORT/V1\0"
RESULT_DOMAIN = b"NOOS/SIG/WWM-MODEL-ASSURANCE-RESULT/V1\0"
CAMPAIGN_ID_DOMAIN = b"NOOS/WWM/MODEL-ASSURANCE-CAMPAIGN/V1\0"
REPORT_ID_DOMAIN = b"NOOS/WWM/MODEL-ASSURANCE-REPORT/V1\0"
RESULT_ID_DOMAIN = b"NOOS/WWM/MODEL-ASSURANCE-RESULT/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_REPORTS = 100_000
REGISTERED_PARAMETERS = 494_000_000
MINIMUM_OPERATOR_INSTANCES = 1_000_000_000
MINIMUM_CUSTODY_DURATION_SECONDS = 30 * 24 * 60 * 60
MINIMUM_HONEST_CHUNKS = 1_000_000
REQUIRED_OPERATORS = frozenset(
    {
        "tokenizer",
        "quantize",
        "dequantize",
        "rms_norm",
        "matmul",
        "rope",
        "silu",
        "softmax",
        "kv_evolution",
        "logits",
        "greedy_decode",
    }
)
CUSTODY_FAULTS = frozenset(
    {"random_loss", "correlated_loss", "poison", "replay", "repair", "reconstruction"}
)
DISPUTE_FAULTS = frozenset(
    {
        "gemm",
        "normalization",
        "rope",
        "activation",
        "kv",
        "logit",
        "token",
        "history",
        "deadline",
        "evidence",
        "equivocation",
    }
)
LATENCY_FAULTS = frozenset(
    {"baseline", "packet_loss", "worker_crash", "slow_member", "chain_load"}
)
CONCURRENCY_LEVELS = frozenset({1, 4, 16, 64})
KINDS = frozenset({"CROSS_VENDOR", "CUSTODY", "DISPUTE", "LATENCY"})
PLATFORMS = frozenset({"cpu", "amd", "nvidia", "storage", "challenger", "committee"})
ROLES = frozenset({"implementation", "custodian", "challenger", "committee"})


class CampaignError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_object(path: Path, maximum_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        if resolved.stat().st_size > maximum_bytes:
            raise CampaignError(f"JSON exceeds byte bound: {resolved.name}")
        value = json.loads(resolved.read_bytes())
    except (OSError, ValueError) as error:
        raise CampaignError(f"cannot load model-assurance JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise CampaignError("model-assurance JSON must be an object")
    return value


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise CampaignError(f"cannot atomically write {path}: {error}") from error


def parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise CampaignError(f"{field} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise CampaignError(f"{field} is not a valid UTC timestamp") from error
    return parsed


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require_hex(value: object, field: str, pattern: re.Pattern[str] = HEX64) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CampaignError(f"{field} must be canonical lowercase hex")
    return value


def require_token(value: object, field: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise CampaignError(f"{field} must be a canonical token")
    return value


def require_uint(value: object, field: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise CampaignError(f"{field} must be an integer within {minimum}..{maximum}")
    return value


def decode_public(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise CampaignError(f"{field} must be base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise CampaignError(f"{field} is not canonical base64") from error
    if len(decoded) != 32:
        raise CampaignError(f"{field} must contain one Ed25519 public key")
    return decoded


def decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise CampaignError("signature must be base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise CampaignError("signature is not canonical base64") from error
    if len(decoded) != 64:
        raise CampaignError("signature must contain one Ed25519 signature")
    return decoded


def load_seed(path: Path) -> bytes:
    try:
        raw = path.resolve(strict=True).read_bytes()
    except OSError as error:
        raise CampaignError(f"cannot read signing seed {path}: {error}") from error
    if len(raw) == 32:
        return raw
    try:
        decoded = base64.b64decode(raw.strip(), validate=True)
    except ValueError as error:
        raise CampaignError("signing seed must be 32 raw bytes or canonical base64") from error
    if len(decoded) != 32:
        raise CampaignError("signing seed must decode to exactly 32 bytes")
    return decoded


def public_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes_raw()


def identifier(body: dict[str, Any], field: str, domain: bytes) -> str:
    payload = dict(body)
    payload.pop(field, None)
    return sha256(domain + canonical_json(payload))


def sign_envelope(schema: str, body: dict[str, Any], seed: bytes, domain: bytes) -> dict[str, Any]:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = public_bytes(private)
    return {
        "schema": schema,
        "body": body,
        "attestation": {
            "key_id": sha256(public),
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "signature_base64": base64.b64encode(private.sign(domain + canonical_json(body))).decode("ascii"),
        },
    }


def verify_envelope(
    document: object,
    *,
    schema: str,
    domain: bytes,
    expected_public: bytes | None = None,
) -> tuple[dict[str, Any], bytes]:
    if not isinstance(document, dict) or set(document) != {"schema", "body", "attestation"}:
        raise CampaignError("signed model-assurance envelope is malformed")
    if document.get("schema") != schema:
        raise CampaignError("signed model-assurance envelope schema mismatch")
    body = document.get("body")
    attestation = document.get("attestation")
    if not isinstance(body, dict) or not isinstance(attestation, dict):
        raise CampaignError("signed model-assurance body or attestation is malformed")
    if set(attestation) != {"key_id", "public_key_base64", "signature_base64"}:
        raise CampaignError("model-assurance attestation fields are not exact")
    public = decode_public(attestation.get("public_key_base64"), "attestation public key")
    if attestation.get("key_id") != sha256(public):
        raise CampaignError("model-assurance attestation key ID mismatch")
    if expected_public is not None and public != expected_public:
        raise CampaignError("model-assurance report signer is not the registered participant")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(attestation.get("signature_base64")), domain + canonical_json(body)
        )
    except InvalidSignature as error:
        raise CampaignError("model-assurance signature is invalid") from error
    return body, public


def validate_model(model: object) -> dict[str, Any]:
    fields = {
        "parameter_count",
        "source_checkpoint_root",
        "weight_manifest_root",
        "tokenizer_root",
        "numeric_profile_id",
        "runtime_root",
    }
    if not isinstance(model, dict) or set(model) != fields:
        raise CampaignError("registered model identity fields are not exact")
    if model.get("parameter_count") != REGISTERED_PARAMETERS:
        raise CampaignError("campaign is not bound to the registered 494M model")
    for field in fields - {"parameter_count"}:
        require_hex(model.get(field), f"model {field}")
    return model


def validate_participant(value: object) -> dict[str, Any]:
    fields = {
        "participant_id",
        "organization_id",
        "role",
        "region",
        "platform",
        "implementation_lineage",
        "adapter_sha256",
        "funded",
        "key_id",
        "public_key_base64",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CampaignError("participant fields are not exact")
    require_token(value.get("participant_id"), "participant ID")
    require_token(value.get("organization_id"), "participant organization ID")
    require_token(value.get("region"), "participant region")
    require_token(value.get("implementation_lineage"), "participant implementation lineage")
    if value.get("role") not in ROLES or value.get("platform") not in PLATFORMS:
        raise CampaignError("participant role or platform is not registered")
    require_hex(value.get("adapter_sha256"), "participant adapter SHA-256")
    if value.get("funded") is not True:
        raise CampaignError("campaign participants must be explicitly funded")
    public = decode_public(value.get("public_key_base64"), "participant public key")
    if value.get("key_id") != sha256(public):
        raise CampaignError("participant key ID does not match its public key")
    return value


def exact_tokens(value: object, expected: frozenset[str], field: str) -> None:
    if not isinstance(value, list) or len(value) != len(expected):
        raise CampaignError(f"{field} must contain the exact registered set")
    if any(not isinstance(item, str) for item in value):
        raise CampaignError(f"{field} entries must be strings")
    if set(value) != expected:
        raise CampaignError(f"{field} must contain the exact registered set")


def validate_configuration(kind: str, configuration: object) -> dict[str, Any]:
    if not isinstance(configuration, dict):
        raise CampaignError("campaign configuration must be an object")
    if kind == "CROSS_VENDOR":
        fields = {
            "vector_manifest_sha256",
            "required_operators",
            "minimum_operator_instances_per_implementation",
            "minimum_cpu_lineages",
            "required_platforms",
        }
        if set(configuration) != fields:
            raise CampaignError("cross-vendor configuration fields are not exact")
        require_hex(configuration.get("vector_manifest_sha256"), "vector manifest SHA-256")
        exact_tokens(configuration.get("required_operators"), REQUIRED_OPERATORS, "required operators")
        if configuration.get("minimum_operator_instances_per_implementation") != MINIMUM_OPERATOR_INSTANCES:
            raise CampaignError("cross-vendor minimum must be one billion instances per implementation")
        if configuration.get("minimum_cpu_lineages") != 2:
            raise CampaignError("cross-vendor campaign requires two CPU lineages")
        exact_tokens(configuration.get("required_platforms"), frozenset({"cpu", "amd", "nvidia"}), "required platforms")
    elif kind == "CUSTODY":
        fields = {
            "minimum_custodians",
            "minimum_regions",
            "minimum_duration_seconds",
            "minimum_retrieval_success_ppm",
            "required_fault_classes",
            "weight_shard_min_bytes",
            "weight_shard_max_bytes",
        }
        if set(configuration) != fields:
            raise CampaignError("custody configuration fields are not exact")
        expected = {
            "minimum_custodians": 5,
            "minimum_regions": 3,
            "minimum_duration_seconds": MINIMUM_CUSTODY_DURATION_SECONDS,
            "minimum_retrieval_success_ppm": 999_000,
            "weight_shard_min_bytes": 4 * 1024 * 1024,
            "weight_shard_max_bytes": 16 * 1024 * 1024,
        }
        if any(configuration.get(field) != value for field, value in expected.items()):
            raise CampaignError("custody configuration weakens a registered threshold")
        exact_tokens(configuration.get("required_fault_classes"), CUSTODY_FAULTS, "custody fault classes")
    elif kind == "DISPUTE":
        fields = {
            "tree_depth",
            "required_fault_classes",
            "minimum_honest_chunks",
            "terminal_max_seconds",
            "expected_rounds",
            "round_tolerance",
            "expected_transactions",
            "transaction_tolerance",
            "expected_transcript_bytes",
            "transcript_byte_tolerance",
        }
        if set(configuration) != fields:
            raise CampaignError("dispute configuration fields are not exact")
        expected = {
            "tree_depth": 32,
            "minimum_honest_chunks": MINIMUM_HONEST_CHUNKS,
            "terminal_max_seconds": 6 * 60 * 60,
            "expected_rounds": 19,
            "round_tolerance": 1,
            "expected_transactions": 40,
            "transaction_tolerance": 2,
            "expected_transcript_bytes": 8_100,
            "transcript_byte_tolerance": 1_024,
        }
        if any(configuration.get(field) != value for field, value in expected.items()):
            raise CampaignError("dispute configuration weakens a registered threshold")
        exact_tokens(configuration.get("required_fault_classes"), DISPUTE_FAULTS, "dispute fault classes")
    elif kind == "LATENCY":
        fields = {
            "concurrency_levels",
            "fault_classes",
            "minimum_completion_ppm",
            "committed_token_p95_max_ms",
            "committed_token_p99_max_ms",
            "maximum_consensus_degradation_ppm",
        }
        if set(configuration) != fields:
            raise CampaignError("latency configuration fields are not exact")
        levels = configuration.get("concurrency_levels")
        if (
            not isinstance(levels, list)
            or any(not isinstance(value, int) or isinstance(value, bool) for value in levels)
            or set(levels) != CONCURRENCY_LEVELS
        ):
            raise CampaignError("latency concurrency levels are not the registered matrix")
        exact_tokens(configuration.get("fault_classes"), LATENCY_FAULTS, "latency fault classes")
        expected = {
            "minimum_completion_ppm": 999_000,
            "committed_token_p95_max_ms": 2_000,
            "committed_token_p99_max_ms": 5_000,
            "maximum_consensus_degradation_ppm": 50_000,
        }
        if any(configuration.get(field) != value for field, value in expected.items()):
            raise CampaignError("latency configuration weakens a registered threshold")
    else:
        raise CampaignError("campaign kind is not registered")
    return configuration


def validate_campaign_body(body: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    fields = {
        "campaign_id",
        "kind",
        "source_revision",
        "release_version",
        "production",
        "promotion_effect",
        "started_at_utc",
        "ends_at_utc",
        "model",
        "participants",
        "configuration",
    }
    if set(body) != fields:
        raise CampaignError("campaign body fields are not exact")
    if body.get("kind") not in KINDS:
        raise CampaignError("campaign kind is not registered")
    revision = require_hex(body.get("source_revision"), "campaign source revision", HEX40)
    if body.get("release_version") != f"0.1.0+git.{revision}":
        raise CampaignError("campaign release version is not exact")
    if body.get("production") is not False or body.get("promotion_effect") != "NONE":
        raise CampaignError("model-assurance campaign must remain non-promoting")
    start = parse_utc(body.get("started_at_utc"), "campaign start")
    end = parse_utc(body.get("ends_at_utc"), "campaign end")
    if end <= start:
        raise CampaignError("campaign end must follow campaign start")
    validate_model(body.get("model"))
    participants = body.get("participants")
    if not isinstance(participants, list) or not participants or len(participants) > 1_024:
        raise CampaignError("campaign participant inventory is empty or oversized")
    validated = [validate_participant(row) for row in participants]
    for field in ("participant_id", "key_id"):
        values = [row[field] for row in validated]
        if len(values) != len(set(values)):
            raise CampaignError(f"campaign participant {field} is duplicated")
    validate_configuration(str(body["kind"]), body.get("configuration"))
    if body.get("campaign_id") != identifier(body, "campaign_id", CAMPAIGN_ID_DOMAIN):
        raise CampaignError("campaign ID is not content-derived")
    return body


def validate_campaign(document: dict[str, Any], *, now: datetime | None = None) -> tuple[dict[str, Any], bytes]:
    body, public = verify_envelope(document, schema=CAMPAIGN_SCHEMA, domain=CAMPAIGN_DOMAIN)
    return validate_campaign_body(body, now=now), public


def freeze_campaign(draft: dict[str, Any], seed: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    if "campaign_id" in draft:
        raise CampaignError("campaign draft must not supply a campaign ID")
    body = dict(draft)
    body["campaign_id"] = identifier(body, "campaign_id", CAMPAIGN_ID_DOMAIN)
    validate_campaign_body(body, now=now)
    return sign_envelope(CAMPAIGN_SCHEMA, body, seed, CAMPAIGN_DOMAIN)


def participant_map(campaign: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["participant_id"]: row for row in campaign["participants"]}


def validate_artifacts(value: object) -> dict[str, str]:
    fields = {"raw_log_sha256", "environment_manifest_sha256", "result_artifact_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise CampaignError("report artifact fields are not exact")
    for field in fields:
        require_hex(value.get(field), f"report {field}")
    return value


def validate_report_body(
    body: dict[str, Any],
    campaign: dict[str, Any],
    participant: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    fields = {
        "report_id",
        "campaign_id",
        "kind",
        "participant_id",
        "observed_start_utc",
        "observed_end_utc",
        "artifacts",
        "metrics",
    }
    if set(body) != fields:
        raise CampaignError("model-assurance report fields are not exact")
    if body.get("campaign_id") != campaign["campaign_id"] or body.get("kind") != campaign["kind"]:
        raise CampaignError("report campaign binding mismatch")
    if body.get("participant_id") != participant["participant_id"]:
        raise CampaignError("report participant binding mismatch")
    start = parse_utc(body.get("observed_start_utc"), "report start")
    end = parse_utc(body.get("observed_end_utc"), "report end")
    campaign_start = parse_utc(campaign["started_at_utc"], "campaign start")
    campaign_end = parse_utc(campaign["ends_at_utc"], "campaign end")
    if end < start or start < campaign_start or end > campaign_end:
        raise CampaignError("report observation is outside the frozen campaign window")
    if now is not None and end > now:
        raise CampaignError("report observation ends in the future")
    validate_artifacts(body.get("artifacts"))
    if not isinstance(body.get("metrics"), dict):
        raise CampaignError("report metrics must be an object")
    if body.get("report_id") != identifier(body, "report_id", REPORT_ID_DOMAIN):
        raise CampaignError("report ID is not content-derived")
    return body


def sign_report(
    campaign_document: dict[str, Any],
    participant_id: str,
    draft: dict[str, Any],
    seed: bytes,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    campaign, _ = validate_campaign(campaign_document, now=now)
    participants = participant_map(campaign)
    participant = participants.get(participant_id)
    if participant is None:
        raise CampaignError("report signer is not a campaign participant")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    if public_bytes(private) != decode_public(participant["public_key_base64"], "participant public key"):
        raise CampaignError("report signing seed does not match the registered participant")
    forbidden = {"report_id", "campaign_id", "kind", "participant_id"} & set(draft)
    if forbidden:
        raise CampaignError("report draft must not supply derived campaign fields")
    body = {
        "campaign_id": campaign["campaign_id"],
        "kind": campaign["kind"],
        "participant_id": participant_id,
        **draft,
    }
    body["report_id"] = identifier(body, "report_id", REPORT_ID_DOMAIN)
    validate_report_body(body, campaign, participant, now=now)
    return sign_envelope(REPORT_SCHEMA, body, seed, REPORT_DOMAIN)


def load_reports(
    directory: Path,
    campaign: dict[str, Any],
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    try:
        resolved = directory.resolve(strict=True)
    except OSError as error:
        raise CampaignError(f"cannot resolve report directory: {error}") from error
    if not resolved.is_dir():
        raise CampaignError("report path is not a directory")
    paths = sorted(resolved.glob("*.json"))
    if not paths or len(paths) > MAX_REPORTS:
        raise CampaignError("campaign report inventory is empty or oversized")
    participants = participant_map(campaign)
    reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        document = load_object(path)
        raw_body = document.get("body")
        participant_id = raw_body.get("participant_id") if isinstance(raw_body, dict) else None
        participant = participants.get(str(participant_id))
        if participant is None:
            raise CampaignError(f"report {path.name} uses an unregistered participant")
        expected_public = decode_public(participant["public_key_base64"], "participant public key")
        body, _ = verify_envelope(
            document,
            schema=REPORT_SCHEMA,
            domain=REPORT_DOMAIN,
            expected_public=expected_public,
        )
        validate_report_body(body, campaign, participant, now=now)
        report_id = str(body["report_id"])
        if report_id in seen:
            raise CampaignError("campaign report ID is duplicated")
        seen.add(report_id)
        reports.append(body)
    return reports


def require_metric_fields(metrics: dict[str, Any], expected: set[str], label: str) -> None:
    if set(metrics) != expected:
        raise CampaignError(f"{label} metric fields are not exact")


def aggregate_cross_vendor(campaign: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    participants = participant_map(campaign)
    implementations = [row for row in participants.values() if row["role"] == "implementation"]
    if len(implementations) != len(participants):
        raise CampaignError("cross-vendor campaign may contain only implementation participants")
    by_platform: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for participant in implementations:
        by_platform[participant["platform"]].append(participant)
    if set(by_platform) != {"cpu", "amd", "nvidia"} or len(by_platform["cpu"]) < 2:
        raise CampaignError("cross-vendor campaign lacks two CPU, AMD, and NVIDIA implementations")
    if len({row["implementation_lineage"] for row in by_platform["cpu"]}) < 2:
        raise CampaignError("CPU implementations do not have independent lineages")
    if len({row["organization_id"] for row in implementations}) != len(implementations):
        raise CampaignError("cross-vendor implementations are not organization-independent")

    expected_fields = {
        "segment_id",
        "operator_instances",
        "operator_counts",
        "execution_root",
        "mismatch_count",
        "fallback_count",
        "mismatch_reproducer_count",
        "vector_count",
    }
    segments: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    totals: dict[str, int] = defaultdict(int)
    for report in reports:
        metrics = report["metrics"]
        require_metric_fields(metrics, expected_fields, "cross-vendor")
        segment = require_hex(metrics.get("segment_id"), "conformance segment ID")
        participant_id = str(report["participant_id"])
        if participant_id in segments[segment]:
            raise CampaignError("implementation submitted a duplicate conformance segment")
        instances = require_uint(metrics.get("operator_instances"), "operator instance count", minimum=1)
        counts = metrics.get("operator_counts")
        if not isinstance(counts, dict) or set(counts) != REQUIRED_OPERATORS:
            raise CampaignError("operator count inventory is not exact")
        validated_counts = {
            operator: require_uint(counts[operator], f"{operator} instance count", minimum=1)
            for operator in sorted(REQUIRED_OPERATORS)
        }
        if sum(validated_counts.values()) != instances:
            raise CampaignError("operator counts do not conserve the declared instance total")
        require_hex(metrics.get("execution_root"), "execution transcript root")
        require_uint(metrics.get("vector_count"), "vector count", minimum=1)
        for field in ("mismatch_count", "fallback_count", "mismatch_reproducer_count"):
            if metrics.get(field) != 0:
                raise CampaignError(f"cross-vendor {field} must be zero")
        segments[segment][participant_id] = metrics
        totals[participant_id] += instances
    expected_participants = set(participants)
    if any(set(segment) != expected_participants for segment in segments.values()):
        raise CampaignError("every conformance segment must be replayed by every implementation")
    if set(totals) != expected_participants:
        raise CampaignError("cross-vendor participant coverage is incomplete")
    if any(total < MINIMUM_OPERATOR_INSTANCES for total in totals.values()):
        raise CampaignError("every implementation must execute at least one billion operator instances")
    for segment_reports in segments.values():
        roots = {row["execution_root"] for row in segment_reports.values()}
        operator_counts = {canonical_json(row["operator_counts"]) for row in segment_reports.values()}
        vector_counts = {row["vector_count"] for row in segment_reports.values()}
        if len(roots) != 1 or len(operator_counts) != 1 or len(vector_counts) != 1:
            raise CampaignError("cross-vendor segment outputs or coverage diverge")
    return {
        "implementations": len(implementations),
        "cpu_lineages": len({row["implementation_lineage"] for row in by_platform["cpu"]}),
        "platforms": sorted(by_platform),
        "segments": len(segments),
        "operator_instances_by_participant": dict(sorted(totals.items())),
        "minimum_operator_instances_per_implementation": min(totals.values()),
        "mismatches": 0,
        "fallbacks": 0,
        "verdict": "PASS",
    }


def campaign_days(start: datetime, end: datetime) -> set[str]:
    days: set[str] = set()
    current = start.date()
    while datetime.combine(current, datetime.min.time(), tzinfo=timezone.utc) < end:
        days.add(current.isoformat())
        current += timedelta(days=1)
    return days


def aggregate_custody(campaign: dict[str, Any], reports: list[dict[str, Any]], *, now: datetime) -> dict[str, Any]:
    start = parse_utc(campaign["started_at_utc"], "campaign start")
    end = parse_utc(campaign["ends_at_utc"], "campaign end")
    if end > now or int((end - start).total_seconds()) < MINIMUM_CUSTODY_DURATION_SECONDS:
        raise CampaignError("custody campaign has not completed thirty real days")
    participants = participant_map(campaign)
    custodians = [row for row in participants.values() if row["role"] == "custodian" and row["platform"] == "storage"]
    if len(custodians) != len(participants) or len(custodians) < 5:
        raise CampaignError("custody campaign requires at least five storage custodians")
    if len({row["organization_id"] for row in custodians}) != len(custodians):
        raise CampaignError("custodians are not organization-independent")
    if len({row["region"] for row in custodians}) < 3:
        raise CampaignError("custody campaign covers fewer than three regions")
    expected_days = campaign_days(start, end)
    expected_fields = {
        "day_utc",
        "retrieval_attempts",
        "retrieval_successes",
        "corrupt_shards_observed",
        "corrupt_shards_rejected",
        "replayed_shards_observed",
        "replayed_shards_rejected",
        "reconstruction_attempts",
        "reconstruction_successes",
        "permitted_loss_attempts",
        "permitted_loss_successes",
        "false_availability_events",
        "repair_bytes",
        "fault_classes",
        "maximum_reconstruction_ms",
    }
    coverage: dict[str, set[str]] = defaultdict(set)
    totals: dict[str, int] = defaultdict(int)
    faults: set[str] = set()
    maximum_reconstruction_ms = 0
    for report in reports:
        metrics = report["metrics"]
        require_metric_fields(metrics, expected_fields, "custody")
        participant_id = str(report["participant_id"])
        day_value = metrics.get("day_utc")
        if not isinstance(day_value, str) or not DAY.fullmatch(day_value) or day_value not in expected_days:
            raise CampaignError("custody report day is outside the required campaign days")
        if day_value in coverage[participant_id]:
            raise CampaignError("custodian submitted duplicate daily evidence")
        if not str(report["observed_start_utc"]).startswith(day_value):
            raise CampaignError("custody report timestamp does not bind its day")
        coverage[participant_id].add(day_value)
        for field in (
            "retrieval_attempts",
            "retrieval_successes",
            "corrupt_shards_observed",
            "corrupt_shards_rejected",
            "replayed_shards_observed",
            "replayed_shards_rejected",
            "reconstruction_attempts",
            "reconstruction_successes",
            "permitted_loss_attempts",
            "permitted_loss_successes",
            "false_availability_events",
            "repair_bytes",
        ):
            totals[field] += require_uint(metrics.get(field), f"custody {field}")
        maximum_reconstruction_ms = max(
            maximum_reconstruction_ms,
            require_uint(
                metrics.get("maximum_reconstruction_ms"),
                "custody maximum_reconstruction_ms",
            ),
        )
        if metrics["retrieval_successes"] > metrics["retrieval_attempts"]:
            raise CampaignError("custody retrieval successes exceed attempts")
        if metrics["corrupt_shards_rejected"] != metrics["corrupt_shards_observed"]:
            raise CampaignError("custody campaign accepted a corrupt shard")
        if metrics["replayed_shards_rejected"] != metrics["replayed_shards_observed"]:
            raise CampaignError("custody campaign accepted a replayed shard")
        if metrics["reconstruction_successes"] != metrics["reconstruction_attempts"]:
            raise CampaignError("custody reconstruction did not succeed exactly")
        if metrics["permitted_loss_successes"] != metrics["permitted_loss_attempts"]:
            raise CampaignError("permitted shard-loss reconstruction failed")
        report_faults = metrics.get("fault_classes")
        if not isinstance(report_faults, list) or any(item not in CUSTODY_FAULTS for item in report_faults):
            raise CampaignError("custody report contains an unregistered fault class")
        faults.update(report_faults)
    if set(coverage) != set(participants) or any(days != expected_days for days in coverage.values()):
        raise CampaignError("every custodian must submit evidence for every campaign day")
    if totals["retrieval_attempts"] == 0:
        raise CampaignError("custody campaign contains no retrieval probes")
    retrieval_ppm = totals["retrieval_successes"] * 1_000_000 // totals["retrieval_attempts"]
    if retrieval_ppm < 999_000:
        raise CampaignError("custody retrieval success is below 99.9 percent")
    if totals["corrupt_shards_observed"] == 0 or totals["replayed_shards_observed"] == 0:
        raise CampaignError("custody campaign lacks poison or replay probes")
    if totals["reconstruction_attempts"] == 0 or totals["permitted_loss_attempts"] == 0:
        raise CampaignError("custody campaign lacks reconstruction and permitted-loss probes")
    if totals["false_availability_events"] != 0 or faults != CUSTODY_FAULTS:
        raise CampaignError("custody campaign has false availability or incomplete fault coverage")
    return {
        "custodians": len(custodians),
        "organizations": len({row["organization_id"] for row in custodians}),
        "regions": len({row["region"] for row in custodians}),
        "duration_seconds": int((end - start).total_seconds()),
        "covered_days": len(expected_days),
        "retrieval_attempts": totals["retrieval_attempts"],
        "retrieval_successes": totals["retrieval_successes"],
        "retrieval_success_ppm": retrieval_ppm,
        "repair_bytes": totals["repair_bytes"],
        "maximum_reconstruction_ms": maximum_reconstruction_ms,
        "false_availability_events": 0,
        "fault_classes": sorted(faults),
        "verdict": "PASS",
    }


def aggregate_dispute(campaign: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    participants = participant_map(campaign)
    challengers = [row for row in participants.values() if row["role"] == "challenger" and row["platform"] == "challenger"]
    if len(challengers) != len(participants) or len(challengers) < 2:
        raise CampaignError("dispute campaign requires at least two funded challengers")
    if len({row["organization_id"] for row in challengers}) != len(challengers):
        raise CampaignError("challengers are not organization-independent")
    expected_fields = {
        "case_id",
        "fault_class",
        "challenger_mode",
        "objective_fault_injected",
        "challenge_outcome",
        "honest_chunks",
        "false_slash_count",
        "rounds",
        "transactions",
        "transcript_bytes",
        "terminal_seconds",
        "unrelated_jobs_interrupted",
        "base_consensus_interrupted",
        "bond_conserved",
        "tail_replay_exact",
    }
    matrix: set[tuple[str, str]] = set()
    participant_cases: set[str] = set()
    honest_chunks = 0
    for report in reports:
        metrics = report["metrics"]
        require_metric_fields(metrics, expected_fields, "dispute")
        require_hex(metrics.get("case_id"), "dispute case ID")
        fault = metrics.get("fault_class")
        mode = metrics.get("challenger_mode")
        if fault not in DISPUTE_FAULTS or mode not in {"honest", "frivolous"}:
            raise CampaignError("dispute fault or challenger mode is not registered")
        key = (str(fault), str(mode))
        if key in matrix:
            raise CampaignError("dispute matrix cell is duplicated")
        matrix.add(key)
        participant_cases.add(str(report["participant_id"]))
        injected = metrics.get("objective_fault_injected")
        outcome = metrics.get("challenge_outcome")
        if mode == "honest" and (injected is not True or outcome != "UPHELD"):
            raise CampaignError("objective fault was not detected and upheld")
        if mode == "frivolous" and (injected is not False or outcome != "REJECTED"):
            raise CampaignError("frivolous challenge was not rejected")
        chunks = require_uint(metrics.get("honest_chunks"), "honest chunk count")
        honest_chunks += chunks
        if metrics.get("false_slash_count") != 0:
            raise CampaignError("dispute campaign contains a false slash")
        rounds = require_uint(metrics.get("rounds"), "dispute rounds", minimum=1)
        transactions = require_uint(metrics.get("transactions"), "dispute transactions", minimum=1)
        transcript_bytes = require_uint(metrics.get("transcript_bytes"), "dispute transcript bytes", minimum=1)
        terminal_seconds = require_uint(metrics.get("terminal_seconds"), "dispute terminal seconds", minimum=1)
        if not 18 <= rounds <= 20 or not 38 <= transactions <= 42 or not 7_076 <= transcript_bytes <= 9_124:
            raise CampaignError("dispute cost is outside the preregistered tolerance")
        if terminal_seconds >= 6 * 60 * 60:
            raise CampaignError("dispute did not terminate below six hours")
        if (
            metrics.get("unrelated_jobs_interrupted") != 0
            or metrics.get("base_consensus_interrupted") is not False
            or metrics.get("bond_conserved") is not True
            or metrics.get("tail_replay_exact") is not True
        ):
            raise CampaignError("dispute violated isolation, conservation, or replay correctness")
    required_matrix = {(fault, mode) for fault in DISPUTE_FAULTS for mode in ("honest", "frivolous")}
    if matrix != required_matrix:
        raise CampaignError("dispute fault and challenger matrix is incomplete")
    if participant_cases != set(participants):
        raise CampaignError("every funded challenger must submit at least one case")
    if honest_chunks < MINIMUM_HONEST_CHUNKS:
        raise CampaignError("dispute negative controls cover fewer than one million honest chunks")
    return {
        "challengers": len(challengers),
        "fault_classes": sorted(DISPUTE_FAULTS),
        "matrix_cases": len(matrix),
        "honest_chunks": honest_chunks,
        "false_slashes": 0,
        "unrelated_jobs_interrupted": 0,
        "verdict": "PASS",
    }


def nearest_rank(values: list[int], percentile: float) -> int:
    if not values:
        raise CampaignError("latency distribution is empty")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def degradation_ppm(baseline: int, loaded: int) -> int:
    if baseline <= 0:
        raise CampaignError("consensus baseline latency must be positive")
    if loaded <= baseline:
        return 0
    return (loaded - baseline) * 1_000_000 // baseline


def aggregate_latency(campaign: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    participants = participant_map(campaign)
    committees = [row for row in participants.values() if row["role"] == "committee" and row["platform"] == "committee"]
    if len(committees) != len(participants) or len(committees) < 3:
        raise CampaignError("latency campaign requires at least three committee clusters")
    if len({row["organization_id"] for row in committees}) != len(committees):
        raise CampaignError("latency committee clusters are not organization-independent")
    if len({row["region"] for row in committees}) < 3:
        raise CampaignError("latency campaign covers fewer than three regions")
    expected_fields = {
        "cell_id",
        "concurrency",
        "fault_class",
        "jobs_admitted",
        "jobs_completed",
        "false_assured",
        "committed_token_latency_ms",
        "ttft_ms",
        "elapsed_ms",
        "tokens_committed",
        "maximum_memory_bytes",
        "evidence_bytes",
        "queue_drops",
        "refunds",
        "base_finality_p95_baseline_ms",
        "base_finality_p95_loaded_ms",
        "transaction_p95_baseline_ms",
        "transaction_p95_loaded_ms",
    }
    cells: dict[str, set[tuple[int, str]]] = defaultdict(set)
    committed_latencies: list[int] = []
    ttft_values: list[int] = []
    totals: dict[str, int] = defaultdict(int)
    maximum_memory = 0
    maximum_degradation = 0
    for report in reports:
        metrics = report["metrics"]
        require_metric_fields(metrics, expected_fields, "latency")
        require_hex(metrics.get("cell_id"), "latency cell ID")
        concurrency = require_uint(metrics.get("concurrency"), "latency concurrency", minimum=1)
        fault = metrics.get("fault_class")
        if concurrency not in CONCURRENCY_LEVELS or fault not in LATENCY_FAULTS:
            raise CampaignError("latency report is outside the registered matrix")
        participant_id = str(report["participant_id"])
        cell = (concurrency, str(fault))
        if cell in cells[participant_id]:
            raise CampaignError("latency matrix cell is duplicated")
        cells[participant_id].add(cell)
        admitted = require_uint(metrics.get("jobs_admitted"), "admitted jobs", minimum=1)
        completed = require_uint(metrics.get("jobs_completed"), "completed jobs")
        if completed > admitted:
            raise CampaignError("completed jobs exceed admitted jobs")
        if metrics.get("false_assured") != 0:
            raise CampaignError("latency campaign produced a false ASSURED result")
        committed = metrics.get("committed_token_latency_ms")
        ttft = metrics.get("ttft_ms")
        if (
            not isinstance(committed, list)
            or not committed
            or len(committed) > 1_000_000
            or not isinstance(ttft, list)
            or not ttft
            or len(ttft) > 1_000_000
        ):
            raise CampaignError("latency distributions are empty or oversized")
        committed_latencies.extend(
            require_uint(value, "committed-token latency", minimum=1, maximum=3_600_000)
            for value in committed
        )
        ttft_values.extend(
            require_uint(value, "TTFT latency", minimum=1, maximum=3_600_000)
            for value in ttft
        )
        elapsed = require_uint(metrics.get("elapsed_ms"), "latency elapsed milliseconds", minimum=1)
        tokens = require_uint(metrics.get("tokens_committed"), "committed tokens", minimum=1)
        memory = require_uint(metrics.get("maximum_memory_bytes"), "maximum memory bytes", minimum=1)
        evidence_bytes = require_uint(metrics.get("evidence_bytes"), "evidence bytes", minimum=1)
        queue_drops = require_uint(metrics.get("queue_drops"), "queue drops")
        refunds = require_uint(metrics.get("refunds"), "refund count")
        base_baseline = require_uint(metrics.get("base_finality_p95_baseline_ms"), "base finality baseline", minimum=1)
        base_loaded = require_uint(metrics.get("base_finality_p95_loaded_ms"), "base finality loaded", minimum=1)
        transaction_baseline = require_uint(metrics.get("transaction_p95_baseline_ms"), "transaction baseline", minimum=1)
        transaction_loaded = require_uint(metrics.get("transaction_p95_loaded_ms"), "transaction loaded", minimum=1)
        report_degradation = max(
            degradation_ppm(base_baseline, base_loaded),
            degradation_ppm(transaction_baseline, transaction_loaded),
        )
        if report_degradation >= 50_000:
            raise CampaignError("latency campaign degrades consensus p95 by at least five percent")
        maximum_degradation = max(maximum_degradation, report_degradation)
        totals["jobs_admitted"] += admitted
        totals["jobs_completed"] += completed
        totals["elapsed_ms"] += elapsed
        totals["tokens_committed"] += tokens
        totals["evidence_bytes"] += evidence_bytes
        totals["queue_drops"] += queue_drops
        totals["refunds"] += refunds
        maximum_memory = max(maximum_memory, memory)
    required_cells = {(concurrency, fault) for concurrency in CONCURRENCY_LEVELS for fault in LATENCY_FAULTS}
    if set(cells) != set(participants) or any(observed != required_cells for observed in cells.values()):
        raise CampaignError("every committee cluster must complete the latency and fault matrix")
    completion_ppm = totals["jobs_completed"] * 1_000_000 // totals["jobs_admitted"]
    committed_p95 = nearest_rank(committed_latencies, 0.95)
    committed_p99 = nearest_rank(committed_latencies, 0.99)
    if completion_ppm < 999_000 or committed_p95 >= 2_000 or committed_p99 >= 5_000:
        raise CampaignError("latency completion or committed-token threshold failed")
    return {
        "committee_clusters": len(committees),
        "regions": len({row["region"] for row in committees}),
        "matrix_cells": len(required_cells) * len(committees),
        "jobs_admitted": totals["jobs_admitted"],
        "jobs_completed": totals["jobs_completed"],
        "completion_ppm": completion_ppm,
        "committed_token_p50_ms": nearest_rank(committed_latencies, 0.50),
        "committed_token_p95_ms": committed_p95,
        "committed_token_p99_ms": committed_p99,
        "ttft_p95_ms": nearest_rank(ttft_values, 0.95),
        "goodput_milli_tokens_per_second": totals["tokens_committed"] * 1_000_000 // totals["elapsed_ms"],
        "maximum_memory_bytes": maximum_memory,
        "evidence_bytes": totals["evidence_bytes"],
        "queue_drops": totals["queue_drops"],
        "refunds": totals["refunds"],
        "maximum_consensus_degradation_ppm": maximum_degradation,
        "false_assured": 0,
        "verdict": "PASS",
    }


def aggregate(campaign: dict[str, Any], reports: list[dict[str, Any]], *, now: datetime) -> dict[str, Any]:
    kind = campaign["kind"]
    if kind == "CROSS_VENDOR":
        return aggregate_cross_vendor(campaign, reports)
    if kind == "CUSTODY":
        return aggregate_custody(campaign, reports, now=now)
    if kind == "DISPUTE":
        return aggregate_dispute(campaign, reports)
    if kind == "LATENCY":
        return aggregate_latency(campaign, reports)
    raise CampaignError("campaign kind is not registered")


def result_body(
    campaign: dict[str, Any], reports: list[dict[str, Any]], metrics: dict[str, Any], observed_at: datetime
) -> dict[str, Any]:
    report_ids = sorted(str(report["report_id"]) for report in reports)
    body = {
        "campaign_id": campaign["campaign_id"],
        "kind": campaign["kind"],
        "source_revision": campaign["source_revision"],
        "release_version": campaign["release_version"],
        "observed_at_utc": format_utc(observed_at),
        "report_count": len(reports),
        "report_root": sha256(canonical_json(report_ids)),
        "participant_ids": sorted({str(report["participant_id"]) for report in reports}),
        "metrics": metrics,
        "verdict": "PASS",
        "production": False,
        "promotion_effect": "NONE",
    }
    body["result_id"] = identifier(body, "result_id", RESULT_ID_DOMAIN)
    return body


def seal_campaign(
    campaign_document: dict[str, Any],
    reports_directory: Path,
    seed: bytes,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed = now or datetime.now(timezone.utc)
    campaign, campaign_public = validate_campaign(campaign_document, now=observed)
    result_public = public_bytes(Ed25519PrivateKey.from_private_bytes(seed))
    if result_public != campaign_public:
        raise CampaignError("result signing seed does not match the campaign authority")
    if parse_utc(campaign["ends_at_utc"], "campaign end") > observed:
        raise CampaignError("campaign cannot seal before its frozen end")
    reports = load_reports(reports_directory, campaign, now=observed)
    metrics = aggregate(campaign, reports, now=observed)
    return sign_envelope(
        RESULT_SCHEMA,
        result_body(campaign, reports, metrics, observed),
        seed,
        RESULT_DOMAIN,
    )


def verify_result(
    campaign_document: dict[str, Any],
    reports_directory: Path,
    result_document: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed = now or datetime.now(timezone.utc)
    campaign, campaign_public = validate_campaign(campaign_document, now=observed)
    reports = load_reports(reports_directory, campaign, now=observed)
    body, _ = verify_envelope(
        result_document,
        schema=RESULT_SCHEMA,
        domain=RESULT_DOMAIN,
        expected_public=campaign_public,
    )
    required = {
        "result_id",
        "campaign_id",
        "kind",
        "source_revision",
        "release_version",
        "observed_at_utc",
        "report_count",
        "report_root",
        "participant_ids",
        "metrics",
        "verdict",
        "production",
        "promotion_effect",
    }
    if set(body) != required:
        raise CampaignError("model-assurance result fields are not exact")
    if body.get("campaign_id") != campaign["campaign_id"] or body.get("kind") != campaign["kind"]:
        raise CampaignError("result campaign binding mismatch")
    if body.get("source_revision") != campaign["source_revision"] or body.get("release_version") != campaign["release_version"]:
        raise CampaignError("result release identity mismatch")
    if body.get("verdict") != "PASS" or body.get("production") is not False or body.get("promotion_effect") != "NONE":
        raise CampaignError("result is not a passing non-promoting envelope")
    if parse_utc(body.get("observed_at_utc"), "result observation") > observed:
        raise CampaignError("result observation is in the future")
    expected_metrics = aggregate(campaign, reports, now=observed)
    report_ids = sorted(str(report["report_id"]) for report in reports)
    if (
        body.get("report_count") != len(reports)
        or body.get("report_root") != sha256(canonical_json(report_ids))
        or body.get("participant_ids") != sorted({str(report["participant_id"]) for report in reports})
        or body.get("metrics") != expected_metrics
    ):
        raise CampaignError("result does not reproduce from the signed campaign reports")
    if body.get("result_id") != identifier(body, "result_id", RESULT_ID_DOMAIN):
        raise CampaignError("result ID is not content-derived")
    return body


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze, collect, seal, and verify strict WWM model-assurance campaigns")
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("--draft", type=Path, required=True)
    freeze.add_argument("--signing-seed", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    report = commands.add_parser("sign-report")
    report.add_argument("--campaign", type=Path, required=True)
    report.add_argument("--participant-id", required=True)
    report.add_argument("--draft", type=Path, required=True)
    report.add_argument("--signing-seed", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    seal = commands.add_parser("seal")
    seal.add_argument("--campaign", type=Path, required=True)
    seal.add_argument("--reports", type=Path, required=True)
    seal.add_argument("--signing-seed", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--campaign", type=Path, required=True)
    verify.add_argument("--reports", type=Path, required=True)
    verify.add_argument("--result", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            result = freeze_campaign(load_object(args.draft), load_seed(args.signing_seed))
            atomic_write(args.output, result)
        elif args.command == "sign-report":
            result = sign_report(
                load_object(args.campaign),
                args.participant_id,
                load_object(args.draft),
                load_seed(args.signing_seed),
            )
            atomic_write(args.output, result)
        elif args.command == "seal":
            result = seal_campaign(
                load_object(args.campaign),
                args.reports,
                load_seed(args.signing_seed),
            )
            atomic_write(args.output, result)
        else:
            result = verify_result(
                load_object(args.campaign),
                args.reports,
                load_object(args.result),
            )
    except CampaignError as error:
        print(f"model-assurance campaign failed: {error}", file=sys.stderr)
        return 1
    emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
