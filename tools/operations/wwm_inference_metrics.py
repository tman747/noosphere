#!/usr/bin/env python3
"""Collect and verify signed inference lifecycle and base-finality metrics."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPORT_SCHEMA = "noos/wwm-inference-performance-evidence/v1"
BASE_IMPACT_SCHEMA = "noos/wwm-inference-base-impact-input/v1"
SIGNING_DOMAIN = b"NOOS/SIG/WWM-INFERENCE-PERFORMANCE-EVIDENCE/V1\0"
REPORT_ID_DOMAIN = b"NOOS/WWM-INFERENCE-PERFORMANCE-EVIDENCE-ID/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TERMINAL_STATUSES = frozenset({"COMPLETED", "CANCELLED", "FAILED", "NO_QUORUM"})
ALL_STATUSES = TERMINAL_STATUSES | {"QUEUED", "RUNNING", "CANCEL_REQUESTED"}
FAILURE_MODES = frozenset(
    {
        "success",
        "cancellation",
        "timeout",
        "gateway_restart",
        "worker_restart",
        "invalid_proof",
    }
)
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_BASE_SAMPLES = 10_000
MIN_BASE_SAMPLES = 10
MAX_JOBS = 100_000
MAX_CONCURRENCY = 64
QUEUE_LIMIT = 2
DISTRIBUTION_METHOD = "NEAREST_RANK_CEIL_PERCENT_N_ONE_INDEXED_INTEGER"
BASE_PHASE_FIELDS = {"start_height", "end_height", "finality_latency_us"}
BASE_INPUT_FIELDS = {
    "schema",
    "source_revision",
    "deployment_sha256",
    "baseline",
    "stressed",
    "production",
    "promotion_effect",
}
REPORT_FIELDS = {
    "report_id",
    "source_revision",
    "deployment_sha256",
    "database_sha256",
    "base_input_sha256",
    "window",
    "campaign",
    "jobs",
    "latency_ms",
    "evidence_bytes",
    "base_finality",
    "observed_at_utc",
    "production",
    "promotion_effect",
}
SIGNER_FIELDS = {"algorithm", "key_id", "public_key_base64", "signature_base64"}


class MetricsError(RuntimeError):
    """The inference metrics source or signed report is unsafe or malformed."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise MetricsError(f"cannot hash evidence input: {error}") from error
    return digest.hexdigest()


def load_json(path: Path, maximum_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise MetricsError(f"cannot read JSON input: {error}") from error
    if not raw or len(raw) > maximum_bytes:
        raise MetricsError("JSON input size is outside the bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MetricsError("JSON input is malformed") from error
    if not isinstance(value, dict):
        raise MetricsError("JSON input must be an object")
    return value


def load_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise MetricsError(f"cannot read signing seed: {error}") from error
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeError, ValueError) as error:
            raise MetricsError("signing seed must be raw32 or lowercase hex64") from error
    elif len(raw) == 32:
        seed = raw
    else:
        raise MetricsError("signing seed must be raw32 or lowercase hex64")
    if seed == bytes(32):
        raise MetricsError("all-zero signing seed is forbidden")
    return seed


def atomic_create(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise MetricsError("refusing to overwrite immutable inference metrics evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = canonical_json(value) + b"\n"
    try:
        with temporary.open("xb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise MetricsError(f"cannot create inference metrics evidence: {error}") from error


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def exact_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise MetricsError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def nearest_rank(values: Sequence[int], percentile: int) -> int | None:
    if not values:
        return None
    if not 1 <= percentile <= 100:
        raise MetricsError("percentile must be in [1, 100]")
    ordered = sorted(values)
    rank = (percentile * len(ordered) + 99) // 100
    return ordered[rank - 1]


def distribution(values: Iterable[int]) -> dict[str, Any]:
    ordered = sorted(values)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in ordered):
        raise MetricsError("latency distributions require nonnegative integer samples")
    return {
        "method": DISTRIBUTION_METHOD,
        "count": len(ordered),
        "min": ordered[0] if ordered else None,
        "p50": nearest_rank(ordered, 50),
        "p95": nearest_rank(ordered, 95),
        "p99": nearest_rank(ordered, 99),
        "max": ordered[-1] if ordered else None,
        "raw_samples": ordered,
    }


def validate_distribution(value: Any, label: str) -> dict[str, Any]:
    fields = {"method", "count", "min", "p50", "p95", "p99", "max", "raw_samples"}
    if not isinstance(value, dict) or set(value) != fields:
        raise MetricsError(f"{label} distribution has the wrong closed schema")
    samples = value["raw_samples"]
    if not isinstance(samples, list) or len(samples) > MAX_JOBS:
        raise MetricsError(f"{label} raw sample count is outside the bound")
    expected = distribution(samples)
    if value != expected:
        raise MetricsError(f"{label} distribution does not match its raw samples")
    return value


def validate_base_phase(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BASE_PHASE_FIELDS:
        raise MetricsError(f"{label} base-finality phase has the wrong closed schema")
    start = exact_int(value["start_height"], f"{label}.start_height", 0, (1 << 63) - 1)
    end = exact_int(value["end_height"], f"{label}.end_height", 1, (1 << 63) - 1)
    samples = value["finality_latency_us"]
    if start >= end:
        raise MetricsError(f"{label} base-finality height interval is empty")
    if not isinstance(samples, list) or not MIN_BASE_SAMPLES <= len(samples) <= MAX_BASE_SAMPLES:
        raise MetricsError(f"{label} base-finality sample count is outside the bound")
    for index, sample in enumerate(samples):
        exact_int(sample, f"{label}.finality_latency_us[{index}]", 1, 3_600_000_000)
    return value


def validate_base_input(value: Any, source_revision: str, deployment_sha256: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BASE_INPUT_FIELDS:
        raise MetricsError("base-finality input has the wrong closed schema")
    if (
        value.get("schema") != BASE_IMPACT_SCHEMA
        or value.get("source_revision") != source_revision
        or value.get("deployment_sha256") != deployment_sha256
        or value.get("production") is not False
        or value.get("promotion_effect") != "NONE"
    ):
        raise MetricsError("base-finality input release or nonproduction boundary is invalid")
    baseline = validate_base_phase(value["baseline"], "baseline")
    stressed = validate_base_phase(value["stressed"], "stressed")
    if int(stressed["start_height"]) < int(baseline["end_height"]):
        raise MetricsError("stressed base-finality phase overlaps or predates baseline")
    return value


def base_finality_metrics(value: Mapping[str, Any]) -> dict[str, Any]:
    baseline_phase = value["baseline"]
    stressed_phase = value["stressed"]
    baseline_us = distribution(int(sample) for sample in baseline_phase["finality_latency_us"])
    stressed_us = distribution(int(sample) for sample in stressed_phase["finality_latency_us"])
    baseline_p95 = int(baseline_us["p95"])
    stressed_p95 = int(stressed_us["p95"])
    difference = stressed_p95 - baseline_p95
    degradation_bps = difference * 10_000 // baseline_p95
    return {
        "baseline": {
            "start_height": baseline_phase["start_height"],
            "end_height": baseline_phase["end_height"],
            "latency_us": baseline_us,
        },
        "stressed": {
            "start_height": stressed_phase["start_height"],
            "end_height": stressed_phase["end_height"],
            "latency_us": stressed_us,
        },
        "p95_difference_us": difference,
        "p95_degradation_basis_points": degradation_bps,
    }


def _snapshot_database(database: Path, destination: Path) -> None:
    try:
        source = database.resolve(strict=True)
    except OSError as error:
        raise MetricsError(f"inference database is unavailable: {error}") from error
    if not source.is_file() or source.stat().st_size > MAX_DATABASE_BYTES:
        raise MetricsError("inference database size is outside the bound")
    try:
        with closing(sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True, timeout=10)) as source_db:
            with closing(sqlite3.connect(destination, timeout=10)) as snapshot_db:
                source_db.backup(snapshot_db)
    except sqlite3.Error as error:
        raise MetricsError(f"cannot create a consistent inference database snapshot: {error}") from error


def _required_job_columns(db: sqlite3.Connection) -> None:
    columns = {str(row[1]) for row in db.execute("PRAGMA table_info(inference_jobs)").fetchall()}
    required = {
        "job_id",
        "status",
        "receipt_json",
        "created_ms",
        "started_ms",
        "deadline_at_ms",
        "queue_depth_at_submit",
    }
    if not required <= columns:
        raise MetricsError("inference database predates required durable metrics columns")
    tables = {
        str(row[0])
        for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    if not {"inference_jobs", "inference_events", "inference_settlements"} <= tables:
        raise MetricsError("inference database is missing durable lifecycle tables")


def _utf8_bytes(value: Any) -> int:
    return 0 if value is None else len(str(value).encode("utf-8"))


def _parse_receipt(saved: Any, job_id: str, status: str) -> dict[str, Any] | None:
    if saved is None:
        return None
    try:
        receipt = json.loads(str(saved))
    except json.JSONDecodeError as error:
        raise MetricsError("stored inference receipt is malformed") from error
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "noos/wwm-receipt/v2"
        or receipt.get("job_id") != job_id
        or receipt.get("terminal_status") != status
    ):
        raise MetricsError("stored inference receipt changed lifecycle identity")
    return receipt


def collect_database_metrics(
    snapshot: Path,
    *,
    window_start_ms: int,
    window_end_ms: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
    with closing(sqlite3.connect(snapshot, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        _required_job_columns(db)
        rows = db.execute(
            """
            SELECT job_id,status,receipt_json,created_ms,started_ms,deadline_at_ms,queue_depth_at_submit
            FROM inference_jobs
            WHERE created_ms>=? AND created_ms<?
            ORDER BY created_ms,job_id
            """,
            (window_start_ms, window_end_ms),
        ).fetchall()
        if not rows or len(rows) > MAX_JOBS:
            raise MetricsError("inference campaign job count is outside the bound")

        status_counts: Counter[str] = Counter()
        end_to_end_ms: list[int] = []
        execution_ms: list[int] = []
        queue_ms: list[int] = []
        settlement_ms: list[int] = []
        finalized_refunds = 0
        pending_refunds = 0
        legacy_queue_unknown = 0
        maximum_queue_depth = 0
        receipts_bytes = 0
        terminal_jobs = 0

        for row in rows:
            job_id = str(row["job_id"])
            status = str(row["status"])
            if status not in ALL_STATUSES or HEX64.fullmatch(job_id) is None:
                raise MetricsError("inference job identity or status is malformed")
            created_ms = exact_int(row["created_ms"], "job.created_ms", 0, (1 << 63) - 1)
            deadline_at_ms = exact_int(
                row["deadline_at_ms"], "job.deadline_at_ms", created_ms + 1, (1 << 63) - 1
            )
            queue_depth = exact_int(
                row["queue_depth_at_submit"], "job.queue_depth_at_submit", 0, QUEUE_LIMIT
            )
            if queue_depth == 0:
                legacy_queue_unknown += 1
            else:
                maximum_queue_depth = max(maximum_queue_depth, queue_depth)
            started_ms = row["started_ms"]
            if started_ms is not None:
                started = exact_int(started_ms, "job.started_ms", created_ms, deadline_at_ms - 1)
                queue_ms.append(started - created_ms)
            status_counts[status] += 1
            receipt = _parse_receipt(row["receipt_json"], job_id, status)
            receipts_bytes += _utf8_bytes(row["receipt_json"])
            if status in TERMINAL_STATUSES:
                terminal_jobs += 1
                if receipt is None:
                    raise MetricsError("terminal inference job is missing its receipt")
                completed_at_ms = exact_int(
                    receipt.get("completed_at_ms"),
                    "receipt.completed_at_ms",
                    created_ms,
                    (1 << 63) - 1,
                )
                end_to_end_ms.append(completed_at_ms - created_ms)
                if status == "COMPLETED":
                    execution_ms.append(
                        exact_int(receipt.get("duration_ms"), "receipt.duration_ms", 1, 3_600_000)
                    )
                settlement_state = receipt.get("settlement_state")
                if status != "COMPLETED":
                    if settlement_state == "FINALIZED_REFUNDED":
                        finalized_refunds += 1
                    elif settlement_state == "PENDING_CHAIN":
                        pending_refunds += 1
                    else:
                        raise MetricsError("failed inference receipt has an invalid refund state")
                settled_at_ms = receipt.get("settled_at_ms")
                if settled_at_ms is not None:
                    settled = exact_int(
                        settled_at_ms,
                        "receipt.settled_at_ms",
                        completed_at_ms,
                        (1 << 63) - 1,
                    )
                    settlement_ms.append(settled - completed_at_ms)
            elif receipt is not None:
                raise MetricsError("nonterminal inference job unexpectedly has a receipt")

        event_bytes = int(
            db.execute(
                """
                SELECT COALESCE(SUM(LENGTH(e.payload_json)),0)
                FROM inference_events e
                JOIN inference_jobs j ON j.job_id=e.job_id
                WHERE j.created_ms>=? AND j.created_ms<?
                """,
                (window_start_ms, window_end_ms),
            ).fetchone()[0]
        )
        settlement_row = db.execute(
            """
            SELECT
              COALESCE(SUM(LENGTH(s.request_json)),0),
              COALESCE(SUM(LENGTH(s.checkpoint_json)),0),
              COALESCE(SUM(LENGTH(s.result_json)),0)
            FROM inference_settlements s
            JOIN inference_jobs j ON j.job_id=s.job_id
            WHERE j.created_ms>=? AND j.created_ms<?
            """,
            (window_start_ms, window_end_ms),
        ).fetchone()
        settlement_bytes = sum(int(value) for value in settlement_row)

    admitted = len(rows)
    completed = status_counts["COMPLETED"]
    jobs = {
        "admitted": admitted,
        "terminal": terminal_jobs,
        "status_counts": {status: status_counts.get(status, 0) for status in sorted(ALL_STATUSES)},
        "terminal_rate_basis_points": terminal_jobs * 10_000 // admitted,
        "success_rate_basis_points": completed * 10_000 // admitted,
        "finalized_refunds": finalized_refunds,
        "pending_refunds": pending_refunds,
        "queue_limit": QUEUE_LIMIT,
        "maximum_observed_queue_depth": maximum_queue_depth,
        "legacy_queue_depth_unknown": legacy_queue_unknown,
    }
    latency = {
        "end_to_end": distribution(end_to_end_ms),
        "execution": distribution(execution_ms),
        "queue": distribution(queue_ms),
        "settlement": distribution(settlement_ms),
    }
    evidence = {
        "receipts": receipts_bytes,
        "events": event_bytes,
        "settlements": settlement_bytes,
        "total": receipts_bytes + event_bytes + settlement_bytes,
    }
    return jobs, latency, evidence


def _rate(numerator: int, denominator: int) -> int:
    return numerator * 10_000 // denominator


def validate_report_body(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REPORT_FIELDS:
        raise MetricsError("inference metrics report has the wrong closed schema")
    if (
        not HEX64.fullmatch(str(value["report_id"]))
        or not HEX40.fullmatch(str(value["source_revision"]))
        or not HEX64.fullmatch(str(value["deployment_sha256"]))
        or not HEX64.fullmatch(str(value["database_sha256"]))
        or not HEX64.fullmatch(str(value["base_input_sha256"]))
        or value["production"] is not False
        or value["promotion_effect"] != "NONE"
    ):
        raise MetricsError("inference metrics release or nonproduction identity is invalid")
    window = value["window"]
    if not isinstance(window, dict) or set(window) != {"start_ms", "end_ms"}:
        raise MetricsError("inference metrics window has the wrong closed schema")
    start = exact_int(window["start_ms"], "window.start_ms", 0, (1 << 63) - 2)
    end = exact_int(window["end_ms"], "window.end_ms", 1, (1 << 63) - 1)
    if start >= end:
        raise MetricsError("inference metrics window is empty")
    campaign = value["campaign"]
    if not isinstance(campaign, dict) or set(campaign) != {
        "declared_concurrency",
        "failure_modes",
    }:
        raise MetricsError("inference campaign declaration has the wrong closed schema")
    exact_int(
        campaign["declared_concurrency"],
        "campaign.declared_concurrency",
        1,
        MAX_CONCURRENCY,
    )
    modes = campaign["failure_modes"]
    if (
        not isinstance(modes, list)
        or not modes
        or modes != sorted(set(modes))
        or any(mode not in FAILURE_MODES for mode in modes)
    ):
        raise MetricsError("inference campaign failure modes are malformed")
    jobs = value["jobs"]
    job_fields = {
        "admitted",
        "terminal",
        "status_counts",
        "terminal_rate_basis_points",
        "success_rate_basis_points",
        "finalized_refunds",
        "pending_refunds",
        "queue_limit",
        "maximum_observed_queue_depth",
        "legacy_queue_depth_unknown",
    }
    if not isinstance(jobs, dict) or set(jobs) != job_fields:
        raise MetricsError("inference job metrics have the wrong closed schema")
    admitted = exact_int(jobs["admitted"], "jobs.admitted", 1, MAX_JOBS)
    terminal = exact_int(jobs["terminal"], "jobs.terminal", 0, admitted)
    counts = jobs["status_counts"]
    if not isinstance(counts, dict) or set(counts) != ALL_STATUSES:
        raise MetricsError("inference status counts have the wrong closed schema")
    for status, count in counts.items():
        exact_int(count, f"jobs.status_counts.{status}", 0, admitted)
    if sum(counts.values()) != admitted or sum(counts[status] for status in TERMINAL_STATUSES) != terminal:
        raise MetricsError("inference status counts do not conserve admitted jobs")
    if jobs["terminal_rate_basis_points"] != _rate(terminal, admitted):
        raise MetricsError("inference terminal rate is forged")
    if jobs["success_rate_basis_points"] != _rate(counts["COMPLETED"], admitted):
        raise MetricsError("inference success rate is forged")
    refunds = counts["CANCELLED"] + counts["FAILED"] + counts["NO_QUORUM"]
    finalized_refunds = exact_int(jobs["finalized_refunds"], "jobs.finalized_refunds", 0, refunds)
    pending_refunds = exact_int(jobs["pending_refunds"], "jobs.pending_refunds", 0, refunds)
    if finalized_refunds + pending_refunds != refunds:
        raise MetricsError("inference refund outcomes do not conserve failed jobs")
    if jobs["queue_limit"] != QUEUE_LIMIT:
        raise MetricsError("inference queue limit changed")
    exact_int(
        jobs["maximum_observed_queue_depth"],
        "jobs.maximum_observed_queue_depth",
        0,
        QUEUE_LIMIT,
    )
    exact_int(
        jobs["legacy_queue_depth_unknown"],
        "jobs.legacy_queue_depth_unknown",
        0,
        admitted,
    )
    latency = value["latency_ms"]
    if not isinstance(latency, dict) or set(latency) != {
        "end_to_end",
        "execution",
        "queue",
        "settlement",
    }:
        raise MetricsError("inference latency metrics have the wrong closed schema")
    for label, samples in latency.items():
        validate_distribution(samples, f"latency_ms.{label}")
    if latency["end_to_end"]["count"] != terminal:
        raise MetricsError("end-to-end latency count does not match terminal jobs")
    if latency["execution"]["count"] != counts["COMPLETED"]:
        raise MetricsError("execution latency count does not match successful jobs")
    evidence = value["evidence_bytes"]
    if not isinstance(evidence, dict) or set(evidence) != {
        "receipts",
        "events",
        "settlements",
        "total",
    }:
        raise MetricsError("inference evidence byte metrics have the wrong closed schema")
    for field in ("receipts", "events", "settlements", "total"):
        exact_int(evidence[field], f"evidence_bytes.{field}", 0, 1 << 50)
    if evidence["total"] != evidence["receipts"] + evidence["events"] + evidence["settlements"]:
        raise MetricsError("inference evidence byte total is forged")
    base = value["base_finality"]
    if not isinstance(base, dict) or set(base) != {
        "baseline",
        "stressed",
        "p95_difference_us",
        "p95_degradation_basis_points",
    }:
        raise MetricsError("base-finality metrics have the wrong closed schema")
    for phase_name in ("baseline", "stressed"):
        phase = base[phase_name]
        if not isinstance(phase, dict) or set(phase) != {
            "start_height",
            "end_height",
            "latency_us",
        }:
            raise MetricsError(f"base-finality {phase_name} metrics are malformed")
        phase_start = exact_int(phase["start_height"], f"{phase_name}.start_height", 0, (1 << 63) - 1)
        phase_end = exact_int(phase["end_height"], f"{phase_name}.end_height", 1, (1 << 63) - 1)
        if phase_start >= phase_end:
            raise MetricsError(f"base-finality {phase_name} interval is empty")
        validate_distribution(phase["latency_us"], f"base_finality.{phase_name}.latency_us")
        if not MIN_BASE_SAMPLES <= phase["latency_us"]["count"] <= MAX_BASE_SAMPLES:
            raise MetricsError(f"base-finality {phase_name} sample count is outside the bound")
        if any(sample < 1 for sample in phase["latency_us"]["raw_samples"]):
            raise MetricsError(f"base-finality {phase_name} latency must be positive")
    baseline_p95 = int(base["baseline"]["latency_us"]["p95"])
    stressed_p95 = int(base["stressed"]["latency_us"]["p95"])
    difference = stressed_p95 - baseline_p95
    if base["p95_difference_us"] != difference:
        raise MetricsError("base-finality p95 difference is forged")
    if base["p95_degradation_basis_points"] != difference * 10_000 // baseline_p95:
        raise MetricsError("base-finality p95 degradation is forged")
    observed_at = value["observed_at_utc"]
    if not isinstance(observed_at, str) or UTC.fullmatch(observed_at) is None:
        raise MetricsError("inference metrics observation time is malformed")
    try:
        datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise MetricsError("inference metrics observation time is invalid") from error
    unsigned = {**value, "report_id": ""}
    if value["report_id"] != sha256_bytes(REPORT_ID_DOMAIN + canonical_json(unsigned)):
        raise MetricsError("inference metrics report ID is invalid")
    return value


def sign_report(body: dict[str, Any], seed: bytes) -> dict[str, Any]:
    validate_report_body(body)
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes_raw()
    signature = private.sign(SIGNING_DOMAIN + canonical_json(body))
    return {
        "schema": REPORT_SCHEMA,
        "body": body,
        "signer": {
            "algorithm": "Ed25519",
            "key_id": sha256_bytes(public),
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def validate_envelope(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "body", "signer"}
        or value.get("schema") != REPORT_SCHEMA
    ):
        raise MetricsError("inference metrics envelope has the wrong closed schema")
    body = validate_report_body(value["body"])
    signer = value["signer"]
    if not isinstance(signer, dict) or set(signer) != SIGNER_FIELDS or signer.get("algorithm") != "Ed25519":
        raise MetricsError("inference metrics signer record is malformed")
    try:
        public = base64.b64decode(signer["public_key_base64"], validate=True)
        signature = base64.b64decode(signer["signature_base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise MetricsError("inference metrics signature encoding is malformed") from error
    if (
        len(public) != 32
        or len(signature) != 64
        or not HEX64.fullmatch(str(signer["key_id"]))
        or sha256_bytes(public) != signer["key_id"]
    ):
        raise MetricsError("inference metrics signer identity is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature,
            SIGNING_DOMAIN + canonical_json(body),
        )
    except (ValueError, InvalidSignature) as error:
        raise MetricsError("inference metrics signature is forged or invalid") from error
    return body


def collect_report(
    *,
    database: Path,
    base_input_path: Path,
    source_revision: str,
    deployment_sha256: str,
    window_start_ms: int,
    window_end_ms: int,
    declared_concurrency: int,
    failure_modes: Sequence[str],
) -> dict[str, Any]:
    if HEX40.fullmatch(source_revision) is None or HEX64.fullmatch(deployment_sha256) is None:
        raise MetricsError("inference metrics release identity is malformed")
    exact_int(window_start_ms, "window_start_ms", 0, (1 << 63) - 2)
    exact_int(window_end_ms, "window_end_ms", 1, (1 << 63) - 1)
    if window_start_ms >= window_end_ms:
        raise MetricsError("inference metrics window is empty")
    exact_int(declared_concurrency, "declared_concurrency", 1, MAX_CONCURRENCY)
    normalized_modes = sorted(set(failure_modes))
    if not normalized_modes or len(normalized_modes) != len(failure_modes) or any(
        mode not in FAILURE_MODES for mode in normalized_modes
    ):
        raise MetricsError("inference campaign failure modes are duplicated or unknown")
    base_input = validate_base_input(
        load_json(base_input_path),
        source_revision,
        deployment_sha256,
    )
    with tempfile.TemporaryDirectory(prefix="wwm-inference-metrics-") as temporary:
        snapshot = Path(temporary) / "inference.snapshot.sqlite3"
        _snapshot_database(database, snapshot)
        jobs, latency, evidence = collect_database_metrics(
            snapshot,
            window_start_ms=window_start_ms,
            window_end_ms=window_end_ms,
        )
        database_sha256 = sha256_file(snapshot)
    body: dict[str, Any] = {
        "report_id": "",
        "source_revision": source_revision,
        "deployment_sha256": deployment_sha256,
        "database_sha256": database_sha256,
        "base_input_sha256": sha256_file(base_input_path),
        "window": {"start_ms": window_start_ms, "end_ms": window_end_ms},
        "campaign": {
            "declared_concurrency": declared_concurrency,
            "failure_modes": normalized_modes,
        },
        "jobs": jobs,
        "latency_ms": latency,
        "evidence_bytes": evidence,
        "base_finality": base_finality_metrics(base_input),
        "observed_at_utc": utc_now(),
        "production": False,
        "promotion_effect": "NONE",
    }
    body["report_id"] = sha256_bytes(
        REPORT_ID_DOMAIN + canonical_json({**body, "report_id": ""})
    )
    return validate_report_body(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--database", type=Path, required=True)
    collect_parser.add_argument("--base-input", type=Path, required=True)
    collect_parser.add_argument("--source-revision", required=True)
    collect_parser.add_argument("--deployment-sha256", required=True)
    collect_parser.add_argument("--window-start-ms", type=int, required=True)
    collect_parser.add_argument("--window-end-ms", type=int, required=True)
    collect_parser.add_argument("--declared-concurrency", type=int, required=True)
    collect_parser.add_argument(
        "--failure-mode",
        action="append",
        choices=sorted(FAILURE_MODES),
        required=True,
    )
    collect_parser.add_argument("--signing-seed", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            body = collect_report(
                database=args.database,
                base_input_path=args.base_input,
                source_revision=args.source_revision,
                deployment_sha256=args.deployment_sha256,
                window_start_ms=args.window_start_ms,
                window_end_ms=args.window_end_ms,
                declared_concurrency=args.declared_concurrency,
                failure_modes=args.failure_mode,
            )
            envelope = sign_report(body, load_seed(args.signing_seed))
            validate_envelope(envelope)
            atomic_create(args.output, envelope)
        else:
            body = validate_envelope(load_json(args.input))
    except MetricsError as error:
        print(f"inference metrics failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "report_id": body["report_id"],
                "jobs": body["jobs"]["admitted"],
                "terminal_rate_basis_points": body["jobs"]["terminal_rate_basis_points"],
                "p95_end_to_end_ms": body["latency_ms"]["end_to_end"]["p95"],
                "p95_base_degradation_basis_points": body["base_finality"][
                    "p95_degradation_basis_points"
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
