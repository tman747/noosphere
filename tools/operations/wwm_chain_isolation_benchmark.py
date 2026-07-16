#!/usr/bin/env python3
"""Measure ordinary devnet transaction finality under isolated coordinator load.

The operator sends pre-built, unique ordinary transaction envelopes to the
loopback node RPC. It records live submission, receipt, and finalized-status
responses at baseline, under a configured synthetic coordinator distribution,
and while the same coordinator endpoint is deliberately unavailable. Passing
evidence is signed, insert-once, and explicitly has no production effect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

EVIDENCE_SCHEMA = "noos/wwm-chain-isolation-benchmark-evidence/v1"
DISTRIBUTION_SCHEMA = "noos/wwm-chain-isolation-load-distribution/v1"
OUTAGE_CONTROL_SCHEMA = "noos/wwm-chain-isolation-outage-control/v1"
SIGNATURE_DOMAIN = b"NOOS/SIG/WWM-CHAIN-ISOLATION-BENCHMARK/V1\x00"
SCOPE = "OWNER_CONTROLLED_LOOPBACK_DEVNET_LIVE_MEASUREMENT"
SYNTHETIC_SCOPE = "SYNTHETIC_OPERATOR_CONFIG_NOT_REAL_PARTICIPANT_DISTRIBUTION"
P95_METHOD = "NEAREST_RANK_CEIL_0.95_N_ONE_INDEXED_OVER_INTEGER_MICROSECONDS"
DEVNET_EPOCH_BLOCKS = 256
FINALITY_ALIGNMENT_WINDOW_BLOCKS = 1
HARD_MIN_SAMPLE_FLOOR = 10
MAX_SAMPLES_PER_PHASE = 10_000
MAX_COORDINATOR_REQUESTS = 1_000_000
MAX_HTTP_BYTES = 1024 * 1024
MAX_JSON_FILE_BYTES = 16 * 1024 * 1024
MAX_ERROR_EXAMPLES = 128
HEX32 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class BenchmarkError(RuntimeError):
    """A live precondition or pass criterion failed closed."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys != expected:
        raise BenchmarkError(f"{label} fields are closed; expected {sorted(expected)}, got {sorted(keys)}")


def require_hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise BenchmarkError(f"{label} must be canonical lowercase hex32")
    return value


def load_json(path: Path, label: str, maximum: int = MAX_JSON_FILE_BYTES) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > maximum:
            raise BenchmarkError(f"{label} exceeds its byte bound or is empty")
        value = json.loads(path.read_text(encoding="utf-8"))
    except BenchmarkError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    return value


def validate_loopback_base(url: str, label: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}:
        raise BenchmarkError(f"{label} must be explicit numeric loopback HTTP; localhost/public URLs are ambiguous")
    if parsed.port is None or parsed.username is not None or parsed.password is not None:
        raise BenchmarkError(f"{label} must have an explicit port and no URL credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise BenchmarkError(f"{label} must be an origin URL without path, query, or fragment")
    host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
    return f"http://{host}:{parsed.port}"


def parse_json_body(raw: bytes, url: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"non-JSON live response from {url}") from error
    if not isinstance(value, dict):
        raise BenchmarkError(f"live response from {url} is not a JSON object")
    return value


@dataclass(frozen=True)
class HttpResult:
    status: int | None
    body: bytes
    latency_us: int
    error: str | None


def http_request(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float,
) -> HttpResult:
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
    started = time.perf_counter_ns()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > MAX_HTTP_BYTES:
                raise BenchmarkError(f"live response from {url} exceeds {MAX_HTTP_BYTES} bytes")
            raw = response.read(MAX_HTTP_BYTES + 1)
            if len(raw) > MAX_HTTP_BYTES:
                raise BenchmarkError(f"live response from {url} exceeds {MAX_HTTP_BYTES} bytes")
            return HttpResult(response.status, raw, max(1, (time.perf_counter_ns() - started) // 1000), None)
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_HTTP_BYTES + 1)
        if len(raw) > MAX_HTTP_BYTES:
            raw = raw[:MAX_HTTP_BYTES]
        return HttpResult(error.code, raw, max(1, (time.perf_counter_ns() - started) // 1000), f"HTTP_{error.code}")
    except BenchmarkError:
        raise
    except (OSError, urllib.error.URLError) as error:
        return HttpResult(None, b"", max(1, (time.perf_counter_ns() - started) // 1000), type(error).__name__)


class NodeRecorder:
    def __init__(self, base_url: str, token: str, timeout: float):
        self.base_url = base_url
        self.token = token
        self.timeout = timeout
        self.requests = Counter()
        self.responses = Counter()
        self.errors = Counter()

    def request(self, method: str, path: str, body: bytes | None = None) -> HttpResult:
        self.requests[f"{method} {path.split('/')[1] if path.startswith('/') and len(path.split('/')) > 1 else path}"] += 1
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        result = http_request(self.base_url + path, method=method, body=body, headers=headers, timeout=self.timeout)
        if result.status is None:
            self.errors[result.error or "NETWORK_ERROR"] += 1
        else:
            self.responses[str(result.status)] += 1
        return result

    def require_json(self, method: str, path: str, body: bytes | None = None) -> tuple[dict[str, Any], int]:
        result = self.request(method, path, body)
        if result.status != 200 or result.error is not None:
            raise BenchmarkError(f"node RPC {method} {path} did not return a live HTTP 200 response")
        return parse_json_body(result.body, self.base_url + path), result.latency_us

    def summary(self) -> dict[str, Any]:
        return {
            "requests_by_route": dict(sorted(self.requests.items())),
            "responses_by_status": dict(sorted(self.responses.items())),
            "network_errors": dict(sorted(self.errors.items())),
            "total_requests": sum(self.requests.values()),
            "total_live_http_responses": sum(self.responses.values()),
        }


def validate_node_status(value: Mapping[str, Any], chain_id: str, genesis_hash: str) -> dict[str, Any]:
    if value.get("chain_id") != chain_id or value.get("genesis_hash") != genesis_hash:
        raise BenchmarkError("node live status does not match the operator-declared devnet chain/genesis")
    unsafe = value.get("unsafe_head")
    finalized = value.get("finalized")
    if not isinstance(unsafe, dict) or not isinstance(unsafe.get("height"), int) or unsafe["height"] < 0:
        raise BenchmarkError("node live status has no valid unsafe_head.height")
    finalized_height(value)
    return {"chain_id": chain_id, "genesis_hash": genesis_hash, "unsafe_height": unsafe["height"], "finalized_height": finalized_height(value)}


def finalized_height(status: Mapping[str, Any]) -> int:
    finalized = status.get("finalized")
    if not isinstance(finalized, dict):
        raise BenchmarkError("node live status has no finalized object")
    if isinstance(finalized.get("height"), int) and finalized["height"] >= 0:
        return finalized["height"]
    if isinstance(finalized.get("epoch"), int) and finalized["epoch"] >= 0:
        return finalized["epoch"] * DEVNET_EPOCH_BLOCKS
    raise BenchmarkError("node live status has neither finalized.height nor finalized.epoch")


def wait_phase_alignment(
    name: str,
    recorder: NodeRecorder,
    chain_id: str,
    genesis_hash: str,
    timeout: float,
    poll_interval: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    poll_count = 0
    while time.monotonic() < deadline:
        status, _ = recorder.require_json("GET", "/status")
        identity = validate_node_status(status, chain_id, genesis_hash)
        poll_count += 1
        offset = identity["unsafe_height"] % DEVNET_EPOCH_BLOCKS
        if offset <= FINALITY_ALIGNMENT_WINDOW_BLOCKS:
            return {
                "method": "UNSAFE_HEAD_MODULO_DEVNET_EPOCH",
                "epoch_blocks": DEVNET_EPOCH_BLOCKS,
                "window_blocks": FINALITY_ALIGNMENT_WINDOW_BLOCKS,
                "unsafe_height": identity["unsafe_height"],
                "finalized_height": identity["finalized_height"],
                "offset_blocks": offset,
                "poll_count": poll_count,
            }
        time.sleep(poll_interval)
    raise BenchmarkError(f"{name} phase could not align to a comparable devnet finality window")


def validate_coordinator_config(value: Mapping[str, Any], chain_id: str, genesis_hash: str) -> dict[str, Any]:
    if value.get("schema") != "noos/wwm-web-capacity/v1":
        raise BenchmarkError("coordinator live config has the wrong schema")
    if value.get("experiment_state") != "DEVNET":
        raise BenchmarkError("coordinator must be in explicit DEVNET state")
    if value.get("production_custody") is not False or value.get("rewards") is not False:
        raise BenchmarkError("coordinator live config is production/reward capable")
    if value.get("participant_classes") != ["STATIC_HOST_SEEDER", "BROWSER_ADVISORY_CACHE"]:
        raise BenchmarkError("coordinator live config has unexpected participant classes")
    binding = value.get("chain_binding")
    if not isinstance(binding, dict) or binding.get("chain_id") != chain_id or binding.get("genesis_hash") != genesis_hash:
        raise BenchmarkError("coordinator live config does not bind the node devnet chain/genesis")
    artifact_id = require_hex32(binding.get("artifact_id"), "coordinator artifact_id")
    manifest_root = require_hex32(binding.get("manifest_root"), "coordinator manifest_root")
    coordinator_key = require_hex32(value.get("coordinator_key"), "coordinator_key")
    return {
        "schema": value["schema"],
        "experiment_state": value["experiment_state"],
        "chain_binding": {"chain_id": chain_id, "genesis_hash": genesis_hash, "artifact_id": artifact_id, "manifest_root": manifest_root},
        "coordinator_key": coordinator_key,
        "production_custody": False,
        "rewards": False,
    }


def coordinator_config(base_url: str, timeout: float) -> tuple[dict[str, Any] | None, HttpResult]:
    path = "/api/wwm-web-capacity/v1/config"
    result = http_request(base_url + path, headers={"Accept": "application/json"}, timeout=timeout)
    if result.status == 200 and result.error is None:
        return parse_json_body(result.body, base_url + path), result
    return None, result


def load_distribution(path: Path) -> dict[str, Any]:
    value = load_json(path, "synthetic distribution", maximum=64 * 1024)
    require_exact_keys(value, {"schema", "scope", "requests"}, "synthetic distribution")
    if value["schema"] != DISTRIBUTION_SCHEMA or value["scope"] != SYNTHETIC_SCOPE:
        raise BenchmarkError("distribution must explicitly identify configured synthetic, not measured-real, requests")
    rows = value["requests"]
    if not isinstance(rows, list) or not rows or len(rows) > 64:
        raise BenchmarkError("distribution requests must contain 1..64 rows")
    names: set[str] = set()
    total_weight = 0
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BenchmarkError(f"distribution row {index} must be an object")
        require_exact_keys(row, {"name", "method", "path", "weight", "expected_statuses", "headers", "body"}, f"distribution row {index}")
        name = row["name"]
        method = row["method"]
        request_path = row["path"]
        weight = row["weight"]
        statuses = row["expected_statuses"]
        headers = row["headers"]
        body = row["body"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", name) or name in names:
            raise BenchmarkError("distribution names must be unique bounded lowercase identifiers")
        names.add(name)
        if method not in {"GET", "POST", "PUT"}:
            raise BenchmarkError("distribution method must be GET, POST, or PUT")
        if not isinstance(request_path, str) or not request_path.startswith("/api/wwm-web-capacity/v1/") or "?" in request_path or "#" in request_path or ".." in request_path:
            raise BenchmarkError("distribution paths must be bounded coordinator v1 API paths")
        if not isinstance(weight, int) or isinstance(weight, bool) or not 1 <= weight <= 10_000:
            raise BenchmarkError("distribution weights must be integers in 1..10000")
        total_weight += weight
        if not isinstance(statuses, list) or not statuses or len(statuses) > 16 or any(not isinstance(code, int) or isinstance(code, bool) or not 100 <= code <= 599 for code in statuses) or len(set(statuses)) != len(statuses):
            raise BenchmarkError("expected_statuses must be unique HTTP statuses")
        if not isinstance(headers, dict) or any(key not in {"Origin", "Content-Type", "Accept"} or not isinstance(val, str) or len(val) > 512 for key, val in headers.items()):
            raise BenchmarkError("distribution headers are limited to Origin, Content-Type, and Accept")
        if method == "GET" and body is not None:
            raise BenchmarkError("GET distribution rows cannot carry a body")
        if method != "GET" and not isinstance(body, dict):
            raise BenchmarkError("mutating distribution rows require an explicit JSON object body")
        encoded = None if body is None else canonical_json(body)
        if encoded is not None and len(encoded) > 64 * 1024:
            raise BenchmarkError("distribution request body exceeds 64 KiB")
        normalized.append({"name": name, "method": method, "path": request_path, "weight": weight, "expected_statuses": statuses, "headers": headers, "body": body})
    if total_weight > 10_000:
        raise BenchmarkError("sum of distribution weights exceeds 10000")
    return {"schema": DISTRIBUTION_SCHEMA, "scope": SYNTHETIC_SCOPE, "requests": normalized}


def load_transactions(path: Path, required_count: int) -> list[bytes]:
    try:
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_JSON_FILE_BYTES:
            raise BenchmarkError("transaction JSONL exceeds its byte bound or is empty")
        lines = path.read_text(encoding="utf-8").splitlines()
    except BenchmarkError:
        raise
    except (OSError, UnicodeDecodeError) as error:
        raise BenchmarkError(f"cannot read transaction JSONL: {error}") from error
    if len(lines) != required_count:
        raise BenchmarkError(f"transaction JSONL must contain exactly {required_count} unique live submissions")
    payloads: list[bytes] = []
    seen: set[str] = set()
    for index, line in enumerate(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise BenchmarkError(f"transaction row {index} is invalid JSON") from error
        if not isinstance(row, dict):
            raise BenchmarkError(f"transaction row {index} must be an object")
        require_exact_keys(row, {"tx", "witnesses"}, f"transaction row {index}")
        for field in ("tx", "witnesses"):
            raw = row[field]
            if not isinstance(raw, str) or len(raw) == 0 or len(raw) > 2 * MAX_HTTP_BYTES or len(raw) % 2 or re.fullmatch(r"[0-9a-f]+", raw) is None:
                raise BenchmarkError(f"transaction row {index} {field} is not bounded canonical lowercase hex")
        payload = canonical_json(row)
        if len(payload) > MAX_HTTP_BYTES:
            raise BenchmarkError(f"transaction row {index} exceeds the node request bound")
        digest = sha256_bytes(payload)
        if digest in seen:
            raise BenchmarkError("transaction JSONL contains duplicate/replayed envelopes")
        seen.add(digest)
        payloads.append(payload)
    return payloads


def nearest_rank_p95(values: Sequence[int]) -> int:
    if not values or any(not isinstance(value, int) or value < 1 for value in values):
        raise BenchmarkError("p95 requires non-empty positive integer microsecond samples")
    ordered = sorted(values)
    rank = (95 * len(ordered) + 99) // 100
    return ordered[rank - 1]


def phase_summary(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    finality = [int(row["finality_latency_us"]) for row in samples]
    return {
        "sample_count": len(samples),
        "p95_method": P95_METHOD,
        "submission_p95_us": nearest_rank_p95([int(row["submission_latency_us"]) for row in samples]),
        "receipt_p95_us": nearest_rank_p95([int(row["receipt_latency_us"]) for row in samples]),
        "finality_p95_us": nearest_rank_p95(finality),
        "raw_samples": list(samples),
    }


def degradation(baseline_p95: int, observed_p95: int) -> dict[str, Any]:
    numerator = observed_p95 - baseline_p95
    basis_points = numerator * 10_000 / baseline_p95
    return {
        "baseline_p95_us": baseline_p95,
        "observed_p95_us": observed_p95,
        "difference_us": numerator,
        "degradation_basis_points": round(basis_points, 6),
        "threshold_basis_points": 500,
        "comparison": "PASS_IFF_OBSERVED_TIMES_10000_LT_BASELINE_TIMES_10500",
        "passed": observed_p95 * 10_000 < baseline_p95 * 10_500,
    }


def run_node_phase(
    name: str,
    recorder: NodeRecorder,
    payloads: Sequence[bytes],
    chain_id: str,
    genesis_hash: str,
    phase_timeout: float,
    poll_interval: float,
) -> dict[str, Any]:
    transactions: list[dict[str, Any]] = []
    for index, payload in enumerate(payloads):
        started = time.perf_counter_ns()
        submitted, submission_request_us = recorder.require_json("POST", "/submit_tx", payload)
        if submitted.get("accepted") is not True:
            raise BenchmarkError(f"{name} transaction {index} was not accepted")
        txid = require_hex32(submitted.get("txid"), f"{name} transaction {index} live txid")
        transactions.append({
            "sequence": index,
            "payload": payload,
            "started_ns": started,
            "submission_latency_us": submission_request_us,
            "txid": txid,
            "receipt_polls": 0,
            "status_polls": 0,
            "receipt": None,
            "receipt_latency_us": None,
            "finality_latency_us": None,
            "finalized_height": None,
        })

    deadline = time.monotonic() + phase_timeout
    pending_receipts = set(range(len(transactions)))
    while pending_receipts and time.monotonic() < deadline:
        for item_index in sorted(pending_receipts):
            transaction = transactions[item_index]
            result = recorder.request("GET", f"/receipt/{transaction['txid']}")
            transaction["receipt_polls"] += 1
            if result.status == 200 and result.error is None:
                candidate = parse_json_body(result.body, recorder.base_url + f"/receipt/{transaction['txid']}")
                candidate_state = candidate.get("state")
                candidate_record = candidate.get("receipt")
                candidate_height = candidate_state.get("settled_height") if isinstance(candidate_state, dict) else None
                if isinstance(candidate_height, int) and not isinstance(candidate_height, bool) and isinstance(candidate_record, dict):
                    if (
                        candidate_height < 0
                        or candidate_state.get("status_code") != 0
                        or candidate_record.get("txid") != transaction["txid"]
                        or candidate_record.get("status") != 0
                    ):
                        raise BenchmarkError(f"{name} transaction {transaction['txid']} live receipt is not a successful ordinary settlement")
                    transaction["receipt"] = candidate
                    transaction["receipt_latency_us"] = max(
                        1, (time.perf_counter_ns() - transaction["started_ns"]) // 1000
                    )
                    pending_receipts.remove(item_index)
                    continue
                if isinstance(candidate_state, dict) and candidate_state.get("status_code") not in {None, 0}:
                    raise BenchmarkError(f"{name} transaction {transaction['txid']} reached a failed terminal receipt")
            elif result.status != 404:
                raise BenchmarkError(
                    f"{name} transaction {transaction['txid']} receipt returned an error instead of a live 404/200"
                )
        if pending_receipts:
            time.sleep(poll_interval)
    if pending_receipts:
        transaction = transactions[min(pending_receipts)]
        raise BenchmarkError(f"{name} transaction {transaction['txid']} produced no live receipt before timeout")

    pending_finality = set(range(len(transactions)))
    while pending_finality and time.monotonic() < deadline:
        status, _ = recorder.require_json("GET", "/status")
        validate_node_status(status, chain_id, genesis_hash)
        observed_finalized_height = finalized_height(status)
        observed_at = time.perf_counter_ns()
        for item_index in sorted(pending_finality):
            transaction = transactions[item_index]
            transaction["status_polls"] += 1
            state = transaction["receipt"]["state"]
            if observed_finalized_height >= state["settled_height"]:
                transaction["finalized_height"] = observed_finalized_height
                transaction["finality_latency_us"] = max(
                    1, (observed_at - transaction["started_ns"]) // 1000
                )
                pending_finality.remove(item_index)
        if pending_finality:
            time.sleep(poll_interval)
    if pending_finality:
        transaction = transactions[min(pending_finality)]
        raise BenchmarkError(
            f"{name} transaction {transaction['txid']} did not receive live finalized coverage before timeout"
        )

    samples = []
    for transaction in transactions:
        state = transaction["receipt"]["state"]
        samples.append({
            "sequence": transaction["sequence"],
            "transaction_payload_sha256": sha256_bytes(transaction["payload"]),
            "txid": transaction["txid"],
            "settled_height": state["settled_height"],
            "finalized_height": transaction["finalized_height"],
            "submission_latency_us": transaction["submission_latency_us"],
            "receipt_latency_us": transaction["receipt_latency_us"],
            "finality_latency_us": transaction["finality_latency_us"],
            "receipt_poll_count": transaction["receipt_polls"],
            "status_poll_count": transaction["status_polls"],
        })
    return phase_summary(samples)


class CoordinatorSaturator:
    def __init__(self, base_url: str, distribution: Mapping[str, Any], workers: int, timeout: float, maximum: int, expect_available: bool):
        self.base_url = base_url
        self.rows = list(distribution["requests"])
        self.schedule: list[int] = []
        for index, row in enumerate(self.rows):
            self.schedule.extend([index] * int(row["weight"]))
        self.workers = workers
        self.timeout = timeout
        self.maximum = maximum
        self.expect_available = expect_available
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.next_index = 0
        self.results: list[dict[str, Any]] = []

    def start(self) -> None:
        for index in range(self.workers):
            thread = threading.Thread(target=self._worker, name=f"coordinator-load-{index}", daemon=True)
            self.threads.append(thread)
            thread.start()

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            with self.lock:
                if self.next_index >= self.maximum:
                    return
                sequence = self.next_index
                self.next_index += 1
            row = self.rows[self.schedule[sequence % len(self.schedule)]]
            body = None if row["body"] is None else canonical_json(row["body"])
            result = http_request(
                self.base_url + row["path"], method=row["method"], body=body,
                headers={**row["headers"], "Accept": row["headers"].get("Accept", "application/json")}, timeout=self.timeout,
            )
            expected = result.status is not None and result.status in row["expected_statuses"]
            if self.expect_available:
                classification = "EXPECTED_LIVE_RESPONSE" if expected else "ERROR"
            else:
                classification = "UNEXPECTED_LIVE_SUCCESS" if expected else "EXPECTED_OUTAGE_ERROR"
            record = {
                "sequence": sequence,
                "request_name": row["name"],
                "status": result.status,
                "latency_us": result.latency_us,
                "error": result.error,
                "classification": classification,
                "_completed_ns": time.perf_counter_ns(),
            }
            with self.lock:
                self.results.append(record)

    def wait_for_requests(self, count: int, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if len(self.results) >= count:
                    return
                exhausted = self.next_index >= self.maximum and len(self.results) >= self.next_index
            if exhausted:
                break
            time.sleep(0.005)
        raise BenchmarkError(f"coordinator load produced fewer than {count} completed live requests")

    def stop(self, measurement_window_ns: tuple[int, int] | None = None) -> dict[str, Any]:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=max(1.0, self.timeout + 0.5))
        if any(thread.is_alive() for thread in self.threads):
            raise BenchmarkError("coordinator load worker did not stop within its bound")
        ordered = sorted(self.results, key=lambda row: row["sequence"])
        public_ordered = [
            {key: value for key, value in row.items() if key != "_completed_ns"}
            for row in ordered
        ]
        counts = Counter(row["request_name"] for row in public_ordered)
        statuses = Counter("NETWORK_ERROR" if row["status"] is None else str(row["status"]) for row in public_ordered)
        classes = Counter(row["classification"] for row in public_ordered)
        errors = [row for row in public_ordered if row["classification"] != "EXPECTED_LIVE_RESPONSE"]
        latency = [int(row["latency_us"]) for row in public_ordered]
        stream = b"".join(canonical_json(row) + b"\n" for row in public_ordered)
        concurrent = None
        if measurement_window_ns is not None:
            window_start, window_end = measurement_window_ns
            concurrent = sum(window_start <= row["_completed_ns"] <= window_end for row in ordered)
        return {
            "total_requests": len(public_ordered),
            "requests_completed_during_ordinary_rpc_phase": concurrent,
            "requests_by_distribution_name": dict(sorted(counts.items())),
            "responses_by_status": dict(sorted(statuses.items())),
            "classifications": dict(sorted(classes.items())),
            "latency_p95_us": nearest_rank_p95(latency) if latency else None,
            "result_stream_sha256": sha256_bytes(stream),
            "result_stream_encoding": "CANONICAL_JSON_LINES_SEQUENCE_ORDER",
            "error_count": len(errors),
            "error_examples": errors[:MAX_ERROR_EXAMPLES],
        }


def load_outage_control(path: Path) -> dict[str, Any]:
    value = load_json(path, "outage control", maximum=64 * 1024)
    require_exact_keys(value, {"schema", "stop_argv", "start_argv"}, "outage control")
    if value["schema"] != OUTAGE_CONTROL_SCHEMA:
        raise BenchmarkError("unsupported outage-control schema")
    normalized: dict[str, Any] = {"schema": OUTAGE_CONTROL_SCHEMA}
    for field in ("stop_argv", "start_argv"):
        argv = value[field]
        if not isinstance(argv, list) or not 1 <= len(argv) <= 32 or any(not isinstance(part, str) or not part or len(part) > 4096 or "\x00" in part for part in argv):
            raise BenchmarkError(f"{field} must be a bounded non-shell argv")
        executable = Path(argv[0])
        if not executable.is_absolute() or not executable.is_file():
            raise BenchmarkError(f"{field} executable must be an existing absolute file")
        normalized[field] = argv
    return normalized


def run_control(argv: Sequence[str], timeout: float, label: str) -> dict[str, Any]:
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(list(argv), shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BenchmarkError(f"{label} outage-control command failed: {error}") from error
    if completed.returncode != 0:
        raise BenchmarkError(f"{label} outage-control command returned {completed.returncode}")
    return {
        "label": label,
        "executable": argv[0],
        "argv_sha256": sha256_bytes(canonical_json(list(argv))),
        "returncode": completed.returncode,
        "duration_us": max(1, (time.perf_counter_ns() - started) // 1000),
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr_sha256": sha256_bytes(completed.stderr),
    }


def wait_coordinator_state(base_url: str, timeout: float, expected_up: bool) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    attempts = 0
    last: HttpResult | None = None
    while time.monotonic() < deadline:
        attempts += 1
        value, result = coordinator_config(base_url, min(1.0, timeout))
        last = result
        up = value is not None
        if up == expected_up:
            return value, {"attempts": attempts, "last_status": result.status, "last_error": result.error}
        time.sleep(0.05)
    state = "up" if expected_up else "unavailable"
    detail = None if last is None else {"status": last.status, "error": last.error}
    raise BenchmarkError(f"coordinator did not become {state} within timeout; last={detail}")


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise BenchmarkError(f"cannot read signing key: {error}") from error
    if len(raw) == 64:
        try:
            text = raw.decode("ascii")
            if re.fullmatch(r"[0-9a-f]{64}", text):
                raw = bytes.fromhex(text)
        except UnicodeDecodeError:
            pass
    if len(raw) != 32:
        raise BenchmarkError("signing key must be exactly 32 raw bytes or 64 lowercase hex characters")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as error:
        raise BenchmarkError("signing key is not a valid Ed25519 seed") from error


def sign_evidence(payload: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    canonical = canonical_json(payload)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "schema": EVIDENCE_SCHEMA,
        "payload": dict(payload),
        "signature": {
            "suite": "Ed25519",
            "domain": SIGNATURE_DOMAIN.decode("ascii", errors="strict"),
            "public_key": public.hex(),
            "signed_payload_sha256": sha256_bytes(canonical),
            "signature": key.sign(SIGNATURE_DOMAIN + canonical).hex(),
        },
    }


def verify_evidence(evidence: Mapping[str, Any]) -> None:
    require_exact_keys(evidence, {"schema", "payload", "signature"}, "evidence envelope")
    if evidence["schema"] != EVIDENCE_SCHEMA or not isinstance(evidence["payload"], dict) or not isinstance(evidence["signature"], dict):
        raise BenchmarkError("evidence envelope is malformed")
    signature = evidence["signature"]
    require_exact_keys(signature, {"suite", "domain", "public_key", "signed_payload_sha256", "signature"}, "evidence signature")
    payload = evidence["payload"]
    canonical = canonical_json(payload)
    if signature["suite"] != "Ed25519" or signature["domain"] != SIGNATURE_DOMAIN.decode() or signature["signed_payload_sha256"] != sha256_bytes(canonical):
        raise BenchmarkError("evidence signature metadata is forged or malformed")
    try:
        public = bytes.fromhex(require_hex32(signature["public_key"], "evidence public key"))
        raw_signature = bytes.fromhex(signature["signature"])
        if len(raw_signature) != 64:
            raise ValueError("signature length")
        Ed25519PublicKey.from_public_bytes(public).verify(raw_signature, SIGNATURE_DOMAIN + canonical)
    except (ValueError, InvalidSignature) as error:
        raise BenchmarkError("evidence Ed25519 signature is forged or invalid") from error
    if (
        payload.get("environment") != "DEVNET"
        or payload.get("scope") != SCOPE
        or payload.get("insert_once") is not True
        or payload.get("verdict") != "PASS"
        or payload.get("proof_claim") is not True
    ):
        raise BenchmarkError("evidence is not a passing insert-once live DEVNET measurement")
    promotion = payload.get("promotion")
    if promotion != {"production": False, "production_custody": False, "rewards": False, "controls_enabled": False, "decision": "HOLD_DEVNET_ONLY"}:
        raise BenchmarkError("evidence is not explicitly non-promoting")
    phases = payload.get("ordinary_rpc_phases")
    if not isinstance(phases, dict) or set(phases) != {"baseline", "loaded", "coordinator_outage"}:
        raise BenchmarkError("evidence phase set is incomplete")
    floor = payload.get("sample_floor")
    if not isinstance(floor, int) or floor < HARD_MIN_SAMPLE_FLOOR:
        raise BenchmarkError("evidence sample floor is not meaningful")
    for name, phase in phases.items():
        if not isinstance(phase, dict) or phase.get("sample_count") < floor or phase.get("p95_method") != P95_METHOD:
            raise BenchmarkError(f"evidence phase {name} has insufficient or ambiguous samples")
        raw = phase.get("raw_samples")
        if not isinstance(raw, list) or len(raw) != phase["sample_count"]:
            raise BenchmarkError(f"evidence phase {name} does not carry its raw samples")
        if nearest_rank_p95([row["finality_latency_us"] for row in raw]) != phase.get("finality_p95_us"):
            raise BenchmarkError(f"evidence phase {name} p95 is forged")
    base = phases["baseline"]["finality_p95_us"]
    for key, phase_name in (("loaded_vs_baseline", "loaded"), ("outage_vs_baseline", "coordinator_outage")):
        expected = degradation(base, phases[phase_name]["finality_p95_us"])
        if payload.get("degradation", {}).get(key) != expected or not expected["passed"]:
            raise BenchmarkError(f"evidence {key} degradation does not pass")
    load = payload.get("coordinator_load")
    outage = payload.get("coordinator_outage")
    if (
        not isinstance(load, dict)
        or load.get("requests_completed_during_ordinary_rpc_phase", 0) < floor
        or load.get("classifications", {}).get("EXPECTED_LIVE_RESPONSE", 0) < floor
        or load.get("error_count") != 0
    ):
        raise BenchmarkError("evidence has no concurrent clean live coordinator saturation")
    if (
        not isinstance(outage, dict)
        or outage.get("requests_completed_during_ordinary_rpc_phase", 0) < floor
        or outage.get("classifications", {}).get("UNEXPECTED_LIVE_SUCCESS", 0) != 0
        or outage.get("classifications", {}).get("EXPECTED_OUTAGE_ERROR", 0) < floor
    ):
        raise BenchmarkError("evidence did not observe concurrent coordinator outage while ordinary RPC continued")
    if payload.get("coordinator_restored") is not True:
        raise BenchmarkError("evidence does not show coordinator restoration")


def write_create_new(path: Path, evidence: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json(evidence) + b"\n"
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise BenchmarkError("evidence output already exists; benchmark evidence is insert-once") from error
    except OSError as error:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise BenchmarkError(f"cannot create evidence output: {error}") from error


def validate_operator_hashes(repository_revision: str, repository_tree_sha256: str, node_process_sha256: str, coordinator_process_sha256: str) -> dict[str, Any]:
    if REVISION.fullmatch(repository_revision) is None:
        raise BenchmarkError("repository revision must be canonical lowercase 40- or 64-hex")
    return {
        "repository_revision": repository_revision,
        "repository_tree_sha256": require_hex32(repository_tree_sha256, "repository tree SHA-256"),
        "node_process_sha256": require_hex32(node_process_sha256, "node process SHA-256"),
        "coordinator_process_sha256": require_hex32(coordinator_process_sha256, "coordinator process SHA-256"),
        "provenance": "SUPPLIED_BY_OPERATOR_NOT_RECOMPUTED_BY_BENCHMARK",
    }


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    if args.environment != "DEVNET":
        raise BenchmarkError("benchmark environment must be explicit DEVNET")
    if args.sample_floor < HARD_MIN_SAMPLE_FLOOR or args.sample_floor > MAX_SAMPLES_PER_PHASE:
        raise BenchmarkError(f"sample floor must be {HARD_MIN_SAMPLE_FLOOR}..={MAX_SAMPLES_PER_PHASE}")
    if args.samples < args.sample_floor or args.samples > MAX_SAMPLES_PER_PHASE:
        raise BenchmarkError("samples per phase must meet the configured meaningful floor and hard bound")
    if not 1 <= args.load_workers <= 64:
        raise BenchmarkError("load workers must be 1..64")
    if not args.sample_floor <= args.max_coordinator_requests <= MAX_COORDINATOR_REQUESTS:
        raise BenchmarkError("max coordinator requests must meet the sample floor and hard bound")
    if not 0.01 <= args.http_timeout <= 300 or not 0.001 <= args.poll_interval <= 10 or not 0.1 <= args.phase_timeout <= 3600 or not 0.1 <= args.control_timeout <= 300:
        raise BenchmarkError("timeout/poll arguments are outside bounded ranges")
    node_url = validate_loopback_base(args.node_url, "node URL")
    coordinator_url = validate_loopback_base(args.coordinator_url, "coordinator URL")
    if urlsplit(node_url).netloc == urlsplit(coordinator_url).netloc:
        raise BenchmarkError("node and coordinator must use distinct isolated loopback listeners")
    if args.output.exists():
        raise BenchmarkError("evidence output already exists; benchmark evidence is insert-once")
    chain_id = require_hex32(args.chain_id, "chain_id")
    genesis_hash = require_hex32(args.genesis_hash, "genesis_hash")
    identities = validate_operator_hashes(args.repository_revision, args.repository_tree_sha256, args.node_process_sha256, args.coordinator_process_sha256)
    try:
        token = args.node_token_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise BenchmarkError(f"cannot read node bearer token: {error}") from error
    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise BenchmarkError("node bearer token file must contain one bounded non-whitespace token")
    distribution = load_distribution(args.distribution)
    outage_control = load_outage_control(args.outage_control)
    payloads = load_transactions(args.transactions, args.samples * 3)
    key = load_signing_key(args.signing_key)
    recorder = NodeRecorder(node_url, token, args.http_timeout)
    initial_status, _ = recorder.require_json("GET", "/status")
    node_identity = validate_node_status(initial_status, chain_id, genesis_hash)
    live_config, config_result = coordinator_config(coordinator_url, args.http_timeout)
    if live_config is None:
        raise BenchmarkError("coordinator config endpoint returned no live HTTP 200 response")
    coordinator_identity = validate_coordinator_config(live_config, chain_id, genesis_hash)
    transaction_set_sha256 = sha256_bytes(b"".join(sha256_bytes(payload).encode("ascii") + b"\n" for payload in payloads))

    baseline_alignment = wait_phase_alignment(
        "baseline", recorder, chain_id, genesis_hash, args.phase_timeout, args.poll_interval
    )
    baseline = run_node_phase("baseline", recorder, payloads[:args.samples], chain_id, genesis_hash, args.phase_timeout, args.poll_interval)
    baseline["alignment"] = baseline_alignment

    load_runner = CoordinatorSaturator(coordinator_url, distribution, args.load_workers, args.http_timeout, args.max_coordinator_requests, True)
    load_runner.start()
    load_window_start: int | None = None
    try:
        load_runner.wait_for_requests(args.sample_floor, args.phase_timeout)
        loaded_alignment = wait_phase_alignment(
            "loaded", recorder, chain_id, genesis_hash, args.phase_timeout, args.poll_interval
        )
        load_window_start = time.perf_counter_ns()
        loaded = run_node_phase("loaded", recorder, payloads[args.samples:2 * args.samples], chain_id, genesis_hash, args.phase_timeout, args.poll_interval)
        loaded["alignment"] = loaded_alignment
    finally:
        load_window = None if load_window_start is None else (load_window_start, time.perf_counter_ns())
        load_summary = load_runner.stop(load_window)
    if (
        load_summary["total_requests"] < args.sample_floor
        or load_summary["requests_completed_during_ordinary_rpc_phase"] < args.sample_floor
        or load_summary["error_count"] != 0
    ):
        raise BenchmarkError("coordinator saturation did not produce enough concurrent clean live responses")

    stop_record = run_control(outage_control["stop_argv"], args.control_timeout, "stop")
    stopped = True
    start_record: dict[str, Any] | None = None
    restored_probe: dict[str, Any] | None = None
    try:
        _, unavailable_probe = wait_coordinator_state(coordinator_url, args.control_timeout, False)
        outage_runner = CoordinatorSaturator(coordinator_url, distribution, args.load_workers, args.http_timeout, args.max_coordinator_requests, False)
        outage_runner.start()
        outage_window_start: int | None = None
        try:
            outage_runner.wait_for_requests(args.sample_floor, args.phase_timeout)
            outage_alignment = wait_phase_alignment(
                "coordinator_outage",
                recorder,
                chain_id,
                genesis_hash,
                args.phase_timeout,
                args.poll_interval,
            )
            outage_window_start = time.perf_counter_ns()
            outage_phase = run_node_phase("coordinator_outage", recorder, payloads[2 * args.samples:], chain_id, genesis_hash, args.phase_timeout, args.poll_interval)
            outage_phase["alignment"] = outage_alignment
        finally:
            outage_window = None if outage_window_start is None else (outage_window_start, time.perf_counter_ns())
            outage_summary = outage_runner.stop(outage_window)
        if (
            outage_summary["requests_completed_during_ordinary_rpc_phase"] < args.sample_floor
            or outage_summary["classifications"].get("UNEXPECTED_LIVE_SUCCESS", 0) != 0
            or outage_summary["classifications"].get("EXPECTED_OUTAGE_ERROR", 0) < args.sample_floor
        ):
            raise BenchmarkError("coordinator did not remain unavailable under concurrent outage traffic")
    finally:
        if stopped:
            start_record = run_control(outage_control["start_argv"], args.control_timeout, "start")
            restored_value, restored_probe = wait_coordinator_state(coordinator_url, args.control_timeout, True)
            if restored_value is None:
                raise BenchmarkError("coordinator did not return a live config after restart")
            validate_coordinator_config(restored_value, chain_id, genesis_hash)

    loaded_degradation = degradation(baseline["finality_p95_us"], loaded["finality_p95_us"])
    outage_degradation = degradation(baseline["finality_p95_us"], outage_phase["finality_p95_us"])
    if not loaded_degradation["passed"]:
        raise BenchmarkError(
            "loaded ordinary finality p95 degradation is greater than or equal to 5%; "
            f"baseline_us={baseline['finality_p95_us']} loaded_us={loaded['finality_p95_us']} "
            f"degradation_bps={loaded_degradation['degradation_basis_points']}"
        )
    if not outage_degradation["passed"]:
        raise BenchmarkError(
            "coordinator-outage ordinary finality p95 degradation is greater than or equal to 5%; "
            f"baseline_us={baseline['finality_p95_us']} outage_us={outage_phase['finality_p95_us']} "
            f"degradation_bps={outage_degradation['degradation_basis_points']}"
        )
    final_status, _ = recorder.require_json("GET", "/status")
    terminal_node = validate_node_status(final_status, chain_id, genesis_hash)
    if recorder.errors:
        raise BenchmarkError("ordinary authenticated node RPC had network errors")

    payload: dict[str, Any] = {
        "environment": args.environment,
        "scope": SCOPE,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "insert_once": True,
        "verdict": "PASS",
        "proof_claim": True,
        "claim": "LIVE_LOOPBACK_DEVNET_CHAIN_ISOLATION_THRESHOLD_MET_ONLY",
        "promotion": {"production": False, "production_custody": False, "rewards": False, "controls_enabled": False, "decision": "HOLD_DEVNET_ONLY"},
        "sample_floor": args.sample_floor,
        "samples_per_phase": args.samples,
        "endpoint_identities": {
            "node_rpc": node_url,
            "coordinator": coordinator_url,
            "node_initial": node_identity,
            "node_terminal": terminal_node,
            "coordinator_config": coordinator_identity,
            "coordinator_config_probe_latency_us": config_result.latency_us,
        },
        "operator_supplied_hashes": identities,
        "transaction_set": {"count": len(payloads), "ordered_payload_digest_sha256": transaction_set_sha256, "source": "PREBUILT_UNIQUE_ORDINARY_AUTHENTICATED_NODE_RPC_ENVELOPES"},
        "synthetic_distribution": distribution,
        "synthetic_distribution_sha256": sha256_bytes(canonical_json(distribution)),
        "ordinary_rpc_phases": {"baseline": baseline, "loaded": loaded, "coordinator_outage": outage_phase},
        "degradation": {"loaded_vs_baseline": loaded_degradation, "outage_vs_baseline": outage_degradation},
        "node_rpc_traffic": recorder.summary(),
        "coordinator_load": load_summary,
        "coordinator_outage": outage_summary,
        "outage_control": {
            "mode": "OPERATOR_CONTROLLED_SAME_ENDPOINT_PROCESS_UNAVAILABILITY",
            "stop": stop_record,
            "unavailable_probe": unavailable_probe,
            "start": start_record,
            "restored_probe": restored_probe,
        },
        "coordinator_restored": True,
        "errors": {"ordinary_node_rpc": [], "coordinator_loaded": load_summary["error_examples"], "coordinator_outage_expected": outage_summary["error_examples"]},
        "disclosures": [
            "Ordinary transaction/finality latencies are measured from real authenticated loopback node RPC responses.",
            "Coordinator request selection is a configured synthetic distribution, not a measured real-participant workload distribution.",
            "This evidence is owner-controlled loopback devnet evidence only and cannot promote production custody, rewards, controls, or public availability.",
            "Operator-supplied process and repository hashes are recorded but are not independently recomputed by this benchmark.",
        ],
    }
    evidence = sign_evidence(payload, key)
    verify_evidence(evidence)
    return evidence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, choices=("DEVNET",), help="must be the explicit non-production DEVNET profile")
    parser.add_argument("--node-url", required=True, help="explicit numeric loopback node origin, e.g. http://127.0.0.1:9000")
    parser.add_argument("--node-token-file", type=Path, required=True, help="file containing the live node RPC bearer token")
    parser.add_argument("--coordinator-url", required=True, help="distinct explicit numeric loopback coordinator origin")
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--genesis-hash", required=True)
    parser.add_argument("--transactions", type=Path, required=True, help="JSONL of exactly 3*samples unique {tx,witnesses} envelopes")
    parser.add_argument("--distribution", type=Path, required=True, help="closed synthetic coordinator request distribution JSON")
    parser.add_argument("--outage-control", type=Path, required=True, help="closed non-shell stop/start argv JSON for the coordinator")
    parser.add_argument("--signing-key", type=Path, required=True, help="32 raw-byte or lowercase-hex Ed25519 devnet evidence seed")
    parser.add_argument("--output", type=Path, required=True, help="create-new signed evidence path")
    parser.add_argument("--repository-revision", required=True)
    parser.add_argument("--repository-tree-sha256", required=True)
    parser.add_argument("--node-process-sha256", required=True)
    parser.add_argument("--coordinator-process-sha256", required=True)
    parser.add_argument("--sample-floor", type=int, default=30)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--load-workers", type=int, default=8)
    parser.add_argument("--max-coordinator-requests", type=int, default=100_000)
    parser.add_argument("--http-timeout", type=float, default=2.0)
    parser.add_argument("--poll-interval", type=float, default=0.05)
    parser.add_argument("--phase-timeout", type=float, default=180.0)
    parser.add_argument("--control-timeout", type=float, default=30.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        evidence = run_benchmark(args)
        write_create_new(args.output, evidence)
    except BenchmarkError as error:
        parser.exit(1, f"chain-isolation benchmark rejected: {error}\n")
    print(json.dumps({
        "verdict": evidence["payload"]["verdict"],
        "proof_claim": evidence["payload"]["proof_claim"],
        "scope": evidence["payload"]["scope"],
        "output": str(args.output),
        "signed_payload_sha256": evidence["signature"]["signed_payload_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
