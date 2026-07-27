#!/usr/bin/env python3
"""Finality-anchored, non-production WWM continual-learning coordinator.

The coordinator observes a quorum of node status endpoints, durably queues
insert-once model-improvement requests, and runs at most one shadow cycle per
finalized cadence. It never signs a chain transaction, mutates a serving alias,
or enables WWM controls. Successful output is an opaque signed handoff for the
separate reviewed operational-reconfiguration process.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import re
import signal
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import wwm_model_improvement as improvement

CONFIG_SCHEMA = "noos/wwm-continuous-learning-config/v1"
STATUS_SCHEMA = "noos/wwm-continuous-learning-status/v1"
HANDOFF_SCHEMA = "noos/wwm-continuous-learning-handoff/v1"
EPOCH_LENGTH = 256
MAX_CONFIG_BYTES = 1_048_576
MAX_REQUEST_BYTES = 4_194_304
MAX_STATUS_BYTES = 65_536
MAX_ERROR_BYTES = 2_048
MAX_ENDPOINTS = 16
MIN_ENDPOINTS = 3
FIXED_QUORUM = 2
REQUEST_STATES = (
    "QUEUED",
    "FINALITY_BLOCKED",
    "RUNNING",
    "SHADOW_CANDIDATE_READY",
    "REJECTED",
    "INTERRUPTED",
)
HEX32 = re.compile(r"^[0-9a-f]{64}$")


class ContinuousLearningError(RuntimeError):
    """Fail-closed coordinator error."""


@dataclass(frozen=True)
class StatusEndpoint:
    url: str
    control_cluster: str
    bearer_token_file: Path | None


@dataclass(frozen=True)
class CoordinatorConfig:
    environment: str
    production: bool
    monitoring_enabled: bool
    execution_enabled: bool
    chain_id: str
    genesis_hash: str
    status_endpoints: tuple[StatusEndpoint, ...]
    request_dir: Path
    evidence_root: Path
    state_db: Path
    status_file: Path
    gate_config: Path
    role_key_files: Mapping[str, Path | tuple[Path, ...]]
    poll_seconds: int
    request_timeout_seconds: int
    minimum_finalized_advance: int
    maximum_queued_cycles: int
    listen_host: str
    listen_port: int


@dataclass(frozen=True)
class FinalizedAnchor:
    chain_id: str
    genesis_hash: str
    epoch: int
    height: int
    checkpoint_hash: str
    control_clusters: tuple[str, ...]
    observed_endpoints: int
    observed_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "epoch": self.epoch,
            "height": self.height,
            "checkpoint_hash": self.checkpoint_hash,
            "control_clusters": list(self.control_clusters),
            "observed_endpoints": self.observed_endpoints,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class QueuedRequest:
    request_id: str
    path: Path
    request_sha256: str
    request_bytes: bytes
    not_before_finalized_height: int
    required_finalized_hash: str | None


StatusFetcher = Callable[[StatusEndpoint, int], Mapping[str, Any]]
CheckpointFetcher = Callable[[StatusEndpoint, int, int], str]
WorkflowRunner = Callable[[Mapping[str, Any], Path], Mapping[str, Any]]


def _bounded_load_with_bytes(path: Path, maximum: int) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ContinuousLearningError(f"regular non-symlink file required: {path}")
    try:
        with path.open("rb") as source:
            raw = source.read(maximum + 1)
    except OSError as error:
        raise ContinuousLearningError(f"cannot read JSON file {path}: {error}") from error
    if not raw or len(raw) > maximum:
        raise ContinuousLearningError(f"file size outside 1..{maximum}: {path}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContinuousLearningError(f"invalid JSON file {path}: {error}") from error
    if not isinstance(value, dict):
        raise ContinuousLearningError(f"JSON object required: {path}")
    return value, raw


def _bounded_load(path: Path, maximum: int) -> dict[str, Any]:
    value, _ = _bounded_load_with_bytes(path, maximum)
    return value


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None or value == "0" * 64:
        raise ContinuousLearningError(f"{label} must be nonzero lowercase hex32")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ContinuousLearningError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _resolve(base: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ContinuousLearningError(f"{label} path is required")
    path = Path(value)
    return path if path.is_absolute() else (base / path).resolve()


def _endpoint(base: Path, value: Any, index: int) -> StatusEndpoint:
    if not isinstance(value, dict):
        raise ContinuousLearningError(f"status_endpoints[{index}] must be an object")
    url = value.get("url")
    if not isinstance(url, str):
        raise ContinuousLearningError(f"status_endpoints[{index}].url is required")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ContinuousLearningError(f"status_endpoints[{index}].url is not a bounded HTTP(S) URL")
    cluster = _hex32(value.get("control_cluster"), f"status_endpoints[{index}].control_cluster")
    token_value = value.get("bearer_token_file")
    token_file = None if token_value is None else _resolve(base, token_value, "bearer_token_file")
    if (
        token_file is not None
        and parsed.scheme != "https"
        and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
    ):
        raise ContinuousLearningError(
            f"status_endpoints[{index}] bearer tokens require HTTPS or loopback"
        )
    return StatusEndpoint(url, cluster, token_file)


def load_config(path: Path) -> CoordinatorConfig:
    value = _bounded_load(path, MAX_CONFIG_BYTES)
    if value.get("schema") != CONFIG_SCHEMA:
        raise ContinuousLearningError("unsupported continuous-learning config schema")
    environment = value.get("environment")
    production = value.get("production")
    if environment not in {"local", "devnet", "testnet"} or production is not False:
        raise ContinuousLearningError("continuous learning is restricted to explicit non-production environments")
    monitoring_enabled = value.get("monitoring_enabled")
    execution_enabled = value.get("execution_enabled")
    if not isinstance(monitoring_enabled, bool) or not isinstance(execution_enabled, bool):
        raise ContinuousLearningError("monitoring_enabled and execution_enabled must be booleans")
    if not monitoring_enabled:
        raise ContinuousLearningError("monitoring_enabled must remain true")

    base = path.resolve().parent
    raw_endpoints = value.get("status_endpoints")
    if not isinstance(raw_endpoints, list) or not MIN_ENDPOINTS <= len(raw_endpoints) <= MAX_ENDPOINTS:
        raise ContinuousLearningError(f"status_endpoints must contain {MIN_ENDPOINTS}..{MAX_ENDPOINTS} entries")
    endpoints = tuple(_endpoint(base, item, index) for index, item in enumerate(raw_endpoints))
    clusters = [endpoint.control_cluster for endpoint in endpoints]
    if len(set(clusters)) != len(clusters):
        raise ContinuousLearningError("status endpoint control clusters must be distinct")
    urls = [endpoint.url for endpoint in endpoints]
    if len(set(urls)) != len(urls):
        raise ContinuousLearningError("status endpoint URLs must be distinct")

    role_files_value = value.get("role_key_files", {})
    if not isinstance(role_files_value, dict):
        raise ContinuousLearningError("role_key_files must be an object")
    role_files: dict[str, Path | tuple[Path, ...]] = {}
    if execution_enabled:
        expected = {"builder", "sponsor", "trainer", "successor", "activator", "evaluators"}
        if set(role_files_value) != expected:
            raise ContinuousLearningError(f"execution requires exactly these role key files: {sorted(expected)}")
        for role in expected - {"evaluators"}:
            role_files[role] = _resolve(base, role_files_value[role], f"role_key_files.{role}")
        evaluator_values = role_files_value["evaluators"]
        if not isinstance(evaluator_values, list) or len(evaluator_values) < 2:
            raise ContinuousLearningError("at least two evaluator key files are required")
        role_files["evaluators"] = tuple(
            _resolve(base, item, f"role_key_files.evaluators[{index}]")
            for index, item in enumerate(evaluator_values)
        )
    elif role_files_value:
        raise ContinuousLearningError("role_key_files must be absent while execution is disabled")

    listen = value.get("listen")
    if not isinstance(listen, dict):
        raise ContinuousLearningError("listen object is required")
    listen_host = listen.get("host")
    if listen_host not in {"127.0.0.1", "::1", "localhost"}:
        raise ContinuousLearningError("continual-learning status must bind to loopback")

    return CoordinatorConfig(
        environment=environment,
        production=False,
        monitoring_enabled=True,
        execution_enabled=execution_enabled,
        chain_id=_hex32(value.get("chain_id"), "chain_id"),
        genesis_hash=_hex32(value.get("genesis_hash"), "genesis_hash"),
        status_endpoints=endpoints,
        request_dir=_resolve(base, value.get("request_dir"), "request_dir"),
        evidence_root=_resolve(base, value.get("evidence_root"), "evidence_root"),
        state_db=_resolve(base, value.get("state_db"), "state_db"),
        status_file=_resolve(base, value.get("status_file"), "status_file"),
        gate_config=_resolve(base, value.get("gate_config"), "gate_config"),
        role_key_files=role_files,
        poll_seconds=_integer(value.get("poll_seconds"), "poll_seconds", 1, 3_600),
        request_timeout_seconds=_integer(
            value.get("request_timeout_seconds"), "request_timeout_seconds", 1, 120
        ),
        minimum_finalized_advance=_integer(
            value.get("minimum_finalized_advance"), "minimum_finalized_advance", 1, 1_000_000
        ),
        maximum_queued_cycles=_integer(
            value.get("maximum_queued_cycles"), "maximum_queued_cycles", 1, 32
        ),
        listen_host=listen_host,
        listen_port=_integer(listen.get("port"), "listen.port", 1, 65_535),
    )


def _read_secret(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise ContinuousLearningError(f"{label} key must be a regular non-symlink file")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ContinuousLearningError(f"{label} key file must not be group/world accessible")
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ContinuousLearningError(f"cannot read {label} key file") from error
    return _hex32(value, f"{label} signing seed")


def load_role_seeds(config: CoordinatorConfig) -> dict[str, Any]:
    if not config.execution_enabled:
        raise ContinuousLearningError("role keys are unavailable while execution is disabled")
    seeds: dict[str, Any] = {}
    for role in ("builder", "sponsor", "trainer", "successor", "activator"):
        path = config.role_key_files[role]
        if not isinstance(path, Path):
            raise ContinuousLearningError(f"invalid {role} key binding")
        seeds[role] = _read_secret(path, role)
    evaluator_paths = config.role_key_files["evaluators"]
    if not isinstance(evaluator_paths, tuple):
        raise ContinuousLearningError("invalid evaluator key bindings")
    seeds["evaluators"] = [
        _read_secret(path, f"evaluator[{index}]") for index, path in enumerate(evaluator_paths)
    ]
    flattened = [seeds[role] for role in ("builder", "sponsor", "trainer", "successor", "activator")]
    flattened.extend(seeds["evaluators"])
    if len(set(flattened)) != len(flattened):
        raise ContinuousLearningError("every learning role must use a distinct signing key")
    return seeds


def _token(path: Path | None) -> str | None:
    if path is None:
        return None
    if path.is_symlink() or not path.is_file():
        raise ContinuousLearningError(f"bearer token must be a regular non-symlink file: {path}")
    try:
        token = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ContinuousLearningError("cannot read status endpoint bearer token") from error
    if not token or len(token.encode("utf-8")) > 4_096 or "\r" in token or "\n" in token:
        raise ContinuousLearningError("invalid status endpoint bearer token")
    return token


def fetch_status(endpoint: StatusEndpoint, timeout_seconds: int) -> Mapping[str, Any]:
    headers = {"Accept": "application/json", "User-Agent": "noos-wwm-learningd/1"}
    token = _token(endpoint.bearer_token_file)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(endpoint.url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            content_type = response.headers.get_content_type()
            body = response.read(MAX_STATUS_BYTES + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise ContinuousLearningError(f"status endpoint unavailable: {endpoint.url}: {error}") from error
    if content_type != "application/json" or len(body) > MAX_STATUS_BYTES:
        raise ContinuousLearningError(f"status endpoint returned an invalid bounded response: {endpoint.url}")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContinuousLearningError(f"status endpoint returned invalid JSON: {endpoint.url}") from error
    if not isinstance(value, dict):
        raise ContinuousLearningError(f"status endpoint returned a non-object: {endpoint.url}")
    return value


def fetch_checkpoint(
    endpoint: StatusEndpoint,
    height: int,
    timeout_seconds: int,
) -> str:
    parsed = urllib.parse.urlsplit(endpoint.url)
    path = parsed.path.rstrip("/")
    prefix = path.rsplit("/", 1)[0]
    checkpoint_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"{prefix}/block/{height}", "", "")
    )
    checkpoint_endpoint = StatusEndpoint(
        checkpoint_url,
        endpoint.control_cluster,
        endpoint.bearer_token_file,
    )
    value = fetch_status(checkpoint_endpoint, timeout_seconds)
    observed_height = _integer(
        value.get("height"), "historical checkpoint height", 0, 2**63 - 1
    )
    if observed_height != height:
        raise ContinuousLearningError("historical checkpoint response has the wrong height")
    return _hex32(value.get("hash"), "historical checkpoint hash")




def observe_finalized(
    config: CoordinatorConfig,
    fetcher: StatusFetcher = fetch_status,
    now: Callable[[], float] = time.time,
    checkpoint_fetcher: CheckpointFetcher = fetch_checkpoint,
) -> FinalizedAnchor:
    observations: list[tuple[StatusEndpoint, int, str]] = []
    failures: list[str] = []
    for endpoint in config.status_endpoints:
        try:
            status = fetcher(endpoint, config.request_timeout_seconds)
            chain_id = _hex32(status.get("chain_id"), "observed chain_id")
            genesis_hash = _hex32(status.get("genesis_hash"), "observed genesis_hash")
            finalized = status.get("finalized")
            if not isinstance(finalized, dict):
                raise ContinuousLearningError("observed finalized checkpoint is missing")
            epoch = _integer(finalized.get("epoch"), "observed finalized epoch", 0, 2**55 - 1)
            checkpoint_hash = _hex32(finalized.get("hash"), "observed finalized hash")
            if chain_id != config.chain_id or genesis_hash != config.genesis_hash:
                raise ContinuousLearningError("wrong protocol identity")
            observations.append((endpoint, epoch, checkpoint_hash))
        except ContinuousLearningError as error:
            failures.append(str(error))

    candidates: dict[tuple[int, str], set[str]] = {}
    for endpoint, epoch, checkpoint_hash in observations:
        candidates.setdefault((epoch, checkpoint_hash), set()).add(endpoint.control_cluster)
    for (candidate_epoch, candidate_hash), support in candidates.items():
        candidate_height = candidate_epoch * EPOCH_LENGTH
        for endpoint, observed_epoch, _ in observations:
            if observed_epoch <= candidate_epoch or endpoint.control_cluster in support:
                continue
            try:
                historical_hash = checkpoint_fetcher(
                    endpoint,
                    candidate_height,
                    config.request_timeout_seconds,
                )
                historical_hash = _hex32(
                    historical_hash, "historical finalized checkpoint hash"
                )
                if historical_hash == candidate_hash:
                    support.add(endpoint.control_cluster)
            except ContinuousLearningError as error:
                failures.append(str(error))

    quorum_candidates = [
        (key, clusters)
        for key, clusters in candidates.items()
        if len(clusters) >= FIXED_QUORUM
    ]
    if quorum_candidates:
        highest_epoch = max(key[0] for key, _ in quorum_candidates)
        winners = [
            (key, clusters)
            for key, clusters in quorum_candidates
            if key[0] == highest_epoch
        ]
    else:
        winners = []
    if len(winners) != 1:
        detail = "; ".join(failures[:3])
        raise ContinuousLearningError(
            f"finalized status quorum unavailable or ambiguous ({len(winners)} highest quorum groups; {detail})"
        )
    (epoch, checkpoint_hash), clusters = winners[0]
    return FinalizedAnchor(
        chain_id=config.chain_id,
        genesis_hash=config.genesis_hash,
        epoch=epoch,
        height=epoch * EPOCH_LENGTH,
        checkpoint_hash=checkpoint_hash,
        control_clusters=tuple(sorted(clusters)),
        observed_endpoints=len(observations),
        observed_at=int(now()),
    )


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    payload = improvement.canonical_json(value) + b"\n"
    with temporary.open("wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    if os.name != "nt":
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class CoordinatorStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS anchors (
                checkpoint_hash TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL,
                height INTEGER NOT NULL,
                observed_at INTEGER NOT NULL,
                anchor_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY,
                request_path TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                request_json BLOB NOT NULL,
                not_before_height INTEGER NOT NULL,
                required_finalized_hash TEXT,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                anchor_height INTEGER,
                anchor_hash TEXT,
                error TEXT,
                result_json TEXT
            );
            CREATE INDEX IF NOT EXISTS requests_state_order
                ON requests(state, not_before_height, request_id);
            """
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(requests)")}
        if "request_json" not in columns:
            self._db.execute("ALTER TABLE requests ADD COLUMN request_json BLOB")
            self._db.execute(
                "UPDATE requests SET state='INTERRUPTED',updated_at=?,"
                "error='coordinator upgrade could not recover the original request bytes' "
                "WHERE request_json IS NULL AND state IN ('QUEUED','FINALITY_BLOCKED','RUNNING')",
                (int(time.time()),),
            )
        self.recover_interrupted()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def recover_interrupted(self) -> int:
        now = int(time.time())
        with self._lock:
            cursor = self._db.execute(
                "UPDATE requests SET state='INTERRUPTED', updated_at=?, "
                "error='coordinator restarted during a running cycle' WHERE state='RUNNING'",
                (now,),
            )
            return cursor.rowcount

    def record_anchor(self, anchor: FinalizedAnchor) -> None:
        payload = json.dumps(anchor.as_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            maximum = self._db.execute("SELECT MAX(height) FROM anchors").fetchone()
            if maximum is not None and maximum[0] is not None and anchor.height < int(maximum[0]):
                raise ContinuousLearningError("finalized checkpoint observation regressed")
            existing = self._db.execute(
                "SELECT checkpoint_hash FROM anchors WHERE height=?", (anchor.height,)
            ).fetchall()
            if existing and all(row[0] != anchor.checkpoint_hash for row in existing):
                raise ContinuousLearningError("conflicting finalized checkpoint at an observed height")
            self._db.execute(
                "INSERT OR IGNORE INTO anchors(checkpoint_hash,epoch,height,observed_at,anchor_json) "
                "VALUES(?,?,?,?,?)",
                (anchor.checkpoint_hash, anchor.epoch, anchor.height, anchor.observed_at, payload),
            )

    def insert_request(self, request: QueuedRequest, maximum_queued: int) -> bool:
        now = int(time.time())
        with self._lock:
            row = self._db.execute(
                "SELECT request_sha256 FROM requests WHERE request_id=?", (request.request_id,)
            ).fetchone()
            if row is not None:
                if row[0] != request.request_sha256:
                    raise ContinuousLearningError("request_id collision with different request bytes")
                return False
            queued = self._db.execute(
                "SELECT COUNT(*) FROM requests WHERE state IN ('QUEUED','FINALITY_BLOCKED','RUNNING')"
            ).fetchone()[0]
            if queued >= maximum_queued:
                raise ContinuousLearningError("durable learning queue reached maximum_queued_cycles")
            self._db.execute(
                "INSERT INTO requests(request_id,request_path,request_sha256,request_json,"
                "not_before_height,required_finalized_hash,state,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,'QUEUED',?,?)",
                (
                    request.request_id,
                    str(request.path),
                    request.request_sha256,
                    sqlite3.Binary(request.request_bytes),
                    request.not_before_finalized_height,
                    request.required_finalized_hash,
                    now,
                    now,
                ),
            )
            return True

    def state_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._db.execute("SELECT state,COUNT(*) FROM requests GROUP BY state").fetchall()
        counts = {state: 0 for state in REQUEST_STATES}
        counts.update({str(state): int(count) for state, count in rows})
        return counts

    def last_attempted_anchor_height(self) -> int | None:
        with self._lock:
            row = self._db.execute(
                "SELECT MAX(anchor_height) FROM requests WHERE anchor_height IS NOT NULL"
            ).fetchone()
        return None if row is None or row[0] is None else int(row[0])

    def next_request(self, anchor: FinalizedAnchor, cadence: int) -> QueuedRequest | None:
        last = self.last_attempted_anchor_height()
        cadence_ready = last is None or anchor.height >= last + cadence
        with self._lock:
            rows = self._db.execute(
                "SELECT request_id,request_path,request_sha256,request_json,"
                "not_before_height,required_finalized_hash "
                "FROM requests WHERE state IN ('QUEUED','FINALITY_BLOCKED') "
                "ORDER BY not_before_height,request_id"
            ).fetchall()
            selected: tuple[Any, ...] | None = None
            for row in rows:
                ready = (
                    cadence_ready
                    and anchor.height >= int(row[4])
                    and (row[5] is None or row[5] == anchor.checkpoint_hash)
                )
                state = "QUEUED" if ready else "FINALITY_BLOCKED"
                self._db.execute(
                    "UPDATE requests SET state=?,updated_at=? WHERE request_id=?",
                    (state, int(time.time()), row[0]),
                )
                if ready and selected is None:
                    selected = row
            if selected is None:
                return None
            return QueuedRequest(
                request_id=str(selected[0]),
                path=Path(str(selected[1])),
                request_sha256=str(selected[2]),
                request_bytes=bytes(selected[3]),
                not_before_finalized_height=int(selected[4]),
                required_finalized_hash=None if selected[5] is None else str(selected[5]),
            )

    def mark_running(self, request_id: str, anchor: FinalizedAnchor) -> None:
        with self._lock:
            cursor = self._db.execute(
                "UPDATE requests SET state='RUNNING',updated_at=?,anchor_height=?,anchor_hash=?,error=NULL "
                "WHERE request_id=? AND state='QUEUED'",
                (int(time.time()), anchor.height, anchor.checkpoint_hash, request_id),
            )
            if cursor.rowcount != 1:
                raise ContinuousLearningError("request did not make an atomic QUEUED to RUNNING transition")

    def finish(
        self,
        request_id: str,
        state: str,
        result: Mapping[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        if state not in {"SHADOW_CANDIDATE_READY", "REJECTED", "INTERRUPTED"}:
            raise ContinuousLearningError("invalid terminal request state")
        bounded_error = None if error is None else error.encode("utf-8")[:MAX_ERROR_BYTES].decode("utf-8", errors="replace")
        result_json = None if result is None else json.dumps(result, sort_keys=True, separators=(",", ":"))
        with self._lock:
            cursor = self._db.execute(
                "UPDATE requests SET state=?,updated_at=?,error=?,result_json=? "
                "WHERE request_id=? AND state='RUNNING'",
                (state, int(time.time()), bounded_error, result_json, request_id),
            )
            if cursor.rowcount != 1:
                raise ContinuousLearningError("request did not make an atomic RUNNING to terminal transition")

    def latest_request(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT request_id,state,not_before_height,anchor_height,anchor_hash,error,result_json,updated_at "
                "FROM requests ORDER BY updated_at DESC,request_id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        result = None if row[6] is None else json.loads(row[6])
        return {
            "request_id": row[0],
            "state": row[1],
            "not_before_finalized_height": row[2],
            "anchor_height": row[3],
            "anchor_hash": row[4],
            "error": row[5],
            "result": result,
            "updated_at": row[7],
        }


def _validated_request(
    value: dict[str, Any],
    request_bytes: bytes,
    path: Path,
    config: CoordinatorConfig,
) -> tuple[QueuedRequest, dict[str, Any]]:
    if value.get("schema") != improvement.REQUEST_SCHEMA:
        raise ContinuousLearningError("request has the wrong model-improvement schema")
    if "signing_seeds" in value:
        raise ContinuousLearningError("request must not contain signing seeds")
    if value.get("environment") not in {"local", "devnet", "testnet"} or value.get("production") is not False:
        raise ContinuousLearningError("request must be explicitly non-production")
    binding = value.get("chain_binding")
    if not isinstance(binding, dict):
        raise ContinuousLearningError("request chain_binding is required")
    if binding.get("chain_id") != config.chain_id or binding.get("genesis_hash") != config.genesis_hash:
        raise ContinuousLearningError("request is bound to the wrong chain identity")
    request_id = _hex32(value.get("request_id"), "request_id")
    body = {key: item for key, item in value.items() if key != "request_id"}
    expected_id = hashlib.sha256(improvement.canonical_json(body)).hexdigest()
    if request_id != expected_id:
        raise ContinuousLearningError("request_id does not match canonical request bytes")
    not_before = _integer(
        value.get("not_before_finalized_height"),
        "not_before_finalized_height",
        0,
        2**55 - 1,
    )
    required_hash = value.get("required_finalized_hash")
    if required_hash is not None:
        required_hash = _hex32(required_hash, "required_finalized_hash")
    request_sha = hashlib.sha256(request_bytes).hexdigest()
    return (
        QueuedRequest(
            request_id,
            path.resolve(),
            request_sha,
            request_bytes,
            not_before,
            required_hash,
        ),
        value,
    )


def parse_request(path: Path, config: CoordinatorConfig) -> tuple[QueuedRequest, dict[str, Any]]:
    value, request_bytes = _bounded_load_with_bytes(path, MAX_REQUEST_BYTES)
    return _validated_request(value, request_bytes, path, config)


class ContinuousLearningCoordinator:
    def __init__(
        self,
        config: CoordinatorConfig,
        *,
        status_fetcher: StatusFetcher = fetch_status,
        workflow_runner: WorkflowRunner = improvement.run_workflow,
        clock: Callable[[], float] = time.time,
        prerequisite_probe: Callable[[Mapping[str, Any]], improvement.GateResult] = improvement.probe_gate,
    ):
        self.config = config
        self.store = CoordinatorStore(config.state_db)
        self.status_fetcher = status_fetcher
        self.workflow_runner = workflow_runner
        self.clock = clock
        self.prerequisite_probe = prerequisite_probe
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {}
        self._anchor: FinalizedAnchor | None = None
        self._invalid_requests: dict[str, str] = {}
        self._metrics = {
            "polls_total": 0,
            "chain_quorum_failures_total": 0,
            "requests_queued_total": 0,
            "cycles_started_total": 0,
            "cycles_ready_total": 0,
            "cycles_rejected_total": 0,
        }
        if config.execution_enabled:
            load_role_seeds(config)
        self._prerequisite = self._probe_prerequisite()
        self._publish_status("STARTING", None)

    def close(self) -> None:
        self.store.close()

    def _probe_prerequisite(self) -> dict[str, Any]:
        try:
            gate = improvement.load_object(self.config.gate_config)
            result = self.prerequisite_probe(gate)
            ready = result.passed or result.code == "ROUNDTRIP_NOT_EXECUTED"
            return {
                "probe_passed": result.passed,
                "ready_for_execution": ready,
                "code": result.code,
                "detail": result.detail,
            }
        except (OSError, improvement.ImprovementError) as error:
            return {
                "probe_passed": False,
                "ready_for_execution": False,
                "code": "GATE_CONFIG_REJECTED",
                "detail": str(error),
            }

    def _scan_requests(self) -> None:
        self.config.request_dir.mkdir(parents=True, exist_ok=True)
        paths = sorted(self.config.request_dir.glob("*.json"))
        if len(paths) > self.config.maximum_queued_cycles:
            raise ContinuousLearningError("request directory exceeds maximum_queued_cycles")
        archive = self.config.request_dir / "admitted"
        for path in paths:
            try:
                request, _ = parse_request(path, self.config)
                archived_path = archive / f"{request.request_id}.json"
                durable_request = QueuedRequest(
                    request.request_id,
                    archived_path.resolve(),
                    request.request_sha256,
                    request.request_bytes,
                    request.not_before_finalized_height,
                    request.required_finalized_hash,
                )
                if self.store.insert_request(
                    durable_request, self.config.maximum_queued_cycles
                ):
                    self._metrics["requests_queued_total"] += 1
                archive.mkdir(parents=True, exist_ok=True)
                if archived_path.exists():
                    _, archived_bytes = _bounded_load_with_bytes(
                        archived_path, MAX_REQUEST_BYTES
                    )
                    if hashlib.sha256(archived_bytes).hexdigest() != request.request_sha256:
                        raise ContinuousLearningError(
                            "admitted request archive collision with different bytes"
                        )
                    path.unlink()
                else:
                    os.replace(path, archived_path)
                self._invalid_requests.pop(path.name, None)
            except (ContinuousLearningError, OSError) as error:
                self._invalid_requests[path.name] = str(error)[:MAX_ERROR_BYTES]

    def _load_request_again(self, queued: QueuedRequest) -> dict[str, Any]:
        if (
            not queued.request_bytes
            or len(queued.request_bytes) > MAX_REQUEST_BYTES
            or hashlib.sha256(queued.request_bytes).hexdigest() != queued.request_sha256
        ):
            raise ContinuousLearningError("durably stored request bytes failed their admission hash")
        try:
            value = json.loads(queued.request_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ContinuousLearningError("durably stored request bytes are invalid JSON") from error
        if not isinstance(value, dict):
            raise ContinuousLearningError("durably stored request must remain a JSON object")
        parsed, validated = _validated_request(
            value, queued.request_bytes, queued.path, self.config
        )
        if parsed.request_id != queued.request_id:
            raise ContinuousLearningError("durably stored request identity changed after admission")
        return validated

    def _run_cycle(self, queued: QueuedRequest, anchor: FinalizedAnchor) -> bool:
        role_seeds = load_role_seeds(self.config)
        self.store.mark_running(queued.request_id, anchor)
        self._metrics["cycles_started_total"] += 1
        cycle_root = self.config.evidence_root / "cycles" / queued.request_id
        try:
            request = self._load_request_again(queued)
            request["signing_seeds"] = role_seeds
            summary = dict(self.workflow_runner(request, cycle_root))
            if summary.get("passed") is not True:
                raise ContinuousLearningError("shadow model-improvement workflow did not pass")
            summary_id = _hex32(summary.get("object_id"), "shadow summary object_id")
            candidate = _hex32(summary.get("candidate_revision_id"), "candidate_revision_id")
            successor = _hex32(summary.get("successor_id"), "successor_id")
            handoff_body = {
                "schema": HANDOFF_SCHEMA,
                "request_id": queued.request_id,
                "chain_id": anchor.chain_id,
                "genesis_hash": anchor.genesis_hash,
                "finalized_height": anchor.height,
                "finalized_hash": anchor.checkpoint_hash,
                "shadow_summary_id": summary_id,
                "candidate_revision_id": candidate,
                "successor_id": successor,
                "promotion_effect": "NONE",
                "serving_alias_mutated": False,
                "control_state_mutated": False,
                "operational_reconfiguration_required": True,
                "direct_canonical_training_objects_require_reviewed_wwm_v3": True,
            }
            handoff = improvement.signed_record(
                "NOOS-WWM-CONTINUAL-LEARNING-HANDOFF-V1",
                handoff_body,
                role_seeds["activator"],
            )
            _atomic_json(cycle_root / "handoff.json", handoff)
            result = {
                "shadow_summary_id": summary_id,
                "candidate_revision_id": candidate,
                "successor_id": successor,
                "handoff_id": handoff["object_id"],
                "promotion_effect": "NONE",
            }
            self.store.finish(queued.request_id, "SHADOW_CANDIDATE_READY", result=result)
            self._metrics["cycles_ready_total"] += 1
            return True
        except Exception as error:
            try:
                self.store.finish(queued.request_id, "REJECTED", error=str(error))
            finally:
                self._metrics["cycles_rejected_total"] += 1
            return False

    def tick(self) -> dict[str, Any]:
        self._metrics["polls_total"] += 1
        try:
            anchor = observe_finalized(self.config, self.status_fetcher, self.clock)
            self.store.record_anchor(anchor)
            self._anchor = anchor
        except ContinuousLearningError as error:
            self._metrics["chain_quorum_failures_total"] += 1
            return self._publish_status("CHAIN_QUORUM_UNAVAILABLE", str(error))
        try:
            self._scan_requests()
            self._prerequisite = self._probe_prerequisite()
            if self.config.execution_enabled:
                if self._prerequisite.get("ready_for_execution") is not True:
                    return self._publish_status(
                        "EXECUTION_PREREQUISITE_UNAVAILABLE",
                        str(self._prerequisite.get("detail", "shadow prerequisite unavailable")),
                    )
                queued = self.store.next_request(
                    anchor, self.config.minimum_finalized_advance
                )
                if queued is not None and not self._run_cycle(queued, anchor):
                    return self._publish_status("CYCLE_REJECTED", None)
                mode = "READY"
            else:
                mode = "MONITORING_EXECUTION_DISABLED"
            return self._publish_status(mode, None)
        except ContinuousLearningError as error:
            return self._publish_status("DEGRADED", str(error))

    def _publish_status(self, mode: str, error: str | None) -> dict[str, Any]:
        counts = self.store.state_counts()
        status = {
            "schema": STATUS_SCHEMA,
            "environment": self.config.environment,
            "production": False,
            "mode": mode,
            "monitoring_enabled": True,
            "execution_enabled": self.config.execution_enabled,
            "shadow_training_configured": self.config.execution_enabled,
            "canonical_training_enabled": False,
            "automatic_promotion_enabled": False,
            "controls_enabled": False,
            "promotion_effect": "NONE",
            "chain_id": self.config.chain_id,
            "genesis_hash": self.config.genesis_hash,
            "finalized_anchor": None if self._anchor is None else self._anchor.as_dict(),
            "prerequisite": self._prerequisite,
            "queue": counts,
            "latest_request": self.store.latest_request(),
            "invalid_requests": dict(sorted(self._invalid_requests.items())),
            "error": None if error is None else error.encode("utf-8")[:MAX_ERROR_BYTES].decode(
                "utf-8", errors="replace"
            ),
            "updated_at": int(self.clock()),
        }
        with self._lock:
            self._status = status
        _atomic_json(self.config.status_file, status)
        return status

    def status(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._status))

    def healthy(self) -> bool:
        status = self.status()
        anchor = status.get("finalized_anchor")
        if not isinstance(anchor, dict):
            return False
        age = int(self.clock()) - int(anchor["observed_at"])
        return status.get("mode") not in {
            "CHAIN_QUORUM_UNAVAILABLE",
            "DEGRADED",
            "EXECUTION_PREREQUISITE_UNAVAILABLE",
        } and age <= 3 * self.config.poll_seconds

    def metrics(self) -> str:
        counts = self.store.state_counts()
        lines = [
            "# HELP noos_wwm_learning_info Coordinator mode flags.",
            "# TYPE noos_wwm_learning_info gauge",
            f'noos_wwm_learning_info{{environment="{self.config.environment}",production="false"}} 1',
        ]
        for name, value in sorted(self._metrics.items()):
            lines.extend(
                [
                    f"# TYPE noos_wwm_learning_{name} counter",
                    f"noos_wwm_learning_{name} {value}",
                ]
            )
        for state, value in sorted(counts.items()):
            lines.append(f'noos_wwm_learning_requests{{state="{state}"}} {value}')
        lines.append("")
        return "\n".join(lines)


def _handler(coordinator: ContinuousLearningCoordinator) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            route = urllib.parse.urlsplit(self.path).path
            if route == "/healthz":
                healthy = coordinator.healthy()
                self._send_json(200 if healthy else 503, {"healthy": healthy})
            elif route == "/status":
                self._send_json(200, coordinator.status())
            elif route == "/metrics":
                payload = coordinator.metrics().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                self._send_json(404, {"error": "not_found"})

        def _send_json(self, status: int, value: Mapping[str, Any]) -> None:
            payload = improvement.canonical_json(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return Handler


def _poll(coordinator: ContinuousLearningCoordinator, stopped: threading.Event) -> None:
    while not stopped.is_set():
        try:
            coordinator.tick()
        except Exception as error:
            coordinator._publish_status("DEGRADED", str(error))
        stopped.wait(coordinator.config.poll_seconds)


def _terminate_as_interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    coordinator: ContinuousLearningCoordinator | None = None
    try:
        config = load_config(args.config)
        coordinator = ContinuousLearningCoordinator(config)
        if args.once:
            status = coordinator.tick()
            print(json.dumps(status, sort_keys=True))
            return 0 if coordinator.healthy() else 2
        stopped = threading.Event()
        poller = threading.Thread(target=_poll, args=(coordinator, stopped), daemon=True)
        poller.start()
        server = http.server.ThreadingHTTPServer(
            (config.listen_host, config.listen_port), _handler(coordinator)
        )
        server.daemon_threads = True
        previous_sigterm = signal.signal(signal.SIGTERM, _terminate_as_interrupt)
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            stopped.set()
            server.server_close()
            poller.join(timeout=config.poll_seconds + 1)
            signal.signal(signal.SIGTERM, previous_sigterm)
        return 0
    except (ContinuousLearningError, improvement.ImprovementError, OSError, sqlite3.Error) as error:
        print(
            json.dumps(
                {
                    "schema": STATUS_SCHEMA,
                    "production": False,
                    "shadow_training_configured": False,
                    "canonical_training_enabled": False,
                    "automatic_promotion_enabled": False,
                    "controls_enabled": False,
                    "promotion_effect": "NONE",
                    "error": str(error),
                },
                sort_keys=True,
            ),
            file=os.sys.stderr,
        )
        return 2
    finally:
        if coordinator is not None:
            coordinator.close()


if __name__ == "__main__":
    raise SystemExit(main())
