from __future__ import annotations

import base64
import codecs
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Final, Iterable, Mapping, Protocol
from urllib.parse import urlsplit

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CHAIN_ID: Final[str] = "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b"
GENESIS_HASH: Final[str] = "8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e"
CAPSULE_ID: Final[str] = "e50b777f52cdb85aad7f7da4be3b705199357fa02c81fca811feae402f34235d"
ARTIFACT_ID: Final[str] = "d3d1bcf9f704c58c695d7c0837be25a5cfbd7ff71b440bfc9be4a4a46bb528b0"
ARTIFACT_SHA256: Final[str] = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
MANIFEST_ROOT: Final[str] = "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7"
RUNTIME_ROOT: Final[str] = "690d9bbd8d44631fb971e0b0677e10c8d0bb1e08a743bb720eeaab728e30ba27"
EXECUTION_PROFILE_ID: Final[str] = "780a01d1f41ab0f3aaee4a3cbc196f1ee211ca99cd5ec00a0e5ed17669daf182"
QUERY_PROFILE_ID: Final[str] = "98021a08b5fa7d364e8c4071d4544441c4c53150134102ae38a754207612688c"
AVAILABILITY_CERTIFICATE_ID: Final[str] = "510db55c2d08e02f5aee28c0391a5d4159cc9157b4fa23e47adb45dce2ddd4d9"
MONITOR_SIGNER_KEY_ID: Final[str] = "edaabc9658bdeb58dd093bb7992bd2862e39efb4953771113801bcf125e366d7"
MODEL_BYTES: Final[int] = 3_803_452_480
ENCODED_BYTES: Final[int] = 5_707_063_296
SHARE_BYTES: Final[int] = 1_047_552
DATA_SHARDS: Final[int] = 8
PARITY_SHARDS: Final[int] = 4
RECONSTRUCTION_THRESHOLD: Final[int] = 8
SCHEDULABLE_MINIMUM: Final[int] = 9
MAX_PROMPT_BYTES: Final[int] = 12_000
MAX_INPUT_TOKENS: Final[int] = 4_096
OUTPUT_TOKEN_LIMITS: Final[frozenset[int]] = frozenset({8, 16})
MAX_OUTPUT_BYTES: Final[int] = 128 * 1024
MAX_UPSTREAM_BYTES: Final[int] = 2 * 1024 * 1024
QUOTE_WINDOW_SECONDS: Final[int] = 600
QUOTE_LIMIT: Final[int] = 30
GLOBAL_QUOTE_LIMIT: Final[int] = 300
JOB_WINDOW_SECONDS: Final[int] = 3_600
JOB_LIMIT: Final[int] = 3
GLOBAL_JOB_LIMIT: Final[int] = 24
MAX_RUNNING: Final[int] = 1
MAX_QUEUED: Final[int] = 2
QUOTE_HEIGHT_TTL: Final[int] = 256
SPONSOR_REFERENCE: Final[str] = "PUBLIC_TESTNET_SPONSOR_V1"
HEX16 = re.compile(r"^[0-9a-f]{32}$")
HEX32 = re.compile(r"^[0-9a-f]{64}$")
JOB_STREAM_ROUTE = re.compile(r"^/api/wwm/v2/jobs/([0-9a-f]{64})/stream$")
JOB_RECEIPT_ROUTE = re.compile(r"^/api/wwm/v2/jobs/([0-9a-f]{64})/receipt$")
JOB_CANCEL_ROUTE = re.compile(r"^/api/wwm/v2/jobs/([0-9a-f]{64})/cancel$")
WORKER_STREAM_ROUTE = re.compile(r"^/internal/wwm/v1/jobs/[0-9a-f]{64}/stream$")
PROMPT_DOMAIN: Final[bytes] = b"NOOS/WWM/PROMPT-COMMITMENT/V2\0"
SIGNING_DOMAIN: Final[bytes] = b"NOOS/SIG/WWM/PUBLIC-INFERENCE/V1\0"
MONITOR_DOMAIN: Final[bytes] = b"NOOS/SIG/WWM/V1\0PUBLIC-TESTNET-MONITOR-SAMPLE\0"
MONITOR_OMITTED: Final[frozenset[str]] = frozenset(
    {"sample_id", "signer_key_id", "public_key_base64", "signature_base64"}
)
TERMINAL_STATUSES: Final[frozenset[str]] = frozenset({"COMPLETED", "CANCELLED", "FAILED", "NO_QUORUM"})


class InferenceError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


@dataclass(frozen=True)
class InferenceReply:
    status: int
    value: dict
    retry_after: int | None = None


@dataclass(frozen=True)
class StateSnapshot:
    resolution: dict
    monitor: dict
    head_height: int


@dataclass(frozen=True)
class ExecutionResult:
    output: bytes
    output_root: str
    output_tokens: int
    token_history_root: str
    tokenizer_sha256: str
    duration_ms: int


class SnapshotProvider(Protocol):
    def snapshot(self) -> StateSnapshot: ...


class Executor(Protocol):
    def run(
        self,
        job_id: str,
        prompt: str,
        maximum_output_tokens: int,
        on_chunk: Callable[[bytes, str], None],
    ) -> ExecutionResult: ...


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _required_text(value: Mapping[str, object], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise InferenceError(502, "MALFORMED_UPSTREAM", f"Upstream field {key} is missing.")
    return selected


def _required_uint(value: Mapping[str, object], key: str) -> int:
    selected = value.get(key)
    if isinstance(selected, bool) or not isinstance(selected, int) or selected < 0:
        raise InferenceError(502, "MALFORMED_UPSTREAM", f"Upstream field {key} is invalid.")
    return selected


def _bounded_json(request: urllib.request.Request, maximum: int = MAX_UPSTREAM_BYTES, timeout: int = 15) -> dict:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(maximum + 1)
            if len(body) > maximum:
                raise InferenceError(502, "UPSTREAM_TOO_LARGE", "Upstream response exceeded its bound.")
            if response.headers.get_content_type() not in {"application/json", "text/json"}:
                raise InferenceError(502, "INVALID_UPSTREAM", "Upstream returned a non-JSON response.")
    except urllib.error.HTTPError as error:
        detail = error.read(512).decode("utf-8", "replace")
        raise InferenceError(502, "UPSTREAM_REJECTED", detail or f"Upstream returned HTTP {error.code}.") from error
    except (OSError, urllib.error.URLError) as error:
        raise InferenceError(503, "UPSTREAM_UNAVAILABLE", "Required private inference upstream is unavailable.") from error
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InferenceError(502, "INVALID_UPSTREAM", "Upstream returned malformed JSON.") from error
    if not isinstance(parsed, dict):
        raise InferenceError(502, "INVALID_UPSTREAM", "Upstream JSON must be an object.")
    return parsed


def _verify_monitor(sample: dict) -> None:
    if (
        sample.get("schema") != "noos/wwm-public-testnet-monitor-sample/v1"
        or sample.get("environment") != "public-testnet"
        or sample.get("production") is not False
        or sample.get("promotion_effect") != "NONE"
        or sample.get("signer_key_id") != MONITOR_SIGNER_KEY_ID
    ):
        raise InferenceError(503, "MONITOR_REJECTED", "Signed testnet monitor identity is invalid.")
    try:
        public_key = base64.b64decode(_required_text(sample, "public_key_base64"), validate=True)
        signature = base64.b64decode(_required_text(sample, "signature_base64"), validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise InferenceError(503, "MONITOR_REJECTED", "Signed monitor key material is malformed.") from error
    if len(public_key) != 32 or len(signature) != 64 or hashlib.sha256(public_key).hexdigest() != MONITOR_SIGNER_KEY_ID:
        raise InferenceError(503, "MONITOR_REJECTED", "Signed monitor key is not pinned.")
    payload = {key: value for key, value in sample.items() if key not in MONITOR_OMITTED}
    message = MONITOR_DOMAIN + canonical_json(payload)
    if hashlib.sha256(message).hexdigest() != sample.get("sample_id"):
        raise InferenceError(503, "MONITOR_REJECTED", "Signed monitor sample ID is invalid.")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (ValueError, InvalidSignature) as error:
        raise InferenceError(503, "MONITOR_REJECTED", "Signed monitor signature is invalid.") from error


def _monitor_check(sample: Mapping[str, object], name: str) -> dict:
    checks = sample.get("checks")
    if not isinstance(checks, list):
        raise InferenceError(503, "MONITOR_REJECTED", "Signed monitor checks are missing.")
    for check in checks:
        if isinstance(check, dict) and check.get("name") == name:
            return check
    raise InferenceError(503, "MONITOR_REJECTED", f"Signed monitor check {name} is missing.")


class LiveStateProvider:
    def __init__(
        self,
        *,
        node_sources: Iterable[tuple[str, str]],
        monitor_url: str,
        cache_seconds: float = 3.0,
    ):
        self.node_sources = tuple((origin.rstrip("/"), token) for origin, token in node_sources)
        if not self.node_sources:
            raise InferenceError(500, "INVALID_CONFIGURATION", "At least one private node source is required.")
        self.monitor_url = monitor_url.rstrip("/")
        self.cache_seconds = cache_seconds
        self._lock = threading.Lock()
        self._cached: StateSnapshot | None = None
        self._cached_until = 0.0

    @staticmethod
    def _node_json(origin: str, token: str, path: str) -> dict:
        return _bounded_json(
            urllib.request.Request(
                origin + path,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "mindchain-public-inference/1",
                },
                method="GET",
            )
        )

    def _uncached(self) -> StateSnapshot:
        candidates: list[tuple[int, str, str, dict]] = []
        last_error: InferenceError | None = None
        for origin, token in self.node_sources:
            try:
                status = self._node_json(origin, token, "/status")
                if status.get("chain_id") != CHAIN_ID or status.get("genesis_hash") != GENESIS_HASH:
                    raise InferenceError(502, "WRONG_CHAIN_IDENTITY", "Private node returned the wrong chain identity.")
                head = status.get("unsafe_head")
                if not isinstance(head, dict):
                    raise InferenceError(502, "MALFORMED_UPSTREAM", "Private node head is missing.")
                candidates.append((_required_uint(head, "height"), origin, token, status))
            except InferenceError as error:
                last_error = error
        if not candidates:
            if last_error is not None:
                raise last_error
            raise InferenceError(503, "NODE_UNAVAILABLE", "No private finalized-state source is available.")
        head_height, origin, token, _ = max(candidates, key=lambda row: row[0])
        resolution = self._node_json(origin, token, "/model-resolution/bonsai-q1")
        active = resolution.get("active")
        exact = {
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "selector": "bonsai-q1",
            "registration_state": "ACTIVE_TESTNET",
            "control_mode": "TESTNET",
            "production_effect": "NONE",
            "trust_scope": "LOCAL_FULL_NODE_FINALIZED_STATE",
        }
        if any(resolution.get(key) != expected for key, expected in exact.items()):
            raise InferenceError(503, "RESOLUTION_REJECTED", "Finalized model resolution is not the pinned testnet state.")
        if resolution.get("proofs_verified") is not True or resolution.get("proof_count") != 17 or not isinstance(active, dict):
            raise InferenceError(503, "RESOLUTION_REJECTED", "Finalized 17-object model proof is unavailable.")
        active_exact = {
            "capsule_id": CAPSULE_ID,
            "artifact_id": ARTIFACT_ID,
            "artifact_sha256": ARTIFACT_SHA256,
            "manifest_root": MANIFEST_ROOT,
            "runtime_root": RUNTIME_ROOT,
            "execution_profile_id": EXECUTION_PROFILE_ID,
            "query_policy_id": QUERY_PROFILE_ID,
            "availability_certificate_id": AVAILABILITY_CERTIFICATE_ID,
            "artifact_bytes": MODEL_BYTES,
            "model_name": "Bonsai-27B-Q1_0.gguf",
        }
        if any(active.get(key) != expected for key, expected in active_exact.items()):
            raise InferenceError(503, "RESOLUTION_REJECTED", "Active model graph does not match the pinned Bonsai capsule.")
        monitor = _bounded_json(
            urllib.request.Request(
                self.monitor_url + "/status.json",
                headers={"Accept": "application/json", "User-Agent": "mindchain-public-inference/1"},
                method="GET",
            )
        )
        _verify_monitor(monitor)
        return StateSnapshot(resolution=resolution, monitor=monitor, head_height=head_height)

    def snapshot(self) -> StateSnapshot:
        with self._lock:
            now = time.monotonic()
            if self._cached is None or now >= self._cached_until:
                self._cached = self._uncached()
                self._cached_until = now + self.cache_seconds
            return self._cached


class OfflineTokenizer:
    def __init__(self, *, executable: Path, model: Path, expected_executable_sha256: str):
        self.executable = executable.resolve(strict=True)
        self.model = model.resolve(strict=True)
        if not self.executable.is_file() or not self.model.is_file():
            raise InferenceError(500, "MISSING_RUNTIME", "Pinned tokenizer or reconstructed model is unavailable.")
        if self.model.stat().st_size != MODEL_BYTES:
            raise InferenceError(500, "MODEL_SIZE_MISMATCH", "Reconstructed Bonsai model has the wrong byte length.")
        digest = hashlib.sha256()
        with self.executable.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        self.executable_sha256 = digest.hexdigest()
        if self.executable_sha256 != expected_executable_sha256:
            raise InferenceError(500, "TOKENIZER_IDENTITY_MISMATCH", "Pinned tokenizer executable hash changed.")

    def tokenize(self, value: bytes, maximum: int) -> list[int]:
        environment = os.environ.copy()
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            environment[key] = ""
        environment["NO_PROXY"] = "*"
        try:
            process = subprocess.run(
                (
                    str(self.executable),
                    "--model",
                    str(self.model),
                    "--stdin",
                    "--ids",
                    "--no-bos",
                ),
                cwd=self.executable.parent,
                input=value,
                capture_output=True,
                check=False,
                timeout=300,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InferenceError(503, "TOKENIZER_UNAVAILABLE", "Pinned offline tokenizer did not complete.") from error
        if process.returncode != 0 or len(process.stdout) > 1024 * 1024:
            raise InferenceError(502, "TOKENIZER_REJECTED", "Pinned offline tokenizer rejected the bounded text.")
        try:
            encoded = process.stdout.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise InferenceError(502, "TOKENIZER_REJECTED", "Pinned tokenizer returned non-ASCII token IDs.") from error
        if re.fullmatch(r"\[?\s*\d+(?:[\s,]+\d+)*\s*\]?", encoded) is None:
            raise InferenceError(502, "TOKENIZER_REJECTED", "Pinned tokenizer returned malformed token IDs.")
        token_ids = [int(item) for item in re.findall(r"\d+", encoded)]
        if not token_ids or len(token_ids) > maximum or any(item > 0xFFFF_FFFF for item in token_ids):
            raise InferenceError(400, "TOKEN_LIMIT_EXCEEDED", "Text exceeds the pinned tokenizer bound.")
        return token_ids

    def output_commitment(self, output: bytes, maximum: int) -> tuple[int, str]:
        token_ids = self.tokenize(output, maximum)
        history = bytearray(b"NOOS/WWM/LLAMA-TOKEN-HISTORY/V1\0")
        history.extend(len(token_ids).to_bytes(4, "little"))
        for token_id in token_ids:
            history.extend(token_id.to_bytes(4, "little"))
        return len(token_ids), blake3(bytes(history)).hexdigest()


class WorkerdExecutor:
    def __init__(self, *, origin: str, token: str, tokenizer: OfflineTokenizer):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
            or parsed.port is None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise InferenceError(500, "INVALID_EXECUTOR_ORIGIN", "Inference worker must be an exact loopback HTTP origin.")
        if len(token) < 32 or any(character.isspace() for character in token):
            raise InferenceError(500, "INVALID_EXECUTOR_TOKEN", "Inference worker token is invalid.")
        self.origin = origin.rstrip("/")
        self.token = token
        self.tokenizer = tokenizer

    def _json(self, path: str, body: dict) -> dict:
        return _bounded_json(
            urllib.request.Request(
                self.origin + path,
                data=canonical_json(body),
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                    "User-Agent": "mindchain-public-inference/1",
                },
                method="POST",
            ),
            timeout=300,
        )

    def run(
        self,
        job_id: str,
        prompt: str,
        maximum_output_tokens: int,
        on_chunk: Callable[[bytes, str], None],
    ) -> ExecutionResult:
        started = time.monotonic()
        prompt_ids = self.tokenizer.tokenize(prompt.encode("utf-8"), MAX_INPUT_TOKENS)
        self._json(
            "/internal/wwm/v1/capacity-quotes",
            {"prompt_tokens": len(prompt_ids), "max_output_tokens": maximum_output_tokens},
        )
        accepted = self._json(
            "/internal/wwm/v1/jobs",
            {
                "job_id": job_id,
                "prompt": prompt,
                "prompt_token_ids": prompt_ids,
                "runtime_token_ids": prompt_ids,
                "max_output_tokens": maximum_output_tokens,
            },
        )
        stream_path = _required_text(accepted, "stream")
        if WORKER_STREAM_ROUTE.fullmatch(stream_path) is None:
            raise InferenceError(502, "INVALID_EXECUTOR_STREAM", "Inference worker returned an invalid private stream path.")
        request = urllib.request.Request(
            self.origin + stream_path,
            headers={
                "Accept": "text/event-stream",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "mindchain-public-inference/1",
            },
            method="GET",
        )
        output = bytearray()
        terminal: dict | None = None
        expected_sequence = 1
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                if response.headers.get_content_type() != "text/event-stream":
                    raise InferenceError(502, "INVALID_EXECUTOR_STREAM", "Inference worker returned a non-SSE stream.")
                while True:
                    line = response.readline(MAX_UPSTREAM_BYTES + 1)
                    if len(line) > MAX_UPSTREAM_BYTES:
                        raise InferenceError(502, "EXECUTOR_EVENT_TOO_LARGE", "Inference worker event exceeded its bound.")
                    if not line:
                        break
                    text = line.decode("utf-8", "strict").strip()
                    if not text.startswith("data:"):
                        continue
                    try:
                        event = json.loads(text[5:].strip())
                    except json.JSONDecodeError as error:
                        raise InferenceError(502, "INVALID_EXECUTOR_STREAM", "Inference worker emitted malformed JSON.") from error
                    if not isinstance(event, dict):
                        raise InferenceError(502, "INVALID_EXECUTOR_STREAM", "Inference worker emitted a non-object event.")
                    if event.get("type") == "token_bytes":
                        sequence = event.get("sequence")
                        bytes_hex = event.get("bytes_hex")
                        incremental_root = event.get("incremental_root")
                        if (
                            sequence != expected_sequence
                            or not isinstance(bytes_hex, str)
                            or len(bytes_hex) % 2 != 0
                            or re.fullmatch(r"[0-9a-f]*", bytes_hex) is None
                            or not isinstance(incremental_root, str)
                            or HEX32.fullmatch(incremental_root) is None
                        ):
                            raise InferenceError(502, "INVALID_EXECUTOR_STREAM", "Inference worker emitted malformed ordered bytes.")
                        chunk = bytes.fromhex(bytes_hex)
                        output.extend(chunk)
                        if len(output) > MAX_OUTPUT_BYTES or blake3(bytes(output)).hexdigest() != incremental_root:
                            raise InferenceError(502, "EXECUTOR_COMMITMENT_MISMATCH", "Inference worker output commitment did not verify.")
                        expected_sequence += 1
                        on_chunk(chunk, incremental_root)
                    elif event.get("type") == "terminal":
                        terminal = event
                        break
        except UnicodeDecodeError as error:
            raise InferenceError(502, "INVALID_EXECUTOR_STREAM", "Inference worker stream was not UTF-8.") from error
        except urllib.error.HTTPError as error:
            raise InferenceError(502, "EXECUTOR_REJECTED", f"Inference worker returned HTTP {error.code}.") from error
        except (OSError, urllib.error.URLError) as error:
            raise InferenceError(503, "EXECUTOR_UNAVAILABLE", "Private inference worker became unavailable.") from error
        if terminal is None or terminal.get("code") != "completed":
            raise InferenceError(502, "EXECUTOR_INCOMPLETE", "Inference worker did not emit a completed terminal event.")
        output_root = terminal.get("output_root")
        if not isinstance(output_root, str) or HEX32.fullmatch(output_root) is None or blake3(bytes(output)).hexdigest() != output_root:
            raise InferenceError(502, "EXECUTOR_COMMITMENT_MISMATCH", "Inference worker terminal commitment did not verify.")
        output_tokens, token_history_root = self.tokenizer.output_commitment(bytes(output), maximum_output_tokens)
        return ExecutionResult(
            output=bytes(output),
            output_root=output_root,
            output_tokens=output_tokens,
            token_history_root=token_history_root,
            tokenizer_sha256=self.tokenizer.executable_sha256,
            duration_ms=max(1, int((time.monotonic() - started) * 1000)),
        )


class InferenceService:
    def __init__(
        self,
        *,
        database: Path,
        signing_seed: bytes,
        provider: SnapshotProvider,
        executor: Executor,
        now_ms: Callable[[], int] | None = None,
        start_worker: bool = True,
    ):
        if len(signing_seed) != 32:
            raise InferenceError(500, "INVALID_SIGNING_SEED", "Inference signing seed must be 32 bytes.")
        self.database = database.resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
        public_key = self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key_base64 = base64.b64encode(public_key).decode("ascii")
        self.signing_key_id = hashlib.sha256(public_key).hexdigest()
        self.client_pepper = hmac.new(signing_seed, b"NOOS/WWM/PUBLIC-INFERENCE/CLIENT-PEPPER/V1", hashlib.sha256).digest()
        self.provider = provider
        self.executor = executor
        self.now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._admission_lock = threading.Lock()
        self._condition = threading.Condition()
        self._closed = threading.Event()
        self._queue: queue.Queue[str | None] = queue.Queue(maxsize=MAX_QUEUED)
        self._worker: threading.Thread | None = None
        self._initialize_database()
        self._recover_interrupted_jobs()
        if start_worker:
            self._worker = threading.Thread(target=self._worker_loop, name="wwm-public-inference", daemon=True)
            self._worker.start()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS inference_quotes (
                    quote_id TEXT PRIMARY KEY,
                    client_hash TEXT NOT NULL,
                    quote_json TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    expires_height INTEGER NOT NULL,
                    used_job_id TEXT
                );
                CREATE INDEX IF NOT EXISTS inference_quotes_client_created
                    ON inference_quotes(client_hash, created_ms);
                CREATE TABLE IF NOT EXISTS inference_jobs (
                    job_id TEXT PRIMARY KEY,
                    quote_id TEXT NOT NULL UNIQUE REFERENCES inference_quotes(quote_id),
                    client_hash TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    prompt TEXT,
                    prompt_commitment TEXT NOT NULL,
                    maximum_output_tokens INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    receipt_json TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    UNIQUE(client_hash, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS inference_jobs_client_created
                    ON inference_jobs(client_hash, created_ms);
                CREATE INDEX IF NOT EXISTS inference_jobs_status
                    ON inference_jobs(status);
                CREATE TABLE IF NOT EXISTS inference_events (
                    job_id TEXT NOT NULL REFERENCES inference_jobs(job_id),
                    event_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    PRIMARY KEY(job_id, event_id)
                );
                """
            )

    def _recover_interrupted_jobs(self) -> None:
        with self._connect() as db:
            rows = db.execute(
                "SELECT job_id, quote_id FROM inference_jobs WHERE status IN ('QUEUED','RUNNING','CANCEL_REQUESTED')"
            ).fetchall()
        for row in rows:
            self._complete_without_output(str(row["job_id"]), "FAILED", "GATEWAY_RESTARTED")

    def close(self) -> None:
        self._closed.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        with self._condition:
            self._condition.notify_all()
        if self._worker is not None:
            self._worker.join(timeout=5)

    @staticmethod
    def is_get_route(path: str) -> bool:
        return path == "/api/wwm/v2/state" or JOB_STREAM_ROUTE.fullmatch(path) is not None or JOB_RECEIPT_ROUTE.fullmatch(path) is not None

    @staticmethod
    def is_post_route(path: str) -> bool:
        return path in {"/api/wwm/v2/quotes", "/api/wwm/v2/jobs"} or JOB_CANCEL_ROUTE.fullmatch(path) is not None

    @staticmethod
    def is_stream_route(path: str) -> bool:
        return JOB_STREAM_ROUTE.fullmatch(path) is not None

    def _sign(self, value: dict, kind: str) -> dict:
        signed = dict(value)
        signed["signing_key_id"] = self.signing_key_id
        message = SIGNING_DOMAIN + kind.encode("ascii") + b"\0" + canonical_json(signed)
        signed["signature"] = base64.b64encode(self.signing_key.sign(message)).decode("ascii")
        return signed

    def _client_hash(self, client: str) -> str:
        try:
            normalized = str(ipaddress.ip_address(client.strip()))
        except ValueError:
            normalized = "invalid-client"
        return hmac.new(self.client_pepper, normalized.encode("ascii"), hashlib.sha256).hexdigest()

    @staticmethod
    def _active(snapshot: StateSnapshot) -> dict:
        active = snapshot.resolution["active"]
        assert isinstance(active, dict)
        return active

    @staticmethod
    def _worker_ready(snapshot: StateSnapshot) -> bool:
        inference = _monitor_check(snapshot.monitor, "inference_worker")
        model = _monitor_check(snapshot.monitor, "model_resolution")
        detail = inference.get("detail")
        return (
            inference.get("ok") is True
            and isinstance(detail, dict)
            and detail.get("ready") is True
            and model.get("ok") is True
        )

    def _state_value(self, snapshot: StateSnapshot) -> dict:
        active = self._active(snapshot)
        custodians = active.get("custodian_profiles")
        executors = active.get("executor_profile_ids")
        if not isinstance(custodians, list) or len(custodians) != 12 or not isinstance(executors, list) or len(executors) != 8:
            raise InferenceError(503, "RESOLUTION_REJECTED", "Finalized custody or executor topology is malformed.")
        hosting = {
            "artifact_id": active["artifact_id"],
            "manifest_root": active["manifest_root"],
            "runtime_root": active["runtime_root"],
            "artifact_sha256": active["artifact_sha256"],
            "source_bytes": active["artifact_bytes"],
            "encoded_bytes": ENCODED_BYTES,
            "share_bytes": SHARE_BYTES,
            "stripe_count": active["stripe_count"],
            "position_count": len(custodians),
            "data_shards": DATA_SHARDS,
            "parity_shards": PARITY_SHARDS,
            "reconstruction_threshold": RECONSTRUCTION_THRESHOLD,
            "schedulable_minimum": SCHEDULABLE_MINIMUM,
            "availability_certificate_id": active["availability_certificate_id"],
            "certificate_issued_height": active["certificate_issued_height"],
            "certificate_valid_until_height": str(active["certificate_valid_until"]),
            "custodians": [
                {
                    "position": position,
                    "profile_id": row.get("profile_id") if isinstance(row, dict) else None,
                    "endpoint_root": row.get("endpoint_root") if isinstance(row, dict) else None,
                    "status": row.get("status") if isinstance(row, dict) else None,
                }
                for position, row in enumerate(custodians)
            ],
            "executor_profile_ids": list(executors),
            "worker": {
                "state": "READY" if self._worker_ready(snapshot) else "FAILED",
                "source": "SIGNED_OPERATOR_MONITOR",
                "monitor_sample_id": snapshot.monitor["sample_id"],
                "monitor_signer_key_id": snapshot.monitor["signer_key_id"],
            },
        }
        return {
            "schema": "noos/wwm-gateway/v2",
            "enabled": self._worker_ready(snapshot),
            "environment": "public-testnet",
            "production": False,
            "promotion_effect": "NONE",
            "disclosure": "Interactive answers run off-chain on one bounded operator executor. The browser verifies the signed monitor, pinned finalized model resolution, gateway signatures, output commitments, and receipt. Interactive jobs are not on-chain settlements; scheduled neural pulses are separate finalized chain records.",
            "limits": {
                "prompt_bytes": MAX_PROMPT_BYTES,
                "output_tokens": sorted(OUTPUT_TOKEN_LIMITS),
                "jobs_per_hour_per_client": JOB_LIMIT,
                "jobs_per_hour_global": GLOBAL_JOB_LIMIT,
                "running": MAX_RUNNING,
                "queued": MAX_QUEUED,
                "payment_modes": ["SPONSORED"],
            },
            "signer": {
                "algorithm": "Ed25519",
                "key_id": self.signing_key_id,
                "public_key_base64": self.public_key_base64,
            },
            "monitor": snapshot.monitor,
            "resolution": {
                "chain_id": snapshot.resolution["chain_id"],
                "genesis_hash": snapshot.resolution["genesis_hash"],
                "finalized_height": snapshot.resolution["finalized_height"],
                "finalized_hash": snapshot.resolution["finalized_hash"],
                "objects_root": snapshot.resolution["objects_root"],
                "pin_id": active["authorized_config_id"],
                "active": {
                    "capsule_id": active["capsule_id"],
                    "execution_profile_id": active["execution_profile_id"],
                    "query_profile_id": active["query_policy_id"],
                    "artifact_sha256": active["artifact_sha256"],
                    "artifact_length": active["artifact_bytes"],
                    "activation_state": "ACTIVE",
                },
                "candidates": [],
                "hosting": hosting,
                "proof_source": {
                    "schema": snapshot.resolution["schema"],
                    "selector": snapshot.resolution["selector"],
                    "trust_scope": snapshot.resolution["trust_scope"],
                    "proof_count": snapshot.resolution["proof_count"],
                    "proofs_verified": snapshot.resolution["proofs_verified"],
                },
            },
        }

    def get(self, path: str, query: str, client: str) -> InferenceReply:
        if query:
            raise InferenceError(400, "INVALID_QUERY", "Public inference routes do not accept query strings.")
        if path == "/api/wwm/v2/state":
            return InferenceReply(200, self._state_value(self.provider.snapshot()))
        receipt = JOB_RECEIPT_ROUTE.fullmatch(path)
        if receipt:
            with self._connect() as db:
                row = db.execute(
                    "SELECT receipt_json FROM inference_jobs WHERE job_id=?",
                    (receipt.group(1),),
                ).fetchone()
            if row is None:
                raise InferenceError(404, "JOB_NOT_FOUND", "Inference job was not found.")
            if row["receipt_json"] is None:
                raise InferenceError(409, "JOB_NOT_TERMINAL", "Inference job has not produced a terminal receipt.")
            return InferenceReply(200, json.loads(str(row["receipt_json"])))
        if JOB_STREAM_ROUTE.fullmatch(path):
            raise InferenceError(400, "STREAM_REQUIRED", "Use the bounded SSE stream response for this route.")
        raise InferenceError(404, "NOT_FOUND", "Inference route not found.")

    def post(self, path: str, body: dict, client: str, idempotency_key: str | None) -> InferenceReply:
        if path == "/api/wwm/v2/quotes":
            return self._quote(body, client)
        if path == "/api/wwm/v2/jobs":
            return self._submit(body, client, idempotency_key)
        cancel = JOB_CANCEL_ROUTE.fullmatch(path)
        if cancel:
            return self._cancel(cancel.group(1), body)
        raise InferenceError(404, "NOT_FOUND", "Inference route not found.")

    @staticmethod
    def _hex(value: object, pattern: re.Pattern[str], code: str, message: str) -> str:
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise InferenceError(400, code, message)
        return value

    def _quote(self, request: dict, client: str) -> InferenceReply:
        request_id = self._hex(request.get("request_id"), HEX16, "INVALID_REQUEST_ID", "request_id must be lowercase hex16.")
        prompt_commitment = self._hex(request.get("prompt_commitment"), HEX32, "INVALID_PROMPT_COMMITMENT", "Prompt commitment must be lowercase hex32.")
        self._hex(request.get("client_nonce"), HEX32, "INVALID_CLIENT_NONCE", "client_nonce must be lowercase hex32.")
        input_tokens = request.get("input_tokens")
        maximum = request.get("maximum_output_tokens")
        if isinstance(input_tokens, bool) or not isinstance(input_tokens, int) or not 1 <= input_tokens <= MAX_INPUT_TOKENS:
            raise InferenceError(400, "INVALID_INPUT_TOKENS", "Input token estimate is outside the bounded admission range.")
        if maximum not in OUTPUT_TOKEN_LIMITS:
            raise InferenceError(400, "INVALID_OUTPUT_LIMIT", "Public inference supports exactly 8 or 16 output tokens.")
        payment = request.get("payment")
        if not isinstance(payment, dict) or payment.get("mode") != "SPONSORED" or payment.get("authorization") != "":
            raise InferenceError(400, "PAYMENT_MODE_UNAVAILABLE", "This public pilot supports bounded sponsored jobs only.")
        snapshot = self.provider.snapshot()
        state = self._state_value(snapshot)
        if state["enabled"] is not True:
            raise InferenceError(503, "ADMISSION_DISABLED", "Signed worker readiness is unavailable.")
        active = state["resolution"]["active"]
        expected = {
            "pin_id": state["resolution"]["pin_id"],
            "capsule_id": active["capsule_id"],
            "execution_profile_id": active["execution_profile_id"],
            "query_profile_id": active["query_profile_id"],
        }
        if any(request.get(key) != value for key, value in expected.items()):
            raise InferenceError(409, "ACTIVE_BINDING_MISMATCH", "Quote request is not bound to the current finalized active capsule.")
        now = self.now_ms()
        client_hash = self._client_hash(client)
        with self._admission_lock, self._connect() as db:
            recent = db.execute(
                "SELECT COUNT(*) FROM inference_quotes WHERE client_hash=? AND created_ms>=?",
                (client_hash, now - QUOTE_WINDOW_SECONDS * 1000),
            ).fetchone()
            if recent is not None and int(recent[0]) >= QUOTE_LIMIT:
                raise InferenceError(429, "QUOTE_RATE_LIMIT", "Too many recent quote requests.", retry_after=60)
            global_recent = db.execute(
                "SELECT COUNT(*) FROM inference_quotes WHERE created_ms>=?",
                (now - QUOTE_WINDOW_SECONDS * 1000,),
            ).fetchone()
            if global_recent is not None and int(global_recent[0]) >= GLOBAL_QUOTE_LIMIT:
                raise InferenceError(429, "GLOBAL_QUOTE_RATE_LIMIT", "Public quote capacity is temporarily exhausted.", retry_after=60)
            quote_id = secrets.token_hex(32)
            quote = self._sign(
                {
                    "schema": "noos/wwm-quote/v2",
                    "quote_id": quote_id,
                    "request_id": request_id,
                    "pin_id": expected["pin_id"],
                    "capsule_id": expected["capsule_id"],
                    "execution_profile_id": expected["execution_profile_id"],
                    "query_profile_id": expected["query_profile_id"],
                    "prompt_commitment": prompt_commitment,
                    "input_tokens": input_tokens,
                    "maximum_output_tokens": maximum,
                    "payment_mode": "SPONSORED",
                    "payment_reference": SPONSOR_REFERENCE,
                    "maximum_fee_micro_noos": 0,
                    "expires_at_height": snapshot.head_height + QUOTE_HEIGHT_TTL,
                    "issued_at_ms": now,
                    "production": False,
                    "promotion_effect": "NONE",
                },
                "QUOTE",
            )
            db.execute(
                "INSERT INTO inference_quotes(quote_id,client_hash,quote_json,request_json,created_ms,expires_height) VALUES(?,?,?,?,?,?)",
                (
                    quote_id,
                    client_hash,
                    canonical_json(quote).decode("utf-8"),
                    canonical_json(request).decode("utf-8"),
                    now,
                    quote["expires_at_height"],
                ),
            )
        return InferenceReply(200, quote)

    def _submit(self, body: dict, client: str, idempotency_key: str | None) -> InferenceReply:
        quote_id = self._hex(body.get("quote_id"), HEX32, "INVALID_QUOTE_ID", "quote_id must be lowercase hex32.")
        commitment = self._hex(body.get("prompt_commitment"), HEX32, "INVALID_PROMPT_COMMITMENT", "Prompt commitment must be lowercase hex32.")
        salt = self._hex(body.get("prompt_salt"), HEX32, "INVALID_PROMPT_SALT", "Prompt salt must be lowercase hex32.")
        key = self._hex(idempotency_key, HEX16, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key must be lowercase hex16.")
        prompt = body.get("prompt")
        if not isinstance(prompt, str):
            raise InferenceError(400, "INVALID_PROMPT", "Prompt must be text.")
        normalized = prompt.replace("\r\n", "\n").strip()
        encoded_prompt = normalized.encode("utf-8")
        if normalized != prompt or not encoded_prompt or len(encoded_prompt) > MAX_PROMPT_BYTES:
            raise InferenceError(400, "INVALID_PROMPT", "Prompt must be normalized non-empty UTF-8 within 12,000 bytes.")
        computed = hashlib.sha256(PROMPT_DOMAIN + bytes.fromhex(salt) + encoded_prompt).hexdigest()
        if computed != commitment:
            raise InferenceError(400, "PROMPT_COMMITMENT_MISMATCH", "Prompt bytes do not match the quoted commitment.")
        now = self.now_ms()
        client_hash = self._client_hash(client)
        with self._admission_lock, self._connect() as db:
            replay = db.execute(
                "SELECT job_id,quote_id,prompt_commitment,status FROM inference_jobs WHERE client_hash=? AND idempotency_key=?",
                (client_hash, key),
            ).fetchone()
            if replay is not None:
                if replay["quote_id"] != quote_id or replay["prompt_commitment"] != commitment:
                    raise InferenceError(409, "IDEMPOTENCY_CONFLICT", "Idempotency key is already bound to another request.")
                return InferenceReply(
                    200,
                    {"schema": "noos/wwm-job/v2", "job_id": replay["job_id"], "status": replay["status"], "replayed": True},
                )
            quote_row = db.execute(
                "SELECT client_hash,quote_json,used_job_id,expires_height FROM inference_quotes WHERE quote_id=?",
                (quote_id,),
            ).fetchone()
            if quote_row is None or quote_row["client_hash"] != client_hash:
                raise InferenceError(404, "QUOTE_NOT_FOUND", "Quote was not found for this client.")
            quote = json.loads(str(quote_row["quote_json"]))
            if quote_row["used_job_id"] is not None:
                raise InferenceError(409, "QUOTE_ALREADY_USED", "Quote was already consumed by a job.")
            if quote.get("prompt_commitment") != commitment:
                raise InferenceError(409, "QUOTE_BINDING_MISMATCH", "Prompt commitment does not match the quote.")
            snapshot = self.provider.snapshot()
            if snapshot.head_height > int(quote_row["expires_height"]):
                raise InferenceError(409, "QUOTE_EXPIRED", "Quote expired at its bounded chain height.")
            recent = db.execute(
                "SELECT COUNT(*) FROM inference_jobs WHERE client_hash=? AND created_ms>=?",
                (client_hash, now - JOB_WINDOW_SECONDS * 1000),
            ).fetchone()
            if recent is not None and int(recent[0]) >= JOB_LIMIT:
                oldest = db.execute(
                    "SELECT MIN(created_ms) FROM inference_jobs WHERE client_hash=? AND created_ms>=?",
                    (client_hash, now - JOB_WINDOW_SECONDS * 1000),
                ).fetchone()
                remaining = JOB_WINDOW_SECONDS
                if oldest is not None and oldest[0] is not None:
                    remaining = max(1, (int(oldest[0]) + JOB_WINDOW_SECONDS * 1000 - now + 999) // 1000)
                raise InferenceError(429, "JOB_RATE_LIMIT", "Public pilot limit is three jobs per client per hour.", retry_after=remaining)
            global_recent = db.execute(
                "SELECT COUNT(*) FROM inference_jobs WHERE created_ms>=?",
                (now - JOB_WINDOW_SECONDS * 1000,),
            ).fetchone()
            if global_recent is not None and int(global_recent[0]) >= GLOBAL_JOB_LIMIT:
                oldest_global = db.execute(
                    "SELECT MIN(created_ms) FROM inference_jobs WHERE created_ms>=?",
                    (now - JOB_WINDOW_SECONDS * 1000,),
                ).fetchone()
                global_remaining = JOB_WINDOW_SECONDS
                if oldest_global is not None and oldest_global[0] is not None:
                    global_remaining = max(
                        1,
                        (int(oldest_global[0]) + JOB_WINDOW_SECONDS * 1000 - now + 999) // 1000,
                    )
                raise InferenceError(
                    429,
                    "GLOBAL_JOB_RATE_LIMIT",
                    "Public pilot global limit is twenty-four jobs per hour.",
                    retry_after=global_remaining,
                )
            queued = int(db.execute("SELECT COUNT(*) FROM inference_jobs WHERE status='QUEUED'").fetchone()[0])
            if queued >= MAX_QUEUED:
                raise InferenceError(429, "EXECUTOR_QUEUE_FULL", "The bounded two-job waiting queue is full.", retry_after=30)
            job_id = secrets.token_hex(32)
            db.execute(
                "INSERT INTO inference_jobs(job_id,quote_id,client_hash,idempotency_key,prompt,prompt_commitment,maximum_output_tokens,status,created_ms,updated_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (job_id, quote_id, client_hash, key, prompt, commitment, quote["maximum_output_tokens"], "QUEUED", now, now),
            )
            db.execute("UPDATE inference_quotes SET used_job_id=? WHERE quote_id=?", (job_id, quote_id))
        try:
            self._queue.put_nowait(job_id)
        except queue.Full:
            self._complete_without_output(job_id, "FAILED", "EXECUTOR_QUEUE_DESYNCHRONIZED")
            raise InferenceError(503, "EXECUTOR_QUEUE_FULL", "Bounded executor queue became unavailable.", retry_after=30)
        return InferenceReply(202, {"schema": "noos/wwm-job/v2", "job_id": job_id, "status": "QUEUED", "replayed": False})

    def _cancel(self, job_id: str, body: dict) -> InferenceReply:
        reason = body.get("reason", "USER_REQUESTED")
        if reason != "USER_REQUESTED":
            raise InferenceError(400, "INVALID_CANCEL_REASON", "Only USER_REQUESTED cancellation is accepted.")
        now = self.now_ms()
        with self._connect() as db:
            row = db.execute("SELECT status FROM inference_jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                raise InferenceError(404, "JOB_NOT_FOUND", "Inference job was not found.")
            status = str(row["status"])
            if status not in TERMINAL_STATUSES:
                status = "CANCEL_REQUESTED"
                db.execute("UPDATE inference_jobs SET status=?,updated_ms=? WHERE job_id=?", (status, now, job_id))
        with self._condition:
            self._condition.notify_all()
        return InferenceReply(200, {"schema": "noos/wwm-cancel/v2", "job_id": job_id, "status": status})

    def _stream_position(self, path: str, last_event_id: str | None) -> tuple[str, int]:
        matched = JOB_STREAM_ROUTE.fullmatch(path)
        if matched is None:
            raise InferenceError(404, "NOT_FOUND", "Inference stream route not found.")
        job_id = matched.group(1)
        if last_event_id is None or last_event_id == "":
            cursor = 0
        elif not last_event_id.isascii() or not last_event_id.isdigit():
            raise InferenceError(400, "INVALID_LAST_EVENT_ID", "Last-Event-ID must be a canonical decimal event ID.")
        else:
            cursor = int(last_event_id)
        with self._connect() as db:
            if db.execute("SELECT 1 FROM inference_jobs WHERE job_id=?", (job_id,)).fetchone() is None:
                raise InferenceError(404, "JOB_NOT_FOUND", "Inference job was not found.")
        return job_id, cursor

    def validate_stream(self, path: str, last_event_id: str | None) -> None:
        self._stream_position(path, last_event_id)

    def stream(self, path: str, last_event_id: str | None) -> Iterable[dict | None]:
        job_id, cursor = self._stream_position(path, last_event_id)
        while not self._closed.is_set():
            with self._connect() as db:
                rows = db.execute(
                    "SELECT event_id,payload_json FROM inference_events WHERE job_id=? AND event_id>? ORDER BY event_id",
                    (job_id, cursor),
                ).fetchall()
                status_row = db.execute("SELECT status FROM inference_jobs WHERE job_id=?", (job_id,)).fetchone()
            for row in rows:
                payload = json.loads(str(row["payload_json"]))
                cursor = int(row["event_id"])
                yield payload
            if status_row is None or str(status_row["status"]) in TERMINAL_STATUSES:
                return
            with self._condition:
                notified = self._condition.wait(timeout=15)
            if not notified:
                yield None

    def _append_event(self, job_id: str, event_type: str, data: dict) -> dict:
        with self._connect() as db:
            row = db.execute(
                "SELECT COALESCE(MAX(event_id),0)+1 FROM inference_events WHERE job_id=?",
                (job_id,),
            ).fetchone()
            event_id = int(row[0])
            payload = self._sign({"id": event_id, "type": event_type, "data": data}, "STREAM-EVENT")
            db.execute(
                "INSERT INTO inference_events(job_id,event_id,event_type,payload_json,created_ms) VALUES(?,?,?,?,?)",
                (job_id, event_id, event_type, canonical_json(payload).decode("utf-8"), self.now_ms()),
            )
        with self._condition:
            self._condition.notify_all()
        return payload

    def _receipt_base(
        self,
        job_id: str,
        quote: dict,
        status: str,
        *,
        evidence: str,
        error_code: str | None = None,
    ) -> dict:
        value = {
            "schema": "noos/wwm-receipt/v2",
            "job_id": job_id,
            "capsule_id": quote["capsule_id"],
            "execution_profile_id": quote["execution_profile_id"],
            "query_profile_id": quote["query_profile_id"],
            "terminal_status": status,
            "evidence_state": evidence,
            "chain_anchor": None,
            "settlement_state": "PENDING_CHAIN",
            "execution_scope": "OFF_CHAIN_INTERACTIVE_TESTNET",
            "production": False,
            "promotion_effect": "NONE",
            "disclosure": "Gateway-signed off-chain interactive execution receipt. It is not a factuality certificate and has not been settled on MindChain.",
            "completed_at_ms": self.now_ms(),
        }
        if error_code is not None:
            value["error_code"] = error_code
        return value

    def _job_quote(self, db: sqlite3.Connection, job_id: str) -> tuple[sqlite3.Row, dict]:
        row = db.execute(
            "SELECT j.*,q.quote_json FROM inference_jobs j JOIN inference_quotes q ON q.quote_id=j.quote_id WHERE j.job_id=?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise InferenceError(404, "JOB_NOT_FOUND", "Inference job was not found.")
        return row, json.loads(str(row["quote_json"]))

    def _store_receipt(self, job_id: str, status: str, receipt: dict) -> None:
        now = self.now_ms()
        with self._connect() as db:
            db.execute(
                "UPDATE inference_jobs SET status=?,receipt_json=?,prompt=NULL,updated_ms=? WHERE job_id=?",
                (status, canonical_json(receipt).decode("utf-8"), now, job_id),
            )
        self._append_event(job_id, "receipt.completed", receipt)

    def _complete_without_output(self, job_id: str, status: str, error_code: str) -> None:
        with self._connect() as db:
            row, quote = self._job_quote(db, job_id)
            if str(row["status"]) in TERMINAL_STATUSES and row["receipt_json"] is not None:
                return
        receipt = self._sign(
            self._receipt_base(job_id, quote, status, evidence="NONE", error_code=error_code),
            "RECEIPT",
        )
        self._store_receipt(job_id, status, receipt)

    def _worker_loop(self) -> None:
        while not self._closed.is_set():
            try:
                job_id = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if job_id is None:
                return
            try:
                self._execute_job(job_id)
            except Exception as error:
                try:
                    self._complete_without_output(job_id, "FAILED", "INTERNAL_EXECUTION_ERROR")
                except Exception:
                    pass
                print(
                    json.dumps(
                        {
                            "schema": "noos/wwm-public-inference-log/v1",
                            "event": "worker_error",
                            "job_id": job_id,
                            "error_type": type(error).__name__,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            finally:
                self._queue.task_done()

    def _execute_job(self, job_id: str) -> None:
        with self._connect() as db:
            row, quote = self._job_quote(db, job_id)
            if row["status"] == "CANCEL_REQUESTED":
                pass
            elif row["status"] != "QUEUED":
                return
            else:
                db.execute(
                    "UPDATE inference_jobs SET status='RUNNING',updated_ms=? WHERE job_id=?",
                    (self.now_ms(), job_id),
                )
        if row["status"] == "CANCEL_REQUESTED":
            self._complete_without_output(job_id, "CANCELLED", "USER_REQUESTED")
            return
        prompt = str(row["prompt"])
        maximum = int(row["maximum_output_tokens"])
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        output_bytes = 0

        def on_chunk(chunk: bytes, incremental_root: str) -> None:
            nonlocal output_bytes
            output_bytes += len(chunk)
            with self._connect() as event_db:
                current = event_db.execute("SELECT status FROM inference_jobs WHERE job_id=?", (job_id,)).fetchone()
            if current is None or current["status"] == "CANCEL_REQUESTED":
                return
            delta = decoder.decode(chunk, final=False)
            if delta:
                self._append_event(
                    job_id,
                    "output.delta",
                    {
                        "job_id": job_id,
                        "capsule_id": quote["capsule_id"],
                        "delta": delta,
                        "evidence_state": "PROVISIONAL_SIGNED",
                        "incremental_output_root": incremental_root,
                        "output_bytes": output_bytes,
                    },
                )

        try:
            result = self.executor.run(job_id, prompt, maximum, on_chunk)
            tail = decoder.decode(b"", final=True)
            if tail:
                self._append_event(
                    job_id,
                    "output.delta",
                    {
                        "job_id": job_id,
                        "capsule_id": quote["capsule_id"],
                        "delta": tail,
                        "evidence_state": "PROVISIONAL_SIGNED",
                        "incremental_output_root": result.output_root,
                        "output_bytes": len(result.output),
                    },
                )
            with self._connect() as db:
                current = db.execute("SELECT status FROM inference_jobs WHERE job_id=?", (job_id,)).fetchone()
            if current is not None and current["status"] == "CANCEL_REQUESTED":
                self._complete_without_output(job_id, "CANCELLED", "USER_REQUESTED")
                return
            receipt = self._receipt_base(job_id, quote, "COMPLETED", evidence="PROVISIONAL_SIGNED")
            receipt.update(
                {
                    "output_root": result.output_root,
                    "token_history_root": result.token_history_root,
                    "output_tokens": result.output_tokens,
                    "output_bytes": len(result.output),
                    "duration_ms": result.duration_ms,
                    "tokenizer_executable_sha256": result.tokenizer_sha256,
                }
            )
            self._store_receipt(job_id, "COMPLETED", self._sign(receipt, "RECEIPT"))
        except (InferenceError, UnicodeDecodeError) as error:
            code = error.code if isinstance(error, InferenceError) else "INVALID_UTF8_OUTPUT"
            self._complete_without_output(job_id, "FAILED", code)
