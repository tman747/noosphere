from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA: Final[str] = "noos/wwm-public-testnet-monitor/v1"
SAMPLE_SCHEMA: Final[str] = "noos/wwm-public-testnet-monitor-sample/v1"
SUMMARY_SCHEMA: Final[str] = "noos/wwm-public-testnet-monitor-daily-summary/v1"
KEY_SCHEMA: Final[str] = "noos/wwm-public-testnet-monitor-key/v1"
SAMPLE_DOMAIN: Final[bytes] = b"NOOS/SIG/WWM/V1\0PUBLIC-TESTNET-MONITOR-SAMPLE\0"
SUMMARY_DOMAIN: Final[bytes] = b"NOOS/SIG/WWM/V1\0PUBLIC-TESTNET-MONITOR-DAILY\0"
LOOPBACK_NAMES: Final[set[str]] = {"127.0.0.1", "::1", "localhost"}
HEX40: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES: Final[int] = 2 * 1024 * 1024
MAX_DAY_BYTES: Final[int] = 16 * 1024 * 1024
SHARE_BYTES: Final[int] = 1_047_552
EXPECTED_R2_BUCKET: Final[str] = "mindchain-wwm-artifacts-pilot"


class MonitorError(RuntimeError):
    pass


@dataclass(frozen=True)
class MonitorConfig:
    listen_host: str
    listen_port: int
    deployment_path: Path
    evidence_dir: Path
    signing_key_path: Path
    r2_report_path: Path
    worker_bearer_token: str
    source_revision: str
    interval_seconds: int
    request_timeout_seconds: float
    seed_hostname: str
    seed_ip: str
    seed2_hostname: str
    seed2_ip: str
    seed_rpc_port: int
    chain_id: str
    genesis_hash: str
    artifact_id: str
    manifest_root: str
    site_origin: str
    rpc_origin: str
    status_origin: str
    artifact_origin: str


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    latency_ms: int
    detail: dict[str, object]

    def document(self) -> dict[str, object]:
        return {"name": self.name, "ok": self.ok, "latency_ms": self.latency_ms, "detail": self.detail}


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, raw_port = value.rpartition(":")
    if not separator or host not in LOOPBACK_NAMES:
        raise MonitorError("listen address must be loopback host:port")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise MonitorError("listen port must be an integer") from error
    if not 1 <= port <= 65535:
        raise MonitorError("listen port must be within 1..65535")
    return host, port


def exact_https_origin(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise MonitorError(f"{label} must be an HTTPS origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise MonitorError(f"{label} must be an exact HTTPS origin")
    return f"https://{parsed.hostname.lower()}"


def load_object(path: Path, maximum: int = MAX_JSON_BYTES) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > maximum:
        raise MonitorError(f"JSON document exceeds byte bound: {resolved.name}")
    try:
        value = json.loads(resolved.read_bytes())
    except (OSError, ValueError) as error:
        raise MonitorError(f"JSON document is invalid: {resolved.name}") from error
    if not isinstance(value, dict):
        raise MonitorError(f"JSON document must be an object: {resolved.name}")
    return value


def require_hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise MonitorError(f"{label} must be canonical hex32")
    return value


def load_worker_bearer_token(path: Path) -> str:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > 65_536:
        raise MonitorError("workerd configuration exceeds byte bound")
    try:
        text = resolved.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise MonitorError("workerd configuration is not UTF-8") from error
    sections = list(re.finditer(r"(?m)^\s*\[worker\]\s*(?:#.*)?$", text))
    if len(sections) != 1:
        raise MonitorError("workerd configuration must contain one worker section")
    following = re.search(r"(?m)^\s*\[", text[sections[0].end():])
    end = sections[0].end() + following.start() if following else len(text)
    block = text[sections[0].end():end]
    tokens = re.findall(
        r'(?m)^\s*sidecar_token_hex\s*=\s*"([0-9a-f]{64})"\s*(?:#.*)?$',
        block,
    )
    if len(tokens) != 1 or tokens[0] == "0" * 64:
        raise MonitorError("workerd configuration has no unique valid sidecar token")
    return tokens[0]


def load_config(args: argparse.Namespace) -> MonitorConfig:
    listen_host, listen_port = parse_listen(args.listen)
    if not HEX40.fullmatch(args.source_revision):
        raise MonitorError("source revision must be a lowercase 40-character Git commit")
    if not 30 <= args.interval_seconds <= 3_600:
        raise MonitorError("interval seconds must be within 30..3600")
    if not 1 <= args.request_timeout_seconds <= 30:
        raise MonitorError("request timeout seconds must be within 1..30")
    deployment_path = args.deployment.resolve(strict=True)
    deployment = load_object(deployment_path)
    if (
        deployment.get("schema") != "noos/wwm-public-testnet/v1"
        or deployment.get("environment") != "public-testnet"
        or deployment.get("production") is not False
        or deployment.get("production_capable") is not False
        or deployment.get("promotion_effect") != "NONE"
    ):
        raise MonitorError("deployment is not the fail-closed public testnet profile")
    chain = deployment.get("chain_binding")
    model = deployment.get("model_binding")
    endpoints = deployment.get("public_endpoints")
    if not isinstance(chain, dict) or not isinstance(model, dict) or not isinstance(endpoints, dict):
        raise MonitorError("deployment is missing chain, model, or endpoint bindings")
    evidence_dir = args.evidence_dir.resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    signing_key = args.signing_key.resolve(strict=True)
    r2_report = args.r2_report.resolve(strict=True)
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", args.seed_hostname):
        raise MonitorError("seed hostname is invalid")
    try:
        socket.inet_pton(socket.AF_INET, args.seed_ip)
    except OSError as error:
        raise MonitorError("seed IP must be canonical IPv4") from error
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", args.seed2_hostname):
        raise MonitorError("second seed hostname is invalid")
    try:
        socket.inet_pton(socket.AF_INET, args.seed2_ip)
    except OSError as error:
        raise MonitorError("second seed IP must be canonical IPv4") from error
    if not 1 <= args.seed_rpc_port <= 65535:
        raise MonitorError("seed RPC port is invalid")
    return MonitorConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        deployment_path=deployment_path,
        evidence_dir=evidence_dir,
        signing_key_path=signing_key,
        r2_report_path=r2_report,
        worker_bearer_token=load_worker_bearer_token(args.worker_config),
        source_revision=args.source_revision,
        interval_seconds=args.interval_seconds,
        request_timeout_seconds=args.request_timeout_seconds,
        seed_hostname=args.seed_hostname,
        seed_ip=args.seed_ip,
        seed2_hostname=args.seed2_hostname,
        seed2_ip=args.seed2_ip,
        seed_rpc_port=args.seed_rpc_port,
        chain_id=require_hex32(chain.get("chain_id"), "chain ID"),
        genesis_hash=require_hex32(chain.get("genesis_hash"), "genesis hash"),
        artifact_id=require_hex32(model.get("artifact_id"), "artifact ID"),
        manifest_root=require_hex32(model.get("manifest_root"), "manifest root"),
        site_origin=exact_https_origin(endpoints.get("site"), "site endpoint"),
        rpc_origin=exact_https_origin(endpoints.get("read_gateway"), "RPC endpoint"),
        status_origin=exact_https_origin(endpoints.get("status"), "status endpoint"),
        artifact_origin=exact_https_origin(endpoints.get("artifacts"), "artifact endpoint"),
    )


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise MonitorError("monitor signing key must contain exactly 32 raw bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as error:
        raise MonitorError("monitor signing key is invalid") from error


def public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()


def generate_key(private_path: Path, public_path: Path) -> dict[str, object]:
    private = private_path.resolve()
    public_file = public_path.resolve()
    if private.exists() or public_file.exists():
        raise MonitorError("monitor key paths are insert-once and must not already exist")
    private.parent.mkdir(parents=True, exist_ok=True)
    public_file.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    public = public_key_bytes(key)
    with private.open("xb") as handle:
        handle.write(seed)
        handle.flush()
        os.fsync(handle.fileno())
    document = {
        "schema": KEY_SCHEMA,
        "environment": "public-testnet",
        "production": False,
        "role": "testnet_monitor",
        "key_id": key_id(public),
        "public_key_base64": base64.b64encode(public).decode("ascii"),
    }
    try:
        with public_file.open("xb") as handle:
            handle.write(canonical_json(document) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        private.unlink(missing_ok=True)
        raise
    return document


def request_bytes(url: str, timeout: float, *, headers: dict[str, str] | None = None) -> tuple[int, object, bytes]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "mindchain-wwm-testnet-monitor/1", **(headers or {})},
        method="GET",
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_JSON_BYTES + 1)
        if len(body) > MAX_JSON_BYTES:
            raise MonitorError("response exceeded monitor byte bound")
        return int(response.status), response.headers, body


def request_json(
    url: str,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, object, dict[str, object]]:
    status, response_headers, body = request_bytes(url, timeout, headers=headers)
    try:
        value = json.loads(body)
    except ValueError as error:
        raise MonitorError("endpoint returned malformed JSON") from error
    if not isinstance(value, dict):
        raise MonitorError("endpoint JSON must be an object")
    return status, response_headers, value


def run_check(name: str, function: Callable[[], dict[str, object]]) -> CheckResult:
    started = time.monotonic()
    try:
        detail = function()
        return CheckResult(name, True, round((time.monotonic() - started) * 1000), detail)
    except Exception as error:  # each probe is isolated; failures become bounded public status
        message = str(error) if isinstance(error, MonitorError) else type(error).__name__
        return CheckResult(name, False, round((time.monotonic() - started) * 1000), {"error": message[:160]})


def tls_probe(origin: str, timeout: float) -> dict[str, object]:
    hostname = urlsplit(origin).hostname
    if hostname is None:
        raise MonitorError("TLS origin has no hostname")
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=timeout) as plain:
        with context.wrap_socket(plain, server_hostname=hostname) as secure:
            certificate = secure.getpeercert()
    expiry_text = certificate.get("notAfter")
    if not isinstance(expiry_text, str):
        raise MonitorError("TLS certificate has no expiry")
    expires_at = int(ssl.cert_time_to_seconds(expiry_text))
    remaining = expires_at - int(time.time())
    if remaining < 7 * 86_400:
        raise MonitorError("TLS certificate expires within seven days")
    return {"hostname": hostname, "expires_at": expires_at, "remaining_days": remaining // 86_400}


def worker_probe(config: MonitorConfig, timeout: float) -> dict[str, object]:
    status, _, body = request_json(
        "http://127.0.0.1:29807/health/ready",
        timeout,
        headers={"Authorization": f"Bearer {config.worker_bearer_token}"},
    )
    if status != 200:
        raise MonitorError("inference worker is not ready")
    return {"status": status, "ready": body.get("ready", True)}


def collect_checks(config: MonitorConfig) -> list[CheckResult]:
    timeout = config.request_timeout_seconds

    def site() -> dict[str, object]:
        status, _, body = request_bytes(config.site_origin + "/", timeout, headers={"Accept": "text/html"})
        if status != 200 or b"MindChain" not in body:
            raise MonitorError("pilot site response is invalid")
        return {"status": status, "bytes": len(body)}

    def gateway() -> dict[str, object]:
        status, _, body = request_json(config.rpc_origin + "/healthz", timeout)
        if status != 200 or body.get("production") is not False or body.get("promotion_effect") != "NONE":
            raise MonitorError("gateway is not healthy and fail-closed")
        if body.get("chain_id") != config.chain_id or body.get("genesis_hash") != config.genesis_hash:
            raise MonitorError("gateway chain identity mismatch")
        head = body.get("unsafe_head") if isinstance(body.get("unsafe_head"), dict) else {}
        finalized = body.get("finalized") if isinstance(body.get("finalized"), dict) else {}
        return {"status": status, "unsafe_height": head.get("height"), "finalized_epoch": finalized.get("epoch")}

    def model() -> dict[str, object]:
        status, _, body = request_json(config.rpc_origin + "/api/model-resolution/bonsai-q1", timeout)
        active = body.get("active") if isinstance(body.get("active"), dict) else {}
        if status != 200 or body.get("production_effect") != "NONE":
            raise MonitorError("model resolution is unavailable or promotion-capable")
        if active.get("artifact_id") != config.artifact_id or active.get("manifest_root") != config.manifest_root:
            raise MonitorError("model resolution binding mismatch")
        return {"status": status, "registration_state": body.get("registration_state")}

    def artifacts() -> dict[str, object]:
        status, _, body = request_json(config.artifact_origin + "/healthz", timeout)
        if status != 200 or body.get("production") is not False or body.get("production_custody") is not False:
            raise MonitorError("artifact host is unavailable or production-promoting")
        share_count = body.get("share_count")
        if not isinstance(share_count, int) or share_count < 9:
            raise MonitorError("artifact host share count is insufficient")
        return {"status": status, "share_count": share_count, "share_bytes": body.get("share_bytes")}

    def range_probe() -> dict[str, object]:
        status, headers, body = request_bytes(
            config.artifact_origin + "/shares/000000/00.share", timeout, headers={"Range": "bytes=0-99"}
        )
        if status != 206 or len(body) != 100 or headers.get("Content-Range") != f"bytes 0-99/{SHARE_BYTES}":
            raise MonitorError("artifact range response is invalid")
        return {"status": status, "bytes": len(body)}

    def coordinator() -> dict[str, object]:
        status, _, body = request_json(config.site_origin + "/api/wwm-web-capacity/v1/config", timeout)
        binding = body.get("chain_binding") if isinstance(body.get("chain_binding"), dict) else {}
        if status != 200 or body.get("production_custody") is not False or body.get("rewards") is not False:
            raise MonitorError("browser coordinator is unavailable or production-promoting")
        if (
            binding.get("chain_id") != config.chain_id
            or binding.get("genesis_hash") != config.genesis_hash
            or binding.get("artifact_id") != config.artifact_id
            or binding.get("manifest_root") != config.manifest_root
        ):
            raise MonitorError("browser coordinator binding mismatch")
        if config.artifact_origin not in (body.get("source_allowlist") or []):
            raise MonitorError("artifact source is not coordinator-authorized")
        return {"status": status, "experiment_state": body.get("experiment_state")}

    def worker() -> dict[str, object]:
        return worker_probe(config, timeout)

    def r2() -> dict[str, object]:
        report = load_object(config.r2_report_path)
        if (
            report.get("schema") != "noos/wwm-r2-static-bundle-sync/v1"
            or report.get("verdict") != "PASS"
            or report.get("bucket") != EXPECTED_R2_BUCKET
            or report.get("production") is not False
            or report.get("production_custody") is not False
        ):
            raise MonitorError("private R2 mirror report is invalid")
        return {
            "bucket": EXPECTED_R2_BUCKET,
            "object_count": report.get("object_count"),
            "bundle_bytes": report.get("bundle_bytes"),
            "completed_at": report.get("completed_at"),
        }

    def seed_dns(hostname: str, expected_ip: str) -> dict[str, object]:
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(hostname, None, socket.AF_INET)})
        if expected_ip not in addresses:
            raise MonitorError("seed DNS does not resolve to the pinned public IP")
        return {"hostname": hostname, "addresses": addresses}

    def seed_rpc_closed(public_ip: str) -> dict[str, object]:
        try:
            with socket.create_connection((public_ip, config.seed_rpc_port), timeout=timeout):
                raise MonitorError("seed operator RPC is publicly reachable")
        except MonitorError:
            raise
        except OSError:
            return {"public_ip": public_ip, "port": config.seed_rpc_port, "closed": True}

    checks = [
        run_check("site", site),
        run_check("gateway", gateway),
        run_check("model_resolution", model),
        run_check("artifact_host", artifacts),
        run_check("artifact_range", range_probe),
        run_check("browser_coordinator", coordinator),
        run_check("inference_worker", worker),
        run_check("r2_private_mirror", r2),
        run_check("seed_1_dns", lambda: seed_dns(config.seed_hostname, config.seed_ip)),
        run_check("seed_2_dns", lambda: seed_dns(config.seed2_hostname, config.seed2_ip)),
        run_check("seed_1_rpc_closed", lambda: seed_rpc_closed(config.seed_ip)),
        run_check("seed_2_rpc_closed", lambda: seed_rpc_closed(config.seed2_ip)),
    ]
    for label, origin in (
        ("site_tls", config.site_origin),
        ("rpc_tls", config.rpc_origin),
        ("status_tls", config.status_origin),
        ("artifact_tls", config.artifact_origin),
    ):
        checks.append(run_check(label, lambda origin=origin: tls_probe(origin, timeout)))
    return checks


def sign_payload(payload: dict[str, object], key: Ed25519PrivateKey, domain: bytes, id_field: str) -> dict[str, object]:
    message = domain + canonical_json(payload)
    public = public_key_bytes(key)
    envelope = dict(payload)
    envelope[id_field] = hashlib.sha256(message).hexdigest()
    envelope["signer_key_id"] = key_id(public)
    envelope["public_key_base64"] = base64.b64encode(public).decode("ascii")
    envelope["signature_base64"] = base64.b64encode(key.sign(message)).decode("ascii")
    return envelope


def verify_envelope(envelope: dict[str, object], domain: bytes, id_field: str) -> None:
    try:
        public = base64.b64decode(str(envelope["public_key_base64"]), validate=True)
        signature = base64.b64decode(str(envelope["signature_base64"]), validate=True)
    except (KeyError, ValueError) as error:
        raise MonitorError("signed monitor envelope encoding is invalid") from error
    payload = {key: value for key, value in envelope.items() if key not in {id_field, "signer_key_id", "public_key_base64", "signature_base64"}}
    message = domain + canonical_json(payload)
    expected_id = hashlib.sha256(message).hexdigest()
    if envelope.get(id_field) != expected_id or envelope.get("signer_key_id") != key_id(public):
        raise MonitorError("signed monitor envelope identity is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (ValueError, InvalidSignature) as error:
        raise MonitorError("signed monitor envelope signature is invalid") from error


class EvidenceStore:
    def __init__(self, root: Path, key: Ed25519PrivateKey, source_revision: str, deployment_sha256: str):
        self.root = root
        self.key = key
        self.source_revision = source_revision
        self.deployment_sha256 = deployment_sha256
        self.samples = root / "samples"
        self.summaries = root / "daily"
        self.samples.mkdir(parents=True, exist_ok=True)
        self.summaries.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def _sample_path(self, day: str) -> Path:
        return self.samples / f"{day}.jsonl"

    def _last_id(self, path: Path) -> str | None:
        if not path.exists():
            return None
        if path.stat().st_size > MAX_DAY_BYTES:
            raise MonitorError("daily sample ledger exceeds byte bound")
        rows = [line for line in path.read_bytes().splitlines() if line]
        if not rows:
            return None
        try:
            envelope = json.loads(rows[-1])
        except ValueError as error:
            raise MonitorError("daily sample ledger tail is malformed") from error
        if not isinstance(envelope, dict):
            raise MonitorError("daily sample ledger tail is not an object")
        verify_envelope(envelope, SAMPLE_DOMAIN, "sample_id")
        sample_id = envelope.get("sample_id")
        if not isinstance(sample_id, str):
            raise MonitorError("daily sample ledger tail has no sample ID")
        return sample_id

    def append(self, checks: list[CheckResult], observed_at: str) -> dict[str, object]:
        day = observed_at[:10]
        path = self._sample_path(day)
        with self.lock:
            payload = {
                "schema": SAMPLE_SCHEMA,
                "environment": "public-testnet",
                "production": False,
                "production_authorized": False,
                "promotion_effect": "NONE",
                "source_revision": self.source_revision,
                "deployment_sha256": self.deployment_sha256,
                "observed_at_utc": observed_at,
                "previous_sample_id": self._last_id(path),
                "status": "ok" if all(check.ok for check in checks) else "degraded",
                "checks": [check.document() for check in checks],
            }
            envelope = sign_payload(payload, self.key, SAMPLE_DOMAIN, "sample_id")
            encoded = canonical_json(envelope) + b"\n"
            if path.exists() and path.stat().st_size + len(encoded) > MAX_DAY_BYTES:
                raise MonitorError("daily sample ledger would exceed byte bound")
            with path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            return envelope

    def summarize(self, day: str) -> dict[str, object]:
        path = self._sample_path(day)
        if not path.is_file() or path.stat().st_size > MAX_DAY_BYTES:
            raise MonitorError("daily sample ledger is missing or oversized")
        envelopes: list[dict[str, object]] = []
        previous: str | None = None
        for raw in path.read_bytes().splitlines():
            if not raw:
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise MonitorError("daily sample entry is not an object")
            verify_envelope(value, SAMPLE_DOMAIN, "sample_id")
            if value.get("previous_sample_id") != previous:
                raise MonitorError("daily sample hash chain is discontinuous")
            previous = str(value["sample_id"])
            envelopes.append(value)
        if not envelopes:
            raise MonitorError("daily sample ledger is empty")
        timestamps = [str(row["observed_at_utc"]) for row in envelopes]
        passed = sum(row.get("status") == "ok" for row in envelopes)
        summary_payload = {
            "schema": SUMMARY_SCHEMA,
            "environment": "public-testnet",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "source_revision": self.source_revision,
            "deployment_sha256": self.deployment_sha256,
            "day_utc": day,
            "observed_start_utc": timestamps[0],
            "observed_end_utc": timestamps[-1],
            "sample_count": len(envelopes),
            "passing_samples": passed,
            "degraded_samples": len(envelopes) - passed,
            "first_sample_id": envelopes[0]["sample_id"],
            "last_sample_id": envelopes[-1]["sample_id"],
            "coverage_complete": False,
            "formal_e_wwm_23_evidence": False,
        }
        summary = sign_payload(summary_payload, self.key, SUMMARY_DOMAIN, "summary_id")
        destination = self.summaries / f"{day}.json"
        if destination.exists():
            existing = load_object(destination)
            if existing != summary:
                raise MonitorError("daily summary is immutable and already differs")
            return existing
        with destination.open("xb") as handle:
            handle.write(canonical_json(summary) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return summary


class MonitorState:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.key = load_signing_key(config.signing_key_path)
        deployment_sha256 = hashlib.sha256(config.deployment_path.read_bytes()).hexdigest()
        self.store = EvidenceStore(config.evidence_dir, self.key, config.source_revision, deployment_sha256)
        self.lock = threading.Lock()
        self.latest: dict[str, object] | None = None
        self.previous_day: str | None = None
        self.last_error: str | None = None

    def collect(self) -> dict[str, object]:
        observed_at = utc_now()
        checks = collect_checks(self.config)
        envelope = self.store.append(checks, observed_at)
        day = observed_at[:10]
        if self.previous_day is not None and self.previous_day != day:
            self.store.summarize(self.previous_day)
        self.previous_day = day
        with self.lock:
            self.latest = envelope
            self.last_error = None
        return envelope

    def snapshot(self) -> dict[str, object] | None:
        with self.lock:
            return None if self.latest is None else dict(self.latest)

    def metrics(self) -> bytes:
        latest = self.snapshot()
        lines = [
            "# HELP mindchain_wwm_public_testnet_up All required public testnet checks pass.",
            "# TYPE mindchain_wwm_public_testnet_up gauge",
        ]
        overall = 0
        if latest is not None:
            overall = int(latest.get("status") == "ok")
        lines.append(f"mindchain_wwm_public_testnet_up {overall}")
        lines.extend([
            "# HELP mindchain_wwm_production_authorized Production activation authorization state.",
            "# TYPE mindchain_wwm_production_authorized gauge",
            "mindchain_wwm_production_authorized 0",
            "# HELP mindchain_wwm_public_check_up Individual bounded monitor check state.",
            "# TYPE mindchain_wwm_public_check_up gauge",
        ])
        if latest is not None:
            checks = latest.get("checks") if isinstance(latest.get("checks"), list) else []
            for check in checks:
                if isinstance(check, dict) and re.fullmatch(r"[a-z0-9_]{1,64}", str(check.get("name"))):
                    lines.append(f'mindchain_wwm_public_check_up{{check="{check["name"]}"}} {int(check.get("ok") is True)}')
        return ("\n".join(lines) + "\n").encode("ascii")


class MonitorHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mindchain-wwm-public-testnet-monitor/1"

    @property
    def state(self) -> MonitorState:
        state = getattr(self.server, "monitor_state", None)
        if not isinstance(state, MonitorState):
            raise MonitorError("monitor server state is missing")
        return state

    def log_message(self, format: str, *args: object) -> None:
        print(f"monitor {self.client_address[0]} {format % args}", flush=True)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path)
        if path.query or path.fragment:
            self._json(400, {"schema": SCHEMA, "status": "error", "error": "INVALID_PATH"})
            return
        if path.path == "/metrics":
            self._reply(200, "text/plain; version=0.0.4; charset=utf-8", self.state.metrics())
            return
        latest = self.state.snapshot()
        if path.path in {"/", "/status.json", "/healthz"}:
            if latest is None:
                self._json(503, {"schema": SCHEMA, "status": "starting", "production": False})
                return
            status = 200 if path.path != "/healthz" or latest.get("status") == "ok" else 503
            self._json(status, latest)
            return
        self._json(404, {"schema": SCHEMA, "status": "error", "error": "NOT_FOUND"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        self._json(405, {"schema": SCHEMA, "status": "error", "error": "METHOD_NOT_ALLOWED"})

    def _json(self, status: int, value: object) -> None:
        self._reply(status, "application/json; charset=utf-8", canonical_json(value) + b"\n")

    def _reply(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class MonitorServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, state: MonitorState):
        super().__init__((state.config.listen_host, state.config.listen_port), MonitorHandler)
        self.monitor_state = state


def collector_loop(state: MonitorState, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            sample = state.collect()
            print(json.dumps({"event": "sample", "sample_id": sample["sample_id"], "status": sample["status"]}, sort_keys=True), flush=True)
        except Exception as error:
            with state.lock:
                state.last_error = str(error)[:160]
            print(json.dumps({"event": "collection_error", "error": type(error).__name__}, sort_keys=True), flush=True)
        stop.wait(state.config.interval_seconds)


def serve(config: MonitorConfig) -> None:
    state = MonitorState(config)
    server = MonitorServer(state)
    stop = threading.Event()
    collector = threading.Thread(target=collector_loop, args=(state, stop), daemon=True)
    collector.start()
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "event": "ready",
                "listen": f"{config.listen_host}:{config.listen_port}",
                "environment": "public-testnet",
                "production": False,
                "production_authorized": False,
                "source_revision": config.source_revision,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()
        collector.join(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Signed Prometheus-compatible monitor for the WWM public testnet")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    monitor = commands.add_parser("serve")
    monitor.add_argument("--listen", default="127.0.0.1:29901")
    monitor.add_argument("--deployment", type=Path, required=True)
    monitor.add_argument("--evidence-dir", type=Path, required=True)
    monitor.add_argument("--signing-key", type=Path, required=True)
    monitor.add_argument("--r2-report", type=Path, required=True)
    monitor.add_argument("--worker-config", type=Path, required=True)
    monitor.add_argument("--source-revision", required=True)
    monitor.add_argument("--interval-seconds", type=int, default=60)
    monitor.add_argument("--request-timeout-seconds", type=float, default=10.0)
    monitor.add_argument("--seed-hostname", default="wwm-seed.mindchain.network")
    monitor.add_argument("--seed-ip", default="20.15.164.29")
    monitor.add_argument("--seed2-hostname", default="wwm-seed-2.mindchain.network")
    monitor.add_argument("--seed2-ip", default="172.202.41.123")
    monitor.add_argument("--seed-rpc-port", type=int, default=29652)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "keygen":
            print(json.dumps(generate_key(args.private_key, args.public_key), sort_keys=True), flush=True)
        else:
            serve(load_config(args))
        return 0
    except (MonitorError, OSError, ValueError) as error:
        print(f"public testnet monitor failed: {error}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
