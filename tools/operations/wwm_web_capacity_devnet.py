#!/usr/bin/env python3
"""Owner-controlled loopback HTTPS smoke for experimental WWM web capacity.

The harness serves only operator-authorized static bundles, drives the existing
coordinator HTTP/queue-restore contracts, and optionally invokes the canonical
artifact-service importer.  It never scans, enrolls, uploads, rewards, certifies,
or promotes by default.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA = "noos/wwm-web-capacity-multi-origin-devnet/v1"
EVIDENCE_SCHEMA = "noos/wwm-web-capacity-multi-origin-devnet-evidence/v1"
MARKER_SCHEMA = "noos/wwm-web-capacity-multi-origin-devnet-workspace/v1"
WEB_SCHEMA = "noos/wwm-web-capacity/v1"
MEDIA_TYPE = "application/vnd.noos.wwm-web-capacity.v1+json"
SHARE_BYTES = 1_047_552
MAX_JSON_BYTES = 64 * 1024
MAX_ASSIGNMENT_BYTES = 512 * 1024
FULL_POSITION_RESTORE_LIFETIME_SECONDS = 900
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
REVALIDATE_CACHE = "public, max-age=0, no-cache, must-revalidate"
EVIDENCE_DOMAIN = b"NOOS/SIG/WWM-WEB-MULTI-ORIGIN-DEVNET/V1\0"
HEX32 = set("0123456789abcdef")


class DevnetError(RuntimeError):
    """A fail-closed smoke prerequisite or observed contract was invalid."""


@dataclass(frozen=True)
class OriginConfig:
    origin: str
    bundle_root: Path
    provider: str
    region: str
    failure_domain: str


@dataclass(frozen=True)
class Commands:
    artifact_service: tuple[str, ...]
    coordinator: tuple[str, ...]


@dataclass(frozen=True)
class RuntimeConfig:
    config_path: Path
    config_digest: str
    workspace_root: Path
    run_root: Path
    evidence_path: Path
    certificate: Path
    private_key: Path
    ca_certificate: Path
    coordinator_url: str
    coordinator_config: Path
    mutation_origin: str
    consent_version: str
    evidence_seed_env: str
    chain_binding: dict[str, str]
    artifact_store: dict[str, Any]
    origins: tuple[OriginConfig, ...]
    commands: Commands
    manage_coordinator_process: bool
    restore_opt_in: bool
    corruption_probe: bool
    import_config: dict[str, Any] | None


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_object(path: Path, maximum: int = MAX_INVENTORY_BYTES) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise DevnetError(f"cannot read {path}: {error}") from error
    if not raw or len(raw) > maximum:
        raise DevnetError(f"JSON input is empty or exceeds {maximum} bytes: {path}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DevnetError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise DevnetError(f"JSON input must be an object: {path}")
    return value


def require_hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in HEX32 for char in value):
        raise DevnetError(f"{label} must be canonical lowercase hex32")
    return value


def require_text(value: Any, label: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise DevnetError(f"{label} must contain 1..={maximum} UTF-8 bytes")
    return value


def canonical_loopback_origin(value: Any, label: str, *, https: bool = True) -> str:
    if not isinstance(value, str):
        raise DevnetError(f"{label} must be an origin string")
    parsed = urllib.parse.urlsplit(value)
    expected_scheme = "https" if https else parsed.scheme
    if parsed.scheme != expected_scheme or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise DevnetError(f"{label} must be a canonical {'HTTPS ' if https else ''}loopback origin")
    if parsed.hostname is None or parsed.port is None:
        raise DevnetError(f"{label} must include an explicit loopback port")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise DevnetError(f"{label} must use literal 127.0.0.1 or ::1; DNS names are forbidden") from error
    if address not in {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}:
        raise DevnetError(f"{label} must use exact 127.0.0.1 or ::1")
    canonical_host = f"[{parsed.hostname.lower()}]" if ":" in parsed.hostname else parsed.hostname.lower()
    canonical = f"{parsed.scheme}://{canonical_host}:{parsed.port}"
    if value.rstrip("/") != canonical:
        raise DevnetError(f"{label} is not canonical: expected {canonical}")
    return canonical


def resolve_existing(path: Any, base: Path, label: str, *, file: bool | None = None) -> Path:
    if not isinstance(path, str) or not path:
        raise DevnetError(f"{label} path is missing")
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise DevnetError(f"{label} does not exist: {candidate}") from error
    if file is True and not resolved.is_file():
        raise DevnetError(f"{label} must be a regular file: {resolved}")
    if file is False and not resolved.is_dir():
        raise DevnetError(f"{label} must be a directory: {resolved}")
    return resolved


def resolve_output(path: Any, base: Path, label: str) -> Path:
    if not isinstance(path, str) or not path:
        raise DevnetError(f"{label} path is missing")
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve(strict=False)


def child_of(path: Path, parent: Path, label: str) -> None:
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise DevnetError(f"{label} must remain below {parent}") from error
    if path == parent:
        raise DevnetError(f"{label} cannot be the workspace root itself")


def parse_command(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise DevnetError(f"{label} must be a nonempty argv array")
    return tuple(value)

def validate_coordinator_fixture_config(
    path: Path,
    ca_certificate: Path,
    mutation_origin: str,
    origins: Sequence[OriginConfig],
) -> bool:
    document = load_object(path, MAX_JSON_BYTES)
    if (
        document.get("activation_scope") != "EXPERIMENTAL_TEST_ONLY"
        or document.get("experiment_state") not in {"LOCAL_FIXTURE", "DEVNET"}
        or document.get("production") is not False
        or document.get("rewards") is not False
    ):
        raise DevnetError("coordinator config must be explicit EXPERIMENTAL_TEST_ONLY local/devnet with production=false and rewards=false")
    isolation = document.get("isolation")
    if (
        not isinstance(isolation, dict)
        or any(
            isolation.get(key) is not None
            for key in ("validator_key_path", "consensus_store_path", "model_execution_path")
        )
        or isolation.get("authority_to_issue_custody_certificates") is not False
    ):
        raise DevnetError("coordinator fixture must have no validator, consensus, execution, or certificate authority")
    listen = document.get("listen")
    if not isinstance(listen, str):
        raise DevnetError("coordinator fixture listener is missing")
    listener_host = listen[1 : listen.index("]")] if listen.startswith("[") and "]:" in listen else listen.rsplit(":", 1)[0]
    try:
        listener_address = ipaddress.ip_address(listener_host)
    except ValueError as error:
        raise DevnetError("coordinator fixture listener must be a literal loopback socket") from error
    if not listener_address.is_loopback:
        raise DevnetError("coordinator fixture listener must be loopback")
    loopback = document.get("loopback_test_transport")
    if not isinstance(loopback, dict) or loopback.get("enabled") is not True or set(loopback) != {"enabled", "ca_certificate_path", "full_position_repair"}:
        raise DevnetError("coordinator fixture must explicitly enable the bounded loopback_test_transport")
    configured_ca = resolve_existing(loopback["ca_certificate_path"], path.parent, "coordinator loopback CA", file=True)
    if configured_ca != ca_certificate:
        raise DevnetError("harness and coordinator must pin the same operator loopback CA")
    expected_sources = {
        origin.origin: (origin.provider, origin.region, origin.failure_domain) for origin in origins
    }
    configured_sources: dict[str, tuple[str, str, str]] = {}
    for source in document.get("source_allowlist", []):
        if not isinstance(source, dict):
            raise DevnetError("coordinator source_allowlist contains a non-object")
        configured_sources[source.get("origin")] = (
            source.get("provider"),
            source.get("region"),
            source.get("control_cluster"),
        )
    if configured_sources != expected_sources:
        raise DevnetError("coordinator source_allowlist must exactly match authorized origin/provider/region/failure-domain labels")
    registered = document.get("registered_origins")
    if not isinstance(registered, list) or mutation_origin not in registered:
        raise DevnetError("coordinator registered_origins must include the exact advisory mutation origin")
    full_position_repair = loopback.get("full_position_repair") is True
    maximum_quarantine = document.get("max_quarantine_bytes")
    if full_position_repair:
        if maximum_quarantine != 475_588_608:
            raise DevnetError("full-position repair requires the exact 475,588,608-byte quarantine cap")
        if not isinstance(document.get("rate_limit_per_minute"), int) or document["rate_limit_per_minute"] < 1_024:
            raise DevnetError("full-position repair requires an explicit coordinator mutation rate cap of at least 1,024/minute")
        if not isinstance(document.get("restore_lifetime_seconds"), int) or document["restore_lifetime_seconds"] < FULL_POSITION_RESTORE_LIFETIME_SECONDS:
            raise DevnetError("full-position repair requires a restore lifetime of at least 900 seconds")
    elif not isinstance(maximum_quarantine, int) or not 1 <= maximum_quarantine <= 268_173_312:
        raise DevnetError("ordinary loopback fixtures must retain the conservative quarantine cap")
    return full_position_repair


def validate_config(path: Path) -> RuntimeConfig:
    raw_bytes = path.read_bytes()
    document = load_object(path, MAX_JSON_BYTES)
    base = path.parent.resolve()
    required_flags = {
        "schema": SCHEMA,
        "activation_scope": "OWNER_CONTROLLED_LOOPBACK_DEVNET",
        "production": False,
        "rewards": False,
        "production_custody": False,
        "availability_certificate_effect": False,
        "public_scanning": False,
        "default_upload": False,
    }
    for key, expected in required_flags.items():
        if document.get(key) != expected:
            raise DevnetError(f"{key} must be exactly {expected!r}")
    workspace = resolve_existing(document.get("workspace_root"), base, "workspace_root", file=False)
    run_root = resolve_output(document.get("run_root"), base, "run_root")
    evidence = resolve_output(document.get("evidence_path"), base, "evidence_path")
    child_of(run_root, workspace, "run_root")
    if evidence == run_root or evidence.is_relative_to(run_root):
        raise DevnetError("evidence_path must be outside disposable run_root")
    certificate = resolve_existing(document.get("tls_certificate"), base, "tls_certificate", file=True)
    private_key = resolve_existing(document.get("tls_private_key"), base, "tls_private_key", file=True)
    ca_certificate = resolve_existing(document.get("tls_ca_certificate"), base, "tls_ca_certificate", file=True)
    coordinator_url = canonical_loopback_origin(document.get("coordinator_url"), "coordinator_url", https=False)
    if urllib.parse.urlsplit(coordinator_url).scheme not in {"http", "https"}:
        raise DevnetError("coordinator_url must use loopback HTTP or HTTPS")
    coordinator_config = resolve_existing(document.get("coordinator_config"), base, "coordinator_config", file=True)
    mutation_origin = canonical_loopback_origin(document.get("mutation_origin"), "mutation_origin")
    consent_version = require_text(document.get("consent_version"), "consent_version", 64)
    evidence_seed_env = require_text(document.get("evidence_signing_seed_env"), "evidence_signing_seed_env")
    chain = document.get("chain_binding")
    if not isinstance(chain, dict) or set(chain) != {"chain_id", "genesis_hash", "artifact_id", "manifest_root"}:
        raise DevnetError("chain_binding must contain exactly four frozen identity hashes")
    chain_binding = {key: require_hex32(chain[key], f"chain_binding.{key}") for key in chain}
    store = document.get("artifact_store")
    if not isinstance(store, dict) or set(store) != {"store_root", "consensus_root", "quota_bytes"}:
        raise DevnetError("artifact_store must contain store_root, consensus_root, and quota_bytes")
    artifact_store = {
        "store_root": str(resolve_existing(store["store_root"], base, "artifact store root", file=False)),
        "consensus_root": str(resolve_existing(store["consensus_root"], base, "artifact consensus root", file=False)),
        "quota_bytes": int(store["quota_bytes"]),
    }
    if artifact_store["quota_bytes"] <= 0:
        raise DevnetError("artifact_store.quota_bytes must be positive")
    commands_doc = document.get("commands")
    if not isinstance(commands_doc, dict) or set(commands_doc) != {"artifact_service", "coordinator"}:
        raise DevnetError("commands must contain artifact_service and coordinator argv arrays")
    commands = Commands(parse_command(commands_doc["artifact_service"], "artifact_service command"), parse_command(commands_doc["coordinator"], "coordinator command"))
    manage_coordinator = document.get("manage_coordinator_process")
    if not isinstance(manage_coordinator, bool):
        raise DevnetError("manage_coordinator_process must be an explicit boolean")
    origins_doc = document.get("origins")
    if not isinstance(origins_doc, list) or not (2 <= len(origins_doc) <= 32):
        raise DevnetError("origins must contain 2..=32 owner-authorized entries")
    origins: list[OriginConfig] = []
    seen_origins: set[str] = set()
    seen_bundles: set[Path] = set()
    for index, item in enumerate(origins_doc):
        if not isinstance(item, dict) or set(item) != {"origin", "bundle_root", "operator_authorized", "provider", "region", "failure_domain"}:
            raise DevnetError(f"origins[{index}] has unknown or missing fields")
        if item["operator_authorized"] is not True:
            raise DevnetError(f"origins[{index}] is not explicitly operator-authorized")
        origin = canonical_loopback_origin(item["origin"], f"origins[{index}].origin")
        bundle = resolve_existing(item["bundle_root"], base, f"origins[{index}].bundle_root", file=False)
        if origin in seen_origins or bundle in seen_bundles:
            raise DevnetError("each origin and authorized bundle root must be distinct")
        seen_origins.add(origin)
        seen_bundles.add(bundle)
        origins.append(OriginConfig(origin, bundle, require_text(item["provider"], "provider"), require_text(item["region"], "region"), require_text(item["failure_domain"], "failure_domain")))
    full_position_repair = validate_coordinator_fixture_config(
        coordinator_config,
        ca_certificate,
        mutation_origin,
        origins,
    )
    restore_opt_in = document.get("browser_restore_upload_opt_in") is True
    corruption_probe = document.get("corruption_rejection_probe", True) is True
    import_doc = document.get("artifact_import")
    import_config: dict[str, Any] | None = None
    if import_doc is not None:
        if not isinstance(import_doc, dict) or import_doc.get("enabled") is not True:
            raise DevnetError("artifact_import must be absent or explicitly enabled")
        required = {"enabled", "quarantine_root", "index_path", "target_position", "coordinator_public_key", "replacement_root", "replacement_consensus_root", "replacement_quota_bytes", "report_path", "release_report_path"}
        if set(import_doc) != required:
            raise DevnetError("artifact_import has unknown or missing fields")
        target = int(import_doc["target_position"])
        quota = int(import_doc["replacement_quota_bytes"])
        if not 0 <= target < 12 or quota <= 0:
            raise DevnetError("artifact_import position or quota is invalid")
        import_config = {
            "quarantine_root": str(resolve_existing(import_doc["quarantine_root"], base, "quarantine_root", file=False)),
            "index_path": str(resolve_output(import_doc["index_path"], base, "signed import index path")),
            "target_position": target,
            "coordinator_public_key": require_hex32(import_doc["coordinator_public_key"], "coordinator_public_key"),
            "replacement_root": str(resolve_existing(import_doc["replacement_root"], base, "replacement_root", file=False)),
            "replacement_consensus_root": str(resolve_existing(import_doc["replacement_consensus_root"], base, "replacement_consensus_root", file=False)),
            "replacement_quota_bytes": quota,
            "report_path": str(resolve_output(import_doc["report_path"], base, "import report_path")),
            "release_report_path": str(resolve_output(import_doc["release_report_path"], base, "release report path")),
        }
        if not restore_opt_in:
            raise DevnetError("artifact_import requires explicit browser_restore_upload_opt_in")
    if full_position_repair != (import_config is not None):
        raise DevnetError("coordinator full_position_repair must be enabled exactly when artifact_import is enabled")
    return RuntimeConfig(path.resolve(), hashlib.sha256(raw_bytes).hexdigest(), workspace, run_root, evidence, certificate, private_key, ca_certificate, coordinator_url, coordinator_config, mutation_origin, consent_version, evidence_seed_env, chain_binding, artifact_store, tuple(origins), commands, manage_coordinator, restore_opt_in, corruption_probe, import_config)


def bundle_files(origin: OriginConfig, chain_binding: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_path = origin.bundle_root / ".well-known" / "noos" / "wwm-web-capacity-v1.json"
    inventory_path = origin.bundle_root / "inventory-v1.json"
    manifest_raw = manifest_path.read_bytes()
    inventory_raw = inventory_path.read_bytes()
    manifest = load_object(manifest_path, MAX_JSON_BYTES)
    inventory = load_object(inventory_path, MAX_INVENTORY_BYTES)
    if canonical_json(manifest) != manifest_raw or canonical_json(inventory) != inventory_raw:
        raise DevnetError(f"bundle JSON is not canonical at {origin.bundle_root}")
    if manifest.get("schema") != WEB_SCHEMA or manifest.get("record_kind") != "STATIC_HOST_MANIFEST" or manifest.get("participant_class") != "STATIC_HOST_SEEDER" or manifest.get("admission_class") != "StatelessReissueable":
        raise DevnetError(f"static host identity is invalid at {origin.bundle_root}")
    if manifest.get("canonical_origin") != origin.origin or manifest.get("chain_binding") != dict(chain_binding):
        raise DevnetError(f"static host origin or chain binding differs at {origin.bundle_root}")
    if manifest.get("production_custody") is not False or manifest.get("rewards") is not False:
        raise DevnetError("static bundle attempts custody or rewards authority")
    policy = manifest.get("transport_policy")
    if policy != {"cors_allow_origin": "*", "credentials": "omit", "redirects": "reject", "range_requests": True, "immutable_cache": True, "content_encoding": "identity"}:
        raise DevnetError("static bundle transport policy is not exact")
    binding = manifest.get("inventory")
    if not isinstance(binding, dict) or binding.get("url") != f"{origin.origin}/inventory-v1.json" or binding.get("bytes") != len(inventory_raw) or binding.get("sha256") != hashlib.sha256(inventory_raw).hexdigest():
        raise DevnetError("inventory byte length, URL, or SHA-256 differs from signed binding")
    if inventory.get("schema") != WEB_SCHEMA or inventory.get("record_kind") != "STATIC_INVENTORY" or inventory.get("canonical_origin") != origin.origin or inventory.get("chain_binding") != dict(chain_binding) or inventory.get("inventory_root") != binding.get("inventory_root"):
        raise DevnetError("inventory identity differs from signed host binding")
    rows = inventory.get("rows")
    if not isinstance(rows, list) or not rows or len(rows) > 5_448:
        raise DevnetError("inventory must contain 1..=5,448 rows")
    prior: tuple[int, int] | None = None
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"stripe", "position", "bytes", "transport_sha256", "protocol_share_digest", "probe_root", "url"}:
            raise DevnetError("inventory row shape is invalid")
        coordinate = (row["stripe"], row["position"])
        if not isinstance(coordinate[0], int) or not isinstance(coordinate[1], int) or not 0 <= coordinate[0] < 454 or not 0 <= coordinate[1] < 12 or row["bytes"] != SHARE_BYTES or (prior is not None and coordinate <= prior):
            raise DevnetError("inventory rows must be ordered unique canonical coordinates")
        prior = coordinate
        for key in ("transport_sha256", "protocol_share_digest", "probe_root"):
            require_hex32(row.get(key), f"inventory row {key}")
        expected_url = f"{origin.origin}/shares/{coordinate[0]:06d}/{coordinate[1]:02d}.share"
        if row.get("url") != expected_url:
            raise DevnetError("inventory share URL differs from canonical origin/coordinate")
        share_path = origin.bundle_root / "shares" / f"{coordinate[0]:06d}" / f"{coordinate[1]:02d}.share"
        if not share_path.is_file() or share_path.stat().st_size != SHARE_BYTES:
            raise DevnetError(f"share length differs at {share_path}")
        digest = hashlib.sha256(share_path.read_bytes()).hexdigest()
        if digest != row["transport_sha256"]:
            raise DevnetError(f"share transport SHA-256 differs at {share_path}")
    signature = manifest.get("signature")
    if not isinstance(signature, dict) or signature.get("suite") != "Ed25519" or signature.get("domain") != "NOOS/SIG/WWM-WEB-HOST-MANIFEST/V1" or signature.get("public_key") != manifest.get("host_signing_key"):
        raise DevnetError("host manifest signature envelope is invalid")
    require_hex32(signature.get("public_key"), "host public key")
    if not isinstance(signature.get("signature"), str) or len(signature["signature"]) != 128:
        raise DevnetError("host signature must be hex64")
    return manifest, inventory


def run_command(command: Sequence[str], *, timeout: float = 120.0) -> str:
    process = subprocess.run(list(command), capture_output=True, timeout=timeout, check=False)
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace").strip() or process.stdout.decode("utf-8", "replace").strip()
        raise DevnetError(f"command failed ({process.returncode}): {' '.join(command)}: {detail}")
    return process.stdout.decode("utf-8", "replace").strip()


def run_json(command: Sequence[str], *, env: Mapping[str, str] | None = None, timeout: float = 120.0) -> dict[str, Any]:
    process = subprocess.run(list(command), capture_output=True, env=None if env is None else dict(env), timeout=timeout, check=False)
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace").strip() or process.stdout.decode("utf-8", "replace").strip()
        raise DevnetError(f"command failed ({process.returncode}): {' '.join(command)}: {detail}")
    try:
        value = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DevnetError(f"command did not emit one JSON object: {' '.join(command)}") from error
    if not isinstance(value, dict):
        raise DevnetError("command JSON output was not an object")
    return value


def verify_bundles(config: RuntimeConfig) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for origin in config.origins:
        _manifest, inventory = bundle_files(origin, config.chain_binding)
        command = [*config.commands.artifact_service, "verify-web-bundle", "--store-root", config.artifact_store["store_root"], "--consensus-root", config.artifact_store["consensus_root"], "--quota-bytes", str(config.artifact_store["quota_bytes"]), "--bundle-root", str(origin.bundle_root), "--origin", origin.origin, "--chain-id", config.chain_binding["chain_id"], "--genesis-hash", config.chain_binding["genesis_hash"]]
        report = run_json(command, timeout=600)
        if report.get("signature_verified") is not True or report.get("noos_da_verified") is not True or report.get("production_custody") is not False or report.get("rewards") is not False:
            raise DevnetError("artifact-service did not canonically verify the static bundle")
        reports.append({"origin": origin.origin, "provider": origin.provider, "region": origin.region, "failure_domain": origin.failure_domain, "inventory_root": inventory["inventory_root"], "verified_rows": len(inventory["rows"]), "artifact_service_report": report})
    return reports


class BundleHandler(http.server.BaseHTTPRequestHandler):
    server_version = "noos-loopback-static/1"

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(True)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(False)

    def _serve(self, head: bool) -> None:
        server = self.server
        assert isinstance(server, BundleServer)
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.query or parsed.fragment or not parsed.path.startswith("/"):
            self.send_error(404)
            return
        allowed = server.allowed.get(parsed.path)
        if allowed is None:
            self.send_error(404)
            return
        path, kind = allowed
        body = path.read_bytes()
        range_header = self.headers.get("Range")
        if range_header is not None:
            if kind != "share" or not range_header.startswith("bytes=") or "," in range_header:
                self.send_error(416)
                return
            parts = range_header[6:].split("-", 1)
            try:
                start = int(parts[0]); end = int(parts[1])
            except (ValueError, IndexError):
                self.send_error(416)
                return
            if start < 0 or end < start or start >= len(body):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(body)}")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Encoding", "identity")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            end = min(end, len(body) - 1)
            selected = body[start : end + 1]
            self.send_response(206)
            self._headers(kind, len(selected))
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(body)}")
            self.end_headers()
            if not head:
                self.wfile.write(selected)
            return
        self.send_response(200)
        self._headers(kind, len(body))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _headers(self, kind: str, length: int) -> None:
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Type", "application/json" if kind in {"manifest", "inventory"} else "application/octet-stream" if kind == "share" else "text/plain; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Encoding", "identity")
        if kind == "share":
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Cache-Control", IMMUTABLE_CACHE)
        elif kind in {"manifest", "inventory"}:
            self.send_header("Cache-Control", REVALIDATE_CACHE)
        else:
            self.send_header("Cache-Control", IMMUTABLE_CACHE)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class BundleServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, origin: OriginConfig, inventory: Mapping[str, Any], certificate: Path, private_key: Path):
        parsed = urllib.parse.urlsplit(origin.origin)
        host = parsed.hostname or "127.0.0.1"
        super().__init__((host, parsed.port or 0), BundleHandler)
        self.allowed: dict[str, tuple[Path, str]] = {
            "/.well-known/noos/wwm-web-capacity-v1.json": (origin.bundle_root / ".well-known" / "noos" / "wwm-web-capacity-v1.json", "manifest"),
            "/inventory-v1.json": (origin.bundle_root / "inventory-v1.json", "inventory"),
            "/LICENSE.txt": (origin.bundle_root / "LICENSE.txt", "legal"),
            "/NOTICE.txt": (origin.bundle_root / "NOTICE.txt", "legal"),
        }
        for row in inventory["rows"]:
            path = urllib.parse.urlsplit(row["url"]).path
            self.allowed[path] = (origin.bundle_root / path.lstrip("/"), "share")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate), str(private_key))
        self.socket = context.wrap_socket(self.socket, server_side=True)


class RunningOrigins:
    def __init__(self, config: RuntimeConfig, inventories: Sequence[Mapping[str, Any]]):
        self.servers = [BundleServer(origin, inventory, config.certificate, config.private_key) for origin, inventory in zip(config.origins, inventories, strict=True)]
        self.threads: list[threading.Thread] = []

    def __enter__(self) -> "RunningOrigins":
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start(); self.threads.append(thread)
        return self

    def __exit__(self, *_args: Any) -> None:
        for server in self.servers:
            server.shutdown(); server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)

class RunningCoordinator:
    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.process: subprocess.Popen[bytes] | None = None
        self.log: Any = None

    def __enter__(self) -> "RunningCoordinator":
        if not self.config.manage_coordinator_process:
            return self
        log_path = self.config.run_root / "coordinator.log"
        self.log = log_path.open("xb")
        self.process = subprocess.Popen(
            [*self.config.commands.coordinator, "--config", str(self.config.coordinator_config)],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self._stop()
                raise DevnetError(f"managed coordinator exited before readiness; see {log_path}")
            try:
                coordinator_json(self.config, "GET", "/api/wwm-web-capacity/v1/config")
                return self
            except DevnetError:
                time.sleep(0.1)
        self._stop()
        raise DevnetError(f"managed coordinator did not become ready; see {log_path}")

    def __exit__(self, *_args: Any) -> None:
        self._stop()

    def _stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log is not None and not self.log.closed:
            self.log.close()


def ssl_context(config: RuntimeConfig) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(config.ca_certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise DevnetError("redirect response is forbidden")


def http_request(config: RuntimeConfig, method: str, url: str, *, json_body: Mapping[str, Any] | None = None, raw_body: bytes | None = None, headers: Mapping[str, str] | None = None, expected: set[int] = {200}, maximum: int = MAX_INVENTORY_BYTES) -> tuple[int, Mapping[str, str], bytes]:
    body = raw_body if raw_body is not None else (canonical_json(json_body) if json_body is not None else None)
    request_headers = dict(headers or {})
    if json_body is not None:
        request_headers["Content-Type"] = MEDIA_TYPE
    request = urllib.request.Request(url, data=body, method=method, headers=request_headers)
    opener = urllib.request.build_opener(RejectRedirects(), urllib.request.HTTPSHandler(context=ssl_context(config)))
    try:
        response = opener.open(request, timeout=30)
        status = response.status; final_url = response.geturl(); response_headers = {key.lower(): value for key, value in response.headers.items()}; payload = response.read(maximum + 1)
    except urllib.error.HTTPError as error:
        status = error.code; final_url = error.geturl(); response_headers = {key.lower(): value for key, value in error.headers.items()}; payload = error.read(maximum + 1)
    except (OSError, urllib.error.URLError) as error:
        raise DevnetError(f"HTTP {method} failed for {url}: {error}") from error
    if final_url != url:
        raise DevnetError(f"HTTP response redirected from {url} to {final_url}")
    if len(payload) > maximum:
        raise DevnetError(f"HTTP {method} {url} response exceeded its {maximum}-byte bound")
    if status not in expected:
        raise DevnetError(f"HTTP {method} {url} returned {status}: {payload[:512]!r}")
    return status, response_headers, payload


def decode_json(body: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DevnetError(f"{label} response is not JSON") from error
    if not isinstance(value, dict):
        raise DevnetError(f"{label} response must be an object")
    return value


def validate_share_transport(config: RuntimeConfig, row: Mapping[str, Any]) -> tuple[bytes, int]:
    url = row["url"]
    status, headers, body = http_request(config, "GET", url, expected={200}, maximum=SHARE_BYTES)
    required = {"access-control-allow-origin": "*", "content-encoding": "identity", "accept-ranges": "bytes", "content-length": str(SHARE_BYTES), "cache-control": IMMUTABLE_CACHE}
    if status != 200 or any(headers.get(key) != value for key, value in required.items()) or len(body) != SHARE_BYTES or hashlib.sha256(body).hexdigest() != row["transport_sha256"]:
        raise DevnetError("full share transport headers, length, or SHA-256 are invalid")
    _, head_headers, head_body = http_request(config, "HEAD", url, expected={200}, maximum=1)
    if head_body or head_headers.get("content-length") != str(SHARE_BYTES):
        raise DevnetError("share HEAD semantics are invalid")
    middle = SHARE_BYTES // 2
    _, range_headers, ranged = http_request(config, "GET", url, headers={"Range": f"bytes={middle}-{middle + 1023}"}, expected={206}, maximum=1024)
    if ranged != body[middle : middle + 1024] or range_headers.get("content-range") != f"bytes {middle}-{middle + 1023}/{SHARE_BYTES}" or range_headers.get("content-length") != "1024":
        raise DevnetError("share Range semantics are invalid")
    _, invalid_headers, invalid_body = http_request(config, "GET", url, headers={"Range": f"bytes={SHARE_BYTES}-{SHARE_BYTES}"}, expected={416}, maximum=1)
    if invalid_body or invalid_headers.get("content-range") != f"bytes */{SHARE_BYTES}":
        raise DevnetError("share 416 semantics are invalid")
    return body, 4


def coordinator_json(config: RuntimeConfig, method: str, path: str, body: Mapping[str, Any] | None = None, *, token: str | None = None, expected: set[int] = {200}, maximum: int = MAX_JSON_BYTES) -> dict[str, Any]:
    headers = {"Origin": config.mutation_origin}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    _, _, raw = http_request(config, method, config.coordinator_url + path, json_body=body, headers=headers, expected=expected, maximum=maximum)
    return decode_json(raw, path)


def queue_restore(config: RuntimeConfig, session: Mapping[str, Any], row: Mapping[str, Any], source_origin: str, suffix: str, *, lifetime_seconds: int = FULL_POSITION_RESTORE_LIFETIME_SECONDS) -> dict[str, Any]:
    if not 1 <= lifetime_seconds <= FULL_POSITION_RESTORE_LIFETIME_SECONDS:
        raise DevnetError("restore task lifetime must be within 1..=900 seconds")
    request_path = config.run_root / f"queue-restore-{suffix}.json"
    report_path = config.run_root / f"queue-restore-{suffix}-report.json"
    request = {"schema": WEB_SCHEMA, "record_kind": "QUEUE_RESTORE_REQUEST", "session_token": session["session_token"], "canonical_origin": config.mutation_origin, "source_origin": source_origin, "expires_at": int(time.time()) + lifetime_seconds, "coordinate": {key: row[key] for key in ("stripe", "position", "bytes", "transport_sha256", "protocol_share_digest", "probe_root", "url")}}
    request_path.write_bytes(canonical_json(request))
    command = [*config.commands.coordinator, "queue-restore", "--config", str(config.coordinator_config), "--request", str(request_path), "--report", str(report_path)]
    run_command(command)
    report = load_object(report_path, MAX_JSON_BYTES)
    if report.get("production_custody") is not False or report.get("rewards") is not False or report.get("insert_once") is not True:
        raise DevnetError("queue-restore report is promoting, rewarded, or mutable")
    return report


def invoke_import(config: RuntimeConfig, coordinator_key: str, expected_stripes: int) -> dict[str, Any] | None:
    item = config.import_config
    if item is None:
        return None
    index_path = Path(item["index_path"])
    report_path = Path(item["report_path"])
    for label, path in (("signed import index", index_path), ("artifact import report", report_path)):
        if path.exists():
            raise DevnetError(f"{label} is create-new and already exists: {path}")
    run_command(
        [
            *config.commands.coordinator,
            "export-restored-position",
            "--config",
            str(config.coordinator_config),
            "--position",
            str(item["target_position"]),
            "--expires-at",
            str(int(time.time()) + 300),
            "--output",
            str(index_path),
        ]
    )
    index = load_object(index_path, 2 * 1024 * 1024)
    signature = index.get("signature")
    if (
        index.get("schema") != WEB_SCHEMA
        or index.get("record_kind") != "WEB_RESTORED_POSITION_IMPORT_INDEX"
        or index.get("coordinator_public_key") != coordinator_key
        or index.get("chain_binding") != config.chain_binding
        or index.get("target_position") != item["target_position"]
        or not isinstance(index.get("rows"), list)
        or len(index["rows"]) != expected_stripes
        or not isinstance(signature, dict)
        or signature.get("suite") != "Ed25519"
        or signature.get("domain") != "NOOS/SIG/WWM-WEB-RESTORE-IMPORT-INDEX/V1"
        or signature.get("public_key") != coordinator_key
    ):
        raise DevnetError("coordinator emitted an invalid, incomplete, or unpinned restored-position index")
    chain = config.chain_binding
    store = config.artifact_store
    command = [*config.commands.artifact_service, "import-web-restored-position", "--store-root", store["store_root"], "--consensus-root", store["consensus_root"], "--quota-bytes", str(store["quota_bytes"]), "--quarantine-root", item["quarantine_root"], "--import-index", str(index_path), "--position", str(item["target_position"]), "--coordinator-public-key", item["coordinator_public_key"], "--chain-id", chain["chain_id"], "--genesis-hash", chain["genesis_hash"], "--artifact-id", chain["artifact_id"], "--manifest-root", chain["manifest_root"], "--replacement-root", item["replacement_root"], "--replacement-consensus-root", item["replacement_consensus_root"], "--replacement-quota-bytes", str(item["replacement_quota_bytes"]), "--report", str(report_path)]
    run_json(command, timeout=900)
    report = load_object(report_path, MAX_JSON_BYTES)
    for key in ("production_custody", "availability_certificate_effect", "rewards"):
        if report.get(key) is not False:
            raise DevnetError(f"artifact import report {key} must remain false")
    if report.get("insert_once") is not True:
        raise DevnetError("artifact import report must be insert-once")
    release_path = Path(item["release_report_path"])
    if release_path.exists():
        raise DevnetError(f"release report is create-new and already exists: {release_path}")
    run_command(
        [
            *config.commands.coordinator,
            "release-restored-position",
            "--config",
            str(config.coordinator_config),
            "--index",
            str(index_path),
            "--import-evidence",
            str(report_path),
            "--report",
            str(release_path),
        ]
    )
    release = load_object(release_path, MAX_JSON_BYTES)
    if (
        release.get("artifact_id") != config.chain_binding["artifact_id"]
        or release.get("manifest_root") != config.chain_binding["manifest_root"]
        or release.get("target_position") != item["target_position"]
        or release.get("released_share_count") != expected_stripes
        or release.get("released_bytes") != expected_stripes * SHARE_BYTES
        or release.get("production_custody") is not False
        or release.get("availability_certificate_effect") is not False
        or release.get("rewards") is not False
        or release.get("insert_once") is not True
    ):
        raise DevnetError("post-import quarantine release report is incomplete, unbound, or promoting")
    return {"import": report, "release": release}


def create_workspace(config: RuntimeConfig) -> None:
    try:
        config.run_root.mkdir(parents=False)
    except FileExistsError as error:
        raise DevnetError(f"run_root is create-new and already exists: {config.run_root}") from error
    marker = {"schema": MARKER_SCHEMA, "config_sha256": config.config_digest, "run_root": str(config.run_root)}
    (config.run_root / ".wwm-web-capacity-devnet-workspace.json").write_bytes(canonical_json(marker))


def cleanup(config: RuntimeConfig) -> dict[str, Any]:
    if not config.run_root.exists():
        return {"cleaned": False, "reason": "ABSENT", "run_root": str(config.run_root)}
    child_of(config.run_root.resolve(), config.workspace_root.resolve(), "run_root")
    marker_path = config.run_root / ".wwm-web-capacity-devnet-workspace.json"
    marker = load_object(marker_path, MAX_JSON_BYTES)
    if marker != {"schema": MARKER_SCHEMA, "config_sha256": config.config_digest, "run_root": str(config.run_root)}:
        raise DevnetError("refusing cleanup: disposable workspace marker differs")
    if config.run_root.is_symlink():
        raise DevnetError("refusing cleanup of a symlinked run_root")
    shutil.rmtree(config.run_root)
    return {"cleaned": True, "run_root": str(config.run_root), "bounded_to_workspace": True}


def sign_evidence(config: RuntimeConfig, unsigned: dict[str, Any]) -> dict[str, Any]:
    value = os.environ.get(config.evidence_seed_env)
    if value is None:
        raise DevnetError(f"evidence signing seed environment variable is absent: {config.evidence_seed_env}")
    try:
        seed = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value, validate=True)
    except ValueError as error:
        raise DevnetError("evidence signing seed must be raw hex32 or canonical base64") from error
    if len(seed) != 32:
        raise DevnetError("evidence signing seed must decode to 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    signature = key.sign(EVIDENCE_DOMAIN + canonical_json(unsigned))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    result = dict(unsigned)
    result["signature"] = {"suite": "Ed25519", "domain": EVIDENCE_DOMAIN[:-1].decode(), "public_key": public.hex(), "signature": signature.hex()}
    return result


def write_new(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(body); output.flush(); os.fsync(output.fileno())
    except FileExistsError as error:
        raise DevnetError(f"refusing to overwrite create-new evidence: {path}") from error


def run_smoke(config: RuntimeConfig, verification: list[dict[str, Any]]) -> dict[str, Any]:
    create_workspace(config)
    inventories = [bundle_files(origin, config.chain_binding)[1] for origin in config.origins]
    request_count = 0
    with RunningOrigins(config, inventories), RunningCoordinator(config):
        coordinator = coordinator_json(config, "GET", "/api/wwm-web-capacity/v1/config")
        request_count += 1
        coordinator_key = require_hex32(coordinator.get("coordinator_key"), "coordinator key")
        if coordinator.get("chain_binding") != config.chain_binding or coordinator.get("production_custody") is not False or coordinator.get("rewards") is not False:
            raise DevnetError("coordinator config is promoting, rewarded, or chain-unbound")
        for origin in config.origins:
            response = coordinator_json(config, "POST", "/api/wwm-web-capacity/v1/hosts", {"schema": WEB_SCHEMA, "record_kind": "HOST_REGISTRATION_REQUEST", "canonical_origin": origin.origin}, expected={201})
            request_count += 1
            if response.get("canonical_origin") != origin.origin or response.get("production_custody") is not False or response.get("rewards") is not False:
                raise DevnetError("coordinator host registration response is invalid")
        geometry = coordinator.get("geometry")
        if not isinstance(geometry, dict):
            raise DevnetError("coordinator config lacks exact artifact geometry")
        stripe_count = geometry.get("stripes")
        if (
            not isinstance(stripe_count, int)
            or not 1 <= stripe_count <= 454
            or geometry.get("share_bytes") != SHARE_BYTES
            or geometry.get("positions") != 12
        ):
            raise DevnetError("coordinator geometry differs from the bounded canonical shape")
        expected_rows = {
            (origin.origin, row["stripe"], row["position"]): row
            for origin, inventory in zip(config.origins, inventories, strict=True)
            for row in inventory["rows"]
        }
        authorized_origins = {origin.origin for origin in config.origins}
        upload_policy = {"enabled": config.restore_opt_in, "daily_egress_bytes": SHARE_BYTES * 256 if config.restore_opt_in else 0}
        session_last_active: dict[str, float] = {}

        def open_advisory_session() -> tuple[dict[str, Any], list[dict[str, Any]]]:
            nonlocal request_count
            offer = {"schema": WEB_SCHEMA, "record_kind": "OFFER_REQUEST", "canonical_origin": config.mutation_origin, "consent_version": config.consent_version, "quota_shares": 256, "effective_bytes": SHARE_BYTES * 256, "storage_class": "OPFS", "upload_policy": upload_policy, "page_active": True}
            browser_session = coordinator_json(config, "POST", "/api/wwm-web-capacity/v1/offers", offer, expected={201})
            request_count += 1
            if browser_session.get("participant_class") != "BROWSER_ADVISORY_CACHE" or browser_session.get("admission_class") != "ChorusAdvisory" or browser_session.get("production_custody") is not False or browser_session.get("rewards") is not False:
                raise DevnetError("browser session is not advisory/non-promoting")
            heartbeat = coordinator_json(config, "POST", "/api/wwm-web-capacity/v1/heartbeat", {"schema": WEB_SCHEMA, "record_kind": "HEARTBEAT_REQUEST", "session_token": browser_session["session_token"], "canonical_origin": config.mutation_origin, "page_active": True, "stored_coordinate_digests": [], "available_bytes": SHARE_BYTES * 256}, maximum=MAX_ASSIGNMENT_BYTES)
            request_count += 1
            session_last_active[browser_session["session_token"]] = time.monotonic()
            assignment = heartbeat.get("assignment")
            if not isinstance(assignment, dict) or not assignment.get("rows") or len(assignment["rows"]) > 256:
                raise DevnetError("coordinator did not return a bounded signed assignment")
            assignment_signature = assignment.get("signature")
            if not isinstance(assignment_signature, dict) or assignment_signature.get("suite") != "Ed25519" or assignment_signature.get("domain") != "NOOS/SIG/WWM-WEB-ASSIGNMENT/V1" or assignment_signature.get("public_key") != coordinator_key or not isinstance(assignment_signature.get("signature"), str) or len(assignment_signature["signature"]) != 128:
                raise DevnetError("assignment is not signed by the pinned coordinator key")
            assigned_rows = assignment["rows"]
            for row in assigned_rows:
                expected = expected_rows.get((row.get("source_origin"), row.get("stripe"), row.get("position")))
                if expected is None or any(row.get(key) != expected.get(key) for key in ("bytes", "transport_sha256", "protocol_share_digest", "probe_root", "url")):
                    raise DevnetError("assignment row differs from the verified authorized inventory")
            return browser_session, assigned_rows

        target_position = config.import_config["target_position"] if config.import_config is not None else None
        if target_position is not None:
            available = {
                row["stripe"]
                for inventory in inventories
                for row in inventory["rows"]
                if row["position"] == target_position
            }
            if available != set(range(stripe_count)):
                raise DevnetError("authorized static bundles do not cover every stripe of the requested import position")
        assigned_by_coordinate: dict[tuple[int, int], tuple[dict[str, Any], dict[str, Any]]] = {}
        all_assignment_origins: set[str] = set()
        session_limit = 8 if target_position is not None else 1
        for _ in range(session_limit):
            session, rows = open_advisory_session()
            all_assignment_origins.update(row["source_origin"] for row in rows)
            for row in rows:
                coordinate = (row["stripe"], row["position"])
                if target_position is None or row["position"] == target_position:
                    assigned_by_coordinate.setdefault(coordinate, (row, session))
            if target_position is None or len(assigned_by_coordinate) == stripe_count:
                break
        if len(all_assignment_origins) < 2 or not all_assignment_origins.issubset(authorized_origins):
            raise DevnetError("assignments did not exercise at least two authorized HTTPS origins")
        if target_position is not None and set(assigned_by_coordinate) != {
            (stripe, target_position) for stripe in range(stripe_count)
        }:
            raise DevnetError("bounded advisory sessions did not receive one complete import position")
        restore_targets = (
            [assigned_by_coordinate[key] for key in sorted(assigned_by_coordinate)]
            if target_position is not None
            else [next(iter(assigned_by_coordinate.values()))]
        )
        corruption_rejected = None
        restore_receipt = None
        restored_share_count = 0
        if config.restore_opt_in and config.corruption_probe:
            corrupt_row, corrupt_session = restore_targets[0]
            share, transport_requests = validate_share_transport(config, corrupt_row); request_count += transport_requests
            quarantine_before = sum(1 for path in Path(config.import_config["quarantine_root"]).rglob("*") if path.is_file()) if config.import_config is not None else None
            corrupt_queued = queue_restore(config, corrupt_session, corrupt_row, corrupt_row["source_origin"], "corrupt", lifetime_seconds=FULL_POSITION_RESTORE_LIFETIME_SECONDS - 1)
            corrupt_task = corrupt_queued["task"]
            corrupt = bytearray(share); corrupt[0] ^= 1
            headers = {"Origin": config.mutation_origin, "Authorization": f"Bearer {corrupt_session['session_token']}", "Content-Type": "application/octet-stream", "Content-Length": str(len(corrupt))}
            status, _, _ = http_request(config, "PUT", config.coordinator_url + f"/api/wwm-web-capacity/v1/restores/{corrupt_task['task_id']}", raw_body=bytes(corrupt), headers=headers, expected={400, 409, 422}, maximum=MAX_JSON_BYTES)
            request_count += 1
            corruption_rejected = status in {400, 409, 422}
            if quarantine_before is not None:
                quarantine_after = sum(1 for path in Path(config.import_config["quarantine_root"]).rglob("*") if path.is_file())
                corruption_rejected = corruption_rejected and quarantine_after == quarantine_before
            if not corruption_rejected:
                raise DevnetError("corrupt restore was not rejected without a quarantine write")
        for row, row_session in restore_targets:
            share, transport_requests = validate_share_transport(config, row); request_count += transport_requests
            if not config.restore_opt_in:
                break
            token = row_session["session_token"]
            if time.monotonic() - session_last_active[token] > 60:
                active = coordinator_json(config, "POST", "/api/wwm-web-capacity/v1/heartbeat", {"schema": WEB_SCHEMA, "record_kind": "HEARTBEAT_REQUEST", "session_token": token, "canonical_origin": config.mutation_origin, "page_active": True, "stored_coordinate_digests": [], "available_bytes": 0}, maximum=MAX_ASSIGNMENT_BYTES)
                request_count += 1
                if active.get("record_kind") != "HEARTBEAT_RESPONSE":
                    raise DevnetError("active-page heartbeat failed during bounded restore")
                session_last_active[token] = time.monotonic()
            suffix = f"{row['stripe']}-{row['position']}"
            queued = queue_restore(config, row_session, row, row["source_origin"], suffix)
            task = queued.get("task")
            task_signature = task.get("signature") if isinstance(task, dict) else None
            if not isinstance(task, dict) or task.get("coordinate") != {key: row[key] for key in ("stripe", "position", "bytes", "transport_sha256", "protocol_share_digest", "probe_root", "url")} or not isinstance(task_signature, dict) or task_signature.get("suite") != "Ed25519" or task_signature.get("domain") != "NOOS/SIG/WWM-WEB-RESTORE-TASK/V1" or task_signature.get("public_key") != coordinator_key:
                raise DevnetError("queue-restore report lacks an exact coordinator-signed task")
            headers = {"Origin": config.mutation_origin, "Authorization": f"Bearer {row_session['session_token']}", "Content-Type": "application/octet-stream", "Content-Length": str(len(share))}
            _, _, restore_raw = http_request(config, "PUT", config.coordinator_url + f"/api/wwm-web-capacity/v1/restores/{task['task_id']}", raw_body=share, headers=headers, expected={201}, maximum=MAX_JSON_BYTES)
            request_count += 1
            restore_receipt = decode_json(restore_raw, "restore")
            if restore_receipt.get("canonical_verified") is not True or restore_receipt.get("bytes") != SHARE_BYTES:
                raise DevnetError("restore did not enter quarantine through canonical verification")
            restored_share_count += 1
        import_report = invoke_import(config, coordinator_key, stripe_count)
    unsigned = {
        "schema": EVIDENCE_SCHEMA,
        "evidence_class": "OWNER_CONTROLLED_LOOPBACK_DEVNET_SMOKE",
        "run_id": hashlib.sha256(f"{config.config_digest}:{time.time_ns()}".encode()).hexdigest(),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "chain_binding": config.chain_binding,
        "origin_count": len(config.origins),
        "origins": verification,
        "measured_http_request_count": request_count,
        "geometry": geometry,
        "assigned_origin_count": len(all_assignment_origins),
        "restored_share_count": restored_share_count,
        "synthetic_workload_distribution": False,
        "real_public_pilot": False,
        "production_custody": False,
        "availability_certificate_effect": False,
        "rewards": False,
        "coordinator_process_managed": config.manage_coordinator_process,
        "promotion_authorized": False,
        "browser_upload_default": False,
        "browser_restore_upload_explicitly_opted_in": config.restore_opt_in,
        "assignment_observed": True,
        "restore_receipt": restore_receipt,
        "corruption_rejected": corruption_rejected,
        "artifact_import_report": import_report,
        "artifact_import_exercised": import_report is not None,
        "insert_once": True,
    }
    evidence = sign_evidence(config, unsigned)
    write_new(config.evidence_path, canonical_json(evidence))
    return evidence


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--cleanup", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        config = validate_config(args.config.resolve(strict=True))
        if args.cleanup:
            result = cleanup(config)
        else:
            verification = verify_bundles(config)
            if args.validate_only:
                result = {"schema": SCHEMA, "mode": "VALIDATE_ONLY", "origin_count": len(config.origins), "origins": verification, "production_custody": False, "availability_certificate_effect": False, "rewards": False, "promotion_authorized": False, "harness_outputs_created": False, "services_started": False}
            else:
                result = run_smoke(config, verification)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (DevnetError, OSError, subprocess.TimeoutExpired, ValueError) as error:
        print(json.dumps({"error": str(error), "production_custody": False, "rewards": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
