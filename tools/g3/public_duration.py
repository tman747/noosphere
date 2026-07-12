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
import importlib.metadata
import io
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
MAX_OTS_PROOF_BYTES = 1024 * 1024
MAX_BITCOIN_TIP_AGE_SECONDS = 6 * 60 * 60
OTS_CLIENT_VERSION = "0.7.2"
OTS_RUNTIME_VERSIONS = {
    "opentimestamps-client": OTS_CLIENT_VERSION,
    "opentimestamps": "0.4.5",
    "python-bitcoinlib": "0.12.2",
    "pycryptodomex": "3.23.0",
    "GitPython": "3.1.50",
    "gitdb": "4.0.12",
    "smmap": "5.0.3",
    "PySocks": "1.7.1",
    "appdirs": "1.4.4",
}
BITCOIN_MAINNET_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
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


def manifest_signature_payload_hash(manifest: dict[str, Any]) -> str:
    return sha256_bytes(canonical(unsigned_manifest(manifest)))


def manifest_hash(manifest: dict[str, Any]) -> str:
    """Bind checkpoints to the exact finalized manifest, including its signer set."""
    return sha256_bytes(canonical(manifest))


def checkpoint_payload(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in checkpoint.items() if key not in {"signatures", "external_timestamp_receipt"}}


def payload_hash(checkpoint: dict[str, Any]) -> str:
    return sha256_bytes(canonical(checkpoint_payload(checkpoint)))


def checkpoint_hash(checkpoint: dict[str, Any]) -> str:
    return sha256_bytes(canonical(checkpoint))


def signed_checkpoint(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """The noncircular object timestamped after all operator signatures exist."""
    return {key: value for key, value in checkpoint.items() if key != "external_timestamp_receipt"}


def timestamp_commitment(checkpoint: dict[str, Any]) -> str:
    return sha256_bytes(canonical(signed_checkpoint(checkpoint)))


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


def require_opentimestamps() -> tuple[Any, Any, Any, Any]:
    try:
        for distribution, required_version in OTS_RUNTIME_VERSIONS.items():
            version = importlib.metadata.version(distribution)
            if version != required_version:
                raise EvidenceError(
                    f"pinned OpenTimestamps runtime requires {distribution}=={required_version}; found {version}"
                )
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import DeserializationError, StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise EvidenceError(
            f"complete pinned OpenTimestamps client {OTS_CLIENT_VERSION} runtime is required for receipt verification"
        ) from exc
    return DetachedTimestampFile, StreamDeserializationContext, OpSHA256, (BitcoinBlockHeaderAttestation, DeserializationError)


def deserialize_ots_proof(proof_base64: Any, commitment_sha256: str, *, require_confirmed: bool = True) -> tuple[Any, Any]:
    if not isinstance(proof_base64, str):
        raise EvidenceError("OpenTimestamps proof must be canonical base64")
    try:
        raw = base64.b64decode(proof_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError("OpenTimestamps proof must be canonical base64") from exc
    if not raw or len(raw) > MAX_OTS_PROOF_BYTES or base64.b64encode(raw).decode("ascii") != proof_base64:
        raise EvidenceError("OpenTimestamps proof size/base64 encoding is invalid")
    DetachedTimestampFile, StreamDeserializationContext, OpSHA256, classes = require_opentimestamps()
    BitcoinBlockHeaderAttestation, DeserializationError = classes
    try:
        detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(raw)))
    except Exception as exc:
        if isinstance(exc, (DeserializationError, ValueError, EOFError)):
            raise EvidenceError("malformed OpenTimestamps proof") from exc
        raise
    if detached.file_hash_op.__class__ is not OpSHA256 or detached.file_digest.hex() != commitment_sha256:
        raise EvidenceError("OpenTimestamps proof is not bound to the exact signed checkpoint commitment")
    attestations = [
        (message, attestation)
        for message, attestation in detached.timestamp.all_attestations()
        if attestation.__class__ is BitcoinBlockHeaderAttestation
    ]
    if require_confirmed and not attestations:
        raise EvidenceError("OpenTimestamps proof is unconfirmed: no Bitcoin block attestation")
    return detached, attestations


class BitcoinRPC:
    """Minimal Bitcoin Core JSON-RPC reader; the verifier controls this trust endpoint."""

    def __init__(self, url: str):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise EvidenceError("Bitcoin RPC URL must be an http(s) Bitcoin Core endpoint")
        if parsed.password is not None and parsed.username is None:
            raise EvidenceError("Bitcoin RPC password requires a username")
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        self.url = urllib.parse.urlunsplit((parsed.scheme, f"{host}:{parsed.port or (443 if parsed.scheme == 'https' else 8332)}", "/", "", ""))
        self.authorization = None
        if parsed.username is not None:
            credentials = f"{urllib.parse.unquote(parsed.username)}:{urllib.parse.unquote(parsed.password or '')}"
            self.authorization = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        self._request_id = 0

    def call(self, method: str, *params: Any) -> Any:
        self._request_id += 1
        request_id = self._request_id
        body = canonical({"jsonrpc": "2.0", "id": request_id, "method": method, "params": list(params)})
        headers = {"Content-Type": "application/json", "User-Agent": "noos-g3-ots-verifier/2"}
        if self.authorization:
            headers["Authorization"] = self.authorization
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                result = json.loads(response.read(4 * 1024 * 1024), object_pairs_hook=reject_duplicates)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"Bitcoin Core RPC unavailable: {exc}") from exc
        if not isinstance(result, dict) or result.get("id") != request_id or result.get("error") is not None or "result" not in result:
            raise EvidenceError(f"Bitcoin Core RPC {method} failed")
        return result["result"]

    def verify_mainnet(self) -> int:
        info = self.call("getblockchaininfo")
        if not isinstance(info, dict) or info.get("chain") != "main" or info.get("initialblockdownload") is not False:
            raise EvidenceError("Bitcoin Core must be synchronized on mainnet")
        if self.call("getblockhash", 0) != BITCOIN_MAINNET_GENESIS:
            raise EvidenceError("Bitcoin Core mainnet genesis trust root mismatch")
        height = self.call("getblockcount")
        if not isinstance(height, int) or height < 0:
            raise EvidenceError("Bitcoin Core returned an invalid active-chain height")
        if info.get("blocks") != height or info.get("headers") != height or self.call("getblockhash", height) != info.get("bestblockhash"):
            raise EvidenceError("Bitcoin Core is not synchronized to its best validated header")
        tip = self.call("getblockheader", info["bestblockhash"], True)
        tip_time = tip.get("time") if isinstance(tip, dict) else None
        now_unix = int(utc_now().timestamp())
        if not isinstance(tip_time, int) or tip_time < now_unix - MAX_BITCOIN_TIP_AGE_SECONDS or tip_time > now_unix + 7200:
            raise EvidenceError("Bitcoin Core active-chain tip is stale or future-dated")
        return height

    def active_block_header(self, height: int, tip_height: int) -> tuple[Any, int]:
        if not isinstance(height, int) or height < 0 or height > tip_height:
            raise EvidenceError("OpenTimestamps Bitcoin block height is not on the current chain")
        block_hash = self.call("getblockhash", height)
        header = self.call("getblockheader", block_hash, True)
        if not isinstance(header, dict) or header.get("hash") != block_hash or header.get("height") != height:
            raise EvidenceError("Bitcoin Core returned an inconsistent active-chain header")
        merkle_root = header.get("merkleroot")
        block_time = header.get("time")
        confirmations = header.get("confirmations")
        if not isinstance(merkle_root, str) or not HEX64.fullmatch(merkle_root) or not isinstance(block_time, int) or not isinstance(confirmations, int):
            raise EvidenceError("Bitcoin Core returned a malformed active-chain header")
        expected_confirmations = tip_height - height + 1
        if confirmations != expected_confirmations or confirmations <= 0:
            raise EvidenceError("OpenTimestamps block is no longer in the current Bitcoin main chain")
        header_view = type("BitcoinHeaderView", (), {})()
        header_view.hashMerkleRoot = bytes.fromhex(merkle_root)[::-1]
        header_view.nTime = block_time
        return header_view, confirmations


def test_receipt_proof(checkpoint: dict[str, Any], publication_time_utc: str) -> str:
    return sha256_bytes(canonical({
        "domain": "NOOS/G3/TEST_ONLY_EXTERNAL_TIMESTAMP/v1",
        "commitment_sha256": timestamp_commitment(checkpoint),
        "publication_time_utc": publication_time_utc,
    }))


def verify_external_receipt(
    manifest: dict[str, Any], checkpoint: dict[str, Any], *, live_trust: bool, bitcoin_rpc: BitcoinRPC | None
) -> dict[str, Any]:
    receipt = checkpoint.get("external_timestamp_receipt")
    if receipt is None:
        raise EvidenceError("checkpoint lacks an external publication-time receipt")
    commitment = timestamp_commitment(checkpoint)
    if manifest["manifest_state"] == "TEST_FIXTURE_NOT_EVIDENCE":
        exact_fields(receipt, {"receipt_version", "system", "commitment_sha256", "publication_time_utc", "proof_sha256"}, "external_timestamp_receipt")
        publication = parse_utc(receipt["publication_time_utc"], "test receipt publication_time_utc")
        if receipt["receipt_version"] != 1 or receipt["system"] != "TEST_ONLY-deterministic" or receipt["commitment_sha256"] != commitment or receipt["proof_sha256"] != test_receipt_proof(checkpoint, receipt["publication_time_utc"]):
            raise EvidenceError("invalid deterministic TEST_ONLY timestamp receipt")
        return {"publication_time": publication, "trusted": False, "test_only": True}

    exact_fields(receipt, {"receipt_version", "system", "bitcoin_network", "commitment_sha256", "proof_base64"}, "external_timestamp_receipt")
    if receipt["receipt_version"] != 1 or receipt["system"] != "opentimestamps-bitcoin" or receipt["bitcoin_network"] != "mainnet" or receipt["commitment_sha256"] != commitment:
        raise EvidenceError("external timestamp receipt checkpoint/network binding is invalid")
    _, attestations = deserialize_ots_proof(receipt["proof_base64"], commitment)
    if not live_trust:
        return {"publication_time": None, "trusted": False, "test_only": False}
    if bitcoin_rpc is None:
        raise EvidenceError("live OpenTimestamps verification requires a verifier-controlled Bitcoin Core RPC endpoint")
    tip_height = bitcoin_rpc.verify_mainnet()
    minimum_confirmations = manifest["timestamp_policy"]["minimum_confirmations"]
    valid: list[dt.datetime] = []
    saw_unconfirmed = False
    for message, attestation in attestations:
        header, confirmations = bitcoin_rpc.active_block_header(attestation.height, tip_height)
        if confirmations < minimum_confirmations:
            saw_unconfirmed = True
            continue
        try:
            attested_unix = attestation.verify_against_blockheader(message, header)
        except Exception:
            continue
        valid.append(dt.datetime.fromtimestamp(attested_unix, tz=dt.timezone.utc))
    if not valid:
        if saw_unconfirmed:
            raise EvidenceError(f"OpenTimestamps proof has fewer than {minimum_confirmations} Bitcoin confirmations")
        raise EvidenceError("OpenTimestamps proof does not verify against a current Bitcoin main-chain block")
    return {"publication_time": min(valid), "trusted": True, "test_only": False}


def validate_manifest(manifest: dict[str, Any], *, live_dns: bool = False, require_signatures: bool = True) -> None:
    expected = {"schema_version", "manifest_kind", "manifest_state", "network", "release_binding", "evidence_policy", "timestamp_policy", "operators", "lanes", "topology", "drill_schedule", "public_ledger_urls", "manifest_signatures"}
    exact_fields(manifest, expected, "manifest")
    if manifest["schema_version"] != 2 or manifest["manifest_kind"] != "noos-g3-public-duration":
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
    timestamp_policy = exact_fields(
        manifest["timestamp_policy"],
        {"system", "bitcoin_network", "opentimestamps_client_version", "minimum_confirmations", "maximum_anchor_delay_seconds", "maximum_negative_block_time_tolerance_seconds"},
        "timestamp_policy",
    )
    if timestamp_policy["system"] != "opentimestamps-bitcoin" or timestamp_policy["bitcoin_network"] != "mainnet" or timestamp_policy["opentimestamps_client_version"] != OTS_CLIENT_VERSION:
        raise EvidenceError("timestamp policy must use the pinned Bitcoin-mainnet OpenTimestamps verifier")
    if not isinstance(timestamp_policy["minimum_confirmations"], int) or timestamp_policy["minimum_confirmations"] < 6:
        raise EvidenceError("timestamp policy requires at least six Bitcoin confirmations")
    if not isinstance(timestamp_policy["maximum_anchor_delay_seconds"], int) or not 3600 <= timestamp_policy["maximum_anchor_delay_seconds"] <= 172800:
        raise EvidenceError("timestamp anchor delay policy is outside the hard security bound")
    if timestamp_policy["maximum_negative_block_time_tolerance_seconds"] != 7200:
        raise EvidenceError("Bitcoin block-clock tolerance must be exactly 7200 seconds")
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
    mirror_hosts: set[str] = set()
    for index, url in enumerate(manifest["public_ledger_urls"]):
        public_url(url, f"public_ledger_urls[{index}]", live_dns and manifest["manifest_state"] == "ACTIVE")
        mirror_hosts.add((urllib.parse.urlsplit(url).hostname or "").lower())
    if len(mirror_hosts) < 2:
        raise EvidenceError("public ledger mirrors must use at least two distinct public hosts")
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
            digest = manifest_signature_payload_hash(manifest)
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


def verify_checkpoint(
    manifest: dict[str, Any],
    checkpoint: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    now: dt.datetime,
    live_trust: bool = False,
    bitcoin_rpc: BitcoinRPC | None = None,
    allow_missing_receipt: bool = False,
) -> dict[str, Any]:
    expected = {"schema_version", "record_kind", "network_id", "manifest_sha256", "exact_revision", "sequence", "previous_checkpoint_sha256", "wall_clock", "lane_observations", "operator_observations", "drill_observations", "signatures", "external_timestamp_receipt"}
    exact_fields(checkpoint, expected, "checkpoint")
    if checkpoint["schema_version"] != 2 or checkpoint["record_kind"] != "noos-g3-daily-checkpoint":
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
    if checkpoint["external_timestamp_receipt"] is None and allow_missing_receipt:
        return {"publication_time": None, "trusted": False, "test_only": False}
    receipt_result = verify_external_receipt(
        manifest, checkpoint, live_trust=live_trust, bitcoin_rpc=bitcoin_rpc
    )
    publication = receipt_result["publication_time"]
    if publication is not None:
        latest_signature = max(
            parse_utc(item["signed_at_utc"], "signature.signed_at_utc") for item in signatures
        )
        timestamp_policy = manifest["timestamp_policy"]
        delta = (publication - latest_signature).total_seconds()
        if delta < -timestamp_policy["maximum_negative_block_time_tolerance_seconds"]:
            raise EvidenceError("external publication time predates the signed checkpoint beyond Bitcoin clock tolerance")
        if delta > timestamp_policy["maximum_anchor_delay_seconds"]:
            raise EvidenceError("external publication time is too late for the claimed observation/signature window")
        if publication > now + dt.timedelta(seconds=timestamp_policy["maximum_negative_block_time_tolerance_seconds"]):
            raise EvidenceError("external publication time is implausibly future-dated")
    return receipt_result


def verify_evidence(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    now: dt.datetime,
    live_trust: bool = False,
    bitcoin_rpc: BitcoinRPC | None = None,
    public_mirrors_verified: bool = False,
) -> dict[str, Any]:
    validate_manifest(manifest)
    if manifest["manifest_state"] == "TEMPLATE_NOT_STARTED":
        return {"status": "NOT_STARTED", "qualifying_real_days": 0, "ai_off_real_days": 0, "lane_status": {}, "blockers": ["exact active G2-revision manifest and production-evidence keys have not been supplied"], "promotion_effect": "NONE"}
    if not records:
        return {"status": "NOT_STARTED", "qualifying_real_days": 0, "ai_off_real_days": 0, "lane_status": {}, "blockers": ["no signed public daily checkpoint exists"], "promotion_effect": "NONE"}
    previous = None
    receipt_results: list[dict[str, Any]] = []
    for record in records:
        receipt_results.append(verify_checkpoint(
            manifest, record, previous, now=now, live_trust=live_trust, bitcoin_rpc=bitcoin_rpc
        ))
        previous = record
    publication_times = [item["publication_time"] for item in receipt_results]
    trusted_times_available = all(item is not None for item in publication_times)
    if trusted_times_available:
        for earlier, later in zip(publication_times, publication_times[1:]):
            gap = (later - earlier).total_seconds()
            if gap <= 0:
                raise EvidenceError("external publication time did not increase monotonically")
            if gap > manifest["evidence_policy"]["maximum_checkpoint_gap_seconds"]:
                raise EvidenceError("externally timestamped daily checkpoint gap exceeds policy")
        first_time = publication_times[0]
        last_time = publication_times[-1]
        real_days = max(0.0, (last_time - first_time).total_seconds() / 86400)
    else:
        first_time = None
        real_days = 0.0
    minimum_signatures = manifest["evidence_policy"]["minimum_independent_signatures"]
    blockers: list[str] = []
    if manifest["manifest_state"] == "TEST_FIXTURE_NOT_EVIDENCE":
        blockers.append("deterministic TEST_ONLY timestamps and keys cannot qualify as ACTIVE production evidence")
    if not live_trust or not trusted_times_available or not all(item["trusted"] for item in receipt_results):
        if manifest["manifest_state"] == "ACTIVE":
            blockers.append("live Bitcoin-mainnet trust-root verification is required for qualifying elapsed time")
    if manifest["manifest_state"] == "ACTIVE" and not public_mirrors_verified:
        blockers.append("at least two independent public ledger mirrors have not been live-verified")
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
    for index, (earlier, later) in enumerate(zip(records, records[1:])):
        if all(not item["ai_processes_enabled"] for item in earlier["operator_observations"]) and all(not item["ai_processes_enabled"] for item in later["operator_observations"]):
            if trusted_times_available:
                ai_off_current_seconds += (publication_times[index + 1] - publication_times[index]).total_seconds()
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
            scheduled_start = first_time + dt.timedelta(days=scheduled["start_after_real_days"]) if first_time is not None else None
            if scheduled_start is not None and parse_utc(item["started_at_utc"], "scheduled drill start") >= scheduled_start:
                completed_drills.add(item["drill_type"])
            else:
                blockers.append(f"{item['drill_id']} ran before its preregistered real-time schedule")
    missing_drills = sorted(REQUIRED_DRILLS - completed_drills)
    if missing_drills:
        blockers.append("completed signed drill evidence missing: " + ", ".join(missing_drills))
    status = "EVIDENCE_COMPLETE" if manifest["manifest_state"] == "ACTIVE" and live_trust and public_mirrors_verified and not blockers else "IN_PROGRESS"
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
        "schema_version": 2,
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
        "external_timestamp_receipt": None,
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
    if checkpoint.get("external_timestamp_receipt") is not None:
        raise EvidenceError("cannot add or replace operator signatures after external timestamping")
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
    digest = manifest_signature_payload_hash(manifest)
    raw = sign_ed25519(args.private_key, signature_message(digest, args.operator_id, signed_at, "exact-revision-manifest"))
    signed = json.loads(json.dumps(manifest))
    signed["manifest_signatures"].append({"operator_id": args.operator_id, "key_id": operator["key_id"], "algorithm": "ed25519", "payload_sha256": digest, "signed_at_utc": signed_at, "signature_base64": base64.b64encode(raw).decode("ascii")})
    args.output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Exact-revision manifest signed by configured operator key: {args.output}")
    print("A valid signature proves key control; organizational independence remains external evidence.")


def run_ots(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    require_opentimestamps()
    command = [sys.executable, "-c", "from otsclient.ots import main; main()", *arguments]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(errors="replace").strip()
        raise EvidenceError(f"OpenTimestamps {arguments[0]} failed: {detail}")
    return completed


def stamp_checkpoint(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest); checkpoint = load_json(args.checkpoint)
    validate_manifest(manifest)
    if manifest["manifest_state"] != "ACTIVE":
        raise EvidenceError("production OpenTimestamps stamping requires an ACTIVE manifest")
    if checkpoint.get("external_timestamp_receipt") is not None:
        raise EvidenceError("checkpoint already has an external timestamp receipt")
    records = read_ledger(args.ledger)
    verify_checkpoint(manifest, checkpoint, records[-1] if records else None, now=utc_now(), allow_missing_receipt=True)
    with tempfile.TemporaryDirectory(prefix="noos-g3-ots-stamp-") as tmp:
        target = Path(tmp) / "signed-checkpoint.canonical.json"
        target.write_bytes(canonical(signed_checkpoint(checkpoint)))
        run_ots(["stamp", str(target)])
        proof_path = Path(str(target) + ".ots")
        if not proof_path.is_file():
            raise EvidenceError("OpenTimestamps did not produce a detached proof")
        proof = proof_path.read_bytes()
    proof_base64 = base64.b64encode(proof).decode("ascii")
    deserialize_ots_proof(proof_base64, timestamp_commitment(checkpoint), require_confirmed=False)
    stamped = json.loads(json.dumps(checkpoint))
    stamped["external_timestamp_receipt"] = {
        "receipt_version": 1,
        "system": "opentimestamps-bitcoin",
        "bitcoin_network": "mainnet",
        "commitment_sha256": timestamp_commitment(checkpoint),
        "proof_base64": proof_base64,
    }
    args.output.write_text(json.dumps(stamped, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Pending Bitcoin-mainnet OpenTimestamps receipt attached: {args.output}")
    print("status=IN_PROGRESS (upgrade after calendar aggregation and Bitcoin confirmation)")


def upgrade_checkpoint(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest); checkpoint = load_json(args.checkpoint)
    validate_manifest(manifest)
    if manifest["manifest_state"] != "ACTIVE":
        raise EvidenceError("production OpenTimestamps upgrade requires an ACTIVE manifest")
    receipt = checkpoint.get("external_timestamp_receipt")
    if not isinstance(receipt, dict):
        raise EvidenceError("checkpoint has no production OpenTimestamps receipt to upgrade")
    exact_fields(receipt, {"receipt_version", "system", "bitcoin_network", "commitment_sha256", "proof_base64"}, "external_timestamp_receipt")
    commitment = timestamp_commitment(checkpoint)
    if receipt["receipt_version"] != 1 or receipt["system"] != "opentimestamps-bitcoin" or receipt["bitcoin_network"] != "mainnet" or receipt["commitment_sha256"] != commitment:
        raise EvidenceError("pending OpenTimestamps receipt binding is invalid")
    deserialize_ots_proof(receipt["proof_base64"], commitment, require_confirmed=False)
    with tempfile.TemporaryDirectory(prefix="noos-g3-ots-upgrade-") as tmp:
        proof_path = Path(tmp) / "checkpoint.ots"
        proof_path.write_bytes(base64.b64decode(receipt["proof_base64"], validate=True))
        run_ots(["upgrade", str(proof_path)])
        upgraded_proof = proof_path.read_bytes()
    upgraded = json.loads(json.dumps(checkpoint))
    upgraded["external_timestamp_receipt"]["proof_base64"] = base64.b64encode(upgraded_proof).decode("ascii")
    deserialize_ots_proof(upgraded["external_timestamp_receipt"]["proof_base64"], timestamp_commitment(upgraded))
    args.output.write_text(json.dumps(upgraded, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Confirmed-attestation OpenTimestamps proof embedded: {args.output}")
    print("status=IN_PROGRESS (live Bitcoin finality verification and append still required)")


def append_checkpoint(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest); checkpoint = load_json(args.checkpoint)
    validate_manifest(manifest)
    now = utc_now()
    if len(checkpoint["signatures"]) < manifest["evidence_policy"]["minimum_independent_signatures"]:
        raise EvidenceError("append refused: independent operator signature threshold not met")
    if checkpoint.get("external_timestamp_receipt") is None:
        raise EvidenceError("append refused: confirmed external publication-time receipt is required")
    if manifest["manifest_state"] != "ACTIVE":
        raise EvidenceError("append refused: only ACTIVE production evidence may be appended")
    bitcoin_rpc = BitcoinRPC(args.bitcoin_rpc_url)
    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    lock_path = args.ledger.with_name(args.ledger.name + ".append.lock")
    try:
        lock_descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise EvidenceError("another checkpoint append is active (or a stale lock requires operator review)") from exc
    try:
        os.close(lock_descriptor)
        records = read_ledger(args.ledger)
        verify_evidence(manifest, [*records, checkpoint], now=now, live_trust=True, bitcoin_rpc=bitcoin_rpc)
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


def live_probe(manifest: dict[str, Any], ledger: Path) -> None:
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
    expected_ledger = ledger.read_bytes()
    if len(expected_ledger) > 32 * 1024 * 1024:
        raise EvidenceError("local public-duration ledger exceeds live mirror verification limit")
    verified_hosts: set[str] = set()
    for url in manifest["public_ledger_urls"]:
        request = urllib.request.Request(url, headers={"User-Agent": "noos-g3-verifier/2"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                public_url(response.geturl(), "redirected public ledger URL", resolve_dns=True)
                body = response.read(32 * 1024 * 1024 + 1)
                if response.status != 200 or body != expected_ledger:
                    raise EvidenceError(f"public ledger mirror does not exactly match {ledger}")
                verified_hosts.add((urllib.parse.urlsplit(response.geturl()).hostname or "").lower())
        except (OSError, urllib.error.URLError) as exc:
            raise EvidenceError(f"public ledger mirror probe failed: {exc}") from exc
    if len(verified_hosts) < 2:
        raise EvidenceError("fewer than two distinct public ledger mirrors were live-verified")


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__)
    sub = top.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify manifest and append-only duration ledger")
    verify.add_argument("--manifest", type=Path, required=True); verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--live", action="store_true", help="verify Bitcoin main-chain trust, telemetry, and both public ledger mirrors")
    verify.add_argument("--bitcoin-rpc-url", default=os.environ.get("G3_BITCOIN_RPC_URL"), help="verifier-controlled synchronized Bitcoin Core RPC URL (or G3_BITCOIN_RPC_URL)")
    verify.add_argument("--json", action="store_true")
    create = sub.add_parser("create-checkpoint", help="create an unsigned checkpoint using only the current clocks")
    create.add_argument("--manifest", type=Path, required=True); create.add_argument("--ledger", type=Path, required=True)
    create.add_argument("--lanes", type=Path, required=True); create.add_argument("--operators", type=Path, required=True); create.add_argument("--drills", type=Path, required=True); create.add_argument("--output", type=Path, required=True)
    sign = sub.add_parser("sign-checkpoint", help="add one configured operator signature to a new file")
    sign.add_argument("--manifest", type=Path, required=True); sign.add_argument("--checkpoint", type=Path, required=True); sign.add_argument("--operator-id", required=True); sign.add_argument("--private-key", type=Path, required=True); sign.add_argument("--output", type=Path, required=True)
    sign_manifest_parser = sub.add_parser("sign-manifest", help="add one configured operator signature to an exact-revision manifest")
    sign_manifest_parser.add_argument("--manifest", type=Path, required=True); sign_manifest_parser.add_argument("--operator-id", required=True); sign_manifest_parser.add_argument("--private-key", type=Path, required=True); sign_manifest_parser.add_argument("--output", type=Path, required=True)
    stamp = sub.add_parser("stamp-checkpoint", help="submit the exact threshold-signed checkpoint to OpenTimestamps calendars")
    stamp.add_argument("--manifest", type=Path, required=True); stamp.add_argument("--checkpoint", type=Path, required=True); stamp.add_argument("--ledger", type=Path, required=True); stamp.add_argument("--output", type=Path, required=True)
    upgrade = sub.add_parser("upgrade-checkpoint", help="upgrade a pending OpenTimestamps receipt to a Bitcoin block attestation")
    upgrade.add_argument("--manifest", type=Path, required=True); upgrade.add_argument("--checkpoint", type=Path, required=True); upgrade.add_argument("--output", type=Path, required=True)
    append = sub.add_parser("append-checkpoint", help="live-verify and atomically append a timestamped threshold-signed checkpoint")
    append.add_argument("--manifest", type=Path, required=True); append.add_argument("--checkpoint", type=Path, required=True); append.add_argument("--ledger", type=Path, required=True); append.add_argument("--bitcoin-rpc-url", required=True)
    return top


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "create-checkpoint": create_checkpoint(args); return 0
        if args.command == "sign-checkpoint": sign_checkpoint(args); return 0
        if args.command == "sign-manifest": sign_manifest(args); return 0
        if args.command == "stamp-checkpoint": stamp_checkpoint(args); return 0
        if args.command == "upgrade-checkpoint": upgrade_checkpoint(args); return 0
        if args.command == "append-checkpoint": append_checkpoint(args); return 0
        manifest = load_json(args.manifest); records = read_ledger(args.ledger)
        bitcoin_rpc = None
        mirrors_verified = False
        if args.live and manifest.get("manifest_state") == "ACTIVE":
            if not args.bitcoin_rpc_url:
                raise EvidenceError("--live requires --bitcoin-rpc-url or G3_BITCOIN_RPC_URL")
            bitcoin_rpc = BitcoinRPC(args.bitcoin_rpc_url)
            live_probe(manifest, args.ledger)
            mirrors_verified = True
        result = verify_evidence(
            manifest, records, now=utc_now(), live_trust=args.live,
            bitcoin_rpc=bitcoin_rpc, public_mirrors_verified=mirrors_verified,
        )
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
