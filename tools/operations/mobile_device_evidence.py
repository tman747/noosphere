#!/usr/bin/env python3
"""Sign and seal physical mobile-wallet security evidence.

A bundle passes only with physical Android StrongBox, Android non-StrongBox, and
iOS Secure Enclave observations for one exact source/artifact revision. It never
substitutes simulator evidence for hardware behavior and has no release effect.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

OBSERVATION_SCHEMA = "noos/mobile-wallet-physical-device-observation/v1"
BUNDLE_SCHEMA = "noos/mobile-wallet-physical-device-evidence/v1"
OBSERVATION_DOMAIN = b"NOOS/SIG/MOBILE-WALLET-PHYSICAL-DEVICE-OBSERVATION/V1\0"
BUNDLE_DOMAIN = b"NOOS/SIG/MOBILE-WALLET-PHYSICAL-DEVICE-EVIDENCE/V1\0"
OBSERVATION_ID_DOMAIN = b"NOOS/MOBILE-WALLET-PHYSICAL-DEVICE-OBSERVATION-ID/V1\0"
BUNDLE_ID_DOMAIN = b"NOOS/MOBILE-WALLET-PHYSICAL-DEVICE-EVIDENCE-ID/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PLATFORMS = frozenset({"ANDROID", "IOS"})
ANDROID_SECURITY = frozenset({"STRONGBOX", "TEE", "SOFTWARE_BACKED"})
IOS_SECURITY = frozenset({"SECURE_ENCLAVE"})
SCENARIOS = frozenset(
    {
        "hardware_key_generation",
        "biometric_success",
        "biometric_fallback",
        "biometric_enrollment_change",
        "backup_exclusion",
        "recovery_import",
        "deletion",
        "migration",
        "plaintext_absence",
    }
)
MAX_OBSERVATIONS = 64
MAX_EVIDENCE_BYTES = 1024 * 1024 * 1024


class DeviceEvidenceError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(canonical_json(value) + b"\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def load_json(path: Path, maximum: int = 16 * 1024 * 1024) -> dict[str, Any]:
    try:
        if path.stat().st_size > maximum:
            raise DeviceEvidenceError("device evidence JSON exceeds its byte bound")
        value = json.loads(path.read_text(encoding="utf-8"))
    except DeviceEvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeviceEvidenceError(f"cannot load device evidence JSON: {error}") from error
    if not isinstance(value, dict):
        raise DeviceEvidenceError("device evidence JSON must be an object")
    return value


def load_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise DeviceEvidenceError(f"cannot read signing seed: {error}") from error
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeError, ValueError) as error:
            raise DeviceEvidenceError("signing seed must be 32 raw bytes or lowercase hex64") from error
    elif len(raw) == 32:
        seed = raw
    else:
        raise DeviceEvidenceError("signing seed must be 32 raw bytes or lowercase hex64")
    if seed == bytes(32):
        raise DeviceEvidenceError("all-zero signing seed is forbidden")
    return seed


def _decode_public(value: Any, key_id: Any) -> bytes:
    if not isinstance(value, str) or not isinstance(key_id, str) or not HEX64.fullmatch(key_id):
        raise DeviceEvidenceError("device evidence signer is malformed")
    try:
        public = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise DeviceEvidenceError("device evidence public key is not canonical base64") from error
    if len(public) != 32 or sha256(public) != key_id:
        raise DeviceEvidenceError("device evidence key id does not bind its public key")
    return public


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise DeviceEvidenceError("device evidence signature is missing")
    try:
        signature = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise DeviceEvidenceError("device evidence signature is not canonical base64") from error
    if len(signature) != 64:
        raise DeviceEvidenceError("device evidence signature must contain 64 bytes")
    return signature


def sign_body(schema: str, domain: bytes, body: dict[str, Any], seed: bytes) -> dict[str, Any]:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes_raw()
    return {
        "schema": schema,
        "body": body,
        "signer": {
            "key_id": sha256(public),
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "signature_base64": base64.b64encode(private.sign(domain + canonical_json(body))).decode("ascii"),
        },
    }


def verify_envelope(value: Any, schema: str, domain: bytes) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "body", "signer"} or value.get("schema") != schema:
        raise DeviceEvidenceError("signed device evidence envelope is malformed")
    body = value["body"]
    signer = value["signer"]
    if not isinstance(body, dict) or not isinstance(signer, dict) or set(signer) != {
        "key_id",
        "public_key_base64",
        "signature_base64",
    }:
        raise DeviceEvidenceError("signed device evidence body or signer is malformed")
    public = _decode_public(signer["public_key_base64"], signer["key_id"])
    signature = _decode_signature(signer["signature_base64"])
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, domain + canonical_json(body))
    except InvalidSignature as error:
        raise DeviceEvidenceError("device evidence signature is invalid") from error
    return body


def _text(value: Any, field: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise DeviceEvidenceError(f"{field} must contain 1..={maximum} UTF-8 bytes")
    return value


def _utc(value: Any, field: str) -> str:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise DeviceEvidenceError(f"{field} must be canonical second-precision UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise DeviceEvidenceError(f"{field} is not a valid UTC instant") from error
    return value


def observation_id(body: dict[str, Any]) -> str:
    return sha256(OBSERVATION_ID_DOMAIN + canonical_json({**body, "observation_id": ""}))


def validate_observation_body(body: Any) -> dict[str, Any]:
    fields = {
        "observation_id",
        "source_revision",
        "release_artifact_sha256",
        "release_manifest_sha256",
        "platform",
        "security_mode",
        "physical_device",
        "simulator",
        "device_fingerprint_sha256",
        "manufacturer",
        "model",
        "os_version",
        "os_build",
        "security_patch",
        "hardware_attestation_sha256",
        "lab_organization_root",
        "lab_control_cluster_id",
        "started_at_utc",
        "completed_at_utc",
        "scenarios",
        "production",
        "promotion_effect",
    }
    if not isinstance(body, dict) or set(body) != fields:
        raise DeviceEvidenceError("physical-device observation has the wrong closed schema")
    if body["observation_id"] != observation_id(body) or not HEX64.fullmatch(str(body["observation_id"])):
        raise DeviceEvidenceError("physical-device observation id mismatch")
    if not HEX40.fullmatch(str(body["source_revision"])):
        raise DeviceEvidenceError("physical-device source revision is malformed")
    for field in (
        "release_artifact_sha256",
        "release_manifest_sha256",
        "device_fingerprint_sha256",
        "hardware_attestation_sha256",
        "lab_organization_root",
        "lab_control_cluster_id",
    ):
        if not HEX64.fullmatch(str(body[field])):
            raise DeviceEvidenceError(f"physical-device {field} is malformed")
    platform = body["platform"]
    security_mode = body["security_mode"]
    if platform not in PLATFORMS or (
        platform == "ANDROID" and security_mode not in ANDROID_SECURITY
    ) or (platform == "IOS" and security_mode not in IOS_SECURITY):
        raise DeviceEvidenceError("physical-device platform or security mode is invalid")
    if body["physical_device"] is not True or body["simulator"] is not False:
        raise DeviceEvidenceError("simulator/emulator evidence cannot satisfy a physical-device observation")
    for field in ("manufacturer", "model", "os_version", "os_build", "security_patch"):
        _text(body[field], field)
    started = _utc(body["started_at_utc"], "started_at_utc")
    completed = _utc(body["completed_at_utc"], "completed_at_utc")
    if completed <= started:
        raise DeviceEvidenceError("physical-device observation duration is non-positive")
    scenarios = body["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != len(SCENARIOS):
        raise DeviceEvidenceError("physical-device observation must contain every exact scenario")
    scenario_fields = {"scenario", "verdict", "evidence_sha256", "evidence_bytes", "observed_at_utc"}
    observed: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != scenario_fields:
            raise DeviceEvidenceError("physical-device scenario evidence is malformed")
        name = scenario["scenario"]
        if name not in SCENARIOS or name in observed or scenario["verdict"] != "PASS":
            raise DeviceEvidenceError("physical-device scenario is duplicated, unknown, or failing")
        if not HEX64.fullmatch(str(scenario["evidence_sha256"])):
            raise DeviceEvidenceError("physical-device scenario digest is malformed")
        size = scenario["evidence_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_EVIDENCE_BYTES:
            raise DeviceEvidenceError("physical-device scenario evidence byte count is invalid")
        observed_at = _utc(scenario["observed_at_utc"], "scenario observed_at_utc")
        if not started <= observed_at <= completed:
            raise DeviceEvidenceError("physical-device scenario time is outside the observation")
        observed.add(name)
    if observed != SCENARIOS:
        raise DeviceEvidenceError("physical-device scenario coverage is incomplete")
    if body["production"] is not False or body["promotion_effect"] != "NONE":
        raise DeviceEvidenceError("physical-device evidence violates the nonproduction boundary")
    return body


def sign_observation(body: dict[str, Any], seed: bytes) -> dict[str, Any]:
    body = dict(body)
    body["observation_id"] = observation_id(body)
    validate_observation_body(body)
    return sign_body(OBSERVATION_SCHEMA, OBSERVATION_DOMAIN, body, seed)


def validate_observation(value: Any) -> dict[str, Any]:
    return validate_observation_body(verify_envelope(value, OBSERVATION_SCHEMA, OBSERVATION_DOMAIN))


def bundle_id(body: dict[str, Any]) -> str:
    return sha256(BUNDLE_ID_DOMAIN + canonical_json({**body, "bundle_id": ""}))


def seal_bundle(observations: list[dict[str, Any]], seed: bytes) -> dict[str, Any]:
    if not 3 <= len(observations) <= MAX_OBSERVATIONS:
        raise DeviceEvidenceError("physical-device bundle requires 3..=64 observations")
    bodies = [validate_observation(observation) for observation in observations]
    identities = {
        (body["source_revision"], body["release_artifact_sha256"], body["release_manifest_sha256"])
        for body in bodies
    }
    if len(identities) != 1:
        raise DeviceEvidenceError("physical-device observations do not bind one exact release")
    profile_classes = {
        "ANDROID_STRONGBOX": any(body["platform"] == "ANDROID" and body["security_mode"] == "STRONGBOX" for body in bodies),
        "ANDROID_NON_STRONGBOX": any(body["platform"] == "ANDROID" and body["security_mode"] != "STRONGBOX" for body in bodies),
        "IOS_SECURE_ENCLAVE": any(body["platform"] == "IOS" and body["security_mode"] == "SECURE_ENCLAVE" for body in bodies),
    }
    if not all(profile_classes.values()):
        raise DeviceEvidenceError("physical-device bundle lacks StrongBox, non-StrongBox, or Secure Enclave coverage")
    fingerprints = {body["device_fingerprint_sha256"] for body in bodies}
    organizations = {body["lab_organization_root"] for body in bodies}
    controls = {body["lab_control_cluster_id"] for body in bodies}
    signer_ids = {observation["signer"]["key_id"] for observation in observations}
    if len(fingerprints) != len(bodies):
        raise DeviceEvidenceError("physical-device bundle duplicates a device fingerprint")
    if len(organizations) < 2 or len(controls) < 2 or len(signer_ids) < 2:
        raise DeviceEvidenceError("physical-device bundle lacks independent lab/control/signing evidence")
    source_revision, artifact_sha, manifest_sha = identities.pop()
    ordered = sorted(observations, key=lambda observation: observation["body"]["observation_id"])
    body: dict[str, Any] = {
        "bundle_id": "",
        "source_revision": source_revision,
        "release_artifact_sha256": artifact_sha,
        "release_manifest_sha256": manifest_sha,
        "profile_classes": profile_classes,
        "observation_ids": [observation["body"]["observation_id"] for observation in ordered],
        "observation_sha256": [sha256(canonical_json(observation)) for observation in ordered],
        "observations": ordered,
        "independent_organization_count": len(organizations),
        "independent_control_cluster_count": len(controls),
        "independent_signer_count": len(signer_ids),
        "verdict": "PASS",
        "production": False,
        "promotion_effect": "NONE",
    }
    body["bundle_id"] = bundle_id(body)
    return sign_body(BUNDLE_SCHEMA, BUNDLE_DOMAIN, body, seed)


def validate_bundle(value: Any) -> dict[str, Any]:
    body = verify_envelope(value, BUNDLE_SCHEMA, BUNDLE_DOMAIN)
    fields = {
        "bundle_id", "source_revision", "release_artifact_sha256", "release_manifest_sha256", "profile_classes",
        "observation_ids", "observation_sha256", "observations", "independent_organization_count",
        "independent_control_cluster_count", "independent_signer_count", "verdict", "production", "promotion_effect",
    }
    if set(body) != fields or body["bundle_id"] != bundle_id(body):
        raise DeviceEvidenceError("physical-device bundle body or id is malformed")
    observations = body["observations"]
    if not isinstance(observations, list):
        raise DeviceEvidenceError("physical-device bundle observations are malformed")
    rebuilt = seal_bundle(observations, bytes.fromhex("01" * 32))["body"]
    for field in fields - {"bundle_id"}:
        if body[field] != rebuilt[field]:
            raise DeviceEvidenceError("physical-device bundle is inconsistent with embedded observations")
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign and seal mobile-wallet physical-device evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)
    sign_parser = subparsers.add_parser("sign-observation")
    sign_parser.add_argument("--body", type=Path, required=True)
    sign_parser.add_argument("--signing-seed", type=Path, required=True)
    sign_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify-observation")
    verify_parser.add_argument("--input", type=Path, required=True)
    seal_parser = subparsers.add_parser("seal-bundle")
    seal_parser.add_argument("--observation", action="append", type=Path, required=True)
    seal_parser.add_argument("--signing-seed", type=Path, required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    bundle_parser = subparsers.add_parser("verify-bundle")
    bundle_parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "sign-observation":
            value = sign_observation(load_json(args.body), load_seed(args.signing_seed))
            atomic_write(args.output, value)
            result = value["body"]
        elif args.command == "verify-observation":
            result = validate_observation(load_json(args.input))
        elif args.command == "seal-bundle":
            value = seal_bundle([load_json(path) for path in args.observation], load_seed(args.signing_seed))
            validate_bundle(value)
            atomic_write(args.output, value)
            result = value["body"]
        else:
            result = validate_bundle(load_json(args.input))
    except DeviceEvidenceError as error:
        print(f"mobile device evidence failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"id": result.get("observation_id", result.get("bundle_id")), "verdict": result.get("verdict", "PASS")}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
