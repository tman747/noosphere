#!/usr/bin/env python3
"""Freeze and verify the signed registry for bounded compute workloads."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REGISTRY_SCHEMA = "noos/compute-workload-registry/v1"
REGISTRY_ID_DOMAIN = b"NOOS/COMPUTE/WORKLOAD-REGISTRY/V1\0"
WORKLOAD_ID_DOMAIN = b"NOOS/COMPUTE/WORKLOAD/V1\0"
SIGNATURE_DOMAIN = b"NOOS/SIG/COMPUTE-WORKLOAD-REGISTRY/V1\0"
MIX32_INPUT_DOMAIN = b"NOOS/COMPUTE/MIX32/INPUT/V1"
MIX32_RESULT_DOMAIN = b"NOOS/COMPUTE/MIX32/RESULT/V1"
MAX_REGISTRY_BYTES = 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UINT64_MAX = (1 << 64) - 1

REJECTION_VECTORS = [
    {"condition": "registry chain_id differs from the configured chain", "code": "WRONG_CHAIN"},
    {"condition": "registry genesis_hash differs from the configured genesis", "code": "WRONG_GENESIS"},
    {"condition": "registry height precedes valid_from_height", "code": "REGISTRY_NOT_ACTIVE"},
    {"condition": "registry height reaches expires_at_height", "code": "REGISTRY_EXPIRED"},
    {"condition": "signature key is not the explicitly trusted key", "code": "UNTRUSTED_SIGNER"},
    {"condition": "signature or signed body is modified", "code": "SIGNATURE_INVALID"},
    {"condition": "workload kind is absent from the registry", "code": "UNREGISTERED_WORKLOAD"},
    {"condition": "height precedes workload activation", "code": "WORKLOAD_NOT_ACTIVE"},
    {"condition": "height reaches workload retirement", "code": "WORKLOAD_RETIRED"},
    {"condition": "payload fields differ from the canonical schema", "code": "PAYLOAD_FIELDS"},
    {"condition": "payload fields are not exact integers", "code": "PAYLOAD_TYPE"},
    {"condition": "seed or start exceeds its unsigned range", "code": "PAYLOAD_RANGE"},
    {"condition": "units or unit_size exceeds the signed limits", "code": "WORKLOAD_LIMIT"},
    {"condition": "units multiplied by unit_size exceeds the signed operation limit", "code": "REGISTRY_OPERATION_BUDGET"},
    {"condition": "operations exceed the worker-local operation limit", "code": "LOCAL_OPERATION_BUDGET"},
    {"condition": "payload meter differs from the on-chain meter", "code": "METER_MISMATCH"},
    {"condition": "payload commitment differs from the on-chain input root", "code": "INPUT_COMMITMENT_MISMATCH"},
]

WORKLOAD_FIELDS = {
    "workload_id",
    "workload_kind",
    "canonical_name",
    "version",
    "payload",
    "input_commitment",
    "result_commitment",
    "verifier",
    "metering",
    "limits",
    "lifecycle",
}
BODY_FIELDS = {
    "registry_id",
    "chain_id",
    "genesis_hash",
    "sequence",
    "previous_registry_id",
    "valid_from_height",
    "expires_at_height",
    "workloads",
    "rejection_vectors",
}


class WorkloadRegistryError(ValueError):
    """Fail-closed registry or workload rejection with a stable reason code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def reject(code: str, message: str) -> None:
    raise WorkloadRegistryError(code, message)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_file(value: object) -> bytes:
    return canonical_json(value) + b"\n"


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _uint(value: Any, field: str, *, minimum: int = 0, maximum: int = UINT64_MAX) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        reject("REGISTRY_MALFORMED", f"{field} must be an integer in [{minimum}, {maximum}]")
    return value


def _job_uint(value: Any, field: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and (value == "0" or (value and value[0] != "0" and value.isascii() and value.isdigit())):
        parsed = int(value)
        if parsed <= UINT64_MAX:
            return parsed
    reject("METER_MISMATCH", f"on-chain {field} is not a canonical unsigned integer")


def _hex64(value: Any, field: str, *, code: str = "REGISTRY_MALFORMED") -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        reject(code, f"{field} must be 32-byte lowercase hex")
    return value


def _decode_public_text(value: Any) -> bytes:
    if not isinstance(value, str):
        reject("REGISTRY_MALFORMED", "registry public key must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise WorkloadRegistryError("REGISTRY_MALFORMED", "registry public key is not canonical base64") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        reject("REGISTRY_MALFORMED", "registry public key must contain one canonical Ed25519 key")
    return decoded


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        reject("REGISTRY_MALFORMED", "registry signature must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise WorkloadRegistryError("REGISTRY_MALFORMED", "registry signature is not canonical base64") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        reject("REGISTRY_MALFORMED", "registry signature must contain 64 canonical bytes")
    return decoded


def read_private_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise WorkloadRegistryError("KEY_IO", f"cannot read workload registry private key: {error}") from error
    stripped = raw.strip()
    if len(raw) == 32:
        seed = raw
    elif len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise WorkloadRegistryError("KEY_MALFORMED", "private key must be 32 raw bytes or lowercase hex64") from error
        if stripped.decode("ascii") != seed.hex():
            reject("KEY_MALFORMED", "private key hex must be canonical lowercase")
    else:
        reject("KEY_MALFORMED", "private key must be 32 raw bytes or lowercase hex64")
    if seed == bytes(32):
        reject("KEY_MALFORMED", "all-zero workload registry private key is forbidden")
    return seed


def read_public_key(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise WorkloadRegistryError("KEY_IO", f"cannot read trusted workload registry key: {error}") from error
    stripped = raw.strip()
    if len(raw) == 32:
        public = raw
    elif len(stripped) == 64:
        try:
            public = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise WorkloadRegistryError("KEY_MALFORMED", "trusted key must be 32 raw bytes, lowercase hex64, or canonical base64") from error
        if stripped.decode("ascii") != public.hex():
            reject("KEY_MALFORMED", "trusted key hex must be canonical lowercase")
    else:
        try:
            text = stripped.decode("ascii")
            public = base64.b64decode(text, validate=True)
        except (UnicodeDecodeError, ValueError) as error:
            raise WorkloadRegistryError("KEY_MALFORMED", "trusted key must be 32 raw bytes, lowercase hex64, or canonical base64") from error
        if len(public) != 32 or base64.b64encode(public).decode("ascii") != text:
            reject("KEY_MALFORMED", "trusted key base64 is not canonical Ed25519 public key data")
    if len(public) != 32:
        reject("KEY_MALFORMED", "trusted workload registry key must contain 32 bytes")
    return public


def public_from_seed(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def workload_identity(workload: dict[str, Any]) -> str:
    payload = dict(workload)
    payload.pop("workload_id", None)
    return sha256(WORKLOAD_ID_DOMAIN + canonical_json(payload))


def registry_identity(body: dict[str, Any]) -> str:
    payload = dict(body)
    payload.pop("registry_id", None)
    return sha256(REGISTRY_ID_DOMAIN + canonical_json(payload))


def make_mix32_workload(
    *,
    activate_at_height: int,
    retire_at_height: int,
    max_units: int = 1_000_000,
    max_unit_size: int = 1_048_576,
    max_operations: int = 100_000_000,
) -> dict[str, Any]:
    activate = _uint(activate_at_height, "workload activate_at_height")
    retire = _uint(retire_at_height, "workload retire_at_height", minimum=1)
    units = _uint(max_units, "workload max_units", minimum=1, maximum=1_000_000)
    unit_size = _uint(max_unit_size, "workload max_unit_size", minimum=1, maximum=1_048_576)
    operations = _uint(max_operations, "workload max_operations", minimum=1)
    if retire <= activate:
        reject("REGISTRY_MALFORMED", "workload retirement must follow activation")
    if operations > units * unit_size:
        reject("REGISTRY_MALFORMED", "workload operation limit exceeds its meter envelope")
    workload: dict[str, Any] = {
        "workload_id": "",
        "workload_kind": 0,
        "canonical_name": "noos.compute.mix32",
        "version": 1,
        "payload": {
            "canonical_encoding": "utf8-json-sorted-keys-no-whitespace-v1",
            "fields": [
                {"name": "seed", "type": "u32"},
                {"name": "start", "type": "u64"},
                {"name": "units", "type": "u32"},
                {"name": "rounds", "type": "u32"},
            ],
        },
        "input_commitment": {"algorithm": "sha256", "domain_hex": MIX32_INPUT_DOMAIN.hex()},
        "result_commitment": {
            "algorithm": "sha256",
            "domain_hex": MIX32_RESULT_DOMAIN.hex(),
            "item_encoding": "u32-little-endian",
        },
        "verifier": "deterministic-full-independent-recomputation-v1",
        "metering": {
            "unit": "mix32-item",
            "unit_size_field": "rounds",
            "operation_formula": "units*rounds",
        },
        "limits": {
            "max_units": units,
            "max_unit_size": unit_size,
            "max_operations": operations,
        },
        "lifecycle": {"activate_at_height": activate, "retire_at_height": retire},
    }
    workload["workload_id"] = workload_identity(workload)
    return workload


def _validate_workload(value: Any, registry_valid_from: int, registry_expires: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != WORKLOAD_FIELDS:
        reject("REGISTRY_MALFORMED", "workload registry entry fields are malformed")
    if value.get("workload_kind") != 0 or value.get("canonical_name") != "noos.compute.mix32" or value.get("version") != 1:
        reject("REGISTRY_MALFORMED", "registry v1 only admits canonical MIX32 workload kind 0")
    if value.get("payload") != {
        "canonical_encoding": "utf8-json-sorted-keys-no-whitespace-v1",
        "fields": [
            {"name": "seed", "type": "u32"},
            {"name": "start", "type": "u64"},
            {"name": "units", "type": "u32"},
            {"name": "rounds", "type": "u32"},
        ],
    }:
        reject("REGISTRY_MALFORMED", "MIX32 payload schema is not canonical")
    if value.get("input_commitment") != {"algorithm": "sha256", "domain_hex": MIX32_INPUT_DOMAIN.hex()}:
        reject("REGISTRY_MALFORMED", "MIX32 input commitment is not canonical")
    if value.get("result_commitment") != {
        "algorithm": "sha256",
        "domain_hex": MIX32_RESULT_DOMAIN.hex(),
        "item_encoding": "u32-little-endian",
    }:
        reject("REGISTRY_MALFORMED", "MIX32 result commitment is not canonical")
    if value.get("verifier") != "deterministic-full-independent-recomputation-v1":
        reject("REGISTRY_MALFORMED", "MIX32 verifier is not canonical")
    if value.get("metering") != {
        "unit": "mix32-item",
        "unit_size_field": "rounds",
        "operation_formula": "units*rounds",
    }:
        reject("REGISTRY_MALFORMED", "MIX32 metering law is not canonical")
    limits = value.get("limits")
    if not isinstance(limits, dict) or set(limits) != {"max_units", "max_unit_size", "max_operations"}:
        reject("REGISTRY_MALFORMED", "MIX32 limits are malformed")
    max_units = _uint(limits["max_units"], "MIX32 max_units", minimum=1, maximum=1_000_000)
    max_unit_size = _uint(limits["max_unit_size"], "MIX32 max_unit_size", minimum=1, maximum=1_048_576)
    max_operations = _uint(limits["max_operations"], "MIX32 max_operations", minimum=1)
    if max_operations > max_units * max_unit_size:
        reject("REGISTRY_MALFORMED", "MIX32 operation limit exceeds its meter envelope")
    lifecycle = value.get("lifecycle")
    if not isinstance(lifecycle, dict) or set(lifecycle) != {"activate_at_height", "retire_at_height"}:
        reject("REGISTRY_MALFORMED", "MIX32 lifecycle is malformed")
    activate = _uint(lifecycle["activate_at_height"], "MIX32 activate_at_height")
    retire = _uint(lifecycle["retire_at_height"], "MIX32 retire_at_height", minimum=1)
    if activate < registry_valid_from or retire > registry_expires or retire <= activate:
        reject("REGISTRY_MALFORMED", "MIX32 lifecycle is outside the registry validity interval")
    _hex64(value.get("workload_id"), "workload_id")
    if value["workload_id"] != workload_identity(value):
        reject("REGISTRY_MALFORMED", "workload identity does not match its canonical specification")
    return value


@dataclass(frozen=True)
class WorkloadSpec:
    value: dict[str, Any]

    @property
    def workload_id(self) -> str:
        return self.value["workload_id"]

    @property
    def workload_kind(self) -> int:
        return self.value["workload_kind"]

    @property
    def input_domain(self) -> bytes:
        return bytes.fromhex(self.value["input_commitment"]["domain_hex"])

    @property
    def result_domain(self) -> bytes:
        return bytes.fromhex(self.value["result_commitment"]["domain_hex"])

    @property
    def limits(self) -> dict[str, int]:
        return self.value["limits"]

    @property
    def activate_at_height(self) -> int:
        return self.value["lifecycle"]["activate_at_height"]

    @property
    def retire_at_height(self) -> int:
        return self.value["lifecycle"]["retire_at_height"]


@dataclass(frozen=True)
class VerifiedRegistry:
    body: dict[str, Any]
    signer_key_id: str
    workloads: dict[int, WorkloadSpec]

    @property
    def registry_id(self) -> str:
        return self.body["registry_id"]

    def workload(self, kind: int) -> WorkloadSpec:
        try:
            return self.workloads[kind]
        except KeyError as error:
            raise WorkloadRegistryError("UNREGISTERED_WORKLOAD", "unregistered workload kind") from error

    def require_active(self, kind: int, height: int) -> WorkloadSpec:
        current = _uint(height, "current height")
        if current < self.body["valid_from_height"]:
            reject("REGISTRY_NOT_ACTIVE", "workload registry is not active at the current height")
        if current >= self.body["expires_at_height"]:
            reject("REGISTRY_EXPIRED", "workload registry expired at the current height")
        workload = self.workload(kind)
        if current < workload.activate_at_height:
            reject("WORKLOAD_NOT_ACTIVE", "workload is not active at the current height")
        if current >= workload.retire_at_height:
            reject("WORKLOAD_RETIRED", "workload retired at the current height")
        return workload

    def summary(self) -> dict[str, Any]:
        return {
            "schema": REGISTRY_SCHEMA,
            "registry_id": self.registry_id,
            "chain_id": self.body["chain_id"],
            "genesis_hash": self.body["genesis_hash"],
            "sequence": self.body["sequence"],
            "valid_from_height": self.body["valid_from_height"],
            "expires_at_height": self.body["expires_at_height"],
            "signer_key_id": self.signer_key_id,
            "workloads": [
                {
                    "workload_id": item.workload_id,
                    "workload_kind": item.workload_kind,
                    "activate_at_height": item.activate_at_height,
                    "retire_at_height": item.retire_at_height,
                    "limits": item.limits,
                }
                for item in sorted(self.workloads.values(), key=lambda row: row.workload_kind)
            ],
        }


def freeze_registry(
    *,
    chain_id: str,
    genesis_hash: str,
    sequence: int,
    previous_registry_id: str | None,
    valid_from_height: int,
    expires_at_height: int,
    activate_at_height: int,
    retire_at_height: int,
    max_units: int,
    max_unit_size: int,
    max_operations: int,
    private_seed: bytes,
) -> dict[str, Any]:
    _hex64(chain_id, "chain_id")
    _hex64(genesis_hash, "genesis_hash")
    seq = _uint(sequence, "registry sequence", minimum=1)
    valid_from = _uint(valid_from_height, "registry valid_from_height")
    expires = _uint(expires_at_height, "registry expires_at_height", minimum=1)
    if expires <= valid_from:
        reject("REGISTRY_MALFORMED", "registry expiration must follow activation")
    if seq == 1 and previous_registry_id is not None:
        reject("REGISTRY_MALFORMED", "registry sequence one cannot name a predecessor")
    if seq > 1:
        _hex64(previous_registry_id, "previous_registry_id")
    if len(private_seed) != 32 or private_seed == bytes(32):
        reject("KEY_MALFORMED", "workload registry private seed must contain 32 nonzero bytes")
    workload = make_mix32_workload(
        activate_at_height=activate_at_height,
        retire_at_height=retire_at_height,
        max_units=max_units,
        max_unit_size=max_unit_size,
        max_operations=max_operations,
    )
    if workload["lifecycle"]["activate_at_height"] < valid_from or workload["lifecycle"]["retire_at_height"] > expires:
        reject("REGISTRY_MALFORMED", "workload lifecycle must fit inside registry validity")
    body: dict[str, Any] = {
        "registry_id": "",
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "sequence": seq,
        "previous_registry_id": previous_registry_id,
        "valid_from_height": valid_from,
        "expires_at_height": expires,
        "workloads": [workload],
        "rejection_vectors": REJECTION_VECTORS,
    }
    body["registry_id"] = registry_identity(body)
    private = Ed25519PrivateKey.from_private_bytes(private_seed)
    public = public_from_seed(private_seed)
    signature = private.sign(SIGNATURE_DOMAIN + canonical_json(body))
    return {
        "schema": REGISTRY_SCHEMA,
        "body": body,
        "signature": {
            "algorithm": "ed25519",
            "key_id": sha256(public),
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_registry(
    envelope: Any,
    *,
    trusted_public_key: bytes,
    expected_chain_id: str,
    expected_genesis_hash: str,
    height: int | None = None,
) -> VerifiedRegistry:
    _hex64(expected_chain_id, "expected chain_id")
    _hex64(expected_genesis_hash, "expected genesis_hash")
    if len(trusted_public_key) != 32:
        reject("KEY_MALFORMED", "trusted workload registry key must contain 32 bytes")
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "body", "signature"} or envelope.get("schema") != REGISTRY_SCHEMA:
        reject("REGISTRY_MALFORMED", "workload registry envelope is malformed")
    body = envelope["body"]
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        reject("REGISTRY_MALFORMED", "workload registry body fields are malformed")
    chain_id = _hex64(body.get("chain_id"), "chain_id")
    genesis_hash = _hex64(body.get("genesis_hash"), "genesis_hash")
    if chain_id != expected_chain_id:
        reject("WRONG_CHAIN", "workload registry is bound to a different chain")
    if genesis_hash != expected_genesis_hash:
        reject("WRONG_GENESIS", "workload registry is bound to a different genesis")
    sequence = _uint(body.get("sequence"), "registry sequence", minimum=1)
    previous = body.get("previous_registry_id")
    if sequence == 1:
        if previous is not None:
            reject("REGISTRY_MALFORMED", "registry sequence one cannot name a predecessor")
    else:
        _hex64(previous, "previous_registry_id")
    valid_from = _uint(body.get("valid_from_height"), "registry valid_from_height")
    expires = _uint(body.get("expires_at_height"), "registry expires_at_height", minimum=1)
    if expires <= valid_from:
        reject("REGISTRY_MALFORMED", "registry expiration must follow activation")
    workloads = body.get("workloads")
    if not isinstance(workloads, list) or not 1 <= len(workloads) <= 16:
        reject("REGISTRY_MALFORMED", "workload registry must contain one to sixteen workloads")
    validated = [_validate_workload(item, valid_from, expires) for item in workloads]
    kinds = [item["workload_kind"] for item in validated]
    if kinds != sorted(set(kinds)):
        reject("REGISTRY_MALFORMED", "workload kinds must be unique and sorted")
    if body.get("rejection_vectors") != REJECTION_VECTORS:
        reject("REGISTRY_MALFORMED", "workload registry rejection vectors are incomplete or reordered")
    _hex64(body.get("registry_id"), "registry_id")
    if body["registry_id"] != registry_identity(body):
        reject("REGISTRY_MALFORMED", "registry identity does not match its signed body")
    signature = envelope["signature"]
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm",
        "key_id",
        "public_key_base64",
        "signature_base64",
    } or signature.get("algorithm") != "ed25519":
        reject("REGISTRY_MALFORMED", "workload registry signature envelope is malformed")
    public = _decode_public_text(signature.get("public_key_base64"))
    if public != trusted_public_key:
        reject("UNTRUSTED_SIGNER", "workload registry was not signed by the explicitly trusted key")
    if signature.get("key_id") != sha256(public):
        reject("REGISTRY_MALFORMED", "workload registry signer key id is invalid")
    raw_signature = _decode_signature(signature.get("signature_base64"))
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            raw_signature,
            SIGNATURE_DOMAIN + canonical_json(body),
        )
    except InvalidSignature as error:
        raise WorkloadRegistryError("SIGNATURE_INVALID", "workload registry signature verification failed") from error
    registry = VerifiedRegistry(
        body=body,
        signer_key_id=signature["key_id"],
        workloads={item["workload_kind"]: WorkloadSpec(item) for item in validated},
    )
    if height is not None:
        current = _uint(height, "current height")
        if current < valid_from:
            reject("REGISTRY_NOT_ACTIVE", "workload registry is not active at the current height")
        if current >= expires:
            reject("REGISTRY_EXPIRED", "workload registry expired at the current height")
    return registry


def load_registry(
    path: Path,
    *,
    trusted_public_key: bytes,
    expected_chain_id: str,
    expected_genesis_hash: str,
    height: int | None = None,
) -> VerifiedRegistry:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise WorkloadRegistryError("REGISTRY_IO", f"cannot read workload registry: {error}") from error
    if not 1 <= len(raw) <= MAX_REGISTRY_BYTES:
        reject("REGISTRY_MALFORMED", "workload registry file size is outside bounds")
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkloadRegistryError("REGISTRY_MALFORMED", "workload registry is not valid UTF-8 JSON") from error
    if raw != canonical_file(envelope):
        reject("REGISTRY_MALFORMED", "workload registry file is not canonical JSON")
    return verify_registry(
        envelope,
        trusted_public_key=trusted_public_key,
        expected_chain_id=expected_chain_id,
        expected_genesis_hash=expected_genesis_hash,
        height=height,
    )


def _payload_values(payload: Any) -> tuple[int, int, int, int]:
    if not isinstance(payload, dict) or set(payload) != {"seed", "start", "units", "rounds"}:
        reject("PAYLOAD_FIELDS", "MIX32 payload fields mismatch")
    if any(not isinstance(payload[name], int) or isinstance(payload[name], bool) for name in payload):
        reject("PAYLOAD_TYPE", "MIX32 payload fields must be exact integers")
    seed, start, units, rounds = payload["seed"], payload["start"], payload["units"], payload["rounds"]
    if not 0 <= seed <= 0xFFFFFFFF or not 0 <= start <= UINT64_MAX:
        reject("PAYLOAD_RANGE", "MIX32 seed or start is out of range")
    return seed, start, units, rounds


def commit_input(workload: WorkloadSpec, payload: Any) -> str:
    _, _, units, rounds = _payload_values(payload)
    limits = workload.limits
    if not 1 <= units <= limits["max_units"] or not 1 <= rounds <= limits["max_unit_size"]:
        reject("WORKLOAD_LIMIT", "MIX32 workload bounds exceeded")
    if units * rounds > limits["max_operations"]:
        reject("REGISTRY_OPERATION_BUDGET", "MIX32 signed registry operation budget exceeded")
    return sha256(workload.input_domain + canonical_json(payload))


def validate_payload(
    registry: VerifiedRegistry,
    job: Any,
    payload: Any,
    *,
    height: int | None,
    max_operations: int | None,
) -> tuple[WorkloadSpec, int, int, int, int]:
    if not isinstance(job, dict):
        reject("METER_MISMATCH", "on-chain job must be an object")
    kind = _job_uint(job.get("workload_kind"), "workload_kind")
    workload = registry.require_active(kind, height) if height is not None else registry.workload(kind)
    seed, start, units, rounds = _payload_values(payload)
    limits = workload.limits
    if not 1 <= units <= limits["max_units"] or not 1 <= rounds <= limits["max_unit_size"]:
        reject("WORKLOAD_LIMIT", "MIX32 workload bounds exceeded")
    operations = units * rounds
    if operations > limits["max_operations"]:
        reject("REGISTRY_OPERATION_BUDGET", "MIX32 signed registry operation budget exceeded")
    if max_operations is not None:
        local_limit = _uint(max_operations, "worker max_operations", minimum=1)
        if operations > local_limit:
            reject("LOCAL_OPERATION_BUDGET", "MIX32 worker-local operation budget exceeded")
    if units != _job_uint(job.get("units"), "units") or rounds != _job_uint(job.get("unit_size"), "unit_size"):
        reject("METER_MISMATCH", "MIX32 payload differs from the on-chain meter")
    commitment = sha256(workload.input_domain + canonical_json(payload))
    input_root = job.get("input_root")
    if not isinstance(input_root, str) or not HEX64.fullmatch(input_root) or commitment != input_root:
        reject("INPUT_COMMITMENT_MISMATCH", "MIX32 payload commitment mismatch")
    return workload, seed, start, units, rounds


def _write_new(path: Path, value: bytes, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise WorkloadRegistryError("OUTPUT_EXISTS", f"{label} already exists: {path}") from error
    except OSError as error:
        raise WorkloadRegistryError("OUTPUT_IO", f"cannot write {label}: {error}") from error


def command_keygen(args: argparse.Namespace) -> dict[str, Any]:
    seed = os.urandom(32)
    public = public_from_seed(seed)
    _write_new(args.private_key, seed, "private key")
    try:
        os.chmod(args.private_key, 0o600)
    except OSError:
        pass
    _write_new(args.public_key, public.hex().encode("ascii") + b"\n", "public key")
    return {"public_key": public.hex(), "key_id": sha256(public)}


def command_freeze(args: argparse.Namespace) -> dict[str, Any]:
    envelope = freeze_registry(
        chain_id=args.chain_id,
        genesis_hash=args.genesis_hash,
        sequence=args.sequence,
        previous_registry_id=args.previous_registry_id,
        valid_from_height=args.valid_from_height,
        expires_at_height=args.expires_at_height,
        activate_at_height=args.activate_at_height,
        retire_at_height=args.retire_at_height,
        max_units=args.max_units,
        max_unit_size=args.max_unit_size,
        max_operations=args.max_operations,
        private_seed=read_private_seed(args.private_key),
    )
    _write_new(args.output, canonical_file(envelope), "workload registry")
    return {
        "output": str(args.output),
        "registry_id": envelope["body"]["registry_id"],
        "signer_key_id": envelope["signature"]["key_id"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="create a new registry signing keypair")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    keygen.set_defaults(handler=command_keygen)

    freeze = commands.add_parser("freeze", help="freeze and sign a canonical MIX32 registry")
    freeze.add_argument("--chain-id", required=True)
    freeze.add_argument("--genesis-hash", required=True)
    freeze.add_argument("--private-key", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--sequence", type=int, default=1)
    freeze.add_argument("--previous-registry-id")
    freeze.add_argument("--valid-from-height", type=int, required=True)
    freeze.add_argument("--expires-at-height", type=int, required=True)
    freeze.add_argument("--activate-at-height", type=int, required=True)
    freeze.add_argument("--retire-at-height", type=int, required=True)
    freeze.add_argument("--max-units", type=int, default=1_000_000)
    freeze.add_argument("--max-unit-size", type=int, default=1_048_576)
    freeze.add_argument("--max-operations", type=int, default=100_000_000)
    freeze.set_defaults(handler=command_freeze)

    verify = commands.add_parser("verify", help="verify a frozen registry against explicit trust")
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--trusted-public-key", type=Path, required=True)
    verify.add_argument("--chain-id", required=True)
    verify.add_argument("--genesis-hash", required=True)
    verify.add_argument("--height", type=int, required=True)
    verify.set_defaults(
        handler=lambda args: load_registry(
            args.registry,
            trusted_public_key=read_public_key(args.trusted_public_key),
            expected_chain_id=args.chain_id,
            expected_genesis_hash=args.genesis_hash,
            height=args.height,
        ).summary()
    )

    args = parser.parse_args()
    try:
        result = args.handler(args)
    except WorkloadRegistryError as error:
        parser.error(f"{error.code}: {error}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
