#!/usr/bin/env python3
"""Fail-closed NOOSPHERE production genesis authorization and ceremony CLI.

This module prepares and verifies cryptographically bound records.  It never
chooses production economics, creates long-term role keys, treats a role label
as proof of human independence, converts simulated time into public elapsed
time, or changes the promotion ledger.  Production-writing commands are
append-only (an existing output path is refused).

The only secret generation performed here is an ephemeral dealerless DKG
polynomial, using ``secrets.randbelow`` (the operating-system CSPRNG).  Role
keys must be supplied by their owners.  Test fixtures are accepted only by
library calls with ``test_mode=True``; the CLI has no production bypass.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - supported fallback
    import tomli as tomllib

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[2]
HASH32 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = re.compile(r"(?:OWNER_BLOCKED|PENDING|REPLACE_ME|EXAMPLE)")
QUIET_WEEK_SECONDS = 7 * 24 * 60 * 60
BITCOIN_MAINNET_POW_LIMIT = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

DOMAIN_FREEZE = "NOOS/GENESIS/FREEZE/V1"
DOMAIN_REPRO_POLICY = "NOOS/REPRO-POLICY/V1"
DOMAIN_PUBLICATION = "NOOS/GENESIS/PUBLICATION/V1"
DOMAIN_BITCOIN_ANCHOR = "NOOS/GENESIS/BITCOIN-ANCHOR/V1"
DOMAIN_DKG_DESCRIPTOR = "NOOS/DKG/DESCRIPTOR/V1"
DOMAIN_DKG_RECORD = "NOOS/DKG/RECORD/V1"
DOMAIN_REBUILD = "NOOS/GENESIS/REBUILD/V1"
DOMAIN_FINAL_FREEZE = "NOOS/GENESIS/FINAL-FREEZE/V1"
DOMAIN_CUTOVER = "NOOS/CUTOVER/AUTHORIZATION/V1"
DOMAIN_DKG_TRANSCRIPT = b"NOOS/DKG/TRANSCRIPT/V1"
DOMAIN_DKG_PARTICIPANTS = b"NOOS/DKG/PARTICIPANTS/V1"

FREEZE_ROLES = ("release-owner", "independent-build-reviewer")
FINAL_ROLES = ("release-owner", "independent-build-reviewer", "independent-genesis-rebuilder")
CUTOVER_ROLES = ("release-owner", "independent-build-reviewer", "operations-owner", "security-reviewer")


class AuthorizationError(RuntimeError):
    """A fail-closed validation or authorization failure."""


def canonical_json(value: Any) -> bytes:
    """Closed canonical JSON used for records (UTF-8, sorted, no whitespace)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def domain_hash(domain: bytes, *parts: bytes) -> bytes:
    h = blake3()
    h.update(domain)
    for part in parts:
        h.update(part)
    return h.digest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"{path}: JSON read failed: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthorizationError(f"{path}: top level must be an object")
    return value


def read_toml(path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthorizationError(f"{path}: TOML read failed: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthorizationError(f"{path}: top level must be a table")
    return value


def write_new_json(path: Path, value: Mapping[str, Any], *, private: bool = False) -> None:
    """Append-only record write: refuse replacement and use canonical bytes."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    mode = stat.S_IRUSR | stat.S_IWUSR if private else stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise AuthorizationError(f"append-only output already exists: {path}") from exc
    try:
        payload = canonical_json(value) + b"\n"
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if private:
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def require_exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise AuthorizationError(
            f"{context}: field set mismatch; missing={sorted(expected-actual)} extra={sorted(actual-expected)}"
        )


def require_hash(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HASH32.fullmatch(value):
        raise AuthorizationError(f"{context}: expected lowercase hash32")
    return value


def require_revision(value: Any, context: str = "exact_revision") -> str:
    if not isinstance(value, str) or not REVISION.fullmatch(value):
        raise AuthorizationError(f"{context}: expected a full lowercase Git revision")
    return value


def require_current_revision(revision: str) -> None:
    """Production CLI records must be made from the exact checked-out source."""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuthorizationError("cannot establish current Git revision") from exc
    if head != revision:
        raise AuthorizationError(f"stale revision: artifact binds {revision}, current checkout is {head}")


def require_non_fixture(doc: Any, context: str, *, test_mode: bool = False) -> None:
    """Reject fixture markers and placeholder strings in production inputs."""
    if test_mode:
        return
    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if value.get("is_test_fixture") is True:
                raise AuthorizationError(f"{context}{path}: test fixture refused by production command")
            for key, child in value.items():
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")
        elif isinstance(value, str) and PLACEHOLDER.search(value):
            raise AuthorizationError(f"{context}{path}: placeholder refused: {value!r}")
    walk(doc, "")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_text(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value: Any, context: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuthorizationError(f"{context}: expected UTC timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorizationError(f"{context}: invalid timestamp") from exc
    return parsed.astimezone(dt.timezone.utc)


# ---------------------------------------------------------------------------
# Ed25519 role keyring and detached records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RoleKey:
    role: str
    key_id: str
    public: Ed25519PublicKey
    public_hex: str


def load_keyring(path: Path, *, test_mode: bool = False) -> tuple[dict[str, RoleKey], dict[str, Any]]:
    doc = read_json(path)
    require_exact_keys(
        doc,
        {"schema_version", "kind", "exact_revision", "is_test_fixture", "keys", "role_label_notice"},
        "role keyring",
    )
    if doc["schema_version"] != 1 or doc["kind"] != "noosphere-role-keyring-v1":
        raise AuthorizationError("role keyring: wrong kind/version")
    require_revision(doc["exact_revision"], "role keyring exact_revision")
    require_non_fixture(doc, "role keyring", test_mode=test_mode)
    if doc.get("role_label_notice") != "A cryptographic role label does not establish human identity or independence.":
        raise AuthorizationError("role keyring: required human-independence limitation missing")
    keys: dict[str, RoleKey] = {}
    key_ids: set[str] = set()
    public_values: set[str] = set()
    if not isinstance(doc["keys"], list) or not doc["keys"]:
        raise AuthorizationError("role keyring: keys must be a non-empty list")
    for entry in doc["keys"]:
        if not isinstance(entry, dict):
            raise AuthorizationError("role keyring: malformed key entry")
        require_exact_keys(entry, {"role", "key_id", "public_key_ed25519_hex"}, "role key")
        role, key_id, public_hex = entry["role"], entry["key_id"], entry["public_key_ed25519_hex"]
        if not all(isinstance(x, str) and x for x in (role, key_id, public_hex)):
            raise AuthorizationError("role keyring: empty role/key field")
        if role in keys or key_id in key_ids or public_hex in public_values:
            raise AuthorizationError("role keyring: roles, key IDs, and public keys must be unique")
        try:
            raw = bytes.fromhex(public_hex)
            public = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise AuthorizationError(f"role keyring: invalid Ed25519 key for {role}") from exc
        if len(raw) != 32:
            raise AuthorizationError(f"role keyring: invalid Ed25519 key length for {role}")
        keys[role] = RoleKey(role, key_id, public, public_hex)
        key_ids.add(key_id)
        public_values.add(public_hex)
    return keys, doc


def load_private_role_key(path: Path, role: RoleKey, *, test_mode: bool = False) -> Ed25519PrivateKey:
    """Load an owner-supplied PEM or closed JSON seed record; never generate."""
    raw = path.read_bytes()
    private: Ed25519PrivateKey
    if raw.lstrip().startswith(b"-----BEGIN"):
        try:
            loaded = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError) as exc:
            raise AuthorizationError(f"{path}: Ed25519 PEM load failed") from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise AuthorizationError(f"{path}: private key is not Ed25519")
        private = loaded
    else:
        doc = read_json(path)
        require_exact_keys(
            doc,
            {"schema_version", "kind", "role", "key_id", "private_key_seed_hex", "is_test_fixture"},
            "private role key",
        )
        require_non_fixture(doc, "private role key", test_mode=test_mode)
        if doc["schema_version"] != 1 or doc["kind"] != "noosphere-ed25519-private-role-key-v1":
            raise AuthorizationError(f"{path}: wrong private role key kind/version")
        if doc["role"] != role.role or doc["key_id"] != role.key_id:
            raise AuthorizationError(f"{path}: private key role/key ID does not match keyring")
        try:
            seed = bytes.fromhex(doc["private_key_seed_hex"])
            private = Ed25519PrivateKey.from_private_bytes(seed)
        except (ValueError, TypeError) as exc:
            raise AuthorizationError(f"{path}: invalid Ed25519 private seed") from exc
        if len(seed) != 32:
            raise AuthorizationError(f"{path}: Ed25519 seed must be 32 bytes")
    derived = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if derived != role.public_hex:
        raise AuthorizationError(f"{path}: private key does not match keyring role {role.role}")
    return private


def signature_message(domain: str, payload: bytes) -> bytes:
    return domain.encode("ascii") + b"\x00" + payload


def make_detached_signatures(
    payload: bytes,
    domain: str,
    exact_revision: str,
    required_roles: Sequence[str],
    keyring: Mapping[str, RoleKey],
    private_paths: Mapping[str, Path],
    *,
    test_mode: bool = False,
) -> dict[str, Any]:
    require_revision(exact_revision)
    if set(private_paths) != set(required_roles):
        raise AuthorizationError(
            f"role key set mismatch; required={sorted(required_roles)} supplied={sorted(private_paths)}"
        )
    signatures = []
    message = signature_message(domain, payload)
    for role_name in required_roles:
        if role_name not in keyring:
            raise AuthorizationError(f"role keyring missing required role {role_name}")
        role = keyring[role_name]
        private = load_private_role_key(private_paths[role_name], role, test_mode=test_mode)
        signatures.append(
            {
                "role": role.role,
                "key_id": role.key_id,
                "signature_ed25519_hex": private.sign(message).hex(),
            }
        )
    return {
        "schema_version": 1,
        "kind": "noosphere-detached-role-signatures-v1",
        "algorithm": "ed25519",
        "domain": domain,
        "payload_sha256": sha256(payload),
        "exact_revision": exact_revision,
        "required_roles": list(required_roles),
        "role_label_notice": "Signatures authorize bytes for named roles; they do not prove that a signer is an independent human.",
        "signatures": signatures,
    }


def verify_detached_signatures(
    payload: bytes,
    record: Mapping[str, Any],
    domain: str,
    exact_revision: str,
    required_roles: Sequence[str],
    keyring: Mapping[str, RoleKey],
) -> None:
    require_exact_keys(
        record,
        {
            "schema_version", "kind", "algorithm", "domain", "payload_sha256", "exact_revision",
            "required_roles", "role_label_notice", "signatures",
        },
        "detached signature record",
    )
    if record["schema_version"] != 1 or record["kind"] != "noosphere-detached-role-signatures-v1":
        raise AuthorizationError("detached signature record: wrong kind/version")
    if record["algorithm"] != "ed25519" or record["domain"] != domain:
        raise AuthorizationError("detached signature record: algorithm/domain mismatch")
    if record["payload_sha256"] != sha256(payload):
        raise AuthorizationError("detached signature record: payload hash mismatch")
    if record["exact_revision"] != exact_revision:
        raise AuthorizationError("detached signature record: stale revision")
    if record["required_roles"] != list(required_roles):
        raise AuthorizationError("detached signature record: required role sequence mismatch")
    if record.get("role_label_notice") != "Signatures authorize bytes for named roles; they do not prove that a signer is an independent human.":
        raise AuthorizationError("detached signature record: human-independence limitation missing")
    entries = record["signatures"]
    if not isinstance(entries, list):
        raise AuthorizationError("detached signature record: signatures must be a list")
    by_role: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise AuthorizationError("detached signature record: malformed signature")
        require_exact_keys(entry, {"role", "key_id", "signature_ed25519_hex"}, "signature entry")
        role_name = entry["role"]
        if role_name in by_role:
            raise AuthorizationError(f"detached signature record: duplicate role {role_name}")
        by_role[role_name] = entry
    if set(by_role) != set(required_roles):
        raise AuthorizationError(
            f"detached signature record: missing/extra role; required={sorted(required_roles)} got={sorted(by_role)}"
        )
    message = signature_message(domain, payload)
    for role_name in required_roles:
        role = keyring.get(role_name)
        if role is None:
            raise AuthorizationError(f"role keyring missing required role {role_name}")
        entry = by_role[role_name]
        if entry["key_id"] != role.key_id:
            raise AuthorizationError(f"detached signature record: key ID mismatch for {role_name}")
        try:
            signature = bytes.fromhex(entry["signature_ed25519_hex"])
            role.public.verify(signature, message)
        except (ValueError, InvalidSignature) as exc:
            raise AuthorizationError(f"detached signature record: invalid signature for {role_name}") from exc


def parse_role_paths(values: Sequence[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise AuthorizationError("role key arguments must be ROLE=PATH")
        role, raw_path = value.split("=", 1)
        if not role or role in result or not raw_path:
            raise AuthorizationError(f"invalid/duplicate role key argument: {value!r}")
        result[role] = Path(raw_path)
    return result


# ---------------------------------------------------------------------------
# Mainnet parameter freeze and signed reproducibility policy
# ---------------------------------------------------------------------------

ZERO_CONTROLS = {
    "work_loom_credit_enabled": False,
    "work_loom_weight_cap": 0,
    "witness_proofpower_bonus_enabled": False,
    "neural_lane_enabled": False,
    "reflex_lane_enabled": False,
    "umbra_suite_enabled": False,
    "dream_lane_enabled": False,
    "class_gate_irreversible_budget": 0,
}


def _uint(value: Any, bits: int, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise AuthorizationError(f"{context}: expected u{bits}")
    return value


def _le(value: Any, width: int, context: str) -> bytes:
    return _uint(value, width * 8, context).to_bytes(width, "little")


def _hex32(value: Any, context: str) -> bytes:
    return bytes.fromhex(require_hash(value, context))


def _bounded_bytes(value: Any, maximum: int, context: str) -> bytes:
    if not isinstance(value, str):
        raise AuthorizationError(f"{context}: expected string")
    raw = value.encode("utf-8")
    if not raw or len(raw) > maximum:
        raise AuthorizationError(f"{context}: UTF-8 length must be 1..{maximum}")
    return len(raw).to_bytes(4, "little") + raw


def validate_mainnet_parameters(doc: Mapping[str, Any], *, test_mode: bool = False) -> None:
    require_non_fixture(doc, "mainnet parameters", test_mode=test_mode)
    if doc.get("schema_version") != 1 or doc.get("is_test_network") is not False:
        raise AuthorizationError("mainnet parameters: schema_version=1 and is_test_network=false required")
    if doc.get("is_template") is not False or doc.get("owner_signed") is not True:
        raise AuthorizationError("mainnet parameters: production file must be non-template and owner_signed=true")
    token = doc.get("token", {})
    if token != {"symbol": "NOOS", "decimals": 6, "base_unit": "micro-NOOS"}:
        raise AuthorizationError("mainnet parameters: frozen token identity mismatch")
    consensus = doc.get("consensus", {})
    frozen_consensus = {
        "slot_seconds": 6, "epoch_length": 256, "max_slot_skip": 20,
        "median_time_past_blocks": 11, "witness_membership_lookback_epochs": 2,
        "pulse_target_spacing_seconds": 6, "pulse_half_life_seconds": 3600,
    }
    for key, expected in frozen_consensus.items():
        if consensus.get(key) != expected:
            raise AuthorizationError(f"mainnet parameters: consensus.{key} must equal frozen value {expected}")
    if consensus.get("max_future_drift_ms") not in {12_000, 18_000, 30_000}:
        raise AuthorizationError("mainnet parameters: max_future_drift_ms must be an owner-selected E-WAN candidate")
    ring = doc.get("witness_ring", {})
    if (ring.get("n_max"), ring.get("n_tail"), ring.get("n_hard")) != (256, 32, 1024):
        raise AuthorizationError("mainnet parameters: frozen witness caps mismatch")
    _uint(ring.get("min_bond_micro_noos"), 128, "witness_ring.min_bond_micro_noos")
    if ring.get("min_bond_micro_noos") == 1_000_000_000_000:
        raise AuthorizationError("mainnet parameters: known valueless devnet bond fixture refused")
    controls = doc.get("controls", {})
    for key, expected in ZERO_CONTROLS.items():
        if controls.get(key) != expected:
            raise AuthorizationError(f"mainnet parameters: controls.{key} must be {expected!r} at genesis")
    emission = doc.get("emission", {})
    max_supply = _uint(emission.get("max_supply_micro_noos"), 128, "emission.max_supply_micro_noos")
    terminal = _uint(emission.get("emission_terminal_height"), 64, "emission.emission_terminal_height")
    if max_supply == 0 or terminal == 0:
        raise AuthorizationError("mainnet parameters: placeholder zero economics refused")
    _hex32(emission.get("emission_table_root"), "emission.emission_table_root")
    shares = [
        _uint(emission.get(name), 16, f"emission.{name}")
        for name in ("recipient_share_ground_bp", "recipient_share_witness_bp", "recipient_share_treasury_bp")
    ]
    if sum(shares) != 10_000:
        raise AuthorizationError("mainnet parameters: recipient shares must sum to 10000 bp")
    _uint(emission.get("rounding_rule_id"), 8, "emission.rounding_rule_id")
    _uint(emission.get("fee_disposition_id"), 8, "emission.fee_disposition_id")
    _hex32(doc.get("allocations", {}).get("allocations_root"), "allocations.allocations_root")
    for name in ("claim_registry_root", "conformance_vector_root", "software_manifest_root"):
        _hex32(doc.get("commitments", {}).get(name), f"commitments.{name}")
    dkg = doc.get("dkg", {})
    participants = _uint(dkg.get("participants"), 16, "dkg.participants")
    threshold = _uint(dkg.get("threshold"), 16, "dkg.threshold")
    if participants < 2 or threshold < 2 or threshold > participants:
        raise AuthorizationError("mainnet parameters: DKG requires 2 <= threshold <= participants")
    auth = doc.get("authorization", {})
    require_revision(auth.get("exact_revision"), "authorization.exact_revision")
    for key in ("role_keyring_path", "signed_repro_policy_record_path"):
        if not isinstance(auth.get(key), str) or not auth[key]:
            raise AuthorizationError(f"mainnet parameters: authorization.{key} missing")
    signatures = doc.get("signatures", {})
    if signatures.get("required_roles") != list(FREEZE_ROLES):
        raise AuthorizationError("mainnet parameters: exact freeze role sequence mismatch")
    if not isinstance(signatures.get("record_path"), str) or not signatures["record_path"]:
        raise AuthorizationError("mainnet parameters: signatures.record_path missing")


def canonical_mainnet_manifest(doc: Mapping[str, Any], *, test_mode: bool = False) -> bytes:
    """Canonical GenesisParameterManifestV1 bytes from spec section 3."""
    validate_mainnet_parameters(doc, test_mode=test_mode)
    consensus = doc["consensus"]
    ring = doc["witness_ring"]
    controls = doc["controls"]
    emission = doc["emission"]
    out = bytearray()
    out += _le(1, 2, "manifest.version")
    out += _bounded_bytes(doc["chain_name"], 64, "chain_name")
    out += b"\x00"  # is_test_network=false
    out += _le(doc["token"]["decimals"], 1, "token.decimals")
    out += _le(consensus["slot_seconds"] * 1000, 4, "slot_ms")
    out += _le(consensus["epoch_length"], 4, "epoch_length")
    out += _le(consensus["max_slot_skip"], 4, "max_slot_skip")
    out += _le(consensus["median_time_past_blocks"], 2, "median_time_past_blocks")
    out += _le(consensus["witness_membership_lookback_epochs"], 2, "witness_membership_lookback_epochs")
    out += _le(consensus["pulse_target_spacing_seconds"] * 1000, 4, "pulse_target_spacing_ms")
    out += _le(consensus["pulse_half_life_seconds"], 4, "pulse_half_life_s")
    out += _le(consensus["max_future_drift_ms"], 4, "max_future_drift_ms")
    out += _le(ring["n_max"], 4, "witness_n_max")
    out += _le(ring["n_tail"], 4, "witness_n_tail")
    out += _le(ring["n_hard"], 4, "witness_n_hard")
    out += _le(ring["min_bond_micro_noos"], 16, "min_witness_bond_micro")
    out += bytes([int(controls["work_loom_credit_enabled"])])
    out += _le(controls["work_loom_weight_cap"], 2, "work_loom_weight_cap_permille")
    out += bytes([int(controls["witness_proofpower_bonus_enabled"])])
    out += (0).to_bytes(4, "little")  # empty umbra suite list
    out += bytes([int(controls["dream_lane_enabled"])])
    out += bytes([int(controls["neural_lane_enabled"])])
    out += bytes([int(controls["reflex_lane_enabled"])])
    out += _le(controls["class_gate_irreversible_budget"], 8, "class_gate_irreversible_budget")
    out += _le(emission["max_supply_micro_noos"], 16, "max_supply_micro")
    out += _le(emission["emission_terminal_height"], 8, "emission_terminal_height")
    out += _hex32(emission["emission_table_root"], "emission_table_root")
    for name in ("recipient_share_ground_bp", "recipient_share_witness_bp", "recipient_share_treasury_bp"):
        out += _le(emission[name], 2, name)
    out += _le(emission["rounding_rule_id"], 1, "rounding_rule_id")
    out += _le(emission["fee_disposition_id"], 1, "fee_disposition_id")
    out += _hex32(doc["allocations"]["allocations_root"], "allocations_root")
    for name in ("claim_registry_root", "conformance_vector_root", "software_manifest_root"):
        out += _hex32(doc["commitments"][name], name)
    return bytes(out)


def verify_signed_repro_policy(
    policy_path: Path,
    signature_path: Path,
    keyring: Mapping[str, RoleKey],
    exact_revision: str,
) -> None:
    policy = read_toml(policy_path)
    require_non_fixture(policy, "signed reproducibility policy")
    if policy.get("state") != "SIGNED":
        raise AuthorizationError("reproducibility policy state is not SIGNED")
    sig_policy = policy.get("signature_policy", {})
    if sig_policy.get("detached_signature_algorithm") != "ed25519":
        raise AuthorizationError("reproducibility policy does not require Ed25519")
    roles = sig_policy.get("required_roles")
    if roles != list(FREEZE_ROLES):
        raise AuthorizationError("reproducibility policy required roles mismatch")
    verify_detached_signatures(
        policy_path.read_bytes(), read_json(signature_path), DOMAIN_REPRO_POLICY,
        exact_revision, FREEZE_ROLES, keyring,
    )


def build_freeze_manifest(
    params_path: Path,
    policy_path: Path,
    policy_signature_path: Path,
    keyring_path: Path,
    *,
    test_mode: bool = False,
) -> tuple[dict[str, Any], dict[str, RoleKey]]:
    params = read_toml(params_path)
    canonical = canonical_mainnet_manifest(params, test_mode=test_mode)
    revision = params["authorization"]["exact_revision"]
    if not test_mode:
        require_current_revision(revision)
    keyring, keyring_doc = load_keyring(keyring_path, test_mode=test_mode)
    if keyring_doc["exact_revision"] != revision:
        raise AuthorizationError("role keyring revision does not match parameters")
    configured_keyring = Path(params["authorization"]["role_keyring_path"])
    configured_policy_record = Path(params["authorization"]["signed_repro_policy_record_path"])
    if not configured_keyring.is_absolute():
        configured_keyring = ROOT / configured_keyring
    if not configured_policy_record.is_absolute():
        configured_policy_record = ROOT / configured_policy_record
    try:
        if configured_keyring.resolve() != keyring_path.resolve():
            raise AuthorizationError("parameters bind a different role keyring path")
        if configured_policy_record.resolve() != policy_signature_path.resolve():
            raise AuthorizationError("parameters bind a different reproducibility-policy signature path")
    except OSError as exc:
        raise AuthorizationError(f"authorization path resolution failed: {exc}") from exc
    verify_signed_repro_policy(policy_path, policy_signature_path, keyring, revision)
    manifest_hash = domain_hash(b"NOOS/GENESIS/PARAMS/V1", canonical).hex()
    chain_id = domain_hash(b"NOOS/CHAIN/V1", bytes.fromhex(manifest_hash)).hex()
    freeze = {
        "schema_version": 1,
        "kind": "noosphere-canonical-parameter-freeze-v1",
        "exact_revision": revision,
        "source_parameters_sha256": file_sha256(params_path),
        "canonical_encoding": "GenesisParameterManifestV1/spec-v1-fixed-order-little-endian",
        "canonical_manifest_bytes_hex": canonical.hex(),
        "parameter_manifest_hash": manifest_hash,
        "chain_id": chain_id,
        "claim_registry_root": params["commitments"]["claim_registry_root"],
        "conformance_vector_root": params["commitments"]["conformance_vector_root"],
        "software_manifest_root": params["commitments"]["software_manifest_root"],
        "role_keyring_sha256": file_sha256(keyring_path),
        "repro_policy_sha256": file_sha256(policy_path),
        "repro_policy_signatures_sha256": file_sha256(policy_signature_path),
        "is_test_fixture": bool(test_mode),
        "assurance_limit": "This freeze records signed bytes; role labels do not establish human independence or satisfy promotion gates.",
    }
    require_non_fixture(freeze, "freeze manifest", test_mode=test_mode)
    return freeze, keyring


def verify_freeze_manifest(
    freeze: Mapping[str, Any],
    signatures: Mapping[str, Any],
    keyring: Mapping[str, RoleKey],
    *,
    test_mode: bool = False,
) -> None:
    require_non_fixture(freeze, "freeze manifest", test_mode=test_mode)
    revision = require_revision(freeze.get("exact_revision"))
    canonical = bytes.fromhex(freeze.get("canonical_manifest_bytes_hex", ""))
    if domain_hash(b"NOOS/GENESIS/PARAMS/V1", canonical).hex() != freeze.get("parameter_manifest_hash"):
        raise AuthorizationError("freeze manifest: parameter manifest hash mismatch")
    if domain_hash(b"NOOS/CHAIN/V1", bytes.fromhex(freeze["parameter_manifest_hash"])).hex() != freeze.get("chain_id"):
        raise AuthorizationError("freeze manifest: chain ID mismatch")
    verify_detached_signatures(canonical_json(freeze), signatures, DOMAIN_FREEZE, revision, FREEZE_ROLES, keyring)


def verify_mainnet_params_binding(
    params: Mapping[str, Any], params_path: Path, freeze: Mapping[str, Any]
) -> None:
    canonical = canonical_mainnet_manifest(params)
    if canonical.hex() != freeze.get("canonical_manifest_bytes_hex"):
        raise AuthorizationError("mainnet parameter canonical bytes do not match signed freeze")
    if file_sha256(params_path) != freeze.get("source_parameters_sha256"):
        raise AuthorizationError("mainnet parameter source bytes do not match signed freeze")


# ---------------------------------------------------------------------------
# Quiet-week publication records and live-clock verification
# ---------------------------------------------------------------------------

def fetch_public_bytes(url: str, timeout: float = 20.0) -> tuple[bytes, str | None]:
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        raise AuthorizationError("public publication URL must use https://")
    request = urllib.request.Request(url, headers={"User-Agent": "noosphere-genesis-verifier/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise AuthorizationError(f"publication fetch returned HTTP {response.status}")
            return response.read(), response.headers.get("Date")
    except (OSError, urllib.error.URLError) as exc:
        raise AuthorizationError(f"publication fetch failed: {exc}") from exc


def make_publication_record(
    freeze: Mapping[str, Any],
    publication_url: str,
    published_bytes: bytes,
    observed_at: dt.datetime,
    *,
    http_date: str | None = None,
    test_mode: bool = False,
) -> dict[str, Any]:
    require_non_fixture(freeze, "freeze manifest", test_mode=test_mode)
    expected = sha256(canonical_json(freeze) + b"\n")
    if sha256(published_bytes) != expected:
        raise AuthorizationError("published payload does not byte-match canonical freeze file")
    if not test_mode and not publication_url.lower().startswith("https://"):
        raise AuthorizationError("production publication requires HTTPS")
    return {
        "schema_version": 1,
        "kind": "noosphere-quiet-week-publication-v1",
        "exact_revision": freeze["exact_revision"],
        "freeze_file_sha256": expected,
        "parameter_manifest_hash": freeze["parameter_manifest_hash"],
        "chain_id": freeze["chain_id"],
        "publication_url": publication_url,
        "first_observed_at_utc": utc_text(observed_at),
        "http_date_at_first_observation": http_date,
        "clock_source": "live-system-utc" if not test_mode else "explicit-test-clock",
        "is_test_fixture": bool(test_mode),
        "assurance_limit": "This record proves a signed observation time, not continuous availability between observations.",
    }


def verify_quiet_week(
    record: Mapping[str, Any],
    signatures: Mapping[str, Any],
    freeze: Mapping[str, Any],
    keyring: Mapping[str, RoleKey],
    live_published_bytes: bytes,
    *,
    now: dt.datetime | None = None,
    test_mode: bool = False,
) -> int:
    require_non_fixture(record, "publication record", test_mode=test_mode)
    if record.get("kind") != "noosphere-quiet-week-publication-v1":
        raise AuthorizationError("publication record kind mismatch")
    if record.get("exact_revision") != freeze.get("exact_revision"):
        raise AuthorizationError("publication record: stale revision")
    expected_freeze_file = sha256(canonical_json(freeze) + b"\n")
    if record.get("freeze_file_sha256") != expected_freeze_file:
        raise AuthorizationError("publication record: freeze hash mismatch")
    if sha256(live_published_bytes) != expected_freeze_file:
        raise AuthorizationError("quiet-week live publication bytes changed or disappeared")
    verify_detached_signatures(
        canonical_json(record), signatures, DOMAIN_PUBLICATION,
        freeze["exact_revision"], FREEZE_ROLES, keyring,
    )
    if now is not None and not test_mode:
        raise AuthorizationError("production quiet-week verification cannot override live time")
    current = now if now is not None else utc_now()
    first = parse_utc(record.get("first_observed_at_utc"), "first_observed_at_utc")
    elapsed = int((current - first).total_seconds())
    if elapsed < 0:
        raise AuthorizationError("publication observation is in the future")
    if elapsed < QUIET_WEEK_SECONDS:
        raise AuthorizationError(
            f"quiet week has not elapsed in real time: {elapsed}s observed, {QUIET_WEEK_SECONDS}s required"
        )
    return elapsed


# ---------------------------------------------------------------------------
# Bitcoin header / PoW / linked-chain anchor verification
# ---------------------------------------------------------------------------

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    negative = bool(bits & 0x00800000)
    if negative or mantissa == 0:
        raise AuthorizationError("Bitcoin compact target is negative or zero")
    target = mantissa >> (8 * (3 - exponent)) if exponent <= 3 else mantissa << (8 * (exponent - 3))
    if target <= 0 or target.bit_length() > 256:
        raise AuthorizationError("Bitcoin compact target overflows uint256")
    return target


def header_fields(header_hex: str) -> dict[str, Any]:
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError as exc:
        raise AuthorizationError("Bitcoin header is not hex") from exc
    if len(raw) != 80:
        raise AuthorizationError("Bitcoin header must be exactly 80 bytes")
    digest_internal = double_sha256(raw)
    bits = int.from_bytes(raw[72:76], "little")
    target = compact_target(bits)
    return {
        "raw": raw,
        "hash_internal": digest_internal,
        "hash_display": digest_internal[::-1].hex(),
        "previous_internal": raw[4:36],
        "timestamp": int.from_bytes(raw[68:72], "little"),
        "bits": bits,
        "target": target,
        "work": (1 << 256) // (target + 1),
    }


def verify_bitcoin_anchor_bundle(
    bundle: Mapping[str, Any],
    publication: Mapping[str, Any],
    *,
    test_mode: bool = False,
) -> dict[str, Any]:
    require_non_fixture(bundle, "Bitcoin anchor bundle", test_mode=test_mode)
    if bundle.get("kind") != "noosphere-bitcoin-anchor-chain-v1" or bundle.get("schema_version") != 1:
        raise AuthorizationError("Bitcoin anchor bundle kind/version mismatch")
    if bundle.get("exact_revision") != publication.get("exact_revision"):
        raise AuthorizationError("Bitcoin anchor bundle: stale revision")
    checkpoint = bundle.get("trusted_checkpoint")
    headers = bundle.get("headers")
    if not isinstance(checkpoint, dict) or not isinstance(headers, list) or not headers:
        raise AuthorizationError("Bitcoin anchor bundle requires checkpoint and non-empty headers")
    checkpoint_height = _uint(checkpoint.get("height"), 32, "trusted checkpoint height")
    checkpoint_header = header_fields(checkpoint.get("header_hex", ""))
    if checkpoint_header["hash_display"] != checkpoint.get("block_hash_display_hex"):
        raise AuthorizationError("trusted checkpoint header hash mismatch")
    pow_limit = (1 << 255) - 1 if test_mode else BITCOIN_MAINNET_POW_LIMIT
    if checkpoint_header["target"] > pow_limit:
        raise AuthorizationError("trusted checkpoint target exceeds Bitcoin mainnet PoW limit")
    if int.from_bytes(checkpoint_header["hash_internal"], "little") > checkpoint_header["target"]:
        raise AuthorizationError("trusted checkpoint proof of work invalid")
    previous = checkpoint_header
    previous_height = checkpoint_height
    chainwork = 0
    quiet_end = parse_utc(publication.get("first_observed_at_utc"), "first_observed_at_utc") + dt.timedelta(seconds=QUIET_WEEK_SECONDS)
    for position, entry in enumerate(headers):
        if not isinstance(entry, dict) or set(entry) != {"height", "header_hex"}:
            raise AuthorizationError(f"Bitcoin header {position}: exact height/header_hex fields required")
        height = _uint(entry["height"], 32, f"Bitcoin header {position} height")
        if height != previous_height + 1:
            raise AuthorizationError("Bitcoin header heights must be contiguous and ordered")
        current = header_fields(entry["header_hex"])
        if current["previous_internal"] != previous["hash_internal"]:
            raise AuthorizationError("Bitcoin header chain link mismatch")
        if current["target"] > pow_limit:
            raise AuthorizationError("Bitcoin header target exceeds Bitcoin mainnet PoW limit")
        if int.from_bytes(current["hash_internal"], "little") > current["target"]:
            raise AuthorizationError("Bitcoin header proof of work invalid")
        if height % 2016 == 0:
            raise AuthorizationError("bundle crosses a Bitcoin retarget boundary; supply a trusted checkpoint after it")
        if current["bits"] != previous["bits"]:
            raise AuthorizationError("Bitcoin difficulty bits changed outside a retarget boundary")
        if dt.datetime.fromtimestamp(current["timestamp"], dt.timezone.utc) < quiet_end:
            raise AuthorizationError("Bitcoin anchor chain includes a pre-quiet-week header")
        chainwork += current["work"]
        previous, previous_height = current, height
    if previous_height != bundle.get("anchor_height") or previous["hash_display"] != bundle.get("anchor_hash_display_hex"):
        raise AuthorizationError("Bitcoin anchor does not match final validated header")
    minimum_chainwork_hex = bundle.get("minimum_chainwork_hex")
    if not isinstance(minimum_chainwork_hex, str) or not re.fullmatch(r"[0-9a-f]{1,64}", minimum_chainwork_hex):
        raise AuthorizationError("Bitcoin bundle requires explicit minimum_chainwork_hex")
    if chainwork < int(minimum_chainwork_hex, 16):
        raise AuthorizationError("Bitcoin header chainwork below supplied minimum")
    observed = parse_utc(bundle.get("anchor_observed_at_utc"), "anchor_observed_at_utc")
    if observed < quiet_end:
        raise AuthorizationError("Bitcoin anchor was observed before Quiet Week completed")
    header_time = dt.datetime.fromtimestamp(previous["timestamp"], dt.timezone.utc)
    if header_time > observed + dt.timedelta(hours=2):
        raise AuthorizationError("Bitcoin anchor header time is implausibly after its observation")
    return {
        "height": previous_height,
        "block_hash_display_hex": previous["hash_display"],
        "block_hash_internal_hex": previous["hash_internal"].hex(),
        "header_time_utc": utc_text(dt.datetime.fromtimestamp(previous["timestamp"], dt.timezone.utc)),
        "observed_at_utc": utc_text(observed),
        "validated_chainwork_hex": f"{chainwork:x}",
    }


def verify_signed_bitcoin_anchor(
    bundle: Mapping[str, Any], signatures: Mapping[str, Any],
    keyring: Mapping[str, RoleKey], exact_revision: str,
) -> None:
    verify_detached_signatures(
        canonical_json(bundle), signatures, DOMAIN_BITCOIN_ANCHOR,
        exact_revision, FREEZE_ROLES, keyring,
    )


# ---------------------------------------------------------------------------
# Dealerless Feldman DKG records
# ---------------------------------------------------------------------------

def _bls_imports():
    try:
        from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
        from py_ecc.optimized_bls12_381 import G1, Z1, add, curve_order, multiply, normalize
    except ImportError as exc:  # pragma: no cover
        raise AuthorizationError(f"py_ecc is required for DKG verification: {exc}") from exc
    return G1_to_pubkey, pubkey_to_G1, G1, Z1, add, curve_order, multiply, normalize


def validate_dkg_descriptor(
    descriptor: Mapping[str, Any],
    signatures: Mapping[str, Any],
    keyring: Mapping[str, RoleKey],
    freeze: Mapping[str, Any],
    *,
    test_mode: bool = False,
) -> list[dict[str, Any]]:
    require_non_fixture(descriptor, "DKG descriptor", test_mode=test_mode)
    require_exact_keys(
        descriptor,
        {"schema_version", "kind", "ceremony_id", "exact_revision", "freeze_manifest_sha256", "quiet_week_publication_sha256", "authorized_at_utc", "chain_id", "threshold", "participants", "is_test_fixture", "assurance_limit"},
        "DKG descriptor",
    )
    if descriptor["schema_version"] != 1 or descriptor["kind"] != "noosphere-dealerless-dkg-v1":
        raise AuthorizationError("DKG descriptor kind/version mismatch")
    revision = require_revision(descriptor["exact_revision"])
    if revision != freeze.get("exact_revision") or descriptor["chain_id"] != freeze.get("chain_id"):
        raise AuthorizationError("DKG descriptor freeze identity mismatch")
    if descriptor["freeze_manifest_sha256"] != sha256(canonical_json(freeze) + b"\n"):
        raise AuthorizationError("DKG descriptor freeze hash mismatch")
    parse_utc(descriptor["authorized_at_utc"], "DKG descriptor authorized_at_utc")
    participants = descriptor["participants"]
    if not isinstance(participants, list) or len(participants) < 2:
        raise AuthorizationError("DKG descriptor requires multiple participants")
    threshold = _uint(descriptor["threshold"], 16, "DKG threshold")
    if not 2 <= threshold <= len(participants):
        raise AuthorizationError("DKG threshold must satisfy 2 <= threshold <= participants")
    expected_indices = list(range(1, len(participants) + 1))
    ids: set[str] = set()
    roles: set[str] = set()
    for expected_index, participant in zip(expected_indices, participants):
        if not isinstance(participant, dict):
            raise AuthorizationError("DKG participant entry malformed")
        require_exact_keys(participant, {"participant_id", "index", "signing_role"}, "DKG participant")
        if participant["index"] != expected_index:
            raise AuthorizationError("DKG participants must be ordered by contiguous index")
        pid, role = participant["participant_id"], participant["signing_role"]
        if not isinstance(pid, str) or not pid or not isinstance(role, str) or role != f"dkg-participant:{pid}":
            raise AuthorizationError("DKG participant role must be dkg-participant:<participant_id>")
        if pid in ids or role in roles or role not in keyring:
            raise AuthorizationError("DKG participant identity/role is duplicate or absent from keyring")
        ids.add(pid); roles.add(role)
    expected_ceremony = domain_hash(
        b"NOOS/DKG/CEREMONY-ID/V1",
        bytes.fromhex(freeze["chain_id"]),
        canonical_json({
            "freeze_manifest_sha256": descriptor["freeze_manifest_sha256"],
            "quiet_week_publication_sha256": descriptor["quiet_week_publication_sha256"],
            "authorized_at_utc": descriptor["authorized_at_utc"],
            "threshold": threshold,
            "participants": participants,
        }),
    ).hex()
    if descriptor["ceremony_id"] != expected_ceremony:
        raise AuthorizationError("DKG descriptor ceremony_id mismatch")
    verify_detached_signatures(canonical_json(descriptor), signatures, DOMAIN_DKG_DESCRIPTOR, revision, FREEZE_ROLES, keyring)
    return participants


def verify_dkg_publication_sequence(
    transcript: Mapping[str, Any], publication: Mapping[str, Any],
    *, genesis_time_ms: int | None = None,
) -> None:
    descriptor = transcript.get("descriptor", {})
    expected_publication_hash = sha256(canonical_json(publication) + b"\n")
    if descriptor.get("quiet_week_publication_sha256") != expected_publication_hash:
        raise AuthorizationError("DKG descriptor does not bind the signed Quiet Week publication record")
    quiet_end = parse_utc(publication.get("first_observed_at_utc"), "first_observed_at_utc") + dt.timedelta(seconds=QUIET_WEEK_SECONDS)
    authorized = parse_utc(descriptor.get("authorized_at_utc"), "DKG descriptor authorized_at_utc")
    if authorized < quiet_end:
        raise AuthorizationError("DKG descriptor was authorized before Quiet Week completed")
    genesis_time = None if genesis_time_ms is None else dt.datetime.fromtimestamp(genesis_time_ms / 1000, dt.timezone.utc)
    for record in transcript.get("erasure_confirmations", []):
        payload = record.get("payload", {})
        confirmed = parse_utc(payload.get("confirmed_at_utc"), "DKG erasure confirmed_at_utc")
        if confirmed < authorized:
            raise AuthorizationError("DKG erasure attestation predates ceremony authorization")
        if genesis_time is not None and confirmed > genesis_time:
            raise AuthorizationError("DKG erasure attestation occurs after declared genesis time")


def _signed_record(payload: Mapping[str, Any], role: RoleKey, private: Ed25519PrivateKey) -> dict[str, Any]:
    raw = canonical_json(payload)
    return {
        "payload": dict(payload),
        "signer_role": role.role,
        "key_id": role.key_id,
        "signature_ed25519_hex": private.sign(signature_message(DOMAIN_DKG_RECORD, raw)).hex(),
    }


def _verify_signed_record(record: Mapping[str, Any], keyring: Mapping[str, RoleKey]) -> Mapping[str, Any]:
    require_exact_keys(record, {"payload", "signer_role", "key_id", "signature_ed25519_hex"}, "DKG signed record")
    payload = record["payload"]
    if not isinstance(payload, dict):
        raise AuthorizationError("DKG signed record payload malformed")
    role = keyring.get(record["signer_role"])
    if role is None or role.key_id != record["key_id"]:
        raise AuthorizationError("DKG signed record signer absent/mismatched in keyring")
    try:
        role.public.verify(
            bytes.fromhex(record["signature_ed25519_hex"]),
            signature_message(DOMAIN_DKG_RECORD, canonical_json(payload)),
        )
    except (ValueError, InvalidSignature) as exc:
        raise AuthorizationError(f"DKG signed record invalid for {role.role}") from exc
    return payload


def dkg_contribution(
    descriptor: Mapping[str, Any],
    participant_id: str,
    role: RoleKey,
    private: Ed25519PrivateKey,
    *,
    coefficients: Sequence[int] | None = None,
    test_mode: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    G1_to_pubkey, _, G1, _, _, curve_order, multiply, _ = _bls_imports()
    participants = descriptor["participants"]
    participant = next((p for p in participants if p["participant_id"] == participant_id), None)
    if participant is None or role.role != participant["signing_role"]:
        raise AuthorizationError("DKG contribution participant/role mismatch")
    threshold = descriptor["threshold"]
    if coefficients is not None and not test_mode:
        raise AuthorizationError("production DKG coefficients cannot be injected")
    if coefficients is None:
        coefficients = [secrets.randbelow(curve_order - 1) + 1 for _ in range(threshold)]
        randomness = "python-secrets/os-csprng"
    else:
        randomness = "deterministic-test-fixture"
    if len(coefficients) != threshold or any(not 0 < c < curve_order for c in coefficients):
        raise AuthorizationError("DKG polynomial coefficients invalid")
    commitments = [G1_to_pubkey(multiply(G1, c)).hex() for c in coefficients]
    context = {
        "ceremony_id": descriptor["ceremony_id"],
        "exact_revision": descriptor["exact_revision"],
        "chain_id": descriptor["chain_id"],
        "participant_set_sha256": sha256(canonical_json(participants)),
    }
    public_payload = {
        "kind": "dkg-feldman-contribution-v1",
        **context,
        "dealer_id": participant_id,
        "dealer_index": participant["index"],
        "threshold": threshold,
        "commitments_g1_compressed_hex": commitments,
        "randomness_source": randomness,
        "is_test_fixture": bool(test_mode),
    }
    private_state = {
        "schema_version": 1,
        "kind": "dkg-ephemeral-polynomial-state-v1",
        **context,
        "dealer_id": participant_id,
        "dealer_index": participant["index"],
        "threshold": threshold,
        "coefficient_scalars_hex": [f"{c:064x}" for c in coefficients],
        "public_contribution_sha256": sha256(canonical_json(public_payload)),
        "randomness_source": randomness,
        "is_test_fixture": bool(test_mode),
        "secret_warning": "EPHEMERAL SECRET: securely erase through an operator-approved process after share review.",
    }
    return _signed_record(public_payload, role, private), private_state


def dkg_share_packet(
    private_state: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    recipient_id: str,
    role: RoleKey,
    private: Ed25519PrivateKey,
) -> dict[str, Any]:
    _, _, _, _, _, curve_order, _, _ = _bls_imports()
    if private_state.get("kind") != "dkg-ephemeral-polynomial-state-v1":
        raise AuthorizationError("DKG private state kind mismatch")
    dealer_id = private_state["dealer_id"]
    participant = next((p for p in descriptor["participants"] if p["participant_id"] == recipient_id), None)
    if participant is None or role.role != f"dkg-participant:{dealer_id}":
        raise AuthorizationError("DKG share dealer/recipient/role mismatch")
    if private_state.get("ceremony_id") != descriptor.get("ceremony_id"):
        raise AuthorizationError("DKG private state belongs to another ceremony")
    coefficients = [int(x, 16) for x in private_state["coefficient_scalars_hex"]]
    x = participant["index"]
    share, power = 0, 1
    for coefficient in coefficients:
        share = (share + coefficient * power) % curve_order
        power = (power * x) % curve_order
    payload = {
        "kind": "dkg-private-share-packet-v1",
        "ceremony_id": descriptor["ceremony_id"],
        "exact_revision": descriptor["exact_revision"],
        "chain_id": descriptor["chain_id"],
        "participant_set_sha256": sha256(canonical_json(descriptor["participants"])),
        "dealer_id": dealer_id,
        "dealer_index": private_state["dealer_index"],
        "recipient_id": recipient_id,
        "recipient_index": x,
        "public_contribution_sha256": private_state["public_contribution_sha256"],
        "share_scalar_hex": f"{share:064x}",
        "is_test_fixture": bool(private_state.get("is_test_fixture")),
        "secret_warning": "PRIVATE DKG SHARE: transport only through an operator-approved confidential channel.",
    }
    return _signed_record(payload, role, private)


def _point_equal(a: Any, b: Any, normalize: Any) -> bool:
    return normalize(a) == normalize(b)


def verify_share_against_contribution(
    packet_record: Mapping[str, Any], contribution_record: Mapping[str, Any],
    descriptor: Mapping[str, Any], expected_recipient_id: str,
    keyring: Mapping[str, RoleKey],
) -> bool:
    _, pubkey_to_G1, G1, Z1, add, curve_order, multiply, normalize = _bls_imports()
    packet = _verify_signed_record(packet_record, keyring)
    contribution = _verify_signed_record(contribution_record, keyring)
    if packet.get("kind") != "dkg-private-share-packet-v1" or contribution.get("kind") != "dkg-feldman-contribution-v1":
        raise AuthorizationError("DKG share/contribution record kind mismatch")
    participants = descriptor.get("participants")
    if not isinstance(participants, list):
        raise AuthorizationError("DKG share descriptor participants malformed")
    dealer_id = contribution.get("dealer_id")
    dealer = next(
        (p for p in participants if isinstance(p, dict) and p.get("participant_id") == dealer_id),
        None,
    )
    recipient = next(
        (p for p in participants if isinstance(p, dict) and p.get("participant_id") == expected_recipient_id),
        None,
    )
    if dealer is None or recipient is None:
        raise AuthorizationError("DKG share dealer/recipient absent from descriptor")
    expected_dealer_role = f"dkg-participant:{dealer_id}"
    if dealer.get("signing_role") != expected_dealer_role:
        raise AuthorizationError("DKG share descriptor dealer role is not canonical")
    dealer_key = keyring.get(expected_dealer_role)
    if dealer_key is None:
        raise AuthorizationError("DKG share descriptor dealer key absent from keyring")
    for label, record in (("contribution", contribution_record), ("packet", packet_record)):
        if (
            record.get("signer_role") != expected_dealer_role
            or record.get("key_id") != dealer_key.key_id
        ):
            raise AuthorizationError(f"DKG share {label} signer does not match descriptor dealer")
    participant_set_sha256 = sha256(canonical_json(participants))
    for key, expected in (
        ("ceremony_id", descriptor.get("ceremony_id")),
        ("exact_revision", descriptor.get("exact_revision")),
        ("chain_id", descriptor.get("chain_id")),
        ("participant_set_sha256", participant_set_sha256),
    ):
        if packet.get(key) != expected or contribution.get(key) != expected:
            raise AuthorizationError(f"DKG share descriptor context mismatch at {key}")
    if contribution.get("threshold") != descriptor.get("threshold"):
        raise AuthorizationError("DKG share descriptor context mismatch at threshold")
    if (
        packet.get("is_test_fixture") != descriptor.get("is_test_fixture")
        or contribution.get("is_test_fixture") != descriptor.get("is_test_fixture")
    ):
        raise AuthorizationError("DKG share descriptor context mismatch at is_test_fixture")
    if packet.get("dealer_id") != dealer_id:
        raise AuthorizationError("DKG share transcript splice detected at dealer_id")
    if (
        packet.get("dealer_index") != dealer.get("index")
        or contribution.get("dealer_index") != dealer.get("index")
    ):
        raise AuthorizationError("DKG share dealer index does not match descriptor")
    if packet.get("recipient_id") != expected_recipient_id:
        raise AuthorizationError("DKG share recipient does not match expected recipient")
    if packet.get("recipient_index") != recipient.get("index"):
        raise AuthorizationError("DKG share recipient index does not match descriptor")
    if packet.get("public_contribution_sha256") != sha256(canonical_json(contribution)):
        raise AuthorizationError("DKG share contribution hash mismatch")
    try:
        share = int(packet["share_scalar_hex"], 16)
    except (KeyError, ValueError, TypeError) as exc:
        raise AuthorizationError("DKG share scalar malformed") from exc
    if not 0 < share < curve_order:
        raise AuthorizationError("DKG share scalar outside group order")
    commitments = []
    try:
        for encoded in contribution["commitments_g1_compressed_hex"]:
            point = pubkey_to_G1(bytes.fromhex(encoded))
            if _point_equal(point, Z1, normalize):
                raise AuthorizationError("DKG rogue contribution contains point at infinity")
            commitments.append(point)
    except (ValueError, TypeError) as exc:
        raise AuthorizationError("DKG contribution point malformed") from exc
    expected, power = Z1, 1
    x = packet["recipient_index"]
    for commitment in commitments:
        expected = add(expected, multiply(commitment, power))
        power = (power * x) % curve_order
    return _point_equal(multiply(G1, share), expected, normalize)


def dkg_review_record(
    packet_record: Mapping[str, Any],
    contribution_record: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    recipient_role: RoleKey,
    recipient_private: Ed25519PrivateKey,
    keyring: Mapping[str, RoleKey],
) -> dict[str, Any]:
    packet = _verify_signed_record(packet_record, keyring)
    expected_role = f"dkg-participant:{packet['recipient_id']}"
    if recipient_role.role != expected_role:
        raise AuthorizationError("DKG review signer is not the named recipient")
    valid = verify_share_against_contribution(
        packet_record, contribution_record, descriptor, packet["recipient_id"], keyring
    )
    payload = {
        "kind": "dkg-share-review-v1",
        "ceremony_id": packet["ceremony_id"],
        "exact_revision": packet["exact_revision"],
        "chain_id": packet["chain_id"],
        "participant_set_sha256": packet["participant_set_sha256"],
        "dealer_id": packet["dealer_id"],
        "dealer_index": packet["dealer_index"],
        "recipient_id": packet["recipient_id"],
        "recipient_index": packet["recipient_index"],
        "packet_sha256": sha256(canonical_json(packet_record)),
        "public_contribution_sha256": packet["public_contribution_sha256"],
        "verdict": "VALID" if valid else "COMPLAINT",
        "complaint_packet": None if valid else dict(packet_record),
        "is_test_fixture": bool(packet.get("is_test_fixture")),
    }
    return _signed_record(payload, recipient_role, recipient_private)


def dkg_erasure_record(
    descriptor: Mapping[str, Any],
    contribution_record: Mapping[str, Any],
    participant_id: str,
    role: RoleKey,
    private: Ed25519PrivateKey,
    confirmed_at: dt.datetime,
    *,
    test_mode: bool = False,
) -> dict[str, Any]:
    contribution = contribution_record["payload"]
    if role.role != f"dkg-participant:{participant_id}" or contribution.get("dealer_id") != participant_id:
        raise AuthorizationError("DKG erasure participant/role/contribution mismatch")
    payload = {
        "kind": "dkg-ephemeral-erasure-attestation-v1",
        "ceremony_id": descriptor["ceremony_id"],
        "exact_revision": descriptor["exact_revision"],
        "chain_id": descriptor["chain_id"],
        "participant_id": participant_id,
        "public_contribution_sha256": sha256(canonical_json(contribution)),
        "confirmed_at_utc": utc_text(confirmed_at),
        "operator_statement": "The participant operator attests that ephemeral polynomial coefficients and outbound share plaintexts were erased using its approved process.",
        "assurance_limit": "This signed statement is an operator attestation; software cannot prove physical-media erasure.",
        "is_test_fixture": bool(test_mode),
    }
    return _signed_record(payload, role, private)


def verify_dkg_transcript(
    transcript: Mapping[str, Any],
    keyring: Mapping[str, RoleKey],
    freeze: Mapping[str, Any],
    *,
    test_mode: bool = False,
) -> dict[str, Any]:
    require_non_fixture(transcript, "DKG transcript", test_mode=test_mode)
    require_exact_keys(
        transcript,
        {"schema_version", "kind", "descriptor", "descriptor_signatures", "contributions", "reviews", "exclusions", "erasure_confirmations", "group_public_key_g1_hex", "participant_set_root", "dkg_root", "is_test_fixture"},
        "DKG transcript",
    )
    descriptor = transcript["descriptor"]
    participants = validate_dkg_descriptor(
        descriptor, transcript["descriptor_signatures"], keyring, freeze, test_mode=test_mode
    )
    by_id = {p["participant_id"]: p for p in participants}
    threshold = descriptor["threshold"]
    contributions = transcript["contributions"]
    if not isinstance(contributions, list) or len(contributions) != len(participants):
        raise AuthorizationError("DKG transcript requires one contribution per participant")
    contribution_by_id: dict[str, Mapping[str, Any]] = {}
    contribution_hash: dict[str, str] = {}
    previous_index = 0
    _, pubkey_to_G1, _, Z1, add, _, _, normalize = _bls_imports()
    constant_points: dict[str, Any] = {}
    for signed in contributions:
        payload = _verify_signed_record(signed, keyring)
        dealer = payload.get("dealer_id")
        if payload.get("kind") != "dkg-feldman-contribution-v1" or dealer not in by_id:
            raise AuthorizationError("DKG rogue or malformed contribution")
        participant = by_id[dealer]
        if signed["signer_role"] != participant["signing_role"]:
            raise AuthorizationError("DKG contribution signer mismatch")
        context = {
            "ceremony_id": descriptor["ceremony_id"], "exact_revision": descriptor["exact_revision"],
            "chain_id": descriptor["chain_id"], "participant_set_sha256": sha256(canonical_json(participants)),
        }
        if any(payload.get(k) != v for k, v in context.items()):
            raise AuthorizationError("DKG contribution transcript splice")
        if payload.get("dealer_index") != participant["index"] or payload["dealer_index"] <= previous_index:
            raise AuthorizationError("DKG contributions must be in participant index order")
        previous_index = payload["dealer_index"]
        commitments = payload.get("commitments_g1_compressed_hex")
        if not isinstance(commitments, list) or len(commitments) != threshold:
            raise AuthorizationError("DKG contribution commitment degree/threshold mismatch")
        try:
            points = [pubkey_to_G1(bytes.fromhex(x)) for x in commitments]
        except (ValueError, TypeError) as exc:
            raise AuthorizationError("DKG contribution contains invalid compressed point") from exc
        if any(_point_equal(point, Z1, normalize) for point in points):
            raise AuthorizationError("DKG rogue contribution contains point at infinity")
        contribution_by_id[dealer] = signed
        contribution_hash[dealer] = sha256(canonical_json(payload))
        constant_points[dealer] = points[0]
    reviews = transcript["reviews"]
    if not isinstance(reviews, list):
        raise AuthorizationError("DKG reviews must be a list")
    review_matrix: dict[tuple[str, str], Mapping[str, Any]] = {}
    last_pair = (0, 0)
    valid_complaints: dict[str, list[str]] = {pid: [] for pid in by_id}
    for signed in reviews:
        payload = _verify_signed_record(signed, keyring)
        dealer, recipient = payload.get("dealer_id"), payload.get("recipient_id")
        if dealer not in by_id or recipient not in by_id or payload.get("kind") != "dkg-share-review-v1":
            raise AuthorizationError("DKG rogue/malformed share review")
        if signed["signer_role"] != by_id[recipient]["signing_role"]:
            raise AuthorizationError("DKG share review signer is not recipient")
        pair = (by_id[dealer]["index"], by_id[recipient]["index"])
        if pair <= last_pair:
            raise AuthorizationError("DKG reviews must be strictly ordered by dealer,recipient index")
        last_pair = pair
        if pair in review_matrix:
            raise AuthorizationError("DKG duplicate share review")
        for key, expected in (
            ("ceremony_id", descriptor["ceremony_id"]), ("exact_revision", descriptor["exact_revision"]),
            ("chain_id", descriptor["chain_id"]), ("participant_set_sha256", sha256(canonical_json(participants))),
            ("dealer_index", pair[0]), ("recipient_index", pair[1]),
            ("public_contribution_sha256", contribution_hash[dealer]),
        ):
            if payload.get(key) != expected:
                raise AuthorizationError(f"DKG review transcript splice/hash mismatch at {key}")
        verdict = payload.get("verdict")
        complaint_packet = payload.get("complaint_packet")
        if verdict == "VALID":
            if complaint_packet is not None:
                raise AuthorizationError("DKG valid receipt must not reveal a complaint packet")
        elif verdict == "COMPLAINT":
            if not isinstance(complaint_packet, dict):
                raise AuthorizationError("DKG complaint omitted its signed disputed packet")
            if sha256(canonical_json(complaint_packet)) != payload.get("packet_sha256"):
                raise AuthorizationError("DKG complaint packet hash mismatch")
            if verify_share_against_contribution(
                complaint_packet, contribution_by_id[dealer], descriptor, recipient, keyring
            ):
                raise AuthorizationError("DKG complaint is invalid: revealed share verifies")
            valid_complaints[dealer].append(sha256(canonical_json(payload)))
        else:
            raise AuthorizationError("DKG share review verdict invalid")
        review_matrix[(dealer, recipient)] = payload
    required_pairs = {(dealer, recipient) for dealer in by_id for recipient in by_id}
    if set(review_matrix) != required_pairs:
        missing = sorted(required_pairs - set(review_matrix))
        raise AuthorizationError(f"DKG complaint/receipt omission: missing pairs {missing}")
    expected_exclusions = [
        {"dealer_id": pid, "complaint_hashes": sorted(valid_complaints[pid])}
        for pid in sorted(by_id, key=lambda p: by_id[p]["index"]) if valid_complaints[pid]
    ]
    if transcript["exclusions"] != expected_exclusions:
        raise AuthorizationError("DKG exclusion record does not exactly match valid complaints")
    excluded = {entry["dealer_id"] for entry in expected_exclusions}
    active = [p for p in participants if p["participant_id"] not in excluded]
    if len(active) < threshold:
        raise AuthorizationError("DKG threshold failure after complaint exclusions")
    erasures = transcript["erasure_confirmations"]
    if not isinstance(erasures, list) or len(erasures) != len(participants):
        raise AuthorizationError("DKG requires one erasure attestation per participant")
    for participant, signed in zip(participants, erasures):
        payload = _verify_signed_record(signed, keyring)
        pid = participant["participant_id"]
        if signed["signer_role"] != participant["signing_role"] or payload.get("participant_id") != pid:
            raise AuthorizationError("DKG erasure record ordering/signer mismatch")
        if payload.get("kind") != "dkg-ephemeral-erasure-attestation-v1":
            raise AuthorizationError("DKG erasure record kind mismatch")
        if payload.get("ceremony_id") != descriptor["ceremony_id"] or payload.get("exact_revision") != descriptor["exact_revision"]:
            raise AuthorizationError("DKG erasure record transcript splice")
        if payload.get("public_contribution_sha256") != contribution_hash[pid]:
            raise AuthorizationError("DKG erasure record contribution mismatch")
        if payload.get("assurance_limit") != "This signed statement is an operator attestation; software cannot prove physical-media erasure.":
            raise AuthorizationError("DKG erasure record overclaims automated proof")
    group = Z1
    for participant in active:
        group = add(group, constant_points[participant["participant_id"]])
    from py_ecc.bls.g2_primitives import G1_to_pubkey
    group_hex = G1_to_pubkey(group).hex()
    if transcript["group_public_key_g1_hex"] != group_hex:
        raise AuthorizationError("DKG group public key mismatch")
    participant_root = domain_hash(
        DOMAIN_DKG_PARTICIPANTS,
        canonical_json([
            {"participant": p, "contribution_sha256": contribution_hash[p["participant_id"]]}
            for p in active
        ]),
    ).hex()
    if transcript["participant_set_root"] != participant_root:
        raise AuthorizationError("DKG participant set root mismatch")
    root_input = dict(transcript)
    root_input.pop("dkg_root", None)
    root = domain_hash(DOMAIN_DKG_TRANSCRIPT, canonical_json(root_input)).hex()
    if transcript["dkg_root"] != root:
        raise AuthorizationError("DKG transcript root mismatch")
    return {
        "dkg_root": root,
        "group_public_key_g1_hex": group_hex,
        "participant_set_root": participant_root,
        "active_participants": [p["participant_id"] for p in active],
        "excluded_participants": sorted(excluded),
        "threshold": threshold,
    }


def finalize_dkg_transcript(
    descriptor: Mapping[str, Any], descriptor_signatures: Mapping[str, Any],
    contributions: Sequence[Mapping[str, Any]], reviews: Sequence[Mapping[str, Any]],
    exclusions: Sequence[Mapping[str, Any]], erasures: Sequence[Mapping[str, Any]],
    keyring: Mapping[str, RoleKey], freeze: Mapping[str, Any], *, test_mode: bool = False,
) -> dict[str, Any]:
    """Assemble roots, then run the same verifier used by independent parties."""
    # Compute expected group/participant roots from a temporary transcript by
    # reusing the verifier's deterministic rules without trusting caller roots.
    participants = validate_dkg_descriptor(descriptor, descriptor_signatures, keyring, freeze, test_mode=test_mode)
    excluded = {x["dealer_id"] for x in exclusions}
    active = [p for p in participants if p["participant_id"] not in excluded]
    _, pubkey_to_G1, _, Z1, add, _, _, _ = _bls_imports()
    contribution_payloads = {r["payload"]["dealer_id"]: r["payload"] for r in contributions}
    group = Z1
    for participant in active:
        payload = contribution_payloads[participant["participant_id"]]
        group = add(group, pubkey_to_G1(bytes.fromhex(payload["commitments_g1_compressed_hex"][0])))
    from py_ecc.bls.g2_primitives import G1_to_pubkey
    participant_root = domain_hash(
        DOMAIN_DKG_PARTICIPANTS,
        canonical_json([
            {"participant": p, "contribution_sha256": sha256(canonical_json(contribution_payloads[p["participant_id"]]))}
            for p in active
        ]),
    ).hex()
    transcript: dict[str, Any] = {
        "schema_version": 1,
        "kind": "noosphere-dkg-transcript-v1",
        "descriptor": dict(descriptor),
        "descriptor_signatures": dict(descriptor_signatures),
        "contributions": list(contributions),
        "reviews": list(reviews),
        "exclusions": list(exclusions),
        "erasure_confirmations": list(erasures),
        "group_public_key_g1_hex": G1_to_pubkey(group).hex(),
        "participant_set_root": participant_root,
        "dkg_root": "",
        "is_test_fixture": bool(test_mode),
    }
    root_input = dict(transcript); root_input.pop("dkg_root")
    transcript["dkg_root"] = domain_hash(DOMAIN_DKG_TRANSCRIPT, canonical_json(root_input)).hex()
    verify_dkg_transcript(transcript, keyring, freeze, test_mode=test_mode)
    return transcript


def dkg_finalize_participant_share(
    transcript: Mapping[str, Any], packet_records: Sequence[Mapping[str, Any]],
    participant_id: str, keyring: Mapping[str, RoleKey], freeze: Mapping[str, Any],
    participant_role: RoleKey, participant_private: Ed25519PrivateKey,
    *, test_mode: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Combine verified non-excluded dealer packets into one threshold share."""
    summary = verify_dkg_transcript(transcript, keyring, freeze, test_mode=test_mode)
    descriptor = transcript["descriptor"]
    participant = next((p for p in descriptor["participants"] if p["participant_id"] == participant_id), None)
    if participant is None or participant_role.role != participant["signing_role"]:
        raise AuthorizationError("DKG final share participant/role mismatch")
    active = summary["active_participants"]
    if len(packet_records) != len(active):
        raise AuthorizationError("DKG final share requires exactly one packet from every active dealer")
    contributions = {r["payload"]["dealer_id"]: r for r in transcript["contributions"]}
    packets: dict[str, Mapping[str, Any]] = {}
    _, pubkey_to_G1, G1, Z1, add, curve_order, multiply, normalize = _bls_imports()
    total = 0
    for packet_record in packet_records:
        packet = _verify_signed_record(packet_record, keyring)
        dealer = packet.get("dealer_id")
        if dealer not in active or dealer in packets:
            raise AuthorizationError("DKG final share has rogue, excluded, or duplicate dealer packet")
        if packet.get("recipient_id") != participant_id or packet.get("recipient_index") != participant["index"]:
            raise AuthorizationError("DKG final share packet belongs to another recipient")
        if not verify_share_against_contribution(
            packet_record, contributions[dealer], descriptor, participant_id, keyring
        ):
            raise AuthorizationError("DKG final share includes an invalid dealer share")
        total = (total + int(packet["share_scalar_hex"], 16)) % curve_order
        packets[dealer] = packet_record
    if set(packets) != set(active) or total == 0:
        raise AuthorizationError("DKG final share active dealer coverage/aggregate invalid")
    expected = Z1
    x = participant["index"]
    for dealer in active:
        power = 1
        for encoded in contributions[dealer]["payload"]["commitments_g1_compressed_hex"]:
            expected = add(expected, multiply(pubkey_to_G1(bytes.fromhex(encoded)), power))
            power = (power * x) % curve_order
    actual = multiply(G1, total)
    if not _point_equal(actual, expected, normalize):
        raise AuthorizationError("DKG final secret share does not match aggregate Feldman verification vector")
    from py_ecc.bls.g2_primitives import G1_to_pubkey
    public_payload = {
        "kind": "dkg-final-public-share-v1",
        "ceremony_id": descriptor["ceremony_id"],
        "exact_revision": descriptor["exact_revision"],
        "chain_id": descriptor["chain_id"],
        "dkg_root": summary["dkg_root"],
        "participant_id": participant_id,
        "participant_index": participant["index"],
        "public_share_g1_compressed_hex": G1_to_pubkey(actual).hex(),
        "active_dealers": active,
        "is_test_fixture": bool(test_mode),
    }
    secret_state = {
        "schema_version": 1,
        "kind": "dkg-final-secret-share-v1",
        "ceremony_id": descriptor["ceremony_id"],
        "exact_revision": descriptor["exact_revision"],
        "chain_id": descriptor["chain_id"],
        "dkg_root": summary["dkg_root"],
        "participant_id": participant_id,
        "participant_index": participant["index"],
        "secret_share_scalar_hex": f"{total:064x}",
        "public_share_sha256": sha256(canonical_json(public_payload)),
        "is_test_fixture": bool(test_mode),
        "secret_warning": "LONG-LIVED THRESHOLD SECRET SHARE: protect with the participant's production key-custody process.",
    }
    return _signed_record(public_payload, participant_role, participant_private), secret_state


# ---------------------------------------------------------------------------
# Final genesis rebuild/freeze and cutover authorization
# ---------------------------------------------------------------------------

FINAL_BODY_KEYS = {
    "version", "parameter_manifest_hash", "genesis_time_ms", "dkg_suite_id",
    "dkg_group_pubkey_hex", "dkg_participant_set_root", "genesis_witness_set_root",
    "genesis_state_roots", "is_test_fixture",
}
STATE_ROOT_NAMES = ("notes_root", "nullifiers_root", "accounts_root", "objects_root", "receipts_root", "params_root")


def canonical_final_genesis_body(body: Mapping[str, Any], freeze: Mapping[str, Any], dkg: Mapping[str, Any], *, test_mode: bool = False) -> bytes:
    require_exact_keys(body, FINAL_BODY_KEYS, "FinalGenesisBodyV1 input")
    require_non_fixture(body, "FinalGenesisBodyV1", test_mode=test_mode)
    if body["version"] != 1 or body["parameter_manifest_hash"] != freeze["parameter_manifest_hash"]:
        raise AuthorizationError("FinalGenesisBodyV1 version/manifest hash mismatch")
    if _uint(body["dkg_suite_id"], 16, "final.dkg_suite_id") == 0:
        raise AuthorizationError("FinalGenesisBodyV1 DKG suite ID zero is unregistered")
    if body["dkg_participant_set_root"] != dkg["participant_set_root"]:
        raise AuthorizationError("FinalGenesisBodyV1 DKG participant root mismatch")
    if body["dkg_group_pubkey_hex"] != dkg["group_public_key_g1_hex"]:
        raise AuthorizationError("FinalGenesisBodyV1 DKG group key mismatch")
    group_key = bytes.fromhex(body["dkg_group_pubkey_hex"])
    if not group_key or len(group_key) > 192:
        raise AuthorizationError("FinalGenesisBodyV1 DKG group key length invalid")
    roots = body["genesis_state_roots"]
    if not isinstance(roots, dict) or list(roots) != list(STATE_ROOT_NAMES):
        raise AuthorizationError("FinalGenesisBodyV1 state roots must use frozen insertion order")
    out = bytearray()
    out += _le(body["version"], 2, "final.version")
    out += _hex32(body["parameter_manifest_hash"], "final.parameter_manifest_hash")
    out += _le(body["genesis_time_ms"], 8, "final.genesis_time_ms")
    out += _le(body["dkg_suite_id"], 2, "final.dkg_suite_id")
    out += len(group_key).to_bytes(4, "little") + group_key
    out += _hex32(body["dkg_participant_set_root"], "final.dkg_participant_set_root")
    out += _hex32(body["genesis_witness_set_root"], "final.genesis_witness_set_root")
    for name in STATE_ROOT_NAMES:
        out += _hex32(roots[name], f"final.genesis_state_roots.{name}")
    return bytes(out)


def derive_final_identity(
    freeze: Mapping[str, Any], anchor_summary: Mapping[str, Any], dkg_summary: Mapping[str, Any],
    body: Mapping[str, Any], *, test_mode: bool = False,
) -> dict[str, Any]:
    canonical = canonical_final_genesis_body(body, freeze, dkg_summary, test_mode=test_mode)
    if not test_mode:
        genesis_time = dt.datetime.fromtimestamp(body["genesis_time_ms"] / 1000, dt.timezone.utc)
        anchor_observed = parse_utc(anchor_summary.get("observed_at_utc"), "anchor observed_at_utc")
        if genesis_time <= anchor_observed:
            raise AuthorizationError("declared genesis time must be strictly after the Bitcoin anchor observation")
    anchor = _le(anchor_summary["height"], 8, "anchor height") + bytes.fromhex(anchor_summary["block_hash_internal_hex"])
    genesis_hash = domain_hash(
        b"NOOS/GENESIS/FINAL/V1",
        bytes.fromhex(freeze["chain_id"]), anchor, bytes.fromhex(dkg_summary["dkg_root"]), canonical,
    ).hex()
    return {
        "chain_id": freeze["chain_id"],
        "genesis_hash": genesis_hash,
        "canonical_final_body_bytes_hex": canonical.hex(),
        "bitcoin_anchor_bytes_hex": anchor.hex(),
    }


def make_rebuild_record(
    identity: Mapping[str, Any], freeze_file: Path, anchor_file: Path, transcript_file: Path,
    body_file: Path, exact_revision: str, participant_id: str,
) -> dict[str, Any]:
    if not participant_id:
        raise AuthorizationError("independent rebuild participant ID is required")
    return {
        "schema_version": 1,
        "kind": "noosphere-independent-genesis-rebuild-v1",
        "exact_revision": exact_revision,
        "participant_id": participant_id,
        "chain_id": identity["chain_id"],
        "genesis_hash": identity["genesis_hash"],
        "freeze_file_sha256": file_sha256(freeze_file),
        "anchor_file_sha256": file_sha256(anchor_file),
        "dkg_transcript_file_sha256": file_sha256(transcript_file),
        "final_body_file_sha256": file_sha256(body_file),
        "rebuild_method": "independent deterministic re-encoding and domain-hash derivation",
        "assurance_limit": "The signature records a role-authorized rebuild; tooling does not establish that the participant is an independent human.",
        "is_test_fixture": False,
    }


def verify_rebuild_record(
    record: Mapping[str, Any], signatures: Mapping[str, Any], identity: Mapping[str, Any],
    keyring: Mapping[str, RoleKey], exact_revision: str,
) -> None:
    if record.get("chain_id") != identity.get("chain_id") or record.get("genesis_hash") != identity.get("genesis_hash"):
        raise AuthorizationError("independent rebuild record identity mismatch")
    verify_detached_signatures(
        canonical_json(record), signatures, DOMAIN_REBUILD, exact_revision,
        ("independent-genesis-rebuilder",), keyring,
    )


def make_final_freeze_bundle(
    identity: Mapping[str, Any], freeze_file: Path, freeze_signatures_file: Path,
    publication_file: Path, publication_signatures_file: Path,
    anchor_file: Path, anchor_signatures_file: Path, transcript_file: Path,
    body_file: Path, rebuild_file: Path, rebuild_signatures_file: Path,
    exact_revision: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "noosphere-chain-genesis-freeze-v1",
        "exact_revision": exact_revision,
        "chain_id": identity["chain_id"],
        "genesis_hash": identity["genesis_hash"],
        "parameter_freeze_file_sha256": file_sha256(freeze_file),
        "parameter_freeze_signatures_sha256": file_sha256(freeze_signatures_file),
        "quiet_week_publication_file_sha256": file_sha256(publication_file),
        "quiet_week_publication_signatures_sha256": file_sha256(publication_signatures_file),
        "bitcoin_anchor_file_sha256": file_sha256(anchor_file),
        "bitcoin_anchor_signatures_sha256": file_sha256(anchor_signatures_file),
        "dkg_transcript_file_sha256": file_sha256(transcript_file),
        "final_genesis_body_file_sha256": file_sha256(body_file),
        "independent_rebuild_record_sha256": file_sha256(rebuild_file),
        "independent_rebuild_signatures_sha256": file_sha256(rebuild_signatures_file),
        "is_test_fixture": False,
        "promotion_state": "AUTHORIZATION_ARTIFACT_ONLY_NOT_A_GATE_PASS",
        "assurance_limit": "This bundle freezes identity bytes but does not mark GENESIS or any promotion gate passed.",
    }


def verify_cutover_authorization(
    authorization: Mapping[str, Any], signatures: Mapping[str, Any], keyring: Mapping[str, RoleKey],
    promotion_ledger: Mapping[str, Any], release_manifest: Mapping[str, Any], final_freeze: Mapping[str, Any],
    prepared_cutover: Mapping[str, Any],
    *, raw_component_hashes: Mapping[str, str] | None = None,
) -> None:
    require_non_fixture(authorization, "cutover authorization")
    require_exact_keys(
        authorization,
        {"schema_version", "kind", "exact_revision", "chain_id", "genesis_hash", "promotion_ledger_sha256", "release_manifest_sha256", "final_freeze_sha256", "prepared_cutover_sha256", "is_test_fixture", "authorization_scope"},
        "cutover authorization",
    )
    if authorization["schema_version"] != 1 or authorization["kind"] != "noosphere-multiparty-cutover-authorization-v1":
        raise AuthorizationError("cutover authorization kind/version mismatch")
    revision = require_revision(authorization["exact_revision"])
    if promotion_ledger.get("protocol_binding", {}).get("revision") != revision:
        raise AuthorizationError("cutover authorization stale against promotion ledger revision")
    gates = promotion_ledger.get("gates")
    gate_order = ["G0", "G1", "G2", "G3", "GENESIS", "G4", "G5"]
    if (
        not isinstance(gates, list)
        or [g.get("gate") for g in gates] != gate_order
        or [g.get("state") for g in gates] != ["PASSED"] * 7
        or any(not isinstance(g.get("signatures"), list) or not g["signatures"] for g in gates)
    ):
        raise AuthorizationError("cutover prohibited: every G0..G5 gate must already be PASSED")
    if promotion_ledger.get("cutover", {}).get("execution_authority") != "SIGNED_G5_ONLY":
        raise AuthorizationError("cutover ledger execution authority mismatch")
    if final_freeze.get("chain_id") != authorization["chain_id"] or final_freeze.get("genesis_hash") != authorization["genesis_hash"]:
        raise AuthorizationError("cutover authorization/final freeze identity mismatch")
    if final_freeze.get("exact_revision") != revision:
        raise AuthorizationError("cutover final freeze revision mismatch")
    release_identity = release_manifest.get("identity", {})
    if release_identity.get("chain_id") != authorization["chain_id"] or release_identity.get("genesis_hash") != authorization["genesis_hash"]:
        raise AuthorizationError("cutover release manifest identity mismatch")
    if release_manifest.get("source", {}).get("repo_revision") != revision:
        raise AuthorizationError("cutover release manifest revision mismatch")
    expected_hashes = dict(raw_component_hashes) if raw_component_hashes is not None else {
        "promotion_ledger_sha256": sha256(canonical_json(promotion_ledger) + b"\n"),
        "release_manifest_sha256": sha256(canonical_json(release_manifest) + b"\n"),
        "final_freeze_sha256": sha256(canonical_json(final_freeze) + b"\n"),
        "prepared_cutover_sha256": sha256(canonical_json(prepared_cutover) + b"\n"),
    }
    if set(expected_hashes) != {
        "promotion_ledger_sha256", "release_manifest_sha256", "final_freeze_sha256", "prepared_cutover_sha256"
    }:
        raise AuthorizationError("cutover verifier component hash set mismatch")
    for key, expected in expected_hashes.items():
        if authorization.get(key) != expected:
            raise AuthorizationError(f"cutover authorization component hash mismatch: {key}")
    execution = prepared_cutover.get("execution", {})
    if (
        prepared_cutover.get("manifest_state") != "PREPARED_NOT_EXECUTED"
        or execution.get("authorized") is not False
        or execution.get("executed") is not False
        or execution.get("dns_cutover") != "PROHIBITED"
        or execution.get("required_authority") != "SIGNED_G5_PROMOTION_OVER_EXACT_MANIFEST_HASH"
    ):
        raise AuthorizationError("cutover prepared manifest state mismatch")
    verify_detached_signatures(
        canonical_json(authorization), signatures, DOMAIN_CUTOVER, revision, CUTOVER_ROLES, keyring
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_keys_for_revision(keyring_path: Path, revision: str) -> dict[str, RoleKey]:
    require_current_revision(revision)
    keys, doc = load_keyring(keyring_path)
    if doc["exact_revision"] != revision:
        raise AuthorizationError("keyring revision mismatch")
    return keys


def command_freeze(args: argparse.Namespace) -> None:
    params_doc = read_toml(Path(args.params))
    configured_signatures = Path(params_doc.get("signatures", {}).get("record_path", ""))
    if not configured_signatures.is_absolute():
        configured_signatures = ROOT / configured_signatures
    if configured_signatures.resolve() != Path(args.signatures_out).resolve():
        raise AuthorizationError("mainnet parameters bind a different freeze signature output path")
    freeze, keyring = build_freeze_manifest(
        Path(args.params), Path(args.policy), Path(args.policy_signatures), Path(args.keyring)
    )
    keys = parse_role_paths(args.role_key)
    signatures = make_detached_signatures(
        canonical_json(freeze), DOMAIN_FREEZE, freeze["exact_revision"], FREEZE_ROLES, keyring, keys
    )
    write_new_json(Path(args.out), freeze)
    write_new_json(Path(args.signatures_out), signatures)


def command_sign_policy(args: argparse.Namespace) -> None:
    policy_path = Path(args.policy)
    policy = read_toml(policy_path)
    require_non_fixture(policy, "signed reproducibility policy")
    if policy.get("state") != "SIGNED":
        raise AuthorizationError("refusing to sign policy until an owner sets state = SIGNED")
    revision = require_revision(args.exact_revision)
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    signatures = make_detached_signatures(
        policy_path.read_bytes(), DOMAIN_REPRO_POLICY, revision, FREEZE_ROLES,
        keyring, parse_role_paths(args.role_key),
    )
    write_new_json(Path(args.out), signatures)


def command_publish(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze))
    revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    verify_freeze_manifest(freeze, read_json(Path(args.freeze_signatures)), keyring)
    published, http_date = fetch_public_bytes(args.url)
    record = make_publication_record(freeze, args.url, published, utc_now(), http_date=http_date)
    signatures = make_detached_signatures(
        canonical_json(record), DOMAIN_PUBLICATION, revision, FREEZE_ROLES,
        keyring, parse_role_paths(args.role_key),
    )
    write_new_json(Path(args.out), record)
    write_new_json(Path(args.signatures_out), signatures)


def command_verify_quiet(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze))
    revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    record = read_json(Path(args.publication))
    live, _ = fetch_public_bytes(record.get("publication_url", ""))
    elapsed = verify_quiet_week(
        record, read_json(Path(args.publication_signatures)), freeze, keyring, live
    )
    print(f"QUIET_WEEK_ELIGIBLE elapsed_real_seconds={elapsed} assurance=observed-at-start-and-live-now")


def command_verify_anchor(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    publication = read_json(Path(args.publication))
    live, _ = fetch_public_bytes(publication.get("publication_url", ""))
    verify_quiet_week(
        publication, read_json(Path(args.publication_signatures)), freeze, keyring, live
    )
    anchor = read_json(Path(args.anchor))
    verify_signed_bitcoin_anchor(anchor, read_json(Path(args.anchor_signatures)), keyring, revision)
    summary = verify_bitcoin_anchor_bundle(anchor, publication)
    print(json.dumps(summary, sort_keys=True))


def command_sign_anchor(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    publication = read_json(Path(args.publication))
    live, _ = fetch_public_bytes(publication.get("publication_url", ""))
    verify_quiet_week(
        publication, read_json(Path(args.publication_signatures)), freeze, keyring, live
    )
    anchor = read_json(Path(args.anchor))
    verify_bitcoin_anchor_bundle(anchor, publication)
    signatures = make_detached_signatures(
        canonical_json(anchor), DOMAIN_BITCOIN_ANCHOR, revision, FREEZE_ROLES,
        keyring, parse_role_paths(args.role_key),
    )
    write_new_json(Path(args.out), signatures)


def command_dkg_contribute(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    descriptor = read_json(Path(args.descriptor))
    validate_dkg_descriptor(descriptor, read_json(Path(args.descriptor_signatures)), keyring, freeze)
    participant = next((p for p in descriptor["participants"] if p["participant_id"] == args.participant_id), None)
    if participant is None:
        raise AuthorizationError("participant absent from signed DKG descriptor")
    role = keyring[participant["signing_role"]]
    private = load_private_role_key(Path(args.participant_key), role)
    contribution, state = dkg_contribution(descriptor, args.participant_id, role, private)
    write_new_json(Path(args.contribution_out), contribution)
    write_new_json(Path(args.private_state_out), state, private=True)


def command_sign_dkg_descriptor(args: argparse.Namespace) -> None:
    params_path = Path(args.params); params = read_toml(params_path); validate_mainnet_parameters(params)
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    verify_freeze_manifest(freeze, read_json(Path(args.freeze_signatures)), keyring)
    verify_mainnet_params_binding(params, params_path, freeze)
    publication = read_json(Path(args.publication))
    live, _ = fetch_public_bytes(publication.get("publication_url", ""))
    verify_quiet_week(
        publication, read_json(Path(args.publication_signatures)), freeze, keyring, live
    )
    descriptor = read_json(Path(args.descriptor))
    if descriptor.get("quiet_week_publication_sha256") != sha256(canonical_json(publication) + b"\n"):
        raise AuthorizationError("DKG descriptor does not bind the signed Quiet Week publication record")
    authorized = parse_utc(descriptor.get("authorized_at_utc"), "DKG descriptor authorized_at_utc")
    now = utc_now()
    if abs((now - authorized).total_seconds()) > 600:
        raise AuthorizationError("DKG descriptor authorization time must be within 10 minutes of the live signing clock")
    if (len(descriptor.get("participants", [])), descriptor.get("threshold")) != (
        params["dkg"]["participants"], params["dkg"]["threshold"]
    ):
        raise AuthorizationError("DKG descriptor does not match owner parameter participant/threshold choices")
    signatures = make_detached_signatures(
        canonical_json(descriptor), DOMAIN_DKG_DESCRIPTOR, revision, FREEZE_ROLES,
        keyring, parse_role_paths(args.role_key),
    )
    validate_dkg_descriptor(descriptor, signatures, keyring, freeze)
    write_new_json(Path(args.out), signatures)


def command_dkg_share(args: argparse.Namespace) -> None:
    descriptor = read_json(Path(args.descriptor)); state = read_json(Path(args.private_state))
    revision = require_revision(descriptor.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    role = keyring.get(f"dkg-participant:{state.get('dealer_id')}")
    if role is None:
        raise AuthorizationError("dealer role absent from keyring")
    private = load_private_role_key(Path(args.participant_key), role)
    packet = dkg_share_packet(state, descriptor, args.recipient_id, role, private)
    write_new_json(Path(args.out), packet, private=True)


def command_dkg_review(args: argparse.Namespace) -> None:
    packet = read_json(Path(args.packet)); payload = packet.get("payload", {})
    descriptor = read_json(Path(args.descriptor))
    revision = require_revision(payload.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    role = keyring.get(f"dkg-participant:{payload.get('recipient_id')}")
    if role is None:
        raise AuthorizationError("recipient role absent from keyring")
    private = load_private_role_key(Path(args.participant_key), role)
    review = dkg_review_record(packet, read_json(Path(args.contribution)), descriptor, role, private, keyring)
    write_new_json(Path(args.out), review)


def command_dkg_erasure(args: argparse.Namespace) -> None:
    state_path = Path(args.private_state)
    if state_path.exists():
        raise AuthorizationError(
            "ephemeral state still exists; erase it through the participant's approved process before attesting"
        )
    exact_statement = "I attest that the ephemeral DKG secrets were erased using the participant's approved process."
    if args.operator_confirmation != exact_statement:
        raise AuthorizationError("exact operator erasure confirmation text was not supplied")
    descriptor = read_json(Path(args.descriptor)); revision = require_revision(descriptor.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    role = keyring.get(f"dkg-participant:{args.participant_id}")
    if role is None:
        raise AuthorizationError("participant role absent from keyring")
    private = load_private_role_key(Path(args.participant_key), role)
    record = dkg_erasure_record(
        descriptor, read_json(Path(args.contribution)), args.participant_id, role, private, utc_now()
    )
    write_new_json(Path(args.out), record)


def command_verify_dkg(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    summary = verify_dkg_transcript(read_json(Path(args.transcript)), keyring, freeze)
    print(json.dumps(summary, sort_keys=True))


def command_finalize_dkg(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    descriptor = read_json(Path(args.descriptor))
    descriptor_signatures = read_json(Path(args.descriptor_signatures))
    contributions = [read_json(Path(path)) for path in args.contribution]
    reviews = [read_json(Path(path)) for path in args.review]
    erasures = [read_json(Path(path)) for path in args.erasure]
    complaint_hashes: dict[str, list[str]] = {}
    for review in reviews:
        payload = review.get("payload", {})
        if payload.get("verdict") == "COMPLAINT":
            complaint_hashes.setdefault(payload.get("dealer_id", ""), []).append(
                sha256(canonical_json(payload))
            )
    participant_order = {p["participant_id"]: p["index"] for p in descriptor.get("participants", [])}
    exclusions = [
        {"dealer_id": dealer, "complaint_hashes": sorted(hashes)}
        for dealer, hashes in sorted(complaint_hashes.items(), key=lambda item: participant_order.get(item[0], 1 << 30))
    ]
    transcript = finalize_dkg_transcript(
        descriptor, descriptor_signatures, contributions, reviews, exclusions,
        erasures, keyring, freeze,
    )
    write_new_json(Path(args.out), transcript)


def command_finalize_dkg_share(args: argparse.Namespace) -> None:
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    role = keyring.get(f"dkg-participant:{args.participant_id}")
    if role is None:
        raise AuthorizationError("participant role absent from keyring")
    private = load_private_role_key(Path(args.participant_key), role)
    public, secret = dkg_finalize_participant_share(
        read_json(Path(args.transcript)), [read_json(Path(path)) for path in args.packet],
        args.participant_id, keyring, freeze, role, private,
    )
    write_new_json(Path(args.public_share_out), public)
    write_new_json(Path(args.private_share_out), secret, private=True)


def command_rebuild(args: argparse.Namespace) -> None:
    params_path = Path(args.params); params = read_toml(params_path); validate_mainnet_parameters(params)
    freeze = read_json(Path(args.freeze)); revision = require_revision(freeze.get("exact_revision"))
    if params["authorization"]["exact_revision"] != revision:
        raise AuthorizationError("mainnet parameters and freeze revision mismatch")
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    verify_freeze_manifest(freeze, read_json(Path(args.freeze_signatures)), keyring)
    verify_mainnet_params_binding(params, params_path, freeze)
    publication = read_json(Path(args.publication))
    live, _ = fetch_public_bytes(publication.get("publication_url", ""))
    verify_quiet_week(
        publication, read_json(Path(args.publication_signatures)), freeze, keyring, live
    )
    anchor_doc = read_json(Path(args.anchor))
    verify_signed_bitcoin_anchor(anchor_doc, read_json(Path(args.anchor_signatures)), keyring, revision)
    anchor = verify_bitcoin_anchor_bundle(anchor_doc, publication)
    transcript = read_json(Path(args.transcript))
    dkg = verify_dkg_transcript(transcript, keyring, freeze)
    descriptor = transcript["descriptor"]
    if (len(descriptor["participants"]), descriptor["threshold"]) != (
        params["dkg"]["participants"], params["dkg"]["threshold"]
    ):
        raise AuthorizationError("signed DKG descriptor does not match owner parameter participant/threshold choices")
    body = read_json(Path(args.final_body))
    verify_dkg_publication_sequence(transcript, publication, genesis_time_ms=body.get("genesis_time_ms"))
    identity = derive_final_identity(freeze, anchor, dkg, body)
    role = keyring.get("independent-genesis-rebuilder")
    if role is None:
        raise AuthorizationError("independent-genesis-rebuilder role absent from keyring")
    private = load_private_role_key(Path(args.participant_key), role)
    record = make_rebuild_record(
        identity, Path(args.freeze), Path(args.anchor), Path(args.transcript), Path(args.final_body),
        revision, args.participant_id,
    )
    signatures = make_detached_signatures(
        canonical_json(record), DOMAIN_REBUILD, revision, ("independent-genesis-rebuilder",),
        keyring, {"independent-genesis-rebuilder": Path(args.participant_key)},
    )
    # private was intentionally loaded before writes so a bad key cannot leave a partial record.
    del private
    write_new_json(Path(args.out), record)
    write_new_json(Path(args.signatures_out), signatures)


def command_freeze_final(args: argparse.Namespace) -> None:
    params_path = Path(args.params); params = read_toml(params_path); validate_mainnet_parameters(params)
    freeze_path = Path(args.freeze); freeze = read_json(freeze_path)
    revision = require_revision(freeze.get("exact_revision"))
    if params["authorization"]["exact_revision"] != revision:
        raise AuthorizationError("mainnet parameters and freeze revision mismatch")
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    verify_freeze_manifest(freeze, read_json(Path(args.freeze_signatures)), keyring)
    verify_mainnet_params_binding(params, params_path, freeze)
    publication = read_json(Path(args.publication))
    live, _ = fetch_public_bytes(publication.get("publication_url", ""))
    verify_quiet_week(
        publication, read_json(Path(args.publication_signatures)), freeze, keyring, live
    )
    anchor_path = Path(args.anchor); anchor_doc = read_json(anchor_path)
    verify_signed_bitcoin_anchor(anchor_doc, read_json(Path(args.anchor_signatures)), keyring, revision)
    anchor = verify_bitcoin_anchor_bundle(anchor_doc, publication)
    transcript_path = Path(args.transcript); transcript = read_json(transcript_path)
    dkg = verify_dkg_transcript(transcript, keyring, freeze)
    if (len(transcript["descriptor"]["participants"]), transcript["descriptor"]["threshold"]) != (
        params["dkg"]["participants"], params["dkg"]["threshold"]
    ):
        raise AuthorizationError("signed DKG descriptor does not match owner parameter participant/threshold choices")
    body_path = Path(args.final_body); body = read_json(body_path)
    verify_dkg_publication_sequence(transcript, publication, genesis_time_ms=body.get("genesis_time_ms"))
    identity = derive_final_identity(freeze, anchor, dkg, body)
    rebuild_path = Path(args.rebuild_record); rebuild = read_json(rebuild_path)
    verify_rebuild_record(
        rebuild, read_json(Path(args.rebuild_signatures)), identity, keyring, revision
    )
    expected_rebuild_hashes = {
        "freeze_file_sha256": file_sha256(freeze_path),
        "anchor_file_sha256": file_sha256(anchor_path),
        "dkg_transcript_file_sha256": file_sha256(transcript_path),
        "final_body_file_sha256": file_sha256(body_path),
    }
    for key, expected in expected_rebuild_hashes.items():
        if rebuild.get(key) != expected:
            raise AuthorizationError(f"independent rebuild component hash mismatch: {key}")
    bundle = make_final_freeze_bundle(
        identity, freeze_path, Path(args.freeze_signatures),
        Path(args.publication), Path(args.publication_signatures),
        anchor_path, Path(args.anchor_signatures), transcript_path, body_path,
        rebuild_path, Path(args.rebuild_signatures), revision,
    )
    signatures = make_detached_signatures(
        canonical_json(bundle), DOMAIN_FINAL_FREEZE, revision, FINAL_ROLES,
        keyring, parse_role_paths(args.role_key),
    )
    write_new_json(Path(args.out), bundle)
    write_new_json(Path(args.signatures_out), signatures)


def command_verify_cutover(args: argparse.Namespace) -> None:
    authorization = read_json(Path(args.authorization)); revision = require_revision(authorization.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    final_freeze = read_json(Path(args.final_freeze))
    verify_detached_signatures(
        canonical_json(final_freeze), read_json(Path(args.final_freeze_signatures)),
        DOMAIN_FINAL_FREEZE, revision, FINAL_ROLES, keyring,
    )
    component_paths = {
        "promotion_ledger_sha256": Path(args.promotion_ledger),
        "release_manifest_sha256": Path(args.release_manifest),
        "final_freeze_sha256": Path(args.final_freeze),
        "prepared_cutover_sha256": Path(args.prepared_cutover),
    }
    verify_cutover_authorization(
        authorization, read_json(Path(args.signatures)), keyring,
        read_json(Path(args.promotion_ledger)), read_json(Path(args.release_manifest)),
        final_freeze, read_json(Path(args.prepared_cutover)),
        raw_component_hashes={key: file_sha256(path) for key, path in component_paths.items()},
    )
    print("CUTOVER_AUTHORIZATION_VALID cryptographic_roles_verified=true human_independence_not_established=true")


def command_sign_cutover(args: argparse.Namespace) -> None:
    authorization = read_json(Path(args.authorization)); revision = require_revision(authorization.get("exact_revision"))
    keyring = _load_keys_for_revision(Path(args.keyring), revision)
    final_freeze = read_json(Path(args.final_freeze))
    verify_detached_signatures(
        canonical_json(final_freeze), read_json(Path(args.final_freeze_signatures)),
        DOMAIN_FINAL_FREEZE, revision, FINAL_ROLES, keyring,
    )
    signatures = make_detached_signatures(
        canonical_json(authorization), DOMAIN_CUTOVER, revision, CUTOVER_ROLES,
        keyring, parse_role_paths(args.role_key),
    )
    component_paths = {
        "promotion_ledger_sha256": Path(args.promotion_ledger),
        "release_manifest_sha256": Path(args.release_manifest),
        "final_freeze_sha256": Path(args.final_freeze),
        "prepared_cutover_sha256": Path(args.prepared_cutover),
    }
    verify_cutover_authorization(
        authorization, signatures, keyring,
        read_json(Path(args.promotion_ledger)), read_json(Path(args.release_manifest)),
        final_freeze, read_json(Path(args.prepared_cutover)),
        raw_component_hashes={key: file_sha256(path) for key, path in component_paths.items()},
    )
    write_new_json(Path(args.out), signatures)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    def role_keys(p: argparse.ArgumentParser) -> None:
        p.add_argument("--role-key", action="append", required=True, help="required ROLE=private-key-path")
    p = sub.add_parser("sign-policy"); p.set_defaults(func=command_sign_policy)
    p.add_argument("--policy", required=True); p.add_argument("--exact-revision", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--out", required=True); role_keys(p)
    p = sub.add_parser("freeze-parameters"); p.set_defaults(func=command_freeze)
    p.add_argument("--params", required=True); p.add_argument("--policy", required=True)
    p.add_argument("--policy-signatures", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--out", required=True); p.add_argument("--signatures-out", required=True); role_keys(p)
    p = sub.add_parser("record-publication"); p.set_defaults(func=command_publish)
    p.add_argument("--freeze", required=True); p.add_argument("--freeze-signatures", required=True)
    p.add_argument("--url", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--out", required=True); p.add_argument("--signatures-out", required=True); role_keys(p)
    p = sub.add_parser("verify-quiet-week"); p.set_defaults(func=command_verify_quiet)
    p.add_argument("--freeze", required=True); p.add_argument("--publication", required=True)
    p.add_argument("--publication-signatures", required=True); p.add_argument("--keyring", required=True)
    p = sub.add_parser("sign-bitcoin-anchor"); p.set_defaults(func=command_sign_anchor)
    p.add_argument("--freeze", required=True); p.add_argument("--publication", required=True)
    p.add_argument("--publication-signatures", required=True); p.add_argument("--anchor", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--out", required=True); role_keys(p)
    p = sub.add_parser("verify-bitcoin-anchor"); p.set_defaults(func=command_verify_anchor)
    p.add_argument("--freeze", required=True); p.add_argument("--publication", required=True)
    p.add_argument("--publication-signatures", required=True); p.add_argument("--anchor", required=True)
    p.add_argument("--anchor-signatures", required=True); p.add_argument("--keyring", required=True)
    p = sub.add_parser("sign-dkg-descriptor"); p.set_defaults(func=command_sign_dkg_descriptor)
    p.add_argument("--params", required=True); p.add_argument("--freeze", required=True)
    p.add_argument("--freeze-signatures", required=True); p.add_argument("--descriptor", required=True)
    p.add_argument("--publication", required=True); p.add_argument("--publication-signatures", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--out", required=True); role_keys(p)
    p = sub.add_parser("dkg-contribute"); p.set_defaults(func=command_dkg_contribute)
    p.add_argument("--freeze", required=True); p.add_argument("--descriptor", required=True)
    p.add_argument("--descriptor-signatures", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--participant-id", required=True); p.add_argument("--participant-key", required=True)
    p.add_argument("--contribution-out", required=True); p.add_argument("--private-state-out", required=True)
    p = sub.add_parser("dkg-share"); p.set_defaults(func=command_dkg_share)
    p.add_argument("--descriptor", required=True); p.add_argument("--private-state", required=True)
    p.add_argument("--recipient-id", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--participant-key", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("dkg-review-share"); p.set_defaults(func=command_dkg_review)
    p.add_argument("--descriptor", required=True); p.add_argument("--packet", required=True)
    p.add_argument("--contribution", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--participant-key", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("dkg-confirm-erasure"); p.set_defaults(func=command_dkg_erasure)
    p.add_argument("--descriptor", required=True); p.add_argument("--contribution", required=True)
    p.add_argument("--private-state", required=True); p.add_argument("--participant-id", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--participant-key", required=True)
    p.add_argument("--operator-confirmation", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("verify-dkg-transcript"); p.set_defaults(func=command_verify_dkg)
    p.add_argument("--transcript", required=True); p.add_argument("--freeze", required=True)
    p.add_argument("--keyring", required=True)
    p = sub.add_parser("finalize-dkg-transcript"); p.set_defaults(func=command_finalize_dkg)
    p.add_argument("--descriptor", required=True); p.add_argument("--descriptor-signatures", required=True)
    p.add_argument("--freeze", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--contribution", action="append", required=True)
    p.add_argument("--review", action="append", required=True)
    p.add_argument("--erasure", action="append", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("dkg-finalize-share"); p.set_defaults(func=command_finalize_dkg_share)
    p.add_argument("--transcript", required=True); p.add_argument("--freeze", required=True)
    p.add_argument("--participant-id", required=True); p.add_argument("--participant-key", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--packet", action="append", required=True)
    p.add_argument("--public-share-out", required=True); p.add_argument("--private-share-out", required=True)
    p = sub.add_parser("rebuild-final-genesis"); p.set_defaults(func=command_rebuild)
    p.add_argument("--params", required=True); p.add_argument("--freeze", required=True)
    p.add_argument("--freeze-signatures", required=True); p.add_argument("--publication", required=True)
    p.add_argument("--publication-signatures", required=True); p.add_argument("--anchor", required=True)
    p.add_argument("--anchor-signatures", required=True); p.add_argument("--transcript", required=True)
    p.add_argument("--final-body", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--participant-id", required=True); p.add_argument("--participant-key", required=True)
    p.add_argument("--out", required=True); p.add_argument("--signatures-out", required=True)
    p = sub.add_parser("freeze-final-identity"); p.set_defaults(func=command_freeze_final)
    p.add_argument("--params", required=True); p.add_argument("--freeze", required=True)
    p.add_argument("--freeze-signatures", required=True); p.add_argument("--publication", required=True)
    p.add_argument("--publication-signatures", required=True); p.add_argument("--anchor", required=True)
    p.add_argument("--anchor-signatures", required=True); p.add_argument("--transcript", required=True)
    p.add_argument("--final-body", required=True); p.add_argument("--rebuild-record", required=True)
    p.add_argument("--rebuild-signatures", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--out", required=True); p.add_argument("--signatures-out", required=True); role_keys(p)
    p = sub.add_parser("sign-cutover"); p.set_defaults(func=command_sign_cutover)
    p.add_argument("--authorization", required=True); p.add_argument("--keyring", required=True)
    p.add_argument("--promotion-ledger", required=True); p.add_argument("--release-manifest", required=True)
    p.add_argument("--final-freeze", required=True); p.add_argument("--final-freeze-signatures", required=True)
    p.add_argument("--prepared-cutover", required=True); p.add_argument("--out", required=True); role_keys(p)
    p = sub.add_parser("verify-cutover"); p.set_defaults(func=command_verify_cutover)
    p.add_argument("--authorization", required=True); p.add_argument("--signatures", required=True)
    p.add_argument("--keyring", required=True); p.add_argument("--promotion-ledger", required=True)
    p.add_argument("--release-manifest", required=True); p.add_argument("--final-freeze", required=True)
    p.add_argument("--final-freeze-signatures", required=True)
    p.add_argument("--prepared-cutover", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (AuthorizationError, OSError, ValueError, KeyError) as exc:
        print(f"AUTHORIZATION_REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
