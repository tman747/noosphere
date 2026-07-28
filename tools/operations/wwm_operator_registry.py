from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ENTRY_SCHEMA = "noos/wwm-operator-registry-entry/v1"
POLICY_SCHEMA = "noos/wwm-operator-diversity-policy/v1"
RECORD_DOMAIN = b"NOOS/WWM/OPERATOR-RECORD/V1\0"
ENTRY_ID_DOMAIN = b"NOOS/WWM/OPERATOR-REGISTRY-ENTRY/V1\0"
SIGNATURE_DOMAIN = b"NOOS/SIG/WWM-OPERATOR-REGISTRY-ENTRY/V1\0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLE = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_ENTRY_BYTES = 256 * 1024
RECORD_FIELDS = {
    "record_id",
    "operator_id",
    "organization_root",
    "beneficial_owner_root",
    "control_cluster_id",
    "provider_root",
    "region_id",
    "asn",
    "software_lineage_root",
    "model_publisher_root",
    "identity_public_key_base64",
    "operational_public_key_base64",
    "revocation_public_key_base64",
    "roles",
    "capacity",
    "valid_from_height",
    "expires_at_height",
    "incident_contact_root",
}
CAPACITY_FIELDS = {
    "compute_units",
    "memory_bytes",
    "storage_bytes",
    "bandwidth_bps",
}
COMMON_ENTRY_FIELDS = {
    "entry_id",
    "operator_id",
    "sequence",
    "previous_entry_id",
    "operation",
    "effective_height",
}


class RegistryError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def decode_public(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise RegistryError(f"{field} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise RegistryError(f"{field} is not canonical base64") from error
    if len(decoded) != 32:
        raise RegistryError(f"{field} must contain a 32-byte Ed25519 key")
    return decoded


def decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise RegistryError("operator registry signature must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise RegistryError("operator registry signature is not canonical base64") from error
    if len(decoded) != 64:
        raise RegistryError("operator registry signature must contain 64 bytes")
    return decoded


def load_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RegistryError(f"cannot read operator signing seed: {error}") from error
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise RegistryError("operator signing seed must be 32 raw bytes or 64 hex characters") from error
    elif len(raw) == 32:
        seed = raw
    else:
        raise RegistryError("operator signing seed must be 32 raw bytes or 64 hex characters")
    if seed == bytes(32):
        raise RegistryError("all-zero operator signing seed is forbidden")
    return seed


def record_id(record: dict[str, Any]) -> str:
    payload = dict(record)
    payload.pop("record_id", None)
    return sha256(RECORD_DOMAIN + canonical_json(payload))


def validate_record(record: Any, *, initial: bool = False) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise RegistryError("operator enrollment record fields are malformed")
    for field in (
        "record_id",
        "operator_id",
        "organization_root",
        "beneficial_owner_root",
        "control_cluster_id",
        "provider_root",
        "region_id",
        "software_lineage_root",
        "model_publisher_root",
        "incident_contact_root",
    ):
        if not isinstance(record[field], str) or not HEX64.fullmatch(record[field]):
            raise RegistryError(f"operator enrollment {field} must be lowercase hex64")
    if record["record_id"] != record_id(record):
        raise RegistryError("operator enrollment record id mismatch")
    keys = [
        decode_public(record["identity_public_key_base64"], "identity key"),
        decode_public(record["operational_public_key_base64"], "operational key"),
        decode_public(record["revocation_public_key_base64"], "revocation key"),
    ]
    if len(set(keys)) != 3:
        raise RegistryError("operator identity, operational, and revocation keys must be distinct")
    if initial and record["operator_id"] != sha256(RECORD_DOMAIN + keys[0]):
        raise RegistryError("initial operator id is not derived from its identity key")
    roles = record["roles"]
    if (
        not isinstance(roles, list)
        or not roles
        or len(roles) > 16
        or roles != sorted(set(roles))
        or any(not isinstance(role, str) or not ROLE.fullmatch(role) for role in roles)
    ):
        raise RegistryError("operator enrollment roles are malformed")
    capacity = record["capacity"]
    if (
        not isinstance(capacity, dict)
        or set(capacity) != CAPACITY_FIELDS
        or any(
            not isinstance(capacity[field], int)
            or isinstance(capacity[field], bool)
            or capacity[field] < 0
            for field in CAPACITY_FIELDS
        )
        or capacity["compute_units"] == 0
    ):
        raise RegistryError("operator enrollment capacity is malformed")
    asn = record["asn"]
    if not isinstance(asn, int) or isinstance(asn, bool) or not 1 <= asn <= 4_294_967_295:
        raise RegistryError("operator enrollment ASN is invalid")
    valid_from = record["valid_from_height"]
    expires = record["expires_at_height"]
    if (
        not isinstance(valid_from, int)
        or isinstance(valid_from, bool)
        or valid_from < 0
        or not isinstance(expires, int)
        or isinstance(expires, bool)
        or expires <= valid_from
    ):
        raise RegistryError("operator enrollment validity interval is invalid")
    return record


def entry_id(body: dict[str, Any]) -> str:
    payload = dict(body)
    payload.pop("entry_id", None)
    return sha256(ENTRY_ID_DOMAIN + canonical_json(payload))


def signature_map(entry: dict[str, Any]) -> dict[bytes, bytes]:
    signatures = entry.get("signatures")
    if not isinstance(signatures, list) or not signatures or len(signatures) > 8:
        raise RegistryError("operator registry entry signatures are malformed")
    result: dict[bytes, bytes] = {}
    body = entry["body"]
    message = SIGNATURE_DOMAIN + canonical_json(body)
    for row in signatures:
        if not isinstance(row, dict) or set(row) != {
            "key_id",
            "public_key_base64",
            "signature_base64",
        }:
            raise RegistryError("operator registry signature row is malformed")
        public = decode_public(row["public_key_base64"], "signature public key")
        if row["key_id"] != sha256(public) or public in result:
            raise RegistryError("operator registry signature key id is invalid or duplicated")
        signature = decode_signature(row["signature_base64"])
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        except InvalidSignature as error:
            raise RegistryError("operator registry signature is invalid") from error
        result[public] = signature
    return result


def required_public_keys(record: dict[str, Any]) -> set[bytes]:
    return {
        decode_public(record["identity_public_key_base64"], "identity key"),
        decode_public(record["operational_public_key_base64"], "operational key"),
        decode_public(record["revocation_public_key_base64"], "revocation key"),
    }


def validate_entry_envelope(entry: Any) -> tuple[dict[str, Any], dict[bytes, bytes]]:
    if not isinstance(entry, dict) or set(entry) != {"schema", "body", "signatures"} or entry.get("schema") != ENTRY_SCHEMA:
        raise RegistryError("operator registry entry envelope is malformed")
    body = entry["body"]
    if not isinstance(body, dict):
        raise RegistryError("operator registry entry body must be an object")
    common = COMMON_ENTRY_FIELDS
    operation = body.get("operation")
    operation_fields = {
        "ENROLL": {"record"},
        "PUBLISH_SUCCESSOR": {"successor", "overlap_until_height"},
        "ACTIVATE_SUCCESSOR": {"successor_record_id"},
        "REVOKE": {"target_record_id", "reason_root"},
    }
    if operation not in operation_fields or set(body) != common | operation_fields[operation]:
        raise RegistryError("operator registry operation fields are malformed")
    for field in ("entry_id", "operator_id"):
        if not isinstance(body[field], str) or not HEX64.fullmatch(body[field]):
            raise RegistryError(f"operator registry {field} is invalid")
    if body["entry_id"] != entry_id(body):
        raise RegistryError("operator registry entry id mismatch")
    sequence = body["sequence"]
    effective = body["effective_height"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise RegistryError("operator registry sequence is invalid")
    if not isinstance(effective, int) or isinstance(effective, bool) or effective < 0:
        raise RegistryError("operator registry effective height is invalid")
    previous = body["previous_entry_id"]
    if previous is not None and (not isinstance(previous, str) or not HEX64.fullmatch(previous)):
        raise RegistryError("operator registry previous entry id is invalid")
    if operation == "ENROLL":
        validate_record(body["record"], initial=True)
        if body["record"]["operator_id"] != body["operator_id"]:
            raise RegistryError("operator enrollment operator id mismatch")
    elif operation == "PUBLISH_SUCCESSOR":
        validate_record(body["successor"])
        overlap = body["overlap_until_height"]
        if not isinstance(overlap, int) or isinstance(overlap, bool) or overlap <= effective:
            raise RegistryError("operator successor overlap interval is invalid")
    else:
        target_field = "successor_record_id" if operation == "ACTIVATE_SUCCESSOR" else "target_record_id"
        if not isinstance(body[target_field], str) or not HEX64.fullmatch(body[target_field]):
            raise RegistryError("operator transition target record id is invalid")
        if operation == "REVOKE" and (
            not isinstance(body["reason_root"], str) or not HEX64.fullmatch(body["reason_root"])
        ):
            raise RegistryError("operator revocation reason root is invalid")
    return body, signature_map(entry)


@dataclass
class OperatorState:
    operator_id: str
    sequence: int
    last_entry_id: str
    active: dict[str, Any]
    pending: dict[str, Any] | None = None
    overlap_until_height: int | None = None
    revoked_at_height: int | None = None

    def record_at(self, height: int) -> dict[str, Any] | None:
        if self.revoked_at_height is not None and height >= self.revoked_at_height:
            return None
        if self.active["valid_from_height"] <= height < self.active["expires_at_height"]:
            return self.active
        return None


def require_signers(observed: dict[bytes, bytes], expected: Iterable[bytes], label: str) -> None:
    required = set(expected)
    if set(observed) != required:
        raise RegistryError(f"{label} signatures do not prove possession of the exact required keys")


def apply_entry(states: dict[str, OperatorState], entry: dict[str, Any]) -> None:
    body, signatures = validate_entry_envelope(entry)
    operator_id = body["operator_id"]
    state = states.get(operator_id)
    operation = body["operation"]
    if operation == "ENROLL":
        record = body["record"]
        if state is not None or body["sequence"] != 1 or body["previous_entry_id"] is not None:
            raise RegistryError("initial enrollment is duplicated or does not start at sequence one")
        if body["effective_height"] != record["valid_from_height"]:
            raise RegistryError("initial enrollment effective height mismatch")
        require_signers(signatures, required_public_keys(record), "initial enrollment")
        states[operator_id] = OperatorState(operator_id, 1, body["entry_id"], record)
        return
    if state is None:
        raise RegistryError("operator transition has no initial enrollment")
    if body["sequence"] != state.sequence + 1 or body["previous_entry_id"] != state.last_entry_id:
        raise RegistryError("operator transition sequence or predecessor is discontinuous")
    if state.revoked_at_height is not None:
        raise RegistryError("revoked operator cannot publish another transition")
    current_identity = decode_public(state.active["identity_public_key_base64"], "active identity key")
    if operation == "PUBLISH_SUCCESSOR":
        successor = body["successor"]
        if successor["operator_id"] != operator_id or state.pending is not None:
            raise RegistryError("operator successor has the wrong identity or a predecessor is already pending")
        if (
            successor["record_id"] == state.active["record_id"]
            or successor["valid_from_height"] < body["effective_height"]
            or successor["valid_from_height"] > body["overlap_until_height"]
            or body["overlap_until_height"] >= state.active["expires_at_height"]
        ):
            raise RegistryError("operator successor validity or overlap is unsafe")
        require_signers(
            signatures,
            {current_identity, *required_public_keys(successor)},
            "successor publication",
        )
        state.pending = successor
        state.overlap_until_height = body["overlap_until_height"]
    elif operation == "ACTIVATE_SUCCESSOR":
        pending = state.pending
        if pending is None or body["successor_record_id"] != pending["record_id"]:
            raise RegistryError("operator activation does not name the published successor")
        if (
            state.overlap_until_height is None
            or body["effective_height"] < pending["valid_from_height"]
            or body["effective_height"] > state.overlap_until_height
        ):
            raise RegistryError("operator successor activation is outside the overlap")
        successor_identity = decode_public(pending["identity_public_key_base64"], "successor identity key")
        require_signers(signatures, {current_identity, successor_identity}, "successor activation")
        state.active = pending
        state.pending = None
        state.overlap_until_height = None
    else:
        if body["target_record_id"] != state.active["record_id"]:
            raise RegistryError("operator revocation does not target the active record")
        if body["effective_height"] < state.active["valid_from_height"]:
            raise RegistryError("operator revocation predates the active record")
        revocation = decode_public(state.active["revocation_public_key_base64"], "revocation key")
        require_signers(signatures, {revocation}, "operator revocation")
        state.revoked_at_height = body["effective_height"]
        state.pending = None
        state.overlap_until_height = None
    state.sequence = body["sequence"]
    state.last_entry_id = body["entry_id"]


def load_ledger(path: Path) -> tuple[list[dict[str, Any]], dict[str, OperatorState]]:
    if not path.exists():
        return [], {}
    try:
        size = path.stat().st_size
        if size > MAX_LEDGER_BYTES:
            raise RegistryError("operator registry ledger exceeds its byte bound")
        entries: list[dict[str, Any]] = []
        states: dict[str, OperatorState] = {}
        with path.open("r", encoding="utf-8") as source:
            for number, line in enumerate(source, 1):
                if number > MAX_ENTRIES:
                    raise RegistryError("operator registry ledger exceeds its entry bound")
                if not line.endswith("\n") or len(line.encode("utf-8")) > MAX_ENTRY_BYTES:
                    raise RegistryError(f"operator registry ledger line {number} is truncated or oversized")
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as error:
                    raise RegistryError(f"operator registry ledger line {number} is malformed") from error
                if not isinstance(entry, dict):
                    raise RegistryError(f"operator registry ledger line {number} is not an object")
                apply_entry(states, entry)
                entries.append(entry)
    except (OSError, UnicodeDecodeError) as error:
        raise RegistryError(f"cannot read operator registry ledger: {error}") from error
    return entries, states


def append_entry(ledger: Path, entry: dict[str, Any]) -> dict[str, OperatorState]:
    encoded = canonical_json(entry) + b"\n"
    if len(encoded) > MAX_ENTRY_BYTES:
        raise RegistryError("operator registry entry exceeds its byte bound")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    lock = ledger.with_suffix(ledger.suffix + ".lock")
    descriptor: int | None = None
    lock_acquired = False
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        lock_acquired = True
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.close(descriptor)
        descriptor = None
        entries, states = load_ledger(ledger)
        if len(entries) >= MAX_ENTRIES:
            raise RegistryError("operator registry ledger entry bound reached")
        apply_entry(states, entry)
        with ledger.open("ab") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
        _, recovered = load_ledger(ledger)
        return recovered
    except FileExistsError as error:
        raise RegistryError("operator registry ledger is locked by another writer") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if lock_acquired:
            lock.unlink(missing_ok=True)


def sign_body(body: dict[str, Any], seeds: Iterable[bytes]) -> dict[str, Any]:
    body = dict(body)
    body["entry_id"] = entry_id(body)
    keys = [Ed25519PrivateKey.from_private_bytes(seed) for seed in seeds]
    if not keys:
        raise RegistryError("operator registry signing requires at least one seed")
    message = SIGNATURE_DOMAIN + canonical_json(body)
    signatures = []
    for key in keys:
        public = key.public_key().public_bytes_raw()
        signatures.append(
            {
                "key_id": sha256(public),
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "signature_base64": base64.b64encode(key.sign(message)).decode("ascii"),
            }
        )
    signatures.sort(key=lambda row: row["key_id"])
    entry = {"schema": ENTRY_SCHEMA, "body": body, "signatures": signatures}
    validate_entry_envelope(entry)
    return entry


def active_operational_key(states: dict[str, OperatorState], operator_id: str, height: int) -> bytes:
    state = states.get(operator_id)
    record = None if state is None else state.record_at(height)
    if record is None:
        raise RegistryError("operator has no active unexpired enrollment at this height")
    return decode_public(record["operational_public_key_base64"], "operational key")


def validate_policy(policy: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "minimum_members",
        "minimum_distinct_beneficial_owners",
        "minimum_distinct_control_clusters",
        "minimum_distinct_providers",
        "minimum_distinct_regions",
        "minimum_distinct_asns",
        "minimum_distinct_software_lineages",
        "minimum_distinct_model_publishers",
        "maximum_members_per_provider",
        "maximum_members_per_region",
    }
    if not isinstance(policy, dict) or set(policy) != fields or policy.get("schema") != POLICY_SCHEMA:
        raise RegistryError("operator diversity policy is malformed")
    minimum = policy["minimum_members"]
    if not isinstance(minimum, int) or isinstance(minimum, bool) or not 1 <= minimum <= 32:
        raise RegistryError("operator diversity minimum member count is invalid")
    for field in fields - {"schema", "minimum_members", "maximum_members_per_provider", "maximum_members_per_region"}:
        value = policy[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= minimum:
            raise RegistryError(f"operator diversity {field} is invalid")
    for field in ("maximum_members_per_provider", "maximum_members_per_region"):
        value = policy[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= minimum:
            raise RegistryError(f"operator diversity {field} is invalid")
    return policy


def admit_committee(
    states: dict[str, OperatorState], operator_ids: list[str], height: int, policy: dict[str, Any]
) -> dict[str, Any]:
    policy = validate_policy(policy)
    if operator_ids != sorted(set(operator_ids)) or len(operator_ids) < policy["minimum_members"]:
        raise RegistryError("operator committee identifiers are duplicated, unsorted, or too few")
    records = []
    for operator_id in operator_ids:
        if not HEX64.fullmatch(operator_id):
            raise RegistryError("operator committee identifier is malformed")
        state = states.get(operator_id)
        record = None if state is None else state.record_at(height)
        if record is None:
            raise RegistryError("operator committee includes an inactive, expired, or revoked enrollment")
        records.append(record)
    dimensions = {
        "beneficial_owners": ("beneficial_owner_root", "minimum_distinct_beneficial_owners"),
        "control_clusters": ("control_cluster_id", "minimum_distinct_control_clusters"),
        "providers": ("provider_root", "minimum_distinct_providers"),
        "regions": ("region_id", "minimum_distinct_regions"),
        "asns": ("asn", "minimum_distinct_asns"),
        "software_lineages": ("software_lineage_root", "minimum_distinct_software_lineages"),
        "model_publishers": ("model_publisher_root", "minimum_distinct_model_publishers"),
    }
    observed: dict[str, int] = {}
    for name, (record_field, policy_field) in dimensions.items():
        count = len({record[record_field] for record in records})
        observed[name] = count
        if count < policy[policy_field]:
            raise RegistryError(f"operator committee violates {name} diversity")
    for record_field, policy_field, label in (
        ("provider_root", "maximum_members_per_provider", "provider concentration"),
        ("region_id", "maximum_members_per_region", "region concentration"),
    ):
        counts: dict[Any, int] = {}
        for record in records:
            counts[record[record_field]] = counts.get(record[record_field], 0) + 1
        if max(counts.values()) > policy[policy_field]:
            raise RegistryError(f"operator committee violates {label}")
    return {
        "schema": "noos/wwm-operator-committee-admission/v1",
        "height": height,
        "operator_ids": operator_ids,
        "distinct": observed,
        "policy_sha256": sha256(canonical_json(policy)),
        "admitted": True,
    }


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistryError(f"cannot load operator registry JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise RegistryError(f"operator registry JSON must be an object: {path}")
    return value


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
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise RegistryError(f"cannot write operator registry JSON {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign, append, verify, and admit WWM operator enrollment records")
    subparsers = parser.add_subparsers(dest="command", required=True)
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--body", type=Path, required=True)
    sign_parser.add_argument("--seed-file", action="append", type=Path, required=True)
    sign_parser.add_argument("--output", type=Path, required=True)
    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("--ledger", type=Path, required=True)
    append_parser.add_argument("--entry", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--ledger", type=Path, required=True)
    committee_parser = subparsers.add_parser("committee")
    committee_parser.add_argument("--ledger", type=Path, required=True)
    committee_parser.add_argument("--policy", type=Path, required=True)
    committee_parser.add_argument("--height", type=int, required=True)
    committee_parser.add_argument("--operator", action="append", default=[], required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            value = sign_body(load_object(args.body), [load_seed(path) for path in args.seed_file])
            atomic_write(args.output, value)
        elif args.command == "append":
            states = append_entry(args.ledger, load_object(args.entry))
            value = {"operators": len(states), "ledger": str(args.ledger)}
        elif args.command == "verify":
            entries, states = load_ledger(args.ledger)
            value = {"entries": len(entries), "operators": len(states), "ledger_sha256": sha256(args.ledger.read_bytes())}
        else:
            _, states = load_ledger(args.ledger)
            value = admit_committee(states, sorted(args.operator), args.height, load_object(args.policy))
    except RegistryError as error:
        print(f"operator registry failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
