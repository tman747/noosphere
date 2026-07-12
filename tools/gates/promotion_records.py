"""Canonical cryptographic validation for v2 promotion-gate records.

Blocked ledgers may remain unsigned.  A gate can be interpreted as PASSED only
through this module and only when its closed record, evidence bytes, predecessor
chain, pinned external role keyring, and every required signature verify.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature

ORDER = ["G0", "G1", "G2", "G3", "GENESIS", "G4", "G5"]
HASH = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = re.compile(r"(?:OWNER_BLOCKED|PENDING|REPLACE_ME|EXAMPLE|fixture\s*:\s*true)", re.IGNORECASE)
DOMAIN = "NOOS/PROMOTION/GATE/V2"
REQUIRED_ROLES = ("release-owner", "independent-build-reviewer", "operations-owner", "security-reviewer")
REQUIRED_REQUIREMENTS = {
    "G0": ["G0.REGISTRY_SCHEMA", "G0.OWNER_CONSTANTS"],
    "G1": ["G1.DETERMINISTIC_LAB"],
    "G2": ["G2.INDEPENDENT_DEVNET"],
    "G3": ["G3.PUBLIC_DURATION", "G3.A_BRAID_AI_OFF", "G3.EXTERNAL_ASSURANCE"],
    "GENESIS": ["GENESIS.QUIET_WEEK", "GENESIS.BITCOIN_ANCHOR", "GENESIS.DKG", "GENESIS.MAINNET_ECONOMICS", "GENESIS.REPRO_DEMO"],
    "G4": ["G4.CANARY_DURATION", "G4.EXIT_AND_FAULT_DRILLS", "G4.HARDWARE_BUILDERS"],
    "G5": ["G5.EXACT_LOWER_GATES", "G5.CLAIM_COMPLETENESS", "G5.EXTERNAL_REVIEWS", "G5.LIVE_DIVERSITY", "G5.SIGNATURES"],
}
RECORD_KEYS = {
    "schema_version", "kind", "gate_id", "exact_revision", "chain_id", "genesis_hash",
    "ordered_prerequisite_record_hashes", "requirement_ids", "evidence_artifacts", "unresolved",
    "decision", "signer_roles", "signer_key_ids", "predecessor_record_hash",
    "predecessor_ledger_root", "role_keyring_sha256",
}
EVIDENCE_KEYS = {"requirement_id", "path", "sha256", "schema", "kind"}
SIGNATURE_KEYS = {"role", "key_id", "signature_ed25519_hex"}


class PromotionValidationError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def ledger_root(record_hashes: Sequence[str]) -> str:
    return digest(b"NOOS/PROMOTION/LEDGER/V2\x00" + canonical_json(list(record_hashes)))


def _safe(root: Path, rel: Any) -> Path:
    if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or "\\" in rel:
        raise PromotionValidationError(f"unsafe evidence path: {rel!r}")
    path = (root / rel).resolve()
    resolved_root = root.resolve()
    if path != resolved_root and resolved_root not in path.parents:
        raise PromotionValidationError(f"evidence path escapes repository: {rel}")
    return path


def _validate_evidence(root: Path, descriptor: Mapping[str, Any], gate_id: str, revision: str,
                       chain_id: str, genesis_hash: str, *, test_mode: bool) -> None:
    if set(descriptor) != EVIDENCE_KEYS:
        raise PromotionValidationError("evidence descriptor field set mismatch")
    if not HASH.fullmatch(str(descriptor.get("sha256", ""))):
        raise PromotionValidationError("evidence descriptor sha256 malformed")
    path = _safe(root, descriptor.get("path"))
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != descriptor["sha256"]:
        raise PromotionValidationError(f"evidence bytes/hash mismatch: {descriptor.get('path')}")
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionValidationError(f"evidence must be typed canonical JSON: {path}: {exc}") from exc
    schema, kind = descriptor.get("schema"), descriptor.get("kind")
    if schema == "urn:noos:stage-evidence:v1" and kind == "stage-evidence":
        binding = doc.get("protocol_binding", {}) if isinstance(doc, dict) else {}
        if (
            doc.get("schema_version") != 1 or doc.get("stage") != gate_id
            or doc.get("evaluation", {}).get("verdict") != "PASS"
            or binding.get("revision") != revision or binding.get("chain_id") != chain_id
            or binding.get("genesis_hash") != genesis_hash
        ):
            raise PromotionValidationError("stage evidence type/revision/identity/verdict mismatch")
        if (
            doc.get("execution", {}).get("exit_code") != 0
            or doc.get("evaluation", {}).get("conflicts") != []
            or doc.get("evaluation", {}).get("exclusions") != []
        ):
            raise PromotionValidationError("stage evidence execution/conflicts/exclusions do not validate as PASS")
        hashed_files = list(doc.get("raw_artifacts", [])) + list(doc.get("inputs", {}).get("fixtures", []))
        if not hashed_files:
            raise PromotionValidationError("stage evidence has no content-addressed raw artifacts")
        for artifact in hashed_files:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "bytes", "sha256"}:
                raise PromotionValidationError("stage evidence raw artifact descriptor malformed")
            artifact_path = _safe(root, artifact.get("path"))
            if (
                not artifact_path.is_file() or artifact_path.stat().st_size != artifact.get("bytes")
                or hashlib.sha256(artifact_path.read_bytes()).hexdigest() != artifact.get("sha256")
            ):
                raise PromotionValidationError(f"stage evidence raw artifact bytes/hash mismatch: {artifact.get('path')}")
        if PLACEHOLDER.search(json.dumps(doc, sort_keys=True)):
            raise PromotionValidationError("stage evidence contains placeholder/fixture fields")
    elif test_mode and schema == "noos/test-promotion-evidence/v1" and kind == "signed-test-fixture":
        if doc != {
            "schema": schema, "kind": kind, "gate_id": gate_id,
            "exact_revision": revision, "chain_id": chain_id, "genesis_hash": genesis_hash,
            "is_test_fixture": True, "verdict": "PASS",
        }:
            raise PromotionValidationError("test evidence fixture is not the closed explicit test shape")
    else:
        raise PromotionValidationError(f"unknown evidence schema/kind: {schema!r}/{kind!r}")


def validate_promotion_ledger(
    ledger: Mapping[str, Any], root: Path, keyring: Mapping[str, Any] | None = None,
    *, trusted_role_keyring_sha256: str | None = None, expected_revision: str | None = None,
    expected_chain_id: str | None = None, expected_genesis_hash: str | None = None,
    require_all_passed: bool = False, test_mode: bool = False,
) -> dict[str, Any]:
    binding = ledger.get("protocol_binding", {})
    revision = binding.get("revision")
    chain_id = binding.get("chain_id")
    genesis_hash = binding.get("genesis_hash")
    if expected_revision is not None and revision != expected_revision:
        raise PromotionValidationError("promotion revision mismatch")
    if expected_chain_id is not None and chain_id != expected_chain_id:
        raise PromotionValidationError("promotion chain_id mismatch")
    if expected_genesis_hash is not None and genesis_hash != expected_genesis_hash:
        raise PromotionValidationError("promotion genesis_hash mismatch")
    gates = ledger.get("gates")
    if not isinstance(gates, list) or [g.get("gate") for g in gates if isinstance(g, dict)] != ORDER:
        raise PromotionValidationError("promotion gate order mismatch")
    auth_binding = ledger.get("authorization_binding", {})
    passed_hashes: list[str] = []
    all_passed = True
    for index, gate in enumerate(gates):
        state = gate.get("state")
        if state != "PASSED":
            all_passed = False
            if gate.get("signatures"):
                raise PromotionValidationError(f"{ORDER[index]}: non-PASSED gate cannot carry signatures")
            continue
        if not REVISION.fullmatch(str(revision or "")) or not HASH.fullmatch(str(chain_id or "")) or not HASH.fullmatch(str(genesis_hash or "")):
            raise PromotionValidationError("PASSED gate requires frozen revision/chain/genesis identity")
        if keyring is None or trusted_role_keyring_sha256 is None or not HASH.fullmatch(trusted_role_keyring_sha256):
            raise PromotionValidationError("PASSED gate requires an externally pinned role keyring root")
        if auth_binding.get("role_keyring_sha256") != trusted_role_keyring_sha256:
            raise PromotionValidationError("ledger role keyring root is not the externally pinned root")
        record = gate.get("authorization_record")
        if not isinstance(record, dict) or set(record) != RECORD_KEYS:
            raise PromotionValidationError(f"{ORDER[index]}: closed authorization record missing/fields mismatch")
        if not test_mode and PLACEHOLDER.search(json.dumps(record, sort_keys=True)):
            raise PromotionValidationError(f"{ORDER[index]}: authorization record contains placeholder/fixture fields")
        requirement_ids = [r.get("requirement_id") for r in gate.get("requirements", []) if isinstance(r, dict)]
        if requirement_ids != REQUIRED_REQUIREMENTS[ORDER[index]]:
            raise PromotionValidationError(f"{ORDER[index]}: exact ordered requirement ID set mismatch")
        expected_predecessor = passed_hashes[-1] if passed_hashes else "0" * 64
        expected_prior_root = ledger_root(passed_hashes)
        expected_key_ids = [getattr(keyring.get(role), "key_id", None) for role in REQUIRED_ROLES]
        expected_values = {
            "schema_version": 2, "kind": "noosphere-promotion-gate-record-v2",
            "gate_id": ORDER[index], "exact_revision": revision, "chain_id": chain_id,
            "genesis_hash": genesis_hash, "ordered_prerequisite_record_hashes": passed_hashes,
            "requirement_ids": requirement_ids, "unresolved": [], "decision": "PASSED",
            "signer_roles": list(REQUIRED_ROLES), "signer_key_ids": expected_key_ids,
            "predecessor_record_hash": expected_predecessor,
            "predecessor_ledger_root": expected_prior_root,
            "role_keyring_sha256": trusted_role_keyring_sha256,
        }
        for field, expected in expected_values.items():
            if record.get(field) != expected:
                raise PromotionValidationError(f"{ORDER[index]}: authorization record mismatch at {field}")
        if gate.get("unresolved") != []:
            raise PromotionValidationError(f"{ORDER[index]}: PASSED gate has unresolved requirements")
        requirements = gate.get("requirements", [])
        if not requirements or any(r.get("status") != "SATISFIED" or r.get("verdict") != "PASS" or r.get("exact_revision") != revision for r in requirements):
            raise PromotionValidationError(f"{ORDER[index]}: requirements do not recompute to PASSED")
        evidence = record.get("evidence_artifacts")
        if not isinstance(evidence, list) or not evidence:
            raise PromotionValidationError(f"{ORDER[index]}: PASSED gate has no typed evidence")
        evidence_requirement_ids = {item.get("requirement_id") for item in evidence if isinstance(item, dict)}
        if evidence_requirement_ids != set(requirement_ids):
            raise PromotionValidationError(f"{ORDER[index]}: evidence does not cover exact requirement set")
        for descriptor in evidence:
            if not isinstance(descriptor, dict):
                raise PromotionValidationError("evidence descriptor malformed")
            _validate_evidence(root, descriptor, ORDER[index], revision, chain_id, genesis_hash, test_mode=test_mode)
        raw = canonical_json(record)
        record_hash = digest(raw)
        signatures = gate.get("signatures")
        if not isinstance(signatures, list) or len(signatures) != len(REQUIRED_ROLES):
            raise PromotionValidationError(f"{ORDER[index]}: exact required signature set absent")
        by_role: dict[str, Mapping[str, Any]] = {}
        for signature in signatures:
            if not isinstance(signature, dict) or set(signature) != SIGNATURE_KEYS:
                raise PromotionValidationError("promotion signature field set mismatch")
            role = signature.get("role")
            if role in by_role or role not in REQUIRED_ROLES:
                raise PromotionValidationError("promotion signature duplicate/unknown role")
            by_role[role] = signature
        message = DOMAIN.encode("ascii") + b"\x00" + raw
        for role_name in REQUIRED_ROLES:
            role = keyring.get(role_name)
            signature = by_role.get(role_name)
            if role is None or signature is None or signature.get("key_id") != getattr(role, "key_id", None):
                raise PromotionValidationError(f"promotion signature role/key mismatch: {role_name}")
            try:
                role.public.verify(bytes.fromhex(signature["signature_ed25519_hex"]), message)
            except (ValueError, TypeError, InvalidSignature) as exc:
                raise PromotionValidationError(f"promotion signature invalid: {role_name}") from exc
        passed_hashes.append(record_hash)
    computed_root = ledger_root(passed_hashes)
    if all_passed:
        if auth_binding.get("ledger_root") != computed_root:
            raise PromotionValidationError("complete promotion ledger root mismatch")
    elif auth_binding.get("ledger_root") not in (None, "OWNER_BLOCKED"):
        raise PromotionValidationError("incomplete promotion ledger cannot claim a ledger root")
    if require_all_passed and not all_passed:
        raise PromotionValidationError("cutover prohibited: every G0..G5 gate must cryptographically validate as PASSED")
    return {"all_passed": all_passed, "ledger_root": computed_root, "record_hashes": passed_hashes}
