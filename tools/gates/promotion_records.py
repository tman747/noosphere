"""Canonical cryptographic validation for explicitly selected promotion ledgers.

V1 remains a historical validation surface. Protocol/API V2 is a clean ledger
whose first edge binds the exact immutable V1 file bytes. Blocked ledgers may
remain unsigned; a gate is PASSED only after its closed record, evidence,
predecessor chain, externally pinned role keys, and every signature verify.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from validate_registry import schema_validate

ORDER = ["G0", "G1", "G2", "G3", "GENESIS", "G4", "G5"]
HASH = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = re.compile(r"(?:OWNER_BLOCKED|PENDING|REPLACE_ME|EXAMPLE|fixture\s*:\s*true)", re.IGNORECASE)
V1_LEDGER_DOMAIN_ID = "D-PROMOTION-LEDGER-V2"
V1_PREDECESSOR_PATH = "protocol/release/promotion-blockers.json"
V1_PREDECESSOR_SHA256 = "2509d617934e2c69eea64c6af228ae1b43aa2953269589c9da8b0099f0faf759"
V1_RELEASE_SCHEMA_PATH = "protocol/release/manifest-schema-v1.json"
V1_RELEASE_SCHEMA_SHA256 = "10d9f1e939fa304508f483db4023bd3d412458136c4b628c48831e2052fcb6c5"
REQUIRED_ROLES = ("release-owner", "independent-build-reviewer", "operations-owner", "security-reviewer")
REQUIRED_REQUIREMENTS_V1 = {
    "G0": ["G0.REGISTRY_SCHEMA", "G0.OWNER_CONSTANTS"],
    "G1": ["G1.DETERMINISTIC_LAB"],
    "G2": ["G2.INDEPENDENT_DEVNET"],
    "G3": ["G3.PUBLIC_DURATION", "G3.A_BRAID_AI_OFF", "G3.EXTERNAL_ASSURANCE"],
    "GENESIS": ["GENESIS.QUIET_WEEK", "GENESIS.BITCOIN_ANCHOR", "GENESIS.DKG", "GENESIS.MAINNET_ECONOMICS", "GENESIS.REPRO_DEMO"],
    "G4": ["G4.CANARY_DURATION", "G4.EXIT_AND_FAULT_DRILLS", "G4.HARDWARE_BUILDERS"],
    "G5": ["G5.EXACT_LOWER_GATES", "G5.CLAIM_COMPLETENESS", "G5.EXTERNAL_REVIEWS", "G5.LIVE_DIVERSITY", "G5.SIGNATURES"],
}
REQUIRED_REQUIREMENTS_V2 = {
    **REQUIRED_REQUIREMENTS_V1,
    "G0": ["G0.PROTOCOL_V2_SCHEMA", "G0.V1_PREDECESSOR", "G0.OWNER_CONSTANTS", "G0.INDEPENDENT_REVIEW"],
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


def registered_domain(domain_id: str, *, root: Path | None = None) -> str:
    """Resolve one generated-domain source entry; callers never copy contexts."""
    registry = (root or Path(__file__).resolve().parents[2]) / "protocol/spec/crypto-domains-v1.csv"
    with registry.open(newline="", encoding="utf-8") as stream:
        rows = csv.DictReader(line for line in stream if not line.startswith("#"))
        matches = [row["context_string"] for row in rows if row.get("domain_id") == domain_id]
    if len(matches) != 1:
        raise PromotionValidationError(f"domain registry selection is not unique: {domain_id}")
    return matches[0]


def ledger_root(record_hashes: Sequence[str], *, schema_version: int = 1) -> str:
    if schema_version == 1:
        domain = registered_domain(V1_LEDGER_DOMAIN_ID).encode("ascii")
    elif schema_version == 2:
        domain = registered_domain("D-PROMOTION-PROTOCOL-V2-LEDGER").encode("ascii")
    else:
        raise PromotionValidationError(f"unsupported promotion schema version: {schema_version}")
    return digest(domain + b"\x00" + canonical_json(list(record_hashes)))


def validate_schema_dispatch(ledger: Mapping[str, Any], root: Path, schema_version: int) -> None:
    """Reject inference and mixed schema/protocol/API identities."""
    if schema_version == 1:
        expected = {
            "$schema": "promotion-blockers-schema-v1.json",
            "schema_version": 1,
        }
        for key, value in expected.items():
            if key in ledger and ledger.get(key) != value:
                raise PromotionValidationError(f"V1 promotion ledger mismatch at {key}")
        binding = ledger.get("protocol_binding", {})
        for key in ("protocol_version", "api_version"):
            if key in binding and binding.get(key) != "v1":
                raise PromotionValidationError(f"V1 promotion ledger has mixed {key}")
        if "predecessor" in ledger:
            raise PromotionValidationError("V1 promotion ledger cannot carry a V2 predecessor")
        return
    if schema_version != 2:
        raise PromotionValidationError(f"unsupported promotion schema version: {schema_version}")
    if ledger.get("$schema") != "promotion-blockers-schema-v2.json" or ledger.get("schema_version") != 2:
        raise PromotionValidationError("V2 promotion ledger/schema binding mismatch")
    binding = ledger.get("protocol_binding", {})
    expected_binding = {
        "protocol_identity": "noos-protocol-identity-v2",
        "protocol_version": "v2",
        "api_version": "v2",
        "peer_identity": "v2-only",
    }
    for key, value in expected_binding.items():
        if binding.get(key) != value:
            raise PromotionValidationError(f"V2 promotion ledger has mixed identity at {key}")
    predecessor = ledger.get("predecessor")
    expected_predecessor = {
        "kind": "noosphere-promotion-ledger-predecessor-v1",
        "ledger_path": V1_PREDECESSOR_PATH,
        "schema_version": 1,
        "protocol_version": "v1",
        "api_version": "v1",
        "release_version": "0.0.0-preproduction",
        "root_algorithm": "SHA-256-EXACT-FILE-BYTES",
        "predecessor_root": V1_PREDECESSOR_SHA256,
        "relation": "DIRECT_IMMUTABLE_PREDECESSOR",
    }
    if predecessor != expected_predecessor:
        raise PromotionValidationError("V2 promotion ledger predecessor is missing, wrong, or cyclic")
    predecessor_path = _safe(root, V1_PREDECESSOR_PATH)
    if not predecessor_path.is_file() or digest(predecessor_path.read_bytes()) != V1_PREDECESSOR_SHA256:
        raise PromotionValidationError("immutable V1 predecessor bytes/root mismatch")
    try:
        predecessor_doc = json.loads(predecessor_path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionValidationError(f"immutable V1 predecessor cannot be decoded: {exc}") from exc
    if (
        predecessor_doc.get("$schema") != "promotion-blockers-schema-v1.json"
        or predecessor_doc.get("schema_version") != 1
        or predecessor_doc.get("protocol_binding", {}).get("protocol_version") != "v1"
        or predecessor_doc.get("protocol_binding", {}).get("api_version") != "v1"
    ):
        raise PromotionValidationError("immutable predecessor is not the closed V1 identity")
    contracts = ledger.get("contracts", {})
    if contracts.get("v1_decode_policy") != "REJECT_V1_WWM_BYTES":
        raise PromotionValidationError("V2 promotion ledger permits mixed WWM bytes")
    if contracts.get("action_registry") != {
        "container": "ActionV1", "first_discriminant": 40,
        "last_discriminant": 65, "variant_count": 66,
    }:
        raise PromotionValidationError("V2 action discriminant/count contract mismatch")
    if contracts.get("transaction_bounds") != {
        "action_call_max_bytes": 65536, "tx_plus_witness_max_bytes": 65532,
        "tx_push_max_bytes": 65536, "tx_push_length_prefix_bytes": 4,
    }:
        raise PromotionValidationError("V2 transaction bound contract mismatch")
    if contracts.get("light_update") != {
        "protocol": "/noos/sync/light-update/2", "max_items": 128,
        "max_item_bytes": 262144, "request_min_items": 1,
    }:
        raise PromotionValidationError("V2 light-update contract mismatch")
    if contracts.get("resolver") != {
        "target": "/model-resolution/<selector>", "max_bytes": 262144,
        "max_proofs": 17, "normal_leaf_count": 17,
        "authorized_target": "/authorized-config/<config_id>", "authorized_max_bytes": 393216,
        "neural_target": "/neural-oracle/<query_id>", "neural_response_max_bytes": 16384,
    }:
        raise PromotionValidationError("V2 resolver contract mismatch")
    expected_tags = {
        "action_41": ["InstallProfile", "TransitionCapability"],
        "action_50": ["InstallProfile", "TransitionCapability"],
        "action_52": ["StageFundProfile", "LockFundMutation", "ActivateFundProfile", "CloseFundProfile"],
        "action_58": ["TransitionServingAlias"],
        "action_59": ["Activate", "EmergencyDisable", "AuthorizeOperationalConfig", "ApplyOperationalConfig", "Recover"],
    }
    if contracts.get("payload_tags") != expected_tags:
        raise PromotionValidationError("V2 payload tag contract mismatch")
    auth_binding = ledger.get("authorization_binding", {})
    if auth_binding.get("gate_record_domain_id") != "D-PROMOTION-GATE-V2":
        raise PromotionValidationError("V2 gate-record domain selection mismatch")
    release_manifest = ledger.get("release_manifest", {})
    if (
        release_manifest.get("schema") != "protocol-release-manifest-v2.schema.json"
        or release_manifest.get("path") != "protocol/release/protocol-release-manifest-v2.json"
    ):
        raise PromotionValidationError("V2 release-manifest schema/path binding mismatch")
    manifest_status = release_manifest.get("status")
    manifest_hash = release_manifest.get("sha256")
    if not (
        (manifest_status == "OWNER_BLOCKED" and manifest_hash == "OWNER_BLOCKED")
        or (manifest_status == "BOUND" and isinstance(manifest_hash, str) and HASH.fullmatch(manifest_hash))
    ):
        raise PromotionValidationError("V2 release-manifest blocker/hash binding mismatch")
    schema_path = root / "protocol/release/promotion-blockers-schema-v2.json"
    try:
        schema = json.loads(schema_path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionValidationError(f"V2 promotion schema cannot be loaded: {exc}") from exc
    schema_errors = schema_validate(ledger, schema)
    if schema_errors:
        raise PromotionValidationError(f"V2 promotion schema violation: {schema_errors[0]}")


def validate_protocol_release_manifest_header(manifest: Mapping[str, Any], root: Path, schema_version: int) -> None:
    """Validate version identity and immutable predecessor before artifact work."""
    if schema_version == 1:
        if manifest.get("schema_version") != 1 or manifest.get("manifest_kind") != "noosphere-release-manifest":
            raise PromotionValidationError("wrong V1 release manifest schema/kind")
        release = manifest.get("release")
        if isinstance(release, Mapping) and (
            release.get("protocol_version") != "v1" or release.get("api_version") != "v1"
        ):
            raise PromotionValidationError("V1 release manifest has mixed protocol/API identity")
        if "predecessor_binding" in manifest:
            raise PromotionValidationError("V1 release manifest cannot carry a V2 predecessor")
        return
    if schema_version != 2:
        raise PromotionValidationError(f"unsupported release schema version: {schema_version}")
    if (
        manifest.get("$schema") != "protocol-release-manifest-v2.schema.json"
        or manifest.get("schema_version") != 2
        or manifest.get("manifest_kind") != "noosphere-protocol-release-manifest-v2"
    ):
        raise PromotionValidationError("wrong V2 release manifest schema/kind")
    release = manifest.get("release", {})
    expected_release = {
        "protocol_identity": "noos-protocol-identity-v2",
        "protocol_version": "v2",
        "api_version": "v2",
        "peer_identity": "v2-only",
    }
    for key, value in expected_release.items():
        if release.get(key) != value:
            raise PromotionValidationError(f"V2 release manifest has mixed identity at {key}")
    identity = manifest.get("identity", {})
    if identity.get("protocol_identity") != "noos-protocol-identity-v2":
        raise PromotionValidationError("V2 release chain identity is mixed")
    expected_predecessor = {
        "promotion_ledger": {
            "path": V1_PREDECESSOR_PATH, "schema_version": 1,
            "protocol_version": "v1", "api_version": "v1",
            "root_algorithm": "SHA-256-EXACT-FILE-BYTES", "root": V1_PREDECESSOR_SHA256,
        },
        "release_schema": {
            "path": V1_RELEASE_SCHEMA_PATH, "schema_version": 1,
            "root_algorithm": "SHA-256-EXACT-FILE-BYTES", "root": V1_RELEASE_SCHEMA_SHA256,
        },
        "relation": "CLEAN_V2_CUTOVER_FROM_IMMUTABLE_V1",
    }
    if manifest.get("predecessor_binding") != expected_predecessor:
        raise PromotionValidationError("V2 release predecessor is missing, wrong, or cyclic")
    for relative, expected in (
        (V1_PREDECESSOR_PATH, V1_PREDECESSOR_SHA256),
        (V1_RELEASE_SCHEMA_PATH, V1_RELEASE_SCHEMA_SHA256),
    ):
        path = _safe(root, relative)
        if not path.is_file() or digest(path.read_bytes()) != expected:
            raise PromotionValidationError(f"immutable V1 release predecessor bytes/root mismatch: {relative}")
    if manifest.get("activation_boundary") != {
        "controls_enabled": False, "promotion_effect": "NONE",
        "dns_cutover": "PROHIBITED",
        "model_execution": "LARGE_MODELS_OFF_CHAIN_BOUNDED_L1_NEURAL_ONLY",
    }:
        raise PromotionValidationError("V2 release manifest fabricates activation or promotion")
    contracts = manifest.get("contracts", {})
    if contracts.get("action_variant_count") != 66 or contracts.get("action_discriminants") != list(range(40, 66)):
        raise PromotionValidationError("V2 release action registry mismatch")
    if contracts.get("payload_tags") != {
        "41": ["InstallProfile", "TransitionCapability"],
        "50": ["InstallProfile", "TransitionCapability"],
        "52": ["StageFundProfile", "LockFundMutation", "ActivateFundProfile", "CloseFundProfile"],
        "58": ["TransitionServingAlias"],
        "59": ["Activate", "EmergencyDisable", "AuthorizeOperationalConfig", "ApplyOperationalConfig", "Recover"],
    }:
        raise PromotionValidationError("V2 release payload tag registry mismatch")
    if contracts.get("resolver") != {
        "normal_max_bytes": 262144, "normal_max_proofs": 17,
        "authorized_max_bytes": 393216,
        "neural_target": "/neural-oracle/<query_id>",
        "neural_response_max_bytes": 16384,
    }:
        raise PromotionValidationError("V2 release resolver bounds mismatch")
    if contracts.get("light_update") != {
        "protocol": "/noos/sync/light-update/2", "min_items": 1,
        "max_items": 128, "max_item_bytes": 262144,
    }:
        raise PromotionValidationError("V2 release light-update bounds mismatch")
    if contracts.get("transaction_bounds") != {
        "action_call_max_bytes": 65536, "tx_plus_witness_max_bytes": 65532,
        "tx_push_prefix_bytes": 4, "tx_push_max_bytes": 65536,
    }:
        raise PromotionValidationError("V2 release transaction bounds mismatch")
    if contracts.get("v1_wwm_decode") != "REJECT":
        raise PromotionValidationError("V2 release permits mixed V1 WWM bytes")
    verdicts = manifest.get("gate_verdicts")
    if not isinstance(verdicts, list) or [row.get("gate") for row in verdicts if isinstance(row, Mapping)] != ORDER:
        raise PromotionValidationError("V2 release gate order mismatch")
    if any(row.get("verdict") != "BLOCKED" or row.get("ledger_record_hash") != "OWNER_BLOCKED" for row in verdicts):
        raise PromotionValidationError("V2 release manifest fabricates a gate PASS")
    if manifest.get("signatures") not in ([], None):
        if not isinstance(manifest.get("signatures"), list):
            raise PromotionValidationError("V2 release signatures are malformed")
    schema_path = root / "protocol/release/protocol-release-manifest-v2.schema.json"
    try:
        schema = json.loads(schema_path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionValidationError(f"V2 release schema cannot be loaded: {exc}") from exc
    schema_errors = schema_validate(manifest, schema)
    if schema_errors:
        raise PromotionValidationError(f"V2 release schema violation: {schema_errors[0]}")




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
    *, schema_version: int, trusted_role_keyring_sha256: str | None = None,
    expected_revision: str | None = None, expected_chain_id: str | None = None,
    expected_genesis_hash: str | None = None, require_all_passed: bool = False,
    test_mode: bool = False,
) -> dict[str, Any]:
    validate_schema_dispatch(ledger, root, schema_version)
    required_requirements = REQUIRED_REQUIREMENTS_V1 if schema_version == 1 else REQUIRED_REQUIREMENTS_V2
    gate_domain = registered_domain("D-PROMOTION-GATE-V2")
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
    if schema_version == 1:
        if auth_binding.get("gate_record_domain") not in (None, gate_domain):
            raise PromotionValidationError("V1 promotion gate-record domain mismatch")
    elif auth_binding.get("gate_record_domain_id") != "D-PROMOTION-GATE-V2":
        raise PromotionValidationError("V2 promotion gate-record domain mismatch")
    passed_hashes: list[str] = []
    all_passed = True
    for index, gate in enumerate(gates):
        if not isinstance(gate, Mapping):
            raise PromotionValidationError(f"{ORDER[index]}: promotion gate row malformed")
        state = gate.get("state")
        if state not in {"BLOCKED", "PASSED", "KILLED"}:
            raise PromotionValidationError(f"{ORDER[index]}: unknown promotion gate state")
        requirement_ids = [r.get("requirement_id") for r in gate.get("requirements", []) if isinstance(r, Mapping)]
        if requirement_ids != required_requirements[ORDER[index]]:
            raise PromotionValidationError(f"{ORDER[index]}: exact ordered requirement ID set mismatch")
        if state != "PASSED":
            all_passed = False
            if gate.get("signatures"):
                raise PromotionValidationError(f"{ORDER[index]}: non-PASSED gate cannot carry signatures")
            if gate.get("authorization_record") is not None:
                raise PromotionValidationError(f"{ORDER[index]}: non-PASSED gate cannot carry an authorization record")
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
        expected_predecessor = passed_hashes[-1] if passed_hashes else "0" * 64
        expected_prior_root = ledger_root(passed_hashes, schema_version=schema_version)
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
        message = gate_domain.encode("ascii") + b"\x00" + raw
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
    computed_root = ledger_root(passed_hashes, schema_version=schema_version)
    if all_passed:
        if auth_binding.get("ledger_root") != computed_root:
            raise PromotionValidationError("complete promotion ledger root mismatch")
    elif auth_binding.get("ledger_root") not in (None, "OWNER_BLOCKED"):
        raise PromotionValidationError("incomplete promotion ledger cannot claim a ledger root")
    if require_all_passed and not all_passed:
        raise PromotionValidationError("cutover prohibited: every G0..G5 gate must cryptographically validate as PASSED")
    return {
        "schema_version": schema_version, "all_passed": all_passed,
        "ledger_root": computed_root, "record_hashes": passed_hashes,
    }
