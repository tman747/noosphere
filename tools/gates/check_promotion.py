#!/usr/bin/env python3
"""Fail-closed validator for the immutable staged-promotion blocker ledger."""
from __future__ import annotations
import json
import argparse
import re
import sys
from pathlib import Path
from promotion_records import (
    PromotionValidationError,
    REQUIRED_REQUIREMENTS_V1,
    REQUIRED_REQUIREMENTS_V2,
    validate_promotion_ledger,
)

ORDER = ["G0", "G1", "G2", "G3", "GENESIS", "G4", "G5"]
HASH = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_REQUIREMENTS = {
    1: {gate: set(requirements) for gate, requirements in REQUIRED_REQUIREMENTS_V1.items()},
    2: {gate: set(requirements) for gate, requirements in REQUIRED_REQUIREMENTS_V2.items()},
}
VALID_STATUS = {"UNSATISFIED", "SATISFIED", "OWNER_BLOCKED", "EXTERNAL_BLOCKED", "KILLED", "NOT_APPLICABLE"}
VALID_VERDICT = {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "KILLED"}
BLOCKING = {"UNSATISFIED", "OWNER_BLOCKED", "EXTERNAL_BLOCKED", "KILLED"}


def load(path: Path, errors: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{path}: parse failed: {exc}")
        return {}


def validate(root: Path, keyring=None, trusted_role_keyring_sha256: str | None = None,
             expected_revision: str | None = None, expected_chain_id: str | None = None,
             expected_genesis_hash: str | None = None, *, schema_version: int = 2,
             ledger_path: Path | None = None) -> list[str]:
    errors: list[str] = []
    relative = (
        Path("protocol/release/promotion-blockers.json")
        if schema_version == 1
        else Path("protocol/release/promotion-blockers-v2.json")
    )
    path = ledger_path or root / relative
    doc = load(path, errors)
    schema_name = f"promotion-blockers-schema-v{schema_version}.json"
    schema = load(root / "protocol/release" / schema_name, errors)
    if errors:
        return errors
    expected_schema_id = f"urn:noos:promotion-blockers:v{schema_version}"
    if doc.get("$schema") != schema_name or doc.get("schema_version") != schema_version or schema.get("$id") != expected_schema_id:
        errors.append(f"explicit V{schema_version} ledger/schema binding mismatch")
    policy = doc.get("ledger_policy", {})
    if policy != {"append_only": True, "no_waivers": True, "no_fabricated_evidence": True, "promotion_order": ORDER}:
        errors.append("immutable no-waiver/no-fabrication ledger policy changed")
    binding = doc.get("protocol_binding", {})
    expected_wire_version = f"v{schema_version}"
    for key in ("protocol_version", "api_version"):
        if binding.get(key) != expected_wire_version:
            errors.append(f"protocol binding {key} must be {expected_wire_version}")
    for key in ("release_version", "revision", "chain_id", "genesis_hash"):
        if not isinstance(binding.get(key), str) or not binding[key]:
            errors.append(f"protocol binding {key} absent")
    if schema_version == 2:
        if binding.get("protocol_identity") != "noos-protocol-identity-v2" or binding.get("peer_identity") != "v2-only":
            errors.append("protocol-v2 identity/peer binding is mixed")
    for key in ("chain_id", "genesis_hash"):
        value = binding.get(key)
        if value != "OWNER_BLOCKED" and not (isinstance(value, str) and HASH.fullmatch(value)):
            errors.append(f"{key} must be OWNER_BLOCKED or lowercase hash32")
    authorization_binding = doc.get("authorization_binding", {})
    if schema_version == 1:
        blocked_authorization = {
            "schema_version": 2, "gate_record_domain": "NOOS/PROMOTION/GATE/V2",
            "role_keyring_sha256": "OWNER_BLOCKED", "final_freeze_sha256": "OWNER_BLOCKED",
            "ledger_root": "OWNER_BLOCKED",
        }
        pinned_domain = authorization_binding.get("gate_record_domain") == "NOOS/PROMOTION/GATE/V2"
    else:
        blocked_authorization = {
            "schema_version": 2, "gate_record_domain_id": "D-PROMOTION-GATE-V2",
            "role_keyring_sha256": "OWNER_BLOCKED", "final_freeze_sha256": "OWNER_BLOCKED",
            "ledger_root": "OWNER_BLOCKED",
        }
        pinned_domain = authorization_binding.get("gate_record_domain_id") == "D-PROMOTION-GATE-V2"
    if authorization_binding != blocked_authorization and not (
        authorization_binding.get("schema_version") == 2
        and pinned_domain
        and all(HASH.fullmatch(str(authorization_binding.get(k, ""))) for k in ("role_keyring_sha256", "final_freeze_sha256", "ledger_root"))
    ):
        errors.append("promotion authorization binding is neither honestly blocked nor fully pinned")
    cutover = doc.get("cutover", {})
    if cutover.get("dns_cutover") != "PROHIBITED" or cutover.get("execution_authority") != "SIGNED_G5_ONLY":
        errors.append("DNS cutover must remain PROHIBITED and SIGNED_G5_ONLY")
    manifest_rel = cutover.get("prepared_manifest")
    manifest_path = root / manifest_rel if isinstance(manifest_rel, str) else None
    if manifest_path is None or not manifest_path.is_file():
        errors.append("prepared cutover manifest missing")
    else:
        manifest = load(manifest_path, errors)
        execution = manifest.get("execution", {})
        if manifest.get("manifest_state") != "PREPARED_NOT_EXECUTED" or execution.get("authorized") is not False or execution.get("executed") is not False:
            errors.append("cutover manifest must remain prepared, unauthorized, and unexecuted")
        if execution.get("dns_cutover") != "PROHIBITED" or execution.get("required_authority") != "SIGNED_G5_PROMOTION_OVER_EXACT_MANIFEST_HASH":
            errors.append("cutover manifest execution authority is not fail-closed")
        rollback = manifest.get("rollback", {})
        for key in ("old_rpc_fallback", "old_indexer_fallback", "old_wallet_fallback", "old_state_fallback"):
            if rollback.get(key) is not False:
                errors.append(f"cutover manifest must prohibit {key}")
        if rollback.get("target_kind") != "STATIC_MAINTENANCE_ARCHIVE" or rollback.get("target_origin") != "OWNER_BLOCKED":
            errors.append("first-launch rollback must remain OWNER_BLOCKED static maintenance/archive")
        archive = manifest.get("historical_archive", {})
        for export in ("site_export", "indexed_state_export"):
            if archive.get(export, {}).get("status") != "OWNER_BLOCKED":
                errors.append(f"unavailable historical {export} must remain honestly OWNER_BLOCKED")
        if manifest.get("rehearsal", {}).get("evidence_bundle_refs") or manifest.get("execution", {}).get("signatures"):
            errors.append("unexecuted cutover cannot claim rehearsal evidence or signatures")
    gates = doc.get("gates")
    if not isinstance(gates, list) or [g.get("gate") for g in gates if isinstance(g, dict)] != ORDER:
        errors.append("gate records must occur exactly once in immutable promotion order")
        gates = gates if isinstance(gates, list) else []
    prior_passed = True
    for gate in gates:
        if not isinstance(gate, dict):
            errors.append("gate record must be an object")
            continue
        name = gate.get("gate")
        state = gate.get("state")
        if gate.get("immutable_record") is not True or state not in {"BLOCKED", "PASSED", "KILLED"}:
            errors.append(f"{name}: invalid immutable state")
        reqs = gate.get("requirements")
        if not isinstance(reqs, list):
            errors.append(f"{name}: requirements absent")
            reqs = []
        ids = [r.get("requirement_id") for r in reqs if isinstance(r, dict)]
        expected_requirements = REQUIRED_REQUIREMENTS.get(schema_version, {}).get(name, set())
        if set(ids) != expected_requirements or len(ids) != len(set(ids)):
            errors.append(f"{name}: exact engineering requirement set mismatch")
        has_blocker = False
        for req in reqs:
            if not isinstance(req, dict):
                errors.append(f"{name}: malformed requirement")
                continue
            required = {"requirement_id", "description", "status", "bundle_refs", "exact_revision", "threshold", "observed", "verdict"}
            if set(req) != required:
                errors.append(f"{name}/{req.get('requirement_id')}: evidence fields mismatch")
            if req.get("status") not in VALID_STATUS or req.get("verdict") not in VALID_VERDICT:
                errors.append(f"{name}/{req.get('requirement_id')}: invalid status/verdict")
            if req.get("status") in BLOCKING:
                has_blocker = True
            if req.get("status") == "SATISFIED":
                refs = req.get("bundle_refs")
                if req.get("verdict") != "PASS" or not isinstance(refs, list) or not refs:
                    errors.append(f"{name}/{req.get('requirement_id')}: SATISFIED needs PASS and evidence bundle refs")
                for rel in refs or []:
                    if not (root / rel).is_file():
                        errors.append(f"{name}/{req.get('requirement_id')}: evidence ref missing: {rel}")
            elif req.get("verdict") == "PASS":
                errors.append(f"{name}/{req.get('requirement_id')}: PASS cannot accompany blocker/non-applicable status")
            for text_key in ("description", "exact_revision", "threshold", "observed"):
                if not isinstance(req.get(text_key), str) or not req[text_key].strip():
                    errors.append(f"{name}/{req.get('requirement_id')}: {text_key} absent")
        if state == "PASSED" and (has_blocker or not prior_passed):
            errors.append(f"{name}: cannot PASS with blockers or an unpassed predecessor")
        if state == "PASSED" and (not isinstance(gate.get("signatures"), list) or not gate["signatures"]):
            errors.append(f"{name}: PASSED requires signatures")
        if state == "BLOCKED" and not has_blocker:
            errors.append(f"{name}: BLOCKED state lacks a blocking requirement")
        if not isinstance(gate.get("unresolved"), list) or (state == "BLOCKED" and not gate["unresolved"]):
            errors.append(f"{name}: unresolved blocker list absent")
        prior_passed = prior_passed and state == "PASSED"
    owner = doc.get("owner_decisions", [])
    external = doc.get("external_blockers", [])
    if not owner or any(x.get("status") != "OWNER_BLOCKED" for x in owner if isinstance(x, dict)):
        errors.append("unresolved owner decision ledger absent or dishonest")
    required_external = (
        {"EXT.PUBLIC_TESTNET", "EXT.DKG", "EXT.ECONOMICS_COUNSEL", "EXT.CANARY", "EXT.PRODUCTION_ECOSYSTEM"}
        if schema_version == 1
        else {"EXT.W0_REVIEW", "EXT.PUBLIC_TESTNET", "EXT.DKG", "EXT.CANARY", "EXT.PRODUCTION_ECOSYSTEM"}
    )
    if {x.get("id") for x in external if isinstance(x, dict)} != required_external:
        errors.append("external blocker set incomplete")
    try:
        validate_promotion_ledger(
            doc, root, keyring, schema_version=schema_version,
            trusted_role_keyring_sha256=trusted_role_keyring_sha256,
            expected_revision=expected_revision, expected_chain_id=expected_chain_id,
            expected_genesis_hash=expected_genesis_hash,
        )
    except PromotionValidationError as exc:
        errors.append(str(exc))
    return errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--schema-version", type=int, choices=(1, 2), default=2)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--keyring")
    parser.add_argument("--final-freeze")
    parser.add_argument("--final-freeze-signatures")
    args = parser.parse_args(argv[1:])
    root = Path(args.root).resolve()
    keyring = None
    trust_root = None
    expected_revision = expected_chain_id = expected_genesis_hash = None
    pre_errors: list[str] = []
    supplied = [args.keyring, args.final_freeze, args.final_freeze_signatures]
    if any(supplied) and not all(supplied):
        pre_errors.append("--keyring, --final-freeze, and --final-freeze-signatures must be supplied together")
    elif args.keyring:
        try:
            genesis_tools = root / "tools/genesis"
            if str(genesis_tools) not in sys.path:
                sys.path.insert(0, str(genesis_tools))
            from production_authorization import DOMAIN_FINAL_FREEZE, FINAL_ROLES, canonical_json, file_sha256, load_keyring, read_json, verify_detached_signatures
            keyring_path = Path(args.keyring); freeze_path = Path(args.final_freeze)
            if not keyring_path.is_absolute(): keyring_path = root / keyring_path
            if not freeze_path.is_absolute(): freeze_path = root / freeze_path
            keyring, keyring_doc = load_keyring(keyring_path)
            trust_root = file_sha256(keyring_path)
            freeze = read_json(freeze_path)
            expected_revision = freeze.get("exact_revision")
            expected_chain_id = freeze.get("chain_id")
            expected_genesis_hash = freeze.get("genesis_hash")
            if keyring_doc.get("exact_revision") != expected_revision:
                raise ValueError("final freeze/keyring revision mismatch")
            if freeze.get("role_keyring_sha256") != trust_root:
                raise ValueError("final freeze does not pin supplied role keyring bytes")
            signature_path = Path(args.final_freeze_signatures)
            if not signature_path.is_absolute(): signature_path = root / signature_path
            verify_detached_signatures(
                canonical_json(freeze), read_json(signature_path), DOMAIN_FINAL_FREEZE,
                expected_revision, FINAL_ROLES, keyring,
            )
        except Exception as exc:
            pre_errors.append(f"trusted keyring/final-freeze load failed: {exc}")
    ledger_path = args.ledger
    if ledger_path is not None and not ledger_path.is_absolute():
        ledger_path = root / ledger_path
    errors = pre_errors + validate(
        root, keyring, trust_root, expected_revision, expected_chain_id, expected_genesis_hash,
        schema_version=args.schema_version, ledger_path=ledger_path,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"Promotion gate: FAIL ({len(errors)} error(s))")
        return 1
    print("Promotion gate: PASS (ledger structurally valid; DNS prohibited; current promotion remains honestly BLOCKED)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
