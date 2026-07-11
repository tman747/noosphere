#!/usr/bin/env python3
"""Fail-closed validator for the immutable staged-promotion blocker ledger."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ORDER = ["G0", "G1", "G2", "G3", "GENESIS", "G4", "G5"]
HASH = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_REQUIREMENTS = {
    "G0": {"G0.REGISTRY_SCHEMA", "G0.OWNER_CONSTANTS"},
    "G1": {"G1.DETERMINISTIC_LAB"},
    "G2": {"G2.INDEPENDENT_DEVNET"},
    "G3": {"G3.PUBLIC_DURATION", "G3.A_BRAID_AI_OFF", "G3.EXTERNAL_ASSURANCE"},
    "GENESIS": {"GENESIS.QUIET_WEEK", "GENESIS.BITCOIN_ANCHOR", "GENESIS.DKG", "GENESIS.MAINNET_ECONOMICS", "GENESIS.REPRO_DEMO"},
    "G4": {"G4.CANARY_DURATION", "G4.EXIT_AND_FAULT_DRILLS", "G4.HARDWARE_BUILDERS"},
    "G5": {"G5.EXACT_LOWER_GATES", "G5.CLAIM_COMPLETENESS", "G5.EXTERNAL_REVIEWS", "G5.LIVE_DIVERSITY", "G5.SIGNATURES"},
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


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    path = root / "protocol/release/promotion-blockers.json"
    doc = load(path, errors)
    schema = load(root / "protocol/release/promotion-blockers-schema-v1.json", errors)
    if errors:
        return errors
    if doc.get("$schema") != "promotion-blockers-schema-v1.json" or schema.get("$id") != "urn:noos:promotion-blockers:v1":
        errors.append("ledger/schema binding mismatch")
    policy = doc.get("ledger_policy", {})
    if policy != {"append_only": True, "no_waivers": True, "no_fabricated_evidence": True, "promotion_order": ORDER}:
        errors.append("immutable no-waiver/no-fabrication ledger policy changed")
    binding = doc.get("protocol_binding", {})
    for key in ("protocol_version", "api_version", "release_version", "revision", "chain_id", "genesis_hash"):
        if not isinstance(binding.get(key), str) or not binding[key]:
            errors.append(f"protocol binding {key} absent")
    for key in ("chain_id", "genesis_hash"):
        value = binding.get(key)
        if value != "OWNER_BLOCKED" and not (isinstance(value, str) and HASH.fullmatch(value)):
            errors.append(f"{key} must be OWNER_BLOCKED or lowercase hash32")
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
        if set(ids) != REQUIRED_REQUIREMENTS.get(name, set()) or len(ids) != len(set(ids)):
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
    required_external = {"EXT.PUBLIC_TESTNET", "EXT.DKG", "EXT.ECONOMICS_COUNSEL", "EXT.CANARY", "EXT.PRODUCTION_ECOSYSTEM"}
    if {x.get("id") for x in external if isinstance(x, dict)} != required_external:
        errors.append("external blocker set incomplete")
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[2]
    errors = validate(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"Promotion gate: FAIL ({len(errors)} error(s))")
        return 1
    print("Promotion gate: PASS (ledger structurally valid; DNS prohibited; current promotion remains honestly BLOCKED)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
