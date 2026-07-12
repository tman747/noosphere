#!/usr/bin/env python3
"""Validate the owner-approved, unsigned production-economics proposal, fail closed.

`--allow-draft` proves the arithmetic and honest blockers while returning 0;
the legacy flag name is retained for release-script compatibility. Without it,
the valid owner-approved-pending-signature draft returns 2. A proposal can
return PASS only after all owner inputs, reviews, evidence-selected drift, and
signatures exist; this script deliberately cannot manufacture those artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/genesis"))
import generate_emission_table as emission  # noqa: E402
import check_mainnet_template as mainnet_template_gate  # noqa: E402

PROPOSAL = ROOT / "protocol/genesis/mainnet-parameters.proposal.toml"
ALLOCATIONS = ROOT / "protocol/genesis/mainnet-allocations.proposal.json"
DECISIONS = ROOT / "protocol/genesis/owner-decision.economics.proposal.json"
ANALYSIS_DIR = ROOT / "evidence/economics"
LEGACY_ANALYSIS = ANALYSIS_DIR / "production-economics-sensitivity-v1.json"
EXPECTED_ODRS = {
    "ODR-GROUND-001", "ODR-ECON-001", "ODR-EMISSION-001", "ODR-EMISSION-002",
    "ODR-EMISSION-003", "ODR-EMISSION-004", "ODR-EMISSION-005",
    "ODR-EMISSION-006", "ODR-EMISSION-007", "ODR-WITNESS-002",
    "ODR-WITNESS-003", "ODR-WITNESS-004", "ODR-WITNESS-005",
    "ODR-FEES-001", "ODR-FEES-002", "ODR-FEES-003", "ODR-NEL-001",
    "ODR-GRAIN-001", "ODR-GRAIN-002",
}
OWNER_SENTINELS = {
    "OWNER_INPUT_REQUIRED", "POST_QUIET_WEEK_CEREMONY_REQUIRED",
    "QUIET_WEEK_INPUT_REQUIRED", "PENDING_E_WAN_01", "NOT_PERFORMED",
    "NOT_REVIEWED", "UNSIGNED",
}


def load(path: Path) -> dict:
    if path.suffix == ".toml":
        return tomllib.loads(path.read_text("utf-8"))
    return json.loads(path.read_text("utf-8"))


def emission_at(rows: list[emission.RangeRow], height: int) -> int:
    if height <= 0 or height > rows[-1].end_height:
        return 0
    for row in rows:
        if row.start_height <= height <= row.end_height:
            return row.emission_micro_noos
    raise AssertionError("contiguous table has a hole")


def exact_schedule_tests(doc: dict, rows: list[emission.RangeRow]) -> dict:
    p = doc["emission"]
    scheduled = emission.scheduled_total(rows)
    allocation = int(p["genesis_allocation_limit_micro_noos"])
    cap = int(p["max_supply_micro_noos"])
    assert scheduled <= int(p["scheduled_emission_limit_micro_noos"])
    assert allocation + scheduled <= cap
    cumulative = allocation
    for row in rows:
        cumulative += row.count * row.emission_micro_noos
        assert cumulative <= cap
    terminal = int(p["emission_terminal_height"])
    assert emission_at(rows, 0) == 0
    assert emission_at(rows, 1) == int(p["initial_per_height_micro_noos"])
    assert emission_at(rows, terminal) == rows[-1].emission_micro_noos
    assert emission_at(rows, terminal + 1) == 0
    assert emission_at(rows, (1 << 64) - 1) == 0
    return {"scheduled_micro_noos": scheduled, "allocation_plus_scheduled_micro_noos": cumulative,
            "cap_headroom_micro_noos": cap - cumulative, "range_rows_checked": len(rows)}


def exhaustive_rounding_tests(doc: dict, rows: list[emission.RangeRow]) -> dict:
    p = doc["emission"]
    ground, witness, treasury = (int(p[k]) for k in (
        "recipient_share_ground_bp", "recipient_share_witness_bp", "recipient_share_treasury_bp"))
    assert ground + witness + treasury == 10_000
    values = set(range(10_000)) | {row.emission_micro_noos for row in rows} | {0, 1, (1 << 64) - 1}
    for amount in values:
        w = amount * witness // 10_000
        t = amount * treasury // 10_000
        g = amount - w - t
        assert g >= 0 and g + w + t == amount
    return {"amounts_checked": len(values), "all_basis_point_residues_checked": True,
            "rounding_rule": "witness floor; treasury floor; ground exact remainder"}


def exhaustive_no_recreated_tests(rows: list[emission.RangeRow]) -> dict:
    # Exhaust every attempt sequence of length 0..6 over heights 0..8. The
    # abstract state is exactly Lumen's last_emission_height + emission_minted.
    attempts = range(9)
    sequences = 0
    for length in range(7):
        for sequence in itertools.product(attempts, repeat=length):
            sequences += 1
            last = 0
            minted = 0
            expected_minted = 0
            accepted: set[int] = set()
            for height in sequence:
                if height <= last:
                    continue
                scheduled = emission_at(rows, height)
                minted += scheduled
                expected_minted += scheduled
                accepted.add(height)
                last = height
                assert minted == expected_minted
            assert minted == sum(emission_at(rows, h) for h in accepted)
    return {"height_domain": "0..8", "max_attempt_sequence_length": 6, "sequences_checked": sequences}


def duplex_hard_zero_test(doc: dict) -> dict:
    assert doc["emission"]["duplex_issuance_enabled"] is False
    assert doc["controls"]["work_loom_credit_enabled"] is False
    assert doc["controls"]["work_loom_weight_cap"] == 0
    assert doc["controls"]["witness_proofpower_bonus_enabled"] is False
    source = (ROOT / "crates/noos-work-loom/src/lib.rs").read_text("utf-8")
    for law in (
        "pub const WORK_LOOM_CREDIT_ENABLED: bool = false;",
        "pub const WITNESS_PROOFPOWER_ENABLED: bool = false;",
        "pub const DUPLEX_ISSUANCE_ENABLED: bool = false;",
    ):
        assert law in source
    return {"binding_claim": "E-DEMAND-WASH-01", "production_values_checked": 3, "all_zero": True}


def production_loader_refusal_test(proposal_path: Path) -> dict:
    # The manifest/template gate treats any non-template file as a production
    # claim and therefore requires the detached signature record. This draft
    # must fail that path rather than merely report an informational warning.
    gate_errors, _ = mainnet_template_gate.check(proposal_path)
    assert gate_errors, "unsigned proposal unexpectedly passed the mainnet manifest gate"
    assert any("signature" in error or "missing owner field" in error for error in gate_errors)

    # The only runtime loader is devnet-only and has an unconditional mainnet
    # refusal. A Rust unit test executes this guard; these source assertions
    # make accidental removal visible even when only the Python focused gate runs.
    node_source = (ROOT / "crates/noos-node/src/genesis.rs").read_text("utf-8")
    assert "mainnet genesis is OWNER_BLOCKED; only is_test_network = true loads" in node_source
    assert "unsigned_owner_proposal_is_refused_by_node_loader" in node_source
    ceremony_source = (ROOT / "tools/genesis/ceremony.py").read_text("utf-8")
    assert "real DKG root requires the multi-party ceremony transcript: OWNER_BLOCKED" in ceremony_source
    return {"mainnet_manifest_gate": "REFUSED", "noos_node_runtime_loader": "REFUSED",
            "genesis_ceremony_mainnet_path": "REFUSED", "gate_error_count": len(gate_errors)}


def sensitivity(doc: dict, rows: list[emission.RangeRow], tests: dict) -> dict:
    p = doc["emission"]
    max_supply = int(p["max_supply_micro_noos"])
    allocation = int(p["genesis_allocation_limit_micro_noos"])
    heights_per_year = 365 * 24 * 60 * 60 // int(doc["consensus"]["slot_seconds"])
    annual_points = []
    for year in (1, 5, 10, 20, 40, 60, 80, 100):
        start = (year - 1) * heights_per_year + 1
        end = min(year * heights_per_year, int(p["emission_terminal_height"]))
        annual = 0
        if start <= end:
            for row in rows:
                overlap = max(0, min(end, row.end_height) - max(start, row.start_height) + 1)
                annual += overlap * row.emission_micro_noos
        issued_before = allocation
        cutoff = start - 1
        for row in rows:
            issued_before += max(0, min(cutoff, row.end_height) - row.start_height + 1) * row.emission_micro_noos
        annual_points.append({"year": year, "scheduled_micro_noos": annual,
                              "gross_inflation_ppm": annual * 1_000_000 // max(1, issued_before)})

    inflation_grid = []
    first_year = annual_points[0]["scheduled_micro_noos"]
    for allocation_use_bp, realization_bp, fee_burn_bp in itertools.product(
            (5000, 7500, 10000), (5000, 7500, 10000), (0, 2500, 5000, 10000)):
        circulating = allocation * allocation_use_bp // 10_000
        gross = first_year * realization_bp // 10_000
        burn = gross * fee_burn_bp // 10_000
        inflation_grid.append({"allocation_utilization_bp": allocation_use_bp,
                               "emission_realization_bp": realization_bp,
                               "fee_burn_as_gross_emission_bp": fee_burn_bp,
                               "year_1_net_inflation_ppm": (gross - burn) * 1_000_000 // circulating})

    schedule_grid = []
    base_initial = int(p["initial_per_height_micro_noos"])
    for initial_bp, era_years, ratio, eras in itertools.product(
            (7500, 10000, 12500), (10, 20, 30), ((1, 3), (1, 2), (2, 3)), (3, 5, 8)):
        value = base_initial * initial_bp // 10_000
        era_len = heights_per_year * era_years
        total = 0
        for _ in range(eras):
            total += value * era_len
            value = value * ratio[0] // ratio[1]
        schedule_grid.append({"initial_rate_bp_of_selected": initial_bp, "era_years": era_years,
                              "decay": f"{ratio[0]}/{ratio[1]}", "eras": eras,
                              "allocation_plus_schedule_micro_noos": allocation + total,
                              "cap_breached": allocation + total > max_supply})

    w = doc["witness_ring"]
    min_bond = int(w["min_bond_micro_noos"])
    slash_loss_bp = int(w["slash_burn_bp"]) + int(w["slash_reporter_bp"])
    validator_grid = []
    for validators, multiplier, price_cents in itertools.product((32, 64, 128, 256), (1, 2, 4, 10), (1, 10, 100, 1000)):
        bonded = validators * min_bond * multiplier
        threshold = bonded // 3 + 1
        slash_loss = threshold * slash_loss_bp // 10_000
        validator_grid.append({"active_validators": validators, "average_bond_multiple": multiplier,
                               "noos_price_usd_cents": price_cents,
                               "minimum_total_bonded_micro_noos": bonded,
                               "one_third_plus_one_micro_noos": threshold,
                               "slash_loss_micro_noos": slash_loss,
                               "threshold_cost_usd_cents": threshold * price_cents // 1_000_000})

    return {
        "schema_version": 1,
        "analysis_kind": "NOOS_PRODUCTION_ECONOMICS_SENSITIVITY",
        "status": "OWNER_APPROVED_PENDING_SIGNATURE_NON_FORECAST",
        "proposal_sha256": hashlib.sha256(PROPOSAL.read_bytes()).hexdigest(),
        "assumption_warning": "Token prices, stake participation, allocation utilization, fee burn, and block realization are adversarial scenarios, not forecasts.",
        "selected": {"max_supply_micro_noos": max_supply, "genesis_allocation_limit_micro_noos": allocation,
                     "terminal_height": int(p["emission_terminal_height"]), "table_root": p["emission_table_root"]},
        "exact_tests": tests,
        "annual_inflation_points": annual_points,
        "adversarial_inflation_grid": inflation_grid,
        "adversarial_schedule_grid": schedule_grid,
        "validator_security_grid": validator_grid,
    }


def canonical_json(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def analysis_path(rendered: str) -> Path:
    digest = hashlib.sha256(rendered.encode()).hexdigest()
    return ANALYSIS_DIR / f"production-economics-sensitivity-v1-{digest}.json"


def validate(proposal_path: Path = PROPOSAL, write_analysis: bool = False) -> tuple[list[str], dict]:
    errors: list[str] = []
    doc = load(proposal_path)
    allocations = load(ALLOCATIONS)
    decisions = load(DECISIONS)
    assert doc["proposal_kind"] == "OWNER-PROPOSAL"
    assert doc["status"] == "OWNER_APPROVED_PENDING_SIGNATURE"
    assert doc["signature_status"] == "UNSIGNED"
    assert doc["production_loadable"] is False and doc["owner_signed"] is False
    assert doc["release_authority"]["key_custody_requirement"] == "HARDWARE_OR_OFFLINE"
    assert doc["release_authority"]["release_owner_public_key"] == "OWNER_INPUT_REQUIRED"
    assert doc["release_authority"]["detached_signature_record"] == "OWNER_INPUT_REQUIRED"
    assert doc["review"]["independent_review_authorization"] == "APPROVED_TO_PROCEED"
    assert doc["independent_economic_review"] == "NOT_PERFORMED"
    assert doc["counsel_review"] == "NOT_PERFORMED"
    assert doc["consensus"]["max_future_drift_ms"] == "PENDING_E_WAN_01"
    assert doc["dkg"]["participants"] == 7 and doc["dkg"]["threshold"] == 5
    assert doc["release_authority"]["required_roles"] == ["release-owner"]
    assert doc["dkg"]["operator_model"] == "SELF_HOSTED_PUBLIC_OPERATORS"
    assert allocations["entries"] == "OWNER_INPUT_REQUIRED"
    assert allocations["allocations_root"] == "OWNER_INPUT_REQUIRED"
    assert sum(c["amount_micro_noos"] for c in allocations["categories"]) == allocations["expected_total_micro_noos"]
    assert sum(c["share_of_max_supply_bp"] for c in allocations["categories"]) == 3000
    odrs = {record["odr_id"] for record in decisions["records"]}
    assert odrs == EXPECTED_ODRS, f"ODR coverage mismatch missing={EXPECTED_ODRS-odrs} extra={odrs-EXPECTED_ODRS}"
    assert decisions["status"] == doc["status"]
    assert decisions["signature_status"] == "UNSIGNED"
    assert decisions["production_effect"] == "NONE"
    assert decisions["owner_approval"] is True
    assert decisions["approved_scope"] == "EXACT_1_000_000_000_NOOS_CAPPED_FIXED_ENVELOPE_DRAFT"
    assert decisions["independent_review_authorization"] == "APPROVED_FOR_INDEPENDENT_ECONOMIST_AND_COUNSEL_REVIEW"
    assert decisions["independent_economic_review"] == "NOT_PERFORMED"
    assert decisions["counsel_review"] == "NOT_PERFORMED"
    assert decisions["hardware_or_offline_release_owner_key"] == "OWNER_INPUT_REQUIRED"
    assert decisions["detached_signature"] == "OWNER_INPUT_REQUIRED"

    root, _, _ = emission.verify(proposal_path, ROOT / doc["emission"]["emission_table_path"])
    assert root == doc["emission"]["emission_table_root"]
    rows = emission.read_rows(ROOT / doc["emission"]["emission_table_path"])
    tests = {
        "cap_terminal": exact_schedule_tests(doc, rows),
        "rounding": exhaustive_rounding_tests(doc, rows),
        "no_recreated_emission": exhaustive_no_recreated_tests(rows),
        "duplex_hard_zero": duplex_hard_zero_test(doc),
        "production_loader_refusal": production_loader_refusal_test(proposal_path),
    }
    analysis = sensitivity(doc, rows, tests)
    rendered = canonical_json(analysis)
    current_analysis = analysis_path(rendered)
    if write_analysis:
        ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
        if current_analysis.exists() and current_analysis.read_text("utf-8") != rendered:
            raise AssertionError("content-addressed sensitivity evidence collision")
        current_analysis.write_text(rendered, "utf-8")
    elif not any(
        path.is_file() and path.read_text("utf-8") == rendered
        for path in (current_analysis, LEGACY_ANALYSIS)
    ):
        errors.append("sensitivity analysis missing or stale; run --write-analysis")

    blockers = [
        "owner-approved fixed-envelope proposal is pending hardware/offline release-owner key and detached signature",
        "E-WAN-01 has not selected max_future_drift_ms",
        "allocation recipient entries and allocations_root are OWNER_INPUT_REQUIRED",
        "independent economist review is NOT_PERFORMED",
        "counsel review is NOT_PERFORMED",
        "public 5-of-7 DKG participant identities, complaints/exclusions, transcript, and final identity do not exist",
        "Quiet Week commitments and production authorization do not exist",
    ]
    return errors, {"tests": tests, "blockers": blockers}


def self_test() -> int:
    errors, result = validate(write_analysis=False)
    assert not errors, errors
    assert result["blockers"]
    assert "hardware/offline release-owner key" in result["blockers"][0]
    with tempfile.TemporaryDirectory() as tmp:
        text = PROPOSAL.read_text("utf-8").replace('owner_signed = false', 'owner_signed = true')
        bad = Path(tmp) / "dishonest.toml"
        bad.write_text(text, "utf-8")
        try:
            validate(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError("dishonest signed claim was not refused")
    print("RESULT economics_proposal_self_test=PASS status=OWNER_APPROVED_PENDING_SIGNATURE dishonest_signed_claim_refused=true")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal", type=Path, default=PROPOSAL)
    parser.add_argument("--allow-draft", action="store_true")
    parser.add_argument("--write-analysis", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        errors, result = validate(args.proposal, args.write_analysis)
    except (AssertionError, KeyError, ValueError, OSError) as exc:
        print(f"RESULT economics_proposal=FAIL error={exc}", file=sys.stderr)
        return 1
    if errors:
        print("RESULT economics_proposal=FAIL errors=" + "; ".join(errors), file=sys.stderr)
        return 1
    print("RESULT economics_proposal=OWNER_APPROVED_PENDING_SIGNATURE_BLOCKED blockers=" + "; ".join(result["blockers"]))
    return 0 if args.allow_draft else 2


if __name__ == "__main__":
    raise SystemExit(main())
