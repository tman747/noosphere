#!/usr/bin/env python3
"""Run exact local Dream/Chorus contracts and emit immutable evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from decimal import Decimal
from pathlib import Path

from experimental_gate import (
    ROOT,
    base_continuity,
    cargo_test,
    emit,
    evidence_check,
    require_disabled_controls,
)

CLAIMS = (
    "S-ACCESS",
    "S-CHORUS",
    "S-DREAM",
    "S-DREAM-LANE",
    "S-GLOBAL-ORGANISM",
    "E-DREAM-02",
)
DREAM_ARTIFACT_ROOT = Path("C:/tmp/dream-lane")
PREMIUMS = (0, 271, 542, 813, 1084)
EVENTS = 100_000
SEED = 20_260_710
QUALITY_THRESHOLD_MB = Decimal("75")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_dream_sweep() -> dict[str, object]:
    rows: list[dict[str, object]] = []
    hashes: dict[str, str] = {}
    eligible_passes: list[int] = []
    common_manipulator_entry: Decimal | None = None
    for premium in PREMIUMS:
        path = DREAM_ARTIFACT_ROOT / f"results-v2-p{premium}.json"
        if not path.is_file():
            raise SystemExit(f"frozen E-DREAM-02 artifact missing: {path}")
        document = json.loads(path.read_text(encoding="utf-8"), parse_float=Decimal)
        main = document.get("runs", {}).get("main", {})
        v2 = document.get("v2", {})
        gates = document.get("gates", [])
        if main.get("events") != EVENTS or main.get("seed") != SEED:
            raise SystemExit(f"wrong E-DREAM-02 event/seed preregistration: {path}")
        if v2.get("influence_premium_uT") != premium or v2.get("insulated_only") is not True:
            raise SystemExit(f"wrong E-DREAM-02 premium/insulation arm: {path}")
        expected_exclusion = premium == 0
        if v2.get("manipulator_excluded") is not expected_exclusion:
            raise SystemExit(f"wrong E-DREAM-02 exclusion policy: {path}")
        if not gates or any(gate.get("ok") is not True for gate in gates):
            raise SystemExit(f"E-DREAM-02 mechanism gate failure in frozen artifact: {path}")

        manipulator_net = Decimal(v2["manipulator_net_uT_per_event"])
        honest_net = Decimal(v2["honest_net_uT_per_event"])
        main_quality = Decimal(v2["main_improve_mB"])
        manipulation_quality = Decimal(v2["manip_arm_improve_mB"])
        eligible = 542 <= premium <= 1084
        passes = (
            eligible
            and manipulator_net <= 0
            and honest_net > 0
            and main_quality >= QUALITY_THRESHOLD_MB
            and manipulation_quality >= QUALITY_THRESHOLD_MB
        )
        if passes:
            eligible_passes.append(premium)
        if premium > 0:
            entry_before_premium = manipulator_net + Decimal(premium)
            if common_manipulator_entry is None:
                common_manipulator_entry = entry_before_premium
            elif entry_before_premium != common_manipulator_entry:
                raise SystemExit("E-DREAM-02 premium sweep is not exact-linear")
        rows.append(
            {
                "premium_uT": premium,
                "eligible": eligible,
                "manipulator_excluded": expected_exclusion,
                "manipulator_net_uT_per_event": str(manipulator_net),
                "honest_net_uT_per_event": str(honest_net),
                "main_improve_mB": str(main_quality),
                "manip_arm_improve_mB": str(manipulation_quality),
                "passes": passes,
            }
        )
        hashes[path.as_posix()] = file_sha256(path)

    if eligible_passes:
        raise SystemExit(f"E-DREAM-02 expected KILL contradicted by premiums {eligible_passes}")
    if common_manipulator_entry != Decimal("1605.6299"):
        raise SystemExit("E-DREAM-02 measured entry margin changed")
    return {
        "name": "frozen preregistered premium sweep re-evaluation",
        "passed": True,
        "verdict": "KILLED",
        "events_per_arm": EVENTS,
        "seed": SEED,
        "quality_threshold_mB": str(QUALITY_THRESHOLD_MB),
        "common_manipulator_entry_uT_per_event": str(common_manipulator_entry),
        "eligible_passes": eligible_passes,
        "rows": rows,
        "artifact_sha256": hashes,
    }


def rollback_check(claim: str) -> int:
    package = {
        "S-ACCESS": "noos-loam",
        "S-CHORUS": "noos-chorus",
        "S-GLOBAL-ORGANISM": "noos-swarm",
    }.get(claim, "noos-reflex")
    cargo_test([package])
    continuity = base_continuity()
    if claim in {"S-DREAM", "S-DREAM-LANE", "E-DREAM-02"}:
        require_disabled_controls(["dream_lane_enabled"])
    if not continuity["ordinary_base_live"] or not continuity["rollback_verified"]:
        raise SystemExit("ordinary-base rollback continuity failed")
    print(f"RESULT {claim} rollback=PASSED")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", choices=CLAIMS, required=True)
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    if args.rollback_check:
        return rollback_check(args.claim)

    if args.claim == "S-CHORUS":
        local = cargo_test(["noos-chorus"])
        emit(
            gate="chorus-mesh",
            claims=[args.claim],
            result="EXTERNAL_BLOCKED",
            expected="EXTERNAL_BLOCKED",
            checks=[
                evidence_check("local-precursor", "falsifier", True, local),
                evidence_check("physical-device-threshold", "external_requirement", False, "requires consenting physical devices, emulator farms, latency, bytes, battery, attrition, and real diversity observations"),
            ],
            sources=[
                "crates/noos-chorus/Cargo.toml",
                "crates/noos-chorus/src/lib.rs",
                "tools/gates/run_dream_chorus_claim.py",
            ],
            limitations=[
                "Software signatures are a local identity/profile-binding precursor, not hardware attestation.",
                "No phone p95, 20 MB, battery, attrition, or real 10x Sybil influence result is claimed.",
                "Chorus output is advisory with zero proposal/finality weight and zero slashing.",
            ],
        )
        return 0

    if args.claim == "S-ACCESS":
        local = cargo_test(["noos-loam"])
        emit(
            gate="access-recovery",
            claims=[args.claim],
            result="EXTERNAL_BLOCKED",
            expected="EXTERNAL_BLOCKED",
            checks=[
                evidence_check("local-access-falsifiers", "falsifier", True, local),
                evidence_check(
                    "independent-operator-threshold",
                    "external_requirement",
                    False,
                    "requires a partition drill across at least three independently operated recovery and artifact paths",
                ),
            ],
            sources=[
                "crates/noos-loam/Cargo.toml",
                "crates/noos-loam/src/lib.rs",
                "crates/noos-loam/src/access.rs",
                "tools/gates/run_dream_chorus_claim.py",
            ],
            limitations=[
                "The manifest rejects repeated declared failure domains, repeated operators, missing path kinds, ambiguous content, and two-domain outages.",
                "Fixture operator identifiers are declarations, not evidence of independently operated providers.",
                "Inference remains typed off-consensus and no network-scale continuity result is claimed.",
            ],
        )
        return 0

    if args.claim == "S-GLOBAL-ORGANISM":
        local = cargo_test(["noos-swarm"])
        emit(
            gate="global-organism-g0",
            claims=[args.claim],
            result="EXTERNAL_BLOCKED",
            expected="EXTERNAL_BLOCKED",
            checks=[
                evidence_check("finite-component-falsifiers", "falsifier", True, local),
                evidence_check(
                    "global-observables-threshold",
                    "external_requirement",
                    False,
                    "no production threshold or preregistered global resilience, control, continuity, rights, and benefit observables exist",
                ),
            ],
            sources=[
                "crates/noos-swarm/Cargo.toml",
                "crates/noos-swarm/src/lib.rs",
                "crates/noos-swarm/src/organism.rs",
                "tools/gates/run_dream_chorus_claim.py",
            ],
            limitations=[
                "Finite component aggregation explicitly returns establishes_global_organism=false.",
                "Component fixtures are not planet-scale, independently operated, or production evidence.",
                "The aggregate has zero proposal and finality weight and remains at G0.",
            ],
        )
        return 0

    local = cargo_test(["noos-reflex"])
    disabled = require_disabled_controls(["dream_lane_enabled"])
    dream_sources = [
        "crates/noos-reflex/Cargo.toml",
        "crates/noos-reflex/src/lib.rs",
        "crates/noos-reflex/src/dream.rs",
        "protocol/spec/constants-v1.toml",
        "tools/gates/run_dream_chorus_claim.py",
    ]
    if args.claim == "S-DREAM":
        emit(
            gate="foresight-sandbox",
            claims=[args.claim],
            result="EXTERNAL_BLOCKED",
            expected="EXTERNAL_BLOCKED",
            checks=[
                evidence_check("local-precursor", "falsifier", True, local),
                disabled,
                evidence_check("forecast-harm-threshold", "external_requirement", False, "requires preregistered held-out events, non-persona baseline, proper scoring, and protected-group evaluation"),
            ],
            sources=dream_sources,
            limitations=[
                "No 10% calibrated forecast gain or protected-group harm result is claimed.",
                "Persona output is non-authoritative and realization requires a distinct owner-signed capability.",
            ],
        )
        return 0

    if args.claim == "S-DREAM-LANE":
        emit(
            gate="dream-lane-disabled",
            claims=[args.claim],
            result="DISABLED",
            expected="DISABLED",
            checks=[
                evidence_check("notebook-lifecycle-falsifier", "falsifier", True, local),
                disabled,
            ],
            sources=dream_sources,
            limitations=[
                "The killed general market remains disabled; only private, payout-free, non-authoritative research survives.",
                "No 90-day external paid-demand or production causal-insulation evidence is claimed.",
            ],
        )
        return 0


    sweep = load_dream_sweep()
    emit(
        gate="e-dream-02-kill",
        claims=[args.claim],
        result="KILLED",
        expected="KILLED",
        checks=[
            evidence_check("registered-falsifier", "falsifier", True, {"local": local, "sweep": sweep}),
            disabled,
        ],
        sources=dream_sources,
        limitations=[
            "The frozen simulator artifacts are re-evaluated, not represented as independent or cross-vendor evidence.",
            "The repository module is a deterministic instrument/lifecycle precursor; it does not regenerate the 100,000-event arms.",
            "The kill is preserved without sweep extension or threshold adjustment.",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
