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
DREAM_SWEEP_PROJECTION = ROOT / "tools/gates/fixtures/e_dream_02_sweep.json"
PREMIUMS = (0, 271, 542, 813, 1084)
EVENTS = 100_000
SEED = 20_260_710
QUALITY_THRESHOLD_MB = Decimal("75")
DREAM_SWEEP_PROJECTION_SHA256 = "b886a5825377358961628e0cf79dfaa963285ec806160727804c79533bb00c06"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_dream_sweep() -> dict[str, object]:
    path = DREAM_SWEEP_PROJECTION
    if not path.is_file():
        raise SystemExit(f"frozen E-DREAM-02 projection missing: {path}")
    projection_sha256 = file_sha256(path)
    if projection_sha256 != DREAM_SWEEP_PROJECTION_SHA256:
        raise SystemExit("frozen E-DREAM-02 projection hash changed")
    document = json.loads(path.read_text(encoding="utf-8"), parse_float=Decimal)
    required_fields = {
        "schema",
        "source_artifact_sha256",
        "events_per_arm",
        "seed",
        "quality_threshold_mB",
        "registered_verdict",
        "rows",
    }
    if set(document) != required_fields:
        raise SystemExit("frozen E-DREAM-02 projection fields changed")
    if (
        document["schema"] != "noos/e-dream-02-frozen-sweep-projection/v1"
        or document["events_per_arm"] != EVENTS
        or document["seed"] != SEED
        or Decimal(document["quality_threshold_mB"]) != QUALITY_THRESHOLD_MB
        or document["registered_verdict"] != "KILLED"
    ):
        raise SystemExit("frozen E-DREAM-02 preregistration changed")
    hashes = document["source_artifact_sha256"]
    expected_names = {f"results-v2-p{premium}.json" for premium in PREMIUMS}
    if (
        not isinstance(hashes, dict)
        or set(hashes) != expected_names
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in hashes.values()
        )
    ):
        raise SystemExit("frozen E-DREAM-02 source artifact hashes changed")

    raw_rows = document["rows"]
    if not isinstance(raw_rows, list) or len(raw_rows) != len(PREMIUMS):
        raise SystemExit("frozen E-DREAM-02 projection arm count changed")
    row_fields = {
        "premium_uT",
        "eligible",
        "manipulator_excluded",
        "manipulator_net_uT_per_event",
        "honest_net_uT_per_event",
        "main_improve_mB",
        "manip_arm_improve_mB",
        "passes",
    }
    rows: list[dict[str, object]] = []
    eligible_passes: list[int] = []
    common_manipulator_entry: Decimal | None = None
    for premium, raw in zip(PREMIUMS, raw_rows, strict=True):
        if not isinstance(raw, dict) or set(raw) != row_fields or raw["premium_uT"] != premium:
            raise SystemExit("frozen E-DREAM-02 projection arm fields changed")
        expected_exclusion = premium == 0
        eligible = 542 <= premium <= 1084
        manipulator_net = Decimal(raw["manipulator_net_uT_per_event"])
        honest_net = Decimal(raw["honest_net_uT_per_event"])
        main_quality = Decimal(raw["main_improve_mB"])
        manipulation_quality = Decimal(raw["manip_arm_improve_mB"])
        passes = (
            eligible
            and manipulator_net <= 0
            and honest_net > 0
            and main_quality >= QUALITY_THRESHOLD_MB
            and manipulation_quality >= QUALITY_THRESHOLD_MB
        )
        if (
            raw["eligible"] is not eligible
            or raw["manipulator_excluded"] is not expected_exclusion
            or raw["passes"] is not passes
        ):
            raise SystemExit("frozen E-DREAM-02 derived verdict changed")
        if passes:
            eligible_passes.append(premium)
        if premium > 0:
            entry_before_premium = manipulator_net + Decimal(premium)
            if common_manipulator_entry is None:
                common_manipulator_entry = entry_before_premium
            elif entry_before_premium != common_manipulator_entry:
                raise SystemExit("E-DREAM-02 premium sweep is not exact-linear")
        rows.append(dict(raw))

    if eligible_passes:
        raise SystemExit(f"E-DREAM-02 expected KILL contradicted by premiums {eligible_passes}")
    if common_manipulator_entry != Decimal("1605.6299"):
        raise SystemExit("E-DREAM-02 measured entry margin changed")
    return {
        "name": "frozen preregistered premium sweep projection re-evaluation",
        "passed": True,
        "verdict": "KILLED",
        "events_per_arm": EVENTS,
        "seed": SEED,
        "quality_threshold_mB": str(QUALITY_THRESHOLD_MB),
        "common_manipulator_entry_uT_per_event": str(common_manipulator_entry),
        "eligible_passes": eligible_passes,
        "rows": rows,
        "artifact_sha256": {
            f"C:/tmp/dream-lane/{name}": digest for name, digest in sorted(hashes.items())
        },
        "projection": {
            "path": "tools/gates/fixtures/e_dream_02_sweep.json",
            "sha256": projection_sha256,
        },
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
    negative_result = {"S-DREAM-LANE": "DISABLED", "E-DREAM-02": "KILLED"}.get(claim)
    if negative_result is None:
        print(f"RESULT rollback=PASSED claim={claim}")
    else:
        print(f"RESULT rollback={negative_result} claim={claim} base_continuity=PASSED")
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
        "tools/gates/fixtures/e_dream_02_sweep.json",
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
            "The committed projection re-evaluates the registered metrics and binds the original simulator artifact hashes; it does not regenerate or claim custody of the historical 100,000-event raw arms.",
            "The kill is preserved without sweep extension or threshold adjustment.",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
