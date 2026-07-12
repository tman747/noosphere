#!/usr/bin/env python3
"""Run local tensor/residue/HDF/adjoint claim precursors and emit immutable evidence.

All six rows remain PARTIAL locally except that the retired universal HDF rows
emit their frozen KILLED disposition.  A passing local crate corpus does not
manufacture independently authored verifiers, hardware/error-distribution
measurements, beacon unpredictability, or a public training proof campaign.
"""
from __future__ import annotations

import argparse

from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check

RUNNER = "tools/gates/run_tensor_hdf_claim.py"

# Packages, exact source modules, evidence disposition, and external residue.
CLAIM_BINDINGS = {
    "M-TENSOR": (
        ("noos-analytics",),
        ("crates/noos-analytics/src/tensor.rs",),
        "EXTERNAL_BLOCKED",
        [
            "The canonical vectors and mutation corpus are local Rust evidence, not two independently authored cross-verifiers.",
            "Post-commit beacon unpredictability is an explicit external randomness assumption; no production beacon campaign is claimed.",
            "The frozen 256x256 paid encrypted-delivery trial and calibrated work-per-joule campaign remain external.",
        ],
    ),
    "M-RESIDUE": (
        ("noos-analytics",),
        ("crates/noos-analytics/src/residue.rs",),
        "EXTERNAL_BLOCKED",
        [
            "Fast and residual-dot verifiers are independently structured local code in one repository, not independently authored verifier families.",
            "Exhaustive F3 enumeration exercises the exact q^-rank identity locally; preregistered production beacon uniformity and independence tests remain external.",
            "Large-field soundness is the proved field theorem and is not inferred from the seeded empirical sweep.",
        ],
    ),
    "M-HDF": (
        ("noos-analytics",),
        (
            "crates/noos-analytics/src/lib.rs",
            "crates/noos-analytics/src/hdf_profile.rs",
        ),
        "KILLED",
        [
            "The universal M-HDF claim remains RETIRED: flat-error worsening, characteristic-two collapse, adaptive timing, and quantization-floor counterexamples are permanent tests.",
            "No exact Freivalds amplification or pointwise detection dominance is implemented or claimed.",
        ],
    ),
    "M-HDF-ENERGY": (
        ("noos-analytics",),
        (
            "crates/noos-analytics/src/lib.rs",
            "crates/noos-analytics/src/hdf_profile.rs",
        ),
        "EXTERNAL_BLOCKED",
        [
            "Local exact integer tests exercise energy conservation, exhaustive 2x2 unbiasedness/fourth-moment variance bounds, commit-before-derived-challenge binding, and permanent counterexamples.",
            "The <=1e-6 false-positive, >=99.9% named-attack detection, equal-cost non-inferiority, and <=0.5% compatible-resident-HD latency thresholds require pinned hardware/error-distribution experiments.",
            "All outputs are SHADOW_ONLY and cannot affect exact Freivalds acceptance, Ground, Ring weight, issuance, or production settlement.",
        ],
    ),
    "S-HDF": (
        ("noos-analytics",),
        ("crates/noos-analytics/src/hdf_profile.rs",),
        "KILLED",
        [
            "S-HDF inherits the retired universal M-HDF disposition; passing one local model/profile cannot generalize.",
            "The profile-bound wrapper is only an M-HDF-ENERGY shadow precursor and rejects model, numeric-profile, challenge, and residual splices.",
            "Profile-specific multi-hardware false-positive and cost thresholds remain external.",
        ],
    ),
    "M-ADJOINT": (
        ("noos-training", "noos-analytics"),
        (
            "crates/noos-training/src/adjoint.rs",
            "crates/noos-analytics/src/residue.rs",
        ),
        "EXTERNAL_BLOCKED",
        [
            "The local exact-integer precursor binds all three training GEMMs, global dual identity, optimizer clipping/momentum/update, policy lag, and post-commit challenges.",
            "The local 10^7 campaign exercises structured capsule header/profile/root mutations; full relation-level adversarial capsules at that scale, private-example leakage measurement, and an independent proof/verifier campaign remain external.",
            "The operation census is below deterministic GEMM replay at the exercised 32^3 profile, but real proof plus witness-availability cost on a production training profile is unmeasured; training remains SHADOW_ONLY and non-slashable.",
        ],
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIM_BINDINGS))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    packages, modules, result, limitations = CLAIM_BINDINGS[args.claim]
    test = cargo_test(packages)
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    sources = [RUNNER]
    for package in packages:
        sources.append(f"crates/{package}/Cargo.toml")
    for module in modules:
        if not (ROOT / module).is_file():
            raise SystemExit(f"missing claim module: {module}")
        sources.append(module)
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=[
            evidence_check("claim-falsifiers", "falsifier", True, test),
        ] if result == "KILLED" else [
            evidence_check("local-precursor", "implementation", True, test),
            evidence_check("external-pass-threshold", "external_requirement", False, limitations),
        ],
        sources=sources,
        limitations=["This is local precursor evidence, not independent or production evidence."]
        + limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
