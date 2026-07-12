#!/usr/bin/env python3
"""Run Hearth local precursors without mislabeling them as field evidence."""
from __future__ import annotations

import argparse

from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check


CLAIMS = (
    "H-HEARTH",
    "H-FEDERATE",
    "H-SEED",
    "H-AUDIT",
    "H-REPAIR",
    "H-TRAIN",
    "H-RELAY",
    "H-PAY",
    *(f"E-HEARTH-0{i}" for i in range(1, 9)),
)

PACKAGES = {
    "H-HEARTH": ("noos-hearth", "noos-workerd"),
    "H-FEDERATE": ("noos-hearth", "noos-workerd"),
    "H-SEED": ("noos-hearth", "noos-workerd"),
    "H-AUDIT": ("noos-hearth", "noos-workerd", "noos-nel", "noos-work-loom"),
    "H-REPAIR": ("noos-hearth", "noos-nel"),
    "H-TRAIN": ("noos-training", "noos-hearth", "noos-nel", "noos-work-loom"),
    "H-RELAY": ("noos-hearth", "noos-workerd"),
    "H-PAY": ("noos-hearth", "noos-work-loom"),
    "E-HEARTH-01": ("noos-hearth", "noos-nel"),
    "E-HEARTH-02": ("noos-hearth", "noos-nel", "noos-workerd"),
    "E-HEARTH-03": ("noos-hearth", "noos-nel"),
    "E-HEARTH-04": ("noos-hearth",),
    "E-HEARTH-05": ("noos-hearth", "noos-workerd"),
    "E-HEARTH-06": ("noos-training", "noos-hearth", "noos-nel", "noos-work-loom"),
    "E-HEARTH-07": ("noos-hearth", "noos-work-loom"),
    "E-HEARTH-08": ("noos-hearth", "noos-workerd"),
}

CONTRACTS = {
    "H-HEARTH": "five-state lifecycle, exact optimal contiguous planner, integer boundary binding, conformance falsifiers",
    "H-FEDERATE": "whole-job locality placement, zero token cross-traffic, 0.8x scaling evaluator, WAN inversion rule",
    "H-SEED": "systematic Reed-Solomon 8-of-12, content-address verification, corruption rejection, resumable departure",
    "H-AUDIT": "post-commit Chorus assignment, TOPLOC-to-Freivalds-to-dispute ladder, phone shard protocol shape",
    "H-REPAIR": "p=0.3/0.6/0.9 replication controls, availability classes, commitment-to-reseed repair path",
    "H-TRAIN": "H=500 pilot shape, three integer GEMM audits, four attack classes, trusted-federation rollback",
    "H-RELAY": "direct traversal, mandatory funded relay fallback, RTT-class honesty, locality/cost evaluator",
    "H-PAY": "bonded mixed-vendor admission, replay/latency Sybil checks, escrow conservation, anti-wash eligibility",
    "E-HEARTH-01": "local placement/schedule commitment falsifier and mandatory FP16 negative-control evaluator",
    "E-HEARTH-02": "40-phone two-layer shard protocol shape and four exact-fault escalation classes",
    "E-HEARTH-03": "synthetic p=0.3/0.6/0.9 controls and complete deterministic departure path",
    "E-HEARTH-04": "all any-8 reconstruction patterns, corrupt seeder rejection, mid-fetch re-sourcing",
    "E-HEARTH-05": "2/3/4-hop integer latency decomposition and retired-and-replaced refutation evaluator",
    "E-HEARTH-06": "1.5B/32-hearth/H=500 model plus three-GEMM and planted-attack precursor",
    "E-HEARTH-07": "one-third/bond cohort evaluator and independent conformance/latency detectors",
    "E-HEARTH-08": "60% direct, 100% relay reachability, 20% cost and locality threshold evaluator",
}

BLOCKERS = {
    "H-HEARTH": "requires >=10^9 measured operator instances on real NVIDIA, AMD, and CPU implementations",
    "H-FEDERATE": "requires measured 1000-hearth goodput and a public real-WAN autopsy",
    "H-SEED": "requires 100 fresh hearths on measured residential links fetching the real 8.03 GB member",
    "H-AUDIT": "requires sustained real-silicon results on two independent phone platforms and live witness delivery",
    "H-REPAIR": "requires 300 consenting households in three regions for 90 public elapsed days",
    "H-TRAIN": "requires 32 physical 24 GB hearths, a real 1.5B run, residential WAN, and live testnet stake",
    "H-RELAY": "requires deployment-population NAT traversal, relay billing, and locality measurements",
    "H-PAY": "requires a funded independent red team and twelve months of external non-circular demand",
    "E-HEARTH-01": "real mixed-vendor hardware campaign and >=10^9 measured instances are unavailable",
    "E-HEARTH-02": "real 3090/4090 hearths and two independent phone platforms are unavailable",
    "E-HEARTH-03": "300-household, three-region, 90-day trace corpus is unavailable",
    "E-HEARTH-04": "100 real fresh hearths, residential links, and the real 8.03 GB member are unavailable",
    "E-HEARTH-05": "real multi-hop WAN measurements and public negative-result publication are unavailable",
    "E-HEARTH-06": "32 real hearths, residential links, a 1.5B training run, and live testnet slashing are unavailable",
    "E-HEARTH-07": "funded independent red-team operators and real-value attack economics are unavailable",
    "E-HEARTH-08": "deployed volunteer population NAT and funded relay measurements are unavailable",
}

SOURCES = {
    "H-HEARTH": ("lifecycle.rs", "lib.rs"),
    "H-FEDERATE": ("federation.rs", "lib.rs"),
    "H-SEED": ("seeding.rs", "lib.rs"),
    "H-AUDIT": ("audit.rs", "lib.rs"),
    "H-REPAIR": ("repair.rs", "lib.rs"),
    "H-RELAY": ("relay.rs", "lib.rs"),
    "H-PAY": ("payment.rs", "lib.rs"),
}


def source_paths(claim: str) -> list[str]:
    sources = [
        "tools/gates/run_hearth_claim.py",
        "crates/noos-hearth/src/rollback.rs",
    ]
    mechanism = claim
    if claim.startswith("E-HEARTH-"):
        mechanism = {
            "E-HEARTH-01": "H-HEARTH",
            "E-HEARTH-02": "H-AUDIT",
            "E-HEARTH-03": "H-REPAIR",
            "E-HEARTH-04": "H-SEED",
            "E-HEARTH-05": "H-FEDERATE",
            "E-HEARTH-06": "H-TRAIN",
            "E-HEARTH-07": "H-PAY",
            "E-HEARTH-08": "H-RELAY",
        }[claim]
    if mechanism == "H-TRAIN":
        sources.extend(("crates/noos-training/Cargo.toml", "crates/noos-training/src/lib.rs"))
    else:
        sources.append("crates/noos-hearth/Cargo.toml")
        sources.extend(f"crates/noos-hearth/src/{name}" for name in SOURCES[mechanism])
    for package in PACKAGES[claim]:
        manifest = f"crates/{package}/Cargo.toml"
        if (ROOT / manifest).is_file():
            sources.append(manifest)
        source_root = ROOT / "crates" / package / "src"
        if source_root.is_dir():
            sources.extend(
                path.relative_to(ROOT).as_posix()
                for path in source_root.rglob("*.rs")
            )
    return sorted(set(sources))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=CLAIMS)
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()

    test = cargo_test(PACKAGES[args.claim])
    if args.rollback_check:
        continuity = base_continuity()
        if not continuity["ordinary_base_live"] or not continuity["rollback_verified"]:
            raise SystemExit("ordinary-base rollback continuity failed")
        print(f"RESULT {args.claim} rollback=PASSED local_fallback_tests=PASSED")
        return 0

    emit(
        gate="hearth-local-" + args.claim.lower(),
        claims=[args.claim],
        result="EXTERNAL_BLOCKED",
        expected="EXTERNAL_BLOCKED",
        checks=[
            evidence_check("local-precursor", "falsifier", True, {"contract": CONTRACTS[args.claim], "test": test}),
            evidence_check("external-pass-threshold", "external_requirement", False, BLOCKERS[args.claim]),
        ],
        sources=source_paths(args.claim),
        limitations=[
            BLOCKERS[args.claim],
            "Deterministic fixtures and modeled threshold evaluators are local precursor evidence, not hardware, operator, WAN, public-duration, or independent evidence.",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
