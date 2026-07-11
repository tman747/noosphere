#!/usr/bin/env python3
"""Run a privacy-claim local implementation test and emit raw immutable evidence.

Dedicated runner for the umbra / private-BESI claim family. IMPLEMENTED rows carry a complete
local contract with falsifier tests; PARTIAL rows (the HFHE refresh family) run the same crate
tests but emit EXTERNAL_BLOCKED because their claim text requires externals (standard-assumption
reduction, concrete parameters, a zero-knowledge prover, and a second independent verifier).
"""
from __future__ import annotations

import argparse
from experimental_gate import ROOT, base_continuity, cargo_test, emit

# Audited bindings from claim to the crate(s) implementing its local contract, plus the
# module files that carry it and whether the local state is complete.
CLAIM_BINDINGS = {
    "P1-S-DUAL-ROOT": (("noos-private-besi",), ("crates/noos-private-besi/src/dual_root.rs",), True),
    "P2-S-FUSED-AUDIT": (("noos-private-besi",), ("crates/noos-private-besi/src/fused_audit.rs",), True),
    "P3-S-ALGORITHM-TRANSITION": (("noos-private-besi",), ("crates/noos-private-besi/src/transition_market.rs",), True),
    "P4-S-PAID-DELIVERY": (("noos-private-besi",), ("crates/noos-private-besi/src/delivery.rs",), True),
    "M-3PC-MALICIOUS": (("noos-private-besi",), ("crates/noos-private-besi/src/mpc3.rs",), True),
    "M-HFHE-SUITE": (("noos-private-besi",), ("crates/noos-private-besi/src/refresh.rs",), False),
    "M-PROOF-CARRYING-REFRESH": (("noos-private-besi",), ("crates/noos-private-besi/src/refresh.rs",), False),
    "M-PRIVACY-DEPTH": (("noos-private-besi",), ("crates/noos-private-besi/src/depth.rs", "crates/noos-private-besi/src/refresh.rs"), True),
    "A-UMBRA-BASE": (("noos-umbra",), ("crates/noos-umbra/src/lib.rs", "crates/noos-umbra/src/stealth.rs"), True),
    "A-UMBRA-HIDDEN": (("noos-umbra",), ("crates/noos-umbra/src/hidden.rs",), True),
    "M-FIBER": (("noos-umbra",), ("crates/noos-umbra/src/fiber_dag.rs",), True),
    "M-BRANCH": (("noos-umbra",), ("crates/noos-umbra/src/branch.rs",), True),
}

PARTIAL_LIMITATIONS = [
    "The refresh skeleton's continuity tag is a symmetric-key stand-in for the required zero-knowledge prover.",
    "No IND-style model, concrete attack estimate, or production parameters exist for the HFHE suite.",
    "No second independent verifier implementation exists.",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIM_BINDINGS))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    packages, modules, implemented = CLAIM_BINDINGS[args.claim]
    test = cargo_test(packages)
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0
    sources: list[str] = []
    for package in packages:
        sources.append(f"crates/{package}/Cargo.toml")
    for module in modules:
        if not (ROOT / module).is_file():
            raise SystemExit(f"missing claim module: {module}")
        sources.append(module)
    result = "IMPLEMENTED" if implemented else "EXTERNAL_BLOCKED"
    limitations = ["This is local implementation evidence, not independent or production evidence."]
    if not implemented:
        limitations += PARTIAL_LIMITATIONS
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=[{"name": "claim-specific crate tests with falsifiers", "passed": True, "detail": test}],
        sources=sources,
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
