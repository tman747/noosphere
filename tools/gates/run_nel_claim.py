#!/usr/bin/env python3
"""Run a neural-lane claim local implementation test and emit raw immutable evidence.

Dedicated runner for the NEL N-* mechanism family. IMPLEMENTED rows carry a complete local
contract with falsifier tests over the frozen mini W8A8 integer profile (noos-nel inference
module, protocol/vectors/nel/forward-w8a8-v1.json) plus the noos-hearth/noos-work-loom
settlement integration. PARTIAL rows run the same crate tests but emit EXTERNAL_BLOCKED
because their claim text requires externals (cross-vendor GPU conformance at 0.5B, the
tokenizer byte-spec campaign, live-network retrieval and beacon-liveness drills, a measured
real prover)."""
from __future__ import annotations

import argparse

from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check

NEL_PACKAGES = ("noos-nel", "noos-hearth", "noos-work-loom")
INFERENCE = (
    "crates/noos-nel/src/inference.rs",
    "crates/noos-nel/src/luts.rs",
    "protocol/vectors/nel/forward-w8a8-v1.json",
)
SETTLEMENT = ("crates/noos-nel/tests/settlement.rs",)

# Audited bindings from claim to the crate(s) implementing its local contract, plus the
# module files that carry it and whether the local state is complete.
CLAIM_BINDINGS = {
    "N-PROFILE": (NEL_PACKAGES[:1], INFERENCE, False),
    "N-TOKEN-STATE": (NEL_PACKAGES[:1], INFERENCE + ("crates/noos-nel/src/lib.rs",), True),
    "N-CHUNK-FREIVALDS": (NEL_PACKAGES[:1], INFERENCE + ("crates/noos-nel/src/lib.rs",), True),
    "N-BISECT": (NEL_PACKAGES, INFERENCE + SETTLEMENT + ("crates/noos-nel/src/lib.rs",), True),
    "N-ACT-DA": (NEL_PACKAGES, INFERENCE + SETTLEMENT, True),
    "N-KV-REPLAY": (NEL_PACKAGES[:1], INFERENCE, True),
    "N-SAMPLER": (NEL_PACKAGES[:1], INFERENCE, True),
}

PARTIAL_LIMITATIONS = {
    "N-PROFILE": [
        "The frozen integer profile is exercised at mini shape (hidden 32, 2 layers); the "
        "registered 0.5B model, the tokenizer byte-spec, and the >=10^9-instance cross-vendor "
        "NVIDIA/AMD/CPU conformance campaign (E-NEL-01/G5) remain external.",
    ],
}


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
    limitations += PARTIAL_LIMITATIONS.get(args.claim, [])
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=[
            evidence_check("claim-implementation", "implementation", True, test),
            evidence_check("claim-falsifiers", "falsifier", True, test),
        ] if implemented else [
            evidence_check("local-precursor", "implementation", True, test),
            evidence_check("external-pass-threshold", "external_requirement", False, PARTIAL_LIMITATIONS[args.claim]),
        ],
        sources=sources,
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
