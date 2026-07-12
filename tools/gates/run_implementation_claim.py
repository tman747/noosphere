#!/usr/bin/env python3
"""Run a claim-specific local implementation test and emit raw immutable evidence."""
from __future__ import annotations

import argparse
import json
from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check

# Audited bindings from claim to the crate(s) that implement its local
# contract live in the versioned registry sidecar so the claim matrix,
# this runner, and central update tooling share one source of truth.
BINDINGS_PATH = ROOT / "protocol/claims/claim-packages.json"
CLAIM_PACKAGES = {
    claim: tuple(packages)
    for claim, packages in json.loads(BINDINGS_PATH.read_text(encoding="utf-8")).items()
}

PARTIAL_GAPS = {
    "E-WEFT-03": "RISC Zero 32^3/64^3 derived-guest parity and cycle envelope remain external.",
    "E-WEFT-05": "Compiler-integrated flow lowering and the 10^6 accepted-elaboration campaign remain unmet.",
    "E-WEFT-06": "Bonded lifecycle, appeal, and two-profitable-challenger economics remain unmet.",
    "E-WEFT-07": "Typed repair debt, ledger-closure comparison, and production annotation-burden study remain unmet.",
    "E-WEFT-08": "Two consecutive quarters of admission, audit-cost, and incident telemetry remain unmet.",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIM_PACKAGES))
    parser.add_argument("--rollback-check", action="store_true")
    parser.add_argument(
        "--result",
        choices=("IMPLEMENTED", "PARTIAL"),
        default="IMPLEMENTED",
        help="emit PARTIAL evidence without promoting an incomplete local implementation",
    )
    args = parser.parse_args()
    packages = CLAIM_PACKAGES[args.claim]
    test = cargo_test(packages)
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0
    claim_test_stem = args.claim.lower().replace("-", "_").replace(".", "_")
    canonical_weft_sources = (
        "protocol/schemas/weft-v0.md",
        "protocol/vectors/weft/weft-profile-v0.json",
        "protocol/vectors/weft/weft-cost-v0.json",
        "protocol/vectors/weft/weft-refs-v0.json",
    )
    sources: list[str] = list(canonical_weft_sources) if args.claim.startswith("E-WEFT-") else []
    for package in packages:
        base = ROOT / "crates" / package
        sources.append(f"crates/{package}/Cargo.toml")
        source = base / "src" / "lib.rs"
        if not source.is_file():
            source = base / "src" / "main.rs"
        sources.append(source.relative_to(ROOT).as_posix())
        tests = base / "tests"
        if tests.is_dir():
            sources.extend(
                test.relative_to(ROOT).as_posix()
                for test in sorted(tests.glob(f"{claim_test_stem}*.rs"))
            )
    checks = [
        evidence_check("claim-implementation", "implementation", True, test),
        evidence_check("claim-falsifiers", "falsifier", True, test),
    ]
    limitations = ["This is local implementation evidence, not independent or production evidence."]
    if args.result == "PARTIAL":
        gap = PARTIAL_GAPS.get(args.claim)
        if gap is None:
            raise SystemExit(f"--result PARTIAL has no audited residual gap for {args.claim}")
        checks.append(evidence_check("residual-requirement", "external_requirement", False, gap))
        limitations.append(gap)
    emit(
        gate=("implementation-" if args.result == "IMPLEMENTED" else "partial-implementation-")
        + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=args.result,
        expected=args.result,
        checks=checks,
        sources=sources,
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
