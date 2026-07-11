#!/usr/bin/env python3
"""Run a claim-specific local implementation test and emit raw immutable evidence."""
from __future__ import annotations

import argparse
import json
from experimental_gate import ROOT, base_continuity, cargo_test, emit

# Audited bindings from claim to the crate(s) that implement its local
# contract live in the versioned registry sidecar so the claim matrix,
# this runner, and central update tooling share one source of truth.
BINDINGS_PATH = ROOT / "protocol/claims/claim-packages.json"
CLAIM_PACKAGES = {
    claim: tuple(packages)
    for claim, packages in json.loads(BINDINGS_PATH.read_text(encoding="utf-8")).items()
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIM_PACKAGES))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    packages = CLAIM_PACKAGES[args.claim]
    test = cargo_test(packages)
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0
    sources: list[str] = []
    for package in packages:
        base = ROOT / "crates" / package
        sources.append(f"crates/{package}/Cargo.toml")
        source = base / "src" / "lib.rs"
        if not source.is_file():
            source = base / "src" / "main.rs"
        sources.append(source.relative_to(ROOT).as_posix())
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result="IMPLEMENTED",
        expected="IMPLEMENTED",
        checks=[{"name": "claim-specific crate tests", "passed": True, "detail": test}],
        sources=sources,
        limitations=["This is local implementation evidence, not independent or production evidence."],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
