#!/usr/bin/env python3
"""Execute registered falsifiers for locally implemented negative claims."""
from __future__ import annotations

import argparse
from experimental_gate import cargo_test, emit, evidence_check, require_disabled_controls


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=["A-CLASS-GATE.v1", "E-DEMAND-WASH-01"])
    args = parser.parse_args()
    if args.claim == "A-CLASS-GATE.v1":
        test = cargo_test(["noos-agent-class"])
        checks = [
            require_disabled_controls(["class_gate_irreversible_budget"]),
            evidence_check("registered-falsifier", "falsifier", True, test),
        ]
        sources = [
            "crates/noos-agent-class/Cargo.toml",
            "crates/noos-agent-class/src/lib.rs",
            "protocol/spec/constants-v1.toml",
        ]
    else:
        test = cargo_test(["noos-work-loom", "noos-analytics"])
        checks = [
            require_disabled_controls(["work_loom_credit_enabled", "work_loom_weight_cap", "witness_proofpower_bonus_enabled"]),
            evidence_check("registered-falsifier", "falsifier", True, test),
        ]
        sources = [
            "crates/noos-work-loom/Cargo.toml",
            "crates/noos-work-loom/src/lib.rs",
            "crates/noos-analytics/Cargo.toml",
            "crates/noos-analytics/src/lib.rs",
            "protocol/spec/constants-v1.toml",
        ]
    emit(
        gate="negative-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result="KILLED",
        expected="KILLED",
        checks=checks,
        sources=sources,
        limitations=["The killed claim remains fail-closed; the replacement mechanism is a separate claim."],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
