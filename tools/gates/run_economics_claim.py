#!/usr/bin/env python3
"""Run deterministic economics precursors and emit source-bound evidence.

Every assigned economics claim has an external or owner-controlled pass
threshold.  This gate therefore records the local falsifiers as
``EXTERNAL_BLOCKED`` evidence and never promotes a synthetic run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check

CLAIMS = (
    "M-OMEGA",
    "M-ISSUANCE",
    "A-DUPLEX-ISSUANCE",
    "S-DEMAND",
    "E-DEMAND-PREDICATE",
    "M-PROOFPOWER",
)

COMMON_SOURCES = (
    "protocol/claims/registry.json",
    "protocol/spec/constants-v1.toml",
    "tools/gates/run_economics_claim.py",
)

CLAIM_SOURCES = {
    "M-OMEGA": (
        "crates/noos-analytics/src/lib.rs",
        "crates/noos-work-loom/src/economics.rs",
    ),
    "M-ISSUANCE": (
        "crates/noos-lumen/src/issuance.rs",
        "crates/noos-lumen/src/state.rs",
    ),
    "A-DUPLEX-ISSUANCE": (
        "crates/noos-lumen/src/issuance.rs",
        "crates/noos-work-loom/src/economics.rs",
    ),
    "S-DEMAND": ("crates/noos-work-loom/src/economics.rs",),
    "E-DEMAND-PREDICATE": ("crates/noos-work-loom/src/economics.rs",),
    "M-PROOFPOWER": (
        "crates/noos-work-loom/src/economics.rs",
        "crates/noos-jet/src/proof.rs",
        "crates/noos-witness/src/lib.rs",
    ),
}

PACKAGES = {
    "M-OMEGA": ("noos-analytics", "noos-work-loom"),
    "M-ISSUANCE": ("noos-lumen",),
    "A-DUPLEX-ISSUANCE": ("noos-work-loom", "noos-lumen"),
    "S-DEMAND": ("noos-work-loom",),
    "E-DEMAND-PREDICATE": ("noos-work-loom",),
    "M-PROOFPOWER": ("noos-work-loom", "noos-jet", "noos-witness"),
}

LIMITATIONS = {
    "M-OMEGA": [
        "Assumption boundary: local measurements are deterministic fixtures, not the required 99%-confidence cross-shape and cross-hardware cost-per-joule campaign or independent reproductions.",
        "Sustained admitted demand for one retarget half-life is unavailable; production Omega credit remains structurally zero.",
    ],
    "M-ISSUANCE": [
        "Assumption boundary: tests use valueless NOOS_TEST parameters; signed mainnet supply, recipient shares, rounding, terminal height, and fee disposition remain OWNER_BLOCKED.",
        "A second consensus client and production zero-AI-demand liveness evidence are unavailable.",
    ],
    "A-DUPLEX-ISSUANCE": [
        "Assumption boundary: the allocator is shadow-only and uses fixture schedules; no preregistered base-security stress minimum has been owner-frozen.",
        "Ninety public days above 80% external paid-delivered demand and production blackout finality are unavailable; production reallocation remains zero.",
    ],
    "S-DEMAND": [
        "Assumption boundary: INDEPENDENT means only the enumerated challengeable evidence fields; hidden beneficial ownership and quality remain explicit non-claims.",
        "A blinded false-independent campaign and a real rolling 30-day public diversity window are unavailable; demand-derived production influence remains zero.",
    ],
    "E-DEMAND-PREDICATE": [
        "Assumption boundary: the predicate establishes the enumerated evidence bundle, not economic truth, hidden beneficial ownership, or output quality.",
        "A real public 30-day aggregate meeting the value, diversity, and concentration thresholds is unavailable; synthetic observations cannot satisfy the claim threshold.",
    ],
    "M-PROOFPOWER": [
        "Assumption boundary: local accounting consumes challengeable demand evidence and committed receipts; it does not establish hidden ownership or an adversary capital budget.",
        "Preregistered wash/capture power, blinded false-credit measurement, and proof that no economic entity reaches one third under the declared budget are unavailable; production beta remains zero.",
    ],
}


def run(command: list[str]) -> dict[str, object]:
    env = os.environ.copy()
    env.setdefault(
        "LIBCLANG_PATH",
        "C:/Users/ntrap/AppData/Local/Programs/Swift/Toolchains/6.3.2+Asserts/usr/bin",
    )
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode:
        sys.stderr.write(completed.stdout)
        digest = hashlib.sha256(completed.stdout.encode()).hexdigest()
        raise SystemExit(
            f"economics claim check failed ({completed.returncode}); log_sha256={digest}"
        )
    return {"command": command, "exit_code": 0}


def main() -> int:
    os.environ.setdefault(
        "LIBCLANG_PATH",
        "C:/Users/ntrap/AppData/Local/Programs/Swift/Toolchains/6.3.2+Asserts/usr/bin",
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=CLAIMS)
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()

    if args.rollback_check:
        continuity = base_continuity()
        if (
            continuity["ordinary_base_live"] is not True
            or continuity["rollback_verified"] is not True
        ):
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    observations: list[object] = [cargo_test(PACKAGES[args.claim])]
    if args.claim == "M-ISSUANCE":
        observations.append(
            run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--release",
                    "-p",
                    "noos-lumen",
                    "issuance::tests::issuance_adversarial_paths_10m",
                    "--",
                    "--ignored",
                    "--exact",
                ]
            )
        )

    limitations = LIMITATIONS[args.claim]
    emit(
        gate="claim-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result="EXTERNAL_BLOCKED",
        expected="EXTERNAL_BLOCKED",
        checks=[
            evidence_check(
                "local-deterministic-mechanism",
                "implementation",
                True,
                observations,
            ),
            evidence_check(
                "local-falsifier-battery",
                "falsifier",
                True,
                observations,
            ),
            evidence_check(
                "full-claim-pass-threshold",
                "external_requirement",
                False,
                limitations,
            ),
        ],
        sources=COMMON_SOURCES + CLAIM_SOURCES[args.claim],
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
