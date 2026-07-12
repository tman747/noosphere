#!/usr/bin/env python3
"""Run exact local precursors for the base-network claim cluster.

E-BASE-01 is parameterized up to the frozen 10^7 transition threshold, but
remains externally blocked unless that full campaign is run by independently
managed clients.  E-BLACKOUT-01 and E-WAN-01 likewise emit honest local
precursor evidence only; public duration, external operators, regions, and
independent carriers are never simulated into existence.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys

from experimental_gate import ROOT, base_continuity, emit

CLAIMS = (
    "A-KEYLESS-CONSENSUS",
    "E-BASE-01",
    "E-BLACKOUT-01",
    "E-WAN-01",
)
MAX_GENERATED = 10_000_000
ELAPSED_RE = re.compile(
    r"(?P<prefix>target\(s\) in |; finished in )(?:(?:\d+)m )?\d+(?:\.\d+)?s"
)


def stable_log_sha256(output: str) -> str:
    canonical = ELAPSED_RE.sub(r"\g<prefix><DURATION>", output.replace("\r\n", "\n"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def run(command: list[str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode:
        sys.stderr.write(completed.stdout)
        digest = hashlib.sha256(completed.stdout.encode()).hexdigest()
        raise SystemExit(f"claim precursor failed ({completed.returncode}); log_sha256={digest}")
    return {
        "command": command,
        "exit_code": 0,
        "stdout_sha256": stable_log_sha256(completed.stdout),
    }


def cargo_test(package: str, test_filter: str) -> dict[str, object]:
    return run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            package,
            test_filter,
            "--",
            "--test-threads=1",
        ]
    )


def checks_for(claim: str, generated: int) -> list[dict[str, object]]:
    if claim == "A-KEYLESS-CONSENSUS":
        return [
            cargo_test("noos-braid", "keyless::tests"),
            cargo_test(
                "noos-node",
                "claim_e_blackout_all_optional_controls_off_keeps_base_live",
            ),
        ]
    if claim == "E-BASE-01":
        return [
            run(
                [
                    sys.executable,
                    "tools/gates/differential_transitions.py",
                    "--generated",
                    str(generated),
                    "--parameterized-max",
                    str(MAX_GENERATED),
                    "--restart-every",
                    str(max(1, min(generated, 25_000))),
                    "--process-matrix",
                ]
            ),
            cargo_test("noos-node", "e2e_happy_path_finality_and_restart_recovery"),
            cargo_test("noos-node", "snapshot_sync_assembles_from_multiple_sources_and_recovers_state"),
            cargo_test("noos-node", "reorg_below_finality_rolls_back_and_replays"),
            cargo_test("noos-node", "claim_e_base_unknown_fields_fail_closed_on_the_production_wire"),
        ]
    if claim == "E-BLACKOUT-01":
        return [
            cargo_test(
                "noos-node",
                "claim_e_blackout_all_optional_controls_off_keeps_base_live",
            )
        ]
    return [
        cargo_test("noos-p2p", "fault::tests"),
        cargo_test("noos-node", "claim_e_wan_drift_sweep_selects_smallest_passing_genesis_value"),
        cargo_test(
            "noos-node",
            "claim_e_wan_partition_eclipse_da_withholding_heal_without_conflicting_finality",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=CLAIMS)
    parser.add_argument("--generated", type=int, default=10_000)
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.generated <= MAX_GENERATED:
        parser.error(f"--generated must be in 1..{MAX_GENERATED}")
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    checks = checks_for(args.claim, args.generated)
    implemented = args.claim == "A-KEYLESS-CONSENSUS"
    result = "IMPLEMENTED" if implemented else "EXTERNAL_BLOCKED"
    limitations = ["Evidence exercises real local NodeCore/P2P paths; it is not external evidence."]
    if args.claim == "E-BASE-01":
        limitations += [
            f"This run exercised {args.generated} of the required {MAX_GENERATED} generated transitions.",
            "The Rust and Go clients are separate codebases/processes but are not independently managed for this run.",
            "The Python small-state oracle is local and cannot self-certify independent authorship or review.",
        ]
    elif args.claim == "E-BLACKOUT-01":
        limitations += [
            "The real base node ran with every optional genesis control disabled, but the 30 simulated days and seven public-testnet days were not elapsed here.",
            "No separately operated maximum-load NEL service fleet was available to kill mid-window.",
        ]
    elif args.claim == "E-WAN-01":
        limitations += [
            "Fault scheduling is deterministic and local; it is not four external regions or independent carriers.",
            "The required six-hour real partition and public elapsed-duration evidence remain external.",
        ]

    sources = [
        "crates/noos-braid/src/keyless.rs",
        "crates/noos-braid/src/lib.rs",
        "crates/noos-node/src/consensus.rs",
        "crates/noos-node/src/network.rs",
        "crates/noos-node/src/tests/claims.rs",
        "crates/noos-p2p/src/fault.rs",
        "crates/noos-p2p/src/lib.rs",
        "tools/gates/run_base_network_claim.py",
    ]
    if args.claim == "E-BASE-01":
        sources += [
            "tools/gates/differential_transitions.py",
            "crates/noos-node/src/tests/e2e.rs",
            "crates/noos-node/src/tests/import_matrix.rs",
            "crates/noos-node/src/tests/sync_tests.rs",
        ]
    emit(
        gate="implementation-" + args.claim.lower(),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=[{"name": "deterministic behavior/falsifier precursor", "passed": True, "detail": item} for item in checks],
        sources=sources,
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
