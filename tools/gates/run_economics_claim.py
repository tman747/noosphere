#!/usr/bin/env python3
"""Run exact local economics contracts without upgrading empirical claims."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

from experimental_gate import ROOT, base_continuity, cargo_test, emit

CLAIMS = {
    "A-LOOM-MARKET",
    "M-OMEGA",
    "M-ISSUANCE",
    "A-DUPLEX-ISSUANCE",
    "S-DEMAND",
    "E-DEMAND-PREDICATE",
    "M-PROOFPOWER",
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
    parser.add_argument("--claim", required=True, choices=sorted(CLAIMS))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()

    if args.rollback_check:
        if args.claim == "A-LOOM-MARKET":
            run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    "noos-work-loom",
                    "tests::unresolved_dispute_timeout_has_no_trapped_escrow",
                    "--",
                    "--exact",
                ]
            )
        continuity = base_continuity()
        if (
            continuity["ordinary_base_live"] is not True
            or continuity["rollback_verified"] is not True
        ):
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    if args.claim == "M-ISSUANCE":
        local = cargo_test(["noos-lumen"])
        path_battery = run(
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
        print(
            "RESULT claim=M-ISSUANCE local_precursor=PASSED "
            "registry_state=PARTIAL external=second_client_and_signed_parameters"
        )
        print(f"CHECKS crate={local} path_battery={path_battery}")
        return 0

    if args.claim == "M-OMEGA":
        local = cargo_test(["noos-analytics", "noos-work-loom"])
    else:
        local = cargo_test(["noos-work-loom"])

    if args.claim != "A-LOOM-MARKET":
        blockers = {
            "M-OMEGA": "cross_hardware_99pct_measurements_and_sustained_demand",
            "A-DUPLEX-ISSUANCE": "stress_security_and_90_public_days",
            "S-DEMAND": "blinded_false_independent_campaign_and_public_window",
            "E-DEMAND-PREDICATE": "public_30_day_aggregate_and_cluster_diversity",
            "M-PROOFPOWER": "preregistered_wash_capture_power_and_adversary_budget",
        }
        print(
            f"RESULT claim={args.claim} local_precursor=PASSED "
            f"registry_state=PARTIAL external={blockers[args.claim]}"
        )
        print(f"CHECKS crate={local}")
        return 0

    registry = json.loads(
        (ROOT / "protocol/claims/registry.json").read_text(encoding="utf-8")
    )
    row = next(row for row in registry["claims"] if row["claim_id"] == args.claim)
    if (
        row.get("local_implementation_state") != "IMPLEMENTED"
        or row.get("expected_result") != "IMPLEMENTED"
    ):
        print(
            "RESULT claim=A-LOOM-MARKET local_precursor=PASSED "
            "registry_state=PROPOSAL_PENDING manifest=EconomicsClaims.json"
        )
        print(f"CHECKS crate={local}")
        return 0

    emit(
        gate="claim-a-loom-market",
        claims=[args.claim],
        result="IMPLEMENTED",
        expected="IMPLEMENTED",
        checks=[
            {
                "name": "seeded terminal-state model, conservation, and mutation falsifiers",
                "passed": True,
                "detail": local,
            },
            {
                "name": "rollback timeout releases requester, worker, and challenger escrow",
                "passed": True,
                "detail": "unresolved dispute timeout and all 4096 seeded traces end terminal with locked=0",
            },
        ],
        sources=[
            "crates/noos-work-loom/Cargo.toml",
            "crates/noos-work-loom/src/lib.rs",
            "crates/noos-work-loom/src/tests.rs",
        ],
        limitations=[
            "Local deterministic implementation evidence only; no external demand or production-credit claim.",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
