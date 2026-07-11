#!/usr/bin/env python3
"""Run Species/Reaction local contracts and emit immutable claim evidence.

The runner distinguishes complete local transition laws from claims whose
frozen threshold requires an independent implementation, a hidden/public
corpus, preregistered statistical power, or observables that do not yet exist.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys

from experimental_gate import ROOT, base_continuity, emit


CLAIMS = {
    "S-ARTIFACT": {
        "package": "noos-species",
        "filter": "claim_artifact",
        "sources": ("crates/noos-species/src/artifact.rs",),
        "implemented": True,
        "limitations": (
            "The local erasure profile deliberately supports one XOR parity shard and declares a one-shard loss bound; broader Reed-Solomon profiles are not claimed.",
            "No production promoted-artifact corpus or geographic E-WAN-01 run is represented by this local evidence.",
        ),
    },
    "S-SPECIES": {
        "package": "noos-species",
        "filter": "claim_species",
        "sources": ("crates/noos-species/src/lib.rs",),
        "implemented": False,
        "limitations": (
            "The two resolver paths are local dual-path code, not independently implemented resolver families.",
            "The frozen 10^7 generated graph/query campaign has not been run.",
        ),
    },
    "M-QUOTIENT": {
        "package": "noos-species",
        "filter": "claim_quotient",
        "sources": ("crates/noos-species/src/quotient.rs",),
        "implemented": False,
        "limitations": (
            "No rotating public plus post-commit hidden suite or 99% confidence campaign exists locally.",
            "No external semantic ground truth establishes a false-equivalence rate below 1%.",
        ),
    },
    "S-REACTION": {
        "package": "noos-training",
        "filter": "claim_reaction",
        "sources": (
            "crates/noos-training/src/reaction.rs",
            "crates/noos-species/Cargo.toml",
            "crates/noos-species/src/lib.rs",
            "crates/noos-species/src/canonical.rs",
            "crates/noos-species/src/update.rs",
        ),
        "implemented": True,
        "limitations": (
            "This proves the local immutable transition, reproduction, delay, challenge, replay, and pointer rollback laws; it is not production or independent-operator evidence.",
        ),
    },
    "S-UPDATE": {
        "package": "noos-species",
        "filter": "claim_update",
        "sources": ("crates/noos-species/src/update.rs", "crates/noos-species/src/canonical.rs"),
        "implemented": False,
        "limitations": (
            "Only one implementation family exists; canonical encode/decode round trips are not cross-vendor evidence.",
            "No independent replay engine has established profile-tolerance identity.",
        ),
    },
    "S-RL-LAG": {
        "package": "noos-training",
        "filter": "claim_rl_lag",
        "sources": ("crates/noos-training/src/rl_lag.rs",),
        "implemented": False,
        "limitations": (
            "Exact boundaries and 500,500 generated policy pairs are locally exercised, but no preregistered training-stability fault-injection campaign exists.",
        ),
    },
    "S-TOPLOC": {
        "package": "noos-training",
        "filter": "claim_toploc",
        "sources": ("crates/noos-training/src/toploc.rs",),
        "implemented": False,
        "limitations": (
            "The committed-seed named-model/profile fingerprint precursor is local only.",
            "No published attack corpus, 99% confidence detection estimate, false-positive SLA measurement, or adaptive collision campaign exists.",
        ),
    },
    "S-QUALITY": {
        "package": "noos-swarm",
        "filter": "claim_quality",
        "sources": ("crates/noos-swarm/src/quality.rs",),
        "implemented": False,
        "limitations": (
            "Escrow mechanics and within-domain Sybil non-inflation are implemented locally.",
            "The preregistered adversarial rank-capture rate and independent real evaluator/payment campaign required by E-COLLUSION-01 do not exist.",
        ),
    },
    "S-GLOBAL-ORGANISM": {
        "package": "noos-swarm",
        "filter": "claim_global_organism",
        "sources": ("crates/noos-swarm/src/organism.rs",),
        "implemented": False,
        "limitations": (
            "The frozen claim has no production threshold and finite component aggregation explicitly cannot establish it.",
            "Resilience, ownership/control concentration, semantic continuity, rights compliance, and decision-benefit observables have not been preregistered globally.",
        ),
    },
}


def run_filtered_test(package: str, test_filter: str) -> dict[str, object]:
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        package,
        test_filter,
        "--",
        "--test-threads=1",
    ]
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
        raise SystemExit(f"claim test failed ({completed.returncode}); log_sha256={digest}")
    if f"test result: ok." not in completed.stdout or "0 passed" in completed.stdout:
        raise SystemExit("claim filter executed no passing tests")
    return {
        "command": command,
        "exit_code": completed.returncode,
        "package": package,
        "filter": test_filter,
        "log_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIMS))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    binding = CLAIMS[args.claim]
    test = run_filtered_test(str(binding["package"]), str(binding["filter"]))
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print(f"RESULT rollback=PASSED claim={args.claim}")
        return 0
    implemented = bool(binding["implemented"])
    result = "IMPLEMENTED" if implemented else "EXTERNAL_BLOCKED"
    sources = [
        "tools/gates/run_species_reaction_claim.py",
        f"crates/{binding['package']}/Cargo.toml",
        f"crates/{binding['package']}/src/lib.rs",
        *binding["sources"],
    ]
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=[{"name": "claim-specific behavior and falsifier tests", "passed": True, "detail": test}],
        sources=sources,
        limitations=list(binding["limitations"]),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
