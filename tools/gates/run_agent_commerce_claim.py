#!/usr/bin/env python3
"""Run the assigned agent/commerce claim cluster and emit immutable local evidence."""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from experimental_gate import ROOT, base_continuity, cargo_test, emit

CLAIM_BINDINGS = {
    "S-AGENT": (
        ("noos-agent-class", "noos-contracts"),
        (
            "crates/noos-agent-class/src/lib.rs",
            "crates/noos-contracts/src/router.rs",
        ),
    ),
    "S-FREYSA": (
        ("noos-agent-class",),
        ("crates/noos-agent-class/src/lib.rs",),
    ),
    "S-COMMERCE": (
        ("noos-commerce",),
        ("crates/noos-commerce/src/lib.rs",),
    ),
    "S-ATTRIBUTION": (
        ("noos-commerce",),
        ("crates/noos-commerce/src/lib.rs",),
    ),
    "S-ACCESS": (
        ("noos-loam",),
        ("crates/noos-loam/src/access.rs",),
    ),
    "S-TWIN-PROFILE": (
        ("noos-loam",),
        ("crates/noos-loam/src/twin_profile.rs",),
    ),
    "I-AGENT": (
        ("noos-agent-class", "noos-commerce", "noos-contracts"),
        (
            "crates/noos-agent-class/src/lib.rs",
            "crates/noos-commerce/src/lib.rs",
            "crates/noos-contracts/src/router.rs",
            "crates/noos-contracts/src/agent_object.rs",
        ),
    ),
}

LIMITATIONS = {
    "S-ATTRIBUTION": [
        "Attribution thresholds are measured on deterministic synthetic ground truth; the score is advisory and has zero consensus weight.",
    ],
    "S-ACCESS": [
        "The three paths are declared local fixture domains, not evidence from three independent production providers.",
    ],
    "I-AGENT": [
        "The composed drill and its lineage/quarantine dependencies are lab fixtures, not a production phone mesh or settlement deployment.",
    ],
}

LOCAL_IMPLEMENTED = {claim for claim in CLAIM_BINDINGS if claim != "S-ACCESS"}

FIXTURES = (
    (
        Path("C:/tmp/chorus-quorum-lab"),
        "chorus_adapter.py",
        (
            "METRIC mechanism_false_accept=0",
            "METRIC clone_collapsed_weight=1",
            "METRIC engine_invariant_gate=1",
        ),
    ),
    (
        Path("C:/tmp/nel-quarantine-lab"),
        "nel_adapter.py",
        (
            "METRIC double_payouts=0",
            "METRIC gate_failures=0",
            "GATE cinder_execution_right_reuse_refused expected=True measured=True verdict=PASS",
            "GATE dryad_dispute_proof_reuse_refused expected=True measured=True verdict=PASS",
        ),
    ),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_fixture(directory: Path, script: str, required: tuple[str, ...]) -> dict[str, object]:
    path = directory / script
    if not path.is_file():
        raise SystemExit(f"canonical fixture missing: {path}")
    completed = subprocess.run(
        [sys.executable, script],
        cwd=directory,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode:
        sys.stderr.write(completed.stdout)
        raise SystemExit(f"canonical fixture failed: {path}")
    missing = [marker for marker in required if marker not in completed.stdout]
    if missing:
        sys.stderr.write(completed.stdout)
        raise SystemExit(f"canonical fixture omitted required metrics: {missing}")
    sources = sorted(
        file for file in directory.iterdir() if file.is_file() and file.suffix in {".py", ".md"}
    )
    return {
        "name": f"canonical fixture {directory.name}",
        "passed": True,
        "command": [sys.executable, script],
        "required_metrics": list(required),
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "fixture_sha256": {file.name: sha256(file) for file in sources},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIM_BINDINGS))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    if args.rollback_check:
        continuity = base_continuity()
        if continuity["ordinary_base_live"] is not True or continuity["rollback_verified"] is not True:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    packages, modules = CLAIM_BINDINGS[args.claim]
    test = cargo_test(packages)
    checks: list[dict[str, object]] = [
        {
            "name": "claim-specific deterministic falsifier tests",
            "passed": True,
            "detail": test,
        }
    ]
    if args.claim == "I-AGENT":
        checks.extend(run_fixture(*fixture) for fixture in FIXTURES)
    sources = ["tools/gates/run_agent_commerce_claim.py"]
    sources.extend(f"crates/{package}/Cargo.toml" for package in packages)
    sources.extend(modules)
    result = "IMPLEMENTED" if args.claim in LOCAL_IMPLEMENTED else "EXTERNAL_BLOCKED"
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=checks,
        sources=sources,
        limitations=[
            "This is deterministic local implementation evidence, not independent or production evidence.",
            *LIMITATIONS.get(args.claim, []),
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
