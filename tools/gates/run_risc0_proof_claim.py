#!/usr/bin/env python3
"""Run exact local RISC Zero/jet precursor gates for the assigned claim cluster."""
from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import time

from experimental_gate import ROOT, base_continuity, emit


CLAIMS = {
    "P5-S-KERNEL-JET": {
        "tests": [
            "tests::jet_output_equals_interpreted_grain_on_seeded_corpus",
            "tests::rv32_random_corpus_never_answers_wrongly",
        ],
        "limitations": [
            "No CuTe/CUDA kernel, CUDA compiler/device matrix, race campaign, or second independent checker is available on this AMD workstation.",
            "The canonical Grain interpreter remains the rollback path; this evidence does not claim GPU kernel admission.",
        ],
    },
    "A-JET-CERT": {
        "tests": [
            "tests::forged_equivalence_root_is_rejected_even_with_recomputed_digest",
            "tests::divergent_native_cannot_certify_and_cannot_be_admitted",
            "tests::risc0_builder_rejects_uncertified_jet_and_image_substitution",
        ],
        "limitations": [
            "No proof-assistant universal equivalence certificate, emitted-binary translation validation, second independent checker, or 10^8-case campaign is claimed.",
        ],
    },
    "M-RECURSIVE-VERIFIER": {
        "tests": ["risc0_"],
        "risc0": True,
        "limitations": [
            "RISC Zero CPU composite and succinct-recursive receipts are local first-party precursors, not Pearl's independently reproduced Plonky2/STARKy verifier path.",
            "The required second independently implemented verifier and 10^8 structured/mutated-proof identity campaign remain external.",
        ],
    },
    "S-PROOF-ARCH": {
        "tests": ["tests::proof_architecture_profile_binds_every_declared_choice"],
        "limitations": [
            "Profile binding is implemented, but cross-hardware conformance for every vector and profile tolerance has not been run on independent hardware.",
        ],
    },
    "S-GPU-COMMIT": {
        "tests": [
            "tests::cpu_commitment_reference_binds_artifact_challenge_profile_and_fused_relation"
        ],
        "limitations": [
            "Only the canonical CPU/reference commitment relation is exercised; no GPU root, imperfect-tree GPU corpus, transfer-integrated benchmark, or independent pinned H100 latency/energy reproduction exists.",
        ],
    },
}


SOURCES = [
    "Cargo.toml",
    "Cargo.lock",
    "crates/noos-jet/Cargo.toml",
    "crates/noos-jet/src/architecture.rs",
    "crates/noos-jet/src/lib.rs",
    "crates/noos-jet/src/proof.rs",
    "crates/noos-jet/src/risc0.rs",
    "crates/noos-jet/src/rv32.rs",
    "crates/noos-jet/src/tests.rs",
    "crates/noos-jet/src/vectors.rs",
    "crates/noos-jet/src/bin/jet-risc0-vec.rs",
    "crates/noos-jet/risc0-methods/Cargo.toml",
    "crates/noos-jet/risc0-methods/Cargo.lock",
    "crates/noos-jet/risc0-methods/build.rs",
    "crates/noos-jet/risc0-methods/src/lib.rs",
    "crates/noos-jet/risc0-methods/rebuild-guest.ps1",
    "crates/noos-jet/risc0-methods/artifacts/jet_proof.bin",
    "crates/noos-jet/risc0-methods/guest/Cargo.toml",
    "crates/noos-jet/risc0-methods/guest/src/main.rs",
    "crates/noos-jet/risc0-methods/shared/Cargo.toml",
    "crates/noos-jet/risc0-methods/shared/src/lib.rs",
    "protocol/vectors/jet/jet-risc0-proof-v1.json",
    "tools/gates/run_risc0_proof_claim.py",
]


def _run(command: list[str], *, use_wsl: bool) -> dict[str, object]:
    started = time.monotonic()
    env = os.environ.copy()
    env.pop("RISC0_DEV_MODE", None)
    if use_wsl and os.name == "nt":
        translated = subprocess.run(
            ["wsl.exe", "-e", "wslpath", "-a", str(ROOT)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        linux_command = (
            f"cd {shlex.quote(translated)} && "
            "env -u RISC0_DEV_MODE RISC0_PROVER=local "
            "CARGO_TARGET_DIR=$HOME/.cache/noosphere-risc0-target "
            + shlex.join(command)
        )
        actual = ["wsl.exe", "-e", "bash", "-lc", linux_command]
    else:
        actual = command
        if use_wsl:
            env["RISC0_PROVER"] = "local"
    completed = subprocess.run(
        actual,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    duration = round(time.monotonic() - started, 3)
    digest = hashlib.sha256(completed.stdout.encode()).hexdigest()
    if completed.returncode:
        sys.stderr.write(completed.stdout)
        raise SystemExit(
            f"RISC Zero claim test failed ({completed.returncode}); log_sha256={digest}"
        )
    return {
        "command": actual,
        "exit_code": completed.returncode,
        "duration_seconds": duration,
        "log_sha256": digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=sorted(CLAIMS))
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    if args.rollback_check:
        continuity = base_continuity()
        if not continuity["ordinary_base_live"] or not continuity["rollback_verified"]:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    config = CLAIMS[args.claim]
    use_risc0 = bool(config.get("risc0"))
    runs = []
    for test_filter in config["tests"]:
        command = ["cargo", "test", "-p", "noos-jet"]
        if use_risc0 or test_filter.startswith("tests::risc0_"):
            command += ["--features", "risc0"]
        command += ["--locked", test_filter, "--", "--test-threads=1"]
        runs.append(_run(command, use_wsl=use_risc0 or test_filter.startswith("tests::risc0_")))

    emit(
        gate="risc0-proof-" + args.claim.lower(),
        claims=[args.claim],
        result="EXTERNAL_BLOCKED",
        expected="EXTERNAL_BLOCKED",
        checks=[
            {
                "name": "exact local precursor tests",
                "passed": True,
                "detail": runs,
            },
            {
                "name": "frozen pass threshold honesty check",
                "passed": True,
                "detail": "Local precursors passed; external threshold components are explicitly unsatisfied.",
            },
        ],
        sources=SOURCES,
        limitations=list(config["limitations"]),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
