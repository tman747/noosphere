#!/usr/bin/env python3
"""Run local M-CLOCK / identity / Reflex claim precursors and emit evidence.

Only M-CLOCK has a complete local threshold: its fork tuple is differentially
executed by the Rust and Go clients over one shared 100,000-case generated
corpus, while the Rust state machine exercises cap, epoch, replay, blackout,
and rollback rules. Identity claims retain their production-shape/cycle/testnet
gaps; A-REFLEX retains its live-devnet drill; withdrawn E-REFLEX-01 stays void.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess

from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check, require_disabled_controls

CLAIMS = (
    "M-CLOCK",
    "I-PENTAGON",
    "E-IDENT-01",
    "E-IDENT-02",
    "E-IDENT-03",
    "A-REFLEX",
    "E-REFLEX-01",
)

COMMON_SOURCES = (
    "crates/noos-reflex/Cargo.toml",
    "crates/noos-reflex/src/lib.rs",
    "crates/noos-reflex/src/clock.rs",
    "crates/noos-reflex/src/identity.rs",
    "tools/gates/run_identity_reflex_claim.py",
)

CLAIM_SOURCES = {
    "M-CLOCK": (
        "crates/noos-reflex/src/bin/m-clock-diff.rs",
        "crates/noos-braid/src/fork.rs",
        "go/braidref/forkchoice.go",
        "go/cmd/mclockdiff/main.go",
    ),
    "I-PENTAGON": (
        "crates/noos-training/src/lib.rs",
        "crates/noos-nel/src/inference.rs",
        "crates/noos-umbra/src/branch.rs",
        "crates/noos-work-loom/src/lib.rs",
    ),
    "E-IDENT-01": (
        "crates/noos-training/src/lib.rs",
        "crates/noos-nel/src/inference.rs",
        "crates/noos-umbra/src/branch.rs",
        "crates/noos-work-loom/src/lib.rs",
    ),
    "E-IDENT-02": (
        "crates/noos-training/src/lib.rs",
        "crates/noos-nel/src/inference.rs",
    ),
    "E-IDENT-03": ("crates/noos-training/src/lib.rs",),
    "A-REFLEX": ("crates/noos-agent-class/src/lib.rs",),
    "E-REFLEX-01": (),
}

LIMITATIONS = {
    "I-PENTAGON": [
        "The exact local precursor emits five products from one real 32^3 C32 witness, but the claim threshold requires a production-shaped 0.5B-class T=32 witness and measured chapter-09 marginal-cost vector.",
        "Production Loom, paid demand, Chorus, and dream lanes remain shadow-only or disabled; no composition receipt has consensus credit.",
    ],
    "E-IDENT-01": [
        "The 100,000-ordering double-credit gate, five-path delivery, witness mutation, adjoint substitution, branch capability, and single-product disablement run locally at 32^3, not on the required production-shaped 0.5B cycle harness.",
        "No production cycles/bytes/wall-clock vector exists against the chapter-09 section-2 rates.",
    ],
    "E-IDENT-02": [
        "The exact 32^3 and rectangular integer GEMM triples pass a 3.0x MAC census, 15/15 mutation rejection, domain substitution rejection, and exact phase sums, but no RV32IM cycle-model run was performed.",
        "The operation census is local precursor evidence, not a substitute for the required cycle measurements.",
    ],
    "E-IDENT-03": [
        "The deterministic eight-epoch closure state machine exercises both four-lane cycles, 1.25x/2x thresholds, rollback labels, fork detection, and base-chain universal kill, but no shadow-lane testnet epochs elapsed.",
    ],
    "A-REFLEX": [
        "The complete local lifecycle exercises signed bonded ticks, exact roots/gas, handoff pause, canonical inclusion/omission/contradiction, class-gate binding, monotone budgets, split-view liability, integer compensation, and canonical-only rollback.",
        "The required live-devnet cadence, handoff-gap p95, partitioned delivery trials, and real bond payouts have not run; production enablement remains impossible from local evidence.",
    ],
    "E-REFLEX-01": [
        "Frozen E-REFLEX-01 is withdrawn in full and has zero evidentiary weight. This gate verifies that the withdrawn instrument cannot enable Reflex; it does not revive or supersede it.",
    ],
}


def _tuple(finalized: int, justified: int, work: bytes, block_hash: bytes) -> bytes:
    return struct.pack("<QQ", finalized, justified) + work + block_hash


def generated_clock_corpus(count: int = 100_000) -> bytes:
    """One deterministic corpus shared byte-for-byte by both real clients."""
    mask = (1 << 64) - 1
    state = 0x5EEDC10C20260710

    def next_u64() -> int:
        nonlocal state
        state ^= (state << 13) & mask
        state ^= state >> 7
        state ^= (state << 17) & mask
        state &= mask
        return state

    def random_tuple() -> bytes:
        work = b"".join(struct.pack("<Q", next_u64()) for _ in range(4))
        block_hash = b"".join(struct.pack("<Q", next_u64()) for _ in range(4))
        return _tuple(next_u64() % 16, next_u64() % 24, work, block_hash)

    corpus = bytearray()
    for _ in range(count):
        corpus.extend(random_tuple())
        corpus.extend(random_tuple())
    return bytes(corpus)


def run_clock_differential() -> dict[str, object]:
    corpus = generated_clock_corpus()
    rust_command = [
        "cargo",
        "run",
        "--quiet",
        "--locked",
        "-p",
        "noos-reflex",
        "--bin",
        "m-clock-diff",
    ]
    go_command = ["go", "run", "./cmd/mclockdiff"]
    rust = subprocess.run(
        rust_command,
        cwd=ROOT,
        input=corpus,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if rust.returncode:
        raise SystemExit(
            f"Rust M-CLOCK differential client failed: {rust.stderr.decode(errors='replace')}"
        )
    go = subprocess.run(
        go_command,
        cwd=ROOT / "go",
        input=corpus,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if go.returncode:
        raise SystemExit(
            f"Go M-CLOCK differential client failed: {go.stderr.decode(errors='replace')}"
        )
    if len(rust.stdout) != 100_000 or rust.stdout != go.stdout:
        raise SystemExit(
            "M-CLOCK client divergence: "
            f"rust_cases={len(rust.stdout)} go_cases={len(go.stdout)} "
            f"rust_sha256={hashlib.sha256(rust.stdout).hexdigest()} "
            f"go_sha256={hashlib.sha256(go.stdout).hexdigest()}"
        )
    return {
        "passed": True,
        "cases": 100_000,
        "corpus_sha256": hashlib.sha256(corpus).hexdigest(),
        "winner_sha256": hashlib.sha256(rust.stdout).hexdigest(),
        "rust_command": rust_command,
        "go_command": go_command,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=CLAIMS)
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()

    local = cargo_test(("noos-reflex",))
    observations: list[object] = [local]
    if args.claim == "M-CLOCK":
        differential = run_clock_differential()
        observations.append(differential)

    if args.rollback_check:
        continuity = base_continuity()
        if not continuity["ordinary_base_live"] or not continuity["rollback_verified"]:
            raise SystemExit("ordinary-base rollback continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    if args.claim == "M-CLOCK":
        result = "IMPLEMENTED"
        limitations = [
            "This is complete local two-client implementation evidence, not independent-vendor, public-duration, or production promotion evidence."
        ]
    elif args.claim == "E-REFLEX-01":
        result = "DISABLED"
        limitations = LIMITATIONS[args.claim]
    else:
        result = "EXTERNAL_BLOCKED"
        limitations = LIMITATIONS[args.claim]
    if result == "IMPLEMENTED":
        checks = [
            evidence_check("claim-implementation", "implementation", True, observations),
            evidence_check("claim-falsifiers", "falsifier", True, observations),
        ]
    elif result == "DISABLED":
        checks = [
            require_disabled_controls(["reflex_lane_enabled"]),
            evidence_check("withdrawn-v1-falsifier", "falsifier", True, observations),
        ]
    else:
        checks = [
            evidence_check("local-precursor", "falsifier", True, observations),
            evidence_check("external-pass-threshold", "external_requirement", False, limitations),
        ]
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result=result,
        expected=result,
        checks=checks,
        sources=COMMON_SOURCES + CLAIM_SOURCES[args.claim],
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
