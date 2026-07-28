#!/usr/bin/env python3
"""S02 Molecular Quarantine wired into NEL settlement (nel-quarantine-lab).

The engine is an unmodified copy of the S02 survivor test
(`molecular_quarantine_test.py`, from C:/tmp/international-lab/survivors/).
This adapter re-expresses the fixture in NEL settlement vocabulary
(noosphere/05-neural-lane.md) and runs the engine's own enumeration and
decision logic on it, unchanged.

Vocabulary mapping (engine term -> NEL term, section refs are 05-neural-lane.md):

  JobSpec                 -> PromptJob                 (section 2.3: the escrowed job object)
  ReactantID(BUDGET, s)   -> EscrowNote                (section 9.1: the job's fee_escrow tranche note)
  ReactantID(RIGHT, s)    -> ExecutionRight            (section 1: the committee seat's right to execute)
  ReactantID(PROOF, s)    -> DisputeProof              (section 5: the leaf receipt / dispute proof)
  Evidence.FAVORABLE      -> matching ChunkClaim       (section 2.5: 2-of-3 quorum, replicas byte-equal)
  Evidence.CONTRARY       -> conflicting ChunkClaim    (section 3 rule 5: replica claim mismatch)
  Phase.QUARANTINED       -> DIVERGED dispute freeze   (section 3 rule 5: the job freezes; ONLY that job)
  Phase.PROOF             -> settlement session open   (chunk anchored, window running)
  Phase.CLOSED            -> SETTLED                   (escrow tranches released, section 9.1)
  OPEN_SESSION event      -> settlement session open   (permitted only if all observed ChunkClaims agree)
  SUBMIT event            -> settlement submission     (atomically consumes {EscrowNote, ExecutionRight,
                                                        DisputeProof} -- each a globally unique typed ID)
  monitor rejection       -> settlement monitor reject (event refused; nothing consumed)

Scenario (causally isomorphic to the engine's own fixture -- same event
dependency graph, so the linear-extension count is directly comparable):

  job-atlas    receives one matching and one conflicting ChunkClaim ->
               per-job dispute freeze (DIVERGED). Its session-open and
               settlement submission must both be rejected.
  job-borealis settles cleanly, but a settlement submission is delivered
               while still in the claim phase -- it must be rejected
               WITHOUT consuming the dispute proof, and the legal retry
               after session open must still settle.
  job-cinder   tries to settle reusing borealis's already-consumed
               ExecutionRight (globally unique typed ID -> must be refused).
  job-dryad    tries to settle reusing borealis's already-consumed
               DisputeProof (same rule).

Baseline (rejected design): monolithic global settlement -- one conflicting
ChunkClaim anywhere fail-stops the whole batch; nothing settles.

Every METRIC value below is measured by running the engine logic; expected
gate values are compared and any mismatch is reported as GATE ... verdict=FAIL
with a nonzero exit -- never faked.
"""

from __future__ import annotations

import sys
from collections import Counter

from molecular_quarantine_test import (
    Event,
    EventKind,
    Evidence,
    JobSpec,
    Phase,
    ReactantID,
    ResourceKind,
    baseline_settlement_count,
    build_fixture,
    duplicate_consumptions,
    exercise_invalid_order_permutations,
    explore_valid_interleavings,
)

# ---------------------------------------------------------------------------
# NEL constructors: globally unique typed reactant IDs.
# str(ReactantID) renders as "<kind>:<serial>"; the serial carries the NEL
# object name so ledger keys read as e.g. "right:execution-right/job-borealis".
# ---------------------------------------------------------------------------


def escrow_note(job: str) -> ReactantID:
    return ReactantID(ResourceKind.BUDGET, f"escrow-note/{job}")


def execution_right(job: str) -> ReactantID:
    return ReactantID(ResourceKind.RIGHT, f"execution-right/{job}")


def dispute_proof(job: str) -> ReactantID:
    return ReactantID(ResourceKind.PROOF, f"dispute-proof/{job}")


def prompt_job(job_id: str, note: ReactantID, right: ReactantID, proof: ReactantID) -> JobSpec:
    """A PromptJob is the engine's JobSpec: settlement consumes exactly its
    {EscrowNote, ExecutionRight, DisputeProof} triple, atomically."""
    return JobSpec(job_id, note, right, proof)


def build_nel_fixture() -> tuple[list[JobSpec], list[Event]]:
    """The engine fixture, re-expressed as NEL PromptJobs and ChunkClaim events.

    The `after` dependency graph is kept isomorphic to the engine's own
    build_fixture() so the causal-interleaving enumeration is identical and
    the counts can be cross-checked.
    """
    atlas = prompt_job(
        "job-atlas",
        escrow_note("job-atlas"),
        execution_right("job-atlas"),
        dispute_proof("job-atlas"),
    )
    borealis = prompt_job(
        "job-borealis",
        escrow_note("job-borealis"),
        execution_right("job-borealis"),
        dispute_proof("job-borealis"),
    )
    # cinder attempts to reuse borealis's consumed ExecutionRight.
    cinder = prompt_job(
        "job-cinder",
        escrow_note("job-cinder"),
        borealis.right,
        dispute_proof("job-cinder"),
    )
    # dryad independently attempts to reuse borealis's consumed DisputeProof.
    dryad = prompt_job(
        "job-dryad",
        escrow_note("job-dryad"),
        execution_right("job-dryad"),
        borealis.proof,
    )
    specs = [atlas, borealis, cinder, dryad]

    events = [
        # job-atlas: replica quorum agrees on one chunk...
        Event(
            "atlas-chunkclaim-quorum",
            "job-atlas",
            EventKind.EVIDENCE,
            evidence=Evidence.FAVORABLE,
        ),
        # ...then a replica publishes a conflicting ChunkClaim -> DIVERGED freeze.
        Event(
            "atlas-chunkclaim-conflict",
            "job-atlas",
            EventKind.EVIDENCE,
            evidence=Evidence.CONTRARY,
        ),
        Event(
            "atlas-open-settlement",
            "job-atlas",
            EventKind.OPEN_SESSION,
            after=frozenset({"atlas-chunkclaim-quorum", "atlas-chunkclaim-conflict"}),
        ),
        Event(
            "atlas-settle",
            "job-atlas",
            EventKind.SUBMIT,
            reactants=atlas.reactants,
            after=frozenset({"atlas-open-settlement"}),
        ),
        # job-borealis: clean quorum ChunkClaim...
        Event(
            "borealis-chunkclaim-quorum",
            "job-borealis",
            EventKind.EVIDENCE,
            evidence=Evidence.FAVORABLE,
        ),
        # ...a real settlement submission delivered in the claim phase. It must
        # be rejected without consuming the DisputeProof; the legal retry
        # follows the settlement-session open.
        Event(
            "borealis-early-settle",
            "job-borealis",
            EventKind.SUBMIT,
            reactants=borealis.reactants,
        ),
        Event(
            "borealis-open-settlement",
            "job-borealis",
            EventKind.OPEN_SESSION,
            after=frozenset({"borealis-chunkclaim-quorum", "borealis-early-settle"}),
        ),
        Event(
            "borealis-settle",
            "job-borealis",
            EventKind.SUBMIT,
            reactants=borealis.reactants,
            after=frozenset({"borealis-open-settlement"}),
        ),
        # job-cinder: legitimate-looking flow, but its settlement reuses
        # borealis's consumed ExecutionRight.
        Event(
            "cinder-chunkclaim-quorum",
            "job-cinder",
            EventKind.EVIDENCE,
            evidence=Evidence.FAVORABLE,
        ),
        Event(
            "cinder-open-settlement",
            "job-cinder",
            EventKind.OPEN_SESSION,
            after=frozenset({"cinder-chunkclaim-quorum"}),
        ),
        Event(
            "cinder-reuse-execution-right",
            "job-cinder",
            EventKind.SUBMIT,
            reactants=cinder.reactants,
            after=frozenset({"cinder-open-settlement", "borealis-settle"}),
        ),
        # job-dryad: same, reusing borealis's consumed DisputeProof.
        Event(
            "dryad-chunkclaim-quorum",
            "job-dryad",
            EventKind.EVIDENCE,
            evidence=Evidence.FAVORABLE,
        ),
        Event(
            "dryad-open-settlement",
            "job-dryad",
            EventKind.OPEN_SESSION,
            after=frozenset({"dryad-chunkclaim-quorum"}),
        ),
        Event(
            "dryad-reuse-dispute-proof",
            "job-dryad",
            EventKind.SUBMIT,
            reactants=dryad.reactants,
            after=frozenset({"dryad-open-settlement", "borealis-settle"}),
        ),
    ]
    return specs, events


def main() -> int:
    specs, events = build_nel_fixture()

    # Baseline: monolithic settlement -- one conflicting ChunkClaim anywhere
    # fail-stops the entire batch. The engine asserts the fixture exercises it.
    baseline_settled = baseline_settlement_count(events)

    # Mechanism: the engine's exhaustive causal-interleaving enumeration.
    # Every linear extension of the event dependency graph is executed and
    # confluence is asserted at every causal prefix (engine logic, untouched).
    terminal, interleavings_enumerated = explore_valid_interleavings(specs, events)

    # The engine's own local-order permutation exercise (invalid orders must
    # be monitor rejections, never executions).
    invalid_orders_checked = exercise_invalid_order_permutations()

    double_payouts, duplicate_details = duplicate_consumptions(terminal.payouts)
    settled_jobs = tuple(sorted(payout.job_id for payout in terminal.payouts))
    quarantined_jobs = tuple(sorted(terminal.quarantined))
    reasons = Counter(
        reason.split(":", 1)[0] for reason in terminal.monitor_rejections.values()
    )

    # Cross-check: the NEL fixture must be causally isomorphic to the engine's
    # own fixture -- identical linear-extension count proves the dependency
    # graph survived the vocabulary mapping.
    engine_specs, engine_events = build_fixture()
    _, engine_interleavings = explore_valid_interleavings(engine_specs, engine_events)
    causal_structure_preserved = int(interleavings_enumerated == engine_interleavings)

    print(f"METRIC baseline_settled={baseline_settled}")
    print(f"METRIC mechanism_settled={len(terminal.payouts)}")
    print(f"METRIC quarantined_jobs={len(terminal.quarantined)}")
    print(f"METRIC double_payouts={double_payouts}")
    print(f"METRIC monitor_rejections={len(terminal.monitor_rejections)}")
    print(f"METRIC interleavings_enumerated={interleavings_enumerated}")
    print(f"METRIC engine_fixture_interleavings={engine_interleavings}")
    print(f"METRIC causal_structure_preserved={causal_structure_preserved}")
    print(f"METRIC invalid_order_permutations={invalid_orders_checked}")
    print(f"DETAIL settled_jobs={settled_jobs}")
    print(f"DETAIL quarantined_jobs={quarantined_jobs}")
    print(f"DETAIL rejection_classes={dict(sorted(reasons.items()))}")
    if duplicate_details:
        print(f"DETAIL double_payout_evidence={'; '.join(duplicate_details)}")

    # --- Gates (S02 gate set in NEL vocabulary). Measured vs expected; any
    # --- mismatch is reported and fails the run -- never faked.
    gates: list[tuple[str, object, object]] = [
        ("baseline_settled", 0, baseline_settled),
        ("mechanism_settled", 1, len(terminal.payouts)),
        ("quarantined_jobs", 1, len(terminal.quarantined)),
        ("double_payouts", 0, double_payouts),
        ("settled_job_is_borealis", ("job-borealis",), settled_jobs),
        ("quarantined_job_is_atlas", ("job-atlas",), quarantined_jobs),
        ("atlas_frozen_diverged", True, terminal.membranes["job-atlas"].phase is Phase.QUARANTINED),
        (
            "early_settle_rejected_wrong_phase",
            "wrong_phase:evidence",
            terminal.monitor_rejections.get("borealis-early-settle"),
        ),
        (
            "cinder_execution_right_reuse_refused",
            True,
            terminal.monitor_rejections.get("cinder-reuse-execution-right", "").startswith(
                "consumed_resource:"
            ),
        ),
        (
            "dryad_dispute_proof_reuse_refused",
            True,
            terminal.monitor_rejections.get("dryad-reuse-dispute-proof", "").startswith(
                "consumed_resource:"
            ),
        ),
        (
            "rejection_classes",
            {"consumed_resource": 2, "quarantined": 2, "wrong_phase": 1},
            dict(sorted(reasons.items())),
        ),
        (
            "consumed_exactly_borealis_triple",
            True,
            terminal.consumed
            == set(next(s for s in specs if s.job_id == "job-borealis").reactants),
        ),
        ("cinder_still_open_not_settled", True, terminal.membranes["job-cinder"].phase is Phase.PROOF),
        ("dryad_still_open_not_settled", True, terminal.membranes["job-dryad"].phase is Phase.PROOF),
        ("causal_structure_preserved", 1, causal_structure_preserved),
        ("invalid_order_permutations", 5, invalid_orders_checked),
        ("interleavings_enumerated_nonzero", True, interleavings_enumerated > 0),
    ]

    failures = 0
    for name, expected, measured in gates:
        verdict = "PASS" if measured == expected else "FAIL"
        if verdict == "FAIL":
            failures += 1
        print(f"GATE {name} expected={expected!r} measured={measured!r} verdict={verdict}")

    print(f"METRIC gate_failures={failures}")
    print(f"METRIC invariant_gate={int(failures == 0)}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
