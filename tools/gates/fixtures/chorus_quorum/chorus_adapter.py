"""S01 Genealogical Quorum wired into Chorus phone testimony (NOOSPHERE ch03 section 6).

This adapter renames and wraps the survivor fixture `lineage_quorum_engine.py`
into Chorus vocabulary; every acceptance decision is made by the engine, never
re-implemented here.  Mapping:

    engine term                  Chorus term (noosphere/03-living-model.md section 6)
    ---------------------------  ----------------------------------------------------
    signer                       phone testifier (device identity on a ChorusTestimony)
    payload lineage / prov root  testimony evidence root (transitive root of the
                                 evidence a testimony commits to)
    quorum weight                ChorusTestimony aggregate confidence -- "Aggregate
                                 confidence counts failure domains, not signatures"
                                 (section 6.2)
    FCA counterexample           failure-domain split (a concrete observation that
                                 forbids collapsing two testimonies into one domain)

The statistical scenario is IDENTICAL to the preserved survivor run: 12 clone
testifiers behind relay identities descending from one adversary root, quorum
threshold 3, 96 input-order permutations under seed 0x501A6E.  Nothing here is
a cryptographic or authenticity claim; declared fingerprints stay opaque labels.
"""

from __future__ import annotations

import contextlib
import io
from dataclasses import dataclass
from typing import Sequence

import lineage_quorum_engine as engine


PERMUTATION_SEED = 0x501A6E  # identical to the engine's own determinism loop


@dataclass(frozen=True)
class ChorusTestimonyView:
    """One engine attestation read as a phone-court ChorusTestimony."""

    testimony_id: str
    testifier: str            # engine: signer
    evidence_root_hint: str   # engine: payload_fingerprint (lineage collapses it)
    claim: str

    @staticmethod
    def of(attestation: engine.Attestation) -> "ChorusTestimonyView":
        return ChorusTestimonyView(
            testimony_id=attestation.attestation_id,
            testifier=attestation.signer,
            evidence_root_hint=attestation.payload_fingerprint,
            claim=attestation.claim,
        )


def signature_count_confidence(
    state: engine.SimulationState, testimony_ids: Sequence[str], claim: str
) -> int:
    """Baseline mesh: confidence = distinct testifier signatures (the bug Chorus bans)."""

    return engine.baseline_weight(
        engine.registry_for(state.attestations), testimony_ids, claim
    )


def aggregate_confidence(
    state: engine.SimulationState,
    testimony_ids: Sequence[str],
    claim: str,
    use_failure_domain_splits: bool = True,
) -> int:
    """Chorus mesh: confidence = independent failure domains (engine quotient weight)."""

    return engine.mechanism_weight(
        state, testimony_ids, claim, use_counterexamples=use_failure_domain_splits
    )


def run_engine_invariants() -> str:
    """Execute the survivor engine's own invariant assertions, unmodified.

    Any violated invariant raises AssertionError here and the adapter exits
    non-zero.  Output is captured so adapter METRIC lines stay unambiguous.
    """

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        engine.main()
    text = captured.getvalue()
    if "METRIC invariant_gate=1" not in text:
        raise AssertionError("engine invariant gate did not report success")
    return text


def main() -> None:
    # 1. The engine's own invariant suite (9 assertions + its 96-permutation
    #    determinism loop) must pass before any Chorus reading is printed.
    run_engine_invariants()

    # 2. Rebuild the identical fixture and measure every reported value live.
    state, clone_ids, honest_ids, context_ids = engine.build_state()
    registry = engine.registry_for(state.attestations)
    testimonies = {
        tid: ChorusTestimonyView.of(registry[tid])
        for tid in (*clone_ids, *honest_ids, *context_ids)
    }

    clone_testifiers = {testimonies[tid].testifier for tid in clone_ids}
    if len(clone_testifiers) != len(clone_ids):
        raise AssertionError("clone testifiers must present distinct device identities")

    expected = engine.evaluate(state, clone_ids, honest_ids, context_ids)

    baseline_conf = signature_count_confidence(state, clone_ids, engine.FALSE_CLAIM)
    clone_conf = aggregate_confidence(state, clone_ids, engine.FALSE_CLAIM)
    honest_conf = aggregate_confidence(state, honest_ids, engine.HONEST_CLAIM)
    domains_before_split = aggregate_confidence(
        state, context_ids, engine.CONTEXT_CLAIM, use_failure_domain_splits=False
    )
    domains_after_split = aggregate_confidence(
        state, context_ids, engine.CONTEXT_CLAIM, use_failure_domain_splits=True
    )

    baseline_false_accept = int(baseline_conf >= engine.THRESHOLD)
    mechanism_false_accept = int(clone_conf >= engine.THRESHOLD)
    honest_accept = int(honest_conf >= engine.THRESHOLD)

    # Cross-check the adapter's live reading against the engine's own verdict:
    # the wrapper is not allowed to change any decision.
    assert baseline_false_accept == expected.baseline_false_accept
    assert mechanism_false_accept == expected.mechanism_false_accept
    assert clone_conf == expected.clone_weight
    assert honest_accept == expected.honest_accept

    # 3. Input-order determinism, counted (not assumed): same seed, same 96
    #    permutations as the survivor run; every run must reproduce `expected`.
    import random

    rng = random.Random(PERMUTATION_SEED)
    identical_runs = 0
    for run_index in range(engine.PERMUTATION_RUNS):
        shuffled_state = engine.SimulationState(
            engine.permuted_copy(state.attestations, rng),
            engine.permuted_copy(state.counterexamples, rng),
        )
        actual = engine.evaluate(
            shuffled_state,
            engine.permuted_copy(clone_ids, rng),
            engine.permuted_copy(honest_ids, rng),
            engine.permuted_copy(context_ids, rng),
        )
        assert actual == expected, (
            f"Chorus aggregation must be arrival-order independent; "
            f"permutation {run_index} diverged"
        )
        identical_runs += 1

    print(
        "CHORUS clone farm: 12 phone testifiers with distinct signatures relay one "
        "adversary evidence root; signature counting reaches quorum, failure-domain "
        "counting collapses them to aggregate confidence 1"
    )
    print(
        "CHORUS honest quorum: 3 testimonies on independent evidence roots reach "
        f"aggregate confidence {honest_conf} >= threshold {engine.THRESHOLD}"
    )
    print(
        "CHORUS failure-domain split: jurisdiction counterexample splits an "
        f"over-collapsed domain {domains_before_split}->{domains_after_split}"
    )
    print(f"METRIC baseline_false_accept={baseline_false_accept}")
    print(f"METRIC mechanism_false_accept={mechanism_false_accept}")
    print(f"METRIC clone_count={len(clone_ids)}")
    print(f"METRIC clone_collapsed_weight={clone_conf}")
    print(f"METRIC honest_accept={honest_accept}")
    print(f"METRIC permutation_runs={identical_runs}")
    print(f"METRIC quorum_threshold={engine.THRESHOLD}")
    print(f"METRIC honest_aggregate_confidence={honest_conf}")
    print(f"METRIC failure_domain_splits={len(state.counterexamples)}")
    print(f"METRIC domains_before_split={domains_before_split}")
    print(f"METRIC domains_after_split={domains_after_split}")
    print("METRIC engine_invariant_gate=1")


if __name__ == "__main__":
    main()
