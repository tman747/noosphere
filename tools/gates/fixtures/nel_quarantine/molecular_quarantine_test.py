#!/usr/bin/env python3
"""Deterministic Phase-4 simulation for S02 Molecular Quarantine Settlement.

The preserved first run used job-scoped consumption keys, so globally linear
rights and proofs could be paid again under another membrane.  This corrected
revision keys the ledger by globally meaningful typed ReactantID values.
"""

from __future__ import annotations

import copy
import itertools
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class ResourceKind(str, Enum):
    BUDGET = "budget"
    RIGHT = "right"
    PROOF = "proof"


class Evidence(str, Enum):
    FAVORABLE = "favorable"
    CONTRARY = "contrary"


class Phase(str, Enum):
    EVIDENCE = "evidence"
    PROOF = "proof"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


class EventKind(str, Enum):
    EVIDENCE = "evidence"
    OPEN_SESSION = "open_session"
    SUBMIT = "submit"


@dataclass(frozen=True, order=True)
class ReactantID:
    kind: ResourceKind
    serial: str

    def __post_init__(self) -> None:
        if not self.serial:
            raise ValueError("reactant serial must be nonempty")

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.serial}"


@dataclass(frozen=True)
class JobSpec:
    job_id: str
    budget: ReactantID
    right: ReactantID
    proof: ReactantID

    def __post_init__(self) -> None:
        expected = (ResourceKind.BUDGET, ResourceKind.RIGHT, ResourceKind.PROOF)
        actual = (self.budget.kind, self.right.kind, self.proof.kind)
        if actual != expected:
            raise TypeError(f"job {self.job_id} has mistyped reactants: {actual}")

    @property
    def reactants(self) -> tuple[ReactantID, ReactantID, ReactantID]:
        return (self.budget, self.right, self.proof)


@dataclass
class Membrane:
    spec: JobSpec
    phase: Phase = Phase.EVIDENCE
    evidence: set[Evidence] = field(default_factory=set)


@dataclass(frozen=True)
class Payout:
    job_id: str
    reactants: tuple[ReactantID, ReactantID, ReactantID]


@dataclass(frozen=True)
class Event:
    event_id: str
    job_id: str
    kind: EventKind
    evidence: Evidence | None = None
    reactants: tuple[ReactantID, ReactantID, ReactantID] | None = None
    after: frozenset[str] = frozenset()


class MolecularSettlement:
    """Per-job membranes plus an atomic payout/consumption ledger."""

    def __init__(self, specs: Iterable[JobSpec]) -> None:
        self.membranes = {spec.job_id: Membrane(spec) for spec in specs}
        self.consumed: set[ReactantID] = set()
        self.payouts: list[Payout] = []
        self.quarantined: set[str] = set()
        self.monitor_rejections: dict[str, str] = {}

    def _reject(self, event: Event, reason: str) -> None:
        if event.event_id in self.monitor_rejections:
            raise AssertionError(f"event replayed in one trace: {event.event_id}")
        self.monitor_rejections[event.event_id] = reason


    def apply(self, event: Event) -> None:
        membrane = self.membranes[event.job_id]
        if event.kind is EventKind.EVIDENCE:
            self._apply_evidence(membrane, event)
        elif event.kind is EventKind.OPEN_SESSION:
            self._open_session(membrane, event)
        elif event.kind is EventKind.SUBMIT:
            self._settle(membrane, event)
        else:  # pragma: no cover - Enum makes this unreachable.
            raise AssertionError(f"unknown event kind: {event.kind}")

    def _apply_evidence(self, membrane: Membrane, event: Event) -> None:
        if membrane.phase is Phase.QUARANTINED:
            self._reject(event, "quarantined")
            return
        if membrane.phase is not Phase.EVIDENCE:
            self._reject(event, f"wrong_phase:{membrane.phase.value}")
            return
        if event.evidence is None:
            raise AssertionError("evidence event has no evidence")
        membrane.evidence.add(event.evidence)
        if membrane.evidence == {Evidence.FAVORABLE, Evidence.CONTRARY}:
            membrane.phase = Phase.QUARANTINED
            self.quarantined.add(membrane.spec.job_id)

    def _open_session(self, membrane: Membrane, event: Event) -> None:
        if membrane.phase is Phase.QUARANTINED:
            self._reject(event, "quarantined")
            return
        if membrane.phase is not Phase.EVIDENCE:
            self._reject(event, f"wrong_phase:{membrane.phase.value}")
            return
        if membrane.evidence != {Evidence.FAVORABLE}:
            self._reject(event, "evidence_guard")
            return
        membrane.phase = Phase.PROOF

    def _settle(self, membrane: Membrane, event: Event) -> None:
        if membrane.phase is Phase.QUARANTINED:
            self._reject(event, "quarantined")
            return
        if membrane.phase is not Phase.PROOF:
            self._reject(event, f"wrong_phase:{membrane.phase.value}")
            return
        if event.reactants != membrane.spec.reactants:
            self._reject(event, "unbound_reactant")
            return
        assert event.reactants is not None
        already_used = [
            resource for resource in event.reactants if resource in self.consumed
        ]
        if already_used:
            rendered = ",".join(str(resource) for resource in sorted(already_used))
            self._reject(event, f"consumed_resource:{rendered}")
            return
        self.consumed.update(event.reactants)
        self.payouts.append(Payout(event.job_id, event.reactants))
        membrane.phase = Phase.CLOSED

    def projection(self) -> tuple[object, ...]:
        membrane_projection = tuple(
            sorted(
                (
                    job_id,
                    membrane.phase.value,
                    tuple(sorted(item.value for item in membrane.evidence)),
                )
                for job_id, membrane in self.membranes.items()
            )
        )
        payout_projection = tuple(
            sorted((payout.job_id, tuple(map(str, payout.reactants))) for payout in self.payouts)
        )
        rejection_projection = tuple(sorted(self.monitor_rejections.items()))
        consumed_projection = tuple(sorted(str(resource) for resource in self.consumed))
        return (
            membrane_projection,
            payout_projection,
            tuple(sorted(self.quarantined)),
            rejection_projection,
            consumed_projection,
        )


def resource(kind: ResourceKind, serial: str) -> ReactantID:
    return ReactantID(kind, serial)


def build_fixture() -> tuple[list[JobSpec], list[Event]]:
    budget_a = resource(ResourceKind.BUDGET, "budget-a")
    right_a = resource(ResourceKind.RIGHT, "right-a")
    proof_a = resource(ResourceKind.PROOF, "proof-a")
    budget_b = resource(ResourceKind.BUDGET, "budget-b")
    right_b = resource(ResourceKind.RIGHT, "right-b")
    proof_b = resource(ResourceKind.PROOF, "proof-b")

    specs = [
        JobSpec("A", budget_a, right_a, proof_a),
        JobSpec("B", budget_b, right_b, proof_b),
        # C attempts to reuse B's consumed right with otherwise fresh reactants.
        JobSpec(
            "C",
            resource(ResourceKind.BUDGET, "budget-c"),
            right_b,
            resource(ResourceKind.PROOF, "proof-c"),
        ),
        # D independently attempts to reuse B's consumed proof.
        JobSpec(
            "D",
            resource(ResourceKind.BUDGET, "budget-d"),
            resource(ResourceKind.RIGHT, "right-d"),
            proof_b,
        ),
    ]
    by_job = {spec.job_id: spec for spec in specs}
    events = [
        Event("a-favorable", "A", EventKind.EVIDENCE, evidence=Evidence.FAVORABLE),
        Event("a-contrary", "A", EventKind.EVIDENCE, evidence=Evidence.CONTRARY),
        Event(
            "a-open",
            "A",
            EventKind.OPEN_SESSION,
            after=frozenset({"a-favorable", "a-contrary"}),
        ),
        Event(
            "a-submit",
            "A",
            EventKind.SUBMIT,
            reactants=by_job["A"].reactants,
            after=frozenset({"a-open"}),
        ),
        Event("b-favorable", "B", EventKind.EVIDENCE, evidence=Evidence.FAVORABLE),
        # This is a real proof message delivered in the evidence phase. It must be
        # rejected without consuming the proof; the legal retry follows session open.
        Event(
            "b-wrong-phase-proof",
            "B",
            EventKind.SUBMIT,
            reactants=by_job["B"].reactants,
        ),
        Event(
            "b-open",
            "B",
            EventKind.OPEN_SESSION,
            after=frozenset({"b-favorable", "b-wrong-phase-proof"}),
        ),
        Event(
            "b-submit",
            "B",
            EventKind.SUBMIT,
            reactants=by_job["B"].reactants,
            after=frozenset({"b-open"}),
        ),
        Event("c-favorable", "C", EventKind.EVIDENCE, evidence=Evidence.FAVORABLE),
        Event(
            "c-open",
            "C",
            EventKind.OPEN_SESSION,
            after=frozenset({"c-favorable"}),
        ),
        Event(
            "c-reuse-right",
            "C",
            EventKind.SUBMIT,
            reactants=by_job["C"].reactants,
            after=frozenset({"c-open", "b-submit"}),
        ),
        Event("d-favorable", "D", EventKind.EVIDENCE, evidence=Evidence.FAVORABLE),
        Event(
            "d-open",
            "D",
            EventKind.OPEN_SESSION,
            after=frozenset({"d-favorable"}),
        ),
        Event(
            "d-reuse-proof",
            "D",
            EventKind.SUBMIT,
            reactants=by_job["D"].reactants,
            after=frozenset({"d-open", "b-submit"}),
        ),
    ]
    return specs, events


def explore_valid_interleavings(
    specs: list[JobSpec], events: list[Event]
) -> tuple[MolecularSettlement, int]:
    """Exhaust every linear extension and prove confluence at every causal prefix."""

    indices = {event.event_id: index for index, event in enumerate(events)}
    dependency_masks: list[int] = []
    for event in events:
        unknown = event.after.difference(indices)
        if unknown:
            raise AssertionError(f"unknown dependencies for {event.event_id}: {unknown}")
        mask = 0
        for predecessor in event.after:
            mask |= 1 << indices[predecessor]
        dependency_masks.append(mask)

    states: dict[int, MolecularSettlement] = {0: MolecularSettlement(specs)}
    path_counts: dict[int, int] = {0: 1}
    terminal_mask = (1 << len(events)) - 1
    for mask in range(terminal_mask + 1):
        if mask not in states:
            continue
        state = states[mask]
        for index, event in enumerate(events):
            bit = 1 << index
            if mask & bit or dependency_masks[index] & ~mask:
                continue
            next_mask = mask | bit
            next_state = copy.deepcopy(state)
            next_state.apply(event)
            if next_mask in states:
                assert next_state.projection() == states[next_mask].projection(), (
                    f"non-deterministic causal prefix after {event.event_id}"
                )
            else:
                states[next_mask] = next_state
            path_counts[next_mask] = path_counts.get(next_mask, 0) + path_counts[mask]

    assert terminal_mask in states, "causal event graph has no terminal schedule"
    return states[terminal_mask], path_counts[terminal_mask]


def exercise_invalid_order_permutations() -> int:
    """Classify all noncausal local orders as monitor rejections, not executions."""

    spec = JobSpec(
        "X",
        resource(ResourceKind.BUDGET, "budget-x"),
        resource(ResourceKind.RIGHT, "right-x"),
        resource(ResourceKind.PROOF, "proof-x"),
    )
    local_events = {
        "favorable": Event(
            "x-favorable", "X", EventKind.EVIDENCE, evidence=Evidence.FAVORABLE
        ),
        "open": Event("x-open", "X", EventKind.OPEN_SESSION),
        "proof": Event(
            "x-proof", "X", EventKind.SUBMIT, reactants=spec.reactants
        ),
    }
    valid_order = ("favorable", "open", "proof")
    invalid_checked = 0
    for order in itertools.permutations(local_events):
        state = MolecularSettlement([spec])
        for name in order:
            state.apply(local_events[name])
        if order == valid_order:
            assert tuple(payout.job_id for payout in state.payouts) == ("X",)
            assert not state.monitor_rejections
            continue
        invalid_checked += 1
        assert not state.payouts, f"invalid local order paid out: {order}"
        assert state.monitor_rejections, f"invalid local order was not rejected: {order}"
        assert not state.consumed, f"rejected proof consumed reactants: {order}"
    assert invalid_checked == 5
    return invalid_checked


def baseline_settlement_count(events: list[Event]) -> int:
    """Model the rejected baseline: one contradiction explodes the global batch."""

    evidence_by_job: dict[str, set[Evidence]] = {}
    for event in events:
        if event.kind is EventKind.EVIDENCE:
            assert event.evidence is not None
            evidence_by_job.setdefault(event.job_id, set()).add(event.evidence)
    global_fail_stop = any(
        evidence == {Evidence.FAVORABLE, Evidence.CONTRARY}
        for evidence in evidence_by_job.values()
    )
    assert global_fail_stop, "fixture must exercise the monolithic explosion"
    return 0


def duplicate_consumptions(payouts: list[Payout]) -> tuple[int, tuple[str, ...]]:
    first_consumer: dict[ReactantID, str] = {}
    duplicates: list[str] = []
    for payout in payouts:
        for reactant in payout.reactants:
            if reactant in first_consumer:
                duplicates.append(
                    f"{reactant} consumed by {first_consumer[reactant]} and {payout.job_id}"
                )
            else:
                first_consumer[reactant] = payout.job_id
    return len(duplicates), tuple(duplicates)


def rejection_counts(state: MolecularSettlement) -> Counter[str]:
    return Counter(reason.split(":", 1)[0] for reason in state.monitor_rejections.values())


def main() -> None:
    specs, events = build_fixture()
    baseline_settled = baseline_settlement_count(events)
    terminal, interleavings_checked = explore_valid_interleavings(specs, events)
    invalid_orders_checked = exercise_invalid_order_permutations()
    double_payouts, duplicate_details = duplicate_consumptions(terminal.payouts)
    settled_jobs = tuple(sorted(payout.job_id for payout in terminal.payouts))
    reasons = rejection_counts(terminal)

    print(f"METRIC baseline_settled={baseline_settled}")
    print(f"METRIC mechanism_settled={len(terminal.payouts)}")
    print(f"METRIC quarantined_jobs={len(terminal.quarantined)}")
    print(f"METRIC double_payouts={double_payouts}")
    print(f"METRIC monitor_rejections={len(terminal.monitor_rejections)}")
    print(f"METRIC interleavings_checked={interleavings_checked}")
    print(f"DETAIL invalid_order_permutations={invalid_orders_checked}")
    print(f"DETAIL rejection_classes={dict(sorted(reasons.items()))}")

    # The first-run log proves this gate failed before consumption identity was
    # made global. Keep it before the more specific terminal-state assertions.
    assert double_payouts == 0, "linearity invariant failed: " + "; ".join(
        duplicate_details
    )
    assert settled_jobs == ("B",), f"only independent job B may settle: {settled_jobs}"
    assert terminal.quarantined == {"A"}
    assert terminal.membranes["A"].phase is Phase.QUARANTINED
    assert "b-wrong-phase-proof" in terminal.monitor_rejections
    assert terminal.monitor_rejections["b-wrong-phase-proof"] == "wrong_phase:evidence"
    assert "c-reuse-right" in terminal.monitor_rejections
    assert "d-reuse-proof" in terminal.monitor_rejections
    assert reasons == Counter(
        {"quarantined": 2, "wrong_phase": 1, "consumed_resource": 2}
    )
    assert terminal.consumed == set(next(spec for spec in specs if spec.job_id == "B").reactants)
    assert terminal.membranes["C"].phase is Phase.PROOF
    assert terminal.membranes["D"].phase is Phase.PROOF
    assert baseline_settled < len(terminal.payouts)
    print("METRIC invariant_gate=1")


if __name__ == "__main__":
    main()
