"""Deterministic declared-provenance simulation for S01 Genealogical Quorum.

This is a behavioral model, not a cryptographic construction.  Payload
"fingerprints" are opaque declared labels: the simulation makes no authenticity,
collision-resistance, identity, or security claim about them or the signers.

The preserved first run grouped evidence by its immediate parent.  Twelve clone
identities were placed behind twelve relay parents, all descended from one source,
so that bug assigned weight 12 to a single provenance root.  This revision walks
parent/source ancestry transitively and collapses payloads through the transitive
closure of declared variant links.  FCA-style counterexamples may then split a
class whose shared lineage hides a concrete distinguishing feature.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Iterable, Mapping, Sequence


THRESHOLD = 3
CLONE_COUNT = 12
PERMUTATION_RUNS = 96
FALSE_CLAIM = "claim:unsafe_bridge_is_safe"
HONEST_CLAIM = "claim:independent_observation_confirmed"
CONTEXT_CLAIM = "claim:site_is_eligible"


@dataclass(frozen=True)
class Attestation:
    """One declared object in the provenance and feature context."""

    attestation_id: str
    signer: str
    parent_sources: tuple[str, ...]
    payload_fingerprint: str
    payload_variant_of: tuple[str, ...]
    claim: str
    features: frozenset[str]


@dataclass(frozen=True)
class Counterexample:
    """A formal-context observation that forbids one over-broad collapse."""

    counterexample_id: str
    left_attestation_id: str
    right_attestation_id: str
    feature_family: str
    observation: str


@dataclass(frozen=True)
class SimulationState:
    attestations: tuple[Attestation, ...]
    counterexamples: tuple[Counterexample, ...]


@dataclass(frozen=True)
class TerminalResult:
    baseline_false_accept: int
    mechanism_false_accept: int
    clone_count: int
    honest_accept: int
    counterexamples_added: int
    clone_weight: int
    honest_weight_before_addition: int
    honest_weight_after_addition: int
    context_classes_before_counterexample: int
    context_classes_after_counterexample: int


BaseKey = tuple[str, tuple[str, ...], str]
RefinedKey = tuple[BaseKey, tuple[tuple[str, str], ...]]


class PayloadLineage:
    """Order-independent components of declared payload variant links."""

    def __init__(self, attestations: Iterable[Attestation]) -> None:
        parent: dict[str, str] = {}

        def ensure(node: str) -> None:
            parent.setdefault(node, node)

        def find(node: str) -> str:
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        def union(left: str, right: str) -> None:
            left_root = find(left)
            right_root = find(right)
            if left_root == right_root:
                return
            # The lexicographically smaller representative is canonical, so the
            # component label does not depend on declaration or union order.
            small, large = sorted((left_root, right_root))
            parent[large] = small

        edges: set[tuple[str, str]] = set()
        for attestation in attestations:
            ensure(attestation.payload_fingerprint)
            for ancestor in attestation.payload_variant_of:
                ensure(ancestor)
                edges.add(tuple(sorted((attestation.payload_fingerprint, ancestor))))
        for left, right in sorted(edges):
            union(left, right)

        members: dict[str, list[str]] = {}
        for node in sorted(parent):
            members.setdefault(find(node), []).append(node)
        self._component = {
            node: component_members[0]
            for component_members in members.values()
            for node in component_members
        }

    def component(self, payload_fingerprint: str) -> str:
        return self._component[payload_fingerprint]


def registry_for(attestations: Sequence[Attestation]) -> dict[str, Attestation]:
    registry: dict[str, Attestation] = {}
    for attestation in attestations:
        if attestation.attestation_id in registry:
            raise ValueError(f"duplicate attestation id: {attestation.attestation_id}")
        registry[attestation.attestation_id] = attestation
    for attestation in registry.values():
        missing = sorted(set(attestation.parent_sources) - registry.keys())
        if missing:
            raise ValueError(
                f"{attestation.attestation_id} has missing parent/source: {missing}"
            )
    return registry


def provenance_roots(
    attestation_id: str,
    registry: Mapping[str, Attestation],
    memo: dict[str, tuple[str, ...]],
    active: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    """Return every transitive declared source root, rejecting ancestry cycles."""

    if attestation_id in memo:
        return memo[attestation_id]
    if attestation_id in active:
        cycle = sorted((*active, attestation_id))
        raise ValueError(f"provenance cycle involving: {cycle}")
    attestation = registry[attestation_id]
    if not attestation.parent_sources:
        roots = (attestation_id,)
    else:
        next_active = active | {attestation_id}
        roots = tuple(
            sorted(
                {
                    root
                    for parent_id in attestation.parent_sources
                    for root in provenance_roots(
                        parent_id, registry, memo, next_active
                    )
                }
            )
        )
    memo[attestation_id] = roots
    return roots


def feature_value(attestation: Attestation, family: str) -> str:
    prefix = f"{family}="
    values = sorted(
        feature[len(prefix) :]
        for feature in attestation.features
        if feature.startswith(prefix)
    )
    if len(values) != 1:
        raise ValueError(
            f"{attestation.attestation_id} needs exactly one {family!r} feature; "
            f"found {values}"
        )
    return values[0]


def base_key(
    attestation: Attestation,
    registry: Mapping[str, Attestation],
    lineage: PayloadLineage,
    root_memo: dict[str, tuple[str, ...]],
) -> BaseKey:
    return (
        attestation.claim,
        provenance_roots(attestation.attestation_id, registry, root_memo),
        lineage.component(attestation.payload_fingerprint),
    )


def refinement_families(
    counterexamples: Sequence[Counterexample],
    registry: Mapping[str, Attestation],
    lineage: PayloadLineage,
    root_memo: dict[str, tuple[str, ...]],
) -> dict[BaseKey, tuple[str, ...]]:
    """Translate concrete FCA counterexamples into deterministic class splits."""

    families: dict[BaseKey, set[str]] = {}
    seen_ids: set[str] = set()
    for counterexample in sorted(
        counterexamples, key=lambda item: item.counterexample_id
    ):
        if counterexample.counterexample_id in seen_ids:
            raise ValueError(
                f"duplicate counterexample id: {counterexample.counterexample_id}"
            )
        seen_ids.add(counterexample.counterexample_id)
        left = registry[counterexample.left_attestation_id]
        right = registry[counterexample.right_attestation_id]
        left_key = base_key(left, registry, lineage, root_memo)
        right_key = base_key(right, registry, lineage, root_memo)
        if left_key != right_key:
            raise ValueError(
                f"counterexample {counterexample.counterexample_id} does not split "
                "one collapsed provenance/payload class"
            )
        left_value = feature_value(left, counterexample.feature_family)
        right_value = feature_value(right, counterexample.feature_family)
        if left_value == right_value:
            raise ValueError(
                f"counterexample {counterexample.counterexample_id} has no "
                f"distinguishing {counterexample.feature_family!r} value"
            )
        families.setdefault(left_key, set()).add(counterexample.feature_family)
    return {key: tuple(sorted(value)) for key, value in families.items()}


def quotient_groups(
    registry: Mapping[str, Attestation],
    lineage: PayloadLineage,
    selected_ids: Sequence[str],
    claim: str,
    counterexamples: Sequence[Counterexample],
) -> dict[RefinedKey, frozenset[str]]:
    """Map evidence to provenance/payload units and their eligible signers."""

    root_memo: dict[str, tuple[str, ...]] = {}
    families = refinement_families(
        counterexamples, registry, lineage, root_memo
    )
    mutable_groups: dict[RefinedKey, set[str]] = {}
    for attestation_id in selected_ids:
        attestation = registry[attestation_id]
        if attestation.claim != claim:
            continue
        unrefined = base_key(attestation, registry, lineage, root_memo)
        feature_signature = tuple(
            (family, feature_value(attestation, family))
            for family in families.get(unrefined, ())
        )
        mutable_groups.setdefault((unrefined, feature_signature), set()).add(
            attestation.signer
        )
    return {
        key: frozenset(signers)
        for key, signers in mutable_groups.items()
    }


def maximum_distinct_signer_weight(
    groups: Mapping[RefinedKey, frozenset[str]],
) -> int:
    """Count quotient units while retaining baseline's distinct-signer rule."""

    signer_to_group: dict[str, RefinedKey] = {}

    def assign(group: RefinedKey, visited: set[str]) -> bool:
        for signer in sorted(groups[group]):
            if signer in visited:
                continue
            visited.add(signer)
            previous_group = signer_to_group.get(signer)
            if previous_group is None or assign(previous_group, visited):
                signer_to_group[signer] = group
                return True
        return False

    weight = 0
    for group in sorted(groups):
        if assign(group, set()):
            weight += 1
    return weight


def baseline_weight(
    registry: Mapping[str, Attestation], selected_ids: Sequence[str], claim: str
) -> int:
    """Ordinary k-of-n baseline: only distinct declared signer identities count."""

    return len(
        {
            registry[attestation_id].signer
            for attestation_id in selected_ids
            if registry[attestation_id].claim == claim
        }
    )


def mechanism_weight(
    state: SimulationState,
    selected_ids: Sequence[str],
    claim: str,
    use_counterexamples: bool = True,
) -> int:
    registry = registry_for(state.attestations)
    lineage = PayloadLineage(state.attestations)
    groups = quotient_groups(
        registry,
        lineage,
        selected_ids,
        claim,
        state.counterexamples if use_counterexamples else (),
    )
    return maximum_distinct_signer_weight(groups)


def build_state() -> tuple[
    SimulationState, tuple[str, ...], tuple[str, ...], tuple[str, ...]
]:
    attestations: list[Attestation] = []

    adversary_root = Attestation(
        "adversary-root",
        "controller",
        (),
        "payload:adversary-root",
        (),
        FALSE_CLAIM,
        frozenset({"role=source", "domain=bridge"}),
    )
    attestations.append(adversary_root)
    clone_ids: list[str] = []
    for index in range(CLONE_COUNT):
        relay = Attestation(
            f"adversary-relay-{index:02d}",
            f"relay-identity-{index:02d}",
            (adversary_root.attestation_id,),
            f"payload:adversary-relay-{index:02d}",
            (adversary_root.payload_fingerprint,),
            FALSE_CLAIM,
            frozenset({"role=relay", "domain=bridge"}),
        )
        clone = Attestation(
            f"clone-evidence-{index:02d}",
            f"clone-signer-{index:02d}",
            (relay.attestation_id,),
            f"payload:clone-report-{index:02d}",
            (relay.payload_fingerprint,),
            FALSE_CLAIM,
            frozenset({"role=evidence", "domain=bridge"}),
        )
        attestations.extend((relay, clone))
        clone_ids.append(clone.attestation_id)

    honest_ids: list[str] = []
    for index in range(3):
        source = Attestation(
            f"honest-source-{index}",
            f"source-custodian-{index}",
            (),
            f"payload:honest-source-{index}",
            ("payload:shared-calibration-lineage",),
            HONEST_CLAIM,
            frozenset({"role=source", "instrument=calibrated"}),
        )
        evidence = Attestation(
            f"honest-evidence-{index}",
            f"honest-signer-{index}",
            (source.attestation_id,),
            f"payload:honest-report-{index}",
            (source.payload_fingerprint,),
            HONEST_CLAIM,
            frozenset({"role=evidence", "instrument=calibrated"}),
        )
        attestations.extend((source, evidence))
        honest_ids.append(evidence.attestation_id)

    context_root = Attestation(
        "context-policy-root",
        "policy-publisher",
        (),
        "payload:policy-common",
        (),
        CONTEXT_CLAIM,
        frozenset({"role=source", "jurisdiction=global"}),
    )
    context_north = Attestation(
        "context-north",
        "north-inspector",
        (context_root.attestation_id,),
        "payload:policy-north",
        (context_root.payload_fingerprint,),
        CONTEXT_CLAIM,
        frozenset({"role=evidence", "jurisdiction=north", "medium=water"}),
    )
    context_south = Attestation(
        "context-south",
        "south-inspector",
        (context_root.attestation_id,),
        "payload:policy-south",
        (context_root.payload_fingerprint,),
        CONTEXT_CLAIM,
        frozenset({"role=evidence", "jurisdiction=south", "medium=desert"}),
    )
    attestations.extend((context_root, context_north, context_south))

    counterexample = Counterexample(
        "counterexample:jurisdiction-applicability",
        context_north.attestation_id,
        context_south.attestation_id,
        "jurisdiction",
        "North water rules and South desert rules have different applicability.",
    )
    state = SimulationState(tuple(attestations), (counterexample,))
    return (
        state,
        tuple(clone_ids),
        tuple(honest_ids),
        (context_north.attestation_id, context_south.attestation_id),
    )


def evaluate(
    state: SimulationState,
    clone_ids: Sequence[str],
    honest_ids: Sequence[str],
    context_ids: Sequence[str],
) -> TerminalResult:
    registry = registry_for(state.attestations)
    baseline_clone_weight = baseline_weight(registry, clone_ids, FALSE_CLAIM)
    candidate_clone_weight = mechanism_weight(state, clone_ids, FALSE_CLAIM)
    honest_before = mechanism_weight(state, honest_ids[:2], HONEST_CLAIM)
    honest_after = mechanism_weight(state, honest_ids, HONEST_CLAIM)
    context_before = mechanism_weight(
        state, context_ids, CONTEXT_CLAIM, use_counterexamples=False
    )
    context_after = mechanism_weight(
        state, context_ids, CONTEXT_CLAIM, use_counterexamples=True
    )
    return TerminalResult(
        baseline_false_accept=int(baseline_clone_weight >= THRESHOLD),
        mechanism_false_accept=int(candidate_clone_weight >= THRESHOLD),
        clone_count=len(clone_ids),
        honest_accept=int(honest_after >= THRESHOLD),
        counterexamples_added=len(state.counterexamples),
        clone_weight=candidate_clone_weight,
        honest_weight_before_addition=honest_before,
        honest_weight_after_addition=honest_after,
        context_classes_before_counterexample=context_before,
        context_classes_after_counterexample=context_after,
    )


def permuted_copy(items: Sequence[object], rng: random.Random) -> tuple[object, ...]:
    copied = list(items)
    rng.shuffle(copied)
    return tuple(copied)


def main() -> None:
    state, clone_ids, honest_ids, context_ids = build_state()
    expected = evaluate(state, clone_ids, honest_ids, context_ids)

    # Each assertion names an observable protocol-model invariant.  Flipping the
    # ancestry walk to immediate parents, removing payload transitivity, counting
    # signer aliases, ignoring the new honest root, or dropping the FCA split
    # makes the corresponding assertion fail.
    assert expected.baseline_false_accept == 1, (
        "baseline must be fooled by 12 distinct signer aliases"
    )
    assert expected.mechanism_false_accept == 0, (
        "lineage quotient must reject one-root clone fan-out"
    )
    assert expected.clone_weight == 1, (
        "all clone variants share one transitive root and payload lineage"
    )
    assert expected.honest_weight_before_addition == THRESHOLD - 1, (
        "two independent roots must remain below quorum"
    )
    assert expected.honest_weight_after_addition == THRESHOLD, (
        "one genuine independent-root addition must add exactly one unit"
    )
    assert expected.honest_accept == 1, (
        "three independent roots with distinct signers must reach quorum"
    )
    assert expected.context_classes_before_counterexample == 1, (
        "shared root/payload lineage must expose the initial over-collapse"
    )
    assert expected.context_classes_after_counterexample == 2, (
        "the jurisdiction counterexample must split the over-collapsed class"
    )
    assert expected.counterexamples_added == 1

    # Shuffle declarations and every evidence selection independently.  The fixed
    # seed is reproducible; equality includes all acceptance and class-count state.
    rng = random.Random(0x501A6E)
    for run_index in range(PERMUTATION_RUNS):
        shuffled_state = SimulationState(
            permuted_copy(state.attestations, rng),
            permuted_copy(state.counterexamples, rng),
        )
        actual = evaluate(
            shuffled_state,
            permuted_copy(clone_ids, rng),
            permuted_copy(honest_ids, rng),
            permuted_copy(context_ids, rng),
        )
        assert actual == expected, (
            f"input-order determinism failed on permutation {run_index}: "
            f"{actual!r} != {expected!r}"
        )

    print(
        "CHECK clone aliases: baseline_weight=12 candidate_weight=1 "
        "transitive_root=adversary-root"
    )
    print(
        "CHECK honest addition: independent_root_weight=2->3 threshold=3"
    )
    print(
        "CHECK FCA counterexample: jurisdiction split changed class_count=1->2"
    )
    print(f"METRIC baseline_false_accept={expected.baseline_false_accept}")
    print(f"METRIC mechanism_false_accept={expected.mechanism_false_accept}")
    print(f"METRIC clone_count={expected.clone_count}")
    print(f"METRIC honest_accept={expected.honest_accept}")
    print(f"METRIC counterexamples_added={expected.counterexamples_added}")
    print(f"METRIC permutation_runs={PERMUTATION_RUNS}")
    print("METRIC invariant_gate=1")


if __name__ == "__main__":
    main()
