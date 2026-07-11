//! E-WEFT-05 — Beacon-order noninterference (ch04 §3.7).
//!
//! Claim under test: no well-typed term lets beacon output influence bytes
//! whose commitment indexes that beacon; the grind corpus is 100%
//! ill-typed; required commit-then-beacon patterns stay expressible.
//! Kill: one well-typed grind path.
//!
//! This module proves both the source type gate and the deterministic
//! post-elaboration indexed-taint gate. The frozen 10^6 accepted-language-
//! elaboration campaign remains larger than the local 65,536-flow precursor.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use noos_weft_compile::{audit_beacon_flow, compile, BeaconAdapter, BeaconFlowError, BeaconFlowOp};

// ---------------------------------------------------------------------------
// Grind corpus: every laundering attempt is ill-typed
// ---------------------------------------------------------------------------

#[test]
fn grind_corpus_is_fully_ill_typed() {
    let grind = [
        // Direct uncommitted preimage.
        (
            "fn f(x: u64) -> Rand256<h> ! {beacon} { beacon(x) }",
            "E-EFFECT-002",
        ),
        // Wrapper laundering through a let.
        (
            "fn f(x: u64) -> Rand256<h> ! {beacon} { let y = x; beacon(y) }",
            "E-EFFECT-002",
        ),
        // Wrapper laundering through a tuple.
        (
            "fn f(x: u64) -> Rand256<h> ! {beacon} { beacon((x, x)) }",
            "E-EFFECT-002",
        ),
        // Wrapper laundering through a branch join.
        (
            "fn f(c: Bool, x: u64, y: u64) -> Rand256<h> ! {beacon} \
             { beacon(if c { x } else { y }) }",
            "E-EFFECT-002",
        ),
        // Effect-row laundering: the beacon effect must be declared.
        (
            "fn f(t: Committed<u64, h>) -> Rand256<h> ! {} { beacon(t) }",
            "E-EFFECT-001",
        ),
        // Re-committing beacon output under the beacon's own index: the
        // freshly derived commitment can never carry the original index.
        (
            "fn f(r: Rand256<h>) -> Committed<Rand256<h>, h> ! {commit} { commit(r) }",
            "E-TYPE-002",
        ),
    ];
    let mut ill_typed = 0;
    for (source, want) in grind {
        let err = compile(source).unwrap_err();
        assert!(
            err.iter().any(|d| d.code == want),
            "grind path got {:?}, want {want}: {source}",
            err.iter().map(|d| d.code).collect::<Vec<_>>()
        );
        ill_typed += 1;
    }
    assert_eq!(
        ill_typed,
        grind.len(),
        "grind corpus must be 100% ill-typed"
    );
}

// ---------------------------------------------------------------------------
// Required verifier/sampling patterns stay expressible
// ---------------------------------------------------------------------------

#[test]
fn commit_then_beacon_patterns_compile() {
    // Canonical protocol shape: a committed token yields randomness under
    // the same index; the beacon effect is declared.
    let ok = compile(
        "fn draw(t: Committed<u64, h>) -> Rand256<h> ! {beacon} cost 64 dec 0 { beacon(t) }",
    )
    .unwrap();
    assert_eq!(ok.units[0].meaning_contract.effects, vec!["beacon"]);

    // Commit is expressible and its output is index-typed as derived.
    compile("fn seal(x: u64) -> Committed<u64, derived> ! {commit} cost 64 dec 0 { commit(x) }")
        .unwrap();
}

#[test]
fn effect_rows_are_reported_in_the_meaning_contract() {
    // The elaborated contract carries the inferred effect row — downstream
    // ordering enforcement keys off these bytes.
    let ok = compile(
        "fn draw(t: Committed<u64, h>) -> Rand256<h> ! {beacon, commit} cost 64 dec 0 { beacon(t) }",
    )
    .unwrap();
    // Only inferred effects (beacon), not the wider declared row.
    assert_eq!(ok.units[0].meaning_contract.effects, vec!["beacon"]);
}

// ---------------------------------------------------------------------------
// Post-elaboration taint audit: reorder and every named adaptation surface
// ---------------------------------------------------------------------------

#[test]
fn beacon_reorder_and_index_substitution_reject() {
    let reordered = [
        BeaconFlowOp::Source { out: 0 },
        BeaconFlowOp::Beacon {
            index: 7,
            committed: 0,
            out: 1,
        },
    ];
    assert_eq!(
        audit_beacon_flow(&reordered),
        Err(BeaconFlowError::BeaconBeforeCommit { index: 7 })
    );

    let substituted = [
        BeaconFlowOp::Source { out: 0 },
        BeaconFlowOp::Commit {
            index: 8,
            input: 0,
            out: 1,
        },
        BeaconFlowOp::Beacon {
            index: 7,
            committed: 1,
            out: 2,
        },
    ];
    assert_eq!(
        audit_beacon_flow(&substituted),
        Err(BeaconFlowError::BeaconIndexMismatch {
            expected: 7,
            actual: 8,
        })
    );
}

#[test]
fn beacon_adaptation_cannot_launder_through_named_surfaces() {
    for adapter in [
        BeaconAdapter::Jet,
        BeaconAdapter::TrapRecovery,
        BeaconAdapter::Serialization,
        BeaconAdapter::DreamReentry,
    ] {
        let grind = [
            BeaconFlowOp::Source { out: 0 },
            BeaconFlowOp::Commit {
                index: 7,
                input: 0,
                out: 1,
            },
            BeaconFlowOp::Beacon {
                index: 7,
                committed: 1,
                out: 2,
            },
            BeaconFlowOp::Adapt {
                adapter,
                input: 2,
                out: 3,
            },
            BeaconFlowOp::Commit {
                index: 7,
                input: 3,
                out: 4,
            },
        ];
        assert_eq!(
            audit_beacon_flow(&grind),
            Err(BeaconFlowError::BeaconInfluencesCommitment { index: 7 }),
            "{adapter:?} laundered same-index beacon taint"
        );
    }
}

#[test]
fn deterministic_accepted_flow_corpus_has_zero_beacon_to_preimage_paths() {
    // Local precursor to the frozen 10^6-elaboration campaign: 65,536
    // independently indexed accepted traces exercise commit, beacon, and
    // all adaptation surfaces without permitting same-index feedback.
    for index in 0..65_536u32 {
        let adapter = match index % 4 {
            0 => BeaconAdapter::Jet,
            1 => BeaconAdapter::TrapRecovery,
            2 => BeaconAdapter::Serialization,
            _ => BeaconAdapter::DreamReentry,
        };
        let accepted = [
            BeaconFlowOp::Source { out: 0 },
            BeaconFlowOp::Commit {
                index,
                input: 0,
                out: 1,
            },
            BeaconFlowOp::Beacon {
                index,
                committed: 1,
                out: 2,
            },
            BeaconFlowOp::Adapt {
                adapter,
                input: 2,
                out: 3,
            },
            // Cross-index commitments are allowed: their bytes do not
            // index the beacon that influenced them.
            BeaconFlowOp::Commit {
                index: index.wrapping_add(1),
                input: 3,
                out: 4,
            },
        ];
        let report = audit_beacon_flow(&accepted).unwrap();
        assert_eq!(report.beacons, 1);
        assert_eq!(report.commitments, 2);
    }
}
