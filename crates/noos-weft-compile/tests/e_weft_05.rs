//! E-WEFT-05 — Beacon-order noninterference (ch04 §3.7).
//!
//! Claim under test: no well-typed term lets beacon output influence bytes
//! whose commitment indexes that beacon; the grind corpus is 100%
//! ill-typed; required commit-then-beacon patterns stay expressible.
//! Kill: one well-typed grind path.
//!
//! The 10^6-elaboration taint-analysis sweep is a separate analyzer that
//! does not exist locally; this module proves the type-level gate, which is
//! the mechanism the taint sweep would audit.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use noos_weft_compile::compile;

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
