//! E-WEFT-07 — Rights-row decidability and ergonomics (ch04 §3.7).
//!
//! Claim under test (lab corpus): rights-row inference over the typed
//! lattice is decidable, deterministic, and exact on a frozen transform
//! corpus — zero under-approximation (a right never appears from nowhere)
//! and zero over-approximation (dropping an annotation drops the row).
//! The annotation-burden study over a production transform corpus is
//! external; the claim stays [DREAM] until it runs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use noos_weft_compile::compile;

// ---------------------------------------------------------------------------
// Decidable, exact inference on the frozen mini-corpus
// ---------------------------------------------------------------------------

#[test]
fn rights_rows_are_inferred_exactly_and_deterministically() {
    let ok =
        compile("fn hold(x: u64 & rights {Own, Use}) -> u64 ! {} cost 16 dec 0 { 1 }").unwrap();
    assert_eq!(ok.units[0].meaning_contract.rights, vec!["Own", "Use"]);

    // Rows union across parameters and returns; ordering is canonical.
    let multi = compile(
        "fn route(a: u64 & rights {Use}, b: u64 & rights {Disclose, Own}) -> u64 ! {} cost 16 dec 0 { 1 }",
    )
    .unwrap();
    assert_eq!(
        multi.units[0].meaning_contract.rights,
        vec!["Disclose", "Own", "Use"]
    );

    // Determinism: the closure is the same on every run.
    let again = compile(
        "fn route(a: u64 & rights {Use}, b: u64 & rights {Disclose, Own}) -> u64 ! {} cost 16 dec 0 { 1 }",
    )
    .unwrap();
    assert_eq!(multi, again);
}

#[test]
fn deep_chains_terminate_inside_the_budget() {
    // Nested carriers with rights at several depths: inference must
    // terminate (totality of the row walk) and surface the full closure.
    let deep = compile(
        "fn chain(x: (u64 & rights {Own}, (u64 & rights {Use}, u64 & rights {Disclose}))) -> u64 ! {} cost 16 dec 0 { 1 }",
    )
    .unwrap();
    assert_eq!(
        deep.units[0].meaning_contract.rights,
        vec!["Disclose", "Own", "Use"]
    );
}

// ---------------------------------------------------------------------------
// No under-approximation: revocation changes the row; use without the
// right is ill-typed
// ---------------------------------------------------------------------------

#[test]
fn revoking_an_edge_shrinks_the_closure() {
    let full =
        compile("fn f(x: u64 & rights {Own, Disclose}) -> u64 ! {} cost 16 dec 0 { 1 }").unwrap();
    let revoked = compile("fn f(x: u64 & rights {Own}) -> u64 ! {} cost 16 dec 0 { 1 }").unwrap();
    assert_eq!(
        full.units[0].meaning_contract.rights,
        vec!["Disclose", "Own"]
    );
    assert_eq!(revoked.units[0].meaning_contract.rights, vec!["Own"]);
    // The mutated lattice must not resurrect the dropped right anywhere.
    assert!(!revoked.units[0]
        .meaning_contract
        .rights
        .iter()
        .any(|r| r == "Disclose"));
}

#[test]
fn declassification_requires_the_disclose_right() {
    // With the right: expressible.
    compile(
        "fn open(x: u64 & rights {Disclose}, proof: u64) -> u64 ! {open} cost 32 dec 0 { declassify(x, proof) }",
    )
    .unwrap();
    // Without it: stable rejection — typed repair cannot mint rights.
    let err = compile(
        "fn open(x: u64 & rights {Own}, proof: u64) -> u64 ! {open} cost 32 dec 0 { declassify(x, proof) }",
    )
    .unwrap_err();
    assert_eq!(err[0].code, "E-RIGHT-002");
    // And on a bare value with no row at all.
    let bare = compile(
        "fn open(x: u64, proof: u64) -> u64 ! {open} cost 32 dec 0 { declassify(x, proof) }",
    )
    .unwrap_err();
    assert_eq!(bare[0].code, "E-RIGHT-002");
}

#[test]
fn ambiguous_and_unbounded_rights_rows_reject_stably() {
    let duplicate =
        compile("fn f(x: u64 & rights {Own, Own}) -> u64 ! {} cost 16 dec 0 { 1 }").unwrap_err();
    assert_eq!(duplicate[0].code, "E-RIGHT-003");

    let oversized = (0..17)
        .map(|i| format!("Right{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let source =
        format!("fn f(x: u64 & rights {{{oversized}}}) -> u64 ! {{}} cost 16 dec 0 {{ 1 }}");
    let unbounded = compile(&source).unwrap_err();
    assert!(unbounded.iter().any(|d| d.code == "E-RIGHT-004"));

    let empty = compile("fn f(x: u64 & rights {}) -> u64 ! {} cost 16 dec 0 { 1 }").unwrap_err();
    assert!(empty.iter().any(|d| d.code == "E-RIGHT-004"));
}

#[test]
fn pathological_rights_carrier_depth_rejects_inside_a_fixed_budget() {
    let nested = format!(
        "{}u64 & rights {{Own}}{}",
        "Dream<".repeat(129),
        "> ".repeat(129)
    );
    let source = format!("fn f(x: {nested}) -> u64 ! {{}} cost 16 dec 0 {{ 1 }}");
    let err = compile(&source).unwrap_err();
    assert!(
        err.iter().any(|d| d.code == "E-RIGHT-004"),
        "unexpected diagnostics: {err:?}"
    );
}

#[test]
fn revocation_storm_has_no_resurrection_or_order_dependence() {
    for i in 0..4096u32 {
        let row = match i % 4 {
            0 => "Own, Use, Disclose",
            1 => "Own, Use",
            2 => "Own",
            _ => "Use",
        };
        let source = format!("fn f(x: u64 & rights {{{row}}}) -> u64 ! {{}} cost 16 dec 0 {{ 1 }}");
        let compiled = compile(&source).unwrap();
        let rights = &compiled.units[0].meaning_contract.rights;
        assert_eq!(rights.iter().any(|right| right == "Disclose"), i % 4 == 0);
        assert_eq!(rights.iter().any(|right| right == "Own"), i % 4 != 3);
    }
}
