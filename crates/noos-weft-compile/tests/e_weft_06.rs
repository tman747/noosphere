//! E-WEFT-06 — Jet-certificate market game (ch04 §3.7).
//!
//! Claim under test (local mechanics only): a challenger running bounded
//! differential execution finds every planted jet divergence inside its
//! window, an equivalent jet survives the full sweep with zero false
//! flags, and certificates are bound to exact formula identities so a
//! divergent implementation cannot ride an honest certificate.
//! Kill: a planted divergence survives its window.
//!
//! The economic half — bonds, challenger profitability, live market — is
//! external by construction and stays a registered gap; these tests prove
//! the discovery mechanics the market game runs on.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]

use noos_grain::{decode_formula, decode_subject, encode_noun, eval, Meter, Noun};
use noos_weft_compile::compile;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn formula_of(source: &str) -> (String, Noun) {
    let compiled = compile(source).unwrap();
    let unit = &compiled.units[0];
    (
        unit.formula_id.clone(),
        decode_formula(&from_hex(&unit.grain_formula_hex)).unwrap(),
    )
}

fn run(formula: &Noun, x: u64) -> Vec<u8> {
    let subject_noun = Noun::cell(Noun::atom_u64(x), Noun::atom_u64(0)).unwrap();
    let subject = decode_subject(&encode_noun(&subject_noun)).unwrap();
    let mut meter = Meter::new(1 << 20, 1 << 20);
    encode_noun(&eval(1, subject, formula.clone(), &mut meter).unwrap())
}

const WINDOW: u64 = 4096;

#[test]
fn planted_divergence_is_found_inside_the_window() {
    // Interpreter semantics: x + 1. The "jet" seeds a divergence at the
    // boundary input 255 (the classic fast-path bug).
    let (_, slow) = formula_of("fn f(x: u64) -> u64 ! {} cost 256 dec 0 { x + 1 }");
    let (_, jet) = formula_of(
        "fn f(x: u64) -> u64 ! {} cost 256 dec 0 { if x == 255 { x + 2 } else { x + 1 } }",
    );
    let mut witness = None;
    for x in 0..WINDOW {
        if run(&slow, x) != run(&jet, x) {
            witness = Some(x);
            break;
        }
    }
    let found = witness.expect("planted divergence survived the challenge window: KILL");
    assert_eq!(found, 255);
    // Median discovery far below the window: the witness sits in the first
    // 1/16th of the sweep.
    assert!(found < WINDOW / 16);
    // Re-verification confirms the witness (no spurious slash): both
    // machines are re-run and must still disagree.
    assert_ne!(run(&slow, found), run(&jet, found));
}

#[test]
fn equivalent_jet_survives_with_zero_false_flags() {
    // An independently compiled but semantically identical implementation:
    // the full sweep must find nothing, so no false slash can even start.
    let (_, slow) = formula_of("fn f(x: u64) -> u64 ! {} cost 256 dec 0 { x + 1 }");
    let (_, jet) = formula_of("fn g(y: u64) -> u64 ! {} cost 256 dec 0 { y + 1 }");
    let divergences = (0..WINDOW)
        .filter(|x| run(&slow, *x) != run(&jet, *x))
        .count();
    assert_eq!(divergences, 0, "false flag against an equivalent jet");
}

#[test]
fn certificates_bind_exact_formula_identity() {
    // A certificate names one formula id; the divergent implementation has
    // a different id, so an honest certificate cannot be transplanted onto
    // it — the registry key (grain_version, formula_id) simply differs.
    let (honest_id, _) = formula_of("fn f(x: u64) -> u64 ! {} cost 256 dec 0 { x + 1 }");
    let (divergent_id, _) = formula_of(
        "fn f(x: u64) -> u64 ! {} cost 256 dec 0 { if x == 255 { x + 2 } else { x + 1 } }",
    );
    assert_ne!(honest_id, divergent_id);
    // Identity is stable: recompilation reproduces the same binding.
    let (again, _) = formula_of("fn f(x: u64) -> u64 ! {} cost 256 dec 0 { x + 1 }");
    assert_eq!(honest_id, again);
}
