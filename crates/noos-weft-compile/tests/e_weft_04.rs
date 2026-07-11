//! E-WEFT-04 — Linearity and no-double-spend (ch04 §3.7).
//!
//! Claim under test: well-typed completed paths consume each `lin` value
//! exactly once under trap-atomic semantics; the rejection corpus gets
//! stable errors; spend/escrow/saga patterns stay expressible.
//! Kill: one well-typed double use.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]

use noos_grain::{decode_formula, decode_subject, encode_noun, eval, GrainTrap, Meter, Noun};
use noos_weft_compile::compile;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Rejection corpus: stable classes, run twice for stability
// ---------------------------------------------------------------------------

#[test]
fn rejection_corpus_gets_stable_errors() {
    let corpus = [
        // Drop: the resource strands.
        ("fn f(x: lin Hash) -> () ! {} { () }", "E-LIN-001"),
        // Double use through a tuple.
        (
            "fn f(x: lin Hash) -> ((), ()) ! {} { (consume(x), consume(x)) }",
            "E-LIN-002",
        ),
        // Double use through a let body.
        (
            "fn f(x: lin Hash) -> () ! {} { let a = consume(x); consume(x) }",
            "E-LIN-002",
        ),
        // Branch skew: one arm consumes, the other strands.
        (
            "fn f(c: Bool, x: lin Hash) -> () ! {} { if c { consume(x) } else { () } }",
            "E-LIN-003",
        ),
        // Consumption of a non-linear value.
        ("fn f(x: u64) -> () ! {} { consume(x) }", "E-LIN-004"),
        // Dropped linear let binding.
        (
            "fn f(x: lin Hash) -> () ! {} { let y = x; () }",
            "E-LIN-001",
        ),
    ];
    for (source, want) in corpus {
        for round in 0..2 {
            let err = compile(source).unwrap_err();
            assert_eq!(err[0].code, want, "round {round} for {source:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Required patterns stay expressible
// ---------------------------------------------------------------------------

#[test]
fn spend_escrow_and_saga_patterns_compile() {
    // Spend: consume the note, emit a receipt.
    compile("fn spend(n: lin Hash, to: u64) -> ((), u64) ! {} cost 64 dec 0 { (consume(n), to) }")
        .unwrap();
    // Escrow: both settlement arms consume exactly once.
    compile(
        "fn settle(release: Bool, escrow: lin Hash) -> () ! {} cost 64 dec 0 \
         { if release { consume(escrow) } else { consume(escrow) } }",
    )
    .unwrap();
    // Saga: two linear legs consumed in sequence.
    compile(
        "fn saga(leg1: lin Hash, leg2: lin Hash) -> ((), ()) ! {} cost 64 dec 0 \
         { (consume(leg1), consume(leg2)) }",
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Seeded fuzz: acceptance iff exactly-once on every path
// ---------------------------------------------------------------------------

#[test]
fn fuzzed_elaborations_never_admit_double_or_zero_use() {
    let mut state = 0x0407_2026u64;
    let mut accepted = 0u32;
    let mut rejected = 0u32;
    for _ in 0..2000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let n = (state >> 33) as u32;
        // Four structural families over one linear resource.
        let (source, expect_ok) = match n % 4 {
            0 => (
                "fn f(x: lin Hash) -> () ! {} { consume(x) }".to_string(),
                true,
            ),
            1 => ("fn f(x: lin Hash) -> () ! {} { () }".to_string(), false),
            2 => (
                "fn f(x: lin Hash) -> ((), ()) ! {} { (consume(x), consume(x)) }".to_string(),
                false,
            ),
            _ => (
                format!(
                    "fn f(c: Bool, x: lin Hash) -> u64 ! {{}} \
                     {{ if c {{ let u = consume(x); {} }} else {{ let u = consume(x); {} }} }}",
                    n % 97,
                    n % 89
                ),
                true,
            ),
        };
        match compile(&source) {
            Ok(_) => {
                assert!(expect_ok, "accepted a non-linear elaboration: {source}");
                accepted += 1;
            }
            Err(e) => {
                assert!(
                    !expect_ok,
                    "rejected a legal spend: {source} ({})",
                    e[0].code
                );
                assert!(e[0].code.starts_with("E-LIN-"), "wrong class {}", e[0].code);
                rejected += 1;
            }
        }
    }
    assert!(accepted > 400 && rejected > 400, "fuzz families collapsed");
}

// ---------------------------------------------------------------------------
// Trap atomicity: a trapped path yields no value, charges exactly the limit
// ---------------------------------------------------------------------------

#[test]
fn trapped_spend_is_atomic() {
    let compiled = compile(
        "fn spend(n: lin Hash, to: u64) -> ((), u64) ! {} cost 64 dec 0 { (consume(n), to) }",
    )
    .unwrap();
    let formula = decode_formula(&from_hex(&compiled.units[0].grain_formula_hex)).unwrap();
    let subject_noun = Noun::cell(
        Noun::atom_u64(0xAB),
        Noun::cell(Noun::atom_u64(7), Noun::atom_u64(0)).unwrap(),
    )
    .unwrap();
    let subject = decode_subject(&encode_noun(&subject_noun)).unwrap();
    // Under-provisioned meter: the machine traps; Result semantics mean no
    // partial value can escape — the note is either spent in a completed
    // path or the whole path never happened.
    let mut meter = Meter::new(3, 1 << 20);
    assert_eq!(
        eval(1, subject.clone(), formula.clone(), &mut meter).unwrap_err(),
        GrainTrap::MeterExhausted
    );
    assert_eq!(meter.spent(), 3, "exhaustion charges exactly the limit");
    // The same spend completes under an adequate meter.
    let mut meter = Meter::new(1 << 16, 1 << 20);
    eval(1, subject, formula, &mut meter).unwrap();
}
