//! E-WEFT-02 — Cost-certificate soundness and expressiveness (ch04 §3.7).
//!
//! Claim under test: static cost certificates upper-bound Grain semantic
//! meter use with declared slack, the recurrence/totality checker rejects
//! unproven recursion, and inference stays inside its compile budget.
//! Kill: one admitted meter overrun, or the working corpus becoming
//! inexpressible.
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

fn args_subject(args: &[u64]) -> Noun {
    args.iter().rev().fold(Noun::atom_u64(0), |acc, x| {
        Noun::cell(Noun::atom_u64(*x), acc).unwrap()
    })
}

/// Runs every unit of `source` on `inputs`, asserting the meter never
/// exceeds the derived constant. Returns (spent, bound) samples.
fn measure(source: &str, inputs: &[Vec<u64>]) -> Vec<(u64, u64)> {
    let compiled = compile(source).unwrap();
    let mut samples = Vec::new();
    for unit in &compiled.units {
        let bound = unit.cost.derived_constant;
        assert!(
            bound > 0,
            "{}: static bound must exist for this corpus",
            unit.name
        );
        let formula = decode_formula(&from_hex(&unit.grain_formula_hex)).unwrap();
        for args in inputs {
            let subject = decode_subject(&encode_noun(&args_subject(args))).unwrap();
            // The certificate IS the meter: running under exactly `bound`
            // steps must complete. Exhaustion here is an admitted overrun —
            // the E-WEFT-02 kill condition.
            let mut meter = Meter::new(bound, 1 << 20);
            eval(1, subject, formula.clone(), &mut meter).unwrap_or_else(|t| {
                panic!("meter overrun or trap for {} on {args:?}: {t:?}", unit.name)
            });
            samples.push((meter.spent(), bound));
        }
    }
    samples
}

// ---------------------------------------------------------------------------
// Soundness: zero overruns over corpus programs and overrun-seeking inputs
// ---------------------------------------------------------------------------

#[test]
fn zero_meter_overruns_across_adversarial_corpus() {
    // Adversarial inputs: zero, boundary loobeans, maxima the static
    // ValBound must still cover (u64 stays 8 bytes after the +4096 unroll).
    let one = vec![vec![0], vec![1], vec![(1 << 32) - 1], vec![u64::MAX - 5000]];
    let two: Vec<Vec<u64>> = one
        .iter()
        .flat_map(|a| [vec![a[0], 0], vec![a[0], u64::MAX - 5000]])
        .collect();
    let three: Vec<Vec<u64>> = [0u64, 1]
        .iter()
        .map(|c| vec![*c, 7, u64::MAX - 5000])
        .collect();

    let mut samples = Vec::new();
    samples.extend(measure(
        "fn identity(x: u64) -> u64 ! {} cost 16 dec 0 { x }",
        &one,
    ));
    samples.extend(measure(
        "fn deep(x: u64) -> u64 ! {} cost 100000 dec 0 { x + 4096 }",
        &one,
    ));
    samples.extend(measure(
        "fn eq(x: u64, y: u64) -> Bool ! {} cost 64 dec 0 { x == y }",
        &two,
    ));
    samples.extend(measure(
        "fn pair(x: u64, y: u64) -> (u64, u64) ! {} cost 64 dec 0 { (x, y) }",
        &two,
    ));
    samples.extend(measure(
        "fn select(c: Bool, x: u64, y: u64) -> u64 ! {} cost 64 dec 0 { if c { x } else { y } }",
        &three,
    ));
    samples.extend(measure(
        "fn inc(x: u64) -> u64 ! {} cost 32 dec 0 { x + 1 }\n\
         fn twice(x: u64) -> u64 ! {} cost 128 dec 0 { inc(inc(x)) }",
        &one,
    ));
    samples.extend(measure(
        "fn nest(x: u64) -> u64 ! {} cost 512 dec 0 { let a = x + 3; let b = a + 5; b + 7 }",
        &one,
    ));
    // Every sample has spent <= bound by construction (the meter enforced
    // it); make the census explicit.
    let overruns = samples
        .iter()
        .filter(|(spent, bound)| spent > bound)
        .count();
    assert_eq!(overruns, 0, "admitted meter overruns");
    assert!(samples.len() >= 30);
}

// ---------------------------------------------------------------------------
// Tightness: declared slack, not vacuous bounds
// ---------------------------------------------------------------------------

#[test]
fn certificates_are_tight_on_the_working_corpus() {
    let inputs = vec![vec![5u64], vec![1 << 16]];
    let two = vec![vec![5u64, 9], vec![1 << 16, 3]];
    let three = vec![vec![0u64, 5, 9], vec![1u64, 5, 9]];
    let mut ratios = Vec::new();
    for (source, args) in [
        ("fn identity(x: u64) -> u64 ! {} cost 16 dec 0 { x }", &inputs),
        ("fn add(x: u64) -> u64 ! {} cost 256 dec 0 { x + 12 }", &inputs),
        ("fn eq(x: u64, y: u64) -> Bool ! {} cost 64 dec 0 { x == y }", &two),
        ("fn pair(x: u64, y: u64) -> (u64, u64) ! {} cost 64 dec 0 { (x, y) }", &two),
        (
            "fn select(c: Bool, x: u64, y: u64) -> u64 ! {} cost 64 dec 0 { if c { x } else { y } }",
            &three,
        ),
        (
            "fn inc(x: u64) -> u64 ! {} cost 32 dec 0 { x + 1 }\n\
             fn twice(x: u64) -> u64 ! {} cost 128 dec 0 { inc(inc(x)) }",
            &inputs,
        ),
    ] {
        for (spent, bound) in measure(source, args) {
            ratios.push(spent as f64 / bound as f64);
        }
    }
    ratios.sort_by(f64::total_cmp);
    let min = ratios[0];
    let median = ratios[ratios.len() / 2];
    // E-WEFT-02 tightness gate at lab scale: ≥95% of the corpus within 10x
    // slack (ratio >= 0.10); the E-WEFT-02a measured floor was 0.1125.
    let tight = ratios.iter().filter(|r| **r >= 0.10).count();
    assert!(
        tight * 20 >= ratios.len() * 19,
        "tightness regression: min={min:.4} median={median:.4} tight={tight}/{}",
        ratios.len()
    );
    assert!(median >= 0.25, "median tightness collapsed: {median:.4}");
}

// ---------------------------------------------------------------------------
// Never trust a declared polynomial
// ---------------------------------------------------------------------------

#[test]
fn declared_cost_below_derived_rejects() {
    let err = compile("fn f(x: u64) -> u64 ! {} cost 1 dec 0 { x + 1 }").unwrap_err();
    assert_eq!(err[0].code, "E-COST-001");
}

// ---------------------------------------------------------------------------
// Recurrence checker: totality / dec enforcement
// ---------------------------------------------------------------------------

#[test]
fn recursion_without_dec_measure_rejects() {
    let err = compile("fn f(x: u64) -> u64 ! {} { f(x) }").unwrap_err();
    assert_eq!(err[0].code, "E-TOT-001");
}

#[test]
fn recursion_without_decreasing_argument_rejects() {
    let err = compile("fn f(x: u64) -> u64 ! {} dec 1 { f(x) }").unwrap_err();
    assert_eq!(err[0].code, "E-TOT-002");
}

#[test]
fn mutual_recursion_gets_no_static_constant_and_metering_backstops() {
    // Mutual cycles have no static constant: derived_constant is 0 and the
    // declared bound governs; execution stays safe because Grain step
    // metering is the unconditional backstop (the ch04 §3.7 fallback law).
    let source = "fn f(x: u64) -> u64 ! {} cost 64 dec 0 { g(x) }\n\
                  fn g(x: u64) -> u64 ! {} cost 64 dec 0 { f(x) }";
    let compiled = compile(source).unwrap();
    assert!(compiled.units.iter().all(|u| u.cost.derived_constant == 0));
    let formula = decode_formula(&from_hex(&compiled.units[0].grain_formula_hex)).unwrap();
    let subject = decode_subject(&encode_noun(&args_subject(&[3]))).unwrap();
    let mut meter = Meter::new(10_000, 1 << 20);
    assert_eq!(
        eval(1, subject, formula, &mut meter).unwrap_err(),
        GrainTrap::MeterExhausted,
        "the divergent cycle must die on the meter, atomically"
    );
    assert_eq!(
        meter.spent(),
        10_000,
        "exhaustion charges exactly the limit"
    );
}

// ---------------------------------------------------------------------------
// Inference compile budget
// ---------------------------------------------------------------------------

#[test]
fn deep_arithmetic_stays_inside_the_frozen_inference_budget() {
    // The unroll ceiling is the compile budget: 4096 elaborates, 4097 is a
    // stable rejection instead of an inference blowup.
    assert!(compile("fn f(x: u64) -> u64 ! {} cost 100000 dec 0 { x + 4096 }").is_ok());
    let err = compile("fn f(x: u64) -> u64 ! {} cost 100000 dec 0 { x + 4097 }").unwrap_err();
    assert_eq!(err[0].code, "E-LOWER-003");
}
