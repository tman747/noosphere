//! E-WEFT-08 — v0 sufficiency fallback gate (ch04 §3.7).
//!
//! Claim under test (local half): typed schemas plus the total v0 relation
//! checker cover the current artifact stream — every release-corpus unit
//! elaborated by the full compiler is expressible as an admitted v0
//! CostCertificateV0 — and the checker has no false accepts: a certificate
//! whose bound sits one step below the actual charge is rejected, and a
//! formula/id mismatch is rejected. A checker false accept is a universal
//! kill; an unconditional mock verifier is Severity 1 (plan §5.11).
//!
//! The two-quarter admission-telemetry study that decides full-language
//! necessity is external; locally the v0 coverage census is 100%, which
//! supports keeping the full language in research (never a kill of
//! Grain/v0).
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]

use noos_grain::{decode_formula, decode_subject, encode_noun, eval, Meter, Noun};
use noos_weft_check::{
    check_cost_certificate, formula_id, BranchList, CostBranch, CostCertificateV0, CostTerm,
    CostTrial, Exponents, FormulaBytes, SizeList, SizeVarList, SubjectBytes, TermList, TrialList,
    WeftError,
};
use noos_weft_compile::compile;
use noos_weft_syntax::{parse, Type};
use std::path::PathBuf;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../grain/corpus/weft")
}

/// One trial subject per unit: an argument list of small scalars shaped by
/// the declared parameter types (loobean for Bool, small atom otherwise).
fn subject_for(params: &[Type]) -> Vec<u8> {
    let noun = params
        .iter()
        .enumerate()
        .rev()
        .fold(Noun::atom_u64(0), |acc, (i, t)| {
            let v = match t {
                Type::Bool => (i as u64) % 2,
                _ => 5 + i as u64,
            };
            Noun::cell(Noun::atom_u64(v), acc).unwrap()
        });
    encode_noun(&noun)
}

/// Wraps one elaborated unit as a constant-bound v0 cost certificate with
/// an executed trial.
fn v0_certificate(formula_hex: &str, bound: u64, subject: Vec<u8>) -> CostCertificateV0 {
    let formula_bytes = from_hex(formula_hex);
    CostCertificateV0 {
        formula_id: formula_id(&formula_bytes),
        grain_version: 1,
        size_vars: SizeVarList(Vec::new()),
        branches: BranchList(vec![CostBranch {
            terms: TermList(vec![CostTerm {
                coeff: bound,
                exponents: Exponents(Vec::new()),
            }]),
        }]),
        formula_bytes: FormulaBytes(formula_bytes),
        trials: TrialList(vec![CostTrial {
            sizes: SizeList(Vec::new()),
            subject: SubjectBytes(subject),
        }]),
    }
}

// ---------------------------------------------------------------------------
// Coverage census: the whole release corpus is v0-expressible and admitted
// ---------------------------------------------------------------------------

#[test]
fn release_corpus_is_fully_expressible_in_v0() {
    let mut entries: Vec<_> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "weft"))
        .collect();
    entries.sort();
    let mut units = 0u32;
    let mut admitted = 0u32;
    for path in &entries {
        let source = std::fs::read_to_string(path).unwrap();
        let program = parse(&source).unwrap();
        let compiled = compile(&source).unwrap();
        for (unit, f) in compiled.units.iter().zip(&program.functions) {
            units += 1;
            let params: Vec<Type> = f.params.iter().map(|p| p.ty.clone()).collect();
            let cert = v0_certificate(
                &unit.grain_formula_hex,
                unit.cost.derived_constant,
                subject_for(&params),
            );
            check_cost_certificate(&cert).unwrap_or_else(|e| {
                panic!(
                    "{}: v0 rejected an honest corpus certificate: {e:?}",
                    unit.name
                )
            });
            admitted += 1;
        }
    }
    assert!(units >= 6, "corpus shrank: {units} units");
    // Local census: 100% coverage. Under the frozen kill language this
    // supports the null hypothesis (v0 suffices) — never a kill of v0.
    assert_eq!(admitted, units);
}

// ---------------------------------------------------------------------------
// No false accepts: the universal kill
// ---------------------------------------------------------------------------

#[test]
fn bound_below_actual_charge_is_rejected() {
    let source = "fn inc(x: u64) -> u64 ! {} cost 32 dec 0 { x + 1 }\n\
                  fn twice(x: u64) -> u64 ! {} cost 128 dec 0 { inc(inc(x)) }";
    let compiled = compile(source).unwrap();
    let unit = compiled.units.iter().find(|u| u.name == "twice").unwrap();
    let subject_bytes = subject_for(&[Type::Int {
        signed: false,
        bits: 64,
    }]);
    // Establish the actual charge of the trial run.
    let formula = decode_formula(&from_hex(&unit.grain_formula_hex)).unwrap();
    let subject = decode_subject(&subject_bytes).unwrap();
    let mut meter = Meter::new(1 << 20, 1 << 20);
    eval(1, subject, formula, &mut meter).unwrap();
    let actual = meter.spent();
    assert!(actual > 1);
    // Exactly the actual charge: admitted (the meter is the assertion).
    let exact = v0_certificate(&unit.grain_formula_hex, actual, subject_bytes.clone());
    assert_eq!(check_cost_certificate(&exact), Ok(()));
    // One below: the false-accept probe. Admission here is the universal kill.
    let liar = v0_certificate(&unit.grain_formula_hex, actual - 1, subject_bytes);
    assert_eq!(
        check_cost_certificate(&liar),
        Err(WeftError::CertChargeExceedsBound),
        "v0 checker admitted an under-declared bound: UNIVERSAL KILL"
    );
}

#[test]
fn formula_identity_binding_is_enforced() {
    let compiled = compile("fn f(x: u64) -> u64 ! {} cost 64 dec 0 { x + 1 }").unwrap();
    let unit = &compiled.units[0];
    let mut cert = v0_certificate(
        &unit.grain_formula_hex,
        unit.cost.derived_constant,
        subject_for(&[Type::Int {
            signed: false,
            bits: 64,
        }]),
    );
    // Swap in a different (still decodable) formula without refreshing the
    // id: the certificate no longer names what it embeds.
    let other = compile("fn f(x: u64) -> u64 ! {} cost 64 dec 0 { x + 2 }").unwrap();
    cert.formula_bytes = FormulaBytes(from_hex(&other.units[0].grain_formula_hex));
    assert_eq!(
        check_cost_certificate(&cert),
        Err(WeftError::CertFormulaHashMismatch)
    );
}

#[test]
fn checker_is_not_a_mock_verifier() {
    // An unconditional accept would be Severity 1: feed a structurally
    // valid certificate whose trial traps and one whose formula bytes are
    // garbage — both must reject with distinct stable codes.
    let compiled = compile("fn f(x: u64) -> u64 ! {} cost 64 dec 0 { x + 1 }").unwrap();
    let unit = &compiled.units[0];
    let mut trap = v0_certificate(
        &unit.grain_formula_hex,
        unit.cost.derived_constant,
        Vec::new(),
    );
    trap.trials.0[0].subject = SubjectBytes(encode_noun(&Noun::atom_u64(7)));
    // Bare-atom subject: slot lookups walk off the tree and trap.
    assert_eq!(
        check_cost_certificate(&trap),
        Err(WeftError::CertTrialTrapped)
    );

    let mut garbage = v0_certificate(&unit.grain_formula_hex, 64, Vec::new());
    garbage.formula_bytes = FormulaBytes(vec![0x02]);
    garbage.trials.0[0].subject = SubjectBytes(encode_noun(&Noun::atom_u64(0)));
    assert_eq!(
        check_cost_certificate(&garbage),
        Err(WeftError::CertFormulaInvalid)
    );
}
