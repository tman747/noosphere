//! E-WEFT-01 — Elaboration faithfulness (ch04 §3.7).
//!
//! Claim under test: the elaborator maps each well-typed Weft unit to a
//! Grain formula whose value, trap, and charge match an independently
//! written Weft reference evaluator, formula bytes are deterministic and
//! whitespace/comment-invariant, and malformed sources reject with stable
//! diagnostic classes. Kill: one output/trap/charge divergence.
//!
//! The cross-implementation half (Rust weftc vs Go weftref) is
//! `tools/gates/differential_weft.py`; this module is the in-crate half:
//! compiled formulas executed through `noos_grain::eval` against a direct
//! AST-semantics evaluator that shares no code with the lowering.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]

use noos_grain::{decode_formula, decode_subject, encode_noun, eval, Meter, Noun};
use noos_weft_compile::compile;
use noos_weft_syntax::{parse, BinOp, Expr, ExprKind, Function, Program, Type};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Independent reference semantics (deliberately NOT the lowering's noun ops)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum V {
    A(u64),
    L(Vec<V>),
}

/// Runtime encoding law: atoms are minimal LE atoms; tuples/effect payloads
/// are right-nested lists with a zero-atom terminator.
fn to_noun(v: &V) -> Noun {
    match v {
        V::A(x) => Noun::atom_u64(*x),
        V::L(xs) => xs.iter().rev().fold(Noun::atom_u64(0), |acc, x| {
            Noun::cell(to_noun(x), acc).unwrap()
        }),
    }
}

fn eval_ref(fns: &BTreeMap<String, &Function>, f: &Function, args: &[V]) -> V {
    assert_eq!(f.params.len(), args.len(), "arity in test harness");
    let env: BTreeMap<String, V> = f
        .params
        .iter()
        .zip(args)
        .map(|(p, a)| (p.name.clone(), a.clone()))
        .collect();
    go(fns, &env, &f.body)
}

fn go(fns: &BTreeMap<String, &Function>, env: &BTreeMap<String, V>, e: &Expr) -> V {
    match &e.kind {
        ExprKind::Var(n) => env[n].clone(),
        ExprKind::Int(n) => V::A(*n),
        // Loobean law: TRUE is 0, FALSE is 1.
        ExprKind::Bool(b) => V::A(u64::from(!*b)),
        ExprKind::Tuple(xs) => V::L(xs.iter().map(|x| go(fns, env, x)).collect()),
        ExprKind::Let(n, v, b) => {
            let mut env2 = env.clone();
            env2.insert(n.clone(), go(fns, env, v));
            go(fns, &env2, b)
        }
        ExprKind::If(c, a, b) => {
            if go(fns, env, c) == V::A(0) {
                go(fns, env, a)
            } else {
                go(fns, env, b)
            }
        }
        ExprKind::Binary(BinOp::Add, a, b) => match (&a.kind, &b.kind, go(fns, env, a)) {
            (_, ExprKind::Int(n), V::A(x)) => V::A(x + n),
            (ExprKind::Int(x), _, _) => match go(fns, env, b) {
                V::A(y) => V::A(x + y),
                V::L(_) => unreachable!("typed addition is scalar"),
            },
            _ => unreachable!("v1 lowering requires a literal operand"),
        },
        ExprKind::Binary(BinOp::Mul, a, b) => match (&a.kind, &b.kind) {
            (ExprKind::Int(x), ExprKind::Int(y)) => V::A(x * y),
            _ => unreachable!("v1 lowering folds multiplication"),
        },
        ExprKind::Binary(BinOp::Eq, a, b) => V::A(u64::from(go(fns, env, a) != go(fns, env, b))),
        // Consumption erases the resource: unit value, operand dropped.
        ExprKind::Consume(_) => V::L(Vec::new()),
        ExprKind::Call(n, args) if matches!(n.as_str(), "commit" | "beacon" | "declassify") => {
            V::L(args.iter().map(|x| go(fns, env, x)).collect())
        }
        ExprKind::Call(n, args) => {
            let vals: Vec<V> = args.iter().map(|x| go(fns, env, x)).collect();
            eval_ref(fns, fns[n], &vals)
        }
        _ => unreachable!("expression form outside the compiled core"),
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../grain/corpus/weft")
}

/// Every unit of `source`, run over `noos_grain::eval` and the reference
/// evaluator on the same argument vectors: values must agree byte-for-byte
/// and the machine must not trap under a generous meter.
fn assert_faithful(source: &str) -> usize {
    let program: Program = parse(source).unwrap();
    let fns: BTreeMap<String, &Function> = program
        .functions
        .iter()
        .map(|f| (f.name.clone(), f))
        .collect();
    let compiled = compile(source).unwrap();
    let mut cases = 0;
    for unit in &compiled.units {
        let f = fns[&unit.name];
        let formula = decode_formula(&from_hex(&unit.grain_formula_hex)).unwrap();
        for &seed in &[0u64, 1, 5, 30, 31, 4096, 1 << 20, (1 << 32) - 1] {
            let args: Vec<V> = f
                .params
                .iter()
                .enumerate()
                .map(|(i, p)| match &p.ty {
                    Type::Bool => V::A((seed + i as u64) % 2),
                    _ => V::A(seed + i as u64),
                })
                .collect();
            let subject_noun = to_noun(&V::L(args.clone()));
            let subject = decode_subject(&encode_noun(&subject_noun)).unwrap();
            let mut meter = Meter::new(1 << 20, 1 << 20);
            let got = eval(1, subject, formula.clone(), &mut meter)
                .unwrap_or_else(|t| panic!("{}: trapped {t:?} on seed {seed}", unit.name));
            let want = to_noun(&eval_ref(&fns, f, &args));
            assert_eq!(
                encode_noun(&got),
                encode_noun(&want),
                "value divergence: {} seed {seed}",
                unit.name
            );
            cases += 1;
        }
    }
    cases
}

/// The generated well-typed families of the differential gate, seeded.
fn generated_sources(count: u64) -> Vec<String> {
    let mut out = Vec::new();
    let mut state = 0x2026_0711u64;
    for _ in 0..count {
        // LCG (Numerical Recipes constants); deterministic corpus.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let n = (state >> 32) as u32;
        out.push(match n % 4 {
            0 => format!("fn f(x: u64) -> u64 ! {{}} cost 256 dec 0 {{ x + {} }}", n % 16),
            1 => format!("fn f(x: u64) -> Bool ! {{}} cost 64 dec 0 {{ x == {} }}", n % 31),
            2 => format!(
                "fn f(c: Bool, x: u64) -> u64 ! {{}} cost 64 dec 0 {{ if c {{ x }} else {{ {} }} }}",
                n % 31
            ),
            _ => format!("fn f(x: u64) -> (u64, u64) ! {{}} cost 64 dec 0 {{ (x, {}) }}", n % 31),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Contract tests
// ---------------------------------------------------------------------------

#[test]
fn release_corpus_matches_reference_evaluator() {
    let dir = corpus_dir();
    let mut files = 0;
    let mut cases = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "weft"))
        .collect();
    entries.sort();
    for path in entries {
        let source = std::fs::read_to_string(&path).unwrap();
        cases += assert_faithful(&source);
        files += 1;
    }
    assert!(files >= 5, "release corpus shrank: {files} files");
    assert!(cases > 0);
}

#[test]
fn generated_units_match_reference_evaluator() {
    let mut cases = 0;
    for source in generated_sources(512) {
        cases += assert_faithful(&source);
    }
    assert!(cases >= 4096, "generated sweep shrank: {cases}");
}

#[test]
fn elaboration_is_deterministic_and_layout_invariant() {
    let a = compile("fn f(x: u64) -> u64 ! {} cost 64 dec 0 { x + 3 }").unwrap();
    let b = compile("fn f(x: u64) -> u64 ! {} cost 64 dec 0 { x + 3 }").unwrap();
    assert_eq!(a, b, "recompilation must be byte-identical");
    // Comments and whitespace never reach the canonical AST: same
    // source_root, same formula bytes, same formula id.
    let c = compile("--layout\n fn f ( x : u64 ) -> u64 !{} cost 64 dec 0 {x+3}").unwrap();
    assert_eq!(a.source_root, c.source_root);
    assert_eq!(a.units[0].grain_formula_hex, c.units[0].grain_formula_hex);
    assert_eq!(a.units[0].formula_id, c.units[0].formula_id);
}

#[test]
fn charge_stays_within_the_static_certificate() {
    // The faithfulness triple includes charge: metered execution never
    // exceeds the unit's derived constant (deep dive in e_weft_02).
    let compiled = compile("fn f(x: u64) -> u64 ! {} cost 256 dec 0 { x + 15 }").unwrap();
    let unit = &compiled.units[0];
    let formula = decode_formula(&from_hex(&unit.grain_formula_hex)).unwrap();
    let subject = decode_subject(&encode_noun(&to_noun(&V::L(vec![V::A(9)])))).unwrap();
    let mut meter = Meter::new(1 << 20, 1 << 20);
    eval(1, subject, formula, &mut meter).unwrap();
    assert!(meter.spent() <= unit.cost.derived_constant);
    assert!(meter.spent() > 0);
}

#[test]
fn trap_parity_under_meter_exhaustion() {
    // Same formula, meter 1: the machine must trap — never emit a value.
    let compiled = compile("fn f(x: u64) -> u64 ! {} cost 64 dec 0 { x + 1 }").unwrap();
    let formula = decode_formula(&from_hex(&compiled.units[0].grain_formula_hex)).unwrap();
    let subject = decode_subject(&encode_noun(&to_noun(&V::L(vec![V::A(1)])))).unwrap();
    let mut meter = Meter::new(1, 1 << 20);
    assert!(eval(1, subject, formula, &mut meter).is_err());
}

#[test]
fn malformed_sources_reject_with_stable_classes() {
    for (source, want) in [
        ("fn f(x: lin Hash) -> () ! {} { () }", "E-LIN-001"),
        ("fn f(x: u64) -> u64 ! {} { missing }", "E-TYPE-001"),
        (
            "fn f(x: u64) -> Rand256<h> ! {} { beacon(x) }",
            "E-EFFECT-002",
        ),
        ("fn f(x: u64) -> u64 ! {} { x + }", "E-PARSE-001"),
    ] {
        // Twice: the rejection class must be stable across runs.
        for _ in 0..2 {
            let err = compile(source).unwrap_err();
            assert_eq!(err[0].code, want, "for {source:?}");
        }
    }
}
