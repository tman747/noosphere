//! Conformance vector definitions for `protocol/vectors/grain/` (spec §14).
//!
//! This module is the single source of truth for the frozen fixtures: the
//! `gen_vectors` binary serializes these cases to JSON, and the crate tests
//! execute every case against the interpreter. Expected charges are frozen
//! literals derived from the spec's cost table (§§10–11), so a cost-table
//! regression in the implementation fails the tests rather than silently
//! regenerating different fixtures.

use crate::{encode_noun, GrainTrap, Noun};

// ---------------------------------------------------------------------------
// Case shapes
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum Outcome {
    /// Canonical encoding of the expected result noun.
    Value(Vec<u8>),
    /// Expected stable trap code.
    Trap(u16),
}

#[derive(Clone)]
pub struct Expect {
    pub outcome: Outcome,
    /// Expected `meter.spent()` at return; 0 for decode traps.
    pub charge: u64,
}

pub struct EvalCase {
    pub name: &'static str,
    pub version: u32,
    pub subject: Vec<u8>,
    pub formula: Vec<u8>,
    pub meter_limit: u64,
    pub arena_limit: u64,
    pub expect: Expect,
}

pub struct DecodeCase {
    pub name: &'static str,
    /// "formula" or "subject" — selects the size bound and oversize trap.
    pub role: &'static str,
    pub bytes: Vec<u8>,
    /// `None`: must decode AND re-encode byte-identically. `Some(code)`:
    /// must trap with that code.
    pub expect_trap: Option<u16>,
}

pub struct HintCase {
    pub name: &'static str,
    pub subject: Vec<u8>,
    /// Formula containing opcode-11 hints.
    pub hinted: Vec<u8>,
    /// The same formula with every `[11 h f]` rewritten to `f`.
    pub erased: Vec<u8>,
    pub meter_limit: u64,
    pub arena_limit: u64,
    /// Both evaluations must produce exactly this outcome and charge.
    pub expect: Expect,
}

// ---------------------------------------------------------------------------
// Noun-building helpers (fixture data is always within the frozen bounds)
// ---------------------------------------------------------------------------

fn a(v: u64) -> Noun {
    Noun::atom_u64(v)
}

fn c2(h: Noun, t: Noun) -> Noun {
    match Noun::cell(h, t) {
        Ok(n) => n,
        Err(_) => unreachable!("fixture noun exceeds frozen depth"),
    }
}

fn e(n: &Noun) -> Vec<u8> {
    encode_noun(n)
}

/// Atom of `len` bytes, every byte `fill` (`fill != 0` keeps it minimal).
fn big_atom(len: usize, fill: u8) -> Noun {
    debug_assert!(fill != 0);
    Noun::atom_from_le_bytes(&vec![fill; len])
}

const METER: u64 = 1_000_000;
const ARENA: u64 = 1_000_000;

fn val(name: &'static str, s: &Noun, f: &Noun, result: &Noun, charge: u64) -> EvalCase {
    EvalCase {
        name,
        version: 1,
        subject: e(s),
        formula: e(f),
        meter_limit: METER,
        arena_limit: ARENA,
        expect: Expect {
            outcome: Outcome::Value(e(result)),
            charge,
        },
    }
}

fn trap(name: &'static str, s: &Noun, f: &Noun, code: GrainTrap, charge: u64) -> EvalCase {
    EvalCase {
        name,
        version: 1,
        subject: e(s),
        formula: e(f),
        meter_limit: METER,
        arena_limit: ARENA,
        expect: Expect {
            outcome: Outcome::Trap(code.code()),
            charge,
        },
    }
}

// ---------------------------------------------------------------------------
// Eval cases (schema noos/grain/eval-v1)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub fn eval_cases() -> Vec<EvalCase> {
    let mut cases: Vec<EvalCase> = Vec::new();

    // ---- per-opcode positives (spec §11 worked examples + coverage) -------
    // 1 quote
    cases.push(val("quote_atom", &a(0), &c2(a(1), a(42)), &a(42), 1));
    cases.push(val(
        "quote_cell",
        &a(0),
        &c2(a(1), c2(a(7), a(8))),
        &c2(a(7), a(8)),
        1,
    ));
    // 0 slot
    let s78 = c2(a(7), a(8));
    cases.push(val("slot_whole", &a(42), &c2(a(0), a(1)), &a(42), 2));
    cases.push(val("slot_head", &s78, &c2(a(0), a(2)), &a(7), 3));
    cases.push(val("slot_tail", &s78, &c2(a(0), a(3)), &a(8), 3));
    let s_deep = c2(c2(a(1), a(2)), a(3));
    cases.push(val("slot_head_tail", &s_deep, &c2(a(0), a(5)), &a(2), 4));
    let s_list = c2(a(1), c2(a(2), c2(a(3), a(0))));
    cases.push(val(
        "slot_tail_tail",
        &s_list,
        &c2(a(0), a(7)),
        &c2(a(3), a(0)),
        4,
    ));
    // 3 is-cell
    cases.push(val(
        "iscell_cell",
        &s78,
        &c2(a(3), c2(a(0), a(1))),
        &a(0),
        4,
    ));
    cases.push(val(
        "iscell_atom",
        &a(0),
        &c2(a(3), c2(a(1), a(5))),
        &a(1),
        3,
    ));
    // 4 inc
    cases.push(val(
        "inc_small",
        &a(0),
        &c2(a(4), c2(a(1), a(41))),
        &a(42),
        6,
    ));
    cases.push(val("inc_zero", &a(0), &c2(a(4), c2(a(1), a(0))), &a(1), 5));
    cases.push(val(
        "inc_carry_word",
        &a(0),
        &c2(a(4), c2(a(1), a(255))),
        &a(256),
        6,
    ));
    // cons composition
    cases.push(val(
        "cons_pair",
        &a(0),
        &c2(c2(a(1), a(1)), c2(a(1), a(2))),
        &c2(a(1), a(2)),
        9,
    ));
    // 5 equal
    cases.push(val(
        "equal_yes_atoms",
        &a(0),
        &c2(a(5), c2(c2(a(1), a(5)), c2(a(1), a(5)))),
        &a(0),
        6,
    ));
    cases.push(val(
        "equal_no_shape",
        &a(0),
        &c2(a(5), c2(c2(a(1), a(4)), c2(a(1), c2(a(0), a(0))))),
        &a(1),
        5,
    ));
    cases.push(val(
        "equal_no_length",
        &a(0),
        &c2(a(5), c2(c2(a(1), a(1)), c2(a(1), a(256)))),
        &a(1),
        5,
    ));
    let one_two = c2(a(1), a(2));
    cases.push(val(
        "equal_yes_cells",
        &a(0),
        &c2(
            a(5),
            c2(c2(a(1), one_two.clone()), c2(a(1), one_two.clone())),
        ),
        &a(0),
        9,
    ));
    // 6 if
    cases.push(val(
        "if_then",
        &a(0),
        &c2(
            a(6),
            c2(c2(a(1), a(0)), c2(c2(a(1), a(10)), c2(a(1), a(20)))),
        ),
        &a(10),
        5,
    ));
    cases.push(val(
        "if_else",
        &a(0),
        &c2(
            a(6),
            c2(c2(a(1), a(1)), c2(c2(a(1), a(10)), c2(a(1), a(20)))),
        ),
        &a(20),
        5,
    ));
    // 7 compose
    cases.push(val(
        "compose_quote_slot",
        &a(99),
        &c2(a(7), c2(c2(a(1), a(33)), c2(a(0), a(1)))),
        &a(33),
        6,
    ));
    // 8 push
    cases.push(val(
        "push_new_head",
        &a(99),
        &c2(a(8), c2(c2(a(1), a(5)), c2(a(0), a(2)))),
        &a(5),
        10,
    ));
    cases.push(val(
        "push_old_subject",
        &a(99),
        &c2(a(8), c2(c2(a(1), a(5)), c2(a(0), a(3)))),
        &a(99),
        10,
    ));
    cases.push(val(
        "push_computed_value",
        &a(0),
        &c2(a(8), c2(c2(a(4), c2(a(1), a(1))), c2(a(0), a(2)))),
        &a(2),
        15,
    ));
    // 9 arm
    let core_battery = c2(c2(a(1), a(42)), a(0));
    cases.push(val(
        "arm_battery_head",
        &core_battery,
        &c2(a(9), c2(a(2), c2(a(0), a(1)))),
        &a(42),
        10,
    ));
    // 10 edit
    cases.push(val(
        "edit_head",
        &s78,
        &c2(a(10), c2(c2(a(2), c2(a(1), a(9))), c2(a(0), a(1)))),
        &c2(a(9), a(8)),
        11,
    ));
    cases.push(val(
        "edit_tail",
        &s78,
        &c2(a(10), c2(c2(a(3), c2(a(1), a(9))), c2(a(0), a(1)))),
        &c2(a(7), a(9)),
        11,
    ));
    cases.push(val(
        "edit_root",
        &s78,
        &c2(a(10), c2(c2(a(1), c2(a(1), a(9))), c2(a(0), a(1)))),
        &a(9),
        7,
    ));
    // 11 hint
    cases.push(val(
        "hint_cell_hint_noun",
        &a(0),
        &c2(a(11), c2(c2(a(1), a(1)), c2(a(1), a(42)))),
        &a(42),
        1,
    ));
    cases.push(val(
        "hint_atom_hint_noun",
        &a(0),
        &c2(a(11), c2(a(0), c2(a(4), c2(a(1), a(5))))),
        &a(6),
        6,
    ));
    // 2 apply
    cases.push(val(
        "apply_quoted_formula",
        &a(0),
        &c2(a(2), c2(c2(a(0), a(1)), c2(a(1), c2(a(1), a(99))))),
        &a(99),
        8,
    ));

    // ---- traps -------------------------------------------------------------
    cases.push(trap(
        "trap_axis_zero",
        &a(0),
        &c2(a(0), a(0)),
        GrainTrap::InvalidAxis,
        0,
    ));
    cases.push(trap(
        "trap_axis_into_atom",
        &c2(a(1), a(2)),
        &c2(a(0), a(4)),
        GrainTrap::InvalidAxis,
        4,
    ));
    cases.push(trap(
        "trap_arm_axis_invalid",
        &a(0),
        &c2(a(9), c2(a(4), c2(a(1), c2(a(1), a(5))))),
        GrainTrap::InvalidAxis,
        9,
    ));
    cases.push(trap(
        "trap_edit_axis_into_atom",
        &a(5),
        &c2(a(10), c2(c2(a(2), c2(a(1), a(9))), c2(a(0), a(1)))),
        GrainTrap::InvalidAxis,
        11,
    ));
    cases.push(trap(
        "trap_formula_atom",
        &a(0),
        &a(5),
        GrainTrap::TypeMismatch,
        0,
    ));
    cases.push(trap(
        "trap_inc_of_cell",
        &c2(a(1), a(2)),
        &c2(a(4), c2(a(0), a(1))),
        GrainTrap::TypeMismatch,
        2,
    ));
    cases.push(trap(
        "trap_if_non_loobean",
        &a(0),
        &c2(a(6), c2(c2(a(1), a(2)), c2(c2(a(1), a(0)), c2(a(1), a(1))))),
        GrainTrap::TypeMismatch,
        4,
    ));
    cases.push(trap(
        "trap_slot_axis_cell",
        &a(0),
        &c2(a(0), c2(a(1), a(1))),
        GrainTrap::TypeMismatch,
        0,
    ));
    cases.push(trap(
        "trap_arm_axis_cell",
        &a(0),
        &c2(a(9), c2(c2(a(1), a(1)), c2(a(0), a(1)))),
        GrainTrap::TypeMismatch,
        0,
    ));
    cases.push(trap(
        "trap_hint_atom_arg",
        &a(0),
        &c2(a(11), a(5)),
        GrainTrap::TypeMismatch,
        0,
    ));

    let mut meter_zero = trap(
        "trap_meter_zero",
        &a(0),
        &c2(a(1), a(0)),
        GrainTrap::MeterExhausted,
        0,
    );
    meter_zero.meter_limit = 0;
    cases.push(meter_zero);

    let self_apply = c2(a(2), c2(c2(a(0), a(1)), c2(a(0), a(1))));
    let mut meter_loop = trap(
        "trap_meter_self_apply_loop",
        &self_apply,
        &self_apply,
        GrainTrap::MeterExhausted,
        1000,
    );
    meter_loop.meter_limit = 1000;
    cases.push(meter_loop);

    cases.push(trap(
        "trap_unknown_opcode_12",
        &a(0),
        &c2(a(12), c2(a(1), a(0))),
        GrainTrap::UnknownOpcode,
        0,
    ));
    cases.push(trap(
        "trap_unknown_opcode_multibyte",
        &a(0),
        &c2(a(256), a(0)),
        GrainTrap::UnknownOpcode,
        0,
    ));

    let mut wrong_version = trap(
        "trap_unknown_version",
        &a(0),
        &c2(a(1), a(0)),
        GrainTrap::UnknownVersion,
        0,
    );
    wrong_version.version = 2;
    cases.push(wrong_version);

    // ATOM_BOUND: inc of the maximum atom (65536 bytes of 0xFF).
    cases.push(trap(
        "trap_atom_bound_inc_max",
        &big_atom(65_536, 0xFF),
        &c2(a(4), c2(a(0), a(1))),
        GrainTrap::AtomBound,
        8196, // slot 2 + inc base 2 + 8192 operand words
    ));

    // ARENA_EXHAUSTED: push needs 3 words against a 2-word arena.
    let mut arena_push = trap(
        "trap_arena_exhausted_push",
        &a(99),
        &c2(a(8), c2(c2(a(1), a(5)), c2(a(0), a(2)))),
        GrainTrap::ArenaExhausted,
        7, // push 3 + quote 1 + cell alloc charge 3 (spent before arena check)
    );
    arena_push.arena_limit = 2;
    cases.push(arena_push);

    // Decode-stage traps surfaced through the eval runner (charge 0).
    cases.push(EvalCase {
        name: "trap_formula_oversized",
        version: 1,
        subject: e(&a(0)),
        formula: e(&big_atom(65_532, 0x01)), // 5 + 65_532 = 65_537 > 65_536
        meter_limit: METER,
        arena_limit: ARENA,
        expect: Expect {
            outcome: Outcome::Trap(GrainTrap::FormulaOversized.code()),
            charge: 0,
        },
    });
    cases.push(EvalCase {
        name: "trap_subject_oversized",
        version: 1,
        subject: e(&big_atom(1_048_572, 0x01)), // 5 + 1_048_572 = 1_048_577
        formula: e(&c2(a(1), a(0))),
        meter_limit: METER,
        arena_limit: ARENA,
        expect: Expect {
            outcome: Outcome::Trap(GrainTrap::SubjectOversized.code()),
            charge: 0,
        },
    });
    cases.push(EvalCase {
        name: "trap_subject_atom_over_bound",
        version: 1,
        // tag 0x00, len = 65_537: the atom bound rejects before payload reads.
        subject: {
            let mut b = vec![0x00u8];
            b.extend_from_slice(&65_537u32.to_le_bytes());
            b
        },
        formula: e(&c2(a(1), a(0))),
        meter_limit: METER,
        arena_limit: ARENA,
        expect: Expect {
            outcome: Outcome::Trap(GrainTrap::NounOversized.code()),
            charge: 0,
        },
    });
    cases.push(EvalCase {
        name: "trap_subject_malformed_tag",
        version: 1,
        subject: vec![0x02],
        formula: e(&c2(a(1), a(0))),
        meter_limit: METER,
        arena_limit: ARENA,
        expect: Expect {
            outcome: Outcome::Trap(GrainTrap::MalformedBytes.code()),
            charge: 0,
        },
    });

    // NOUN_OVERSIZED at runtime: subject-growth loop until the depth bound.
    // F = [2 [[0 1] [0 3]] [0 3]], S0 = [0 F]; each cycle costs 19 steps and
    // 3 arena words and deepens the subject by one (spec §11 derivation).
    let f_grow = c2(a(2), c2(c2(c2(a(0), a(1)), c2(a(0), a(3))), c2(a(0), a(3))));
    let s_grow = c2(a(0), f_grow.clone());
    let mut depth_loop = trap(
        "trap_noun_oversized_depth_loop",
        &s_grow,
        &f_grow,
        GrainTrap::NounOversized,
        19_922_865, // 1_048_571 cycles * 19 + 16 partial
    );
    depth_loop.meter_limit = 30_000_000;
    depth_loop.arena_limit = 4_194_304;
    cases.push(depth_loop);

    cases
}

// ---------------------------------------------------------------------------
// Decode cases (schema noos/grain/noun-bytes-v1)
// ---------------------------------------------------------------------------

pub fn decode_cases() -> Vec<DecodeCase> {
    fn ok(name: &'static str, bytes: Vec<u8>) -> DecodeCase {
        DecodeCase {
            name,
            role: "formula",
            bytes,
            expect_trap: None,
        }
    }
    fn bad(name: &'static str, bytes: Vec<u8>, code: GrainTrap) -> DecodeCase {
        DecodeCase {
            name,
            role: "formula",
            bytes,
            expect_trap: Some(code.code()),
        }
    }

    let mut deep = a(0);
    for i in 1..=10u64 {
        deep = c2(a(i), deep);
    }

    vec![
        ok("atom_zero", e(&a(0))),
        ok("atom_one", e(&a(1))),
        ok("atom_42", e(&a(42))),
        ok("atom_256", e(&a(256))),
        ok("atom_word_boundary_8", e(&big_atom(8, 0xAB))),
        ok("atom_word_boundary_9", e(&big_atom(9, 0xAB))),
        ok("cell_pair", e(&c2(a(0), a(1)))),
        ok("cell_nested_right", e(&c2(a(1), c2(a(2), a(3))))),
        ok("cell_nested_left", e(&c2(c2(a(1), a(2)), a(3)))),
        ok("cell_right_list_depth_10", e(&deep)),
        bad("empty_input", vec![], GrainTrap::MalformedBytes),
        bad("bad_tag", vec![0x02], GrainTrap::MalformedBytes),
        bad(
            "truncated_length",
            vec![0x00, 0x01, 0x00],
            GrainTrap::MalformedBytes,
        ),
        bad(
            "truncated_payload",
            vec![0x00, 0x04, 0x00, 0x00, 0x00, 0xAA, 0xBB],
            GrainTrap::MalformedBytes,
        ),
        bad(
            "truncated_cell_missing_tail",
            {
                let mut b = vec![0x01];
                b.extend_from_slice(&e(&a(1)));
                b
            },
            GrainTrap::MalformedBytes,
        ),
        bad(
            "trailing_byte",
            {
                let mut b = e(&a(1));
                b.push(0x00);
                b
            },
            GrainTrap::MalformedBytes,
        ),
        bad(
            "nonminimal_atom_leading_zero_byte",
            vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00],
            GrainTrap::MalformedBytes,
        ),
        bad(
            "nonminimal_zero_as_one_byte",
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            GrainTrap::MalformedBytes,
        ),
        // Atom bound is checked BEFORE the remaining-input check.
        bad(
            "atom_length_max_u32",
            vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF],
            GrainTrap::NounOversized,
        ),
        bad(
            "atom_length_65537",
            {
                let mut b = vec![0x00];
                b.extend_from_slice(&65_537u32.to_le_bytes());
                b
            },
            GrainTrap::NounOversized,
        ),
        DecodeCase {
            name: "formula_oversized_total_length",
            role: "formula",
            bytes: e(&big_atom(65_532, 0x01)),
            expect_trap: Some(GrainTrap::FormulaOversized.code()),
        },
    ]
}

// ---------------------------------------------------------------------------
// Hint-erasure cases (schema noos/grain/hint-erasure-v1)
// ---------------------------------------------------------------------------

pub fn hint_cases() -> Vec<HintCase> {
    fn pair(
        name: &'static str,
        s: &Noun,
        hinted: &Noun,
        erased: &Noun,
        meter_limit: u64,
        outcome: Outcome,
        charge: u64,
    ) -> HintCase {
        HintCase {
            name,
            subject: e(s),
            hinted: e(hinted),
            erased: e(erased),
            meter_limit,
            arena_limit: ARENA,
            expect: Expect { outcome, charge },
        }
    }

    let quote42 = c2(a(1), a(42));
    let hinted_value = c2(a(11), c2(c2(a(1), a(1)), quote42.clone()));

    let inc5 = c2(a(4), c2(a(1), a(5)));
    let hinted_alloc = c2(a(11), c2(a(0), inc5.clone()));

    let quote7 = c2(a(1), a(7));
    let inner_hint = c2(a(11), c2(c2(a(1), a(1)), quote7.clone()));
    let nested_hint = c2(a(11), c2(a(0), inner_hint));

    let slot0 = c2(a(0), a(0));
    let hinted_trap = c2(a(11), c2(a(0), slot0.clone()));

    let self_apply = c2(a(2), c2(c2(a(0), a(1)), c2(a(0), a(1))));
    let hinted_loop = c2(a(11), c2(a(0), self_apply.clone()));

    vec![
        pair(
            "erase_preserves_value",
            &a(0),
            &hinted_value,
            &quote42,
            METER,
            Outcome::Value(e(&a(42))),
            1,
        ),
        pair(
            "erase_preserves_allocation_charge",
            &a(0),
            &hinted_alloc,
            &inc5,
            METER,
            Outcome::Value(e(&a(6))),
            6,
        ),
        pair(
            "erase_nested_hints",
            &a(0),
            &nested_hint,
            &quote7,
            METER,
            Outcome::Value(e(&a(7))),
            1,
        ),
        pair(
            "erase_preserves_trap",
            &a(0),
            &hinted_trap,
            &slot0,
            METER,
            Outcome::Trap(GrainTrap::InvalidAxis.code()),
            0,
        ),
        pair(
            "erase_preserves_meter_exhaustion",
            &self_apply,
            &hinted_loop,
            &self_apply,
            100,
            Outcome::Trap(GrainTrap::MeterExhausted.code()),
            100,
        ),
    ]
}

// ---------------------------------------------------------------------------
// JSON emission (hand-rolled: content is fully controlled ASCII)
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn expect_json(expect: &Expect) -> String {
    match &expect.outcome {
        Outcome::Value(noun) => format!(
            "{{\"kind\":\"value\",\"noun\":\"{}\",\"trap_code\":null,\"charge\":{}}}",
            hex(noun),
            expect.charge
        ),
        Outcome::Trap(code) => format!(
            "{{\"kind\":\"trap\",\"noun\":null,\"trap_code\":{},\"charge\":{}}}",
            code, expect.charge
        ),
    }
}

fn expect_kind(expect: &Expect) -> &'static str {
    match expect.outcome {
        Outcome::Value(_) => "positive",
        Outcome::Trap(_) => "negative",
    }
}

/// `grain-eval-v1.json` (schema noos/grain/eval-v1). `bytes` == `formula`.
pub fn eval_json() -> String {
    let mut out = String::from("{\n  \"schema\": \"noos/grain/eval-v1\",\n  \"cases\": [\n");
    let cases = eval_cases();
    for (i, c) in cases.iter().enumerate() {
        let sep = if i.saturating_add(1) == cases.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"kind\":\"{}\",\"bytes\":\"{}\",\"subject\":\"{}\",\"formula\":\"{}\",\"version\":{},\"meter_limit\":{},\"arena_limit\":{},\"expect\":{}}}{}\n",
            c.name,
            expect_kind(&c.expect),
            hex(&c.formula),
            hex(&c.subject),
            hex(&c.formula),
            c.version,
            c.meter_limit,
            c.arena_limit,
            expect_json(&c.expect),
            sep,
        ));
    }
    out.push_str("  ]\n}\n");
    out
}

/// `grain-noun-bytes-v1.json` (schema noos/grain/noun-bytes-v1).
pub fn decode_json() -> String {
    let mut out = String::from("{\n  \"schema\": \"noos/grain/noun-bytes-v1\",\n  \"cases\": [\n");
    let cases = decode_cases();
    for (i, c) in cases.iter().enumerate() {
        let sep = if i.saturating_add(1) == cases.len() {
            ""
        } else {
            ","
        };
        let (kind, expect) = match c.expect_trap {
            None => (
                "positive",
                "{\"kind\":\"noun\",\"trap_code\":null}".to_string(),
            ),
            Some(code) => (
                "negative",
                format!("{{\"kind\":\"trap\",\"trap_code\":{code}}}"),
            ),
        };
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"kind\":\"{}\",\"bytes\":\"{}\",\"role\":\"{}\",\"expect\":{}}}{}\n",
            c.name,
            kind,
            hex(&c.bytes),
            c.role,
            expect,
            sep,
        ));
    }
    out.push_str("  ]\n}\n");
    out
}

/// `grain-hint-erasure-v1.json` (schema noos/grain/hint-erasure-v1).
/// `bytes` == the hinted formula.
pub fn hint_json() -> String {
    let mut out =
        String::from("{\n  \"schema\": \"noos/grain/hint-erasure-v1\",\n  \"cases\": [\n");
    let cases = hint_cases();
    for (i, c) in cases.iter().enumerate() {
        let sep = if i.saturating_add(1) == cases.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"kind\":\"{}\",\"bytes\":\"{}\",\"subject\":\"{}\",\"erased_formula\":\"{}\",\"meter_limit\":{},\"arena_limit\":{},\"expect\":{}}}{}\n",
            c.name,
            expect_kind(&c.expect),
            hex(&c.hinted),
            hex(&c.subject),
            hex(&c.erased),
            c.meter_limit,
            c.arena_limit,
            expect_json(&c.expect),
            sep,
        ));
    }
    out.push_str("  ]\n}\n");
    out
}
