use crate::vectors::{self, Expect, Outcome};
use crate::{
    decode_formula, decode_subject, encode_noun, eval, GrainTrap, Meter, Noun, GRAIN_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic xorshift64* PRNG (seeded; no host entropy anywhere).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n.max(1)).unwrap_or(0)
    }
}

fn a(v: u64) -> Noun {
    Noun::atom_u64(v)
}

fn c2(h: Noun, t: Noun) -> Noun {
    match Noun::cell(h, t) {
        Ok(n) => n,
        Err(_) => unreachable!("test noun exceeds depth bound"),
    }
}

/// Run one evaluation; return (encoded-value-or-trap-code, charge).
fn run(
    version: u32,
    s: &Noun,
    f: &Noun,
    meter_limit: u64,
    arena_limit: u64,
) -> (Result<Vec<u8>, u16>, u64) {
    let mut meter = Meter::new(meter_limit, arena_limit);
    match eval(version, s.clone(), f.clone(), &mut meter) {
        Ok(n) => (Ok(encode_noun(&n)), meter.spent()),
        Err(t) => (Err(t.code()), meter.spent()),
    }
}

/// The spec §14 eval-runner obligation, byte-in/byte-out.
fn run_eval_bytes(
    version: u32,
    subject: &[u8],
    formula: &[u8],
    meter_limit: u64,
    arena_limit: u64,
) -> (Result<Vec<u8>, u16>, u64) {
    if version != GRAIN_VERSION {
        return (Err(GrainTrap::UnknownVersion.code()), 0);
    }
    let s = match decode_subject(subject) {
        Ok(n) => n,
        Err(t) => return (Err(t.code()), 0),
    };
    let f = match decode_formula(formula) {
        Ok(n) => n,
        Err(t) => return (Err(t.code()), 0),
    };
    run(version, &s, &f, meter_limit, arena_limit)
}

fn expect_pair(expect: &Expect) -> (Result<Vec<u8>, u16>, u64) {
    match &expect.outcome {
        Outcome::Value(noun) => (Ok(noun.clone()), expect.charge),
        Outcome::Trap(code) => (Err(*code), expect.charge),
    }
}

/// Random noun bounded by node budget (structure fuzzing).
fn rand_noun(rng: &mut Rng, budget: &mut u32) -> Noun {
    if *budget == 0 || rng.below(3) == 0 {
        let n = rng.below(4);
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(rng.next() as u8);
        }
        Noun::atom_from_le_bytes(&bytes)
    } else {
        *budget = budget.saturating_sub(1);
        let h = rand_noun(rng, budget);
        let t = rand_noun(rng, budget);
        c2(h, t)
    }
}

/// Random *well-shaped* formula (may still trap dynamically), hint-decorated.
fn rand_formula(rng: &mut Rng, depth: u32) -> Noun {
    if depth == 0 {
        return c2(a(1), a(rng.below(64)));
    }
    let d = depth.saturating_sub(1);
    match rng.below(13) {
        0 => c2(a(0), a(rng.below(7).saturating_add(1))),
        1 => {
            let mut b = 3;
            c2(a(1), rand_noun(rng, &mut b))
        }
        2 => c2(a(2), c2(rand_formula(rng, d), rand_formula(rng, d))),
        3 => c2(a(3), rand_formula(rng, d)),
        4 => c2(a(4), rand_formula(rng, d)),
        5 => c2(a(5), c2(rand_formula(rng, d), rand_formula(rng, d))),
        6 => c2(
            a(6),
            c2(
                rand_formula(rng, d),
                c2(rand_formula(rng, d), rand_formula(rng, d)),
            ),
        ),
        7 => c2(a(7), c2(rand_formula(rng, d), rand_formula(rng, d))),
        8 => c2(a(8), c2(rand_formula(rng, d), rand_formula(rng, d))),
        9 => c2(
            a(9),
            c2(a(rng.below(7).saturating_add(1)), rand_formula(rng, d)),
        ),
        10 => c2(
            a(10),
            c2(
                c2(a(rng.below(7).saturating_add(1)), rand_formula(rng, d)),
                rand_formula(rng, d),
            ),
        ),
        11 => c2(rand_formula(rng, d), rand_formula(rng, d)), // cons
        _ => {
            let mut b = 2;
            let hint = rand_noun(rng, &mut b);
            c2(a(11), c2(hint, rand_formula(rng, d)))
        }
    }
}

/// Formula-syntax-aware hint erasure: rewrite `[11 h f]` to `erase(f)` in
/// every formula position; axes and quoted literals are data, untouched.
fn erase_hints(f: &Noun) -> Noun {
    let Some((head, arg)) = f.as_cell() else {
        return f.clone();
    };
    if head.is_cell() {
        // cons: both sides are formulas
        return c2(erase_hints(head), erase_hints(arg));
    }
    let op = match head.as_atom() {
        Some([]) => 0u8,
        Some(&[b]) => b,
        _ => return f.clone(),
    };
    let arg2 = |arg: &Noun, both: bool| -> Noun {
        match arg.as_cell() {
            Some((b, c)) if both => c2(erase_hints(b), erase_hints(c)),
            _ => arg.clone(),
        }
    };
    match op {
        0 | 1 => f.clone(),
        2 | 5 | 7 | 8 => c2(head.clone(), arg2(arg, true)),
        3 | 4 => c2(head.clone(), erase_hints(arg)),
        6 => match arg.as_cell() {
            Some((b, cd)) => match cd.as_cell() {
                Some((c, d)) => c2(
                    head.clone(),
                    c2(erase_hints(b), c2(erase_hints(c), erase_hints(d))),
                ),
                None => f.clone(),
            },
            None => f.clone(),
        },
        9 => match arg.as_cell() {
            Some((axis, c)) => c2(head.clone(), c2(axis.clone(), erase_hints(c))),
            None => f.clone(),
        },
        10 => match arg.as_cell() {
            Some((bc, d)) => match bc.as_cell() {
                Some((axis, c)) => c2(
                    head.clone(),
                    c2(c2(axis.clone(), erase_hints(c)), erase_hints(d)),
                ),
                None => f.clone(),
            },
            None => f.clone(),
        },
        11 => match arg.as_cell() {
            Some((_hint, inner)) => erase_hints(inner),
            None => f.clone(),
        },
        _ => f.clone(),
    }
}

// ---------------------------------------------------------------------------
// Conformance vectors (the frozen fixtures themselves)
// ---------------------------------------------------------------------------

#[test]
fn vector_eval_cases_conform() {
    for c in vectors::eval_cases() {
        let got = run_eval_bytes(
            c.version,
            &c.subject,
            &c.formula,
            c.meter_limit,
            c.arena_limit,
        );
        let want = expect_pair(&c.expect);
        assert_eq!(got, want, "eval vector `{}` diverged", c.name);
    }
}

#[test]
fn vector_decode_cases_conform() {
    for c in vectors::decode_cases() {
        let decode = match c.role {
            "subject" => decode_subject as fn(&[u8]) -> Result<Noun, GrainTrap>,
            _ => decode_formula as fn(&[u8]) -> Result<Noun, GrainTrap>,
        };
        match (decode(&c.bytes), c.expect_trap) {
            (Ok(n), None) => {
                assert_eq!(
                    encode_noun(&n),
                    c.bytes,
                    "decode vector `{}` not canonical",
                    c.name
                );
            }
            (Err(t), Some(code)) => {
                assert_eq!(t.code(), code, "decode vector `{}` wrong trap", c.name);
            }
            (Ok(_), Some(code)) => {
                panic!("decode vector `{}` accepted; wanted trap {code}", c.name)
            }
            (Err(t), None) => panic!("decode vector `{}` trapped {t}; wanted accept", c.name),
        }
    }
}

#[test]
fn vector_hint_cases_conform() {
    for c in vectors::hint_cases() {
        let hinted = run_eval_bytes(1, &c.subject, &c.hinted, c.meter_limit, c.arena_limit);
        let erased = run_eval_bytes(1, &c.subject, &c.erased, c.meter_limit, c.arena_limit);
        let want = expect_pair(&c.expect);
        assert_eq!(hinted, want, "hint vector `{}` (hinted) diverged", c.name);
        assert_eq!(erased, want, "hint vector `{}` (erased) diverged", c.name);
    }
}

#[test]
fn vector_suite_is_large_enough() {
    let total =
        vectors::eval_cases().len() + vectors::decode_cases().len() + vectors::hint_cases().len();
    assert!(total >= 60, "vector suite shrank to {total} cases");
}

#[test]
fn vector_json_matches_case_tables() {
    // Emission sanity: every case name appears exactly once in its file.
    let ej = vectors::eval_json();
    for c in vectors::eval_cases() {
        assert_eq!(ej.matches(&format!("\"name\":\"{}\"", c.name)).count(), 1);
    }
    let dj = vectors::decode_json();
    for c in vectors::decode_cases() {
        assert_eq!(dj.matches(&format!("\"name\":\"{}\"", c.name)).count(), 1);
    }
    let hj = vectors::hint_json();
    for c in vectors::hint_cases() {
        assert_eq!(hj.matches(&format!("\"name\":\"{}\"", c.name)).count(), 1);
    }
}

// ---------------------------------------------------------------------------
// Property: decode(encode(n)) == n
// ---------------------------------------------------------------------------

#[test]
fn prop_roundtrip_random_nouns() {
    let mut rng = Rng::new(0x6772_6169_6e01);
    for _ in 0..2000 {
        let mut budget = 40;
        let n = rand_noun(&mut rng, &mut budget);
        let bytes = encode_noun(&n);
        let back = match decode_subject(&bytes) {
            Ok(b) => b,
            Err(t) => panic!("roundtrip decode trapped {t}"),
        };
        assert_eq!(back, n, "decode(encode(n)) != n");
        assert_eq!(encode_noun(&back), bytes, "re-encode not byte-identical");
    }
}

// ---------------------------------------------------------------------------
// Property: hint erasure preserves (value-or-trap, charge)
// ---------------------------------------------------------------------------

#[test]
fn prop_hint_erasure_preserves_outcome_and_charge() {
    let mut rng = Rng::new(0x6772_6169_6e02);
    for i in 0..1500 {
        let f = rand_formula(&mut rng, 4);
        let mut budget = 10;
        let s = rand_noun(&mut rng, &mut budget);
        let erased = erase_hints(&f);
        let got_h = run(1, &s, &f, 5_000, 5_000);
        let got_e = run(1, &s, &erased, 5_000, 5_000);
        assert_eq!(
            got_h, got_e,
            "hint erasure changed outcome/charge at iteration {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property: meter monotonicity
// ---------------------------------------------------------------------------

#[test]
fn prop_meter_monotonicity() {
    let mut rng = Rng::new(0x6772_6169_6e03);
    let mut programs: Vec<(Noun, Noun)> = Vec::new();
    for _ in 0..200 {
        let f = rand_formula(&mut rng, 3);
        let mut budget = 8;
        let s = rand_noun(&mut rng, &mut budget);
        programs.push((s, f));
    }
    for (s, f) in programs {
        let (outcome, charge) = run(1, &s, &f, u64::MAX / 2, 100_000);
        if outcome == Err(GrainTrap::MeterExhausted.code()) {
            continue; // unbounded loop; pinning is covered by vectors
        }
        // Exactly at the charge: identical outcome, identical charge.
        assert_eq!(run(1, &s, &f, charge, 100_000), (outcome.clone(), charge));
        // Any lower limit: METER_EXHAUSTED with spent pinned to the limit.
        if charge > 0 {
            for limit in [charge - 1, charge / 2, 0] {
                assert_eq!(
                    run(1, &s, &f, limit, 100_000),
                    (Err(GrainTrap::MeterExhausted.code()), limit),
                    "meter not monotone at limit {limit} (charge {charge})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property: malformed-byte fuzz never panics
// ---------------------------------------------------------------------------

#[test]
fn prop_decode_fuzz_never_panics() {
    let mut rng = Rng::new(0x6772_6169_6e04);
    // Pure random byte strings.
    for _ in 0..4000 {
        let len = rng.below(64) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.next() as u8);
        }
        let _ = decode_formula(&bytes); // must return, never panic
        let _ = decode_subject(&bytes);
    }
    // Mutations of valid encodings: truncation, bit flips, appends.
    for _ in 0..1500 {
        let mut budget = 12;
        let n = rand_noun(&mut rng, &mut budget);
        let mut bytes = encode_noun(&n);
        match rng.below(3) {
            0 => {
                let cut = (rng.below(bytes.len() as u64 + 1)) as usize;
                bytes.truncate(cut);
            }
            1 => {
                if !bytes.is_empty() {
                    let i = rng.below(bytes.len() as u64) as usize;
                    bytes[i] ^= 1 << rng.below(8);
                }
            }
            _ => bytes.push(rng.next() as u8),
        }
        if let Ok(back) = decode_formula(&bytes) {
            // Anything accepted must still be canonical.
            assert_eq!(encode_noun(&back), bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Property: eval fuzz never panics (arbitrary noun shapes as programs)
// ---------------------------------------------------------------------------

#[test]
fn prop_eval_fuzz_never_panics() {
    let mut rng = Rng::new(0x6772_6169_6e05);
    for _ in 0..3000 {
        let mut b1 = 12;
        let mut b2 = 12;
        let s = rand_noun(&mut rng, &mut b1);
        let f = rand_noun(&mut rng, &mut b2);
        let _ = run(1, &s, &f, 2_000, 2_000); // must return, never panic
    }
}

// ---------------------------------------------------------------------------
// Unit: trap codes, version law, meter behavior, sharing
// ---------------------------------------------------------------------------

#[test]
fn trap_codes_are_stable() {
    let expected: [(u16, &str); 12] = [
        (1, "INVALID_AXIS"),
        (2, "TYPE_MISMATCH"),
        (3, "METER_EXHAUSTED"),
        (4, "MANDATORY_JET_UNAVAILABLE"),
        (5, "NOUN_OVERSIZED"),
        (6, "UNKNOWN_OPCODE"),
        (7, "UNKNOWN_VERSION"),
        (8, "MALFORMED_BYTES"),
        (9, "ATOM_BOUND"),
        (10, "ARENA_EXHAUSTED"),
        (11, "FORMULA_OVERSIZED"),
        (12, "SUBJECT_OVERSIZED"),
    ];
    for (code, name) in expected {
        let t = match GrainTrap::from_code(code) {
            Some(t) => t,
            None => panic!("missing trap code {code}"),
        };
        assert_eq!(t.code(), code);
        assert_eq!(t.name(), name);
    }
    assert_eq!(GrainTrap::from_code(0), None);
    assert_eq!(GrainTrap::from_code(13), None);
}

#[test]
fn unknown_version_traps_before_work() {
    for v in [0u32, 2, 3, u32::MAX] {
        let mut meter = Meter::new(1000, 1000);
        let r = eval(v, a(0), c2(a(1), a(0)), &mut meter);
        assert_eq!(r, Err(GrainTrap::UnknownVersion));
        assert_eq!(meter.spent(), 0);
    }
}

#[test]
fn meter_exhaustion_pins_spent_to_limit() {
    let mut meter = Meter::new(3, 1000);
    // quote (1) then a second eval needing more than remains
    let f = c2(a(4), c2(a(1), a(1))); // quote 1 + inc 3 + alloc 2 = 6 total
    let r = eval(1, a(0), f, &mut meter);
    assert_eq!(r, Err(GrainTrap::MeterExhausted));
    assert_eq!(meter.spent(), 3);
}

#[test]
fn slot_shares_structure_without_allocation() {
    let mut meter = Meter::new(1000, 1000);
    let big = c2(c2(a(1), a(2)), c2(a(3), a(4)));
    let r = eval(1, big, c2(a(0), a(2)), &mut meter);
    assert_eq!(r, Ok(c2(a(1), a(2))));
    assert_eq!(meter.arena_used(), 0, "slot must not allocate");
}

#[test]
fn opcode_12_never_interprets() {
    let mut meter = Meter::new(1000, 1000);
    let r = eval(1, a(0), c2(a(12), c2(a(1), a(0))), &mut meter);
    assert_eq!(r, Err(GrainTrap::UnknownOpcode));
    assert_eq!(meter.spent(), 0);
}

#[test]
fn deep_noun_teardown_does_not_recurse() {
    // A right-nested list far deeper than any safe recursion depth.
    let mut n = a(0);
    for i in 0..200_000u64 {
        n = c2(a(i), n);
    }
    assert_eq!(n.depth(), 200_000);
    drop(n); // iterative Drop: must not overflow the host stack

    // Decode roundtrip at a depth that fits MAX_SUBJECT_BYTES
    // (100_000 levels encode to 600_005 bytes <= 1 MiB).
    let mut m = a(0);
    for i in 0..100_000u64 {
        m = c2(a(i), m);
    }
    let bytes = encode_noun(&m);
    let back = match decode_subject(&bytes) {
        Ok(b) => b,
        Err(t) => panic!("deep decode trapped {t}"),
    };
    assert_eq!(back.depth(), 100_000);
    assert_eq!(encode_noun(&back), bytes);
    drop(back);
}
