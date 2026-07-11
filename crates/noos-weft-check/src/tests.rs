//! Unit tests, conformance-vector execution (from the source table AND from
//! the frozen JSON on disk), and the seeded false-accept mutation battery
//! (weft-v0.md §8; plan §5.5 "pass its false-accept gate first").

// Test-only module: hard assertions are the desired failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::objects::{
    BeaconPolicy, CostBranch, CostCertificateV0, CostTerm, Exponents, FormulaBytes, JetStatus,
    ObjectKind, ProfileName, SizeList, SizeVarDecl, SizeVarList, SizeVarName, SubjectBytes,
    TargetTriple, TermList, TrialList, TypeSignature, WeftObjectV0,
};
use crate::vectors::{
    build_fixture, cost_cases, execute, foreign_cost_certificate, foreign_jet_certificate,
    inc_chain_charge, inc_chain_formula, profile_cases, refs_cases, CheckCase, Expect, Fixture,
    FixtureParams,
};
use crate::{certified_bound, content_id, domain_hash, domains, WeftError, WeftStoreV0, ZERO_HASH};
use noos_codec::{NoosDecode, NoosEncode};

// ---------------------------------------------------------------------------
// Deterministic seeded PRNG (splitmix64) for the battery
// ---------------------------------------------------------------------------

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
}

fn seeded_params(rng: &mut SplitMix64) -> FixtureParams {
    let inc_depth = rng.in_range(2, 9);
    FixtureParams {
        inc_depth,
        slack: rng.next_u64() % inc_depth.min(4),
        var_max: inc_depth + rng.in_range(0, 60),
        subject_value: u8::try_from(rng.in_range(0, 40)).unwrap_or(5),
        bond: rng.in_range(1, u64::from(u32::MAX)),
        shape: (
            u32::try_from(rng.in_range(1, 65_535)).unwrap_or(32),
            u32::try_from(rng.in_range(1, 65_535)).unwrap_or(32),
            u32::try_from(rng.in_range(1, 65_535)).unwrap_or(32),
        ),
        reps: u16::try_from(rng.in_range(2, 8)).unwrap_or(2),
    }
}

// ---------------------------------------------------------------------------
// Basic laws
// ---------------------------------------------------------------------------

#[test]
fn objects_round_trip_canonically() {
    let fx = build_fixture(&FixtureParams::default());
    macro_rules! rt {
        ($obj:expr, $ty:ty) => {{
            let bytes = $obj.encode_canonical();
            let back = <$ty as NoosDecode>::decode_canonical(&bytes).expect("round trip");
            assert_eq!(back, $obj.clone());
        }};
    }
    rt!(fx.profile, crate::NumericProfileV0);
    rt!(fx.cost, crate::CostCertificateV0);
    rt!(fx.jet, crate::JetCertificateV0);
    rt!(fx.meaning, crate::MeaningContractV0);
    rt!(fx.span, crate::SpanStatementV0);
}

#[test]
fn content_ids_are_domain_separated_and_distinct() {
    let fx = build_fixture(&FixtureParams::default());
    let ids = [
        content_id(&WeftObjectV0::Profile(fx.profile.clone())),
        content_id(&WeftObjectV0::Cost(fx.cost.clone())),
        content_id(&WeftObjectV0::Jet(fx.jet.clone())),
        content_id(&WeftObjectV0::Meaning(fx.meaning.clone())),
        content_id(&WeftObjectV0::Span(fx.span.clone())),
    ];
    for (i, a) in ids.iter().enumerate() {
        assert_ne!(*a, ZERO_HASH);
        for b in &ids[i + 1..] {
            assert_ne!(a, b, "content ids must be pairwise distinct");
        }
    }
    // The same bytes under two registered domains give different ids.
    let bytes = fx.profile.encode_canonical();
    assert_ne!(
        domain_hash(domains::WEFT_PROFILE, &[&bytes]),
        domain_hash(domains::WEFT_MEANING, &[&bytes]),
    );
}

#[test]
fn error_codes_round_trip_and_are_unique() {
    for e in WeftError::ALL {
        assert_eq!(WeftError::from_code(e.code()), Some(*e));
    }
    let mut codes: Vec<u16> = WeftError::ALL.iter().map(|e| e.code()).collect();
    let mut classes: Vec<&str> = WeftError::ALL.iter().map(|e| e.class_name()).collect();
    codes.sort_unstable();
    codes.dedup();
    classes.sort_unstable();
    classes.dedup();
    assert_eq!(codes.len(), WeftError::ALL.len(), "duplicate error code");
    assert_eq!(classes.len(), WeftError::ALL.len(), "duplicate error class");
    assert_eq!(WeftError::from_code(0), None, "zero is reserved");
}

#[test]
fn inc_chain_charge_matches_grain_meter_exactly() {
    for depth in [2_u64, 3, 7, 20] {
        let bytes = inc_chain_formula(depth);
        let formula = noos_grain::decode_formula(&bytes).expect("fixture formula decodes");
        let subject =
            noos_grain::decode_subject(&noos_grain::encode_noun(&noos_grain::Noun::atom_u64(5)))
                .expect("fixture subject decodes");
        let mut meter = noos_grain::Meter::new(1_000_000, 1_000_000);
        noos_grain::eval(1, subject, formula, &mut meter).expect("fixture evaluates");
        assert_eq!(
            meter.spent(),
            inc_chain_charge(depth),
            "frozen charge law at depth {depth}"
        );
    }
}

#[test]
fn certified_bound_takes_the_branch_max() {
    let cert = CostCertificateV0 {
        formula_id: [1; 32],
        grain_version: 1,
        size_vars: SizeVarList(vec![SizeVarDecl {
            name: SizeVarName(b"n".to_vec()),
            max_value: 100,
        }]),
        branches: crate::objects::BranchList(vec![
            CostBranch {
                terms: TermList(vec![CostTerm {
                    coeff: 1,
                    exponents: Exponents(vec![2]),
                }]),
            },
            CostBranch {
                terms: TermList(vec![CostTerm {
                    coeff: 100,
                    exponents: Exponents(vec![0]),
                }]),
            },
        ]),
        formula_bytes: FormulaBytes(Vec::new()),
        trials: TrialList(Vec::new()),
    };
    // Small n: the constant branch dominates. Large n: the quadratic one.
    assert_eq!(certified_bound(&cert, &[5]).expect("bound"), 100);
    assert_eq!(certified_bound(&cert, &[20]).expect("bound"), 400);
}

#[test]
fn certified_bound_rejects_overflow_with_checked_arithmetic() {
    let cert = CostCertificateV0 {
        formula_id: [1; 32],
        grain_version: 1,
        size_vars: SizeVarList(vec![SizeVarDecl {
            name: SizeVarName(b"n".to_vec()),
            max_value: u64::MAX,
        }]),
        branches: crate::objects::BranchList(vec![CostBranch {
            terms: TermList(vec![CostTerm {
                coeff: crate::MAX_COST_COEFF,
                exponents: Exponents(vec![4]),
            }]),
        }]),
        formula_bytes: FormulaBytes(Vec::new()),
        trials: TrialList(Vec::new()),
    };
    assert_eq!(
        certified_bound(&cert, &[u64::MAX]),
        Err(WeftError::CertBoundOverflow)
    );
    // Above u64::MAX but inside u128 is still an overflow of the meter type.
    let narrow = CostCertificateV0 {
        size_vars: SizeVarList(vec![SizeVarDecl {
            name: SizeVarName(b"n".to_vec()),
            max_value: u64::MAX,
        }]),
        branches: crate::objects::BranchList(vec![CostBranch {
            terms: TermList(vec![CostTerm {
                coeff: 2,
                exponents: Exponents(vec![1]),
            }]),
        }]),
        ..cert
    };
    assert_eq!(
        certified_bound(&narrow, &[u64::MAX]),
        Err(WeftError::CertBoundOverflow)
    );
}

#[test]
fn store_admission_is_idempotent_and_dependency_ordered() {
    let fx = build_fixture(&FixtureParams::default());
    let mut store = WeftStoreV0::new();
    // Out of dependency order: the meaning contract cannot resolve yet.
    assert_eq!(
        store.admit(WeftObjectV0::Meaning(fx.meaning.clone())),
        Err(WeftError::McProfileUnresolved)
    );
    let pid = store
        .admit(WeftObjectV0::Profile(fx.profile.clone()))
        .expect("profile");
    let cid = store
        .admit(WeftObjectV0::Cost(fx.cost.clone()))
        .expect("cost");
    let jid = store.admit(WeftObjectV0::Jet(fx.jet.clone())).expect("jet");
    store
        .admit(WeftObjectV0::Meaning(fx.meaning.clone()))
        .expect("meaning");
    store
        .admit(WeftObjectV0::Span(fx.span.clone()))
        .expect("span");
    assert_eq!((pid, cid, jid), (fx.profile_id, fx.cost_id, fx.jet_id));
    assert_eq!(store.len(), 5);
    // Idempotent re-admission.
    assert_eq!(
        store.admit(WeftObjectV0::Profile(fx.profile.clone())),
        Ok(pid)
    );
    assert_eq!(store.len(), 5);
}

/// Raw Grain remains valid forever: the checker constrains only Weft
/// artifacts. A bare formula evaluates with no store, no certificate, no
/// artifact — v0 adds data about formulas, never gates on them.
#[test]
fn raw_grain_needs_no_weft_artifact() {
    let bytes = inc_chain_formula(3);
    let formula = noos_grain::decode_formula(&bytes).expect("raw formula decodes");
    let subject = noos_grain::Noun::atom_u64(9);
    let mut meter = noos_grain::Meter::new(1_000, 1_000);
    let out = noos_grain::eval(1, subject, formula, &mut meter).expect("raw formula runs");
    assert_eq!(out.as_atom(), Some(&12_u8.to_le_bytes()[..1]));
}

// ---------------------------------------------------------------------------
// Conformance vectors: source table and frozen JSON must both pass
// ---------------------------------------------------------------------------

fn run_case(case: &CheckCase) {
    let got = execute(case.object, &case.bytes, &case.store);
    match (&case.expect, got) {
        (Expect::Accept(id), Ok(got_id)) => {
            assert_eq!(got_id, *id, "case {}: wrong content id", case.name);
        }
        (Expect::Reject(err), Err(got_err)) => {
            assert_eq!(got_err, *err, "case {}: wrong rejection", case.name);
        }
        (Expect::Accept(_), Err(err)) => panic!("case {}: unexpected reject {err}", case.name),
        (Expect::Reject(err), Ok(_)) => {
            panic!("case {}: FALSE ACCEPT (expected {err})", case.name)
        }
    }
}

#[test]
fn vector_tables_pass() {
    let all: Vec<CheckCase> = profile_cases()
        .into_iter()
        .chain(cost_cases())
        .chain(refs_cases())
        .collect();
    assert!(
        all.len() >= 30,
        "the frozen suite must carry at least 30 vectors"
    );
    let mut names: Vec<&str> = all.iter().map(|c| c.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), all.len(), "vector names must be unique");
    for case in &all {
        run_case(case);
    }
}

fn vectors_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors/weft")
}

#[test]
fn frozen_json_vectors_match_and_pass() {
    let files = [
        (
            "weft-profile-v0.json",
            crate::vectors::profile_json(),
            profile_cases().len(),
        ),
        (
            "weft-cost-v0.json",
            crate::vectors::cost_json(),
            cost_cases().len(),
        ),
        (
            "weft-refs-v0.json",
            crate::vectors::refs_json(),
            refs_cases().len(),
        ),
    ];
    for (name, expected_content, case_count) in files {
        let path = vectors_dir().join(name);
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read frozen vectors {}: {e}", path.display()));
        // The emitted file is byte-identical to the source table (modulo
        // line endings a checkout may impose).
        assert_eq!(
            on_disk.replace("\r\n", "\n"),
            expected_content,
            "{name} drifted from the source table; regenerate via gen_vectors"
        );

        // Independently re-execute every case from the JSON itself.
        let doc: serde_json::Value =
            serde_json::from_str(&on_disk).unwrap_or_else(|e| panic!("{name}: bad JSON: {e}"));
        let cases = doc["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: no cases"));
        assert_eq!(cases.len(), case_count, "{name}: case count drifted");
        for case in cases {
            let cname = case["name"].as_str().expect("name");
            let object = case["object"].as_str().expect("object");
            let bytes = unhex(case["bytes"].as_str().expect("bytes"));
            let store: Vec<(ObjectKind, Vec<u8>)> = case["store"]
                .as_array()
                .expect("store")
                .iter()
                .map(|e| {
                    let kind = ObjectKind::from_name(e["object"].as_str().expect("store object"))
                        .expect("store kind");
                    (kind, unhex(e["bytes"].as_str().expect("store bytes")))
                })
                .collect();
            let got = execute(object, &bytes, &store);
            let expect = &case["expect"];
            match expect["result"].as_str().expect("result") {
                "accept" => {
                    let id = got.unwrap_or_else(|e| panic!("{name}/{cname}: rejected: {e}"));
                    assert_eq!(hex(&id), expect["content_id"].as_str().expect("content_id"));
                }
                "reject" => {
                    let err = match got {
                        Err(e) => e,
                        Ok(_) => panic!("{name}/{cname}: FALSE ACCEPT"),
                    };
                    assert_eq!(
                        u64::from(err.code()),
                        expect["error_code"].as_u64().expect("error_code"),
                        "{name}/{cname}"
                    );
                    assert_eq!(
                        err.class_name(),
                        expect["error_class"].as_str().expect("error_class"),
                        "{name}/{cname}"
                    );
                }
                other => panic!("{name}/{cname}: unknown result {other}"),
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// The false-accept mutation battery (weft-v0.md §8)
// ---------------------------------------------------------------------------

struct Attempt {
    object: &'static str,
    bytes: Vec<u8>,
    store: Vec<(ObjectKind, Vec<u8>)>,
}

type MutationFn = Box<dyn Fn(&Fixture, &mut SplitMix64) -> Attempt>;

struct MutationClass {
    name: &'static str,
    /// The stable codes this class is allowed to land on. Any code outside
    /// the set — and above all any ACCEPT — fails the battery.
    expected: &'static [u16],
    apply: MutationFn,
}

fn full_store(fx: &Fixture) -> Vec<(ObjectKind, Vec<u8>)> {
    vec![
        (ObjectKind::NumericProfile, fx.profile.encode_canonical()),
        (ObjectKind::CostCertificate, fx.cost.encode_canonical()),
        (ObjectKind::JetCertificate, fx.jet.encode_canonical()),
    ]
}

fn patch_u16(bytes: &[u8], offset: usize, value: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    out
}

fn patch_u32(bytes: &[u8], offset: usize, value: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    out
}

#[allow(clippy::too_many_lines)]
fn mutation_classes() -> Vec<MutationClass> {
    fn class(
        name: &'static str,
        expected: &'static [u16],
        apply: impl Fn(&Fixture, &mut SplitMix64) -> Attempt + 'static,
    ) -> MutationClass {
        MutationClass {
            name,
            expected,
            apply: Box::new(apply),
        }
    }

    let profile_attempt = |bytes: Vec<u8>| Attempt {
        object: ObjectKind::NumericProfile.name(),
        bytes,
        store: Vec::new(),
    };
    let cost_attempt = |bytes: Vec<u8>| Attempt {
        object: ObjectKind::CostCertificate.name(),
        bytes,
        store: Vec::new(),
    };

    vec![
        // ---- envelope / codec confusion ------------------------------------
        class("version-bump", &[6], move |fx, _| {
            profile_attempt(patch_u16(&fx.profile.encode_canonical(), 0, 1))
        }),
        class("tag-confusion", &[4], move |fx, _| {
            profile_attempt(patch_u16(&fx.profile.encode_canonical(), 2, 2))
        }),
        class("truncate-tail", &[1], move |fx, rng| {
            let bytes = fx.profile.encode_canonical();
            let cut = 1 + usize::try_from(rng.in_range(0, 3)).unwrap_or(1);
            profile_attempt(bytes[..bytes.len() - cut].to_vec())
        }),
        class("append-trailing", &[2], move |fx, rng| {
            let mut bytes = fx.profile.encode_canonical();
            bytes.push(u8::try_from(rng.in_range(0, 255)).unwrap_or(0));
            profile_attempt(bytes)
        }),
        class("collection-length-overflow", &[5], move |fx, _| {
            // size_vars length prefix at frozen offset 44 (weft-v0.md §4.2).
            cost_attempt(patch_u32(&fx.cost.encode_canonical(), 44, 9))
        }),
        class("enum-discriminant-out-of-range", &[7], move |fx, rng| {
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                // beacon_policy u16 at frozen offset 106 (weft-v0.md §4.5).
                bytes: patch_u16(
                    &fx.span.encode_canonical(),
                    106,
                    u16::try_from(rng.in_range(2, 400)).unwrap_or(2),
                ),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        // ---- numeric profile -------------------------------------------------
        class("profile-width-tamper", &[21], move |fx, _| {
            let mut p = fx.profile.clone();
            p.weight_bits = 16;
            profile_attempt(p.encode_canonical())
        }),
        class("profile-accum-inexact", &[22], move |fx, _| {
            let mut p = fx.profile.clone();
            p.accum_exact = 0;
            profile_attempt(p.encode_canonical())
        }),
        class("profile-requant-invalid", &[23], move |fx, rng| {
            let mut p = fx.profile.clone();
            if rng.next_u64() % 2 == 0 {
                p.requant_shift = 0;
            } else {
                p.requant_mult = 0;
            }
            profile_attempt(p.encode_canonical())
        }),
        class("profile-saturate-tamper", &[24], move |fx, _| {
            let mut p = fx.profile.clone();
            p.saturate_min_twos = 0x81;
            profile_attempt(p.encode_canonical())
        }),
        class("profile-forbid-cleared", &[25], move |fx, rng| {
            let mut p = fx.profile.clone();
            p.forbid_flags = u32::try_from(rng.in_range(0, 14)).unwrap_or(0);
            profile_attempt(p.encode_canonical())
        }),
        class("profile-name-invalid", &[20], move |fx, _| {
            let mut p = fx.profile.clone();
            p.name = ProfileName(b"1nvalid".to_vec());
            profile_attempt(p.encode_canonical())
        }),
        // ---- cost certificate (the certificate law) ---------------------------
        class("cert-grain-version", &[40], move |fx, _| {
            let mut c = fx.cost.clone();
            c.grain_version = 2;
            cost_attempt(c.encode_canonical())
        }),
        class("cert-bound-understatement", &[57], move |fx, _| {
            let mut c = fx.cost.clone();
            c.branches.0[0].terms.0[0].coeff = 4; // real slope is 5
            cost_attempt(c.encode_canonical())
        }),
        class("cert-degree-inflation", &[45], move |fx, _| {
            let mut c = fx.cost.clone();
            c.branches.0[0].terms.0[0].exponents = Exponents(vec![5]);
            cost_attempt(c.encode_canonical())
        }),
        class("cert-coeff-zero", &[46], move |fx, _| {
            let mut c = fx.cost.clone();
            c.branches.0[0].terms.0[0].coeff = 0;
            cost_attempt(c.encode_canonical())
        }),
        class("cert-coeff-over-max", &[46], move |fx, _| {
            let mut c = fx.cost.clone();
            c.branches.0[0].terms.0[0].coeff = crate::MAX_COST_COEFF + 1;
            cost_attempt(c.encode_canonical())
        }),
        class("cert-term-arity", &[44], move |fx, _| {
            let mut c = fx.cost.clone();
            c.branches.0[0].terms.0[0].exponents = Exponents(vec![1, 1]);
            cost_attempt(c.encode_canonical())
        }),
        class("cert-bound-overflow", &[47], move |fx, _| {
            let mut c = fx.cost.clone();
            c.size_vars.0[0].max_value = u64::MAX;
            c.branches.0[0].terms.0[0].coeff = crate::MAX_COST_COEFF;
            c.branches.0[0].terms.0[0].exponents = Exponents(vec![4]);
            cost_attempt(c.encode_canonical())
        }),
        class("cert-formula-id-tamper", &[49], move |fx, rng| {
            let mut c = fx.cost.clone();
            let byte = usize::try_from(rng.in_range(0, 31)).unwrap_or(0);
            c.formula_id[byte] ^= 0x5a;
            cost_attempt(c.encode_canonical())
        }),
        class("cert-formula-malformed", &[48], move |fx, _| {
            let mut c = fx.cost.clone();
            c.formula_bytes.0[0] = 0x02;
            cost_attempt(c.encode_canonical())
        }),
        class("cert-trial-subject-malformed", &[54], move |fx, _| {
            let mut c = fx.cost.clone();
            c.trials.0[0].subject = SubjectBytes(vec![0xff]);
            cost_attempt(c.encode_canonical())
        }),
        class("cert-trial-size-out-of-range", &[53], move |fx, _| {
            let mut c = fx.cost.clone();
            c.trials.0[0].sizes = SizeList(vec![c.size_vars.0[0].max_value + 1]);
            cost_attempt(c.encode_canonical())
        }),
        class("cert-trials-dropped", &[50], move |fx, _| {
            let mut c = fx.cost.clone();
            c.trials = TrialList(Vec::new());
            cost_attempt(c.encode_canonical())
        }),
        class("cert-trials-without-formula", &[51], move |fx, _| {
            let mut c = fx.cost.clone();
            c.formula_bytes = FormulaBytes(Vec::new());
            cost_attempt(c.encode_canonical())
        }),
        class("cert-trial-budget-bomb", &[55], move |fx, _| {
            let mut c = fx.cost.clone();
            c.branches.0[0].terms.0[0].coeff = crate::MAX_TRIAL_CHARGE + 1;
            cost_attempt(c.encode_canonical())
        }),
        class("cert-trial-trap", &[56], move |fx, _| {
            let mut c = fx.cost.clone();
            let cell = match noos_grain::Noun::cell(
                noos_grain::Noun::atom_u64(0),
                noos_grain::Noun::atom_u64(0),
            ) {
                Ok(n) => n,
                Err(_) => unreachable!("two-atom cell within bounds"),
            };
            c.trials.0[0].subject = SubjectBytes(noos_grain::encode_noun(&cell));
            cost_attempt(c.encode_canonical())
        }),
        class("cert-size-var-duplicate", &[42], move |fx, _| {
            let mut c = fx.cost.clone();
            let v = c.size_vars.0[0].clone();
            c.size_vars.0.push(v);
            cost_attempt(c.encode_canonical())
        }),
        // ---- meaning contract: reference integrity -----------------------------
        class("mc-cost-reference-transplant", &[66], move |fx, _| {
            let foreign = foreign_cost_certificate();
            let mut m = fx.meaning.clone();
            m.cost_certificate_id = content_id(&WeftObjectV0::Cost(foreign.clone()));
            m.obligation_ids.0.clear();
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: vec![
                    (ObjectKind::NumericProfile, fx.profile.encode_canonical()),
                    (ObjectKind::CostCertificate, foreign.encode_canonical()),
                ],
            }
        }),
        class("mc-profile-reference-dangling", &[64], move |fx, rng| {
            let mut m = fx.meaning.clone();
            let byte = usize::try_from(rng.in_range(0, 31)).unwrap_or(0);
            m.profile_ids.0[0][byte] ^= 0xa5;
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("mc-profile-duplicate", &[63], move |fx, _| {
            let mut m = fx.meaning.clone();
            let p = m.profile_ids.0[0];
            m.profile_ids.0.push(p);
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("mc-obligation-transplant", &[69], move |fx, _| {
            let foreign = foreign_jet_certificate();
            let mut m = fx.meaning.clone();
            m.obligation_ids.0 = vec![content_id(&WeftObjectV0::Jet(foreign.clone()))];
            let mut store = full_store(fx);
            store.push((ObjectKind::JetCertificate, foreign.encode_canonical()));
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store,
            }
        }),
        class("mc-obligation-dangling", &[68], move |fx, _| {
            let mut m = fx.meaning.clone();
            m.obligation_ids.0[0][7] ^= 0x77;
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("mc-type-signature-invalid", &[62], move |fx, _| {
            let mut m = fx.meaning.clone();
            m.type_signature = TypeSignature(vec![0xc0, 0x00]);
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("mc-formula-id-zero", &[61], move |fx, _| {
            let mut m = fx.meaning.clone();
            m.formula_id = ZERO_HASH;
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("mc-grain-version", &[60], move |fx, _| {
            let mut m = fx.meaning.clone();
            m.grain_version = 0;
            Attempt {
                object: ObjectKind::MeaningContract.name(),
                bytes: m.encode_canonical(),
                store: full_store(fx),
            }
        }),
        // ---- jet certificate ------------------------------------------------
        class("jet-impl-hash-zero", &[82], move |fx, _| {
            let mut j = fx.jet.clone();
            j.impl_hash = ZERO_HASH;
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("jet-bond-zero", &[85], move |fx, _| {
            let mut j = fx.jet.clone();
            j.bond_micro_noos = 0;
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("jet-heights-inconsistent", &[86], move |fx, rng| {
            let mut j = fx.jet.clone();
            match rng.next_u64() % 3 {
                0 => j.admitted_height = 3, // Challengeable with a height
                1 => {
                    j.status = JetStatus::Admitted; // admitted without height
                }
                _ => {
                    j.status = JetStatus::Revoked;
                    j.admitted_height = 10;
                    j.revoked_height = 5; // revoked before admission
                }
            }
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("jet-target-invalid", &[83], move |fx, rng| {
            let mut j = fx.jet.clone();
            j.target_triple = if rng.next_u64() % 2 == 0 {
                TargetTriple(Vec::new())
            } else {
                TargetTriple(b"cuda sm90".to_vec())
            };
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("jet-corpus-zero", &[84], move |fx, _| {
            let mut j = fx.jet.clone();
            j.corpus_root = ZERO_HASH;
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: full_store(fx),
            }
        }),
        class("jet-cost-reference-transplant", &[89], move |fx, _| {
            let foreign = foreign_cost_certificate();
            let mut j = fx.jet.clone();
            j.cost_certificate_id = content_id(&WeftObjectV0::Cost(foreign.clone()));
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: vec![
                    (ObjectKind::NumericProfile, fx.profile.encode_canonical()),
                    (ObjectKind::CostCertificate, foreign.encode_canonical()),
                ],
            }
        }),
        class("jet-formula-id-zero", &[81], move |fx, _| {
            let mut j = fx.jet.clone();
            j.formula_id = ZERO_HASH;
            Attempt {
                object: ObjectKind::JetCertificate.name(),
                bytes: j.encode_canonical(),
                store: full_store(fx),
            }
        }),
        // ---- span statement --------------------------------------------------
        class("span-shape-overflow", &[100], move |fx, rng| {
            let mut s = fx.span.clone();
            s.shape_m = 65_536 + u32::try_from(rng.in_range(0, 1000)).unwrap_or(0);
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        class("span-shape-zero", &[100], move |fx, _| {
            let mut s = fx.span.clone();
            s.shape_n = 0;
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        class("span-soundness-understatement", &[103], move |fx, _| {
            let mut s = fx.span.clone();
            s.soundness_reps = 1;
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        class("span-beacon-offline", &[104], move |fx, _| {
            let mut s = fx.span.clone();
            s.beacon_policy = BeaconPolicy::OfflineDerived;
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        class("span-rbits-tamper", &[102], move |fx, _| {
            let mut s = fx.span.clone();
            s.soundness_reps = 4;
            s.soundness_rbits = 16;
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        class("span-verifier-zero", &[101], move |fx, _| {
            let mut s = fx.span.clone();
            s.verifier_ref = ZERO_HASH;
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
        class("span-profile-dangling", &[105], move |fx, rng| {
            let mut s = fx.span.clone();
            let byte = usize::try_from(rng.in_range(0, 31)).unwrap_or(0);
            s.profile_id[byte] ^= 0x3c;
            Attempt {
                object: ObjectKind::SpanStatement.name(),
                bytes: s.encode_canonical(),
                store: vec![(ObjectKind::NumericProfile, fx.profile.encode_canonical())],
            }
        }),
    ]
}

/// Seeded false-accept gate: valid bundles are generated, >= 20 mutation
/// classes are applied across every seed, and 100% of mutants must reject
/// with a stable code from the class's expected set. One accept fails the
/// gate (plan §5.5: "a false accept freezes Weft admission").
#[test]
fn mutation_battery_rejects_every_mutant() {
    const SEEDS: u64 = 16;
    let classes = mutation_classes();
    assert!(
        classes.len() >= 20,
        "battery must carry at least 20 mutation classes"
    );

    let mut attempts: u64 = 0;
    let mut rejected: u64 = 0;
    let mut false_accepts: Vec<String> = Vec::new();
    let mut wrong_codes: Vec<String> = Vec::new();

    for seed in 0..SEEDS {
        let mut rng = SplitMix64(0x0005_7ef7_0000 ^ (seed.wrapping_mul(0x9e37_79b9)));
        let params = seeded_params(&mut rng);
        let fx = build_fixture(&params);

        // Positive control: the unmutated bundle must fully admit.
        let mut store = WeftStoreV0::new();
        store
            .admit(WeftObjectV0::Profile(fx.profile.clone()))
            .expect("control profile");
        store
            .admit(WeftObjectV0::Cost(fx.cost.clone()))
            .expect("control cost");
        store
            .admit(WeftObjectV0::Jet(fx.jet.clone()))
            .expect("control jet");
        store
            .admit(WeftObjectV0::Meaning(fx.meaning.clone()))
            .expect("control meaning");
        store
            .admit(WeftObjectV0::Span(fx.span.clone()))
            .expect("control span");

        for class in &classes {
            let attempt = (class.apply)(&fx, &mut rng);
            attempts += 1;
            match execute(attempt.object, &attempt.bytes, &attempt.store) {
                Ok(id) => {
                    false_accepts.push(format!(
                        "seed {seed} class {} accepted (id {})",
                        class.name,
                        hex(&id)
                    ));
                }
                Err(err) => {
                    rejected += 1;
                    if !class.expected.contains(&err.code()) {
                        wrong_codes.push(format!(
                            "seed {seed} class {}: got {err}, expected one of {:?}",
                            class.name, class.expected
                        ));
                    }
                }
            }
        }
    }

    assert!(
        false_accepts.is_empty(),
        "FALSE ACCEPTS:\n{}",
        false_accepts.join("\n")
    );
    assert!(
        wrong_codes.is_empty(),
        "UNSTABLE ERROR CODES:\n{}",
        wrong_codes.join("\n")
    );
    assert_eq!(rejected, attempts);
    println!(
        "MUTATION_BATTERY classes={} seeds={SEEDS} attempts={attempts} rejected={rejected} \
         rejection_rate=100.00% false_accepts=0",
        classes.len()
    );
}
