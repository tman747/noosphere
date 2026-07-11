//! Conformance fixtures and vector definitions for `protocol/vectors/weft/`
//! (weft-v0.md §7).
//!
//! This module is the single source of truth for the frozen fixtures: the
//! `gen_vectors` binary serializes these cases to JSON, and the crate tests
//! execute every case against the checker — both directly from this table
//! and by re-reading the emitted JSON from disk.
//!
//! Case semantics (the runner obligation, frozen in weft-v0.md §7):
//! 1. Start from an empty [`WeftStoreV0`]; admit every `store` entry in
//!    order — each MUST be accepted (store entries are prerequisites, not
//!    the case under test).
//! 2. Resolve `object`; an unknown kind name is `UNKNOWN_OBJECT_KIND`.
//! 3. `admit_bytes(kind, bytes)`: a positive case must accept with exactly
//!    the recorded `content_id`; a negative case must reject with exactly
//!    the recorded `error_code`/`error_class`.

// Fixture module: every value here is a fully controlled, bounds-asserted
// fixture; hard failure is the desired mode (same posture as the sibling
// vector generators).
#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used
)]

use crate::objects::{
    BeaconPolicy, CostBranch, CostCertificateV0, CostTerm, CostTrial, Exponents, FormulaBytes,
    JetCertificateV0, JetStatus, JournalSchema, MeaningContractV0, NumericProfileV0, ObjectKind,
    ObligationRefList, ProfileName, ProfileRefList, RequantKind, SizeList, SizeVarDecl,
    SizeVarList, SizeVarName, SpanStatementV0, SubjectBytes, TargetTriple, TermList,
    TranscriptLayout, TrialList, TypeSignature, VerifierKind, WeftObjectV0,
};
use crate::{content_id, formula_id, Hash32, WeftError, WeftStoreV0, ZERO_HASH};
use noos_codec::NoosEncode;
use noos_grain::{encode_noun, Noun};

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

/// Deterministic fixture knobs. Every field is bounded so the resulting
/// bundle is always admissible; the mutation battery perturbs the encoded
/// objects, never these inputs.
#[derive(Debug, Clone)]
pub struct FixtureParams {
    /// Inc-chain depth `d` (2..=200): the formula is `[4 [4 … [0 1]]]`.
    pub inc_depth: u64,
    /// Constant slack added to the certified bound (< `inc_depth` so bound
    /// understatement by one coefficient step is always detectable).
    pub slack: u64,
    /// Declared maximum of the single size variable `n` (>= `inc_depth`).
    pub var_max: u64,
    /// Trial subject atom value (kept small so `inc` never grows the atom).
    pub subject_value: u8,
    /// Jet bond in micro-NOOS (nonzero).
    pub bond: u64,
    /// Span shape `(m, k, n)`, each in `1..=65535`.
    pub shape: (u32, u32, u32),
    /// Span Freivalds repetitions (2..=8 keeps `reps * 32 >= 64`).
    pub reps: u16,
}

impl Default for FixtureParams {
    fn default() -> Self {
        FixtureParams {
            inc_depth: 4,
            slack: 0,
            var_max: 64,
            subject_value: 5,
            bond: 50_000_000_000,
            shape: (32, 32, 32),
            reps: 2,
        }
    }
}

/// A complete admissible v0 bundle plus its canonical bytes and ids.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub profile: NumericProfileV0,
    pub cost: CostCertificateV0,
    pub jet: JetCertificateV0,
    pub meaning: MeaningContractV0,
    pub span: SpanStatementV0,
    pub formula_bytes: Vec<u8>,
    pub profile_id: Hash32,
    pub cost_id: Hash32,
    pub jet_id: Hash32,
}

/// Canonical Grain formula `[4 [4 … [0 1]]]` (`depth` nested incs applied
/// to the whole subject). Against a small-atom subject its exact charge is
/// `2 + 5 * depth` grain-steps (slot 2; per inc: base 2 + 1 word + alloc 2).
#[must_use]
pub fn inc_chain_formula(depth: u64) -> Vec<u8> {
    let atom = |v: u64| Noun::atom_u64(v);
    let cell = |h: Noun, t: Noun| match Noun::cell(h, t) {
        Ok(n) => n,
        Err(_) => unreachable!("fixture noun exceeds frozen depth"),
    };
    // [0 1]
    let mut f = cell(atom(0), atom(1));
    for _ in 0..depth {
        f = cell(atom(4), f);
    }
    encode_noun(&f)
}

/// Exact charge of [`inc_chain_formula`] against a one-byte-atom subject
/// whose value stays below 256 throughout (grain-v1.md §§7, 9, 10).
#[must_use]
pub fn inc_chain_charge(depth: u64) -> u64 {
    2 + 5 * depth
}

fn nonzero_hash(fill: u8) -> Hash32 {
    let mut h = [fill; 32];
    if fill == 0 {
        h[0] = 1;
    }
    h
}

/// Builds the canonical admissible bundle for `params`.
#[must_use]
pub fn build_fixture(params: &FixtureParams) -> Fixture {
    assert!(
        params.inc_depth >= 2 && params.inc_depth <= 200,
        "fixture inc_depth out of range"
    );
    assert!(
        params.slack < params.inc_depth,
        "fixture slack must stay below inc_depth"
    );
    assert!(
        params.var_max >= params.inc_depth,
        "fixture var_max below trial size"
    );
    assert!(
        u64::from(params.subject_value) + params.inc_depth < 256,
        "subject atom would grow"
    );

    let profile = NumericProfileV0 {
        name: ProfileName(b"W8A8v1".to_vec()),
        weight_bits: 8,
        activation_bits: 8,
        accum_bits: 32,
        accum_exact: 1,
        requant_kind: RequantKind::RoundHalfUpShift,
        requant_mult: 1_912_602_113,
        requant_shift: 8,
        saturate_min_twos: 0x80,
        saturate_max_twos: 0x7f,
        forbid_flags: crate::PROFILE_FORBID_REQUIRED,
    };
    let pid = content_id(&WeftObjectV0::Profile(profile.clone()));

    let formula_bytes = inc_chain_formula(params.inc_depth);
    let fid = formula_id(&formula_bytes);

    // bound(n) = max(5n + (2 + slack), 3n)  — two branches exercise the
    // frozen branch-`max` semantics; the first dominates on every n >= 1.
    let cost = CostCertificateV0 {
        formula_id: fid,
        grain_version: 1,
        size_vars: SizeVarList(vec![SizeVarDecl {
            name: SizeVarName(b"n".to_vec()),
            max_value: params.var_max,
        }]),
        branches: crate::objects::BranchList(vec![
            CostBranch {
                terms: TermList(vec![
                    CostTerm {
                        coeff: 5,
                        exponents: Exponents(vec![1]),
                    },
                    CostTerm {
                        coeff: 2 + params.slack,
                        exponents: Exponents(vec![0]),
                    },
                ]),
            },
            CostBranch {
                terms: TermList(vec![CostTerm {
                    coeff: 3,
                    exponents: Exponents(vec![1]),
                }]),
            },
        ]),
        formula_bytes: FormulaBytes(formula_bytes.clone()),
        trials: TrialList(vec![
            CostTrial {
                sizes: SizeList(vec![params.inc_depth]),
                subject: SubjectBytes(encode_noun(&Noun::atom_u64(u64::from(
                    params.subject_value,
                )))),
            },
            CostTrial {
                sizes: SizeList(vec![params.inc_depth]),
                subject: SubjectBytes(encode_noun(&Noun::atom_u64(0))),
            },
        ]),
    };
    let cid = content_id(&WeftObjectV0::Cost(cost.clone()));

    let jet = JetCertificateV0 {
        grain_version: 1,
        formula_id: fid,
        impl_hash: nonzero_hash(0x9d),
        target_triple: TargetTriple(b"cuda-sm90".to_vec()),
        profile_id: pid,
        cost_certificate_id: cid,
        corpus_root: nonzero_hash(0xc4),
        bond_micro_noos: params.bond,
        status: JetStatus::Challengeable,
        admitted_height: 0,
        revoked_height: 0,
    };
    let jid = content_id(&WeftObjectV0::Jet(jet.clone()));

    let meaning = MeaningContractV0 {
        formula_id: fid,
        grain_version: 1,
        compiler_id: ZERO_HASH,
        source_root: ZERO_HASH,
        type_signature: TypeSignature(
            b"fn inc_chain<n: Size>(x: u64) -> u64 cost 5*n + 2".to_vec(),
        ),
        profile_ids: ProfileRefList(vec![pid]),
        cost_certificate_id: cid,
        rv32_guest_hash: ZERO_HASH,
        obligation_ids: ObligationRefList(vec![jid]),
    };

    let span = SpanStatementV0 {
        profile_id: pid,
        shape_m: params.shape.0,
        shape_k: params.shape.1,
        shape_n: params.shape.2,
        transcript_layout: TranscriptLayout::Sha256FlatV0,
        verifier_kind: VerifierKind::GrainFormula,
        verifier_ref: fid,
        soundness_reps: params.reps,
        soundness_rbits: crate::SPAN_SHA256_FLAT_V0_RBITS,
        beacon_policy: BeaconPolicy::PostCommitRequired,
        journal_schema: JournalSchema::SpanV0,
    };

    Fixture {
        profile,
        cost,
        jet,
        meaning,
        span,
        formula_bytes,
        profile_id: pid,
        cost_id: cid,
        jet_id: jid,
    }
}

/// A second, independent cost certificate (unembedded) for a DIFFERENT
/// formula id — the transplant target of reference-integrity cases.
#[must_use]
pub fn foreign_cost_certificate() -> CostCertificateV0 {
    CostCertificateV0 {
        formula_id: nonzero_hash(0xaa),
        grain_version: 1,
        size_vars: SizeVarList(vec![SizeVarDecl {
            name: SizeVarName(b"k".to_vec()),
            max_value: 16,
        }]),
        branches: crate::objects::BranchList(vec![CostBranch {
            terms: TermList(vec![CostTerm {
                coeff: 7,
                exponents: Exponents(vec![2]),
            }]),
        }]),
        formula_bytes: FormulaBytes(Vec::new()),
        trials: TrialList(Vec::new()),
    }
}

/// A second jet certificate bound to a DIFFERENT formula id (no cost /
/// profile references, so it is admissible in any store).
#[must_use]
pub fn foreign_jet_certificate() -> JetCertificateV0 {
    JetCertificateV0 {
        grain_version: 1,
        formula_id: nonzero_hash(0xaa),
        impl_hash: nonzero_hash(0x4b),
        target_triple: TargetTriple(b"rv32im".to_vec()),
        profile_id: ZERO_HASH,
        cost_certificate_id: ZERO_HASH,
        corpus_root: nonzero_hash(0x11),
        bond_micro_noos: 1_000_000,
        status: JetStatus::Proposed,
        admitted_height: 0,
        revoked_height: 0,
    }
}

// ---------------------------------------------------------------------------
// Case shapes and the runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Expect {
    /// Must accept, with exactly this content id.
    Accept(Hash32),
    /// Must reject with exactly this stable error.
    Reject(WeftError),
}

#[derive(Debug, Clone)]
pub struct CheckCase {
    pub name: &'static str,
    /// Object kind name (`ObjectKind::name`), or an unknown name for the
    /// `UNKNOWN_OBJECT_KIND` case.
    pub object: &'static str,
    pub bytes: Vec<u8>,
    /// Prerequisite objects admitted (in order) before the case object.
    pub store: Vec<(ObjectKind, Vec<u8>)>,
    pub expect: Expect,
}

/// The frozen runner semantics. Store prerequisites MUST admit (a failure
/// there is a broken fixture, reported distinctly), then the case object is
/// admitted and its outcome returned.
pub fn execute(
    object_name: &str,
    bytes: &[u8],
    store_entries: &[(ObjectKind, Vec<u8>)],
) -> Result<Hash32, WeftError> {
    let mut store = WeftStoreV0::new();
    for (kind, entry) in store_entries {
        // Prerequisites are fixture data; the checker still runs on them.
        store.admit_bytes(*kind, entry)?;
    }
    let Some(kind) = ObjectKind::from_name(object_name) else {
        return Err(WeftError::UnknownObjectKind);
    };
    store.admit_bytes(kind, bytes)
}

// ---------------------------------------------------------------------------
// Byte-surgery helpers (frozen offsets against the canonical fixture bytes)
// ---------------------------------------------------------------------------

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

fn drop_last(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len() - 1].to_vec()
}

fn append_byte(bytes: &[u8], b: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.push(b);
    out
}

// ---------------------------------------------------------------------------
// The frozen vector tables
// ---------------------------------------------------------------------------

fn enc<T: NoosEncode>(o: &T) -> Vec<u8> {
    o.encode_canonical()
}

fn accept(obj: WeftObjectV0) -> Expect {
    Expect::Accept(content_id(&obj))
}

/// `weft-profile-v0.json` — NumericProfileV0 standalone cases.
#[must_use]
pub fn profile_cases() -> Vec<CheckCase> {
    let fx = build_fixture(&FixtureParams::default());
    let base = enc(&fx.profile);
    let with = |f: &dyn Fn(&mut NumericProfileV0)| {
        let mut p = fx.profile.clone();
        f(&mut p);
        enc(&p)
    };
    let obj = ObjectKind::NumericProfile.name();
    let case = |name, bytes, expect| CheckCase {
        name,
        object: obj,
        bytes,
        store: Vec::new(),
        expect,
    };

    vec![
        case(
            "profile-accept",
            base.clone(),
            accept(WeftObjectV0::Profile(fx.profile.clone())),
        ),
        case(
            "profile-name-empty",
            with(&|p| p.name = ProfileName(Vec::new())),
            Expect::Reject(WeftError::ProfileNameInvalid),
        ),
        case(
            "profile-name-bad-first",
            with(&|p| p.name = ProfileName(b"8xA".to_vec())),
            Expect::Reject(WeftError::ProfileNameInvalid),
        ),
        case(
            "profile-name-bad-char",
            with(&|p| p.name = ProfileName(b"W8 A8".to_vec())),
            Expect::Reject(WeftError::ProfileNameInvalid),
        ),
        case(
            "profile-width-w16",
            with(&|p| p.weight_bits = 16),
            Expect::Reject(WeftError::ProfileWidthInadmissible),
        ),
        case(
            "profile-accum-inexact",
            with(&|p| p.accum_exact = 0),
            Expect::Reject(WeftError::ProfileAccumNotExact),
        ),
        case(
            "profile-requant-mult-zero",
            with(&|p| p.requant_mult = 0),
            Expect::Reject(WeftError::ProfileRequantInvalid),
        ),
        case(
            "profile-requant-shift-zero",
            with(&|p| p.requant_shift = 0),
            Expect::Reject(WeftError::ProfileRequantInvalid),
        ),
        case(
            "profile-requant-shift-32",
            with(&|p| p.requant_shift = 32),
            Expect::Reject(WeftError::ProfileRequantInvalid),
        ),
        case(
            "profile-saturate-narrow",
            with(&|p| p.saturate_max_twos = 0x7e),
            Expect::Reject(WeftError::ProfileSaturateInvalid),
        ),
        case(
            "profile-forbid-missing-bit",
            with(&|p| p.forbid_flags = 0x07),
            Expect::Reject(WeftError::ProfileForbidInvalid),
        ),
        case(
            "profile-forbid-unknown-bit",
            with(&|p| p.forbid_flags = 0x1f),
            Expect::Reject(WeftError::ProfileForbidInvalid),
        ),
        // Byte surgery: version at offset 0; first tag at 2; requant_kind
        // discriminant at 28 (2 version + 2 tag + 4 len + 6 name + 3*(2+1)
        // + 2 tag + ... see weft-v0.md §4.1 layout).
        case(
            "profile-version-unknown",
            patch_u16(&base, 0, 1),
            Expect::Reject(WeftError::DecodeUnknownVersion),
        ),
        case(
            "profile-tag-confusion",
            patch_u16(&base, 2, 2),
            Expect::Reject(WeftError::DecodeUnknownField),
        ),
        case(
            "profile-requant-kind-unknown",
            patch_u16(&base, 28, 1),
            Expect::Reject(WeftError::DecodeUnknownDiscriminant),
        ),
        case(
            "profile-truncated",
            drop_last(&base),
            Expect::Reject(WeftError::DecodeTruncated),
        ),
        case(
            "profile-trailing-byte",
            append_byte(&base, 0x00),
            Expect::Reject(WeftError::DecodeTrailingBytes),
        ),
        case(
            "profile-name-length-overflow",
            // name length prefix at offset 4 (2 version + 2 tag): declare 33
            // bytes against the frozen 32-byte maximum.
            patch_u32(&base, 4, 33),
            Expect::Reject(WeftError::DecodeLengthBound),
        ),
    ]
}

/// `weft-cost-v0.json` — CostCertificateV0 standalone cases (the
/// certificate law).
#[must_use]
pub fn cost_cases() -> Vec<CheckCase> {
    let fx = build_fixture(&FixtureParams::default());
    let base = enc(&fx.cost);
    let with = |f: &dyn Fn(&mut CostCertificateV0)| {
        let mut c = fx.cost.clone();
        f(&mut c);
        enc(&c)
    };
    let obj = ObjectKind::CostCertificate.name();
    let case = |name, bytes, expect| CheckCase {
        name,
        object: obj,
        bytes,
        store: Vec::new(),
        expect,
    };

    // An admissible two-variable certificate variant for total-degree cases.
    let two_var = {
        let mut c = fx.cost.clone();
        c.size_vars = SizeVarList(vec![
            SizeVarDecl {
                name: SizeVarName(b"m".to_vec()),
                max_value: 8,
            },
            SizeVarDecl {
                name: SizeVarName(b"k".to_vec()),
                max_value: 8,
            },
        ]);
        c.branches = crate::objects::BranchList(vec![CostBranch {
            terms: TermList(vec![CostTerm {
                coeff: 1,
                exponents: Exponents(vec![4, 3]),
            }]),
        }]);
        c.formula_bytes = FormulaBytes(Vec::new());
        c.trials = TrialList(Vec::new());
        c
    };

    let unembedded = {
        let mut c = fx.cost.clone();
        c.formula_bytes = FormulaBytes(Vec::new());
        c.trials = TrialList(Vec::new());
        c
    };

    vec![
        case(
            "cost-accept-embedded",
            base.clone(),
            accept(WeftObjectV0::Cost(fx.cost.clone())),
        ),
        case(
            "cost-accept-unembedded",
            enc(&unembedded),
            accept(WeftObjectV0::Cost(unembedded.clone())),
        ),
        case(
            "cost-grain-version-2",
            with(&|c| c.grain_version = 2),
            Expect::Reject(WeftError::CertGrainVersion),
        ),
        case(
            "cost-formula-id-zero",
            with(&|c| c.formula_id = ZERO_HASH),
            Expect::Reject(WeftError::CertFormulaIdZero),
        ),
        case(
            "cost-size-var-bad-name",
            with(&|c| c.size_vars.0[0].name = SizeVarName(b"N".to_vec())),
            Expect::Reject(WeftError::CertSizeVarInvalid),
        ),
        case(
            "cost-size-var-max-zero",
            with(&|c| c.size_vars.0[0].max_value = 0),
            Expect::Reject(WeftError::CertSizeVarInvalid),
        ),
        case(
            "cost-size-var-duplicate",
            with(&|c| {
                let v = c.size_vars.0[0].clone();
                c.size_vars.0.push(v);
            }),
            Expect::Reject(WeftError::CertSizeVarInvalid),
        ),
        case(
            "cost-no-branches",
            with(&|c| c.branches.0.clear()),
            Expect::Reject(WeftError::CertNoBranches),
        ),
        case(
            "cost-empty-branch",
            with(&|c| {
                c.branches.0.push(CostBranch {
                    terms: TermList(Vec::new()),
                })
            }),
            Expect::Reject(WeftError::CertNoBranches),
        ),
        case(
            "cost-term-arity",
            with(&|c| c.branches.0[0].terms.0[0].exponents = Exponents(vec![1, 1])),
            Expect::Reject(WeftError::CertTermArity),
        ),
        case(
            "cost-degree-exceeded",
            with(&|c| c.branches.0[0].terms.0[0].exponents = Exponents(vec![5])),
            Expect::Reject(WeftError::CertDegreeExceeded),
        ),
        {
            let mut c = two_var.clone();
            // per-variable exponents legal (4, 3) but total degree 7 > 6.
            c.branches.0[0].terms.0[0].exponents = Exponents(vec![4, 3]);
            case(
                "cost-total-degree-exceeded",
                enc(&c),
                Expect::Reject(WeftError::CertDegreeExceeded),
            )
        },
        case(
            "cost-coeff-zero",
            with(&|c| c.branches.0[0].terms.0[0].coeff = 0),
            Expect::Reject(WeftError::CertCoeffInvalid),
        ),
        case(
            "cost-coeff-over-max",
            with(&|c| c.branches.0[0].terms.0[0].coeff = crate::MAX_COST_COEFF + 1),
            Expect::Reject(WeftError::CertCoeffInvalid),
        ),
        case(
            "cost-bound-overflow",
            with(&|c| {
                c.size_vars.0[0].max_value = u64::MAX;
                c.branches.0[0].terms.0[0].coeff = crate::MAX_COST_COEFF;
                c.branches.0[0].terms.0[0].exponents = Exponents(vec![4]);
            }),
            Expect::Reject(WeftError::CertBoundOverflow),
        ),
        case(
            "cost-formula-malformed",
            with(&|c| c.formula_bytes.0[0] = 0x02),
            Expect::Reject(WeftError::CertFormulaInvalid),
        ),
        case(
            "cost-formula-hash-mismatch",
            with(&|c| c.formula_id[0] ^= 0x01),
            Expect::Reject(WeftError::CertFormulaHashMismatch),
        ),
        case(
            "cost-no-trials",
            with(&|c| c.trials.0.clear()),
            Expect::Reject(WeftError::CertNoTrials),
        ),
        case(
            "cost-trials-without-formula",
            with(&|c| c.formula_bytes = FormulaBytes(Vec::new())),
            Expect::Reject(WeftError::CertTrialsWithoutFormula),
        ),
        case(
            "cost-trial-arity",
            with(&|c| c.trials.0[0].sizes = SizeList(Vec::new())),
            Expect::Reject(WeftError::CertTrialArity),
        ),
        case(
            "cost-trial-size-over-max",
            with(&|c| c.trials.0[0].sizes = SizeList(vec![65])),
            Expect::Reject(WeftError::CertTrialSizeRange),
        ),
        case(
            "cost-trial-subject-malformed",
            with(&|c| c.trials.0[0].subject = SubjectBytes(vec![0x02])),
            Expect::Reject(WeftError::CertTrialSubjectInvalid),
        ),
        case(
            "cost-trial-budget-exceeded",
            // Bound at the trial sizes above the frozen 2^24 checker budget.
            with(&|c| c.branches.0[0].terms.0[0].coeff = (1 << 24) + 1),
            Expect::Reject(WeftError::CertTrialBudgetExceeded),
        ),
        case(
            "cost-trial-trapped",
            // Subject cell: `inc` of a cell traps TYPE_MISMATCH inside the
            // trial run (well below the certified bound).
            with(&|c| {
                let cell = match Noun::cell(Noun::atom_u64(0), Noun::atom_u64(0)) {
                    Ok(n) => n,
                    Err(_) => unreachable!("two-atom cell is within bounds"),
                };
                c.trials.0[0].subject = SubjectBytes(encode_noun(&cell));
            }),
            Expect::Reject(WeftError::CertTrialTrapped),
        ),
        case(
            "cost-charge-exceeds-bound",
            // Bound understatement: 4n + 2 < actual 5n + 2 at n = 4.
            with(&|c| c.branches.0[0].terms.0[0].coeff = 4),
            Expect::Reject(WeftError::CertChargeExceedsBound),
        ),
        case(
            "cost-version-unknown",
            patch_u16(&base, 0, 1),
            Expect::Reject(WeftError::DecodeUnknownVersion),
        ),
        case(
            "cost-size-var-list-overflow",
            // size_vars length prefix at offset 44 (2 version + 2 tag + 32
            // formula_id + 2 tag + 4 grain_version + 2 tag): declare 9
            // entries against the frozen maximum of 8.
            patch_u32(&base, 44, 9),
            Expect::Reject(WeftError::DecodeLengthBound),
        ),
        case(
            // The certificate ends in a length-delimited collection, so tail
            // truncation trips the length-vs-remaining-input bound (codec
            // law: the bound is checked BEFORE any allocation).
            "cost-truncated-into-collection",
            drop_last(&base),
            Expect::Reject(WeftError::DecodeLengthBound),
        ),
    ]
}

/// `weft-refs-v0.json` — store-resolved cases: MeaningContractV0,
/// JetCertificateV0, SpanStatementV0, and the unknown-kind envelope.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn refs_cases() -> Vec<CheckCase> {
    let fx = build_fixture(&FixtureParams::default());
    let profile_bytes = enc(&fx.profile);
    let cost_bytes = enc(&fx.cost);
    let jet_bytes = enc(&fx.jet);
    let foreign_cost = foreign_cost_certificate();
    let foreign_jet = foreign_jet_certificate();

    let store_p = vec![(ObjectKind::NumericProfile, profile_bytes.clone())];
    let store_pc = vec![
        (ObjectKind::NumericProfile, profile_bytes.clone()),
        (ObjectKind::CostCertificate, cost_bytes.clone()),
    ];
    let store_pcj = vec![
        (ObjectKind::NumericProfile, profile_bytes.clone()),
        (ObjectKind::CostCertificate, cost_bytes.clone()),
        (ObjectKind::JetCertificate, jet_bytes.clone()),
    ];

    let mc = |f: &dyn Fn(&mut MeaningContractV0)| {
        let mut m = fx.meaning.clone();
        f(&mut m);
        enc(&m)
    };
    let jet = |f: &dyn Fn(&mut JetCertificateV0)| {
        let mut j = fx.jet.clone();
        f(&mut j);
        enc(&j)
    };
    let span = |f: &dyn Fn(&mut SpanStatementV0)| {
        let mut s = fx.span.clone();
        f(&mut s);
        enc(&s)
    };

    let mc_name = ObjectKind::MeaningContract.name();
    let jet_name = ObjectKind::JetCertificate.name();
    let span_name = ObjectKind::SpanStatement.name();
    let case = |name, object, bytes, store, expect| CheckCase {
        name,
        object,
        bytes,
        store,
        expect,
    };

    vec![
        // ---- positives -----------------------------------------------------
        case(
            "meaning-accept",
            mc_name,
            enc(&fx.meaning),
            store_pcj.clone(),
            accept(WeftObjectV0::Meaning(fx.meaning.clone())),
        ),
        case(
            "jet-accept",
            jet_name,
            jet_bytes.clone(),
            store_pc.clone(),
            accept(WeftObjectV0::Jet(fx.jet.clone())),
        ),
        case(
            "span-accept",
            span_name,
            enc(&fx.span),
            store_p.clone(),
            accept(WeftObjectV0::Span(fx.span.clone())),
        ),
        // ---- meaning contract ----------------------------------------------
        case(
            "mc-grain-version-2",
            mc_name,
            mc(&|m| m.grain_version = 2),
            store_pcj.clone(),
            Expect::Reject(WeftError::McGrainVersion),
        ),
        case(
            "mc-formula-id-zero",
            mc_name,
            mc(&|m| m.formula_id = ZERO_HASH),
            store_pcj.clone(),
            Expect::Reject(WeftError::McFormulaIdZero),
        ),
        case(
            "mc-type-signature-invalid-utf8",
            mc_name,
            mc(&|m| m.type_signature = TypeSignature(vec![0xff, 0xfe, 0x00])),
            store_pcj.clone(),
            Expect::Reject(WeftError::McTypeSignatureInvalid),
        ),
        case(
            "mc-profile-duplicate",
            mc_name,
            mc(&|m| {
                let p = m.profile_ids.0[0];
                m.profile_ids.0.push(p);
            }),
            store_pcj.clone(),
            Expect::Reject(WeftError::McProfileDuplicate),
        ),
        case(
            "mc-profile-unresolved",
            mc_name,
            enc(&fx.meaning),
            Vec::new(),
            Expect::Reject(WeftError::McProfileUnresolved),
        ),
        case(
            "mc-cost-unresolved",
            mc_name,
            mc(&|m| {
                m.obligation_ids.0.clear();
            }),
            store_p.clone(),
            Expect::Reject(WeftError::McCostUnresolved),
        ),
        case(
            "mc-cost-transplant",
            mc_name,
            mc(&|m| {
                m.cost_certificate_id = content_id(&WeftObjectV0::Cost(foreign_cost.clone()));
                m.obligation_ids.0.clear();
            }),
            vec![
                (ObjectKind::NumericProfile, profile_bytes.clone()),
                (ObjectKind::CostCertificate, enc(&foreign_cost)),
            ],
            Expect::Reject(WeftError::McCostFormulaMismatch),
        ),
        case(
            "mc-obligation-duplicate",
            mc_name,
            mc(&|m| {
                let o = m.obligation_ids.0[0];
                m.obligation_ids.0.push(o);
            }),
            store_pcj.clone(),
            Expect::Reject(WeftError::McObligationDuplicate),
        ),
        case(
            "mc-obligation-unresolved",
            mc_name,
            enc(&fx.meaning),
            store_pc.clone(),
            Expect::Reject(WeftError::McObligationUnresolved),
        ),
        case(
            "mc-obligation-transplant",
            mc_name,
            mc(&|m| {
                m.obligation_ids.0 = vec![content_id(&WeftObjectV0::Jet(foreign_jet.clone()))];
            }),
            vec![
                (ObjectKind::NumericProfile, profile_bytes.clone()),
                (ObjectKind::CostCertificate, cost_bytes.clone()),
                (ObjectKind::JetCertificate, enc(&foreign_jet)),
            ],
            Expect::Reject(WeftError::McObligationMismatch),
        ),
        // ---- jet certificate -------------------------------------------------
        case(
            "jet-grain-version-2",
            jet_name,
            jet(&|j| j.grain_version = 2),
            store_pc.clone(),
            Expect::Reject(WeftError::JetGrainVersion),
        ),
        case(
            "jet-formula-id-zero",
            jet_name,
            jet(&|j| j.formula_id = ZERO_HASH),
            store_pc.clone(),
            Expect::Reject(WeftError::JetFormulaIdZero),
        ),
        case(
            "jet-impl-hash-zero",
            jet_name,
            jet(&|j| j.impl_hash = ZERO_HASH),
            store_pc.clone(),
            Expect::Reject(WeftError::JetImplHashZero),
        ),
        case(
            "jet-target-empty",
            jet_name,
            jet(&|j| j.target_triple = TargetTriple(Vec::new())),
            store_pc.clone(),
            Expect::Reject(WeftError::JetTargetInvalid),
        ),
        case(
            "jet-target-space",
            jet_name,
            jet(&|j| j.target_triple = TargetTriple(b"cuda sm90".to_vec())),
            store_pc.clone(),
            Expect::Reject(WeftError::JetTargetInvalid),
        ),
        case(
            "jet-corpus-zero",
            jet_name,
            jet(&|j| j.corpus_root = ZERO_HASH),
            store_pc.clone(),
            Expect::Reject(WeftError::JetCorpusZero),
        ),
        case(
            "jet-bond-zero",
            jet_name,
            jet(&|j| j.bond_micro_noos = 0),
            store_pc.clone(),
            Expect::Reject(WeftError::JetBondZero),
        ),
        case(
            "jet-heights-proposed-nonzero",
            jet_name,
            jet(&|j| j.admitted_height = 7),
            store_pc.clone(),
            Expect::Reject(WeftError::JetHeightsInconsistent),
        ),
        case(
            "jet-heights-admitted-zero",
            jet_name,
            jet(&|j| j.status = JetStatus::Admitted),
            store_pc.clone(),
            Expect::Reject(WeftError::JetHeightsInconsistent),
        ),
        case(
            "jet-heights-revoked-before-admitted",
            jet_name,
            jet(&|j| {
                j.status = JetStatus::Revoked;
                j.admitted_height = 10;
                j.revoked_height = 5;
            }),
            store_pc.clone(),
            Expect::Reject(WeftError::JetHeightsInconsistent),
        ),
        case(
            "jet-profile-unresolved",
            jet_name,
            jet_bytes.clone(),
            Vec::new(),
            Expect::Reject(WeftError::JetProfileUnresolved),
        ),
        case(
            "jet-cost-unresolved",
            jet_name,
            jet_bytes.clone(),
            store_p.clone(),
            Expect::Reject(WeftError::JetCostUnresolved),
        ),
        case(
            "jet-cost-transplant",
            jet_name,
            jet(&|j| j.cost_certificate_id = content_id(&WeftObjectV0::Cost(foreign_cost.clone()))),
            vec![
                (ObjectKind::NumericProfile, profile_bytes.clone()),
                (ObjectKind::CostCertificate, enc(&foreign_cost)),
            ],
            Expect::Reject(WeftError::JetCostFormulaMismatch),
        ),
        case(
            "jet-status-discriminant-unknown",
            jet_name,
            // status discriminant at offset 216: 2 version + (2+32) formula
            // is wrong on purpose? No — layout: v2 t2 gv4 t2 fid32 t2 impl32
            // t2 (4+9 triple) t2 pid32 t2 cid32 t2 corpus32 t2 bond8 t2 -> status.
            {
                // Compute the offset structurally: everything before status
                // is fixed-width except the 9-byte target triple.
                let triple_len = fx.jet.target_triple.0.len();
                let off = 2
                    + (2 + 4)
                    + (2 + 32)
                    + (2 + 32)
                    + (2 + 4 + triple_len)
                    + (2 + 32)
                    + (2 + 32)
                    + (2 + 32)
                    + (2 + 8)
                    + 2;
                patch_u16(&jet_bytes, off, 6)
            },
            store_pc.clone(),
            Expect::Reject(WeftError::DecodeUnknownDiscriminant),
        ),
        // ---- span statement --------------------------------------------------
        case(
            "span-shape-zero",
            span_name,
            span(&|s| s.shape_k = 0),
            store_p.clone(),
            Expect::Reject(WeftError::SpanShapeBound),
        ),
        case(
            "span-shape-overflow",
            span_name,
            span(&|s| s.shape_m = 65_536),
            store_p.clone(),
            Expect::Reject(WeftError::SpanShapeBound),
        ),
        case(
            "span-verifier-zero",
            span_name,
            span(&|s| s.verifier_ref = ZERO_HASH),
            store_p.clone(),
            Expect::Reject(WeftError::SpanVerifierZero),
        ),
        case(
            "span-rbits-layout",
            span_name,
            // reps 4 keeps 4*16 = 64 >= 64, so ONLY the layout law fires.
            span(&|s| {
                s.soundness_reps = 4;
                s.soundness_rbits = 16;
            }),
            store_p.clone(),
            Expect::Reject(WeftError::SpanRbitsLayout),
        ),
        case(
            "span-soundness-understated",
            span_name,
            span(&|s| s.soundness_reps = 1),
            store_p.clone(),
            Expect::Reject(WeftError::SpanSoundnessPolicy),
        ),
        case(
            "span-reps-over-max",
            span_name,
            span(&|s| s.soundness_reps = 9),
            store_p.clone(),
            Expect::Reject(WeftError::SpanSoundnessPolicy),
        ),
        case(
            "span-beacon-offline",
            span_name,
            span(&|s| s.beacon_policy = BeaconPolicy::OfflineDerived),
            store_p.clone(),
            Expect::Reject(WeftError::SpanBeaconPolicy),
        ),
        case(
            "span-profile-unresolved",
            span_name,
            enc(&fx.span),
            Vec::new(),
            Expect::Reject(WeftError::SpanProfileUnresolved),
        ),
        case(
            "span-beacon-discriminant-unknown",
            span_name,
            // beacon_policy u16 at offset 106 (weft-v0.md §4.5 layout).
            patch_u16(&enc(&fx.span), 106, 2),
            store_p.clone(),
            Expect::Reject(WeftError::DecodeUnknownDiscriminant),
        ),
        // ---- envelope ---------------------------------------------------------
        case(
            "unknown-object-kind",
            "wisp",
            Vec::new(),
            Vec::new(),
            Expect::Reject(WeftError::UnknownObjectKind),
        ),
    ]
}

// ---------------------------------------------------------------------------
// JSON emission (hand-rolled from fully controlled ASCII content)
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn case_json(c: &CheckCase) -> String {
    let mut s = String::new();
    s.push_str("    {\n");
    s.push_str(&format!("      \"name\": \"{}\",\n", c.name));
    let kind = match c.expect {
        Expect::Accept(_) => "positive",
        Expect::Reject(_) => "negative",
    };
    s.push_str(&format!("      \"kind\": \"{kind}\",\n"));
    s.push_str(&format!("      \"object\": \"{}\",\n", c.object));
    s.push_str(&format!("      \"bytes\": \"{}\",\n", hex(&c.bytes)));
    s.push_str("      \"store\": [");
    for (i, (k, b)) in c.store.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!(
            "{{\"object\": \"{}\", \"bytes\": \"{}\"}}",
            k.name(),
            hex(b)
        ));
    }
    s.push_str("],\n");
    match &c.expect {
        Expect::Accept(id) => {
            s.push_str(&format!(
                "      \"expect\": {{\"result\": \"accept\", \"content_id\": \"{}\"}}\n",
                hex(id)
            ));
        }
        Expect::Reject(err) => {
            s.push_str(&format!(
                "      \"expect\": {{\"result\": \"reject\", \"error_code\": {}, \"error_class\": \"{}\"}}\n",
                err.code(),
                err.class_name()
            ));
        }
    }
    s.push_str("    }");
    s
}

fn file_json(schema: &str, description: &str, cases: &[CheckCase]) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"schema\": \"{schema}\",\n"));
    out.push_str(&format!("  \"description\": \"{description}\",\n"));
    out.push_str("  \"cases\": [\n");
    for (i, c) in cases.iter().enumerate() {
        out.push_str(&case_json(c));
        out.push_str(if i + 1 < cases.len() { ",\n" } else { "\n" });
    }
    out.push_str("  ]\n}\n");
    out
}

/// `weft-profile-v0.json` content.
#[must_use]
pub fn profile_json() -> String {
    file_json(
        "noos/weft/profile-v0",
        "NumericProfileV0 decode+check cases (weft-v0.md sections 4.1, 5.1, 7). Runner: admit store entries in order, then admit bytes as object; compare outcome and content id or stable error code/class.",
        &profile_cases(),
    )
}

/// `weft-cost-v0.json` content.
#[must_use]
pub fn cost_json() -> String {
    file_json(
        "noos/weft/cost-v0",
        "CostCertificateV0 certificate-law cases (weft-v0.md sections 4.2, 5.2, 7): declared polynomials are never trusted; embedded formulas are executed on trial inputs and the actual Grain charge must not exceed the certified bound.",
        &cost_cases(),
    )
}

/// `weft-refs-v0.json` content.
#[must_use]
pub fn refs_json() -> String {
    file_json(
        "noos/weft/refs-v0",
        "MeaningContractV0 / JetCertificateV0 / SpanStatementV0 store-resolved cases (weft-v0.md sections 4.3-4.5, 5.3-5.5, 7): certificate-reference integrity, lifecycle height law, transcript-layout conformance, soundness and beacon policy.",
        &refs_cases(),
    )
}
