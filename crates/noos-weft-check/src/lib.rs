//! Weft v0 — certificate schemas plus the total, bounded relation checker.
//!
//! Normative source: `protocol/schemas/weft-v0.md` (frozen from
//! `C:/tmp/noosphere/06-weft-language.md` §3.3/§5 and plan §5.5/§5.7–5.8).
//!
//! Law recap:
//! - Weft v0 is **schemas plus a checker**: five typed, versioned,
//!   content-addressed objects (`NumericProfileV0`, `CostCertificateV0`,
//!   `MeaningContractV0`, `JetCertificateV0`, `SpanStatementV0`) and a
//!   total, bounded, deterministic validator over them. No parser, no
//!   inference, no elaboration.
//! - **Raw Grain remains valid forever.** A formula with no Weft artifact
//!   is a first-class citizen indefinitely; v0 artifacts are *data about
//!   formulas* and can be wrong, quarantined, or abandoned without any
//!   state transition changing meaning.
//! - **Never trust a declared polynomial** (plan §5.8). The checker
//!   validates size variables, coefficient/degree/term limits, and overflow
//!   with checked arithmetic; branch semantics are `max`; a certificate
//!   carrying its formula is *executed* on its declared-size trial inputs
//!   through `noos-grain::eval` and the actual charge must be `<=` the
//!   certified bound.
//! - Every check is total and bounded: all collections carry frozen codec
//!   maxima, and trial evaluation runs under a frozen step/arena budget
//!   ([`MAX_TRIAL_CHARGE`], [`MAX_TRIAL_ARENA_WORDS`]). Rejection is a
//!   stable-coded [`WeftError`], never a panic.

#![forbid(unsafe_code)]

use core::fmt;

mod check;
mod objects;
pub mod vectors;

pub use check::{
    certified_bound, check_cost_certificate, check_jet_certificate, check_meaning_contract,
    check_profile, check_span_statement, content_id, cost_certificate_id, jet_certificate_id,
    meaning_id, profile_id, span_id, WeftStoreV0,
};
pub use objects::{
    BeaconPolicy, BranchList, CostBranch, CostCertificateV0, CostTerm, CostTrial, Exponents,
    FormulaBytes, JetCertificateV0, JetStatus, JournalSchema, MeaningContractV0, NumericProfileV0,
    ObjectKind, ObligationRefList, ProfileName, ProfileRefList, RequantKind, SizeList, SizeVarDecl,
    SizeVarList, SizeVarName, SpanStatementV0, SubjectBytes, TargetTriple, TermList,
    TranscriptLayout, TrialList, TypeSignature, VerifierKind, WeftObjectV0,
};

#[cfg(test)]
mod tests;

/// 32-byte BLAKE3 content id / hash value.
pub type Hash32 = [u8; 32];

/// The all-zero hash: the frozen "absent reference" sentinel.
pub const ZERO_HASH: Hash32 = [0u8; 32];

// ---------------------------------------------------------------------------
// Frozen v0 limits (weft-v0.md §2)
// ---------------------------------------------------------------------------

/// The only Weft schema version this crate defines (object `version` field).
pub const WEFT_V0_VERSION: u16 = 0;
/// The only Grain version v0 certificates may cite.
pub const WEFT_V0_GRAIN_VERSION: u32 = 1;

/// Maximum profile-name byte length.
pub const MAX_PROFILE_NAME_BYTES: u32 = 32;
/// Maximum jet target-triple byte length.
pub const MAX_TARGET_TRIPLE_BYTES: u32 = 64;
/// Maximum opaque type-signature byte length (may be empty).
pub const MAX_TYPE_SIGNATURE_BYTES: u32 = 4096;
/// Maximum number of size variables in a cost certificate.
pub const MAX_SIZE_VARS: u32 = 8;
/// Maximum size-variable name byte length.
pub const MAX_SIZE_VAR_NAME_BYTES: u32 = 16;
/// Maximum number of `max`-combined branches in a cost polynomial.
pub const MAX_COST_BRANCHES: u32 = 16;
/// Maximum number of terms per branch.
pub const MAX_COST_TERMS: u32 = 64;
/// Maximum per-variable exponent in one term.
pub const MAX_TERM_EXPONENT: u8 = 4;
/// Maximum total degree (sum of exponents) of one term.
pub const MAX_TERM_TOTAL_DEGREE: u32 = 6;
/// Maximum (and minimum-nonzero) term coefficient: `2^48`.
pub const MAX_COST_COEFF: u64 = 1 << 48;
/// Maximum number of evaluation trials in a cost certificate.
pub const MAX_COST_TRIALS: u32 = 16;
/// Maximum embedded canonical formula byte length (== Grain `MAX_FORMULA_BYTES`).
pub const MAX_EMBEDDED_FORMULA_BYTES: u32 = 65_536;
/// Maximum trial subject byte length (tighter than Grain's 1 MiB subject cap:
/// the checker is bounded by construction).
pub const MAX_TRIAL_SUBJECT_BYTES: u32 = 65_536;
/// Checker execution budget per trial, grain-steps (`2^24`). A certified
/// bound above this at any trial's sizes rejects: the checker never runs an
/// unbounded meter.
pub const MAX_TRIAL_CHARGE: u64 = 1 << 24;
/// Checker arena budget per trial, words (`2^20` = 8 MiB).
pub const MAX_TRIAL_ARENA_WORDS: u64 = 1 << 20;
/// Maximum numeric-profile references in a meaning contract.
pub const MAX_PROFILE_REFS: u32 = 8;
/// Maximum jet-obligation references in a meaning contract.
pub const MAX_OBLIGATION_REFS: u32 = 32;
/// Span dimensions must fit the 16-bit transcript packing: `1..=65535`.
pub const SPAN_DIM_MAX: u32 = 65_535;
/// Minimum span soundness: `reps * rbits >= 64` (2^-64 per span).
pub const SPAN_SOUNDNESS_MIN_BITS: u32 = 64;
/// Maximum Freivalds repetitions a span statement may declare.
pub const SPAN_MAX_REPS: u16 = 8;
/// Challenge-word width of the `SHA256_FLAT_V0` transcript layout.
pub const SPAN_SHA256_FLAT_V0_RBITS: u16 = 32;
/// Required v0 profile forbid mask: float | wrapping | zero_points |
/// kernel_order_dependence, and no unknown bits.
pub const PROFILE_FORBID_REQUIRED: u32 = 0x0F;

// ---------------------------------------------------------------------------
// Registered BLAKE3 domains (protocol/spec/crypto-domains-v1.csv)
// ---------------------------------------------------------------------------

/// Registered BLAKE3 context strings consumed by Weft v0.
pub mod domains {
    /// D-WEFT-PROFILE: `profile_id = H(ctx || canonical NumericProfileV0)`.
    pub const WEFT_PROFILE: &str = "NOOS/WEFT/PROFILE/V0";
    /// D-WEFT-COST: `cost_certificate_id = H(ctx || canonical CostCertificateV0)`.
    pub const WEFT_COST: &str = "NOOS/WEFT/COST/V0";
    /// D-WEFT-MEANING: `meaning_id = H(ctx || canonical MeaningContractV0)`.
    pub const WEFT_MEANING: &str = "NOOS/WEFT/MEANING/V0";
    /// D-WEFT-JETCERT: `jet_certificate_id = H(ctx || canonical JetCertificateV0)`.
    pub const WEFT_JETCERT: &str = "NOOS/WEFT/JETCERT/V0";
    /// D-WEFT-SPAN: `span_id = H(ctx || canonical SpanStatementV0)`.
    pub const WEFT_SPAN: &str = "NOOS/WEFT/SPAN/V0";
    /// D-WEFT-FORMULA: `formula_id = H(ctx || canonical Grain noun bytes)`.
    pub const WEFT_FORMULA: &str = "NOOS/WEFT/FORMULA/V0";
}

/// Domain-bound BLAKE3-256: `H(context_string || parts[0] || parts[1] || ...)`.
///
/// Every context string is a registered `D-WEFT-*` row in
/// `protocol/spec/crypto-domains-v1.csv`; this crate never hashes under an
/// unregistered string.
#[must_use]
pub fn domain_hash(context: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(context.as_bytes());
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// `formula_id = H("NOOS/WEFT/FORMULA/V0" || canonical Grain noun bytes)`
/// (D-WEFT-FORMULA). The bytes MUST be a canonical §4 Grain encoding; the
/// checker recomputes this id from embedded formula bytes.
#[must_use]
pub fn formula_id(canonical_formula_bytes: &[u8]) -> Hash32 {
    domain_hash(domains::WEFT_FORMULA, &[canonical_formula_bytes])
}

// ---------------------------------------------------------------------------
// WeftError — stable numeric rejection codes (weft-v0.md §6)
// ---------------------------------------------------------------------------

/// Closed rejection law of the v0 relation checker. Codes are protocol
/// values: u16, immutable for Weft schema version 0; zero is reserved and
/// never an error. The FIRST failing check of the frozen order names the
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum WeftError {
    // -- canonical decode layer (maps noos-codec CodecError 1:1) -----------
    /// Input ended before a fixed-width field or declared length.
    DecodeTruncated = 1,
    /// Bytes remain after the object's canonical encoding.
    DecodeTrailingBytes = 2,
    /// Non-minimal atom (reserved: no v0 object carries codec atoms).
    DecodeNonMinimalAtom = 3,
    /// Unknown mandatory field tag (includes tag-order confusion).
    DecodeUnknownField = 4,
    /// Collection length prefix beyond the frozen maximum or the input.
    DecodeLengthBound = 5,
    /// Object version is not the frozen v0 version.
    DecodeUnknownVersion = 6,
    /// Enum discriminant outside declaration order.
    DecodeUnknownDiscriminant = 7,
    /// Vector/store entry names an object kind outside the closed v0 set.
    UnknownObjectKind = 10,

    // -- NumericProfileV0 ----------------------------------------------------
    /// Profile name empty, oversized charset, or non-alpha first byte.
    ProfileNameInvalid = 20,
    /// (weight, activation, accum) widths outside the v0-admissible (8,8,32).
    ProfileWidthInadmissible = 21,
    /// `accum_exact != 1`: v0 requires exact integer accumulation (KT-1).
    ProfileAccumNotExact = 22,
    /// `requant_mult == 0` or `requant_shift` outside `1..=31`.
    ProfileRequantInvalid = 23,
    /// Saturation bounds are not the full two's-complement i8 range.
    ProfileSaturateInvalid = 24,
    /// Forbid mask is not exactly the required v0 set.
    ProfileForbidInvalid = 25,

    // -- CostCertificateV0 ---------------------------------------------------
    /// `grain_version != 1`.
    CertGrainVersion = 40,
    /// `formula_id` is the zero sentinel.
    CertFormulaIdZero = 41,
    /// Size variable name invalid/duplicate, or `max_value == 0`.
    CertSizeVarInvalid = 42,
    /// No branches, or a branch with no terms.
    CertNoBranches = 43,
    /// A term's exponent list arity differs from the size-variable count.
    CertTermArity = 44,
    /// A per-variable exponent above 4, or total degree above 6.
    CertDegreeExceeded = 45,
    /// A coefficient of zero or above `MAX_COST_COEFF`.
    CertCoeffInvalid = 46,
    /// The bound overflows u64 at the declared maximum sizes.
    CertBoundOverflow = 47,
    /// Embedded formula bytes are not a canonical Grain formula encoding.
    CertFormulaInvalid = 48,
    /// Embedded formula bytes do not hash to the declared `formula_id`.
    CertFormulaHashMismatch = 49,
    /// Formula embedded but no trials: an unexercised certificate rejects.
    CertNoTrials = 50,
    /// Trials present without an embedded formula to run them against.
    CertTrialsWithoutFormula = 51,
    /// A trial's size-assignment arity differs from the size-variable count.
    CertTrialArity = 52,
    /// A trial size exceeds its variable's declared `max_value`.
    CertTrialSizeRange = 53,
    /// A trial subject is not a canonical Grain subject encoding.
    CertTrialSubjectInvalid = 54,
    /// The certified bound at a trial's sizes exceeds `MAX_TRIAL_CHARGE`.
    CertTrialBudgetExceeded = 55,
    /// Trial evaluation trapped (other than meter exhaustion).
    CertTrialTrapped = 56,
    /// Actual charge exceeded the certified bound (meter exhausted at bound).
    CertChargeExceedsBound = 57,

    // -- MeaningContractV0 ---------------------------------------------------
    /// `grain_version != 1`.
    McGrainVersion = 60,
    /// `formula_id` is the zero sentinel.
    McFormulaIdZero = 61,
    /// `type_signature` is not valid UTF-8.
    McTypeSignatureInvalid = 62,
    /// Duplicate profile reference.
    McProfileDuplicate = 63,
    /// A profile reference does not resolve in the store.
    McProfileUnresolved = 64,
    /// The cost-certificate reference does not resolve in the store.
    McCostUnresolved = 65,
    /// The referenced cost certificate certifies a different formula.
    McCostFormulaMismatch = 66,
    /// Duplicate obligation reference.
    McObligationDuplicate = 67,
    /// An obligation reference does not resolve in the store.
    McObligationUnresolved = 68,
    /// A referenced jet certificate binds a different formula or version.
    McObligationMismatch = 69,

    // -- JetCertificateV0 ----------------------------------------------------
    /// `grain_version != 1`.
    JetGrainVersion = 80,
    /// `formula_id` is the zero sentinel.
    JetFormulaIdZero = 81,
    /// `impl_hash` is the zero sentinel: a jet must bind an exact binary.
    JetImplHashZero = 82,
    /// Target triple empty or outside printable ASCII.
    JetTargetInvalid = 83,
    /// `corpus_root` is the zero sentinel: a committed corpus is mandatory.
    JetCorpusZero = 84,
    /// `bond_micro_noos == 0`.
    JetBondZero = 85,
    /// Status and admitted/revoked heights are mutually inconsistent.
    JetHeightsInconsistent = 86,
    /// The numeric-profile reference does not resolve in the store.
    JetProfileUnresolved = 87,
    /// The cost-certificate reference does not resolve in the store.
    JetCostUnresolved = 88,
    /// The referenced cost certificate certifies a different formula.
    JetCostFormulaMismatch = 89,

    // -- SpanStatementV0 -----------------------------------------------------
    /// A shape dimension of zero or above 65535 (16-bit transcript packing).
    SpanShapeBound = 100,
    /// `verifier_ref` is the zero sentinel.
    SpanVerifierZero = 101,
    /// `soundness_rbits` differs from the registered layout's word width.
    SpanRbitsLayout = 102,
    /// `reps` outside `1..=8` or `reps * rbits < 64`.
    SpanSoundnessPolicy = 103,
    /// Beacon policy is not `POST_COMMIT_REQUIRED`.
    SpanBeaconPolicy = 104,
    /// The numeric-profile reference does not resolve in the store.
    SpanProfileUnresolved = 105,
}

impl WeftError {
    /// Stable numeric rejection code.
    #[inline]
    #[must_use]
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Inverse of [`WeftError::code`].
    #[must_use]
    pub fn from_code(code: u16) -> Option<WeftError> {
        WeftError::ALL.iter().copied().find(|e| e.code() == code)
    }

    /// Every defined error, in code order.
    pub const ALL: &'static [WeftError] = &[
        WeftError::DecodeTruncated,
        WeftError::DecodeTrailingBytes,
        WeftError::DecodeNonMinimalAtom,
        WeftError::DecodeUnknownField,
        WeftError::DecodeLengthBound,
        WeftError::DecodeUnknownVersion,
        WeftError::DecodeUnknownDiscriminant,
        WeftError::UnknownObjectKind,
        WeftError::ProfileNameInvalid,
        WeftError::ProfileWidthInadmissible,
        WeftError::ProfileAccumNotExact,
        WeftError::ProfileRequantInvalid,
        WeftError::ProfileSaturateInvalid,
        WeftError::ProfileForbidInvalid,
        WeftError::CertGrainVersion,
        WeftError::CertFormulaIdZero,
        WeftError::CertSizeVarInvalid,
        WeftError::CertNoBranches,
        WeftError::CertTermArity,
        WeftError::CertDegreeExceeded,
        WeftError::CertCoeffInvalid,
        WeftError::CertBoundOverflow,
        WeftError::CertFormulaInvalid,
        WeftError::CertFormulaHashMismatch,
        WeftError::CertNoTrials,
        WeftError::CertTrialsWithoutFormula,
        WeftError::CertTrialArity,
        WeftError::CertTrialSizeRange,
        WeftError::CertTrialSubjectInvalid,
        WeftError::CertTrialBudgetExceeded,
        WeftError::CertTrialTrapped,
        WeftError::CertChargeExceedsBound,
        WeftError::McGrainVersion,
        WeftError::McFormulaIdZero,
        WeftError::McTypeSignatureInvalid,
        WeftError::McProfileDuplicate,
        WeftError::McProfileUnresolved,
        WeftError::McCostUnresolved,
        WeftError::McCostFormulaMismatch,
        WeftError::McObligationDuplicate,
        WeftError::McObligationUnresolved,
        WeftError::McObligationMismatch,
        WeftError::JetGrainVersion,
        WeftError::JetFormulaIdZero,
        WeftError::JetImplHashZero,
        WeftError::JetTargetInvalid,
        WeftError::JetCorpusZero,
        WeftError::JetBondZero,
        WeftError::JetHeightsInconsistent,
        WeftError::JetProfileUnresolved,
        WeftError::JetCostUnresolved,
        WeftError::JetCostFormulaMismatch,
        WeftError::SpanShapeBound,
        WeftError::SpanVerifierZero,
        WeftError::SpanRbitsLayout,
        WeftError::SpanSoundnessPolicy,
        WeftError::SpanBeaconPolicy,
        WeftError::SpanProfileUnresolved,
    ];

    /// Stable class name used by conformance vectors.
    #[must_use]
    pub fn class_name(self) -> &'static str {
        match self {
            WeftError::DecodeTruncated => "decode_truncated",
            WeftError::DecodeTrailingBytes => "decode_trailing_bytes",
            WeftError::DecodeNonMinimalAtom => "decode_nonminimal_atom",
            WeftError::DecodeUnknownField => "decode_unknown_field",
            WeftError::DecodeLengthBound => "decode_length_bound",
            WeftError::DecodeUnknownVersion => "decode_unknown_version",
            WeftError::DecodeUnknownDiscriminant => "decode_unknown_discriminant",
            WeftError::UnknownObjectKind => "unknown_object_kind",
            WeftError::ProfileNameInvalid => "profile_name_invalid",
            WeftError::ProfileWidthInadmissible => "profile_width_inadmissible",
            WeftError::ProfileAccumNotExact => "profile_accum_not_exact",
            WeftError::ProfileRequantInvalid => "profile_requant_invalid",
            WeftError::ProfileSaturateInvalid => "profile_saturate_invalid",
            WeftError::ProfileForbidInvalid => "profile_forbid_invalid",
            WeftError::CertGrainVersion => "cert_grain_version",
            WeftError::CertFormulaIdZero => "cert_formula_id_zero",
            WeftError::CertSizeVarInvalid => "cert_size_var_invalid",
            WeftError::CertNoBranches => "cert_no_branches",
            WeftError::CertTermArity => "cert_term_arity",
            WeftError::CertDegreeExceeded => "cert_degree_exceeded",
            WeftError::CertCoeffInvalid => "cert_coeff_invalid",
            WeftError::CertBoundOverflow => "cert_bound_overflow",
            WeftError::CertFormulaInvalid => "cert_formula_invalid",
            WeftError::CertFormulaHashMismatch => "cert_formula_hash_mismatch",
            WeftError::CertNoTrials => "cert_no_trials",
            WeftError::CertTrialsWithoutFormula => "cert_trials_without_formula",
            WeftError::CertTrialArity => "cert_trial_arity",
            WeftError::CertTrialSizeRange => "cert_trial_size_range",
            WeftError::CertTrialSubjectInvalid => "cert_trial_subject_invalid",
            WeftError::CertTrialBudgetExceeded => "cert_trial_budget_exceeded",
            WeftError::CertTrialTrapped => "cert_trial_trapped",
            WeftError::CertChargeExceedsBound => "cert_charge_exceeds_bound",
            WeftError::McGrainVersion => "mc_grain_version",
            WeftError::McFormulaIdZero => "mc_formula_id_zero",
            WeftError::McTypeSignatureInvalid => "mc_type_signature_invalid",
            WeftError::McProfileDuplicate => "mc_profile_duplicate",
            WeftError::McProfileUnresolved => "mc_profile_unresolved",
            WeftError::McCostUnresolved => "mc_cost_unresolved",
            WeftError::McCostFormulaMismatch => "mc_cost_formula_mismatch",
            WeftError::McObligationDuplicate => "mc_obligation_duplicate",
            WeftError::McObligationUnresolved => "mc_obligation_unresolved",
            WeftError::McObligationMismatch => "mc_obligation_mismatch",
            WeftError::JetGrainVersion => "jet_grain_version",
            WeftError::JetFormulaIdZero => "jet_formula_id_zero",
            WeftError::JetImplHashZero => "jet_impl_hash_zero",
            WeftError::JetTargetInvalid => "jet_target_invalid",
            WeftError::JetCorpusZero => "jet_corpus_zero",
            WeftError::JetBondZero => "jet_bond_zero",
            WeftError::JetHeightsInconsistent => "jet_heights_inconsistent",
            WeftError::JetProfileUnresolved => "jet_profile_unresolved",
            WeftError::JetCostUnresolved => "jet_cost_unresolved",
            WeftError::JetCostFormulaMismatch => "jet_cost_formula_mismatch",
            WeftError::SpanShapeBound => "span_shape_bound",
            WeftError::SpanVerifierZero => "span_verifier_zero",
            WeftError::SpanRbitsLayout => "span_rbits_layout",
            WeftError::SpanSoundnessPolicy => "span_soundness_policy",
            WeftError::SpanBeaconPolicy => "span_beacon_policy",
            WeftError::SpanProfileUnresolved => "span_profile_unresolved",
        }
    }

    /// Canonical mapping from the codec's closed decode-error law.
    #[must_use]
    pub fn from_codec(e: noos_codec::CodecError) -> WeftError {
        match e {
            noos_codec::CodecError::Truncated => WeftError::DecodeTruncated,
            noos_codec::CodecError::TrailingBytes => WeftError::DecodeTrailingBytes,
            noos_codec::CodecError::NonMinimalAtom => WeftError::DecodeNonMinimalAtom,
            noos_codec::CodecError::UnknownMandatoryField => WeftError::DecodeUnknownField,
            noos_codec::CodecError::LengthExceedsBound => WeftError::DecodeLengthBound,
            noos_codec::CodecError::UnknownVersion => WeftError::DecodeUnknownVersion,
            noos_codec::CodecError::UnknownDiscriminant => WeftError::DecodeUnknownDiscriminant,
        }
    }
}

impl fmt::Display for WeftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.class_name(), self.code())
    }
}

impl std::error::Error for WeftError {}

impl From<noos_codec::CodecError> for WeftError {
    fn from(e: noos_codec::CodecError) -> Self {
        WeftError::from_codec(e)
    }
}
