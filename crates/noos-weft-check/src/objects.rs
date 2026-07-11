//! The five Weft v0 wire objects (weft-v0.md §4).
//!
//! Encoding law is `noos-codec` law: `u16` version (== 0), `u16` mandatory
//! tags in declaration order, fixed-width little-endian primitives,
//! canonical `u32`-length bounded collections, whole-input decode.
//! Every bound below is a frozen constant from the crate root.

use crate::{
    Hash32, MAX_COST_BRANCHES, MAX_COST_TERMS, MAX_COST_TRIALS, MAX_EMBEDDED_FORMULA_BYTES,
    MAX_OBLIGATION_REFS, MAX_PROFILE_NAME_BYTES, MAX_PROFILE_REFS, MAX_SIZE_VARS,
    MAX_SIZE_VAR_NAME_BYTES, MAX_TARGET_TRIPLE_BYTES, MAX_TRIAL_SUBJECT_BYTES,
    MAX_TYPE_SIGNATURE_BYTES,
};
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};

// ---------------------------------------------------------------------------
// Bounded byte-string wrappers
// ---------------------------------------------------------------------------

macro_rules! bounded_bytes {
    ($(#[$meta:meta])* $name:ident, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name(pub Vec<u8>);

        impl NoosEncode for $name {
            fn encode(&self, w: &mut Writer) {
                w.put_bytes(&self.0, $max);
            }
        }

        impl NoosDecode for $name {
            fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
                Ok(Self(r.get_bytes($max)?))
            }
        }
    };
}

bounded_bytes!(
    /// Profile name (<= 32 bytes; checker: `[A-Za-z][A-Za-z0-9._-]*`).
    ProfileName,
    MAX_PROFILE_NAME_BYTES
);
bounded_bytes!(
    /// Jet target triple (<= 64 bytes; checker: nonempty printable ASCII).
    TargetTriple,
    MAX_TARGET_TRIPLE_BYTES
);
bounded_bytes!(
    /// Opaque type signature (<= 4096 bytes; checker: valid UTF-8; may be empty).
    TypeSignature,
    MAX_TYPE_SIGNATURE_BYTES
);
bounded_bytes!(
    /// Canonical Grain formula bytes (<= 65536 bytes; empty = not embedded).
    FormulaBytes,
    MAX_EMBEDDED_FORMULA_BYTES
);
bounded_bytes!(
    /// Canonical Grain subject bytes for one trial (<= 65536 bytes).
    SubjectBytes,
    MAX_TRIAL_SUBJECT_BYTES
);
bounded_bytes!(
    /// Per-variable exponents of one term, one byte each (<= 8 bytes; the
    /// checker requires the arity to equal the size-variable count).
    Exponents,
    MAX_SIZE_VARS
);
bounded_bytes!(
    /// Size-variable name (<= 16 bytes; checker: `[a-z][a-z0-9_]*`).
    SizeVarName,
    MAX_SIZE_VAR_NAME_BYTES
);

// ---------------------------------------------------------------------------
// Bounded list wrappers
// ---------------------------------------------------------------------------

macro_rules! bounded_list {
    ($(#[$meta:meta])* $name:ident, $elem:ty, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name(pub Vec<$elem>);

        impl NoosEncode for $name {
            fn encode(&self, w: &mut Writer) {
                w.put_list(&self.0, $max);
            }
        }

        impl NoosDecode for $name {
            fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
                Ok(Self(r.get_list($max)?))
            }
        }
    };
}

bounded_list!(
    /// Size-variable declarations (<= 8).
    SizeVarList,
    SizeVarDecl,
    MAX_SIZE_VARS
);
bounded_list!(
    /// `max`-combined polynomial branches (<= 16).
    BranchList,
    CostBranch,
    MAX_COST_BRANCHES
);
bounded_list!(
    /// Terms of one branch (<= 64).
    TermList,
    CostTerm,
    MAX_COST_TERMS
);
bounded_list!(
    /// Evaluation trials (<= 16).
    TrialList,
    CostTrial,
    MAX_COST_TRIALS
);
bounded_list!(
    /// Trial size assignment (<= 8 u64 values).
    SizeList,
    u64,
    MAX_SIZE_VARS
);
bounded_list!(
    /// Numeric-profile references (<= 8).
    ProfileRefList,
    Hash32,
    MAX_PROFILE_REFS
);
bounded_list!(
    /// Jet-obligation references (<= 32).
    ObligationRefList,
    Hash32,
    MAX_OBLIGATION_REFS
);

// ---------------------------------------------------------------------------
// Closed u16 enums (declaration-order discriminants; unknown rejects)
// ---------------------------------------------------------------------------

macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $disc:expr ),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u16)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $disc, )+
        }

        impl $name {
            const VARIANT_COUNT: u16 = {
                let mut n: u16 = 0;
                $( let _ = $name::$variant; n += 1; )+
                n
            };

            /// Stable wire discriminant.
            #[inline]
            #[must_use]
            pub fn discriminant(self) -> u16 {
                self as u16
            }
        }

        impl NoosEncode for $name {
            fn encode(&self, w: &mut Writer) {
                w.put_u16(*self as u16);
            }
        }

        impl NoosDecode for $name {
            fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
                let d = r.get_discriminant(Self::VARIANT_COUNT)?;
                $( if d == $disc { return Ok($name::$variant); } )+
                Err(CodecError::UnknownDiscriminant)
            }
        }
    };
}

wire_enum!(
    /// Requantization rule of a numeric profile. `RoundHalfUpShift` is the
    /// measured kt-ladder rule: `sat8((i64(acc)*i64(mult) + (1<<(shift-1))) >> shift)`.
    RequantKind {
        RoundHalfUpShift = 0,
    }
);

wire_enum!(
    /// Certificate market lifecycle status (ch06 §5.4 vocabulary).
    JetStatus {
        Proposed = 0,
        Challengeable = 1,
        Admitted = 2,
        Quarantined = 3,
        Revoked = 4,
        Superseded = 5,
    }
);

wire_enum!(
    /// Registered transcript layout. `Sha256FlatV0` is `tl:sha256-flat-v0`:
    /// `root = SHA256(A || B || C32 || params24)`; challenge block 0 is the
    /// root in place, `block_i = SHA256(root || u32le(i))` (32-bit words).
    TranscriptLayout {
        Sha256FlatV0 = 0,
    }
);

wire_enum!(
    /// What `verifier_ref` names.
    VerifierKind {
        /// A canonical Grain formula id (D-WEFT-FORMULA).
        GrainFormula = 0,
        /// An RV32IM guest binary hash.
        Rv32Guest = 1,
    }
);

wire_enum!(
    /// Beacon discipline. The checker accepts only `PostCommitRequired`;
    /// `OfflineDerived` is expressible on the wire exactly so it can be
    /// rejected with a stable code (ch06 §3.3 "checker: rejects
    /// offline-derived").
    BeaconPolicy {
        PostCommitRequired = 0,
        OfflineDerived = 1,
    }
);

wire_enum!(
    /// Registered journal schema. `SpanV0` is `js:span-v0`:
    /// `(m,k,n,quant,H(A),H(B),H(C32),H(C8),beacon,payout,root)`.
    JournalSchema {
        SpanV0 = 0,
    }
);

// ---------------------------------------------------------------------------
// Cost-polynomial component structs
// ---------------------------------------------------------------------------

/// One declared size variable with its inclusive upper bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeVarDecl {
    pub name: SizeVarName,
    pub max_value: u64,
}

impl NoosEncode for SizeVarDecl {
    fn encode(&self, w: &mut Writer) {
        self.name.encode(w);
        w.put_u64(self.max_value);
    }
}

impl NoosDecode for SizeVarDecl {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            name: SizeVarName::decode(r)?,
            max_value: r.get_u64()?,
        })
    }
}

/// One monomial: `coeff * prod(size_i ^ exponents[i])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostTerm {
    pub coeff: u64,
    pub exponents: Exponents,
}

impl NoosEncode for CostTerm {
    fn encode(&self, w: &mut Writer) {
        w.put_u64(self.coeff);
        self.exponents.encode(w);
    }
}

impl NoosDecode for CostTerm {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            coeff: r.get_u64()?,
            exponents: Exponents::decode(r)?,
        })
    }
}

/// One branch: the sum of its terms. The certificate's bound is the `max`
/// over all branches (frozen branch-`max` semantics, plan §5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostBranch {
    pub terms: TermList,
}

impl NoosEncode for CostBranch {
    fn encode(&self, w: &mut Writer) {
        self.terms.encode(w);
    }
}

impl NoosDecode for CostBranch {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            terms: TermList::decode(r)?,
        })
    }
}

/// One evaluation trial: a full size assignment plus a canonical Grain
/// subject the checker evaluates the embedded formula against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostTrial {
    pub sizes: SizeList,
    pub subject: SubjectBytes,
}

impl NoosEncode for CostTrial {
    fn encode(&self, w: &mut Writer) {
        self.sizes.encode(w);
        self.subject.encode(w);
    }
}

impl NoosDecode for CostTrial {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            sizes: SizeList::decode(r)?,
            subject: SubjectBytes::decode(r)?,
        })
    }
}

// ---------------------------------------------------------------------------
// The five v0 objects
// ---------------------------------------------------------------------------

define_object! {
    /// NumericProfileV0 (weft-v0.md §4.1): exact quantization semantics as
    /// data. `profile_id = H(D-WEFT-PROFILE || canonical bytes)`.
    pub struct NumericProfileV0 {
        version: 0;
        1 => name: ProfileName,
        2 => weight_bits: u8,
        3 => activation_bits: u8,
        4 => accum_bits: u8,
        5 => accum_exact: u8,
        6 => requant_kind: RequantKind,
        7 => requant_mult: u32,
        8 => requant_shift: u8,
        9 => saturate_min_twos: u8,
        10 => saturate_max_twos: u8,
        11 => forbid_flags: u32,
    }
}

define_object! {
    /// CostCertificateV0 (weft-v0.md §4.2): a declared cost polynomial over
    /// size variables, NEVER trusted — the checker re-derives every bound
    /// with checked arithmetic and, when the formula is embedded, executes
    /// the trials. `cost_certificate_id = H(D-WEFT-COST || canonical bytes)`.
    pub struct CostCertificateV0 {
        version: 0;
        1 => formula_id: [u8; 32],
        2 => grain_version: u32,
        3 => size_vars: SizeVarList,
        4 => branches: BranchList,
        5 => formula_bytes: FormulaBytes,
        6 => trials: TrialList,
    }
}

define_object! {
    /// MeaningContractV0 (weft-v0.md §4.3, ch06 §5.2): binds every
    /// representation of a computation to one Grain meaning.
    /// `meaning_id = H(D-WEFT-MEANING || canonical bytes)`. Zero hashes are
    /// the frozen "absent" sentinel for `compiler_id` (hand-authored — v0
    /// has no compiler), `source_root`, `cost_certificate_id`, and
    /// `rv32_guest_hash`.
    pub struct MeaningContractV0 {
        version: 0;
        1 => formula_id: [u8; 32],
        2 => grain_version: u32,
        3 => compiler_id: [u8; 32],
        4 => source_root: [u8; 32],
        5 => type_signature: TypeSignature,
        6 => profile_ids: ProfileRefList,
        7 => cost_certificate_id: [u8; 32],
        8 => rv32_guest_hash: [u8; 32],
        9 => obligation_ids: ObligationRefList,
    }
}

define_object! {
    /// JetCertificateV0 (weft-v0.md §4.4; ch01 §7.4 JetEntry / ch06 §4.2
    /// EquivalenceObligation): a bonded observational-equivalence claim.
    /// The registry key stays `(grain_version, formula_id)`; this object is
    /// the certificate the registry stores under it.
    /// `jet_certificate_id = H(D-WEFT-JETCERT || canonical bytes)`.
    pub struct JetCertificateV0 {
        version: 0;
        1 => grain_version: u32,
        2 => formula_id: [u8; 32],
        3 => impl_hash: [u8; 32],
        4 => target_triple: TargetTriple,
        5 => profile_id: [u8; 32],
        6 => cost_certificate_id: [u8; 32],
        7 => corpus_root: [u8; 32],
        8 => bond_micro_noos: u64,
        9 => status: JetStatus,
        10 => admitted_height: u64,
        11 => revoked_height: u64,
    }
}

define_object! {
    /// SpanStatementV0 (weft-v0.md §4.5, ch06 §3.3 wire example): a
    /// dispute-leaf-ready span claim. `span_id = H(D-WEFT-SPAN || canonical
    /// bytes)`.
    pub struct SpanStatementV0 {
        version: 0;
        1 => profile_id: [u8; 32],
        2 => shape_m: u32,
        3 => shape_k: u32,
        4 => shape_n: u32,
        5 => transcript_layout: TranscriptLayout,
        6 => verifier_kind: VerifierKind,
        7 => verifier_ref: [u8; 32],
        8 => soundness_reps: u16,
        9 => soundness_rbits: u16,
        10 => beacon_policy: BeaconPolicy,
        11 => journal_schema: JournalSchema,
    }
}

// ---------------------------------------------------------------------------
// Object kinds and the tagged union
// ---------------------------------------------------------------------------

/// Closed set of v0 object kinds. The stable names are the vector/store
/// vocabulary; anything else is `UNKNOWN_OBJECT_KIND`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    NumericProfile,
    CostCertificate,
    MeaningContract,
    JetCertificate,
    SpanStatement,
}

impl ObjectKind {
    /// Every kind, in canonical order.
    pub const ALL: &'static [ObjectKind] = &[
        ObjectKind::NumericProfile,
        ObjectKind::CostCertificate,
        ObjectKind::MeaningContract,
        ObjectKind::JetCertificate,
        ObjectKind::SpanStatement,
    ];

    /// Stable kind name used by conformance vectors.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ObjectKind::NumericProfile => "numeric_profile",
            ObjectKind::CostCertificate => "cost_certificate",
            ObjectKind::MeaningContract => "meaning_contract",
            ObjectKind::JetCertificate => "jet_certificate",
            ObjectKind::SpanStatement => "span_statement",
        }
    }

    /// Inverse of [`ObjectKind::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<ObjectKind> {
        ObjectKind::ALL.iter().copied().find(|k| k.name() == name)
    }
}

/// A decoded v0 object of any kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeftObjectV0 {
    Profile(NumericProfileV0),
    Cost(CostCertificateV0),
    Meaning(MeaningContractV0),
    Jet(JetCertificateV0),
    Span(SpanStatementV0),
}

impl WeftObjectV0 {
    #[must_use]
    pub fn kind(&self) -> ObjectKind {
        match self {
            WeftObjectV0::Profile(_) => ObjectKind::NumericProfile,
            WeftObjectV0::Cost(_) => ObjectKind::CostCertificate,
            WeftObjectV0::Meaning(_) => ObjectKind::MeaningContract,
            WeftObjectV0::Jet(_) => ObjectKind::JetCertificate,
            WeftObjectV0::Span(_) => ObjectKind::SpanStatement,
        }
    }

    /// Canonical bytes of the wrapped object.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        match self {
            WeftObjectV0::Profile(o) => o.encode_canonical(),
            WeftObjectV0::Cost(o) => o.encode_canonical(),
            WeftObjectV0::Meaning(o) => o.encode_canonical(),
            WeftObjectV0::Jet(o) => o.encode_canonical(),
            WeftObjectV0::Span(o) => o.encode_canonical(),
        }
    }

    /// Whole-input canonical decode of `bytes` as `kind`.
    pub fn decode_canonical(
        kind: ObjectKind,
        bytes: &[u8],
    ) -> Result<WeftObjectV0, crate::WeftError> {
        Ok(match kind {
            ObjectKind::NumericProfile => {
                WeftObjectV0::Profile(NumericProfileV0::decode_canonical(bytes)?)
            }
            ObjectKind::CostCertificate => {
                WeftObjectV0::Cost(CostCertificateV0::decode_canonical(bytes)?)
            }
            ObjectKind::MeaningContract => {
                WeftObjectV0::Meaning(MeaningContractV0::decode_canonical(bytes)?)
            }
            ObjectKind::JetCertificate => {
                WeftObjectV0::Jet(JetCertificateV0::decode_canonical(bytes)?)
            }
            ObjectKind::SpanStatement => {
                WeftObjectV0::Span(SpanStatementV0::decode_canonical(bytes)?)
            }
        })
    }
}
