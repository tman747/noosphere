//! Canonical `BlockHeaderV1` (plan §6.3; header-body.md; ch01 §9.1) plus the
//! block-hash and proposal-commitment laws.
//!
//! ## Wire layout
//!
//! The header is a versioned mandatory-tagged noos-codec object. The leading
//! canonical `u16` object version IS schema field #1 (`version`) of
//! `header-body.md`, hoisted to the front per the noos-codec object law; the
//! remaining 29 fields follow as `tag:u16 || value` pairs in exact schema
//! order with tags 1..=29:
//!
//! | tag | field (schema #) | tag | field (schema #) |
//! |----:|---|----:|---|
//! | 1 | `chain_id` (0) | 16 | `lumen_receipts_state_root` (16) |
//! | 2 | `height` (2) | 17 | `params_root` (17) |
//! | 3 | `slot` (3) | 18 | `justified_checkpoint` (18) |
//! | 4 | `timestamp_ms` (4) | 19 | `finalized_checkpoint` (19) |
//! | 5 | `parent_hash` (5) | 20 | `finality_certificate_root` (20) |
//! | 6 | `proposer_key` (6) | 21 | `witness_membership_root` (21) |
//! | 7 | `tx_root` (7) | 22 | `ground_profile_id` (22) |
//! | 8 | `witness_root` (8) | 23 | `ground_target` (23) |
//! | 9 | `execution_receipt_root` (9) | 24 | `ground_ticket_root` (24) |
//! | 10 | `evidence_root` (10) | 25 | `loom_credit_root` (25) |
//! | 11 | `body_da_root` (11) | 26 | `loom_credit` (26) |
//! | 12 | `notes_root` (12) | 27 | `gas_used` (27) |
//! | 13 | `nullifiers_root` (13) | 28 | `base_prices` (28) |
//! | 14 | `accounts_root` (14) | 29 | `proposer_signature` (29) |
//! | 15 | `objects_root` (15) | | |
//!
//! ## The receipt split (plan §6.3, decode-level enforcement)
//!
//! ch01 §9.1 sketched a single `receipt_root`; the plan resolves it into TWO
//! mandatory fields with distinct wire tags:
//!
//! * `execution_receipt_root` (tag 9) — ordered execution receipts emitted by
//!   THIS block;
//! * `lumen_receipts_state_root` (tag 16) — post-state projection of
//!   `LumenState.receipts_root` (the compact settled-receipt index).
//!
//! Because decoding demands the exact tag sequence 1..=29, an encoding that
//! omits either field, carries one tag twice, or presents the tags out of
//! order rejects with `UnknownMandatoryField` (or `Truncated`) before any
//! semantic work — field-level interchange is a decode impossibility, never a
//! validation afterthought. (Swapping the two 32-byte *values* under their
//! correct tags is byte-plausible; that confusion is caught by state-root
//! verification in the transition layer, ch01 §9.3.)
//!
//! ## Hash laws
//!
//! * Block hash = `BLAKE3-256("NOOS/BLOCK/HEADER/V1" || canonical header)`,
//!   the full encoding INCLUDING `proposer_signature` (ch01 §9.1;
//!   D-BLOCK-HEADER).
//! * `proposal_commitment` (ch01 §4.2) = `BLAKE3-256("NOOS/BLOCK/PROPOSAL/V1"
//!   || version_u16_le || (tag_u16_le || canonical bytes) for every header
//!   field in tag order EXCEPT tags 24 (`ground_ticket_root`) and 29
//!   (`proposer_signature`))`. The ticket itself and the final block hash are
//!   not header fields, so their exclusion is structural. All fields are
//!   fixed-width and tags are distinct, so the preimage is injective.

use core::fmt;
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};
use noos_crypto::{hash_domain, CryptoError, DomainId, Hash32};
use noos_ground::{GROUND_PROFILE_ID_V1, U256};

/// Epoch length in block heights (ch01 §4.1; constants-v1.toml `[braid]`).
pub const EPOCH_LENGTH: u64 = 256;

/// The all-zero 32-byte root: canonical value for disabled-lane roots.
pub const ZERO_ROOT: [u8; 32] = [0_u8; 32];

// ---------------------------------------------------------------------------
// Fixed-width compound field types
// ---------------------------------------------------------------------------

/// BLS public key bytes (header schema `Bytes48`), raw fixed width on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bytes48(pub [u8; 48]);

impl fmt::Debug for Bytes48 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes48(..)")
    }
}

impl NoosEncode for Bytes48 {
    fn encode(&self, w: &mut Writer) {
        w.put_raw(&self.0);
    }
}

impl NoosDecode for Bytes48 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut out = [0_u8; 48];
        for b in &mut out {
            *b = r.get_u8()?;
        }
        Ok(Self(out))
    }
}

/// BLS signature bytes (header schema `Bytes96`), raw fixed width on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Bytes96(pub [u8; 96]);

impl fmt::Debug for Bytes96 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes96(..)")
    }
}

impl NoosEncode for Bytes96 {
    fn encode(&self, w: &mut Writer) {
        w.put_raw(&self.0);
    }
}

impl NoosDecode for Bytes96 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut out = [0_u8; 96];
        for b in &mut out {
            *b = r.get_u8()?;
        }
        Ok(Self(out))
    }
}

/// Checkpoint reference (header-body.md; ch01 §4.1: the checkpoint for epoch
/// `e` is the first block at height `e * 256`).
///
/// Fixed 40-byte inline compound: `epoch u64 LE || checkpoint_hash 32`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckpointRef {
    pub epoch: u64,
    pub checkpoint_hash: [u8; 32],
}

impl CheckpointRef {
    /// Height at which this checkpoint block must sit (ch01 §4.1).
    ///
    /// `None` on `epoch * 256` overflow (unreachable on any real chain).
    #[must_use]
    pub fn expected_height(&self) -> Option<u64> {
        self.epoch.checked_mul(EPOCH_LENGTH)
    }
}

impl NoosEncode for CheckpointRef {
    fn encode(&self, w: &mut Writer) {
        w.put_u64(self.epoch);
        w.put_array32(&self.checkpoint_hash);
    }
}

impl NoosDecode for CheckpointRef {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: r.get_u64()?,
            checkpoint_hash: r.get_array32()?,
        })
    }
}

/// Header resource total: 5 × u64 LE = 40 bytes, axes B, G, V, R, D
/// (header-body.md field 27; ch01 §6.9).
///
/// Distinct from `noos_lumen::objects::ResourceVector`, which is the
/// *internal* six-word usage vector (state reads/writes split); the header
/// wire law is the frozen five-axis form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceVectorV1 {
    /// B: transaction/body bytes.
    pub bytes: u64,
    /// G: Grain evaluation steps.
    pub grain_steps: u64,
    /// V: proof-verification units.
    pub proof_units: u64,
    /// R: persistent state-word epochs.
    pub state_word_epochs: u64,
    /// D: consensus blob bytes.
    pub blob_bytes: u64,
}

impl NoosEncode for ResourceVectorV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u64(self.bytes);
        w.put_u64(self.grain_steps);
        w.put_u64(self.proof_units);
        w.put_u64(self.state_word_epochs);
        w.put_u64(self.blob_bytes);
    }
}

impl NoosDecode for ResourceVectorV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            bytes: r.get_u64()?,
            grain_steps: r.get_u64()?,
            proof_units: r.get_u64()?,
            state_word_epochs: r.get_u64()?,
            blob_bytes: r.get_u64()?,
        })
    }
}

/// Header per-dimension base prices: 5 × u64 LE = 40 bytes, same axis order
/// as [`ResourceVectorV1`] (header-body.md field 28).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourcePriceVectorV1 {
    pub p_bytes: u64,
    pub p_grain_steps: u64,
    pub p_proof_units: u64,
    pub p_state_word_epochs: u64,
    pub p_blob_bytes: u64,
}

impl NoosEncode for ResourcePriceVectorV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u64(self.p_bytes);
        w.put_u64(self.p_grain_steps);
        w.put_u64(self.p_proof_units);
        w.put_u64(self.p_state_word_epochs);
        w.put_u64(self.p_blob_bytes);
    }
}

impl NoosDecode for ResourcePriceVectorV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            p_bytes: r.get_u64()?,
            p_grain_steps: r.get_u64()?,
            p_proof_units: r.get_u64()?,
            p_state_word_epochs: r.get_u64()?,
            p_blob_bytes: r.get_u64()?,
        })
    }
}

// ---------------------------------------------------------------------------
// BlockHeaderV1
// ---------------------------------------------------------------------------

define_object! {
    /// Canonical block header (header-body.md; ch01 §9.1 with the plan §6.3
    /// receipt split). The leading object version is schema field #1; the 29
    /// tagged fields follow in schema order. See the module docs for the
    /// full tag table and hash laws.
    pub struct BlockHeaderV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => height: u64,
        3 => slot: u64,
        4 => timestamp_ms: u64,
        5 => parent_hash: [u8; 32],
        6 => proposer_key: Bytes48,
        7 => tx_root: [u8; 32],
        8 => witness_root: [u8; 32],
        9 => execution_receipt_root: [u8; 32],
        10 => evidence_root: [u8; 32],
        11 => body_da_root: [u8; 32],
        12 => notes_root: [u8; 32],
        13 => nullifiers_root: [u8; 32],
        14 => accounts_root: [u8; 32],
        15 => objects_root: [u8; 32],
        16 => lumen_receipts_state_root: [u8; 32],
        17 => params_root: [u8; 32],
        18 => justified_checkpoint: CheckpointRef,
        19 => finalized_checkpoint: CheckpointRef,
        20 => finality_certificate_root: [u8; 32],
        21 => witness_membership_root: [u8; 32],
        22 => ground_profile_id: u32,
        23 => ground_target: [u8; 32],
        24 => ground_ticket_root: [u8; 32],
        25 => loom_credit_root: [u8; 32],
        26 => loom_credit: u128,
        27 => gas_used: ResourceVectorV1,
        28 => base_prices: ResourcePriceVectorV1,
        29 => proposer_signature: Bytes96,
    }
}

/// Tag of `ground_ticket_root` (excluded from the proposal commitment).
pub const TAG_GROUND_TICKET_ROOT: u16 = 24;
/// Tag of `proposer_signature` (excluded from the proposal commitment).
pub const TAG_PROPOSER_SIGNATURE: u16 = 29;

impl BlockHeaderV1 {
    /// `ground_target` as an exact [`U256`] (wire field 23 is 32 bytes LE).
    #[must_use]
    pub fn ground_target_u256(&self) -> U256 {
        U256::from_le_bytes(&self.ground_target)
    }

    /// Block hash: `BLAKE3-256(D-BLOCK-HEADER || canonical header)`, the
    /// full encoding including `proposer_signature` (ch01 §9.1).
    ///
    /// # Errors
    /// Only on registry misuse inside `noos-crypto`; `D-BLOCK-HEADER` is a
    /// registered `BLAKE3_CONTEXT` row, so callers may treat an error as a
    /// build defect.
    pub fn block_hash(&self) -> Result<Hash32, CryptoError> {
        hash_domain(DomainId::BlockHeader, &[&self.encode_canonical()])
    }

    /// Proposal commitment (ch01 §4.2; D-PROPOSAL-COMMITMENT).
    ///
    /// Preimage: `version u16 LE`, then `tag u16 LE || canonical bytes` for
    /// every header field in tag order 1..=29 EXCEPT
    /// [`TAG_GROUND_TICKET_ROOT`] (24) and [`TAG_PROPOSER_SIGNATURE`] (29).
    /// The ticket itself and the final block hash are not header fields, so
    /// the ch01 §4.2 exclusion list is complete. This binds all body/state/
    /// DA roots, checkpoint references, resource totals, base prices, and
    /// the complete Loom credit root/value BEFORE Ground nonce search.
    ///
    /// # Errors
    /// Only on registry misuse inside `noos-crypto` (see
    /// [`block_hash`](Self::block_hash)).
    pub fn proposal_commitment(&self) -> Result<Hash32, CryptoError> {
        let mut w = Writer::with_capacity(640);
        w.put_u16(Self::VERSION);
        macro_rules! field {
            ($tag:expr, $f:ident) => {
                w.put_mandatory_tag($tag);
                NoosEncode::encode(&self.$f, &mut w);
            };
        }
        field!(1, chain_id);
        field!(2, height);
        field!(3, slot);
        field!(4, timestamp_ms);
        field!(5, parent_hash);
        field!(6, proposer_key);
        field!(7, tx_root);
        field!(8, witness_root);
        field!(9, execution_receipt_root);
        field!(10, evidence_root);
        field!(11, body_da_root);
        field!(12, notes_root);
        field!(13, nullifiers_root);
        field!(14, accounts_root);
        field!(15, objects_root);
        field!(16, lumen_receipts_state_root);
        field!(17, params_root);
        field!(18, justified_checkpoint);
        field!(19, finalized_checkpoint);
        field!(20, finality_certificate_root);
        field!(21, witness_membership_root);
        field!(22, ground_profile_id);
        field!(23, ground_target);
        // tag 24 ground_ticket_root: EXCLUDED (searched after commitment).
        field!(25, loom_credit_root);
        field!(26, loom_credit);
        field!(27, gas_used);
        field!(28, base_prices);
        // tag 29 proposer_signature: EXCLUDED (signed after search).
        hash_domain(DomainId::ProposalCommitment, &[w.as_bytes()])
    }

    /// Structural header validation, independent of parent context:
    ///
    /// 1. `chain_id` equals the local frozen identity, else
    ///    `wrong_protocol_identity` (identity-v1.md);
    /// 2. `ground_profile_id == 1` under Braid v1 (ch01 §4.2 rule 1);
    /// 3. while `work_loom_credit_enabled = false` (genesis control), the
    ///    Loom credit fields canonicalize to zero: `loom_credit == 0` AND
    ///    `loom_credit_root == ZERO_ROOT` (plan §6.3);
    /// 4. checkpoint sanity: `justified.epoch >= finalized.epoch`.
    ///
    /// Parent-relative laws (height/slot/timestamp linkage, checkpoint
    /// monotonicity) live in the DAG insert path; the full Ground ticket law
    /// is `noos_ground::validate_ticket`.
    ///
    /// # Errors
    /// The first violated rule, as a [`HeaderError`].
    pub fn validate_structure(
        &self,
        expected_chain_id: &[u8; 32],
        work_loom_credit_enabled: bool,
    ) -> Result<(), HeaderError> {
        if &self.chain_id != expected_chain_id {
            return Err(HeaderError::WrongProtocolIdentity);
        }
        if self.ground_profile_id != GROUND_PROFILE_ID_V1 {
            return Err(HeaderError::WrongGroundProfile {
                got: self.ground_profile_id,
            });
        }
        if !work_loom_credit_enabled
            && (self.loom_credit != 0 || self.loom_credit_root != ZERO_ROOT)
        {
            return Err(HeaderError::LoomCreditDisabled);
        }
        if self.justified_checkpoint.epoch < self.finalized_checkpoint.epoch {
            return Err(HeaderError::JustifiedBelowFinalized);
        }
        Ok(())
    }
}

/// Structural header validation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// `chain_id` does not match the frozen local identity; old-protocol
    /// artifacts reject here, never auto-convert (plan §2.4).
    WrongProtocolIdentity,
    /// `ground_profile_id != 1` under Braid v1.
    WrongGroundProfile { got: u32 },
    /// Nonzero `loom_credit` or `loom_credit_root` while
    /// `work_loom_credit_enabled = false` (plan §6.3; E-DEMAND-WASH-01 keeps
    /// the lane hard-zero).
    LoomCreditDisabled,
    /// `justified_checkpoint.epoch < finalized_checkpoint.epoch`.
    JustifiedBelowFinalized,
}

impl HeaderError {
    /// Stable class name used by conformance vectors.
    #[must_use]
    pub fn class_name(self) -> &'static str {
        match self {
            HeaderError::WrongProtocolIdentity => "wrong_protocol_identity",
            HeaderError::WrongGroundProfile { .. } => "wrong_ground_profile",
            HeaderError::LoomCreditDisabled => "loom_credit_disabled",
            HeaderError::JustifiedBelowFinalized => "justified_below_finalized",
        }
    }
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::WrongProtocolIdentity => f.write_str("wrong_protocol_identity"),
            HeaderError::WrongGroundProfile { got } => {
                write!(f, "wrong ground profile id {got} (expected 1)")
            }
            HeaderError::LoomCreditDisabled => {
                f.write_str("nonzero loom credit while work_loom_credit_enabled=false")
            }
            HeaderError::JustifiedBelowFinalized => {
                f.write_str("justified checkpoint epoch below finalized checkpoint epoch")
            }
        }
    }
}

impl std::error::Error for HeaderError {}
