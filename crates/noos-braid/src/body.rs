//! Canonical `BlockBodyV1` (header-body.md; ch01 §9.2) plus
//! `FinalityCertificateV1` and `BlobDescriptorV1`.
//!
//! Collection maxima are the PROPOSED-G0 values of the schema table; each is
//! a decode-level bound (`LengthExceedsBound` past it). Element families
//! owned by other layers are reused, never re-declared:
//!
//! * `transactions[]` — `noos_lumen::objects::TransactionV1` (max 1048576);
//! * `segregated_witnesses[]` — `noos_lumen::objects::TransactionWitnessesV1`
//!   (max 1048576), positionally corresponding to `transactions[]`; the
//!   "keyed by txid" phrasing of ch01 §9.2 is realized by the `witness_root`
//!   commitment, not by a redundant wire key;
//! * `system_transitions[]` — opaque canonical bytes (max 256 elements,
//!   65536 bytes each, PROPOSED-G0) pending the system-transition schema
//!   table; applied before transactions (ch01 §9.3);
//! * `finality_certificates[]` — [`FinalityCertificateV1`] (max 8);
//! * `ground_ticket` — exactly one [`noos_ground::GroundTicketV1`], carried
//!   as its frozen 76-byte fixed-width encoding (mandatory on every block,
//!   ch01 §4.2);
//! * `loom_credit_claims[]` — collection max **0** while
//!   `work_loom_credit_enabled = false`: any nonzero count is a decode-level
//!   `LengthExceedsBound`, so a body smuggling Loom claims cannot even be
//!   parsed (plan §6.3); enabling the lane is a versioned wire change;
//! * `consensus_blob_descriptors[]` — [`BlobDescriptorV1`] (max 64, da.md).

use core::fmt;
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};
use noos_ground::{GroundTicketV1, TICKET_ENCODED_BYTES};
use noos_lumen::objects::{
    BoundedBytes, BoundedList, OptionalHash32, OptionalObject, TransactionV1,
    TransactionWitnessesV1,
};

use crate::header::{Bytes96, CheckpointRef};

/// Maximum transactions per macroblock (PROPOSED-G0 high-throughput profile).
pub const MAX_TRANSACTIONS: u32 = 1_048_576;
/// Maximum segregated witness bundles per macroblock.
pub const MAX_SEGREGATED_WITNESSES: u32 = 1_048_576;
/// Maximum system transitions per block (PROPOSED-G0).
pub const MAX_SYSTEM_TRANSITIONS: u32 = 256;
/// Maximum finality certificates per block (PROPOSED-G0).
pub const MAX_FINALITY_CERTIFICATES: u32 = 8;
/// Maximum Loom credit claims per block: hard zero while disabled (plan §6.3).
pub const MAX_LOOM_CREDIT_CLAIMS: u32 = 0;
/// Maximum consensus blob descriptors per block (PROPOSED-G0, da.md).
pub const MAX_CONSENSUS_BLOB_DESCRIPTORS: u32 = 64;
/// Maximum participation-bitmap bytes: covers `N_hard = 1024` bits.
pub const MAX_PARTICIPATION_BITMAP_BYTES: u32 = 128;

// ---------------------------------------------------------------------------
// Ground ticket wire adapter
// ---------------------------------------------------------------------------

/// noos-codec adapter around the fixed-width [`GroundTicketV1`] encoding
/// (`profile_id u32 LE || nonce u64 LE || extra_nonce[32] || digest[32]`,
/// 76 bytes; noos-ground owns the layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroundTicketWire(pub GroundTicketV1);

impl NoosEncode for GroundTicketWire {
    fn encode(&self, w: &mut Writer) {
        w.put_raw(&self.0.encode());
    }
}

impl NoosDecode for GroundTicketWire {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut raw = [0_u8; TICKET_ENCODED_BYTES];
        for b in &mut raw {
            *b = r.get_u8()?;
        }
        // The 76-byte layout is total: every byte pattern decodes.
        GroundTicketV1::decode(&raw)
            .map(Self)
            .ok_or(CodecError::Truncated)
    }
}

// ---------------------------------------------------------------------------
// FinalityCertificateV1
// ---------------------------------------------------------------------------

define_object! {
    /// Aggregate checkpoint-vote certificate (ch01 §4.8 prose; plan §6.6;
    /// header-body.md). Justification requires `floor(2*W/3)+1` on BOTH the
    /// raw and effective totals; threshold evaluation is the Witness Ring
    /// crate's concern, this is the frozen wire shape.
    pub struct FinalityCertificateV1 {
        version: 1;
        1 => source: CheckpointRef,
        2 => target: CheckpointRef,
        3 => participation_bitmap: BoundedBytes<MAX_PARTICIPATION_BITMAP_BYTES>,
        4 => aggregate_signature: Bytes96,
        5 => raw_weight_sum: u128,
        6 => effective_weight_sum: u128,
        7 => membership_root: [u8; 32],
    }
}

// ---------------------------------------------------------------------------
// BlobDescriptorV1
// ---------------------------------------------------------------------------

define_object! {
    /// Consensus blob descriptor (ch01 §10.2; da.md widths PROPOSED-G0).
    pub struct BlobDescriptorV1 {
        version: 1;
        1 => namespace: u32,
        2 => content_root: [u8; 32],
        3 => original_bytes: u64,
        4 => shard_bytes: u32,
        5 => data_shards: u16,
        6 => parity_shards: u16,
        7 => retention_epochs: u32,
        8 => codec_id: u16,
        9 => encryption_descriptor: OptionalObject<BoundedBytes<256>>,
        10 => access_policy_root: OptionalHash32,
    }
}

// ---------------------------------------------------------------------------
// BlockBodyV1
// ---------------------------------------------------------------------------

define_object! {
    /// Canonical block body (ch01 §9.2; header-body.md). See the module docs
    /// for element families and maxima.
    pub struct BlockBodyV1 {
        version: 1;
        1 => transactions: BoundedList<TransactionV1, MAX_TRANSACTIONS>,
        2 => segregated_witnesses: BoundedList<TransactionWitnessesV1, MAX_SEGREGATED_WITNESSES>,
        3 => system_transitions: BoundedList<BoundedBytes<65536>, MAX_SYSTEM_TRANSITIONS>,
        4 => finality_certificates: BoundedList<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>,
        5 => ground_ticket: GroundTicketWire,
        6 => loom_credit_claims: BoundedList<BoundedBytes<4096>, MAX_LOOM_CREDIT_CLAIMS>,
        7 => consensus_blob_descriptors: BoundedList<BlobDescriptorV1, MAX_CONSENSUS_BLOB_DESCRIPTORS>,
    }
}

impl BlockBodyV1 {
    /// Canonically encodes this body while substituting only the Ground
    /// ticket. This preserves the exact object wire law without deep-cloning
    /// high-throughput transaction and witness collections.
    #[must_use]
    pub fn encode_canonical_with_ground_ticket(&self, ticket: GroundTicketV1) -> Vec<u8> {
        let estimated = 128_usize
            .saturating_add(self.transactions.len().saturating_mul(384))
            .saturating_add(self.segregated_witnesses.len().saturating_mul(192));
        let mut writer = Writer::with_capacity(estimated);
        writer.put_u16(Self::VERSION);
        writer.put_mandatory_tag(1);
        self.transactions.encode(&mut writer);
        writer.put_mandatory_tag(2);
        self.segregated_witnesses.encode(&mut writer);
        writer.put_mandatory_tag(3);
        self.system_transitions.encode(&mut writer);
        writer.put_mandatory_tag(4);
        self.finality_certificates.encode(&mut writer);
        writer.put_mandatory_tag(5);
        GroundTicketWire(ticket).encode(&mut writer);
        writer.put_mandatory_tag(6);
        self.loom_credit_claims.encode(&mut writer);
        writer.put_mandatory_tag(7);
        self.consensus_blob_descriptors.encode(&mut writer);
        writer.into_bytes()
    }
}

impl fmt::Display for BlockBodyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockBodyV1 {{ txs: {}, certs: {}, blobs: {} }}",
            self.transactions.as_slice().len(),
            self.finality_certificates.as_slice().len(),
            self.consensus_blob_descriptors.as_slice().len()
        )
    }
}
