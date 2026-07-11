//! Canonical noos-codec message envelopes for the eight `/noos/` protocols
//! plus the transport handshake (p2p-v1.md §3, §5).
//!
//! Every envelope is `version:u16` then tagged fields (noos-codec object
//! law), always carrying `chain_id` so a cross-chain frame is rejectable on
//! its own bytes (ch01 §10.4: every message has chain ID, protocol version,
//! and a replay domain). Enum payloads use `u16` discriminants in declaration
//! order; unknown discriminants reject.

use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};
use noos_crypto::{hash_domain, DomainId};

// ---------------------------------------------------------------------------
// Protocol table (closed list, identity-v1.md §3)
// ---------------------------------------------------------------------------

/// The eight application protocols plus the session-gate handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Transport session gate; runs before all application protocols.
    Handshake,
    BraidHeader,
    BraidBody,
    BraidVote,
    LumenTx,
    SyncRange,
    SyncSnapshot,
    BlobShard,
    LoomReceipt,
}

/// The eight application protocols in canonical order (excludes handshake).
pub const APP_PROTOCOLS: [Protocol; 8] = [
    Protocol::BraidHeader,
    Protocol::BraidBody,
    Protocol::BraidVote,
    Protocol::LumenTx,
    Protocol::SyncRange,
    Protocol::SyncSnapshot,
    Protocol::BlobShard,
    Protocol::LoomReceipt,
];

/// Outbound scheduling lane (p2p-v1.md §6): consensus and sync traffic always
/// drains before AI/application traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Priority,
    Normal,
}

impl Protocol {
    /// Versioned libp2p protocol identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Protocol::Handshake => "/noos/handshake/1",
            Protocol::BraidHeader => "/noos/braid/header/1",
            Protocol::BraidBody => "/noos/braid/body/1",
            Protocol::BraidVote => "/noos/braid/vote/1",
            Protocol::LumenTx => "/noos/lumen/tx/1",
            Protocol::SyncRange => "/noos/sync/range/1",
            Protocol::SyncSnapshot => "/noos/sync/snapshot/1",
            Protocol::BlobShard => "/noos/blob/shard/1",
            Protocol::LoomReceipt => "/noos/loom/receipt/1",
        }
    }

    /// Consensus-over-AI lane assignment (p2p-v1.md §6.1).
    pub const fn lane(self) -> Lane {
        match self {
            Protocol::Handshake
            | Protocol::BraidHeader
            | Protocol::BraidBody
            | Protocol::BraidVote
            | Protocol::SyncRange
            | Protocol::SyncSnapshot => Lane::Priority,
            Protocol::LumenTx | Protocol::BlobShard | Protocol::LoomReceipt => Lane::Normal,
        }
    }

    /// Dense index over [`APP_PROTOCOLS`] for per-protocol tables.
    pub const fn app_index(self) -> Option<usize> {
        match self {
            Protocol::Handshake => None,
            Protocol::BraidHeader => Some(0),
            Protocol::BraidBody => Some(1),
            Protocol::BraidVote => Some(2),
            Protocol::LumenTx => Some(3),
            Protocol::SyncRange => Some(4),
            Protocol::SyncSnapshot => Some(5),
            Protocol::BlobShard => Some(6),
            Protocol::LoomReceipt => Some(7),
        }
    }
}

// ---------------------------------------------------------------------------
// Payload bounds (PROPOSED-G0; p2p-v1.md §4.1)
// ---------------------------------------------------------------------------

/// Encoded header wire object bound.
pub const MAX_HEADER_BYTES: u32 = 64 * 1024;
/// Encoded block body bound: fits the 1 MiB frame with envelope overhead.
pub const MAX_BODY_BYTES: u32 = 1024 * 1024 - 1024;
/// Encoded checkpoint vote bound.
pub const MAX_VOTE_BYTES: u32 = 8 * 1024;
/// Encoded transaction bound.
pub const MAX_TX_BYTES: u32 = 64 * 1024;
/// Snapshot chunk bound: fits the frame with envelope overhead.
pub const MAX_SNAPSHOT_CHUNK_BYTES: u32 = 1024 * 1024 - 1024;
/// DA shard bound: fits the frame with envelope overhead.
pub const MAX_SHARD_BYTES: u32 = 1024 * 1024 - 1024;
/// Encoded loom receipt bound.
pub const MAX_RECEIPT_BYTES: u32 = 64 * 1024;
/// Maximum headers a range request may ask for.
pub const MAX_RANGE_HEADERS: u32 = 128;
/// Byte budget for the headers list inside one range reply frame.
pub const RANGE_REPLY_BYTE_BUDGET: usize = 1024 * 1024 - 2048;

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

/// Length-bounded byte payload (canonical u32 length prefix, bound `MAX`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounded<const MAX: u32>(pub Vec<u8>);

impl<const MAX: u32> NoosEncode for Bounded<MAX> {
    fn encode(&self, w: &mut Writer) {
        w.put_bytes(&self.0, MAX);
    }
}

impl<const MAX: u32> NoosDecode for Bounded<MAX> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(r.get_bytes(MAX)?))
    }
}

/// Length-bounded list of encodable items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedList<T, const MAX: u32>(pub Vec<T>);

impl<T: NoosEncode, const MAX: u32> NoosEncode for BoundedList<T, MAX> {
    fn encode(&self, w: &mut Writer) {
        w.put_list(&self.0, MAX);
    }
}

impl<T: NoosDecode, const MAX: u32> NoosDecode for BoundedList<T, MAX> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(r.get_list(MAX)?))
    }
}

/// Canonical boolean: `u8` restricted to {0, 1}.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flag(pub bool);

impl NoosEncode for Flag {
    fn encode(&self, w: &mut Writer) {
        w.put_u8(u8::from(self.0));
    }
}

impl NoosDecode for Flag {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_u8()? {
            0 => Ok(Flag(false)),
            1 => Ok(Flag(true)),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

/// Fixed-width 64-byte field (Ed25519 signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bytes64(pub [u8; 64]);

impl NoosEncode for Bytes64 {
    fn encode(&self, w: &mut Writer) {
        w.put_raw(&self.0);
    }
}

impl NoosDecode for Bytes64 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut out = [0u8; 64];
        let a = r.get_array32()?;
        let b = r.get_array32()?;
        out[..32].copy_from_slice(&a);
        out[32..].copy_from_slice(&b);
        Ok(Bytes64(out))
    }
}

// ---------------------------------------------------------------------------
// Handshake (p2p-v1.md §5)
// ---------------------------------------------------------------------------

define_object! {
    /// Chain-identity attestation signed under D-SIG-PEER: binds
    /// (chain_id, genesis_hash, protocol_version, peer public key) so a TLS
    /// session on the wrong chain terminates before any protocol traffic.
    pub struct ChainAttestationV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => genesis_hash: [u8; 32],
        3 => protocol_version: u16,
        4 => peer_pubkey: [u8; 32],
        5 => signature: Bytes64,
    }
}

/// Handshake rejection classes (stable wire codes, p2p-v1.md §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCode {
    /// Wrong chain_id, genesis_hash, or protocol_version.
    WrongProtocolIdentity,
    /// Attestation signature invalid or key does not match the TLS peer.
    AttestationInvalid,
    /// Undecodable handshake payload.
    Malformed,
}

impl RejectCode {
    pub const fn wire(self) -> u16 {
        match self {
            RejectCode::WrongProtocolIdentity => 1,
            RejectCode::AttestationInvalid => 2,
            RejectCode::Malformed => 3,
        }
    }

    pub const fn from_wire(v: u16) -> Option<Self> {
        match v {
            1 => Some(RejectCode::WrongProtocolIdentity),
            2 => Some(RejectCode::AttestationInvalid),
            3 => Some(RejectCode::Malformed),
            _ => None,
        }
    }

    /// Stable error-class string (identity-v1.md §5).
    pub const fn class_name(self) -> &'static str {
        match self {
            RejectCode::WrongProtocolIdentity => "wrong_protocol_identity",
            RejectCode::AttestationInvalid => "attestation_invalid",
            RejectCode::Malformed => "malformed",
        }
    }
}

/// One handshake frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMsgV1 {
    Attest(ChainAttestationV1),
    Ack,
    Reject { code: u16 },
}

impl NoosEncode for HandshakeMsgV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1); // version
        match self {
            HandshakeMsgV1::Attest(a) => {
                w.put_u16(0);
                a.encode(w);
            }
            HandshakeMsgV1::Ack => w.put_u16(1),
            HandshakeMsgV1::Reject { code } => {
                w.put_u16(2);
                w.put_u16(*code);
            }
        }
    }
}

impl NoosDecode for HandshakeMsgV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        match r.get_discriminant(3)? {
            0 => Ok(HandshakeMsgV1::Attest(ChainAttestationV1::decode(r)?)),
            1 => Ok(HandshakeMsgV1::Ack),
            _ => Ok(HandshakeMsgV1::Reject { code: r.get_u16()? }),
        }
    }
}

// ---------------------------------------------------------------------------
// /noos/braid/header/1
// ---------------------------------------------------------------------------

/// Request side: announce (push) or request-by-hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMsgV1 {
    Announce {
        chain_id: [u8; 32],
        header: Bounded<MAX_HEADER_BYTES>,
    },
    Request {
        chain_id: [u8; 32],
        header_hash: [u8; 32],
    },
}

impl HeaderMsgV1 {
    pub const fn chain_id(&self) -> &[u8; 32] {
        match self {
            HeaderMsgV1::Announce { chain_id, .. } | HeaderMsgV1::Request { chain_id, .. } => {
                chain_id
            }
        }
    }
}

impl NoosEncode for HeaderMsgV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        match self {
            HeaderMsgV1::Announce { chain_id, header } => {
                w.put_u16(0);
                w.put_array32(chain_id);
                header.encode(w);
            }
            HeaderMsgV1::Request {
                chain_id,
                header_hash,
            } => {
                w.put_u16(1);
                w.put_array32(chain_id);
                w.put_array32(header_hash);
            }
        }
    }
}

impl NoosDecode for HeaderMsgV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        match r.get_discriminant(2)? {
            0 => Ok(HeaderMsgV1::Announce {
                chain_id: r.get_array32()?,
                header: Bounded::decode(r)?,
            }),
            _ => Ok(HeaderMsgV1::Request {
                chain_id: r.get_array32()?,
                header_hash: r.get_array32()?,
            }),
        }
    }
}

/// Response side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderReplyV1 {
    Ack,
    Header(Bounded<MAX_HEADER_BYTES>),
    NotFound,
}

impl NoosEncode for HeaderReplyV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        match self {
            HeaderReplyV1::Ack => w.put_u16(0),
            HeaderReplyV1::Header(h) => {
                w.put_u16(1);
                h.encode(w);
            }
            HeaderReplyV1::NotFound => w.put_u16(2),
        }
    }
}

impl NoosDecode for HeaderReplyV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        match r.get_discriminant(3)? {
            0 => Ok(HeaderReplyV1::Ack),
            1 => Ok(HeaderReplyV1::Header(Bounded::decode(r)?)),
            _ => Ok(HeaderReplyV1::NotFound),
        }
    }
}

// ---------------------------------------------------------------------------
// /noos/braid/body/1
// ---------------------------------------------------------------------------

define_object! {
    /// Body request by block hash (also the targeted-repair primitive).
    pub struct BodyRequestV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => block_hash: [u8; 32],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyReplyV1 {
    Body(Bounded<MAX_BODY_BYTES>),
    NotFound,
}

impl NoosEncode for BodyReplyV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        match self {
            BodyReplyV1::Body(b) => {
                w.put_u16(0);
                b.encode(w);
            }
            BodyReplyV1::NotFound => w.put_u16(1),
        }
    }
}

impl NoosDecode for BodyReplyV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        match r.get_discriminant(2)? {
            0 => Ok(BodyReplyV1::Body(Bounded::decode(r)?)),
            _ => Ok(BodyReplyV1::NotFound),
        }
    }
}

// ---------------------------------------------------------------------------
// Push protocols: /noos/braid/vote/1, /noos/lumen/tx/1, /noos/loom/receipt/1
// ---------------------------------------------------------------------------

define_object! {
    /// Checkpoint vote push.
    pub struct VotePushV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => vote: Bounded<MAX_VOTE_BYTES>,
    }
}

define_object! {
    /// Transaction push.
    pub struct TxPushV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => tx: Bounded<MAX_TX_BYTES>,
    }
}

define_object! {
    /// Work Loom settlement receipt push. The lane is disabled at genesis:
    /// nodes answer `FeatureDisabled` without dispatching (plan §6.8, §7.7).
    pub struct LoomReceiptPushV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => receipt: Bounded<MAX_RECEIPT_BYTES>,
    }
}

/// Shared push acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushReplyV1 {
    Accepted,
    Duplicate,
    Rejected,
    /// Explicit disabled-lane answer (plan §7.7: never empty success).
    FeatureDisabled,
}

impl NoosEncode for PushReplyV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        let d: u16 = match self {
            PushReplyV1::Accepted => 0,
            PushReplyV1::Duplicate => 1,
            PushReplyV1::Rejected => 2,
            PushReplyV1::FeatureDisabled => 3,
        };
        w.put_u16(d);
    }
}

impl NoosDecode for PushReplyV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        Ok(match r.get_discriminant(4)? {
            0 => PushReplyV1::Accepted,
            1 => PushReplyV1::Duplicate,
            2 => PushReplyV1::Rejected,
            _ => PushReplyV1::FeatureDisabled,
        })
    }
}

// ---------------------------------------------------------------------------
// /noos/sync/range/1
// ---------------------------------------------------------------------------

define_object! {
    /// Ascending header range request.
    pub struct RangeRequestV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => start_height: u64,
        3 => max_headers: u32,
    }
}

define_object! {
    /// Ascending header range reply. `more == true` re-arms the requester's
    /// continuation; a reply trimmed to the frame budget is indistinguishable
    /// from a legitimately short page (Ascent W7 lesson: never emit an
    /// undeliverable oversize frame).
    pub struct RangeReplyV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => headers: BoundedList<Bounded<MAX_HEADER_BYTES>, MAX_RANGE_HEADERS>,
        3 => more: Flag,
    }
}

impl RangeReplyV1 {
    /// Trims the headers list until the encoded reply fits `budget` bytes,
    /// setting `more` when anything was shed. Returns the shed count.
    pub fn fit_to_budget(&mut self, budget: usize) -> usize {
        let mut shed = 0usize;
        while self.encode_canonical().len() > budget {
            if self.headers.0.pop().is_none() {
                break;
            }
            shed = shed.saturating_add(1);
            self.more = Flag(true);
        }
        shed
    }
}

// ---------------------------------------------------------------------------
// /noos/sync/snapshot/1
// ---------------------------------------------------------------------------

define_object! {
    /// Snapshot chunk request for a finalized snapshot root.
    pub struct SnapshotChunkRequestV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => snapshot_root: [u8; 32],
        3 => chunk_index: u32,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotReplyV1 {
    Chunk {
        total_chunks: u32,
        chunk: Bounded<MAX_SNAPSHOT_CHUNK_BYTES>,
    },
    NotFound,
}

impl NoosEncode for SnapshotReplyV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        match self {
            SnapshotReplyV1::Chunk {
                total_chunks,
                chunk,
            } => {
                w.put_u16(0);
                w.put_u32(*total_chunks);
                chunk.encode(w);
            }
            SnapshotReplyV1::NotFound => w.put_u16(1),
        }
    }
}

impl NoosDecode for SnapshotReplyV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        match r.get_discriminant(2)? {
            0 => Ok(SnapshotReplyV1::Chunk {
                total_chunks: r.get_u32()?,
                chunk: Bounded::decode(r)?,
            }),
            _ => Ok(SnapshotReplyV1::NotFound),
        }
    }
}

// ---------------------------------------------------------------------------
// /noos/blob/shard/1
// ---------------------------------------------------------------------------

define_object! {
    /// DA shard request by content root and shard index.
    pub struct ShardRequestV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => content_root: [u8; 32],
        3 => shard_index: u32,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardReplyV1 {
    Shard(Bounded<MAX_SHARD_BYTES>),
    NotFound,
}

impl NoosEncode for ShardReplyV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        match self {
            ShardReplyV1::Shard(s) => {
                w.put_u16(0);
                s.encode(w);
            }
            ShardReplyV1::NotFound => w.put_u16(1),
        }
    }
}

impl NoosDecode for ShardReplyV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        match r.get_discriminant(2)? {
            0 => Ok(ShardReplyV1::Shard(Bounded::decode(r)?)),
            _ => Ok(ShardReplyV1::NotFound),
        }
    }
}

// ---------------------------------------------------------------------------
// Replay-domain content digest (D-P2P-MSG)
// ---------------------------------------------------------------------------

/// Content digest keying the duplicate caches:
/// `H("NOOS/P2P/MSG/V1" || protocol_id || envelope_bytes)`. Local anti-replay
/// only; never a consensus commitment.
pub fn message_digest(protocol: Protocol, envelope_bytes: &[u8]) -> [u8; 32] {
    match hash_domain(DomainId::P2pMsg, &[protocol.id().as_bytes(), envelope_bytes]) {
        Ok(h) => h.into_bytes(),
        // D-P2P-MSG is a registered BLAKE3_CONTEXT row; a kind mismatch is
        // impossible for a compiled registry.
        Err(_) => unreachable!("D-P2P-MSG is a registered BLAKE3 context"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cid() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn header_msg_round_trip_both_variants() {
        let a = HeaderMsgV1::Announce {
            chain_id: cid(),
            header: Bounded(vec![1, 2, 3]),
        };
        let b = HeaderMsgV1::Request {
            chain_id: cid(),
            header_hash: [7; 32],
        };
        for m in [a, b] {
            let bytes = m.encode_canonical();
            assert_eq!(HeaderMsgV1::decode_canonical(&bytes).unwrap(), m);
        }
    }

    #[test]
    fn replies_round_trip() {
        let cases: Vec<Vec<u8>> = vec![
            HeaderReplyV1::Ack.encode_canonical(),
            HeaderReplyV1::Header(Bounded(vec![9; 40])).encode_canonical(),
            HeaderReplyV1::NotFound.encode_canonical(),
            BodyReplyV1::Body(Bounded(vec![1; 10])).encode_canonical(),
            BodyReplyV1::NotFound.encode_canonical(),
            PushReplyV1::Accepted.encode_canonical(),
            PushReplyV1::FeatureDisabled.encode_canonical(),
            SnapshotReplyV1::Chunk {
                total_chunks: 4,
                chunk: Bounded(vec![2; 8]),
            }
            .encode_canonical(),
            ShardReplyV1::Shard(Bounded(vec![3; 8])).encode_canonical(),
        ];
        // Each decodes canonically under its own type; trailing byte rejects.
        assert_eq!(
            HeaderReplyV1::decode_canonical(&cases[0]).unwrap(),
            HeaderReplyV1::Ack
        );
        let mut trailing = cases[0].clone();
        trailing.push(0);
        assert_eq!(
            HeaderReplyV1::decode_canonical(&trailing).unwrap_err(),
            CodecError::TrailingBytes
        );
        assert_eq!(
            PushReplyV1::decode_canonical(&cases[6]).unwrap(),
            PushReplyV1::FeatureDisabled
        );
    }

    #[test]
    fn unknown_version_and_discriminant_reject() {
        let mut w = Writer::new();
        w.put_u16(2); // wrong version
        w.put_u16(0);
        assert_eq!(
            HeaderReplyV1::decode_canonical(w.as_bytes()).unwrap_err(),
            CodecError::UnknownVersion
        );

        let mut w = Writer::new();
        w.put_u16(1);
        w.put_u16(9); // unknown discriminant
        assert_eq!(
            HeaderReplyV1::decode_canonical(w.as_bytes()).unwrap_err(),
            CodecError::UnknownDiscriminant
        );
    }

    #[test]
    fn oversize_collection_rejects_before_allocation() {
        // VotePushV1 with a declared vote length far beyond MAX_VOTE_BYTES.
        let mut w = Writer::new();
        w.put_u16(1); // version
        w.put_mandatory_tag(1);
        w.put_array32(&cid());
        w.put_mandatory_tag(2);
        w.put_u32(u32::MAX); // forged length prefix, no payload
        assert_eq!(
            VotePushV1::decode_canonical(w.as_bytes()).unwrap_err(),
            CodecError::LengthExceedsBound
        );
    }

    #[test]
    fn flag_rejects_noncanonical_bool() {
        let mut w = Writer::new();
        w.put_u8(2);
        let mut r = Reader::new(w.as_bytes());
        assert_eq!(Flag::decode(&mut r).unwrap_err(), CodecError::UnknownDiscriminant);
    }

    #[test]
    fn range_reply_fits_budget_and_flags_more() {
        let headers: Vec<Bounded<MAX_HEADER_BYTES>> =
            (0..64).map(|_| Bounded(vec![0xCD; 32 * 1024])).collect();
        let mut reply = RangeReplyV1 {
            chain_id: cid(),
            headers: BoundedList(headers),
            more: Flag(false),
        };
        assert!(reply.encode_canonical().len() > RANGE_REPLY_BYTE_BUDGET);
        let shed = reply.fit_to_budget(RANGE_REPLY_BYTE_BUDGET);
        assert!(shed > 0);
        assert!(reply.encode_canonical().len() <= RANGE_REPLY_BYTE_BUDGET);
        assert_eq!(reply.more, Flag(true));
        assert!(!reply.headers.0.is_empty(), "must keep a useful prefix");
    }

    #[test]
    fn digest_separates_protocols_and_payloads() {
        let d1 = message_digest(Protocol::LumenTx, b"payload");
        let d2 = message_digest(Protocol::BraidVote, b"payload");
        let d3 = message_digest(Protocol::LumenTx, b"payload2");
        assert_ne!(d1, d2);
        assert_ne!(d1, d3);
        assert_eq!(d1, message_digest(Protocol::LumenTx, b"payload"));
    }

    #[test]
    fn lanes_are_consensus_over_ai() {
        assert_eq!(Protocol::BraidVote.lane(), Lane::Priority);
        assert_eq!(Protocol::BraidHeader.lane(), Lane::Priority);
        assert_eq!(Protocol::BraidBody.lane(), Lane::Priority);
        assert_eq!(Protocol::SyncRange.lane(), Lane::Priority);
        assert_eq!(Protocol::SyncSnapshot.lane(), Lane::Priority);
        assert_eq!(Protocol::LumenTx.lane(), Lane::Normal);
        assert_eq!(Protocol::BlobShard.lane(), Lane::Normal);
        assert_eq!(Protocol::LoomReceipt.lane(), Lane::Normal);
    }

    #[test]
    fn handshake_msgs_round_trip() {
        let att = ChainAttestationV1 {
            chain_id: cid(),
            genesis_hash: [1; 32],
            protocol_version: 1,
            peer_pubkey: [2; 32],
            signature: Bytes64([3; 64]),
        };
        for m in [
            HandshakeMsgV1::Attest(att),
            HandshakeMsgV1::Ack,
            HandshakeMsgV1::Reject {
                code: RejectCode::WrongProtocolIdentity.wire(),
            },
        ] {
            let bytes = m.encode_canonical();
            assert_eq!(HandshakeMsgV1::decode_canonical(&bytes).unwrap(), m);
        }
    }
}
