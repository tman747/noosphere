//! Canonical noos-codec message envelopes for the nine `/noos/` application
//! protocols plus the transport handshake (p2p-v1.md §3, §5; v2 light sync).
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

/// The nine application protocols plus the session-gate handshake.
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
    SyncLightUpdate,
    BlobShard,
    LoomReceipt,
}

/// The nine application protocols in canonical order (excludes handshake).
pub const APP_PROTOCOLS: [Protocol; 9] = [
    Protocol::BraidHeader,
    Protocol::BraidBody,
    Protocol::BraidVote,
    Protocol::LumenTx,
    Protocol::SyncRange,
    Protocol::SyncSnapshot,
    Protocol::SyncLightUpdate,
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
            Protocol::SyncLightUpdate => "/noos/sync/light-update/2",
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
            | Protocol::SyncSnapshot
            | Protocol::SyncLightUpdate => Lane::Priority,
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
            Protocol::SyncLightUpdate => Some(6),
            Protocol::BlobShard => Some(7),
            Protocol::LoomReceipt => Some(8),
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
/// Maximum light-update items requested or returned in one page.
pub const MAX_LIGHT_UPDATE_ITEMS: u32 = 128;
/// Maximum canonical bytes in one light-update item.
pub const MAX_LIGHT_UPDATE_ITEM_BYTES: u32 = 262_144;
/// Maximum canonical bytes in the complete reply frame.
pub const MAX_LIGHT_UPDATE_REPLY_ENCODED_BYTES: usize = 1_048_576;
/// Maximum compact consensus members in one light snapshot.
pub const MAX_LIGHT_MEMBERS: u32 = 1_024;
/// Fixed canonical bytes per compact membership entry.
pub const LIGHT_MEMBER_ENCODED_BYTES: usize = 112;
/// Maximum canonical bytes in the compact snapshot.
pub const MAX_LIGHT_MEMBERSHIP_SNAPSHOT_BYTES: usize = 122_880;
/// Maximum canonical bytes in handover/rotation evidence.
pub const MAX_LIGHT_HANDOVER_BYTES: u32 = 32_768;
/// Maximum compact snapshot plus handover bytes in one item.
pub const MAX_LIGHT_MEMBERSHIP_WITNESS_BYTES: usize = 155_648;
/// Header sub-budget inside a light-update item.
pub const MAX_LIGHT_HEADER_BYTES: u32 = 65_536;
/// Compact finality-certificate sub-budget inside a light-update item.
pub const MAX_LIGHT_FINALITY_BYTES: u32 = 32_768;
/// Ground-ticket and item-wrapper sub-budget.
pub const MAX_LIGHT_ITEM_AUX_BYTES: u32 = 8_192;

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
// /noos/sync/light-update/2
// ---------------------------------------------------------------------------

/// Fixed-width BLS public key used by compact membership entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LightBytes48(pub [u8; 48]);

impl NoosEncode for LightBytes48 {
    fn encode(&self, w: &mut Writer) {
        w.put_raw(&self.0);
    }
}

impl NoosDecode for LightBytes48 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut out = [0_u8; 48];
        for byte in &mut out {
            *byte = r.get_u8()?;
        }
        Ok(Self(out))
    }
}

/// Consensus-only membership projection. Its canonical encoding is exactly
/// 112 bytes and deliberately excludes `MemberV1.failure_domains`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightMemberV1 {
    pub validator_id: [u8; 32],
    pub consensus_bls_key: LightBytes48,
    pub raw_weight: u128,
    pub effective_weight: u128,
}

impl NoosEncode for LightMemberV1 {
    fn encode(&self, w: &mut Writer) {
        self.validator_id.encode(w);
        self.consensus_bls_key.encode(w);
        self.raw_weight.encode(w);
        self.effective_weight.encode(w);
    }
}

impl NoosDecode for LightMemberV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            validator_id: <[u8; 32]>::decode(r)?,
            consensus_bls_key: LightBytes48::decode(r)?,
            raw_weight: u128::decode(r)?,
            effective_weight: u128::decode(r)?,
        })
    }
}

/// Semantic failures for a compact membership snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightMembershipError {
    TooManyMembers,
    MemberOrder,
    WeightOverflow,
    TotalMismatch,
    RootMismatch,
    EncodedBudget,
}

/// Compact membership snapshot authenticated by the same SMT law as the full
/// Witness Ring snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightMembershipSnapshotV1 {
    epoch: u64,
    claimed_root: [u8; 32],
    total_raw_weight: u128,
    total_effective_weight: u128,
    members: Vec<LightMemberV1>,
}

impl LightMembershipSnapshotV1 {
    /// Constructs a canonical snapshot, deriving all commitments from members.
    pub fn from_members(
        epoch: u64,
        members: Vec<LightMemberV1>,
    ) -> Result<Self, LightMembershipError> {
        let (claimed_root, total_raw_weight, total_effective_weight) = Self::derived(&members)?;
        let snapshot = Self {
            epoch,
            claimed_root,
            total_raw_weight,
            total_effective_weight,
            members,
        };
        snapshot.verify()?;
        Ok(snapshot)
    }

    /// Constructs from carried commitments and verifies every carried value.
    pub fn checked(
        epoch: u64,
        claimed_root: [u8; 32],
        total_raw_weight: u128,
        total_effective_weight: u128,
        members: Vec<LightMemberV1>,
    ) -> Result<Self, LightMembershipError> {
        let snapshot = Self {
            epoch,
            claimed_root,
            total_raw_weight,
            total_effective_weight,
            members,
        };
        snapshot.verify()?;
        Ok(snapshot)
    }

    fn derived(members: &[LightMemberV1]) -> Result<([u8; 32], u128, u128), LightMembershipError> {
        if members.len() > MAX_LIGHT_MEMBERS as usize {
            return Err(LightMembershipError::TooManyMembers);
        }
        if members
            .windows(2)
            .any(|pair| pair[0].validator_id >= pair[1].validator_id)
        {
            return Err(LightMembershipError::MemberOrder);
        }
        let mut total_raw = 0_u128;
        let mut total_effective = 0_u128;
        let mut smt = noos_lumen::smt::Smt::new();
        for member in members {
            total_raw = total_raw
                .checked_add(member.raw_weight)
                .ok_or(LightMembershipError::WeightOverflow)?;
            total_effective = total_effective
                .checked_add(member.effective_weight)
                .ok_or(LightMembershipError::WeightOverflow)?;
            let mut value = Vec::with_capacity(80);
            value.extend_from_slice(&member.consensus_bls_key.0);
            value.extend_from_slice(&member.raw_weight.to_le_bytes());
            value.extend_from_slice(&member.effective_weight.to_le_bytes());
            if smt.insert(member.validator_id, value).is_some() {
                return Err(LightMembershipError::MemberOrder);
            }
        }
        Ok((smt.root(), total_raw, total_effective))
    }

    /// Recomputes totals and root and checks canonical order and byte budget.
    pub fn verify(&self) -> Result<(), LightMembershipError> {
        let (root, raw, effective) = Self::derived(&self.members)?;
        if raw != self.total_raw_weight || effective != self.total_effective_weight {
            return Err(LightMembershipError::TotalMismatch);
        }
        if root != self.claimed_root {
            return Err(LightMembershipError::RootMismatch);
        }
        if self.encode_canonical().len() > MAX_LIGHT_MEMBERSHIP_SNAPSHOT_BYTES {
            return Err(LightMembershipError::EncodedBudget);
        }
        Ok(())
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.claimed_root
    }

    #[must_use]
    pub fn total_raw_weight(&self) -> u128 {
        self.total_raw_weight
    }

    #[must_use]
    pub fn total_effective_weight(&self) -> u128 {
        self.total_effective_weight
    }

    #[must_use]
    pub fn members(&self) -> &[LightMemberV1] {
        &self.members
    }
}

impl NoosEncode for LightMembershipSnapshotV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_mandatory_tag(1);
        self.epoch.encode(w);
        w.put_mandatory_tag(2);
        self.claimed_root.encode(w);
        w.put_mandatory_tag(3);
        self.total_raw_weight.encode(w);
        w.put_mandatory_tag(4);
        self.total_effective_weight.encode(w);
        w.put_mandatory_tag(5);
        w.put_list(&self.members, MAX_LIGHT_MEMBERS);
    }
}

impl NoosDecode for LightMembershipSnapshotV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        r.expect_mandatory_tag(1)?;
        let epoch = u64::decode(r)?;
        r.expect_mandatory_tag(2)?;
        let claimed_root = <[u8; 32]>::decode(r)?;
        r.expect_mandatory_tag(3)?;
        let total_raw_weight = u128::decode(r)?;
        r.expect_mandatory_tag(4)?;
        let total_effective_weight = u128::decode(r)?;
        r.expect_mandatory_tag(5)?;
        let members = r.get_list(MAX_LIGHT_MEMBERS)?;
        Self::checked(
            epoch,
            claimed_root,
            total_raw_weight,
            total_effective_weight,
            members,
        )
        .map_err(|_| CodecError::UnknownDiscriminant)
    }
}

/// Membership transition class. A second consecutive emergency transition is
/// invalid; `Halt` is terminal and cannot accompany another finalized item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightMembershipTransitionKind {
    Normal,
    EmergencyContinuation,
    Halt,
}

impl NoosEncode for LightMembershipTransitionKind {
    fn encode(&self, w: &mut Writer) {
        w.put_u8(match self {
            Self::Normal => 0,
            Self::EmergencyContinuation => 1,
            Self::Halt => 2,
        });
    }
}

impl NoosDecode for LightMembershipTransitionKind {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(3)? {
            0 => Ok(Self::Normal),
            1 => Ok(Self::EmergencyContinuation),
            2 => Ok(Self::Halt),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

define_object! {
    /// Old-set quorum attestation over one compact membership rotation.
    pub struct LightMembershipHandoverV1 {
        version: 1;
        1 => kind: LightMembershipTransitionKind,
        2 => chain_id: [u8; 32],
        3 => old_epoch: u64,
        4 => new_epoch: u64,
        5 => old_membership_root: [u8; 32],
        6 => new_membership_root: [u8; 32],
        7 => finalized_checkpoint_epoch: u64,
        8 => finalized_checkpoint_hash: [u8; 32],
        9 => participation_bitmap: Bounded<128>,
        10 => aggregate_signature: Bounded<96>,
        11 => raw_weight_sum: u128,
        12 => effective_weight_sum: u128,
    }
}

/// Compact snapshot plus bounded membership handover/rotation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightMembershipWitnessV1 {
    pub snapshot: LightMembershipSnapshotV1,
    pub handover: Bounded<MAX_LIGHT_HANDOVER_BYTES>,
}

impl LightMembershipWitnessV1 {
    pub fn verify(&self) -> Result<(), LightMembershipError> {
        self.snapshot.verify()?;
        if self.encode_canonical().len() > MAX_LIGHT_MEMBERSHIP_WITNESS_BYTES {
            return Err(LightMembershipError::EncodedBudget);
        }
        Ok(())
    }
}

impl NoosEncode for LightMembershipWitnessV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_mandatory_tag(1);
        self.snapshot.encode(w);
        w.put_mandatory_tag(2);
        self.handover.encode(w);
    }
}

impl NoosDecode for LightMembershipWitnessV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        r.expect_mandatory_tag(1)?;
        let snapshot = LightMembershipSnapshotV1::decode(r)?;
        r.expect_mandatory_tag(2)?;
        let handover = Bounded::decode(r)?;
        let out = Self { snapshot, handover };
        out.verify().map_err(|_| CodecError::LengthExceedsBound)?;
        Ok(out)
    }
}

/// One finalized light-client history item. Full bodies, bonds, and telemetry
/// have no field here and therefore cannot enter the witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightUpdateItemV1 {
    pub height: u64,
    pub header: Bounded<MAX_LIGHT_HEADER_BYTES>,
    pub finality: Bounded<MAX_LIGHT_FINALITY_BYTES>,
    pub membership: LightMembershipWitnessV1,
    pub ground_ticket: Bounded<MAX_LIGHT_ITEM_AUX_BYTES>,
}

impl LightUpdateItemV1 {
    pub fn verify_bounds(&self) -> Result<(), CodecError> {
        self.membership
            .verify()
            .map_err(|_| CodecError::LengthExceedsBound)?;
        if self.encode_canonical().len() > MAX_LIGHT_UPDATE_ITEM_BYTES as usize {
            return Err(CodecError::LengthExceedsBound);
        }
        Ok(())
    }
}

impl NoosEncode for LightUpdateItemV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_mandatory_tag(1);
        self.height.encode(w);
        w.put_mandatory_tag(2);
        self.header.encode(w);
        w.put_mandatory_tag(3);
        self.finality.encode(w);
        w.put_mandatory_tag(4);
        self.membership.encode(w);
        w.put_mandatory_tag(5);
        self.ground_ticket.encode(w);
    }
}

impl NoosDecode for LightUpdateItemV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        r.expect_mandatory_tag(1)?;
        let height = u64::decode(r)?;
        r.expect_mandatory_tag(2)?;
        let header = Bounded::decode(r)?;
        r.expect_mandatory_tag(3)?;
        let finality = Bounded::decode(r)?;
        r.expect_mandatory_tag(4)?;
        let membership = LightMembershipWitnessV1::decode(r)?;
        r.expect_mandatory_tag(5)?;
        let ground_ticket = Bounded::decode(r)?;
        let item = Self {
            height,
            header,
            finality,
            membership,
            ground_ticket,
        };
        item.verify_bounds()?;
        Ok(item)
    }
}

/// Bounded ascending light-update request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightUpdateRequestV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub start_height: u64,
    pub max_items: u32,
}

impl LightUpdateRequestV1 {
    pub fn checked(
        chain_id: [u8; 32],
        genesis_hash: [u8; 32],
        start_height: u64,
        max_items: u32,
    ) -> Result<Self, CodecError> {
        if !(1..=MAX_LIGHT_UPDATE_ITEMS).contains(&max_items) {
            return Err(CodecError::LengthExceedsBound);
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            start_height,
            max_items,
        })
    }
}

impl NoosEncode for LightUpdateRequestV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_mandatory_tag(1);
        self.chain_id.encode(w);
        w.put_mandatory_tag(2);
        self.genesis_hash.encode(w);
        w.put_mandatory_tag(3);
        self.start_height.encode(w);
        w.put_mandatory_tag(4);
        self.max_items.encode(w);
    }
}

impl NoosDecode for LightUpdateRequestV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        r.expect_mandatory_tag(1)?;
        let chain_id = <[u8; 32]>::decode(r)?;
        r.expect_mandatory_tag(2)?;
        let genesis_hash = <[u8; 32]>::decode(r)?;
        r.expect_mandatory_tag(3)?;
        let start_height = u64::decode(r)?;
        r.expect_mandatory_tag(4)?;
        let max_items = u32::decode(r)?;
        Self::checked(chain_id, genesis_hash, start_height, max_items)
    }
}

/// Reply-shaping failure when even one valid item cannot fit the requested
/// frame budget. Callers must not return an empty `more=true` page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightReplyFitError {
    SingleItemOversize { encoded: usize, budget: usize },
    NonCanonicalPage,
}

/// Ascending light-update reply. The byte bound applies to this whole encoded
/// object, not merely to its item list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightUpdateReplyV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub requested_start: u64,
    pub items: BoundedList<LightUpdateItemV1, MAX_LIGHT_UPDATE_ITEMS>,
    pub next_height: u64,
    pub more: Flag,
}

impl LightUpdateReplyV1 {
    pub fn verify_page(&self) -> Result<(), LightReplyFitError> {
        if self.items.0.len() > MAX_LIGHT_UPDATE_ITEMS as usize {
            return Err(LightReplyFitError::NonCanonicalPage);
        }
        if self
            .items
            .0
            .windows(2)
            .any(|pair| pair[0].height >= pair[1].height)
        {
            return Err(LightReplyFitError::NonCanonicalPage);
        }
        if let Some(first) = self.items.0.first() {
            if first.height != self.requested_start {
                return Err(LightReplyFitError::NonCanonicalPage);
            }
        }
        let expected_next = self
            .items
            .0
            .last()
            .map_or(self.requested_start, |item| item.height.saturating_add(1));
        if self.next_height != expected_next || (self.more.0 && self.items.0.is_empty()) {
            return Err(LightReplyFitError::NonCanonicalPage);
        }
        Ok(())
    }

    /// Removes only a suffix until the entire reply fits. The retained prefix
    /// and `next_height` form the next request. Empty continuation pages are
    /// forbidden, yielding a typed single-item error instead.
    pub fn fit_to_budget(&mut self, budget: usize) -> Result<usize, LightReplyFitError> {
        self.verify_page()?;
        let mut shed = 0_usize;
        loop {
            let encoded = self.encode_canonical().len();
            if encoded <= budget {
                return Ok(shed);
            }
            if self.items.0.len() <= 1 {
                return Err(LightReplyFitError::SingleItemOversize { encoded, budget });
            }
            self.items.0.pop();
            shed = shed.saturating_add(1);
            self.more = Flag(true);
            self.next_height = self
                .items
                .0
                .last()
                .map_or(self.requested_start, |item| item.height.saturating_add(1));
        }
    }
}

impl NoosEncode for LightUpdateReplyV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_mandatory_tag(1);
        self.chain_id.encode(w);
        w.put_mandatory_tag(2);
        self.genesis_hash.encode(w);
        w.put_mandatory_tag(3);
        self.requested_start.encode(w);
        w.put_mandatory_tag(4);
        self.items.encode(w);
        w.put_mandatory_tag(5);
        self.next_height.encode(w);
        w.put_mandatory_tag(6);
        self.more.encode(w);
    }
}

impl NoosDecode for LightUpdateReplyV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        r.expect_mandatory_tag(1)?;
        let chain_id = <[u8; 32]>::decode(r)?;
        r.expect_mandatory_tag(2)?;
        let genesis_hash = <[u8; 32]>::decode(r)?;
        r.expect_mandatory_tag(3)?;
        let requested_start = u64::decode(r)?;
        r.expect_mandatory_tag(4)?;
        let items = BoundedList::decode(r)?;
        r.expect_mandatory_tag(5)?;
        let next_height = u64::decode(r)?;
        r.expect_mandatory_tag(6)?;
        let more = Flag::decode(r)?;
        let reply = Self {
            chain_id,
            genesis_hash,
            requested_start,
            items,
            next_height,
            more,
        };
        reply
            .verify_page()
            .map_err(|_| CodecError::UnknownDiscriminant)?;
        Ok(reply)
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
    match hash_domain(
        DomainId::P2pMsg,
        &[protocol.id().as_bytes(), envelope_bytes],
    ) {
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

    fn light_member(index: u32) -> LightMemberV1 {
        let mut validator_id = [0_u8; 32];
        validator_id[28..].copy_from_slice(&index.to_be_bytes());
        LightMemberV1 {
            validator_id,
            consensus_bls_key: LightBytes48([index as u8; 48]),
            raw_weight: u128::from(index).saturating_add(1),
            effective_weight: u128::from(index).saturating_add(1),
        }
    }

    fn light_item(height: u64, header_bytes: usize) -> LightUpdateItemV1 {
        let snapshot = LightMembershipSnapshotV1::from_members(1, vec![light_member(1)]).unwrap();
        LightUpdateItemV1 {
            height,
            header: Bounded(vec![0x11; header_bytes]),
            finality: Bounded(vec![0x22; 64]),
            membership: LightMembershipWitnessV1 {
                snapshot,
                handover: Bounded(Vec::new()),
            },
            ground_ticket: Bounded(vec![0x33; 64]),
        }
    }

    fn raw_light_request(max_items: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u16(1);
        w.put_mandatory_tag(1);
        w.put_array32(&cid());
        w.put_mandatory_tag(2);
        w.put_array32(&[0xBB; 32]);
        w.put_mandatory_tag(3);
        w.put_u64(7);
        w.put_mandatory_tag(4);
        w.put_u32(max_items);
        w.into_bytes()
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
        assert_eq!(
            Flag::decode(&mut r).unwrap_err(),
            CodecError::UnknownDiscriminant
        );
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
    fn light_request_rejects_zero_and_max_plus_one() {
        assert_eq!(
            LightUpdateRequestV1::decode_canonical(&raw_light_request(0)).unwrap_err(),
            CodecError::LengthExceedsBound
        );
        for count in [1, MAX_LIGHT_UPDATE_ITEMS] {
            let request =
                LightUpdateRequestV1::decode_canonical(&raw_light_request(count)).unwrap();
            assert_eq!(request.max_items, count);
        }
        assert_eq!(
            LightUpdateRequestV1::decode_canonical(&raw_light_request(MAX_LIGHT_UPDATE_ITEMS + 1))
                .unwrap_err(),
            CodecError::LengthExceedsBound
        );
    }

    #[test]
    fn compact_member_is_fixed_112_bytes_and_snapshot_checks_totals_root_order() {
        assert_eq!(
            light_member(1).encode_canonical().len(),
            LIGHT_MEMBER_ENCODED_BYTES
        );
        let members: Vec<_> = (0..1_024).map(light_member).collect();
        let snapshot = LightMembershipSnapshotV1::from_members(9, members.clone()).unwrap();
        assert_eq!(snapshot.members().len(), 1_024);
        assert_eq!(
            snapshot.total_raw_weight(),
            members.iter().map(|m| m.raw_weight).sum()
        );
        assert_eq!(
            snapshot.total_effective_weight(),
            members.iter().map(|m| m.effective_weight).sum()
        );
        assert!(snapshot.encode_canonical().len() <= MAX_LIGHT_MEMBERSHIP_SNAPSHOT_BYTES);
        assert_eq!(
            LightMembershipSnapshotV1::checked(
                9,
                snapshot.root(),
                snapshot.total_raw_weight().saturating_add(1),
                snapshot.total_effective_weight(),
                members.clone(),
            ),
            Err(LightMembershipError::TotalMismatch)
        );
        let mut wrong_root = snapshot.root();
        wrong_root[0] ^= 1;
        assert_eq!(
            LightMembershipSnapshotV1::checked(
                9,
                wrong_root,
                snapshot.total_raw_weight(),
                snapshot.total_effective_weight(),
                members.clone(),
            ),
            Err(LightMembershipError::RootMismatch)
        );
        let mut reversed = members;
        reversed.swap(0, 1);
        assert_eq!(
            LightMembershipSnapshotV1::from_members(9, reversed),
            Err(LightMembershipError::MemberOrder)
        );
    }

    #[test]
    fn compact_snapshot_rejects_duplicate_and_overflow_weights() {
        let one = light_member(1);
        assert_eq!(
            LightMembershipSnapshotV1::from_members(1, vec![one.clone(), one]),
            Err(LightMembershipError::MemberOrder)
        );
        let mut a = light_member(1);
        let mut b = light_member(2);
        a.raw_weight = u128::MAX;
        b.raw_weight = 1;
        assert_eq!(
            LightMembershipSnapshotV1::from_members(1, vec![a, b]),
            Err(LightMembershipError::WeightOverflow)
        );
    }

    #[test]
    fn light_reply_trims_suffix_and_continues_without_empty_page() {
        let items = (100..120)
            .map(|height| light_item(height, 60_000))
            .collect();
        let mut reply = LightUpdateReplyV1 {
            chain_id: cid(),
            genesis_hash: [0xBB; 32],
            requested_start: 100,
            items: BoundedList(items),
            next_height: 120,
            more: Flag(false),
        };
        assert!(reply.encode_canonical().len() > MAX_LIGHT_UPDATE_REPLY_ENCODED_BYTES);
        let shed = reply
            .fit_to_budget(MAX_LIGHT_UPDATE_REPLY_ENCODED_BYTES)
            .unwrap();
        assert!(shed > 0);
        assert!(reply.encode_canonical().len() <= MAX_LIGHT_UPDATE_REPLY_ENCODED_BYTES);
        assert!(reply.more.0);
        assert_eq!(
            reply.next_height,
            reply.items.0.last().unwrap().height.saturating_add(1)
        );
        assert_eq!(reply.items.0.first().unwrap().height, 100);
        assert_eq!(
            LightUpdateReplyV1::decode_canonical(&reply.encode_canonical()).unwrap(),
            reply
        );

        let mut one = LightUpdateReplyV1 {
            chain_id: cid(),
            genesis_hash: [0xBB; 32],
            requested_start: 7,
            items: BoundedList(vec![light_item(7, 1_024)]),
            next_height: 8,
            more: Flag(false),
        };
        assert!(matches!(
            one.fit_to_budget(64),
            Err(LightReplyFitError::SingleItemOversize { .. })
        ));
        assert_eq!(one.items.0.len(), 1);
    }

    #[test]
    fn light_item_exact_nested_maxima_and_malicious_length_reject() {
        let mut item = light_item(4, MAX_LIGHT_HEADER_BYTES as usize);
        item.finality = Bounded(vec![0x44; MAX_LIGHT_FINALITY_BYTES as usize]);
        item.membership.handover = Bounded(vec![0x55; MAX_LIGHT_HANDOVER_BYTES as usize]);
        item.ground_ticket = Bounded(vec![0x66; MAX_LIGHT_ITEM_AUX_BYTES as usize]);
        item.verify_bounds().unwrap();
        assert!(item.encode_canonical().len() <= MAX_LIGHT_UPDATE_ITEM_BYTES as usize);
        assert_eq!(
            LightUpdateItemV1::decode_canonical(&item.encode_canonical()).unwrap(),
            item
        );

        let mut malicious = Writer::new();
        malicious.put_u16(1);
        malicious.put_mandatory_tag(1);
        malicious.put_u64(4);
        malicious.put_mandatory_tag(2);
        malicious.put_u32(MAX_LIGHT_HEADER_BYTES + 1);
        assert_eq!(
            LightUpdateItemV1::decode_canonical(malicious.as_bytes()).unwrap_err(),
            CodecError::LengthExceedsBound
        );
    }

    #[test]
    fn light_reply_rejects_malicious_item_count_before_allocation() {
        let mut malicious = Writer::new();
        malicious.put_u16(1);
        malicious.put_mandatory_tag(1);
        malicious.put_array32(&cid());
        malicious.put_mandatory_tag(2);
        malicious.put_array32(&[0xBB; 32]);
        malicious.put_mandatory_tag(3);
        malicious.put_u64(0);
        malicious.put_mandatory_tag(4);
        malicious.put_u32(MAX_LIGHT_UPDATE_ITEMS + 1);
        assert_eq!(
            LightUpdateReplyV1::decode_canonical(malicious.as_bytes()).unwrap_err(),
            CodecError::LengthExceedsBound
        );
    }

    #[test]
    fn one_near_max_and_128_small_items_obey_page_laws() {
        let near_max = light_item(0, MAX_LIGHT_HEADER_BYTES as usize);
        assert!(near_max.encode_canonical().len() <= MAX_LIGHT_UPDATE_ITEM_BYTES as usize);
        let one = LightUpdateReplyV1 {
            chain_id: cid(),
            genesis_hash: [0xBB; 32],
            requested_start: 0,
            items: BoundedList(vec![near_max]),
            next_height: 1,
            more: Flag(false),
        };
        assert!(one.encode_canonical().len() <= MAX_LIGHT_UPDATE_REPLY_ENCODED_BYTES);

        let small = LightUpdateReplyV1 {
            chain_id: cid(),
            genesis_hash: [0xBB; 32],
            requested_start: 10,
            items: BoundedList((10..138).map(|height| light_item(height, 0)).collect()),
            next_height: 138,
            more: Flag(false),
        };
        small.verify_page().unwrap();
        assert_eq!(small.items.0.len(), MAX_LIGHT_UPDATE_ITEMS as usize);
        assert!(small.encode_canonical().len() <= MAX_LIGHT_UPDATE_REPLY_ENCODED_BYTES);
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
        assert_eq!(Protocol::SyncLightUpdate.lane(), Lane::Priority);
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
