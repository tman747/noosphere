//! # noos-p2p — NOOSPHERE transport (plan §7.4, ch01 §10.4)
//!
//! libp2p QUIC transport with chain-identity binding and exactly the eight
//! versioned `/noos/` application protocols (identity-v1.md §3), specified in
//! `protocol/schemas/p2p-v1.md`:
//!
//! ```text
//! /noos/braid/header/1     header announce / request        priority
//! /noos/braid/body/1       body request / transfer          priority
//! /noos/braid/vote/1       checkpoint vote push             priority
//! /noos/lumen/tx/1         transaction push                 normal
//! /noos/sync/range/1       header range request             priority
//! /noos/sync/snapshot/1    snapshot chunk request           priority
//! /noos/blob/shard/1       DA shard request / transfer      normal
//! /noos/loom/receipt/1     loom receipt push (lane OFF)     normal
//! ```
//!
//! plus the session gate `/noos/handshake/1`, which exchanges a D-SIG-PEER
//! attestation over `(chain_id, genesis_hash, protocol_version, peer_pubkey)`
//! before any application traffic; a wrong chain or genesis rejects with the
//! stable class `wrong_protocol_identity`.
//!
//! Ported Ascent patterns, re-implemented fresh (plan §7.4): 1 MiB bounded
//! frames (oversize = violation + disconnect), priority/normal outbound lanes
//! with consensus-over-AI scheduling, per-peer per-protocol token buckets,
//! content-digest LRU duplicate caches, violation scoring with progressive
//! cooldowns, deterministic-jitter reconnect backoff, and targeted repair
//! (ask a specific peer for a specific hash).
//!
//! Non-goals: sync algorithms, mempool policy, RPC. The embedder answers
//! request substreams through [`ProtocolStore`] and consumes pushes as
//! [`P2pEvent`]s.

#![forbid(unsafe_code)]

mod backoff;
mod envelope;
mod frame;
mod identity;
mod limits;
mod node;
mod queue;

pub use backoff::{ReconnectBackoff, SplitMix64};
pub use envelope::{
    message_digest, BodyReplyV1, BodyRequestV1, Bounded, BoundedList, Bytes64, ChainAttestationV1,
    Flag, HandshakeMsgV1, HeaderMsgV1, HeaderReplyV1, Lane, LoomReceiptPushV1, Protocol,
    PushReplyV1, RangeReplyV1, RangeRequestV1, RejectCode, ShardReplyV1, ShardRequestV1,
    SnapshotChunkRequestV1, SnapshotReplyV1, TxPushV1, VotePushV1, APP_PROTOCOLS, MAX_BODY_BYTES,
    MAX_HEADER_BYTES, MAX_RANGE_HEADERS, MAX_RECEIPT_BYTES, MAX_SHARD_BYTES,
    MAX_SNAPSHOT_CHUNK_BYTES, MAX_TX_BYTES, MAX_VOTE_BYTES, RANGE_REPLY_BYTE_BUDGET,
};
pub use frame::{
    read_frame, write_frame, write_raw_declared, FrameError, MAX_FRAME_BYTES,
    MAX_HANDSHAKE_FRAME_BYTES,
};
pub use identity::{sign_attestation, verify_attestation, ChainIdentity};
pub use limits::{
    CooldownLedger, DupCache, LimitsConfig, RateLimit, TokenBucket, Violation, COOLDOWN_BASE_MS,
    COOLDOWN_MAX_MS, DISCONNECT_SCORE,
};
pub use node::{
    EmptyStore, InboundItem, P2pConfig, P2pEvent, P2pHandle, P2pNode, ProtocolStore, SendError,
    SpawnError,
};

// Re-exported so embedders and tests need no direct libp2p dependency for
// the common surface.
pub use libp2p::{Multiaddr, PeerId, StreamProtocol};
