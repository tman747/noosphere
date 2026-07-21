//! # noos-node — the noosd bounded supervisor runtime (plan §7.5-7.7)
//!
//! Composes every finished protocol crate into the reference full node:
//!
//! * [`genesis`] — devnet parameter loading (`protocol/genesis/
//!   devnet-parameters.toml`, valueless `NOOS_TEST` fixtures gated on
//!   `is_test_network = true`), the canonical
//!   `GenesisParameterManifestV1`, chain-id / genesis-hash derivation under
//!   the registered `D-GENESIS-PARAMS` / `D-CHAIN-ID` / `D-GENESIS-FINAL`
//!   domains, and genesis block construction;
//! * [`roots`] — the header body-root binding law (`D-BODY-*` rows of
//!   `crypto-domains-v1.csv`, frozen in `protocol/schemas/node-v1.md` §3);
//! * [`consensus`] — the deterministic single-writer consensus core: the
//!   ch01 §9.3 import pipeline (header → ticket → DA → execution → root
//!   comparison → fork choice → finality), block production, reorg
//!   rollback/replay through the store, and restart recovery;
//! * [`mempool`] — canonical-decode admission, chain/version/expiry, fee
//!   floor, per-payer FIFO ordering, byte/count caps, per-source limits,
//!   duplicate cache, fee-density eviction, deterministic template
//!   assembly under the body caps;
//! * [`sync`] and [`network`] — the thin [`sync::NetworkEdge`] trait bound
//!   to the production `noos-p2p` adapter, header-first full sync, and
//!   finalized snapshot sync over a multi-peer
//!   [`sync::SnapshotSource`] set, light mode, and the
//!   SOCIAL-INPUT weak-subjectivity checkpoint law (never overrides local
//!   finality);
//! * [`witness_role`] — persist-before-vote: the `noos-witness`
//!   [`noos_witness::beacon::DurabilityBarrier`] wired to
//!   `noos-store::Store::persist_safety_record`, and the vote gate that
//!   never releases a vote before its safety record is durable;
//! * [`pool`] — bounded proof-check worker pool returning deterministic
//!   `(profile_id, input_digest, verdict, cost)` records; a worker crash
//!   is a typed verdict, never consensus corruption;
//! * [`supervisor`] — the bounded task topology (consensus single writer;
//!   store, RPC, sync as separate tasks over bounded channels) with
//!   contained crash + restart;
//! * [`rpc`] — minimal localhost bearer-token operator RPC: `/status`
//!   (unsafe/justified/finalized heads SEPARATELY, never a merged
//!   "latest"), `/submit_tx`, `/block/{id}`, `/receipt/{txid}`, and the
//!   `noos_*` `/metrics` text endpoint; observer mode disables submission
//!   with an explicit `feature_disabled` error carrying a mechanism id;
//! * [`view`] — the bounded RPC chain view with retention pruning (the
//!   Ascent chain-view retention defect is independently re-proven fixed
//!   here; see `node-v1.md` §8).
//!
//! Normative companion document: `protocol/schemas/node-v1.md`.
//!
//! Non-goals (later product phases): the public REST API v1
//! (`openapi-v1.yaml`), CUDA/Go worker processes, installers.

#![forbid(unsafe_code)]

pub mod artifact_store_port;
pub mod auth;
mod bonsai_fixture;
pub mod consensus;
pub mod devnet_fixture;
pub mod genesis;
pub mod mempool;
pub mod metrics;
pub mod network;
pub mod pool;
pub mod resolver;
pub mod roots;
pub mod rpc;
pub mod store_port;
pub mod supervisor;
pub mod sync;
pub mod view;
pub mod witness_role;

#[cfg(test)]
mod tests;

use std::fmt;
/// Exact source revision embedded by controlled release builds.
///
/// Ordinary developer builds remain visibly unbound rather than claiming a
/// revision they cannot prove.
pub const SOURCE_REVISION: &str = match option_env!("NOOS_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "UNBOUND",
};

/// SemVer release identity. Controlled builds bind it to the exact Git
/// revision while ordinary builds retain the package version.
pub const RELEASE_VERSION: &str = match option_env!("NOOS_RELEASE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};


/// 32-byte digest alias matching `noos_lumen::Hash32` (plain array).
pub type Hash32 = [u8; 32];

/// Typed node-layer failures. Consensus-rule rejections carry the exact
/// upstream error; nothing here is ever a silent fallback.
#[derive(Debug)]
pub enum NodeError {
    /// Canonical decode failure (includes the receipt-root interchange,
    /// which the header tag law rejects at decode).
    Codec(noos_codec::CodecError),
    /// Structural header / DAG rule violation.
    Dag(noos_braid::DagError),
    /// Ground ticket law violation (ch01 §4.2).
    Ground(noos_ground::GroundError),
    /// Pulse retarget contract violation.
    Pulse(noos_ground::PulseError),
    /// Data-availability failure. `DaError::NotEnoughValidShards` is a
    /// PAUSE (block parked awaiting shards), not a rejection.
    Da(noos_da::DaError),
    /// Lumen transaction rejection inside a block body: the block is
    /// invalid (a proposer must not include rejected transactions).
    LumenReject(noos_lumen::state::RejectReason),
    /// Emission law violation while executing a block.
    Emission(noos_lumen::state::EmissionError),
    /// Deterministic activation migration failed due to conflicting state.
    Migration(noos_lumen::state::MigrationError),
    /// Witness Ring failure (vote/certificate/membership).
    Witness(noos_witness::WitnessError),
    /// Durable store failure.
    Store(noos_store::StoreError),
    /// Fatal store startup condition.
    StoreFatal(noos_store::FatalError),
    /// Proof-carrying WWM model resolution failure.
    Resolution(crate::resolver::ResolutionError),
    /// Claimed header roots do not match the recomputed transition
    /// (ch01 §9.3): names the first mismatching field.
    RootMismatch { field: &'static str },
    /// Body carries system transitions, whose schema table is not yet
    /// frozen: fail closed (plan §1.7 spirit; node-v1.md §4).
    SystemTransitionsUnfrozen,
    /// Body/header cross-check failure (e.g. body ticket differs from the
    /// gossiped ticket, oversized body, cert count).
    BodyMismatch { what: &'static str },
    /// A weak-subjectivity SOCIAL INPUT conflicts with locally finalized
    /// state; it never overrides local finality (ch01 §10.5).
    SocialCheckpointConflictsLocalFinality {
        local: noos_braid::CheckpointRef,
        social: noos_braid::CheckpointRef,
    },
    /// Genesis / configuration violation (e.g. test fixtures on a
    /// non-test network, malformed parameters file).
    Config(String),
    /// A supervisor channel closed (peer task exited).
    ChannelClosed(&'static str),
    /// The persist-before-vote barrier failed: nothing was emitted.
    BarrierFailed(String),
    /// Registered-domain hashing failed: build defect, never a data error.
    Crypto,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Codec(e) => write!(f, "codec: {e}"),
            NodeError::Dag(e) => write!(f, "dag: {e}"),
            NodeError::Ground(e) => write!(f, "ground: {e}"),
            NodeError::Pulse(e) => write!(f, "pulse: {e}"),
            NodeError::Da(e) => write!(f, "da: {e}"),
            NodeError::LumenReject(e) => write!(f, "lumen reject: {e:?}"),
            NodeError::Emission(e) => write!(f, "emission: {e:?}"),
            NodeError::Migration(e) => write!(f, "migration: {e:?}"),
            NodeError::Witness(e) => write!(f, "witness: {e:?}"),
            NodeError::Store(e) => write!(f, "store: {e}"),
            NodeError::StoreFatal(e) => write!(f, "store fatal: {e}"),
            NodeError::Resolution(e) => write!(f, "model resolution: {e:?}"),
            NodeError::RootMismatch { field } => {
                write!(f, "claimed header root mismatch: {field}")
            }
            NodeError::SystemTransitionsUnfrozen => {
                write!(f, "system transitions schema unfrozen: fail closed")
            }
            NodeError::BodyMismatch { what } => write!(f, "body mismatch: {what}"),
            NodeError::SocialCheckpointConflictsLocalFinality { local, social } => write!(
                f,
                "SOCIAL INPUT checkpoint (epoch {}, {:02x?}…) conflicts with locally \
                 finalized state (epoch {}, {:02x?}…); local finality is never overridden",
                social.epoch,
                &social.checkpoint_hash[..4],
                local.epoch,
                &local.checkpoint_hash[..4]
            ),
            NodeError::Config(msg) => write!(f, "config: {msg}"),
            NodeError::ChannelClosed(which) => write!(f, "channel closed: {which}"),
            NodeError::BarrierFailed(msg) => write!(f, "durability barrier failed: {msg}"),
            NodeError::Crypto => write!(f, "registered-domain hashing failed (build defect)"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<noos_codec::CodecError> for NodeError {
    fn from(e: noos_codec::CodecError) -> Self {
        NodeError::Codec(e)
    }
}
impl From<noos_braid::DagError> for NodeError {
    fn from(e: noos_braid::DagError) -> Self {
        NodeError::Dag(e)
    }
}
impl From<noos_ground::GroundError> for NodeError {
    fn from(e: noos_ground::GroundError) -> Self {
        NodeError::Ground(e)
    }
}
impl From<noos_ground::PulseError> for NodeError {
    fn from(e: noos_ground::PulseError) -> Self {
        NodeError::Pulse(e)
    }
}
impl From<noos_da::DaError> for NodeError {
    fn from(e: noos_da::DaError) -> Self {
        NodeError::Da(e)
    }
}
impl From<noos_witness::WitnessError> for NodeError {
    fn from(e: noos_witness::WitnessError) -> Self {
        NodeError::Witness(e)
    }
}
impl From<noos_store::StoreError> for NodeError {
    fn from(e: noos_store::StoreError) -> Self {
        NodeError::Store(e)
    }
}
