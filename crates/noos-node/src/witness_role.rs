//! Persist-before-vote (plan §6.1/§7.6; witness-v1.md §4.4; node-v1.md §7).
//!
//! Two safety lanes share the same law — durable BEFORE visible:
//!
//! * **Beacon**: [`StoreBarrier`] implements the `noos-witness`
//!   [`DurabilityBarrier`] over [`StorePort::persist_safety`] with the
//!   reserved kind [`crate::store_port::SAFETY_KIND_BEACON`]. `BeaconState`
//!   already refuses to emit before its barrier acks; the adapter makes
//!   that barrier the store's fsynced WAL.
//! * **Votes**: [`sign_and_release_vote`] persists a canonical
//!   [`VoteSafetyRecordV1`] (kind [`crate::store_port::SAFETY_KIND_VOTE`])
//!   and only THEN returns the signed vote for emission. A failed barrier
//!   emits nothing. Restart replays the records: a conflicting vote for an
//!   already-voted epoch is refused locally ([`VoteRefused::Slashable`])
//!   before any slashable message can exist.

use noos_braid::CheckpointRef;
use noos_codec::{define_object, NoosDecode, NoosEncode};
use noos_crypto::BlsSecretKey;
use noos_witness::beacon::{BarrierError, BeaconSafetyRecordV1, DurabilityBarrier};
use noos_witness::vote::FinalityVoteV1;

use crate::store_port::{StorePort, SAFETY_KIND_BEACON, SAFETY_KIND_VOTE};
use crate::{Hash32, NodeError};

/// `noos-store`-backed durability barrier for the beacon state machine.
pub struct StoreBarrier<'a, P: StorePort> {
    port: &'a mut P,
}

impl<'a, P: StorePort> StoreBarrier<'a, P> {
    pub fn new(port: &'a mut P) -> Self {
        StoreBarrier { port }
    }
}

impl<P: StorePort> DurabilityBarrier for StoreBarrier<'_, P> {
    fn persist(&mut self, record: &BeaconSafetyRecordV1) -> Result<(), BarrierError> {
        self.port
            .persist_safety(SAFETY_KIND_BEACON, &record.encode_canonical())
            .map(|_| ())
            .map_err(|e| BarrierError(e.to_string()))
    }
}

define_object! {
    /// Canonical persist-before-vote safety record.
    pub struct VoteSafetyRecordV1 {
        version: 1;
        1 => validator_id: [u8; 32],
        2 => epoch: u64,
        3 => source: CheckpointRef,
        4 => target: CheckpointRef,
    }
}

/// Why a vote was locally refused (nothing was signed or emitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteRefused {
    /// A durable record for this epoch exists with a DIFFERENT target:
    /// signing would be slashable double voting.
    Slashable { existing_target: CheckpointRef },
    /// The barrier failed: nothing may be emitted.
    Barrier(String),
    /// Signing/registry failure.
    Crypto,
    /// Store read-back failure while checking history.
    Store(String),
}

/// Signs a checkpoint vote and releases it ONLY after its safety record is
/// durable (WAL append + fsync ack through the port).
///
/// Order of operations (the ordering test pins this exactly):
/// 1. scan durable vote records; refuse a slashable conflict;
/// 2. persist the new record (fsync-backed);
/// 3. sign and return the vote — the caller may now emit it.
#[allow(clippy::too_many_arguments)]
pub fn sign_and_release_vote<P: StorePort>(
    port: &mut P,
    chain_id: Hash32,
    epoch: u64,
    source: CheckpointRef,
    target: CheckpointRef,
    validator_id: Hash32,
    membership_root: Hash32,
    secret: &BlsSecretKey,
) -> Result<FinalityVoteV1, VoteRefused> {
    // 1. Double-vote guard over the durable history.
    let records = port
        .safety_records(SAFETY_KIND_VOTE)
        .map_err(|e| VoteRefused::Store(e.to_string()))?;
    for raw in records {
        let Ok(rec) = VoteSafetyRecordV1::decode_canonical(&raw) else {
            // Malformed persisted safety state is fatal-shaped; refuse.
            return Err(VoteRefused::Store("malformed vote safety record".into()));
        };
        if rec.validator_id == validator_id && rec.epoch == epoch && rec.target != target {
            return Err(VoteRefused::Slashable {
                existing_target: rec.target,
            });
        }
    }

    // 2. Persist BEFORE any signable artifact exists outside this frame.
    let record = VoteSafetyRecordV1 {
        validator_id,
        epoch,
        source,
        target,
    };
    port.persist_safety(SAFETY_KIND_VOTE, &record.encode_canonical())
        .map_err(|e| VoteRefused::Barrier(e.to_string()))?;

    // 3. Sign; the caller receives the vote only past the barrier.
    FinalityVoteV1::sign(
        chain_id,
        epoch,
        source,
        target,
        validator_id,
        membership_root,
        secret,
    )
    .map_err(|_| VoteRefused::Crypto)
}

/// Convenience: run a closure against a [`StoreBarrier`] over `port`.
pub fn with_barrier<P: StorePort, T>(
    port: &mut P,
    f: impl FnOnce(&mut StoreBarrier<'_, P>) -> Result<T, NodeError>,
) -> Result<T, NodeError> {
    let mut barrier = StoreBarrier::new(port);
    f(&mut barrier)
}
