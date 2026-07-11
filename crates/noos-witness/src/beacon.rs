//! Epoch randomness: delay-VRF commit/reveal mix (witness-v1.md §4;
//! ch01 §4.9; plan §6.7).
//!
//! Per epoch, over the snapshot membership:
//!
//! 1. COMMIT: each eligible witness submits exactly one commitment before
//!    the frozen cutoff slot ([`crate::BEACON_COMMIT_CUTOFF_SLOT_OFFSET`]).
//!    The commit message carries `reveal_hash = H_reveal(reveal)`
//!    (`D-BEACON-REVEAL`); the commitment digest binds
//!    `chain_id || epoch_le || membership_root || validator_id ||
//!    reveal_hash` under `D-BEACON-COMMIT`. Duplicates and post-cutoff
//!    commits reject.
//! 2. After the commit set FINALIZES: only the matching delay-VRF reveal
//!    is accepted. Late, alternate, or mismatched reveals reject.
//! 3. MIX: deterministic membership-ordered fold under `D-BEACON-MIX` over
//!    `chain_id || epoch_le || membership_root || contribution bitmap ||
//!    prev finalized certificate digest || m_1 || … || m_n`, with
//!    `m_i = reveal_i` if revealed else the already-committed
//!    `reveal_hash_i` — withholding cannot select among outputs, it only
//!    incurs the frozen penalty (ODR-WITNESS-002 family).
//! 4. PERSIST-BEFORE-MESSAGE: local commit/reveal safety state reaches the
//!    [`DurabilityBarrier`] BEFORE any beacon message is returned for
//!    emission. A failed barrier emits nothing.
//! 5. Consumers see `R_e` only after its carrying certificate finalizes:
//!    the mix output is a [`SealedRandomness`] that opens only against a
//!    [`crate::finality::FinalityTracker`] finalized-carrier digest.

use std::collections::BTreeMap;

use noos_codec::define_object;
use noos_crypto::{hash_domain, DomainId, Hash32};

use crate::finality::{bitmap_len, set_bitmap_bit, FinalityTracker};
use crate::membership::MembershipSnapshotV1;
use crate::{WitnessError, BEACON_COMMIT_CUTOFF_SLOT_OFFSET};

// ---------------------------------------------------------------------------
// Durability barrier (persist-before-message)
// ---------------------------------------------------------------------------

/// Kind tag inside [`BeaconSafetyRecordV1`]: a commit record.
pub const SAFETY_RECORD_COMMIT: u16 = 0;
/// Kind tag inside [`BeaconSafetyRecordV1`]: a reveal record.
pub const SAFETY_RECORD_REVEAL: u16 = 1;

define_object! {
    /// The beacon safety record persisted BEFORE any message is emitted
    /// (persist-before-vote generalization, plan §6.7). `noos-store`
    /// carries these bytes in its WAL; a composition-layer adapter
    /// implements [`DurabilityBarrier`] over it.
    pub struct BeaconSafetyRecordV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => epoch: u64,
        3 => membership_root: [u8; 32],
        4 => validator_id: [u8; 32],
        5 => kind: u16,
        6 => payload: [u8; 32],
    }
}

/// Durability failure: nothing was persisted, nothing may be emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierError(pub String);

/// The persist-before-message barrier. `noos-store` implements the durable
/// substrate; `Ok` means the record survives a crash (WAL append + fsync).
pub trait DurabilityBarrier {
    fn persist(&mut self, record: &BeaconSafetyRecordV1) -> Result<(), BarrierError>;
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

define_object! {
    /// Beacon commit message: publishes the committed reveal hash; the
    /// commitment digest is recomputed by every verifier (§4.1).
    pub struct BeaconCommitV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => epoch: u64,
        3 => membership_root: [u8; 32],
        4 => validator_id: [u8; 32],
        5 => reveal_hash: [u8; 32],
    }
}

define_object! {
    /// Beacon reveal message: the delay-VRF output preimage (§4.2).
    pub struct BeaconRevealV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => epoch: u64,
        3 => membership_root: [u8; 32],
        4 => validator_id: [u8; 32],
        5 => reveal: [u8; 32],
    }
}

/// Committed reveal hash under `D-BEACON-REVEAL`.
pub fn reveal_hash(reveal: &[u8; 32]) -> Result<[u8; 32], WitnessError> {
    hash_domain(DomainId::BeaconReveal, &[reveal])
        .map(Hash32::into_bytes)
        .map_err(|_| WitnessError::CryptoRejected)
}

/// Commitment digest `c_i` under `D-BEACON-COMMIT` (§4.1).
pub fn commit_digest(
    chain_id: &[u8; 32],
    epoch: u64,
    membership_root: &[u8; 32],
    validator_id: &[u8; 32],
    reveal_hash: &[u8; 32],
) -> Result<[u8; 32], WitnessError> {
    hash_domain(
        DomainId::BeaconCommit,
        &[
            chain_id,
            &epoch.to_le_bytes(),
            membership_root,
            validator_id,
            reveal_hash,
        ],
    )
    .map(Hash32::into_bytes)
    .map_err(|_| WitnessError::CryptoRejected)
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Beacon phase for one epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconPhase {
    /// Accepting commits before the cutoff slot.
    Commit,
    /// Commit set finalized; accepting matching reveals.
    Reveal,
    /// Mix computed; the epoch transcript is closed.
    Mixed,
}

/// The mix result: sealed randomness plus the public transcript facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRandomness {
    randomness: [u8; 32],
    /// Contribution bitmap over the canonical member order (who revealed).
    pub contribution_bitmap: Vec<u8>,
    /// Committed-but-unrevealed members, in canonical order: each incurs
    /// the frozen penalty (`WitnessParamsV1::missed_reveal_penalty`).
    pub withheld: Vec<[u8; 32]>,
}

impl SealedRandomness {
    /// Consumers see `R_e` only after its carrying certificate finalizes
    /// (§4.5): opening requires the tracker to know `carrying_digest` as a
    /// finalization-advancing certificate digest.
    #[must_use]
    pub fn open(&self, tracker: &FinalityTracker, carrying_digest: &[u8; 32]) -> Option<[u8; 32]> {
        tracker
            .is_finalized_carrier(carrying_digest)
            .then_some(self.randomness)
    }

    /// Test/vector access without a finality gate. Hidden from consumers;
    /// the generator must reproduce transcripts byte-for-byte.
    #[doc(hidden)]
    #[must_use]
    pub fn raw_for_vectors(&self) -> [u8; 32] {
        self.randomness
    }
}

/// Per-epoch beacon state machine over the snapshot membership.
#[derive(Clone, Debug)]
pub struct BeaconState {
    chain_id: [u8; 32],
    epoch: u64,
    membership_root: [u8; 32],
    /// Canonical member order (ascending validator id).
    member_ids: Vec<[u8; 32]>,
    phase: BeaconPhase,
    /// validator id → committed reveal hash.
    commits: BTreeMap<[u8; 32], [u8; 32]>,
    /// validator id → accepted reveal.
    reveals: BTreeMap<[u8; 32], [u8; 32]>,
}

impl BeaconState {
    #[must_use]
    pub fn new(chain_id: [u8; 32], snapshot: &MembershipSnapshotV1) -> Self {
        Self {
            chain_id,
            epoch: snapshot.epoch(),
            membership_root: snapshot.root(),
            member_ids: snapshot.members().iter().map(|m| m.validator_id).collect(),
            phase: BeaconPhase::Commit,
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn phase(&self) -> BeaconPhase {
        self.phase
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn is_member(&self, validator_id: &[u8; 32]) -> bool {
        self.member_ids.binary_search(validator_id).is_ok()
    }

    fn check_commit(
        &self,
        validator_id: &[u8; 32],
        slot_in_epoch: u64,
    ) -> Result<(), WitnessError> {
        if self.phase != BeaconPhase::Commit {
            return Err(WitnessError::WrongBeaconPhase);
        }
        if slot_in_epoch >= BEACON_COMMIT_CUTOFF_SLOT_OFFSET {
            return Err(WitnessError::PostCutoffCommit);
        }
        if !self.is_member(validator_id) {
            return Err(WitnessError::NotAMember);
        }
        if self.commits.contains_key(validator_id) {
            // Exactly-one-commit law (§4.1).
            return Err(WitnessError::DuplicateCommit);
        }
        Ok(())
    }

    /// LOCAL commit path: validates, PERSISTS through the barrier, records,
    /// and only then returns the message for emission. A barrier failure
    /// emits nothing and records nothing.
    pub fn local_commit(
        &mut self,
        barrier: &mut impl DurabilityBarrier,
        validator_id: [u8; 32],
        reveal_hash: [u8; 32],
        slot_in_epoch: u64,
    ) -> Result<BeaconCommitV1, WitnessError> {
        self.check_commit(&validator_id, slot_in_epoch)?;
        let record = BeaconSafetyRecordV1 {
            chain_id: self.chain_id,
            epoch: self.epoch,
            membership_root: self.membership_root,
            validator_id,
            kind: SAFETY_RECORD_COMMIT,
            payload: reveal_hash,
        };
        barrier
            .persist(&record)
            .map_err(|_| WitnessError::BarrierFailed)?;
        self.commits.insert(validator_id, reveal_hash);
        Ok(BeaconCommitV1 {
            chain_id: self.chain_id,
            epoch: self.epoch,
            membership_root: self.membership_root,
            validator_id,
            reveal_hash,
        })
    }

    /// Ingests a peer commit (already emitted remotely; no local barrier).
    pub fn ingest_commit(
        &mut self,
        msg: &BeaconCommitV1,
        slot_in_epoch: u64,
    ) -> Result<(), WitnessError> {
        if msg.chain_id != self.chain_id {
            return Err(WitnessError::WrongChain);
        }
        if msg.epoch != self.epoch {
            return Err(WitnessError::EpochMismatch);
        }
        if msg.membership_root != self.membership_root {
            return Err(WitnessError::MembershipRootMismatch);
        }
        self.check_commit(&msg.validator_id, slot_in_epoch)?;
        self.commits.insert(msg.validator_id, msg.reveal_hash);
        Ok(())
    }

    /// The commit set FINALIZED on chain (§4.2): reveals open.
    pub fn finalize_commits(&mut self) -> Result<(), WitnessError> {
        if self.phase != BeaconPhase::Commit {
            return Err(WitnessError::WrongBeaconPhase);
        }
        self.phase = BeaconPhase::Reveal;
        Ok(())
    }

    fn check_reveal(&self, validator_id: &[u8; 32], reveal: &[u8; 32]) -> Result<(), WitnessError> {
        match self.phase {
            BeaconPhase::Commit => return Err(WitnessError::WrongBeaconPhase),
            // Late reveals (after the mix) reject (§4.2).
            BeaconPhase::Mixed => return Err(WitnessError::WrongBeaconPhase),
            BeaconPhase::Reveal => {}
        }
        let committed = self
            .commits
            .get(validator_id)
            .ok_or(WitnessError::UnknownCommit)?;
        if self.reveals.contains_key(validator_id) {
            return Err(WitnessError::DuplicateReveal);
        }
        // Alternate/mismatched reveals reject (§4.2).
        if reveal_hash(reveal)? != *committed {
            return Err(WitnessError::RevealMismatch);
        }
        Ok(())
    }

    /// LOCAL reveal path: persist-before-message, exactly like commits.
    pub fn local_reveal(
        &mut self,
        barrier: &mut impl DurabilityBarrier,
        validator_id: [u8; 32],
        reveal: [u8; 32],
    ) -> Result<BeaconRevealV1, WitnessError> {
        self.check_reveal(&validator_id, &reveal)?;
        let record = BeaconSafetyRecordV1 {
            chain_id: self.chain_id,
            epoch: self.epoch,
            membership_root: self.membership_root,
            validator_id,
            kind: SAFETY_RECORD_REVEAL,
            payload: reveal,
        };
        barrier
            .persist(&record)
            .map_err(|_| WitnessError::BarrierFailed)?;
        self.reveals.insert(validator_id, reveal);
        Ok(BeaconRevealV1 {
            chain_id: self.chain_id,
            epoch: self.epoch,
            membership_root: self.membership_root,
            validator_id,
            reveal,
        })
    }

    /// Ingests a peer reveal.
    pub fn ingest_reveal(&mut self, msg: &BeaconRevealV1) -> Result<(), WitnessError> {
        if msg.chain_id != self.chain_id {
            return Err(WitnessError::WrongChain);
        }
        if msg.epoch != self.epoch {
            return Err(WitnessError::EpochMismatch);
        }
        if msg.membership_root != self.membership_root {
            return Err(WitnessError::MembershipRootMismatch);
        }
        self.check_reveal(&msg.validator_id, &msg.reveal)?;
        self.reveals.insert(msg.validator_id, msg.reveal);
        Ok(())
    }

    /// Computes `R_e` (§4.3): the deterministic membership-ordered fold.
    /// Members without a commit contribute nothing; a committed-but-
    /// withheld member contributes its already-committed reveal hash and
    /// is reported for the frozen penalty.
    pub fn compute_mix(
        &mut self,
        prev_finalized_certificate_digest: &[u8; 32],
    ) -> Result<SealedRandomness, WitnessError> {
        if self.phase != BeaconPhase::Reveal {
            return Err(WitnessError::WrongBeaconPhase);
        }
        let mut bitmap = vec![0_u8; bitmap_len(self.member_ids.len())];
        let mut contributions: Vec<[u8; 32]> = Vec::new();
        let mut withheld = Vec::new();
        for (i, id) in self.member_ids.iter().enumerate() {
            if let Some(reveal) = self.reveals.get(id) {
                set_bitmap_bit(&mut bitmap, i);
                contributions.push(*reveal);
            } else if let Some(committed) = self.commits.get(id) {
                // Missing reveal: the committed hash substitutes (§4.3).
                contributions.push(*committed);
                withheld.push(*id);
            }
        }
        let mut parts: Vec<&[u8]> = Vec::with_capacity(contributions.len().saturating_add(5));
        let epoch_le = self.epoch.to_le_bytes();
        parts.push(&self.chain_id);
        parts.push(&epoch_le);
        parts.push(&self.membership_root);
        parts.push(&bitmap);
        parts.push(prev_finalized_certificate_digest);
        for m in &contributions {
            parts.push(m);
        }
        let randomness = hash_domain(DomainId::BeaconMix, &parts)
            .map(Hash32::into_bytes)
            .map_err(|_| WitnessError::CryptoRejected)?;
        self.phase = BeaconPhase::Mixed;
        Ok(SealedRandomness {
            randomness,
            contribution_bitmap: bitmap,
            withheld,
        })
    }

    /// Rebuilds local safety state from persisted records (crash recovery).
    /// Records must match this epoch's binding exactly; a record that
    /// contradicts another (two commits for one witness, a reveal without
    /// its commit, a reveal not matching its commit) is typed-fatal — the
    /// history is malformed and startup must stop (§6).
    pub fn restore(&mut self, records: &[BeaconSafetyRecordV1]) -> Result<(), WitnessError> {
        for record in records {
            if record.chain_id != self.chain_id
                || record.epoch != self.epoch
                || record.membership_root != self.membership_root
            {
                return Err(WitnessError::MalformedSafetyRecord);
            }
            match record.kind {
                SAFETY_RECORD_COMMIT => {
                    if !self.is_member(&record.validator_id) {
                        return Err(WitnessError::MalformedSafetyRecord);
                    }
                    if let Some(existing) = self.commits.get(&record.validator_id) {
                        if *existing != record.payload {
                            return Err(WitnessError::MalformedSafetyRecord);
                        }
                    } else {
                        self.commits.insert(record.validator_id, record.payload);
                    }
                }
                SAFETY_RECORD_REVEAL => {
                    let committed = self
                        .commits
                        .get(&record.validator_id)
                        .ok_or(WitnessError::MalformedSafetyRecord)?;
                    if reveal_hash(&record.payload)? != *committed {
                        return Err(WitnessError::MalformedSafetyRecord);
                    }
                    self.reveals.insert(record.validator_id, record.payload);
                }
                _ => return Err(WitnessError::MalformedSafetyRecord),
            }
        }
        Ok(())
    }
}
