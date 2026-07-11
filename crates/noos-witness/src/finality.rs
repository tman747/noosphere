//! Justification and finality (witness-v1.md §3, §1.3, §6; ch01 §4.8;
//! plan §§6.6–6.7).
//!
//! * Thresholds are EXACT integers: `Q = floor(2W/3) + 1`, computed
//!   separately on raw and effective totals; both must pass. Never a
//!   rounded "two thirds" (the naive ceiling `ceil(2W/3)` differs exactly
//!   when `3 | W`, and the threshold vectors pin that difference).
//! * Certificate verification recomputes BOTH weight sums from the epoch
//!   snapshot — the certificate's carried sums are cross-checked, never
//!   trusted — and verifies bitmap↔signer set, source ancestry, and the
//!   BLS aggregate under the vote DST over each signer's canonical vote
//!   body before any pointer moves.
//! * The genesis checkpoint is justified and finalized; a justified source
//!   finalizes exactly when its DIRECT CHILD epoch checkpoint is justified
//!   from it. Finalized checkpoints never revert.
//! * Duplicate certificates short-circuit on content digest
//!   (`D-WITNESS-CERT-DIGEST`) BEFORE re-verification.
//! * Historical snapshots are retained for certificate verification at any
//!   height; malformed persisted history STOPS startup (typed fatal),
//!   never resets safety state (§6).

use std::collections::{BTreeMap, BTreeSet};

use noos_braid::{CheckpointRef, FinalityCertificateV1};
use noos_codec::NoosEncode;
use noos_crypto::{
    bls_aggregate, bls_aggregate_verify, bls_fast_aggregate_verify, hash_domain, BlsPublicKey,
    BlsSignature, DomainId, Hash32,
};
use noos_lumen::objects::BoundedBytes;

use crate::membership::MembershipSnapshotV1;
use crate::vote::{vote_signing_bytes, CheckpointView, FinalityVoteV1};
use crate::{WitnessError, N_HARD};

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/// Exact justification threshold `Q = floor(2W/3) + 1` (§3).
///
/// Overflow-free for all `u128` totals: with `W = 3q + r`,
/// `floor(2W/3) = 2q + floor(2r/3) = 2q + (r == 2)`.
// Structural math: q <= u128::MAX/3, so 2q + 2 cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn quorum_threshold(total_weight: u128) -> u128 {
    let q = total_weight / 3;
    let r = total_weight % 3;
    2 * q + u128::from(r == 2) + 1
}

// ---------------------------------------------------------------------------
// Bitmap law (constants-v1.toml [witness] bitmap_bit_order)
// ---------------------------------------------------------------------------

/// Canonical bitmap length for `n` members: exactly `ceil(n/8)` bytes.
#[must_use]
pub fn bitmap_len(member_count: usize) -> usize {
    member_count.div_ceil(8)
}

/// Whether bit `i` (LSB-first within each byte) is set.
#[must_use]
pub fn bitmap_bit(bitmap: &[u8], i: usize) -> bool {
    bitmap
        .get(i / 8)
        .is_some_and(|byte| byte >> (i % 8) & 1 == 1)
}

/// Sets bit `i` (LSB-first). Caller guarantees capacity.
pub fn set_bitmap_bit(bitmap: &mut [u8], i: usize) {
    if let Some(byte) = bitmap.get_mut(i / 8) {
        *byte |= 1 << (i % 8);
    }
}

/// Decodes a participation bitmap against the member count: exact
/// canonical length, no bit at or beyond `member_count`, at least one bit.
// Index math bounded by bitmap.len() <= 128 and bit < 8; `bits - 1` is
// guarded by `bits != 0`. No value arithmetic.
#[allow(clippy::arithmetic_side_effects)]
pub fn bitmap_indices(bitmap: &[u8], member_count: usize) -> Result<Vec<usize>, WitnessError> {
    if bitmap.len() != bitmap_len(member_count) || member_count > N_HARD {
        return Err(WitnessError::BitmapLengthInvalid);
    }
    let mut indices = Vec::new();
    for (byte_index, byte) in bitmap.iter().enumerate() {
        let mut bits = *byte;
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            let i = byte_index * 8 + bit;
            if i >= member_count {
                return Err(WitnessError::BitmapOutOfRange);
            }
            indices.push(i);
            bits &= bits - 1;
        }
    }
    if indices.is_empty() {
        return Err(WitnessError::EmptySignerSet);
    }
    Ok(indices)
}

// ---------------------------------------------------------------------------
// Certificate digest and verification
// ---------------------------------------------------------------------------

/// Content digest of a certificate under `D-WITNESS-CERT-DIGEST` — the
/// duplicate-ingest short-circuit key (§1.3/§6) and the beacon transcript's
/// previous-certificate binding (§4.3).
pub fn certificate_digest(cert: &FinalityCertificateV1) -> Result<[u8; 32], WitnessError> {
    hash_domain(DomainId::WitnessCertDigest, &[&cert.encode_canonical()])
        .map(Hash32::into_bytes)
        .map_err(|_| WitnessError::CryptoRejected)
}

/// A verified certificate's recomputed facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCertificate {
    pub digest: [u8; 32],
    pub source: CheckpointRef,
    pub target: CheckpointRef,
    /// Canonical member indices of the signer set.
    pub signer_indices: Vec<usize>,
    /// Raw weight sum RECOMPUTED from the snapshot.
    pub raw_weight: u128,
    /// Effective weight sum RECOMPUTED from the snapshot.
    pub effective_weight: u128,
}

/// Full §1.3/§3 certificate verification against the epoch snapshot.
///
/// `chain_id` binds the vote bodies; `view` supplies source justification
/// and ancestry. Nothing carried by the certificate is trusted: both sums
/// are recomputed and cross-checked, the bitmap is resolved to the signer
/// set, and the aggregate is verified under the vote DST over each
/// signer's canonical vote body.
pub fn verify_certificate(
    cert: &FinalityCertificateV1,
    chain_id: &[u8; 32],
    snapshot: &MembershipSnapshotV1,
    view: &impl CheckpointView,
) -> Result<VerifiedCertificate, WitnessError> {
    // Epoch relationship: the certificate justifies its target epoch, whose
    // snapshot this must be; the interval must move forward.
    if cert.target.epoch != snapshot.epoch() {
        return Err(WitnessError::EpochMismatch);
    }
    if cert.target.epoch <= cert.source.epoch {
        return Err(WitnessError::MalformedInterval);
    }
    if cert.membership_root != snapshot.root() {
        return Err(WitnessError::MembershipRootMismatch);
    }

    let signer_indices = bitmap_indices(cert.participation_bitmap.as_slice(), snapshot.len())?;

    // Recompute BOTH sums from the snapshot (never trusted, §1.3).
    let members = snapshot.members();
    let mut raw = 0_u128;
    let mut eff = 0_u128;
    for &i in &signer_indices {
        raw = raw
            .checked_add(members[i].raw_weight)
            .ok_or(WitnessError::ArithmeticOverflow)?;
        eff = eff
            .checked_add(members[i].effective_weight)
            .ok_or(WitnessError::ArithmeticOverflow)?;
    }
    // Carried sums must equal the recomputation (sum inflation rejects).
    if raw != cert.raw_weight_sum || eff != cert.effective_weight_sum {
        return Err(WitnessError::WeightSumMismatch);
    }
    // Dual exact thresholds; the effective quorum can only strengthen the
    // raw quorum, never substitute for it (ch01 §4.10).
    if raw < quorum_threshold(snapshot.total_raw_weight()) {
        return Err(WitnessError::RawThresholdNotMet);
    }
    if eff < quorum_threshold(snapshot.total_effective_weight()) {
        return Err(WitnessError::EffectiveThresholdNotMet);
    }

    // Ancestry before pairing work: source justified, target descended.
    if !view.is_justified(&cert.source) {
        return Err(WitnessError::SourceNotJustified);
    }
    if !view.descends(&cert.source, &cert.target) {
        return Err(WitnessError::TargetNotDescended);
    }

    // Aggregate under the vote DST over each signer's canonical vote body
    // (fields 0–5; distinct validator_id makes every message distinct).
    let keys: Vec<BlsPublicKey> = signer_indices
        .iter()
        .map(|&i| BlsPublicKey::from_bytes(members[i].consensus_bls_key.0))
        .collect();
    let messages: Vec<Vec<u8>> = signer_indices
        .iter()
        .map(|&i| {
            vote_signing_bytes(
                chain_id,
                cert.target.epoch,
                &cert.source,
                &cert.target,
                &members[i].validator_id,
                &cert.membership_root,
            )
        })
        .collect();
    let message_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let signature = BlsSignature::from_bytes(cert.aggregate_signature.0);
    bls_aggregate_verify(DomainId::BlsVote, &keys, &message_refs, &signature)
        .map_err(|_| WitnessError::AggregateInvalid)?;

    Ok(VerifiedCertificate {
        digest: certificate_digest(cert)?,
        source: cert.source,
        target: cert.target,
        signer_indices,
        raw_weight: raw,
        effective_weight: eff,
    })
}

/// Builds a certificate from verified votes — the ONLY certificate
/// constructor in this crate, and it demands the quorum inputs (§5: no API
/// fabricates a certificate for an epoch whose thresholds failed).
///
/// All votes must target the same (source, target, membership root) under
/// `chain_id`, be cast by distinct snapshot members, and their weights must
/// meet BOTH exact thresholds; each signature is verified before
/// aggregation.
pub fn build_certificate(
    votes: &[FinalityVoteV1],
    chain_id: &[u8; 32],
    snapshot: &MembershipSnapshotV1,
) -> Result<FinalityCertificateV1, WitnessError> {
    let first = votes.first().ok_or(WitnessError::QuorumNotMet)?;
    if first.target.epoch != snapshot.epoch() {
        return Err(WitnessError::EpochMismatch);
    }
    let mut bitmap = vec![0_u8; bitmap_len(snapshot.len())];
    let mut raw = 0_u128;
    let mut eff = 0_u128;
    let mut seen = BTreeSet::new();
    let mut signatures = Vec::with_capacity(votes.len());
    for vote in votes {
        if vote.chain_id != *chain_id {
            return Err(WitnessError::WrongChain);
        }
        if vote.source != first.source
            || vote.target != first.target
            || vote.membership_root != first.membership_root
            || vote.epoch != first.epoch
        {
            return Err(WitnessError::EpochMismatch);
        }
        if vote.membership_root != snapshot.root() {
            return Err(WitnessError::MembershipRootMismatch);
        }
        let index = snapshot
            .index_of(&vote.validator_id)
            .ok_or(WitnessError::UnknownValidator)?;
        if !seen.insert(index) {
            return Err(WitnessError::DuplicateValidatorId);
        }
        let member = &snapshot.members()[index];
        vote.verify_signature(&BlsPublicKey::from_bytes(member.consensus_bls_key.0))?;
        set_bitmap_bit(&mut bitmap, index);
        raw = raw
            .checked_add(member.raw_weight)
            .ok_or(WitnessError::ArithmeticOverflow)?;
        eff = eff
            .checked_add(member.effective_weight)
            .ok_or(WitnessError::ArithmeticOverflow)?;
        signatures.push(BlsSignature::from_bytes(vote.signature.0));
    }
    if raw < quorum_threshold(snapshot.total_raw_weight()) {
        return Err(WitnessError::QuorumNotMet);
    }
    if eff < quorum_threshold(snapshot.total_effective_weight()) {
        return Err(WitnessError::QuorumNotMet);
    }
    let aggregate = bls_aggregate(&signatures).map_err(|_| WitnessError::CryptoRejected)?;
    Ok(FinalityCertificateV1 {
        source: first.source,
        target: first.target,
        participation_bitmap: BoundedBytes::new(bitmap).ok_or(WitnessError::BitmapLengthInvalid)?,
        aggregate_signature: noos_braid::Bytes96(aggregate.into_bytes()),
        raw_weight_sum: raw,
        effective_weight_sum: eff,
        membership_root: snapshot.root(),
    })
}

// ---------------------------------------------------------------------------
// Snapshot registry (historical sets, §6)
// ---------------------------------------------------------------------------

/// Typed fatal startup failures: malformed persisted history STOPS the
/// node, never resets safety state (§6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FatalHistoryError {
    /// Two persisted snapshots claim the same epoch.
    DuplicateEpoch(u64),
    /// A persisted root does not match its recomputed member map.
    RootMismatch(u64),
}

impl core::fmt::Display for FatalHistoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateEpoch(e) => write!(f, "duplicate persisted snapshot epoch {e}"),
            Self::RootMismatch(e) => write!(f, "persisted membership root mismatch at epoch {e}"),
        }
    }
}

impl std::error::Error for FatalHistoryError {}

/// Historical membership snapshots, retained for certificate verification
/// at any height (§6).
#[derive(Clone, Debug, Default)]
pub struct SnapshotRegistry {
    by_epoch: BTreeMap<u64, MembershipSnapshotV1>,
}

impl SnapshotRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a snapshot; re-registering an epoch is a duplicate.
    pub fn insert(&mut self, snapshot: MembershipSnapshotV1) -> Result<(), FatalHistoryError> {
        let epoch = snapshot.epoch();
        if self.by_epoch.contains_key(&epoch) {
            return Err(FatalHistoryError::DuplicateEpoch(epoch));
        }
        self.by_epoch.insert(epoch, snapshot);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, epoch: u64) -> Option<&MembershipSnapshotV1> {
        self.by_epoch.get(&epoch)
    }

    /// Loads persisted history with a claimed root per snapshot. The root
    /// is RECOMPUTED and compared; any mismatch or duplicate is typed
    /// fatal (§6).
    pub fn load_history<I>(entries: I) -> Result<Self, FatalHistoryError>
    where
        I: IntoIterator<Item = (MembershipSnapshotV1, [u8; 32])>,
    {
        let mut registry = Self::new();
        for (snapshot, claimed_root) in entries {
            if crate::membership::membership_root(snapshot.members()) != claimed_root
                || snapshot.root() != claimed_root
            {
                return Err(FatalHistoryError::RootMismatch(snapshot.epoch()));
            }
            registry.insert(snapshot)?;
        }
        Ok(registry)
    }
}

// ---------------------------------------------------------------------------
// Justified/finalized pointer state machine (§3)
// ---------------------------------------------------------------------------

/// Certificate ingestion outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Content digest already seen: short-circuited before verification.
    Duplicate,
    /// Target justified; no finalization advance.
    Justified,
    /// Target justified AND the certificate's source finalized (direct
    /// child rule).
    Finalized(CheckpointRef),
}

/// The local justified/finalized pointer pair with the never-revert law.
///
/// Also the crate's [`CheckpointView`] justification oracle; checkpoint
/// ancestry (a Braid DAG concern) is layered in by the caller.
#[derive(Clone, Debug)]
pub struct FinalityTracker {
    chain_id: [u8; 32],
    /// Every justified checkpoint, by (epoch, hash).
    justified: BTreeSet<(u64, [u8; 32])>,
    highest_justified: CheckpointRef,
    finalized: CheckpointRef,
    /// Duplicate-ingest short-circuit set (content digests).
    seen: BTreeSet<[u8; 32]>,
    /// Digests of certificates whose ingestion advanced finalization —
    /// the beacon's carrying-certificate release gate (§4.5).
    finalized_carriers: BTreeSet<[u8; 32]>,
}

impl FinalityTracker {
    /// Genesis: the genesis checkpoint is justified AND finalized (§3).
    #[must_use]
    pub fn genesis(chain_id: [u8; 32], genesis: CheckpointRef) -> Self {
        let mut justified = BTreeSet::new();
        justified.insert((genesis.epoch, genesis.checkpoint_hash));
        Self {
            chain_id,
            justified,
            highest_justified: genesis,
            finalized: genesis,
            seen: BTreeSet::new(),
            finalized_carriers: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn justified_head(&self) -> CheckpointRef {
        self.highest_justified
    }

    #[must_use]
    pub fn finalized_head(&self) -> CheckpointRef {
        self.finalized
    }

    #[must_use]
    pub fn is_checkpoint_justified(&self, checkpoint: &CheckpointRef) -> bool {
        self.justified
            .contains(&(checkpoint.epoch, checkpoint.checkpoint_hash))
    }

    /// Whether `digest` belongs to a certificate whose ingestion advanced
    /// finalization (the §4.5 randomness release gate).
    #[must_use]
    pub fn is_finalized_carrier(&self, digest: &[u8; 32]) -> bool {
        self.finalized_carriers.contains(digest)
    }

    /// Ingests one certificate: duplicate short-circuit on content digest,
    /// full verification against the historical snapshot, then the pointer
    /// moves — target justified; source finalized exactly when the target
    /// is its direct child epoch checkpoint. Finalized checkpoints never
    /// revert; a verified conflict at or below the finalized epoch is a
    /// fatal safety violation and changes nothing.
    pub fn ingest_certificate(
        &mut self,
        cert: &FinalityCertificateV1,
        registry: &SnapshotRegistry,
        ancestry: &impl Ancestry,
    ) -> Result<IngestOutcome, WitnessError> {
        let digest = certificate_digest(cert)?;
        if self.seen.contains(&digest) {
            return Ok(IngestOutcome::Duplicate);
        }
        let snapshot = registry
            .get(cert.target.epoch)
            .ok_or(WitnessError::UnknownSnapshot)?;
        let view = TrackerView {
            tracker: self,
            ancestry,
        };
        let chain_id = self.chain_id;
        let verified = verify_certificate(cert, &chain_id, snapshot, &view)?;

        // Never-revert law: a conflicting target at or below the finalized
        // epoch cannot be justified, let alone finalized.
        if verified.target.epoch <= self.finalized.epoch
            && !self.is_checkpoint_justified(&verified.target)
        {
            return Err(WitnessError::ConflictingFinalization);
        }

        self.seen.insert(digest);
        self.justified
            .insert((verified.target.epoch, verified.target.checkpoint_hash));
        if verified.target.epoch > self.highest_justified.epoch {
            self.highest_justified = verified.target;
        }

        // Direct-child finalization rule (§3).
        if Some(verified.target.epoch) == verified.source.epoch.checked_add(1) {
            if verified.source.epoch < self.finalized.epoch {
                // Older consistent finalization: no pointer motion.
                return Ok(IngestOutcome::Justified);
            }
            if verified.source.epoch == self.finalized.epoch {
                if verified.source.checkpoint_hash != self.finalized.checkpoint_hash {
                    return Err(WitnessError::ConflictingFinalization);
                }
                return Ok(IngestOutcome::Justified);
            }
            self.finalized = verified.source;
            self.finalized_carriers.insert(digest);
            return Ok(IngestOutcome::Finalized(verified.source));
        }
        Ok(IngestOutcome::Justified)
    }
}

/// Checkpoint ancestry oracle (Braid DAG knowledge).
pub trait Ancestry {
    /// Whether `target` is an epoch checkpoint descended from `source`.
    fn descends(&self, source: &CheckpointRef, target: &CheckpointRef) -> bool;
}

/// Tracker + ancestry composed into the vote/certificate [`CheckpointView`].
struct TrackerView<'a, A: Ancestry> {
    tracker: &'a FinalityTracker,
    ancestry: &'a A,
}

impl<A: Ancestry> CheckpointView for TrackerView<'_, A> {
    fn is_justified(&self, checkpoint: &CheckpointRef) -> bool {
        self.tracker.is_checkpoint_justified(checkpoint)
    }
    fn descends(&self, source: &CheckpointRef, target: &CheckpointRef) -> bool {
        self.ancestry.descends(source, target)
    }
}

// ---------------------------------------------------------------------------
// Reconfiguration handover (§6)
// ---------------------------------------------------------------------------

noos_codec::define_object! {
    /// Handover binding: (chain, epoch, old root, new root, finalized
    /// checkpoint) under a registered domain (§6).
    pub struct HandoverBindingV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => epoch: u64,
        3 => old_membership_root: [u8; 32],
        4 => new_membership_root: [u8; 32],
        5 => finalized_checkpoint: CheckpointRef,
    }
}

/// Handover transcript hash under `D-WITNESS-HANDOVER`.
pub fn handover_digest(binding: &HandoverBindingV1) -> Result<[u8; 32], WitnessError> {
    hash_domain(DomainId::WitnessHandover, &[&binding.encode_canonical()])
        .map(Hash32::into_bytes)
        .map_err(|_| WitnessError::CryptoRejected)
}

/// Verifies an aggregate handover attestation: the OLD set's signers sign
/// the transcript hash under the `D-BLS-HANDOVER` DST (same message —
/// fast aggregate).
pub fn verify_handover_attestation(
    binding: &HandoverBindingV1,
    signers: &[BlsPublicKey],
    aggregate: &BlsSignature,
) -> Result<(), WitnessError> {
    let digest = handover_digest(binding)?;
    bls_fast_aggregate_verify(DomainId::BlsHandover, signers, &digest, aggregate)
        .map_err(|_| WitnessError::AggregateInvalid)
}
