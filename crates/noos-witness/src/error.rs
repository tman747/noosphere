//! Closed typed error law for the Witness Ring.
//!
//! Every rejection carries a stable class name; conformance vectors in
//! `protocol/vectors/witness/` cross-check rejections by class, exactly the
//! braid pattern.

use core::fmt;

/// Every semantic rejection this crate can produce.
///
/// Wire-level failures stay `noos_codec::CodecError`; this enum covers the
/// witness-v1.md validity laws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    // -- registration (§1.1) -------------------------------------------------
    /// The 32-byte withdrawal key appears inside the consensus key material.
    KeyMaterialOverlap,
    /// BLS proof of possession failed under `D-BLS-POP`.
    PossessionProofInvalid,
    /// Ed25519 self-signature failed under `NOOS/SIG/TX/V1`.
    SelfSignatureInvalid,
    /// `exit_epoch` is nonzero but not after `activation_epoch`.
    MalformedExitEpoch,
    /// Two candidates share a `validator_id` (conflicting declarations).
    DuplicateValidatorId,
    /// Two candidates share a consensus BLS key.
    DuplicateConsensusKey,

    // -- membership (§2) ------------------------------------------------------
    /// The candidate list yields an empty eligible set.
    EmptyEligibleSet,

    // -- votes / certificates (§§1.2, 1.3, 3) ---------------------------------
    /// Vote or evidence bound to a different chain id.
    WrongChain,
    /// Vote `epoch` field does not equal the target checkpoint epoch.
    EpochMismatch,
    /// `membership_root` does not equal the snapshotted Ring for the epoch.
    MembershipRootMismatch,
    /// The voter is not a member of the epoch snapshot.
    UnknownValidator,
    /// The vote/certificate source is not justified in the local view.
    SourceNotJustified,
    /// The target does not descend from the source.
    TargetNotDescended,
    /// Source/target interval is malformed (`target.epoch <= source.epoch`).
    MalformedInterval,
    /// A BLS signature failed verification under the registered DST.
    SignatureInvalid,
    /// Participation bitmap is not exactly `ceil(n/8)` bytes.
    BitmapLengthInvalid,
    /// Participation bitmap sets a bit at or beyond the member count.
    BitmapOutOfRange,
    /// Participation bitmap selects no signers.
    EmptySignerSet,
    /// A certificate-carried weight sum differs from the recomputation.
    WeightSumMismatch,
    /// Recomputed raw weight below `floor(2W/3) + 1`.
    RawThresholdNotMet,
    /// Recomputed effective weight below `floor(2W/3) + 1`.
    EffectiveThresholdNotMet,
    /// The aggregate signature failed under the vote DST.
    AggregateInvalid,
    /// No snapshot is registered for the certificate epoch.
    UnknownSnapshot,
    /// Verified certificate would finalize a conflicting checkpoint at or
    /// below the finalized epoch: fatal safety violation, never applied.
    ConflictingFinalization,
    /// Vote quorum inputs missing: a certificate cannot be constructed.
    QuorumNotMet,

    // -- slashing (§1.4) ------------------------------------------------------
    /// Both votes name the same target: not a double vote.
    TargetsNotDistinct,
    /// The two votes are the same vote (byte-identical).
    IdenticalVotes,
    /// Votes were cast by different validators.
    ValidatorMismatch,
    /// Double-vote predicate needs equal target epochs.
    TargetEpochMismatch,
    /// The outer interval does not strictly surround the inner one.
    NotSurrounding,
    /// The committed body is unavailable: NEVER slashable (ch01 §4.8 rule 3).
    BodyUnavailable,
    /// Deterministic re-execution matched the vote: no divergence.
    NoDivergence,
    /// The evidence's divergence witness does not match the recheck result.
    DivergenceWitnessMismatch,
    /// Evidence is older than the evidence horizon (ODR-WITNESS-005).
    EvidenceExpired,

    // -- beacon (§4) -----------------------------------------------------------
    /// The submitter is not in the epoch snapshot.
    NotAMember,
    /// A second commit from the same witness (exactly-one-commit law).
    DuplicateCommit,
    /// Commit at or after the frozen cutoff slot.
    PostCutoffCommit,
    /// Message arrived in the wrong beacon phase.
    WrongBeaconPhase,
    /// Reveal without a finalized commitment from this witness.
    UnknownCommit,
    /// Reveal does not match the committed hash.
    RevealMismatch,
    /// A second reveal from the same witness.
    DuplicateReveal,
    /// The durability barrier failed; nothing was emitted.
    BarrierFailed,
    /// Persisted safety records disagree with the local state (typed fatal).
    MalformedSafetyRecord,

    // -- shared ----------------------------------------------------------------
    /// Checked arithmetic overflowed (weights near `u128::MAX`).
    ArithmeticOverflow,
    /// An underlying cryptographic primitive rejected its input.
    CryptoRejected,
}

impl WitnessError {
    /// Stable class name used by conformance vectors.
    #[must_use]
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::KeyMaterialOverlap => "key_material_overlap",
            Self::PossessionProofInvalid => "possession_proof_invalid",
            Self::SelfSignatureInvalid => "self_signature_invalid",
            Self::MalformedExitEpoch => "malformed_exit_epoch",
            Self::DuplicateValidatorId => "duplicate_validator_id",
            Self::DuplicateConsensusKey => "duplicate_consensus_key",
            Self::EmptyEligibleSet => "empty_eligible_set",
            Self::WrongChain => "wrong_chain",
            Self::EpochMismatch => "epoch_mismatch",
            Self::MembershipRootMismatch => "membership_root_mismatch",
            Self::UnknownValidator => "unknown_validator",
            Self::SourceNotJustified => "source_not_justified",
            Self::TargetNotDescended => "target_not_descended",
            Self::MalformedInterval => "malformed_interval",
            Self::SignatureInvalid => "signature_invalid",
            Self::BitmapLengthInvalid => "bitmap_length_invalid",
            Self::BitmapOutOfRange => "bitmap_out_of_range",
            Self::EmptySignerSet => "empty_signer_set",
            Self::WeightSumMismatch => "weight_sum_mismatch",
            Self::RawThresholdNotMet => "raw_threshold_not_met",
            Self::EffectiveThresholdNotMet => "effective_threshold_not_met",
            Self::AggregateInvalid => "aggregate_invalid",
            Self::UnknownSnapshot => "unknown_snapshot",
            Self::ConflictingFinalization => "conflicting_finalization",
            Self::QuorumNotMet => "quorum_not_met",
            Self::TargetsNotDistinct => "targets_not_distinct",
            Self::IdenticalVotes => "identical_votes",
            Self::ValidatorMismatch => "validator_mismatch",
            Self::TargetEpochMismatch => "target_epoch_mismatch",
            Self::NotSurrounding => "not_surrounding",
            Self::BodyUnavailable => "body_unavailable",
            Self::NoDivergence => "no_divergence",
            Self::DivergenceWitnessMismatch => "divergence_witness_mismatch",
            Self::EvidenceExpired => "evidence_expired",
            Self::NotAMember => "not_a_member",
            Self::DuplicateCommit => "duplicate_commit",
            Self::PostCutoffCommit => "post_cutoff_commit",
            Self::WrongBeaconPhase => "wrong_beacon_phase",
            Self::UnknownCommit => "unknown_commit",
            Self::RevealMismatch => "reveal_mismatch",
            Self::DuplicateReveal => "duplicate_reveal",
            Self::BarrierFailed => "barrier_failed",
            Self::MalformedSafetyRecord => "malformed_safety_record",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::CryptoRejected => "crypto_rejected",
        }
    }
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_name())
    }
}

impl std::error::Error for WitnessError {}
