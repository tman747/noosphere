//! Slashing evidence and predicates (witness-v1.md §1.4; ch01 §4.8).
//!
//! Three offense classes with declaration-order discriminants:
//!
//! 0. `DoubleVote` — same target epoch, distinct targets;
//! 1. `SurroundVote` — the outer interval STRICTLY surrounds the inner
//!    (both ends);
//! 2. `InvalidTransitionVote` — the complete committed body is available
//!    AND deterministic re-execution yields different state or receipt
//!    roots. Execution recheck stays behind [`TransitionRecheck`].
//!
//! Unavailability alone is NEVER slashable (ch01 §4.8 rule 3). Evidence is
//! chain/domain/epoch-bound and verifiable through the evidence horizon
//! (ODR-WITNESS-005). Penalty split: burn / reporter / locked remainder
//! (ODR-WITNESS-002). Removal happens at the NEXT epoch boundary only —
//! membership never mutates mid-epoch (snapshots are immutable by type).

use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};
use noos_crypto::BlsPublicKey;

use crate::finality::SnapshotRegistry;
use crate::params::{WitnessParamsV1, PPM};
use crate::vote::FinalityVoteV1;
use crate::WitnessError;

define_object! {
    /// Divergence witness for an invalid-transition vote: the claimed vs
    /// deterministically recomputed roots (witness-v1.md §1.4 class 2).
    pub struct DivergenceWitnessV1 {
        version: 1;
        1 => claimed_state_root: [u8; 32],
        2 => recomputed_state_root: [u8; 32],
        3 => claimed_receipt_root: [u8; 32],
        4 => recomputed_receipt_root: [u8; 32],
    }
}

impl DivergenceWitnessV1 {
    /// A divergence exists iff a state or receipt root differs.
    #[must_use]
    pub fn diverges(&self) -> bool {
        self.claimed_state_root != self.recomputed_state_root
            || self.claimed_receipt_root != self.recomputed_receipt_root
    }
}

/// Slashing evidence (ordinary Lumen transaction payload). Discriminants
/// are `u16` in declaration order (noos-codec enum law).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingEvidenceV1 {
    /// Same target epoch, distinct targets.
    DoubleVote {
        vote_a: FinalityVoteV1,
        vote_b: FinalityVoteV1,
    },
    /// `outer` strictly surrounds `inner` on both ends.
    SurroundVote {
        outer: FinalityVoteV1,
        inner: FinalityVoteV1,
    },
    /// Vote for a checkpoint whose deterministic re-execution diverges.
    InvalidTransitionVote {
        vote: FinalityVoteV1,
        /// Content reference of the complete committed body re-executed.
        body_ref: [u8; 32],
        divergence_proof: DivergenceWitnessV1,
    },
}

impl NoosEncode for SlashingEvidenceV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::DoubleVote { vote_a, vote_b } => {
                w.put_u16(0);
                vote_a.encode(w);
                vote_b.encode(w);
            }
            Self::SurroundVote { outer, inner } => {
                w.put_u16(1);
                outer.encode(w);
                inner.encode(w);
            }
            Self::InvalidTransitionVote {
                vote,
                body_ref,
                divergence_proof,
            } => {
                w.put_u16(2);
                vote.encode(w);
                w.put_array32(body_ref);
                divergence_proof.encode(w);
            }
        }
    }
}

impl NoosDecode for SlashingEvidenceV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(3)? {
            0 => Ok(Self::DoubleVote {
                vote_a: FinalityVoteV1::decode(r)?,
                vote_b: FinalityVoteV1::decode(r)?,
            }),
            1 => Ok(Self::SurroundVote {
                outer: FinalityVoteV1::decode(r)?,
                inner: FinalityVoteV1::decode(r)?,
            }),
            _ => Ok(Self::InvalidTransitionVote {
                vote: FinalityVoteV1::decode(r)?,
                body_ref: r.get_array32()?,
                divergence_proof: DivergenceWitnessV1::decode(r)?,
            }),
        }
    }
}

/// Deterministic re-execution outcome for a committed body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecheckOutcome {
    /// The complete committed body is NOT available. Never slashable.
    Unavailable,
    /// Re-execution matched the voted roots: no offense.
    Match,
    /// Re-execution diverged; the witness carries both root pairs.
    Diverged(DivergenceWitnessV1),
}

/// Deterministic transition re-execution, behind a trait (the execution
/// engine is a Lumen/Braid concern; witness-v1.md §1.4 class 2).
pub trait TransitionRecheck {
    fn recheck(&self, body_ref: &[u8; 32], vote: &FinalityVoteV1) -> RecheckOutcome;
}

/// The conserved penalty split (ODR-WITNESS-002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashSplit {
    pub burn: u128,
    pub reporter: u128,
    /// Locked until exit.
    pub locked: u128,
}

impl SlashSplit {
    /// Exact conserved split of `amount` (checked; ppm fractions).
    pub fn compute(amount: u128, params: &WitnessParamsV1) -> Result<Self, WitnessError> {
        if !params.fractions_valid() {
            return Err(WitnessError::ArithmeticOverflow);
        }
        // Division by the nonzero constant PPM cannot panic.
        #[allow(clippy::arithmetic_side_effects)]
        let fraction = |ppm: u32| -> Result<u128, WitnessError> {
            amount
                .checked_mul(u128::from(ppm))
                .map(|v| v / u128::from(PPM))
                .ok_or(WitnessError::ArithmeticOverflow)
        };
        let burn = fraction(params.slash_burn_ppm)?;
        let reporter = fraction(params.slash_reporter_ppm)?;
        let locked = amount
            .checked_sub(burn)
            .and_then(|v| v.checked_sub(reporter))
            .ok_or(WitnessError::ArithmeticOverflow)?;
        Ok(Self {
            burn,
            reporter,
            locked,
        })
    }

    /// Conservation invariant: the three parts recompose the amount.
    #[must_use]
    pub fn conserves(&self, amount: u128) -> bool {
        self.burn
            .checked_add(self.reporter)
            .and_then(|v| v.checked_add(self.locked))
            == Some(amount)
    }
}

/// A verified slashing verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashOutcome {
    pub validator_id: [u8; 32],
    /// The offense epoch (the highest target epoch across the evidence).
    pub offense_epoch: u64,
    pub split: SlashSplit,
    /// Removal happens at the NEXT epoch boundary only (§1.4): the first
    /// epoch whose snapshot excludes the offender.
    pub removal_effective_epoch: u64,
}

/// Chain/domain/epoch binding + signature check for one evidence vote: the
/// vote's membership root must be the registered snapshot root for its
/// epoch, the voter a member, and the signature valid under the vote DST.
fn verify_evidence_vote(
    vote: &FinalityVoteV1,
    chain_id: &[u8; 32],
    registry: &SnapshotRegistry,
) -> Result<u128, WitnessError> {
    if vote.chain_id != *chain_id {
        return Err(WitnessError::WrongChain);
    }
    if vote.epoch != vote.target.epoch {
        return Err(WitnessError::EpochMismatch);
    }
    let snapshot = registry
        .get(vote.epoch)
        .ok_or(WitnessError::UnknownSnapshot)?;
    if vote.membership_root != snapshot.root() {
        return Err(WitnessError::MembershipRootMismatch);
    }
    let member = snapshot
        .member(&vote.validator_id)
        .ok_or(WitnessError::UnknownValidator)?;
    vote.verify_signature(&BlsPublicKey::from_bytes(member.consensus_bls_key.0))?;
    Ok(member.raw_weight)
}

/// Full §1.4 evidence verification.
///
/// * `current_epoch` — evidence-horizon anchor (ODR-WITNESS-005);
/// * `registry` — historical snapshots (evidence verifiable at any height
///   within the horizon);
/// * `recheck` — deterministic re-execution for class 2.
///
/// Unavailability is NEVER slashable; the offender is removed at the next
/// epoch boundary (the returned `removal_effective_epoch`), and existing
/// snapshots are immutable, so membership never mutates mid-epoch.
pub fn verify_evidence(
    evidence: &SlashingEvidenceV1,
    chain_id: &[u8; 32],
    current_epoch: u64,
    registry: &SnapshotRegistry,
    recheck: &impl TransitionRecheck,
    params: &WitnessParamsV1,
) -> Result<SlashOutcome, WitnessError> {
    let (validator_id, offense_epoch, bonded) = match evidence {
        SlashingEvidenceV1::DoubleVote { vote_a, vote_b } => {
            if vote_a.validator_id != vote_b.validator_id {
                return Err(WitnessError::ValidatorMismatch);
            }
            if vote_a == vote_b {
                return Err(WitnessError::IdenticalVotes);
            }
            if vote_a.target.epoch != vote_b.target.epoch {
                return Err(WitnessError::TargetEpochMismatch);
            }
            if vote_a.target == vote_b.target {
                return Err(WitnessError::TargetsNotDistinct);
            }
            let weight = verify_evidence_vote(vote_a, chain_id, registry)?;
            verify_evidence_vote(vote_b, chain_id, registry)?;
            (vote_a.validator_id, vote_a.target.epoch, weight)
        }
        SlashingEvidenceV1::SurroundVote { outer, inner } => {
            if outer.validator_id != inner.validator_id {
                return Err(WitnessError::ValidatorMismatch);
            }
            // STRICT surround on both ends (§1.4 class 1).
            if !(outer.source.epoch < inner.source.epoch && inner.target.epoch < outer.target.epoch)
            {
                return Err(WitnessError::NotSurrounding);
            }
            let weight = verify_evidence_vote(outer, chain_id, registry)?;
            verify_evidence_vote(inner, chain_id, registry)?;
            (outer.validator_id, outer.target.epoch, weight)
        }
        SlashingEvidenceV1::InvalidTransitionVote {
            vote,
            body_ref,
            divergence_proof,
        } => {
            let weight = verify_evidence_vote(vote, chain_id, registry)?;
            match recheck.recheck(body_ref, vote) {
                // Unavailability alone is NEVER slashable (ch01 §4.8 rule 3).
                RecheckOutcome::Unavailable => return Err(WitnessError::BodyUnavailable),
                RecheckOutcome::Match => return Err(WitnessError::NoDivergence),
                RecheckOutcome::Diverged(found) => {
                    if found != *divergence_proof || !found.diverges() {
                        return Err(WitnessError::DivergenceWitnessMismatch);
                    }
                }
            }
            (vote.validator_id, vote.target.epoch, weight)
        }
    };

    // Evidence horizon (ODR-WITNESS-005): the offense must sit within
    // `evidence_horizon_epochs` of the current epoch.
    if current_epoch.saturating_sub(offense_epoch) > params.evidence_horizon_epochs {
        return Err(WitnessError::EvidenceExpired);
    }

    let split = SlashSplit::compute(bonded, params)?;
    Ok(SlashOutcome {
        validator_id,
        offense_epoch,
        split,
        removal_effective_epoch: current_epoch
            .checked_add(1)
            .ok_or(WitnessError::ArithmeticOverflow)?,
    })
}
