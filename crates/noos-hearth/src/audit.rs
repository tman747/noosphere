//! Priced Chorus audit assignment and TOPLOC -> Freivalds -> dispute escalation.

use crate::domain_hash;
use noos_species::Hash32;

pub const TOPLOC_BYTES_PER_32_TOKENS: u32 = 258;
pub const PHONE_70B_SHARD_BYTES: u64 = 1_710_000_000;
pub const PHONE_70B_LAYERS_PER_SHARD: u16 = 2;
pub const PHONE_70B_AUDITORS: u16 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditTier {
    ContinuousToploc,
    SampledFreivalds,
    FullDispute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExactFaultClass {
    AccumulatorLie,
    C8Flip,
    SaturationLie,
    TransplantedReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAuditClaim {
    pub job_id: Hash32,
    pub executor: Hash32,
    pub chunk_index: u64,
    pub chunk_root: Hash32,
    pub toploc_root: Hash32,
    pub c32_root: Hash32,
    pub committed_height: u64,
    pub gain_at_risk: u128,
}

impl ChunkAuditClaim {
    #[must_use]
    pub fn claim_root(&self) -> Hash32 {
        domain_hash(
            "NOOS/HEARTH/AUDIT-CLAIM/V1",
            &[
                &self.job_id,
                &self.executor,
                &self.chunk_index.to_le_bytes(),
                &self.chunk_root,
                &self.toploc_root,
                &self.c32_root,
                &self.committed_height.to_le_bytes(),
                &self.gain_at_risk.to_le_bytes(),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorPolicy {
    pub coverage_bps: u16,
    pub repetitions: u8,
    pub maximum_witness_bytes: u64,
    pub maximum_tasks: u32,
    pub exact_audits_enabled: bool,
}

impl AuditorPolicy {
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.coverage_bps == 0
            || self.coverage_bps > 10_000
            || !matches!(self.repetitions, 1 | 2 | 4)
            || self.maximum_witness_bytes == 0
            || self.maximum_tasks == 0
        {
            return Err(AuditError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAssignment {
    pub assignment_root: Hash32,
    pub claim_root: Hash32,
    pub auditor: Hash32,
    pub weight_shard_root: Hash32,
    pub challenge_beacon: Hash32,
    pub assigned_height: u64,
    pub tier: AuditTier,
    pub witness_bytes: u64,
}

pub fn assign_after_commit(
    claim: &ChunkAuditClaim,
    auditor: Hash32,
    weight_shard_root: Hash32,
    challenge_beacon: Hash32,
    assigned_height: u64,
    witness_bytes: u64,
    policy: AuditorPolicy,
) -> Result<AuditAssignment, AuditError> {
    policy.validate()?;
    if assigned_height <= claim.committed_height {
        return Err(AuditError::ChallengeBeforeCommit);
    }
    if !policy.exact_audits_enabled || witness_bytes > policy.maximum_witness_bytes {
        return Err(AuditError::WitnessBudgetExceeded);
    }
    let claim_root = claim.claim_root();
    let assignment_root = domain_hash(
        "NOOS/HEARTH/AUDIT-ASSIGNMENT/V1",
        &[
            &claim_root,
            &auditor,
            &weight_shard_root,
            &challenge_beacon,
            &assigned_height.to_le_bytes(),
            &witness_bytes.to_le_bytes(),
            &[policy.repetitions],
        ],
    );
    Ok(AuditAssignment {
        assignment_root,
        claim_root,
        auditor,
        weight_shard_root,
        challenge_beacon,
        assigned_height,
        tier: AuditTier::SampledFreivalds,
        witness_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationState {
    ToplocMonitoring,
    ExactAuditRequired,
    ExactAuditClean,
    FullDisputeRequired,
    ExecutorFault,
    ExecutorUpheld,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEscalation {
    pub claim_root: Hash32,
    pub state: EscalationState,
    pub fault_class: Option<ExactFaultClass>,
    pub stake_moved: bool,
}

impl AuditEscalation {
    #[must_use]
    pub fn new(claim: &ChunkAuditClaim) -> Self {
        Self {
            claim_root: claim.claim_root(),
            state: EscalationState::ToplocMonitoring,
            fault_class: None,
            stake_moved: false,
        }
    }

    pub fn observe_toploc(&mut self, exact_match: bool) -> Result<(), AuditError> {
        if self.state != EscalationState::ToplocMonitoring {
            return Err(AuditError::InvalidEscalation);
        }
        if !exact_match {
            self.state = EscalationState::ExactAuditRequired;
        }
        // A fingerprint alone never moves stake.
        self.stake_moved = false;
        Ok(())
    }

    pub fn submit_exact_audit(
        &mut self,
        assignment: &AuditAssignment,
        equality_passed: bool,
        fault_class: Option<ExactFaultClass>,
    ) -> Result<(), AuditError> {
        if !matches!(
            self.state,
            EscalationState::ToplocMonitoring | EscalationState::ExactAuditRequired
        ) || assignment.claim_root != self.claim_root
            || assignment.tier != AuditTier::SampledFreivalds
        {
            return Err(AuditError::InvalidAssignment);
        }
        if equality_passed {
            if fault_class.is_some() {
                return Err(AuditError::ContradictoryVerdict);
            }
            self.state = EscalationState::ExactAuditClean;
        } else {
            self.fault_class = Some(fault_class.ok_or(AuditError::MissingFaultClass)?);
            self.state = EscalationState::FullDisputeRequired;
        }
        self.stake_moved = false;
        Ok(())
    }

    pub fn resolve_full_dispute(&mut self, executor_fault: bool) -> Result<(), AuditError> {
        if self.state != EscalationState::FullDisputeRequired {
            return Err(AuditError::InvalidEscalation);
        }
        self.state = if executor_fault {
            EscalationState::ExecutorFault
        } else {
            EscalationState::ExecutorUpheld
        };
        self.stake_moved = true;
        Ok(())
    }
}

pub fn minimum_deterrence_bond(
    gain_per_cheated_chunk: u128,
    coverage_bps: u16,
) -> Result<u128, AuditError> {
    if coverage_bps == 0 || coverage_bps > 10_000 {
        return Err(AuditError::InvalidPolicy);
    }
    // Strictly greater than gain/c, with c represented in basis points.
    Ok(gain_per_cheated_chunk
        .checked_mul(10_000)
        .ok_or(AuditError::ArithmeticOverflow)?
        .div_ceil(u128::from(coverage_bps))
        .saturating_add(1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhoneShardPlan {
    pub model_layers: u16,
    pub layers_per_phone: u16,
    pub phones_required: u16,
    pub bytes_per_phone: u64,
}

impl PhoneShardPlan {
    pub fn seventy_billion_reference(model_layers: u16) -> Result<Self, AuditError> {
        if model_layers == 0 || !model_layers.is_multiple_of(PHONE_70B_LAYERS_PER_SHARD) {
            return Err(AuditError::InvalidPhoneShardPlan);
        }
        let phones_required = model_layers / PHONE_70B_LAYERS_PER_SHARD;
        if phones_required != PHONE_70B_AUDITORS {
            return Err(AuditError::InvalidPhoneShardPlan);
        }
        Ok(Self {
            model_layers,
            layers_per_phone: PHONE_70B_LAYERS_PER_SHARD,
            phones_required,
            bytes_per_phone: PHONE_70B_SHARD_BYTES,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    InvalidPolicy,
    ChallengeBeforeCommit,
    WitnessBudgetExceeded,
    InvalidEscalation,
    InvalidAssignment,
    ContradictoryVerdict,
    MissingFaultClass,
    ArithmeticOverflow,
    InvalidPhoneShardPlan,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn claim() -> ChunkAuditClaim {
        ChunkAuditClaim {
            job_id: h(1),
            executor: h(2),
            chunk_index: 3,
            chunk_root: h(4),
            toploc_root: h(5),
            c32_root: h(6),
            committed_height: 10,
            gain_at_risk: 100,
        }
    }

    fn assignment(claim: &ChunkAuditClaim) -> AuditAssignment {
        assign_after_commit(
            claim,
            h(7),
            h(8),
            h(9),
            11,
            1_000,
            AuditorPolicy {
                coverage_bps: 150,
                repetitions: 2,
                maximum_witness_bytes: 2_000,
                maximum_tasks: 1,
                exact_audits_enabled: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn assignment_is_post_commit_and_budget_bounded() {
        let claim = claim();
        let policy = AuditorPolicy {
            coverage_bps: 150,
            repetitions: 2,
            maximum_witness_bytes: 2_000,
            maximum_tasks: 1,
            exact_audits_enabled: true,
        };
        assert_eq!(
            assign_after_commit(&claim, h(7), h(8), h(9), 10, 1_000, policy),
            Err(AuditError::ChallengeBeforeCommit)
        );
        assert_eq!(
            assign_after_commit(&claim, h(7), h(8), h(9), 11, 2_001, policy),
            Err(AuditError::WitnessBudgetExceeded)
        );
    }

    #[test]
    fn every_exact_fault_class_escalates_and_only_dispute_moves_stake() {
        let claim = claim();
        let assignment = assignment(&claim);
        for fault in [
            ExactFaultClass::AccumulatorLie,
            ExactFaultClass::C8Flip,
            ExactFaultClass::SaturationLie,
            ExactFaultClass::TransplantedReceipt,
        ] {
            let mut ladder = AuditEscalation::new(&claim);
            ladder.observe_toploc(false).unwrap();
            assert!(!ladder.stake_moved);
            ladder
                .submit_exact_audit(&assignment, false, Some(fault))
                .unwrap();
            assert_eq!(ladder.state, EscalationState::FullDisputeRequired);
            assert!(!ladder.stake_moved);
            ladder.resolve_full_dispute(true).unwrap();
            assert_eq!(ladder.state, EscalationState::ExecutorFault);
            assert!(ladder.stake_moved);
        }
    }

    #[test]
    fn phone_auditor_protocol_shape_is_exact_but_not_silicon_evidence() {
        let plan = PhoneShardPlan::seventy_billion_reference(80).unwrap();
        assert_eq!(plan.phones_required, 40);
        assert_eq!(plan.layers_per_phone, 2);
        assert_eq!(plan.bytes_per_phone, 1_710_000_000);
    }

    #[test]
    fn deterrence_inequality_is_strict() {
        assert_eq!(minimum_deterrence_bond(100, 500).unwrap(), 2_001);
    }
}
