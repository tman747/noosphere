//! Immutable evaluation evidence and fail-closed model activation control.
//!
//! Evaluation reports are insert-once, including unfavorable reports. Canary
//! routing is deterministic and bounded by traffic ceilings. The production
//! alias mutation path remains unavailable until the external activation claim
//! gate changes the compile-time control in a separately reviewed release.

use crate::Hash32;
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub const DIMENSION_COUNT: usize = 6;
pub const CANARY_CEILINGS_PERCENT: [u8; 5] = [1, 5, 25, 50, 100];
pub const MIN_INDEPENDENT_EVALUATORS: usize = 2;
pub const MAX_EVALUATORS: usize = 64;
pub const MAX_ACTIVATORS: usize = 32;
pub const MAX_EMERGENCY_DURATION_BLOCKS: u64 = 7_200;
pub const WWM_MODEL_ACTIVATION_ENABLED: bool = false;
pub const WWM_AUTOMATIC_PRODUCTION_ACTIVATION_ENABLED: bool = false;
pub const WWM_ACTIVATION_CONSENSUS_WEIGHT: u64 = 0;
pub const WWM_ACTIVATION_FINALITY_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    InvalidEvaluator,
    InvalidSignature,
    InvalidReport,
    DuplicateObject,
    UnknownEvaluator,
    UnknownReport,
    MissingReport,
    FailingReport,
    InvalidRoleSeparation,
    InvalidProposal,
    InsufficientAuthority,
    TimeLockOpen,
    InvalidCanary,
    WrongCanaryStage,
    AlreadyTerminal,
    InvalidEmergencyRestriction,
    UnavailableRevision,
    ProductionActivationDisabled,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorProfile {
    pub evaluator_key: Hash32,
    pub control_cluster: Hash32,
    pub competence_root: Hash32,
    pub conflict_policy_root: Hash32,
    pub implementation_root: Hash32,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub profile_id: Hash32,
    pub signature: [u8; 64],
}

impl EvaluatorProfile {
    pub fn issue(
        control_cluster: Hash32,
        competence_root: Hash32,
        conflict_policy_root: Hash32,
        implementation_root: Hash32,
        valid_from_height: u64,
        expires_at_height: u64,
        evaluator: &Keypair,
    ) -> Result<Self, ActivationError> {
        let mut value = Self {
            evaluator_key: evaluator.public_key().into_bytes(),
            control_cluster,
            competence_root,
            conflict_policy_root,
            implementation_root,
            valid_from_height,
            expires_at_height,
            profile_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body();
        value.profile_id = digest(DomainId::WwmEvaluationReport, &[b"EVALUATOR", &body])?;
        value.signature = sign(
            evaluator,
            DomainId::WwmEvaluationReport,
            value.profile_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ActivationError> {
        self.validate_shape()?;
        let body = self.body();
        if digest(DomainId::WwmEvaluationReport, &[b"EVALUATOR", &body])? != self.profile_id {
            return Err(ActivationError::InvalidEvaluator);
        }
        verify(
            self.evaluator_key,
            DomainId::WwmEvaluationReport,
            self.profile_id,
            &body,
            self.signature,
        )
    }

    #[must_use]
    pub fn active_at(&self, height: u64) -> bool {
        self.valid_from_height <= height && height < self.expires_at_height
    }

    fn validate_shape(&self) -> Result<(), ActivationError> {
        if [
            self.evaluator_key,
            self.control_cluster,
            self.competence_root,
            self.conflict_policy_root,
            self.implementation_root,
        ]
        .contains(&[0; 32])
            || self.valid_from_height >= self.expires_at_height
        {
            return Err(ActivationError::InvalidEvaluator);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.evaluator_key);
        out.extend(self.control_cluster);
        out.extend(self.competence_root);
        out.extend(self.conflict_policy_root);
        out.extend(self.implementation_root);
        out.extend(self.valid_from_height.to_le_bytes());
        out.extend(self.expires_at_height.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EvaluationDimension {
    Capability = 0,
    Safety = 1,
    Privacy = 2,
    Rights = 3,
    Conformance = 4,
    Performance = 5,
}

impl EvaluationDimension {
    pub const ALL: [Self; DIMENSION_COUNT] = [
        Self::Capability,
        Self::Safety,
        Self::Privacy,
        Self::Rights,
        Self::Conformance,
        Self::Performance,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DimensionResult {
    pub dimension: EvaluationDimension,
    pub metric_root: Hash32,
    pub score_q20: i64,
    pub critical_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationReport {
    pub candidate_revision_id: Hash32,
    pub parent_revision_id: Hash32,
    pub evaluator_profile_id: Hash32,
    pub evaluator_key: Hash32,
    pub evaluator_control_cluster: Hash32,
    pub public_suite_root: Hash32,
    pub hidden_suite_commitment: Hash32,
    pub hidden_suite_reveal_root: Hash32,
    pub results: [DimensionResult; DIMENSION_COUNT],
    pub critical_failure_bitset: u64,
    pub conflict_disclosure_root: Hash32,
    pub hardware_root: Hash32,
    pub runtime_root: Hash32,
    pub artifact_root: Hash32,
    pub candidate_committed_height: u64,
    pub completed_height: u64,
    pub report_id: Hash32,
    pub signature: [u8; 64],
}

impl EvaluationReport {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        profile: &EvaluatorProfile,
        candidate_revision_id: Hash32,
        parent_revision_id: Hash32,
        public_suite_root: Hash32,
        hidden_suite_commitment: Hash32,
        hidden_suite_reveal_root: Hash32,
        results: [DimensionResult; DIMENSION_COUNT],
        conflict_disclosure_root: Hash32,
        hardware_root: Hash32,
        runtime_root: Hash32,
        artifact_root: Hash32,
        candidate_committed_height: u64,
        completed_height: u64,
        evaluator: &Keypair,
    ) -> Result<Self, ActivationError> {
        if evaluator.public_key().into_bytes() != profile.evaluator_key {
            return Err(ActivationError::InvalidEvaluator);
        }
        let critical_failure_bitset = critical_failure_bitset(&results)?;
        let mut value = Self {
            candidate_revision_id,
            parent_revision_id,
            evaluator_profile_id: profile.profile_id,
            evaluator_key: profile.evaluator_key,
            evaluator_control_cluster: profile.control_cluster,
            public_suite_root,
            hidden_suite_commitment,
            hidden_suite_reveal_root,
            results,
            critical_failure_bitset,
            conflict_disclosure_root,
            hardware_root,
            runtime_root,
            artifact_root,
            candidate_committed_height,
            completed_height,
            report_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape(profile)?;
        let body = value.body();
        value.report_id = digest(DomainId::WwmEvaluationReport, &[&body])?;
        value.signature = sign(
            evaluator,
            DomainId::WwmEvaluationReport,
            value.report_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self, profile: &EvaluatorProfile) -> Result<(), ActivationError> {
        self.validate_shape(profile)?;
        let body = self.body();
        if digest(DomainId::WwmEvaluationReport, &[&body])? != self.report_id {
            return Err(ActivationError::InvalidReport);
        }
        verify(
            self.evaluator_key,
            DomainId::WwmEvaluationReport,
            self.report_id,
            &body,
            self.signature,
        )
    }

    #[must_use]
    pub fn has_critical_failure(&self) -> bool {
        self.critical_failure_bitset != 0
    }

    fn validate_shape(&self, profile: &EvaluatorProfile) -> Result<(), ActivationError> {
        if self.evaluator_profile_id != profile.profile_id
            || self.evaluator_key != profile.evaluator_key
            || self.evaluator_control_cluster != profile.control_cluster
            || !profile.active_at(self.completed_height)
            || [
                self.candidate_revision_id,
                self.parent_revision_id,
                self.public_suite_root,
                self.hidden_suite_commitment,
                self.hidden_suite_reveal_root,
                self.conflict_disclosure_root,
                self.hardware_root,
                self.runtime_root,
                self.artifact_root,
            ]
            .contains(&[0; 32])
            || self.candidate_revision_id == self.parent_revision_id
            || self.candidate_committed_height >= self.completed_height
            || critical_failure_bitset(&self.results)? != self.critical_failure_bitset
        {
            return Err(ActivationError::InvalidReport);
        }
        for (expected, actual) in EvaluationDimension::ALL.into_iter().zip(self.results) {
            if actual.dimension != expected || actual.metric_root == [0; 32] {
                return Err(ActivationError::InvalidReport);
            }
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.candidate_revision_id);
        out.extend(self.parent_revision_id);
        out.extend(self.evaluator_profile_id);
        out.extend(self.evaluator_key);
        out.extend(self.evaluator_control_cluster);
        out.extend(self.public_suite_root);
        out.extend(self.hidden_suite_commitment);
        out.extend(self.hidden_suite_reveal_root);
        for result in self.results {
            out.push(result.dimension as u8);
            out.extend(result.metric_root);
            out.extend(result.score_q20.to_le_bytes());
            out.push(u8::from(result.critical_failure));
        }
        out.extend(self.critical_failure_bitset.to_le_bytes());
        out.extend(self.conflict_disclosure_root);
        out.extend(self.hardware_root);
        out.extend(self.runtime_root);
        out.extend(self.artifact_root);
        out.extend(self.candidate_committed_height.to_le_bytes());
        out.extend(self.completed_height.to_le_bytes());
        out
    }
}

#[derive(Debug, Default)]
pub struct EvaluationRegistry {
    evaluators: BTreeMap<Hash32, EvaluatorProfile>,
    reports: BTreeMap<Hash32, EvaluationReport>,
    reports_by_candidate: BTreeMap<Hash32, BTreeSet<Hash32>>,
}

impl EvaluationRegistry {
    pub fn register_evaluator(&mut self, profile: EvaluatorProfile) -> Result<(), ActivationError> {
        profile.validate()?;
        if self.evaluators.contains_key(&profile.profile_id) {
            return Err(ActivationError::DuplicateObject);
        }
        self.evaluators.insert(profile.profile_id, profile);
        Ok(())
    }

    pub fn register_report(&mut self, report: EvaluationReport) -> Result<(), ActivationError> {
        let profile = self
            .evaluators
            .get(&report.evaluator_profile_id)
            .ok_or(ActivationError::UnknownEvaluator)?;
        report.validate(profile)?;
        if self.reports.contains_key(&report.report_id) {
            return Err(ActivationError::DuplicateObject);
        }
        self.reports_by_candidate
            .entry(report.candidate_revision_id)
            .or_default()
            .insert(report.report_id);
        self.reports.insert(report.report_id, report);
        Ok(())
    }

    #[must_use]
    pub fn evaluator(&self, profile_id: &Hash32) -> Option<&EvaluatorProfile> {
        self.evaluators.get(profile_id)
    }

    #[must_use]
    pub fn report(&self, report_id: &Hash32) -> Option<&EvaluationReport> {
        self.reports.get(report_id)
    }

    #[must_use]
    pub fn report_ids_for(&self, candidate_revision_id: &Hash32) -> Vec<Hash32> {
        self.reports_by_candidate
            .get(candidate_revision_id)
            .map_or_else(Vec::new, |ids| ids.iter().copied().collect())
    }

    #[must_use]
    pub fn report_count(&self) -> usize {
        self.reports.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardFloorPolicy {
    pub minimum_scores_q20: [i64; DIMENSION_COUNT],
    pub policy_root: Hash32,
}

impl HardFloorPolicy {
    pub fn new(minimum_scores_q20: [i64; DIMENSION_COUNT]) -> Result<Self, ActivationError> {
        let mut encoded = Vec::new();
        for score in minimum_scores_q20 {
            encoded.extend(score.to_le_bytes());
        }
        Ok(Self {
            minimum_scores_q20,
            policy_root: digest(DomainId::WwmActivationProposal, &[b"HARD-FLOORS", &encoded])?,
        })
    }

    #[must_use]
    pub fn passes(&self, report: &EvaluationReport) -> bool {
        !report.has_critical_failure()
            && report
                .results
                .iter()
                .zip(self.minimum_scores_q20)
                .all(|(result, floor)| result.score_q20 >= floor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActivationAuthority {
    pub public_key: Hash32,
    pub control_cluster: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritySignature {
    pub authority_index: u8,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationProposal {
    pub candidate_revision_id: Hash32,
    pub parent_revision_id: Hash32,
    pub required_report_ids: Vec<Hash32>,
    pub hard_floor_policy: HardFloorPolicy,
    pub proposal_height: u64,
    pub challenge_end_height: u64,
    pub canary_ceilings_percent: [u8; 5],
    pub rollback_triggers_root: Hash32,
    pub rollback_parent_id: Hash32,
    pub trainer_control_cluster: Hash32,
    pub proposer_key: Hash32,
    pub proposer_control_cluster: Hash32,
    pub evaluator_set_root: Hash32,
    pub activator_set_root: Hash32,
    pub activators: Vec<ActivationAuthority>,
    pub activation_threshold: u8,
    pub proposal_id: Hash32,
    pub proposer_signature: [u8; 64],
    pub activator_signatures: Vec<AuthoritySignature>,
}

impl ActivationProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: &EvaluationRegistry,
        candidate_revision_id: Hash32,
        parent_revision_id: Hash32,
        required_report_ids: Vec<Hash32>,
        hard_floor_policy: HardFloorPolicy,
        proposal_height: u64,
        challenge_end_height: u64,
        rollback_triggers_root: Hash32,
        rollback_parent_id: Hash32,
        trainer_control_cluster: Hash32,
        proposer_control_cluster: Hash32,
        activators: Vec<ActivationAuthority>,
        activation_threshold: u8,
        proposer: &Keypair,
    ) -> Result<Self, ActivationError> {
        let evaluator_set_root = evaluator_set_root(registry, &required_report_ids)?;
        let activator_set_root = activation_authority_root(&activators)?;
        let mut value = Self {
            candidate_revision_id,
            parent_revision_id,
            required_report_ids,
            hard_floor_policy,
            proposal_height,
            challenge_end_height,
            canary_ceilings_percent: CANARY_CEILINGS_PERCENT,
            rollback_triggers_root,
            rollback_parent_id,
            trainer_control_cluster,
            proposer_key: proposer.public_key().into_bytes(),
            proposer_control_cluster,
            evaluator_set_root,
            activator_set_root,
            activators,
            activation_threshold,
            proposal_id: [0; 32],
            proposer_signature: [0; 64],
            activator_signatures: Vec::new(),
        };
        value.validate_shape(registry)?;
        let body = value.body()?;
        value.proposal_id = digest(DomainId::WwmActivationProposal, &[&body])?;
        value.proposer_signature = sign(
            proposer,
            DomainId::WwmActivationProposal,
            value.proposal_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn add_activator_signature(&mut self, activator: &Keypair) -> Result<(), ActivationError> {
        let key = activator.public_key().into_bytes();
        let index = self
            .activators
            .binary_search_by_key(&key, |authority| authority.public_key)
            .map_err(|_| ActivationError::InsufficientAuthority)?;
        let index = u8::try_from(index).map_err(|_| ActivationError::ArithmeticOverflow)?;
        if self
            .activator_signatures
            .iter()
            .any(|signature| signature.authority_index == index)
        {
            return Err(ActivationError::DuplicateObject);
        }
        let body = self.body()?;
        self.activator_signatures.push(AuthoritySignature {
            authority_index: index,
            signature: sign(
                activator,
                DomainId::WwmActivationProposal,
                self.proposal_id,
                &body,
            )?,
        });
        self.activator_signatures
            .sort_by_key(|signature| signature.authority_index);
        Ok(())
    }

    pub fn validate(&self, registry: &EvaluationRegistry) -> Result<(), ActivationError> {
        self.validate_shape(registry)?;
        let body = self.body()?;
        if digest(DomainId::WwmActivationProposal, &[&body])? != self.proposal_id {
            return Err(ActivationError::InvalidProposal);
        }
        verify(
            self.proposer_key,
            DomainId::WwmActivationProposal,
            self.proposal_id,
            &body,
            self.proposer_signature,
        )?;
        let mut seen = BTreeSet::new();
        for signature in &self.activator_signatures {
            let authority = self
                .activators
                .get(usize::from(signature.authority_index))
                .ok_or(ActivationError::InvalidSignature)?;
            if !seen.insert(signature.authority_index) {
                return Err(ActivationError::InvalidSignature);
            }
            verify(
                authority.public_key,
                DomainId::WwmActivationProposal,
                self.proposal_id,
                &body,
                signature.signature,
            )?;
        }
        Ok(())
    }

    pub fn validate_for_canary(
        &self,
        registry: &EvaluationRegistry,
    ) -> Result<(), ActivationError> {
        self.validate(registry)?;
        if self.activator_signatures.len() < usize::from(self.activation_threshold) {
            return Err(ActivationError::InsufficientAuthority);
        }
        Ok(())
    }

    fn validate_shape(&self, registry: &EvaluationRegistry) -> Result<(), ActivationError> {
        if [
            self.candidate_revision_id,
            self.parent_revision_id,
            self.rollback_triggers_root,
            self.rollback_parent_id,
            self.trainer_control_cluster,
            self.proposer_key,
            self.proposer_control_cluster,
            self.evaluator_set_root,
            self.activator_set_root,
            self.hard_floor_policy.policy_root,
        ]
        .contains(&[0; 32])
            || self.candidate_revision_id == self.parent_revision_id
            || self.rollback_parent_id != self.parent_revision_id
            || self.required_report_ids.len() < MIN_INDEPENDENT_EVALUATORS
            || self.required_report_ids.len() > MAX_EVALUATORS
            || !strictly_sorted(&self.required_report_ids)
            || self.proposal_height >= self.challenge_end_height
            || self.canary_ceilings_percent != CANARY_CEILINGS_PERCENT
            || self.activators.len() < 2
            || self.activators.len() > MAX_ACTIVATORS
            || !strictly_sorted_by(&self.activators, |authority| authority.public_key)
            || self.activation_threshold < 2
            || usize::from(self.activation_threshold) > self.activators.len()
        {
            return Err(ActivationError::InvalidProposal);
        }
        let all_report_ids = registry.report_ids_for(&self.candidate_revision_id);
        if all_report_ids != self.required_report_ids {
            return Err(ActivationError::MissingReport);
        }
        let mut evaluator_clusters = BTreeSet::new();
        for report_id in &self.required_report_ids {
            let report = registry
                .report(report_id)
                .ok_or(ActivationError::UnknownReport)?;
            if report.candidate_revision_id != self.candidate_revision_id
                || report.parent_revision_id != self.parent_revision_id
            {
                return Err(ActivationError::InvalidProposal);
            }
            if !self.hard_floor_policy.passes(report) {
                return Err(ActivationError::FailingReport);
            }
            evaluator_clusters.insert(report.evaluator_control_cluster);
        }
        if evaluator_clusters.len() < MIN_INDEPENDENT_EVALUATORS
            || evaluator_set_root(registry, &self.required_report_ids)? != self.evaluator_set_root
            || activation_authority_root(&self.activators)? != self.activator_set_root
        {
            return Err(ActivationError::InvalidProposal);
        }
        let activator_clusters = self
            .activators
            .iter()
            .map(|authority| authority.control_cluster)
            .collect::<BTreeSet<_>>();
        if activator_clusters.len() != self.activators.len()
            || self.trainer_control_cluster == self.proposer_control_cluster
            || evaluator_clusters.contains(&self.trainer_control_cluster)
            || evaluator_clusters.contains(&self.proposer_control_cluster)
            || activator_clusters.contains(&self.trainer_control_cluster)
            || activator_clusters.contains(&self.proposer_control_cluster)
            || !evaluator_clusters.is_disjoint(&activator_clusters)
        {
            return Err(ActivationError::InvalidRoleSeparation);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, ActivationError> {
        let mut out = Vec::new();
        out.extend(self.candidate_revision_id);
        out.extend(self.parent_revision_id);
        push_hashes(&mut out, &self.required_report_ids)?;
        out.extend(self.hard_floor_policy.policy_root);
        for score in self.hard_floor_policy.minimum_scores_q20 {
            out.extend(score.to_le_bytes());
        }
        out.extend(self.proposal_height.to_le_bytes());
        out.extend(self.challenge_end_height.to_le_bytes());
        out.extend(self.canary_ceilings_percent);
        out.extend(self.rollback_triggers_root);
        out.extend(self.rollback_parent_id);
        out.extend(self.trainer_control_cluster);
        out.extend(self.proposer_key);
        out.extend(self.proposer_control_cluster);
        out.extend(self.evaluator_set_root);
        out.extend(self.activator_set_root);
        out.extend(
            u16::try_from(self.activators.len())
                .map_err(|_| ActivationError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for authority in &self.activators {
            out.extend(authority.public_key);
            out.extend(authority.control_cluster);
        }
        out.push(self.activation_threshold);
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryState {
    AwaitingTimeLock,
    Running { stage_index: u8 },
    CanaryComplete,
    RolledBack,
    EmergencyRestricted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryObservation {
    pub proposal_id: Hash32,
    pub stage_index: u8,
    pub traffic_ceiling_percent: u8,
    pub total_requests: u64,
    pub candidate_requests: u64,
    pub results: [DimensionResult; DIMENSION_COUNT],
    pub rollback_trigger_bitset: u64,
    pub artifact_root: Hash32,
    pub monitor_profile_id: Hash32,
    pub monitor_key: Hash32,
    pub monitor_control_cluster: Hash32,
    pub observed_height: u64,
    pub passed: bool,
    pub observation_id: Hash32,
    pub signature: [u8; 64],
}

impl CanaryObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        proposal: &ActivationProposal,
        monitor_profile: &EvaluatorProfile,
        stage_index: u8,
        total_requests: u64,
        candidate_requests: u64,
        results: [DimensionResult; DIMENSION_COUNT],
        rollback_trigger_bitset: u64,
        artifact_root: Hash32,
        observed_height: u64,
        monitor: &Keypair,
    ) -> Result<Self, ActivationError> {
        if monitor.public_key().into_bytes() != monitor_profile.evaluator_key {
            return Err(ActivationError::InvalidEvaluator);
        }
        let ceiling = *CANARY_CEILINGS_PERCENT
            .get(usize::from(stage_index))
            .ok_or(ActivationError::WrongCanaryStage)?;
        let passed = rollback_trigger_bitset == 0
            && results
                .iter()
                .zip(proposal.hard_floor_policy.minimum_scores_q20)
                .all(|(result, floor)| !result.critical_failure && result.score_q20 >= floor);
        let mut value = Self {
            proposal_id: proposal.proposal_id,
            stage_index,
            traffic_ceiling_percent: ceiling,
            total_requests,
            candidate_requests,
            results,
            rollback_trigger_bitset,
            artifact_root,
            monitor_profile_id: monitor_profile.profile_id,
            monitor_key: monitor_profile.evaluator_key,
            monitor_control_cluster: monitor_profile.control_cluster,
            observed_height,
            passed,
            observation_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape(proposal, monitor_profile)?;
        let body = value.body();
        value.observation_id = digest(DomainId::WwmEvaluationReport, &[b"CANARY", &body])?;
        value.signature = sign(
            monitor,
            DomainId::WwmEvaluationReport,
            value.observation_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(
        &self,
        proposal: &ActivationProposal,
        monitor_profile: &EvaluatorProfile,
    ) -> Result<(), ActivationError> {
        self.validate_shape(proposal, monitor_profile)?;
        let body = self.body();
        if digest(DomainId::WwmEvaluationReport, &[b"CANARY", &body])? != self.observation_id {
            return Err(ActivationError::InvalidCanary);
        }
        verify(
            self.monitor_key,
            DomainId::WwmEvaluationReport,
            self.observation_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(
        &self,
        proposal: &ActivationProposal,
        monitor_profile: &EvaluatorProfile,
    ) -> Result<(), ActivationError> {
        let expected_ceiling = *CANARY_CEILINGS_PERCENT
            .get(usize::from(self.stage_index))
            .ok_or(ActivationError::WrongCanaryStage)?;
        let candidate_percent_numerator = u128::from(self.candidate_requests)
            .checked_mul(100)
            .ok_or(ActivationError::ArithmeticOverflow)?;
        let candidate_ceiling = u128::from(self.total_requests)
            .checked_mul(u128::from(self.traffic_ceiling_percent))
            .ok_or(ActivationError::ArithmeticOverflow)?;
        let expected_passed = self.rollback_trigger_bitset == 0
            && self
                .results
                .iter()
                .zip(proposal.hard_floor_policy.minimum_scores_q20)
                .all(|(result, floor)| !result.critical_failure && result.score_q20 >= floor);
        if self.proposal_id != proposal.proposal_id
            || self.traffic_ceiling_percent != expected_ceiling
            || self.total_requests == 0
            || candidate_percent_numerator > candidate_ceiling
            || self.artifact_root == [0; 32]
            || self.monitor_profile_id != monitor_profile.profile_id
            || self.monitor_key != monitor_profile.evaluator_key
            || self.monitor_control_cluster != monitor_profile.control_cluster
            || self.monitor_control_cluster == proposal.trainer_control_cluster
            || self.monitor_control_cluster == proposal.proposer_control_cluster
            || !monitor_profile.active_at(self.observed_height)
            || self.observed_height < proposal.challenge_end_height
            || self.passed != expected_passed
        {
            return Err(ActivationError::InvalidCanary);
        }
        for (expected, actual) in EvaluationDimension::ALL.into_iter().zip(self.results) {
            if actual.dimension != expected || actual.metric_root == [0; 32] {
                return Err(ActivationError::InvalidCanary);
            }
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.proposal_id);
        out.push(self.stage_index);
        out.push(self.traffic_ceiling_percent);
        out.extend(self.total_requests.to_le_bytes());
        out.extend(self.candidate_requests.to_le_bytes());
        for result in self.results {
            out.push(result.dimension as u8);
            out.extend(result.metric_root);
            out.extend(result.score_q20.to_le_bytes());
            out.push(u8::from(result.critical_failure));
        }
        out.extend(self.rollback_trigger_bitset.to_le_bytes());
        out.extend(self.artifact_root);
        out.extend(self.monitor_profile_id);
        out.extend(self.monitor_key);
        out.extend(self.monitor_control_cluster);
        out.extend(self.observed_height.to_le_bytes());
        out.push(u8::from(self.passed));
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasTransitionKind {
    ShadowCanaryStart,
    ShadowCanaryAdvance,
    AutomaticRollback,
    EmergencyRollback,
    CanaryComplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasTransitionRecord {
    pub proposal_id: Hash32,
    pub prior_revision_id: Hash32,
    pub next_revision_id: Hash32,
    pub kind: AliasTransitionKind,
    pub stage_index: Option<u8>,
    pub authorizing_evidence_id: Hash32,
    pub height: u64,
    pub transition_id: Hash32,
}

impl AliasTransitionRecord {
    fn new(
        proposal_id: Hash32,
        prior_revision_id: Hash32,
        next_revision_id: Hash32,
        kind: AliasTransitionKind,
        stage_index: Option<u8>,
        authorizing_evidence_id: Hash32,
        height: u64,
    ) -> Result<Self, ActivationError> {
        if [
            proposal_id,
            prior_revision_id,
            next_revision_id,
            authorizing_evidence_id,
        ]
        .contains(&[0; 32])
        {
            return Err(ActivationError::InvalidCanary);
        }
        let mut value = Self {
            proposal_id,
            prior_revision_id,
            next_revision_id,
            kind,
            stage_index,
            authorizing_evidence_id,
            height,
            transition_id: [0; 32],
        };
        value.transition_id = digest(DomainId::WwmServingAlias, &[&value.body()])?;
        Ok(value)
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.proposal_id);
        out.extend(self.prior_revision_id);
        out.extend(self.next_revision_id);
        out.push(match self.kind {
            AliasTransitionKind::ShadowCanaryStart => 0,
            AliasTransitionKind::ShadowCanaryAdvance => 1,
            AliasTransitionKind::AutomaticRollback => 2,
            AliasTransitionKind::EmergencyRollback => 3,
            AliasTransitionKind::CanaryComplete => 4,
        });
        match self.stage_index {
            Some(stage) => {
                out.push(1);
                out.push(stage);
            }
            None => out.push(0),
        }
        out.extend(self.authorizing_evidence_id);
        out.extend(self.height.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionSelection {
    DefaultAlias,
    Pinned(Hash32),
    ForkBase(Hash32),
}

#[derive(Debug)]
pub struct ActivationController {
    proposal: ActivationProposal,
    state: CanaryState,
    production_alias_revision_id: Hash32,
    shadow_alias_revision_id: Hash32,
    observations: BTreeMap<u8, CanaryObservation>,
    alias_transitions: Vec<AliasTransitionRecord>,
    available_revisions: BTreeSet<Hash32>,
}

impl ActivationController {
    pub fn new(proposal: ActivationProposal) -> Self {
        let parent = proposal.parent_revision_id;
        let available_revisions = BTreeSet::from([parent, proposal.candidate_revision_id]);
        Self {
            proposal,
            state: CanaryState::AwaitingTimeLock,
            production_alias_revision_id: parent,
            shadow_alias_revision_id: parent,
            observations: BTreeMap::new(),
            alias_transitions: Vec::new(),
            available_revisions,
        }
    }

    pub fn begin_canary(
        &mut self,
        registry: &EvaluationRegistry,
        height: u64,
    ) -> Result<(), ActivationError> {
        if self.state != CanaryState::AwaitingTimeLock {
            return Err(ActivationError::AlreadyTerminal);
        }
        self.proposal.validate_for_canary(registry)?;
        if height < self.proposal.challenge_end_height {
            return Err(ActivationError::TimeLockOpen);
        }
        self.state = CanaryState::Running { stage_index: 0 };
        self.shadow_alias_revision_id = self.proposal.candidate_revision_id;
        self.alias_transitions.push(AliasTransitionRecord::new(
            self.proposal.proposal_id,
            self.proposal.parent_revision_id,
            self.proposal.candidate_revision_id,
            AliasTransitionKind::ShadowCanaryStart,
            Some(0),
            self.proposal.proposal_id,
            height,
        )?);
        Ok(())
    }

    pub fn record_canary(
        &mut self,
        observation: CanaryObservation,
        monitor_profile: &EvaluatorProfile,
    ) -> Result<CanaryState, ActivationError> {
        let expected_stage = match self.state {
            CanaryState::Running { stage_index } => stage_index,
            CanaryState::AwaitingTimeLock => return Err(ActivationError::TimeLockOpen),
            CanaryState::CanaryComplete
            | CanaryState::RolledBack
            | CanaryState::EmergencyRestricted => return Err(ActivationError::AlreadyTerminal),
        };
        if observation.stage_index != expected_stage {
            return Err(ActivationError::WrongCanaryStage);
        }
        observation.validate(&self.proposal, monitor_profile)?;
        if self.observations.contains_key(&observation.stage_index) {
            return Err(ActivationError::DuplicateObject);
        }
        let observation_id = observation.observation_id;
        let observed_height = observation.observed_height;
        let passed = observation.passed;
        self.observations
            .insert(observation.stage_index, observation);
        if !passed {
            let prior = self.shadow_alias_revision_id;
            self.shadow_alias_revision_id = self.proposal.rollback_parent_id;
            self.state = CanaryState::RolledBack;
            self.alias_transitions.push(AliasTransitionRecord::new(
                self.proposal.proposal_id,
                prior,
                self.proposal.rollback_parent_id,
                AliasTransitionKind::AutomaticRollback,
                Some(expected_stage),
                observation_id,
                observed_height,
            )?);
            return Ok(self.state);
        }
        let next_stage = expected_stage
            .checked_add(1)
            .ok_or(ActivationError::ArithmeticOverflow)?;
        if usize::from(next_stage) == CANARY_CEILINGS_PERCENT.len() {
            self.state = CanaryState::CanaryComplete;
            self.alias_transitions.push(AliasTransitionRecord::new(
                self.proposal.proposal_id,
                self.shadow_alias_revision_id,
                self.proposal.candidate_revision_id,
                AliasTransitionKind::CanaryComplete,
                Some(expected_stage),
                observation_id,
                observed_height,
            )?);
        } else {
            self.state = CanaryState::Running {
                stage_index: next_stage,
            };
            self.alias_transitions.push(AliasTransitionRecord::new(
                self.proposal.proposal_id,
                self.shadow_alias_revision_id,
                self.proposal.candidate_revision_id,
                AliasTransitionKind::ShadowCanaryAdvance,
                Some(next_stage),
                observation_id,
                observed_height,
            )?);
        }
        Ok(self.state)
    }

    pub fn route_shadow_request(&self, request_id: Hash32) -> Result<Hash32, ActivationError> {
        let stage_index = match self.state {
            CanaryState::Running { stage_index } => stage_index,
            CanaryState::CanaryComplete => return Ok(self.proposal.candidate_revision_id),
            CanaryState::AwaitingTimeLock
            | CanaryState::RolledBack
            | CanaryState::EmergencyRestricted => return Ok(self.proposal.parent_revision_id),
        };
        let ceiling = CANARY_CEILINGS_PERCENT
            .get(usize::from(stage_index))
            .copied()
            .ok_or(ActivationError::WrongCanaryStage)?;
        let selection = digest(
            DomainId::WwmServingAlias,
            &[b"CANARY-ROUTE", &self.proposal.proposal_id, &request_id],
        )?;
        let bucket = u64::from_le_bytes(
            selection[..8]
                .try_into()
                .map_err(|_| ActivationError::InvalidCanary)?,
        ) % 100;
        if bucket < u64::from(ceiling) {
            Ok(self.proposal.candidate_revision_id)
        } else {
            Ok(self.proposal.parent_revision_id)
        }
    }

    pub fn activate_production_alias(&mut self) -> Result<(), ActivationError> {
        Err(ActivationError::ProductionActivationDisabled)
    }

    pub fn apply_emergency_restriction(
        &mut self,
        restriction: &EmergencyRestriction,
        height: u64,
    ) -> Result<(), ActivationError> {
        restriction.validate(&self.proposal, height)?;
        let prior = self.shadow_alias_revision_id;
        self.shadow_alias_revision_id = self.proposal.parent_revision_id;
        self.state = CanaryState::EmergencyRestricted;
        self.alias_transitions.push(AliasTransitionRecord::new(
            self.proposal.proposal_id,
            prior,
            self.proposal.parent_revision_id,
            AliasTransitionKind::EmergencyRollback,
            None,
            restriction.restriction_id,
            height,
        )?);
        Ok(())
    }

    pub fn resolve_selection(
        &self,
        selection: RevisionSelection,
    ) -> Result<Hash32, ActivationError> {
        let revision = match selection {
            RevisionSelection::DefaultAlias => self.production_alias_revision_id,
            RevisionSelection::Pinned(revision) | RevisionSelection::ForkBase(revision) => revision,
        };
        self.available_revisions
            .contains(&revision)
            .then_some(revision)
            .ok_or(ActivationError::UnavailableRevision)
    }

    #[must_use]
    pub const fn state(&self) -> CanaryState {
        self.state
    }

    #[must_use]
    pub const fn production_alias_revision_id(&self) -> Hash32 {
        self.production_alias_revision_id
    }

    #[must_use]
    pub const fn shadow_alias_revision_id(&self) -> Hash32 {
        self.shadow_alias_revision_id
    }

    #[must_use]
    pub fn alias_transitions(&self) -> &[AliasTransitionRecord] {
        &self.alias_transitions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRestriction {
    pub proposal_id: Hash32,
    pub candidate_revision_id: Hash32,
    pub allowed_scope_root: Hash32,
    pub reason_root: Hash32,
    pub issued_height: u64,
    pub expires_at_height: u64,
    pub authority_key: Hash32,
    pub authority_control_cluster: Hash32,
    pub restriction_id: Hash32,
    pub signature: [u8; 64],
}

impl EmergencyRestriction {
    pub fn issue(
        proposal: &ActivationProposal,
        allowed_scope_root: Hash32,
        reason_root: Hash32,
        issued_height: u64,
        expires_at_height: u64,
        authority_control_cluster: Hash32,
        authority: &Keypair,
    ) -> Result<Self, ActivationError> {
        let key = authority.public_key().into_bytes();
        if !proposal.activators.iter().any(|candidate| {
            candidate.public_key == key && candidate.control_cluster == authority_control_cluster
        }) {
            return Err(ActivationError::InsufficientAuthority);
        }
        let mut value = Self {
            proposal_id: proposal.proposal_id,
            candidate_revision_id: proposal.candidate_revision_id,
            allowed_scope_root,
            reason_root,
            issued_height,
            expires_at_height,
            authority_key: key,
            authority_control_cluster,
            restriction_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body();
        value.restriction_id = digest(DomainId::WwmServingAlias, &[b"EMERGENCY", &body])?;
        value.signature = sign(
            authority,
            DomainId::WwmServingAlias,
            value.restriction_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(
        &self,
        proposal: &ActivationProposal,
        height: u64,
    ) -> Result<(), ActivationError> {
        self.validate_shape()?;
        if self.proposal_id != proposal.proposal_id
            || self.candidate_revision_id != proposal.candidate_revision_id
            || !proposal.activators.iter().any(|authority| {
                authority.public_key == self.authority_key
                    && authority.control_cluster == self.authority_control_cluster
            })
            || height < self.issued_height
            || height >= self.expires_at_height
        {
            return Err(ActivationError::InvalidEmergencyRestriction);
        }
        let body = self.body();
        if digest(DomainId::WwmServingAlias, &[b"EMERGENCY", &body])? != self.restriction_id {
            return Err(ActivationError::InvalidEmergencyRestriction);
        }
        verify(
            self.authority_key,
            DomainId::WwmServingAlias,
            self.restriction_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), ActivationError> {
        let duration = self
            .expires_at_height
            .checked_sub(self.issued_height)
            .ok_or(ActivationError::InvalidEmergencyRestriction)?;
        if [
            self.proposal_id,
            self.candidate_revision_id,
            self.allowed_scope_root,
            self.reason_root,
            self.authority_key,
            self.authority_control_cluster,
        ]
        .contains(&[0; 32])
            || duration == 0
            || duration > MAX_EMERGENCY_DURATION_BLOCKS
        {
            return Err(ActivationError::InvalidEmergencyRestriction);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.proposal_id);
        out.extend(self.candidate_revision_id);
        out.extend(self.allowed_scope_root);
        out.extend(self.reason_root);
        out.extend(self.issued_height.to_le_bytes());
        out.extend(self.expires_at_height.to_le_bytes());
        out.extend(self.authority_key);
        out.extend(self.authority_control_cluster);
        out
    }
}

fn critical_failure_bitset(
    results: &[DimensionResult; DIMENSION_COUNT],
) -> Result<u64, ActivationError> {
    let mut bitset = 0_u64;
    for (index, result) in results.iter().enumerate() {
        if result.critical_failure {
            let shift = u32::try_from(index).map_err(|_| ActivationError::ArithmeticOverflow)?;
            bitset |= 1_u64
                .checked_shl(shift)
                .ok_or(ActivationError::ArithmeticOverflow)?;
        }
    }
    Ok(bitset)
}

fn evaluator_set_root(
    registry: &EvaluationRegistry,
    report_ids: &[Hash32],
) -> Result<Hash32, ActivationError> {
    let mut entries = BTreeSet::new();
    for report_id in report_ids {
        let report = registry
            .report(report_id)
            .ok_or(ActivationError::UnknownReport)?;
        entries.insert((report.evaluator_key, report.evaluator_control_cluster));
    }
    let mut out = Vec::new();
    out.extend(
        u16::try_from(entries.len())
            .map_err(|_| ActivationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for (key, cluster) in entries {
        out.extend(key);
        out.extend(cluster);
    }
    digest(DomainId::WwmActivationProposal, &[b"EVALUATOR-SET", &out])
}

fn activation_authority_root(
    authorities: &[ActivationAuthority],
) -> Result<Hash32, ActivationError> {
    if authorities.is_empty()
        || !strictly_sorted_by(authorities, |authority| authority.public_key)
        || authorities.iter().any(|authority| {
            authority.public_key == [0; 32] || authority.control_cluster == [0; 32]
        })
    {
        return Err(ActivationError::InvalidProposal);
    }
    let mut out = Vec::new();
    out.extend(
        u16::try_from(authorities.len())
            .map_err(|_| ActivationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for authority in authorities {
        out.extend(authority.public_key);
        out.extend(authority.control_cluster);
    }
    digest(DomainId::WwmActivationProposal, &[b"ACTIVATOR-SET", &out])
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, K: Ord + Copy>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), ActivationError> {
    out.extend(
        u16::try_from(values.len())
            .map_err(|_| ActivationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for value in values {
        out.extend(value);
    }
    Ok(())
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, ActivationError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| ActivationError::InvalidSignature)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], ActivationError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| ActivationError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), ActivationError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ActivationError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]

    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn results(score: i64) -> [DimensionResult; DIMENSION_COUNT] {
        EvaluationDimension::ALL.map(|dimension| DimensionResult {
            dimension,
            metric_root: h(20_u8.saturating_add(dimension as u8)),
            score_q20: score,
            critical_failure: false,
        })
    }

    struct Fixture {
        registry: EvaluationRegistry,
        profiles: [EvaluatorProfile; 2],
        evaluator_keys: [Keypair; 2],
        activator_keys: [Keypair; 2],
        proposal: ActivationProposal,
    }

    fn fixture() -> Fixture {
        let evaluator_keys = [Keypair::from_seed([1; 32]), Keypair::from_seed([2; 32])];
        let profiles = [
            EvaluatorProfile::issue(h(31), h(32), h(33), h(34), 1, 1_000, &evaluator_keys[0])
                .unwrap(),
            EvaluatorProfile::issue(h(35), h(36), h(37), h(38), 1, 1_000, &evaluator_keys[1])
                .unwrap(),
        ];
        let mut registry = EvaluationRegistry::default();
        for profile in profiles.clone() {
            registry.register_evaluator(profile).unwrap();
        }
        for (profile, evaluator) in profiles.iter().zip(&evaluator_keys) {
            let report = EvaluationReport::issue(
                profile,
                h(40),
                h(41),
                h(42),
                h(43),
                h(44),
                results(100 << 20),
                h(45),
                h(46),
                h(47),
                h(48),
                10,
                100,
                evaluator,
            )
            .unwrap();
            registry.register_report(report).unwrap();
        }
        let activator_keys = [Keypair::from_seed([3; 32]), Keypair::from_seed([4; 32])];
        let mut activators = vec![
            ActivationAuthority {
                public_key: activator_keys[0].public_key().into_bytes(),
                control_cluster: h(51),
            },
            ActivationAuthority {
                public_key: activator_keys[1].public_key().into_bytes(),
                control_cluster: h(52),
            },
        ];
        activators.sort_unstable_by_key(|authority| authority.public_key);
        let proposer = Keypair::from_seed([5; 32]);
        let mut proposal = ActivationProposal::new(
            &registry,
            h(40),
            h(41),
            registry.report_ids_for(&h(40)),
            HardFloorPolicy::new([90 << 20; DIMENSION_COUNT]).unwrap(),
            101,
            200,
            h(53),
            h(41),
            h(54),
            h(55),
            activators,
            2,
            &proposer,
        )
        .unwrap();
        for activator in &activator_keys {
            proposal.add_activator_signature(activator).unwrap();
        }
        Fixture {
            registry,
            profiles,
            evaluator_keys,
            activator_keys,
            proposal,
        }
    }

    #[test]
    fn failing_reports_remain_inserted_and_cannot_be_omitted() {
        let mut fixture = fixture();
        let failing = EvaluationReport::issue(
            &fixture.profiles[0],
            h(40),
            h(41),
            h(60),
            h(61),
            h(62),
            results(1),
            h(63),
            h(64),
            h(65),
            h(66),
            110,
            120,
            &fixture.evaluator_keys[0],
        )
        .unwrap();
        fixture.registry.register_report(failing).unwrap();
        assert_eq!(fixture.registry.report_count(), 3);

        let proposer = Keypair::from_seed([5; 32]);
        assert_eq!(
            ActivationProposal::new(
                &fixture.registry,
                h(40),
                h(41),
                fixture.registry.report_ids_for(&h(40)),
                HardFloorPolicy::new([90 << 20; DIMENSION_COUNT]).unwrap(),
                121,
                220,
                h(67),
                h(41),
                h(54),
                h(55),
                fixture.proposal.activators.clone(),
                2,
                &proposer,
            ),
            Err(ActivationError::FailingReport)
        );
        let favorable_only = fixture.proposal.required_report_ids.clone();
        assert_eq!(
            ActivationProposal::new(
                &fixture.registry,
                h(40),
                h(41),
                favorable_only,
                HardFloorPolicy::new([90 << 20; DIMENSION_COUNT]).unwrap(),
                121,
                220,
                h(67),
                h(41),
                h(54),
                h(55),
                fixture.proposal.activators.clone(),
                2,
                &proposer,
            ),
            Err(ActivationError::MissingReport)
        );
    }

    #[test]
    fn trainer_evaluator_proposer_and_activator_clusters_cannot_overlap() {
        let fixture = fixture();
        let proposer = Keypair::from_seed([5; 32]);
        assert_eq!(
            ActivationProposal::new(
                &fixture.registry,
                h(40),
                h(41),
                fixture.registry.report_ids_for(&h(40)),
                HardFloorPolicy::new([90 << 20; DIMENSION_COUNT]).unwrap(),
                101,
                200,
                h(53),
                h(41),
                h(31),
                h(55),
                fixture.proposal.activators.clone(),
                2,
                &proposer,
            ),
            Err(ActivationError::InvalidRoleSeparation)
        );
    }

    #[test]
    fn time_lock_and_stage_order_fail_closed() {
        let fixture = fixture();
        let mut controller = ActivationController::new(fixture.proposal.clone());
        assert_eq!(
            controller.begin_canary(&fixture.registry, 199),
            Err(ActivationError::TimeLockOpen)
        );
        controller.begin_canary(&fixture.registry, 200).unwrap();
        assert_eq!(controller.state(), CanaryState::Running { stage_index: 0 });

        let request = h(70);
        let routed = controller.route_shadow_request(request).unwrap();
        assert!(routed == h(40) || routed == h(41));
        let wrong_stage = CanaryObservation::issue(
            &fixture.proposal,
            &fixture.profiles[0],
            1,
            100,
            5,
            results(100 << 20),
            0,
            h(71),
            201,
            &fixture.evaluator_keys[0],
        )
        .unwrap();
        assert_eq!(
            controller.record_canary(wrong_stage, &fixture.profiles[0]),
            Err(ActivationError::WrongCanaryStage)
        );
    }

    #[test]
    fn critical_canary_failure_automatically_rolls_shadow_alias_back() {
        let fixture = fixture();
        let mut controller = ActivationController::new(fixture.proposal.clone());
        controller.begin_canary(&fixture.registry, 200).unwrap();
        let failed = CanaryObservation::issue(
            &fixture.proposal,
            &fixture.profiles[0],
            0,
            1_000,
            10,
            results(100 << 20),
            1,
            h(72),
            201,
            &fixture.evaluator_keys[0],
        )
        .unwrap();
        assert_eq!(
            controller
                .record_canary(failed, &fixture.profiles[0])
                .unwrap(),
            CanaryState::RolledBack
        );
        assert_eq!(controller.shadow_alias_revision_id(), h(41));
        assert_eq!(controller.production_alias_revision_id(), h(41));
        assert_eq!(controller.route_shadow_request(h(73)).unwrap(), h(41));
        assert_eq!(
            controller.alias_transitions().last().unwrap().kind,
            AliasTransitionKind::AutomaticRollback
        );
    }

    #[test]
    fn passing_every_canary_stage_still_cannot_activate_production() {
        let fixture = fixture();
        let mut controller = ActivationController::new(fixture.proposal.clone());
        controller.begin_canary(&fixture.registry, 200).unwrap();
        for (stage, ceiling) in CANARY_CEILINGS_PERCENT.into_iter().enumerate() {
            let observation = CanaryObservation::issue(
                &fixture.proposal,
                &fixture.profiles[0],
                u8::try_from(stage).unwrap(),
                100,
                u64::from(ceiling),
                results(100 << 20),
                0,
                h(80_u8.saturating_add(u8::try_from(stage).unwrap())),
                201 + u64::try_from(stage).unwrap(),
                &fixture.evaluator_keys[0],
            )
            .unwrap();
            controller
                .record_canary(observation, &fixture.profiles[0])
                .unwrap();
        }
        assert_eq!(controller.state(), CanaryState::CanaryComplete);
        assert_eq!(controller.production_alias_revision_id(), h(41));
        assert_eq!(
            controller.activate_production_alias(),
            Err(ActivationError::ProductionActivationDisabled)
        );
        assert!(!WWM_MODEL_ACTIVATION_ENABLED);
        assert_eq!(WWM_ACTIVATION_CONSENSUS_WEIGHT, 0);
        assert_eq!(WWM_ACTIVATION_FINALITY_WEIGHT, 0);
    }

    #[test]
    fn emergency_authority_only_narrows_and_expires_while_pins_remain_available() {
        let fixture = fixture();
        let mut controller = ActivationController::new(fixture.proposal.clone());
        controller.begin_canary(&fixture.registry, 200).unwrap();
        let authority = fixture
            .proposal
            .activators
            .iter()
            .find_map(|registered| {
                fixture
                    .activator_keys
                    .iter()
                    .find(|key| key.public_key().into_bytes() == registered.public_key)
                    .map(|key| (registered, key))
            })
            .unwrap();
        let restriction = EmergencyRestriction::issue(
            &fixture.proposal,
            h(90),
            h(91),
            205,
            300,
            authority.0.control_cluster,
            authority.1,
        )
        .unwrap();
        controller
            .apply_emergency_restriction(&restriction, 205)
            .unwrap();
        assert_eq!(controller.state(), CanaryState::EmergencyRestricted);
        assert_eq!(controller.shadow_alias_revision_id(), h(41));
        assert_eq!(
            restriction.validate(&fixture.proposal, 300),
            Err(ActivationError::InvalidEmergencyRestriction)
        );
        assert_eq!(
            controller
                .resolve_selection(RevisionSelection::Pinned(h(40)))
                .unwrap(),
            h(40)
        );
        assert_eq!(
            controller
                .resolve_selection(RevisionSelection::ForkBase(h(41)))
                .unwrap(),
            h(41)
        );
        assert_eq!(
            controller.resolve_selection(RevisionSelection::Pinned(h(99))),
            Err(ActivationError::UnavailableRevision)
        );
    }
}
