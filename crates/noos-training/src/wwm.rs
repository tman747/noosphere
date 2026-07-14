//! Rights-bound World Wide Mind adapter training artifacts.
//!
//! This module records immutable dataset, recipe, update, and trainer objects.
//! It deliberately does not implement a serving-weight mutation path. Secure
//! aggregation is represented only by verifiable protocol evidence supplied by
//! a separately registered implementation; this crate does not claim that a
//! commitment proves privacy, robustness, convergence, or model quality.

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use noos_mind::KnowledgeGraph;
use noos_species::{Hash32, UpdateKind, UpdatePacket};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_DATASET_ITEMS: usize = 1_000_000;
pub const MAX_ADAPTER_RANK: u16 = 256;
pub const MAX_ADAPTER_PARAMETERS: u64 = 50_000_000;
pub const MAX_TRAINING_STEPS: u64 = 10_000_000;
pub const MAX_CHECKPOINTS: usize = 4_096;
pub const MIN_CONFIDENTIAL_COHORT: u32 = 32;
pub const MAX_CONFIDENTIAL_DROPOUT_BPS: u16 = 3_333;
pub const WWM_TRAINING_PROMOTION_ENABLED: bool = false;
pub const WWM_CONFIDENTIAL_COHORT_ACTIVATION_ENABLED: bool = false;
pub const WWM_TRAINING_CONSENSUS_WEIGHT: u64 = 0;
pub const WWM_TRAINING_FINALITY_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WwmTrainingError {
    InvalidDataset,
    RightsViolation,
    InvalidSignature,
    InvalidRecipe,
    InvalidLanePolicy,
    InvalidJob,
    InvalidUpdatePacket,
    InvalidReceipt,
    InvalidLaneEvidence,
    LinkageMismatch,
    DuplicateObject,
    UnknownObject,
    PromotionDisabled,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetSnapshot {
    pub parent_dataset_id: Option<Hash32>,
    pub knowledge_snapshot_id: Hash32,
    pub train_ids: Vec<Hash32>,
    pub evaluation_ids: Vec<Hash32>,
    pub exclusion_ids: Vec<Hash32>,
    pub rights_policy_root: Hash32,
    pub deduplication_report_root: Hash32,
    pub private_canary_commitment: Hash32,
    pub split_commitment: Hash32,
    pub builder_key: Hash32,
    pub builder_control_cluster: Hash32,
    pub created_height: u64,
    pub dataset_id: Hash32,
    pub signature: [u8; 64],
}

impl DatasetSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        graph: &KnowledgeGraph,
        parent_dataset_id: Option<Hash32>,
        knowledge_snapshot_id: Hash32,
        train_ids: Vec<Hash32>,
        evaluation_ids: Vec<Hash32>,
        exclusion_ids: Vec<Hash32>,
        rights_policy_root: Hash32,
        deduplication_report_root: Hash32,
        private_canary_commitment: Hash32,
        builder_control_cluster: Hash32,
        created_height: u64,
        builder: &Keypair,
    ) -> Result<Self, WwmTrainingError> {
        let split_commitment = split_commitment(
            knowledge_snapshot_id,
            &train_ids,
            &evaluation_ids,
            &exclusion_ids,
            deduplication_report_root,
            private_canary_commitment,
        )?;
        let mut value = Self {
            parent_dataset_id,
            knowledge_snapshot_id,
            train_ids,
            evaluation_ids,
            exclusion_ids,
            rights_policy_root,
            deduplication_report_root,
            private_canary_commitment,
            split_commitment,
            builder_key: builder.public_key().into_bytes(),
            builder_control_cluster,
            created_height,
            dataset_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        value.validate_rights(graph)?;
        let body = value.body()?;
        value.dataset_id = digest(DomainId::WwmDatasetSnapshot, &[&body])?;
        value.signature = sign(
            builder,
            DomainId::WwmDatasetSnapshot,
            value.dataset_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self, graph: &KnowledgeGraph) -> Result<(), WwmTrainingError> {
        self.validate_shape()?;
        self.validate_rights(graph)?;
        let body = self.body()?;
        if digest(DomainId::WwmDatasetSnapshot, &[&body])? != self.dataset_id {
            return Err(WwmTrainingError::InvalidDataset);
        }
        verify(
            self.builder_key,
            DomainId::WwmDatasetSnapshot,
            self.dataset_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), WwmTrainingError> {
        let count = self
            .train_ids
            .len()
            .checked_add(self.evaluation_ids.len())
            .ok_or(WwmTrainingError::ArithmeticOverflow)?;
        if self.train_ids.is_empty()
            || self.evaluation_ids.is_empty()
            || count > MAX_DATASET_ITEMS
            || !strictly_sorted(&self.train_ids)
            || !strictly_sorted(&self.evaluation_ids)
            || !strictly_sorted(&self.exclusion_ids)
            || intersects(&self.train_ids, &self.evaluation_ids)
            || intersects(&self.train_ids, &self.exclusion_ids)
            || intersects(&self.evaluation_ids, &self.exclusion_ids)
            || [
                self.knowledge_snapshot_id,
                self.rights_policy_root,
                self.deduplication_report_root,
                self.private_canary_commitment,
                self.split_commitment,
                self.builder_key,
                self.builder_control_cluster,
            ]
            .contains(&[0; 32])
        {
            return Err(WwmTrainingError::InvalidDataset);
        }
        let expected = split_commitment(
            self.knowledge_snapshot_id,
            &self.train_ids,
            &self.evaluation_ids,
            &self.exclusion_ids,
            self.deduplication_report_root,
            self.private_canary_commitment,
        )?;
        if expected != self.split_commitment {
            return Err(WwmTrainingError::InvalidDataset);
        }
        Ok(())
    }

    fn validate_rights(&self, graph: &KnowledgeGraph) -> Result<(), WwmTrainingError> {
        let eligible = graph
            .training_candidate_ids()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if self
            .train_ids
            .iter()
            .chain(&self.evaluation_ids)
            .any(|id| !eligible.contains(id))
            || graph
                .revoked_ids()
                .iter()
                .any(|id| !self.exclusion_ids.contains(id))
        {
            return Err(WwmTrainingError::RightsViolation);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, WwmTrainingError> {
        let mut out = Vec::new();
        push_optional_hash(&mut out, self.parent_dataset_id);
        out.extend(self.knowledge_snapshot_id);
        push_hashes(&mut out, &self.train_ids)?;
        push_hashes(&mut out, &self.evaluation_ids)?;
        push_hashes(&mut out, &self.exclusion_ids)?;
        out.extend(self.rights_policy_root);
        out.extend(self.deduplication_report_root);
        out.extend(self.private_canary_commitment);
        out.extend(self.split_commitment);
        out.extend(self.builder_key);
        out.extend(self.builder_control_cluster);
        out.extend(self.created_height.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrainingLaneKind {
    Auditable = 0,
    ConfidentialCohort = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditableLanePolicy {
    pub authorized_evaluator_set_root: Hash32,
    pub disclosure_rights_root: Hash32,
    pub clipping_norm_q20: u64,
    pub maximum_updates_per_control_cluster: u16,
    pub challenge_window_blocks: u64,
    pub duplicate_analysis_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialCohortPolicy {
    pub secure_aggregation_protocol_root: Hash32,
    pub range_proof_profile_root: Hash32,
    pub aggregate_canary_root: Hash32,
    pub minimum_cohort_size: u32,
    pub maximum_dropout_bps: u16,
    pub declared_byzantine_limit_bps: u16,
    pub contribution_limit: u16,
    pub clipping_norm_q20: u64,
    pub abort_on_threshold_loss: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrainingLanePolicy {
    Auditable(AuditableLanePolicy),
    ConfidentialCohort(ConfidentialCohortPolicy),
}

impl TrainingLanePolicy {
    #[must_use]
    pub const fn kind(&self) -> TrainingLaneKind {
        match self {
            Self::Auditable(_) => TrainingLaneKind::Auditable,
            Self::ConfidentialCohort(_) => TrainingLaneKind::ConfidentialCohort,
        }
    }

    #[must_use]
    pub const fn exposes_individual_updates_to_authorized_evaluators(&self) -> bool {
        matches!(self, Self::Auditable(_))
    }

    #[must_use]
    pub const fn supports_individual_fault_attribution(&self) -> bool {
        matches!(self, Self::Auditable(_))
    }

    #[must_use]
    pub const fn activation_eligible(&self) -> bool {
        false
    }

    fn validate(&self) -> Result<(), WwmTrainingError> {
        match self {
            Self::Auditable(policy) => {
                if [
                    policy.authorized_evaluator_set_root,
                    policy.disclosure_rights_root,
                ]
                .contains(&[0; 32])
                    || policy.clipping_norm_q20 == 0
                    || policy.maximum_updates_per_control_cluster == 0
                    || policy.challenge_window_blocks == 0
                    || !policy.duplicate_analysis_required
                {
                    return Err(WwmTrainingError::InvalidLanePolicy);
                }
            }
            Self::ConfidentialCohort(policy) => {
                if [
                    policy.secure_aggregation_protocol_root,
                    policy.range_proof_profile_root,
                    policy.aggregate_canary_root,
                ]
                .contains(&[0; 32])
                    || policy.minimum_cohort_size < MIN_CONFIDENTIAL_COHORT
                    || policy.maximum_dropout_bps > MAX_CONFIDENTIAL_DROPOUT_BPS
                    || policy.declared_byzantine_limit_bps > 2_000
                    || policy.contribution_limit == 0
                    || policy.clipping_norm_q20 == 0
                    || !policy.abort_on_threshold_loss
                {
                    return Err(WwmTrainingError::InvalidLanePolicy);
                }
            }
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.kind() as u8);
        match self {
            Self::Auditable(policy) => {
                out.extend(policy.authorized_evaluator_set_root);
                out.extend(policy.disclosure_rights_root);
                out.extend(policy.clipping_norm_q20.to_le_bytes());
                out.extend(policy.maximum_updates_per_control_cluster.to_le_bytes());
                out.extend(policy.challenge_window_blocks.to_le_bytes());
                out.push(u8::from(policy.duplicate_analysis_required));
            }
            Self::ConfidentialCohort(policy) => {
                out.extend(policy.secure_aggregation_protocol_root);
                out.extend(policy.range_proof_profile_root);
                out.extend(policy.aggregate_canary_root);
                out.extend(policy.minimum_cohort_size.to_le_bytes());
                out.extend(policy.maximum_dropout_bps.to_le_bytes());
                out.extend(policy.declared_byzantine_limit_bps.to_le_bytes());
                out.extend(policy.contribution_limit.to_le_bytes());
                out.extend(policy.clipping_norm_q20.to_le_bytes());
                out.push(u8::from(policy.abort_on_threshold_loss));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingRecipe {
    pub parent_revision_id: Hash32,
    pub dataset_id: Hash32,
    pub tokenizer_root: Hash32,
    pub numeric_profile_root: Hash32,
    pub optimizer_root: Hash32,
    pub sampling_profile_root: Hash32,
    pub randomness_commitment: Hash32,
    pub intended_capability_root: Hash32,
    pub evaluator_policy_root: Hash32,
    pub rollback_parent_id: Hash32,
    pub budget_root: Hash32,
    pub adapter_rank: u16,
    pub trainable_parameter_count: u64,
    pub maximum_steps: u64,
    pub batch_size: u32,
    pub learning_rate_q32: u64,
    pub clipping_norm_q20: u64,
    pub lane: TrainingLanePolicy,
    pub sponsor_key: Hash32,
    pub sponsor_control_cluster: Hash32,
    pub evaluator_control_clusters: Vec<Hash32>,
    pub created_height: u64,
    pub recipe_id: Hash32,
    pub signature: [u8; 64],
}

impl TrainingRecipe {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_revision_id: Hash32,
        dataset_id: Hash32,
        tokenizer_root: Hash32,
        numeric_profile_root: Hash32,
        optimizer_root: Hash32,
        sampling_profile_root: Hash32,
        randomness_commitment: Hash32,
        intended_capability_root: Hash32,
        evaluator_policy_root: Hash32,
        rollback_parent_id: Hash32,
        budget_root: Hash32,
        adapter_rank: u16,
        trainable_parameter_count: u64,
        maximum_steps: u64,
        batch_size: u32,
        learning_rate_q32: u64,
        clipping_norm_q20: u64,
        lane: TrainingLanePolicy,
        sponsor_control_cluster: Hash32,
        evaluator_control_clusters: Vec<Hash32>,
        created_height: u64,
        sponsor: &Keypair,
    ) -> Result<Self, WwmTrainingError> {
        let mut value = Self {
            parent_revision_id,
            dataset_id,
            tokenizer_root,
            numeric_profile_root,
            optimizer_root,
            sampling_profile_root,
            randomness_commitment,
            intended_capability_root,
            evaluator_policy_root,
            rollback_parent_id,
            budget_root,
            adapter_rank,
            trainable_parameter_count,
            maximum_steps,
            batch_size,
            learning_rate_q32,
            clipping_norm_q20,
            lane,
            sponsor_key: sponsor.public_key().into_bytes(),
            sponsor_control_cluster,
            evaluator_control_clusters,
            created_height,
            recipe_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body()?;
        value.recipe_id = digest(DomainId::WwmTrainingRecipe, &[&body])?;
        value.signature = sign(sponsor, DomainId::WwmTrainingRecipe, value.recipe_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self, dataset: &DatasetSnapshot) -> Result<(), WwmTrainingError> {
        self.validate_shape()?;
        if self.dataset_id != dataset.dataset_id
            || self.rollback_parent_id != self.parent_revision_id
        {
            return Err(WwmTrainingError::LinkageMismatch);
        }
        let body = self.body()?;
        if digest(DomainId::WwmTrainingRecipe, &[&body])? != self.recipe_id {
            return Err(WwmTrainingError::InvalidRecipe);
        }
        verify(
            self.sponsor_key,
            DomainId::WwmTrainingRecipe,
            self.recipe_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), WwmTrainingError> {
        self.lane.validate()?;
        if [
            self.parent_revision_id,
            self.dataset_id,
            self.tokenizer_root,
            self.numeric_profile_root,
            self.optimizer_root,
            self.sampling_profile_root,
            self.randomness_commitment,
            self.intended_capability_root,
            self.evaluator_policy_root,
            self.rollback_parent_id,
            self.budget_root,
            self.sponsor_key,
            self.sponsor_control_cluster,
        ]
        .contains(&[0; 32])
            || self.adapter_rank == 0
            || self.adapter_rank > MAX_ADAPTER_RANK
            || self.trainable_parameter_count == 0
            || self.trainable_parameter_count > MAX_ADAPTER_PARAMETERS
            || self.maximum_steps == 0
            || self.maximum_steps > MAX_TRAINING_STEPS
            || self.batch_size == 0
            || self.learning_rate_q32 == 0
            || self.clipping_norm_q20 == 0
            || self.evaluator_control_clusters.is_empty()
            || !strictly_sorted(&self.evaluator_control_clusters)
            || self
                .evaluator_control_clusters
                .contains(&self.sponsor_control_cluster)
        {
            return Err(WwmTrainingError::InvalidRecipe);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, WwmTrainingError> {
        let mut out = Vec::new();
        out.extend(self.parent_revision_id);
        out.extend(self.dataset_id);
        out.extend(self.tokenizer_root);
        out.extend(self.numeric_profile_root);
        out.extend(self.optimizer_root);
        out.extend(self.sampling_profile_root);
        out.extend(self.randomness_commitment);
        out.extend(self.intended_capability_root);
        out.extend(self.evaluator_policy_root);
        out.extend(self.rollback_parent_id);
        out.extend(self.budget_root);
        out.extend(self.adapter_rank.to_le_bytes());
        out.extend(self.trainable_parameter_count.to_le_bytes());
        out.extend(self.maximum_steps.to_le_bytes());
        out.extend(self.batch_size.to_le_bytes());
        out.extend(self.learning_rate_q32.to_le_bytes());
        out.extend(self.clipping_norm_q20.to_le_bytes());
        self.lane.encode(&mut out);
        out.extend(self.sponsor_key);
        out.extend(self.sponsor_control_cluster);
        push_hashes(&mut out, &self.evaluator_control_clusters)?;
        out.extend(self.created_height.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterJob {
    pub recipe_id: Hash32,
    pub dataset_id: Hash32,
    pub work_loom_assignment_id: Hash32,
    pub trainer_key: Hash32,
    pub trainer_control_cluster: Hash32,
    pub accepted_height: u64,
    pub deadline_height: u64,
    pub job_id: Hash32,
    pub signature: [u8; 64],
}

impl AdapterJob {
    pub fn accept(
        recipe: &TrainingRecipe,
        work_loom_assignment_id: Hash32,
        trainer_control_cluster: Hash32,
        accepted_height: u64,
        deadline_height: u64,
        trainer: &Keypair,
    ) -> Result<Self, WwmTrainingError> {
        if work_loom_assignment_id == [0; 32]
            || trainer_control_cluster == [0; 32]
            || trainer_control_cluster == recipe.sponsor_control_cluster
            || recipe
                .evaluator_control_clusters
                .contains(&trainer_control_cluster)
            || accepted_height >= deadline_height
        {
            return Err(WwmTrainingError::InvalidJob);
        }
        let mut value = Self {
            recipe_id: recipe.recipe_id,
            dataset_id: recipe.dataset_id,
            work_loom_assignment_id,
            trainer_key: trainer.public_key().into_bytes(),
            trainer_control_cluster,
            accepted_height,
            deadline_height,
            job_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body();
        value.job_id = digest(DomainId::WwmTrainingRecipe, &[b"ADAPTER-JOB", &body])?;
        value.signature = sign(trainer, DomainId::WwmTrainingRecipe, value.job_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self, recipe: &TrainingRecipe) -> Result<(), WwmTrainingError> {
        if self.recipe_id != recipe.recipe_id
            || self.dataset_id != recipe.dataset_id
            || self.work_loom_assignment_id == [0; 32]
            || self.trainer_key == [0; 32]
            || self.trainer_control_cluster == [0; 32]
            || self.trainer_control_cluster == recipe.sponsor_control_cluster
            || recipe
                .evaluator_control_clusters
                .contains(&self.trainer_control_cluster)
            || self.accepted_height >= self.deadline_height
        {
            return Err(WwmTrainingError::InvalidJob);
        }
        let body = self.body();
        if digest(DomainId::WwmTrainingRecipe, &[b"ADAPTER-JOB", &body])? != self.job_id {
            return Err(WwmTrainingError::InvalidJob);
        }
        verify(
            self.trainer_key,
            DomainId::WwmTrainingRecipe,
            self.job_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.recipe_id);
        out.extend(self.dataset_id);
        out.extend(self.work_loom_assignment_id);
        out.extend(self.trainer_key);
        out.extend(self.trainer_control_cluster);
        out.extend(self.accepted_height.to_le_bytes());
        out.extend(self.deadline_height.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterCheckpoint {
    pub sequence: u32,
    pub checkpoint_root: Hash32,
    pub parent_checkpoint_root: Option<Hash32>,
    pub optimizer_state_root: Hash32,
    pub examples_seen: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterUpdatePacket {
    pub parent_revision_id: Hash32,
    pub candidate_revision_id: Hash32,
    pub recipe_id: Hash32,
    pub dataset_id: Hash32,
    pub species_packet: UpdatePacket,
    pub checkpoints: Vec<AdapterCheckpoint>,
    pub adapter_rank: u16,
    pub trainable_parameter_count: u64,
    pub lane: TrainingLaneKind,
    pub packet_id: Hash32,
}

impl AdapterUpdatePacket {
    pub fn new(
        recipe: &TrainingRecipe,
        dataset: &DatasetSnapshot,
        candidate_revision_id: Hash32,
        species_packet: UpdatePacket,
        checkpoints: Vec<AdapterCheckpoint>,
    ) -> Result<Self, WwmTrainingError> {
        let mut value = Self {
            parent_revision_id: recipe.parent_revision_id,
            candidate_revision_id,
            recipe_id: recipe.recipe_id,
            dataset_id: dataset.dataset_id,
            species_packet,
            checkpoints,
            adapter_rank: recipe.adapter_rank,
            trainable_parameter_count: recipe.trainable_parameter_count,
            lane: recipe.lane.kind(),
            packet_id: [0; 32],
        };
        value.validate_shape(recipe, dataset)?;
        value.packet_id = digest(DomainId::WwmUpdatePacket, &[&value.body()?])?;
        Ok(value)
    }

    pub fn validate(
        &self,
        recipe: &TrainingRecipe,
        dataset: &DatasetSnapshot,
    ) -> Result<(), WwmTrainingError> {
        self.validate_shape(recipe, dataset)?;
        if digest(DomainId::WwmUpdatePacket, &[&self.body()?])? != self.packet_id {
            return Err(WwmTrainingError::InvalidUpdatePacket);
        }
        Ok(())
    }

    fn validate_shape(
        &self,
        recipe: &TrainingRecipe,
        dataset: &DatasetSnapshot,
    ) -> Result<(), WwmTrainingError> {
        if self.parent_revision_id != recipe.parent_revision_id
            || self.recipe_id != recipe.recipe_id
            || self.dataset_id != dataset.dataset_id
            || self.candidate_revision_id == [0; 32]
            || self.adapter_rank != recipe.adapter_rank
            || self.trainable_parameter_count != recipe.trainable_parameter_count
            || self.lane != recipe.lane.kind()
            || self.species_packet.validate_canonical().is_err()
            || self.species_packet.update_kind != UpdateKind::LowRank
            || self.species_packet.training_recipe != Some(recipe.recipe_id)
            || !self
                .species_packet
                .base_members
                .contains(&recipe.parent_revision_id)
            || self.species_packet.tokenizer != recipe.tokenizer_root
            || self.species_packet.numeric_profile != recipe.numeric_profile_root
            || self.species_packet.rights_expression != dataset.rights_policy_root
            || self.species_packet.provenance_root != dataset.dataset_id
            || self.checkpoints.is_empty()
            || self.checkpoints.len() > MAX_CHECKPOINTS
        {
            return Err(WwmTrainingError::InvalidUpdatePacket);
        }
        for (index, checkpoint) in self.checkpoints.iter().enumerate() {
            let sequence =
                u32::try_from(index).map_err(|_| WwmTrainingError::ArithmeticOverflow)?;
            let expected_parent = index
                .checked_sub(1)
                .map(|prior| self.checkpoints[prior].checkpoint_root);
            if checkpoint.sequence != sequence
                || checkpoint.checkpoint_root == [0; 32]
                || checkpoint.optimizer_state_root == [0; 32]
                || checkpoint.parent_checkpoint_root != expected_parent
            {
                return Err(WwmTrainingError::InvalidUpdatePacket);
            }
        }
        if self.species_packet.payload
            != self
                .checkpoints
                .last()
                .ok_or(WwmTrainingError::InvalidUpdatePacket)?
                .checkpoint_root
        {
            return Err(WwmTrainingError::InvalidUpdatePacket);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, WwmTrainingError> {
        let mut out = Vec::new();
        out.extend(self.parent_revision_id);
        out.extend(self.candidate_revision_id);
        out.extend(self.recipe_id);
        out.extend(self.dataset_id);
        let packet = self.species_packet.canonical_bytes();
        push_bytes(&mut out, &packet)?;
        out.extend(
            u32::try_from(self.checkpoints.len())
                .map_err(|_| WwmTrainingError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for checkpoint in &self.checkpoints {
            out.extend(checkpoint.sequence.to_le_bytes());
            out.extend(checkpoint.checkpoint_root);
            push_optional_hash(&mut out, checkpoint.parent_checkpoint_root);
            out.extend(checkpoint.optimizer_state_root);
            out.extend(checkpoint.examples_seen.to_le_bytes());
        }
        out.extend(self.adapter_rank.to_le_bytes());
        out.extend(self.trainable_parameter_count.to_le_bytes());
        out.push(self.lane as u8);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditableUpdateEvidence {
    pub individual_update_commitments: Vec<Hash32>,
    pub contributor_control_clusters: Vec<Hash32>,
    pub clipping_report_root: Hash32,
    pub duplicate_analysis_root: Hash32,
    pub challenge_transcript_root: Hash32,
    pub evidence_id: Hash32,
}

impl AuditableUpdateEvidence {
    pub fn new(
        individual_update_commitments: Vec<Hash32>,
        contributor_control_clusters: Vec<Hash32>,
        clipping_report_root: Hash32,
        duplicate_analysis_root: Hash32,
        challenge_transcript_root: Hash32,
    ) -> Result<Self, WwmTrainingError> {
        let mut value = Self {
            individual_update_commitments,
            contributor_control_clusters,
            clipping_report_root,
            duplicate_analysis_root,
            challenge_transcript_root,
            evidence_id: [0; 32],
        };
        value.validate_shape()?;
        value.evidence_id = digest(DomainId::WwmTrainerReceipt, &[b"AUDITABLE", &value.body()?])?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), WwmTrainingError> {
        if self.individual_update_commitments.is_empty()
            || !strictly_sorted(&self.individual_update_commitments)
            || self.contributor_control_clusters.is_empty()
            || !strictly_sorted(&self.contributor_control_clusters)
            || [
                self.clipping_report_root,
                self.duplicate_analysis_root,
                self.challenge_transcript_root,
            ]
            .contains(&[0; 32])
        {
            return Err(WwmTrainingError::InvalidLaneEvidence);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, WwmTrainingError> {
        let mut out = Vec::new();
        push_hashes(&mut out, &self.individual_update_commitments)?;
        push_hashes(&mut out, &self.contributor_control_clusters)?;
        out.extend(self.clipping_report_root);
        out.extend(self.duplicate_analysis_root);
        out.extend(self.challenge_transcript_root);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialCohortEvidence {
    pub cohort_aggregate_root: Hash32,
    pub participant_set_commitment: Hash32,
    pub range_proof_batch_root: Hash32,
    pub dropout_transcript_root: Hash32,
    pub aggregate_canary_report_root: Hash32,
    pub expected_participants: u32,
    pub completed_participants: u32,
    pub individual_attribution_available: bool,
    pub evidence_id: Hash32,
}

impl ConfidentialCohortEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &ConfidentialCohortPolicy,
        cohort_aggregate_root: Hash32,
        participant_set_commitment: Hash32,
        range_proof_batch_root: Hash32,
        dropout_transcript_root: Hash32,
        aggregate_canary_report_root: Hash32,
        expected_participants: u32,
        completed_participants: u32,
    ) -> Result<Self, WwmTrainingError> {
        let mut value = Self {
            cohort_aggregate_root,
            participant_set_commitment,
            range_proof_batch_root,
            dropout_transcript_root,
            aggregate_canary_report_root,
            expected_participants,
            completed_participants,
            individual_attribution_available: false,
            evidence_id: [0; 32],
        };
        value.validate_shape(policy)?;
        value.evidence_id = digest(
            DomainId::WwmTrainerReceipt,
            &[b"CONFIDENTIAL-COHORT", &value.body()],
        )?;
        Ok(value)
    }

    fn validate_shape(&self, policy: &ConfidentialCohortPolicy) -> Result<(), WwmTrainingError> {
        let dropped = self
            .expected_participants
            .checked_sub(self.completed_participants)
            .ok_or(WwmTrainingError::InvalidLaneEvidence)?;
        let dropout_bps = u64::from(dropped)
            .checked_mul(10_000)
            .and_then(|value| value.checked_div(u64::from(self.expected_participants)))
            .ok_or(WwmTrainingError::InvalidLaneEvidence)?;
        if [
            self.cohort_aggregate_root,
            self.participant_set_commitment,
            self.range_proof_batch_root,
            self.dropout_transcript_root,
            self.aggregate_canary_report_root,
        ]
        .contains(&[0; 32])
            || self.expected_participants < policy.minimum_cohort_size
            || self.completed_participants < policy.minimum_cohort_size
            || dropout_bps > u64::from(policy.maximum_dropout_bps)
            || self.individual_attribution_available
        {
            return Err(WwmTrainingError::InvalidLaneEvidence);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.cohort_aggregate_root);
        out.extend(self.participant_set_commitment);
        out.extend(self.range_proof_batch_root);
        out.extend(self.dropout_transcript_root);
        out.extend(self.aggregate_canary_report_root);
        out.extend(self.expected_participants.to_le_bytes());
        out.extend(self.completed_participants.to_le_bytes());
        out.push(u8::from(self.individual_attribution_available));
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrainingLaneEvidence {
    Auditable(AuditableUpdateEvidence),
    ConfidentialCohort(ConfidentialCohortEvidence),
}

impl TrainingLaneEvidence {
    fn validate(&self, policy: &TrainingLanePolicy) -> Result<Hash32, WwmTrainingError> {
        match (self, policy) {
            (Self::Auditable(evidence), TrainingLanePolicy::Auditable(_)) => {
                evidence.validate_shape()?;
                if digest(
                    DomainId::WwmTrainerReceipt,
                    &[b"AUDITABLE", &evidence.body()?],
                )? != evidence.evidence_id
                {
                    return Err(WwmTrainingError::InvalidLaneEvidence);
                }
                Ok(evidence.evidence_id)
            }
            (
                Self::ConfidentialCohort(evidence),
                TrainingLanePolicy::ConfidentialCohort(policy),
            ) => {
                evidence.validate_shape(policy)?;
                if digest(
                    DomainId::WwmTrainerReceipt,
                    &[b"CONFIDENTIAL-COHORT", &evidence.body()],
                )? != evidence.evidence_id
                {
                    return Err(WwmTrainingError::InvalidLaneEvidence);
                }
                Ok(evidence.evidence_id)
            }
            _ => Err(WwmTrainingError::InvalidLaneEvidence),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainerReceipt {
    pub job_id: Hash32,
    pub recipe_id: Hash32,
    pub dataset_id: Hash32,
    pub update_packet_id: Hash32,
    pub candidate_revision_id: Hash32,
    pub trainer_key: Hash32,
    pub trainer_control_cluster: Hash32,
    pub lane: TrainingLaneKind,
    pub lane_evidence_id: Hash32,
    pub initial_checkpoint_root: Hash32,
    pub final_checkpoint_root: Hash32,
    pub resource_receipt_root: Hash32,
    pub deterministic_fidelity_audit_root: Hash32,
    pub sampled_fidelity_audit_root: Hash32,
    pub execution_implementation_root: Hash32,
    pub steps_completed: u64,
    pub examples_seen: u64,
    pub started_height: u64,
    pub completed_height: u64,
    pub shadow_only: bool,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl TrainerReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        job: &AdapterJob,
        recipe: &TrainingRecipe,
        update: &AdapterUpdatePacket,
        lane_evidence: &TrainingLaneEvidence,
        resource_receipt_root: Hash32,
        deterministic_fidelity_audit_root: Hash32,
        sampled_fidelity_audit_root: Hash32,
        execution_implementation_root: Hash32,
        steps_completed: u64,
        examples_seen: u64,
        started_height: u64,
        completed_height: u64,
        trainer: &Keypair,
    ) -> Result<Self, WwmTrainingError> {
        let lane_evidence_id = lane_evidence.validate(&recipe.lane)?;
        let first = update
            .checkpoints
            .first()
            .ok_or(WwmTrainingError::InvalidReceipt)?;
        let last = update
            .checkpoints
            .last()
            .ok_or(WwmTrainingError::InvalidReceipt)?;
        let mut value = Self {
            job_id: job.job_id,
            recipe_id: recipe.recipe_id,
            dataset_id: recipe.dataset_id,
            update_packet_id: update.packet_id,
            candidate_revision_id: update.candidate_revision_id,
            trainer_key: trainer.public_key().into_bytes(),
            trainer_control_cluster: job.trainer_control_cluster,
            lane: recipe.lane.kind(),
            lane_evidence_id,
            initial_checkpoint_root: first.checkpoint_root,
            final_checkpoint_root: last.checkpoint_root,
            resource_receipt_root,
            deterministic_fidelity_audit_root,
            sampled_fidelity_audit_root,
            execution_implementation_root,
            steps_completed,
            examples_seen,
            started_height,
            completed_height,
            shadow_only: true,
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape(job, recipe, update, lane_evidence)?;
        let body = value.body();
        value.receipt_id = digest(DomainId::WwmTrainerReceipt, &[&body])?;
        value.signature = sign(
            trainer,
            DomainId::WwmTrainerReceipt,
            value.receipt_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(
        &self,
        job: &AdapterJob,
        recipe: &TrainingRecipe,
        update: &AdapterUpdatePacket,
        lane_evidence: &TrainingLaneEvidence,
    ) -> Result<(), WwmTrainingError> {
        self.validate_shape(job, recipe, update, lane_evidence)?;
        let body = self.body();
        if digest(DomainId::WwmTrainerReceipt, &[&body])? != self.receipt_id {
            return Err(WwmTrainingError::InvalidReceipt);
        }
        verify(
            self.trainer_key,
            DomainId::WwmTrainerReceipt,
            self.receipt_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(
        &self,
        job: &AdapterJob,
        recipe: &TrainingRecipe,
        update: &AdapterUpdatePacket,
        lane_evidence: &TrainingLaneEvidence,
    ) -> Result<(), WwmTrainingError> {
        let lane_evidence_id = lane_evidence.validate(&recipe.lane)?;
        let first = update
            .checkpoints
            .first()
            .ok_or(WwmTrainingError::InvalidReceipt)?;
        let last = update
            .checkpoints
            .last()
            .ok_or(WwmTrainingError::InvalidReceipt)?;
        if self.job_id != job.job_id
            || self.recipe_id != recipe.recipe_id
            || self.dataset_id != recipe.dataset_id
            || self.update_packet_id != update.packet_id
            || self.candidate_revision_id != update.candidate_revision_id
            || self.trainer_key != job.trainer_key
            || self.trainer_control_cluster != job.trainer_control_cluster
            || self.lane != recipe.lane.kind()
            || self.lane_evidence_id != lane_evidence_id
            || self.initial_checkpoint_root != first.checkpoint_root
            || self.final_checkpoint_root != last.checkpoint_root
            || [
                self.resource_receipt_root,
                self.deterministic_fidelity_audit_root,
                self.sampled_fidelity_audit_root,
                self.execution_implementation_root,
            ]
            .contains(&[0; 32])
            || self.steps_completed == 0
            || self.steps_completed > recipe.maximum_steps
            || self.examples_seen == 0
            || self.examples_seen != last.examples_seen
            || self.started_height < job.accepted_height
            || self.completed_height < self.started_height
            || self.completed_height > job.deadline_height
            || !self.shadow_only
        {
            return Err(WwmTrainingError::InvalidReceipt);
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.job_id);
        out.extend(self.recipe_id);
        out.extend(self.dataset_id);
        out.extend(self.update_packet_id);
        out.extend(self.candidate_revision_id);
        out.extend(self.trainer_key);
        out.extend(self.trainer_control_cluster);
        out.push(self.lane as u8);
        out.extend(self.lane_evidence_id);
        out.extend(self.initial_checkpoint_root);
        out.extend(self.final_checkpoint_root);
        out.extend(self.resource_receipt_root);
        out.extend(self.deterministic_fidelity_audit_root);
        out.extend(self.sampled_fidelity_audit_root);
        out.extend(self.execution_implementation_root);
        out.extend(self.steps_completed.to_le_bytes());
        out.extend(self.examples_seen.to_le_bytes());
        out.extend(self.started_height.to_le_bytes());
        out.extend(self.completed_height.to_le_bytes());
        out.push(u8::from(self.shadow_only));
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateTrainingState {
    ShadowOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowCandidate {
    pub candidate_revision_id: Hash32,
    pub parent_revision_id: Hash32,
    pub dataset_id: Hash32,
    pub recipe_id: Hash32,
    pub update_packet_id: Hash32,
    pub trainer_receipt_id: Hash32,
    pub state: CandidateTrainingState,
}

#[derive(Debug, Default)]
pub struct ShadowRegistry {
    candidates: BTreeMap<Hash32, ShadowCandidate>,
    dataset_ids: BTreeSet<Hash32>,
    recipe_ids: BTreeSet<Hash32>,
    update_packet_ids: BTreeSet<Hash32>,
    trainer_receipt_ids: BTreeSet<Hash32>,
}

impl ShadowRegistry {
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        graph: &KnowledgeGraph,
        dataset: &DatasetSnapshot,
        recipe: &TrainingRecipe,
        job: &AdapterJob,
        update: &AdapterUpdatePacket,
        lane_evidence: &TrainingLaneEvidence,
        receipt: &TrainerReceipt,
    ) -> Result<&ShadowCandidate, WwmTrainingError> {
        dataset.validate(graph)?;
        recipe.validate(dataset)?;
        job.validate(recipe)?;
        update.validate(recipe, dataset)?;
        receipt.validate(job, recipe, update, lane_evidence)?;
        if self.candidates.contains_key(&update.candidate_revision_id)
            || self.dataset_ids.contains(&dataset.dataset_id)
            || self.recipe_ids.contains(&recipe.recipe_id)
            || self.update_packet_ids.contains(&update.packet_id)
            || self.trainer_receipt_ids.contains(&receipt.receipt_id)
        {
            return Err(WwmTrainingError::DuplicateObject);
        }
        let candidate = ShadowCandidate {
            candidate_revision_id: update.candidate_revision_id,
            parent_revision_id: recipe.parent_revision_id,
            dataset_id: dataset.dataset_id,
            recipe_id: recipe.recipe_id,
            update_packet_id: update.packet_id,
            trainer_receipt_id: receipt.receipt_id,
            state: CandidateTrainingState::ShadowOnly,
        };
        self.dataset_ids.insert(dataset.dataset_id);
        self.recipe_ids.insert(recipe.recipe_id);
        self.update_packet_ids.insert(update.packet_id);
        self.trainer_receipt_ids.insert(receipt.receipt_id);
        self.candidates
            .insert(update.candidate_revision_id, candidate);
        self.candidates
            .get(&update.candidate_revision_id)
            .ok_or(WwmTrainingError::UnknownObject)
    }

    #[must_use]
    pub fn candidate(&self, candidate_revision_id: &Hash32) -> Option<&ShadowCandidate> {
        self.candidates.get(candidate_revision_id)
    }

    pub const fn promote_to_serving(
        &mut self,
        _candidate_revision_id: Hash32,
    ) -> Result<(), WwmTrainingError> {
        Err(WwmTrainingError::PromotionDisabled)
    }
}

fn split_commitment(
    knowledge_snapshot_id: Hash32,
    train_ids: &[Hash32],
    evaluation_ids: &[Hash32],
    exclusion_ids: &[Hash32],
    deduplication_report_root: Hash32,
    private_canary_commitment: Hash32,
) -> Result<Hash32, WwmTrainingError> {
    let mut out = Vec::new();
    out.extend(knowledge_snapshot_id);
    push_hashes(&mut out, train_ids)?;
    push_hashes(&mut out, evaluation_ids)?;
    push_hashes(&mut out, exclusion_ids)?;
    out.extend(deduplication_report_root);
    out.extend(private_canary_commitment);
    digest(DomainId::WwmDatasetSnapshot, &[b"SPLIT", &out])
}

fn intersects(left: &[Hash32], right: &[Hash32]) -> bool {
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), WwmTrainingError> {
    out.extend(
        u32::try_from(values.len())
            .map_err(|_| WwmTrainingError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for value in values {
        out.extend(value);
    }
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), WwmTrainingError> {
    out.extend(
        u32::try_from(value.len())
            .map_err(|_| WwmTrainingError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    out.extend(value);
    Ok(())
}

fn push_optional_hash(out: &mut Vec<u8>, value: Option<Hash32>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend(value);
        }
        None => out.push(0),
    }
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, WwmTrainingError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| WwmTrainingError::InvalidSignature)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], WwmTrainingError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| WwmTrainingError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), WwmTrainingError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| WwmTrainingError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]

    use super::*;
    use noos_mind::{
        BlindCredentialVerifier, ChallengeState, ChallengeStatus, ContentPayload,
        ContributorIdentity, Lifecycle, MindLink, MindLinkDraft, MindLinkTransition, MindLinkType,
        ModerationState, ModerationStatus, Permission, Provenance, RightsPolicy, Visibility,
    };

    struct NoBlind;

    impl BlindCredentialVerifier for NoBlind {
        fn verify(&self, _: Hash32, _: Hash32, _: &[u8], _: [u8; 64]) -> bool {
            false
        }
    }

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn candidate_graph() -> (KnowledgeGraph, Vec<Hash32>) {
        let contributor = Keypair::from_seed([1; 32]);
        let reviewer = Keypair::from_seed([2; 32]);
        let mut graph =
            KnowledgeGraph::with_reviewers(BTreeSet::from([reviewer.public_key().into_bytes()]))
                .unwrap();
        let mut ids = Vec::new();
        for index in 0..2_u8 {
            let link = MindLink::finalize_signed(
                MindLinkDraft {
                    predecessors: Vec::new(),
                    supersedes: Vec::new(),
                    kind: MindLinkType::Source,
                    title: format!("Training source {index}"),
                    content: ContentPayload::Public {
                        original_text: format!("Rights-cleared training example {index}."),
                        summary: format!("Example {index}."),
                        summary_derived: true,
                    },
                    language: "en".to_owned(),
                    locale: "en-US".to_owned(),
                    domain_tags: vec!["training-test".to_owned()],
                    uncertainty: "Synthetic test fixture.".to_owned(),
                    contributor: ContributorIdentity::Pseudonymous {
                        public_key: contributor.public_key().into_bytes(),
                        display_name: "Fixture contributor".to_owned(),
                    },
                    authority: Vec::new(),
                    provenance: Provenance::default(),
                    relations: Vec::new(),
                    rights: RightsPolicy {
                        visibility: Visibility::Public,
                        retrieval_permission: Permission::Allow,
                        training_permission: Permission::Allow,
                        commercial_use: Permission::Deny,
                        derivative_model_permission: Permission::Allow,
                        attribution_required: true,
                        license: "CC-BY-4.0".to_owned(),
                        retention_request: "retain fixture".to_owned(),
                        cultural_constraints: String::new(),
                    },
                    challenge: ChallengeState {
                        status: ChallengeStatus::Unchallenged,
                        policy_root: h(10),
                        bond_micro_noos: 1,
                        open_challenge_ids: Vec::new(),
                    },
                    moderation: ModerationState {
                        namespace_root: h(11),
                        status: ModerationStatus::NotReviewed,
                        decision_ids: Vec::new(),
                    },
                    created_height: 10,
                },
                &contributor,
            )
            .unwrap();
            let id = link.mindlink_id;
            graph.register(link, &NoBlind).unwrap();
            let path = [
                (Lifecycle::Submitted, Lifecycle::Quarantined),
                (Lifecycle::Quarantined, Lifecycle::ProvenanceChecked),
                (Lifecycle::ProvenanceChecked, Lifecycle::RetrievalEligible),
                (Lifecycle::RetrievalEligible, Lifecycle::SnapshotCandidate),
                (Lifecycle::SnapshotCandidate, Lifecycle::SnapshotAccepted),
                (Lifecycle::SnapshotAccepted, Lifecycle::TrainingCandidate),
            ];
            for (step, (prior, next)) in path.into_iter().enumerate() {
                graph
                    .apply_transition(
                        MindLinkTransition::new(
                            &reviewer,
                            id,
                            prior,
                            next,
                            h(30 + u8::try_from(step).unwrap()),
                            Vec::new(),
                            (matches!(
                                next,
                                Lifecycle::Quarantined
                                    | Lifecycle::ProvenanceChecked
                                    | Lifecycle::RetrievalEligible
                                    | Lifecycle::Rejected
                            ))
                            .then(|| vec![h(91)])
                            .unwrap_or_default(),
                            11 + u64::try_from(step).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap();
            }
            ids.push(id);
        }
        ids.sort_unstable();
        (graph, ids)
    }

    fn dataset(graph: &KnowledgeGraph, ids: &[Hash32]) -> DatasetSnapshot {
        DatasetSnapshot::build(
            graph,
            None,
            h(20),
            vec![ids[0]],
            vec![ids[1]],
            Vec::new(),
            h(21),
            h(22),
            h(23),
            h(24),
            100,
            &Keypair::from_seed([3; 32]),
        )
        .unwrap()
    }

    fn auditable_lane() -> TrainingLanePolicy {
        TrainingLanePolicy::Auditable(AuditableLanePolicy {
            authorized_evaluator_set_root: h(30),
            disclosure_rights_root: h(31),
            clipping_norm_q20: 2 << 20,
            maximum_updates_per_control_cluster: 2,
            challenge_window_blocks: 100,
            duplicate_analysis_required: true,
        })
    }

    fn recipe(dataset: &DatasetSnapshot, trainer_cluster: Hash32) -> TrainingRecipe {
        let evaluator_clusters = vec![h(42), h(43)];
        assert!(!evaluator_clusters.contains(&trainer_cluster));
        TrainingRecipe::new(
            h(32),
            dataset.dataset_id,
            h(33),
            h(34),
            h(35),
            h(36),
            h(37),
            h(38),
            h(39),
            h(32),
            h(40),
            16,
            1_000_000,
            1_000,
            32,
            1 << 20,
            2 << 20,
            auditable_lane(),
            h(41),
            evaluator_clusters,
            101,
            &Keypair::from_seed([4; 32]),
        )
        .unwrap()
    }

    fn species_packet(recipe: &TrainingRecipe, dataset: &DatasetSnapshot) -> UpdatePacket {
        let mut packet = UpdatePacket {
            packet_id: [0; 32],
            base_members: vec![recipe.parent_revision_id],
            update_kind: UpdateKind::LowRank,
            payload: h(50),
            applicability_predicate: h(51),
            tokenizer: recipe.tokenizer_root,
            numeric_profile: recipe.numeric_profile_root,
            training_recipe: Some(recipe.recipe_id),
            source_capsules: vec![h(52)],
            policy_version: Some(1),
            privacy_parameters_root: Some(h(53)),
            rights_expression: dataset.rights_policy_root,
            provenance_root: dataset.dataset_id,
            availability_commitments: vec![h(54)],
            contributor_set: vec![h(55)],
            evaluation_receipts: Vec::new(),
            expiry: Some(1_000),
        };
        packet.packet_id = packet.derived_id();
        packet
    }

    #[test]
    fn rights_clean_dataset_commits_split_and_private_canaries() {
        let (graph, ids) = candidate_graph();
        let dataset = dataset(&graph, &ids);
        dataset.validate(&graph).unwrap();
        let mut swapped = dataset.clone();
        std::mem::swap(&mut swapped.train_ids, &mut swapped.evaluation_ids);
        assert_eq!(
            swapped.validate(&graph),
            Err(WwmTrainingError::InvalidDataset)
        );

        let empty_graph = KnowledgeGraph::default();
        assert_eq!(
            dataset.validate(&empty_graph),
            Err(WwmTrainingError::RightsViolation)
        );
        assert_ne!(dataset.private_canary_commitment, [0; 32]);
    }

    #[test]
    fn bounded_recipe_rejects_role_overlap_and_oversized_adapter() {
        let (graph, ids) = candidate_graph();
        let dataset = dataset(&graph, &ids);
        let recipe = recipe(&dataset, h(44));
        recipe.validate(&dataset).unwrap();

        let mut oversized = recipe.clone();
        oversized.adapter_rank = MAX_ADAPTER_RANK + 1;
        assert_eq!(
            oversized.validate(&dataset),
            Err(WwmTrainingError::InvalidRecipe)
        );
        assert_eq!(
            AdapterJob::accept(
                &recipe,
                h(45),
                h(42),
                110,
                200,
                &Keypair::from_seed([5; 32])
            ),
            Err(WwmTrainingError::InvalidJob)
        );
    }

    #[test]
    fn checkpoint_packet_and_signed_receipt_are_immutable_and_linked() {
        let (graph, ids) = candidate_graph();
        let dataset = dataset(&graph, &ids);
        let trainer = Keypair::from_seed([5; 32]);
        let recipe = recipe(&dataset, h(44));
        let job = AdapterJob::accept(&recipe, h(45), h(44), 110, 200, &trainer).unwrap();
        let checkpoints = vec![
            AdapterCheckpoint {
                sequence: 0,
                checkpoint_root: h(49),
                parent_checkpoint_root: None,
                optimizer_state_root: h(60),
                examples_seen: 100,
            },
            AdapterCheckpoint {
                sequence: 1,
                checkpoint_root: h(50),
                parent_checkpoint_root: Some(h(49)),
                optimizer_state_root: h(61),
                examples_seen: 200,
            },
        ];
        let update = AdapterUpdatePacket::new(
            &recipe,
            &dataset,
            h(62),
            species_packet(&recipe, &dataset),
            checkpoints,
        )
        .unwrap();
        let evidence = TrainingLaneEvidence::Auditable(
            AuditableUpdateEvidence::new(
                vec![h(70), h(71)],
                vec![h(72), h(73)],
                h(74),
                h(75),
                h(76),
            )
            .unwrap(),
        );
        let receipt = TrainerReceipt::issue(
            &job,
            &recipe,
            &update,
            &evidence,
            h(77),
            h(78),
            h(79),
            h(80),
            1_000,
            200,
            111,
            190,
            &trainer,
        )
        .unwrap();
        receipt.validate(&job, &recipe, &update, &evidence).unwrap();

        let mut tampered = receipt.clone();
        tampered.examples_seen = 201;
        assert_eq!(
            tampered.validate(&job, &recipe, &update, &evidence),
            Err(WwmTrainingError::InvalidReceipt)
        );
    }

    #[test]
    fn confidential_lane_enforces_dropout_and_never_claims_attribution() {
        let policy = ConfidentialCohortPolicy {
            secure_aggregation_protocol_root: h(81),
            range_proof_profile_root: h(82),
            aggregate_canary_root: h(83),
            minimum_cohort_size: 32,
            maximum_dropout_bps: 2_500,
            declared_byzantine_limit_bps: 2_000,
            contribution_limit: 1,
            clipping_norm_q20: 2 << 20,
            abort_on_threshold_loss: true,
        };
        let lane = TrainingLanePolicy::ConfidentialCohort(policy.clone());
        lane.validate().unwrap();
        assert!(!lane.exposes_individual_updates_to_authorized_evaluators());
        assert!(!lane.supports_individual_fault_attribution());
        assert!(!lane.activation_eligible());

        let evidence =
            ConfidentialCohortEvidence::new(&policy, h(84), h(85), h(86), h(87), h(88), 40, 32)
                .unwrap();
        assert!(!evidence.individual_attribution_available);
        assert_eq!(
            ConfidentialCohortEvidence::new(&policy, h(84), h(85), h(86), h(87), h(88), 40, 29,),
            Err(WwmTrainingError::InvalidLaneEvidence)
        );
    }

    #[test]
    fn registry_is_insert_once_and_has_no_production_promotion_path() {
        let (graph, ids) = candidate_graph();
        let dataset = dataset(&graph, &ids);
        let trainer = Keypair::from_seed([5; 32]);
        let recipe = recipe(&dataset, h(44));
        let job = AdapterJob::accept(&recipe, h(45), h(44), 110, 200, &trainer).unwrap();
        let checkpoints = vec![AdapterCheckpoint {
            sequence: 0,
            checkpoint_root: h(50),
            parent_checkpoint_root: None,
            optimizer_state_root: h(60),
            examples_seen: 200,
        }];
        let update = AdapterUpdatePacket::new(
            &recipe,
            &dataset,
            h(62),
            species_packet(&recipe, &dataset),
            checkpoints,
        )
        .unwrap();
        let evidence = TrainingLaneEvidence::Auditable(
            AuditableUpdateEvidence::new(vec![h(70)], vec![h(72)], h(74), h(75), h(76)).unwrap(),
        );
        let receipt = TrainerReceipt::issue(
            &job,
            &recipe,
            &update,
            &evidence,
            h(77),
            h(78),
            h(79),
            h(80),
            1_000,
            200,
            111,
            190,
            &trainer,
        )
        .unwrap();
        let mut registry = ShadowRegistry::default();
        let candidate = registry
            .register(
                &graph, &dataset, &recipe, &job, &update, &evidence, &receipt,
            )
            .unwrap();
        assert_eq!(candidate.state, CandidateTrainingState::ShadowOnly);
        assert_eq!(
            registry.register(&graph, &dataset, &recipe, &job, &update, &evidence, &receipt),
            Err(WwmTrainingError::DuplicateObject)
        );
        assert_eq!(
            registry.promote_to_serving(update.candidate_revision_id),
            Err(WwmTrainingError::PromotionDisabled)
        );
        assert!(!WWM_TRAINING_PROMOTION_ENABLED);
        assert_eq!(WWM_TRAINING_CONSENSUS_WEIGHT, 0);
        assert_eq!(WWM_TRAINING_FINALITY_WEIGHT, 0);
    }
}
