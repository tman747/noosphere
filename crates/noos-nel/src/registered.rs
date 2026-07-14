//! Admission contracts for the registered 494M W8A8 inference campaign.
//!
//! This module does not pretend that a local fixture is a production backend.
//! It binds the complete external profile, shard residency, implementation
//! lineage, and signed conformance transcripts. Public scheduling remains hard
//! disabled until independent E-WWM-01 evidence passes the release gate.

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::BTreeSet;

use crate::Hash32;

pub const REGISTERED_PARAMETER_COUNT: u64 = 494_000_000;
pub const REQUIRED_OPERATOR_INSTANCES: u64 = 1_000_000_000;
pub const REQUIRED_IMPLEMENTATION_FAMILIES: usize = 4;
pub const MAX_WEIGHT_SHARDS: usize = 4_096;
pub const WWM_REGISTERED_INFERENCE_ENABLED: bool = false;
pub const WWM_INFERENCE_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredInferenceError {
    InvalidProfile,
    InvalidResidency,
    InvalidTranscript,
    InvalidSignature,
    DuplicateImplementation,
    CommonLineage,
    MissingImplementationFamily,
    TranscriptMismatch,
    Underpowered,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredShape {
    pub parameter_count: u64,
    pub hidden_size: u32,
    pub layer_count: u16,
    pub query_heads: u16,
    pub kv_heads: u16,
    pub head_dimension: u16,
    pub intermediate_size: u32,
    pub vocabulary_size: u32,
    pub maximum_context: u32,
}

impl RegisteredShape {
    #[must_use]
    pub const fn qwen2_5_half_billion() -> Self {
        Self {
            parameter_count: REGISTERED_PARAMETER_COUNT,
            hidden_size: 896,
            layer_count: 24,
            query_heads: 14,
            kv_heads: 2,
            head_dimension: 64,
            intermediate_size: 4_864,
            vocabulary_size: 151_936,
            maximum_context: 32_768,
        }
    }

    fn validate(self) -> Result<(), RegisteredInferenceError> {
        if self != Self::qwen2_5_half_billion() {
            return Err(RegisteredInferenceError::InvalidProfile);
        }
        Ok(())
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.extend(self.parameter_count.to_le_bytes());
        out.extend(self.hidden_size.to_le_bytes());
        out.extend(self.layer_count.to_le_bytes());
        out.extend(self.query_heads.to_le_bytes());
        out.extend(self.kv_heads.to_le_bytes());
        out.extend(self.head_dimension.to_le_bytes());
        out.extend(self.intermediate_size.to_le_bytes());
        out.extend(self.vocabulary_size.to_le_bytes());
        out.extend(self.maximum_context.to_le_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredInferenceProfile {
    pub shape: RegisteredShape,
    pub source_checkpoint_root: Hash32,
    pub weight_manifest_root: Hash32,
    pub tokenizer_root: Hash32,
    pub calibration_root: Hash32,
    pub numeric_profile_root: Hash32,
    pub operator_set_root: Hash32,
    pub kv_semantics_root: Hash32,
    pub greedy_decode_root: Hash32,
    pub conformance_suite_root: Hash32,
    pub compiler_matrix_root: Hash32,
    pub profile_id: Hash32,
}

impl RegisteredInferenceProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_checkpoint_root: Hash32,
        weight_manifest_root: Hash32,
        tokenizer_root: Hash32,
        calibration_root: Hash32,
        numeric_profile_root: Hash32,
        operator_set_root: Hash32,
        kv_semantics_root: Hash32,
        greedy_decode_root: Hash32,
        conformance_suite_root: Hash32,
        compiler_matrix_root: Hash32,
    ) -> Result<Self, RegisteredInferenceError> {
        let mut value = Self {
            shape: RegisteredShape::qwen2_5_half_billion(),
            source_checkpoint_root,
            weight_manifest_root,
            tokenizer_root,
            calibration_root,
            numeric_profile_root,
            operator_set_root,
            kv_semantics_root,
            greedy_decode_root,
            conformance_suite_root,
            compiler_matrix_root,
            profile_id: [0; 32],
        };
        value.profile_id = value.derived_id()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RegisteredInferenceError> {
        self.shape.validate()?;
        if self.roots().iter().any(|root| **root == [0; 32])
            || self.profile_id == [0; 32]
            || self.derived_id()? != self.profile_id
        {
            return Err(RegisteredInferenceError::InvalidProfile);
        }
        Ok(())
    }

    fn roots(&self) -> [&Hash32; 10] {
        [
            &self.source_checkpoint_root,
            &self.weight_manifest_root,
            &self.tokenizer_root,
            &self.calibration_root,
            &self.numeric_profile_root,
            &self.operator_set_root,
            &self.kv_semantics_root,
            &self.greedy_decode_root,
            &self.conformance_suite_root,
            &self.compiler_matrix_root,
        ]
    }

    fn body(&self) -> Result<Vec<u8>, RegisteredInferenceError> {
        self.shape.validate()?;
        if self.roots().iter().any(|root| **root == [0; 32]) {
            return Err(RegisteredInferenceError::InvalidProfile);
        }
        let mut body = Vec::with_capacity(346);
        body.extend(1_u16.to_le_bytes());
        self.shape.encode(&mut body);
        for root in self.roots() {
            body.extend(root);
        }
        Ok(body)
    }

    fn derived_id(&self) -> Result<Hash32, RegisteredInferenceError> {
        let body = self.body()?;
        digest(DomainId::WwmInferenceProfile, &[&body])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentShard {
    pub shard_root: Hash32,
    pub expected_bytes: u32,
    pub resident_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightResidency {
    pub profile_id: Hash32,
    pub manifest_root: Hash32,
    pub shards: Vec<ResidentShard>,
}

impl WeightResidency {
    pub fn validate(
        &self,
        profile: &RegisteredInferenceProfile,
    ) -> Result<u64, RegisteredInferenceError> {
        profile.validate()?;
        if self.profile_id != profile.profile_id
            || self.manifest_root != profile.weight_manifest_root
            || self.shards.is_empty()
            || self.shards.len() > MAX_WEIGHT_SHARDS
        {
            return Err(RegisteredInferenceError::InvalidResidency);
        }
        let mut prior = None;
        let mut total = 0_u64;
        for shard in &self.shards {
            if shard.shard_root == [0; 32]
                || shard.expected_bytes == 0
                || shard.resident_bytes != shard.expected_bytes
                || prior.is_some_and(|root| root >= shard.shard_root)
            {
                return Err(RegisteredInferenceError::InvalidResidency);
            }
            prior = Some(shard.shard_root);
            total = total
                .checked_add(u64::from(shard.resident_bytes))
                .ok_or(RegisteredInferenceError::ArithmeticOverflow)?;
        }
        Ok(total)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ImplementationFamily {
    CpuReference = 1,
    CpuIndependent = 2,
    AmdIntegerKernel = 3,
    NvidiaIntegerKernel = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplementationTranscript {
    pub profile_id: Hash32,
    pub implementation_key: Hash32,
    pub implementation_family: ImplementationFamily,
    pub source_lineage_root: Hash32,
    pub binary_root: Hash32,
    pub environment_root: Hash32,
    pub fixture_root: Hash32,
    pub tokenizer_transcript_root: Hash32,
    pub operator_transcript_root: Hash32,
    pub kv_transcript_root: Hash32,
    pub logits_root: Hash32,
    pub token_history_root: Hash32,
    pub operator_instances: u64,
    pub mismatch_count: u64,
    pub transcript_id: Hash32,
    pub signature: [u8; 64],
}

impl ImplementationTranscript {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: &Keypair,
        profile_id: Hash32,
        implementation_family: ImplementationFamily,
        source_lineage_root: Hash32,
        binary_root: Hash32,
        environment_root: Hash32,
        fixture_root: Hash32,
        tokenizer_transcript_root: Hash32,
        operator_transcript_root: Hash32,
        kv_transcript_root: Hash32,
        logits_root: Hash32,
        token_history_root: Hash32,
        operator_instances: u64,
        mismatch_count: u64,
    ) -> Result<Self, RegisteredInferenceError> {
        let mut value = Self {
            profile_id,
            implementation_key: signer.public_key().into_bytes(),
            implementation_family,
            source_lineage_root,
            binary_root,
            environment_root,
            fixture_root,
            tokenizer_transcript_root,
            operator_transcript_root,
            kv_transcript_root,
            logits_root,
            token_history_root,
            operator_instances,
            mismatch_count,
            transcript_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.transcript_id = digest(DomainId::WwmInferenceTranscript, &[&body])?;
        value.signature = signer
            .sign_domain(
                DomainId::SigWwm,
                &[
                    DomainId::WwmInferenceTranscript.registry_id().as_bytes(),
                    &value.transcript_id,
                    &body,
                ],
            )
            .map_err(|_| RegisteredInferenceError::InvalidSignature)?
            .into_bytes();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RegisteredInferenceError> {
        let body = self.body()?;
        let expected = digest(DomainId::WwmInferenceTranscript, &[&body])?;
        if expected != self.transcript_id || self.transcript_id == [0; 32] {
            return Err(RegisteredInferenceError::InvalidTranscript);
        }
        verify_domain(
            DomainId::SigWwm,
            &PublicKey::from_bytes(self.implementation_key),
            &[
                DomainId::WwmInferenceTranscript.registry_id().as_bytes(),
                &self.transcript_id,
                &body,
            ],
            &Signature::from_bytes(self.signature),
        )
        .map_err(|_| RegisteredInferenceError::InvalidSignature)
    }

    fn body(&self) -> Result<Vec<u8>, RegisteredInferenceError> {
        if self.profile_id == [0; 32]
            || self.implementation_key == [0; 32]
            || self.source_lineage_root == [0; 32]
            || self.binary_root == [0; 32]
            || self.environment_root == [0; 32]
            || self.fixture_root == [0; 32]
            || self.tokenizer_transcript_root == [0; 32]
            || self.operator_transcript_root == [0; 32]
            || self.kv_transcript_root == [0; 32]
            || self.logits_root == [0; 32]
            || self.token_history_root == [0; 32]
            || self.operator_instances == 0
        {
            return Err(RegisteredInferenceError::InvalidTranscript);
        }
        let mut body = Vec::with_capacity(412);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.profile_id);
        body.extend(self.implementation_key);
        body.push(self.implementation_family as u8);
        body.extend(self.source_lineage_root);
        body.extend(self.binary_root);
        body.extend(self.environment_root);
        body.extend(self.fixture_root);
        body.extend(self.tokenizer_transcript_root);
        body.extend(self.operator_transcript_root);
        body.extend(self.kv_transcript_root);
        body.extend(self.logits_root);
        body.extend(self.token_history_root);
        body.extend(self.operator_instances.to_le_bytes());
        body.extend(self.mismatch_count.to_le_bytes());
        Ok(body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceSummary {
    pub implementations: u8,
    pub operator_instances_per_implementation: u64,
    pub mismatches: u64,
    pub common_transcript_root: Hash32,
}

pub fn verify_conformance_campaign(
    profile: &RegisteredInferenceProfile,
    transcripts: &[ImplementationTranscript],
) -> Result<ConformanceSummary, RegisteredInferenceError> {
    profile.validate()?;
    if transcripts.len() != REQUIRED_IMPLEMENTATION_FAMILIES {
        return Err(RegisteredInferenceError::MissingImplementationFamily);
    }
    let required = BTreeSet::from([
        ImplementationFamily::CpuReference,
        ImplementationFamily::CpuIndependent,
        ImplementationFamily::AmdIntegerKernel,
        ImplementationFamily::NvidiaIntegerKernel,
    ]);
    let mut families = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut lineages = BTreeSet::new();
    let first = transcripts
        .first()
        .ok_or(RegisteredInferenceError::MissingImplementationFamily)?;
    let common = transcript_result_tuple(first);
    let mut mismatches = 0_u64;
    let mut minimum_instances = u64::MAX;
    for transcript in transcripts {
        transcript.validate()?;
        if transcript.profile_id != profile.profile_id {
            return Err(RegisteredInferenceError::TranscriptMismatch);
        }
        if !families.insert(transcript.implementation_family)
            || !keys.insert(transcript.implementation_key)
        {
            return Err(RegisteredInferenceError::DuplicateImplementation);
        }
        if !lineages.insert(transcript.source_lineage_root) {
            return Err(RegisteredInferenceError::CommonLineage);
        }
        if transcript_result_tuple(transcript) != common {
            return Err(RegisteredInferenceError::TranscriptMismatch);
        }
        minimum_instances = minimum_instances.min(transcript.operator_instances);
        mismatches = mismatches
            .checked_add(transcript.mismatch_count)
            .ok_or(RegisteredInferenceError::ArithmeticOverflow)?;
    }
    if families != required {
        return Err(RegisteredInferenceError::MissingImplementationFamily);
    }
    if minimum_instances < REQUIRED_OPERATOR_INSTANCES || mismatches != 0 {
        return Err(RegisteredInferenceError::Underpowered);
    }
    let common_transcript_root = digest(
        DomainId::WwmInferenceTranscript,
        &[
            &common.0,
            &common.1,
            &common.2,
            &common.3,
            &common.4,
            &first.fixture_root,
        ],
    )?;
    Ok(ConformanceSummary {
        implementations: u8::try_from(transcripts.len())
            .map_err(|_| RegisteredInferenceError::ArithmeticOverflow)?,
        operator_instances_per_implementation: minimum_instances,
        mismatches,
        common_transcript_root,
    })
}

fn transcript_result_tuple(
    value: &ImplementationTranscript,
) -> (Hash32, Hash32, Hash32, Hash32, Hash32) {
    (
        value.tokenizer_transcript_root,
        value.operator_transcript_root,
        value.kv_transcript_root,
        value.logits_root,
        value.token_history_root,
    )
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, RegisteredInferenceError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| RegisteredInferenceError::InvalidProfile)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        clippy::unwrap_used
    )]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn profile() -> RegisteredInferenceProfile {
        RegisteredInferenceProfile::new(h(1), h(2), h(3), h(4), h(5), h(6), h(7), h(8), h(9), h(10))
            .unwrap()
    }

    fn transcripts(profile_id: Hash32) -> Vec<ImplementationTranscript> {
        [
            ImplementationFamily::CpuReference,
            ImplementationFamily::CpuIndependent,
            ImplementationFamily::AmdIntegerKernel,
            ImplementationFamily::NvidiaIntegerKernel,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, family)| {
            let seed = u8::try_from(index + 20).unwrap();
            ImplementationTranscript::new(
                &Keypair::from_seed([seed; 32]),
                profile_id,
                family,
                h(seed + 10),
                h(seed + 20),
                h(seed + 30),
                h(50),
                h(51),
                h(52),
                h(53),
                h(54),
                h(55),
                REQUIRED_OPERATOR_INSTANCES,
                0,
            )
            .unwrap()
        })
        .collect()
    }

    #[test]
    fn complete_independent_campaign_meets_admission_contract() {
        let profile = profile();
        let summary =
            verify_conformance_campaign(&profile, &transcripts(profile.profile_id)).unwrap();
        assert_eq!(summary.implementations, 4);
        assert_eq!(summary.mismatches, 0);
        assert_eq!(
            summary.operator_instances_per_implementation,
            REQUIRED_OPERATOR_INSTANCES
        );
    }

    #[test]
    fn mismatch_and_common_lineage_fail_closed() {
        let profile = profile();
        let mut mismatch = transcripts(profile.profile_id);
        mismatch[3].logits_root = h(99);
        assert_eq!(
            verify_conformance_campaign(&profile, &mismatch),
            Err(RegisteredInferenceError::InvalidTranscript)
        );
        let mut common = transcripts(profile.profile_id);
        common[3] = ImplementationTranscript::new(
            &Keypair::from_seed([23; 32]),
            profile.profile_id,
            ImplementationFamily::NvidiaIntegerKernel,
            common[0].source_lineage_root,
            h(90),
            h(91),
            h(50),
            h(51),
            h(52),
            h(53),
            h(54),
            h(55),
            REQUIRED_OPERATOR_INSTANCES,
            0,
        )
        .unwrap();
        assert_eq!(
            verify_conformance_campaign(&profile, &common),
            Err(RegisteredInferenceError::CommonLineage)
        );
    }

    #[test]
    fn residency_requires_complete_distinct_shards() {
        let profile = profile();
        let residency = WeightResidency {
            profile_id: profile.profile_id,
            manifest_root: profile.weight_manifest_root,
            shards: vec![
                ResidentShard {
                    shard_root: h(1),
                    expected_bytes: 4,
                    resident_bytes: 4,
                },
                ResidentShard {
                    shard_root: h(2),
                    expected_bytes: 4,
                    resident_bytes: 4,
                },
            ],
        };
        assert_eq!(residency.validate(&profile).unwrap(), 8);
        let mut incomplete = residency;
        incomplete.shards[1].resident_bytes = 3;
        assert_eq!(
            incomplete.validate(&profile),
            Err(RegisteredInferenceError::InvalidResidency)
        );
    }

    #[test]
    fn registered_inference_cannot_affect_consensus() {
        assert!(!WWM_REGISTERED_INFERENCE_ENABLED);
        assert_eq!(WWM_INFERENCE_CONSENSUS_WEIGHT, 0);
    }
}
