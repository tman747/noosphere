//! Immutable Species application registry.
//!
//! Species claims are application evidence. They never alter consensus,
//! execution correctness, or quality, and tolerance claims never compose.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];
pub type Height = u64;

pub mod domains {
    pub const ARTIFACT: &str = "NOOS/ARTIFACT/V1";
    pub const SPECIES: &str = "NOOS/SPECIES/V1";
    pub const REVISION: &str = "NOOS/SPECIES/REVISION/V1";
    pub const CLAIM: &str = "NOOS/SPECIES/EQUIVALENCE/V1";
    pub const UPDATE: &str = "NOOS/SPECIES/UPDATE/V1";
    pub const LEARNING_RECORD: &str = "NOOS/SPECIES/LEARNING-RECORD/V1";
}

#[must_use]
pub fn domain_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    for part in parts {
        h.update(part);
    }
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactKind {
    WeightShard,
    Adapter,
    Tokenizer,
    DatasetShard,
    Environment,
    Evaluator,
    Trace,
    Proof,
    Program,
    Index,
    MemoryCapsule,
    UpdatePacket,
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub artifact_id: Hash32,
    pub kind: ArtifactKind,
    pub media_type: String,
    pub byte_length: u64,
    pub chunking_profile: Hash32,
    pub availability_root: Hash32,
    pub encoding: Hash32,
    pub numeric_profile: Option<Hash32>,
    pub encryption_profile: Option<Hash32>,
    pub rights_root: Hash32,
    pub creator: Hash32,
    pub created_at: Height,
    pub annotations_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rounding {
    TowardZero,
    TowardNegativeInfinity,
    NearestTiesEven,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NanPolicy {
    Reject,
    Canonicalize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumericProfile {
    pub profile_id: Hash32,
    pub accumulation_order_root: Hash32,
    pub rounding: Rounding,
    pub saturation: bool,
    pub prng_derivation_root: Hash32,
    pub sampling_root: Hash32,
    pub termination_root: Hash32,
    pub tensor_encoding_root: Hash32,
    pub nan_policy: NanPolicy,
    pub allowed_kernel_substitutions: BTreeSet<Hash32>,
    pub independent_implementations: u16,
    pub conformance_tested: bool,
}
impl NumericProfile {
    #[must_use]
    pub fn execution_slashing_eligible(&self) -> bool {
        self.conformance_tested && self.independent_implementations >= 2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionAssurance {
    V0,
    V1,
    V2,
    V3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityEvidence {
    Q0,
    Q1,
    Q2,
    Q3,
    Q4,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidentiality {
    Plaintext,
    AccessControlled,
    Tee,
    Mpc,
    Fhe,
    ZkDisclosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingProfile {
    pub profile_id: Hash32,
    pub numeric_profile_id: Hash32,
    pub topology_root: Hash32,
    pub latency_ceiling_ms: u32,
    pub execution_assurance: ExecutionAssurance,
    pub quality_evidence: QualityEvidence,
    pub confidentiality: Confidentiality,
    pub execution_evidence_root: Hash32,
    pub quality_evidence_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeciesManifest {
    pub species_id: Hash32,
    pub manifest_version: u64,
    pub domain: Hash32,
    pub input_schema: Hash32,
    pub output_schema: Hash32,
    pub tokenizer_relation: Hash32,
    pub behavioral_relations: Vec<Hash32>,
    pub conformance_suites: Vec<Hash32>,
    pub evaluator_policies: Vec<Hash32>,
    pub admissible_numeric_profiles: BTreeSet<Hash32>,
    pub minimum_availability: Hash32,
    pub minimum_rights: Hash32,
    pub promotion_rule: Hash32,
    pub safety_constraints: Vec<Hash32>,
    pub predecessor: Option<Hash32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionLifecycle {
    Proposed,
    Available,
    Evaluated,
    Challengeable,
    Admitted,
    Quarantined,
    Revoked,
    Superseded,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeciesRevision {
    pub revision_id: Hash32,
    pub species_id: Hash32,
    pub manifest_version: u64,
    pub composition_root: Hash32,
    pub required_artifacts: Vec<Hash32>,
    pub execution_manifest: Hash32,
    pub relation_claims: Vec<Hash32>,
    pub serving_profiles: Vec<Hash32>,
    pub availability_certificate: Hash32,
    pub rights_certificate: Hash32,
    pub lifecycle: RevisionLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    CanonicalObservationEqual,
    BitExact,
    LogitTolerance,
    DistributionDistance,
    TaskScoreBand,
    SafetyNonregression,
    InterchangeableToolAbi,
}
impl Relation {
    #[must_use]
    pub fn is_exact_equivalence(self) -> bool {
        matches!(
            self,
            Self::CanonicalObservationEqual | Self::BitExact | Self::InterchangeableToolAbi
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivalenceClaim {
    pub claim_id: Hash32,
    pub species_id: Hash32,
    pub candidate: Hash32,
    pub reference_set: Vec<Hash32>,
    pub relation: Relation,
    pub domain_slice: Hash32,
    pub numeric_profile: Hash32,
    pub test_commitment: Hash32,
    pub result_commitment: Hash32,
    pub evaluator_receipts: Vec<Hash32>,
    pub confidence_statement: String,
    pub valid_from: Height,
    pub expires_at: Option<Height>,
    pub challenger_bond: u128,
}
impl EquivalenceClaim {
    #[must_use]
    pub fn applies_directionally(
        &self,
        candidate: &Hash32,
        reference: &Hash32,
        height: Height,
    ) -> bool {
        &self.candidate == candidate
            && self.reference_set.contains(reference)
            && height >= self.valid_from
            && self.expires_at.is_none_or(|expiry| height < expiry)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateKind {
    LowRank,
    SparseDelta,
    GradientSketch,
    PreferenceBatch,
    TrajectoryBatch,
    DistillationBatch,
    EvaluatorPatch,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePacket {
    pub packet_id: Hash32,
    pub base_members: Vec<Hash32>,
    pub update_kind: UpdateKind,
    pub payload: Hash32,
    pub applicability_predicate: Hash32,
    pub tokenizer: Hash32,
    pub numeric_profile: Hash32,
    pub training_recipe: Option<Hash32>,
    pub source_capsules: Vec<Hash32>,
    pub policy_version: Option<u64>,
    pub privacy_parameters_root: Option<Hash32>,
    pub rights_expression: Hash32,
    pub contributor_set: Vec<Hash32>,
    pub evaluation_receipts: Vec<Hash32>,
    pub expiry: Option<Height>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningDecision {
    Accepted,
    Rejected,
    Quarantined,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningRecord {
    pub record_id: Hash32,
    pub packet_id: Hash32,
    pub base_revision: Hash32,
    pub decision: LearningDecision,
    pub evidence_root: Hash32,
    pub decided_at: Height,
    pub promoted_revision: Option<Hash32>,
}
impl LearningRecord {
    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.decision == LearningDecision::Accepted && self.promoted_revision.is_none() {
            return Err(SpeciesError::PromotionRequiresNewRevision);
        }
        if self.decision != LearningDecision::Accepted && self.promoted_revision.is_some() {
            return Err(SpeciesError::InvalidLearningRecord);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendationRequest {
    pub species_id: Hash32,
    pub required_relation: Relation,
    pub minimum_execution: ExecutionAssurance,
    pub minimum_quality: QualityEvidence,
    pub rights_context: Hash32,
    pub privacy_context: Confidentiality,
    pub topology: Hash32,
    pub latency_ceiling_ms: u32,
    pub budget: u128,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recommendation {
    pub revision_id: Hash32,
    pub serving_profile_id: Hash32,
    pub rank: u32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpeciesError {
    DuplicateId,
    UnknownSpecies,
    UnknownNumericProfile,
    UnknownServingProfile,
    InvalidManifest,
    InvalidRevision,
    InvalidClaim,
    InvalidLearningRecord,
    PromotionRequiresNewRevision,
    MutableCurrentWeightsForbidden,
    ToleranceTransitivityForbidden,
    ConsensusEvidenceForbidden,
}

#[derive(Debug, Default)]
pub struct Registry {
    artifacts: BTreeMap<Hash32, Artifact>,
    manifests: BTreeMap<Hash32, SpeciesManifest>,
    revisions: BTreeMap<Hash32, SpeciesRevision>,
    claims: BTreeMap<Hash32, EquivalenceClaim>,
    numeric_profiles: BTreeMap<Hash32, NumericProfile>,
    serving_profiles: BTreeMap<Hash32, ServingProfile>,
    updates: BTreeMap<Hash32, UpdatePacket>,
    learning_records: BTreeMap<Hash32, LearningRecord>,
}

fn insert_once<T>(map: &mut BTreeMap<Hash32, T>, id: Hash32, value: T) -> Result<(), SpeciesError> {
    if map.contains_key(&id) {
        return Err(SpeciesError::DuplicateId);
    }
    map.insert(id, value);
    Ok(())
}

impl Registry {
    pub fn register_artifact(&mut self, value: Artifact) -> Result<(), SpeciesError> {
        if value.media_type.is_empty() {
            return Err(SpeciesError::InvalidManifest);
        }
        insert_once(&mut self.artifacts, value.artifact_id, value)
    }
    pub fn register_numeric_profile(&mut self, value: NumericProfile) -> Result<(), SpeciesError> {
        insert_once(&mut self.numeric_profiles, value.profile_id, value)
    }
    pub fn register_serving_profile(&mut self, value: ServingProfile) -> Result<(), SpeciesError> {
        if !self
            .numeric_profiles
            .contains_key(&value.numeric_profile_id)
        {
            return Err(SpeciesError::UnknownNumericProfile);
        }
        insert_once(&mut self.serving_profiles, value.profile_id, value)
    }
    pub fn register_manifest(&mut self, value: SpeciesManifest) -> Result<(), SpeciesError> {
        if value.manifest_version == 0
            || value.admissible_numeric_profiles.is_empty()
            || value
                .admissible_numeric_profiles
                .iter()
                .any(|id| !self.numeric_profiles.contains_key(id))
        {
            return Err(SpeciesError::InvalidManifest);
        }
        insert_once(&mut self.manifests, value.species_id, value)
    }
    pub fn register_revision(&mut self, value: SpeciesRevision) -> Result<(), SpeciesError> {
        let manifest = self
            .manifests
            .get(&value.species_id)
            .ok_or(SpeciesError::UnknownSpecies)?;
        if manifest.manifest_version != value.manifest_version
            || value.serving_profiles.is_empty()
            || value
                .serving_profiles
                .iter()
                .any(|id| !self.serving_profiles.contains_key(id))
        {
            return Err(SpeciesError::InvalidRevision);
        }
        insert_once(&mut self.revisions, value.revision_id, value)
    }
    pub fn register_claim(&mut self, value: EquivalenceClaim) -> Result<(), SpeciesError> {
        if !self.revisions.contains_key(&value.candidate)
            || value.reference_set.is_empty()
            || value
                .reference_set
                .iter()
                .any(|id| !self.revisions.contains_key(id))
            || value
                .expires_at
                .is_some_and(|expiry| expiry <= value.valid_from)
        {
            return Err(SpeciesError::InvalidClaim);
        }
        insert_once(&mut self.claims, value.claim_id, value)
    }
    pub fn infer_transitive_claim(
        &self,
        _: Hash32,
        _: Hash32,
        relation: Relation,
    ) -> Result<(), SpeciesError> {
        if !relation.is_exact_equivalence() {
            return Err(SpeciesError::ToleranceTransitivityForbidden);
        }
        Err(SpeciesError::InvalidClaim)
    }
    pub fn register_update(&mut self, value: UpdatePacket) -> Result<(), SpeciesError> {
        if value.base_members.is_empty()
            || value
                .base_members
                .iter()
                .any(|id| !self.revisions.contains_key(id))
        {
            return Err(SpeciesError::InvalidRevision);
        }
        insert_once(&mut self.updates, value.packet_id, value)
    }
    pub fn record_learning(&mut self, value: LearningRecord) -> Result<(), SpeciesError> {
        value.validate()?;
        if !self.updates.contains_key(&value.packet_id)
            || !self.revisions.contains_key(&value.base_revision)
            || value
                .promoted_revision
                .is_some_and(|id| !self.revisions.contains_key(&id))
        {
            return Err(SpeciesError::InvalidLearningRecord);
        }
        insert_once(&mut self.learning_records, value.record_id, value)
    }
    pub fn set_current_weights(&mut self, _: Hash32, _: Hash32) -> Result<(), SpeciesError> {
        Err(SpeciesError::MutableCurrentWeightsForbidden)
    }
    pub fn grant_consensus_weight(&self, _: Hash32) -> Result<(), SpeciesError> {
        Err(SpeciesError::ConsensusEvidenceForbidden)
    }
    #[must_use]
    pub fn revision(&self, id: &Hash32) -> Option<&SpeciesRevision> {
        self.revisions.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash32 {
        [n; 32]
    }
    fn numeric() -> NumericProfile {
        NumericProfile {
            profile_id: h(1),
            accumulation_order_root: h(2),
            rounding: Rounding::TowardZero,
            saturation: true,
            prng_derivation_root: h(3),
            sampling_root: h(4),
            termination_root: h(5),
            tensor_encoding_root: h(6),
            nan_policy: NanPolicy::Reject,
            allowed_kernel_substitutions: BTreeSet::new(),
            independent_implementations: 2,
            conformance_tested: true,
        }
    }
    fn manifest() -> SpeciesManifest {
        SpeciesManifest {
            species_id: h(10),
            manifest_version: 1,
            domain: h(11),
            input_schema: h(12),
            output_schema: h(13),
            tokenizer_relation: h(14),
            behavioral_relations: vec![h(15)],
            conformance_suites: vec![h(16)],
            evaluator_policies: vec![h(17)],
            admissible_numeric_profiles: BTreeSet::from([h(1)]),
            minimum_availability: h(18),
            minimum_rights: h(19),
            promotion_rule: h(20),
            safety_constraints: vec![],
            predecessor: None,
        }
    }
    fn serving(id: u8) -> ServingProfile {
        ServingProfile {
            profile_id: h(id),
            numeric_profile_id: h(1),
            topology_root: h(22),
            latency_ceiling_ms: 50,
            execution_assurance: ExecutionAssurance::V1,
            quality_evidence: QualityEvidence::Q0,
            confidentiality: Confidentiality::Plaintext,
            execution_evidence_root: h(23),
            quality_evidence_root: h(24),
        }
    }
    fn revision(id: u8) -> SpeciesRevision {
        SpeciesRevision {
            revision_id: h(id),
            species_id: h(10),
            manifest_version: 1,
            composition_root: h(30),
            required_artifacts: vec![],
            execution_manifest: h(31),
            relation_claims: vec![],
            serving_profiles: vec![h(21)],
            availability_certificate: h(32),
            rights_certificate: h(33),
            lifecycle: RevisionLifecycle::Admitted,
        }
    }
    fn registry() -> Registry {
        let mut r = Registry::default();
        assert!(r.register_numeric_profile(numeric()).is_ok());
        assert!(r.register_serving_profile(serving(21)).is_ok());
        assert!(r.register_manifest(manifest()).is_ok());
        r
    }
    #[test]
    fn profile_slashing_needs_two_implementations() {
        let mut p = numeric();
        p.independent_implementations = 1;
        assert!(!p.execution_slashing_eligible());
        p.independent_implementations = 2;
        assert!(p.execution_slashing_eligible());
    }
    #[test]
    fn immutable_registry_rejects_duplicate() {
        let mut r = registry();
        assert_eq!(
            r.register_manifest(manifest()),
            Err(SpeciesError::DuplicateId)
        );
    }
    #[test]
    fn no_current_weights() {
        assert_eq!(
            registry().set_current_weights(h(10), h(30)),
            Err(SpeciesError::MutableCurrentWeightsForbidden)
        );
    }
    #[test]
    fn tolerance_does_not_compose() {
        assert_eq!(
            registry().infer_transitive_claim(h(1), h(2), Relation::LogitTolerance),
            Err(SpeciesError::ToleranceTransitivityForbidden)
        );
    }
    #[test]
    fn evidence_has_no_consensus_hook() {
        assert_eq!(
            registry().grant_consensus_weight(h(1)),
            Err(SpeciesError::ConsensusEvidenceForbidden)
        );
    }
    #[test]
    fn revision_requires_known_serving_profile() {
        let mut r = registry();
        let mut v = revision(40);
        v.serving_profiles = vec![h(99)];
        assert_eq!(r.register_revision(v), Err(SpeciesError::InvalidRevision));
    }
    #[test]
    fn directional_claim_does_not_reverse() {
        let c = EquivalenceClaim {
            claim_id: h(1),
            species_id: h(2),
            candidate: h(3),
            reference_set: vec![h(4)],
            relation: Relation::TaskScoreBand,
            domain_slice: h(5),
            numeric_profile: h(6),
            test_commitment: h(7),
            result_commitment: h(8),
            evaluator_receipts: vec![],
            confidence_statement: "bounded".into(),
            valid_from: 10,
            expires_at: Some(20),
            challenger_bond: 1,
        };
        assert!(c.applies_directionally(&h(3), &h(4), 10));
        assert!(!c.applies_directionally(&h(4), &h(3), 10));
        assert!(!c.applies_directionally(&h(3), &h(4), 20));
    }
    #[test]
    fn accepted_update_requires_new_revision() {
        let rec = LearningRecord {
            record_id: h(1),
            packet_id: h(2),
            base_revision: h(3),
            decision: LearningDecision::Accepted,
            evidence_root: h(4),
            decided_at: 5,
            promoted_revision: None,
        };
        assert_eq!(
            rec.validate(),
            Err(SpeciesError::PromotionRequiresNewRevision)
        );
    }
}
