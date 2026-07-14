//! Immutable Species application registry.
//!
//! Species claims are application evidence. They never alter consensus,
//! execution correctness, or quality, and tolerance claims never compose.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub mod activation;
pub mod artifact;
mod canonical;
pub mod capsule;
pub mod quotient;
mod update;

pub use artifact::{
    topology_local_indices, ArtifactShard, DerivationEdge, EncodedArtifact, ErasureProfile,
    ServingTraffic, ShardLocation,
};
pub use capsule::{ModelCapsule, PublisherSignature, WWM_MODEL_ACTIVATION_ENABLED};
pub use quotient::{
    build_finite_quotient, FiniteQuotient, NonTransitiveCounterexample, SuiteMember,
};

pub type Hash32 = [u8; 32];
pub type Height = u64;

pub mod domains {
    pub const ARTIFACT: &str = "NOOS/ARTIFACT/V1";
    pub const SPECIES: &str = "NOOS/SPECIES/V1";
    pub const REVISION: &str = "NOOS/SPECIES/REVISION/V1";
    pub const CLAIM: &str = "NOOS/SPECIES/EQUIVALENCE/V1";
    pub const UPDATE: &str = "NOOS/SPECIES/UPDATE/V1";
    pub const LEARNING_RECORD: &str = "NOOS/SPECIES/LEARNING-RECORD/V1";
    pub const VIEW: &str = "NOOS/SPECIES/VIEW/V1";
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
    pub provenance_root: Hash32,
    pub availability_commitments: Vec<Hash32>,
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
    InvalidCapsule,
    InvalidCapsuleSignature,
    InvalidArtifactSchema,
    ArtifactLengthMismatch,
    ArtifactDigestMismatch,
    ArtifactTooLarge,
    InvalidDerivation,
    UnsupportedErasureProfile,
    InvalidShard,
    PoisonedShard,
    LossBoundExceeded,
    WanPerTokenForbidden,
    UnknownEncoding,
    MalformedEncoding,
    NonCanonicalEncoding,
    InvalidUpdatePacket,
    StalePolicy,
    ExpiredUpdate,
    UnavailableArtifact,
    InvalidQuotientInput,
    CriticalSafetyDivergence,
    NonTransitiveQuotient(NonTransitiveCounterexample),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRelation {
    pub claim_id: Hash32,
    pub candidate: Hash32,
    pub reference: Hash32,
    pub relation: Relation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeciesView {
    pub species_id: Hash32,
    pub numeric_profile: Hash32,
    pub suite: Hash32,
    pub height: Height,
    pub members: Vec<Hash32>,
    pub edges: Vec<ResolvedRelation>,
    pub view_id: Hash32,
}

impl SpeciesView {
    fn derive_id(&self) -> Hash32 {
        let mut parts = Vec::new();
        parts.extend_from_slice(&self.species_id);
        parts.extend_from_slice(&self.numeric_profile);
        parts.extend_from_slice(&self.suite);
        parts.extend_from_slice(&self.height.to_be_bytes());
        parts.extend_from_slice(
            &(u32::try_from(self.members.len()).unwrap_or(u32::MAX)).to_be_bytes(),
        );
        for member in &self.members {
            parts.extend_from_slice(member);
        }
        parts.extend_from_slice(
            &(u32::try_from(self.edges.len()).unwrap_or(u32::MAX)).to_be_bytes(),
        );
        for edge in &self.edges {
            parts.extend_from_slice(&edge.claim_id);
            parts.extend_from_slice(&edge.candidate);
            parts.extend_from_slice(&edge.reference);
            parts.push(match edge.relation {
                Relation::CanonicalObservationEqual => 0,
                Relation::BitExact => 1,
                Relation::LogitTolerance => 2,
                Relation::DistributionDistance => 3,
                Relation::TaskScoreBand => 4,
                Relation::SafetyNonregression => 5,
                Relation::InterchangeableToolAbi => 6,
            });
        }
        domain_hash(domains::VIEW, &[&parts])
    }
}

#[derive(Debug, Default)]
pub struct Registry {
    artifacts: BTreeMap<Hash32, Artifact>,
    artifact_payloads: BTreeMap<Hash32, Vec<u8>>,
    derivations: BTreeMap<Hash32, DerivationEdge>,
    manifests: BTreeMap<Hash32, SpeciesManifest>,
    revisions: BTreeMap<Hash32, SpeciesRevision>,
    claims: BTreeMap<Hash32, EquivalenceClaim>,
    numeric_profiles: BTreeMap<Hash32, NumericProfile>,
    serving_profiles: BTreeMap<Hash32, ServingProfile>,
    updates: BTreeMap<Hash32, UpdatePacket>,
    learning_records: BTreeMap<Hash32, LearningRecord>,
    capsules: BTreeMap<Hash32, ModelCapsule>,
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
        value.validate_schema()?;
        insert_once(&mut self.artifacts, value.artifact_id, value)
    }
    pub fn register_artifact_content(
        &mut self,
        value: Artifact,
        payload: Vec<u8>,
    ) -> Result<(), SpeciesError> {
        value.verify_payload(&payload)?;
        let id = value.artifact_id;
        self.register_artifact(value)?;
        self.artifact_payloads.insert(id, payload);
        Ok(())
    }
    pub fn register_derivation(&mut self, value: DerivationEdge) -> Result<(), SpeciesError> {
        value.validate()?;
        if value
            .parents
            .iter()
            .chain(std::iter::once(&value.output))
            .any(|id| !self.artifact_payloads.contains_key(id))
        {
            return Err(SpeciesError::UnavailableArtifact);
        }
        insert_once(&mut self.derivations, value.edge_id, value)
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
            || !canonical::strictly_sorted(&value.behavioral_relations)
            || !canonical::strictly_sorted(&value.conformance_suites)
            || !canonical::strictly_sorted(&value.evaluator_policies)
            || !canonical::strictly_sorted(&value.safety_constraints)
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
            || !canonical::strictly_sorted(&value.required_artifacts)
            || !canonical::strictly_sorted(&value.relation_claims)
            || !canonical::strictly_sorted(&value.serving_profiles)
            || value
                .serving_profiles
                .iter()
                .any(|id| !self.serving_profiles.contains_key(id))
            || (value.lifecycle == RevisionLifecycle::Admitted
                && (value.required_artifacts.is_empty()
                    || value
                        .required_artifacts
                        .iter()
                        .any(|id| !self.artifact_payloads.contains_key(id))))
        {
            return Err(SpeciesError::InvalidRevision);
        }
        insert_once(&mut self.revisions, value.revision_id, value)
    }
    pub fn register_capsule(&mut self, value: ModelCapsule) -> Result<(), SpeciesError> {
        value.validate()?;
        let revision = self
            .revisions
            .get(&value.revision_id)
            .ok_or(SpeciesError::InvalidCapsule)?;
        if revision.species_id != value.species_id
            || !self
                .numeric_profiles
                .contains_key(&value.numeric_profile_id)
            || !revision
                .required_artifacts
                .contains(&value.weight_manifest_root)
            || !revision.required_artifacts.contains(&value.tokenizer_root)
            || value
                .parents
                .iter()
                .any(|id| !self.revisions.contains_key(id))
            || self
                .revisions
                .get(&value.rollback_revision_id)
                .is_none_or(|rollback| rollback.species_id != value.species_id)
        {
            return Err(SpeciesError::InvalidCapsule);
        }
        insert_once(&mut self.capsules, value.capsule_id, value)
    }

    #[must_use]
    pub fn capsule(&self, id: &Hash32) -> Option<&ModelCapsule> {
        self.capsules.get(id)
    }

    #[must_use]
    pub fn capsules_for_species(&self, species_id: &Hash32) -> Vec<&ModelCapsule> {
        self.capsules
            .values()
            .filter(|capsule| &capsule.species_id == species_id)
            .collect()
    }
    pub fn register_claim(&mut self, value: EquivalenceClaim) -> Result<(), SpeciesError> {
        if !self.revisions.contains_key(&value.candidate)
            || value.reference_set.is_empty()
            || !canonical::strictly_sorted(&value.reference_set)
            || !canonical::strictly_sorted(&value.evaluator_receipts)
            || value
                .reference_set
                .iter()
                .any(|id| !self.revisions.contains_key(id))
            || value
                .expires_at
                .is_some_and(|expiry| expiry <= value.valid_from)
            || value.confidence_statement.is_empty()
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
        value.validate_canonical()?;
        if value.base_members.is_empty()
            || value
                .base_members
                .iter()
                .any(|id| !self.revisions.contains_key(id))
            || !self.artifact_payloads.contains_key(&value.payload)
            || !self.artifact_payloads.contains_key(&value.tokenizer)
        {
            return Err(SpeciesError::UnavailableArtifact);
        }
        insert_once(&mut self.updates, value.packet_id, value)
    }
    pub fn validate_update_at(
        &self,
        value: &UpdatePacket,
        exact_policy_version: u64,
        height: Height,
    ) -> Result<(), SpeciesError> {
        value.validate_canonical()?;
        if value.policy_version != Some(exact_policy_version) {
            return Err(SpeciesError::StalePolicy);
        }
        if value.expiry.is_some_and(|expiry| height >= expiry) {
            return Err(SpeciesError::ExpiredUpdate);
        }
        if value
            .base_members
            .iter()
            .any(|id| !self.revisions.contains_key(id))
            || !self.artifact_payloads.contains_key(&value.payload)
            || !self.artifact_payloads.contains_key(&value.tokenizer)
        {
            return Err(SpeciesError::UnavailableArtifact);
        }
        Ok(())
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

    pub fn resolve_view(
        &self,
        species_id: Hash32,
        numeric_profile: Hash32,
        suite: Hash32,
        height: Height,
    ) -> Result<SpeciesView, SpeciesError> {
        if !self.manifests.contains_key(&species_id) {
            return Err(SpeciesError::UnknownSpecies);
        }
        let members = self
            .revisions
            .values()
            .filter(|revision| {
                revision.species_id == species_id
                    && revision.lifecycle == RevisionLifecycle::Admitted
                    && revision.serving_profiles.iter().any(|profile_id| {
                        self.serving_profiles
                            .get(profile_id)
                            .is_some_and(|profile| profile.numeric_profile_id == numeric_profile)
                    })
                    && revision
                        .required_artifacts
                        .iter()
                        .all(|id| self.artifact_payloads.contains_key(id))
            })
            .map(|revision| revision.revision_id)
            .collect::<Vec<_>>();
        let member_set = members.iter().copied().collect::<BTreeSet<_>>();
        let mut edges = Vec::new();
        for claim in self.claims.values() {
            if claim.species_id != species_id
                || claim.numeric_profile != numeric_profile
                || claim.test_commitment != suite
                || !member_set.contains(&claim.candidate)
            {
                continue;
            }
            for reference in &claim.reference_set {
                if member_set.contains(reference)
                    && claim.applies_directionally(&claim.candidate, reference, height)
                {
                    edges.push(ResolvedRelation {
                        claim_id: claim.claim_id,
                        candidate: claim.candidate,
                        reference: *reference,
                        relation: claim.relation,
                    });
                }
            }
        }
        edges.sort_by_key(|edge| (edge.claim_id, edge.candidate, edge.reference));
        let mut view = SpeciesView {
            species_id,
            numeric_profile,
            suite,
            height,
            members,
            edges,
            view_id: [0; 32],
        };
        view.view_id = view.derive_id();
        Ok(view)
    }

    pub fn resolve_view_reference(
        &self,
        species_id: Hash32,
        numeric_profile: Hash32,
        suite: Hash32,
        height: Height,
    ) -> Result<SpeciesView, SpeciesError> {
        let manifest = self
            .manifests
            .get(&species_id)
            .ok_or(SpeciesError::UnknownSpecies)?;
        if !manifest
            .admissible_numeric_profiles
            .contains(&numeric_profile)
        {
            return Err(SpeciesError::UnknownNumericProfile);
        }
        let mut members = Vec::new();
        for (id, revision) in &self.revisions {
            let profile_matches = revision.serving_profiles.iter().any(|profile_id| {
                self.serving_profiles
                    .get(profile_id)
                    .map(|profile| profile.numeric_profile_id == numeric_profile)
                    .unwrap_or(false)
            });
            let available = revision
                .required_artifacts
                .iter()
                .all(|artifact| self.artifact_payloads.contains_key(artifact));
            if revision.species_id == species_id
                && revision.lifecycle == RevisionLifecycle::Admitted
                && profile_matches
                && available
            {
                members.push(*id);
            }
        }
        let mut edges = Vec::new();
        for (id, claim) in &self.claims {
            if claim.species_id == species_id
                && claim.numeric_profile == numeric_profile
                && claim.test_commitment == suite
            {
                for reference in &claim.reference_set {
                    if members.binary_search(&claim.candidate).is_ok()
                        && members.binary_search(reference).is_ok()
                        && claim.applies_directionally(&claim.candidate, reference, height)
                    {
                        edges.push(ResolvedRelation {
                            claim_id: *id,
                            candidate: claim.candidate,
                            reference: *reference,
                            relation: claim.relation,
                        });
                    }
                }
            }
        }
        edges.sort_by_key(|edge| (edge.claim_id, edge.candidate, edge.reference));
        let mut view = SpeciesView {
            species_id,
            numeric_profile,
            suite,
            height,
            members,
            edges,
            view_id: [0; 32],
        };
        view.view_id = view.derive_id();
        Ok(view)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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
            lifecycle: RevisionLifecycle::Proposed,
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

    fn content_artifact(payload: &[u8], kind: ArtifactKind) -> Artifact {
        let mut artifact = Artifact {
            artifact_id: [0; 32],
            kind,
            media_type: "application/noos-test".into(),
            byte_length: u64::try_from(payload.len()).unwrap(),
            chunking_profile: h(51),
            availability_root: h(52),
            encoding: h(53),
            numeric_profile: Some(h(1)),
            encryption_profile: None,
            rights_root: h(54),
            creator: h(55),
            created_at: 1,
            annotations_root: h(56),
        };
        artifact.artifact_id = artifact.derived_id(payload);
        artifact
    }

    #[test]
    fn claim_species_dual_path_view_identity_preserves_direction_and_scope() {
        let mut registry = registry();
        let payload = b"promoted member";
        let artifact = content_artifact(payload, ArtifactKind::WeightShard);
        let artifact_id = artifact.artifact_id;
        registry
            .register_artifact_content(artifact, payload.to_vec())
            .unwrap();
        for id in [40, 41] {
            let mut value = revision(id);
            value.required_artifacts = vec![artifact_id];
            value.lifecycle = RevisionLifecycle::Admitted;
            registry.register_revision(value).unwrap();
        }
        let claim = EquivalenceClaim {
            claim_id: h(60),
            species_id: h(10),
            candidate: h(41),
            reference_set: vec![h(40)],
            relation: Relation::TaskScoreBand,
            domain_slice: h(61),
            numeric_profile: h(1),
            test_commitment: h(62),
            result_commitment: h(63),
            evaluator_receipts: vec![],
            confidence_statement: "tolerance_millionths=10".into(),
            valid_from: 10,
            expires_at: Some(20),
            challenger_bond: 1,
        };
        registry.register_claim(claim).unwrap();
        let optimized = registry.resolve_view(h(10), h(1), h(62), 10).unwrap();
        let reference = registry
            .resolve_view_reference(h(10), h(1), h(62), 10)
            .unwrap();
        assert_eq!(optimized, reference);
        assert_eq!(optimized.members, vec![h(40), h(41)]);
        assert_eq!(optimized.edges.len(), 1);
        assert_eq!(
            (optimized.edges[0].candidate, optimized.edges[0].reference),
            (h(41), h(40))
        );
        assert!(registry
            .resolve_view(h(10), h(1), h(99), 10)
            .unwrap()
            .edges
            .is_empty());
        assert!(registry
            .resolve_view(h(10), h(1), h(62), 20)
            .unwrap()
            .edges
            .is_empty());
    }
}
