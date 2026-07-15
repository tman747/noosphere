//! Rights-first MindLink intake and pinned retrieval service wiring.
//!
//! This service is deliberately application-local and disabled for public
//! activation. It owns the mutable registries so callers cannot bypass the
//! mandatory intake review path, while every accepted object remains signed
//! and insert-once.

use crate::snapshot::{
    CitationSpan, DeterministicLexicalIndex, KnowledgeIndexRoots, KnowledgeSnapshot,
    RetrievalHit, RetrievalProfile, RetrievalProfileClass, RetrievalReceipt, SnapshotBuilder,
    SnapshotCatalog, SnapshotError, MIN_SNAPSHOT_BUILDERS,
};
use crate::{
    BlindCredentialVerifier, ChallengeStatus, ContentPayload, ContributorIdentity, Hash32,
    KnowledgeGraph, Lifecycle, MindError, MindLink, MindLinkTransition, ModerationStatus,
    Permission, Visibility,
};
use noos_crypto::{hash_domain, DomainId, Keypair};
use std::collections::{BTreeMap, BTreeSet};

pub const REVOCATION_SEMANTICS_V1: &str =
    "future canonical use may be revoked; already published bytes may persist";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnowledgeServiceError {
    Mind(MindError),
    Snapshot(SnapshotError),
    ContributorSignatureRequired,
    ProvenanceRequired,
    MissingAttribution,
    MissingRevocationSemantics,
    ContradictoryRights,
    MandatoryChallengeRequired,
    ContributorSelfAuthority,
    BuilderDisagreement,
    DuplicateAdvisoryIndex,
    DuplicateReceipt,
    NoRetrievalResults,
    ArithmeticOverflow,
}

impl From<MindError> for KnowledgeServiceError {
    fn from(value: MindError) -> Self {
        Self::Mind(value)
    }
}

impl From<SnapshotError> for KnowledgeServiceError {
    fn from(value: SnapshotError) -> Self {
        Self::Snapshot(value)
    }
}

struct RejectBlindCredentials;

impl BlindCredentialVerifier for RejectBlindCredentials {
    fn verify(&self, _: Hash32, _: Hash32, _: &[u8], _: [u8; 64]) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvisoryIndexRoots {
    pub vector_root: Hash32,
    pub graph_root: Hash32,
    pub citation_root: Hash32,
}

impl AdvisoryIndexRoots {
    fn validate(self) -> Result<(), KnowledgeServiceError> {
        if [self.vector_root, self.graph_root, self.citation_root].contains(&[0; 32]) {
            return Err(KnowledgeServiceError::BuilderDisagreement);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBuildReport {
    pub builder: SnapshotBuilder,
    pub eligible_mindlink_ids: Vec<Hash32>,
    pub index_roots: KnowledgeIndexRoots,
}

impl SnapshotBuildReport {
    pub fn build(
        builder: SnapshotBuilder,
        graph: &KnowledgeGraph,
        eligible_mindlink_ids: Vec<Hash32>,
        profile: &RetrievalProfile,
        advisory_roots: AdvisoryIndexRoots,
    ) -> Result<Self, KnowledgeServiceError> {
        advisory_roots.validate()?;
        let lexical_root =
            DeterministicLexicalIndex::derive_root(&eligible_mindlink_ids, graph, profile)?;
        Ok(Self {
            builder,
            eligible_mindlink_ids,
            index_roots: KnowledgeIndexRoots {
                lexical_root,
                vector_root: advisory_roots.vector_root,
                graph_root: advisory_roots.graph_root,
                citation_root: advisory_roots.citation_root,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPlan {
    pub parent_snapshot_id: Option<Hash32>,
    pub exclusion_ids: Vec<Hash32>,
    pub rights_policy_root: Hash32,
    pub normalization_profile_root: Hash32,
    pub chunking_profile_root: Hash32,
    pub embedding_capsule_and_profile: Option<(Hash32, Hash32)>,
    pub builder_threshold: u8,
    pub availability_certificate_id: Hash32,
    pub challenge_end_height: u64,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub rollback_parent_id: Option<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryIndexManifest {
    pub snapshot_id: Hash32,
    pub profile_id: Hash32,
    pub index_root: Hash32,
    pub builder_key: Hash32,
    pub availability_certificate_id: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRetrievalRequest {
    pub job_id: Hash32,
    pub snapshot_id: Hash32,
    pub query: String,
    pub maximum_results: usize,
    pub retrieval_policy_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalCitation {
    pub mindlink_id: Hash32,
    pub content_root: Hash32,
    pub context_start: u32,
    pub context_end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRetrievalResult {
    pub hits: Vec<RetrievalHit>,
    pub context: Vec<u8>,
    pub citations: Vec<RetrievalCitation>,
    pub receipt: RetrievalReceipt,
}

#[derive(Debug)]
pub struct RightsFirstKnowledgeService {
    graph: KnowledgeGraph,
    catalog: SnapshotCatalog,
    deterministic_indexes: BTreeMap<Hash32, DeterministicLexicalIndex>,
    advisory_indexes: BTreeMap<(Hash32, Hash32, Hash32), AdvisoryIndexManifest>,
    receipts: BTreeMap<Hash32, RetrievalReceipt>,
    receipt_by_job: BTreeMap<Hash32, Hash32>,
}

impl RightsFirstKnowledgeService {
    pub fn new(reviewer_keys: BTreeSet<Hash32>) -> Result<Self, KnowledgeServiceError> {
        Ok(Self {
            graph: KnowledgeGraph::with_reviewers(reviewer_keys)?,
            catalog: SnapshotCatalog::default(),
            deterministic_indexes: BTreeMap::new(),
            advisory_indexes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            receipt_by_job: BTreeMap::new(),
        })
    }

    pub fn intake_signed(&mut self, mindlink: MindLink) -> Result<Hash32, KnowledgeServiceError> {
        if mindlink.contributor.public_key().is_none() {
            return Err(KnowledgeServiceError::ContributorSignatureRequired);
        }
        validate_rights_first(&mindlink)?;
        let id = mindlink.mindlink_id;
        self.graph.register(mindlink, &RejectBlindCredentials)?;
        Ok(id)
    }

    pub fn apply_transition(
        &mut self,
        transition: MindLinkTransition,
    ) -> Result<(), KnowledgeServiceError> {
        let state = self
            .graph
            .state(&transition.mindlink_id)
            .ok_or(MindError::UnknownMindLink)?;
        if state.lifecycle == Lifecycle::ProvenanceChecked
            && transition.next == Lifecycle::RetrievalEligible
        {
            return Err(KnowledgeServiceError::MandatoryChallengeRequired);
        }
        if transition.next == Lifecycle::ProvenanceChecked {
            let link = self
                .graph
                .mindlink(&transition.mindlink_id)
                .ok_or(MindError::UnknownMindLink)?;
            validate_rights_first(link)?;
        }
        self.graph.apply_transition(transition)?;
        Ok(())
    }

    pub fn register_snapshot(
        &mut self,
        plan: SnapshotPlan,
        mut reports: Vec<SnapshotBuildReport>,
        builder_signers: &[Keypair],
        profile: RetrievalProfile,
    ) -> Result<Hash32, KnowledgeServiceError> {
        if reports.len() < MIN_SNAPSHOT_BUILDERS
            || usize::from(plan.builder_threshold) < MIN_SNAPSHOT_BUILDERS
            || usize::from(plan.builder_threshold) > reports.len()
            || profile.class != RetrievalProfileClass::DeterministicPublic
            || profile.normalization_root != plan.normalization_profile_root
        {
            return Err(KnowledgeServiceError::BuilderDisagreement);
        }
        reports.sort_by_key(|report| report.builder.builder_key);
        if reports
            .windows(2)
            .any(|pair| pair[0].builder.builder_key >= pair[1].builder.builder_key)
        {
            return Err(KnowledgeServiceError::BuilderDisagreement);
        }
        let expected_ids = self.graph.snapshot_eligible_ids();
        let expected_roots = reports[0].index_roots;
        let mut control_clusters = BTreeSet::new();
        let mut implementation_roots = BTreeSet::new();
        for report in &reports {
            if report.eligible_mindlink_ids != expected_ids || report.index_roots != expected_roots {
                return Err(KnowledgeServiceError::BuilderDisagreement);
            }
            control_clusters.insert(report.builder.control_cluster);
            implementation_roots.insert(report.builder.implementation_root);
        }
        if control_clusters.len() < MIN_SNAPSHOT_BUILDERS
            || implementation_roots.len() < MIN_SNAPSHOT_BUILDERS
            || DeterministicLexicalIndex::derive_root(&expected_ids, &self.graph, &profile)?
                != expected_roots.lexical_root
        {
            return Err(KnowledgeServiceError::BuilderDisagreement);
        }
        let builders = reports
            .iter()
            .map(|report| report.builder.clone())
            .collect::<Vec<_>>();
        let mut snapshot = KnowledgeSnapshot::new(
            plan.parent_snapshot_id,
            expected_ids,
            plan.exclusion_ids,
            plan.rights_policy_root,
            plan.normalization_profile_root,
            plan.chunking_profile_root,
            plan.embedding_capsule_and_profile,
            expected_roots,
            builders,
            plan.builder_threshold,
            plan.availability_certificate_id,
            plan.challenge_end_height,
            plan.activation_height,
            plan.retirement_height,
            plan.rollback_parent_id,
        )?;
        for report in &reports {
            let signer = builder_signers
                .iter()
                .find(|signer| signer.public_key().into_bytes() == report.builder.builder_key)
                .ok_or(KnowledgeServiceError::BuilderDisagreement)?;
            snapshot.add_signature(signer)?;
        }
        snapshot.validate_against_graph(&self.graph)?;
        let index = DeterministicLexicalIndex::build(&snapshot, &self.graph, profile)?;
        let snapshot_id = snapshot.snapshot_id;
        self.catalog.register(snapshot)?;
        self.deterministic_indexes.insert(snapshot_id, index);
        Ok(snapshot_id)
    }
    /// Registers an externally signed snapshot without handling builder secret
    /// keys. This is the production intake path for one-shot operators.
    pub fn register_signed_snapshot(
        &mut self,
        snapshot: KnowledgeSnapshot,
        profile: RetrievalProfile,
    ) -> Result<Hash32, KnowledgeServiceError> {
        let expected_ids = self.graph.snapshot_eligible_ids();
        if snapshot.builders.len() != MIN_SNAPSHOT_BUILDERS
            || usize::from(snapshot.builder_threshold) != MIN_SNAPSHOT_BUILDERS
            || snapshot.signatures.len() != MIN_SNAPSHOT_BUILDERS
            || snapshot.eligible_mindlink_ids != expected_ids
            || profile.class != RetrievalProfileClass::DeterministicPublic
            || profile.normalization_root != snapshot.normalization_profile_root
            || DeterministicLexicalIndex::derive_root(&expected_ids, &self.graph, &profile)?
                != snapshot.index_roots.lexical_root
        {
            return Err(KnowledgeServiceError::BuilderDisagreement);
        }
        snapshot.validate_against_graph(&self.graph)?;
        let index = DeterministicLexicalIndex::build(&snapshot, &self.graph, profile)?;
        let snapshot_id = snapshot.snapshot_id;
        self.catalog.register(snapshot)?;
        self.deterministic_indexes.insert(snapshot_id, index);
        Ok(snapshot_id)
    }


    pub fn register_advisory_index(
        &mut self,
        manifest: AdvisoryIndexManifest,
    ) -> Result<(), KnowledgeServiceError> {
        if self.catalog.get(&manifest.snapshot_id).is_none()
            || manifest.profile_id == [0; 32]
            || manifest.index_root == [0; 32]
            || manifest.builder_key == [0; 32]
            || manifest.availability_certificate_id == [0; 32]
            || self
                .catalog
                .get(&manifest.snapshot_id)
                .is_some_and(|snapshot| {
                    !snapshot
                        .builders
                        .iter()
                        .any(|builder| builder.builder_key == manifest.builder_key)
                })
        {
            return Err(KnowledgeServiceError::Snapshot(
                SnapshotError::InvalidIndex,
            ));
        }
        let key = (
            manifest.snapshot_id,
            manifest.profile_id,
            manifest.builder_key,
        );
        if self.advisory_indexes.contains_key(&key) {
            return Err(KnowledgeServiceError::DuplicateAdvisoryIndex);
        }
        self.advisory_indexes.insert(key, manifest);
        Ok(())
    }

    pub fn retrieve_pinned(
        &mut self,
        executor: &Keypair,
        request: PinnedRetrievalRequest,
    ) -> Result<PinnedRetrievalResult, KnowledgeServiceError> {
        if self.receipt_by_job.contains_key(&request.job_id) {
            return Err(KnowledgeServiceError::DuplicateReceipt);
        }
        let snapshot = self
            .catalog
            .get(&request.snapshot_id)
            .ok_or(SnapshotError::UnknownSnapshot)?;
        let index = self
            .deterministic_indexes
            .get(&request.snapshot_id)
            .ok_or(SnapshotError::InvalidIndex)?;
        if index.snapshot_id != snapshot.snapshot_id || index.index_root != snapshot.index_roots.lexical_root {
            return Err(KnowledgeServiceError::Snapshot(
                SnapshotError::InvalidIndex,
            ));
        }
        let hits = index.search(&request.query, request.maximum_results)?;
        if hits.is_empty() {
            return Err(KnowledgeServiceError::NoRetrievalResults);
        }
        let mut context = Vec::new();
        let mut citations = Vec::with_capacity(hits.len());
        let mut spans = Vec::with_capacity(hits.len());
        for (selected_index, hit) in hits.iter().enumerate() {
            if !context.is_empty() {
                context.push(b'\n');
            }
            let link = self
                .graph
                .mindlink(&hit.mindlink_id)
                .ok_or(SnapshotError::InvalidIndex)?;
            let exact_text = match &link.content {
                ContentPayload::Public { original_text, .. } => original_text.as_bytes(),
                ContentPayload::Sealed { .. } => {
                    return Err(KnowledgeServiceError::Snapshot(
                        SnapshotError::PrivateAdapterRequired,
                    ));
                }
            };
            let start = u32::try_from(context.len())
                .map_err(|_| KnowledgeServiceError::ArithmeticOverflow)?;
            context.extend(exact_text);
            let end = u32::try_from(context.len())
                .map_err(|_| KnowledgeServiceError::ArithmeticOverflow)?;
            let selected_index = u16::try_from(selected_index)
                .map_err(|_| KnowledgeServiceError::ArithmeticOverflow)?;
            citations.push(RetrievalCitation {
                mindlink_id: hit.mindlink_id,
                content_root: link.content_root,
                context_start: start,
                context_end: end,
            });
            spans.push(CitationSpan {
                selected_index,
                context_start: start,
                context_end: end,
            });
        }
        let query_commitment = service_digest(&[b"QUERY-COMMITMENT/V1", request.query.as_bytes()])?;
        let output_context_root = service_digest(&[b"RETRIEVAL-CONTEXT/V1", &context])?;
        let receipt = RetrievalReceipt::new(
            executor,
            request.job_id,
            request.snapshot_id,
            query_commitment,
            request.retrieval_policy_root,
            snapshot.index_roots,
            hits.iter().map(|hit| hit.mindlink_id).collect(),
            hits.iter().map(|hit| hit.score_q20).collect(),
            spans,
            output_context_root,
        )?;
        receipt.validate()?;
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err(KnowledgeServiceError::DuplicateReceipt);
        }
        self.receipt_by_job
            .insert(request.job_id, receipt.receipt_id);
        self.receipts.insert(receipt.receipt_id, receipt.clone());
        Ok(PinnedRetrievalResult {
            hits,
            context,
            citations,
            receipt,
        })
    }

    #[must_use]
    pub fn graph(&self) -> &KnowledgeGraph {
        &self.graph
    }

    #[must_use]
    pub fn snapshot(&self, snapshot_id: &Hash32) -> Option<&KnowledgeSnapshot> {
        self.catalog.get(snapshot_id)
    }

    #[must_use]
    pub fn receipt(&self, receipt_id: &Hash32) -> Option<&RetrievalReceipt> {
        self.receipts.get(receipt_id)
    }
}

fn validate_rights_first(mindlink: &MindLink) -> Result<(), KnowledgeServiceError> {
    if mindlink.challenge.status != ChallengeStatus::Unchallenged
        || !mindlink.challenge.open_challenge_ids.is_empty()
        || mindlink.moderation.status != ModerationStatus::NotReviewed
        || !mindlink.moderation.decision_ids.is_empty()
    {
        return Err(KnowledgeServiceError::ContributorSelfAuthority);
    }
    if mindlink.provenance.sources.is_empty() {
        return Err(KnowledgeServiceError::ProvenanceRequired);
    }
    if mindlink.rights.retention_request != REVOCATION_SEMANTICS_V1 {
        return Err(KnowledgeServiceError::MissingRevocationSemantics);
    }
    let training_allowed = mindlink.rights.training_permission == Permission::Allow;
    let derivative_allowed = mindlink.rights.derivative_model_permission == Permission::Allow;
    if training_allowed != derivative_allowed {
        return Err(KnowledgeServiceError::ContradictoryRights);
    }
    if mindlink.rights.attribution_required {
        let display_name = match &mindlink.contributor {
            ContributorIdentity::Named { display_name, .. }
            | ContributorIdentity::Pseudonymous { display_name, .. }
            | ContributorIdentity::BlindCredential { display_name, .. } => display_name,
        };
        if display_name.is_empty() {
            return Err(KnowledgeServiceError::MissingAttribution);
        }
    }
    if mindlink.rights.visibility == Visibility::RevokedFutureUse {
        return Err(KnowledgeServiceError::ContradictoryRights);
    }
    Ok(())
}

fn service_digest(parts: &[&[u8]]) -> Result<Hash32, KnowledgeServiceError> {
    hash_domain(DomainId::WwmRetrievalReceipt, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| KnowledgeServiceError::Snapshot(SnapshotError::InvalidReceipt))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        clippy::unwrap_used
    )]

    use super::*;
    use crate::{
        ChallengeState, MindLinkDraft, MindLinkType, ModerationState, Provenance,
        ProvenanceSource, RightsPolicy,
    };

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn draft(contributor: &Keypair) -> MindLinkDraft {
        MindLinkDraft {
            predecessors: vec![],
            supersedes: vec![],
            kind: MindLinkType::Source,
            title: "Signed river gauge observation".to_owned(),
            content: ContentPayload::Public {
                original_text: "Gauge 7 read 4.25 metres at 06:00 UTC.".to_owned(),
                summary: "Gauge 7 was at 4.25 metres.".to_owned(),
                summary_derived: true,
            },
            language: "en".to_owned(),
            locale: "en-GB".to_owned(),
            domain_tags: vec!["hydrology".to_owned()],
            uncertainty: "Instrument calibration certificate was current.".to_owned(),
            contributor: ContributorIdentity::Pseudonymous {
                public_key: contributor.public_key().into_bytes(),
                display_name: "Watershed observer 12".to_owned(),
            },
            authority: vec![],
            provenance: Provenance {
                sources: vec![ProvenanceSource {
                    uri: "https://data.example.test/gauges/7/2026-07-15T06:00:00Z".to_owned(),
                    content_hash: h(31),
                    title: "Gauge 7 signed reading".to_owned(),
                    publisher: "Watershed Lab".to_owned(),
                    retrieved_at_unix_seconds: 1_773_811_200,
                }],
                evidence_ids: vec![],
                derived_from: vec![],
                c2pa_manifest_refs: vec![],
            },
            relations: vec![],
            rights: RightsPolicy {
                visibility: Visibility::Public,
                retrieval_permission: Permission::Allow,
                training_permission: Permission::Deny,
                commercial_use: Permission::Deny,
                derivative_model_permission: Permission::Deny,
                attribution_required: true,
                license: "CC-BY-NC-4.0".to_owned(),
                retention_request: REVOCATION_SEMANTICS_V1.to_owned(),
                cultural_constraints: String::new(),
            },
            challenge: ChallengeState {
                status: ChallengeStatus::Unchallenged,
                policy_root: h(32),
                bond_micro_noos: 100,
                open_challenge_ids: vec![],
            },
            moderation: ModerationState {
                namespace_root: h(33),
                status: ModerationStatus::NotReviewed,
                decision_ids: vec![],
            },
            created_height: 10,
        }
    }

    fn signed_link(contributor: &Keypair) -> MindLink {
        MindLink::finalize_signed(draft(contributor), contributor).unwrap()
    }

    fn transition(
        actor: &Keypair,
        id: Hash32,
        prior: Lifecycle,
        next: Lifecycle,
        height: u64,
    ) -> MindLinkTransition {
        let challenge_ids = (next == Lifecycle::Challenged)
            .then(|| vec![h(60)])
            .unwrap_or_default();
        let moderation_ids = matches!(
            next,
            Lifecycle::Quarantined
                | Lifecycle::ProvenanceChecked
                | Lifecycle::RetrievalEligible
                | Lifecycle::Rejected
        )
        .then(|| vec![h(61)])
        .unwrap_or_default();
        MindLinkTransition::new(
            actor,
            id,
            prior,
            next,
            h(u8::try_from(height).unwrap()),
            challenge_ids,
            moderation_ids,
            height,
        )
        .unwrap()
    }

    fn accepted_service() -> (RightsFirstKnowledgeService, Keypair, Keypair, Hash32) {
        let contributor = Keypair::from_seed([1; 32]);
        let reviewer = Keypair::from_seed([2; 32]);
        let mut service = RightsFirstKnowledgeService::new(BTreeSet::from([
            reviewer.public_key().into_bytes(),
        ]))
        .unwrap();
        let id = service.intake_signed(signed_link(&contributor)).unwrap();
        let stages = [
            (Lifecycle::Submitted, Lifecycle::Quarantined),
            (Lifecycle::Quarantined, Lifecycle::ProvenanceChecked),
            (Lifecycle::ProvenanceChecked, Lifecycle::Challenged),
            (Lifecycle::Challenged, Lifecycle::RetrievalEligible),
            (Lifecycle::RetrievalEligible, Lifecycle::SnapshotCandidate),
            (Lifecycle::SnapshotCandidate, Lifecycle::SnapshotAccepted),
        ];
        for (offset, (prior, next)) in stages.into_iter().enumerate() {
            service
                .apply_transition(transition(
                    &reviewer,
                    id,
                    prior,
                    next,
                    11 + u64::try_from(offset).unwrap(),
                ))
                .unwrap();
        }
        (service, contributor, reviewer, id)
    }

    fn builders() -> Vec<(Keypair, SnapshotBuilder)> {
        let mut values = (0_u8..2)
            .map(|index| {
                let signer = Keypair::from_seed([40 + index; 32]);
                let identity = SnapshotBuilder {
                    builder_key: signer.public_key().into_bytes(),
                    control_cluster: h(50 + index),
                    implementation_root: h(52 + index),
                };
                (signer, identity)
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|(_, identity)| identity.builder_key);
        values
    }

    fn snapshot_plan(profile: &RetrievalProfile) -> SnapshotPlan {
        SnapshotPlan {
            parent_snapshot_id: None,
            exclusion_ids: vec![],
            rights_policy_root: h(70),
            normalization_profile_root: profile.normalization_root,
            chunking_profile_root: h(71),
            embedding_capsule_and_profile: None,
            builder_threshold: 2,
            availability_certificate_id: h(72),
            challenge_end_height: 30,
            activation_height: 31,
            retirement_height: None,
            rollback_parent_id: None,
        }
    }

    fn build_reports(
        service: &RightsFirstKnowledgeService,
        id: Hash32,
        profile: &RetrievalProfile,
        builders: &[(Keypair, SnapshotBuilder)],
    ) -> Vec<SnapshotBuildReport> {
        builders
            .iter()
            .map(|(_, builder)| {
                SnapshotBuildReport::build(
                    builder.clone(),
                    service.graph(),
                    vec![id],
                    profile,
                    AdvisoryIndexRoots {
                        vector_root: h(73),
                        graph_root: h(74),
                        citation_root: h(75),
                    },
                )
                .unwrap()
            })
            .collect()
    }

    fn register_snapshot_fixture(
        service: &mut RightsFirstKnowledgeService,
        id: Hash32,
    ) -> (Hash32, Vec<(Keypair, SnapshotBuilder)>, RetrievalProfile) {
        let profile = RetrievalProfile::deterministic_ascii_v1(16).unwrap();
        let builder_values = builders();
        let reports = build_reports(service, id, &profile, &builder_values);
        let signers = builder_values
            .iter()
            .map(|(signer, _)| signer.clone())
            .collect::<Vec<_>>();
        let snapshot_id = service
            .register_snapshot(snapshot_plan(&profile), reports, &signers, profile.clone())
            .unwrap();
        (snapshot_id, builder_values, profile)
    }
    fn externally_signed_snapshot(
        service: &RightsFirstKnowledgeService,
        id: Hash32,
        profile: &RetrievalProfile,
        builder_values: &[(Keypair, SnapshotBuilder)],
        index_roots: Option<KnowledgeIndexRoots>,
        parent_and_rollback: Option<Hash32>,
    ) -> KnowledgeSnapshot {
        let reports = build_reports(service, id, profile, builder_values);
        let plan = snapshot_plan(profile);
        let mut snapshot = KnowledgeSnapshot::new(
            parent_and_rollback,
            vec![id],
            vec![],
            plan.rights_policy_root,
            plan.normalization_profile_root,
            plan.chunking_profile_root,
            plan.embedding_capsule_and_profile,
            index_roots.unwrap_or(reports[0].index_roots),
            builder_values
                .iter()
                .map(|(_, builder)| builder.clone())
                .collect(),
            2,
            plan.availability_certificate_id,
            plan.challenge_end_height,
            plan.activation_height,
            plan.retirement_height,
            parent_and_rollback,
        )
        .unwrap();
        for (signer, _) in builder_values {
            snapshot.add_signature(signer).unwrap();
        }
        snapshot
    }

    #[test]
    fn externally_signed_snapshot_requires_valid_independent_agreeing_builders() {
        let profile = RetrievalProfile::deterministic_ascii_v1(16).unwrap();

        let (mut valid_service, _, _, valid_id) = accepted_service();
        let valid_builders = builders();
        let valid_snapshot = externally_signed_snapshot(
            &valid_service,
            valid_id,
            &profile,
            &valid_builders,
            None,
            None,
        );
        valid_service
            .register_signed_snapshot(valid_snapshot, profile.clone())
            .unwrap();

        let (mut forged_service, _, _, forged_id) = accepted_service();
        let forged_builders = builders();
        let mut forged = externally_signed_snapshot(
            &forged_service,
            forged_id,
            &profile,
            &forged_builders,
            None,
            None,
        );
        forged.signatures[0].signature[0] ^= 1;
        assert!(forged_service
            .register_signed_snapshot(forged, profile.clone())
            .is_err());

        let (mut clustered_service, _, _, clustered_id) = accepted_service();
        let mut clustered_builders = builders();
        clustered_builders[1].1.control_cluster = clustered_builders[0].1.control_cluster;
        let clustered = externally_signed_snapshot(
            &clustered_service,
            clustered_id,
            &profile,
            &clustered_builders,
            None,
            None,
        );
        assert!(clustered_service
            .register_signed_snapshot(clustered, profile.clone())
            .is_err());

        let (mut disagreement_service, _, _, disagreement_id) = accepted_service();
        let disagreement_builders = builders();
        let disagreement = externally_signed_snapshot(
            &disagreement_service,
            disagreement_id,
            &profile,
            &disagreement_builders,
            Some(KnowledgeIndexRoots {
                lexical_root: h(99),
                vector_root: h(73),
                graph_root: h(74),
                citation_root: h(75),
            }),
            None,
        );
        assert_eq!(
            disagreement_service.register_signed_snapshot(disagreement, profile.clone()),
            Err(KnowledgeServiceError::BuilderDisagreement)
        );
    }

    #[test]
    fn externally_signed_snapshot_rejects_replay_and_stale_parent() {
        let profile = RetrievalProfile::deterministic_ascii_v1(16).unwrap();
        let (mut replay_service, _, _, replay_id) = accepted_service();
        let replay_builders = builders();
        let snapshot = externally_signed_snapshot(
            &replay_service,
            replay_id,
            &profile,
            &replay_builders,
            None,
            None,
        );
        replay_service
            .register_signed_snapshot(snapshot.clone(), profile.clone())
            .unwrap();
        assert_eq!(
            replay_service.register_signed_snapshot(snapshot, profile.clone()),
            Err(KnowledgeServiceError::Snapshot(
                SnapshotError::DuplicateSnapshot
            ))
        );

        let (mut stale_service, _, _, stale_id) = accepted_service();
        let stale_builders = builders();
        let stale = externally_signed_snapshot(
            &stale_service,
            stale_id,
            &profile,
            &stale_builders,
            None,
            Some(h(98)),
        );
        assert_eq!(
            stale_service.register_signed_snapshot(stale, profile),
            Err(KnowledgeServiceError::Snapshot(SnapshotError::UnknownParent))
        );
    }


    #[test]
    fn valid_signed_intake_binds_exact_text_source_and_explicit_rights() {
        let contributor = Keypair::from_seed([3; 32]);
        let reviewer = Keypair::from_seed([4; 32]);
        let mut service = RightsFirstKnowledgeService::new(BTreeSet::from([
            reviewer.public_key().into_bytes(),
        ]))
        .unwrap();
        let id = service.intake_signed(signed_link(&contributor)).unwrap();
        let stored = service.graph().mindlink(&id).unwrap();
        assert_eq!(
            stored.content,
            ContentPayload::Public {
                original_text: "Gauge 7 read 4.25 metres at 06:00 UTC.".to_owned(),
                summary: "Gauge 7 was at 4.25 metres.".to_owned(),
                summary_derived: true,
            }
        );
        assert_eq!(stored.provenance.sources[0].content_hash, h(31));
        assert_eq!(stored.rights.visibility, Visibility::Public);
        assert_eq!(stored.rights.retrieval_permission, Permission::Allow);
        assert_eq!(stored.rights.training_permission, Permission::Deny);
        assert_eq!(
            stored.rights.derivative_model_permission,
            Permission::Deny
        );
        assert!(stored.rights.attribution_required);
        assert_eq!(stored.rights.retention_request, REVOCATION_SEMANTICS_V1);
    }

    #[test]
    fn bad_signature_and_missing_or_contradictory_rights_reject() {
        let contributor = Keypair::from_seed([5; 32]);
        let reviewer = Keypair::from_seed([6; 32]);
        let reviewer_keys = BTreeSet::from([reviewer.public_key().into_bytes()]);

        let mut bad_signature = signed_link(&contributor);
        bad_signature.signature_or_credential_proof[0] ^= 1;
        let mut service = RightsFirstKnowledgeService::new(reviewer_keys.clone()).unwrap();
        assert_eq!(
            service.intake_signed(bad_signature),
            Err(KnowledgeServiceError::Mind(MindError::InvalidSignature))
        );

        let mut no_provenance = draft(&contributor);
        no_provenance.provenance.sources.clear();
        let no_provenance = MindLink::finalize_signed(no_provenance, &contributor).unwrap();
        let mut service = RightsFirstKnowledgeService::new(reviewer_keys.clone()).unwrap();
        assert_eq!(
            service.intake_signed(no_provenance),
            Err(KnowledgeServiceError::ProvenanceRequired)
        );

        let mut missing_rights = draft(&contributor);
        missing_rights.rights.license.clear();
        assert_eq!(
            MindLink::finalize_signed(missing_rights, &contributor),
            Err(MindError::InvalidMindLink)
        );

        let mut contradictory = draft(&contributor);
        contradictory.rights.training_permission = Permission::Allow;
        let contradictory = MindLink::finalize_signed(contradictory, &contributor).unwrap();
        let mut service = RightsFirstKnowledgeService::new(reviewer_keys.clone()).unwrap();
        assert_eq!(
            service.intake_signed(contradictory),
            Err(KnowledgeServiceError::ContradictoryRights)
        );

        let mut self_authorized = draft(&contributor);
        self_authorized.moderation.status = ModerationStatus::ReviewedEligible;
        let self_authorized = MindLink::finalize_signed(self_authorized, &contributor).unwrap();
        let mut service = RightsFirstKnowledgeService::new(reviewer_keys.clone()).unwrap();
        assert_eq!(
            service.intake_signed(self_authorized),
            Err(KnowledgeServiceError::ContributorSelfAuthority)
        );

        let mut missing_revocation = draft(&contributor);
        missing_revocation.rights.retention_request = "retain indefinitely".to_owned();
        let missing_revocation =
            MindLink::finalize_signed(missing_revocation, &contributor).unwrap();
        let mut service = RightsFirstKnowledgeService::new(reviewer_keys).unwrap();
        assert_eq!(
            service.intake_signed(missing_revocation),
            Err(KnowledgeServiceError::MissingRevocationSemantics)
        );
    }

    #[test]
    fn public_visibility_never_grants_training_or_derivative_consent() {
        let contributor = Keypair::from_seed([7; 32]);
        let reviewer = Keypair::from_seed([8; 32]);
        let mut service = RightsFirstKnowledgeService::new(BTreeSet::from([
            reviewer.public_key().into_bytes(),
        ]))
        .unwrap();
        let id = service.intake_signed(signed_link(&contributor)).unwrap();
        let rights = &service.graph().mindlink(&id).unwrap().rights;
        assert_eq!(rights.visibility, Visibility::Public);
        assert_eq!(rights.retrieval_permission, Permission::Allow);
        assert_eq!(rights.training_permission, Permission::Deny);
        assert_eq!(rights.derivative_model_permission, Permission::Deny);
        assert!(service.graph().training_candidate_ids().is_empty());
    }

    #[test]
    fn mandatory_challenge_revocation_and_append_only_replay_law() {
        let contributor = Keypair::from_seed([9; 32]);
        let reviewer = Keypair::from_seed([10; 32]);
        let mut service = RightsFirstKnowledgeService::new(BTreeSet::from([
            reviewer.public_key().into_bytes(),
        ]))
        .unwrap();
        let id = service.intake_signed(signed_link(&contributor)).unwrap();
        let model_or_untrusted_actor = Keypair::from_seed([11; 32]);
        assert_eq!(
            service.apply_transition(transition(
                &model_or_untrusted_actor,
                id,
                Lifecycle::Submitted,
                Lifecycle::Quarantined,
                11,
            )),
            Err(KnowledgeServiceError::Mind(
                MindError::UnauthorizedTransition
            ))
        );
        let quarantined = transition(
            &reviewer,
            id,
            Lifecycle::Submitted,
            Lifecycle::Quarantined,
            11,
        );
        service.apply_transition(quarantined.clone()).unwrap();
        assert_eq!(
            service.apply_transition(quarantined),
            Err(KnowledgeServiceError::Mind(
                MindError::DuplicateTransition
            ))
        );
        service
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::Quarantined,
                Lifecycle::ProvenanceChecked,
                12,
            ))
            .unwrap();
        assert_eq!(
            service.apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::ProvenanceChecked,
                Lifecycle::RetrievalEligible,
                13,
            )),
            Err(KnowledgeServiceError::MandatoryChallengeRequired)
        );
        assert_eq!(
            MindLinkTransition::new(
                &reviewer,
                id,
                Lifecycle::ProvenanceChecked,
                Lifecycle::Quarantined,
                h(13),
                vec![],
                vec![h(61)],
                13,
            ),
            Err(MindError::InvalidTransition)
        );
        service
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::ProvenanceChecked,
                Lifecycle::Challenged,
                13,
            ))
            .unwrap();
        service
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::Challenged,
                Lifecycle::RetrievalEligible,
                14,
            ))
            .unwrap();
        let revoke = MindLinkTransition::new(
            &contributor,
            id,
            Lifecycle::RetrievalEligible,
            Lifecycle::RevokedFutureUse,
            h(15),
            vec![],
            vec![],
            15,
        )
        .unwrap();
        service.apply_transition(revoke.clone()).unwrap();
        assert_eq!(service.graph().revoked_ids(), vec![id]);
        assert!(service.graph().mindlink(&id).is_some());
        assert_eq!(
            service.apply_transition(revoke),
            Err(KnowledgeServiceError::Mind(
                MindError::DuplicateTransition
            ))
        );
    }

    #[test]
    fn independent_builders_must_agree_and_snapshots_are_insert_once() {
        let (mut service, _, _, id) = accepted_service();
        let profile = RetrievalProfile::deterministic_ascii_v1(16).unwrap();
        let builder_values = builders();
        let reports = build_reports(&service, id, &profile, &builder_values);
        assert_eq!(reports[0].index_roots, reports[1].index_roots);
        assert_ne!(
            reports[0].builder.implementation_root,
            reports[1].builder.implementation_root
        );
        let mut disagreement = reports.clone();
        disagreement[1].index_roots.vector_root = h(99);
        let signers = builder_values
            .iter()
            .map(|(signer, _)| signer.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            service.register_snapshot(
                snapshot_plan(&profile),
                disagreement,
                &signers,
                profile.clone(),
            ),
            Err(KnowledgeServiceError::BuilderDisagreement)
        );
        let snapshot_id = service
            .register_snapshot(
                snapshot_plan(&profile),
                reports.clone(),
                &signers,
                profile.clone(),
            )
            .unwrap();
        assert!(service.snapshot(&snapshot_id).is_some());
        assert_eq!(
            service.register_snapshot(snapshot_plan(&profile), reports, &signers, profile),
            Err(KnowledgeServiceError::Snapshot(
                SnapshotError::DuplicateSnapshot
            ))
        );
    }

    #[test]
    fn pinned_retrieval_has_exact_citations_and_immutable_receipts() {
        let (mut service, _, _, id) = accepted_service();
        let (snapshot_id, builder_values, _) = register_snapshot_fixture(&mut service, id);
        let advisory = AdvisoryIndexManifest {
            snapshot_id,
            profile_id: h(80),
            index_root: h(81),
            builder_key: builder_values[0].1.builder_key,
            availability_certificate_id: h(82),
        };
        service.register_advisory_index(advisory.clone()).unwrap();
        assert_eq!(
            service.register_advisory_index(advisory),
            Err(KnowledgeServiceError::DuplicateAdvisoryIndex)
        );
        let executor = Keypair::from_seed([90; 32]);
        let request = PinnedRetrievalRequest {
            job_id: h(91),
            snapshot_id,
            query: "gauge metres".to_owned(),
            maximum_results: 8,
            retrieval_policy_root: h(92),
        };
        let mut result = service
            .retrieve_pinned(&executor, request.clone())
            .unwrap();
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.citations.len(), 1);
        assert_eq!(result.citations[0].mindlink_id, id);
        let citation = result.citations[0];
        assert_eq!(
            &result.context[usize::try_from(citation.context_start).unwrap()
                ..usize::try_from(citation.context_end).unwrap()],
            b"Gauge 7 read 4.25 metres at 06:00 UTC."
        );
        assert_eq!(
            result.receipt.citation_spans,
            vec![CitationSpan {
                selected_index: 0,
                context_start: citation.context_start,
                context_end: citation.context_end,
            }]
        );
        let receipt_id = result.receipt.receipt_id;
        result.receipt.rank_scores_q20[0] = 0;
        let stored = service.receipt(&receipt_id).unwrap();
        stored.validate().unwrap();
        assert_ne!(stored.rank_scores_q20, result.receipt.rank_scores_q20);
        assert_eq!(
            service.retrieve_pinned(&executor, request),
            Err(KnowledgeServiceError::DuplicateReceipt)
        );
        assert_eq!(
            service.retrieve_pinned(
                &executor,
                PinnedRetrievalRequest {
                    job_id: h(93),
                    snapshot_id: h(94),
                    query: "gauge".to_owned(),
                    maximum_results: 1,
                    retrieval_policy_root: h(95),
                },
            ),
            Err(KnowledgeServiceError::Snapshot(
                SnapshotError::UnknownSnapshot
            ))
        );
    }

    #[test]
    fn rights_first_service_smoke() {
        let (mut service, _, _, id) = accepted_service();
        let (snapshot_id, _, _) = register_snapshot_fixture(&mut service, id);
        let executor = Keypair::from_seed([100; 32]);
        let result = service
            .retrieve_pinned(
                &executor,
                PinnedRetrievalRequest {
                    job_id: h(101),
                    snapshot_id,
                    query: "signed river gauge".to_owned(),
                    maximum_results: 4,
                    retrieval_policy_root: h(102),
                },
            )
            .unwrap();
        assert_eq!(result.receipt.snapshot_id, snapshot_id);
        assert_eq!(result.receipt.selected_mindlink_ids, vec![id]);
        result.receipt.validate().unwrap();
        assert!(!crate::WWM_MINDLINK_REGISTRY_ENABLED);
        assert!(!crate::snapshot::WWM_KNOWLEDGE_SNAPSHOTS_ENABLED);
        assert!(!crate::snapshot::WWM_PUBLIC_RETRIEVAL_ENABLED);
    }
}
