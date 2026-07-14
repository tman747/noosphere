//! Immutable knowledge snapshots, deterministic public retrieval, citations,
//! and signed selection receipts. Receipts prove the pinned selection
//! procedure; they never certify that selected content is true.

use crate::{ContentPayload, Hash32, KnowledgeGraph, Lifecycle, MindError, Permission, Visibility};
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SNAPSHOT_MINDLINKS: usize = 1_000_000;
pub const MAX_SNAPSHOT_BUILDERS: usize = 16;
pub const MAX_RETRIEVAL_RESULTS: usize = 256;
pub const MIN_SNAPSHOT_BUILDERS: usize = 2;
pub const WWM_KNOWLEDGE_SNAPSHOTS_ENABLED: bool = false;
pub const WWM_PUBLIC_RETRIEVAL_ENABLED: bool = false;
pub const WWM_RETRIEVAL_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidSnapshot,
    InvalidSignature,
    InsufficientBuilders,
    DuplicateSnapshot,
    UnknownParent,
    ChallengeOpen,
    AvailabilityRequired,
    RightsViolation,
    RevocationMissing,
    InvalidIndex,
    InvalidQuery,
    PrivateAdapterRequired,
    InvalidReceipt,
    UnknownSnapshot,
    InvalidRollback,
    ArithmeticOverflow,
}

impl From<MindError> for SnapshotError {
    fn from(_: MindError) -> Self {
        Self::InvalidSnapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBuilder {
    pub builder_key: Hash32,
    pub control_cluster: Hash32,
    pub implementation_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotSignature {
    pub builder_index: u8,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeIndexRoots {
    pub lexical_root: Hash32,
    pub vector_root: Hash32,
    pub graph_root: Hash32,
    pub citation_root: Hash32,
}

impl KnowledgeIndexRoots {
    fn validate(self) -> Result<(), SnapshotError> {
        if [
            self.lexical_root,
            self.vector_root,
            self.graph_root,
            self.citation_root,
        ]
        .contains(&[0; 32])
        {
            return Err(SnapshotError::InvalidSnapshot);
        }
        Ok(())
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.extend(self.lexical_root);
        out.extend(self.vector_root);
        out.extend(self.graph_root);
        out.extend(self.citation_root);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeSnapshot {
    pub parent_snapshot_id: Option<Hash32>,
    pub eligible_mindlink_ids: Vec<Hash32>,
    pub exclusion_ids: Vec<Hash32>,
    pub rights_policy_root: Hash32,
    pub normalization_profile_root: Hash32,
    pub chunking_profile_root: Hash32,
    pub embedding_capsule_and_profile: Option<(Hash32, Hash32)>,
    pub index_roots: KnowledgeIndexRoots,
    pub builders: Vec<SnapshotBuilder>,
    pub builder_threshold: u8,
    pub availability_certificate_id: Hash32,
    pub challenge_end_height: u64,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub rollback_parent_id: Option<Hash32>,
    pub snapshot_id: Hash32,
    pub signatures: Vec<SnapshotSignature>,
}

impl KnowledgeSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_snapshot_id: Option<Hash32>,
        eligible_mindlink_ids: Vec<Hash32>,
        exclusion_ids: Vec<Hash32>,
        rights_policy_root: Hash32,
        normalization_profile_root: Hash32,
        chunking_profile_root: Hash32,
        embedding_capsule_and_profile: Option<(Hash32, Hash32)>,
        index_roots: KnowledgeIndexRoots,
        builders: Vec<SnapshotBuilder>,
        builder_threshold: u8,
        availability_certificate_id: Hash32,
        challenge_end_height: u64,
        activation_height: u64,
        retirement_height: Option<u64>,
        rollback_parent_id: Option<Hash32>,
    ) -> Result<Self, SnapshotError> {
        let mut value = Self {
            parent_snapshot_id,
            eligible_mindlink_ids,
            exclusion_ids,
            rights_policy_root,
            normalization_profile_root,
            chunking_profile_root,
            embedding_capsule_and_profile,
            index_roots,
            builders,
            builder_threshold,
            availability_certificate_id,
            challenge_end_height,
            activation_height,
            retirement_height,
            rollback_parent_id,
            snapshot_id: [0; 32],
            signatures: Vec::new(),
        };
        let body = value.body()?;
        value.snapshot_id = digest(DomainId::WwmKnowledgeSnapshot, &[&body])?;
        Ok(value)
    }

    pub fn add_signature(&mut self, builder: &Keypair) -> Result<(), SnapshotError> {
        let body = self.body()?;
        if self.snapshot_id == [0; 32]
            || digest(DomainId::WwmKnowledgeSnapshot, &[&body])? != self.snapshot_id
        {
            return Err(SnapshotError::InvalidSnapshot);
        }
        let key = builder.public_key().into_bytes();
        let index = self
            .builders
            .binary_search_by_key(&key, |identity| identity.builder_key)
            .map_err(|_| SnapshotError::InvalidSignature)?;
        let index = u8::try_from(index).map_err(|_| SnapshotError::ArithmeticOverflow)?;
        if self
            .signatures
            .iter()
            .any(|signature| signature.builder_index == index)
        {
            return Err(SnapshotError::InvalidSignature);
        }
        self.signatures.push(SnapshotSignature {
            builder_index: index,
            signature: sign(
                builder,
                DomainId::WwmKnowledgeSnapshot,
                self.snapshot_id,
                &body,
            )?,
        });
        self.signatures
            .sort_by_key(|signature| signature.builder_index);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SnapshotError> {
        let body = self.body()?;
        if self.snapshot_id == [0; 32]
            || digest(DomainId::WwmKnowledgeSnapshot, &[&body])? != self.snapshot_id
            || self.signatures.len() < usize::from(self.builder_threshold)
            || !strictly_sorted_by(&self.signatures, |signature| signature.builder_index)
        {
            return Err(SnapshotError::InvalidSnapshot);
        }
        let mut signing_clusters = BTreeSet::new();
        let mut signing_implementations = BTreeSet::new();
        for signature in &self.signatures {
            let builder = self
                .builders
                .get(usize::from(signature.builder_index))
                .ok_or(SnapshotError::InvalidSignature)?;
            verify(
                builder.builder_key,
                DomainId::WwmKnowledgeSnapshot,
                self.snapshot_id,
                &body,
                signature.signature,
            )?;
            signing_clusters.insert(builder.control_cluster);
            signing_implementations.insert(builder.implementation_root);
        }
        if signing_clusters.len() < usize::from(self.builder_threshold)
            || signing_implementations.len() < MIN_SNAPSHOT_BUILDERS
        {
            return Err(SnapshotError::InsufficientBuilders);
        }
        Ok(())
    }

    pub fn validate_against_graph(&self, graph: &KnowledgeGraph) -> Result<(), SnapshotError> {
        self.validate()?;
        let revoked = graph.revoked_ids().into_iter().collect::<BTreeSet<_>>();
        if !revoked
            .iter()
            .all(|id| self.exclusion_ids.binary_search(id).is_ok())
        {
            return Err(SnapshotError::RevocationMissing);
        }
        for id in &self.eligible_mindlink_ids {
            let link = graph.mindlink(id).ok_or(SnapshotError::RightsViolation)?;
            let state = graph.state(id).ok_or(SnapshotError::RightsViolation)?;
            if state.lifecycle != Lifecycle::SnapshotAccepted
                || link.rights.retrieval_permission != Permission::Allow
                || link.rights.visibility == Visibility::RevokedFutureUse
                || self.exclusion_ids.binary_search(id).is_ok()
            {
                return Err(SnapshotError::RightsViolation);
            }
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, SnapshotError> {
        self.index_roots.validate()?;
        if self.parent_snapshot_id == Some([0; 32])
            || self.eligible_mindlink_ids.is_empty()
            || self.eligible_mindlink_ids.len() > MAX_SNAPSHOT_MINDLINKS
            || !strictly_sorted(&self.eligible_mindlink_ids)
            || self.eligible_mindlink_ids.contains(&[0; 32])
            || self.exclusion_ids.len() > MAX_SNAPSHOT_MINDLINKS
            || !strictly_sorted(&self.exclusion_ids)
            || self.exclusion_ids.contains(&[0; 32])
            || intersects(&self.eligible_mindlink_ids, &self.exclusion_ids)
            || self.rights_policy_root == [0; 32]
            || self.normalization_profile_root == [0; 32]
            || self.chunking_profile_root == [0; 32]
            || self
                .embedding_capsule_and_profile
                .is_some_and(|(capsule, profile)| capsule == [0; 32] || profile == [0; 32])
            || self.builders.len() < MIN_SNAPSHOT_BUILDERS
            || self.builders.len() > MAX_SNAPSHOT_BUILDERS
            || usize::from(self.builder_threshold) < MIN_SNAPSHOT_BUILDERS
            || usize::from(self.builder_threshold) > self.builders.len()
            || !strictly_sorted_by(&self.builders, |builder| builder.builder_key)
            || self.builders.iter().any(|builder| {
                builder.builder_key == [0; 32]
                    || builder.control_cluster == [0; 32]
                    || builder.implementation_root == [0; 32]
            })
            || self.availability_certificate_id == [0; 32]
            || self.challenge_end_height == 0
            || self.activation_height < self.challenge_end_height
            || self
                .retirement_height
                .is_some_and(|height| height <= self.activation_height)
            || self.rollback_parent_id == Some([0; 32])
            || (self.parent_snapshot_id.is_none() && self.rollback_parent_id.is_some())
            || (self.parent_snapshot_id.is_some() && self.rollback_parent_id.is_none())
        {
            return Err(SnapshotError::InvalidSnapshot);
        }
        let mut body = Vec::new();
        body.extend(1_u16.to_le_bytes());
        push_optional_hash(&mut body, self.parent_snapshot_id);
        push_hashes(&mut body, &self.eligible_mindlink_ids)?;
        push_hashes(&mut body, &self.exclusion_ids)?;
        body.extend(self.rights_policy_root);
        body.extend(self.normalization_profile_root);
        body.extend(self.chunking_profile_root);
        match self.embedding_capsule_and_profile {
            Some((capsule, profile)) => {
                body.push(1);
                body.extend(capsule);
                body.extend(profile);
            }
            None => body.push(0),
        }
        self.index_roots.encode(&mut body);
        body.push(
            u8::try_from(self.builders.len()).map_err(|_| SnapshotError::ArithmeticOverflow)?,
        );
        for builder in &self.builders {
            body.extend(builder.builder_key);
            body.extend(builder.control_cluster);
            body.extend(builder.implementation_root);
        }
        body.push(self.builder_threshold);
        body.extend(self.availability_certificate_id);
        body.extend(self.challenge_end_height.to_le_bytes());
        body.extend(self.activation_height.to_le_bytes());
        push_optional_u64(&mut body, self.retirement_height);
        push_optional_hash(&mut body, self.rollback_parent_id);
        Ok(body)
    }
}

#[derive(Debug, Default)]
pub struct SnapshotCatalog {
    snapshots: BTreeMap<Hash32, KnowledgeSnapshot>,
    active_snapshot_id: Option<Hash32>,
}

impl SnapshotCatalog {
    pub fn register(&mut self, snapshot: KnowledgeSnapshot) -> Result<(), SnapshotError> {
        snapshot.validate()?;
        if self.snapshots.contains_key(&snapshot.snapshot_id) {
            return Err(SnapshotError::DuplicateSnapshot);
        }
        if let Some(parent) = snapshot.parent_snapshot_id {
            if !self.snapshots.contains_key(&parent) {
                return Err(SnapshotError::UnknownParent);
            }
        }
        self.snapshots.insert(snapshot.snapshot_id, snapshot);
        Ok(())
    }

    pub fn activate(&mut self, snapshot_id: Hash32, height: u64) -> Result<(), SnapshotError> {
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or(SnapshotError::UnknownSnapshot)?;
        if height < snapshot.challenge_end_height || height < snapshot.activation_height {
            return Err(SnapshotError::ChallengeOpen);
        }
        if snapshot.availability_certificate_id == [0; 32] {
            return Err(SnapshotError::AvailabilityRequired);
        }
        if let Some(current) = self.active_snapshot_id {
            if snapshot.parent_snapshot_id != Some(current) {
                return Err(SnapshotError::InvalidRollback);
            }
        } else if snapshot.parent_snapshot_id.is_some() {
            return Err(SnapshotError::UnknownParent);
        }
        self.active_snapshot_id = Some(snapshot_id);
        Ok(())
    }

    pub fn rollback_to_parent(&mut self) -> Result<Hash32, SnapshotError> {
        let current_id = self
            .active_snapshot_id
            .ok_or(SnapshotError::UnknownSnapshot)?;
        let current = self
            .snapshots
            .get(&current_id)
            .ok_or(SnapshotError::UnknownSnapshot)?;
        let parent = current
            .rollback_parent_id
            .ok_or(SnapshotError::InvalidRollback)?;
        if !self.snapshots.contains_key(&parent) {
            return Err(SnapshotError::UnknownParent);
        }
        self.active_snapshot_id = Some(parent);
        Ok(parent)
    }

    #[must_use]
    pub fn active(&self) -> Option<&KnowledgeSnapshot> {
        self.active_snapshot_id
            .and_then(|id| self.snapshots.get(&id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrievalProfileClass {
    DeterministicPublic,
    AdvisoryPublic,
    LocalPrivate,
    AttestedPrivate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalProfile {
    pub profile_id: Hash32,
    pub class: RetrievalProfileClass,
    pub normalization_root: Hash32,
    pub scoring_root: Hash32,
    pub tie_break_root: Hash32,
    pub maximum_results: u16,
}

impl RetrievalProfile {
    pub fn deterministic_ascii_v1(maximum_results: u16) -> Result<Self, SnapshotError> {
        if maximum_results == 0 || usize::from(maximum_results) > MAX_RETRIEVAL_RESULTS {
            return Err(SnapshotError::InvalidIndex);
        }
        let normalization_root = digest(
            DomainId::WwmKnowledgeSnapshot,
            &[b"ASCII-LOWER-ALNUM-TERMS/V1"],
        )?;
        let scoring_root = digest(
            DomainId::WwmKnowledgeSnapshot,
            &[b"TERM-MATCH-COUNT-Q20-DIV-DOCUMENT-TERMS/V1"],
        )?;
        let tie_break_root = digest(
            DomainId::WwmKnowledgeSnapshot,
            &[b"SCORE-DESC-MINDLINK-ID-ASC/V1"],
        )?;
        let profile_id = digest(
            DomainId::WwmKnowledgeSnapshot,
            &[
                b"RETRIEVAL-PROFILE/V1",
                &normalization_root,
                &scoring_root,
                &tie_break_root,
                &maximum_results.to_le_bytes(),
            ],
        )?;
        Ok(Self {
            profile_id,
            class: RetrievalProfileClass::DeterministicPublic,
            normalization_root,
            scoring_root,
            tie_break_root,
            maximum_results,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedDocument {
    terms: BTreeMap<String, u32>,
    term_count: u32,
    content_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalHit {
    pub mindlink_id: Hash32,
    pub score_q20: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicLexicalIndex {
    pub snapshot_id: Hash32,
    pub profile: RetrievalProfile,
    pub index_root: Hash32,
    documents: BTreeMap<Hash32, IndexedDocument>,
}

impl DeterministicLexicalIndex {
    pub fn build(
        snapshot: &KnowledgeSnapshot,
        graph: &KnowledgeGraph,
        profile: RetrievalProfile,
    ) -> Result<Self, SnapshotError> {
        snapshot.validate_against_graph(graph)?;
        if profile.class != RetrievalProfileClass::DeterministicPublic
            || profile.normalization_root != snapshot.normalization_profile_root
        {
            return Err(SnapshotError::InvalidIndex);
        }
        let mut documents = BTreeMap::new();
        let mut root_body = Vec::new();
        for id in &snapshot.eligible_mindlink_ids {
            let link = graph.mindlink(id).ok_or(SnapshotError::InvalidIndex)?;
            let (original_text, summary) = match &link.content {
                ContentPayload::Public {
                    original_text,
                    summary,
                    ..
                } => (original_text.as_str(), summary.as_str()),
                ContentPayload::Sealed { .. } => return Err(SnapshotError::PrivateAdapterRequired),
            };
            let combined = format!("{} {} {}", link.title, original_text, summary);
            let terms = normalized_terms(&combined);
            if terms.is_empty() {
                return Err(SnapshotError::InvalidIndex);
            }
            let term_count =
                u32::try_from(terms.len()).map_err(|_| SnapshotError::ArithmeticOverflow)?;
            let mut counts = BTreeMap::new();
            for term in terms {
                let count = counts.entry(term).or_insert(0_u32);
                *count = count
                    .checked_add(1)
                    .ok_or(SnapshotError::ArithmeticOverflow)?;
            }
            root_body.extend(id);
            root_body.extend(link.content_root);
            root_body.extend(term_count.to_le_bytes());
            for (term, count) in &counts {
                root_body.extend(
                    u16::try_from(term.len())
                        .map_err(|_| SnapshotError::ArithmeticOverflow)?
                        .to_le_bytes(),
                );
                root_body.extend(term.as_bytes());
                root_body.extend(count.to_le_bytes());
            }
            documents.insert(
                *id,
                IndexedDocument {
                    terms: counts,
                    term_count,
                    content_root: link.content_root,
                },
            );
        }
        let index_root = digest(
            DomainId::WwmKnowledgeSnapshot,
            &[b"LEXICAL-INDEX/V1", &profile.profile_id, &root_body],
        )?;
        if index_root != snapshot.index_roots.lexical_root {
            return Err(SnapshotError::InvalidIndex);
        }
        Ok(Self {
            snapshot_id: snapshot.snapshot_id,
            profile,
            index_root,
            documents,
        })
    }

    /// Search is defined only for the public deterministic profile. A private
    /// query must use a local or admitted enclave adapter and cannot downgrade.
    pub fn search(
        &self,
        query: &str,
        maximum_results: usize,
    ) -> Result<Vec<RetrievalHit>, SnapshotError> {
        if self.profile.class != RetrievalProfileClass::DeterministicPublic
            || query.is_empty()
            || maximum_results == 0
            || maximum_results > usize::from(self.profile.maximum_results)
        {
            return Err(SnapshotError::InvalidQuery);
        }
        let query_terms = normalized_terms(query).into_iter().collect::<BTreeSet<_>>();
        if query_terms.is_empty() {
            return Err(SnapshotError::InvalidQuery);
        }
        let mut hits = Vec::new();
        for (id, document) in &self.documents {
            let matched = query_terms.iter().try_fold(0_u64, |total, term| {
                total
                    .checked_add(u64::from(*document.terms.get(term).unwrap_or(&0)))
                    .ok_or(SnapshotError::ArithmeticOverflow)
            })?;
            if matched == 0 {
                continue;
            }
            let score = matched
                .checked_mul(1_048_576)
                .and_then(|value| value.checked_div(u64::from(document.term_count)))
                .ok_or(SnapshotError::ArithmeticOverflow)?;
            hits.push(RetrievalHit {
                mindlink_id: *id,
                score_q20: i64::try_from(score).map_err(|_| SnapshotError::ArithmeticOverflow)?,
            });
        }
        hits.sort_by(|left, right| {
            right
                .score_q20
                .cmp(&left.score_q20)
                .then_with(|| left.mindlink_id.cmp(&right.mindlink_id))
        });
        hits.truncate(maximum_results);
        Ok(hits)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CitationSpan {
    pub selected_index: u16,
    pub context_start: u32,
    pub context_end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalReceipt {
    pub job_id: Hash32,
    pub snapshot_id: Hash32,
    pub query_commitment: Hash32,
    pub retrieval_policy_root: Hash32,
    pub index_roots: KnowledgeIndexRoots,
    pub selected_mindlink_ids: Vec<Hash32>,
    pub rank_scores_q20: Vec<i64>,
    pub citation_spans: Vec<CitationSpan>,
    pub output_context_root: Hash32,
    pub executor_key: Hash32,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl RetrievalReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: &Keypair,
        job_id: Hash32,
        snapshot_id: Hash32,
        query_commitment: Hash32,
        retrieval_policy_root: Hash32,
        index_roots: KnowledgeIndexRoots,
        selected_mindlink_ids: Vec<Hash32>,
        rank_scores_q20: Vec<i64>,
        citation_spans: Vec<CitationSpan>,
        output_context_root: Hash32,
    ) -> Result<Self, SnapshotError> {
        let mut value = Self {
            job_id,
            snapshot_id,
            query_commitment,
            retrieval_policy_root,
            index_roots,
            selected_mindlink_ids,
            rank_scores_q20,
            citation_spans,
            output_context_root,
            executor_key: executor.public_key().into_bytes(),
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.receipt_id = digest(DomainId::WwmRetrievalReceipt, &[&body])?;
        value.signature = sign(
            executor,
            DomainId::WwmRetrievalReceipt,
            value.receipt_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SnapshotError> {
        let body = self.body()?;
        if self.receipt_id == [0; 32]
            || digest(DomainId::WwmRetrievalReceipt, &[&body])? != self.receipt_id
        {
            return Err(SnapshotError::InvalidReceipt);
        }
        verify(
            self.executor_key,
            DomainId::WwmRetrievalReceipt,
            self.receipt_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, SnapshotError> {
        self.index_roots.validate()?;
        if [
            self.job_id,
            self.snapshot_id,
            self.query_commitment,
            self.retrieval_policy_root,
            self.output_context_root,
            self.executor_key,
        ]
        .contains(&[0; 32])
            || self.selected_mindlink_ids.is_empty()
            || self.selected_mindlink_ids.len() > MAX_RETRIEVAL_RESULTS
            || self.selected_mindlink_ids.len() != self.rank_scores_q20.len()
            || self
                .selected_mindlink_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.selected_mindlink_ids.len()
            || self.selected_mindlink_ids.contains(&[0; 32])
            || self.rank_scores_q20.iter().any(|score| *score < 0)
            || self.citation_spans.iter().any(|span| {
                usize::from(span.selected_index) >= self.selected_mindlink_ids.len()
                    || span.context_start >= span.context_end
            })
        {
            return Err(SnapshotError::InvalidReceipt);
        }
        let mut body = Vec::new();
        body.extend(1_u16.to_le_bytes());
        body.extend(self.job_id);
        body.extend(self.snapshot_id);
        body.extend(self.query_commitment);
        body.extend(self.retrieval_policy_root);
        self.index_roots.encode(&mut body);
        push_hashes(&mut body, &self.selected_mindlink_ids)?;
        body.extend(
            u16::try_from(self.rank_scores_q20.len())
                .map_err(|_| SnapshotError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for score in &self.rank_scores_q20 {
            body.extend(score.to_le_bytes());
        }
        body.extend(
            u16::try_from(self.citation_spans.len())
                .map_err(|_| SnapshotError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for span in &self.citation_spans {
            body.extend(span.selected_index.to_le_bytes());
            body.extend(span.context_start.to_le_bytes());
            body.extend(span.context_end.to_le_bytes());
        }
        body.extend(self.output_context_root);
        body.extend(self.executor_key);
        Ok(body)
    }
}

pub trait PrivateRetrievalAdapter {
    fn profile_class(&self) -> RetrievalProfileClass;
    fn retrieve(
        &self,
        snapshot_id: Hash32,
        encrypted_query: &[u8],
        maximum_results: usize,
    ) -> Result<Vec<Hash32>, SnapshotError>;
}

pub fn retrieve_private(
    adapter: &dyn PrivateRetrievalAdapter,
    snapshot_id: Hash32,
    encrypted_query: &[u8],
    maximum_results: usize,
) -> Result<Vec<Hash32>, SnapshotError> {
    if !matches!(
        adapter.profile_class(),
        RetrievalProfileClass::LocalPrivate | RetrievalProfileClass::AttestedPrivate
    ) || encrypted_query.is_empty()
        || maximum_results == 0
        || maximum_results > MAX_RETRIEVAL_RESULTS
    {
        return Err(SnapshotError::PrivateAdapterRequired);
    }
    adapter.retrieve(snapshot_id, encrypted_query, maximum_results)
}

fn normalized_terms(value: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut current = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            current.push(char::from(byte.to_ascii_lowercase()));
        } else if !current.is_empty() {
            terms.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        terms.push(current);
    }
    terms
}

fn intersects(left: &[Hash32], right: &[Hash32]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index = left_index.saturating_add(1),
            std::cmp::Ordering::Greater => right_index = right_index.saturating_add(1),
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), SnapshotError> {
    let count = u32::try_from(values.len()).map_err(|_| SnapshotError::ArithmeticOverflow)?;
    out.extend(count.to_le_bytes());
    for value in values {
        out.extend(value);
    }
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

fn push_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend(value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, K: Ord + Copy>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, SnapshotError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| SnapshotError::InvalidSnapshot)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], SnapshotError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| SnapshotError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), SnapshotError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| SnapshotError::InvalidSignature)
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
        ChallengeState, ChallengeStatus, ContentPayload, ContributorIdentity, MindLink,
        MindLinkDraft, MindLinkTransition, MindLinkType, ModerationState, ModerationStatus,
        Provenance, RightsPolicy,
    };

    struct NoBlind;
    impl crate::BlindCredentialVerifier for NoBlind {
        fn verify(&self, _: Hash32, _: Hash32, _: &[u8], _: [u8; 64]) -> bool {
            false
        }
    }

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn eligible_graph() -> (KnowledgeGraph, Hash32, Keypair) {
        let contributor = Keypair::from_seed([1; 32]);
        let reviewer = Keypair::from_seed([2; 32]);
        let link = MindLink::finalize_signed(
            MindLinkDraft {
                predecessors: vec![],
                supersedes: vec![],
                kind: MindLinkType::Observation,
                title: "Spring water level".to_owned(),
                content: ContentPayload::Public {
                    original_text: "The eastern river marker was submerged after heavy rain."
                        .to_owned(),
                    summary: "Eastern marker submerged.".to_owned(),
                    summary_derived: true,
                },
                language: "en".to_owned(),
                locale: "en-US".to_owned(),
                domain_tags: vec!["hydrology".to_owned()],
                uncertainty: "Single direct observation.".to_owned(),
                contributor: ContributorIdentity::Pseudonymous {
                    public_key: contributor.public_key().into_bytes(),
                    display_name: "River notebook 17".to_owned(),
                },
                authority: vec![],
                provenance: Provenance::default(),
                relations: vec![],
                rights: RightsPolicy {
                    visibility: Visibility::Public,
                    retrieval_permission: Permission::Allow,
                    training_permission: Permission::Deny,
                    commercial_use: Permission::Deny,
                    derivative_model_permission: Permission::Deny,
                    attribution_required: true,
                    license: "CC-BY-4.0".to_owned(),
                    retention_request: "retain while canonical".to_owned(),
                    cultural_constraints: String::new(),
                },
                challenge: ChallengeState {
                    status: ChallengeStatus::Unchallenged,
                    policy_root: h(10),
                    bond_micro_noos: 100,
                    open_challenge_ids: vec![],
                },
                moderation: ModerationState {
                    namespace_root: h(11),
                    status: ModerationStatus::NotReviewed,
                    decision_ids: vec![],
                },
                created_height: 10,
            },
            &contributor,
        )
        .unwrap();
        let id = link.mindlink_id;
        let mut graph =
            KnowledgeGraph::with_reviewers(BTreeSet::from([reviewer.public_key().into_bytes()]))
                .unwrap();
        graph.register(link, &NoBlind).unwrap();
        let stages = [
            (Lifecycle::Submitted, Lifecycle::Quarantined),
            (Lifecycle::Quarantined, Lifecycle::ProvenanceChecked),
            (Lifecycle::ProvenanceChecked, Lifecycle::RetrievalEligible),
            (Lifecycle::RetrievalEligible, Lifecycle::SnapshotCandidate),
            (Lifecycle::SnapshotCandidate, Lifecycle::SnapshotAccepted),
        ];
        for (offset, (prior, next)) in stages.into_iter().enumerate() {
            let decision_ids = matches!(
                next,
                Lifecycle::Quarantined
                    | Lifecycle::ProvenanceChecked
                    | Lifecycle::RetrievalEligible
            )
            .then(|| vec![h(20 + offset as u8)])
            .unwrap_or_default();
            graph
                .apply_transition(
                    MindLinkTransition::new(
                        &reviewer,
                        id,
                        prior,
                        next,
                        h(30 + offset as u8),
                        vec![],
                        decision_ids,
                        11 + offset as u64,
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        (graph, id, reviewer)
    }

    fn builders() -> (Vec<Keypair>, Vec<SnapshotBuilder>) {
        let mut pairs = (0_u8..3)
            .map(|index| {
                let key = Keypair::from_seed([50 + index; 32]);
                let builder = SnapshotBuilder {
                    builder_key: key.public_key().into_bytes(),
                    control_cluster: h(60 + index),
                    implementation_root: h(70 + index),
                };
                (key, builder)
            })
            .collect::<Vec<_>>();
        pairs.sort_by_key(|(_, builder)| builder.builder_key);
        let keys = pairs.iter().map(|(key, _)| key.clone()).collect();
        let identities = pairs.into_iter().map(|(_, builder)| builder).collect();
        (keys, identities)
    }

    fn unsigned_snapshot(
        eligible: Vec<Hash32>,
        exclusions: Vec<Hash32>,
        lexical_root: Hash32,
        parent: Option<Hash32>,
    ) -> KnowledgeSnapshot {
        let (_, builder_ids) = builders();
        KnowledgeSnapshot::new(
            parent,
            eligible,
            exclusions,
            h(80),
            RetrievalProfile::deterministic_ascii_v1(16)
                .unwrap()
                .normalization_root,
            h(81),
            None,
            KnowledgeIndexRoots {
                lexical_root,
                vector_root: h(82),
                graph_root: h(83),
                citation_root: h(84),
            },
            builder_ids,
            2,
            h(85),
            20,
            21,
            None,
            parent,
        )
        .unwrap()
    }

    fn sign_snapshot(mut snapshot: KnowledgeSnapshot) -> KnowledgeSnapshot {
        let (keys, _) = builders();
        snapshot.add_signature(&keys[0]).unwrap();
        snapshot.add_signature(&keys[1]).unwrap();
        snapshot
    }

    #[test]
    fn threshold_snapshot_checks_rights_and_revocation_exclusions() {
        let (graph, id, _) = eligible_graph();
        let snapshot = sign_snapshot(unsigned_snapshot(vec![id], vec![], h(90), None));
        snapshot.validate_against_graph(&graph).unwrap();
        let mut mutated = snapshot;
        mutated.eligible_mindlink_ids.push(h(99));
        assert!(mutated.validate().is_err());
    }

    #[test]
    fn deterministic_retrieval_is_reproducible_with_id_ties() {
        let (graph, id, _) = eligible_graph();
        let profile = RetrievalProfile::deterministic_ascii_v1(16).unwrap();
        let link = graph.mindlink(&id).unwrap();
        let combined = format!(
            "{} {} {}",
            link.title,
            match &link.content {
                ContentPayload::Public { original_text, .. } => original_text,
                _ => unreachable!(),
            },
            match &link.content {
                ContentPayload::Public { summary, .. } => summary,
                _ => unreachable!(),
            },
        );
        let terms = normalized_terms(&combined);
        let mut counts = BTreeMap::new();
        for term in &terms {
            *counts.entry(term.clone()).or_insert(0_u32) += 1;
        }
        let mut root_body = Vec::new();
        root_body.extend(id);
        root_body.extend(link.content_root);
        root_body.extend(u32::try_from(terms.len()).unwrap().to_le_bytes());
        for (term, count) in counts {
            root_body.extend(u16::try_from(term.len()).unwrap().to_le_bytes());
            root_body.extend(term.as_bytes());
            root_body.extend(count.to_le_bytes());
        }
        let lexical_root = digest(
            DomainId::WwmKnowledgeSnapshot,
            &[b"LEXICAL-INDEX/V1", &profile.profile_id, &root_body],
        )
        .unwrap();
        let snapshot = sign_snapshot(unsigned_snapshot(vec![id], vec![], lexical_root, None));
        let index = DeterministicLexicalIndex::build(&snapshot, &graph, profile).unwrap();
        let first = index.search("river marker rain", 8).unwrap();
        let second = index.search("river marker rain", 8).unwrap();
        assert_eq!(first, second);
        assert_eq!(first[0].mindlink_id, id);
    }

    #[test]
    fn signed_receipt_binds_order_scores_citations_and_context() {
        let executor = Keypair::from_seed([90; 32]);
        let receipt = RetrievalReceipt::new(
            &executor,
            h(1),
            h(2),
            h(3),
            h(4),
            KnowledgeIndexRoots {
                lexical_root: h(5),
                vector_root: h(6),
                graph_root: h(7),
                citation_root: h(8),
            },
            vec![h(9), h(10)],
            vec![1_000, 900],
            vec![CitationSpan {
                selected_index: 0,
                context_start: 0,
                context_end: 42,
            }],
            h(11),
        )
        .unwrap();
        receipt.validate().unwrap();
        let mut changed = receipt;
        changed.rank_scores_q20.swap(0, 1);
        assert_eq!(changed.validate(), Err(SnapshotError::InvalidReceipt));
    }

    #[test]
    fn catalog_activates_after_challenge_and_rolls_back_parent() {
        let (graph, id, _) = eligible_graph();
        let parent = sign_snapshot(unsigned_snapshot(vec![id], vec![], h(90), None));
        parent.validate_against_graph(&graph).unwrap();
        let parent_id = parent.snapshot_id;
        let child = sign_snapshot(unsigned_snapshot(vec![id], vec![], h(91), Some(parent_id)));
        let child_id = child.snapshot_id;
        let mut catalog = SnapshotCatalog::default();
        catalog.register(parent).unwrap();
        catalog.register(child).unwrap();
        assert_eq!(
            catalog.activate(parent_id, 19),
            Err(SnapshotError::ChallengeOpen)
        );
        catalog.activate(parent_id, 21).unwrap();
        catalog.activate(child_id, 21).unwrap();
        assert_eq!(catalog.rollback_to_parent().unwrap(), parent_id);
    }

    #[test]
    fn retrieval_controls_remain_disabled_and_non_consensus() {
        assert!(!WWM_KNOWLEDGE_SNAPSHOTS_ENABLED);
        assert!(!WWM_PUBLIC_RETRIEVAL_ENABLED);
        assert_eq!(WWM_RETRIEVAL_CONSENSUS_WEIGHT, 0);
    }
}
