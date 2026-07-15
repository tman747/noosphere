//! WWM MindLink v1 knowledge and provenance graph.
//!
//! Contributions are immutable signed objects. Moderation, challenge,
//! correction, and revocation are append-only transitions; contradictory links
//! coexist and public visibility never implies retrieval or training consent.

#![forbid(unsafe_code)]

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub mod service;
pub mod snapshot;

pub type Hash32 = [u8; 32];
pub const MAX_TITLE_BYTES: usize = 180;
pub const MAX_CONTENT_BYTES: usize = 65_536;
pub const MAX_SUMMARY_BYTES: usize = 4_096;
pub const MAX_DOMAIN_TAGS: usize = 32;
pub const MAX_RELATIONS: usize = 256;
pub const MAX_SOURCES: usize = 64;
pub const MAX_AUTHORITIES: usize = 16;
pub const MAX_LINEAGE_LINKS: usize = 16;
pub const MAX_TEXT_FIELD_BYTES: usize = 2_048;
pub const WWM_MINDLINK_REGISTRY_ENABLED: bool = false;
pub const WWM_MINDLINK_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MindError {
    InvalidMindLink,
    InvalidSignature,
    InvalidCredentialProof,
    DuplicateMindLink,
    UnknownMindLink,
    InvalidTransition,
    DuplicateTransition,
    UnauthorizedTransition,
    InvalidChallenge,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MindLinkType {
    Observation = 1,
    Claim = 2,
    Question = 3,
    Correction = 4,
    Counterclaim = 5,
    Source = 6,
    Method = 7,
    Experience = 8,
    Warning = 9,
    Translation = 10,
    CulturalRecord = 11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentPayload {
    Public {
        original_text: String,
        summary: String,
        summary_derived: bool,
    },
    Sealed {
        encrypted_content_root: Hash32,
        summary: String,
        summary_derived: bool,
    },
}

impl ContentPayload {
    fn encode(&self) -> Result<Vec<u8>, MindError> {
        let mut out = Vec::new();
        match self {
            Self::Public {
                original_text,
                summary,
                summary_derived,
            } => {
                if original_text.is_empty()
                    || original_text.len() > MAX_CONTENT_BYTES
                    || summary.len() > MAX_SUMMARY_BYTES
                {
                    return Err(MindError::InvalidMindLink);
                }
                out.push(0);
                push_string(&mut out, original_text, MAX_CONTENT_BYTES)?;
                push_string(&mut out, summary, MAX_SUMMARY_BYTES)?;
                out.push(u8::from(*summary_derived));
            }
            Self::Sealed {
                encrypted_content_root,
                summary,
                summary_derived,
            } => {
                if *encrypted_content_root == [0; 32] || summary.len() > MAX_SUMMARY_BYTES {
                    return Err(MindError::InvalidMindLink);
                }
                out.push(1);
                out.extend(encrypted_content_root);
                push_string(&mut out, summary, MAX_SUMMARY_BYTES)?;
                out.push(u8::from(*summary_derived));
            }
        }
        Ok(out)
    }

    #[must_use]
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContributorIdentity {
    Named {
        public_key: Hash32,
        display_name: String,
    },
    Pseudonymous {
        public_key: Hash32,
        display_name: String,
    },
    BlindCredential {
        credential_root: Hash32,
        display_name: String,
    },
}

impl ContributorIdentity {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), MindError> {
        match self {
            Self::Named {
                public_key,
                display_name,
            } => {
                if *public_key == [0; 32] || display_name.is_empty() || display_name.len() > 160 {
                    return Err(MindError::InvalidMindLink);
                }
                out.push(1);
                out.extend(public_key);
                push_string(out, display_name, 160)?;
            }
            Self::Pseudonymous {
                public_key,
                display_name,
            } => {
                if *public_key == [0; 32] || display_name.len() > 160 {
                    return Err(MindError::InvalidMindLink);
                }
                out.push(2);
                out.extend(public_key);
                push_string(out, display_name, 160)?;
            }
            Self::BlindCredential {
                credential_root,
                display_name,
            } => {
                if *credential_root == [0; 32] || display_name.len() > 160 {
                    return Err(MindError::InvalidMindLink);
                }
                out.push(3);
                out.extend(credential_root);
                push_string(out, display_name, 160)?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn public_key(&self) -> Option<Hash32> {
        match self {
            Self::Named { public_key, .. } | Self::Pseudonymous { public_key, .. } => {
                Some(*public_key)
            }
            Self::BlindCredential { .. } => None,
        }
    }

    #[must_use]
    pub fn credential_root(&self) -> Option<Hash32> {
        match self {
            Self::BlindCredential {
                credential_root, ..
            } => Some(*credential_root),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatement {
    pub domain: String,
    pub statement: String,
    pub evidence_root: Hash32,
    pub valid_from_height: u64,
    pub expires_height: Option<u64>,
}

impl AuthorityStatement {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), MindError> {
        if self.domain.is_empty()
            || self.domain.len() > 128
            || self.statement.is_empty()
            || self.statement.len() > 1_024
            || self.evidence_root == [0; 32]
            || self
                .expires_height
                .is_some_and(|expiry| expiry <= self.valid_from_height)
        {
            return Err(MindError::InvalidMindLink);
        }
        push_string(out, &self.domain, 128)?;
        push_string(out, &self.statement, 1_024)?;
        out.extend(self.evidence_root);
        out.extend(self.valid_from_height.to_le_bytes());
        push_optional_u64(out, self.expires_height);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceSource {
    pub uri: String,
    pub content_hash: Hash32,
    pub title: String,
    pub publisher: String,
    pub retrieved_at_unix_seconds: u64,
}

impl ProvenanceSource {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), MindError> {
        if self.uri.is_empty()
            || self.uri.len() > MAX_TEXT_FIELD_BYTES
            || self.content_hash == [0; 32]
            || self.title.len() > 256
            || self.publisher.len() > 256
            || self.retrieved_at_unix_seconds == 0
        {
            return Err(MindError::InvalidMindLink);
        }
        push_string(out, &self.uri, MAX_TEXT_FIELD_BYTES)?;
        out.extend(self.content_hash);
        push_string(out, &self.title, 256)?;
        push_string(out, &self.publisher, 256)?;
        out.extend(self.retrieved_at_unix_seconds.to_le_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provenance {
    pub sources: Vec<ProvenanceSource>,
    pub evidence_ids: Vec<Hash32>,
    pub derived_from: Vec<Hash32>,
    pub c2pa_manifest_refs: Vec<String>,
}

impl Provenance {
    fn encode(&self) -> Result<Vec<u8>, MindError> {
        if self.sources.len() > MAX_SOURCES
            || self.evidence_ids.len() > MAX_SOURCES
            || self.derived_from.len() > MAX_SOURCES
            || self.c2pa_manifest_refs.len() > 16
            || !strictly_sorted(&self.evidence_ids)
            || !strictly_sorted(&self.derived_from)
            || self.evidence_ids.contains(&[0; 32])
            || self.derived_from.contains(&[0; 32])
            || !strictly_sorted(&self.c2pa_manifest_refs)
        {
            return Err(MindError::InvalidMindLink);
        }
        let mut out = Vec::new();
        out.extend(
            u16::try_from(self.sources.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for source in &self.sources {
            source.encode(&mut out)?;
        }
        push_hashes(&mut out, &self.evidence_ids)?;
        push_hashes(&mut out, &self.derived_from)?;
        out.extend(
            u16::try_from(self.c2pa_manifest_refs.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for reference in &self.c2pa_manifest_refs {
            push_string(&mut out, reference, MAX_TEXT_FIELD_BYTES)?;
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RelationKind {
    Supports = 1,
    Contradicts = 2,
    Corrects = 3,
    Translates = 4,
    Derives = 5,
    Duplicates = 6,
    Contextualizes = 7,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelationEdge {
    pub kind: RelationKind,
    pub target_id: Hash32,
    pub reason: String,
}

impl RelationEdge {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), MindError> {
        if self.target_id == [0; 32] || self.reason.is_empty() || self.reason.len() > 1_024 {
            return Err(MindError::InvalidMindLink);
        }
        out.push(self.kind as u8);
        out.extend(self.target_id);
        push_string(out, &self.reason, 1_024)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Visibility {
    SealedGroup = 1,
    Unlisted = 2,
    Public = 3,
    RevokedFutureUse = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Permission {
    Deny = 0,
    Conditional = 1,
    Allow = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightsPolicy {
    pub visibility: Visibility,
    pub retrieval_permission: Permission,
    pub training_permission: Permission,
    pub commercial_use: Permission,
    pub derivative_model_permission: Permission,
    pub attribution_required: bool,
    pub license: String,
    pub retention_request: String,
    pub cultural_constraints: String,
}

impl RightsPolicy {
    fn encode(&self) -> Result<Vec<u8>, MindError> {
        if self.license.is_empty()
            || self.license.len() > 512
            || self.retention_request.is_empty()
            || self.retention_request.len() > 512
            || self.cultural_constraints.len() > 512
            || self.visibility == Visibility::RevokedFutureUse
        {
            return Err(MindError::InvalidMindLink);
        }
        let mut out = vec![
            self.visibility as u8,
            self.retrieval_permission as u8,
            self.training_permission as u8,
            self.commercial_use as u8,
            self.derivative_model_permission as u8,
            u8::from(self.attribution_required),
        ];
        push_string(&mut out, &self.license, 512)?;
        push_string(&mut out, &self.retention_request, 512)?;
        push_string(&mut out, &self.cultural_constraints, 512)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChallengeStatus {
    Unchallenged = 0,
    Open = 1,
    ResolvedUpheld = 2,
    ResolvedRejected = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeState {
    pub status: ChallengeStatus,
    pub policy_root: Hash32,
    pub bond_micro_noos: u64,
    pub open_challenge_ids: Vec<Hash32>,
}

impl ChallengeState {
    fn encode(&self) -> Result<Vec<u8>, MindError> {
        if self.policy_root == [0; 32]
            || self.open_challenge_ids.len() > 32
            || !strictly_sorted(&self.open_challenge_ids)
            || self.open_challenge_ids.contains(&[0; 32])
            || (self.status == ChallengeStatus::Open && self.open_challenge_ids.is_empty())
            || (self.status != ChallengeStatus::Open && !self.open_challenge_ids.is_empty())
        {
            return Err(MindError::InvalidChallenge);
        }
        let mut out = Vec::new();
        out.push(self.status as u8);
        out.extend(self.policy_root);
        out.extend(self.bond_micro_noos.to_le_bytes());
        push_hashes(&mut out, &self.open_challenge_ids)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModerationStatus {
    NotReviewed = 0,
    Quarantined = 1,
    ReviewedEligible = 2,
    ReviewedRejected = 3,
    RevokedFutureUse = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationState {
    pub namespace_root: Hash32,
    pub status: ModerationStatus,
    pub decision_ids: Vec<Hash32>,
}

impl ModerationState {
    fn encode(&self) -> Result<Vec<u8>, MindError> {
        if self.namespace_root == [0; 32]
            || self.decision_ids.len() > 32
            || !strictly_sorted(&self.decision_ids)
            || self.decision_ids.contains(&[0; 32])
        {
            return Err(MindError::InvalidMindLink);
        }
        let mut out = Vec::new();
        out.extend(self.namespace_root);
        out.push(self.status as u8);
        push_hashes(&mut out, &self.decision_ids)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Lifecycle {
    LocalDraft = 0,
    Submitted = 1,
    Quarantined = 2,
    ProvenanceChecked = 3,
    Challenged = 4,
    RetrievalEligible = 5,
    SnapshotCandidate = 6,
    SnapshotAccepted = 7,
    TrainingCandidate = 8,
    DatasetAccepted = 9,
    Rejected = 10,
    RevokedFutureUse = 11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MindLinkDraft {
    pub predecessors: Vec<Hash32>,
    pub supersedes: Vec<Hash32>,
    pub kind: MindLinkType,
    pub title: String,
    pub content: ContentPayload,
    pub language: String,
    pub locale: String,
    pub domain_tags: Vec<String>,
    pub uncertainty: String,
    pub contributor: ContributorIdentity,
    pub authority: Vec<AuthorityStatement>,
    pub provenance: Provenance,
    pub relations: Vec<RelationEdge>,
    pub rights: RightsPolicy,
    pub challenge: ChallengeState,
    pub moderation: ModerationState,
    pub created_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MindLink {
    pub predecessors: Vec<Hash32>,
    pub supersedes: Vec<Hash32>,
    pub kind: MindLinkType,
    pub title: String,
    pub content: ContentPayload,
    pub language: String,
    pub locale: String,
    pub domain_tags: Vec<String>,
    pub uncertainty: String,
    pub contributor: ContributorIdentity,
    pub authority: Vec<AuthorityStatement>,
    pub provenance: Provenance,
    pub relations: Vec<RelationEdge>,
    pub rights: RightsPolicy,
    pub challenge: ChallengeState,
    pub moderation: ModerationState,
    pub initial_lifecycle: Lifecycle,
    pub created_height: u64,
    pub content_root: Hash32,
    pub provenance_root: Hash32,
    pub rights_root: Hash32,
    pub relations_root: Hash32,
    pub mindlink_id: Hash32,
    pub signature_or_credential_proof: [u8; 64],
}

pub trait BlindCredentialVerifier {
    fn verify(
        &self,
        credential_root: Hash32,
        mindlink_id: Hash32,
        canonical_body: &[u8],
        proof: [u8; 64],
    ) -> bool;
}

impl MindLink {
    pub fn finalize_signed(draft: MindLinkDraft, signer: &Keypair) -> Result<Self, MindError> {
        let expected = draft
            .contributor
            .public_key()
            .ok_or(MindError::InvalidMindLink)?;
        if expected != signer.public_key().into_bytes() {
            return Err(MindError::InvalidSignature);
        }
        let mut value = Self::from_draft(draft)?;
        let body = value.body()?;
        value.mindlink_id = digest(DomainId::WwmMindlink, &[&body])?;
        value.signature_or_credential_proof =
            sign(signer, DomainId::WwmMindlink, value.mindlink_id, &body)?;
        Ok(value)
    }

    pub fn finalize_blind(draft: MindLinkDraft, proof: [u8; 64]) -> Result<Self, MindError> {
        if draft.contributor.credential_root().is_none() || proof == [0; 64] {
            return Err(MindError::InvalidCredentialProof);
        }
        let mut value = Self::from_draft(draft)?;
        let body = value.body()?;
        value.mindlink_id = digest(DomainId::WwmMindlink, &[&body])?;
        value.signature_or_credential_proof = proof;
        Ok(value)
    }

    pub fn validate(&self, blind_verifier: &dyn BlindCredentialVerifier) -> Result<(), MindError> {
        let body = self.body()?;
        if self.mindlink_id == [0; 32]
            || digest(DomainId::WwmMindlink, &[&body])? != self.mindlink_id
        {
            return Err(MindError::InvalidMindLink);
        }
        if let Some(public_key) = self.contributor.public_key() {
            verify(
                public_key,
                DomainId::WwmMindlink,
                self.mindlink_id,
                &body,
                self.signature_or_credential_proof,
            )
        } else if blind_verifier.verify(
            self.contributor
                .credential_root()
                .ok_or(MindError::InvalidCredentialProof)?,
            self.mindlink_id,
            &body,
            self.signature_or_credential_proof,
        ) {
            Ok(())
        } else {
            Err(MindError::InvalidCredentialProof)
        }
    }

    fn from_draft(draft: MindLinkDraft) -> Result<Self, MindError> {
        let content_bytes = draft.content.encode()?;
        let provenance_bytes = draft.provenance.encode()?;
        let rights_bytes = draft.rights.encode()?;
        let relations_bytes = encode_relations(&draft.relations)?;
        let content_root = digest(DomainId::WwmMindlink, &[b"CONTENT", &content_bytes])?;
        let provenance_root = digest(DomainId::WwmMindlink, &[b"PROVENANCE", &provenance_bytes])?;
        let rights_root = digest(DomainId::WwmMindlink, &[b"RIGHTS", &rights_bytes])?;
        let relations_root = digest(DomainId::WwmMindlink, &[b"RELATIONS", &relations_bytes])?;
        let value = Self {
            predecessors: draft.predecessors,
            supersedes: draft.supersedes,
            kind: draft.kind,
            title: draft.title,
            content: draft.content,
            language: draft.language,
            locale: draft.locale,
            domain_tags: draft.domain_tags,
            uncertainty: draft.uncertainty,
            contributor: draft.contributor,
            authority: draft.authority,
            provenance: draft.provenance,
            relations: draft.relations,
            rights: draft.rights,
            challenge: draft.challenge,
            moderation: draft.moderation,
            initial_lifecycle: Lifecycle::Submitted,
            created_height: draft.created_height,
            content_root,
            provenance_root,
            rights_root,
            relations_root,
            mindlink_id: [0; 32],
            signature_or_credential_proof: [0; 64],
        };
        value.body()?;
        Ok(value)
    }

    fn body(&self) -> Result<Vec<u8>, MindError> {
        if self.predecessors.len() > MAX_LINEAGE_LINKS
            || self.supersedes.len() > MAX_LINEAGE_LINKS
            || !strictly_sorted(&self.predecessors)
            || !strictly_sorted(&self.supersedes)
            || self.predecessors.contains(&[0; 32])
            || self.supersedes.contains(&[0; 32])
            || self.title.is_empty()
            || self.title.len() > MAX_TITLE_BYTES
            || !(2..=35).contains(&self.language.len())
            || self.locale.len() > 35
            || self.domain_tags.len() > MAX_DOMAIN_TAGS
            || !strictly_sorted(&self.domain_tags)
            || self
                .domain_tags
                .iter()
                .any(|tag| tag.is_empty() || tag.len() > 64)
            || self.uncertainty.is_empty()
            || self.uncertainty.len() > 1_024
            || self.authority.len() > MAX_AUTHORITIES
            || self.relations.len() > MAX_RELATIONS
            || !strictly_sorted(&self.relations)
            || self.created_height == 0
            || self.initial_lifecycle != Lifecycle::Submitted
        {
            return Err(MindError::InvalidMindLink);
        }
        let content = self.content.encode()?;
        let provenance = self.provenance.encode()?;
        let rights = self.rights.encode()?;
        let relations = encode_relations(&self.relations)?;
        if self.content_root != digest(DomainId::WwmMindlink, &[b"CONTENT", &content])?
            || self.provenance_root != digest(DomainId::WwmMindlink, &[b"PROVENANCE", &provenance])?
            || self.rights_root != digest(DomainId::WwmMindlink, &[b"RIGHTS", &rights])?
            || self.relations_root != digest(DomainId::WwmMindlink, &[b"RELATIONS", &relations])?
            || (self.content.is_sealed() && self.rights.visibility != Visibility::SealedGroup)
            || (!self.content.is_sealed() && self.rights.visibility == Visibility::SealedGroup)
            || (self.kind == MindLinkType::Correction
                && (self.supersedes.is_empty()
                    || !self.relations.iter().any(|relation| {
                        relation.kind == RelationKind::Corrects
                            && self.supersedes.contains(&relation.target_id)
                    })))
        {
            return Err(MindError::InvalidMindLink);
        }
        let mut out = Vec::new();
        out.extend(1_u16.to_le_bytes());
        push_hashes(&mut out, &self.predecessors)?;
        push_hashes(&mut out, &self.supersedes)?;
        out.push(self.kind as u8);
        push_string(&mut out, &self.title, MAX_TITLE_BYTES)?;
        out.extend(
            u32::try_from(content.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(content);
        push_string(&mut out, &self.language, 35)?;
        push_string(&mut out, &self.locale, 35)?;
        out.extend(
            u16::try_from(self.domain_tags.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for tag in &self.domain_tags {
            push_string(&mut out, tag, 64)?;
        }
        push_string(&mut out, &self.uncertainty, 1_024)?;
        self.contributor.encode(&mut out)?;
        out.extend(
            u16::try_from(self.authority.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for authority in &self.authority {
            authority.encode(&mut out)?;
        }
        out.extend(
            u32::try_from(provenance.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(provenance);
        out.extend(
            u32::try_from(relations.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(relations);
        out.extend(
            u32::try_from(rights.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(rights);
        let challenge = self.challenge.encode()?;
        out.extend(
            u16::try_from(challenge.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(challenge);
        let moderation = self.moderation.encode()?;
        out.extend(
            u16::try_from(moderation.len())
                .map_err(|_| MindError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(moderation);
        out.push(self.initial_lifecycle as u8);
        out.extend(self.created_height.to_le_bytes());
        out.extend(self.content_root);
        out.extend(self.provenance_root);
        out.extend(self.rights_root);
        out.extend(self.relations_root);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MindLinkTransition {
    pub mindlink_id: Hash32,
    pub prior: Lifecycle,
    pub next: Lifecycle,
    pub actor_key: Hash32,
    pub reason_root: Hash32,
    pub challenge_ids: Vec<Hash32>,
    pub moderation_decision_ids: Vec<Hash32>,
    pub height: u64,
    pub transition_id: Hash32,
    pub signature: [u8; 64],
}

impl MindLinkTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor: &Keypair,
        mindlink_id: Hash32,
        prior: Lifecycle,
        next: Lifecycle,
        reason_root: Hash32,
        challenge_ids: Vec<Hash32>,
        moderation_decision_ids: Vec<Hash32>,
        height: u64,
    ) -> Result<Self, MindError> {
        let mut value = Self {
            mindlink_id,
            prior,
            next,
            actor_key: actor.public_key().into_bytes(),
            reason_root,
            challenge_ids,
            moderation_decision_ids,
            height,
            transition_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.transition_id = digest(DomainId::WwmMindlinkTransition, &[&body])?;
        value.signature = sign(
            actor,
            DomainId::WwmMindlinkTransition,
            value.transition_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), MindError> {
        let body = self.body()?;
        if self.transition_id == [0; 32]
            || digest(DomainId::WwmMindlinkTransition, &[&body])? != self.transition_id
        {
            return Err(MindError::InvalidTransition);
        }
        verify(
            self.actor_key,
            DomainId::WwmMindlinkTransition,
            self.transition_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, MindError> {
        if self.mindlink_id == [0; 32]
            || self.actor_key == [0; 32]
            || self.reason_root == [0; 32]
            || self.height == 0
            || !valid_transition(self.prior, self.next)
            || self.challenge_ids.len() > 32
            || self.moderation_decision_ids.len() > 32
            || !strictly_sorted(&self.challenge_ids)
            || !strictly_sorted(&self.moderation_decision_ids)
            || self.challenge_ids.contains(&[0; 32])
            || self.moderation_decision_ids.contains(&[0; 32])
            || (self.next == Lifecycle::Challenged && self.challenge_ids.is_empty())
            || (matches!(
                self.next,
                Lifecycle::Quarantined
                    | Lifecycle::ProvenanceChecked
                    | Lifecycle::RetrievalEligible
                    | Lifecycle::Rejected
            ) && self.moderation_decision_ids.is_empty())
        {
            return Err(MindError::InvalidTransition);
        }
        let mut out = Vec::with_capacity(190);
        out.extend(1_u16.to_le_bytes());
        out.extend(self.mindlink_id);
        out.push(self.prior as u8);
        out.push(self.next as u8);
        out.extend(self.actor_key);
        out.extend(self.reason_root);
        push_hashes(&mut out, &self.challenge_ids)?;
        push_hashes(&mut out, &self.moderation_decision_ids)?;
        out.extend(self.height.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentMindLinkState {
    pub lifecycle: Lifecycle,
    pub moderation: ModerationStatus,
    pub challenge: ChallengeStatus,
    pub updated_height: u64,
    pub last_transition_id: Option<Hash32>,
}

#[derive(Debug, Default)]
pub struct KnowledgeGraph {
    mindlinks: BTreeMap<Hash32, MindLink>,
    states: BTreeMap<Hash32, CurrentMindLinkState>,
    transitions: BTreeMap<Hash32, MindLinkTransition>,
    outgoing: BTreeMap<Hash32, Vec<RelationEdge>>,
    incoming: BTreeMap<Hash32, Vec<(Hash32, RelationKind)>>,
    reviewer_keys: BTreeSet<Hash32>,
}

impl KnowledgeGraph {
    pub fn with_reviewers(reviewer_keys: BTreeSet<Hash32>) -> Result<Self, MindError> {
        if reviewer_keys.is_empty() || reviewer_keys.contains(&[0; 32]) {
            return Err(MindError::UnauthorizedTransition);
        }
        Ok(Self {
            reviewer_keys,
            ..Self::default()
        })
    }

    pub fn register(
        &mut self,
        mindlink: MindLink,
        blind_verifier: &dyn BlindCredentialVerifier,
    ) -> Result<(), MindError> {
        mindlink.validate(blind_verifier)?;
        if self.mindlinks.contains_key(&mindlink.mindlink_id) {
            return Err(MindError::DuplicateMindLink);
        }
        let id = mindlink.mindlink_id;
        for relation in &mindlink.relations {
            self.incoming
                .entry(relation.target_id)
                .or_default()
                .push((id, relation.kind));
        }
        self.outgoing.insert(id, mindlink.relations.clone());
        self.states.insert(
            id,
            CurrentMindLinkState {
                lifecycle: Lifecycle::Submitted,
                moderation: mindlink.moderation.status,
                challenge: mindlink.challenge.status,
                updated_height: mindlink.created_height,
                last_transition_id: None,
            },
        );
        self.mindlinks.insert(id, mindlink);
        Ok(())
    }

    pub fn apply_transition(&mut self, transition: MindLinkTransition) -> Result<(), MindError> {
        transition.validate()?;
        if self.transitions.contains_key(&transition.transition_id) {
            return Err(MindError::DuplicateTransition);
        }
        let mindlink = self
            .mindlinks
            .get(&transition.mindlink_id)
            .ok_or(MindError::UnknownMindLink)?;
        let state = self
            .states
            .get_mut(&transition.mindlink_id)
            .ok_or(MindError::UnknownMindLink)?;
        if state.lifecycle != transition.prior
            || transition.height <= state.updated_height
            || state.lifecycle == Lifecycle::Rejected
            || state.lifecycle == Lifecycle::RevokedFutureUse
        {
            return Err(MindError::InvalidTransition);
        }
        let contributor_revoke = mindlink.contributor.public_key() == Some(transition.actor_key)
            && transition.next == Lifecycle::RevokedFutureUse;
        if !contributor_revoke && !self.reviewer_keys.contains(&transition.actor_key) {
            return Err(MindError::UnauthorizedTransition);
        }
        state.lifecycle = transition.next;
        state.updated_height = transition.height;
        state.last_transition_id = Some(transition.transition_id);
        match transition.next {
            Lifecycle::Quarantined => state.moderation = ModerationStatus::Quarantined,
            Lifecycle::ProvenanceChecked | Lifecycle::RetrievalEligible => {
                state.moderation = ModerationStatus::ReviewedEligible;
            }
            Lifecycle::Challenged => state.challenge = ChallengeStatus::Open,
            Lifecycle::Rejected => {
                state.moderation = ModerationStatus::ReviewedRejected;
                state.challenge = ChallengeStatus::ResolvedUpheld;
            }
            Lifecycle::RevokedFutureUse => {
                state.moderation = ModerationStatus::RevokedFutureUse;
            }
            _ => {}
        }
        if transition.prior == Lifecycle::Challenged
            && transition.next == Lifecycle::RetrievalEligible
        {
            state.challenge = ChallengeStatus::ResolvedRejected;
        }
        self.transitions
            .insert(transition.transition_id, transition);
        Ok(())
    }

    #[must_use]
    pub fn mindlink(&self, id: &Hash32) -> Option<&MindLink> {
        self.mindlinks.get(id)
    }

    #[must_use]
    pub fn state(&self, id: &Hash32) -> Option<&CurrentMindLinkState> {
        self.states.get(id)
    }

    #[must_use]
    pub fn outgoing(&self, id: &Hash32) -> &[RelationEdge] {
        self.outgoing.get(id).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn incoming(&self, id: &Hash32) -> &[(Hash32, RelationKind)] {
        self.incoming.get(id).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn snapshot_eligible_ids(&self) -> Vec<Hash32> {
        self.states
            .iter()
            .filter_map(|(id, state)| {
                let mindlink = self.mindlinks.get(id)?;
                (state.lifecycle == Lifecycle::SnapshotAccepted
                    && state.moderation == ModerationStatus::ReviewedEligible
                    && mindlink.rights.retrieval_permission == Permission::Allow
                    && mindlink.rights.visibility != Visibility::RevokedFutureUse)
                    .then_some(*id)
            })
            .collect()
    }

    #[must_use]
    pub fn training_candidate_ids(&self) -> Vec<Hash32> {
        self.states
            .iter()
            .filter_map(|(id, state)| {
                let mindlink = self.mindlinks.get(id)?;
                (state.lifecycle == Lifecycle::TrainingCandidate
                    && mindlink.rights.training_permission == Permission::Allow
                    && state.moderation == ModerationStatus::ReviewedEligible)
                    .then_some(*id)
            })
            .collect()
    }

    #[must_use]
    pub fn revoked_ids(&self) -> Vec<Hash32> {
        self.states
            .iter()
            .filter_map(|(id, state)| {
                (state.lifecycle == Lifecycle::RevokedFutureUse).then_some(*id)
            })
            .collect()
    }
}

fn valid_transition(prior: Lifecycle, next: Lifecycle) -> bool {
    match prior {
        Lifecycle::Submitted => next == Lifecycle::Quarantined,
        Lifecycle::Quarantined => {
            matches!(next, Lifecycle::ProvenanceChecked | Lifecycle::Rejected)
        }
        Lifecycle::ProvenanceChecked => matches!(
            next,
            Lifecycle::Challenged | Lifecycle::RetrievalEligible | Lifecycle::Rejected
        ),
        Lifecycle::Challenged => matches!(next, Lifecycle::RetrievalEligible | Lifecycle::Rejected),
        Lifecycle::RetrievalEligible => {
            matches!(
                next,
                Lifecycle::SnapshotCandidate | Lifecycle::RevokedFutureUse
            )
        }
        Lifecycle::SnapshotCandidate => matches!(
            next,
            Lifecycle::SnapshotAccepted | Lifecycle::Rejected | Lifecycle::RevokedFutureUse
        ),
        Lifecycle::SnapshotAccepted => {
            matches!(
                next,
                Lifecycle::TrainingCandidate | Lifecycle::RevokedFutureUse
            )
        }
        Lifecycle::TrainingCandidate => matches!(
            next,
            Lifecycle::DatasetAccepted | Lifecycle::Rejected | Lifecycle::RevokedFutureUse
        ),
        Lifecycle::LocalDraft | Lifecycle::DatasetAccepted => next == Lifecycle::RevokedFutureUse,
        Lifecycle::Rejected | Lifecycle::RevokedFutureUse => false,
    }
}

fn encode_relations(relations: &[RelationEdge]) -> Result<Vec<u8>, MindError> {
    if relations.len() > MAX_RELATIONS || !strictly_sorted(relations) {
        return Err(MindError::InvalidMindLink);
    }
    let mut out = Vec::new();
    out.extend(
        u16::try_from(relations.len())
            .map_err(|_| MindError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for relation in relations {
        relation.encode(&mut out)?;
    }
    Ok(out)
}

fn push_hashes(out: &mut Vec<u8>, hashes: &[Hash32]) -> Result<(), MindError> {
    let count = u16::try_from(hashes.len()).map_err(|_| MindError::ArithmeticOverflow)?;
    out.extend(count.to_le_bytes());
    for hash in hashes {
        out.extend(hash);
    }
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str, maximum: usize) -> Result<(), MindError> {
    if value.len() > maximum {
        return Err(MindError::InvalidMindLink);
    }
    let length = u32::try_from(value.len()).map_err(|_| MindError::ArithmeticOverflow)?;
    out.extend(length.to_le_bytes());
    out.extend(value.as_bytes());
    Ok(())
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

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, MindError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| MindError::InvalidMindLink)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], MindError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| MindError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), MindError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| MindError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]
    use super::*;

    struct NoBlind;
    impl BlindCredentialVerifier for NoBlind {
        fn verify(&self, _: Hash32, _: Hash32, _: &[u8], _: [u8; 64]) -> bool {
            false
        }
    }

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn rights() -> RightsPolicy {
        RightsPolicy {
            visibility: Visibility::Public,
            retrieval_permission: Permission::Allow,
            training_permission: Permission::Deny,
            commercial_use: Permission::Deny,
            derivative_model_permission: Permission::Deny,
            attribution_required: true,
            license: "CC-BY-4.0".to_owned(),
            retention_request: "retain while canonical".to_owned(),
            cultural_constraints: String::new(),
        }
    }

    fn draft(
        signer: &Keypair,
        kind: MindLinkType,
        supersedes: Vec<Hash32>,
        relations: Vec<RelationEdge>,
    ) -> MindLinkDraft {
        MindLinkDraft {
            predecessors: Vec::new(),
            supersedes,
            kind,
            title: "Observed seasonal water level".to_owned(),
            content: ContentPayload::Public {
                original_text: "The eastern marker was submerged after the June rain.".to_owned(),
                summary: "Eastern marker submerged after rain.".to_owned(),
                summary_derived: true,
            },
            language: "en".to_owned(),
            locale: "en-US".to_owned(),
            domain_tags: vec!["hydrology".to_owned(), "local-observation".to_owned()],
            uncertainty: "One direct observation; instrument calibration was not available."
                .to_owned(),
            contributor: ContributorIdentity::Pseudonymous {
                public_key: signer.public_key().into_bytes(),
                display_name: "River notebook 17".to_owned(),
            },
            authority: Vec::new(),
            provenance: Provenance::default(),
            relations,
            rights: rights(),
            challenge: ChallengeState {
                status: ChallengeStatus::Unchallenged,
                policy_root: h(10),
                bond_micro_noos: 100,
                open_challenge_ids: Vec::new(),
            },
            moderation: ModerationState {
                namespace_root: h(11),
                status: ModerationStatus::NotReviewed,
                decision_ids: Vec::new(),
            },
            created_height: 10,
        }
    }

    fn transition(
        reviewer: &Keypair,
        id: Hash32,
        prior: Lifecycle,
        next: Lifecycle,
        height: u64,
    ) -> MindLinkTransition {
        let challenge_ids = if next == Lifecycle::Challenged {
            vec![h(90)]
        } else {
            Vec::new()
        };
        let moderation_ids = if matches!(
            next,
            Lifecycle::Quarantined
                | Lifecycle::ProvenanceChecked
                | Lifecycle::RetrievalEligible
                | Lifecycle::Rejected
        ) {
            vec![h(91)]
        } else {
            Vec::new()
        };
        MindLinkTransition::new(
            reviewer,
            id,
            prior,
            next,
            h(height as u8),
            challenge_ids,
            moderation_ids,
            height,
        )
        .unwrap()
    }

    #[test]
    fn signed_public_and_sealed_objects_preserve_exact_content_mode() {
        let signer = Keypair::from_seed([1; 32]);
        let public = MindLink::finalize_signed(
            draft(&signer, MindLinkType::Observation, vec![], vec![]),
            &signer,
        )
        .unwrap();
        public.validate(&NoBlind).unwrap();
        let mut sealed_draft = draft(&signer, MindLinkType::Source, vec![], vec![]);
        sealed_draft.content = ContentPayload::Sealed {
            encrypted_content_root: h(20),
            summary: String::new(),
            summary_derived: false,
        };
        sealed_draft.rights.visibility = Visibility::SealedGroup;
        let sealed = MindLink::finalize_signed(sealed_draft, &signer).unwrap();
        sealed.validate(&NoBlind).unwrap();
        assert_ne!(public.content_root, sealed.content_root);
    }

    #[test]
    fn staged_lifecycle_and_contributor_revocation_are_append_only() {
        let contributor = Keypair::from_seed([2; 32]);
        let reviewer = Keypair::from_seed([3; 32]);
        let link = MindLink::finalize_signed(
            draft(&contributor, MindLinkType::Claim, vec![], vec![]),
            &contributor,
        )
        .unwrap();
        let id = link.mindlink_id;
        let mut graph =
            KnowledgeGraph::with_reviewers(BTreeSet::from([reviewer.public_key().into_bytes()]))
                .unwrap();
        graph.register(link, &NoBlind).unwrap();
        graph
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::Submitted,
                Lifecycle::Quarantined,
                11,
            ))
            .unwrap();
        graph
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::Quarantined,
                Lifecycle::ProvenanceChecked,
                12,
            ))
            .unwrap();
        graph
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::ProvenanceChecked,
                Lifecycle::RetrievalEligible,
                13,
            ))
            .unwrap();
        graph
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::RetrievalEligible,
                Lifecycle::SnapshotCandidate,
                14,
            ))
            .unwrap();
        graph
            .apply_transition(transition(
                &reviewer,
                id,
                Lifecycle::SnapshotCandidate,
                Lifecycle::SnapshotAccepted,
                15,
            ))
            .unwrap();
        assert_eq!(graph.snapshot_eligible_ids(), vec![id]);
        let revoke = MindLinkTransition::new(
            &contributor,
            id,
            Lifecycle::SnapshotAccepted,
            Lifecycle::RevokedFutureUse,
            h(40),
            vec![],
            vec![],
            16,
        )
        .unwrap();
        graph.apply_transition(revoke).unwrap();
        assert_eq!(graph.revoked_ids(), vec![id]);
        assert!(graph.mindlink(&id).is_some());
        assert!(graph.snapshot_eligible_ids().is_empty());
    }

    #[test]
    fn corrections_and_contradictions_remain_distinct_graph_nodes() {
        let contributor = Keypair::from_seed([4; 32]);
        let original = MindLink::finalize_signed(
            draft(&contributor, MindLinkType::Claim, vec![], vec![]),
            &contributor,
        )
        .unwrap();
        let target = original.mindlink_id;
        let correction = MindLink::finalize_signed(
            draft(
                &contributor,
                MindLinkType::Correction,
                vec![target],
                vec![RelationEdge {
                    kind: RelationKind::Corrects,
                    target_id: target,
                    reason: "The measurement used the upstream marker, not the eastern marker."
                        .to_owned(),
                }],
            ),
            &contributor,
        )
        .unwrap();
        let correction_id = correction.mindlink_id;
        let reviewer = Keypair::from_seed([5; 32]);
        let mut graph =
            KnowledgeGraph::with_reviewers(BTreeSet::from([reviewer.public_key().into_bytes()]))
                .unwrap();
        graph.register(original, &NoBlind).unwrap();
        graph.register(correction, &NoBlind).unwrap();
        assert!(graph.mindlink(&target).is_some());
        assert!(graph.mindlink(&correction_id).is_some());
        assert_eq!(
            graph.incoming(&target),
            &[(correction_id, RelationKind::Corrects)]
        );
    }

    #[test]
    fn unauthorized_reviewer_transition_rejects() {
        let contributor = Keypair::from_seed([6; 32]);
        let reviewer = Keypair::from_seed([7; 32]);
        let stranger = Keypair::from_seed([8; 32]);
        let link = MindLink::finalize_signed(
            draft(&contributor, MindLinkType::Claim, vec![], vec![]),
            &contributor,
        )
        .unwrap();
        let id = link.mindlink_id;
        let mut graph =
            KnowledgeGraph::with_reviewers(BTreeSet::from([reviewer.public_key().into_bytes()]))
                .unwrap();
        graph.register(link, &NoBlind).unwrap();
        assert_eq!(
            graph.apply_transition(transition(
                &stranger,
                id,
                Lifecycle::Submitted,
                Lifecycle::Quarantined,
                11
            )),
            Err(MindError::UnauthorizedTransition)
        );
    }

    #[test]
    fn knowledge_plane_is_disabled_and_non_consensus() {
        assert!(!WWM_MINDLINK_REGISTRY_ENABLED);
        assert_eq!(WWM_MINDLINK_CONSENSUS_WEIGHT, 0);
    }
}
