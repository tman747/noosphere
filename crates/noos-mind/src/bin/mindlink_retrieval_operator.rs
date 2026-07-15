use noos_crypto::{hash_domain, DomainId, Keypair};
use noos_mind::service::{
    PinnedRetrievalRequest, RightsFirstKnowledgeService,
};
use noos_mind::snapshot::{
    CitationSpan, KnowledgeIndexRoots, KnowledgeSnapshot, RetrievalProfile, RetrievalReceipt,
    SnapshotBuilder, SnapshotSignature, WWM_KNOWLEDGE_SNAPSHOTS_ENABLED,
    WWM_PUBLIC_RETRIEVAL_ENABLED,
};
use noos_mind::{
    AuthorityStatement, ChallengeState, ChallengeStatus, ContentPayload, ContributorIdentity,
    Lifecycle, MindLink, MindLinkTransition, MindLinkType, ModerationState, ModerationStatus,
    Permission, Provenance, ProvenanceSource, RelationEdge, RelationKind, RightsPolicy, Visibility,
    WWM_MINDLINK_REGISTRY_ENABLED,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const REQUEST_SCHEMA: &str = "noos/mindlink-retrieval-operator/v1";
const EVIDENCE_SCHEMA: &str = "noos/mindlink-retrieval-evidence/v1";
const MAX_REQUEST_BYTES: u64 = 1_048_576;
const MAX_REQUEST_MINDLINKS: usize = 256;
const MAX_REQUEST_TRANSITIONS: usize = 1_536;
const MAX_QUERY_BYTES: usize = 2_048;
const WWM_TRAINING_PROMOTION_ENABLED: bool = false;

type Hash32 = [u8; 32];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorRequest {
    schema: String,
    reviewer_keys: Vec<String>,
    mindlinks: Vec<MindLinkRecord>,
    transitions: Vec<TransitionRecord>,
    snapshot: SnapshotRecord,
    retrieval: RetrievalRecord,
    executor_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MindLinkRecord {
    predecessors: Vec<String>,
    supersedes: Vec<String>,
    kind: String,
    title: String,
    content: ContentRecord,
    language: String,
    locale: String,
    domain_tags: Vec<String>,
    uncertainty: String,
    contributor: ContributorRecord,
    authority: Vec<AuthorityRecord>,
    provenance: ProvenanceRecord,
    relations: Vec<RelationRecord>,
    rights: RightsRecord,
    challenge: ChallengeRecord,
    moderation: ModerationRecord,
    initial_lifecycle: String,
    created_height: u64,
    content_root: String,
    provenance_root: String,
    rights_root: String,
    relations_root: String,
    mindlink_id: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum ContentRecord {
    Public {
        original_text: String,
        summary: String,
        summary_derived: bool,
    },
    Sealed {
        encrypted_content_root: String,
        summary: String,
        summary_derived: bool,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum ContributorRecord {
    Named { public_key: String, display_name: String },
    Pseudonymous { public_key: String, display_name: String },
    BlindCredential { credential_root: String, display_name: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRecord {
    domain: String,
    statement: String,
    evidence_root: String,
    valid_from_height: u64,
    expires_height: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceRecord {
    sources: Vec<ProvenanceSourceRecord>,
    evidence_ids: Vec<String>,
    derived_from: Vec<String>,
    c2pa_manifest_refs: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceSourceRecord {
    uri: String,
    content_hash: String,
    title: String,
    publisher: String,
    retrieved_at_unix_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelationRecord {
    kind: String,
    target_id: String,
    reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RightsRecord {
    visibility: String,
    retrieval_permission: String,
    training_permission: String,
    commercial_use: String,
    derivative_model_permission: String,
    attribution_required: bool,
    license: String,
    retention_request: String,
    cultural_constraints: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRecord {
    status: String,
    policy_root: String,
    bond_micro_noos: u64,
    open_challenge_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModerationRecord {
    namespace_root: String,
    status: String,
    decision_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionRecord {
    mindlink_id: String,
    prior: String,
    next: String,
    actor_key: String,
    reason_root: String,
    challenge_ids: Vec<String>,
    moderation_decision_ids: Vec<String>,
    height: u64,
    transition_id: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRecord {
    parent_snapshot_id: Option<String>,
    eligible_mindlink_ids: Vec<String>,
    exclusion_ids: Vec<String>,
    rights_policy_root: String,
    normalization_profile_root: String,
    chunking_profile_root: String,
    embedding_capsule_and_profile: Option<(String, String)>,
    index_roots: IndexRootsRecord,
    builders: Vec<BuilderRecord>,
    builder_threshold: u8,
    availability_certificate_id: String,
    challenge_end_height: u64,
    activation_height: u64,
    retirement_height: Option<u64>,
    rollback_parent_id: Option<String>,
    snapshot_id: String,
    signatures: Vec<SnapshotSignatureRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IndexRootsRecord {
    lexical_root: String,
    vector_root: String,
    graph_root: String,
    citation_root: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuilderRecord {
    builder_key: String,
    control_cluster: String,
    implementation_root: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotSignatureRecord {
    builder_index: u8,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetrievalRecord {
    job_id: String,
    snapshot_id: String,
    query: String,
    maximum_results: usize,
    retrieval_policy_root: String,
    profile_maximum_results: u16,
}

#[derive(Debug, Serialize)]
struct OperatorEvidence {
    schema: &'static str,
    contribution_root: String,
    contribution_ids: Vec<String>,
    lifecycle_transition_root: String,
    snapshot_root: String,
    index_roots: IndexRootsEvidence,
    receipt_root: String,
    citations: Vec<CitationEvidence>,
    retrieval_receipt: ReceiptEvidence,
    production_controls: ProductionControls,
}

#[derive(Debug, Serialize)]
struct IndexRootsEvidence {
    lexical_root: String,
    vector_root: String,
    graph_root: String,
    citation_root: String,
}

#[derive(Debug, Serialize)]
struct CitationEvidence {
    mindlink_id: String,
    content_root: String,
    context_start: u32,
    context_end: u32,
}

#[derive(Debug, Serialize)]
struct ReceiptEvidence {
    job_id: String,
    snapshot_id: String,
    query_commitment: String,
    retrieval_policy_root: String,
    index_roots: IndexRootsEvidence,
    selected_mindlink_ids: Vec<String>,
    rank_scores_q20: Vec<i64>,
    citation_spans: Vec<CitationSpanEvidence>,
    output_context_root: String,
    executor_key: String,
    receipt_id: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct CitationSpanEvidence {
    selected_index: u16,
    context_start: u32,
    context_end: u32,
}

#[derive(Debug, Serialize)]
struct ProductionControls {
    wwm_mindlink_registry_enabled: bool,
    wwm_knowledge_snapshots_enabled: bool,
    wwm_public_retrieval_enabled: bool,
    wwm_training_promotion_enabled: bool,
    production_evidence: bool,
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

fn parse_hash(value: &str, field: &str) -> Result<Hash32, Box<dyn Error>> {
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{field} must be lowercase hex")))?;
    if bytes.len() != 32 || value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid(format!("{field} must be exactly 32 lowercase hex bytes")));
    }
    bytes.try_into().map_err(|_| invalid(format!("invalid {field}")))
}

fn parse_signature(value: &str, field: &str) -> Result<[u8; 64], Box<dyn Error>> {
    let bytes = hex::decode(value).map_err(|_| invalid(format!("{field} must be lowercase hex")))?;
    if bytes.len() != 64 || value.len() != 128 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid(format!("{field} must be exactly 64 lowercase hex bytes")));
    }
    bytes.try_into().map_err(|_| invalid(format!("invalid {field}")))
}

fn parse_hashes(values: &[String], field: &str) -> Result<Vec<Hash32>, Box<dyn Error>> {
    values.iter().map(|value| parse_hash(value, field)).collect()
}

fn parse_lifecycle(value: &str) -> Result<Lifecycle, Box<dyn Error>> {
    match value {
        "SUBMITTED" => Ok(Lifecycle::Submitted),
        "QUARANTINED" => Ok(Lifecycle::Quarantined),
        "PROVENANCE_CHECKED" => Ok(Lifecycle::ProvenanceChecked),
        "CHALLENGED" => Ok(Lifecycle::Challenged),
        "RETRIEVAL_ELIGIBLE" => Ok(Lifecycle::RetrievalEligible),
        "SNAPSHOT_CANDIDATE" => Ok(Lifecycle::SnapshotCandidate),
        "SNAPSHOT_ACCEPTED" => Ok(Lifecycle::SnapshotAccepted),
        "TRAINING_CANDIDATE" => Ok(Lifecycle::TrainingCandidate),
        "DATASET_ACCEPTED" => Ok(Lifecycle::DatasetAccepted),
        "REJECTED" => Ok(Lifecycle::Rejected),
        "REVOKED_FUTURE_USE" => Ok(Lifecycle::RevokedFutureUse),
        _ => Err(invalid("invalid lifecycle")),
    }
}

fn parse_permission(value: &str) -> Result<Permission, Box<dyn Error>> {
    match value {
        "DENY" => Ok(Permission::Deny),
        "CONDITIONAL" => Ok(Permission::Conditional),
        "ALLOW" => Ok(Permission::Allow),
        _ => Err(invalid("invalid permission")),
    }
}

impl MindLinkRecord {
    fn into_core(self) -> Result<MindLink, Box<dyn Error>> {
        let content = match self.content {
            ContentRecord::Public { original_text, summary, summary_derived } => ContentPayload::Public {
                original_text,
                summary,
                summary_derived,
            },
            ContentRecord::Sealed { encrypted_content_root, summary, summary_derived } => ContentPayload::Sealed {
                encrypted_content_root: parse_hash(&encrypted_content_root, "encrypted_content_root")?,
                summary,
                summary_derived,
            },
        };
        let contributor = match self.contributor {
            ContributorRecord::Named { public_key, display_name } => ContributorIdentity::Named {
                public_key: parse_hash(&public_key, "contributor.public_key")?,
                display_name,
            },
            ContributorRecord::Pseudonymous { public_key, display_name } => ContributorIdentity::Pseudonymous {
                public_key: parse_hash(&public_key, "contributor.public_key")?,
                display_name,
            },
            ContributorRecord::BlindCredential { credential_root, display_name } => ContributorIdentity::BlindCredential {
                credential_root: parse_hash(&credential_root, "contributor.credential_root")?,
                display_name,
            },
        };
        let kind = match self.kind.as_str() {
            "OBSERVATION" => MindLinkType::Observation,
            "CLAIM" => MindLinkType::Claim,
            "QUESTION" => MindLinkType::Question,
            "CORRECTION" => MindLinkType::Correction,
            "COUNTERCLAIM" => MindLinkType::Counterclaim,
            "SOURCE" => MindLinkType::Source,
            "METHOD" => MindLinkType::Method,
            "EXPERIENCE" => MindLinkType::Experience,
            "WARNING" => MindLinkType::Warning,
            "TRANSLATION" => MindLinkType::Translation,
            "CULTURAL_RECORD" => MindLinkType::CulturalRecord,
            _ => return Err(invalid("invalid MindLink kind")),
        };
        let visibility = match self.rights.visibility.as_str() {
            "SEALED_GROUP" => Visibility::SealedGroup,
            "UNLISTED" => Visibility::Unlisted,
            "PUBLIC" => Visibility::Public,
            "REVOKED_FUTURE_USE" => Visibility::RevokedFutureUse,
            _ => return Err(invalid("invalid visibility")),
        };
        let challenge_status = match self.challenge.status.as_str() {
            "UNCHALLENGED" => ChallengeStatus::Unchallenged,
            "OPEN" => ChallengeStatus::Open,
            "RESOLVED_UPHELD" => ChallengeStatus::ResolvedUpheld,
            "RESOLVED_REJECTED" => ChallengeStatus::ResolvedRejected,
            _ => return Err(invalid("invalid challenge status")),
        };
        let moderation_status = match self.moderation.status.as_str() {
            "NOT_REVIEWED" => ModerationStatus::NotReviewed,
            "QUARANTINED" => ModerationStatus::Quarantined,
            "REVIEWED_ELIGIBLE" => ModerationStatus::ReviewedEligible,
            "REVIEWED_REJECTED" => ModerationStatus::ReviewedRejected,
            "REVOKED_FUTURE_USE" => ModerationStatus::RevokedFutureUse,
            _ => return Err(invalid("invalid moderation status")),
        };
        let authority = self.authority.into_iter().map(|record| {
            Ok(AuthorityStatement {
                domain: record.domain,
                statement: record.statement,
                evidence_root: parse_hash(&record.evidence_root, "authority.evidence_root")?,
                valid_from_height: record.valid_from_height,
                expires_height: record.expires_height,
            })
        }).collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let sources = self.provenance.sources.into_iter().map(|record| {
            Ok(ProvenanceSource {
                uri: record.uri,
                content_hash: parse_hash(&record.content_hash, "provenance.content_hash")?,
                title: record.title,
                publisher: record.publisher,
                retrieved_at_unix_seconds: record.retrieved_at_unix_seconds,
            })
        }).collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let relations = self.relations.into_iter().map(|record| {
            let kind = match record.kind.as_str() {
                "SUPPORTS" => RelationKind::Supports,
                "CONTRADICTS" => RelationKind::Contradicts,
                "CORRECTS" => RelationKind::Corrects,
                "TRANSLATES" => RelationKind::Translates,
                "DERIVES" => RelationKind::Derives,
                "DUPLICATES" => RelationKind::Duplicates,
                "CONTEXTUALIZES" => RelationKind::Contextualizes,
                _ => return Err(invalid("invalid relation kind")),
            };
            Ok(RelationEdge {
                kind,
                target_id: parse_hash(&record.target_id, "relation.target_id")?,
                reason: record.reason,
            })
        }).collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        Ok(MindLink {
            predecessors: parse_hashes(&self.predecessors, "predecessor")?,
            supersedes: parse_hashes(&self.supersedes, "supersedes")?,
            kind,
            title: self.title,
            content,
            language: self.language,
            locale: self.locale,
            domain_tags: self.domain_tags,
            uncertainty: self.uncertainty,
            contributor,
            authority,
            provenance: Provenance {
                sources,
                evidence_ids: parse_hashes(&self.provenance.evidence_ids, "provenance.evidence_id")?,
                derived_from: parse_hashes(&self.provenance.derived_from, "provenance.derived_from")?,
                c2pa_manifest_refs: self.provenance.c2pa_manifest_refs,
            },
            relations,
            rights: RightsPolicy {
                visibility,
                retrieval_permission: parse_permission(&self.rights.retrieval_permission)?,
                training_permission: parse_permission(&self.rights.training_permission)?,
                commercial_use: parse_permission(&self.rights.commercial_use)?,
                derivative_model_permission: parse_permission(&self.rights.derivative_model_permission)?,
                attribution_required: self.rights.attribution_required,
                license: self.rights.license,
                retention_request: self.rights.retention_request,
                cultural_constraints: self.rights.cultural_constraints,
            },
            challenge: ChallengeState {
                status: challenge_status,
                policy_root: parse_hash(&self.challenge.policy_root, "challenge.policy_root")?,
                bond_micro_noos: self.challenge.bond_micro_noos,
                open_challenge_ids: parse_hashes(&self.challenge.open_challenge_ids, "challenge.id")?,
            },
            moderation: ModerationState {
                namespace_root: parse_hash(&self.moderation.namespace_root, "moderation.namespace_root")?,
                status: moderation_status,
                decision_ids: parse_hashes(&self.moderation.decision_ids, "moderation.decision_id")?,
            },
            initial_lifecycle: parse_lifecycle(&self.initial_lifecycle)?,
            created_height: self.created_height,
            content_root: parse_hash(&self.content_root, "content_root")?,
            provenance_root: parse_hash(&self.provenance_root, "provenance_root")?,
            rights_root: parse_hash(&self.rights_root, "rights_root")?,
            relations_root: parse_hash(&self.relations_root, "relations_root")?,
            mindlink_id: parse_hash(&self.mindlink_id, "mindlink_id")?,
            signature_or_credential_proof: parse_signature(&self.signature, "mindlink.signature")?,
        })
    }
}

impl TransitionRecord {
    fn into_core(self) -> Result<MindLinkTransition, Box<dyn Error>> {
        Ok(MindLinkTransition {
            mindlink_id: parse_hash(&self.mindlink_id, "transition.mindlink_id")?,
            prior: parse_lifecycle(&self.prior)?,
            next: parse_lifecycle(&self.next)?,
            actor_key: parse_hash(&self.actor_key, "transition.actor_key")?,
            reason_root: parse_hash(&self.reason_root, "transition.reason_root")?,
            challenge_ids: parse_hashes(&self.challenge_ids, "transition.challenge_id")?,
            moderation_decision_ids: parse_hashes(&self.moderation_decision_ids, "transition.moderation_decision_id")?,
            height: self.height,
            transition_id: parse_hash(&self.transition_id, "transition.transition_id")?,
            signature: parse_signature(&self.signature, "transition.signature")?,
        })
    }
}

impl IndexRootsRecord {
    fn into_core(self) -> Result<KnowledgeIndexRoots, Box<dyn Error>> {
        Ok(KnowledgeIndexRoots {
            lexical_root: parse_hash(&self.lexical_root, "index.lexical_root")?,
            vector_root: parse_hash(&self.vector_root, "index.vector_root")?,
            graph_root: parse_hash(&self.graph_root, "index.graph_root")?,
            citation_root: parse_hash(&self.citation_root, "index.citation_root")?,
        })
    }
}

impl SnapshotRecord {
    fn into_core(self) -> Result<KnowledgeSnapshot, Box<dyn Error>> {
        let embedding_capsule_and_profile = match self.embedding_capsule_and_profile {
            Some((capsule, profile)) => Some((
                parse_hash(&capsule, "embedding.capsule")?,
                parse_hash(&profile, "embedding.profile")?,
            )),
            None => None,
        };
        Ok(KnowledgeSnapshot {
            parent_snapshot_id: self.parent_snapshot_id.map(|value| parse_hash(&value, "parent_snapshot_id")).transpose()?,
            eligible_mindlink_ids: parse_hashes(&self.eligible_mindlink_ids, "eligible_mindlink_id")?,
            exclusion_ids: parse_hashes(&self.exclusion_ids, "exclusion_id")?,
            rights_policy_root: parse_hash(&self.rights_policy_root, "rights_policy_root")?,
            normalization_profile_root: parse_hash(&self.normalization_profile_root, "normalization_profile_root")?,
            chunking_profile_root: parse_hash(&self.chunking_profile_root, "chunking_profile_root")?,
            embedding_capsule_and_profile,
            index_roots: self.index_roots.into_core()?,
            builders: self.builders.into_iter().map(|builder| {
                Ok(SnapshotBuilder {
                    builder_key: parse_hash(&builder.builder_key, "builder.key")?,
                    control_cluster: parse_hash(&builder.control_cluster, "builder.control_cluster")?,
                    implementation_root: parse_hash(&builder.implementation_root, "builder.implementation_root")?,
                })
            }).collect::<Result<Vec<_>, Box<dyn Error>>>()?,
            builder_threshold: self.builder_threshold,
            availability_certificate_id: parse_hash(&self.availability_certificate_id, "availability_certificate_id")?,
            challenge_end_height: self.challenge_end_height,
            activation_height: self.activation_height,
            retirement_height: self.retirement_height,
            rollback_parent_id: self.rollback_parent_id.map(|value| parse_hash(&value, "rollback_parent_id")).transpose()?,
            snapshot_id: parse_hash(&self.snapshot_id, "snapshot_id")?,
            signatures: self.signatures.into_iter().map(|signature| {
                Ok(SnapshotSignature {
                    builder_index: signature.builder_index,
                    signature: parse_signature(&signature.signature, "snapshot.signature")?,
                })
            }).collect::<Result<Vec<_>, Box<dyn Error>>>()?,
        })
    }
}

fn digest_ids(domain: DomainId, label: &[u8], ids: &[Hash32]) -> Result<Hash32, Box<dyn Error>> {
    let mut body = Vec::with_capacity(ids.len().saturating_mul(32));
    for id in ids {
        body.extend(id);
    }
    hash_domain(domain, &[label, &body])
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|error| invalid(format!("evidence root failure: {error:?}")))
}

fn roots_evidence(roots: KnowledgeIndexRoots) -> IndexRootsEvidence {
    IndexRootsEvidence {
        lexical_root: hex::encode(roots.lexical_root),
        vector_root: hex::encode(roots.vector_root),
        graph_root: hex::encode(roots.graph_root),
        citation_root: hex::encode(roots.citation_root),
    }
}

fn receipt_evidence(receipt: RetrievalReceipt) -> ReceiptEvidence {
    ReceiptEvidence {
        job_id: hex::encode(receipt.job_id),
        snapshot_id: hex::encode(receipt.snapshot_id),
        query_commitment: hex::encode(receipt.query_commitment),
        retrieval_policy_root: hex::encode(receipt.retrieval_policy_root),
        index_roots: roots_evidence(receipt.index_roots),
        selected_mindlink_ids: receipt.selected_mindlink_ids.into_iter().map(hex::encode).collect(),
        rank_scores_q20: receipt.rank_scores_q20,
        citation_spans: receipt.citation_spans.into_iter().map(|span: CitationSpan| CitationSpanEvidence {
            selected_index: span.selected_index,
            context_start: span.context_start,
            context_end: span.context_end,
        }).collect(),
        output_context_root: hex::encode(receipt.output_context_root),
        executor_key: hex::encode(receipt.executor_key),
        receipt_id: hex::encode(receipt.receipt_id),
        signature: hex::encode(receipt.signature),
    }
}

fn canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(invalid("floating point is forbidden in canonical evidence"));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(value) => output.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 { output.push(b','); }
                canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 { output.push(b','); }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn execute(request_bytes: &[u8], executor_seed: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    if request_bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(invalid("request exceeds one MiB"));
    }
    let request: OperatorRequest = serde_json::from_slice(request_bytes)?;
    if request.schema != REQUEST_SCHEMA
        || request.mindlinks.is_empty()
        || request.mindlinks.len() > MAX_REQUEST_MINDLINKS
        || request.transitions.is_empty()
        || request.transitions.len() > MAX_REQUEST_TRANSITIONS
        || request.retrieval.query.is_empty()
        || request.retrieval.query.len() > MAX_QUERY_BYTES
    {
        return Err(invalid("request bounds or schema invalid"));
    }
    if WWM_MINDLINK_REGISTRY_ENABLED
        || WWM_KNOWLEDGE_SNAPSHOTS_ENABLED
        || WWM_PUBLIC_RETRIEVAL_ENABLED
        || WWM_TRAINING_PROMOTION_ENABLED
    {
        return Err(invalid("production controls must remain disabled"));
    }
    let reviewer_keys = request.reviewer_keys.iter()
        .map(|key| parse_hash(key, "reviewer_key"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if reviewer_keys.len() != request.reviewer_keys.len() {
        return Err(invalid("reviewer keys must be unique"));
    }
    let executor = Keypair::from_seed(executor_seed);
    if executor.public_key().into_bytes() != parse_hash(&request.executor_public_key, "executor_public_key")? {
        return Err(invalid("executor seed does not match requested public key"));
    }
    let mut service = RightsFirstKnowledgeService::new(reviewer_keys)
        .map_err(|error| invalid(format!("service initialization rejected: {error:?}")))?;
    let mut contribution_ids = Vec::with_capacity(request.mindlinks.len());
    for record in request.mindlinks {
        let id = service.intake_signed(record.into_core()?)
            .map_err(|error| invalid(format!("MindLink intake rejected: {error:?}")))?;
        contribution_ids.push(id);
    }
    contribution_ids.sort_unstable();
    let mut transition_ids = Vec::with_capacity(request.transitions.len());
    for record in request.transitions {
        let transition = record.into_core()?;
        transition_ids.push(transition.transition_id);
        service.apply_transition(transition)
            .map_err(|error| invalid(format!("lifecycle transition rejected: {error:?}")))?;
    }
    transition_ids.sort_unstable();
    for id in &contribution_ids {
        if service.graph().state(id).map(|state| state.lifecycle) != Some(Lifecycle::SnapshotAccepted) {
            return Err(invalid("every contribution must complete mandatory challenge and snapshot acceptance"));
        }
    }
    let profile = RetrievalProfile::deterministic_ascii_v1(request.retrieval.profile_maximum_results)
        .map_err(|error| invalid(format!("retrieval profile rejected: {error:?}")))?;
    let snapshot = request.snapshot.into_core()?;
    let snapshot_id = service.register_signed_snapshot(snapshot, profile)
        .map_err(|error| invalid(format!("signed snapshot rejected: {error:?}")))?;
    if snapshot_id != parse_hash(&request.retrieval.snapshot_id, "retrieval.snapshot_id")? {
        return Err(invalid("pinned query snapshot disagrees with signed snapshot"));
    }
    let result = service.retrieve_pinned(&executor, PinnedRetrievalRequest {
        job_id: parse_hash(&request.retrieval.job_id, "retrieval.job_id")?,
        snapshot_id,
        query: request.retrieval.query,
        maximum_results: request.retrieval.maximum_results,
        retrieval_policy_root: parse_hash(&request.retrieval.retrieval_policy_root, "retrieval.policy_root")?,
    }).map_err(|error| invalid(format!("pinned retrieval rejected: {error:?}")))?;
    result.receipt.validate().map_err(|error| invalid(format!("receipt verification failed: {error:?}")))?;
    let contribution_root = digest_ids(DomainId::WwmMindlink, b"OPERATOR-EVIDENCE-CONTRIBUTIONS/V1", &contribution_ids)?;
    let transition_root = digest_ids(DomainId::WwmMindlinkTransition, b"OPERATOR-EVIDENCE-TRANSITIONS/V1", &transition_ids)?;
    let evidence = OperatorEvidence {
        schema: EVIDENCE_SCHEMA,
        contribution_root: hex::encode(contribution_root),
        contribution_ids: contribution_ids.into_iter().map(hex::encode).collect(),
        lifecycle_transition_root: hex::encode(transition_root),
        snapshot_root: hex::encode(snapshot_id),
        index_roots: roots_evidence(result.receipt.index_roots),
        receipt_root: hex::encode(result.receipt.receipt_id),
        citations: result.citations.into_iter().map(|citation| CitationEvidence {
            mindlink_id: hex::encode(citation.mindlink_id),
            content_root: hex::encode(citation.content_root),
            context_start: citation.context_start,
            context_end: citation.context_end,
        }).collect(),
        retrieval_receipt: receipt_evidence(result.receipt),
        production_controls: ProductionControls {
            wwm_mindlink_registry_enabled: WWM_MINDLINK_REGISTRY_ENABLED,
            wwm_knowledge_snapshots_enabled: WWM_KNOWLEDGE_SNAPSHOTS_ENABLED,
            wwm_public_retrieval_enabled: WWM_PUBLIC_RETRIEVAL_ENABLED,
            wwm_training_promotion_enabled: WWM_TRAINING_PROMOTION_ENABLED,
            production_evidence: false,
        },
    };
    let value = serde_json::to_value(evidence)?;
    let mut bytes = Vec::new();
    canonical_json(&Value::Object(value.as_object().cloned().unwrap_or_else(Map::new)), &mut bytes)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(invalid(format!("{label} is not a bounded regular file")));
    }
    Ok(fs::read(path)?)
}

fn run_paths(request_path: &Path, output_path: &Path, seed_path: &Path) -> Result<(), Box<dyn Error>> {
    let request = read_bounded(request_path, MAX_REQUEST_BYTES, "request")?;
    let seed_bytes = read_bounded(seed_path, 128, "executor seed")?;
    let seed_text = std::str::from_utf8(&seed_bytes)?.trim();
    let seed = parse_hash(seed_text, "executor seed")?;
    let evidence = execute(&request, seed)?;
    let mut output = OpenOptions::new().write(true).create_new(true).open(output_path)?;
    output.write_all(&evidence)?;
    output.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err(invalid("usage: mindlink_retrieval_operator <request.json> <evidence.json> <executor-seed.hex>"));
    }
    run_paths(Path::new(&arguments[0]), Path::new(&arguments[1]), Path::new(&arguments[2]))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::expect_used,
        clippy::unwrap_used
    )]

    use super::*;
    use noos_mind::service::{
        AdvisoryIndexRoots, SnapshotBuildReport, SnapshotPlan, REVOCATION_SEMANTICS_V1,
    };
    use noos_mind::{MindLinkDraft, Provenance};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn transition(
        reviewer: &Keypair,
        mindlink_id: Hash32,
        prior: Lifecycle,
        next: Lifecycle,
        height: u64,
    ) -> MindLinkTransition {
        MindLinkTransition::new(
            reviewer,
            mindlink_id,
            prior,
            next,
            h(u8::try_from(height).unwrap()),
            (next == Lifecycle::Challenged)
                .then(|| vec![h(60)])
                .unwrap_or_default(),
            matches!(
                next,
                Lifecycle::Quarantined
                    | Lifecycle::ProvenanceChecked
                    | Lifecycle::RetrievalEligible
            )
            .then(|| vec![h(61)])
            .unwrap_or_default(),
            height,
        )
        .unwrap()
    }

    fn transition_name(value: Lifecycle) -> &'static str {
        match value {
            Lifecycle::LocalDraft => "LOCAL_DRAFT",
            Lifecycle::Submitted => "SUBMITTED",
            Lifecycle::Quarantined => "QUARANTINED",
            Lifecycle::ProvenanceChecked => "PROVENANCE_CHECKED",
            Lifecycle::Challenged => "CHALLENGED",
            Lifecycle::RetrievalEligible => "RETRIEVAL_ELIGIBLE",
            Lifecycle::SnapshotCandidate => "SNAPSHOT_CANDIDATE",
            Lifecycle::SnapshotAccepted => "SNAPSHOT_ACCEPTED",
            Lifecycle::TrainingCandidate => "TRAINING_CANDIDATE",
            Lifecycle::DatasetAccepted => "DATASET_ACCEPTED",
            Lifecycle::Rejected => "REJECTED",
            Lifecycle::RevokedFutureUse => "REVOKED_FUTURE_USE",
        }
    }

    fn transition_record(value: &MindLinkTransition) -> TransitionRecord {
        TransitionRecord {
            mindlink_id: hex::encode(value.mindlink_id),
            prior: transition_name(value.prior).to_owned(),
            next: transition_name(value.next).to_owned(),
            actor_key: hex::encode(value.actor_key),
            reason_root: hex::encode(value.reason_root),
            challenge_ids: value.challenge_ids.iter().map(hex::encode).collect(),
            moderation_decision_ids: value
                .moderation_decision_ids
                .iter()
                .map(hex::encode)
                .collect(),
            height: value.height,
            transition_id: hex::encode(value.transition_id),
            signature: hex::encode(value.signature),
        }
    }

    fn link_record(value: &MindLink) -> MindLinkRecord {
        let content = match &value.content {
            ContentPayload::Public {
                original_text,
                summary,
                summary_derived,
            } => ContentRecord::Public {
                original_text: original_text.clone(),
                summary: summary.clone(),
                summary_derived: *summary_derived,
            },
            ContentPayload::Sealed {
                encrypted_content_root,
                summary,
                summary_derived,
            } => ContentRecord::Sealed {
                encrypted_content_root: hex::encode(encrypted_content_root),
                summary: summary.clone(),
                summary_derived: *summary_derived,
            },
        };
        let contributor = match &value.contributor {
            ContributorIdentity::Named {
                public_key,
                display_name,
            } => ContributorRecord::Named {
                public_key: hex::encode(public_key),
                display_name: display_name.clone(),
            },
            ContributorIdentity::Pseudonymous {
                public_key,
                display_name,
            } => ContributorRecord::Pseudonymous {
                public_key: hex::encode(public_key),
                display_name: display_name.clone(),
            },
            ContributorIdentity::BlindCredential {
                credential_root,
                display_name,
            } => ContributorRecord::BlindCredential {
                credential_root: hex::encode(credential_root),
                display_name: display_name.clone(),
            },
        };
        MindLinkRecord {
            predecessors: value.predecessors.iter().map(hex::encode).collect(),
            supersedes: value.supersedes.iter().map(hex::encode).collect(),
            kind: "SOURCE".to_owned(),
            title: value.title.clone(),
            content,
            language: value.language.clone(),
            locale: value.locale.clone(),
            domain_tags: value.domain_tags.clone(),
            uncertainty: value.uncertainty.clone(),
            contributor,
            authority: vec![],
            provenance: ProvenanceRecord {
                sources: value
                    .provenance
                    .sources
                    .iter()
                    .map(|source| ProvenanceSourceRecord {
                        uri: source.uri.clone(),
                        content_hash: hex::encode(source.content_hash),
                        title: source.title.clone(),
                        publisher: source.publisher.clone(),
                        retrieved_at_unix_seconds: source.retrieved_at_unix_seconds,
                    })
                    .collect(),
                evidence_ids: value.provenance.evidence_ids.iter().map(hex::encode).collect(),
                derived_from: value.provenance.derived_from.iter().map(hex::encode).collect(),
                c2pa_manifest_refs: value.provenance.c2pa_manifest_refs.clone(),
            },
            relations: vec![],
            rights: RightsRecord {
                visibility: "PUBLIC".to_owned(),
                retrieval_permission: "ALLOW".to_owned(),
                training_permission: "DENY".to_owned(),
                commercial_use: "DENY".to_owned(),
                derivative_model_permission: "DENY".to_owned(),
                attribution_required: true,
                license: value.rights.license.clone(),
                retention_request: value.rights.retention_request.clone(),
                cultural_constraints: value.rights.cultural_constraints.clone(),
            },
            challenge: ChallengeRecord {
                status: "UNCHALLENGED".to_owned(),
                policy_root: hex::encode(value.challenge.policy_root),
                bond_micro_noos: value.challenge.bond_micro_noos,
                open_challenge_ids: vec![],
            },
            moderation: ModerationRecord {
                namespace_root: hex::encode(value.moderation.namespace_root),
                status: "NOT_REVIEWED".to_owned(),
                decision_ids: vec![],
            },
            initial_lifecycle: "SUBMITTED".to_owned(),
            created_height: value.created_height,
            content_root: hex::encode(value.content_root),
            provenance_root: hex::encode(value.provenance_root),
            rights_root: hex::encode(value.rights_root),
            relations_root: hex::encode(value.relations_root),
            mindlink_id: hex::encode(value.mindlink_id),
            signature: hex::encode(value.signature_or_credential_proof),
        }
    }

    fn snapshot_record(value: &KnowledgeSnapshot) -> SnapshotRecord {
        SnapshotRecord {
            parent_snapshot_id: value.parent_snapshot_id.map(hex::encode),
            eligible_mindlink_ids: value
                .eligible_mindlink_ids
                .iter()
                .map(hex::encode)
                .collect(),
            exclusion_ids: value.exclusion_ids.iter().map(hex::encode).collect(),
            rights_policy_root: hex::encode(value.rights_policy_root),
            normalization_profile_root: hex::encode(value.normalization_profile_root),
            chunking_profile_root: hex::encode(value.chunking_profile_root),
            embedding_capsule_and_profile: value
                .embedding_capsule_and_profile
                .map(|(capsule, profile)| (hex::encode(capsule), hex::encode(profile))),
            index_roots: IndexRootsRecord {
                lexical_root: hex::encode(value.index_roots.lexical_root),
                vector_root: hex::encode(value.index_roots.vector_root),
                graph_root: hex::encode(value.index_roots.graph_root),
                citation_root: hex::encode(value.index_roots.citation_root),
            },
            builders: value
                .builders
                .iter()
                .map(|builder| BuilderRecord {
                    builder_key: hex::encode(builder.builder_key),
                    control_cluster: hex::encode(builder.control_cluster),
                    implementation_root: hex::encode(builder.implementation_root),
                })
                .collect(),
            builder_threshold: value.builder_threshold,
            availability_certificate_id: hex::encode(value.availability_certificate_id),
            challenge_end_height: value.challenge_end_height,
            activation_height: value.activation_height,
            retirement_height: value.retirement_height,
            rollback_parent_id: value.rollback_parent_id.map(hex::encode),
            snapshot_id: hex::encode(value.snapshot_id),
            signatures: value
                .signatures
                .iter()
                .map(|signature| SnapshotSignatureRecord {
                    builder_index: signature.builder_index,
                    signature: hex::encode(signature.signature),
                })
                .collect(),
        }
    }

    fn signed_fixture() -> (Vec<u8>, [u8; 32], String) {
        let contributor = Keypair::from_seed([1; 32]);
        let reviewer = Keypair::from_seed([2; 32]);
        let executor_seed = [3; 32];
        let executor = Keypair::from_seed(executor_seed);
        let link = MindLink::finalize_signed(
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
                        uri: "https://data.example.test/gauges/7".to_owned(),
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
            },
            &contributor,
        )
        .unwrap();
        let stages = [
            (Lifecycle::Submitted, Lifecycle::Quarantined),
            (Lifecycle::Quarantined, Lifecycle::ProvenanceChecked),
            (Lifecycle::ProvenanceChecked, Lifecycle::Challenged),
            (Lifecycle::Challenged, Lifecycle::RetrievalEligible),
            (Lifecycle::RetrievalEligible, Lifecycle::SnapshotCandidate),
            (Lifecycle::SnapshotCandidate, Lifecycle::SnapshotAccepted),
        ];
        let transitions = stages
            .into_iter()
            .enumerate()
            .map(|(offset, (prior, next))| {
                transition(
                    &reviewer,
                    link.mindlink_id,
                    prior,
                    next,
                    11 + u64::try_from(offset).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut fixture_service = RightsFirstKnowledgeService::new(BTreeSet::from([
            reviewer.public_key().into_bytes(),
        ]))
        .unwrap();
        fixture_service.intake_signed(link.clone()).unwrap();
        for value in &transitions {
            fixture_service.apply_transition(value.clone()).unwrap();
        }
        let profile = RetrievalProfile::deterministic_ascii_v1(16).unwrap();
        let mut builders = (0_u8..2)
            .map(|index| {
                let signer = Keypair::from_seed([40 + index; 32]);
                let builder = SnapshotBuilder {
                    builder_key: signer.public_key().into_bytes(),
                    control_cluster: h(50 + index),
                    implementation_root: h(52 + index),
                };
                (signer, builder)
            })
            .collect::<Vec<_>>();
        builders.sort_by_key(|(_, builder)| builder.builder_key);
        let reports = builders
            .iter()
            .map(|(_, builder)| {
                SnapshotBuildReport::build(
                    builder.clone(),
                    fixture_service.graph(),
                    vec![link.mindlink_id],
                    &profile,
                    AdvisoryIndexRoots {
                        vector_root: h(73),
                        graph_root: h(74),
                        citation_root: h(75),
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let plan = SnapshotPlan {
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
        };
        let mut snapshot = KnowledgeSnapshot::new(
            plan.parent_snapshot_id,
            vec![link.mindlink_id],
            plan.exclusion_ids,
            plan.rights_policy_root,
            plan.normalization_profile_root,
            plan.chunking_profile_root,
            plan.embedding_capsule_and_profile,
            reports[0].index_roots,
            builders.iter().map(|(_, builder)| builder.clone()).collect(),
            plan.builder_threshold,
            plan.availability_certificate_id,
            plan.challenge_end_height,
            plan.activation_height,
            plan.retirement_height,
            plan.rollback_parent_id,
        )
        .unwrap();
        for (signer, _) in &builders {
            snapshot.add_signature(signer).unwrap();
        }
        let request = OperatorRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            reviewer_keys: vec![hex::encode(reviewer.public_key().into_bytes())],
            mindlinks: vec![link_record(&link)],
            transitions: transitions.iter().map(transition_record).collect(),
            snapshot: snapshot_record(&snapshot),
            retrieval: RetrievalRecord {
                job_id: hex::encode(h(80)),
                snapshot_id: hex::encode(snapshot.snapshot_id),
                query: "river gauge".to_owned(),
                maximum_results: 4,
                retrieval_policy_root: hex::encode(h(81)),
                profile_maximum_results: 16,
            },
            executor_public_key: hex::encode(executor.public_key().into_bytes()),
        };
        (
            serde_json::to_vec(&request).unwrap(),
            executor_seed,
            hex::encode(snapshot.snapshot_id),
        )
    }

    #[test]
    fn one_shot_smoke_emits_verifiable_receipt_without_secret_or_raw_context() {
        let (request, seed, snapshot_id) = signed_fixture();
        let evidence = execute(&request, seed).unwrap();
        assert!(evidence.ends_with(b"\n"));
        assert!(!evidence.windows(64).any(|window| window == hex::encode(seed).as_bytes()));
        assert!(!String::from_utf8_lossy(&evidence).contains("Gauge 7 read"));
        let value: Value = serde_json::from_slice(&evidence).unwrap();
        assert_eq!(value["snapshot_root"], snapshot_id);
        assert_eq!(value["citations"].as_array().unwrap().len(), 1);
        assert_eq!(value["production_controls"]["wwm_mindlink_registry_enabled"], false);
        assert_eq!(value["production_controls"]["wwm_knowledge_snapshots_enabled"], false);
        assert_eq!(value["production_controls"]["wwm_public_retrieval_enabled"], false);
        assert_eq!(value["production_controls"]["wwm_training_promotion_enabled"], false);
        let receipt = &value["retrieval_receipt"];
        let index = &receipt["index_roots"];
        RetrievalReceipt {
            job_id: parse_hash(receipt["job_id"].as_str().unwrap(), "job").unwrap(),
            snapshot_id: parse_hash(receipt["snapshot_id"].as_str().unwrap(), "snapshot").unwrap(),
            query_commitment: parse_hash(receipt["query_commitment"].as_str().unwrap(), "query").unwrap(),
            retrieval_policy_root: parse_hash(receipt["retrieval_policy_root"].as_str().unwrap(), "policy").unwrap(),
            index_roots: KnowledgeIndexRoots {
                lexical_root: parse_hash(index["lexical_root"].as_str().unwrap(), "lexical").unwrap(),
                vector_root: parse_hash(index["vector_root"].as_str().unwrap(), "vector").unwrap(),
                graph_root: parse_hash(index["graph_root"].as_str().unwrap(), "graph").unwrap(),
                citation_root: parse_hash(index["citation_root"].as_str().unwrap(), "citation").unwrap(),
            },
            selected_mindlink_ids: receipt["selected_mindlink_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| parse_hash(id.as_str().unwrap(), "selected").unwrap())
                .collect(),
            rank_scores_q20: receipt["rank_scores_q20"]
                .as_array()
                .unwrap()
                .iter()
                .map(|score| score.as_i64().unwrap())
                .collect(),
            citation_spans: receipt["citation_spans"]
                .as_array()
                .unwrap()
                .iter()
                .map(|span| CitationSpan {
                    selected_index: u16::try_from(span["selected_index"].as_u64().unwrap()).unwrap(),
                    context_start: u32::try_from(span["context_start"].as_u64().unwrap()).unwrap(),
                    context_end: u32::try_from(span["context_end"].as_u64().unwrap()).unwrap(),
                })
                .collect(),
            output_context_root: parse_hash(receipt["output_context_root"].as_str().unwrap(), "context").unwrap(),
            executor_key: parse_hash(receipt["executor_key"].as_str().unwrap(), "executor").unwrap(),
            receipt_id: parse_hash(receipt["receipt_id"].as_str().unwrap(), "receipt").unwrap(),
            signature: parse_signature(receipt["signature"].as_str().unwrap(), "signature").unwrap(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn rejects_implicit_training_rights_replay_and_builder_failures() {
        let (request, seed, _) = signed_fixture();
        let mut missing_rights: Value = serde_json::from_slice(&request).unwrap();
        missing_rights["mindlinks"][0]["rights"]
            .as_object_mut()
            .unwrap()
            .remove("training_permission");
        assert!(execute(&serde_json::to_vec(&missing_rights).unwrap(), seed).is_err());

        let mut replay: Value = serde_json::from_slice(&request).unwrap();
        let duplicate = replay["transitions"][0].clone();
        replay["transitions"].as_array_mut().unwrap().insert(1, duplicate);
        assert!(execute(&serde_json::to_vec(&replay).unwrap(), seed).is_err());

        let mut same_cluster: Value = serde_json::from_slice(&request).unwrap();
        let cluster = same_cluster["snapshot"]["builders"][0]["control_cluster"].clone();
        same_cluster["snapshot"]["builders"][1]["control_cluster"] = cluster;
        assert!(execute(&serde_json::to_vec(&same_cluster).unwrap(), seed).is_err());

        let mut root_disagreement: Value = serde_json::from_slice(&request).unwrap();
        root_disagreement["snapshot"]["index_roots"]["lexical_root"] =
            Value::String(hex::encode(h(99)));
        assert!(execute(&serde_json::to_vec(&root_disagreement).unwrap(), seed).is_err());
    }

    #[test]
    fn path_runner_creates_insert_once_canonical_evidence() {
        let (request, seed, _) = signed_fixture();
        if let Some(export_root) = env::var_os("NOOS_MIND_TEST_FIXTURE_DIR") {
            let export_root = Path::new(&export_root);
            fs::create_dir_all(export_root).unwrap();
            fs::write(export_root.join("request.json"), &request).unwrap();
            fs::write(export_root.join("executor-seed.hex"), hex::encode(seed)).unwrap();
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("noos-mind-operator-{nonce}"));
        fs::create_dir(&root).unwrap();
        let request_path = root.join("request.json");
        let evidence_path = root.join("evidence.json");
        let seed_path = root.join("executor-seed.hex");
        fs::write(&request_path, &request).unwrap();
        fs::write(&seed_path, hex::encode(seed)).unwrap();
        run_paths(&request_path, &evidence_path, &seed_path).unwrap();
        let first = fs::read(&evidence_path).unwrap();
        assert!(run_paths(&request_path, &evidence_path, &seed_path).is_err());
        assert_eq!(fs::read(&evidence_path).unwrap(), first);
        let parsed: Value = serde_json::from_slice(&first).unwrap();
        let mut reencoded = Vec::new();
        canonical_json(&parsed, &mut reencoded).unwrap();
        reencoded.push(b'\n');
        assert_eq!(first, reencoded);
        fs::remove_dir_all(root).unwrap();
    }
}
