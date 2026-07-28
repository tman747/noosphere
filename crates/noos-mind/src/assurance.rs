//! Deterministic poisoning, Sybil, challenge, reviewer-separation, and
//! contributor-revocation campaigns for the append-only knowledge graph.

use crate::{
    BlindCredentialVerifier, ChallengeState, ChallengeStatus, ContentPayload, ContributorIdentity,
    Hash32, KnowledgeGraph, Lifecycle, MindError, MindLink, MindLinkDraft, MindLinkTransition,
    MindLinkType, ModerationState, ModerationStatus, Permission, Provenance, RightsPolicy,
    Visibility,
};
use noos_crypto::Keypair;
use serde::Serialize;
use std::collections::BTreeSet;

pub const KNOWLEDGE_ASSURANCE_SCHEMA: &str = "noos/knowledge-poison-sybil-campaign/v1";
pub const SYBIL_IDENTITY_COUNT: usize = 128;
pub const CAMPAIGN_IDS: [&str; 5] = [
    "poison_quarantine_rejection",
    "sybil_flood_containment",
    "reviewer_key_separation",
    "challenge_resolution",
    "contributor_revocation",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnowledgeAssuranceError {
    InvalidSourceRevision,
    Mind(MindError),
    Invariant(&'static str),
}

impl From<MindError> for KnowledgeAssuranceError {
    fn from(value: MindError) -> Self {
        Self::Mind(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KnowledgeCampaignStep {
    pub campaign_id: String,
    pub verdict: String,
    pub attempted_objects: u64,
    pub rejected_actions: u64,
    pub eligible_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KnowledgeAssuranceReport {
    pub schema: String,
    pub source_revision: String,
    pub seed: u64,
    pub production_authorized: bool,
    pub promotion_effect: String,
    pub verdict: String,
    pub steps: Vec<KnowledgeCampaignStep>,
}

struct RejectBlindCredentials;

impl BlindCredentialVerifier for RejectBlindCredentials {
    fn verify(&self, _: Hash32, _: Hash32, _: &[u8], _: [u8; 64]) -> bool {
        false
    }
}

pub fn run_knowledge_assurance_campaign(
    source_revision: &str,
    seed: u64,
) -> Result<KnowledgeAssuranceReport, KnowledgeAssuranceError> {
    validate_revision(source_revision)?;
    let steps = vec![
        poison_quarantine_campaign(seed)?,
        sybil_flood_campaign(seed)?,
        reviewer_separation_campaign(seed)?,
        challenge_resolution_campaign(seed)?,
        contributor_revocation_campaign(seed)?,
    ];
    require(
        steps.len() == CAMPAIGN_IDS.len()
            && steps
                .iter()
                .zip(CAMPAIGN_IDS)
                .all(|(step, id)| step.campaign_id == id && step.verdict == "PASS"),
        "knowledge campaign coverage mismatch",
    )?;
    Ok(KnowledgeAssuranceReport {
        schema: KNOWLEDGE_ASSURANCE_SCHEMA.to_owned(),
        source_revision: source_revision.to_owned(),
        seed,
        production_authorized: false,
        promotion_effect: "NONE".to_owned(),
        verdict: "PASS".to_owned(),
        steps,
    })
}

fn poison_quarantine_campaign(seed: u64) -> Result<KnowledgeCampaignStep, KnowledgeAssuranceError> {
    let contributor = keypair(seed, 1);
    let reviewer = keypair(seed, 2);
    let mut graph = graph_with_reviewer(&reviewer)?;
    let mut draft = draft(&contributor, seed, 1, Permission::Allow);
    draft.kind = MindLinkType::Claim;
    draft.content = ContentPayload::Public {
        original_text: "Known poison canary: invented dosage asserted as verified fact.".to_owned(),
        summary: "Known poison canary.".to_owned(),
        summary_derived: false,
    };
    draft.uncertainty = "Adversarial fixture with no supporting provenance.".to_owned();
    let link = MindLink::finalize_signed(draft, &contributor)?;
    let id = link.mindlink_id;
    graph.register(link, &RejectBlindCredentials)?;
    apply(
        &mut graph,
        &reviewer,
        id,
        Lifecycle::Submitted,
        Lifecycle::Quarantined,
        20,
        seed,
    )?;
    let rejected = transition(
        &reviewer,
        id,
        Lifecycle::Quarantined,
        Lifecycle::Rejected,
        21,
        seed,
    )?;
    graph.apply_transition(rejected.clone())?;
    require(
        graph.apply_transition(rejected) == Err(MindError::DuplicateTransition),
        "poison rejection replay was accepted",
    )?;
    require_not_eligible(&graph, id)?;
    require(
        graph.state(&id).is_some_and(|state| {
            state.lifecycle == Lifecycle::Rejected
                && state.moderation == ModerationStatus::ReviewedRejected
        }),
        "poison did not remain rejected",
    )?;
    Ok(step(
        "poison_quarantine_rejection",
        1,
        1,
        eligible_count(&graph)?,
    ))
}

fn sybil_flood_campaign(seed: u64) -> Result<KnowledgeCampaignStep, KnowledgeAssuranceError> {
    let reviewer = keypair(seed, 3);
    let mut graph = graph_with_reviewer(&reviewer)?;
    let mut unauthorized = 0_u64;
    for index in 0..SYBIL_IDENTITY_COUNT {
        let contributor = keypair(
            seed,
            u64::try_from(index)
                .map_err(|_| KnowledgeAssuranceError::Invariant("sybil index overflow"))?
                .checked_add(100)
                .ok_or(KnowledgeAssuranceError::Invariant("sybil seed overflow"))?,
        );
        let link = MindLink::finalize_signed(
            draft(
                &contributor,
                seed,
                u64::try_from(index)
                    .map_err(|_| KnowledgeAssuranceError::Invariant("sybil index overflow"))?
                    .checked_add(100)
                    .ok_or(KnowledgeAssuranceError::Invariant("sybil draft overflow"))?,
                Permission::Allow,
            ),
            &contributor,
        )?;
        let id = link.mindlink_id;
        let created = link.created_height;
        graph.register(link, &RejectBlindCredentials)?;
        let unauthorized_transition = transition(
            &contributor,
            id,
            Lifecycle::Submitted,
            Lifecycle::Quarantined,
            created + 1,
            seed,
        )?;
        if graph.apply_transition(unauthorized_transition) == Err(MindError::UnauthorizedTransition)
        {
            unauthorized =
                unauthorized
                    .checked_add(1)
                    .ok_or(KnowledgeAssuranceError::Invariant(
                        "unauthorized counter overflow",
                    ))?;
        }
        apply(
            &mut graph,
            &reviewer,
            id,
            Lifecycle::Submitted,
            Lifecycle::Quarantined,
            created + 1,
            seed,
        )?;
        apply(
            &mut graph,
            &reviewer,
            id,
            Lifecycle::Quarantined,
            Lifecycle::Rejected,
            created + 2,
            seed,
        )?;
        require_not_eligible(&graph, id)?;
    }
    require(
        unauthorized
            == u64::try_from(SYBIL_IDENTITY_COUNT)
                .map_err(|_| KnowledgeAssuranceError::Invariant("sybil count overflow"))?,
        "sybil contributors crossed reviewer boundary",
    )?;
    require(
        graph.snapshot_eligible_ids().is_empty() && graph.training_candidate_ids().is_empty(),
        "sybil flood entered an eligible set",
    )?;
    Ok(step(
        "sybil_flood_containment",
        u64::try_from(SYBIL_IDENTITY_COUNT)
            .map_err(|_| KnowledgeAssuranceError::Invariant("sybil count overflow"))?,
        unauthorized,
        eligible_count(&graph)?,
    ))
}

fn reviewer_separation_campaign(
    seed: u64,
) -> Result<KnowledgeCampaignStep, KnowledgeAssuranceError> {
    let contributor = keypair(seed, 4);
    let reviewer = keypair(seed, 5);
    let impostor = keypair(seed, 6);
    let mut graph = graph_with_reviewer(&reviewer)?;
    let link = MindLink::finalize_signed(
        draft(&contributor, seed, 500, Permission::Allow),
        &contributor,
    )?;
    let id = link.mindlink_id;
    let height = link.created_height;
    graph.register(link, &RejectBlindCredentials)?;
    let forged = transition(
        &impostor,
        id,
        Lifecycle::Submitted,
        Lifecycle::Quarantined,
        height + 1,
        seed,
    )?;
    require(
        graph.apply_transition(forged) == Err(MindError::UnauthorizedTransition),
        "unregistered reviewer changed knowledge state",
    )?;
    require(
        graph
            .state(&id)
            .is_some_and(|state| state.lifecycle == Lifecycle::Submitted),
        "failed reviewer attempt mutated state",
    )?;
    Ok(step(
        "reviewer_key_separation",
        1,
        1,
        eligible_count(&graph)?,
    ))
}

fn challenge_resolution_campaign(
    seed: u64,
) -> Result<KnowledgeCampaignStep, KnowledgeAssuranceError> {
    let contributor = keypair(seed, 7);
    let reviewer = keypair(seed, 8);
    let mut graph = graph_with_reviewer(&reviewer)?;
    let link = MindLink::finalize_signed(
        draft(&contributor, seed, 600, Permission::Allow),
        &contributor,
    )?;
    let id = link.mindlink_id;
    let height = link.created_height;
    graph.register(link, &RejectBlindCredentials)?;
    apply(
        &mut graph,
        &reviewer,
        id,
        Lifecycle::Submitted,
        Lifecycle::Quarantined,
        height + 1,
        seed,
    )?;
    apply(
        &mut graph,
        &reviewer,
        id,
        Lifecycle::Quarantined,
        Lifecycle::ProvenanceChecked,
        height + 2,
        seed,
    )?;
    apply(
        &mut graph,
        &reviewer,
        id,
        Lifecycle::ProvenanceChecked,
        Lifecycle::Challenged,
        height + 3,
        seed,
    )?;
    apply(
        &mut graph,
        &reviewer,
        id,
        Lifecycle::Challenged,
        Lifecycle::Rejected,
        height + 4,
        seed,
    )?;
    require(
        graph.state(&id).is_some_and(|state| {
            state.lifecycle == Lifecycle::Rejected
                && state.challenge == ChallengeStatus::ResolvedUpheld
        }),
        "upheld challenge did not reject poison",
    )?;
    require_not_eligible(&graph, id)?;
    Ok(step("challenge_resolution", 1, 0, eligible_count(&graph)?))
}

fn contributor_revocation_campaign(
    seed: u64,
) -> Result<KnowledgeCampaignStep, KnowledgeAssuranceError> {
    let contributor = keypair(seed, 9);
    let reviewer = keypair(seed, 10);
    let mut graph = graph_with_reviewer(&reviewer)?;
    let link = MindLink::finalize_signed(
        draft(&contributor, seed, 700, Permission::Allow),
        &contributor,
    )?;
    let id = link.mindlink_id;
    let height = link.created_height;
    graph.register(link, &RejectBlindCredentials)?;
    let path = [
        (Lifecycle::Submitted, Lifecycle::Quarantined),
        (Lifecycle::Quarantined, Lifecycle::ProvenanceChecked),
        (Lifecycle::ProvenanceChecked, Lifecycle::RetrievalEligible),
        (Lifecycle::RetrievalEligible, Lifecycle::SnapshotCandidate),
        (Lifecycle::SnapshotCandidate, Lifecycle::SnapshotAccepted),
        (Lifecycle::SnapshotAccepted, Lifecycle::TrainingCandidate),
    ];
    for (offset, (prior, next)) in path.into_iter().enumerate() {
        apply(
            &mut graph,
            &reviewer,
            id,
            prior,
            next,
            height
                + u64::try_from(offset)
                    .map_err(|_| KnowledgeAssuranceError::Invariant("path overflow"))?
                + 1,
            seed,
        )?;
    }
    require(
        graph.training_candidate_ids().contains(&id),
        "reviewed training candidate never became eligible",
    )?;
    let revoke = transition(
        &contributor,
        id,
        Lifecycle::TrainingCandidate,
        Lifecycle::RevokedFutureUse,
        height + 7,
        seed,
    )?;
    graph.apply_transition(revoke)?;
    require(
        graph.mindlink(&id).is_some(),
        "revocation deleted immutable knowledge object",
    )?;
    require(
        graph.revoked_ids().contains(&id)
            && !graph.training_candidate_ids().contains(&id)
            && !graph.snapshot_eligible_ids().contains(&id),
        "revoked contribution remained eligible",
    )?;
    let reentry = transition(
        &reviewer,
        id,
        Lifecycle::RevokedFutureUse,
        Lifecycle::SnapshotCandidate,
        height + 8,
        seed,
    );
    require(
        reentry == Err(MindError::InvalidTransition),
        "revoked contribution could re-enter lifecycle",
    )?;
    Ok(step(
        "contributor_revocation",
        1,
        1,
        eligible_count(&graph)?,
    ))
}

fn graph_with_reviewer(reviewer: &Keypair) -> Result<KnowledgeGraph, MindError> {
    KnowledgeGraph::with_reviewers(BTreeSet::from([reviewer.public_key().into_bytes()]))
}

fn draft(
    signer: &Keypair,
    seed: u64,
    index: u64,
    training_permission: Permission,
) -> MindLinkDraft {
    let created_height = index.saturating_add(10);
    MindLinkDraft {
        predecessors: Vec::new(),
        supersedes: Vec::new(),
        kind: MindLinkType::Observation,
        title: format!("Knowledge assurance fixture {seed}-{index}"),
        content: ContentPayload::Public {
            original_text: format!("Deterministic knowledge assurance content {seed}-{index}."),
            summary: format!("Assurance fixture {index}."),
            summary_derived: true,
        },
        language: "en".to_owned(),
        locale: "en-US".to_owned(),
        domain_tags: vec!["assurance".to_owned(), "knowledge-safety".to_owned()],
        uncertainty: "Adversarial campaign fixture; no external truth claim.".to_owned(),
        contributor: ContributorIdentity::Pseudonymous {
            public_key: signer.public_key().into_bytes(),
            display_name: format!("campaign-contributor-{index}"),
        },
        authority: Vec::new(),
        provenance: Provenance::default(),
        relations: Vec::new(),
        rights: RightsPolicy {
            visibility: Visibility::Public,
            retrieval_permission: Permission::Allow,
            training_permission,
            commercial_use: Permission::Deny,
            derivative_model_permission: Permission::Deny,
            attribution_required: true,
            license: "CC-BY-4.0".to_owned(),
            retention_request: "retain while canonical".to_owned(),
            cultural_constraints: String::new(),
        },
        challenge: ChallengeState {
            status: ChallengeStatus::Unchallenged,
            policy_root: derive_id(seed, index, b"challenge-policy"),
            bond_micro_noos: 100,
            open_challenge_ids: Vec::new(),
        },
        moderation: ModerationState {
            namespace_root: derive_id(seed, index, b"moderation-namespace"),
            status: ModerationStatus::NotReviewed,
            decision_ids: Vec::new(),
        },
        created_height,
    }
}

fn apply(
    graph: &mut KnowledgeGraph,
    actor: &Keypair,
    id: Hash32,
    prior: Lifecycle,
    next: Lifecycle,
    height: u64,
    seed: u64,
) -> Result<(), KnowledgeAssuranceError> {
    graph.apply_transition(transition(actor, id, prior, next, height, seed)?)?;
    Ok(())
}

fn transition(
    actor: &Keypair,
    id: Hash32,
    prior: Lifecycle,
    next: Lifecycle,
    height: u64,
    seed: u64,
) -> Result<MindLinkTransition, MindError> {
    let challenge_ids = if next == Lifecycle::Challenged {
        vec![derive_id(seed, height, b"challenge")]
    } else {
        Vec::new()
    };
    let moderation_decision_ids = if matches!(
        next,
        Lifecycle::Quarantined
            | Lifecycle::ProvenanceChecked
            | Lifecycle::RetrievalEligible
            | Lifecycle::Rejected
    ) {
        vec![derive_id(seed, height, b"moderation")]
    } else {
        Vec::new()
    };
    MindLinkTransition::new(
        actor,
        id,
        prior,
        next,
        derive_id(seed, height, b"reason"),
        challenge_ids,
        moderation_decision_ids,
        height,
    )
}

fn require_not_eligible(graph: &KnowledgeGraph, id: Hash32) -> Result<(), KnowledgeAssuranceError> {
    require(
        !graph.snapshot_eligible_ids().contains(&id)
            && !graph.training_candidate_ids().contains(&id),
        "unsafe knowledge remained eligible",
    )
}

fn eligible_count(graph: &KnowledgeGraph) -> Result<u64, KnowledgeAssuranceError> {
    let count = graph
        .snapshot_eligible_ids()
        .len()
        .checked_add(graph.training_candidate_ids().len())
        .ok_or(KnowledgeAssuranceError::Invariant(
            "eligible count overflow",
        ))?;
    u64::try_from(count)
        .map_err(|_| KnowledgeAssuranceError::Invariant("eligible count conversion overflow"))
}

fn step(
    id: &str,
    attempted_objects: u64,
    rejected_actions: u64,
    eligible_after: u64,
) -> KnowledgeCampaignStep {
    KnowledgeCampaignStep {
        campaign_id: id.to_owned(),
        verdict: "PASS".to_owned(),
        attempted_objects,
        rejected_actions,
        eligible_after,
    }
}

fn keypair(seed: u64, index: u64) -> Keypair {
    Keypair::from_seed(derive_id(seed, index, b"key"))
}

fn derive_id(seed: u64, index: u64, label: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/KNOWLEDGE-ASSURANCE/ID/V1\0");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

fn validate_revision(source_revision: &str) -> Result<(), KnowledgeAssuranceError> {
    if source_revision.len() == 40
        && source_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(KnowledgeAssuranceError::InvalidSourceRevision)
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), KnowledgeAssuranceError> {
    if condition {
        Ok(())
    } else {
        Err(KnowledgeAssuranceError::Invariant(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVISION: &str = "363fd9eca0868cdde46675e5e15ac079d206ed30";

    #[test]
    fn poison_sybil_challenge_and_revocation_campaigns_pass() {
        let report = run_knowledge_assurance_campaign(REVISION, 20260727).unwrap();
        assert_eq!(report.schema, KNOWLEDGE_ASSURANCE_SCHEMA);
        assert_eq!(report.verdict, "PASS");
        assert!(!report.production_authorized);
        assert_eq!(report.promotion_effect, "NONE");
        assert_eq!(report.steps.len(), CAMPAIGN_IDS.len());
        assert!(report.steps.iter().all(|step| step.eligible_after == 0));
        assert_eq!(report.steps[1].attempted_objects, 128);
        assert_eq!(report.steps[1].rejected_actions, 128);
    }

    #[test]
    fn campaign_is_deterministic() {
        assert_eq!(
            run_knowledge_assurance_campaign(REVISION, 7).unwrap(),
            run_knowledge_assurance_campaign(REVISION, 7).unwrap()
        );
    }

    #[test]
    fn invalid_revision_is_rejected() {
        assert_eq!(
            run_knowledge_assurance_campaign("HEAD", 1),
            Err(KnowledgeAssuranceError::InvalidSourceRevision)
        );
    }
}
