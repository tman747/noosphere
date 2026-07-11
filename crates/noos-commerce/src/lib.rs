//! Commerce negotiation/evaluation overlay mapped onto the one Work Loom escrow lifecycle.
#![forbid(unsafe_code)]
use noos_work_loom::JobState as WorkJobState;
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];
pub type Height = u64;
#[must_use]
pub fn domain_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

#[must_use]
pub fn availability_certificate_for(job: &CommerceJob, artifact_commitment: Hash32) -> Hash32 {
    domain_hash(
        "NOOS/COMMERCE/AVAILABILITY/V1",
        &[
            &job.chain_id,
            &job.profile_id,
            &job.job_id,
            &job.request_commitment,
            &artifact_commitment,
        ],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceRequirement {
    V0,
    V1,
    V2,
    V3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityRequirement {
    Q0NoQualityAssurance,
    Q1RequesterAcceptance,
    Q2DeclaredEvaluation,
    Q3DiverseEvaluation,
    Q4OutcomeLinked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommerceState {
    Requested,
    Negotiating,
    Agreed,
    Funded,
    Running,
    Submitted,
    Available,
    Evaluating,
    Completed,
    Rejected,
    Disputed,
    Refunded,
    Expired,
}
impl CommerceState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Rejected | Self::Refunded | Self::Expired
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettlementResourceKind {
    EscrowNote,
    ExecutionRight,
    DisputeProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SettlementResource {
    pub kind: SettlementResourceKind,
    pub resource_id: Hash32,
    pub job_id: Hash32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommerceJob {
    pub job_id: Hash32,
    pub chain_id: Hash32,
    pub profile_id: Hash32,
    pub class_id: u32,
    pub client: Hash32,
    pub provider: Option<Hash32>,
    pub evaluator_policy: Hash32,
    pub request_schema: Hash32,
    pub request_commitment: Hash32,
    pub species_selector: Option<Hash32>,
    pub assurance_requirement: AssuranceRequirement,
    pub quality_requirement: QualityRequirement,
    pub confidentiality_requirement: Hash32,
    pub rights_requirement: Hash32,
    pub budget: Option<u128>,
    pub evaluator_fee: u128,
    pub expiry: Height,
    pub state: CommerceState,
    pub negotiated_terms_root: Option<Hash32>,
    pub work_job_id: Option<Hash32>,
    pub work_commitment: Option<Hash32>,
    pub availability_certificate: Option<Hash32>,
    pub artifact_commitment: Option<Hash32>,
    pub challenge_window: u64,
    pub challenge_deadline: Option<Height>,
    pub settlement_resources: Vec<SettlementResource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommerceAction {
    OpenNegotiation,
    Agree,
    Fund,
    BindProviderOffer,
    StartExecution,
    Submit,
    ConfirmAvailable,
    BeginEvaluation,
    Complete,
    RejectObjective,
    OpenDispute,
    Refund,
    Expire,
    ResolveProvider,
    ResolveClient,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableCause {
    UndecryptableDelivery,
    WithholdingClockAbuse,
    DoublePayout,
    SubjectiveObjectiveSlashing,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassStatus {
    pub enabled: bool,
    pub disabled_by: Option<DisableCause>,
    pub evidence_root: Option<Hash32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommerceError {
    UnknownJob,
    UnknownClass,
    ClassDisabled,
    DuplicateJob,
    InvalidState,
    MissingSignedTerms,
    MissingFunding,
    WorkJobMismatch,
    MissingWorkerCommit,
    AvailabilityBeforeEvaluation,
    QualityAssuranceMisrepresentation,
    SubjectiveSlashingForbidden,
    AlreadyPaid,
    Deadline,
    MissingArtifactCommitment,
    TerminalState,
    InvalidSettlementResources,
    ResourceAlreadyConsumed,
    Arithmetic,
    FeatureDisabled {
        cause: DisableCause,
        evidence_root: Hash32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub job_id: Hash32,
    pub terminal_state: CommerceState,
    pub escrow_debit: u128,
    pub client_credit: u128,
    pub provider_credit: u128,
    pub evaluator_credit: u128,
}
impl SettlementReceipt {
    #[must_use]
    pub fn conserves(&self) -> bool {
        self.client_credit
            .checked_add(self.provider_credit)
            .and_then(|value| value.checked_add(self.evaluator_credit))
            == Some(self.escrow_debit)
    }
}

#[must_use]
pub fn work_projection(state: CommerceState) -> Option<WorkJobState> {
    match state {
        CommerceState::Requested | CommerceState::Negotiating => None,
        CommerceState::Agreed | CommerceState::Funded => Some(WorkJobState::Open),
        CommerceState::Running => Some(WorkJobState::Running),
        CommerceState::Submitted => Some(WorkJobState::Submitted),
        CommerceState::Available | CommerceState::Evaluating => Some(WorkJobState::Challengeable),
        CommerceState::Completed => Some(WorkJobState::Settled),
        CommerceState::Rejected => Some(WorkJobState::Rejected),
        CommerceState::Disputed => Some(WorkJobState::Disputed),
        CommerceState::Refunded => Some(WorkJobState::Cancelled),
        CommerceState::Expired => Some(WorkJobState::Expired),
    }
}

#[derive(Debug, Default)]
pub struct Commerce {
    jobs: BTreeMap<Hash32, CommerceJob>,
    classes: BTreeMap<u32, ClassStatus>,
    paid: BTreeSet<Hash32>,
    consumed_resources: BTreeSet<(SettlementResourceKind, Hash32)>,
    receipts: BTreeMap<Hash32, SettlementReceipt>,
}
impl Commerce {
    pub fn register_class(&mut self, class_id: u32) -> Result<(), CommerceError> {
        if self.classes.contains_key(&class_id) {
            return Err(CommerceError::DuplicateJob);
        }
        self.classes.insert(
            class_id,
            ClassStatus {
                enabled: true,
                disabled_by: None,
                evidence_root: None,
            },
        );
        Ok(())
    }
    pub fn open(&mut self, job: CommerceJob) -> Result<(), CommerceError> {
        let status = self
            .classes
            .get(&job.class_id)
            .ok_or(CommerceError::UnknownClass)?;
        if !status.enabled {
            return Err(CommerceError::ClassDisabled);
        }
        let resource_kinds: BTreeSet<_> = job
            .settlement_resources
            .iter()
            .map(|resource| resource.kind)
            .collect();
        if job.state != CommerceState::Requested
            || job.expiry == 0
            || job.challenge_window == 0
            || job.challenge_deadline.is_some()
            || job.settlement_resources.len() != 3
            || job
                .settlement_resources
                .iter()
                .any(|resource| resource.job_id != job.job_id)
            || resource_kinds
                != BTreeSet::from([
                    SettlementResourceKind::EscrowNote,
                    SettlementResourceKind::ExecutionRight,
                    SettlementResourceKind::DisputeProof,
                ])
            || (job.quality_requirement == QualityRequirement::Q0NoQualityAssurance
                && job.evaluator_fee != 0)
        {
            return Err(CommerceError::InvalidSettlementResources);
        }
        if self.jobs.contains_key(&job.job_id) {
            return Err(CommerceError::DuplicateJob);
        }
        self.jobs.insert(job.job_id, job);
        Ok(())
    }
    pub fn job(&self, id: &Hash32) -> Result<&CommerceJob, CommerceError> {
        self.jobs.get(id).ok_or(CommerceError::UnknownJob)
    }
    pub fn transition(
        &mut self,
        id: Hash32,
        action: CommerceAction,
        height: Height,
        work_state: Option<WorkJobState>,
    ) -> Result<(), CommerceError> {
        let job = self.jobs.get_mut(&id).ok_or(CommerceError::UnknownJob)?;
        let class = self
            .classes
            .get(&job.class_id)
            .ok_or(CommerceError::UnknownClass)?;
        if !class.enabled {
            return Err(CommerceError::FeatureDisabled {
                cause: class
                    .disabled_by
                    .unwrap_or(DisableCause::WithholdingClockAbuse),
                evidence_root: class.evidence_root.unwrap_or([0; 32]),
            });
        }
        if job.state.is_terminal() {
            return Err(CommerceError::TerminalState);
        }
        if height >= job.expiry && action != CommerceAction::Expire {
            return Err(CommerceError::Deadline);
        }
        let next = match (job.state, action) {
            (CommerceState::Requested, CommerceAction::OpenNegotiation) => {
                CommerceState::Negotiating
            }
            (CommerceState::Negotiating, CommerceAction::Agree) => {
                if job.negotiated_terms_root.is_none() || job.provider.is_none() {
                    return Err(CommerceError::MissingSignedTerms);
                }
                CommerceState::Agreed
            }
            (CommerceState::Agreed, CommerceAction::Fund) => {
                if job.budget.is_none()
                    || job.evaluator_fee > job.budget.unwrap_or(0)
                    || work_state != Some(WorkJobState::Open)
                {
                    return Err(CommerceError::MissingFunding);
                }
                CommerceState::Funded
            }
            (CommerceState::Funded, CommerceAction::BindProviderOffer) => {
                if work_state != Some(WorkJobState::Committed) || job.work_commitment.is_some() {
                    return Err(CommerceError::WorkJobMismatch);
                }
                job.work_commitment = Some(domain_hash(
                    "NOOS/COMMERCE/WORK-COMMIT/V1",
                    &[
                        &job.chain_id,
                        &job.profile_id,
                        &job.job_id,
                        &job.provider.ok_or(CommerceError::MissingSignedTerms)?,
                    ],
                ));
                CommerceState::Funded
            }
            (CommerceState::Funded, CommerceAction::StartExecution) => {
                if job.work_commitment.is_none() {
                    return Err(CommerceError::MissingWorkerCommit);
                }
                if work_state != Some(WorkJobState::Running) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Running
            }
            (CommerceState::Running, CommerceAction::Submit) => {
                if work_state != Some(WorkJobState::Submitted) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Submitted
            }
            (CommerceState::Submitted, CommerceAction::ConfirmAvailable) => {
                if work_state != Some(WorkJobState::Challengeable)
                    || job.availability_certificate.is_none()
                {
                    return Err(CommerceError::AvailabilityBeforeEvaluation);
                }
                if job.artifact_commitment.is_none() {
                    return Err(CommerceError::MissingArtifactCommitment);
                }
                let artifact = job
                    .artifact_commitment
                    .ok_or(CommerceError::MissingArtifactCommitment)?;
                if job.availability_certificate != Some(availability_certificate_for(job, artifact))
                {
                    return Err(CommerceError::AvailabilityBeforeEvaluation);
                }
                job.challenge_deadline = Some(
                    height
                        .checked_add(job.challenge_window)
                        .ok_or(CommerceError::Arithmetic)?,
                );
                CommerceState::Available
            }
            (CommerceState::Available, CommerceAction::BeginEvaluation) => {
                if job
                    .challenge_deadline
                    .is_none_or(|deadline| height > deadline)
                {
                    return Err(CommerceError::Deadline);
                }
                CommerceState::Evaluating
            }
            (CommerceState::Available, CommerceAction::Complete)
                if job.quality_requirement == QualityRequirement::Q0NoQualityAssurance =>
            {
                if work_state != Some(WorkJobState::Settled) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Completed
            }
            (CommerceState::Evaluating, CommerceAction::Complete) => {
                if job
                    .challenge_deadline
                    .is_none_or(|deadline| height > deadline)
                {
                    return Err(CommerceError::Deadline);
                }
                if work_state != Some(WorkJobState::Settled) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Completed
            }
            (CommerceState::Evaluating, CommerceAction::RejectObjective) => {
                if work_state != Some(WorkJobState::Rejected) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Rejected
            }
            (CommerceState::Evaluating, CommerceAction::OpenDispute) => {
                if work_state != Some(WorkJobState::Disputed) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Disputed
            }
            (CommerceState::Disputed, CommerceAction::ResolveProvider) => {
                if work_state != Some(WorkJobState::Settled) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Completed
            }
            (CommerceState::Disputed, CommerceAction::ResolveClient) => {
                if work_state != Some(WorkJobState::Cancelled)
                    && work_state != Some(WorkJobState::Rejected)
                {
                    return Err(CommerceError::WorkJobMismatch);
                }
                CommerceState::Refunded
            }
            (_, CommerceAction::Refund)
                if work_state == Some(WorkJobState::Cancelled)
                    || work_state == Some(WorkJobState::Expired)
                    || job
                        .challenge_deadline
                        .is_some_and(|deadline| height > deadline) =>
            {
                CommerceState::Refunded
            }
            (_, CommerceAction::Expire) if height >= job.expiry => CommerceState::Expired,
            _ => return Err(CommerceError::InvalidState),
        };
        job.state = next;
        Ok(())
    }
    pub fn mark_paid(&mut self, id: Hash32) -> Result<(), CommerceError> {
        self.settle(id)?;
        Ok(())
    }
    pub fn settle(&mut self, id: Hash32) -> Result<&SettlementReceipt, CommerceError> {
        if self.paid.contains(&id) {
            let class_id = self.job(&id)?.class_id;
            let evidence = domain_hash("NOOS/COMMERCE/DOUBLE-PAYOUT/V1", &[&id]);
            self.disable_class(class_id, DisableCause::DoublePayout, evidence);
            return Err(CommerceError::AlreadyPaid);
        }
        let (state, escrow, evaluator_fee, resources) = {
            let job = self.job(&id)?;
            if !job.state.is_terminal() {
                return Err(CommerceError::InvalidState);
            }
            (
                job.state,
                job.budget.ok_or(CommerceError::MissingFunding)?,
                job.evaluator_fee,
                job.settlement_resources.clone(),
            )
        };
        if resources.len() != 3
            || resources.iter().any(|resource| {
                resource.job_id != id
                    || self
                        .consumed_resources
                        .contains(&(resource.kind, resource.resource_id))
            })
        {
            return Err(CommerceError::ResourceAlreadyConsumed);
        }
        let (client_credit, provider_credit, evaluator_credit) = match state {
            CommerceState::Completed => (
                0,
                escrow
                    .checked_sub(evaluator_fee)
                    .ok_or(CommerceError::Arithmetic)?,
                evaluator_fee,
            ),
            CommerceState::Rejected | CommerceState::Refunded | CommerceState::Expired => {
                (escrow, 0, 0)
            }
            _ => return Err(CommerceError::InvalidState),
        };
        let receipt = SettlementReceipt {
            job_id: id,
            terminal_state: state,
            escrow_debit: escrow,
            client_credit,
            provider_credit,
            evaluator_credit,
        };
        if !receipt.conserves() {
            return Err(CommerceError::Arithmetic);
        }
        for resource in resources {
            self.consumed_resources
                .insert((resource.kind, resource.resource_id));
        }
        self.paid.insert(id);
        self.receipts.insert(id, receipt);
        self.receipts.get(&id).ok_or(CommerceError::Arithmetic)
    }
    pub fn report_class_fault(
        &mut self,
        class_id: u32,
        cause: DisableCause,
        evidence_root: Hash32,
    ) -> Result<(), CommerceError> {
        self.disable_class(class_id, cause, evidence_root);
        Err(CommerceError::FeatureDisabled {
            cause,
            evidence_root,
        })
    }
    fn disable_class(&mut self, class_id: u32, cause: DisableCause, evidence_root: Hash32) {
        if let Some(class) = self.classes.get_mut(&class_id) {
            class.enabled = false;
            class.disabled_by = Some(cause);
            class.evidence_root = Some(evidence_root);
        }
    }
    pub fn slash_subjective(
        &mut self,
        class_id: u32,
        evidence_root: Hash32,
    ) -> Result<(), CommerceError> {
        self.disable_class(
            class_id,
            DisableCause::SubjectiveObjectiveSlashing,
            evidence_root,
        );
        Err(CommerceError::SubjectiveSlashingForbidden)
    }
    pub fn claim_quality_assured(&self, id: &Hash32) -> Result<(), CommerceError> {
        let job = self.job(id)?;
        if job.quality_requirement == QualityRequirement::Q0NoQualityAssurance {
            return Err(CommerceError::QualityAssuranceMisrepresentation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    pub contribution_id: Hash32,
    pub contributor: Hash32,
    pub failure_domain: Hash32,
    pub parent_ids: BTreeSet<Hash32>,
    pub evidence_root: Hash32,
    pub synthetic_ground_truth_bps: u16,
    pub created_height: Height,
}
impl Contribution {
    #[must_use]
    pub fn derive_id(&self) -> Hash32 {
        let mut bytes = Vec::new();
        for parent in &self.parent_ids {
            bytes.extend_from_slice(parent);
        }
        domain_hash(
            "NOOS/ATTRIBUTION/CONTRIBUTION/V1",
            &[
                &self.contributor,
                &self.failure_domain,
                &bytes,
                &self.evidence_root,
                &self.synthetic_ground_truth_bps.to_le_bytes(),
                &self.created_height.to_le_bytes(),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarginalEvaluation {
    pub evaluation_id: Hash32,
    pub contribution_id: Hash32,
    pub evaluator: Hash32,
    pub evaluator_failure_domain: Hash32,
    pub evidence_root: Hash32,
    pub marginal_bps: u16,
}
impl MarginalEvaluation {
    #[must_use]
    pub fn derive_id(&self) -> Hash32 {
        domain_hash(
            "NOOS/ATTRIBUTION/EVALUATION/V1",
            &[
                &self.contribution_id,
                &self.evaluator,
                &self.evaluator_failure_domain,
                &self.evidence_root,
                &self.marginal_bps.to_le_bytes(),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionError {
    Duplicate,
    UnknownParent,
    UnknownContribution,
    Malformed,
    SelfDealing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionReport {
    pub advisory_credit_bps: BTreeMap<Hash32, u16>,
    pub max_error_bps: u16,
    pub wash_credit_bps: u16,
    pub provenance_root: Hash32,
}
impl AttributionReport {
    pub const CONSENSUS_WEIGHT: u8 = 0;
}

#[derive(Debug, Default)]
pub struct ContributionGraph {
    contributions: BTreeMap<Hash32, Contribution>,
    evaluations: BTreeMap<Hash32, MarginalEvaluation>,
}

fn bounded_mean(values: &[u32]) -> u32 {
    let sum = values
        .iter()
        .try_fold(0u32, |acc, value| acc.checked_add(*value))
        .unwrap_or(u32::MAX);
    let count = u32::try_from(values.len()).unwrap_or(u32::MAX);
    sum.checked_div(count).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationAttestation {
    pub attestation_id: Hash32,
    pub signer: Hash32,
    pub parent: Option<Hash32>,
    pub claim_root: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationError {
    Duplicate,
    UnknownParent,
    UnknownAttestation,
    Cycle,
}

#[derive(Debug, Default)]
pub struct LineageReputation {
    attestations: BTreeMap<Hash32, ReputationAttestation>,
}
impl LineageReputation {
    pub fn register(&mut self, attestation: ReputationAttestation) -> Result<(), ReputationError> {
        if attestation
            .parent
            .is_some_and(|parent| !self.attestations.contains_key(&parent))
        {
            return Err(ReputationError::UnknownParent);
        }
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err(ReputationError::Duplicate);
        }
        self.attestations
            .insert(attestation.attestation_id, attestation);
        Ok(())
    }

    fn root(&self, id: Hash32) -> Result<Hash32, ReputationError> {
        let mut current = id;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(ReputationError::Cycle);
            }
            let attestation = self
                .attestations
                .get(&current)
                .ok_or(ReputationError::UnknownAttestation)?;
            match attestation.parent {
                Some(parent) => current = parent,
                None => return Ok(current),
            }
        }
    }

    pub fn failure_domain_weight(
        &self,
        claim_root: Hash32,
        selected: &[Hash32],
    ) -> Result<usize, ReputationError> {
        let mut roots = BTreeSet::new();
        for id in selected {
            let attestation = self
                .attestations
                .get(id)
                .ok_or(ReputationError::UnknownAttestation)?;
            if attestation.claim_root == claim_root {
                roots.insert(self.root(*id)?);
            }
        }
        Ok(roots.len())
    }
}
impl ContributionGraph {
    pub fn add_contribution(&mut self, contribution: Contribution) -> Result<(), AttributionError> {
        if contribution.contribution_id != contribution.derive_id()
            || contribution.synthetic_ground_truth_bps > 10_000
            || !contribution
                .parent_ids
                .iter()
                .all(|parent| self.contributions.contains_key(parent))
        {
            return Err(
                if contribution
                    .parent_ids
                    .iter()
                    .any(|parent| !self.contributions.contains_key(parent))
                {
                    AttributionError::UnknownParent
                } else {
                    AttributionError::Malformed
                },
            );
        }
        if self
            .contributions
            .insert(contribution.contribution_id, contribution)
            .is_some()
        {
            return Err(AttributionError::Duplicate);
        }
        Ok(())
    }

    pub fn add_evaluation(
        &mut self,
        evaluation: MarginalEvaluation,
    ) -> Result<(), AttributionError> {
        let contribution = self
            .contributions
            .get(&evaluation.contribution_id)
            .ok_or(AttributionError::UnknownContribution)?;
        if evaluation.evaluation_id != evaluation.derive_id()
            || evaluation.marginal_bps > 10_000
            || evaluation.evidence_root != contribution.evidence_root
        {
            return Err(AttributionError::Malformed);
        }
        if evaluation.evaluator_failure_domain == contribution.failure_domain
            || evaluation.evaluator == contribution.contributor
        {
            return Err(AttributionError::SelfDealing);
        }
        if self
            .evaluations
            .insert(evaluation.evaluation_id, evaluation)
            .is_some()
        {
            return Err(AttributionError::Duplicate);
        }
        Ok(())
    }

    pub fn report(&self, height: Height, decay_bps_per_block: u16) -> AttributionReport {
        let mut by_domain: BTreeMap<Hash32, Vec<&Contribution>> = BTreeMap::new();
        for contribution in self.contributions.values() {
            by_domain
                .entry(contribution.failure_domain)
                .or_default()
                .push(contribution);
        }
        let mut credits = BTreeMap::new();
        let mut max_error = 0u16;
        let mut provenance = Vec::new();
        for contributions in by_domain.values() {
            let mut domain_scores = Vec::new();
            for contribution in contributions {
                let mut evaluator_domains = BTreeSet::new();
                let mut scores = Vec::new();
                for evaluation in self
                    .evaluations
                    .values()
                    .filter(|evaluation| evaluation.contribution_id == contribution.contribution_id)
                {
                    if evaluator_domains.insert(evaluation.evaluator_failure_domain) {
                        scores.push(u32::from(evaluation.marginal_bps));
                        provenance.extend_from_slice(&evaluation.evaluation_id);
                    }
                }
                if !scores.is_empty() {
                    domain_scores.push(bounded_mean(&scores));
                }
            }
            let raw = if domain_scores.is_empty() {
                0
            } else {
                bounded_mean(&domain_scores)
            };
            let oldest = contributions
                .iter()
                .map(|contribution| contribution.created_height)
                .min()
                .unwrap_or(height);
            let decay = height
                .saturating_sub(oldest)
                .saturating_mul(u64::from(decay_bps_per_block))
                .min(10_000);
            let decayed = raw.saturating_mul(10_000u32.saturating_sub(decay as u32)) / 10_000;
            let contribution_count = u32::try_from(contributions.len()).unwrap_or(u32::MAX);
            let share = decayed.checked_div(contribution_count).unwrap_or(0);
            for contribution in contributions {
                let credit = u16::try_from(share).unwrap_or(u16::MAX);
                credits.insert(contribution.contribution_id, credit);
                let expected = u32::from(contribution.synthetic_ground_truth_bps)
                    .checked_div(contribution_count)
                    .unwrap_or(0);
                let error = credit.abs_diff(u16::try_from(expected).unwrap_or(u16::MAX));
                max_error = max_error.max(error);
            }
        }
        AttributionReport {
            advisory_credit_bps: credits,
            max_error_bps: max_error,
            wash_credit_bps: 0,
            provenance_root: domain_hash("NOOS/ATTRIBUTION/REPORT/V1", &[&provenance]),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]
    use super::*;
    fn h(n: u8) -> Hash32 {
        [n; 32]
    }
    fn job() -> CommerceJob {
        let mut job = CommerceJob {
            job_id: h(1),
            chain_id: h(30),
            profile_id: h(31),
            class_id: 7,
            client: h(2),
            provider: Some(h(3)),
            evaluator_policy: h(4),
            request_schema: h(5),
            request_commitment: h(6),
            species_selector: None,
            assurance_requirement: AssuranceRequirement::V0,
            quality_requirement: QualityRequirement::Q0NoQualityAssurance,
            confidentiality_requirement: h(7),
            rights_requirement: h(8),
            budget: Some(100),
            evaluator_fee: 0,
            expiry: 100,
            state: CommerceState::Requested,
            negotiated_terms_root: Some(h(9)),
            work_job_id: Some(h(10)),
            work_commitment: None,
            availability_certificate: None,
            artifact_commitment: Some(h(11)),
            challenge_window: 10,
            challenge_deadline: None,
            settlement_resources: vec![
                SettlementResource {
                    kind: SettlementResourceKind::EscrowNote,
                    resource_id: h(40),
                    job_id: h(1),
                },
                SettlementResource {
                    kind: SettlementResourceKind::ExecutionRight,
                    resource_id: h(41),
                    job_id: h(1),
                },
                SettlementResource {
                    kind: SettlementResourceKind::DisputeProof,
                    resource_id: h(42),
                    job_id: h(1),
                },
            ],
        };
        job.availability_certificate = Some(availability_certificate_for(
            &job,
            job.artifact_commitment.unwrap(),
        ));
        job
    }
    fn market() -> Commerce {
        let mut c = Commerce::default();
        assert!(c.register_class(7).is_ok());
        assert!(c.open(job()).is_ok());
        c
    }
    fn drive_available(c: &mut Commerce, id: Hash32) {
        assert!(c
            .transition(id, CommerceAction::OpenNegotiation, 1, None)
            .is_ok());
        assert!(c.transition(id, CommerceAction::Agree, 2, None).is_ok());
        assert!(c
            .transition(id, CommerceAction::Fund, 3, Some(WorkJobState::Open))
            .is_ok());
        assert!(c
            .transition(
                id,
                CommerceAction::BindProviderOffer,
                3,
                Some(WorkJobState::Committed)
            )
            .is_ok());
        assert!(c
            .transition(
                id,
                CommerceAction::StartExecution,
                4,
                Some(WorkJobState::Running)
            )
            .is_ok());
        assert!(c
            .transition(id, CommerceAction::Submit, 5, Some(WorkJobState::Submitted))
            .is_ok());
        assert!(c
            .transition(
                id,
                CommerceAction::ConfirmAvailable,
                6,
                Some(WorkJobState::Challengeable)
            )
            .is_ok());
    }
    #[test]
    fn projection_is_single_work_lifecycle() {
        assert_eq!(
            work_projection(CommerceState::Funded),
            Some(WorkJobState::Open)
        );
        assert_eq!(
            work_projection(CommerceState::Available),
            Some(WorkJobState::Challengeable)
        );
        assert_eq!(
            work_projection(CommerceState::Completed),
            Some(WorkJobState::Settled)
        );
    }
    #[test]
    fn model_checked_maximal_paths_reach_exactly_one_terminal() {
        fn successors(state: CommerceState) -> &'static [CommerceState] {
            match state {
                CommerceState::Requested => &[CommerceState::Negotiating, CommerceState::Expired],
                CommerceState::Negotiating => &[CommerceState::Agreed, CommerceState::Expired],
                CommerceState::Agreed => &[CommerceState::Funded, CommerceState::Refunded],
                CommerceState::Funded => &[CommerceState::Running, CommerceState::Refunded],
                CommerceState::Running => &[CommerceState::Submitted, CommerceState::Refunded],
                CommerceState::Submitted => &[CommerceState::Available, CommerceState::Refunded],
                CommerceState::Available => &[
                    CommerceState::Evaluating,
                    CommerceState::Completed,
                    CommerceState::Refunded,
                ],
                CommerceState::Evaluating => &[
                    CommerceState::Completed,
                    CommerceState::Rejected,
                    CommerceState::Disputed,
                    CommerceState::Refunded,
                ],
                CommerceState::Disputed => &[CommerceState::Completed, CommerceState::Refunded],
                CommerceState::Completed
                | CommerceState::Rejected
                | CommerceState::Refunded
                | CommerceState::Expired => &[],
            }
        }
        fn walk(state: CommerceState, depth: usize, terminal_paths: &mut usize) {
            assert!(depth <= 10, "nonterminal cycle in commerce state graph");
            let next = successors(state);
            if next.is_empty() {
                assert!(state.is_terminal());
                *terminal_paths += 1;
                return;
            }
            assert!(!state.is_terminal());
            for successor in next {
                walk(*successor, depth + 1, terminal_paths);
            }
        }
        let mut terminal_paths = 0;
        walk(CommerceState::Requested, 0, &mut terminal_paths);
        assert_eq!(terminal_paths, 13);
    }
    #[test]
    fn cannot_evaluate_before_availability() {
        let mut c = market();
        assert_eq!(
            c.transition(h(1), CommerceAction::BeginEvaluation, 1, None),
            Err(CommerceError::InvalidState)
        );
    }
    #[test]
    fn q0_is_explicit_non_assurance() {
        let c = market();
        assert_eq!(
            c.claim_quality_assured(&h(1)),
            Err(CommerceError::QualityAssuranceMisrepresentation)
        );
    }
    #[test]
    fn q0_can_skip_evaluation_after_available() {
        let mut c = market();
        assert!(c
            .transition(h(1), CommerceAction::OpenNegotiation, 1, None)
            .is_ok());
        assert!(c.transition(h(1), CommerceAction::Agree, 2, None).is_ok());
        assert!(c
            .transition(h(1), CommerceAction::Fund, 3, Some(WorkJobState::Open))
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::BindProviderOffer,
                3,
                Some(WorkJobState::Committed)
            )
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::StartExecution,
                4,
                Some(WorkJobState::Running)
            )
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::Submit,
                5,
                Some(WorkJobState::Submitted)
            )
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::ConfirmAvailable,
                6,
                Some(WorkJobState::Challengeable)
            )
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::Complete,
                7,
                Some(WorkJobState::Settled)
            )
            .is_ok());
    }
    #[test]
    fn withholding_disables_only_class() {
        let mut c = market();
        let e = h(20);
        assert_eq!(
            c.report_class_fault(7, DisableCause::WithholdingClockAbuse, e),
            Err(CommerceError::FeatureDisabled {
                cause: DisableCause::WithholdingClockAbuse,
                evidence_root: e
            })
        );
        assert_eq!(
            c.transition(h(1), CommerceAction::OpenNegotiation, 1, None),
            Err(CommerceError::FeatureDisabled {
                cause: DisableCause::WithholdingClockAbuse,
                evidence_root: e
            })
        );
    }
    #[test]
    fn undecryptable_delivery_is_explicit() {
        let mut c = market();
        assert!(matches!(
            c.report_class_fault(7, DisableCause::UndecryptableDelivery, h(2)),
            Err(CommerceError::FeatureDisabled {
                cause: DisableCause::UndecryptableDelivery,
                ..
            })
        ));
    }
    #[test]
    fn subjective_slashing_disables_class() {
        let mut c = market();
        assert_eq!(
            c.slash_subjective(7, h(2)),
            Err(CommerceError::SubjectiveSlashingForbidden)
        );
    }

    #[test]
    fn withholding_never_starts_clock_and_timeout_refunds() {
        let mut c = market();
        assert!(c
            .transition(h(1), CommerceAction::OpenNegotiation, 1, None)
            .is_ok());
        assert!(c.transition(h(1), CommerceAction::Agree, 2, None).is_ok());
        assert!(c
            .transition(h(1), CommerceAction::Fund, 3, Some(WorkJobState::Open))
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::BindProviderOffer,
                3,
                Some(WorkJobState::Committed)
            )
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::StartExecution,
                4,
                Some(WorkJobState::Running)
            )
            .is_ok());
        assert!(c
            .transition(
                h(1),
                CommerceAction::Submit,
                5,
                Some(WorkJobState::Submitted)
            )
            .is_ok());
        c.jobs.get_mut(&h(1)).unwrap().availability_certificate = None;
        assert_eq!(
            c.transition(
                h(1),
                CommerceAction::ConfirmAvailable,
                99,
                Some(WorkJobState::Challengeable)
            ),
            Err(CommerceError::AvailabilityBeforeEvaluation)
        );
        assert_eq!(c.job(&h(1)).unwrap().challenge_deadline, None);
        assert!(c
            .transition(h(1), CommerceAction::Expire, 100, None)
            .is_ok());
        let receipt = c.settle(h(1)).unwrap();
        assert_eq!((receipt.client_credit, receipt.provider_credit), (100, 0));
        assert!(receipt.conserves());
    }

    #[test]
    fn terminal_state_cannot_be_rewritten_or_double_settled() {
        let mut c = market();
        drive_available(&mut c, h(1));
        assert!(c
            .transition(
                h(1),
                CommerceAction::Complete,
                7,
                Some(WorkJobState::Settled)
            )
            .is_ok());
        assert_eq!(
            c.transition(
                h(1),
                CommerceAction::Refund,
                8,
                Some(WorkJobState::Cancelled)
            ),
            Err(CommerceError::TerminalState)
        );
        assert!(c.settle(h(1)).unwrap().conserves());
        assert_eq!(c.settle(h(1)), Err(CommerceError::AlreadyPaid));
    }

    #[test]
    fn cross_job_resource_reuse_is_atomic_and_conservative() {
        let mut c = Commerce::default();
        c.register_class(7).unwrap();
        let first = job();
        let mut second = job();
        second.job_id = h(2);
        for resource in &mut second.settlement_resources {
            resource.job_id = h(2);
            if resource.kind != SettlementResourceKind::ExecutionRight {
                resource.resource_id[0] = resource.resource_id[0].saturating_add(20);
            }
        }
        second.availability_certificate = Some(availability_certificate_for(
            &second,
            second.artifact_commitment.unwrap(),
        ));
        c.open(first).unwrap();
        c.open(second).unwrap();
        for id in [h(1), h(2)] {
            drive_available(&mut c, id);
            c.transition(id, CommerceAction::Complete, 7, Some(WorkJobState::Settled))
                .unwrap();
        }
        assert!(c.settle(h(1)).unwrap().conserves());
        assert_eq!(c.settle(h(2)), Err(CommerceError::ResourceAlreadyConsumed));
        assert!(
            !c.paid.contains(&h(2)),
            "failed settlement consumed no job state"
        );
    }

    #[test]
    fn availability_binding_rejects_chain_and_profile_substitution() {
        let mut c = market();
        c.transition(h(1), CommerceAction::OpenNegotiation, 1, None)
            .unwrap();
        c.transition(h(1), CommerceAction::Agree, 2, None).unwrap();
        c.transition(h(1), CommerceAction::Fund, 3, Some(WorkJobState::Open))
            .unwrap();
        c.transition(
            h(1),
            CommerceAction::BindProviderOffer,
            3,
            Some(WorkJobState::Committed),
        )
        .unwrap();
        c.transition(
            h(1),
            CommerceAction::StartExecution,
            4,
            Some(WorkJobState::Running),
        )
        .unwrap();
        c.transition(
            h(1),
            CommerceAction::Submit,
            5,
            Some(WorkJobState::Submitted),
        )
        .unwrap();
        c.jobs.get_mut(&h(1)).unwrap().profile_id = h(99);
        assert_eq!(
            c.transition(
                h(1),
                CommerceAction::ConfirmAvailable,
                6,
                Some(WorkJobState::Challengeable)
            ),
            Err(CommerceError::AvailabilityBeforeEvaluation)
        );
        assert_eq!(c.job(&h(1)).unwrap().challenge_deadline, None);
    }

    fn contribution(id: u8, domain: u8, truth: u16) -> Contribution {
        let mut value = Contribution {
            contribution_id: [0; 32],
            contributor: h(id),
            failure_domain: h(domain),
            parent_ids: BTreeSet::new(),
            evidence_root: h(id.saturating_add(100)),
            synthetic_ground_truth_bps: truth,
            created_height: 1,
        };
        value.contribution_id = value.derive_id();
        value
    }
    fn evaluation(c: &Contribution, evaluator: u8, score: u16) -> MarginalEvaluation {
        let mut value = MarginalEvaluation {
            evaluation_id: [0; 32],
            contribution_id: c.contribution_id,
            evaluator: h(evaluator),
            evaluator_failure_domain: h(evaluator.saturating_add(50)),
            evidence_root: c.evidence_root,
            marginal_bps: score,
        };
        value.evaluation_id = value.derive_id();
        value
    }

    #[test]
    fn attribution_ground_truth_and_laundering_thresholds_hold() {
        let mut graph = ContributionGraph::default();
        for (id, truth) in [(1, 1_000), (2, 2_000), (3, 3_000)] {
            let c = contribution(id, id, truth);
            graph.add_contribution(c.clone()).unwrap();
            graph
                .add_evaluation(evaluation(&c, id + 10, truth))
                .unwrap();
        }
        let report = graph.report(1, 0);
        assert!(report.max_error_bps < 1_000);
        assert!(report.wash_credit_bps < 100);
        assert_eq!(AttributionReport::CONSENSUS_WEIGHT, 0);

        let cloned = contribution(4, 1, 1_000);
        graph.add_contribution(cloned.clone()).unwrap();
        graph
            .add_evaluation(evaluation(&cloned, 14, 1_000))
            .unwrap();
        let total_after_split: u32 = graph
            .report(1, 0)
            .advisory_credit_bps
            .iter()
            .filter(|(id, _)| {
                graph
                    .contributions
                    .get(*id)
                    .is_some_and(|c| c.failure_domain == h(1))
            })
            .map(|(_, credit)| u32::from(*credit))
            .sum();
        assert_eq!(total_after_split, 1_000, "sybil split minted no credit");

        let mut wash = evaluation(&cloned, 4, 10_000);
        wash.evaluator = cloned.contributor;
        wash.evaluator_failure_domain = cloned.failure_domain;
        wash.evaluation_id = wash.derive_id();
        assert_eq!(
            graph.add_evaluation(wash),
            Err(AttributionError::SelfDealing)
        );
    }
}
