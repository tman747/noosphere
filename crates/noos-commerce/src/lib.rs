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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommerceJob {
    pub job_id: Hash32,
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
    FeatureDisabled {
        cause: DisableCause,
        evidence_root: Hash32,
    },
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
        if job.state != CommerceState::Requested || job.expiry == 0 {
            return Err(CommerceError::InvalidState);
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
                if job.budget.is_none() || work_state != Some(WorkJobState::Open) {
                    return Err(CommerceError::MissingFunding);
                }
                CommerceState::Funded
            }
            (CommerceState::Funded, CommerceAction::BindProviderOffer) => {
                if work_state != Some(WorkJobState::Committed) {
                    return Err(CommerceError::WorkJobMismatch);
                }
                job.work_commitment = Some(domain_hash(
                    "NOOS/COMMERCE/WORK-COMMIT/V1",
                    &[
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
                CommerceState::Available
            }
            (CommerceState::Available, CommerceAction::BeginEvaluation) => {
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
            (_, CommerceAction::Refund) => CommerceState::Refunded,
            (_, CommerceAction::Expire) if height >= job.expiry => CommerceState::Expired,
            _ => return Err(CommerceError::InvalidState),
        };
        job.state = next;
        Ok(())
    }
    pub fn mark_paid(&mut self, id: Hash32) -> Result<(), CommerceError> {
        let job = self.jobs.get(&id).ok_or(CommerceError::UnknownJob)?;
        if job.state != CommerceState::Completed {
            return Err(CommerceError::InvalidState);
        }
        if !self.paid.insert(id) {
            let evidence = domain_hash("NOOS/COMMERCE/DOUBLE-PAYOUT/V1", &[&id]);
            self.disable_class(job.class_id, DisableCause::DoublePayout, evidence);
            return Err(CommerceError::AlreadyPaid);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash32 {
        [n; 32]
    }
    fn job() -> CommerceJob {
        CommerceJob {
            job_id: h(1),
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
            availability_certificate: Some(h(11)),
        }
    }
    fn market() -> Commerce {
        let mut c = Commerce::default();
        assert!(c.register_class(7).is_ok());
        assert!(c.open(job()).is_ok());
        c
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
}
