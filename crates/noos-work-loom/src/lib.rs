//! Work Loom v1: application-only useful-work escrow and settlement.
//!
//! This crate deliberately exposes no proposal, issuance, or finality hook.
//! Experimental economics are available only through [`shadow`], whose
//! production values are hard-zero under `E-DEMAND-WASH-01`.

#![forbid(unsafe_code)]

use noos_lumen::engine::{EscrowError as LumenEscrowError, WorkJobEscrow};
use std::collections::{BTreeMap, BTreeSet};

pub mod economics;
pub mod wwm;

pub type Hash32 = [u8; 32];
pub type AccountId = Hash32;
pub type RegistryId = u32;

pub const DEMAND_WASH_BINDING: &str = "E-DEMAND-WASH-01";
pub const WORK_LOOM_CREDIT_ENABLED: bool = false;
pub const WITNESS_PROOFPOWER_ENABLED: bool = false;
pub const DUPLEX_ISSUANCE_ENABLED: bool = false;

pub mod domains {
    pub const JOB_ID: &str = "NOOS/LOOM/JOB/V1";
    pub const WORKER_COMMIT: &str = "NOOS/LOOM/WORKER-COMMIT/V1";
    pub const CHALLENGE: &str = "NOOS/LOOM/V1";
    pub const RECEIPT_ID: &str = "NOOS/LOOM/RECEIPT/V1";
    pub const ARTIFACT: &str = "NOOS/TENSOR/ARTIFACT/V1";
    pub const WORK: &str = "NOOS/TENSOR/WORK/V1";
    pub const DELIVERY: &str = "NOOS/LOOM/PAID-DELIVERY/V1";
}

#[must_use]
pub fn domain_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn keyed_hash(key: &Hash32, domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryStatus {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assurance {
    V0,
    V1,
    V2,
    V3,
}

impl Assurance {
    const fn tag(self) -> u8 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkClass {
    pub id: RegistryId,
    pub relation_root: Hash32,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerProfile {
    pub id: RegistryId,
    pub source_root: Hash32,
    pub compiler_toolchain_root: Hash32,
    pub machine_code_root: Hash32,
    pub hardware_root: Hash32,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofProfile {
    pub id: RegistryId,
    pub verifier_root: Hash32,
    pub max_proof_bytes: u32,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityPolicy {
    pub id: RegistryId,
    pub min_retrievers: u16,
    pub retention_blocks: u64,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorPolicy {
    pub id: RegistryId,
    pub policy_root: Hash32,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobClass {
    pub id: RegistryId,
    pub work_class_id: RegistryId,
    pub program_or_relation_root: Hash32,
    pub input_schema_root: Hash32,
    pub output_schema_root: Hash32,
    pub numeric_profile_root: Hash32,
    pub allowed_worker_profiles: BTreeSet<RegistryId>,
    pub assurance: Assurance,
    pub confidentiality_flags: u8,
    pub proof_profile_id: RegistryId,
    pub evaluator_policy_id: RegistryId,
    pub availability_policy_id: RegistryId,
    pub max_resources: ResourceVector,
    pub challenge_period: u64,
    pub minimum_worker_bond: u128,
    pub slashable: bool,
    pub status: RegistryStatus,
}

#[derive(Debug, Clone, Default)]
pub struct Registries {
    work_classes: BTreeMap<RegistryId, WorkClass>,
    worker_profiles: BTreeMap<RegistryId, WorkerProfile>,
    proof_profiles: BTreeMap<RegistryId, ProofProfile>,
    availability_policies: BTreeMap<RegistryId, AvailabilityPolicy>,
    evaluator_policies: BTreeMap<RegistryId, EvaluatorPolicy>,
    job_classes: BTreeMap<RegistryId, JobClass>,
}

impl Registries {
    pub fn register_work_class(&mut self, value: WorkClass) -> Result<(), LoomError> {
        insert_once(&mut self.work_classes, value.id, value)
    }
    pub fn register_worker_profile(&mut self, value: WorkerProfile) -> Result<(), LoomError> {
        insert_once(&mut self.worker_profiles, value.id, value)
    }
    pub fn register_proof_profile(&mut self, value: ProofProfile) -> Result<(), LoomError> {
        insert_once(&mut self.proof_profiles, value.id, value)
    }
    pub fn register_availability_policy(
        &mut self,
        value: AvailabilityPolicy,
    ) -> Result<(), LoomError> {
        insert_once(&mut self.availability_policies, value.id, value)
    }
    pub fn register_evaluator_policy(&mut self, value: EvaluatorPolicy) -> Result<(), LoomError> {
        insert_once(&mut self.evaluator_policies, value.id, value)
    }
    pub fn register_job_class(&mut self, value: JobClass) -> Result<(), LoomError> {
        enabled(self.work_classes.get(&value.work_class_id))?;
        enabled(self.proof_profiles.get(&value.proof_profile_id))?;
        enabled(
            self.availability_policies
                .get(&value.availability_policy_id),
        )?;
        enabled(self.evaluator_policies.get(&value.evaluator_policy_id))?;
        if value.allowed_worker_profiles.is_empty() {
            return Err(LoomError::InvalidRegistryEntry);
        }
        for id in &value.allowed_worker_profiles {
            enabled(self.worker_profiles.get(id))?;
        }
        insert_once(&mut self.job_classes, value.id, value)
    }
    pub fn job_class(&self, id: RegistryId) -> Result<&JobClass, LoomError> {
        enabled(self.job_classes.get(&id))
    }
    pub fn worker_profile(&self, id: RegistryId) -> Result<&WorkerProfile, LoomError> {
        enabled(self.worker_profiles.get(&id))
    }
    pub fn proof_profile(&self, id: RegistryId) -> Result<&ProofProfile, LoomError> {
        enabled(self.proof_profiles.get(&id))
    }
    pub fn availability_policy(&self, id: RegistryId) -> Result<&AvailabilityPolicy, LoomError> {
        enabled(self.availability_policies.get(&id))
    }
}

trait HasStatus {
    fn status(&self) -> RegistryStatus;
}
impl HasStatus for WorkClass {
    fn status(&self) -> RegistryStatus {
        self.status
    }
}
impl HasStatus for WorkerProfile {
    fn status(&self) -> RegistryStatus {
        self.status
    }
}
impl HasStatus for ProofProfile {
    fn status(&self) -> RegistryStatus {
        self.status
    }
}
impl HasStatus for AvailabilityPolicy {
    fn status(&self) -> RegistryStatus {
        self.status
    }
}
impl HasStatus for EvaluatorPolicy {
    fn status(&self) -> RegistryStatus {
        self.status
    }
}
impl HasStatus for JobClass {
    fn status(&self) -> RegistryStatus {
        self.status
    }
}

fn enabled<T: HasStatus>(entry: Option<&T>) -> Result<&T, LoomError> {
    let entry = entry.ok_or(LoomError::UnknownRegistryId)?;
    if entry.status() != RegistryStatus::Enabled {
        return Err(LoomError::DisabledRegistryId);
    }
    Ok(entry)
}

fn insert_once<T>(
    map: &mut BTreeMap<RegistryId, T>,
    id: RegistryId,
    value: T,
) -> Result<(), LoomError> {
    if id == 0 {
        return Err(LoomError::InvalidRegistryEntry);
    }
    if map.contains_key(&id) {
        return Err(LoomError::ImmutableRegistry);
    }
    map.insert(id, value);
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceVector {
    pub bytes: u64,
    pub compute: u64,
    pub verification: u64,
    pub reads: u64,
    pub da_bytes: u64,
}

impl ResourceVector {
    fn within(self, max: Self) -> bool {
        self.bytes <= max.bytes
            && self.compute <= max.compute
            && self.verification <= max.verification
            && self.reads <= max.reads
            && self.da_bytes <= max.da_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correctness {
    Unverified,
    Verified,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Committed,
    Available,
    Acknowledged,
}

/// Immutable delivery condition selected when escrow is opened. Availability
/// is sufficient for ordinary compute settlement; paid acknowledgement binds
/// the requester's delivery certificate before funds can leave escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRule {
    Availability,
    PaidAcknowledgement,
}

impl DeliveryRule {
    const fn tag(self) -> u8 {
        match self {
            Self::Availability => 0,
            Self::PaidAcknowledgement => 1,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    NotEvaluated,
    Score(u16),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandClassification {
    Independent,
    Related,
    Subsidized,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Open,
    Committed,
    Running,
    Submitted,
    Challengeable,
    Disputed,
    Settled,
    Rejected,
    Expired,
    Cancelled,
}
impl JobState {
    #[must_use]
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rejected | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJob {
    pub requester: AccountId,
    /// Precommitted refund destination. Cancellation and every timeout path
    /// use this field; no terminal caller chooses a refund direction.
    pub refund_account: AccountId,
    pub class_id: RegistryId,
    pub required_assurance: Assurance,
    pub input_root: Hash32,
    pub model_or_program_root: Hash32,
    pub delivery_pubkey: Hash32,
    pub delivery_rule: DeliveryRule,
    pub settlement_accounts: SettlementAccounts,
    pub max_resources: ResourceVector,
    pub fee_escrow: u128,
    pub evaluator_escrow: u128,
    pub opened_height: u64,
    pub commit_deadline: u64,
    pub submit_deadline: u64,
    pub expiry_height: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCommit {
    pub job_id: Hash32,
    pub worker: AccountId,
    pub implementation_profile: RegistryId,
    pub input_root: Hash32,
    pub worker_nonce_commitment: Hash32,
    pub availability_plan_root: Hash32,
    pub bond: u128,
    pub committed_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkReceipt {
    pub receipt_id: Hash32,
    pub job_id: Hash32,
    pub worker_commit_hash: Hash32,
    pub challenge: Hash32,
    pub artifact_id: Hash32,
    pub work_commit: Hash32,
    pub output_commitment: Hash32,
    pub encrypted_delivery_commitment: Hash32,
    pub execution_evidence_root: Hash32,
    pub proof_profile_id: RegistryId,
    pub proof_bytes_or_blob_root: Hash32,
    pub availability_root: Hash32,
    pub resource_measurement: ResourceVector,
    pub nullifier: Hash32,
    pub worker_signature: [u8; 64],
    pub correctness: Correctness,
    pub external_demand: DemandClassification,
    pub delivery: Delivery,
    pub quality: Quality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityCertificate {
    pub evidence_root: Hash32,
    pub availability_root: Hash32,
    pub retriever_count: u16,
    pub finalized_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidDeliveryCertificate {
    pub job_id: Hash32,
    pub requester_domain: Hash32,
    pub worker_domain: Hash32,
    pub evaluator_domain: Option<Hash32>,
    pub artifact_id: Hash32,
    pub output_commitment: Hash32,
    pub encrypted_delivery_commitment: Hash32,
    pub delivery_ack_signature: [u8; 64],
    pub payment_txid: Hash32,
    pub independence_domains_root: Hash32,
}

impl PaidDeliveryCertificate {
    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        let evaluator = self.evaluator_domain.unwrap_or([0; 32]);
        domain_hash(
            domains::DELIVERY,
            &[
                &self.job_id,
                &self.requester_domain,
                &self.worker_domain,
                &evaluator,
                &self.artifact_id,
                &self.output_commitment,
                &self.encrypted_delivery_commitment,
                &self.delivery_ack_signature,
                &self.payment_txid,
                &self.independence_domains_root,
            ],
        )
    }
}

#[must_use]
pub fn artifact_id(canonical_tensor_descriptor: &[u8], canonical_tensor_bytes: &[u8]) -> Hash32 {
    domain_hash(
        domains::ARTIFACT,
        &[canonical_tensor_descriptor, canonical_tensor_bytes],
    )
}

#[must_use]
pub fn work_commit(
    challenge: &Hash32,
    artifact: &Hash32,
    worker_profile_id: RegistryId,
    trace_root: &Hash32,
) -> Hash32 {
    keyed_hash(
        challenge,
        domains::WORK,
        &[artifact, &worker_profile_id.to_le_bytes(), trace_root],
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementSplit {
    pub worker: u128,
    pub verifier: u128,
    pub evaluator: u128,
    pub da_provider: u128,
}
impl SettlementSplit {
    fn total(self) -> Result<u128, LoomError> {
        checked_sum([self.worker, self.verifier, self.evaluator, self.da_provider])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementAccounts {
    pub verifier: AccountId,
    pub evaluator: AccountId,
    pub da_provider: AccountId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub job: OpenJob,
    pub state: JobState,
    pub worker_commit: Option<WorkerCommit>,
    pub worker_commit_hash: Option<Hash32>,
    pub challenge: Option<Hash32>,
    pub receipt: Option<WorkReceipt>,
    pub availability: Option<AvailabilityCertificate>,
    pub challenge_start: Option<u64>,
    pub dispute: Option<Dispute>,
    pub delivery_certificate: Option<PaidDeliveryCertificate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispute {
    pub challenger: AccountId,
    pub bond: u128,
    pub evidence_root: Hash32,
    pub opened_height: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeVerdict {
    WorkerUpheld,
    WorkerFault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoomError {
    UnknownRegistryId,
    DisabledRegistryId,
    InvalidRegistryEntry,
    ImmutableRegistry,
    ProfileQuarantined,
    UnknownJob,
    DuplicateJob,
    InvalidState,
    Deadline,
    Ordering,
    NotFinalized,
    InsufficientFunds,
    ArithmeticOverflow,
    InvalidCommit,
    InvalidReceipt,
    InvalidAvailability,
    DuplicateNullifier,
    InvalidSettlement,
    DisputeWindowClosed,
    TerminalState,
    AccountConflict,
}

#[derive(Debug, Clone, Default)]
pub struct WorkLoom {
    pub registries: Registries,
    balances: BTreeMap<AccountId, u128>,
    jobs: BTreeMap<Hash32, JobRecord>,
    nullifiers: BTreeSet<Hash32>,
    quarantined_profiles: BTreeSet<RegistryId>,
    locked: u128,
    burned: u128,
    initial_supply: u128,
}

impl WorkLoom {
    #[must_use]
    pub fn new(registries: Registries) -> Self {
        Self {
            registries,
            ..Self::default()
        }
    }
    pub fn credit_genesis(&mut self, account: AccountId, amount: u128) -> Result<(), LoomError> {
        if !self.jobs.is_empty() || self.locked != 0 || self.burned != 0 {
            return Err(LoomError::InvalidState);
        }
        credit(&mut self.balances, account, amount)?;
        self.initial_supply = self
            .initial_supply
            .checked_add(amount)
            .ok_or(LoomError::ArithmeticOverflow)?;
        Ok(())
    }
    #[must_use]
    pub fn balance(&self, account: &AccountId) -> u128 {
        self.balances.get(account).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn locked(&self) -> u128 {
        self.locked
    }
    #[must_use]
    pub fn burned(&self) -> u128 {
        self.burned
    }
    #[must_use]
    pub fn job(&self, id: &Hash32) -> Option<&JobRecord> {
        self.jobs.get(id)
    }
    pub fn assert_conserved(&self) -> Result<(), LoomError> {
        let liquid = self.balances.values().try_fold(0u128, |a, b| {
            a.checked_add(*b).ok_or(LoomError::ArithmeticOverflow)
        })?;
        let actual = checked_sum([liquid, self.locked, self.burned])?;
        if actual != self.initial_supply {
            return Err(LoomError::InvalidSettlement);
        }
        Ok(())
    }
    pub fn open_job(&mut self, job: OpenJob) -> Result<Hash32, LoomError> {
        let class = self.registries.job_class(job.class_id)?;
        if job.required_assurance != class.assurance {
            return Err(LoomError::InvalidRegistryEntry);
        }
        if !(job.opened_height < job.commit_deadline
            && job.commit_deadline < job.submit_deadline
            && job.submit_deadline <= job.expiry_height)
        {
            return Err(LoomError::Deadline);
        }
        if !job.max_resources.within(class.max_resources) {
            return Err(LoomError::InvalidRegistryEntry);
        }
        let escrow = job
            .fee_escrow
            .checked_add(job.evaluator_escrow)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let id = job_id(&job);
        if self.jobs.contains_key(&id) {
            return Err(LoomError::DuplicateJob);
        }
        debit(&mut self.balances, job.requester, escrow)?;
        self.locked = self
            .locked
            .checked_add(escrow)
            .ok_or(LoomError::ArithmeticOverflow)?;
        self.jobs.insert(
            id,
            JobRecord {
                job,
                state: JobState::Open,
                worker_commit: None,
                worker_commit_hash: None,
                challenge: None,
                receipt: None,
                availability: None,
                challenge_start: None,
                dispute: None,
                delivery_certificate: None,
            },
        );
        self.assert_conserved()?;
        Ok(id)
    }
    pub fn commit_worker(&mut self, commit: WorkerCommit) -> Result<Hash32, LoomError> {
        let record = self.jobs.get(&commit.job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Open {
            return Err(LoomError::InvalidState);
        }
        if commit.committed_height > record.job.commit_deadline
            || commit.committed_height < record.job.opened_height
        {
            return Err(LoomError::Deadline);
        }
        if commit.input_root != record.job.input_root {
            return Err(LoomError::InvalidCommit);
        }
        let class = self.registries.job_class(record.job.class_id)?;
        if !class
            .allowed_worker_profiles
            .contains(&commit.implementation_profile)
        {
            return Err(LoomError::InvalidCommit);
        }
        self.registries
            .worker_profile(commit.implementation_profile)?;
        if self
            .quarantined_profiles
            .contains(&commit.implementation_profile)
        {
            return Err(LoomError::ProfileQuarantined);
        }
        if commit.bond < class.minimum_worker_bond {
            return Err(LoomError::InvalidCommit);
        }
        debit(&mut self.balances, commit.worker, commit.bond)?;
        self.locked = self
            .locked
            .checked_add(commit.bond)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let hash = worker_commit_hash(&commit);
        let record = self
            .jobs
            .get_mut(&commit.job_id)
            .ok_or(LoomError::UnknownJob)?;
        record.state = JobState::Committed;
        record.worker_commit_hash = Some(hash);
        record.worker_commit = Some(commit);
        self.assert_conserved()?;
        Ok(hash)
    }
    pub fn assign_finalized_challenge(
        &mut self,
        job_id: Hash32,
        chain_id: Hash32,
        finalized_randomness: Hash32,
        finalized_height: u64,
    ) -> Result<Hash32, LoomError> {
        let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Committed {
            return Err(LoomError::InvalidState);
        }
        let commit = record
            .worker_commit
            .as_ref()
            .ok_or(LoomError::InvalidCommit)?;
        if finalized_height <= commit.committed_height {
            return Err(LoomError::NotFinalized);
        }
        if finalized_height > record.job.submit_deadline {
            return Err(LoomError::Deadline);
        }
        let commit_hash = record.worker_commit_hash.ok_or(LoomError::InvalidCommit)?;
        let challenge = domain_hash(
            domains::CHALLENGE,
            &[&chain_id, &job_id, &commit_hash, &finalized_randomness],
        );
        record.challenge = Some(challenge);
        record.state = JobState::Running;
        Ok(challenge)
    }
    pub fn submit_receipt(&mut self, receipt: WorkReceipt, height: u64) -> Result<(), LoomError> {
        let record = self
            .jobs
            .get(&receipt.job_id)
            .ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Running {
            return Err(LoomError::InvalidState);
        }
        if height > record.job.submit_deadline {
            return Err(LoomError::Deadline);
        }
        if receipt.worker_commit_hash
            != record.worker_commit_hash.ok_or(LoomError::InvalidCommit)?
            || receipt.challenge != record.challenge.ok_or(LoomError::Ordering)?
        {
            return Err(LoomError::InvalidReceipt);
        }
        let commit = record
            .worker_commit
            .as_ref()
            .ok_or(LoomError::InvalidCommit)?;
        let class = self.registries.job_class(record.job.class_id)?;
        if receipt.proof_profile_id != class.proof_profile_id
            || !receipt
                .resource_measurement
                .within(record.job.max_resources)
        {
            return Err(LoomError::InvalidReceipt);
        }
        self.registries.proof_profile(receipt.proof_profile_id)?;
        if receipt.receipt_id != receipt_id(&receipt)
            || receipt.work_commit
                != work_commit(
                    &receipt.challenge,
                    &receipt.artifact_id,
                    commit.implementation_profile,
                    &receipt.execution_evidence_root,
                )
        {
            return Err(LoomError::InvalidReceipt);
        }
        if self.nullifiers.contains(&receipt.nullifier) {
            return Err(LoomError::DuplicateNullifier);
        }
        self.nullifiers.insert(receipt.nullifier);
        let record = self
            .jobs
            .get_mut(&receipt.job_id)
            .ok_or(LoomError::UnknownJob)?;
        record.receipt = Some(receipt);
        record.state = JobState::Submitted;
        Ok(())
    }
    pub fn finalize_availability(
        &mut self,
        job_id: Hash32,
        certificate: AvailabilityCertificate,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Submitted {
            return Err(LoomError::InvalidState);
        }
        let receipt = record.receipt.as_ref().ok_or(LoomError::InvalidReceipt)?;
        let class = self.registries.job_class(record.job.class_id)?;
        let policy = self
            .registries
            .availability_policy(class.availability_policy_id)?;
        if certificate.evidence_root != receipt.execution_evidence_root
            || certificate.availability_root != receipt.availability_root
            || certificate.retriever_count < policy.min_retrievers
        {
            return Err(LoomError::InvalidAvailability);
        }
        if certificate.finalized_height > record.job.expiry_height {
            return Err(LoomError::Deadline);
        }
        let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
        if let Some(receipt) = record.receipt.as_mut() {
            receipt.delivery = Delivery::Available;
        }
        record.challenge_start = Some(certificate.finalized_height);
        record.availability = Some(certificate);
        record.state = JobState::Challengeable;
        Ok(())
    }
    pub fn attach_paid_delivery(
        &mut self,
        job_id: Hash32,
        certificate: PaidDeliveryCertificate,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
        if !matches!(
            record.state,
            JobState::Challengeable | JobState::Disputed | JobState::Settled
        ) {
            return Err(LoomError::InvalidState);
        }
        let receipt = record.receipt.as_mut().ok_or(LoomError::InvalidReceipt)?;
        if certificate.job_id != job_id
            || certificate.artifact_id != receipt.artifact_id
            || certificate.output_commitment != receipt.output_commitment
            || certificate.encrypted_delivery_commitment != receipt.encrypted_delivery_commitment
        {
            return Err(LoomError::InvalidReceipt);
        }
        receipt.delivery = Delivery::Acknowledged;
        record.delivery_certificate = Some(certificate);
        Ok(())
    }
    pub fn open_dispute(
        &mut self,
        job_id: Hash32,
        challenger: AccountId,
        bond: u128,
        evidence_root: Hash32,
        height: u64,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Challengeable {
            return Err(LoomError::InvalidState);
        }
        let start = record.challenge_start.ok_or(LoomError::Ordering)?;
        let period = self
            .registries
            .job_class(record.job.class_id)?
            .challenge_period;
        let end = start
            .checked_add(period)
            .ok_or(LoomError::ArithmeticOverflow)?;
        if height < start || height > end {
            return Err(LoomError::DisputeWindowClosed);
        }
        debit(&mut self.balances, challenger, bond)?;
        self.locked = self
            .locked
            .checked_add(bond)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
        record.dispute = Some(Dispute {
            challenger,
            bond,
            evidence_root,
            opened_height: height,
        });
        record.state = JobState::Disputed;
        self.assert_conserved()?;
        Ok(())
    }
    pub fn resolve_dispute(
        &mut self,
        job_id: Hash32,
        verdict: DisputeVerdict,
        split: SettlementSplit,
        accounts: SettlementAccounts,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Disputed {
            return Err(LoomError::InvalidState);
        }
        let dispute = record
            .dispute
            .as_ref()
            .ok_or(LoomError::InvalidState)?
            .clone();
        match verdict {
            DisputeVerdict::WorkerUpheld => {
                self.release_locked(dispute.challenger, dispute.bond)?;
                let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
                record.state = JobState::Challengeable;
                record.dispute = None;
            }
            DisputeVerdict::WorkerFault => {
                self.reject_worker_fault(job_id, dispute, split, accounts)?;
            }
        }
        self.assert_conserved()
    }
    pub fn settle(
        &mut self,
        job_id: Hash32,
        height: u64,
        split: SettlementSplit,
        accounts: SettlementAccounts,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Challengeable {
            return Err(LoomError::InvalidState);
        }
        if accounts != record.job.settlement_accounts {
            return Err(LoomError::AccountConflict);
        }
        if record.job.delivery_rule == DeliveryRule::PaidAcknowledgement
            && record.delivery_certificate.is_none()
        {
            return Err(LoomError::InvalidSettlement);
        }
        let start = record.challenge_start.ok_or(LoomError::Ordering)?;
        let end = start
            .checked_add(
                self.registries
                    .job_class(record.job.class_id)?
                    .challenge_period,
            )
            .ok_or(LoomError::ArithmeticOverflow)?;
        if height <= end {
            return Err(LoomError::DisputeWindowClosed);
        }
        let expected = record
            .job
            .fee_escrow
            .checked_add(record.job.evaluator_escrow)
            .ok_or(LoomError::ArithmeticOverflow)?;
        if split.total()? != expected {
            return Err(LoomError::InvalidSettlement);
        }
        let worker = record
            .worker_commit
            .as_ref()
            .ok_or(LoomError::InvalidCommit)?
            .worker;
        let bond = record
            .worker_commit
            .as_ref()
            .ok_or(LoomError::InvalidCommit)?
            .bond;
        self.distribute_locked(
            &[
                (worker, split.worker),
                (accounts.verifier, split.verifier),
                (accounts.evaluator, split.evaluator),
                (accounts.da_provider, split.da_provider),
                (worker, bond),
            ],
            0,
        )?;
        let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
        record.state = JobState::Settled;
        self.assert_conserved()
    }
    pub fn cancel_open(
        &mut self,
        job_id: Hash32,
        requester: AccountId,
        height: u64,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state != JobState::Open
            || record.job.requester != requester
            || height > record.job.commit_deadline
        {
            return Err(LoomError::InvalidState);
        }
        let refund = record
            .job
            .fee_escrow
            .checked_add(record.job.evaluator_escrow)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let refund_account = record.job.refund_account;
        self.release_locked(refund_account, refund)?;
        self.jobs
            .get_mut(&job_id)
            .ok_or(LoomError::UnknownJob)?
            .state = JobState::Cancelled;
        self.assert_conserved()
    }
    pub fn expire(&mut self, job_id: Hash32, height: u64) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if record.state.terminal() {
            return Err(LoomError::TerminalState);
        }
        let allowed = match record.state {
            JobState::Open => height > record.job.commit_deadline,
            JobState::Committed | JobState::Running => height > record.job.submit_deadline,
            JobState::Submitted | JobState::Challengeable | JobState::Disputed => {
                height > record.job.expiry_height
            }
            _ => false,
        };
        if !allowed {
            return Err(LoomError::Deadline);
        }
        let refund_account = record.job.refund_account;
        let escrow = record
            .job
            .fee_escrow
            .checked_add(record.job.evaluator_escrow)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let worker_refund = record.worker_commit.as_ref().map(|c| (c.worker, c.bond));
        let challenger_refund = record.dispute.as_ref().map(|d| (d.challenger, d.bond));
        let mut refunds = vec![(refund_account, escrow)];
        if let Some(refund) = worker_refund {
            refunds.push(refund);
        }
        if let Some(refund) = challenger_refund {
            refunds.push(refund);
        }
        self.distribute_locked(&refunds, 0)?;
        self.jobs
            .get_mut(&job_id)
            .ok_or(LoomError::UnknownJob)?
            .state = JobState::Expired;
        self.assert_conserved()
    }
    pub fn quarantine_profile(&mut self, profile: RegistryId) -> Result<(), LoomError> {
        self.registries.worker_profile(profile)?;
        self.quarantined_profiles.insert(profile);
        Ok(())
    }
    #[must_use]
    pub fn production_influence(&self) -> ProductionInfluence {
        ProductionInfluence::default()
    }

    fn reject_worker_fault(
        &mut self,
        job_id: Hash32,
        dispute: Dispute,
        split: SettlementSplit,
        accounts: SettlementAccounts,
    ) -> Result<(), LoomError> {
        let record = self.jobs.get(&job_id).ok_or(LoomError::UnknownJob)?;
        if accounts != record.job.settlement_accounts {
            return Err(LoomError::AccountConflict);
        }
        let requester = record.job.refund_account;
        let worker_bond = record
            .worker_commit
            .as_ref()
            .ok_or(LoomError::InvalidCommit)?
            .bond;
        let escrow = record
            .job
            .fee_escrow
            .checked_add(record.job.evaluator_escrow)
            .ok_or(LoomError::ArithmeticOverflow)?;
        if split.total()? != worker_bond {
            return Err(LoomError::InvalidSettlement);
        }
        self.distribute_locked(
            &[
                (requester, escrow),
                (dispute.challenger, dispute.bond),
                (dispute.challenger, split.worker),
                (accounts.verifier, split.verifier),
                (accounts.evaluator, split.evaluator),
            ],
            split.da_provider,
        )?;
        let record = self.jobs.get_mut(&job_id).ok_or(LoomError::UnknownJob)?;
        if let Some(receipt) = record.receipt.as_mut() {
            receipt.correctness = Correctness::Rejected;
        }
        record.state = JobState::Rejected;
        Ok(())
    }
    fn release_locked(&mut self, account: AccountId, amount: u128) -> Result<(), LoomError> {
        self.distribute_locked(&[(account, amount)], 0)
    }

    /// Preflight an entire terminal distribution before touching balances.
    /// Recipient aliases are aggregated, and overflow or direction mistakes
    /// leave escrow, balances, and burn accounting byte-for-byte unchanged.
    fn distribute_locked(
        &mut self,
        payouts: &[(AccountId, u128)],
        burn: u128,
    ) -> Result<(), LoomError> {
        let mut aggregated = BTreeMap::<AccountId, u128>::new();
        for (account, amount) in payouts {
            let prior = aggregated.get(account).copied().unwrap_or(0);
            aggregated.insert(
                *account,
                prior
                    .checked_add(*amount)
                    .ok_or(LoomError::ArithmeticOverflow)?,
            );
        }
        let payout_total = aggregated.values().try_fold(0u128, |sum, amount| {
            sum.checked_add(*amount)
                .ok_or(LoomError::ArithmeticOverflow)
        })?;
        let released = payout_total
            .checked_add(burn)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let next_locked = self
            .locked
            .checked_sub(released)
            .ok_or(LoomError::InvalidSettlement)?;
        let next_burned = self
            .burned
            .checked_add(burn)
            .ok_or(LoomError::ArithmeticOverflow)?;
        let next_balances = aggregated
            .iter()
            .map(|(account, amount)| {
                self.balance(account)
                    .checked_add(*amount)
                    .map(|next| (*account, next))
                    .ok_or(LoomError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (account, next) in next_balances {
            self.balances.insert(account, next);
        }
        self.locked = next_locked;
        self.burned = next_burned;
        Ok(())
    }
}

fn job_id(job: &OpenJob) -> Hash32 {
    domain_hash(
        domains::JOB_ID,
        &[
            &job.requester,
            &job.refund_account,
            &job.class_id.to_le_bytes(),
            &[job.required_assurance.tag()],
            &job.input_root,
            &job.model_or_program_root,
            &job.delivery_pubkey,
            &[job.delivery_rule.tag()],
            &job.settlement_accounts.verifier,
            &job.settlement_accounts.evaluator,
            &job.settlement_accounts.da_provider,
            &job.max_resources.bytes.to_le_bytes(),
            &job.max_resources.compute.to_le_bytes(),
            &job.max_resources.verification.to_le_bytes(),
            &job.max_resources.reads.to_le_bytes(),
            &job.max_resources.da_bytes.to_le_bytes(),
            &job.fee_escrow.to_le_bytes(),
            &job.evaluator_escrow.to_le_bytes(),
            &job.opened_height.to_le_bytes(),
            &job.commit_deadline.to_le_bytes(),
            &job.submit_deadline.to_le_bytes(),
            &job.expiry_height.to_le_bytes(),
            &job.nonce.to_le_bytes(),
        ],
    )
}
fn worker_commit_hash(commit: &WorkerCommit) -> Hash32 {
    domain_hash(
        domains::WORKER_COMMIT,
        &[
            &commit.job_id,
            &commit.worker,
            &commit.implementation_profile.to_le_bytes(),
            &commit.input_root,
            &commit.worker_nonce_commitment,
            &commit.availability_plan_root,
            &commit.bond.to_le_bytes(),
            &commit.committed_height.to_le_bytes(),
        ],
    )
}
fn receipt_id(receipt: &WorkReceipt) -> Hash32 {
    domain_hash(
        domains::RECEIPT_ID,
        &[
            &receipt.job_id,
            &receipt.worker_commit_hash,
            &receipt.challenge,
            &receipt.artifact_id,
            &receipt.output_commitment,
            &receipt.encrypted_delivery_commitment,
            &receipt.execution_evidence_root,
            &receipt.nullifier,
        ],
    )
}
fn debit(
    balances: &mut BTreeMap<AccountId, u128>,
    account: AccountId,
    amount: u128,
) -> Result<(), LoomError> {
    let balance = balances
        .get_mut(&account)
        .ok_or(LoomError::InsufficientFunds)?;
    *balance = balance
        .checked_sub(amount)
        .ok_or(LoomError::InsufficientFunds)?;
    Ok(())
}
fn credit(
    balances: &mut BTreeMap<AccountId, u128>,
    account: AccountId,
    amount: u128,
) -> Result<(), LoomError> {
    let prior = balances.get(&account).copied().unwrap_or(0);
    balances.insert(
        account,
        prior
            .checked_add(amount)
            .ok_or(LoomError::ArithmeticOverflow)?,
    );
    Ok(())
}
fn checked_sum<const N: usize>(values: [u128; N]) -> Result<u128, LoomError> {
    values.into_iter().try_fold(0u128, |a, b| {
        a.checked_add(b).ok_or(LoomError::ArithmeticOverflow)
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProductionInfluence {
    pub loom_proposal_credit: u128,
    pub proofpower: u128,
    pub duplex_issuance: u128,
}

pub mod shadow {
    use super::{economics::DemandEvidence, Hash32};
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Inputs {
        pub ground_work: u128,
        pub settled_value: u128,
        pub calibration_units: u128,
        pub raw_stake: u128,
        pub demand_evidence: DemandEvidence,
        pub delivered: bool,
        pub paid_certificate: bool,
    }
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Outputs {
        pub counterfactual_loom_credit: u128,
        pub counterfactual_proofpower: u128,
        pub counterfactual_duplex: u128,
        pub production_loom_credit: u128,
        pub production_proofpower: u128,
        pub production_duplex: u128,
    }
    #[must_use]
    pub fn calculate(input: Inputs, _receipt: Hash32) -> Outputs {
        let external =
            input.demand_evidence.qualifies() && input.delivered && input.paid_certificate;
        let cap = input.ground_work / 9;
        Outputs {
            counterfactual_loom_credit: if external {
                input.calibration_units.min(cap)
            } else {
                0
            },
            // Proofpower and Duplex require stateful maturity/duplicate/cap
            // accounting. The legacy stateless quote cannot bypass the exact
            // economics books by manufacturing a self-labelled receipt.
            counterfactual_proofpower: 0,
            counterfactual_duplex: 0,
            ..Outputs::default()
        }
    }
}

/// Adapter for Lumen's frozen three-method escrow hook. A settlement plan is
/// registered before reservation because the trait intentionally carries no
/// recipient argument. Every plan is immutable and must sum to the reservation.
#[derive(Debug, Clone, Default)]
pub struct LumenEscrowAdapter {
    balances: BTreeMap<Hash32, u128>,
    plans: BTreeMap<Hash32, BTreeMap<Hash32, u128>>,
    reservations: BTreeMap<Hash32, (Hash32, u128)>,
    settled: BTreeSet<Hash32>,
}
impl LumenEscrowAdapter {
    pub fn credit_genesis(
        &mut self,
        account: Hash32,
        amount: u128,
    ) -> Result<(), LumenEscrowError> {
        let prior = self.balances.get(&account).copied().unwrap_or(0);
        let next = prior
            .checked_add(amount)
            .ok_or(LumenEscrowError::InsufficientFunds)?;
        self.balances.insert(account, next);
        Ok(())
    }
    pub fn set_plan(
        &mut self,
        job: Hash32,
        plan: BTreeMap<Hash32, u128>,
    ) -> Result<(), LumenEscrowError> {
        if self.plans.contains_key(&job) || self.reservations.contains_key(&job) {
            return Err(LumenEscrowError::AlreadySettled);
        }
        self.plans.insert(job, plan);
        Ok(())
    }
    #[must_use]
    pub fn balance(&self, account: &Hash32) -> u128 {
        self.balances.get(account).copied().unwrap_or(0)
    }
}
impl WorkJobEscrow for LumenEscrowAdapter {
    fn reserve(
        &mut self,
        job_id: &Hash32,
        payer: &Hash32,
        amount: u128,
    ) -> Result<(), LumenEscrowError> {
        if self.reservations.contains_key(job_id) || self.settled.contains(job_id) {
            return Err(LumenEscrowError::AlreadySettled);
        }
        let plan = self.plans.get(job_id).ok_or(LumenEscrowError::UnknownJob)?;
        let total = plan.values().try_fold(0u128, |a, b| {
            a.checked_add(*b).ok_or(LumenEscrowError::InsufficientFunds)
        })?;
        if total != amount {
            return Err(LumenEscrowError::InsufficientFunds);
        }
        let balance = self
            .balances
            .get_mut(payer)
            .ok_or(LumenEscrowError::InsufficientFunds)?;
        *balance = balance
            .checked_sub(amount)
            .ok_or(LumenEscrowError::InsufficientFunds)?;
        self.reservations.insert(*job_id, (*payer, amount));
        Ok(())
    }
    fn settle(&mut self, job_id: &Hash32) -> Result<(), LumenEscrowError> {
        let (_, reserved) =
            self.reservations
                .remove(job_id)
                .ok_or(if self.settled.contains(job_id) {
                    LumenEscrowError::AlreadySettled
                } else {
                    LumenEscrowError::UnknownJob
                })?;
        let plan = self.plans.get(job_id).ok_or(LumenEscrowError::UnknownJob)?;
        let mut paid = 0u128;
        for (recipient, amount) in plan {
            let prior = self.balances.get(recipient).copied().unwrap_or(0);
            self.balances.insert(
                *recipient,
                prior
                    .checked_add(*amount)
                    .ok_or(LumenEscrowError::InsufficientFunds)?,
            );
            paid = paid
                .checked_add(*amount)
                .ok_or(LumenEscrowError::InsufficientFunds)?;
        }
        if paid != reserved {
            return Err(LumenEscrowError::InsufficientFunds);
        }
        self.settled.insert(*job_id);
        Ok(())
    }
    fn refund(&mut self, job_id: &Hash32) -> Result<(), LumenEscrowError> {
        let (payer, amount) =
            self.reservations
                .remove(job_id)
                .ok_or(if self.settled.contains(job_id) {
                    LumenEscrowError::AlreadySettled
                } else {
                    LumenEscrowError::UnknownJob
                })?;
        let prior = self.balances.get(&payer).copied().unwrap_or(0);
        self.balances.insert(
            payer,
            prior
                .checked_add(amount)
                .ok_or(LumenEscrowError::InsufficientFunds)?,
        );
        self.settled.insert(*job_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
