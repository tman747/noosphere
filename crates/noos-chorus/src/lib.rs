//! Chorus retrieval and advisory evidence with lineage/failure-domain quotienting.
#![forbid(unsafe_code)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub const LIFECYCLE: &str = "EXPERIMENTAL";
pub const RESULT: &str = "ADVISORY_ONLY";
pub const DEFAULT_SLASHABLE: bool = false;
pub const SLASHABLE_AUDITS_ENABLED: bool = false;
pub const MAX_TASK_BYTES: u32 = 1_048_576;
pub const MAX_TASK_STEPS: u64 = 10_000_000;
pub const PROPOSAL_WEIGHT: u64 = 0;
pub const FINALITY_WEIGHT: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskKind {
    Retrieval,
    Advisory,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedTask {
    pub task_id: Hash32,
    pub kind: TaskKind,
    pub commitment: Hash32,
    pub beacon: Hash32,
    pub max_input_bytes: u32,
    pub max_output_bytes: u32,
    pub max_steps: u64,
    pub deadline: u64,
}
impl BoundedTask {
    pub fn derive_id(commitment: Hash32, beacon: Hash32, deadline: u64) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/TASK/V1");
        h.update(&commitment);
        h.update(&beacon);
        h.update(&deadline.to_le_bytes());
        *h.finalize().as_bytes()
    }
    pub fn validate(&self) -> Result<(), ChorusError> {
        if self.beacon == [0; 32]
            || self.commitment == [0; 32]
            || self.task_id != Self::derive_id(self.commitment, self.beacon, self.deadline)
        {
            return Err(ChorusError::PredictableOrMalformed);
        }
        if self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_input_bytes > MAX_TASK_BYTES
            || self.max_output_bytes > MAX_TASK_BYTES
            || self.max_steps == 0
            || self.max_steps > MAX_TASK_STEPS
        {
            return Err(ChorusError::Unbounded);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub task_id: Hash32,
    pub worker: Hash32,
    pub lineage_root: Hash32,
    pub failure_domain: Hash32,
    pub value: i128,
    pub object_root: Hash32,
    pub available: bool,
}
fn quotient_key(e: &Evidence) -> (Hash32, Hash32) {
    (e.lineage_root, e.failure_domain)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub median: i128,
    pub quotient_count: usize,
    pub hidden_copy_limitation: &'static str,
    pub authoritative: bool,
}
/// Each lineage/failure-domain quotient gets one deterministic representative;
/// conflicting members invalidate that quotient rather than multiplying votes.
pub fn advisory(task: &BoundedTask, evidence: &[Evidence]) -> Result<Advisory, ChorusError> {
    task.validate()?;
    let mut groups: BTreeMap<(Hash32, Hash32), BTreeSet<i128>> = BTreeMap::new();
    for e in evidence {
        if e.task_id != task.task_id {
            return Err(ChorusError::WrongTask);
        }
        if !e.available {
            continue;
        }
        groups.entry(quotient_key(e)).or_default().insert(e.value);
    }
    let mut values = Vec::new();
    for set in groups.values() {
        if set.len() == 1 {
            values.push(*set.iter().next().ok_or(ChorusError::NoQuotients)?);
        }
    }
    if values.is_empty() {
        return Err(ChorusError::NoQuotients);
    }
    values.sort();
    let median_index = values
        .len()
        .checked_sub(1)
        .and_then(|value| value.checked_div(2))
        .ok_or(ChorusError::NoQuotients)?;
    let median = values[median_index];
    Ok(Advisory {
        median,
        quotient_count: values.len(),
        hidden_copy_limitation: "HIDDEN_COPYING_CANNOT_BE_DETECTED_FROM_DECLARED_LINEAGE",
        authoritative: false,
    })
}
pub const E_ORACLE_01_RESULT: &str = "EXPERIMENTAL_PROFILE";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleReport {
    pub lineage_quotient_median: i128,
    pub quotient_count: usize,
    pub universal_truth: bool,
    pub limitation: &'static str,
}
pub fn oracle_report(
    task: &BoundedTask,
    evidence: &[Evidence],
) -> Result<OracleReport, ChorusError> {
    let result = advisory(task, evidence)?;
    Ok(OracleReport {
        lineage_quotient_median: result.median,
        quotient_count: result.quotient_count,
        universal_truth: false,
        limitation: "HIDDEN_COPIES_OUTSIDE_DECLARED_LINEAGE_REMAIN_UNQUOTIENTED",
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievalResult {
    pub object_root: Hash32,
    pub quotient_count: usize,
    pub advisory_only: bool,
}
pub fn retrieval(
    task: &BoundedTask,
    evidence: &[Evidence],
    minimum_quotients: usize,
) -> Result<RetrievalResult, ChorusError> {
    task.validate()?;
    if task.kind != TaskKind::Retrieval {
        return Err(ChorusError::WrongKind);
    }
    let mut by_object: BTreeMap<Hash32, BTreeSet<(Hash32, Hash32)>> = BTreeMap::new();
    for e in evidence {
        if e.task_id != task.task_id {
            return Err(ChorusError::WrongTask);
        }
        if e.available {
            by_object
                .entry(e.object_root)
                .or_default()
                .insert(quotient_key(e));
        }
    }
    let selected = by_object
        .into_iter()
        .filter(|(_, q)| q.len() >= minimum_quotients)
        .max_by_key(|(root, q)| (q.len(), *root))
        .ok_or(ChorusError::InsufficientDiversity)?;
    Ok(RetrievalResult {
        object_root: selected.0,
        quotient_count: selected.1.len(),
        advisory_only: true,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiversityVerdict {
    AdvisoryEligible,
    HiddenCloneFalsifier,
    ManufacturedThirdFalsifier,
}
pub fn diversity_falsifier(
    total: u64,
    manufactured: u64,
    hidden_clone_detected: bool,
) -> DiversityVerdict {
    if hidden_clone_detected {
        return DiversityVerdict::HiddenCloneFalsifier;
    }
    if total > 0 && u128::from(manufactured) * 3 >= u128::from(total) {
        DiversityVerdict::ManufacturedThirdFalsifier
    } else {
        DiversityVerdict::AdvisoryEligible
    }
}
#[must_use]
pub const fn slash_amount() -> u128 {
    0
}

/// A software-verifiable precursor to a physical-device attestation profile.
/// Hardware provenance and real-world diversity remain external evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceProfile {
    pub device_id: Hash32,
    pub profile_id: Hash32,
    pub verifying_key: [u8; 32],
    pub lineage_root: Hash32,
    pub failure_domain: Hash32,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

impl DeviceProfile {
    #[must_use]
    pub fn derive_device_id(verifying_key: [u8; 32]) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/DEVICE/V1");
        h.update(&verifying_key);
        *h.finalize().as_bytes()
    }

    #[must_use]
    pub fn derive_profile_id(
        device_id: Hash32,
        verifying_key: [u8; 32],
        lineage_root: Hash32,
        failure_domain: Hash32,
        valid_from_ms: u64,
        valid_until_ms: u64,
    ) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/DEVICE-PROFILE/V1");
        h.update(&device_id);
        h.update(&verifying_key);
        h.update(&lineage_root);
        h.update(&failure_domain);
        h.update(&valid_from_ms.to_le_bytes());
        h.update(&valid_until_ms.to_le_bytes());
        *h.finalize().as_bytes()
    }

    pub fn validate(&self) -> Result<(), ChorusError> {
        if self.device_id == [0; 32]
            || self.lineage_root == [0; 32]
            || self.failure_domain == [0; 32]
            || self.valid_from_ms > self.valid_until_ms
            || self.device_id != Self::derive_device_id(self.verifying_key)
            || self.profile_id
                != Self::derive_profile_id(
                    self.device_id,
                    self.verifying_key,
                    self.lineage_root,
                    self.failure_domain,
                    self.valid_from_ms,
                    self.valid_until_ms,
                )
        {
            return Err(ChorusError::ProfileBinding);
        }
        VerifyingKey::from_bytes(&self.verifying_key).map_err(|_| ChorusError::ProfileBinding)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionAssignment {
    pub slice_index: u32,
    pub slice_count: u32,
}

impl ProjectionAssignment {
    pub fn derive(
        task: &BoundedTask,
        device_id: Hash32,
        slice_count: u32,
    ) -> Result<Self, ChorusError> {
        task.validate()?;
        if slice_count == 0 {
            return Err(ChorusError::Projection);
        }
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/PROJECTION/V1");
        h.update(&task.task_id);
        h.update(&task.beacon);
        h.update(&device_id);
        h.update(&slice_count.to_le_bytes());
        let bytes = h.finalize();
        let prefix = bytes.as_bytes().get(..4).ok_or(ChorusError::Projection)?;
        let value = u32::from_le_bytes(prefix.try_into().map_err(|_| ChorusError::Projection)?);
        Ok(Self {
            slice_index: value
                .checked_rem(slice_count)
                .ok_or(ChorusError::Projection)?,
            slice_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshMessage {
    pub task_id: Hash32,
    pub device_id: Hash32,
    pub profile_id: Hash32,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub prior_message: Hash32,
    pub slice_index: u32,
    pub slice_count: u32,
    pub projection_digest: Hash32,
    pub object_root: Hash32,
    pub value: i128,
    pub commitment_checked: bool,
    pub evidence_available: bool,
    pub signature: [u8; 64],
}

impl MeshMessage {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(b"NOOS/CHORUS/MESH-MESSAGE/V1");
        bytes.extend_from_slice(&self.task_id);
        bytes.extend_from_slice(&self.device_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.observed_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.prior_message);
        bytes.extend_from_slice(&self.slice_index.to_le_bytes());
        bytes.extend_from_slice(&self.slice_count.to_le_bytes());
        bytes.extend_from_slice(&self.projection_digest);
        bytes.extend_from_slice(&self.object_root);
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.push(u8::from(self.commitment_checked));
        bytes.push(u8::from(self.evidence_available));
        bytes
    }

    #[must_use]
    pub fn digest(&self) -> Hash32 {
        *blake3::hash(&self.signing_bytes()).as_bytes()
    }

    fn verify_signature(&self, profile: &DeviceProfile) -> Result<(), ChorusError> {
        let key =
            VerifyingKey::from_bytes(&profile.verifying_key).map_err(|_| ChorusError::Signature)?;
        key.verify(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ChorusError::Signature)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshPolicy {
    pub aggregation_enabled: bool,
    pub maximum_past_age_ms: u64,
    pub maximum_future_skew_ms: u64,
}

impl MeshPolicy {
    #[must_use]
    pub const fn research() -> Self {
        Self {
            aggregation_enabled: true,
            maximum_past_age_ms: 60_000,
            maximum_future_skew_ms: 5_000,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            aggregation_enabled: false,
            maximum_past_age_ms: 60_000,
            maximum_future_skew_ms: 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Checkpoint {
    sequence: u64,
    digest: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshSnapshot {
    pub task_id: Hash32,
    pub state_root: Hash32,
    pub advisory: Advisory,
    pub accepted_devices: usize,
    pub rejected_branch_messages: usize,
    pub authoritative: bool,
    pub proposal_weight: u64,
    pub finality_weight: u64,
    accepted_heads: BTreeMap<Hash32, Checkpoint>,
    equivocated_devices: BTreeSet<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshReceipt {
    pub task_id: Hash32,
    pub state_root: Hash32,
    pub accepted_devices: usize,
    pub rejected_branch_messages: usize,
    pub advisory_only: bool,
    pub proposal_weight: u64,
    pub finality_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChorusRollbackReceipt {
    pub prior_journal_root: Hash32,
    pub discarded_messages: usize,
    pub aggregation_enabled: bool,
    pub optional_local_verification_retained: bool,
    pub proposal_weight: u64,
    pub finality_weight: u64,
}

pub struct ChorusMesh {
    policy: MeshPolicy,
    profiles: BTreeMap<Hash32, DeviceProfile>,
    messages: BTreeMap<Hash32, MeshMessage>,
    checkpoints: BTreeMap<(Hash32, Hash32), Checkpoint>,
    quarantined_devices: BTreeSet<(Hash32, Hash32)>,
}

type DeviceMessages<'a> = BTreeMap<Hash32, BTreeMap<u64, Vec<(Hash32, &'a MeshMessage)>>>;

impl ChorusMesh {
    #[must_use]
    pub fn new(policy: MeshPolicy) -> Self {
        Self {
            policy,
            profiles: BTreeMap::new(),
            messages: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            quarantined_devices: BTreeSet::new(),
        }
    }

    pub fn register_profile(&mut self, profile: DeviceProfile) -> Result<(), ChorusError> {
        profile.validate()?;
        if self.profiles.contains_key(&profile.device_id) {
            return Err(ChorusError::DuplicateProfile);
        }
        self.profiles.insert(profile.device_id, profile);
        Ok(())
    }

    fn validate_message(
        &self,
        task: &BoundedTask,
        message: &MeshMessage,
        now_ms: u64,
    ) -> Result<(), ChorusError> {
        task.validate()?;
        if message.task_id != task.task_id {
            return Err(ChorusError::WrongTask);
        }
        let profile = self
            .profiles
            .get(&message.device_id)
            .ok_or(ChorusError::ProfileBinding)?;
        if message.profile_id != profile.profile_id
            || message.observed_at_ms < profile.valid_from_ms
            || message.observed_at_ms > profile.valid_until_ms
        {
            return Err(ChorusError::ProfileBinding);
        }
        let latest_allowed = now_ms
            .checked_add(self.policy.maximum_future_skew_ms)
            .ok_or(ChorusError::ClockSkew)?;
        let expires_at = message
            .observed_at_ms
            .checked_add(self.policy.maximum_past_age_ms)
            .ok_or(ChorusError::ClockSkew)?;
        if message.observed_at_ms > latest_allowed || now_ms > expires_at {
            return Err(ChorusError::ClockSkew);
        }
        let assignment =
            ProjectionAssignment::derive(task, message.device_id, message.slice_count)?;
        if assignment.slice_index != message.slice_index
            || message.projection_digest == [0; 32]
            || message.object_root == [0; 32]
            || !message.commitment_checked
        {
            return Err(ChorusError::Projection);
        }
        message.verify_signature(profile)
    }

    /// Verifies an attestation without adding it to aggregation state. This
    /// remains available after aggregation rollback.
    pub fn verify_locally(
        &self,
        task: &BoundedTask,
        message: &MeshMessage,
        now_ms: u64,
    ) -> Result<(), ChorusError> {
        self.validate_message(task, message, now_ms)
    }

    pub fn submit(
        &mut self,
        task: &BoundedTask,
        message: MeshMessage,
        now_ms: u64,
    ) -> Result<Hash32, ChorusError> {
        if !self.policy.aggregation_enabled {
            return Err(ChorusError::AggregationDisabled);
        }
        self.validate_message(task, &message, now_ms)?;
        if self
            .quarantined_devices
            .contains(&(message.task_id, message.device_id))
        {
            return Err(ChorusError::EquivocatedDevice);
        }
        if let Some(checkpoint) = self.checkpoints.get(&(message.task_id, message.device_id)) {
            if message.sequence <= checkpoint.sequence {
                return Err(ChorusError::StaleMessage);
            }
        }
        let digest = message.digest();
        if self.messages.contains_key(&digest) {
            return Err(ChorusError::DuplicateMessage);
        }
        self.messages.insert(digest, message);
        Ok(digest)
    }

    pub fn snapshot(&self, task: &BoundedTask) -> Result<MeshSnapshot, ChorusError> {
        task.validate()?;
        let mut by_device: DeviceMessages<'_> = BTreeMap::new();
        for (digest, message) in &self.messages {
            if message.task_id == task.task_id {
                by_device
                    .entry(message.device_id)
                    .or_default()
                    .entry(message.sequence)
                    .or_default()
                    .push((*digest, message));
            }
        }

        let mut accepted = Vec::new();
        let mut accepted_heads = BTreeMap::new();
        let mut equivocated_devices = BTreeSet::new();
        let mut rejected_digests = Vec::new();
        let mut rejected_branch_messages = 0usize;
        for (device_id, sequence_messages) in by_device {
            if sequence_messages
                .values()
                .any(|messages| messages.len() != 1)
            {
                rejected_branch_messages = rejected_branch_messages
                    .checked_add(sequence_messages.values().map(Vec::len).sum::<usize>())
                    .ok_or(ChorusError::StateOverflow)?;
                equivocated_devices.insert(device_id);
                rejected_digests.extend(
                    sequence_messages
                        .values()
                        .flat_map(|messages| messages.iter().map(|(digest, _)| *digest)),
                );
                continue;
            }
            let checkpoint = self.checkpoints.get(&(task.task_id, device_id));
            let mut expected_sequence =
                checkpoint.map_or(0, |value| value.sequence.saturating_add(1));
            let mut expected_prior = checkpoint.map_or([0; 32], |value| value.digest);
            let mut latest = None;
            for (sequence, messages) in sequence_messages {
                if sequence != expected_sequence {
                    break;
                }
                let (digest, message) = messages
                    .first()
                    .copied()
                    .ok_or(ChorusError::StateOverflow)?;
                if message.prior_message != expected_prior {
                    break;
                }
                latest = Some((digest, message));
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or(ChorusError::StateOverflow)?;
                expected_prior = digest;
            }
            if let Some((digest, message)) = latest {
                accepted.push((digest, message));
                accepted_heads.insert(
                    device_id,
                    Checkpoint {
                        sequence: message.sequence,
                        digest,
                    },
                );
            }
        }

        let evidence = accepted
            .iter()
            .map(|(_, message)| {
                let profile = self
                    .profiles
                    .get(&message.device_id)
                    .ok_or(ChorusError::ProfileBinding)?;
                Ok(Evidence {
                    task_id: task.task_id,
                    worker: message.device_id,
                    lineage_root: profile.lineage_root,
                    failure_domain: profile.failure_domain,
                    value: message.value,
                    object_root: message.object_root,
                    available: message.evidence_available,
                })
            })
            .collect::<Result<Vec<_>, ChorusError>>()?;
        let advisory = advisory(task, &evidence)?;

        accepted.sort_by_key(|(digest, _)| *digest);
        rejected_digests.sort();
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/MESH-STATE/V1");
        h.update(&task.task_id);
        for (digest, _) in &accepted {
            h.update(digest);
        }
        for digest in &rejected_digests {
            h.update(digest);
        }
        h.update(
            &u64::try_from(rejected_branch_messages)
                .map_err(|_| ChorusError::StateOverflow)?
                .to_le_bytes(),
        );
        let state_root = *h.finalize().as_bytes();
        Ok(MeshSnapshot {
            task_id: task.task_id,
            state_root,
            advisory,
            accepted_devices: accepted.len(),
            rejected_branch_messages,
            authoritative: false,
            proposal_weight: PROPOSAL_WEIGHT,
            finality_weight: FINALITY_WEIGHT,
            accepted_heads,
            equivocated_devices,
        })
    }

    pub fn finalize(&mut self, task: &BoundedTask) -> Result<MeshReceipt, ChorusError> {
        let snapshot = self.snapshot(task)?;
        for (device_id, checkpoint) in &snapshot.accepted_heads {
            self.checkpoints
                .insert((task.task_id, *device_id), *checkpoint);
        }
        for device_id in &snapshot.equivocated_devices {
            self.quarantined_devices.insert((task.task_id, *device_id));
        }
        self.messages
            .retain(|_, message| message.task_id != task.task_id);
        Ok(MeshReceipt {
            task_id: task.task_id,
            state_root: snapshot.state_root,
            accepted_devices: snapshot.accepted_devices,
            rejected_branch_messages: snapshot.rejected_branch_messages,
            advisory_only: true,
            proposal_weight: PROPOSAL_WEIGHT,
            finality_weight: FINALITY_WEIGHT,
        })
    }

    #[must_use]
    pub fn journal_root(&self) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/CHORUS/MESH-JOURNAL/V1");
        for digest in self.messages.keys() {
            h.update(digest);
        }
        *h.finalize().as_bytes()
    }

    pub fn disable_and_rollback(&mut self) -> ChorusRollbackReceipt {
        let prior_journal_root = self.journal_root();
        let discarded_messages = self.messages.len();
        self.messages.clear();
        self.checkpoints.clear();
        self.quarantined_devices.clear();
        self.policy.aggregation_enabled = false;
        ChorusRollbackReceipt {
            prior_journal_root,
            discarded_messages,
            aggregation_enabled: false,
            optional_local_verification_retained: true,
            proposal_weight: PROPOSAL_WEIGHT,
            finality_weight: FINALITY_WEIGHT,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChorusError {
    #[error("task is predictable or malformed")]
    PredictableOrMalformed,
    #[error("task bounds invalid")]
    Unbounded,
    #[error("evidence targets another task")]
    WrongTask,
    #[error("wrong task kind")]
    WrongKind,
    #[error("no valid lineage quotients")]
    NoQuotients,
    #[error("insufficient quotient diversity")]
    InsufficientDiversity,
    #[error("device identity or profile binding invalid")]
    ProfileBinding,
    #[error("duplicate device profile")]
    DuplicateProfile,
    #[error("projection assignment or commitment check invalid")]
    Projection,
    #[error("invalid device signature")]
    Signature,
    #[error("attestation outside the inclusive clock-skew window")]
    ClockSkew,
    #[error("advisory aggregation is disabled")]
    AggregationDisabled,
    #[error("duplicate mesh message")]
    DuplicateMessage,
    #[error("mesh message is stale relative to a finalized receipt")]
    StaleMessage,
    #[error("device equivocated and is quarantined for this task")]
    EquivocatedDevice,
    #[error("mesh state counter overflow")]
    StateOverflow,
}
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants
    )]
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn h(v: u8) -> Hash32 {
        [v; 32]
    }
    fn task(kind: TaskKind) -> BoundedTask {
        let c = h(1);
        let b = h(2);
        let d = 9;
        BoundedTask {
            task_id: BoundedTask::derive_id(c, b, d),
            kind,
            commitment: c,
            beacon: b,
            max_input_bytes: 10,
            max_output_bytes: 10,
            max_steps: 100,
            deadline: d,
        }
    }
    fn e(t: &BoundedTask, w: u8, l: u8, f: u8, v: i128, o: u8) -> Evidence {
        Evidence {
            task_id: t.task_id,
            worker: h(w),
            lineage_root: h(l),
            failure_domain: h(f),
            value: v,
            object_root: h(o),
            available: true,
        }
    }
    fn device_profile(key: &SigningKey, lineage: u8, failure_domain: u8) -> DeviceProfile {
        let verifying_key = key.verifying_key().to_bytes();
        let device_id = DeviceProfile::derive_device_id(verifying_key);
        let lineage_root = h(lineage);
        let failure_domain = h(failure_domain);
        let valid_from_ms = 0;
        let valid_until_ms = 1_000_000;
        DeviceProfile {
            device_id,
            profile_id: DeviceProfile::derive_profile_id(
                device_id,
                verifying_key,
                lineage_root,
                failure_domain,
                valid_from_ms,
                valid_until_ms,
            ),
            verifying_key,
            lineage_root,
            failure_domain,
            valid_from_ms,
            valid_until_ms,
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn message(
        task: &BoundedTask,
        key: &SigningKey,
        profile: &DeviceProfile,
        sequence: u64,
        prior_message: Hash32,
        observed_at_ms: u64,
        value: i128,
        object: u8,
    ) -> MeshMessage {
        let assignment = ProjectionAssignment::derive(task, profile.device_id, 64).unwrap();
        let mut message = MeshMessage {
            task_id: task.task_id,
            device_id: profile.device_id,
            profile_id: profile.profile_id,
            sequence,
            observed_at_ms,
            prior_message,
            slice_index: assignment.slice_index,
            slice_count: assignment.slice_count,
            projection_digest: h(object.wrapping_add(1)),
            object_root: h(object),
            value,
            commitment_checked: true,
            evidence_available: true,
            signature: [0; 64],
        };
        message.signature = key.sign(&message.signing_bytes()).to_bytes();
        message
    }
    #[test]
    fn duplicate_lineage_is_one_vote() {
        let t = task(TaskKind::Advisory);
        let a = advisory(
            &t,
            &[
                e(&t, 1, 1, 1, 10, 8),
                e(&t, 2, 1, 1, 10, 8),
                e(&t, 3, 2, 2, 30, 8),
            ],
        )
        .unwrap();
        assert_eq!(
            (a.median, a.quotient_count, a.authoritative),
            (10, 2, false)
        );
    }
    #[test]
    fn conflicting_clone_group_is_discarded() {
        let t = task(TaskKind::Advisory);
        let a = advisory(
            &t,
            &[
                e(&t, 1, 1, 1, 10, 8),
                e(&t, 2, 1, 1, 11, 8),
                e(&t, 3, 2, 2, 30, 8),
            ],
        )
        .unwrap();
        assert_eq!((a.median, a.quotient_count), (30, 1));
    }
    #[test]
    fn retrieval_requires_distinct_quotients() {
        let t = task(TaskKind::Retrieval);
        assert_eq!(
            retrieval(&t, &[e(&t, 1, 1, 1, 0, 9), e(&t, 2, 1, 1, 0, 9)], 2),
            Err(ChorusError::InsufficientDiversity)
        );
        let r = retrieval(&t, &[e(&t, 1, 1, 1, 0, 9), e(&t, 2, 2, 2, 0, 9)], 2).unwrap();
        assert_eq!(r.object_root, h(9));
    }
    #[test]
    fn task_bounds_and_unpredictability_fail_closed() {
        let mut t = task(TaskKind::Retrieval);
        t.beacon = [0; 32];
        assert_eq!(t.validate(), Err(ChorusError::PredictableOrMalformed));
        let mut t = task(TaskKind::Retrieval);
        t.max_steps = MAX_TASK_STEPS + 1;
        assert_eq!(t.validate(), Err(ChorusError::Unbounded));
    }
    #[test]
    fn falsifiers_and_slashing_literals() {
        assert_eq!(
            diversity_falsifier(9, 3, false),
            DiversityVerdict::ManufacturedThirdFalsifier
        );
        assert_eq!(
            diversity_falsifier(9, 0, true),
            DiversityVerdict::HiddenCloneFalsifier
        );
        assert!(!DEFAULT_SLASHABLE && !SLASHABLE_AUDITS_ENABLED);
        assert_eq!(slash_amount(), 0);
        assert_eq!((LIFECYCLE, RESULT), ("EXPERIMENTAL", "ADVISORY_ONLY"));
    }
    #[test]
    fn oracle_median_is_explicitly_nonauthoritative() {
        let t = task(TaskKind::Advisory);
        let report = oracle_report(&t, &[e(&t, 1, 1, 1, 5, 8), e(&t, 2, 2, 2, 9, 8)]).unwrap();
        assert_eq!(report.lineage_quotient_median, 5);
        assert!(!report.universal_truth);
        assert_eq!(E_ORACLE_01_RESULT, "EXPERIMENTAL_PROFILE");
        assert!(report.limitation.contains("HIDDEN_COPIES"));
    }

    #[test]
    fn mesh_multi_party_order_and_replay_are_deterministic() {
        let task = task(TaskKind::Advisory);
        let keys = [
            SigningKey::from_bytes(&h(21)),
            SigningKey::from_bytes(&h(22)),
            SigningKey::from_bytes(&h(23)),
        ];
        let profiles = [
            device_profile(&keys[0], 31, 41),
            device_profile(&keys[1], 32, 42),
            device_profile(&keys[2], 33, 43),
        ];
        let messages = [
            message(&task, &keys[0], &profiles[0], 0, [0; 32], 100, 10, 9),
            message(&task, &keys[1], &profiles[1], 0, [0; 32], 100, 20, 9),
            message(&task, &keys[2], &profiles[2], 0, [0; 32], 100, 30, 9),
        ];
        let mut left = ChorusMesh::new(MeshPolicy::research());
        let mut right = ChorusMesh::new(MeshPolicy::research());
        for profile in &profiles {
            left.register_profile(profile.clone()).unwrap();
            right.register_profile(profile.clone()).unwrap();
        }
        for index in [0, 1, 2] {
            left.submit(&task, messages[index].clone(), 100).unwrap();
        }
        for index in [2, 0, 1] {
            right.submit(&task, messages[index].clone(), 100).unwrap();
        }
        let left_snapshot = left.snapshot(&task).unwrap();
        let right_snapshot = right.snapshot(&task).unwrap();
        assert_eq!(left_snapshot, right_snapshot);
        assert_eq!(left_snapshot.advisory.median, 20);
        assert_eq!(left_snapshot.accepted_devices, 3);
        assert!(!left_snapshot.authoritative);
        assert_eq!(
            (left_snapshot.proposal_weight, left_snapshot.finality_weight),
            (0, 0)
        );
    }

    #[test]
    fn duplicate_and_finalized_stale_messages_reject_without_state_change() {
        let task = task(TaskKind::Advisory);
        let key = SigningKey::from_bytes(&h(24));
        let profile = device_profile(&key, 31, 41);
        let first = message(&task, &key, &profile, 0, [0; 32], 100, 10, 9);
        let mut mesh = ChorusMesh::new(MeshPolicy::research());
        mesh.register_profile(profile.clone()).unwrap();
        let first_digest = mesh.submit(&task, first.clone(), 100).unwrap();
        let root = mesh.journal_root();
        assert_eq!(
            mesh.submit(&task, first.clone(), 100),
            Err(ChorusError::DuplicateMessage)
        );
        assert_eq!(mesh.journal_root(), root);
        let receipt = mesh.finalize(&task).unwrap();
        assert!(receipt.advisory_only);
        assert_eq!(
            mesh.submit(&task, first, 100),
            Err(ChorusError::StaleMessage)
        );
        let second = message(&task, &key, &profile, 1, first_digest, 101, 11, 9);
        assert!(mesh.submit(&task, second, 101).is_ok());
    }

    #[test]
    fn forked_device_is_deterministically_removed_from_aggregation() {
        let task = task(TaskKind::Advisory);
        let fork_key = SigningKey::from_bytes(&h(25));
        let honest_key = SigningKey::from_bytes(&h(26));
        let fork_profile = device_profile(&fork_key, 31, 41);
        let honest_profile = device_profile(&honest_key, 32, 42);
        let fork_a = message(&task, &fork_key, &fork_profile, 0, [0; 32], 100, 1, 9);
        let fork_b = message(&task, &fork_key, &fork_profile, 0, [0; 32], 100, 99, 9);
        let honest = message(&task, &honest_key, &honest_profile, 0, [0; 32], 100, 50, 9);
        let mut roots = Vec::new();
        for ordering in [[0, 1, 2], [2, 1, 0]] {
            let mut mesh = ChorusMesh::new(MeshPolicy::research());
            mesh.register_profile(fork_profile.clone()).unwrap();
            mesh.register_profile(honest_profile.clone()).unwrap();
            let candidates = [fork_a.clone(), fork_b.clone(), honest.clone()];
            for index in ordering {
                mesh.submit(&task, candidates[index].clone(), 100).unwrap();
            }
            let snapshot = mesh.snapshot(&task).unwrap();
            assert_eq!(snapshot.accepted_devices, 1);
            assert_eq!(snapshot.rejected_branch_messages, 2);
            assert_eq!(snapshot.advisory.median, 50);
            roots.push(snapshot.state_root);
            let receipt = mesh.finalize(&task).unwrap();
            assert_eq!(receipt.rejected_branch_messages, 2);
            let after_fork = message(&task, &fork_key, &fork_profile, 0, [0; 32], 101, 7, 9);
            assert_eq!(
                mesh.submit(&task, after_fork, 101),
                Err(ChorusError::EquivocatedDevice)
            );
        }
        assert_eq!(roots[0], roots[1]);
    }

    #[test]
    fn profile_signature_projection_and_inclusive_clock_boundaries_bind() {
        let task = task(TaskKind::Advisory);
        let key = SigningKey::from_bytes(&h(27));
        let profile = device_profile(&key, 31, 41);
        let now = 100_000;
        let mut mesh = ChorusMesh::new(MeshPolicy::research());
        mesh.register_profile(profile.clone()).unwrap();
        assert!(mesh
            .submit(
                &task,
                message(&task, &key, &profile, 0, [0; 32], now + 5_000, 10, 9,),
                now,
            )
            .is_ok());

        let mut future = message(&task, &key, &profile, 1, [0; 32], now + 5_001, 10, 9);
        assert_eq!(
            mesh.submit(&task, future.clone(), now),
            Err(ChorusError::ClockSkew)
        );
        future.observed_at_ms = now;
        future.profile_id = h(99);
        future.signature = key.sign(&future.signing_bytes()).to_bytes();
        assert_eq!(
            mesh.submit(&task, future.clone(), now),
            Err(ChorusError::ProfileBinding)
        );
        future.profile_id = profile.profile_id;
        future.slice_index = future.slice_index.wrapping_add(1);
        future.signature = key.sign(&future.signing_bytes()).to_bytes();
        assert_eq!(
            mesh.submit(&task, future.clone(), now),
            Err(ChorusError::Projection)
        );
        future.slice_index = ProjectionAssignment::derive(&task, profile.device_id, 64)
            .unwrap()
            .slice_index;
        future.signature = [0; 64];
        assert_eq!(mesh.submit(&task, future, now), Err(ChorusError::Signature));

        let past_key = SigningKey::from_bytes(&h(28));
        let past_profile = device_profile(&past_key, 32, 42);
        let mut past_mesh = ChorusMesh::new(MeshPolicy::research());
        past_mesh.register_profile(past_profile.clone()).unwrap();
        assert!(past_mesh
            .submit(
                &task,
                message(
                    &task,
                    &past_key,
                    &past_profile,
                    0,
                    [0; 32],
                    now - 60_000,
                    10,
                    9,
                ),
                now,
            )
            .is_ok());
        let stale_key = SigningKey::from_bytes(&h(29));
        let stale_profile = device_profile(&stale_key, 33, 43);
        past_mesh.register_profile(stale_profile.clone()).unwrap();
        assert_eq!(
            past_mesh.submit(
                &task,
                message(
                    &task,
                    &stale_key,
                    &stale_profile,
                    0,
                    [0; 32],
                    now - 60_001,
                    10,
                    9,
                ),
                now,
            ),
            Err(ChorusError::ClockSkew)
        );
    }

    #[test]
    fn disabled_mesh_has_no_aggregation_effect_and_rollback_retains_local_checks() {
        let task = task(TaskKind::Advisory);
        let key = SigningKey::from_bytes(&h(30));
        let profile = device_profile(&key, 31, 41);
        let attestation = message(&task, &key, &profile, 0, [0; 32], 100, 10, 9);
        let mut disabled = ChorusMesh::new(MeshPolicy::disabled());
        disabled.register_profile(profile.clone()).unwrap();
        let before = disabled.journal_root();
        assert_eq!(
            disabled.submit(&task, attestation.clone(), 100),
            Err(ChorusError::AggregationDisabled)
        );
        assert_eq!(disabled.journal_root(), before);
        assert!(disabled.verify_locally(&task, &attestation, 100).is_ok());

        let mut mesh = ChorusMesh::new(MeshPolicy::research());
        mesh.register_profile(profile).unwrap();
        mesh.submit(&task, attestation.clone(), 100).unwrap();
        let rollback = mesh.disable_and_rollback();
        assert_eq!(rollback.discarded_messages, 1);
        assert!(!rollback.aggregation_enabled);
        assert!(rollback.optional_local_verification_retained);
        assert_eq!((rollback.proposal_weight, rollback.finality_weight), (0, 0));
        assert!(mesh.verify_locally(&task, &attestation, 100).is_ok());
        let root = mesh.journal_root();
        assert_eq!(
            mesh.submit(&task, attestation, 100),
            Err(ChorusError::AggregationDisabled)
        );
        assert_eq!(mesh.journal_root(), root);
    }
}
