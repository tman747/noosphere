//! Canonical `M-TENSOR` commit-before-beacon receipts.
//!
//! This module implements the frozen Work Loom ordering and hash law.  It is
//! deliberately an exact integer matrix class: no host serialization,
//! floating-point policy, or implicit overflow behavior enters an artifact ID.

#![allow(clippy::arithmetic_side_effects)]

use crate::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const ARTIFACT_DOMAIN: &[u8] = b"NOOS/TENSOR/ARTIFACT/V1";
pub const PRE_BEACON_DOMAIN: &[u8] = b"NOOS/TENSOR/PRE-BEACON/V1";
pub const WORKER_COMMIT_DOMAIN: &[u8] = b"NOOS/LOOM/WORKER-COMMIT/V1";
pub const CHALLENGE_DOMAIN: &[u8] = b"NOOS/LOOM/V1";
pub const WORK_DOMAIN: &[u8] = b"NOOS/TENSOR/WORK/V1";
pub const EVIDENCE_DOMAIN: &[u8] = b"NOOS/TENSOR/EVIDENCE/V1";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TensorError {
    #[error("canonical tensor descriptor or payload is invalid")]
    InvalidTensor,
    #[error("checked size arithmetic overflow")]
    Overflow,
    #[error("receipt nullifier is already registered")]
    Replay,
    #[error("worker output commitment was not registered before the beacon")]
    Ordering,
    #[error("beacon challenge does not follow the registered commitment")]
    Challenge,
    #[error("receipt field, profile, output, delivery, or trace binding mismatch")]
    Binding,
    #[error("required execution evidence is unavailable")]
    EvidenceUnavailable,
    #[error("committed delivery is unavailable")]
    DeliveryUnavailable,
    #[error("receipt lifecycle transition is invalid")]
    Lifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TensorRole {
    OperandA = 1,
    OperandB = 2,
    Output = 3,
    Trace = 4,
}

/// Frozen exact-integer descriptor.  The otherwise easy-to-forget encoding
/// choices are explicit bytes even when they have only one admitted value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorDescriptor {
    pub version: u16,
    pub role: TensorRole,
    pub rows: u32,
    pub cols: u32,
    pub chunk_elements: u32,
    /// Must be 1 (`I64`).
    pub dtype: u8,
    /// Must be 1 (`LITTLE_ENDIAN`).
    pub byte_order: u8,
    /// Must be 0 (`NOT_APPLICABLE`) for exact integers.
    pub signed_zero_policy: u8,
    /// Must be 0 (`REJECT_NOT_APPLICABLE`) for exact integers.
    pub nan_policy: u8,
    /// Must be 0 (`NONE`).
    pub quantization: u8,
    /// Must be 0 (`NONE`).
    pub compression: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTensor {
    pub descriptor: TensorDescriptor,
    /// Row-major exact signed integers.
    pub values: Vec<i64>,
}

impl CanonicalTensor {
    pub fn validate(&self) -> Result<(), TensorError> {
        let expected = usize::try_from(self.descriptor.rows)
            .ok()
            .and_then(|rows| {
                usize::try_from(self.descriptor.cols)
                    .ok()
                    .and_then(|cols| rows.checked_mul(cols))
            })
            .ok_or(TensorError::Overflow)?;
        if self.descriptor.version != 1
            || self.descriptor.rows == 0
            || self.descriptor.cols == 0
            || self.descriptor.chunk_elements == 0
            || self.descriptor.dtype != 1
            || self.descriptor.byte_order != 1
            || self.descriptor.signed_zero_policy != 0
            || self.descriptor.nan_policy != 0
            || self.descriptor.quantization != 0
            || self.descriptor.compression != 0
            || self.values.len() != expected
        {
            return Err(TensorError::InvalidTensor);
        }
        Ok(())
    }

    /// Injective descriptor followed by exact row-major payload bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TensorError> {
        self.validate()?;
        let payload_bytes = self
            .values
            .len()
            .checked_mul(8)
            .ok_or(TensorError::Overflow)?;
        let mut out = Vec::with_capacity(40_usize.saturating_add(payload_bytes));
        out.extend_from_slice(&self.descriptor.version.to_le_bytes());
        out.push(self.descriptor.role as u8);
        out.push(self.descriptor.dtype);
        out.extend_from_slice(&self.descriptor.rows.to_le_bytes());
        out.extend_from_slice(&self.descriptor.cols.to_le_bytes());
        out.extend_from_slice(&self.descriptor.chunk_elements.to_le_bytes());
        out.push(self.descriptor.byte_order);
        out.push(self.descriptor.signed_zero_policy);
        out.push(self.descriptor.nan_policy);
        out.push(self.descriptor.quantization);
        out.push(self.descriptor.compression);
        out.extend_from_slice(&(self.values.len() as u64).to_le_bytes());
        out.extend_from_slice(&(payload_bytes as u64).to_le_bytes());
        for value in &self.values {
            out.extend_from_slice(&value.to_le_bytes());
        }
        Ok(out)
    }

    pub fn artifact_id(&self) -> Result<Hash32, TensorError> {
        let mut hash = blake3::Hasher::new();
        hash.update(ARTIFACT_DOMAIN);
        hash.update(&self.canonical_bytes()?);
        Ok(*hash.finalize().as_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReceiptNullifier {
    pub job_id: Hash32,
    pub worker: Hash32,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorPrecommit {
    pub chain_id: Hash32,
    pub epoch: u64,
    pub job_id: Hash32,
    pub worker: Hash32,
    pub worker_profile_id: u32,
    pub proof_profile_id: u32,
    pub numeric_profile: Hash32,
    pub relation_root: Hash32,
    pub artifact_a: Hash32,
    pub artifact_b: Hash32,
    pub output_artifact: Hash32,
    pub output_commitment: Hash32,
    pub delivery_commitment: Hash32,
    pub trace_root: Hash32,
    pub evidence_root: Hash32,
    pub nonce: u64,
    pub committed_height: u64,
    pub pre_beacon_commit: Hash32,
    pub worker_commit: Hash32,
}

impl TensorPrecommit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: Hash32,
        epoch: u64,
        job_id: Hash32,
        worker: Hash32,
        worker_profile_id: u32,
        proof_profile_id: u32,
        numeric_profile: Hash32,
        relation_root: Hash32,
        artifact_a: Hash32,
        artifact_b: Hash32,
        output_artifact: Hash32,
        output_commitment: Hash32,
        delivery_commitment: Hash32,
        trace_root: Hash32,
        evidence_root: Hash32,
        nonce: u64,
        committed_height: u64,
    ) -> Result<Self, TensorError> {
        if worker_profile_id == 0
            || proof_profile_id == 0
            || [
                chain_id,
                job_id,
                worker,
                numeric_profile,
                relation_root,
                artifact_a,
                artifact_b,
                output_artifact,
                output_commitment,
                delivery_commitment,
                trace_root,
                evidence_root,
            ]
            .contains(&[0; 32])
        {
            return Err(TensorError::Binding);
        }
        let mut out = Self {
            chain_id,
            epoch,
            job_id,
            worker,
            worker_profile_id,
            proof_profile_id,
            numeric_profile,
            relation_root,
            artifact_a,
            artifact_b,
            output_artifact,
            output_commitment,
            delivery_commitment,
            trace_root,
            evidence_root,
            nonce,
            committed_height,
            pre_beacon_commit: [0; 32],
            worker_commit: [0; 32],
        };
        out.pre_beacon_commit = out.derive_pre_beacon_commit();
        out.worker_commit = out.derive_worker_commit();
        Ok(out)
    }

    #[must_use]
    pub fn nullifier(&self) -> ReceiptNullifier {
        ReceiptNullifier {
            job_id: self.job_id,
            worker: self.worker,
            nonce: self.nonce,
        }
    }

    fn validate(&self) -> Result<(), TensorError> {
        if self.worker_profile_id == 0
            || self.proof_profile_id == 0
            || [
                self.chain_id,
                self.job_id,
                self.worker,
                self.numeric_profile,
                self.relation_root,
                self.artifact_a,
                self.artifact_b,
                self.output_artifact,
                self.output_commitment,
                self.delivery_commitment,
                self.trace_root,
                self.evidence_root,
            ]
            .contains(&[0; 32])
            || self.pre_beacon_commit != self.derive_pre_beacon_commit()
            || self.worker_commit != self.derive_worker_commit()
        {
            return Err(TensorError::Binding);
        }
        Ok(())
    }

    fn derive_pre_beacon_commit(&self) -> Hash32 {
        let mut hash = blake3::Hasher::new();
        hash.update(PRE_BEACON_DOMAIN);
        hash.update(&self.artifact_a);
        hash.update(&self.artifact_b);
        hash.update(&self.output_artifact);
        hash.update(&self.output_commitment);
        hash.update(&self.delivery_commitment);
        hash.update(&self.worker_profile_id.to_le_bytes());
        hash.update(&self.proof_profile_id.to_le_bytes());
        hash.update(&self.numeric_profile);
        hash.update(&self.relation_root);
        hash.update(&self.nonce.to_le_bytes());
        *hash.finalize().as_bytes()
    }

    fn derive_worker_commit(&self) -> Hash32 {
        let mut hash = blake3::Hasher::new();
        hash.update(WORKER_COMMIT_DOMAIN);
        hash.update(&self.epoch.to_le_bytes());
        hash.update(&self.job_id);
        hash.update(&self.worker);
        hash.update(&self.pre_beacon_commit);
        hash.update(&self.trace_root);
        hash.update(&self.evidence_root);
        hash.update(&self.committed_height.to_le_bytes());
        *hash.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorChallenge {
    pub nullifier: ReceiptNullifier,
    pub beacon: Hash32,
    pub beacon_height: u64,
    pub challenge: Hash32,
    pub work_commit: Hash32,
}

impl TensorChallenge {
    fn derive(
        precommit: &TensorPrecommit,
        beacon: Hash32,
        beacon_height: u64,
    ) -> Result<Self, TensorError> {
        if beacon_height <= precommit.committed_height || beacon == [0; 32] {
            return Err(TensorError::Ordering);
        }
        let challenge = derive_challenge(precommit, beacon, beacon_height);
        let work_commit = derive_work_commit(precommit, challenge);
        Ok(Self {
            nullifier: precommit.nullifier(),
            beacon,
            beacon_height,
            challenge,
            work_commit,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorReceipt {
    pub precommit: TensorPrecommit,
    pub challenge: TensorChallenge,
    pub opened_output_artifact: Hash32,
    pub opened_delivery_commitment: Hash32,
    pub opened_trace_root: Hash32,
    pub opened_evidence_root: Hash32,
    pub evidence_available: bool,
}

impl TensorReceipt {
    pub fn verify_bindings(&self) -> Result<(), TensorError> {
        self.precommit.validate()?;
        if self.opened_output_artifact != self.precommit.output_artifact
            || self.opened_delivery_commitment != self.precommit.delivery_commitment
            || self.opened_trace_root != self.precommit.trace_root
            || self.opened_evidence_root != self.precommit.evidence_root
            || self.challenge.nullifier != self.precommit.nullifier()
        {
            return Err(TensorError::Binding);
        }
        let expected = TensorChallenge::derive(
            &self.precommit,
            self.challenge.beacon,
            self.challenge.beacon_height,
        )?;
        if self.challenge != expected {
            return Err(TensorError::Challenge);
        }
        if !self.evidence_available {
            return Err(TensorError::EvidenceUnavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TensorReceiptState {
    Committed,
    Challenged,
    Submitted,
    Settled,
    OrdinaryComputeOnly,
}

#[derive(Clone, Debug)]
struct ReceiptEntry {
    precommit: TensorPrecommit,
    challenge: Option<TensorChallenge>,
    state: TensorReceiptState,
}

#[derive(Default)]
pub struct TensorReceiptBook {
    entries: BTreeMap<ReceiptNullifier, ReceiptEntry>,
}

impl TensorReceiptBook {
    pub fn commit(&mut self, precommit: TensorPrecommit) -> Result<ReceiptNullifier, TensorError> {
        precommit.validate()?;
        let nullifier = precommit.nullifier();
        if self.entries.contains_key(&nullifier) {
            return Err(TensorError::Replay);
        }
        self.entries.insert(
            nullifier,
            ReceiptEntry {
                precommit,
                challenge: None,
                state: TensorReceiptState::Committed,
            },
        );
        Ok(nullifier)
    }

    pub fn challenge(
        &mut self,
        nullifier: ReceiptNullifier,
        beacon: Hash32,
        beacon_height: u64,
    ) -> Result<TensorChallenge, TensorError> {
        let entry = self
            .entries
            .get_mut(&nullifier)
            .ok_or(TensorError::Ordering)?;
        if entry.state != TensorReceiptState::Committed {
            return Err(TensorError::Lifecycle);
        }
        let challenge = TensorChallenge::derive(&entry.precommit, beacon, beacon_height)?;
        entry.challenge = Some(challenge.clone());
        entry.state = TensorReceiptState::Challenged;
        Ok(challenge)
    }

    pub fn submit(&mut self, receipt: &TensorReceipt) -> Result<(), TensorError> {
        receipt.verify_bindings()?;
        let entry = self
            .entries
            .get_mut(&receipt.precommit.nullifier())
            .ok_or(TensorError::Ordering)?;
        if entry.state != TensorReceiptState::Challenged
            || entry.precommit != receipt.precommit
            || entry.challenge.as_ref() != Some(&receipt.challenge)
        {
            return Err(TensorError::Binding);
        }
        entry.state = TensorReceiptState::Submitted;
        Ok(())
    }

    pub fn settle(
        &mut self,
        nullifier: ReceiptNullifier,
        delivery_available: bool,
    ) -> Result<TensorReceiptState, TensorError> {
        let entry = self
            .entries
            .get_mut(&nullifier)
            .ok_or(TensorError::Ordering)?;
        if entry.state != TensorReceiptState::Submitted {
            return Err(TensorError::Lifecycle);
        }
        entry.state = if delivery_available {
            TensorReceiptState::Settled
        } else {
            TensorReceiptState::OrdinaryComputeOnly
        };
        if !delivery_available {
            return Err(TensorError::DeliveryUnavailable);
        }
        Ok(entry.state)
    }

    #[must_use]
    pub fn state(&self, nullifier: ReceiptNullifier) -> Option<TensorReceiptState> {
        self.entries.get(&nullifier).map(|entry| entry.state)
    }
}

fn derive_challenge(precommit: &TensorPrecommit, beacon: Hash32, beacon_height: u64) -> Hash32 {
    let mut hash = blake3::Hasher::new();
    hash.update(CHALLENGE_DOMAIN);
    hash.update(&precommit.chain_id);
    hash.update(&precommit.epoch.to_le_bytes());
    hash.update(&precommit.job_id);
    hash.update(&precommit.worker_commit);
    hash.update(&beacon_height.to_le_bytes());
    hash.update(&beacon);
    *hash.finalize().as_bytes()
}

fn derive_work_commit(precommit: &TensorPrecommit, challenge: Hash32) -> Hash32 {
    let mut payload = Vec::with_capacity(WORK_DOMAIN.len() + 32 * 3 + 4);
    payload.extend_from_slice(WORK_DOMAIN);
    payload.extend_from_slice(&precommit.output_artifact);
    payload.extend_from_slice(&precommit.worker_profile_id.to_le_bytes());
    payload.extend_from_slice(&precommit.trace_root);
    payload.extend_from_slice(&precommit.pre_beacon_commit);
    *blake3::keyed_hash(&challenge, &payload).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tensor(role: TensorRole, rows: u32, cols: u32, values: Vec<i64>) -> CanonicalTensor {
        CanonicalTensor {
            descriptor: TensorDescriptor {
                version: 1,
                role,
                rows,
                cols,
                chunk_elements: 3,
                dtype: 1,
                byte_order: 1,
                signed_zero_policy: 0,
                nan_policy: 0,
                quantization: 0,
                compression: 0,
            },
            values,
        }
    }

    fn precommit() -> TensorPrecommit {
        TensorPrecommit::new(
            [1; 32], 4, [2; 32], [3; 32], 7, 8, [13; 32], [14; 32], [4; 32], [5; 32], [6; 32],
            [7; 32], [8; 32], [9; 32], [10; 32], 11, 20,
        )
        .unwrap()
    }

    fn receipt(precommit: TensorPrecommit, challenge: TensorChallenge) -> TensorReceipt {
        TensorReceipt {
            opened_output_artifact: precommit.output_artifact,
            opened_delivery_commitment: precommit.delivery_commitment,
            opened_trace_root: precommit.trace_root,
            opened_evidence_root: precommit.evidence_root,
            precommit,
            challenge,
            evidence_available: true,
        }
    }

    #[test]
    fn canonical_vectors_are_stable_and_shape_role_chunk_bound() {
        let base = tensor(TensorRole::OperandA, 2, 3, vec![1, -2, 3, 4, 5, i64::MIN]);
        assert_eq!(
            hex(&base.artifact_id().unwrap()),
            "75bd93c056e9072920d639f2560b7e8207937d98cc03204215da1ad8de475b24"
        );
        for changed in [
            tensor(TensorRole::OperandB, 2, 3, base.values.clone()),
            tensor(TensorRole::OperandA, 3, 2, base.values.clone()),
            {
                let mut value = base.clone();
                value.descriptor.chunk_elements = 4;
                value
            },
        ] {
            assert_ne!(base.artifact_id().unwrap(), changed.artifact_id().unwrap());
        }
    }

    #[test]
    fn lifecycle_binds_commit_before_beacon_output_delivery_trace_and_evidence() {
        let pre = precommit();
        let mut book = TensorReceiptBook::default();
        let nullifier = book.commit(pre.clone()).unwrap();
        let challenge = book.challenge(nullifier, [12; 32], 21).unwrap();
        let receipt = receipt(pre, challenge);
        book.submit(&receipt).unwrap();
        assert_eq!(
            book.settle(nullifier, true).unwrap(),
            TensorReceiptState::Settled
        );
    }

    #[test]
    fn post_beacon_substitution_profile_splice_and_challenge_replay_reject() {
        let pre = precommit();
        let mut book = TensorReceiptBook::default();
        let nullifier = book.commit(pre.clone()).unwrap();
        let challenge = book.challenge(nullifier, [12; 32], 21).unwrap();

        let mut output_swap = receipt(pre.clone(), challenge.clone());
        output_swap.opened_output_artifact[0] ^= 1;
        assert_eq!(output_swap.verify_bindings(), Err(TensorError::Binding));

        let mut profile_splice = receipt(pre.clone(), challenge.clone());
        profile_splice.precommit.numeric_profile[0] ^= 1;
        assert_eq!(profile_splice.verify_bindings(), Err(TensorError::Binding));

        let mut trace_splice = receipt(pre.clone(), challenge.clone());
        trace_splice.opened_trace_root[0] ^= 1;
        assert_eq!(trace_splice.verify_bindings(), Err(TensorError::Binding));

        let mut stale = receipt(pre, challenge);
        stale.challenge.beacon = [13; 32];
        assert_eq!(stale.verify_bindings(), Err(TensorError::Challenge));
    }

    #[test]
    fn boundary_overflow_malformed_encoding_withholding_and_replay_fail_closed() {
        let mut malformed = tensor(TensorRole::OperandA, u32::MAX, u32::MAX, vec![]);
        assert!(malformed.validate().is_err());
        malformed = tensor(TensorRole::OperandA, 1, 1, vec![i64::MAX]);
        malformed.descriptor.byte_order = 2;
        assert_eq!(malformed.validate(), Err(TensorError::InvalidTensor));

        let pre = precommit();
        let mut book = TensorReceiptBook::default();
        let nullifier = book.commit(pre.clone()).unwrap();
        assert_eq!(book.commit(pre.clone()), Err(TensorError::Replay));
        assert_eq!(
            book.challenge(nullifier, [12; 32], pre.committed_height),
            Err(TensorError::Ordering)
        );
        let challenge = book.challenge(nullifier, [12; 32], 21).unwrap();
        let mut withheld = receipt(pre, challenge);
        withheld.evidence_available = false;
        assert_eq!(
            book.submit(&withheld),
            Err(TensorError::EvidenceUnavailable)
        );
    }

    #[test]
    fn unavailable_delivery_gets_no_receipt_credit_state() {
        let pre = precommit();
        let mut book = TensorReceiptBook::default();
        let nullifier = book.commit(pre.clone()).unwrap();
        let challenge = book.challenge(nullifier, [12; 32], 21).unwrap();
        book.submit(&receipt(pre, challenge)).unwrap();
        assert_eq!(
            book.settle(nullifier, false),
            Err(TensorError::DeliveryUnavailable)
        );
        assert_eq!(
            book.state(nullifier),
            Some(TensorReceiptState::OrdinaryComputeOnly)
        );
    }

    fn hex(bytes: &Hash32) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
