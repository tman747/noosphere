//! Public WWM committee selection, streaming quorum, tail reassignment, and
//! application settlement. Nothing in this module participates in proposal or
//! finality weight; every production control remains disabled.

use crate::{registered::ImplementationFamily, FinalityClass, Hash32, CHUNK_TOKENS};
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub const PUBLIC_COMMITTEE_SIZE: usize = 3;
pub const PUBLIC_COMMITTEE_QUORUM: usize = 2;
pub const MAX_EXECUTOR_CAPSULES: usize = 128;
pub const MAX_STREAM_CHUNKS: u32 = 4_096;
pub const WWM_PUBLIC_COMMITTEE_ENABLED: bool = false;
pub const WWM_PUBLIC_COMMITTEE_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicInferenceError {
    InvalidExecutor,
    InvalidSignature,
    InvalidSelection,
    InsufficientDiversity,
    IneligibleExecutor,
    InvalidClaim,
    NotCommitteeMember,
    DuplicateClaim,
    Equivocation,
    NoQuorum,
    InvalidTransition,
    DeadlineExpired,
    AvailabilityRequired,
    InvalidSettlement,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicExecutorProfile {
    pub executor_key: Hash32,
    pub control_cluster: Hash32,
    pub region: u16,
    pub asn: u32,
    pub implementation_family: ImplementationFamily,
    pub capsule_ids: Vec<Hash32>,
    pub numeric_profile_ids: Vec<Hash32>,
    pub resident_capacity_tokens: u32,
    pub bond_micro_noos: u64,
    pub valid_from_epoch: u64,
    pub expires_epoch: u64,
    pub enabled: bool,
    pub profile_id: Hash32,
    pub signature: [u8; 64],
}

impl PublicExecutorProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: &Keypair,
        control_cluster: Hash32,
        region: u16,
        asn: u32,
        implementation_family: ImplementationFamily,
        capsule_ids: Vec<Hash32>,
        numeric_profile_ids: Vec<Hash32>,
        resident_capacity_tokens: u32,
        bond_micro_noos: u64,
        valid_from_epoch: u64,
        expires_epoch: u64,
    ) -> Result<Self, PublicInferenceError> {
        let mut value = Self {
            executor_key: signer.public_key().into_bytes(),
            control_cluster,
            region,
            asn,
            implementation_family,
            capsule_ids,
            numeric_profile_ids,
            resident_capacity_tokens,
            bond_micro_noos,
            valid_from_epoch,
            expires_epoch,
            enabled: true,
            profile_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.profile_id = digest(DomainId::WwmExecutorProfile, &[&body])?;
        value.signature = sign(
            signer,
            DomainId::WwmExecutorProfile,
            &value.profile_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PublicInferenceError> {
        let body = self.body()?;
        let expected = digest(DomainId::WwmExecutorProfile, &[&body])?;
        if self.profile_id == [0; 32] || expected != self.profile_id {
            return Err(PublicInferenceError::InvalidExecutor);
        }
        verify(
            self.executor_key,
            DomainId::WwmExecutorProfile,
            self.profile_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, PublicInferenceError> {
        if self.executor_key == [0; 32]
            || self.control_cluster == [0; 32]
            || self.region == 0
            || self.asn == 0
            || self.capsule_ids.is_empty()
            || self.capsule_ids.len() > MAX_EXECUTOR_CAPSULES
            || !strictly_sorted(&self.capsule_ids)
            || self.capsule_ids.contains(&[0; 32])
            || self.numeric_profile_ids.is_empty()
            || self.numeric_profile_ids.len() > MAX_EXECUTOR_CAPSULES
            || !strictly_sorted(&self.numeric_profile_ids)
            || self.numeric_profile_ids.contains(&[0; 32])
            || self.resident_capacity_tokens == 0
            || self.bond_micro_noos == 0
            || self.valid_from_epoch >= self.expires_epoch
        {
            return Err(PublicInferenceError::InvalidExecutor);
        }
        let mut body = Vec::with_capacity(256);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.executor_key);
        body.extend(self.control_cluster);
        body.extend(self.region.to_le_bytes());
        body.extend(self.asn.to_le_bytes());
        body.push(self.implementation_family as u8);
        push_hashes(&mut body, &self.capsule_ids)?;
        push_hashes(&mut body, &self.numeric_profile_ids)?;
        body.extend(self.resident_capacity_tokens.to_le_bytes());
        body.extend(self.bond_micro_noos.to_le_bytes());
        body.extend(self.valid_from_epoch.to_le_bytes());
        body.extend(self.expires_epoch.to_le_bytes());
        body.push(u8::from(self.enabled));
        Ok(body)
    }

    fn eligible(
        &self,
        capsule_id: Hash32,
        profile_id: Hash32,
        epoch: u64,
        requested_tokens: u32,
        minimum_bond: u64,
    ) -> bool {
        self.enabled
            && self.valid_from_epoch <= epoch
            && epoch < self.expires_epoch
            && self.resident_capacity_tokens >= requested_tokens
            && self.bond_micro_noos >= minimum_bond
            && self.capsule_ids.binary_search(&capsule_id).is_ok()
            && self.numeric_profile_ids.binary_search(&profile_id).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedCommittee {
    pub committee_id: Hash32,
    pub job_id: Hash32,
    pub epoch: u64,
    pub members: [Hash32; PUBLIC_COMMITTEE_SIZE],
    pub executor_keys: [Hash32; PUBLIC_COMMITTEE_SIZE],
    pub control_clusters: [Hash32; PUBLIC_COMMITTEE_SIZE],
}

#[allow(clippy::too_many_arguments)]
pub fn select_committee(
    job_id: Hash32,
    capsule_id: Hash32,
    numeric_profile_id: Hash32,
    finalized_randomness: Hash32,
    epoch: u64,
    requested_tokens: u32,
    minimum_bond: u64,
    profiles: &[PublicExecutorProfile],
) -> Result<SelectedCommittee, PublicInferenceError> {
    if job_id == [0; 32]
        || capsule_id == [0; 32]
        || numeric_profile_id == [0; 32]
        || finalized_randomness == [0; 32]
        || requested_tokens == 0
    {
        return Err(PublicInferenceError::InvalidSelection);
    }
    let mut ranked = Vec::new();
    let mut ids = BTreeSet::new();
    for profile in profiles {
        profile.validate()?;
        if !ids.insert(profile.profile_id) {
            return Err(PublicInferenceError::InvalidSelection);
        }
        if profile.eligible(
            capsule_id,
            numeric_profile_id,
            epoch,
            requested_tokens,
            minimum_bond,
        ) {
            let score = digest(
                DomainId::WwmPublicCommittee,
                &[
                    &finalized_randomness,
                    &job_id,
                    &epoch.to_le_bytes(),
                    &profile.profile_id,
                ],
            )?;
            ranked.push((score, profile));
        }
    }
    ranked.sort_by_key(|(score, profile)| (*score, profile.profile_id));
    let mut selected = Vec::with_capacity(PUBLIC_COMMITTEE_SIZE);
    let mut clusters = BTreeSet::new();
    for (_, profile) in ranked {
        if clusters.insert(profile.control_cluster) {
            selected.push(profile);
            if selected.len() == PUBLIC_COMMITTEE_SIZE {
                break;
            }
        }
    }
    if selected.len() != PUBLIC_COMMITTEE_SIZE {
        return Err(PublicInferenceError::InsufficientDiversity);
    }
    let families = selected
        .iter()
        .map(|profile| profile.implementation_family)
        .collect::<BTreeSet<_>>();
    if families.len() < 2 {
        return Err(PublicInferenceError::InsufficientDiversity);
    }
    let members = std::array::from_fn(|index| selected[index].profile_id);
    let executor_keys = std::array::from_fn(|index| selected[index].executor_key);
    let control_clusters = std::array::from_fn(|index| selected[index].control_cluster);
    let committee_id = digest(
        DomainId::WwmPublicCommittee,
        &[
            &job_id,
            &epoch.to_le_bytes(),
            &members.concat(),
            &executor_keys.concat(),
            &control_clusters.concat(),
        ],
    )?;
    Ok(SelectedCommittee {
        committee_id,
        job_id,
        epoch,
        members,
        executor_keys,
        control_clusters,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunkClaim {
    pub job_id: Hash32,
    pub committee_id: Hash32,
    pub executor_key: Hash32,
    pub chunk_index: u32,
    pub first_token: u32,
    pub token_count: u16,
    pub previous_state_root: Hash32,
    pub final_state_root: Hash32,
    pub trace_root: Hash32,
    pub token_history_root: Hash32,
    pub evidence_root: Hash32,
    pub available_until_height: u64,
    pub claim_id: Hash32,
    pub signature: [u8; 64],
}

impl StreamChunkClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signer: &Keypair,
        job_id: Hash32,
        committee_id: Hash32,
        chunk_index: u32,
        first_token: u32,
        token_count: u16,
        previous_state_root: Hash32,
        final_state_root: Hash32,
        trace_root: Hash32,
        token_history_root: Hash32,
        evidence_root: Hash32,
        available_until_height: u64,
    ) -> Result<Self, PublicInferenceError> {
        let mut value = Self {
            job_id,
            committee_id,
            executor_key: signer.public_key().into_bytes(),
            chunk_index,
            first_token,
            token_count,
            previous_state_root,
            final_state_root,
            trace_root,
            token_history_root,
            evidence_root,
            available_until_height,
            claim_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.claim_id = digest(DomainId::WwmStreamClaim, &[&body])?;
        value.signature = sign(signer, DomainId::WwmStreamClaim, &value.claim_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PublicInferenceError> {
        let body = self.body()?;
        if self.claim_id == [0; 32] || digest(DomainId::WwmStreamClaim, &[&body])? != self.claim_id
        {
            return Err(PublicInferenceError::InvalidClaim);
        }
        verify(
            self.executor_key,
            DomainId::WwmStreamClaim,
            self.claim_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, PublicInferenceError> {
        if self.job_id == [0; 32]
            || self.committee_id == [0; 32]
            || self.executor_key == [0; 32]
            || self.chunk_index >= MAX_STREAM_CHUNKS
            || self.token_count == 0
            || usize::from(self.token_count) > CHUNK_TOKENS
            || self.previous_state_root == [0; 32]
            || self.final_state_root == [0; 32]
            || self.trace_root == [0; 32]
            || self.token_history_root == [0; 32]
            || self.evidence_root == [0; 32]
            || self.available_until_height == 0
        {
            return Err(PublicInferenceError::InvalidClaim);
        }
        let expected_first = self
            .chunk_index
            .checked_mul(
                u32::try_from(CHUNK_TOKENS)
                    .map_err(|_| PublicInferenceError::ArithmeticOverflow)?,
            )
            .ok_or(PublicInferenceError::ArithmeticOverflow)?;
        if self.first_token != expected_first {
            return Err(PublicInferenceError::InvalidClaim);
        }
        let mut body = Vec::with_capacity(294);
        body.extend(1_u16.to_le_bytes());
        body.extend(self.job_id);
        body.extend(self.committee_id);
        body.extend(self.executor_key);
        body.extend(self.chunk_index.to_le_bytes());
        body.extend(self.first_token.to_le_bytes());
        body.extend(self.token_count.to_le_bytes());
        body.extend(self.previous_state_root);
        body.extend(self.final_state_root);
        body.extend(self.trace_root);
        body.extend(self.token_history_root);
        body.extend(self.evidence_root);
        body.extend(self.available_until_height.to_le_bytes());
        Ok(body)
    }

    fn result_tuple(&self) -> (u32, u16, Hash32, Hash32, Hash32, Hash32, Hash32) {
        (
            self.first_token,
            self.token_count,
            self.previous_state_root,
            self.final_state_root,
            self.trace_root,
            self.token_history_root,
            self.evidence_root,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumChunk {
    pub chunk_index: u32,
    pub claim_ids: [Hash32; PUBLIC_COMMITTEE_QUORUM],
    pub signer_keys: [Hash32; PUBLIC_COMMITTEE_QUORUM],
    pub final_state_root: Hash32,
    pub token_history_root: Hash32,
    pub evidence_root: Hash32,
    pub anchor_deadline_height: u64,
    pub anchored_height: Option<u64>,
    pub available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicJobState {
    Executing,
    Soft,
    Anchored,
    Assured,
    Disputed,
    Reassigned,
    Refunded,
    Settled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicJob {
    pub job_id: Hash32,
    pub total_tokens: u32,
    pub committee: SelectedCommittee,
    pub state: PublicJobState,
    pub finality: Option<FinalityClass>,
    pub invalid_tail_from_chunk: Option<u32>,
    claims: BTreeMap<(u32, Hash32), StreamChunkClaim>,
    chunks: BTreeMap<u32, QuorumChunk>,
}

impl PublicJob {
    pub fn new(
        job_id: Hash32,
        total_tokens: u32,
        committee: SelectedCommittee,
    ) -> Result<Self, PublicInferenceError> {
        if job_id == [0; 32]
            || total_tokens == 0
            || total_tokens.div_ceil(CHUNK_TOKENS as u32) > MAX_STREAM_CHUNKS
            || committee.job_id != job_id
        {
            return Err(PublicInferenceError::InvalidSelection);
        }
        Ok(Self {
            job_id,
            total_tokens,
            committee,
            state: PublicJobState::Executing,
            finality: None,
            invalid_tail_from_chunk: None,
            claims: BTreeMap::new(),
            chunks: BTreeMap::new(),
        })
    }

    pub fn record_claim(
        &mut self,
        claim: StreamChunkClaim,
        current_height: u64,
        anchor_window_blocks: u64,
    ) -> Result<Option<&QuorumChunk>, PublicInferenceError> {
        if !matches!(
            self.state,
            PublicJobState::Executing | PublicJobState::Soft | PublicJobState::Reassigned
        ) || anchor_window_blocks == 0
        {
            return Err(PublicInferenceError::InvalidTransition);
        }
        claim.validate()?;
        if claim.job_id != self.job_id || claim.committee_id != self.committee.committee_id {
            return Err(PublicInferenceError::InvalidClaim);
        }
        if !self.committee.executor_keys.contains(&claim.executor_key) {
            return Err(PublicInferenceError::NotCommitteeMember);
        }
        let required_chunks = self.total_tokens.div_ceil(CHUNK_TOKENS as u32);
        if claim.chunk_index >= required_chunks {
            return Err(PublicInferenceError::InvalidClaim);
        }
        let next_chunk_index = claim
            .chunk_index
            .checked_add(1)
            .ok_or(PublicInferenceError::ArithmeticOverflow)?;
        let expected_count = if next_chunk_index == required_chunks {
            let remainder = self
                .total_tokens
                .checked_rem(CHUNK_TOKENS as u32)
                .ok_or(PublicInferenceError::ArithmeticOverflow)?;
            if remainder == 0 {
                CHUNK_TOKENS as u16
            } else {
                remainder as u16
            }
        } else {
            CHUNK_TOKENS as u16
        };
        if claim.token_count != expected_count || claim.available_until_height <= current_height {
            return Err(PublicInferenceError::InvalidClaim);
        }
        let key = (claim.chunk_index, claim.executor_key);
        if let Some(prior) = self.claims.get(&key) {
            return if prior.claim_id == claim.claim_id {
                Err(PublicInferenceError::DuplicateClaim)
            } else {
                Err(PublicInferenceError::Equivocation)
            };
        }
        let chunk_index = claim.chunk_index;
        self.claims.insert(key, claim);
        if self.chunks.contains_key(&chunk_index) {
            return Ok(self.chunks.get(&chunk_index));
        }
        let matching = self
            .claims
            .values()
            .filter(|candidate| candidate.chunk_index == chunk_index)
            .collect::<Vec<_>>();
        for left in 0..matching.len() {
            let right_start = left
                .checked_add(1)
                .ok_or(PublicInferenceError::ArithmeticOverflow)?;
            for right in right_start..matching.len() {
                if matching[left].executor_key != matching[right].executor_key
                    && matching[left].result_tuple() == matching[right].result_tuple()
                {
                    let deadline = current_height
                        .checked_add(anchor_window_blocks)
                        .ok_or(PublicInferenceError::ArithmeticOverflow)?;
                    let chunk = QuorumChunk {
                        chunk_index,
                        claim_ids: [matching[left].claim_id, matching[right].claim_id],
                        signer_keys: [matching[left].executor_key, matching[right].executor_key],
                        final_state_root: matching[left].final_state_root,
                        token_history_root: matching[left].token_history_root,
                        evidence_root: matching[left].evidence_root,
                        anchor_deadline_height: deadline,
                        anchored_height: None,
                        available: false,
                    };
                    self.chunks.insert(chunk_index, chunk);
                    self.state = PublicJobState::Soft;
                    self.finality = Some(FinalityClass::Soft);
                    return Ok(self.chunks.get(&chunk_index));
                }
            }
        }
        Ok(None)
    }

    pub fn anchor_chunk(
        &mut self,
        chunk_index: u32,
        height: u64,
    ) -> Result<(), PublicInferenceError> {
        let chunk = self
            .chunks
            .get_mut(&chunk_index)
            .ok_or(PublicInferenceError::NoQuorum)?;
        if height > chunk.anchor_deadline_height || chunk.anchored_height.is_some() {
            return Err(PublicInferenceError::DeadlineExpired);
        }
        chunk.anchored_height = Some(height);
        self.state = PublicJobState::Anchored;
        self.finality = Some(FinalityClass::Anchored);
        Ok(())
    }

    pub fn mark_available(&mut self, chunk_index: u32) -> Result<(), PublicInferenceError> {
        let chunk = self
            .chunks
            .get_mut(&chunk_index)
            .ok_or(PublicInferenceError::NoQuorum)?;
        if chunk.anchored_height.is_none() {
            return Err(PublicInferenceError::InvalidTransition);
        }
        chunk.available = true;
        Ok(())
    }

    pub fn assure(&mut self) -> Result<(), PublicInferenceError> {
        let required = self.total_tokens.div_ceil(CHUNK_TOKENS as u32);
        if self.chunks.len()
            != usize::try_from(required).map_err(|_| PublicInferenceError::ArithmeticOverflow)?
            || (0..required).any(|index| {
                self.chunks
                    .get(&index)
                    .is_none_or(|chunk| chunk.anchored_height.is_none() || !chunk.available)
            })
        {
            return Err(PublicInferenceError::AvailabilityRequired);
        }
        self.state = PublicJobState::Assured;
        self.finality = Some(FinalityClass::Assured);
        Ok(())
    }

    pub fn reassign_tail(
        &mut self,
        from_chunk: u32,
        fresh_committee: SelectedCommittee,
    ) -> Result<(), PublicInferenceError> {
        if from_chunk >= self.total_tokens.div_ceil(CHUNK_TOKENS as u32)
            || fresh_committee.job_id != self.job_id
            || fresh_committee.epoch <= self.committee.epoch
            || fresh_committee.members == self.committee.members
        {
            return Err(PublicInferenceError::InvalidTransition);
        }
        self.claims.retain(|(chunk, _), _| *chunk < from_chunk);
        self.chunks.retain(|chunk, _| *chunk < from_chunk);
        self.committee = fresh_committee;
        self.invalid_tail_from_chunk = Some(from_chunk);
        self.state = PublicJobState::Reassigned;
        self.finality = None;
        Ok(())
    }

    #[must_use]
    pub fn chunk(&self, index: u32) -> Option<&QuorumChunk> {
        self.chunks.get(&index)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSettlement {
    pub maximum_fee_micro_noos: u64,
    pub metered_fee_micro_noos: u64,
    pub executor_payment_micro_noos: u64,
    pub challenger_payment_micro_noos: u64,
    pub refund_micro_noos: u64,
    pub base_issuance_micro_noos: u64,
}

pub fn settle_public_job(
    state: PublicJobState,
    maximum_fee_micro_noos: u64,
    metered_fee_micro_noos: u64,
    challenger_award_micro_noos: u64,
) -> Result<PublicSettlement, PublicInferenceError> {
    if maximum_fee_micro_noos == 0
        || metered_fee_micro_noos > maximum_fee_micro_noos
        || challenger_award_micro_noos > maximum_fee_micro_noos
    {
        return Err(PublicInferenceError::InvalidSettlement);
    }
    let (executor_payment, challenger_payment) = match state {
        PublicJobState::Assured | PublicJobState::Settled => (metered_fee_micro_noos, 0),
        PublicJobState::Disputed => (0, challenger_award_micro_noos),
        PublicJobState::Refunded | PublicJobState::Reassigned => (0, 0),
        _ => return Err(PublicInferenceError::InvalidTransition),
    };
    let spent = executor_payment
        .checked_add(challenger_payment)
        .ok_or(PublicInferenceError::ArithmeticOverflow)?;
    if spent > maximum_fee_micro_noos {
        return Err(PublicInferenceError::InvalidSettlement);
    }
    Ok(PublicSettlement {
        maximum_fee_micro_noos,
        metered_fee_micro_noos,
        executor_payment_micro_noos: executor_payment,
        challenger_payment_micro_noos: challenger_payment,
        refund_micro_noos: maximum_fee_micro_noos
            .checked_sub(spent)
            .ok_or(PublicInferenceError::ArithmeticOverflow)?,
        base_issuance_micro_noos: 0,
    })
}

fn push_hashes(out: &mut Vec<u8>, hashes: &[Hash32]) -> Result<(), PublicInferenceError> {
    let count =
        u16::try_from(hashes.len()).map_err(|_| PublicInferenceError::ArithmeticOverflow)?;
    out.extend(count.to_le_bytes());
    for hash in hashes {
        out.extend(hash);
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, PublicInferenceError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| PublicInferenceError::InvalidSelection)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: &Hash32,
    body: &[u8],
) -> Result<[u8; 64], PublicInferenceError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| PublicInferenceError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), PublicInferenceError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| PublicInferenceError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        clippy::unwrap_used
    )]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn profiles(epoch: u64) -> Vec<PublicExecutorProfile> {
        (0_u8..4)
            .map(|index| {
                let family = if index == 0 {
                    ImplementationFamily::CpuReference
                } else {
                    ImplementationFamily::CpuIndependent
                };
                PublicExecutorProfile::new(
                    &Keypair::from_seed([10 + index; 32]),
                    h(30 + index),
                    u16::from(index) + 1,
                    64_500 + u32::from(index),
                    family,
                    vec![h(1)],
                    vec![h(2)],
                    1_024,
                    1_000,
                    epoch,
                    epoch + 10,
                )
                .unwrap()
            })
            .collect()
    }

    fn committee(epoch: u64) -> SelectedCommittee {
        select_committee(h(3), h(1), h(2), h(4), epoch, 64, 100, &profiles(epoch)).unwrap()
    }

    fn claim(
        key: &Keypair,
        committee: &SelectedCommittee,
        chunk: u32,
        token_count: u16,
        result: u8,
    ) -> StreamChunkClaim {
        StreamChunkClaim::new(
            key,
            committee.job_id,
            committee.committee_id,
            chunk,
            chunk * CHUNK_TOKENS as u32,
            token_count,
            h(60 + chunk as u8),
            h(result),
            h(result + 1),
            h(result + 2),
            h(result + 3),
            100,
        )
        .unwrap()
    }

    #[test]
    fn selection_is_deterministic_and_control_cluster_diverse() {
        let first = committee(1);
        let second = committee(1);
        assert_eq!(first, second);
        assert_eq!(
            first
                .control_clusters
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        let mut common = profiles(1);
        for profile in &mut common {
            profile.control_cluster = h(99);
        }
        assert!(common.iter().all(|profile| profile.validate().is_err()));
    }

    #[test]
    fn two_matching_members_advance_soft_anchor_and_assurance() {
        let committee = committee(1);
        let keys = committee
            .executor_keys
            .iter()
            .map(|key| {
                (0_u8..4)
                    .map(|index| Keypair::from_seed([10 + index; 32]))
                    .find(|candidate| candidate.public_key().into_bytes() == *key)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut job = PublicJob::new(h(3), 32, committee.clone()).unwrap();
        assert!(job
            .record_claim(claim(&keys[0], &committee, 0, 32, 70), 10, 5)
            .unwrap()
            .is_none());
        assert!(job
            .record_claim(claim(&keys[1], &committee, 0, 32, 70), 10, 5)
            .unwrap()
            .is_some());
        assert_eq!(job.finality, Some(FinalityClass::Soft));
        job.anchor_chunk(0, 14).unwrap();
        job.mark_available(0).unwrap();
        job.assure().unwrap();
        assert_eq!(job.finality, Some(FinalityClass::Assured));
    }

    #[test]
    fn disagreement_never_manufactures_quorum_and_late_anchor_rejects() {
        let committee = committee(1);
        let keys = (0_u8..4)
            .map(|index| Keypair::from_seed([10 + index; 32]))
            .filter(|key| {
                committee
                    .executor_keys
                    .contains(&key.public_key().into_bytes())
            })
            .collect::<Vec<_>>();
        let mut job = PublicJob::new(h(3), 32, committee.clone()).unwrap();
        job.record_claim(claim(&keys[0], &committee, 0, 32, 70), 10, 5)
            .unwrap();
        assert!(job
            .record_claim(claim(&keys[1], &committee, 0, 32, 80), 10, 5)
            .unwrap()
            .is_none());
        job.record_claim(claim(&keys[2], &committee, 0, 32, 70), 10, 5)
            .unwrap();
        assert_eq!(
            job.anchor_chunk(0, 16),
            Err(PublicInferenceError::DeadlineExpired)
        );
    }

    #[test]
    fn settlement_refunds_unused_application_escrow_only() {
        let settled = settle_public_job(PublicJobState::Assured, 1_000, 600, 0).unwrap();
        assert_eq!(settled.executor_payment_micro_noos, 600);
        assert_eq!(settled.refund_micro_noos, 400);
        assert_eq!(settled.base_issuance_micro_noos, 0);
        assert_eq!(
            settle_public_job(PublicJobState::Executing, 1_000, 600, 0),
            Err(PublicInferenceError::InvalidTransition)
        );
    }

    #[test]
    fn public_inference_never_changes_consensus_weight() {
        assert!(!WWM_PUBLIC_COMMITTEE_ENABLED);
        assert_eq!(WWM_PUBLIC_COMMITTEE_CONSENSUS_WEIGHT, 0);
    }
}
