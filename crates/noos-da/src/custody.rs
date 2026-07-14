//! Application-only model/artifact custody, probes, repair, and availability certificates.
//!
//! These records never make artifact bytes consensus data and never grant proposal,
//! finality, issuance, or Proofpower weight.

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

pub const MAX_CUSTODY_SHARDS: usize = 65_535;
pub const MAX_CUSTODY_VERIFIERS: usize = 16;
pub const MAX_SHARD_BYTES: u32 = 16 * 1024 * 1024;
pub const WWM_MODEL_CUSTODY_ENABLED: bool = false;
pub const WWM_CUSTODY_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    DuplicateId,
    UnknownCustodian,
    UnknownPolicy,
    UnknownCommitment,
    InvalidProfile,
    InvalidPolicy,
    InvalidCommitment,
    InvalidProbe,
    InvalidCertificate,
    InvalidSignature,
    CapacityExceeded,
    ShardMismatch,
    InsufficientReplication,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianProfile {
    pub profile_id: Hash32,
    pub operator_key: Hash32,
    pub control_cluster: Hash32,
    pub failure_domain: Hash32,
    pub region_root: Hash32,
    pub asn: u32,
    pub max_bytes: u64,
    pub bond_micro_noos: u128,
    pub expires_epoch: u64,
    pub signature: [u8; 64],
}

impl CustodianProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keypair: &Keypair,
        control_cluster: Hash32,
        failure_domain: Hash32,
        region_root: Hash32,
        asn: u32,
        max_bytes: u64,
        bond_micro_noos: u128,
        expires_epoch: u64,
    ) -> Result<Self, CustodyError> {
        let mut value = Self {
            profile_id: [0; 32],
            operator_key: keypair.public_key().into_bytes(),
            control_cluster,
            failure_domain,
            region_root,
            asn,
            max_bytes,
            bond_micro_noos,
            expires_epoch,
            signature: [0; 64],
        };
        let body = value.body()?;
        value.profile_id = digest(DomainId::WwmExecutorProfile, &[&body])?;
        value.signature = sign(
            keypair,
            DomainId::WwmExecutorProfile,
            &value.profile_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.profile_id == [0; 32]
            || self.profile_id != digest(DomainId::WwmExecutorProfile, &[&body])?
        {
            return Err(CustodyError::InvalidProfile);
        }
        verify(
            &self.operator_key,
            DomainId::WwmExecutorProfile,
            &self.profile_id,
            &body,
            &self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if [
            self.operator_key,
            self.control_cluster,
            self.failure_domain,
            self.region_root,
        ]
        .contains(&[0; 32])
            || self.asn == 0
            || self.max_bytes == 0
            || self.bond_micro_noos == 0
            || self.expires_epoch == 0
        {
            return Err(CustodyError::InvalidProfile);
        }
        let mut body = Vec::with_capacity(156);
        hash(&mut body, &self.operator_key);
        hash(&mut body, &self.control_cluster);
        hash(&mut body, &self.failure_domain);
        hash(&mut body, &self.region_root);
        u32_le(&mut body, self.asn);
        u64_le(&mut body, self.max_bytes);
        u128_le(&mut body, self.bond_micro_noos);
        u64_le(&mut body, self.expires_epoch);
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyPolicy {
    pub policy_id: Hash32,
    pub artifact_root: Hash32,
    pub shard_roots: Vec<Hash32>,
    pub shard_bytes: Vec<u32>,
    pub replicas_per_shard: u16,
    pub minimum_failure_domains: u16,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub maximum_probe_age_epochs: u64,
    pub authorized_verifiers: Vec<Hash32>,
    pub owner_key: Hash32,
    pub signature: [u8; 64],
}

impl CustodyPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: &Keypair,
        artifact_root: Hash32,
        shard_roots: Vec<Hash32>,
        shard_bytes: Vec<u32>,
        replicas_per_shard: u16,
        minimum_failure_domains: u16,
        start_epoch: u64,
        end_epoch: u64,
        maximum_probe_age_epochs: u64,
        authorized_verifiers: Vec<Hash32>,
    ) -> Result<Self, CustodyError> {
        let mut value = Self {
            policy_id: [0; 32],
            artifact_root,
            shard_roots,
            shard_bytes,
            replicas_per_shard,
            minimum_failure_domains,
            start_epoch,
            end_epoch,
            maximum_probe_age_epochs,
            authorized_verifiers,
            owner_key: owner.public_key().into_bytes(),
            signature: [0; 64],
        };
        let body = value.body()?;
        value.policy_id = digest(DomainId::WwmCustodyPolicy, &[&body])?;
        value.signature = sign(owner, DomainId::WwmCustodyPolicy, &value.policy_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.policy_id == [0; 32]
            || self.policy_id != digest(DomainId::WwmCustodyPolicy, &[&body])?
        {
            return Err(CustodyError::InvalidPolicy);
        }
        verify(
            &self.owner_key,
            DomainId::WwmCustodyPolicy,
            &self.policy_id,
            &body,
            &self.signature,
        )
    }

    #[must_use]
    pub fn shard_root(&self, index: u16) -> Option<Hash32> {
        self.shard_roots.get(usize::from(index)).copied()
    }

    pub fn hash_shard(&self, index: u16, bytes: &[u8]) -> Result<Hash32, CustodyError> {
        if self.shard_root(index).is_none()
            || usize::try_from(self.shard_bytes[usize::from(index)])
                .map_err(|_| CustodyError::ArithmeticOverflow)?
                != bytes.len()
        {
            return Err(CustodyError::ShardMismatch);
        }
        digest(
            DomainId::WwmCustodyShard,
            &[&self.artifact_root, &index.to_le_bytes(), bytes],
        )
    }

    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.artifact_root == [0; 32]
            || self.shard_roots.is_empty()
            || self.shard_roots.len() > MAX_CUSTODY_SHARDS
            || self.shard_roots.len() != self.shard_bytes.len()
            || self.shard_roots.contains(&[0; 32])
            || self
                .shard_bytes
                .iter()
                .any(|size| *size == 0 || *size > MAX_SHARD_BYTES)
            || self.replicas_per_shard < 3
            || self.minimum_failure_domains < 3
            || self.minimum_failure_domains > self.replicas_per_shard
            || self.start_epoch >= self.end_epoch
            || self.maximum_probe_age_epochs == 0
            || self.authorized_verifiers.is_empty()
            || self.authorized_verifiers.len() > MAX_CUSTODY_VERIFIERS
            || !strictly_sorted(&self.authorized_verifiers)
            || self.authorized_verifiers.contains(&[0; 32])
            || self.owner_key == [0; 32]
        {
            return Err(CustodyError::InvalidPolicy);
        }
        let mut body = Vec::new();
        hash(&mut body, &self.artifact_root);
        count(&mut body, self.shard_roots.len())?;
        for (root, size) in self.shard_roots.iter().zip(&self.shard_bytes) {
            hash(&mut body, root);
            u32_le(&mut body, *size);
        }
        u16_le(&mut body, self.replicas_per_shard);
        u16_le(&mut body, self.minimum_failure_domains);
        u64_le(&mut body, self.start_epoch);
        u64_le(&mut body, self.end_epoch);
        u64_le(&mut body, self.maximum_probe_age_epochs);
        hashes(&mut body, &self.authorized_verifiers)?;
        hash(&mut body, &self.owner_key);
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyCommitment {
    pub commitment_id: Hash32,
    pub policy_id: Hash32,
    pub custodian_profile_id: Hash32,
    pub shard_indices: Vec<u16>,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub signature: [u8; 64],
}

impl CustodyCommitment {
    pub fn new(
        keypair: &Keypair,
        policy_id: Hash32,
        custodian_profile_id: Hash32,
        shard_indices: Vec<u16>,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<Self, CustodyError> {
        let mut value = Self {
            commitment_id: [0; 32],
            policy_id,
            custodian_profile_id,
            shard_indices,
            start_epoch,
            end_epoch,
            signature: [0; 64],
        };
        let body = value.body()?;
        value.commitment_id = digest(DomainId::WwmCustodyCommitment, &[&body])?;
        value.signature = sign(
            keypair,
            DomainId::WwmCustodyCommitment,
            &value.commitment_id,
            &body,
        )?;
        Ok(value)
    }

    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.policy_id == [0; 32]
            || self.custodian_profile_id == [0; 32]
            || self.shard_indices.is_empty()
            || self.shard_indices.len() > MAX_CUSTODY_SHARDS
            || !strictly_sorted(&self.shard_indices)
            || self.start_epoch >= self.end_epoch
        {
            return Err(CustodyError::InvalidCommitment);
        }
        let mut body = Vec::new();
        hash(&mut body, &self.policy_id);
        hash(&mut body, &self.custodian_profile_id);
        count(&mut body, self.shard_indices.len())?;
        for index in &self.shard_indices {
            u16_le(&mut body, *index);
        }
        u64_le(&mut body, self.start_epoch);
        u64_le(&mut body, self.end_epoch);
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyProbe {
    pub probe_id: Hash32,
    pub policy_id: Hash32,
    pub commitment_id: Hash32,
    pub shard_index: u16,
    pub epoch: u64,
    pub response_digest: Hash32,
    pub latency_ms: u32,
    pub verifier_key: Hash32,
    pub signature: [u8; 64],
}

impl CustodyProbe {
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.policy_id == [0; 32]
            || self.commitment_id == [0; 32]
            || self.response_digest == [0; 32]
            || self.verifier_key == [0; 32]
        {
            return Err(CustodyError::InvalidProbe);
        }
        let mut body = Vec::with_capacity(142);
        hash(&mut body, &self.policy_id);
        hash(&mut body, &self.commitment_id);
        u16_le(&mut body, self.shard_index);
        u64_le(&mut body, self.epoch);
        hash(&mut body, &self.response_digest);
        u32_le(&mut body, self.latency_ms);
        hash(&mut body, &self.verifier_key);
        Ok(body)
    }

    fn validate_signature(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.probe_id == [0; 32] || self.probe_id != digest(DomainId::WwmCustodyProbe, &[&body])?
        {
            return Err(CustodyError::InvalidProbe);
        }
        verify(
            &self.verifier_key,
            DomainId::WwmCustodyProbe,
            &self.probe_id,
            &body,
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityCertificate {
    pub certificate_id: Hash32,
    pub policy_id: Hash32,
    pub issued_epoch: u64,
    pub valid_until_epoch: u64,
    pub commitment_ids: Vec<Hash32>,
    pub probe_ids: Vec<Hash32>,
    pub verifier_key: Hash32,
    pub signature: [u8; 64],
}

impl AvailabilityCertificate {
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.policy_id == [0; 32]
            || self.issued_epoch >= self.valid_until_epoch
            || self.commitment_ids.is_empty()
            || self.probe_ids.is_empty()
            || !strictly_sorted(&self.commitment_ids)
            || !strictly_sorted(&self.probe_ids)
            || self.verifier_key == [0; 32]
        {
            return Err(CustodyError::InvalidCertificate);
        }
        let mut body = Vec::new();
        hash(&mut body, &self.policy_id);
        u64_le(&mut body, self.issued_epoch);
        u64_le(&mut body, self.valid_until_epoch);
        hashes(&mut body, &self.commitment_ids)?;
        hashes(&mut body, &self.probe_ids)?;
        hash(&mut body, &self.verifier_key);
        Ok(body)
    }

    fn validate_signature(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.certificate_id == [0; 32]
            || self.certificate_id != digest(DomainId::WwmCustodyCertificate, &[&body])?
        {
            return Err(CustodyError::InvalidCertificate);
        }
        verify(
            &self.verifier_key,
            DomainId::WwmCustodyCertificate,
            &self.certificate_id,
            &body,
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairNeed {
    pub shard_index: u16,
    pub missing_replicas: u16,
    pub missing_failure_domains: u16,
}

#[derive(Debug, Default)]
pub struct CustodyLedger {
    custodians: BTreeMap<Hash32, CustodianProfile>,
    policies: BTreeMap<Hash32, CustodyPolicy>,
    commitments: BTreeMap<Hash32, CustodyCommitment>,
    probes: BTreeMap<Hash32, CustodyProbe>,
    certificates: BTreeMap<Hash32, AvailabilityCertificate>,
}

impl CustodyLedger {
    pub fn register_custodian(&mut self, value: CustodianProfile) -> Result<(), CustodyError> {
        value.validate()?;
        insert_once(&mut self.custodians, value.profile_id, value)
    }

    pub fn register_policy(&mut self, value: CustodyPolicy) -> Result<(), CustodyError> {
        value.validate()?;
        insert_once(&mut self.policies, value.policy_id, value)
    }

    pub fn register_commitment(&mut self, value: CustodyCommitment) -> Result<(), CustodyError> {
        let policy = self
            .policies
            .get(&value.policy_id)
            .ok_or(CustodyError::UnknownPolicy)?;
        let profile = self
            .custodians
            .get(&value.custodian_profile_id)
            .ok_or(CustodyError::UnknownCustodian)?;
        let body = value.body()?;
        if value.commitment_id == [0; 32]
            || value.commitment_id != digest(DomainId::WwmCustodyCommitment, &[&body])?
            || value.start_epoch < policy.start_epoch
            || value.end_epoch > policy.end_epoch
            || value.end_epoch > profile.expires_epoch
            || value
                .shard_indices
                .iter()
                .any(|index| usize::from(*index) >= policy.shard_roots.len())
        {
            return Err(CustodyError::InvalidCommitment);
        }
        let required_bytes = value.shard_indices.iter().try_fold(0_u64, |total, index| {
            total
                .checked_add(u64::from(policy.shard_bytes[usize::from(*index)]))
                .ok_or(CustodyError::ArithmeticOverflow)
        })?;
        if required_bytes > profile.max_bytes {
            return Err(CustodyError::CapacityExceeded);
        }
        verify(
            &profile.operator_key,
            DomainId::WwmCustodyCommitment,
            &value.commitment_id,
            &body,
            &value.signature,
        )?;
        insert_once(&mut self.commitments, value.commitment_id, value)
    }

    pub fn record_probe(
        &mut self,
        commitment_id: Hash32,
        shard_index: u16,
        epoch: u64,
        shard_bytes: &[u8],
        latency_ms: u32,
        verifier: &Keypair,
    ) -> Result<Hash32, CustodyError> {
        let commitment = self
            .commitments
            .get(&commitment_id)
            .ok_or(CustodyError::UnknownCommitment)?;
        let policy = self
            .policies
            .get(&commitment.policy_id)
            .ok_or(CustodyError::UnknownPolicy)?;
        let verifier_key = verifier.public_key().into_bytes();
        if policy
            .authorized_verifiers
            .binary_search(&verifier_key)
            .is_err()
            || epoch < commitment.start_epoch
            || epoch >= commitment.end_epoch
            || commitment
                .shard_indices
                .binary_search(&shard_index)
                .is_err()
        {
            return Err(CustodyError::InvalidProbe);
        }
        let response_digest = policy.hash_shard(shard_index, shard_bytes)?;
        if policy.shard_root(shard_index) != Some(response_digest) {
            return Err(CustodyError::ShardMismatch);
        }
        let mut probe = CustodyProbe {
            probe_id: [0; 32],
            policy_id: policy.policy_id,
            commitment_id,
            shard_index,
            epoch,
            response_digest,
            latency_ms,
            verifier_key,
            signature: [0; 64],
        };
        let body = probe.body()?;
        probe.probe_id = digest(DomainId::WwmCustodyProbe, &[&body])?;
        probe.signature = sign(verifier, DomainId::WwmCustodyProbe, &probe.probe_id, &body)?;
        probe.validate_signature()?;
        let id = probe.probe_id;
        insert_once(&mut self.probes, id, probe)?;
        Ok(id)
    }

    pub fn repair_needs(
        &self,
        policy_id: Hash32,
        epoch: u64,
    ) -> Result<Vec<RepairNeed>, CustodyError> {
        let policy = self
            .policies
            .get(&policy_id)
            .ok_or(CustodyError::UnknownPolicy)?;
        let mut needs = Vec::new();
        for index in 0..policy.shard_roots.len() {
            let index = u16::try_from(index).map_err(|_| CustodyError::ArithmeticOverflow)?;
            let (replicas, domains) = self.live_replication(policy, index, epoch);
            let missing_replicas = policy.replicas_per_shard.saturating_sub(replicas);
            let missing_failure_domains = policy.minimum_failure_domains.saturating_sub(domains);
            if missing_replicas > 0 || missing_failure_domains > 0 {
                needs.push(RepairNeed {
                    shard_index: index,
                    missing_replicas,
                    missing_failure_domains,
                });
            }
        }
        Ok(needs)
    }

    pub fn issue_certificate(
        &mut self,
        policy_id: Hash32,
        epoch: u64,
        verifier: &Keypair,
    ) -> Result<Hash32, CustodyError> {
        let policy = self
            .policies
            .get(&policy_id)
            .ok_or(CustodyError::UnknownPolicy)?;
        let verifier_key = verifier.public_key().into_bytes();
        if policy
            .authorized_verifiers
            .binary_search(&verifier_key)
            .is_err()
            || epoch < policy.start_epoch
            || epoch >= policy.end_epoch
            || !self.repair_needs(policy_id, epoch)?.is_empty()
        {
            return Err(CustodyError::InsufficientReplication);
        }
        let mut commitment_ids = BTreeSet::new();
        let mut probe_ids = BTreeSet::new();
        for index in 0..policy.shard_roots.len() {
            let index = u16::try_from(index).map_err(|_| CustodyError::ArithmeticOverflow)?;
            for (commitment, probe) in self.live_copies(policy, index, epoch) {
                commitment_ids.insert(commitment.commitment_id);
                probe_ids.insert(probe.probe_id);
            }
        }
        let valid_until_epoch = policy
            .end_epoch
            .min(epoch.saturating_add(policy.maximum_probe_age_epochs));
        if valid_until_epoch <= epoch {
            return Err(CustodyError::InvalidCertificate);
        }
        let mut certificate = AvailabilityCertificate {
            certificate_id: [0; 32],
            policy_id,
            issued_epoch: epoch,
            valid_until_epoch,
            commitment_ids: commitment_ids.into_iter().collect(),
            probe_ids: probe_ids.into_iter().collect(),
            verifier_key,
            signature: [0; 64],
        };
        let body = certificate.body()?;
        certificate.certificate_id = digest(DomainId::WwmCustodyCertificate, &[&body])?;
        certificate.signature = sign(
            verifier,
            DomainId::WwmCustodyCertificate,
            &certificate.certificate_id,
            &body,
        )?;
        certificate.validate_signature()?;
        let id = certificate.certificate_id;
        insert_once(&mut self.certificates, id, certificate)?;
        Ok(id)
    }

    pub fn validate_certificate(
        &self,
        certificate_id: Hash32,
        epoch: u64,
    ) -> Result<(), CustodyError> {
        let certificate = self
            .certificates
            .get(&certificate_id)
            .ok_or(CustodyError::InvalidCertificate)?;
        certificate.validate_signature()?;
        let policy = self
            .policies
            .get(&certificate.policy_id)
            .ok_or(CustodyError::UnknownPolicy)?;
        if policy
            .authorized_verifiers
            .binary_search(&certificate.verifier_key)
            .is_err()
            || epoch < certificate.issued_epoch
            || epoch >= certificate.valid_until_epoch
            || !self
                .repair_needs(certificate.policy_id, certificate.issued_epoch)?
                .is_empty()
            || certificate
                .commitment_ids
                .iter()
                .any(|id| !self.commitments.contains_key(id))
            || certificate
                .probe_ids
                .iter()
                .any(|id| !self.probes.contains_key(id))
        {
            return Err(CustodyError::InvalidCertificate);
        }
        Ok(())
    }

    #[must_use]
    pub fn certificate(&self, id: &Hash32) -> Option<&AvailabilityCertificate> {
        self.certificates.get(id)
    }

    fn live_replication(&self, policy: &CustodyPolicy, index: u16, epoch: u64) -> (u16, u16) {
        let copies = self.live_copies(policy, index, epoch);
        let clusters = copies
            .iter()
            .filter_map(|(commitment, _)| self.custodians.get(&commitment.custodian_profile_id))
            .map(|profile| profile.control_cluster)
            .collect::<BTreeSet<_>>();
        let domains = copies
            .iter()
            .filter_map(|(commitment, _)| self.custodians.get(&commitment.custodian_profile_id))
            .map(|profile| profile.failure_domain)
            .collect::<BTreeSet<_>>();
        (
            u16::try_from(clusters.len()).unwrap_or(u16::MAX),
            u16::try_from(domains.len()).unwrap_or(u16::MAX),
        )
    }

    fn live_copies<'a>(
        &'a self,
        policy: &CustodyPolicy,
        index: u16,
        epoch: u64,
    ) -> Vec<(&'a CustodyCommitment, &'a CustodyProbe)> {
        let minimum_probe_epoch = epoch.saturating_sub(policy.maximum_probe_age_epochs);
        let mut copies = Vec::new();
        for commitment in self.commitments.values().filter(|commitment| {
            commitment.policy_id == policy.policy_id
                && epoch >= commitment.start_epoch
                && epoch < commitment.end_epoch
                && commitment.shard_indices.binary_search(&index).is_ok()
        }) {
            if let Some(probe) = self
                .probes
                .values()
                .filter(|probe| {
                    probe.commitment_id == commitment.commitment_id
                        && probe.shard_index == index
                        && probe.epoch >= minimum_probe_epoch
                        && probe.epoch <= epoch
                })
                .max_by_key(|probe| probe.epoch)
            {
                copies.push((commitment, probe));
            }
        }
        copies
    }
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, CustodyError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| CustodyError::InvalidSignature)
}

fn sign(
    keypair: &Keypair,
    object_domain: DomainId,
    object_id: &Hash32,
    body: &[u8],
) -> Result<[u8; 64], CustodyError> {
    keypair
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| CustodyError::InvalidSignature)
}

fn verify(
    public_key: &Hash32,
    object_domain: DomainId,
    object_id: &Hash32,
    body: &[u8],
    signature: &[u8; 64],
) -> Result<(), CustodyError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(*public_key),
        &[object_domain.registry_id().as_bytes(), object_id, body],
        &Signature::from_bytes(*signature),
    )
    .map_err(|_| CustodyError::InvalidSignature)
}

fn insert_once<T>(map: &mut BTreeMap<Hash32, T>, id: Hash32, value: T) -> Result<(), CustodyError> {
    if map.contains_key(&id) {
        return Err(CustodyError::DuplicateId);
    }
    map.insert(id, value);
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn hash(out: &mut Vec<u8>, value: &Hash32) {
    out.extend_from_slice(value);
}

fn hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), CustodyError> {
    count(out, values.len())?;
    for value in values {
        hash(out, value);
    }
    Ok(())
}

fn count(out: &mut Vec<u8>, value: usize) -> Result<(), CustodyError> {
    u16_le(
        out,
        u16::try_from(value).map_err(|_| CustodyError::ArithmeticOverflow)?,
    );
    Ok(())
}

fn u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u128_le(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::assertions_on_constants,
    clippy::unwrap_used
)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn setup() -> (
        CustodyLedger,
        CustodyPolicy,
        Vec<Keypair>,
        Keypair,
        Vec<Vec<u8>>,
    ) {
        let owner = Keypair::from_seed([40; 32]);
        let verifier = Keypair::from_seed([41; 32]);
        let shard_bytes = vec![vec![1_u8; 64], vec![2_u8; 64]];
        let artifact_root = h(50);
        let shard_roots = shard_bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                digest(
                    DomainId::WwmCustodyShard,
                    &[
                        &artifact_root,
                        &u16::try_from(index).unwrap().to_le_bytes(),
                        bytes,
                    ],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let policy = CustodyPolicy::new(
            &owner,
            artifact_root,
            shard_roots,
            vec![64, 64],
            3,
            3,
            1,
            100,
            10,
            vec![verifier.public_key().into_bytes()],
        )
        .unwrap();

        let keys = vec![
            Keypair::from_seed([51; 32]),
            Keypair::from_seed([52; 32]),
            Keypair::from_seed([53; 32]),
        ];
        let mut ledger = CustodyLedger::default();
        ledger.register_policy(policy.clone()).unwrap();
        for (offset, key) in keys.iter().enumerate() {
            let value = u8::try_from(offset).unwrap();
            let profile = CustodianProfile::new(
                key,
                h(60 + value),
                h(70 + value),
                h(80 + value),
                64_500 + u32::from(value),
                1_000,
                100,
                100,
            )
            .unwrap();
            let profile_id = profile.profile_id;
            ledger.register_custodian(profile).unwrap();
            let commitment =
                CustodyCommitment::new(key, policy.policy_id, profile_id, vec![0, 1], 1, 100)
                    .unwrap();
            ledger.register_commitment(commitment).unwrap();
        }
        (ledger, policy, keys, verifier, shard_bytes)
    }

    #[test]
    fn independent_recent_copies_issue_certificate() {
        let (mut ledger, policy, _, verifier, shards) = setup();
        let commitments = ledger.commitments.keys().copied().collect::<Vec<_>>();
        for commitment in commitments {
            for (index, bytes) in shards.iter().enumerate() {
                ledger
                    .record_probe(
                        commitment,
                        u16::try_from(index).unwrap(),
                        10,
                        bytes,
                        25,
                        &verifier,
                    )
                    .unwrap();
            }
        }
        assert!(ledger
            .repair_needs(policy.policy_id, 10)
            .unwrap()
            .is_empty());
        let certificate = ledger
            .issue_certificate(policy.policy_id, 10, &verifier)
            .unwrap();
        ledger.validate_certificate(certificate, 10).unwrap();
        assert!(ledger.certificate(&certificate).is_some());
    }

    #[test]
    fn stale_probe_blocks_assurance() {
        let (mut ledger, policy, _, verifier, shards) = setup();
        let commitments = ledger.commitments.keys().copied().collect::<Vec<_>>();
        for commitment in commitments {
            for (index, bytes) in shards.iter().enumerate() {
                ledger
                    .record_probe(
                        commitment,
                        u16::try_from(index).unwrap(),
                        2,
                        bytes,
                        5,
                        &verifier,
                    )
                    .unwrap();
            }
        }
        assert!(ledger.repair_needs(policy.policy_id, 2).unwrap().is_empty());
        assert!(!ledger
            .repair_needs(policy.policy_id, 20)
            .unwrap()
            .is_empty());
        assert_eq!(
            ledger.issue_certificate(policy.policy_id, 20, &verifier),
            Err(CustodyError::InsufficientReplication)
        );
    }

    #[test]
    fn poisoned_shard_and_unauthorized_verifier_reject() {
        let (mut ledger, policy, _, _, shards) = setup();
        let commitment = *ledger.commitments.keys().next().unwrap();
        let unauthorized = Keypair::from_seed([99; 32]);
        assert_eq!(
            ledger.record_probe(commitment, 0, 10, &shards[0], 1, &unauthorized),
            Err(CustodyError::InvalidProbe)
        );
        let mut poisoned = shards[0].clone();
        poisoned[0] ^= 1;
        let verifier = Keypair::from_seed([41; 32]);
        assert_eq!(
            ledger.record_probe(commitment, 0, 10, &poisoned, 1, &verifier),
            Err(CustodyError::ShardMismatch)
        );
        assert_eq!(policy.shard_roots.len(), 2);
    }

    #[test]
    fn custody_controls_never_affect_consensus() {
        assert!(!WWM_MODEL_CUSTODY_ENABLED);
        assert_eq!(WWM_CUSTODY_CONSENSUS_WEIGHT, 0);
    }
}
