//! Position-aware V2 artifact custody, probes, certificates, and handover.
//!
//! These bounded records describe custody evidence only. They never put model
//! bytes on chain and never grant proposal, finality, issuance, or consensus
//! weight. Raw probe leaves/branches and reconstruction evidence remain off
//! chain; certificates bind their signed results.

use std::collections::{BTreeMap, BTreeSet};

use noos_crypto::{verify_domain, DomainId, Keypair, PublicKey, Signature};

use crate::artifact::{
    verify_probe, ArtifactShareCommitmentV1, ARTIFACT_POSITIONS, ARTIFACT_PROBE_DEPTH,
    ARTIFACT_PROBE_LEAF_BYTES, BONSAI_POSITION_BYTES, BONSAI_STRIPES,
};

pub type Hash32 = [u8; 32];
pub const CERTIFICATE_SELECTED_VERIFIERS: usize = 8;
pub const CERTIFICATE_REQUIRED_SIGNATURES: usize = 5;
pub const RECONSTRUCTOR_SELECTED: usize = 5;
pub const RECONSTRUCTOR_MATCHING_ROOTS: usize = 3;
pub const WWM_CUSTODY_CONSENSUS_WEIGHT: u64 = 0;

const PROFILE: &[u8] = b"NOOS/WWM/CUSTODIAN-PROFILE/V2";
const POLICY: &[u8] = b"NOOS/WWM/AVAILABILITY-POLICY/V2";
const COMMITMENT: &[u8] = b"NOOS/WWM/CUSTODY-COMMITMENT/V2";
const CHALLENGE: &[u8] = b"NOOS/WWM/CUSTODY-CHALLENGE/V2";
const PROBE: &[u8] = b"NOOS/WWM/CUSTODY-PROBE/V2";
const EXECUTOR: &[u8] = b"NOOS/WWM/EXECUTOR-PROFILE/V1";
const CERTIFICATE: &[u8] = b"NOOS/WWM/CUSTODY-CERTIFICATE/V2";
const REPAIR: &[u8] = b"NOOS/WWM/CUSTODY-REPAIR/V1";
const RECONSTRUCTION: &[u8] = b"NOOS/WWM/CUSTODY-RECONSTRUCTION/V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyError {
    DuplicateId,
    UnknownId,
    InvalidProfile,
    InvalidPolicy,
    InvalidCommitment,
    InvalidChallenge,
    InvalidProbe,
    InvalidCertificate,
    InvalidSignature,
    InvalidDiversity,
    InvalidSelection,
    InsufficientPositions,
    Expired,
    InvalidRepair,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodianProfileV2 {
    pub profile_id: Hash32,
    pub operator_key: Hash32,
    pub beneficial_control_root: Hash32,
    pub failure_domain_root: Hash32,
    pub region_root: Hash32,
    pub provider_root: Hash32,
    pub asn: u32,
    pub max_bytes: u64,
    pub bond_micro_noos: u128,
    pub attestation_epoch: u64,
    pub control_attestation_expires: u64,
    pub profile_expires: u64,
    pub reviewer_key: Hash32,
    pub operator_signature: [u8; 64],
    pub reviewer_signature: [u8; 64],
}

impl CustodianProfileV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator: &Keypair,
        reviewer: &Keypair,
        beneficial_control_root: Hash32,
        failure_domain_root: Hash32,
        region_root: Hash32,
        provider_root: Hash32,
        asn: u32,
        max_bytes: u64,
        bond_micro_noos: u128,
        attestation_epoch: u64,
        control_attestation_expires: u64,
        profile_expires: u64,
    ) -> Result<Self, CustodyError> {
        let mut value = Self {
            profile_id: [0; 32],
            operator_key: operator.public_key().into_bytes(),
            beneficial_control_root,
            failure_domain_root,
            region_root,
            provider_root,
            asn,
            max_bytes,
            bond_micro_noos,
            attestation_epoch,
            control_attestation_expires,
            profile_expires,
            reviewer_key: reviewer.public_key().into_bytes(),
            operator_signature: [0; 64],
            reviewer_signature: [0; 64],
        };
        let body = value.body()?;
        value.profile_id = digest(PROFILE, &[&body]);
        value.operator_signature = sign(operator, PROFILE, &value.profile_id, &body)?;
        value.reviewer_signature = sign(reviewer, PROFILE, &value.profile_id, &body)?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.profile_id != digest(PROFILE, &[&body]) {
            return Err(CustodyError::InvalidProfile);
        }
        verify(
            &self.operator_key,
            PROFILE,
            &self.profile_id,
            &body,
            &self.operator_signature,
        )?;
        verify(
            &self.reviewer_key,
            PROFILE,
            &self.profile_id,
            &body,
            &self.reviewer_signature,
        )
    }
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if [
            self.operator_key,
            self.beneficial_control_root,
            self.failure_domain_root,
            self.region_root,
            self.provider_root,
            self.reviewer_key,
        ]
        .contains(&[0; 32])
            || self.operator_key == self.reviewer_key
            || self.asn == 0
            || self.max_bytes < BONSAI_POSITION_BYTES
            || self.bond_micro_noos == 0
            || self.attestation_epoch >= self.control_attestation_expires
            || self.attestation_epoch >= self.profile_expires
        {
            return Err(CustodyError::InvalidProfile);
        }
        let mut out = Vec::with_capacity(256);
        hashes(
            &mut out,
            &[
                self.operator_key,
                self.beneficial_control_root,
                self.failure_domain_root,
                self.region_root,
                self.provider_root,
            ],
        );
        u32le(&mut out, self.asn);
        u64le(&mut out, self.max_bytes);
        u128le(&mut out, self.bond_micro_noos);
        u64le(&mut out, self.attestation_epoch);
        u64le(&mut out, self.control_attestation_expires);
        u64le(&mut out, self.profile_expires);
        hash(&mut out, &self.reviewer_key);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityPolicyV2 {
    pub policy_id: Hash32,
    pub artifact_manifest_root: Hash32,
    pub policy_start: u64,
    pub policy_end: u64,
    pub maximum_probe_age: u64,
    pub raw_evidence_retention: u64,
    pub minimum_regions: u8,
    pub maximum_positions_per_region: u8,
    pub maximum_positions_per_asn: u8,
    pub maximum_positions_per_provider: u8,
    pub selected_verifiers: u8,
    pub required_signatures: u8,
}
impl AvailabilityPolicyV2 {
    pub fn new(
        artifact_manifest_root: Hash32,
        policy_start: u64,
        policy_end: u64,
        maximum_probe_age: u64,
        raw_evidence_retention: u64,
    ) -> Result<Self, CustodyError> {
        let mut value = Self {
            policy_id: [0; 32],
            artifact_manifest_root,
            policy_start,
            policy_end,
            maximum_probe_age,
            raw_evidence_retention,
            minimum_regions: 4,
            maximum_positions_per_region: 3,
            maximum_positions_per_asn: 2,
            maximum_positions_per_provider: 3,
            selected_verifiers: 8,
            required_signatures: 5,
        };
        let body = value.body()?;
        value.policy_id = digest(POLICY, &[&body]);
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.policy_id != digest(POLICY, &[&body]) {
            Err(CustodyError::InvalidPolicy)
        } else {
            Ok(())
        }
    }
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.artifact_manifest_root == [0; 32]
            || self.policy_start >= self.policy_end
            || self.maximum_probe_age == 0
            || self.raw_evidence_retention < self.maximum_probe_age
            || self.minimum_regions != 4
            || self.maximum_positions_per_region != 3
            || self.maximum_positions_per_asn != 2
            || self.maximum_positions_per_provider != 3
            || self.selected_verifiers != 8
            || self.required_signatures != 5
        {
            return Err(CustodyError::InvalidPolicy);
        }
        let mut out = Vec::new();
        hash(&mut out, &self.artifact_manifest_root);
        u64le(&mut out, self.policy_start);
        u64le(&mut out, self.policy_end);
        u64le(&mut out, self.maximum_probe_age);
        u64le(&mut out, self.raw_evidence_retention);
        out.extend_from_slice(&[
            self.minimum_regions,
            self.maximum_positions_per_region,
            self.maximum_positions_per_asn,
            self.maximum_positions_per_provider,
            self.selected_verifiers,
            self.required_signatures,
        ]);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyPositionCommitmentV2 {
    pub commitment_id: Hash32,
    pub policy_id: Hash32,
    pub custodian_profile_id: Hash32,
    pub position: u8,
    pub position_root: Hash32,
    pub position_bytes: u64,
    pub starts_at: u64,
    pub ends_at: u64,
    pub signature: [u8; 64],
}
impl CustodyPositionCommitmentV2 {
    pub fn new(
        key: &Keypair,
        policy_id: Hash32,
        custodian_profile_id: Hash32,
        position: u8,
        position_root: Hash32,
        starts_at: u64,
        ends_at: u64,
    ) -> Result<Self, CustodyError> {
        let mut value = Self {
            commitment_id: [0; 32],
            policy_id,
            custodian_profile_id,
            position,
            position_root,
            position_bytes: BONSAI_POSITION_BYTES,
            starts_at,
            ends_at,
            signature: [0; 64],
        };
        let body = value.body()?;
        value.commitment_id = digest(COMMITMENT, &[&body]);
        value.signature = sign(key, COMMITMENT, &value.commitment_id, &body)?;
        Ok(value)
    }
    pub fn validate(&self, profile: &CustodianProfileV2) -> Result<(), CustodyError> {
        let body = self.body()?;
        if profile.profile_id != self.custodian_profile_id
            || self.commitment_id != digest(COMMITMENT, &[&body])
        {
            return Err(CustodyError::InvalidCommitment);
        }
        verify(
            &profile.operator_key,
            COMMITMENT,
            &self.commitment_id,
            &body,
            &self.signature,
        )
    }
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.policy_id == [0; 32]
            || self.custodian_profile_id == [0; 32]
            || self.position_root == [0; 32]
            || self.position as usize >= ARTIFACT_POSITIONS
            || self.position_bytes != BONSAI_POSITION_BYTES
            || self.starts_at >= self.ends_at
        {
            return Err(CustodyError::InvalidCommitment);
        }
        let mut out = Vec::new();
        hashes(&mut out, &[self.policy_id, self.custodian_profile_id]);
        out.push(self.position);
        hash(&mut out, &self.position_root);
        u64le(&mut out, self.position_bytes);
        u64le(&mut out, self.starts_at);
        u64le(&mut out, self.ends_at);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositionChallengeV2 {
    pub position: u8,
    pub stripe: u32,
    pub probe_leaf: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyChallengeV2 {
    pub challenge_id: Hash32,
    pub policy_id: Hash32,
    pub commitment_set_root: Hash32,
    pub beacon_height: u64,
    pub beacon_root: Hash32,
    pub issued_at: u64,
    pub positions: Vec<PositionChallengeV2>,
}
impl CustodyChallengeV2 {
    pub fn derive(
        policy: &AvailabilityPolicyV2,
        commitments: &[CustodyPositionCommitmentV2],
        beacon_height: u64,
        beacon_root: Hash32,
        issued_at: u64,
    ) -> Result<Self, CustodyError> {
        validate_commitment_set(commitments)?;
        if beacon_root == [0; 32]
            || issued_at < policy.policy_start
            || issued_at >= policy.policy_end
            || commitments.iter().any(|c| c.starts_at > issued_at)
        {
            return Err(CustodyError::InvalidChallenge);
        }
        let commitment_set_root = commitment_set_root(commitments);
        let mut positions = Vec::with_capacity(commitments.len());
        for c in commitments {
            let r = digest(
                CHALLENGE,
                &[
                    &policy.policy_id,
                    &commitment_set_root,
                    &beacon_height.to_le_bytes(),
                    &beacon_root,
                    &[c.position],
                ],
            );
            positions.push(PositionChallengeV2 {
                position: c.position,
                stripe: u32::from_le_bytes(r[..4].try_into().expect("four")) % BONSAI_STRIPES,
                probe_leaf: r[4] % 32,
            });
        }
        let mut value = Self {
            challenge_id: [0; 32],
            policy_id: policy.policy_id,
            commitment_set_root,
            beacon_height,
            beacon_root,
            issued_at,
            positions,
        };
        let body = value.body()?;
        value.challenge_id = digest(CHALLENGE, &[&body]);
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.challenge_id != digest(CHALLENGE, &[&body]) {
            Err(CustodyError::InvalidChallenge)
        } else {
            Ok(())
        }
    }
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if self.policy_id == [0; 32]
            || self.commitment_set_root == [0; 32]
            || self.beacon_root == [0; 32]
            || self.positions.len() < 8
            || !strict_positions(&self.positions)
        {
            return Err(CustodyError::InvalidChallenge);
        }
        let mut out = Vec::new();
        hashes(&mut out, &[self.policy_id, self.commitment_set_root]);
        u64le(&mut out, self.beacon_height);
        hash(&mut out, &self.beacon_root);
        u64le(&mut out, self.issued_at);
        out.push(self.positions.len() as u8);
        for p in &self.positions {
            out.push(p.position);
            u32le(&mut out, p.stripe);
            out.push(p.probe_leaf);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyProbeResponseV2 {
    pub probe_id: Hash32,
    pub challenge_id: Hash32,
    pub commitment_id: Hash32,
    pub custodian_profile_id: Hash32,
    pub position: u8,
    pub stripe: u32,
    pub probe_leaf: u8,
    pub observed_at: u64,
    pub leaf_bytes: Box<[u8; ARTIFACT_PROBE_LEAF_BYTES]>,
    pub branch: [Hash32; ARTIFACT_PROBE_DEPTH],
    pub signature: [u8; 64],
}
impl CustodyProbeResponseV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: &Keypair,
        challenge_id: Hash32,
        commitment_id: Hash32,
        custodian_profile_id: Hash32,
        position: u8,
        stripe: u32,
        probe_leaf: u8,
        observed_at: u64,
        leaf_bytes: [u8; ARTIFACT_PROBE_LEAF_BYTES],
        branch: [noos_crypto::Hash32; ARTIFACT_PROBE_DEPTH],
    ) -> Result<Self, CustodyError> {
        let branch = branch.map(noos_crypto::Hash32::into_bytes);
        let mut v = Self {
            probe_id: [0; 32],
            challenge_id,
            commitment_id,
            custodian_profile_id,
            position,
            stripe,
            probe_leaf,
            observed_at,
            leaf_bytes: Box::new(leaf_bytes),
            branch,
            signature: [0; 64],
        };
        let body = v.body()?;
        v.probe_id = digest(PROBE, &[&body]);
        v.signature = sign(key, PROBE, &v.probe_id, &body)?;
        Ok(v)
    }
    pub fn validate(
        &self,
        challenge: &CustodyChallengeV2,
        commitment: &CustodyPositionCommitmentV2,
        profile: &CustodianProfileV2,
        expected: &ArtifactShareCommitmentV1,
    ) -> Result<(), CustodyError> {
        let body = self.body()?;
        let expected_challenge = challenge
            .positions
            .iter()
            .find(|p| p.position == self.position)
            .ok_or(CustodyError::InvalidProbe)?;
        if self.challenge_id != challenge.challenge_id
            || self.commitment_id != commitment.commitment_id
            || self.custodian_profile_id != profile.profile_id
            || self.position != commitment.position
            || self.stripe != expected_challenge.stripe
            || self.probe_leaf != expected_challenge.probe_leaf
            || self.probe_id != digest(PROBE, &[&body])
        {
            return Err(CustodyError::InvalidProbe);
        }
        let root = noos_crypto::Hash32::from_bytes(expected.probe_root.into_bytes());
        let branch = self.branch.map(noos_crypto::Hash32::from_bytes);
        if !verify_probe(
            &root,
            self.stripe,
            self.position,
            self.probe_leaf,
            &*self.leaf_bytes,
            &branch,
        ) {
            return Err(CustodyError::InvalidProbe);
        }
        verify(
            &profile.operator_key,
            PROBE,
            &self.probe_id,
            &body,
            &self.signature,
        )
    }
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if [
            self.challenge_id,
            self.commitment_id,
            self.custodian_profile_id,
        ]
        .contains(&[0; 32])
            || self.position as usize >= ARTIFACT_POSITIONS
            || self.stripe >= BONSAI_STRIPES
            || self.probe_leaf >= 32
            || self.observed_at == 0
        {
            return Err(CustodyError::InvalidProbe);
        }
        let mut out = Vec::new();
        hashes(
            &mut out,
            &[
                self.challenge_id,
                self.commitment_id,
                self.custodian_profile_id,
            ],
        );
        out.push(self.position);
        u32le(&mut out, self.stripe);
        out.push(self.probe_leaf);
        u64le(&mut out, self.observed_at);
        out.extend_from_slice(&*self.leaf_bytes);
        for h in self.branch {
            hash(&mut out, &h)
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorProfileV1 {
    pub executor_id: Hash32,
    pub operator_key: Hash32,
    pub beneficial_control_root: Hash32,
    pub capability_set_root: Hash32,
    pub capability_epoch: u64,
    pub verifier: bool,
    pub reconstructor: bool,
    pub expires_at: u64,
    pub signature: [u8; 64],
}
impl ExecutorProfileV1 {
    pub fn new(
        key: &Keypair,
        beneficial_control_root: Hash32,
        capability_set_root: Hash32,
        capability_epoch: u64,
        verifier: bool,
        reconstructor: bool,
        expires_at: u64,
    ) -> Result<Self, CustodyError> {
        let mut v = Self {
            executor_id: [0; 32],
            operator_key: key.public_key().into_bytes(),
            beneficial_control_root,
            capability_set_root,
            capability_epoch,
            verifier,
            reconstructor,
            expires_at,
            signature: [0; 64],
        };
        let body = v.body()?;
        v.executor_id = digest(EXECUTOR, &[&body]);
        v.signature = sign(key, EXECUTOR, &v.executor_id, &body)?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), CustodyError> {
        let body = self.body()?;
        if self.executor_id != digest(EXECUTOR, &[&body]) {
            return Err(CustodyError::InvalidProfile);
        }
        verify(
            &self.operator_key,
            EXECUTOR,
            &self.executor_id,
            &body,
            &self.signature,
        )
    }
    fn body(&self) -> Result<Vec<u8>, CustodyError> {
        if [
            self.operator_key,
            self.beneficial_control_root,
            self.capability_set_root,
        ]
        .contains(&[0; 32])
            || (!self.verifier && !self.reconstructor)
            || self.capability_epoch == 0
            || self.expires_at == 0
        {
            return Err(CustodyError::InvalidProfile);
        }
        let mut out = Vec::new();
        hashes(
            &mut out,
            &[
                self.operator_key,
                self.beneficial_control_root,
                self.capability_set_root,
            ],
        );
        u64le(&mut out, self.capability_epoch);
        out.extend_from_slice(&[self.verifier as u8, self.reconstructor as u8]);
        u64le(&mut out, self.expires_at);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSignatureV2 {
    pub executor_id: Hash32,
    pub signature: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityCertificateV2 {
    pub certificate_id: Hash32,
    pub policy_id: Hash32,
    pub challenge_id: Hash32,
    pub custodian_set_root: Hash32,
    pub executor_set_root: Hash32,
    pub capability_epoch: u64,
    pub selected_executor_ids: [Hash32; 8],
    pub commitment_ids: Vec<Hash32>,
    pub probe_ids: Vec<Hash32>,
    pub derived_result: Hash32,
    pub issued_at: u64,
    pub valid_until: u64,
    pub signatures: Vec<CertificateSignatureV2>,
}
impl AvailabilityCertificateV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn unsigned(
        policy: &AvailabilityPolicyV2,
        challenge: &CustodyChallengeV2,
        commitments: &[CustodyPositionCommitmentV2],
        profiles: &BTreeMap<Hash32, CustodianProfileV2>,
        probes: &[CustodyProbeResponseV2],
        executors: &[ExecutorProfileV1],
        executor_set_root: Hash32,
        capability_epoch: u64,
        issued_at: u64,
    ) -> Result<Self, CustodyError> {
        policy.validate()?;
        challenge.validate()?;
        validate_live_coverage(policy, commitments, profiles, probes, issued_at)?;
        let selected = select_executors(executors, &challenge.beacon_root, capability_epoch, true)?;
        let selected_executor_ids = selected
            .try_into()
            .map_err(|_| CustodyError::InvalidSelection)?;
        let commitment_ids = commitments
            .iter()
            .map(|c| c.commitment_id)
            .collect::<Vec<_>>();
        let probe_ids = probes.iter().map(|p| p.probe_id).collect::<Vec<_>>();
        let custodian_set_root = commitment_set_root(commitments);
        let valid_until = expiry_intersection(
            policy,
            commitments,
            profiles,
            probes,
            executors,
            &selected_executor_ids,
            issued_at,
        )?;
        let derived_result = digest(
            CERTIFICATE,
            &[
                &policy.policy_id,
                &challenge.challenge_id,
                &custodian_set_root,
                &executor_set_root,
                &capability_epoch.to_le_bytes(),
                &flatten_hashes(&selected_executor_ids),
                &flatten_hashes(&commitment_ids),
                &flatten_hashes(&probe_ids),
                &issued_at.to_le_bytes(),
                &valid_until.to_le_bytes(),
            ],
        );
        let certificate_id = digest(CERTIFICATE, &[&derived_result]);
        Ok(Self {
            certificate_id,
            policy_id: policy.policy_id,
            challenge_id: challenge.challenge_id,
            custodian_set_root,
            executor_set_root,
            capability_epoch,
            selected_executor_ids,
            commitment_ids,
            probe_ids,
            derived_result,
            issued_at,
            valid_until,
            signatures: Vec::new(),
        })
    }
    pub fn sign(
        &mut self,
        executor: &ExecutorProfileV1,
        key: &Keypair,
    ) -> Result<(), CustodyError> {
        if !self.selected_executor_ids.contains(&executor.executor_id)
            || executor.operator_key != key.public_key().into_bytes()
            || self
                .signatures
                .iter()
                .any(|s| s.executor_id == executor.executor_id)
        {
            return Err(CustodyError::InvalidSelection);
        }
        self.signatures.push(CertificateSignatureV2 {
            executor_id: executor.executor_id,
            signature: sign(key, CERTIFICATE, &self.certificate_id, &self.derived_result)?,
        });
        self.signatures.sort_by_key(|s| s.executor_id);
        Ok(())
    }
    pub fn validate(
        &self,
        policy: &AvailabilityPolicyV2,
        challenge: &CustodyChallengeV2,
        commitments: &[CustodyPositionCommitmentV2],
        profiles: &BTreeMap<Hash32, CustodianProfileV2>,
        probes: &[CustodyProbeResponseV2],
        executors: &[ExecutorProfileV1],
        now: u64,
    ) -> Result<(), CustodyError> {
        if self.signatures.len() != CERTIFICATE_REQUIRED_SIGNATURES
            || !strict_ids(
                &self
                    .signatures
                    .iter()
                    .map(|s| s.executor_id)
                    .collect::<Vec<_>>(),
            )
            || self
                .signatures
                .iter()
                .any(|s| !self.selected_executor_ids.contains(&s.executor_id))
        {
            return Err(CustodyError::InvalidCertificate);
        }
        let expected = Self::unsigned(
            policy,
            challenge,
            commitments,
            profiles,
            probes,
            executors,
            self.executor_set_root,
            self.capability_epoch,
            self.issued_at,
        )?;
        if self.certificate_id != expected.certificate_id
            || self.derived_result != expected.derived_result
            || self.valid_until != expected.valid_until
            || self.selected_executor_ids != expected.selected_executor_ids
            || self.commitment_ids != expected.commitment_ids
            || self.probe_ids != expected.probe_ids
            || now >= self.valid_until
        {
            return Err(CustodyError::InvalidCertificate);
        }
        for s in &self.signatures {
            let e = executors
                .iter()
                .find(|e| e.executor_id == s.executor_id)
                .ok_or(CustodyError::InvalidCertificate)?;
            verify(
                &e.operator_key,
                CERTIFICATE,
                &self.certificate_id,
                &self.derived_result,
                &s.signature,
            )?
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactAvailability {
    Schedulable,
    EmergencyRepairOnly,
    Unavailable,
}
pub fn availability_state(
    commitments: &[CustodyPositionCommitmentV2],
    profiles: &BTreeMap<Hash32, CustodianProfileV2>,
    at: u64,
) -> ArtifactAvailability {
    let live = live_deduplicated(commitments, profiles, at);
    match live.len() {
        9..=12 => ArtifactAvailability::Schedulable,
        8 => ArtifactAvailability::EmergencyRepairOnly,
        _ => ArtifactAvailability::Unavailable,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairOrderV1 {
    pub order_id: Hash32,
    pub policy_id: Hash32,
    pub position: u8,
    pub old_commitment_id: Hash32,
    pub replacement_profile_id: Hash32,
    pub source_positions: [u8; 8],
    pub expires_at: u64,
}
impl RepairOrderV1 {
    pub fn new(
        policy_id: Hash32,
        position: u8,
        old_commitment_id: Hash32,
        replacement_profile_id: Hash32,
        mut source_positions: [u8; 8],
        expires_at: u64,
    ) -> Result<Self, CustodyError> {
        source_positions.sort();
        if position as usize >= ARTIFACT_POSITIONS
            || source_positions.contains(&position)
            || source_positions.windows(2).any(|w| w[0] >= w[1])
            || expires_at == 0
        {
            return Err(CustodyError::InvalidRepair);
        }
        let id = digest(
            REPAIR,
            &[
                &policy_id,
                &[position],
                &old_commitment_id,
                &replacement_profile_id,
                &source_positions,
                &expires_at.to_le_bytes(),
            ],
        );
        Ok(Self {
            order_id: id,
            policy_id,
            position,
            old_commitment_id,
            replacement_profile_id,
            source_positions,
            expires_at,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoverStage {
    Staging,
    RootVerified,
    Durable,
    Committed,
    Probed,
    Certified,
    Live,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairHandoverV1 {
    pub order: RepairOrderV1,
    pub stage: HandoverStage,
    pub verified_position_root: Option<Hash32>,
    pub new_commitment_id: Option<Hash32>,
    pub new_probe_id: Option<Hash32>,
    pub new_certificate_id: Option<Hash32>,
}
impl RepairHandoverV1 {
    pub fn new(order: RepairOrderV1) -> Self {
        Self {
            order,
            stage: HandoverStage::Staging,
            verified_position_root: None,
            new_commitment_id: None,
            new_probe_id: None,
            new_certificate_id: None,
        }
    }
    pub fn verify_root(&mut self, root: Hash32) -> Result<(), CustodyError> {
        if self.stage != HandoverStage::Staging || root == [0; 32] {
            return Err(CustodyError::InvalidRepair);
        }
        self.verified_position_root = Some(root);
        self.stage = HandoverStage::RootVerified;
        Ok(())
    }
    pub fn durable(&mut self) -> Result<(), CustodyError> {
        self.advance(HandoverStage::RootVerified, HandoverStage::Durable)
    }
    pub fn commit(&mut self, c: &CustodyPositionCommitmentV2) -> Result<(), CustodyError> {
        if self.stage != HandoverStage::Durable
            || c.position != self.order.position
            || c.custodian_profile_id != self.order.replacement_profile_id
            || Some(c.position_root) != self.verified_position_root
        {
            return Err(CustodyError::InvalidRepair);
        }
        self.new_commitment_id = Some(c.commitment_id);
        self.stage = HandoverStage::Committed;
        Ok(())
    }
    pub fn probe(&mut self, p: &CustodyProbeResponseV2) -> Result<(), CustodyError> {
        if self.stage != HandoverStage::Committed || Some(p.commitment_id) != self.new_commitment_id
        {
            return Err(CustodyError::InvalidRepair);
        }
        self.new_probe_id = Some(p.probe_id);
        self.stage = HandoverStage::Probed;
        Ok(())
    }
    pub fn certify(&mut self, c: &AvailabilityCertificateV2) -> Result<(), CustodyError> {
        if self.stage != HandoverStage::Probed
            || !c
                .commitment_ids
                .contains(&self.new_commitment_id.ok_or(CustodyError::InvalidRepair)?)
            || !c
                .probe_ids
                .contains(&self.new_probe_id.ok_or(CustodyError::InvalidRepair)?)
        {
            return Err(CustodyError::InvalidRepair);
        }
        self.new_certificate_id = Some(c.certificate_id);
        self.stage = HandoverStage::Certified;
        Ok(())
    }
    pub fn activate(&mut self) -> Result<(), CustodyError> {
        self.advance(HandoverStage::Certified, HandoverStage::Live)
    }
    fn advance(&mut self, from: HandoverStage, to: HandoverStage) -> Result<(), CustodyError> {
        if self.stage != from {
            return Err(CustodyError::InvalidRepair);
        }
        self.stage = to;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconstructionSignatureV1 {
    pub executor_id: Hash32,
    pub payload_root: Hash32,
    pub signature: [u8; 64],
}
pub fn validate_reconstruction_evidence(
    selected: &[Hash32; 5],
    evidence: &[ReconstructionSignatureV1],
    executors: &[ExecutorProfileV1],
    expected_root: Hash32,
) -> Result<(), CustodyError> {
    if evidence.len() < 3 {
        return Err(CustodyError::InvalidSelection);
    }
    let mut ids = BTreeSet::new();
    let mut matches = 0;
    for e in evidence {
        if !selected.contains(&e.executor_id) || !ids.insert(e.executor_id) {
            return Err(CustodyError::InvalidSelection);
        }
        let p = executors
            .iter()
            .find(|p| p.executor_id == e.executor_id && p.reconstructor)
            .ok_or(CustodyError::InvalidSelection)?;
        verify(
            &p.operator_key,
            RECONSTRUCTION,
            &e.executor_id,
            &e.payload_root,
            &e.signature,
        )?;
        if e.payload_root == expected_root {
            matches += 1
        }
    }
    if matches < 3 {
        Err(CustodyError::InvalidSelection)
    } else {
        Ok(())
    }
}

fn validate_commitment_set(c: &[CustodyPositionCommitmentV2]) -> Result<(), CustodyError> {
    if c.len() < 8 || c.len() > 12 || c.windows(2).any(|w| w[0].position >= w[1].position) {
        Err(CustodyError::InvalidCommitment)
    } else {
        Ok(())
    }
}
fn commitment_set_root(c: &[CustodyPositionCommitmentV2]) -> Hash32 {
    digest(
        COMMITMENT,
        &[&flatten_hashes(
            &c.iter().map(|x| x.commitment_id).collect::<Vec<_>>(),
        )],
    )
}
fn validate_live_coverage(
    policy: &AvailabilityPolicyV2,
    c: &[CustodyPositionCommitmentV2],
    profiles: &BTreeMap<Hash32, CustodianProfileV2>,
    probes: &[CustodyProbeResponseV2],
    at: u64,
) -> Result<(), CustodyError> {
    validate_commitment_set(c)?;
    if c.len() != probes.len()
        || c.iter()
            .any(|x| x.policy_id != policy.policy_id || x.starts_at > at || x.ends_at <= at)
        || probes.iter().any(|p| {
            p.observed_at > at || p.observed_at.saturating_add(policy.maximum_probe_age) <= at
        })
        || c.iter()
            .zip(probes)
            .any(|(c, p)| c.position != p.position || c.commitment_id != p.commitment_id)
    {
        return Err(CustodyError::InvalidCertificate);
    }
    let selected = c
        .iter()
        .map(|x| {
            profiles
                .get(&x.custodian_profile_id)
                .ok_or(CustodyError::UnknownId)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let controls = selected
        .iter()
        .map(|p| p.beneficial_control_root)
        .collect::<BTreeSet<_>>();
    if controls.len() != selected.len() {
        return Err(CustodyError::InvalidDiversity);
    }
    cap(&selected, |p| p.region_root, 3)?;
    cap(&selected, |p| p.provider_root, 3)?;
    cap(&selected, |p| p.asn, 2)?;
    if selected
        .iter()
        .map(|p| p.region_root)
        .collect::<BTreeSet<_>>()
        .len()
        < 4
    {
        return Err(CustodyError::InvalidDiversity);
    }
    Ok(())
}
fn cap<T: Ord + Copy, F: Fn(&CustodianProfileV2) -> T>(
    p: &[&CustodianProfileV2],
    f: F,
    max: usize,
) -> Result<(), CustodyError> {
    let mut m = BTreeMap::new();
    for x in p {
        *m.entry(f(x)).or_insert(0usize) += 1;
    }
    if m.values().any(|n| *n > max) {
        Err(CustodyError::InvalidDiversity)
    } else {
        Ok(())
    }
}
fn select_executors(
    e: &[ExecutorProfileV1],
    beacon: &Hash32,
    epoch: u64,
    verifier: bool,
) -> Result<Vec<Hash32>, CustodyError> {
    let mut eligible = e
        .iter()
        .filter(|p| {
            p.capability_epoch == epoch
                && if verifier {
                    p.verifier
                } else {
                    p.reconstructor
                }
        })
        .collect::<Vec<_>>();
    eligible.sort_by_key(|p| digest(EXECUTOR, &[beacon, &p.executor_id]));
    let mut controls = BTreeSet::new();
    let out = eligible
        .into_iter()
        .filter(|p| controls.insert(p.beneficial_control_root))
        .map(|p| p.executor_id)
        .take(if verifier { 8 } else { 5 })
        .collect::<Vec<_>>();
    if out.len() != if verifier { 8 } else { 5 } {
        Err(CustodyError::InvalidSelection)
    } else {
        Ok(out)
    }
}
fn expiry_intersection(
    policy: &AvailabilityPolicyV2,
    c: &[CustodyPositionCommitmentV2],
    profiles: &BTreeMap<Hash32, CustodianProfileV2>,
    probes: &[CustodyProbeResponseV2],
    executors: &[ExecutorProfileV1],
    selected: &[Hash32; 8],
    issued: u64,
) -> Result<u64, CustodyError> {
    let mut end = policy.policy_end.min(
        issued
            .checked_add(policy.maximum_probe_age)
            .ok_or(CustodyError::ArithmeticOverflow)?,
    );
    for x in c {
        end = end.min(x.ends_at);
        let p = profiles
            .get(&x.custodian_profile_id)
            .ok_or(CustodyError::UnknownId)?;
        end = end
            .min(p.profile_expires)
            .min(p.control_attestation_expires);
    }
    for p in probes {
        end = end.min(
            p.observed_at
                .checked_add(policy.maximum_probe_age)
                .ok_or(CustodyError::ArithmeticOverflow)?,
        );
    }
    for id in selected {
        end = end.min(
            executors
                .iter()
                .find(|e| e.executor_id == *id)
                .ok_or(CustodyError::UnknownId)?
                .expires_at,
        );
    }
    if end <= issued {
        Err(CustodyError::Expired)
    } else {
        Ok(end)
    }
}
fn live_deduplicated<'a>(
    c: &'a [CustodyPositionCommitmentV2],
    p: &BTreeMap<Hash32, CustodianProfileV2>,
    at: u64,
) -> Vec<&'a CustodyPositionCommitmentV2> {
    let mut controls = BTreeSet::new();
    let mut positions = BTreeSet::new();
    c.iter()
        .filter(|x| x.starts_at <= at && at < x.ends_at)
        .filter(|x| {
            p.get(&x.custodian_profile_id).is_some_and(|v| {
                at < v.profile_expires
                    && at < v.control_attestation_expires
                    && controls.insert(v.beneficial_control_root)
                    && positions.insert(x.position)
            })
        })
        .collect()
}
fn strict_positions(p: &[PositionChallengeV2]) -> bool {
    p.windows(2).all(|w| w[0].position < w[1].position)
}
fn strict_ids(v: &[Hash32]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}
fn digest(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}
fn sign(k: &Keypair, domain: &[u8], id: &Hash32, body: &[u8]) -> Result<[u8; 64], CustodyError> {
    k.sign_domain(DomainId::SigWwm, &[domain, id, body])
        .map(Signature::into_bytes)
        .map_err(|_| CustodyError::InvalidSignature)
}
fn verify(
    k: &Hash32,
    domain: &[u8],
    id: &Hash32,
    body: &[u8],
    s: &[u8; 64],
) -> Result<(), CustodyError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(*k),
        &[domain, id, body],
        &Signature::from_bytes(*s),
    )
    .map_err(|_| CustodyError::InvalidSignature)
}
fn hash(out: &mut Vec<u8>, h: &Hash32) {
    out.extend_from_slice(h)
}
fn hashes(out: &mut Vec<u8>, v: &[Hash32]) {
    for h in v {
        hash(out, h)
    }
}
fn u32le(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_le_bytes())
}
fn u64le(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_le_bytes())
}
fn u128le(o: &mut Vec<u8>, v: u128) {
    o.extend_from_slice(&v.to_le_bytes())
}
fn flatten_hashes(v: &[Hash32]) -> Vec<u8> {
    v.iter().flatten().copied().collect()
}
