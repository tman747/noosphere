//! WWM P1 private-job envelope and composite CPU/GPU attestation admission.
//!
//! Prompt encryption uses RFC 9180 HPKE base mode with
//! X25519-HKDF-SHA256, HKDF-SHA256, and ChaCha20-Poly1305. Keys are released
//! only after a caller-supplied hardware verifier admits the complete pinned
//! tuple. The hardware verifier and forensic evidence remain external gates;
//! P1 activation is hard disabled.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use rand_core::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];
type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub const PRIVATE_JOB_VERSION: u16 = 1;
pub const MAX_PRIVATE_PROMPT_BYTES: usize = 48_000;
pub const MAX_PRIVATE_CONTEXT_BYTES: usize = 512 * 1024;
pub const MAX_PRIVATE_ATTACHMENT_ROOTS: usize = 32;
pub const PRIVATE_BUCKETS: [usize; 3] = [64 * 1024, 256 * 1024, 1024 * 1024];
pub const WWM_P1_PRIVATE_JOBS_ENABLED: bool = false;
pub const WWM_PRIVATE_JOB_CONSENSUS_WEIGHT: u64 = 0;
const HPKE_INFO: &[u8] = b"NOOS/WWM/P1/HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305/V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateJobError {
    InvalidPolicy,
    InvalidSignature,
    DuplicatePolicy,
    UnknownPolicy,
    InvalidQuote,
    QuoteRejected,
    StaleQuote,
    RevokedMeasurement,
    ChallengeMismatch,
    ChallengeReplay,
    Rollback,
    InvalidEnvelope,
    InvalidPayload,
    InvalidBucket,
    Hpke,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeAttestationPolicy {
    pub owner_key: Hash32,
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub capsule_id: Hash32,
    pub numeric_profile_id: Hash32,
    pub decoding_profile_id: Hash32,
    pub allowed_cpu_measurements: Vec<Hash32>,
    pub allowed_gpu_measurements: Vec<Hash32>,
    pub allowed_firmware_roots: Vec<Hash32>,
    pub runtime_root: Hash32,
    pub container_root: Hash32,
    pub attestation_trust_root: Hash32,
    pub minimum_cpu_security_version: u32,
    pub minimum_gpu_security_version: u32,
    pub revocation_epoch: u64,
    pub maximum_quote_age_seconds: u64,
    pub maximum_session_seconds: u64,
    pub policy_id: Hash32,
    pub signature: [u8; 64],
}

impl CompositeAttestationPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: &Keypair,
        chain_id: Hash32,
        genesis_hash: Hash32,
        capsule_id: Hash32,
        numeric_profile_id: Hash32,
        decoding_profile_id: Hash32,
        allowed_cpu_measurements: Vec<Hash32>,
        allowed_gpu_measurements: Vec<Hash32>,
        allowed_firmware_roots: Vec<Hash32>,
        runtime_root: Hash32,
        container_root: Hash32,
        attestation_trust_root: Hash32,
        minimum_cpu_security_version: u32,
        minimum_gpu_security_version: u32,
        revocation_epoch: u64,
        maximum_quote_age_seconds: u64,
        maximum_session_seconds: u64,
    ) -> Result<Self, PrivateJobError> {
        let mut value = Self {
            owner_key: owner.public_key().into_bytes(),
            chain_id,
            genesis_hash,
            capsule_id,
            numeric_profile_id,
            decoding_profile_id,
            allowed_cpu_measurements,
            allowed_gpu_measurements,
            allowed_firmware_roots,
            runtime_root,
            container_root,
            attestation_trust_root,
            minimum_cpu_security_version,
            minimum_gpu_security_version,
            revocation_epoch,
            maximum_quote_age_seconds,
            maximum_session_seconds,
            policy_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.policy_id = digest(DomainId::WwmAttestationPolicy, &[&body])?;
        value.signature = sign(
            owner,
            DomainId::WwmAttestationPolicy,
            value.policy_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PrivateJobError> {
        let body = self.body()?;
        if self.policy_id == [0; 32]
            || digest(DomainId::WwmAttestationPolicy, &[&body])? != self.policy_id
        {
            return Err(PrivateJobError::InvalidPolicy);
        }
        verify(
            self.owner_key,
            DomainId::WwmAttestationPolicy,
            self.policy_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, PrivateJobError> {
        let fixed_roots = [
            self.owner_key,
            self.chain_id,
            self.genesis_hash,
            self.capsule_id,
            self.numeric_profile_id,
            self.decoding_profile_id,
            self.runtime_root,
            self.container_root,
            self.attestation_trust_root,
        ];
        if fixed_roots.contains(&[0; 32])
            || self.allowed_cpu_measurements.is_empty()
            || !strictly_sorted(&self.allowed_cpu_measurements)
            || self.allowed_cpu_measurements.contains(&[0; 32])
            || self.allowed_gpu_measurements.is_empty()
            || !strictly_sorted(&self.allowed_gpu_measurements)
            || self.allowed_gpu_measurements.contains(&[0; 32])
            || self.allowed_firmware_roots.is_empty()
            || !strictly_sorted(&self.allowed_firmware_roots)
            || self.allowed_firmware_roots.contains(&[0; 32])
            || self.minimum_cpu_security_version == 0
            || self.minimum_gpu_security_version == 0
            || self.revocation_epoch == 0
            || self.maximum_quote_age_seconds == 0
            || self.maximum_session_seconds == 0
            || self.maximum_session_seconds > self.maximum_quote_age_seconds
        {
            return Err(PrivateJobError::InvalidPolicy);
        }
        let mut body = Vec::with_capacity(640);
        body.extend(PRIVATE_JOB_VERSION.to_le_bytes());
        for root in fixed_roots {
            body.extend(root);
        }
        push_hashes(&mut body, &self.allowed_cpu_measurements)?;
        push_hashes(&mut body, &self.allowed_gpu_measurements)?;
        push_hashes(&mut body, &self.allowed_firmware_roots)?;
        body.extend(self.minimum_cpu_security_version.to_le_bytes());
        body.extend(self.minimum_gpu_security_version.to_le_bytes());
        body.extend(self.revocation_epoch.to_le_bytes());
        body.extend(self.maximum_quote_age_seconds.to_le_bytes());
        body.extend(self.maximum_session_seconds.to_le_bytes());
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeAttestationQuote {
    pub policy_id: Hash32,
    pub executor_identity: Hash32,
    pub cpu_measurement: Hash32,
    pub gpu_measurement: Hash32,
    pub firmware_root: Hash32,
    pub runtime_root: Hash32,
    pub container_root: Hash32,
    pub capsule_id: Hash32,
    pub numeric_profile_id: Hash32,
    pub decoding_profile_id: Hash32,
    pub recipient_hpke_public_key: [u8; 32],
    pub cpu_security_version: u32,
    pub gpu_security_version: u32,
    pub rollback_counter: u64,
    pub revocation_epoch: u64,
    pub challenge: Hash32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub raw_quote: Vec<u8>,
    pub quote_id: Hash32,
}

impl CompositeAttestationQuote {
    pub fn report_data(&self) -> Result<Hash32, PrivateJobError> {
        let body = self.body()?;
        digest(DomainId::WwmAttestationQuote, &[b"REPORT-DATA", &body])
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, PrivateJobError> {
        if self.quote_id != [0; 32] || self.raw_quote.is_empty() {
            return Err(PrivateJobError::InvalidQuote);
        }
        let body = self.body()?;
        self.quote_id = digest(
            DomainId::WwmAttestationQuote,
            &[
                &body,
                &digest(DomainId::WwmAttestationQuote, &[b"RAW", &self.raw_quote])?,
            ],
        )?;
        Ok(self.quote_id)
    }

    pub fn validate_id(&self) -> Result<(), PrivateJobError> {
        if self.quote_id == [0; 32] || self.raw_quote.is_empty() {
            return Err(PrivateJobError::InvalidQuote);
        }
        let body = self.body()?;
        let expected = digest(
            DomainId::WwmAttestationQuote,
            &[
                &body,
                &digest(DomainId::WwmAttestationQuote, &[b"RAW", &self.raw_quote])?,
            ],
        )?;
        if expected != self.quote_id {
            return Err(PrivateJobError::InvalidQuote);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, PrivateJobError> {
        let roots = [
            self.policy_id,
            self.executor_identity,
            self.cpu_measurement,
            self.gpu_measurement,
            self.firmware_root,
            self.runtime_root,
            self.container_root,
            self.capsule_id,
            self.numeric_profile_id,
            self.decoding_profile_id,
            self.recipient_hpke_public_key,
            self.challenge,
        ];
        if roots.contains(&[0; 32])
            || self.cpu_security_version == 0
            || self.gpu_security_version == 0
            || self.rollback_counter == 0
            || self.revocation_epoch == 0
            || self.issued_at == 0
            || self.issued_at >= self.expires_at
        {
            return Err(PrivateJobError::InvalidQuote);
        }
        let mut body = Vec::with_capacity(430);
        body.extend(PRIVATE_JOB_VERSION.to_le_bytes());
        for root in roots {
            body.extend(root);
        }
        body.extend(self.cpu_security_version.to_le_bytes());
        body.extend(self.gpu_security_version.to_le_bytes());
        body.extend(self.rollback_counter.to_le_bytes());
        body.extend(self.revocation_epoch.to_le_bytes());
        body.extend(self.issued_at.to_le_bytes());
        body.extend(self.expires_at.to_le_bytes());
        Ok(body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCompositeAttestation {
    pub attestation_trust_root: Hash32,
    pub executor_identity: Hash32,
    pub cpu_measurement: Hash32,
    pub gpu_measurement: Hash32,
    pub firmware_root: Hash32,
    pub runtime_root: Hash32,
    pub container_root: Hash32,
    pub recipient_hpke_public_key: [u8; 32],
    pub cpu_security_version: u32,
    pub gpu_security_version: u32,
    pub rollback_counter: u64,
    pub revocation_epoch: u64,
}

pub trait CompositeQuoteVerifier {
    fn verify(
        &self,
        raw_quote: &[u8],
        expected_report_data: Hash32,
    ) -> Result<VerifiedCompositeAttestation, PrivateJobError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedWorkload {
    pub quote_id: Hash32,
    pub policy_id: Hash32,
    pub executor_identity: Hash32,
    pub recipient_hpke_public_key: [u8; 32],
    pub expires_at: u64,
}

#[derive(Debug, Default)]
pub struct CompositeAttestationRegistry {
    policies: BTreeMap<Hash32, CompositeAttestationPolicy>,
    revoked_measurements: BTreeMap<Hash32, u64>,
    seen_challenges: BTreeSet<Hash32>,
    high_rollback_counters: BTreeMap<Hash32, u64>,
}

impl CompositeAttestationRegistry {
    pub fn register_policy(
        &mut self,
        policy: CompositeAttestationPolicy,
    ) -> Result<(), PrivateJobError> {
        policy.validate()?;
        if self.policies.contains_key(&policy.policy_id) {
            return Err(PrivateJobError::DuplicatePolicy);
        }
        self.policies.insert(policy.policy_id, policy);
        Ok(())
    }

    pub fn revoke_measurement(
        &mut self,
        measurement: Hash32,
        revocation_epoch: u64,
    ) -> Result<(), PrivateJobError> {
        if measurement == [0; 32] || revocation_epoch == 0 {
            return Err(PrivateJobError::InvalidPolicy);
        }
        self.revoked_measurements
            .entry(measurement)
            .and_modify(|epoch| *epoch = (*epoch).min(revocation_epoch))
            .or_insert(revocation_epoch);
        Ok(())
    }

    pub fn admit(
        &mut self,
        quote: &CompositeAttestationQuote,
        expected_challenge: Hash32,
        now: u64,
        verifier: &dyn CompositeQuoteVerifier,
    ) -> Result<AdmittedWorkload, PrivateJobError> {
        quote.validate_id()?;
        let policy = self
            .policies
            .get(&quote.policy_id)
            .ok_or(PrivateJobError::UnknownPolicy)?;
        if expected_challenge == [0; 32] || quote.challenge != expected_challenge {
            return Err(PrivateJobError::ChallengeMismatch);
        }
        if self.seen_challenges.contains(&expected_challenge) {
            return Err(PrivateJobError::ChallengeReplay);
        }
        let latest = quote
            .issued_at
            .checked_add(policy.maximum_quote_age_seconds)
            .ok_or(PrivateJobError::ArithmeticOverflow)?;
        let session_duration = quote
            .expires_at
            .checked_sub(quote.issued_at)
            .ok_or(PrivateJobError::StaleQuote)?;
        if quote.issued_at > now
            || now >= quote.expires_at
            || quote.expires_at > latest
            || session_duration > policy.maximum_session_seconds
        {
            return Err(PrivateJobError::StaleQuote);
        }
        if quote.capsule_id != policy.capsule_id
            || quote.numeric_profile_id != policy.numeric_profile_id
            || quote.decoding_profile_id != policy.decoding_profile_id
            || quote.runtime_root != policy.runtime_root
            || quote.container_root != policy.container_root
            || quote.revocation_epoch != policy.revocation_epoch
            || !policy
                .allowed_cpu_measurements
                .contains(&quote.cpu_measurement)
            || !policy
                .allowed_gpu_measurements
                .contains(&quote.gpu_measurement)
            || !policy.allowed_firmware_roots.contains(&quote.firmware_root)
            || quote.cpu_security_version < policy.minimum_cpu_security_version
            || quote.gpu_security_version < policy.minimum_gpu_security_version
        {
            return Err(PrivateJobError::QuoteRejected);
        }
        for measurement in [
            quote.cpu_measurement,
            quote.gpu_measurement,
            quote.firmware_root,
        ] {
            if self
                .revoked_measurements
                .get(&measurement)
                .is_some_and(|epoch| *epoch <= quote.revocation_epoch)
            {
                return Err(PrivateJobError::RevokedMeasurement);
            }
        }
        let verified = verifier.verify(&quote.raw_quote, quote.report_data()?)?;
        if verified.attestation_trust_root != policy.attestation_trust_root
            || verified.executor_identity != quote.executor_identity
            || verified.cpu_measurement != quote.cpu_measurement
            || verified.gpu_measurement != quote.gpu_measurement
            || verified.firmware_root != quote.firmware_root
            || verified.runtime_root != quote.runtime_root
            || verified.container_root != quote.container_root
            || verified.recipient_hpke_public_key != quote.recipient_hpke_public_key
            || verified.cpu_security_version != quote.cpu_security_version
            || verified.gpu_security_version != quote.gpu_security_version
            || verified.rollback_counter != quote.rollback_counter
            || verified.revocation_epoch != quote.revocation_epoch
        {
            return Err(PrivateJobError::QuoteRejected);
        }
        if self
            .high_rollback_counters
            .get(&quote.executor_identity)
            .is_some_and(|prior| quote.rollback_counter <= *prior)
        {
            return Err(PrivateJobError::Rollback);
        }
        self.seen_challenges.insert(expected_challenge);
        self.high_rollback_counters
            .insert(quote.executor_identity, quote.rollback_counter);
        Ok(AdmittedWorkload {
            quote_id: quote.quote_id,
            policy_id: quote.policy_id,
            executor_identity: quote.executor_identity,
            recipient_hpke_public_key: quote.recipient_hpke_public_key,
            expires_at: quote.expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateJobAad {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub capsule_id: Hash32,
    pub policy_id: Hash32,
    pub quote_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub route_policy_id: Hash32,
    pub client_nonce: Hash32,
    pub plaintext_bucket_bytes: u32,
}

impl PrivateJobAad {
    fn encode(&self) -> Result<Vec<u8>, PrivateJobError> {
        let roots = [
            self.chain_id,
            self.genesis_hash,
            self.capsule_id,
            self.policy_id,
            self.quote_id,
            self.knowledge_snapshot_id,
            self.route_policy_id,
            self.client_nonce,
        ];
        if roots.contains(&[0; 32])
            || !PRIVATE_BUCKETS.contains(
                &usize::try_from(self.plaintext_bucket_bytes)
                    .map_err(|_| PrivateJobError::InvalidBucket)?,
            )
        {
            return Err(PrivateJobError::InvalidEnvelope);
        }
        let mut out = Vec::with_capacity(262);
        out.extend(PRIVATE_JOB_VERSION.to_le_bytes());
        for root in roots {
            out.extend(root);
        }
        out.extend(self.plaintext_bucket_bytes.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug)]
pub struct PrivateJobPayload {
    prompt: Vec<u8>,
    retrieved_context: Vec<u8>,
    attachment_roots: Vec<Hash32>,
    output_key: [u8; 32],
    zeroized: bool,
}

impl PrivateJobPayload {
    pub fn new(
        prompt: Vec<u8>,
        retrieved_context: Vec<u8>,
        attachment_roots: Vec<Hash32>,
        output_key: [u8; 32],
    ) -> Result<Self, PrivateJobError> {
        if prompt.is_empty()
            || prompt.len() > MAX_PRIVATE_PROMPT_BYTES
            || retrieved_context.len() > MAX_PRIVATE_CONTEXT_BYTES
            || attachment_roots.len() > MAX_PRIVATE_ATTACHMENT_ROOTS
            || !strictly_sorted(&attachment_roots)
            || attachment_roots.contains(&[0; 32])
            || output_key == [0; 32]
        {
            return Err(PrivateJobError::InvalidPayload);
        }
        Ok(Self {
            prompt,
            retrieved_context,
            attachment_roots,
            output_key,
            zeroized: false,
        })
    }

    #[must_use]
    pub fn prompt(&self) -> &[u8] {
        &self.prompt
    }

    #[must_use]
    pub fn retrieved_context(&self) -> &[u8] {
        &self.retrieved_context
    }

    #[must_use]
    pub fn attachment_roots(&self) -> &[Hash32] {
        &self.attachment_roots
    }

    #[must_use]
    pub fn output_key(&self) -> &[u8; 32] {
        &self.output_key
    }

    pub fn zeroize(&mut self) {
        self.prompt.fill(0);
        self.retrieved_context.fill(0);
        self.output_key.fill(0);
        self.zeroized = true;
    }

    #[must_use]
    pub fn is_zeroized(&self) -> bool {
        self.zeroized
            && self.prompt.iter().all(|byte| *byte == 0)
            && self.retrieved_context.iter().all(|byte| *byte == 0)
            && self.output_key == [0; 32]
    }

    fn encode_padded(&self, bucket: usize) -> Result<Vec<u8>, PrivateJobError> {
        if self.zeroized || !PRIVATE_BUCKETS.contains(&bucket) {
            return Err(PrivateJobError::InvalidPayload);
        }
        let prompt_len =
            u32::try_from(self.prompt.len()).map_err(|_| PrivateJobError::ArithmeticOverflow)?;
        let context_len = u32::try_from(self.retrieved_context.len())
            .map_err(|_| PrivateJobError::ArithmeticOverflow)?;
        let attachment_count = u16::try_from(self.attachment_roots.len())
            .map_err(|_| PrivateJobError::ArithmeticOverflow)?;
        let body_len = 2_usize
            .checked_add(4)
            .and_then(|value| value.checked_add(self.prompt.len()))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(self.retrieved_context.len()))
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(self.attachment_roots.len().checked_mul(32)?))
            .and_then(|value| value.checked_add(32))
            .ok_or(PrivateJobError::ArithmeticOverflow)?;
        let framed_len = body_len
            .checked_add(4)
            .ok_or(PrivateJobError::ArithmeticOverflow)?;
        if framed_len > bucket {
            return Err(PrivateJobError::InvalidBucket);
        }
        let mut out = Vec::with_capacity(bucket);
        out.extend(
            u32::try_from(body_len)
                .map_err(|_| PrivateJobError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        out.extend(PRIVATE_JOB_VERSION.to_le_bytes());
        out.extend(prompt_len.to_le_bytes());
        out.extend(&self.prompt);
        out.extend(context_len.to_le_bytes());
        out.extend(&self.retrieved_context);
        out.extend(attachment_count.to_le_bytes());
        for root in &self.attachment_roots {
            out.extend(root);
        }
        out.extend(self.output_key);
        out.resize(bucket, 0);
        Ok(out)
    }

    fn decode_padded(bytes: &[u8]) -> Result<Self, PrivateJobError> {
        if !PRIVATE_BUCKETS.contains(&bytes.len()) || bytes.len() < 6 {
            return Err(PrivateJobError::InvalidBucket);
        }
        let mut offset = 0;
        let body_len = usize::try_from(take_u32(bytes, &mut offset)?)
            .map_err(|_| PrivateJobError::InvalidPayload)?;
        let body_end = 4_usize
            .checked_add(body_len)
            .ok_or(PrivateJobError::ArithmeticOverflow)?;
        if body_end > bytes.len() || bytes[body_end..].iter().any(|byte| *byte != 0) {
            return Err(PrivateJobError::InvalidPayload);
        }
        if take_u16(bytes, &mut offset)? != PRIVATE_JOB_VERSION {
            return Err(PrivateJobError::InvalidPayload);
        }
        let prompt_len = usize::try_from(take_u32(bytes, &mut offset)?)
            .map_err(|_| PrivateJobError::InvalidPayload)?;
        let prompt = take_vec(bytes, &mut offset, prompt_len)?;
        let context_len = usize::try_from(take_u32(bytes, &mut offset)?)
            .map_err(|_| PrivateJobError::InvalidPayload)?;
        let retrieved_context = take_vec(bytes, &mut offset, context_len)?;
        let attachment_count = usize::from(take_u16(bytes, &mut offset)?);
        if attachment_count > MAX_PRIVATE_ATTACHMENT_ROOTS {
            return Err(PrivateJobError::InvalidPayload);
        }
        let mut attachment_roots = Vec::with_capacity(attachment_count);
        for _ in 0..attachment_count {
            attachment_roots.push(take_array::<32>(bytes, &mut offset)?);
        }
        let output_key = take_array::<32>(bytes, &mut offset)?;
        if offset != body_end {
            return Err(PrivateJobError::InvalidPayload);
        }
        Self::new(prompt, retrieved_context, attachment_roots, output_key)
    }
}

impl Drop for PrivateJobPayload {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateJobEnvelope {
    pub aad: PrivateJobAad,
    pub encapsulated_key: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub envelope_id: Hash32,
}

pub fn generate_hpke_keypair<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<([u8; 32], [u8; 32]), PrivateJobError> {
    let (private, public) = Kem::gen_keypair(rng);
    Ok((
        fixed_bytes(private.to_bytes().as_slice())?,
        fixed_bytes(public.to_bytes().as_slice())?,
    ))
}

pub fn seal_private_job<R: CryptoRng + RngCore>(
    admitted: &AdmittedWorkload,
    aad: PrivateJobAad,
    payload: &PrivateJobPayload,
    rng: &mut R,
) -> Result<PrivateJobEnvelope, PrivateJobError> {
    if aad.policy_id != admitted.policy_id || aad.quote_id != admitted.quote_id {
        return Err(PrivateJobError::InvalidEnvelope);
    }
    let aad_bytes = aad.encode()?;
    let bucket =
        usize::try_from(aad.plaintext_bucket_bytes).map_err(|_| PrivateJobError::InvalidBucket)?;
    let mut plaintext = payload.encode_padded(bucket)?;
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&admitted.recipient_hpke_public_key)
        .map_err(|_| PrivateJobError::Hpke)?;
    let (encapped, ciphertext) = single_shot_seal::<Aead, Kdf, Kem, R>(
        &OpModeS::Base,
        &recipient,
        HPKE_INFO,
        &plaintext,
        &aad_bytes,
        rng,
    )
    .map_err(|_| PrivateJobError::Hpke)?;
    plaintext.fill(0);
    let encapsulated_key = fixed_bytes(encapped.to_bytes().as_slice())?;
    let envelope_id = digest(
        DomainId::WwmPrivateEnvelope,
        &[&aad_bytes, &encapsulated_key, &ciphertext],
    )?;
    Ok(PrivateJobEnvelope {
        aad,
        encapsulated_key,
        ciphertext,
        envelope_id,
    })
}

pub fn open_private_job(
    recipient_private_key: [u8; 32],
    envelope: &PrivateJobEnvelope,
) -> Result<PrivateJobPayload, PrivateJobError> {
    let aad = envelope.aad.encode()?;
    if envelope.envelope_id == [0; 32]
        || digest(
            DomainId::WwmPrivateEnvelope,
            &[&aad, &envelope.encapsulated_key, &envelope.ciphertext],
        )? != envelope.envelope_id
    {
        return Err(PrivateJobError::InvalidEnvelope);
    }
    let private = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private_key)
        .map_err(|_| PrivateJobError::Hpke)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.encapsulated_key)
        .map_err(|_| PrivateJobError::Hpke)?;
    let mut plaintext = single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private,
        &encapped,
        HPKE_INFO,
        &envelope.ciphertext,
        &aad,
    )
    .map_err(|_| PrivateJobError::Hpke)?;
    let result = PrivateJobPayload::decode_padded(&plaintext);
    plaintext.fill(0);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateJobDisposition {
    Completed = 1,
    Cancelled = 2,
    TimedOut = 3,
    Refunded = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedPrivateReceipt {
    pub job_handle: Hash32,
    pub envelope_id: Hash32,
    pub policy_id: Hash32,
    pub quote_id: Hash32,
    pub output_ciphertext_root: Hash32,
    pub disposition: PrivateJobDisposition,
    pub charged_micro_noos: u64,
    pub refunded_micro_noos: u64,
    pub unlinkability_nonce: Hash32,
    pub receipt_id: Hash32,
}

impl BlindedPrivateReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_handle: Hash32,
        envelope_id: Hash32,
        policy_id: Hash32,
        quote_id: Hash32,
        output_ciphertext_root: Hash32,
        disposition: PrivateJobDisposition,
        charged_micro_noos: u64,
        refunded_micro_noos: u64,
        unlinkability_nonce: Hash32,
    ) -> Result<Self, PrivateJobError> {
        let mut value = Self {
            job_handle,
            envelope_id,
            policy_id,
            quote_id,
            output_ciphertext_root,
            disposition,
            charged_micro_noos,
            refunded_micro_noos,
            unlinkability_nonce,
            receipt_id: [0; 32],
        };
        let body = value.body()?;
        value.receipt_id = digest(DomainId::WwmBlindedReceipt, &[&body])?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PrivateJobError> {
        let body = self.body()?;
        if self.receipt_id == [0; 32]
            || digest(DomainId::WwmBlindedReceipt, &[&body])? != self.receipt_id
        {
            return Err(PrivateJobError::InvalidEnvelope);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, PrivateJobError> {
        if [
            self.job_handle,
            self.envelope_id,
            self.policy_id,
            self.quote_id,
            self.output_ciphertext_root,
            self.unlinkability_nonce,
        ]
        .contains(&[0; 32])
        {
            return Err(PrivateJobError::InvalidEnvelope);
        }
        let mut body = Vec::with_capacity(210);
        body.extend(PRIVATE_JOB_VERSION.to_le_bytes());
        body.extend(self.job_handle);
        body.extend(self.envelope_id);
        body.extend(self.policy_id);
        body.extend(self.quote_id);
        body.extend(self.output_ciphertext_root);
        body.push(self.disposition as u8);
        body.extend(self.charged_micro_noos.to_le_bytes());
        body.extend(self.refunded_micro_noos.to_le_bytes());
        body.extend(self.unlinkability_nonce);
        Ok(body)
    }
}

fn fixed_bytes(bytes: &[u8]) -> Result<[u8; 32], PrivateJobError> {
    bytes.try_into().map_err(|_| PrivateJobError::Hpke)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], PrivateJobError> {
    let end = offset
        .checked_add(N)
        .ok_or(PrivateJobError::ArithmeticOverflow)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(PrivateJobError::InvalidPayload)?
        .try_into()
        .map_err(|_| PrivateJobError::InvalidPayload)?;
    *offset = end;
    Ok(value)
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, PrivateJobError> {
    Ok(u16::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, PrivateJobError> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_vec(bytes: &[u8], offset: &mut usize, length: usize) -> Result<Vec<u8>, PrivateJobError> {
    let end = offset
        .checked_add(length)
        .ok_or(PrivateJobError::ArithmeticOverflow)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(PrivateJobError::InvalidPayload)?
        .to_vec();
    *offset = end;
    Ok(value)
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), PrivateJobError> {
    let count = u16::try_from(values.len()).map_err(|_| PrivateJobError::ArithmeticOverflow)?;
    out.extend(count.to_le_bytes());
    for value in values {
        out.extend(value);
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, PrivateJobError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| PrivateJobError::InvalidEnvelope)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], PrivateJobError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| PrivateJobError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), PrivateJobError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| PrivateJobError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn policy() -> CompositeAttestationPolicy {
        CompositeAttestationPolicy::new(
            &Keypair::from_seed([1; 32]),
            h(2),
            h(3),
            h(4),
            h(5),
            h(6),
            vec![h(7)],
            vec![h(8)],
            vec![h(9)],
            h(10),
            h(11),
            h(12),
            3,
            4,
            5,
            60,
            30,
        )
        .unwrap()
    }

    fn quote(
        public_key: [u8; 32],
        policy: &CompositeAttestationPolicy,
        counter: u64,
        challenge: Hash32,
    ) -> CompositeAttestationQuote {
        let mut quote = CompositeAttestationQuote {
            policy_id: policy.policy_id,
            executor_identity: h(13),
            cpu_measurement: h(7),
            gpu_measurement: h(8),
            firmware_root: h(9),
            runtime_root: h(10),
            container_root: h(11),
            capsule_id: h(4),
            numeric_profile_id: h(5),
            decoding_profile_id: h(6),
            recipient_hpke_public_key: public_key,
            cpu_security_version: 3,
            gpu_security_version: 4,
            rollback_counter: counter,
            revocation_epoch: 5,
            challenge,
            issued_at: 100,
            expires_at: 125,
            raw_quote: Vec::new(),
            quote_id: [0; 32],
        };
        quote.raw_quote = quote.report_data().unwrap().to_vec();
        quote.finalize_id().unwrap();
        quote
    }

    struct Verifier {
        verified: VerifiedCompositeAttestation,
    }

    impl CompositeQuoteVerifier for Verifier {
        fn verify(
            &self,
            raw_quote: &[u8],
            expected_report_data: Hash32,
        ) -> Result<VerifiedCompositeAttestation, PrivateJobError> {
            if raw_quote != expected_report_data {
                return Err(PrivateJobError::QuoteRejected);
            }
            Ok(self.verified.clone())
        }
    }

    fn verifier(quote: &CompositeAttestationQuote) -> Verifier {
        Verifier {
            verified: VerifiedCompositeAttestation {
                attestation_trust_root: h(12),
                executor_identity: quote.executor_identity,
                cpu_measurement: quote.cpu_measurement,
                gpu_measurement: quote.gpu_measurement,
                firmware_root: quote.firmware_root,
                runtime_root: quote.runtime_root,
                container_root: quote.container_root,
                recipient_hpke_public_key: quote.recipient_hpke_public_key,
                cpu_security_version: quote.cpu_security_version,
                gpu_security_version: quote.gpu_security_version,
                rollback_counter: quote.rollback_counter,
                revocation_epoch: quote.revocation_epoch,
            },
        }
    }

    fn aad(
        policy: &CompositeAttestationPolicy,
        quote: &CompositeAttestationQuote,
        bucket: usize,
    ) -> PrivateJobAad {
        PrivateJobAad {
            chain_id: h(2),
            genesis_hash: h(3),
            capsule_id: h(4),
            policy_id: policy.policy_id,
            quote_id: quote.quote_id,
            knowledge_snapshot_id: h(20),
            route_policy_id: h(21),
            client_nonce: h(22),
            plaintext_bucket_bytes: u32::try_from(bucket).unwrap(),
        }
    }

    #[test]
    fn admitted_composite_quote_releases_hpke_session_only_to_workload() {
        let mut rng = StdRng::from_seed([44; 32]);
        let (private_key, public_key) = generate_hpke_keypair(&mut rng).unwrap();
        let policy = policy();
        let quote = quote(public_key, &policy, 1, h(30));
        let mut registry = CompositeAttestationRegistry::default();
        registry.register_policy(policy.clone()).unwrap();
        let admitted = registry
            .admit(&quote, h(30), 110, &verifier(&quote))
            .unwrap();
        let payload = PrivateJobPayload::new(
            b"private prompt".to_vec(),
            b"private retrieval context".to_vec(),
            vec![h(31)],
            h(32),
        )
        .unwrap();
        let envelope = seal_private_job(
            &admitted,
            aad(&policy, &quote, PRIVATE_BUCKETS[0]),
            &payload,
            &mut rng,
        )
        .unwrap();
        let opened = open_private_job(private_key, &envelope).unwrap();
        assert_eq!(opened.prompt(), b"private prompt");
        assert_eq!(opened.retrieved_context(), b"private retrieval context");
        assert_eq!(envelope.ciphertext.len(), PRIVATE_BUCKETS[0] + 16);
        assert!(matches!(
            open_private_job([99; 32], &envelope),
            Err(PrivateJobError::Hpke)
        ));
    }

    #[test]
    fn replay_rollback_revocation_and_wrong_gpu_fail_closed() {
        let mut rng = StdRng::from_seed([45; 32]);
        let (_, public_key) = generate_hpke_keypair(&mut rng).unwrap();
        let policy = policy();
        let attestation_quote = quote(public_key, &policy, 2, h(33));
        let mut registry = CompositeAttestationRegistry::default();
        registry.register_policy(policy.clone()).unwrap();
        registry
            .admit(
                &attestation_quote,
                h(33),
                110,
                &verifier(&attestation_quote),
            )
            .unwrap();
        assert_eq!(
            registry.admit(
                &attestation_quote,
                h(33),
                110,
                &verifier(&attestation_quote),
            ),
            Err(PrivateJobError::ChallengeReplay)
        );
        let rollback = quote(public_key, &policy, 1, h(34));
        assert_eq!(
            registry.admit(&rollback, h(34), 110, &verifier(&rollback)),
            Err(PrivateJobError::Rollback)
        );

        let mut revoked_registry = CompositeAttestationRegistry::default();
        revoked_registry.register_policy(policy.clone()).unwrap();
        revoked_registry.revoke_measurement(h(8), 5).unwrap();
        let revoked = quote(public_key, &policy, 3, h(35));
        assert_eq!(
            revoked_registry.admit(&revoked, h(35), 110, &verifier(&revoked)),
            Err(PrivateJobError::RevokedMeasurement)
        );

        let mut wrong_gpu = quote(public_key, &policy, 4, h(36));
        wrong_gpu.gpu_measurement = h(99);
        wrong_gpu.quote_id = [0; 32];
        wrong_gpu.raw_quote = wrong_gpu.report_data().unwrap().to_vec();
        wrong_gpu.finalize_id().unwrap();
        assert_eq!(
            CompositeAttestationRegistry::default().admit(
                &wrong_gpu,
                h(36),
                110,
                &verifier(&wrong_gpu)
            ),
            Err(PrivateJobError::UnknownPolicy)
        );
        let mut wrong_registry = CompositeAttestationRegistry::default();
        wrong_registry.register_policy(policy).unwrap();
        assert_eq!(
            wrong_registry.admit(&wrong_gpu, h(36), 110, &verifier(&wrong_gpu)),
            Err(PrivateJobError::QuoteRejected)
        );
    }

    #[test]
    fn buckets_hide_plaintext_length_and_tampering_rejects() {
        let mut rng = StdRng::from_seed([46; 32]);
        let (private_key, public_key) = generate_hpke_keypair(&mut rng).unwrap();
        let policy = policy();
        let quote = quote(public_key, &policy, 1, h(40));
        let mut registry = CompositeAttestationRegistry::default();
        registry.register_policy(policy.clone()).unwrap();
        let admitted = registry
            .admit(&quote, h(40), 110, &verifier(&quote))
            .unwrap();
        let short = PrivateJobPayload::new(vec![1], vec![], vec![], h(50)).unwrap();
        let long = PrivateJobPayload::new(vec![2; 20_000], vec![], vec![], h(51)).unwrap();
        let first = seal_private_job(
            &admitted,
            aad(&policy, &quote, PRIVATE_BUCKETS[0]),
            &short,
            &mut rng,
        )
        .unwrap();
        let second = seal_private_job(
            &admitted,
            aad(&policy, &quote, PRIVATE_BUCKETS[0]),
            &long,
            &mut rng,
        )
        .unwrap();
        assert_eq!(first.ciphertext.len(), second.ciphertext.len());
        let mut tampered = first;
        tampered.ciphertext[0] ^= 1;
        tampered.envelope_id = digest(
            DomainId::WwmPrivateEnvelope,
            &[
                &tampered.aad.encode().unwrap(),
                &tampered.encapsulated_key,
                &tampered.ciphertext,
            ],
        )
        .unwrap();
        assert!(matches!(
            open_private_job(private_key, &tampered),
            Err(PrivateJobError::Hpke)
        ));
    }

    #[test]
    fn payload_zeroization_and_private_controls_are_explicit() {
        let mut payload =
            PrivateJobPayload::new(b"secret".to_vec(), b"context".to_vec(), vec![], h(60)).unwrap();
        payload.zeroize();
        assert!(payload.is_zeroized());
        assert!(!WWM_P1_PRIVATE_JOBS_ENABLED);
        assert_eq!(WWM_PRIVATE_JOB_CONSENSUS_WEIGHT, 0);
    }
}
