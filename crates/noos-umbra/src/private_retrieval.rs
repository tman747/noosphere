//! Encrypted, profile-bound private retrieval output and blinded receipts.
//!
//! Retrieval executes only through an explicitly selected local, same-workload,
//! or separately attested adapter. Queries, context, citations, and output stay
//! inside encrypted envelopes. Public fallback is not representable here.

use crate::{private_job::PrivateJobDisposition, Hash32};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use rand_core::{CryptoRng, RngCore};

pub const PRIVATE_RETRIEVAL_VERSION: u16 = 1;
pub const MAX_PRIVATE_CITATIONS: usize = 64;
pub const MAX_PRIVATE_OUTPUT_BYTES: usize = 1024 * 1024;
pub const PRIVATE_OUTPUT_BUCKETS: [usize; 5] = [4_096, 16_384, 65_536, 262_144, 1_048_576];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateRetrievalError {
    InvalidDisclosure,
    InvalidPayload,
    InvalidBucket,
    InvalidEnvelope,
    InvalidReceipt,
    InvalidSignature,
    Crypto,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateRetrievalMode {
    LocalSnapshot = 1,
    SameAttestedWorkload = 2,
    SeparateAttestedEnclave = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateRetrievalDisclosure {
    pub mode: PrivateRetrievalMode,
    pub snapshot_id: Hash32,
    pub profile_id: Hash32,
    pub retrieval_policy_root: Hash32,
    pub leakage_budget_root: Hash32,
    pub attestation_quote_id: Hash32,
    pub query_ciphertext_root: Hash32,
    pub result_count: u16,
    pub citation_ciphertext_root: Hash32,
    pub disclosure_id: Hash32,
}

impl PrivateRetrievalDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: PrivateRetrievalMode,
        snapshot_id: Hash32,
        profile_id: Hash32,
        retrieval_policy_root: Hash32,
        leakage_budget_root: Hash32,
        attestation_quote_id: Hash32,
        query_ciphertext_root: Hash32,
        result_count: u16,
        citation_ciphertext_root: Hash32,
    ) -> Result<Self, PrivateRetrievalError> {
        let mut value = Self {
            mode,
            snapshot_id,
            profile_id,
            retrieval_policy_root,
            leakage_budget_root,
            attestation_quote_id,
            query_ciphertext_root,
            result_count,
            citation_ciphertext_root,
            disclosure_id: [0; 32],
        };
        let body = value.body()?;
        value.disclosure_id = digest(DomainId::WwmBlindedReceipt, &[b"PRIVATE-RETRIEVAL", &body])?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PrivateRetrievalError> {
        let body = self.body()?;
        if self.disclosure_id == [0; 32]
            || digest(DomainId::WwmBlindedReceipt, &[b"PRIVATE-RETRIEVAL", &body])?
                != self.disclosure_id
        {
            return Err(PrivateRetrievalError::InvalidDisclosure);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, PrivateRetrievalError> {
        if [
            self.snapshot_id,
            self.profile_id,
            self.retrieval_policy_root,
            self.leakage_budget_root,
            self.query_ciphertext_root,
            self.citation_ciphertext_root,
        ]
        .contains(&[0; 32])
            || usize::from(self.result_count) > MAX_PRIVATE_CITATIONS
        {
            return Err(PrivateRetrievalError::InvalidDisclosure);
        }
        match self.mode {
            PrivateRetrievalMode::LocalSnapshot if self.attestation_quote_id != [0; 32] => {
                return Err(PrivateRetrievalError::InvalidDisclosure);
            }
            PrivateRetrievalMode::SameAttestedWorkload
            | PrivateRetrievalMode::SeparateAttestedEnclave
                if self.attestation_quote_id == [0; 32] =>
            {
                return Err(PrivateRetrievalError::InvalidDisclosure);
            }
            _ => {}
        }
        let mut body = Vec::with_capacity(263);
        body.extend(PRIVATE_RETRIEVAL_VERSION.to_le_bytes());
        body.push(self.mode as u8);
        body.extend(self.snapshot_id);
        body.extend(self.profile_id);
        body.extend(self.retrieval_policy_root);
        body.extend(self.leakage_budget_root);
        body.extend(self.attestation_quote_id);
        body.extend(self.query_ciphertext_root);
        body.extend(self.result_count.to_le_bytes());
        body.extend(self.citation_ciphertext_root);
        Ok(body)
    }
}

/// Plaintext exists only after client-side decryption. Drop wipes output,
/// citation identifiers, and the local-history key identifier.
pub struct PrivateRetrievalOutput {
    output: Vec<u8>,
    citation_ids: Vec<Hash32>,
    local_history_key_id: Hash32,
    zeroized: bool,
}

impl PrivateRetrievalOutput {
    pub fn new(
        output: Vec<u8>,
        citation_ids: Vec<Hash32>,
        local_history_key_id: Hash32,
    ) -> Result<Self, PrivateRetrievalError> {
        if output.is_empty()
            || output.len() > MAX_PRIVATE_OUTPUT_BYTES
            || citation_ids.len() > MAX_PRIVATE_CITATIONS
            || citation_ids.contains(&[0; 32])
            || citation_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || local_history_key_id == [0; 32]
        {
            return Err(PrivateRetrievalError::InvalidPayload);
        }
        Ok(Self {
            output,
            citation_ids,
            local_history_key_id,
            zeroized: false,
        })
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    #[must_use]
    pub fn citation_ids(&self) -> &[Hash32] {
        &self.citation_ids
    }

    #[must_use]
    pub fn local_history_key_id(&self) -> Hash32 {
        self.local_history_key_id
    }

    pub fn zeroize(&mut self) {
        self.output.fill(0);
        for citation in &mut self.citation_ids {
            citation.fill(0);
        }
        self.local_history_key_id.fill(0);
        self.zeroized = true;
    }

    #[must_use]
    pub fn is_zeroized(&self) -> bool {
        self.zeroized
            && self.output.iter().all(|byte| *byte == 0)
            && self
                .citation_ids
                .iter()
                .all(|citation| *citation == [0; 32])
            && self.local_history_key_id == [0; 32]
    }

    fn encode_padded(&self, bucket: usize) -> Result<Vec<u8>, PrivateRetrievalError> {
        if self.zeroized || !PRIVATE_OUTPUT_BUCKETS.contains(&bucket) {
            return Err(PrivateRetrievalError::InvalidPayload);
        }
        let output_len = u32::try_from(self.output.len())
            .map_err(|_| PrivateRetrievalError::ArithmeticOverflow)?;
        let citation_count = u16::try_from(self.citation_ids.len())
            .map_err(|_| PrivateRetrievalError::ArithmeticOverflow)?;
        let citations_bytes = self
            .citation_ids
            .len()
            .checked_mul(32)
            .ok_or(PrivateRetrievalError::ArithmeticOverflow)?;
        let body_len = 2_usize
            .checked_add(4)
            .and_then(|value| value.checked_add(self.output.len()))
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(citations_bytes))
            .and_then(|value| value.checked_add(32))
            .ok_or(PrivateRetrievalError::ArithmeticOverflow)?;
        let framed_len = body_len
            .checked_add(4)
            .ok_or(PrivateRetrievalError::ArithmeticOverflow)?;
        if framed_len > bucket {
            return Err(PrivateRetrievalError::InvalidBucket);
        }
        let mut bytes = Vec::with_capacity(bucket);
        bytes.extend(
            u32::try_from(body_len)
                .map_err(|_| PrivateRetrievalError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        bytes.extend(PRIVATE_RETRIEVAL_VERSION.to_le_bytes());
        bytes.extend(output_len.to_le_bytes());
        bytes.extend(&self.output);
        bytes.extend(citation_count.to_le_bytes());
        for citation in &self.citation_ids {
            bytes.extend(citation);
        }
        bytes.extend(self.local_history_key_id);
        bytes.resize(bucket, 0);
        Ok(bytes)
    }

    fn decode_padded(bytes: &[u8]) -> Result<Self, PrivateRetrievalError> {
        if !PRIVATE_OUTPUT_BUCKETS.contains(&bytes.len()) || bytes.len() < 10 {
            return Err(PrivateRetrievalError::InvalidBucket);
        }
        let mut offset = 0;
        let body_len = usize::try_from(take_u32(bytes, &mut offset)?)
            .map_err(|_| PrivateRetrievalError::InvalidPayload)?;
        let body_end = 4_usize
            .checked_add(body_len)
            .ok_or(PrivateRetrievalError::ArithmeticOverflow)?;
        if body_end > bytes.len() || bytes[body_end..].iter().any(|byte| *byte != 0) {
            return Err(PrivateRetrievalError::InvalidPayload);
        }
        if take_u16(bytes, &mut offset)? != PRIVATE_RETRIEVAL_VERSION {
            return Err(PrivateRetrievalError::InvalidPayload);
        }
        let output_len = usize::try_from(take_u32(bytes, &mut offset)?)
            .map_err(|_| PrivateRetrievalError::InvalidPayload)?;
        let output = take_vec(bytes, &mut offset, output_len)?;
        let citation_count = usize::from(take_u16(bytes, &mut offset)?);
        if citation_count > MAX_PRIVATE_CITATIONS {
            return Err(PrivateRetrievalError::InvalidPayload);
        }
        let mut citation_ids = Vec::with_capacity(citation_count);
        for _ in 0..citation_count {
            citation_ids.push(take_array::<32>(bytes, &mut offset)?);
        }
        let local_history_key_id = take_array::<32>(bytes, &mut offset)?;
        if offset != body_end {
            return Err(PrivateRetrievalError::InvalidPayload);
        }
        Self::new(output, citation_ids, local_history_key_id)
    }
}

impl Drop for PrivateRetrievalOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateOutputEnvelope {
    pub job_handle: Hash32,
    pub retrieval_disclosure_id: Hash32,
    pub plaintext_bucket_bytes: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub ciphertext_root: Hash32,
}

impl PrivateOutputEnvelope {
    fn aad(&self) -> Result<Vec<u8>, PrivateRetrievalError> {
        let bucket = usize::try_from(self.plaintext_bucket_bytes)
            .map_err(|_| PrivateRetrievalError::InvalidBucket)?;
        if self.job_handle == [0; 32]
            || self.retrieval_disclosure_id == [0; 32]
            || !PRIVATE_OUTPUT_BUCKETS.contains(&bucket)
        {
            return Err(PrivateRetrievalError::InvalidEnvelope);
        }
        let mut aad = Vec::with_capacity(70);
        aad.extend(PRIVATE_RETRIEVAL_VERSION.to_le_bytes());
        aad.extend(self.job_handle);
        aad.extend(self.retrieval_disclosure_id);
        aad.extend(self.plaintext_bucket_bytes.to_le_bytes());
        Ok(aad)
    }

    pub fn validate(&self) -> Result<(), PrivateRetrievalError> {
        let aad = self.aad()?;
        let bucket = usize::try_from(self.plaintext_bucket_bytes)
            .map_err(|_| PrivateRetrievalError::InvalidBucket)?;
        if self.nonce == [0; 24]
            || self.ciphertext.len() != bucket.saturating_add(16)
            || self.ciphertext_root == [0; 32]
            || digest(
                DomainId::WwmPrivateEnvelope,
                &[b"PRIVATE-OUTPUT", &aad, &self.nonce, &self.ciphertext],
            )? != self.ciphertext_root
        {
            return Err(PrivateRetrievalError::InvalidEnvelope);
        }
        Ok(())
    }
}

pub fn seal_private_output<R: CryptoRng + RngCore>(
    output_key: &[u8; 32],
    job_handle: Hash32,
    disclosure: &PrivateRetrievalDisclosure,
    output: &PrivateRetrievalOutput,
    bucket: usize,
    rng: &mut R,
) -> Result<PrivateOutputEnvelope, PrivateRetrievalError> {
    disclosure.validate()?;
    if *output_key == [0; 32] || job_handle == [0; 32] || !PRIVATE_OUTPUT_BUCKETS.contains(&bucket)
    {
        return Err(PrivateRetrievalError::InvalidEnvelope);
    }
    let mut nonce = [0_u8; 24];
    rng.fill_bytes(&mut nonce);
    if nonce == [0; 24] {
        return Err(PrivateRetrievalError::Crypto);
    }
    let plaintext_bucket_bytes =
        u32::try_from(bucket).map_err(|_| PrivateRetrievalError::ArithmeticOverflow)?;
    let mut envelope = PrivateOutputEnvelope {
        job_handle,
        retrieval_disclosure_id: disclosure.disclosure_id,
        plaintext_bucket_bytes,
        nonce,
        ciphertext: Vec::new(),
        ciphertext_root: [0; 32],
    };
    let aad = envelope.aad()?;
    let mut plaintext = output.encode_padded(bucket)?;
    let nonce_value = XNonce::from(nonce);
    let ciphertext = XChaCha20Poly1305::new(output_key.into())
        .encrypt(
            &nonce_value,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| PrivateRetrievalError::Crypto)?;
    plaintext.fill(0);
    envelope.ciphertext_root = digest(
        DomainId::WwmPrivateEnvelope,
        &[b"PRIVATE-OUTPUT", &aad, &nonce, &ciphertext],
    )?;
    envelope.ciphertext = ciphertext;
    Ok(envelope)
}

pub fn open_private_output(
    output_key: &[u8; 32],
    disclosure: &PrivateRetrievalDisclosure,
    envelope: &PrivateOutputEnvelope,
) -> Result<PrivateRetrievalOutput, PrivateRetrievalError> {
    disclosure.validate()?;
    envelope.validate()?;
    if *output_key == [0; 32] || envelope.retrieval_disclosure_id != disclosure.disclosure_id {
        return Err(PrivateRetrievalError::InvalidEnvelope);
    }
    let aad = envelope.aad()?;
    let nonce_value = XNonce::from(envelope.nonce);
    let mut plaintext = XChaCha20Poly1305::new(output_key.into())
        .decrypt(
            &nonce_value,
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| PrivateRetrievalError::Crypto)?;
    let result = PrivateRetrievalOutput::decode_padded(&plaintext);
    plaintext.fill(0);
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedRetrievalReceipt {
    pub job_handle: Hash32,
    pub input_envelope_id: Hash32,
    pub compute_policy_id: Hash32,
    pub compute_quote_id: Hash32,
    pub retrieval_disclosure_id: Hash32,
    pub retrieval_profile_id: Hash32,
    pub route_policy_id: Hash32,
    pub output_ciphertext_root: Hash32,
    pub disposition: PrivateJobDisposition,
    pub charged_micro_noos: u64,
    pub refunded_micro_noos: u64,
    pub unlinkability_nonce: Hash32,
    pub executor_key: Hash32,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl BlindedRetrievalReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: &Keypair,
        job_handle: Hash32,
        input_envelope_id: Hash32,
        compute_policy_id: Hash32,
        compute_quote_id: Hash32,
        disclosure: &PrivateRetrievalDisclosure,
        route_policy_id: Hash32,
        output_ciphertext_root: Hash32,
        disposition: PrivateJobDisposition,
        charged_micro_noos: u64,
        refunded_micro_noos: u64,
        unlinkability_nonce: Hash32,
    ) -> Result<Self, PrivateRetrievalError> {
        disclosure.validate()?;
        let mut value = Self {
            job_handle,
            input_envelope_id,
            compute_policy_id,
            compute_quote_id,
            retrieval_disclosure_id: disclosure.disclosure_id,
            retrieval_profile_id: disclosure.profile_id,
            route_policy_id,
            output_ciphertext_root,
            disposition,
            charged_micro_noos,
            refunded_micro_noos,
            unlinkability_nonce,
            executor_key: executor.public_key().into_bytes(),
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        let body = value.body()?;
        value.receipt_id = digest(DomainId::WwmBlindedReceipt, &[b"PRIVATE-RECEIPT", &body])?;
        value.signature = sign(
            executor,
            DomainId::WwmBlindedReceipt,
            value.receipt_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(
        &self,
        disclosure: &PrivateRetrievalDisclosure,
        output: Option<&PrivateOutputEnvelope>,
    ) -> Result<(), PrivateRetrievalError> {
        disclosure.validate()?;
        let body = self.body()?;
        if self.retrieval_disclosure_id != disclosure.disclosure_id
            || self.retrieval_profile_id != disclosure.profile_id
            || self.receipt_id == [0; 32]
            || digest(DomainId::WwmBlindedReceipt, &[b"PRIVATE-RECEIPT", &body])? != self.receipt_id
        {
            return Err(PrivateRetrievalError::InvalidReceipt);
        }
        match (self.disposition, output) {
            (PrivateJobDisposition::Completed, Some(envelope)) => {
                envelope.validate()?;
                if envelope.job_handle != self.job_handle
                    || envelope.retrieval_disclosure_id != disclosure.disclosure_id
                    || envelope.ciphertext_root != self.output_ciphertext_root
                {
                    return Err(PrivateRetrievalError::InvalidReceipt);
                }
            }
            (PrivateJobDisposition::Completed, None) => {
                return Err(PrivateRetrievalError::InvalidReceipt);
            }
            (_, Some(_)) => return Err(PrivateRetrievalError::InvalidReceipt),
            (_, None) => {}
        }
        verify(
            self.executor_key,
            DomainId::WwmBlindedReceipt,
            self.receipt_id,
            &body,
            self.signature,
        )
    }

    fn body(&self) -> Result<Vec<u8>, PrivateRetrievalError> {
        if [
            self.job_handle,
            self.input_envelope_id,
            self.compute_policy_id,
            self.compute_quote_id,
            self.retrieval_disclosure_id,
            self.retrieval_profile_id,
            self.route_policy_id,
            self.unlinkability_nonce,
            self.executor_key,
        ]
        .contains(&[0; 32])
            || (self.disposition == PrivateJobDisposition::Completed
                && self.output_ciphertext_root == [0; 32])
            || (self.disposition != PrivateJobDisposition::Completed
                && self.output_ciphertext_root != [0; 32])
        {
            return Err(PrivateRetrievalError::InvalidReceipt);
        }
        let mut body = Vec::with_capacity(371);
        body.extend(PRIVATE_RETRIEVAL_VERSION.to_le_bytes());
        body.extend(self.job_handle);
        body.extend(self.input_envelope_id);
        body.extend(self.compute_policy_id);
        body.extend(self.compute_quote_id);
        body.extend(self.retrieval_disclosure_id);
        body.extend(self.retrieval_profile_id);
        body.extend(self.route_policy_id);
        body.extend(self.output_ciphertext_root);
        body.push(self.disposition as u8);
        body.extend(self.charged_micro_noos.to_le_bytes());
        body.extend(self.refunded_micro_noos.to_le_bytes());
        body.extend(self.unlinkability_nonce);
        body.extend(self.executor_key);
        Ok(body)
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], PrivateRetrievalError> {
    let end = offset
        .checked_add(N)
        .ok_or(PrivateRetrievalError::ArithmeticOverflow)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(PrivateRetrievalError::InvalidPayload)?
        .try_into()
        .map_err(|_| PrivateRetrievalError::InvalidPayload)?;
    *offset = end;
    Ok(value)
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, PrivateRetrievalError> {
    Ok(u16::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, PrivateRetrievalError> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_vec(
    bytes: &[u8],
    offset: &mut usize,
    length: usize,
) -> Result<Vec<u8>, PrivateRetrievalError> {
    let end = offset
        .checked_add(length)
        .ok_or(PrivateRetrievalError::ArithmeticOverflow)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(PrivateRetrievalError::InvalidPayload)?
        .to_vec();
    *offset = end;
    Ok(value)
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, PrivateRetrievalError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| PrivateRetrievalError::InvalidReceipt)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], PrivateRetrievalError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| PrivateRetrievalError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), PrivateRetrievalError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| PrivateRetrievalError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn make_disclosure(mode: PrivateRetrievalMode) -> PrivateRetrievalDisclosure {
        let quote = if mode == PrivateRetrievalMode::LocalSnapshot {
            [0; 32]
        } else {
            h(6)
        };
        PrivateRetrievalDisclosure::new(mode, h(1), h(2), h(3), h(4), quote, h(7), 2, h(8)).unwrap()
    }

    #[test]
    fn private_output_encrypts_citations_and_is_profile_bound() {
        let disclosure = make_disclosure(PrivateRetrievalMode::LocalSnapshot);
        let output = PrivateRetrievalOutput::new(
            b"private answer canary".to_vec(),
            vec![h(20), h(21)],
            h(22),
        )
        .unwrap();
        let key = h(23);
        let mut rng = StdRng::from_seed([24; 32]);
        let envelope = seal_private_output(
            &key,
            h(25),
            &disclosure,
            &output,
            PRIVATE_OUTPUT_BUCKETS[0],
            &mut rng,
        )
        .unwrap();
        assert_eq!(envelope.ciphertext.len(), PRIVATE_OUTPUT_BUCKETS[0] + 16);
        assert!(!envelope
            .ciphertext
            .windows(b"private answer canary".len())
            .any(|window| window == b"private answer canary"));
        assert!(!envelope
            .ciphertext
            .windows(32)
            .any(|window| window == h(20)));
        let opened = open_private_output(&key, &disclosure, &envelope).unwrap();
        assert_eq!(opened.output(), b"private answer canary");
        assert_eq!(opened.citation_ids(), &[h(20), h(21)]);
        assert_eq!(opened.local_history_key_id(), h(22));

        let other = make_disclosure(PrivateRetrievalMode::SameAttestedWorkload);
        assert!(matches!(
            open_private_output(&key, &other, &envelope),
            Err(PrivateRetrievalError::InvalidEnvelope)
        ));
        assert!(matches!(
            open_private_output(&h(99), &disclosure, &envelope),
            Err(PrivateRetrievalError::Crypto)
        ));
    }

    #[test]
    fn signed_blinded_receipt_binds_route_profile_and_ciphertext() {
        let disclosure = make_disclosure(PrivateRetrievalMode::SeparateAttestedEnclave);
        let output = PrivateRetrievalOutput::new(b"answer".to_vec(), vec![h(30)], h(31)).unwrap();
        let mut rng = StdRng::from_seed([32; 32]);
        let envelope = seal_private_output(
            &h(33),
            h(34),
            &disclosure,
            &output,
            PRIVATE_OUTPUT_BUCKETS[0],
            &mut rng,
        )
        .unwrap();
        let signer = Keypair::from_seed([35; 32]);
        let receipt = BlindedRetrievalReceipt::new(
            &signer,
            h(34),
            h(36),
            h(37),
            h(38),
            &disclosure,
            h(39),
            envelope.ciphertext_root,
            PrivateJobDisposition::Completed,
            100,
            0,
            h(40),
        )
        .unwrap();
        receipt.validate(&disclosure, Some(&envelope)).unwrap();

        let mut tampered = receipt.clone();
        tampered.route_policy_id = h(41);
        assert_eq!(
            tampered.validate(&disclosure, Some(&envelope)),
            Err(PrivateRetrievalError::InvalidReceipt)
        );
        assert_eq!(
            receipt.validate(&disclosure, None),
            Err(PrivateRetrievalError::InvalidReceipt)
        );
    }

    #[test]
    fn retrieval_modes_reject_attestation_downgrade_and_public_fallback_is_absent() {
        assert_eq!(
            PrivateRetrievalDisclosure::new(
                PrivateRetrievalMode::LocalSnapshot,
                h(1),
                h(2),
                h(3),
                h(4),
                h(5),
                h(6),
                0,
                h(7),
            ),
            Err(PrivateRetrievalError::InvalidDisclosure)
        );
        assert_eq!(
            PrivateRetrievalDisclosure::new(
                PrivateRetrievalMode::SeparateAttestedEnclave,
                h(1),
                h(2),
                h(3),
                h(4),
                [0; 32],
                h(6),
                0,
                h(7),
            ),
            Err(PrivateRetrievalError::InvalidDisclosure)
        );
    }

    #[test]
    fn opened_output_wipes_client_plaintext_and_history_binding() {
        let mut output = PrivateRetrievalOutput::new(b"secret".to_vec(), vec![h(1)], h(2)).unwrap();
        output.zeroize();
        assert!(output.is_zeroized());
    }
}
