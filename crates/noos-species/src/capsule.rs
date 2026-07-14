use crate::{Hash32, SpeciesError};
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};

pub const MODEL_CAPSULE_VERSION: u16 = 1;
pub const MAX_CAPSULE_PARENTS: usize = 8;
pub const MAX_DECODING_PROFILES: usize = 16;
pub const MAX_PUBLISHERS: usize = 16;
pub const WWM_MODEL_ACTIVATION_ENABLED: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublisherSignature {
    pub publisher_index: u8,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCapsule {
    pub version: u16,
    pub species_id: Hash32,
    pub revision_id: Hash32,
    pub parents: Vec<Hash32>,
    pub architecture_root: Hash32,
    pub weight_manifest_root: Hash32,
    pub tokenizer_root: Hash32,
    pub numeric_profile_id: Hash32,
    pub decoding_profiles: Vec<Hash32>,
    pub context_policy_root: Hash32,
    pub reference_interpreter_root: Hash32,
    pub compiler_root: Hash32,
    pub runtime_root: Hash32,
    pub sbom_root: Hash32,
    pub conformance_suite_root: Hash32,
    pub independent_implementation_families: u8,
    pub license_root: Hash32,
    pub rights_root: Hash32,
    pub provenance_root: Hash32,
    pub evaluation_policy_root: Hash32,
    pub safety_policy_root: Hash32,
    pub privacy_profiles_bitset: u8,
    pub knowledge_policy_root: Hash32,
    pub tool_policy_root: Hash32,
    pub availability_policy_id: u32,
    pub minimum_custodians: u16,
    pub minimum_failure_domains: u16,
    pub activation_policy_root: Hash32,
    pub rollback_revision_id: Hash32,
    pub created_height: u64,
    pub expires_height: Option<u64>,
    pub publisher_keys: Vec<Hash32>,
    pub publisher_threshold: u8,
    pub capsule_id: Hash32,
    pub signatures: Vec<PublisherSignature>,
}

impl ModelCapsule {
    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        if !self.signatures.is_empty() {
            return Err(SpeciesError::InvalidCapsuleSignature);
        }
        let id = self.derived_id()?;
        self.capsule_id = id;
        Ok(id)
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        let body = self.canonical_body()?;
        hash_domain(DomainId::WwmModelCapsule, &[&body])
            .map(noos_crypto::Hash32::into_bytes)
            .map_err(|_| SpeciesError::InvalidCapsule)
    }

    pub fn add_signature(&mut self, keypair: &Keypair) -> Result<(), SpeciesError> {
        if self.capsule_id == [0; 32] || self.derived_id()? != self.capsule_id {
            return Err(SpeciesError::InvalidCapsule);
        }
        let public_key = keypair.public_key().into_bytes();
        let index = self
            .publisher_keys
            .binary_search(&public_key)
            .map_err(|_| SpeciesError::InvalidCapsuleSignature)?;
        let index = u8::try_from(index).map_err(|_| SpeciesError::InvalidCapsuleSignature)?;
        if self
            .signatures
            .iter()
            .any(|entry| entry.publisher_index == index)
        {
            return Err(SpeciesError::InvalidCapsuleSignature);
        }
        let body = self.canonical_body()?;
        let domain_id = DomainId::WwmModelCapsule.registry_id().as_bytes();
        let signature = keypair
            .sign_domain(DomainId::SigWwm, &[domain_id, &self.capsule_id, &body])
            .map_err(|_| SpeciesError::InvalidCapsuleSignature)?;
        self.signatures.push(PublisherSignature {
            publisher_index: index,
            signature: signature.into_bytes(),
        });
        self.signatures.sort_by_key(|entry| entry.publisher_index);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        self.validate_shape()?;
        if self.capsule_id == [0; 32] || self.derived_id()? != self.capsule_id {
            return Err(SpeciesError::InvalidCapsule);
        }
        if self.signatures.len() < usize::from(self.publisher_threshold)
            || self.signatures.len() > self.publisher_keys.len()
            || !self
                .signatures
                .windows(2)
                .all(|pair| pair[0].publisher_index < pair[1].publisher_index)
        {
            return Err(SpeciesError::InvalidCapsuleSignature);
        }
        let body = self.canonical_body()?;
        let domain_id = DomainId::WwmModelCapsule.registry_id().as_bytes();
        for entry in &self.signatures {
            let key_bytes = self
                .publisher_keys
                .get(usize::from(entry.publisher_index))
                .ok_or(SpeciesError::InvalidCapsuleSignature)?;
            verify_domain(
                DomainId::SigWwm,
                &PublicKey::from_bytes(*key_bytes),
                &[domain_id, &self.capsule_id, &body],
                &Signature::from_bytes(entry.signature),
            )
            .map_err(|_| SpeciesError::InvalidCapsuleSignature)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn execution_slashing_eligible(&self) -> bool {
        self.validate().is_ok() && self.independent_implementation_families >= 2
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, SpeciesError> {
        self.validate()?;
        let mut bytes = self.canonical_body()?;
        bytes.extend_from_slice(&self.capsule_id);
        push_u16(
            &mut bytes,
            u16::try_from(self.signatures.len()).map_err(|_| SpeciesError::InvalidCapsule)?,
        );
        for entry in &self.signatures {
            bytes.push(entry.publisher_index);
            bytes.extend_from_slice(&entry.signature);
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SpeciesError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u16()?;
        let species_id = decoder.hash()?;
        let revision_id = decoder.hash()?;
        let parents = decoder.hashes(MAX_CAPSULE_PARENTS)?;
        let architecture_root = decoder.hash()?;
        let weight_manifest_root = decoder.hash()?;
        let tokenizer_root = decoder.hash()?;
        let numeric_profile_id = decoder.hash()?;
        let decoding_profiles = decoder.hashes(MAX_DECODING_PROFILES)?;
        let context_policy_root = decoder.hash()?;
        let reference_interpreter_root = decoder.hash()?;
        let compiler_root = decoder.hash()?;
        let runtime_root = decoder.hash()?;
        let sbom_root = decoder.hash()?;
        let conformance_suite_root = decoder.hash()?;
        let independent_implementation_families = decoder.u8()?;
        let license_root = decoder.hash()?;
        let rights_root = decoder.hash()?;
        let provenance_root = decoder.hash()?;
        let evaluation_policy_root = decoder.hash()?;
        let safety_policy_root = decoder.hash()?;
        let privacy_profiles_bitset = decoder.u8()?;
        let knowledge_policy_root = decoder.hash()?;
        let tool_policy_root = decoder.hash()?;
        let availability_policy_id = decoder.u32()?;
        let minimum_custodians = decoder.u16()?;
        let minimum_failure_domains = decoder.u16()?;
        let activation_policy_root = decoder.hash()?;
        let rollback_revision_id = decoder.hash()?;
        let created_height = decoder.u64()?;
        let expires_height = decoder.optional_u64()?;
        let publisher_keys = decoder.hashes(MAX_PUBLISHERS)?;
        let publisher_threshold = decoder.u8()?;
        let capsule_id = decoder.hash()?;
        let signature_count = usize::from(decoder.u16()?);
        if signature_count > MAX_PUBLISHERS {
            return Err(SpeciesError::MalformedEncoding);
        }
        let mut signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            signatures.push(PublisherSignature {
                publisher_index: decoder.u8()?,
                signature: decoder.signature()?,
            });
        }
        decoder.finish()?;
        let value = Self {
            version,
            species_id,
            revision_id,
            parents,
            architecture_root,
            weight_manifest_root,
            tokenizer_root,
            numeric_profile_id,
            decoding_profiles,
            context_policy_root,
            reference_interpreter_root,
            compiler_root,
            runtime_root,
            sbom_root,
            conformance_suite_root,
            independent_implementation_families,
            license_root,
            rights_root,
            provenance_root,
            evaluation_policy_root,
            safety_policy_root,
            privacy_profiles_bitset,
            knowledge_policy_root,
            tool_policy_root,
            availability_policy_id,
            minimum_custodians,
            minimum_failure_domains,
            activation_policy_root,
            rollback_revision_id,
            created_height,
            expires_height,
            publisher_keys,
            publisher_threshold,
            capsule_id,
            signatures,
        };
        value.validate()?;
        if value.encode_canonical()? != bytes {
            return Err(SpeciesError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(1_024);
        push_u16(&mut bytes, self.version);
        push_hash(&mut bytes, &self.species_id);
        push_hash(&mut bytes, &self.revision_id);
        push_hashes(&mut bytes, &self.parents)?;
        push_hash(&mut bytes, &self.architecture_root);
        push_hash(&mut bytes, &self.weight_manifest_root);
        push_hash(&mut bytes, &self.tokenizer_root);
        push_hash(&mut bytes, &self.numeric_profile_id);
        push_hashes(&mut bytes, &self.decoding_profiles)?;
        push_hash(&mut bytes, &self.context_policy_root);
        push_hash(&mut bytes, &self.reference_interpreter_root);
        push_hash(&mut bytes, &self.compiler_root);
        push_hash(&mut bytes, &self.runtime_root);
        push_hash(&mut bytes, &self.sbom_root);
        push_hash(&mut bytes, &self.conformance_suite_root);
        bytes.push(self.independent_implementation_families);
        push_hash(&mut bytes, &self.license_root);
        push_hash(&mut bytes, &self.rights_root);
        push_hash(&mut bytes, &self.provenance_root);
        push_hash(&mut bytes, &self.evaluation_policy_root);
        push_hash(&mut bytes, &self.safety_policy_root);
        bytes.push(self.privacy_profiles_bitset);
        push_hash(&mut bytes, &self.knowledge_policy_root);
        push_hash(&mut bytes, &self.tool_policy_root);
        push_u32(&mut bytes, self.availability_policy_id);
        push_u16(&mut bytes, self.minimum_custodians);
        push_u16(&mut bytes, self.minimum_failure_domains);
        push_hash(&mut bytes, &self.activation_policy_root);
        push_hash(&mut bytes, &self.rollback_revision_id);
        push_u64(&mut bytes, self.created_height);
        match self.expires_height {
            Some(height) => {
                bytes.push(1);
                push_u64(&mut bytes, height);
            }
            None => bytes.push(0),
        }
        push_hashes(&mut bytes, &self.publisher_keys)?;
        bytes.push(self.publisher_threshold);
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<(), SpeciesError> {
        let nonzero_roots = [
            self.species_id,
            self.revision_id,
            self.architecture_root,
            self.weight_manifest_root,
            self.tokenizer_root,
            self.numeric_profile_id,
            self.context_policy_root,
            self.reference_interpreter_root,
            self.compiler_root,
            self.runtime_root,
            self.sbom_root,
            self.conformance_suite_root,
            self.license_root,
            self.rights_root,
            self.provenance_root,
            self.evaluation_policy_root,
            self.safety_policy_root,
            self.knowledge_policy_root,
            self.tool_policy_root,
            self.activation_policy_root,
            self.rollback_revision_id,
        ];
        if self.version != MODEL_CAPSULE_VERSION
            || nonzero_roots.contains(&[0; 32])
            || self.parents.len() > MAX_CAPSULE_PARENTS
            || !strictly_sorted(&self.parents)
            || self.decoding_profiles.is_empty()
            || self.decoding_profiles.len() > MAX_DECODING_PROFILES
            || !strictly_sorted(&self.decoding_profiles)
            || self.publisher_keys.is_empty()
            || self.publisher_keys.len() > MAX_PUBLISHERS
            || !strictly_sorted(&self.publisher_keys)
            || self.publisher_threshold == 0
            || usize::from(self.publisher_threshold) > self.publisher_keys.len()
            || self.privacy_profiles_bitset == 0
            || self.privacy_profiles_bitset & !0x0f != 0
            || self.minimum_custodians < 3
            || self.minimum_failure_domains < 3
            || self.minimum_failure_domains > self.minimum_custodians
            || self.availability_policy_id == 0
            || self
                .expires_height
                .is_some_and(|expiry| expiry <= self.created_height)
        {
            return Err(SpeciesError::InvalidCapsule);
        }
        Ok(())
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_hash(bytes: &mut Vec<u8>, value: &Hash32) {
    bytes.extend_from_slice(value);
}

fn push_hashes(bytes: &mut Vec<u8>, values: &[Hash32]) -> Result<(), SpeciesError> {
    push_u16(
        bytes,
        u16::try_from(values.len()).map_err(|_| SpeciesError::InvalidCapsule)?,
    );
    for value in values {
        push_hash(bytes, value);
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn finish(self) -> Result<(), SpeciesError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(SpeciesError::NonCanonicalEncoding)
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], SpeciesError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(SpeciesError::MalformedEncoding)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SpeciesError::MalformedEncoding)?;
        self.cursor = end;
        value
            .try_into()
            .map_err(|_| SpeciesError::MalformedEncoding)
    }

    fn u8(&mut self) -> Result<u8, SpeciesError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, SpeciesError> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, SpeciesError> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, SpeciesError> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    fn hash(&mut self) -> Result<Hash32, SpeciesError> {
        self.take()
    }

    fn signature(&mut self) -> Result<[u8; 64], SpeciesError> {
        self.take()
    }

    fn hashes(&mut self, maximum: usize) -> Result<Vec<Hash32>, SpeciesError> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(SpeciesError::MalformedEncoding);
        }
        let required = count
            .checked_mul(32)
            .ok_or(SpeciesError::MalformedEncoding)?;
        if required > self.bytes.len().saturating_sub(self.cursor) {
            return Err(SpeciesError::MalformedEncoding);
        }
        (0..count).map(|_| self.hash()).collect()
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, SpeciesError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(SpeciesError::NonCanonicalEncoding),
        }
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn capsule() -> (ModelCapsule, Keypair, Keypair) {
        let first = Keypair::from_seed([1; 32]);
        let second = Keypair::from_seed([2; 32]);
        let mut publisher_keys = vec![
            first.public_key().into_bytes(),
            second.public_key().into_bytes(),
        ];
        publisher_keys.sort();
        let mut value = ModelCapsule {
            version: MODEL_CAPSULE_VERSION,
            species_id: h(1),
            revision_id: h(2),
            parents: vec![],
            architecture_root: h(3),
            weight_manifest_root: h(4),
            tokenizer_root: h(5),
            numeric_profile_id: h(6),
            decoding_profiles: vec![h(7)],
            context_policy_root: h(8),
            reference_interpreter_root: h(9),
            compiler_root: h(10),
            runtime_root: h(11),
            sbom_root: h(12),
            conformance_suite_root: h(13),
            independent_implementation_families: 2,
            license_root: h(14),
            rights_root: h(15),
            provenance_root: h(16),
            evaluation_policy_root: h(17),
            safety_policy_root: h(18),
            privacy_profiles_bitset: 1,
            knowledge_policy_root: h(19),
            tool_policy_root: h(20),
            availability_policy_id: 1,
            minimum_custodians: 3,
            minimum_failure_domains: 3,
            activation_policy_root: h(21),
            rollback_revision_id: h(2),
            created_height: 5,
            expires_height: Some(500),
            publisher_keys,
            publisher_threshold: 2,
            capsule_id: [0; 32],
            signatures: vec![],
        };
        value.finalize_id().unwrap();
        (value, first, second)
    }

    #[test]
    fn threshold_signed_capsule_roundtrips() {
        let (mut value, first, second) = capsule();
        value.add_signature(&first).unwrap();
        value.add_signature(&second).unwrap();
        value.validate().unwrap();
        assert!(value.execution_slashing_eligible());
        let bytes = value.encode_canonical().unwrap();
        assert_eq!(ModelCapsule::decode_canonical(&bytes).unwrap(), value);
    }

    #[test]
    fn mutation_and_signature_substitution_reject() {
        let (mut value, first, second) = capsule();
        value.add_signature(&first).unwrap();
        value.add_signature(&second).unwrap();
        let mut mutated = value.clone();
        mutated.runtime_root[0] ^= 1;
        assert_eq!(mutated.validate(), Err(SpeciesError::InvalidCapsule));

        let mut forged = value;
        forged.signatures[0].signature[0] ^= 1;
        assert_eq!(
            forged.validate(),
            Err(SpeciesError::InvalidCapsuleSignature)
        );
    }

    #[test]
    fn duplicate_profiles_and_trailing_bytes_reject() {
        let (mut value, first, second) = capsule();
        value.add_signature(&first).unwrap();
        value.add_signature(&second).unwrap();
        let mut duplicate = value.clone();
        duplicate.decoding_profiles.push(h(7));
        assert_eq!(duplicate.validate(), Err(SpeciesError::InvalidCapsule));

        let mut bytes = value.encode_canonical().unwrap();
        bytes.push(0);
        assert_eq!(
            ModelCapsule::decode_canonical(&bytes),
            Err(SpeciesError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn control_literals_remain_disabled() {
        assert!(!WWM_MODEL_ACTIVATION_ENABLED);
    }
}
