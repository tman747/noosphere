use crate::artifact::PublisherSignatureV2;
use crate::canonical::{strictly_sorted, Encoder};
use crate::{domain_hash, Hash32, SpeciesError};
use noos_crypto::{verify_domain, DomainId, Keypair, PublicKey, Signature};

pub const MODEL_CAPSULE_VERSION: u16 = 2;
pub const MAX_CAPSULE_PARENTS: usize = 8;
pub const MAX_EXECUTION_PROFILES: usize = 16;
pub const MAX_PUBLISHERS: usize = 16;
const CAPSULE_DOMAIN: &str = "NOOS/WWM/MODEL-CAPSULE/V2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCapsuleV2 {
    pub version: u16,
    pub parents: Vec<Hash32>,
    pub artifact_id: Hash32,
    pub payload_root: Hash32,
    pub artifact_manifest_id: Hash32,
    pub weight_manifest_id: Hash32,
    pub tokenizer_root: Hash32,
    pub chat_template_root: Hash32,
    pub runtime_source_root: Hash32,
    pub runtime_build_id: Hash32,
    pub sbom_root: Hash32,
    pub conformance_suite_root: Hash32,
    pub execution_policy_root: Hash32,
    pub query_policy_root: Hash32,
    pub license_root: Hash32,
    pub rights_root: Hash32,
    pub provenance_root: Hash32,
    pub availability_policy_root: Hash32,
    pub lifecycle_policy_root: Hash32,
    pub rollback_capsule_id: Option<Hash32>,
    pub execution_profile_ids: Vec<Hash32>,
    pub publisher_keys: Vec<Hash32>,
    pub publisher_threshold: u8,
    pub created_height: u64,
    pub expires_height: Option<u64>,
    pub capsule_id: Hash32,
    pub signatures: Vec<PublisherSignatureV2>,
}

impl ModelCapsuleV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != MODEL_CAPSULE_VERSION
            || self.parents.len() > MAX_CAPSULE_PARENTS
            || !strictly_sorted(&self.parents)
            || self.parents.contains(&self.capsule_id)
            || [
                self.artifact_id,
                self.payload_root,
                self.artifact_manifest_id,
                self.weight_manifest_id,
                self.tokenizer_root,
                self.chat_template_root,
                self.runtime_source_root,
                self.runtime_build_id,
                self.sbom_root,
                self.conformance_suite_root,
                self.execution_policy_root,
                self.query_policy_root,
                self.license_root,
                self.rights_root,
                self.provenance_root,
                self.availability_policy_root,
                self.lifecycle_policy_root,
            ]
            .contains(&[0; 32])
            || self.rollback_capsule_id == Some([0; 32])
            || self.rollback_capsule_id == Some(self.capsule_id)
            || self.execution_profile_ids.is_empty()
            || self.execution_profile_ids.len() > MAX_EXECUTION_PROFILES
            || !strictly_sorted(&self.execution_profile_ids)
            || self.publisher_keys.is_empty()
            || self.publisher_keys.len() > MAX_PUBLISHERS
            || !strictly_sorted(&self.publisher_keys)
            || self.publisher_threshold == 0
            || usize::from(self.publisher_threshold) > self.publisher_keys.len()
            || self
                .expires_height
                .is_some_and(|height| height <= self.created_height)
        {
            return Err(SpeciesError::InvalidCapsule);
        }
        let mut encoder = Encoder::new(CAPSULE_DOMAIN);
        encoder.u16(self.version);
        encoder.hashes(&self.parents);
        encoder.hash(&self.artifact_id);
        encoder.hash(&self.payload_root);
        encoder.hash(&self.artifact_manifest_id);
        encoder.hash(&self.weight_manifest_id);
        encoder.hash(&self.tokenizer_root);
        encoder.hash(&self.chat_template_root);
        encoder.hash(&self.runtime_source_root);
        encoder.hash(&self.runtime_build_id);
        encoder.hash(&self.sbom_root);
        encoder.hash(&self.conformance_suite_root);
        encoder.hash(&self.execution_policy_root);
        encoder.hash(&self.query_policy_root);
        encoder.hash(&self.license_root);
        encoder.hash(&self.rights_root);
        encoder.hash(&self.provenance_root);
        encoder.hash(&self.availability_policy_root);
        encoder.hash(&self.lifecycle_policy_root);
        encoder.optional_hash(self.rollback_capsule_id.as_ref());
        encoder.hashes(&self.execution_profile_ids);
        encoder.hashes(&self.publisher_keys);
        encoder.u8(self.publisher_threshold);
        encoder.u64(self.created_height);
        encoder.optional_u64(self.expires_height);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(CAPSULE_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        if !self.signatures.is_empty() {
            return Err(SpeciesError::InvalidCapsuleSignature);
        }
        self.capsule_id = [0; 32];
        self.capsule_id = self.derived_id()?;
        Ok(self.capsule_id)
    }

    pub fn add_signature(&mut self, keypair: &Keypair) -> Result<(), SpeciesError> {
        if self.capsule_id == [0; 32] || self.derived_id()? != self.capsule_id {
            return Err(SpeciesError::InvalidCapsule);
        }
        let key = keypair.public_key().into_bytes();
        let index = self
            .publisher_keys
            .binary_search(&key)
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
        let signature = keypair
            .sign_domain(
                DomainId::SigWwm,
                &[CAPSULE_DOMAIN.as_bytes(), &self.capsule_id, &body],
            )
            .map_err(|_| SpeciesError::InvalidCapsuleSignature)?;
        self.signatures.push(PublisherSignatureV2 {
            publisher_index: index,
            signature: signature.into_bytes(),
        });
        self.signatures.sort_by_key(|entry| entry.publisher_index);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
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
        for entry in &self.signatures {
            let key = self
                .publisher_keys
                .get(usize::from(entry.publisher_index))
                .ok_or(SpeciesError::InvalidCapsuleSignature)?;
            verify_domain(
                DomainId::SigWwm,
                &PublicKey::from_bytes(*key),
                &[CAPSULE_DOMAIN.as_bytes(), &self.capsule_id, &body],
                &Signature::from_bytes(entry.signature),
            )
            .map_err(|_| SpeciesError::InvalidCapsuleSignature)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn capsule() -> (ModelCapsuleV2, Keypair, Keypair) {
        let first = Keypair::from_seed([1; 32]);
        let second = Keypair::from_seed([2; 32]);
        let mut publisher_keys = vec![
            first.public_key().into_bytes(),
            second.public_key().into_bytes(),
        ];
        publisher_keys.sort();
        let mut value = ModelCapsuleV2 {
            version: MODEL_CAPSULE_VERSION,
            parents: vec![h(1)],
            artifact_id: h(2),
            payload_root: h(3),
            artifact_manifest_id: h(4),
            weight_manifest_id: h(5),
            tokenizer_root: h(6),
            chat_template_root: h(7),
            runtime_source_root: h(8),
            runtime_build_id: h(9),
            sbom_root: h(10),
            conformance_suite_root: h(11),
            execution_policy_root: h(12),
            query_policy_root: h(13),
            license_root: h(14),
            rights_root: h(15),
            provenance_root: h(16),
            availability_policy_root: h(17),
            lifecycle_policy_root: h(18),
            rollback_capsule_id: Some(h(19)),
            execution_profile_ids: vec![h(20), h(21)],
            publisher_keys,
            publisher_threshold: 2,
            created_height: 5,
            expires_height: Some(500),
            capsule_id: [0; 32],
            signatures: Vec::new(),
        };
        value.finalize_id().unwrap();
        (value, first, second)
    }

    #[test]
    fn capsule_v2_binds_hash_policy_and_whole_input_signatures() {
        let (mut value, first, second) = capsule();
        value.add_signature(&first).unwrap();
        value.add_signature(&second).unwrap();
        value.validate().unwrap();
        let original = value.capsule_id;
        let mut changed = value.clone();
        changed.availability_policy_root[0] ^= 1;
        assert_ne!(changed.derived_id().unwrap(), original);
        assert_eq!(changed.validate(), Err(SpeciesError::InvalidCapsule));
        let mut forged = value;
        forged.signatures[0].signature[0] ^= 1;
        assert_eq!(
            forged.validate(),
            Err(SpeciesError::InvalidCapsuleSignature)
        );
    }

    #[test]
    fn direct_self_cycles_and_u32_policy_shapes_are_impossible() {
        let (mut value, _, _) = capsule();
        value.parents = vec![value.capsule_id];
        assert_eq!(value.canonical_body(), Err(SpeciesError::InvalidCapsule));
        assert_eq!(std::mem::size_of_val(&value.availability_policy_root), 32);
    }
}
