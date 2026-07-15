use crate::canonical::{strictly_sorted, Encoder};
use crate::{domain_hash, ArtifactKind, Hash32, SpeciesError};
use noos_crypto::{verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::BTreeSet;

pub const ARTIFACT_SHARE_VERSION: u16 = 2;
pub const ARTIFACT_STRIPE_VERSION: u16 = 2;
pub const ARTIFACT_MANIFEST_VERSION: u16 = 2;
pub const ARTIFACT_DESCRIPTOR_VERSION: u16 = 2;
pub const WEIGHT_MANIFEST_VERSION: u16 = 2;
pub const WEIGHT_INSPECTION_VERSION: u16 = 2;
pub const BONSAI_SOURCE_BYTES: u64 = 3_803_452_480;
pub const BONSAI_STRIPE_COUNT: usize = 454;
pub const PADDED_STRIPE_BYTES: u32 = 8_380_416;
pub const SHARE_BYTES: u32 = 1_047_552;
pub const DATA_POSITIONS: u8 = 8;
pub const PARITY_POSITIONS: u8 = 4;
pub const POSITION_COUNT: usize = 12;
pub const PROBE_LEAF_COUNT: u8 = 32;
pub const PROBE_LEAF_BYTES: u32 = 32_736;
pub const FINAL_SOURCE_BYTES: u32 = 7_124_032;
pub const FINAL_PADDING_BYTES: u32 = 1_256_384;

const SHARE_DOMAIN: &str = "NOOS/WWM/ARTIFACT/SHARE/V2";
const STRIPE_DOMAIN: &str = "NOOS/WWM/ARTIFACT/STRIPE/V2";
const MANIFEST_DOMAIN: &str = "NOOS/WWM/ARTIFACT/MANIFEST/V2";
const DESCRIPTOR_DOMAIN: &str = "NOOS/WWM/ARTIFACT/DESCRIPTOR/V2";
const WEIGHT_DOMAIN: &str = "NOOS/WWM/WEIGHT/MANIFEST/V2";
const INSPECTION_DOMAIN: &str = "NOOS/WWM/WEIGHT/INSPECTION/V2";
const DERIVATION_DOMAIN: &str = "NOOS/WWM/ARTIFACT/DERIVATION/V2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublisherSignatureV2 {
    pub publisher_index: u8,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactShareV2 {
    pub version: u16,
    pub erasure_profile_id: Hash32,
    pub stripe_index: u32,
    pub position_index: u8,
    pub encoded_byte_length: u32,
    pub full_share_digest: Hash32,
    pub probe_root: Hash32,
    pub probe_leaf_count: u8,
    pub probe_leaf_bytes: u32,
    pub share_id: Hash32,
}

impl ArtifactShareV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != ARTIFACT_SHARE_VERSION
            || self.erasure_profile_id == [0; 32]
            || usize::from(self.position_index) >= POSITION_COUNT
            || self.encoded_byte_length != SHARE_BYTES
            || self.full_share_digest == [0; 32]
            || self.probe_root == [0; 32]
            || self.probe_leaf_count != PROBE_LEAF_COUNT
            || self.probe_leaf_bytes != PROBE_LEAF_BYTES
        {
            return Err(SpeciesError::InvalidArtifactSchema);
        }
        let mut encoder = Encoder::new(SHARE_DOMAIN);
        encoder.u16(self.version);
        encoder.hash(&self.erasure_profile_id);
        encoder.u32(self.stripe_index);
        encoder.u8(self.position_index);
        encoder.u32(self.encoded_byte_length);
        encoder.hash(&self.full_share_digest);
        encoder.hash(&self.probe_root);
        encoder.u8(self.probe_leaf_count);
        encoder.u32(self.probe_leaf_bytes);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(SHARE_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        self.share_id = self.derived_id()?;
        Ok(self.share_id)
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.share_id == [0; 32] || self.derived_id()? != self.share_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStripeV2 {
    pub version: u16,
    pub erasure_profile_id: Hash32,
    pub stripe_index: u32,
    pub source_offset: u64,
    pub padded_source_bytes: u32,
    pub actual_source_bytes: u32,
    pub zero_padding_bytes: u32,
    pub padded_content_root: Hash32,
    pub blob_descriptor_id: Hash32,
    pub ordered_share_ids: Vec<Hash32>,
    pub stripe_id: Hash32,
}

impl ArtifactStripeV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        let expected_offset = u64::from(self.stripe_index)
            .checked_mul(u64::from(PADDED_STRIPE_BYTES))
            .ok_or(SpeciesError::ArtifactTooLarge)?;
        if self.version != ARTIFACT_STRIPE_VERSION
            || self.erasure_profile_id == [0; 32]
            || self.source_offset != expected_offset
            || self.padded_source_bytes != PADDED_STRIPE_BYTES
            || self.actual_source_bytes == 0
            || self.actual_source_bytes > PADDED_STRIPE_BYTES
            || self
                .actual_source_bytes
                .checked_add(self.zero_padding_bytes)
                != Some(PADDED_STRIPE_BYTES)
            || self.padded_content_root == [0; 32]
            || self.blob_descriptor_id == [0; 32]
            || self.ordered_share_ids.len() != POSITION_COUNT
            || self.ordered_share_ids.iter().any(|id| *id == [0; 32])
            || self
                .ordered_share_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != POSITION_COUNT
        {
            return Err(SpeciesError::InvalidArtifactSchema);
        }
        let mut encoder = Encoder::new(STRIPE_DOMAIN);
        encoder.u16(self.version);
        encoder.hash(&self.erasure_profile_id);
        encoder.u32(self.stripe_index);
        encoder.u64(self.source_offset);
        encoder.u32(self.padded_source_bytes);
        encoder.u32(self.actual_source_bytes);
        encoder.u32(self.zero_padding_bytes);
        encoder.hash(&self.padded_content_root);
        encoder.hash(&self.blob_descriptor_id);
        encoder.hashes(&self.ordered_share_ids);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(STRIPE_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        self.stripe_id = self.derived_id()?;
        Ok(self.stripe_id)
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.stripe_id == [0; 32] || self.derived_id()? != self.stripe_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactManifestV2 {
    pub version: u16,
    pub erasure_profile_id: Hash32,
    pub source_byte_length: u64,
    pub source_sha256: Hash32,
    pub payload_root: Hash32,
    pub stripe_ids: Vec<Hash32>,
    pub position_roots: Vec<Hash32>,
    pub final_actual_source_bytes: u32,
    pub final_zero_padding_bytes: u32,
    pub manifest_id: Hash32,
}

impl ArtifactManifestV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != ARTIFACT_MANIFEST_VERSION
            || self.erasure_profile_id == [0; 32]
            || self.source_byte_length != BONSAI_SOURCE_BYTES
            || self.source_sha256 == [0; 32]
            || self.payload_root == [0; 32]
            || self.stripe_ids.len() != BONSAI_STRIPE_COUNT
            || self.stripe_ids.iter().any(|id| *id == [0; 32])
            || self
                .stripe_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != BONSAI_STRIPE_COUNT
            || self.position_roots.len() != POSITION_COUNT
            || self.position_roots.iter().any(|root| *root == [0; 32])
            || self.final_actual_source_bytes != FINAL_SOURCE_BYTES
            || self.final_zero_padding_bytes != FINAL_PADDING_BYTES
        {
            return Err(SpeciesError::InvalidArtifactSchema);
        }
        let mut encoder = Encoder::new(MANIFEST_DOMAIN);
        encoder.u16(self.version);
        encoder.hash(&self.erasure_profile_id);
        encoder.u64(self.source_byte_length);
        encoder.hash(&self.source_sha256);
        encoder.hash(&self.payload_root);
        encoder.hashes(&self.stripe_ids);
        encoder.hashes(&self.position_roots);
        encoder.u32(self.final_actual_source_bytes);
        encoder.u32(self.final_zero_padding_bytes);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(MANIFEST_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        self.manifest_id = self.derived_id()?;
        Ok(self.manifest_id)
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.manifest_id == [0; 32] || self.derived_id()? != self.manifest_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDescriptorV2 {
    pub version: u16,
    pub kind: ArtifactKind,
    pub media_type: String,
    pub byte_length: u64,
    pub payload_root: Hash32,
    pub source_sha256: Hash32,
    pub manifest_id: Hash32,
    pub erasure_profile_id: Hash32,
    pub stripe_count: u32,
    pub license_root: Hash32,
    pub rights_root: Hash32,
    pub provenance_root: Hash32,
    pub publisher_keys: Vec<Hash32>,
    pub publisher_threshold: u8,
    pub published_height: u64,
    pub annotations_root: Hash32,
    pub descriptor_id: Hash32,
    pub signatures: Vec<PublisherSignatureV2>,
}

impl ArtifactDescriptorV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != ARTIFACT_DESCRIPTOR_VERSION
            || self.media_type.is_empty()
            || self.media_type.len() > 255
            || self.byte_length != BONSAI_SOURCE_BYTES
            || self.payload_root == [0; 32]
            || self.source_sha256 == [0; 32]
            || self.manifest_id == [0; 32]
            || self.erasure_profile_id == [0; 32]
            || usize::try_from(self.stripe_count).ok() != Some(BONSAI_STRIPE_COUNT)
            || self.license_root == [0; 32]
            || self.rights_root == [0; 32]
            || self.provenance_root == [0; 32]
            || self.annotations_root == [0; 32]
            || self.publisher_keys.is_empty()
            || self.publisher_keys.len() > 16
            || !strictly_sorted(&self.publisher_keys)
            || self.publisher_threshold == 0
            || usize::from(self.publisher_threshold) > self.publisher_keys.len()
        {
            return Err(SpeciesError::InvalidArtifactSchema);
        }
        let mut encoder = Encoder::new(DESCRIPTOR_DOMAIN);
        encoder.u16(self.version);
        encoder.u8(kind_tag(self.kind));
        encoder.string(&self.media_type);
        encoder.u64(self.byte_length);
        encoder.hash(&self.payload_root);
        encoder.hash(&self.source_sha256);
        encoder.hash(&self.manifest_id);
        encoder.hash(&self.erasure_profile_id);
        encoder.u32(self.stripe_count);
        encoder.hash(&self.license_root);
        encoder.hash(&self.rights_root);
        encoder.hash(&self.provenance_root);
        encoder.hashes(&self.publisher_keys);
        encoder.u8(self.publisher_threshold);
        encoder.u64(self.published_height);
        encoder.hash(&self.annotations_root);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(DESCRIPTOR_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        if !self.signatures.is_empty() {
            return Err(SpeciesError::InvalidArtifactSignature);
        }
        self.descriptor_id = self.derived_id()?;
        Ok(self.descriptor_id)
    }

    pub fn add_signature(&mut self, keypair: &Keypair) -> Result<(), SpeciesError> {
        if self.descriptor_id == [0; 32] || self.derived_id()? != self.descriptor_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        let index = signer_index(&self.publisher_keys, keypair)?;
        if self
            .signatures
            .iter()
            .any(|entry| entry.publisher_index == index)
        {
            return Err(SpeciesError::InvalidArtifactSignature);
        }
        let body = self.canonical_body()?;
        let signature = keypair
            .sign_domain(
                DomainId::SigWwm,
                &[DESCRIPTOR_DOMAIN.as_bytes(), &self.descriptor_id, &body],
            )
            .map_err(|_| SpeciesError::InvalidArtifactSignature)?;
        self.signatures.push(PublisherSignatureV2 {
            publisher_index: index,
            signature: signature.into_bytes(),
        });
        self.signatures.sort_by_key(|entry| entry.publisher_index);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.descriptor_id == [0; 32] || self.derived_id()? != self.descriptor_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        verify_threshold_signatures(
            DESCRIPTOR_DOMAIN,
            self.descriptor_id,
            &self.canonical_body()?,
            &self.publisher_keys,
            self.publisher_threshold,
            &self.signatures,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightManifestV2 {
    pub version: u16,
    pub artifact_id: Hash32,
    pub gguf_version: u32,
    pub architecture: String,
    pub file_type: u32,
    pub alignment: u32,
    pub metadata_count: u64,
    pub tensor_count: u64,
    pub q1_tensor_count: u64,
    pub f32_tensor_count: u64,
    pub data_offset: u64,
    pub metadata_root: Hash32,
    pub tensor_table_root: Hash32,
    pub tensor_bounds_root: Hash32,
    pub dtype_root: Hash32,
    pub quantization_root: Hash32,
    pub tokenizer_root: Hash32,
    pub special_token_root: Hash32,
    pub chat_template_root: Hash32,
    pub runtime_compatibility_root: Hash32,
    pub weight_manifest_id: Hash32,
}

impl WeightManifestV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != WEIGHT_MANIFEST_VERSION
            || self.artifact_id == [0; 32]
            || self.gguf_version != 3
            || self.architecture != "qwen35"
            || self.file_type != 40
            || self.alignment != 32
            || self.metadata_count == 0
            || self.tensor_count == 0
            || self.q1_tensor_count == 0
            || self.q1_tensor_count.checked_add(self.f32_tensor_count) != Some(self.tensor_count)
            || self.data_offset == 0
            || [
                self.metadata_root,
                self.tensor_table_root,
                self.tensor_bounds_root,
                self.dtype_root,
                self.quantization_root,
                self.tokenizer_root,
                self.special_token_root,
                self.chat_template_root,
                self.runtime_compatibility_root,
            ]
            .contains(&[0; 32])
        {
            return Err(SpeciesError::InvalidWeightManifest);
        }
        let mut encoder = Encoder::new(WEIGHT_DOMAIN);
        encoder.u16(self.version);
        encoder.hash(&self.artifact_id);
        encoder.u32(self.gguf_version);
        encoder.string(&self.architecture);
        encoder.u32(self.file_type);
        encoder.u32(self.alignment);
        encoder.u64(self.metadata_count);
        encoder.u64(self.tensor_count);
        encoder.u64(self.q1_tensor_count);
        encoder.u64(self.f32_tensor_count);
        encoder.u64(self.data_offset);
        encoder.hash(&self.metadata_root);
        encoder.hash(&self.tensor_table_root);
        encoder.hash(&self.tensor_bounds_root);
        encoder.hash(&self.dtype_root);
        encoder.hash(&self.quantization_root);
        encoder.hash(&self.tokenizer_root);
        encoder.hash(&self.special_token_root);
        encoder.hash(&self.chat_template_root);
        encoder.hash(&self.runtime_compatibility_root);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(WEIGHT_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        self.weight_manifest_id = self.derived_id()?;
        Ok(self.weight_manifest_id)
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.weight_manifest_id == [0; 32] || self.derived_id()? != self.weight_manifest_id {
            return Err(SpeciesError::InvalidWeightManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightInspectionReceiptV2 {
    pub version: u16,
    pub artifact_id: Hash32,
    pub weight_manifest_id: Hash32,
    pub runtime_build_id: Hash32,
    pub observed_byte_length: u64,
    pub observed_sha256: Hash32,
    pub observed_metadata_root: Hash32,
    pub observed_tensor_table_root: Hash32,
    pub inspector_public_key: Hash32,
    pub inspected_at_unix_seconds: u64,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl WeightInspectionReceiptV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != WEIGHT_INSPECTION_VERSION
            || self.observed_byte_length != BONSAI_SOURCE_BYTES
            || [
                self.artifact_id,
                self.weight_manifest_id,
                self.runtime_build_id,
                self.observed_sha256,
                self.observed_metadata_root,
                self.observed_tensor_table_root,
                self.inspector_public_key,
            ]
            .contains(&[0; 32])
            || self.inspected_at_unix_seconds == 0
        {
            return Err(SpeciesError::InvalidInspectionReceipt);
        }
        let mut encoder = Encoder::new(INSPECTION_DOMAIN);
        encoder.u16(self.version);
        encoder.hash(&self.artifact_id);
        encoder.hash(&self.weight_manifest_id);
        encoder.hash(&self.runtime_build_id);
        encoder.u64(self.observed_byte_length);
        encoder.hash(&self.observed_sha256);
        encoder.hash(&self.observed_metadata_root);
        encoder.hash(&self.observed_tensor_table_root);
        encoder.hash(&self.inspector_public_key);
        encoder.u64(self.inspected_at_unix_seconds);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(INSPECTION_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn sign(&mut self, keypair: &Keypair) -> Result<Hash32, SpeciesError> {
        if keypair.public_key().into_bytes() != self.inspector_public_key
            || self.signature != [0; 64]
        {
            return Err(SpeciesError::InvalidInspectionSignature);
        }
        self.receipt_id = self.derived_id()?;
        let body = self.canonical_body()?;
        self.signature = keypair
            .sign_domain(
                DomainId::SigWwm,
                &[INSPECTION_DOMAIN.as_bytes(), &self.receipt_id, &body],
            )
            .map_err(|_| SpeciesError::InvalidInspectionSignature)?
            .into_bytes();
        Ok(self.receipt_id)
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.receipt_id == [0; 32]
            || self.derived_id()? != self.receipt_id
            || self.signature == [0; 64]
        {
            return Err(SpeciesError::InvalidInspectionReceipt);
        }
        verify_domain(
            DomainId::SigWwm,
            &PublicKey::from_bytes(self.inspector_public_key),
            &[
                INSPECTION_DOMAIN.as_bytes(),
                &self.receipt_id,
                &self.canonical_body()?,
            ],
            &Signature::from_bytes(self.signature),
        )
        .map_err(|_| SpeciesError::InvalidInspectionSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDerivationV2 {
    pub version: u16,
    pub parents: Vec<Hash32>,
    pub output: Hash32,
    pub transform_root: Hash32,
    pub recipe_root: Hash32,
    pub provenance_root: Hash32,
    pub derivation_id: Hash32,
}

impl ArtifactDerivationV2 {
    pub fn canonical_body(&self) -> Result<Vec<u8>, SpeciesError> {
        if self.version != 2
            || self.parents.is_empty()
            || self.parents.len() > 32
            || !strictly_sorted(&self.parents)
            || self.parents.contains(&self.output)
            || [
                self.output,
                self.transform_root,
                self.recipe_root,
                self.provenance_root,
            ]
            .contains(&[0; 32])
        {
            return Err(SpeciesError::InvalidDerivation);
        }
        let mut encoder = Encoder::new(DERIVATION_DOMAIN);
        encoder.u16(self.version);
        encoder.hashes(&self.parents);
        encoder.hash(&self.output);
        encoder.hash(&self.transform_root);
        encoder.hash(&self.recipe_root);
        encoder.hash(&self.provenance_root);
        Ok(encoder.finish())
    }

    pub fn derived_id(&self) -> Result<Hash32, SpeciesError> {
        Ok(domain_hash(DERIVATION_DOMAIN, &[&self.canonical_body()?]))
    }

    pub fn finalize_id(&mut self) -> Result<Hash32, SpeciesError> {
        self.derivation_id = self.derived_id()?;
        Ok(self.derivation_id)
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.derivation_id == [0; 32] || self.derived_id()? != self.derivation_id {
            return Err(SpeciesError::InvalidDerivation);
        }
        Ok(())
    }
}

fn signer_index(keys: &[Hash32], keypair: &Keypair) -> Result<u8, SpeciesError> {
    let key = keypair.public_key().into_bytes();
    let index = keys
        .binary_search(&key)
        .map_err(|_| SpeciesError::InvalidArtifactSignature)?;
    u8::try_from(index).map_err(|_| SpeciesError::InvalidArtifactSignature)
}

fn verify_threshold_signatures(
    domain: &str,
    object_id: Hash32,
    body: &[u8],
    keys: &[Hash32],
    threshold: u8,
    signatures: &[PublisherSignatureV2],
) -> Result<(), SpeciesError> {
    if signatures.len() < usize::from(threshold)
        || signatures.len() > keys.len()
        || !signatures
            .windows(2)
            .all(|pair| pair[0].publisher_index < pair[1].publisher_index)
    {
        return Err(SpeciesError::InvalidArtifactSignature);
    }
    for entry in signatures {
        let key = keys
            .get(usize::from(entry.publisher_index))
            .ok_or(SpeciesError::InvalidArtifactSignature)?;
        verify_domain(
            DomainId::SigWwm,
            &PublicKey::from_bytes(*key),
            &[domain.as_bytes(), &object_id, body],
            &Signature::from_bytes(entry.signature),
        )
        .map_err(|_| SpeciesError::InvalidArtifactSignature)?;
    }
    Ok(())
}

fn kind_tag(kind: ArtifactKind) -> u8 {
    match kind {
        ArtifactKind::WeightShard => 0,
        ArtifactKind::Adapter => 1,
        ArtifactKind::Tokenizer => 2,
        ArtifactKind::DatasetShard => 3,
        ArtifactKind::Environment => 4,
        ArtifactKind::Evaluator => 5,
        ArtifactKind::Trace => 6,
        ArtifactKind::Proof => 7,
        ArtifactKind::Program => 8,
        ArtifactKind::Index => 9,
        ArtifactKind::MemoryCapsule => 10,
        ArtifactKind::UpdatePacket => 11,
        ArtifactKind::Report => 12,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn descriptor() -> (ArtifactDescriptorV2, Keypair, Keypair) {
        let first = Keypair::from_seed([1; 32]);
        let second = Keypair::from_seed([2; 32]);
        let mut keys = vec![
            first.public_key().into_bytes(),
            second.public_key().into_bytes(),
        ];
        keys.sort();
        let mut value = ArtifactDescriptorV2 {
            version: ARTIFACT_DESCRIPTOR_VERSION,
            kind: ArtifactKind::WeightShard,
            media_type: "application/vnd.gguf".into(),
            byte_length: BONSAI_SOURCE_BYTES,
            payload_root: h(1),
            source_sha256: h(2),
            manifest_id: h(3),
            erasure_profile_id: h(4),
            stripe_count: BONSAI_STRIPE_COUNT as u32,
            license_root: h(5),
            rights_root: h(6),
            provenance_root: h(7),
            publisher_keys: keys,
            publisher_threshold: 2,
            published_height: 9,
            annotations_root: h(8),
            descriptor_id: [0; 32],
            signatures: Vec::new(),
        };
        value.finalize_id().unwrap();
        (value, first, second)
    }

    #[test]
    fn descriptor_id_and_threshold_signatures_cover_whole_input() {
        let (mut value, first, second) = descriptor();
        value.add_signature(&first).unwrap();
        value.add_signature(&second).unwrap();
        value.validate().unwrap();
        let mut changed = value.clone();
        changed.rights_root[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(SpeciesError::ArtifactDigestMismatch)
        );
        let mut forged = value;
        forged.signatures[0].signature[0] ^= 1;
        assert_eq!(
            forged.validate(),
            Err(SpeciesError::InvalidArtifactSignature)
        );
    }

    #[test]
    fn manifest_is_identity_only_and_rejects_duplicates() {
        let mut value = ArtifactManifestV2 {
            version: ARTIFACT_MANIFEST_VERSION,
            erasure_profile_id: h(1),
            source_byte_length: BONSAI_SOURCE_BYTES,
            source_sha256: h(2),
            payload_root: h(3),
            stripe_ids: (0..BONSAI_STRIPE_COUNT)
                .map(|index| domain_hash("stripe", &[&index.to_be_bytes()]))
                .collect(),
            position_roots: (0..POSITION_COUNT)
                .map(|index| domain_hash("position", &[&index.to_be_bytes()]))
                .collect(),
            final_actual_source_bytes: FINAL_SOURCE_BYTES,
            final_zero_padding_bytes: FINAL_PADDING_BYTES,
            manifest_id: [0; 32],
        };
        value.finalize_id().unwrap();
        value.validate().unwrap();
        assert!(value.canonical_body().unwrap().len() < 65_536);
        let mut duplicate = value;
        duplicate.stripe_ids[1] = duplicate.stripe_ids[0];
        assert_eq!(
            duplicate.validate(),
            Err(SpeciesError::InvalidArtifactSchema)
        );
    }

    #[test]
    fn share_stripe_and_weight_ids_form_forward_only_dag() {
        let mut share = ArtifactShareV2 {
            version: ARTIFACT_SHARE_VERSION,
            erasure_profile_id: h(1),
            stripe_index: 0,
            position_index: 0,
            encoded_byte_length: SHARE_BYTES,
            full_share_digest: h(2),
            probe_root: h(3),
            probe_leaf_count: PROBE_LEAF_COUNT,
            probe_leaf_bytes: PROBE_LEAF_BYTES,
            share_id: [0; 32],
        };
        share.finalize_id().unwrap();
        share.validate().unwrap();

        let ordered_share_ids = (0_u8..POSITION_COUNT as u8)
            .map(|position| domain_hash("test-share", &[&[position]]))
            .collect::<Vec<_>>();
        let mut stripe = ArtifactStripeV2 {
            version: ARTIFACT_STRIPE_VERSION,
            erasure_profile_id: h(1),
            stripe_index: 0,
            source_offset: 0,
            padded_source_bytes: PADDED_STRIPE_BYTES,
            actual_source_bytes: PADDED_STRIPE_BYTES,
            zero_padding_bytes: 0,
            padded_content_root: h(4),
            blob_descriptor_id: h(5),
            ordered_share_ids,
            stripe_id: [0; 32],
        };
        stripe.finalize_id().unwrap();
        stripe.validate().unwrap();
        let stripe_id = stripe.stripe_id;
        stripe.ordered_share_ids[0] = share.share_id;
        assert_ne!(stripe.derived_id().unwrap(), stripe_id);

        let mut weight = WeightManifestV2 {
            version: WEIGHT_MANIFEST_VERSION,
            artifact_id: h(10),
            gguf_version: 3,
            architecture: "qwen35".into(),
            file_type: 40,
            alignment: 32,
            metadata_count: 37,
            tensor_count: 851,
            q1_tensor_count: 498,
            f32_tensor_count: 353,
            data_offset: 10_992_704,
            metadata_root: h(11),
            tensor_table_root: h(12),
            tensor_bounds_root: h(13),
            dtype_root: h(14),
            quantization_root: h(15),
            tokenizer_root: h(16),
            special_token_root: h(17),
            chat_template_root: h(18),
            runtime_compatibility_root: h(19),
            weight_manifest_id: [0; 32],
        };
        weight.finalize_id().unwrap();
        weight.validate().unwrap();
        let weight_id = weight.weight_manifest_id;
        weight.runtime_compatibility_root[0] ^= 1;
        assert_ne!(weight.derived_id().unwrap(), weight_id);
        assert_eq!(weight.validate(), Err(SpeciesError::InvalidWeightManifest));
    }

    #[test]
    fn inspection_signature_is_bound_to_every_observation() {
        let key = Keypair::from_seed([4; 32]);
        let mut receipt = WeightInspectionReceiptV2 {
            version: WEIGHT_INSPECTION_VERSION,
            artifact_id: h(1),
            weight_manifest_id: h(2),
            runtime_build_id: h(3),
            observed_byte_length: BONSAI_SOURCE_BYTES,
            observed_sha256: h(4),
            observed_metadata_root: h(5),
            observed_tensor_table_root: h(6),
            inspector_public_key: key.public_key().into_bytes(),
            inspected_at_unix_seconds: 7,
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        receipt.sign(&key).unwrap();
        receipt.validate().unwrap();
        receipt.observed_metadata_root[0] ^= 1;
        assert_eq!(
            receipt.validate(),
            Err(SpeciesError::InvalidInspectionReceipt)
        );
    }
}
