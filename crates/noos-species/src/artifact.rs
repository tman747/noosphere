use crate::canonical::{strictly_sorted, Encoder};
use crate::{domain_hash, domains, Artifact, ArtifactKind, Hash32, SpeciesError};
use std::collections::BTreeSet;

const SHARD_DOMAIN: &str = "NOOS/ARTIFACT/SHARD/V1";
const DERIVATION_DOMAIN: &str = "NOOS/ARTIFACT/DERIVATION/V1";

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

impl Artifact {
    fn identity_bytes(&self, payload: &[u8]) -> Vec<u8> {
        let mut value = Encoder::new(domains::ARTIFACT);
        value.u8(kind_tag(self.kind));
        value.string(&self.media_type);
        value.u64(self.byte_length);
        value.hash(&self.chunking_profile);
        value.hash(&self.availability_root);
        value.hash(&self.encoding);
        value.optional_hash(self.numeric_profile.as_ref());
        value.optional_hash(self.encryption_profile.as_ref());
        value.hash(&self.rights_root);
        value.hash(&self.creator);
        value.u64(self.created_at);
        value.hash(&self.annotations_root);
        value.bytes(payload);
        value.finish()
    }

    #[must_use]
    pub fn derived_id(&self, payload: &[u8]) -> Hash32 {
        *blake3::hash(&self.identity_bytes(payload)).as_bytes()
    }

    pub fn validate_schema(&self) -> Result<(), SpeciesError> {
        if self.media_type.is_empty()
            || self.media_type.len() > 255
            || self.chunking_profile == [0; 32]
            || self.availability_root == [0; 32]
            || self.encoding == [0; 32]
            || self.rights_root == [0; 32]
            || self.creator == [0; 32]
        {
            return Err(SpeciesError::InvalidArtifactSchema);
        }
        Ok(())
    }

    pub fn verify_payload(&self, payload: &[u8]) -> Result<(), SpeciesError> {
        self.validate_schema()?;
        if u64::try_from(payload.len()).map_err(|_| SpeciesError::ArtifactTooLarge)?
            != self.byte_length
        {
            return Err(SpeciesError::ArtifactLengthMismatch);
        }
        if self.derived_id(payload) != self.artifact_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationEdge {
    pub edge_id: Hash32,
    pub parents: Vec<Hash32>,
    pub output: Hash32,
    pub transform: Hash32,
    pub recipe: Hash32,
    pub provenance_root: Hash32,
    pub created_at: u64,
}

impl DerivationEdge {
    fn identity_bytes(&self) -> Vec<u8> {
        let mut value = Encoder::new(DERIVATION_DOMAIN);
        value.hashes(&self.parents);
        value.hash(&self.output);
        value.hash(&self.transform);
        value.hash(&self.recipe);
        value.hash(&self.provenance_root);
        value.u64(self.created_at);
        value.finish()
    }

    #[must_use]
    pub fn derived_id(&self) -> Hash32 {
        *blake3::hash(&self.identity_bytes()).as_bytes()
    }

    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.parents.is_empty()
            || !strictly_sorted(&self.parents)
            || self.parents.contains(&self.output)
            || self.transform == [0; 32]
            || self.recipe == [0; 32]
            || self.provenance_root == [0; 32]
        {
            return Err(SpeciesError::InvalidDerivation);
        }
        if self.derived_id() != self.edge_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureProfile {
    pub data_shards: u16,
    pub parity_shards: u16,
    pub shard_length: u32,
    pub original_length: u64,
}

impl ErasureProfile {
    pub fn validate(&self) -> Result<(), SpeciesError> {
        if self.data_shards == 0
            || self.parity_shards != 1
            || self.shard_length == 0
            || self.data_shards > 255
        {
            return Err(SpeciesError::UnsupportedErasureProfile);
        }
        let capacity = u64::from(self.data_shards)
            .checked_mul(u64::from(self.shard_length))
            .ok_or(SpeciesError::ArtifactTooLarge)?;
        if self.original_length == 0 || self.original_length > capacity {
            return Err(SpeciesError::UnsupportedErasureProfile);
        }
        Ok(())
    }

    #[must_use]
    pub const fn declared_loss_bound(self) -> u16 {
        self.parity_shards
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactShard {
    pub index: u16,
    pub bytes: Vec<u8>,
    pub digest: Hash32,
}

fn shard_digest(artifact_id: &Hash32, index: u16, bytes: &[u8]) -> Hash32 {
    domain_hash(SHARD_DOMAIN, &[artifact_id, &index.to_be_bytes(), bytes])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedArtifact {
    pub artifact_id: Hash32,
    pub profile: ErasureProfile,
    pub shards: Vec<ArtifactShard>,
}

impl EncodedArtifact {
    pub fn encode(
        artifact: &Artifact,
        payload: &[u8],
        data_shards: u16,
    ) -> Result<Self, SpeciesError> {
        artifact.verify_payload(payload)?;
        if data_shards == 0 || payload.is_empty() {
            return Err(SpeciesError::UnsupportedErasureProfile);
        }
        let length = u64::try_from(payload.len()).map_err(|_| SpeciesError::ArtifactTooLarge)?;
        let rounding = u64::from(data_shards)
            .checked_sub(1)
            .ok_or(SpeciesError::ArtifactTooLarge)?;
        let shard_length_u64 = length
            .checked_add(rounding)
            .ok_or(SpeciesError::ArtifactTooLarge)?
            .checked_div(u64::from(data_shards))
            .ok_or(SpeciesError::ArtifactTooLarge)?;
        let shard_length =
            u32::try_from(shard_length_u64).map_err(|_| SpeciesError::ArtifactTooLarge)?;
        let profile = ErasureProfile {
            data_shards,
            parity_shards: 1,
            shard_length,
            original_length: length,
        };
        profile.validate()?;
        let width = usize::try_from(shard_length).map_err(|_| SpeciesError::ArtifactTooLarge)?;
        let mut data = Vec::with_capacity(usize::from(data_shards));
        for index in 0..data_shards {
            let start = usize::from(index)
                .checked_mul(width)
                .ok_or(SpeciesError::ArtifactTooLarge)?;
            let end = start.saturating_add(width).min(payload.len());
            let mut bytes = vec![0; width];
            if start < payload.len() {
                let copied = end
                    .checked_sub(start)
                    .ok_or(SpeciesError::ArtifactTooLarge)?;
                bytes[..copied].copy_from_slice(&payload[start..end]);
            }
            data.push(bytes);
        }
        let mut parity = vec![0_u8; width];
        for shard in &data {
            for (out, byte) in parity.iter_mut().zip(shard) {
                *out ^= byte;
            }
        }
        data.push(parity);
        let shards = data
            .into_iter()
            .enumerate()
            .map(|(index, bytes)| {
                let index = u16::try_from(index).unwrap_or(u16::MAX);
                ArtifactShard {
                    index,
                    digest: shard_digest(&artifact.artifact_id, index, &bytes),
                    bytes,
                }
            })
            .collect();
        Ok(Self {
            artifact_id: artifact.artifact_id,
            profile,
            shards,
        })
    }

    pub fn reconstruct(
        &self,
        artifact: &Artifact,
        offered: &[ArtifactShard],
    ) -> Result<Vec<u8>, SpeciesError> {
        self.profile.validate()?;
        if artifact.artifact_id != self.artifact_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        let total = self
            .profile
            .data_shards
            .checked_add(self.profile.parity_shards)
            .ok_or(SpeciesError::ArtifactTooLarge)?;
        let width = usize::try_from(self.profile.shard_length)
            .map_err(|_| SpeciesError::ArtifactTooLarge)?;
        let mut seen = BTreeSet::new();
        let mut slots = vec![None; usize::from(total)];
        for shard in offered {
            if shard.index >= total || !seen.insert(shard.index) || shard.bytes.len() != width {
                return Err(SpeciesError::InvalidShard);
            }
            let expected_digest = self
                .shards
                .iter()
                .find(|expected| expected.index == shard.index)
                .map(|expected| expected.digest)
                .ok_or(SpeciesError::InvalidShard)?;
            if shard_digest(&self.artifact_id, shard.index, &shard.bytes) != shard.digest
                || shard.digest != expected_digest
            {
                return Err(SpeciesError::PoisonedShard);
            }
            slots[usize::from(shard.index)] = Some(shard.bytes.clone());
        }
        let missing = slots.iter().filter(|value| value.is_none()).count();
        if missing > usize::from(self.profile.declared_loss_bound()) {
            return Err(SpeciesError::LossBoundExceeded);
        }
        let parity_index = usize::from(self.profile.data_shards);
        let missing_data = (0..parity_index)
            .filter(|index| slots[*index].is_none())
            .collect::<Vec<_>>();
        if let Some(missing_index) = missing_data.first().copied() {
            let mut recovered = slots
                .get(parity_index)
                .and_then(Clone::clone)
                .ok_or(SpeciesError::LossBoundExceeded)?;
            for (index, shard) in slots.iter().enumerate().take(parity_index) {
                if index != missing_index {
                    let shard = shard.as_ref().ok_or(SpeciesError::LossBoundExceeded)?;
                    for (out, byte) in recovered.iter_mut().zip(shard) {
                        *out ^= byte;
                    }
                }
            }
            slots[missing_index] = Some(recovered);
        }
        let mut payload = Vec::new();
        for shard in slots.iter().take(parity_index) {
            payload.extend_from_slice(shard.as_ref().ok_or(SpeciesError::LossBoundExceeded)?);
        }
        let original_length = usize::try_from(self.profile.original_length)
            .map_err(|_| SpeciesError::ArtifactTooLarge)?;
        payload.truncate(original_length);
        artifact.verify_payload(&payload)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingTraffic {
    InteractiveToken,
    Batch,
    Replica,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardLocation {
    pub index: u16,
    pub site: Hash32,
    pub region: Hash32,
}

pub fn topology_local_indices(
    profile: ErasureProfile,
    locations: &[ShardLocation],
    request_site: Hash32,
    request_region: Hash32,
    traffic: ServingTraffic,
) -> Result<Vec<u16>, SpeciesError> {
    profile.validate()?;
    let total = profile
        .data_shards
        .checked_add(profile.parity_shards)
        .ok_or(SpeciesError::ArtifactTooLarge)?;
    let mut locations = locations.to_vec();
    locations.sort_by_key(|location| {
        let locality = if location.site == request_site {
            0
        } else if location.region == request_region {
            1
        } else {
            2
        };
        (locality, location.index, location.site)
    });
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for location in locations {
        if location.index >= total || !seen.insert(location.index) {
            continue;
        }
        if traffic == ServingTraffic::InteractiveToken && location.site != request_site {
            continue;
        }
        selected.push(location.index);
        if selected.len() == usize::from(profile.data_shards) {
            return Ok(selected);
        }
    }
    if traffic == ServingTraffic::InteractiveToken {
        Err(SpeciesError::WanPerTokenForbidden)
    } else {
        Err(SpeciesError::LossBoundExceeded)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn artifact(payload: &[u8]) -> Artifact {
        let mut artifact = Artifact {
            artifact_id: [0; 32],
            kind: ArtifactKind::Adapter,
            media_type: "application/noos-adapter".into(),
            byte_length: u64::try_from(payload.len()).unwrap(),
            chunking_profile: h(1),
            availability_root: h(2),
            encoding: h(3),
            numeric_profile: Some(h(4)),
            encryption_profile: None,
            rights_root: h(5),
            creator: h(6),
            created_at: 7,
            annotations_root: h(8),
        };
        artifact.artifact_id = artifact.derived_id(payload);
        artifact
    }

    #[test]
    fn claim_artifact_reconstructs_at_declared_loss_and_rejects_poison() {
        let payload = b"deterministic adapter payload with uneven shard boundary";
        let artifact = artifact(payload);
        let encoded = EncodedArtifact::encode(&artifact, payload, 4).unwrap();
        assert_eq!(encoded.profile.declared_loss_bound(), 1);
        for missing in 0..encoded.shards.len() {
            let offered = encoded
                .shards
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != missing)
                .map(|(_, shard)| shard.clone())
                .collect::<Vec<_>>();
            assert_eq!(encoded.reconstruct(&artifact, &offered).unwrap(), payload);
        }
        let mut poisoned = encoded.shards.clone();
        poisoned[0].bytes[0] ^= 1;
        poisoned[0].digest = shard_digest(&artifact.artifact_id, 0, &poisoned[0].bytes);
        assert_eq!(
            encoded.reconstruct(&artifact, &poisoned),
            Err(SpeciesError::PoisonedShard)
        );
        let mut spliced = artifact.clone();
        spliced.media_type = "application/different-schema".into();
        assert_eq!(
            encoded.reconstruct(&spliced, &encoded.shards),
            Err(SpeciesError::ArtifactDigestMismatch)
        );
    }

    #[test]
    fn claim_artifact_locality_escape_is_fail_closed() {
        let profile = ErasureProfile {
            data_shards: 2,
            parity_shards: 1,
            shard_length: 8,
            original_length: 16,
        };
        let local_site = h(1);
        let local_region = h(2);
        let locations = vec![
            ShardLocation {
                index: 0,
                site: local_site,
                region: local_region,
            },
            ShardLocation {
                index: 1,
                site: h(3),
                region: local_region,
            },
            ShardLocation {
                index: 2,
                site: h(4),
                region: h(5),
            },
        ];
        assert_eq!(
            topology_local_indices(
                profile,
                &locations,
                local_site,
                local_region,
                ServingTraffic::InteractiveToken,
            ),
            Err(SpeciesError::WanPerTokenForbidden)
        );
        assert_eq!(
            topology_local_indices(
                profile,
                &locations,
                local_site,
                local_region,
                ServingTraffic::Batch,
            )
            .unwrap(),
            vec![0, 1]
        );
    }

    #[test]
    fn claim_artifact_derivation_tamper_and_splice_reject() {
        let mut edge = DerivationEdge {
            edge_id: [0; 32],
            parents: vec![h(1), h(2)],
            output: h(3),
            transform: h(4),
            recipe: h(5),
            provenance_root: h(6),
            created_at: 7,
        };
        edge.edge_id = edge.derived_id();
        assert_eq!(edge.validate(), Ok(()));
        edge.parents.swap(0, 1);
        assert_eq!(edge.validate(), Err(SpeciesError::InvalidDerivation));
        edge.parents.sort();
        edge.provenance_root = h(9);
        assert_eq!(edge.validate(), Err(SpeciesError::ArtifactDigestMismatch));
    }
}
