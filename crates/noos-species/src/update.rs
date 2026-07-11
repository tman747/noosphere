use crate::canonical::{strictly_sorted, Decoder, Encoder};
use crate::{domains, Hash32, SpeciesError, UpdateKind, UpdatePacket};

fn kind_tag(kind: UpdateKind) -> u8 {
    match kind {
        UpdateKind::LowRank => 0,
        UpdateKind::SparseDelta => 1,
        UpdateKind::GradientSketch => 2,
        UpdateKind::PreferenceBatch => 3,
        UpdateKind::TrajectoryBatch => 4,
        UpdateKind::DistillationBatch => 5,
        UpdateKind::EvaluatorPatch => 6,
    }
}

fn parse_kind(tag: u8) -> Result<UpdateKind, SpeciesError> {
    match tag {
        0 => Ok(UpdateKind::LowRank),
        1 => Ok(UpdateKind::SparseDelta),
        2 => Ok(UpdateKind::GradientSketch),
        3 => Ok(UpdateKind::PreferenceBatch),
        4 => Ok(UpdateKind::TrajectoryBatch),
        5 => Ok(UpdateKind::DistillationBatch),
        6 => Ok(UpdateKind::EvaluatorPatch),
        _ => Err(SpeciesError::UnknownEncoding),
    }
}

impl UpdatePacket {
    fn encode_fields(&self, include_id: bool) -> Vec<u8> {
        let mut value = Encoder::new(domains::UPDATE);
        if include_id {
            value.hash(&self.packet_id);
        }
        value.hashes(&self.base_members);
        value.u8(kind_tag(self.update_kind));
        value.hash(&self.payload);
        value.hash(&self.applicability_predicate);
        value.hash(&self.tokenizer);
        value.hash(&self.numeric_profile);
        value.optional_hash(self.training_recipe.as_ref());
        value.hashes(&self.source_capsules);
        value.optional_u64(self.policy_version);
        value.optional_hash(self.privacy_parameters_root.as_ref());
        value.hash(&self.rights_expression);
        value.hash(&self.provenance_root);
        value.hashes(&self.availability_commitments);
        value.hashes(&self.contributor_set);
        value.hashes(&self.evaluation_receipts);
        value.optional_u64(self.expiry);
        value.finish()
    }

    #[must_use]
    pub fn derived_id(&self) -> Hash32 {
        *blake3::hash(&self.encode_fields(false)).as_bytes()
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_fields(true)
    }

    pub fn validate_canonical(&self) -> Result<(), SpeciesError> {
        if self.base_members.is_empty()
            || !strictly_sorted(&self.base_members)
            || !strictly_sorted(&self.source_capsules)
            || !strictly_sorted(&self.availability_commitments)
            || !strictly_sorted(&self.contributor_set)
            || !strictly_sorted(&self.evaluation_receipts)
            || self.payload == [0; 32]
            || self.applicability_predicate == [0; 32]
            || self.tokenizer == [0; 32]
            || self.numeric_profile == [0; 32]
            || self.rights_expression == [0; 32]
            || self.provenance_root == [0; 32]
            || self.policy_version.is_none()
            || self.availability_commitments.is_empty()
        {
            return Err(SpeciesError::InvalidUpdatePacket);
        }
        if self.derived_id() != self.packet_id {
            return Err(SpeciesError::ArtifactDigestMismatch);
        }
        Ok(())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SpeciesError> {
        let mut value = Decoder::new(bytes, domains::UPDATE)?;
        let packet = Self {
            packet_id: value.hash()?,
            base_members: value.hashes()?,
            update_kind: parse_kind(value.u8()?)?,
            payload: value.hash()?,
            applicability_predicate: value.hash()?,
            tokenizer: value.hash()?,
            numeric_profile: value.hash()?,
            training_recipe: value.optional_hash()?,
            source_capsules: value.hashes()?,
            policy_version: value.optional_u64()?,
            privacy_parameters_root: value.optional_hash()?,
            rights_expression: value.hash()?,
            provenance_root: value.hash()?,
            availability_commitments: value.hashes()?,
            contributor_set: value.hashes()?,
            evaluation_receipts: value.hashes()?,
            expiry: value.optional_u64()?,
        };
        value.finish()?;
        packet.validate_canonical()?;
        if packet.canonical_bytes() != bytes {
            return Err(SpeciesError::NonCanonicalEncoding);
        }
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn packet() -> UpdatePacket {
        let mut packet = UpdatePacket {
            packet_id: [0; 32],
            base_members: vec![h(1), h(2)],
            update_kind: UpdateKind::LowRank,
            payload: h(3),
            applicability_predicate: h(4),
            tokenizer: h(5),
            numeric_profile: h(6),
            training_recipe: Some(h(7)),
            source_capsules: vec![h(8)],
            policy_version: Some(11),
            privacy_parameters_root: Some(h(9)),
            rights_expression: h(10),
            provenance_root: h(11),
            availability_commitments: vec![h(12), h(13)],
            contributor_set: vec![h(14)],
            evaluation_receipts: vec![h(15)],
            expiry: Some(20),
        };
        packet.packet_id = packet.derived_id();
        packet
    }

    #[test]
    fn claim_update_canonical_replay_identity_and_ambiguity_rejection() {
        let packet = packet();
        let bytes = packet.canonical_bytes();
        let decoded = UpdatePacket::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, packet);
        assert_eq!(decoded.canonical_bytes(), bytes);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            UpdatePacket::decode_canonical(&trailing),
            Err(SpeciesError::NonCanonicalEncoding)
        );

        let mut truncated = bytes.clone();
        truncated.pop();
        assert_eq!(
            UpdatePacket::decode_canonical(&truncated),
            Err(SpeciesError::MalformedEncoding)
        );

        let mut unknown_kind = bytes.clone();
        let kind_offset = 4 + domains::UPDATE.len() + 32 + 4 + (2 * 32);
        unknown_kind[kind_offset] = 255;
        assert_eq!(
            UpdatePacket::decode_canonical(&unknown_kind),
            Err(SpeciesError::UnknownEncoding)
        );

        let mut reordered = packet.clone();
        reordered.base_members.swap(0, 1);
        reordered.packet_id = reordered.derived_id();
        assert_eq!(
            UpdatePacket::decode_canonical(&reordered.canonical_bytes()),
            Err(SpeciesError::InvalidUpdatePacket)
        );

        let mut duplicate = packet;
        duplicate.availability_commitments = vec![h(12), h(12)];
        duplicate.packet_id = duplicate.derived_id();
        assert_eq!(
            UpdatePacket::decode_canonical(&duplicate.canonical_bytes()),
            Err(SpeciesError::InvalidUpdatePacket)
        );
    }

    #[test]
    fn claim_update_tamper_and_splice_change_identity() {
        let packet = packet();
        let mut tampered = packet.clone();
        tampered.policy_version = Some(10);
        assert_eq!(
            tampered.validate_canonical(),
            Err(SpeciesError::ArtifactDigestMismatch)
        );
        let mut spliced = packet;
        spliced.provenance_root = h(99);
        assert_eq!(
            spliced.validate_canonical(),
            Err(SpeciesError::ArtifactDigestMismatch)
        );
    }

    #[test]
    fn claim_update_stale_policy_and_expiry_reject_before_replay() {
        let packet = packet();
        let registry = crate::Registry::default();
        assert_eq!(
            registry.validate_update_at(&packet, 12, 19),
            Err(SpeciesError::StalePolicy)
        );
        assert_eq!(
            registry.validate_update_at(&packet, 11, 20),
            Err(SpeciesError::ExpiredUpdate)
        );
    }
}
