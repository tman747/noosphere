//! Hearth orchestration for the canonical streaming artifact codec.
//!
//! Coding, commitments, padding, reconstruction, and repair are owned by
//! `noos-da`. Hearth deliberately contains no coding matrix or whole-artifact
//! encoded representation.

use std::io::{Read, Seek, Write};

pub use noos_da::{
    ArtifactDecoderV1, ArtifactEncoderV1, ArtifactError, ArtifactManifestV1, ArtifactShareSink,
    ArtifactShareSource, ARTIFACT_CODEC_WORKING_SET_BYTES, ARTIFACT_DATA_POSITIONS,
    ARTIFACT_PARITY_POSITIONS, ARTIFACT_POSITIONS, ARTIFACT_SHARE_BYTES, ARTIFACT_STRIPE_BYTES,
};

/// Stream a publisher source through the sole RS(8,4) implementation into a
/// durable, checkpointing share sink. The encoder publishes the manifest only
/// after all stripes and position roots are complete.
pub fn seed_artifact<R: Read + Seek, S: ArtifactShareSink>(
    source: &mut R,
    sink: &mut S,
    retention_epochs: u32,
) -> Result<ArtifactManifestV1, ArtifactError> {
    ArtifactEncoderV1::new()?.encode(source, sink, retention_epochs)
}

/// Reconstruct into a streaming consumer after verifying the manifest,
/// stripe/position commitments, final zero padding, payload root, and SHA-256.
pub fn fetch_artifact<S: ArtifactShareSource, W: Write>(
    manifest: &ArtifactManifestV1,
    source: &mut S,
    output: &mut W,
) -> Result<(), ArtifactError> {
    ArtifactDecoderV1::new()?.decode(manifest, source, output)
}

/// Stream-repair one missing position. The sink is responsible for staging
/// and atomic handover; the canonical decoder verifies every reconstructed
/// share and the manifest position root before publication.
pub fn repair_artifact_position<S: ArtifactShareSource, K: ArtifactShareSink>(
    manifest: &ArtifactManifestV1,
    missing_position: u8,
    source: &mut S,
    replacement: &mut K,
) -> Result<(), ArtifactError> {
    ArtifactDecoderV1::new()?.repair_position(manifest, missing_position, source, replacement)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedRaceObservation {
    pub fresh_hearths: u32,
    pub seeders: u8,
    pub median_join_seconds: u64,
    pub modeled_join_seconds: u64,
    pub corrupted_shares_accepted: u64,
    pub recovered_without_restart: bool,
}

impl SeedRaceObservation {
    #[must_use]
    pub fn threshold_met(self) -> bool {
        self.fresh_hearths >= 100
            && matches!(self.seeders, 5 | 10)
            && self.median_join_seconds <= self.modeled_join_seconds.saturating_mul(2)
            && self.corrupted_shares_accepted == 0
            && self.recovered_without_restart
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hearth_uses_the_bounded_canonical_profile() {
        assert_eq!(ARTIFACT_DATA_POSITIONS, 8);
        assert_eq!(ARTIFACT_PARITY_POSITIONS, 4);
        assert_eq!(ARTIFACT_POSITIONS, 12);
        assert!(ARTIFACT_CODEC_WORKING_SET_BYTES <= 32 * 1024 * 1024);
    }
}
