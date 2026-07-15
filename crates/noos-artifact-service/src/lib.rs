//! Isolated, bounded storage adapter for the canonical WWM artifact codec.
//!
//! This crate does not define artifact bytes, commitments, or reconstruction.
//! `noos-da` remains the sole codec implementation and `noos-store` owns the
//! physically isolated durable layout.

pub mod server;
pub mod web_bundle;
pub mod web_restore_import;

use noos_crypto::Hash32;
use noos_da::{
    share_commitment, ArtifactError, ArtifactManifestV1, ArtifactShareSink, ArtifactShareSource,
    ARTIFACT_POSITIONS, ARTIFACT_SHARE_BYTES, BONSAI_SOURCE_BYTES, BONSAI_STRIPES,
};
use noos_store::{
    ArtifactIngestSpec, ArtifactKey, ArtifactResumeState, ArtifactStore, ArtifactStoreError,
};
use serde::Serialize;

pub const BONSAI_ARTIFACT_ID_HEX: &str =
    "d3d1bcf9f704c58c695d7c0837be25a5cfbd7ff71b440bfc9be4a4a46bb528b0";
pub const BONSAI_PAYLOAD_ROOT_HEX: &str =
    "d9fd68fd5b262b0b3672f71c633956c93228e6e3f331ed92ef40e2647de475f7";
pub const BONSAI_MANIFEST_ROOT_HEX: &str =
    "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7";
pub const BONSAI_SHA256_HEX: &str =
    "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0";
// Frozen inside each codec descriptor and therefore the manifest root; this is
// distinct from the availability policy's evidence-retention horizon.
pub const BONSAI_RETENTION_EPOCHS: u32 = 1;

#[derive(Debug, Serialize)]
pub struct StoreVerificationReport {
    pub schema: &'static str,
    pub artifact_id: String,
    pub source_bytes: u64,
    pub published_sha256: String,
    pub protocol_payload_root: String,
    pub manifest_root: String,
    pub stripe_count: u32,
    pub position_count: u8,
    pub position_roots: Vec<String>,
    pub verified_share_count: u64,
    pub encoded_share_bytes: u64,
    pub store_used_bytes: u64,
    pub store_quota_bytes: u64,
    pub published: bool,
}

pub struct BonsaiStoreSink {
    store: ArtifactStore,
    artifact: ArtifactKey,
    initial_resume: Option<ArtifactResumeState>,
}

impl BonsaiStoreSink {
    pub fn new(store: ArtifactStore) -> Result<Self, String> {
        Ok(Self {
            store,
            artifact: decode_hex32(BONSAI_ARTIFACT_ID_HEX)?,
            initial_resume: None,
        })
    }

    #[must_use]
    pub fn initial_resume(&self) -> Option<&ArtifactResumeState> {
        self.initial_resume.as_ref()
    }

    #[must_use]
    pub fn store(&self) -> &ArtifactStore {
        &self.store
    }

    #[must_use]
    pub fn into_store(self) -> ArtifactStore {
        self.store
    }
}

impl ArtifactShareSink for BonsaiStoreSink {
    fn begin_artifact(
        &mut self,
        source_length: u64,
        protocol_payload_root: &Hash32,
        published_sha256: &[u8; 32],
        stripe_count: u32,
    ) -> Result<(), ArtifactError> {
        if source_length != BONSAI_SOURCE_BYTES || stripe_count != BONSAI_STRIPES {
            return Err(ArtifactError::InvalidManifest("Bonsai source geometry"));
        }
        let expected_payload = decode_hash(BONSAI_PAYLOAD_ROOT_HEX)?;
        let expected_sha = decode_hex32(BONSAI_SHA256_HEX).map_err(ArtifactError::Sink)?;
        if *protocol_payload_root != expected_payload || *published_sha256 != expected_sha {
            return Err(ArtifactError::InvalidManifest("Bonsai source identity"));
        }
        let state = self
            .store
            .begin_ingest(ArtifactIngestSpec {
                artifact: self.artifact,
                stripe_count,
                positions: (0..ARTIFACT_POSITIONS as u8).collect(),
            })
            .map_err(store_sink_error)?;
        self.initial_resume = Some(state);
        Ok(())
    }

    fn stage_share(
        &mut self,
        stripe: u32,
        position: u8,
        bytes: &[u8],
    ) -> Result<(), ArtifactError> {
        self.store
            .stage_share(&self.artifact, stripe, position, bytes)
            .map_err(store_sink_error)
    }

    fn checkpoint_stripe(&mut self, stripe: u32) -> Result<(), ArtifactError> {
        self.store
            .checkpoint_stripe(&self.artifact, stripe)
            .map_err(store_sink_error)?;
        let completed = stripe.saturating_add(1);
        if completed == BONSAI_STRIPES || completed.is_multiple_of(32) {
            eprintln!("ingest committed {completed}/{BONSAI_STRIPES} stripes");
        }
        Ok(())
    }

    fn publish_manifest(&mut self, manifest: &ArtifactManifestV1) -> Result<(), ArtifactError> {
        manifest.validate_bonsai_geometry()?;
        let actual_manifest_root = manifest.manifest_root();
        let expected_manifest_root = decode_hash(BONSAI_MANIFEST_ROOT_HEX)?;
        if actual_manifest_root != expected_manifest_root {
            return Err(ArtifactError::Sink(format!(
                "Bonsai manifest root mismatch: actual={} expected={}",
                hex::encode(actual_manifest_root.as_bytes()),
                BONSAI_MANIFEST_ROOT_HEX
            )));
        }
        self.store
            .publish(&self.artifact, &manifest.canonical_bytes())
            .map_err(store_sink_error)
    }
}

pub fn verify_bonsai_store(store: &ArtifactStore) -> Result<StoreVerificationReport, String> {
    let artifact = decode_hex32(BONSAI_ARTIFACT_ID_HEX)?;
    let manifest_bytes = store.read_manifest(&artifact).map_err(store_error)?;
    let manifest = ArtifactManifestV1::from_canonical_bytes(&manifest_bytes)
        .map_err(|error| error.to_string())?;
    manifest
        .validate_bonsai_geometry()
        .map_err(|error| error.to_string())?;

    let expected_sha = decode_hex32(BONSAI_SHA256_HEX)?;
    let expected_payload = decode_hex32(BONSAI_PAYLOAD_ROOT_HEX).map(Hash32::from_bytes)?;
    let expected_manifest = decode_hex32(BONSAI_MANIFEST_ROOT_HEX).map(Hash32::from_bytes)?;
    if manifest.published_sha256 != expected_sha
        || manifest.protocol_payload_root != expected_payload
        || manifest.manifest_root() != expected_manifest
    {
        return Err("published Bonsai manifest identity mismatch".into());
    }

    let mut share = vec![0_u8; ARTIFACT_SHARE_BYTES];
    let mut verified_share_count = 0_u64;
    for stripe in &manifest.stripes {
        for position in 0..ARTIFACT_POSITIONS as u8 {
            store
                .read_share(&artifact, stripe.stripe_index, position, &mut share)
                .map_err(store_error)?;
            let commitment = share_commitment(stripe.stripe_index, position, &share)
                .map_err(|error| error.to_string())?;
            if commitment != stripe.shares[position as usize] {
                return Err(format!(
                    "share commitment mismatch at stripe {} position {}",
                    stripe.stripe_index, position
                ));
            }
            verified_share_count = verified_share_count
                .checked_add(1)
                .ok_or_else(|| "share count overflow".to_string())?;
        }
    }

    let resume = store.resume_state(&artifact).map_err(store_error)?;
    let encoded_share_bytes = verified_share_count
        .checked_mul(ARTIFACT_SHARE_BYTES as u64)
        .ok_or_else(|| "encoded byte count overflow".to_string())?;
    Ok(StoreVerificationReport {
        schema: "noos.wwm.artifact-store-verification.v1",
        artifact_id: BONSAI_ARTIFACT_ID_HEX.into(),
        source_bytes: manifest.source_length,
        published_sha256: hex::encode(manifest.published_sha256),
        protocol_payload_root: hex::encode(manifest.protocol_payload_root.as_bytes()),
        manifest_root: hex::encode(manifest.manifest_root().as_bytes()),
        stripe_count: manifest.stripes.len() as u32,
        position_count: ARTIFACT_POSITIONS as u8,
        position_roots: manifest
            .position_roots
            .iter()
            .map(|root| hex::encode(root.as_bytes()))
            .collect(),
        verified_share_count,
        encoded_share_bytes,
        store_used_bytes: store.used_bytes(),
        store_quota_bytes: store.config().quota_bytes,
        published: resume.published,
    })
}

#[derive(Debug, Serialize)]
pub struct PositionRepairReport {
    pub schema: &'static str,
    pub artifact_id: String,
    pub manifest_root: String,
    pub repaired_position: u8,
    pub source_positions: Vec<u8>,
    pub repaired_shares: u32,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub position_root: String,
    pub replacement_store_used_bytes: u64,
    pub published: bool,
}

struct SelectedStoreSource<'a> {
    store: &'a ArtifactStore,
    artifact: ArtifactKey,
    selected: [bool; ARTIFACT_POSITIONS],
}

impl ArtifactShareSource for SelectedStoreSource<'_> {
    fn read_share(
        &mut self,
        stripe: u32,
        position: u8,
        out: &mut [u8],
    ) -> Result<bool, ArtifactError> {
        if !self
            .selected
            .get(position as usize)
            .copied()
            .unwrap_or(false)
        {
            return Ok(false);
        }
        match self.store.read_share(&self.artifact, stripe, position, out) {
            Ok(()) => Ok(true),
            Err(ArtifactStoreError::NotFound) => Ok(false),
            Err(error) => Err(store_sink_error(error)),
        }
    }
}

struct PositionRepairSink {
    store: ArtifactStore,
    artifact: ArtifactKey,
    position: u8,
}

impl ArtifactShareSink for PositionRepairSink {
    fn stage_share(
        &mut self,
        stripe: u32,
        position: u8,
        bytes: &[u8],
    ) -> Result<(), ArtifactError> {
        if position != self.position {
            return Err(ArtifactError::InvalidShare { stripe, position });
        }
        self.store
            .stage_share(&self.artifact, stripe, position, bytes)
            .map_err(store_sink_error)
    }

    fn checkpoint_stripe(&mut self, stripe: u32) -> Result<(), ArtifactError> {
        self.store
            .checkpoint_stripe(&self.artifact, stripe)
            .map_err(store_sink_error)
    }

    fn publish_manifest(&mut self, manifest: &ArtifactManifestV1) -> Result<(), ArtifactError> {
        self.store
            .publish(&self.artifact, &manifest.canonical_bytes())
            .map_err(store_sink_error)
    }
}

/// Repairs one complete Bonsai position using exactly eight other positions
/// through the sole `noos-hearth`/`noos-da` decoder path.
pub fn repair_bonsai_position(
    source_store: &ArtifactStore,
    mut replacement_store: ArtifactStore,
    missing_position: u8,
    source_positions: &[u8],
) -> Result<PositionRepairReport, String> {
    if missing_position as usize >= ARTIFACT_POSITIONS || source_positions.len() != 8 {
        return Err("repair requires one position in 0..12 and exactly eight sources".into());
    }
    let mut selected = [false; ARTIFACT_POSITIONS];
    for position in source_positions {
        let index = *position as usize;
        if index >= ARTIFACT_POSITIONS || *position == missing_position || selected[index] {
            return Err(
                "repair source positions must be unique, in range, and exclude target".into(),
            );
        }
        selected[index] = true;
    }
    let artifact = decode_hex32(BONSAI_ARTIFACT_ID_HEX)?;
    let manifest_bytes = source_store.read_manifest(&artifact).map_err(store_error)?;
    let manifest = ArtifactManifestV1::from_canonical_bytes(&manifest_bytes)
        .map_err(|error| error.to_string())?;
    manifest
        .validate_bonsai_geometry()
        .map_err(|error| error.to_string())?;
    if hex::encode(manifest.manifest_root().as_bytes()) != BONSAI_MANIFEST_ROOT_HEX {
        return Err("repair manifest is not the frozen Bonsai manifest".into());
    }
    replacement_store
        .begin_ingest(ArtifactIngestSpec {
            artifact,
            stripe_count: BONSAI_STRIPES,
            positions: vec![missing_position],
        })
        .map_err(store_error)?;
    let mut source = SelectedStoreSource {
        store: source_store,
        artifact,
        selected,
    };
    let mut sink = PositionRepairSink {
        store: replacement_store,
        artifact,
        position: missing_position,
    };
    noos_hearth::repair_artifact_position(&manifest, missing_position, &mut source, &mut sink)
        .map_err(|error| error.to_string())?;

    let mut share = vec![0_u8; ARTIFACT_SHARE_BYTES];
    for stripe in &manifest.stripes {
        sink.store
            .read_share(&artifact, stripe.stripe_index, missing_position, &mut share)
            .map_err(store_error)?;
        let commitment = share_commitment(stripe.stripe_index, missing_position, &share)
            .map_err(|error| error.to_string())?;
        if commitment != stripe.shares[missing_position as usize] {
            return Err(format!(
                "repaired share commitment mismatch at stripe {}",
                stripe.stripe_index
            ));
        }
    }
    let resume = sink.store.resume_state(&artifact).map_err(store_error)?;
    Ok(PositionRepairReport {
        schema: "noos.wwm.artifact-position-repair.v1",
        artifact_id: BONSAI_ARTIFACT_ID_HEX.into(),
        manifest_root: BONSAI_MANIFEST_ROOT_HEX.into(),
        repaired_position: missing_position,
        source_positions: source_positions.to_vec(),
        repaired_shares: BONSAI_STRIPES,
        bytes_read: u64::from(BONSAI_STRIPES)
            .saturating_mul(8)
            .saturating_mul(ARTIFACT_SHARE_BYTES as u64),
        bytes_written: u64::from(BONSAI_STRIPES).saturating_mul(ARTIFACT_SHARE_BYTES as u64),
        position_root: hex::encode(manifest.position_roots[missing_position as usize].as_bytes()),
        replacement_store_used_bytes: sink.store.used_bytes(),
        published: resume.published,
    })
}

fn store_sink_error(error: ArtifactStoreError) -> ArtifactError {
    ArtifactError::Sink(error.to_string())
}

fn store_error(error: ArtifactStoreError) -> String {
    error.to_string()
}

fn decode_hash(value: &str) -> Result<Hash32, ArtifactError> {
    decode_hex32(value)
        .map(Hash32::from_bytes)
        .map_err(ArtifactError::Sink)
}

fn decode_hex32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".to_string())
}
