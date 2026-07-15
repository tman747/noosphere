//! Streaming, stripe-bounded RS(8,4) artifact coding.
//!
//! This is the sole artifact codec. Consensus bodies retain their separately
//! named 16+16 profile in `body`; artifact callers use this module only.

use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};

use noos_braid::BlobDescriptorV1;
use noos_crypto::Hash32;
use noos_lumen::objects::{OptionalHash32, OptionalObject};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

pub const ARTIFACT_PROFILE_ID: u16 = 1;
pub const ARTIFACT_DATA_POSITIONS: usize = 8;
pub const ARTIFACT_PARITY_POSITIONS: usize = 4;
pub const ARTIFACT_POSITIONS: usize = 12;
pub const ARTIFACT_SHARE_BYTES: usize = 1_047_552;
pub const ARTIFACT_STRIPE_BYTES: usize = ARTIFACT_DATA_POSITIONS * ARTIFACT_SHARE_BYTES;
pub const ARTIFACT_PROBE_LEAVES: usize = 32;
pub const ARTIFACT_PROBE_LEAF_BYTES: usize = ARTIFACT_SHARE_BYTES / ARTIFACT_PROBE_LEAVES;
pub const ARTIFACT_PROBE_DEPTH: usize = 5;
pub const BONSAI_SOURCE_BYTES: u64 = 3_803_452_480;
pub const BONSAI_STRIPES: u32 = 454;
pub const BONSAI_FINAL_ACTUAL_BYTES: u32 = 7_124_032;
pub const BONSAI_FINAL_PADDING_BYTES: u32 = 1_256_384;
pub const BONSAI_POSITION_BYTES: u64 = 475_588_608;
pub const ARTIFACT_MANIFEST_GLOBAL_INDEX: u32 = u32::MAX;
pub const ARTIFACT_CODEC_WORKING_SET_BYTES: usize =
    ARTIFACT_POSITIONS * ARTIFACT_SHARE_BYTES + ARTIFACT_SHARE_BYTES + 512 * 32;
pub const ARTIFACT_MANIFEST_FIXED_BYTES: usize = 464;
pub const ARTIFACT_MANIFEST_STRIPE_BYTES: usize = 840;
pub const ARTIFACT_MAX_STRIPES: usize =
    (ARTIFACT_SHARE_BYTES - ARTIFACT_MANIFEST_FIXED_BYTES) / ARTIFACT_MANIFEST_STRIPE_BYTES;
pub const ARTIFACT_MAX_SOURCE_BYTES: u64 =
    ARTIFACT_MAX_STRIPES as u64 * ARTIFACT_STRIPE_BYTES as u64;
pub const ARTIFACT_CHECKPOINT_FIXED_BYTES: usize = 84;

const PAYLOAD_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/PAYLOAD/V1";
const STRIPE_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/STRIPE/V1";
const SHARE_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/SHARE/V1";
const PROBE_LEAF_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/PROBE-LEAF/V1";
const PROBE_NODE_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/PROBE-NODE/V1";
const POSITION_LEAF_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/POSITION-LEAF/V1";
const POSITION_NODE_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/POSITION-NODE/V1";
const POSITION_EMPTY_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/POSITION-EMPTY/V1";
const MANIFEST_DOMAIN: &[u8] = b"NOOS/WWM/ARTIFACT/MANIFEST/V1";

#[derive(Debug)]
pub enum ArtifactError {
    Io(std::io::Error),
    Empty,
    SourceLengthChanged,
    TooManyStripes,
    InvalidManifest(&'static str),
    InvalidShare { stripe: u32, position: u8 },
    InsufficientShares { stripe: u32, valid: u8 },
    ReedSolomon,
    Sink(String),
    NonZeroFinalPadding,
    OutputLength,
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "artifact I/O: {e}"),
            Self::Empty => f.write_str("empty artifacts are not canonical"),
            Self::SourceLengthChanged => {
                f.write_str("source length changed between hashing and coding passes")
            }
            Self::TooManyStripes => {
                f.write_str("artifact exceeds the bounded profile stripe count")
            }
            Self::InvalidManifest(s) => write!(f, "invalid artifact manifest: {s}"),
            Self::InvalidShare { stripe, position } => {
                write!(f, "invalid share at stripe {stripe}, position {position}")
            }
            Self::InsufficientShares { stripe, valid } => write!(
                f,
                "stripe {stripe} has {valid} valid shares; eight required"
            ),
            Self::ReedSolomon => f.write_str("Reed-Solomon operation failed"),
            Self::Sink(s) => write!(f, "artifact sink: {s}"),
            Self::NonZeroFinalPadding => f.write_str("final source-stripe padding is not all zero"),
            Self::OutputLength => f.write_str("decoded output length does not match manifest"),
        }
    }
}

impl std::error::Error for ArtifactError {}
impl From<std::io::Error> for ArtifactError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactShareCommitmentV1 {
    pub share_digest: Hash32,
    pub probe_root: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactStripeV1 {
    pub stripe_index: u32,
    pub descriptor: BlobDescriptorV1,
    pub actual_source_bytes: u32,
    pub padding_bytes: u32,
    pub shares: [ArtifactShareCommitmentV1; ARTIFACT_POSITIONS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactManifestV1 {
    pub version: u16,
    pub profile_id: u16,
    pub source_length: u64,
    pub protocol_payload_root: Hash32,
    pub published_sha256: [u8; 32],
    pub stripes: Vec<ArtifactStripeV1>,
    pub position_roots: [Hash32; ARTIFACT_POSITIONS],
}

impl ArtifactManifestV1 {
    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.version != 1 || self.profile_id != ARTIFACT_PROFILE_ID {
            return Err(ArtifactError::InvalidManifest("version/profile"));
        }
        if self.source_length == 0 || self.stripes.is_empty() {
            return Err(ArtifactError::InvalidManifest("empty"));
        }
        if self.source_length > ARTIFACT_MAX_SOURCE_BYTES {
            return Err(ArtifactError::TooManyStripes);
        }
        if self.stripes.len() > ARTIFACT_MAX_STRIPES {
            return Err(ArtifactError::TooManyStripes);
        }
        let expected_count = self.source_length.div_ceil(ARTIFACT_STRIPE_BYTES as u64);
        if expected_count != self.stripes.len() as u64 {
            return Err(ArtifactError::InvalidManifest("stripe count"));
        }
        let mut roots = [Hash32::ZERO; ARTIFACT_POSITIONS];
        for (i, stripe) in self.stripes.iter().enumerate() {
            if stripe.stripe_index != i as u32 {
                return Err(ArtifactError::InvalidManifest(
                    "non-contiguous stripe index",
                ));
            }
            validate_stripe_geometry(stripe, i + 1 == self.stripes.len(), self.source_length)?;
        }
        for (position, root) in roots.iter_mut().enumerate() {
            *root = position_root(&self.stripes, position as u8);
        }
        if roots != self.position_roots {
            return Err(ArtifactError::InvalidManifest("position roots"));
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.stripes.len() * 896);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.profile_id.to_le_bytes());
        out.extend_from_slice(&self.source_length.to_le_bytes());
        out.extend_from_slice(self.protocol_payload_root.as_bytes());
        out.extend_from_slice(&self.published_sha256);
        out.extend_from_slice(&(self.stripes.len() as u32).to_le_bytes());
        for stripe in &self.stripes {
            encode_stripe(stripe, &mut out);
        }
        for root in self.position_roots {
            out.extend_from_slice(root.as_bytes());
        }
        out
    }

    /// Decodes one whole canonical manifest. Length/count bounds are checked
    /// before allocating stripe storage, and trailing bytes are rejected.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < ARTIFACT_MANIFEST_FIXED_BYTES || bytes.len() > ARTIFACT_SHARE_BYTES {
            return Err(ArtifactError::InvalidManifest("manifest byte length"));
        }
        let mut at = 0_usize;
        let version = take_u16(bytes, &mut at)?;
        let profile_id = take_u16(bytes, &mut at)?;
        let source_length = take_u64(bytes, &mut at)?;
        let protocol_payload_root = Hash32::from_bytes(take_array::<32>(bytes, &mut at)?);
        let published_sha256 = take_array::<32>(bytes, &mut at)?;
        let count = take_u32(bytes, &mut at)? as usize;
        if count == 0 || count > ARTIFACT_MAX_STRIPES {
            return Err(ArtifactError::TooManyStripes);
        }
        let expected_len = ARTIFACT_MANIFEST_FIXED_BYTES
            .checked_add(
                count
                    .checked_mul(ARTIFACT_MANIFEST_STRIPE_BYTES)
                    .ok_or(ArtifactError::TooManyStripes)?,
            )
            .ok_or(ArtifactError::TooManyStripes)?;
        if bytes.len() != expected_len {
            return Err(ArtifactError::InvalidManifest("manifest count/length"));
        }
        let mut stripes = Vec::with_capacity(count);
        for _ in 0..count {
            stripes.push(decode_stripe(bytes, &mut at)?);
        }
        let mut position_roots = [Hash32::ZERO; ARTIFACT_POSITIONS];
        for root in &mut position_roots {
            *root = Hash32::from_bytes(take_array::<32>(bytes, &mut at)?);
        }
        if at != bytes.len() {
            return Err(ArtifactError::InvalidManifest("trailing bytes"));
        }
        let manifest = Self {
            version,
            profile_id,
            source_length,
            protocol_payload_root,
            published_sha256,
            stripes,
            position_roots,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    #[must_use]
    pub fn manifest_root(&self) -> Hash32 {
        domain_hash(MANIFEST_DOMAIN, &[&self.canonical_bytes()])
    }

    pub fn validate_bonsai_geometry(&self) -> Result<(), ArtifactError> {
        self.validate()?;
        if self.source_length != BONSAI_SOURCE_BYTES
            || self.stripes.len() != BONSAI_STRIPES as usize
        {
            return Err(ArtifactError::InvalidManifest("Bonsai length/stripe count"));
        }
        let last = self
            .stripes
            .last()
            .ok_or(ArtifactError::InvalidManifest("empty"))?;
        if last.actual_source_bytes != BONSAI_FINAL_ACTUAL_BYTES
            || last.padding_bytes != BONSAI_FINAL_PADDING_BYTES
        {
            return Err(ArtifactError::InvalidManifest("Bonsai final padding"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactEncodeCheckpointV1 {
    pub source_length: u64,
    pub protocol_payload_root: Hash32,
    pub published_sha256: [u8; 32],
    pub retention_epochs: u32,
    pub stripes: Vec<ArtifactStripeV1>,
}

impl ArtifactEncodeCheckpointV1 {
    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.source_length == 0
            || self.source_length > ARTIFACT_MAX_SOURCE_BYTES
            || self.retention_epochs == 0
            || self.stripes.len() > ARTIFACT_MAX_STRIPES
        {
            return Err(ArtifactError::InvalidManifest("checkpoint bounds"));
        }
        let total = self.source_length.div_ceil(ARTIFACT_STRIPE_BYTES as u64) as usize;
        if self.stripes.len() > total {
            return Err(ArtifactError::InvalidManifest("checkpoint stripe count"));
        }
        for (index, stripe) in self.stripes.iter().enumerate() {
            if stripe.stripe_index != index as u32
                || stripe.descriptor.retention_epochs != self.retention_epochs
            {
                return Err(ArtifactError::InvalidManifest("checkpoint continuity"));
            }
            validate_stripe_geometry(stripe, index + 1 == total, self.source_length)?;
        }
        Ok(())
    }

    /// Encodes a bounded, self-identifying checkpoint. It contains only
    /// complete contiguous stripe rows and is never a published manifest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        self.validate()?;
        let mut out = Vec::with_capacity(
            ARTIFACT_CHECKPOINT_FIXED_BYTES + self.stripes.len() * ARTIFACT_MANIFEST_STRIPE_BYTES,
        );
        out.extend_from_slice(&1_u16.to_le_bytes());
        out.extend_from_slice(&ARTIFACT_PROFILE_ID.to_le_bytes());
        out.extend_from_slice(&self.source_length.to_le_bytes());
        out.extend_from_slice(self.protocol_payload_root.as_bytes());
        out.extend_from_slice(&self.published_sha256);
        out.extend_from_slice(&self.retention_epochs.to_le_bytes());
        out.extend_from_slice(&(self.stripes.len() as u32).to_le_bytes());
        for stripe in &self.stripes {
            encode_stripe(stripe, &mut out);
        }
        Ok(out)
    }

    /// Decodes a whole checkpoint after checking its count and byte length
    /// before allocating rows. Unknown versions and trailing bytes reject.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < ARTIFACT_CHECKPOINT_FIXED_BYTES || bytes.len() > ARTIFACT_SHARE_BYTES {
            return Err(ArtifactError::InvalidManifest("checkpoint byte length"));
        }
        let mut at = 0_usize;
        if take_u16(bytes, &mut at)? != 1 || take_u16(bytes, &mut at)? != ARTIFACT_PROFILE_ID {
            return Err(ArtifactError::InvalidManifest("checkpoint version/profile"));
        }
        let source_length = take_u64(bytes, &mut at)?;
        let protocol_payload_root = Hash32::from_bytes(take_array::<32>(bytes, &mut at)?);
        let published_sha256 = take_array::<32>(bytes, &mut at)?;
        let retention_epochs = take_u32(bytes, &mut at)?;
        let count = take_u32(bytes, &mut at)? as usize;
        if count > ARTIFACT_MAX_STRIPES {
            return Err(ArtifactError::TooManyStripes);
        }
        let expected_len = ARTIFACT_CHECKPOINT_FIXED_BYTES
            .checked_add(
                count
                    .checked_mul(ARTIFACT_MANIFEST_STRIPE_BYTES)
                    .ok_or(ArtifactError::TooManyStripes)?,
            )
            .ok_or(ArtifactError::TooManyStripes)?;
        if bytes.len() != expected_len {
            return Err(ArtifactError::InvalidManifest("checkpoint count/length"));
        }
        let mut stripes = Vec::with_capacity(count);
        for _ in 0..count {
            stripes.push(decode_stripe(bytes, &mut at)?);
        }
        if at != bytes.len() {
            return Err(ArtifactError::InvalidManifest("checkpoint trailing bytes"));
        }
        let checkpoint = Self {
            source_length,
            protocol_payload_root,
            published_sha256,
            retention_epochs,
            stripes,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

pub trait ArtifactShareSink {
    /// Called after pass-one identity and bounds checks, before any share is staged.
    fn begin_artifact(
        &mut self,
        _source_length: u64,
        _protocol_payload_root: &Hash32,
        _published_sha256: &[u8; 32],
        _stripe_count: u32,
    ) -> Result<(), ArtifactError> {
        Ok(())
    }
    fn stage_share(&mut self, stripe: u32, position: u8, bytes: &[u8])
        -> Result<(), ArtifactError>;
    fn checkpoint_stripe(&mut self, stripe: u32) -> Result<(), ArtifactError>;
    /// Supplies the canonical row needed for a stripe-resumable checkpoint.
    fn checkpoint_artifact_stripe(
        &mut self,
        stripe: &ArtifactStripeV1,
    ) -> Result<(), ArtifactError> {
        self.checkpoint_stripe(stripe.stripe_index)
    }
    fn publish_manifest(&mut self, manifest: &ArtifactManifestV1) -> Result<(), ArtifactError>;
}

pub trait ArtifactShareSource {
    /// Fills `out` with one exact share. `Ok(false)` means unavailable.
    fn read_share(
        &mut self,
        stripe: u32,
        position: u8,
        out: &mut [u8],
    ) -> Result<bool, ArtifactError>;
}

pub struct ArtifactEncoderV1 {
    rs: ReedSolomon,
}
pub struct ArtifactDecoderV1 {
    rs: ReedSolomon,
}

impl ArtifactEncoderV1 {
    pub fn new() -> Result<Self, ArtifactError> {
        Ok(Self {
            rs: ReedSolomon::new(ARTIFACT_DATA_POSITIONS, ARTIFACT_PARITY_POSITIONS)
                .map_err(|_| ArtifactError::ReedSolomon)?,
        })
    }

    pub fn encode<R: Read + Seek, S: ArtifactShareSink>(
        &self,
        source: &mut R,
        sink: &mut S,
        retention_epochs: u32,
    ) -> Result<ArtifactManifestV1, ArtifactError> {
        self.encode_resume(source, sink, retention_epochs, None)
    }

    /// Resumes after the complete rows in `checkpoint`. Pass one is always
    /// repeated to bind the current source identity. Completed rows are
    /// re-derived and idempotently staged, so corrupt checkpoint rows or
    /// durable shares reject instead of being carried into a manifest.
    pub fn encode_resume<R: Read + Seek, S: ArtifactShareSink>(
        &self,
        source: &mut R,
        sink: &mut S,
        retention_epochs: u32,
        checkpoint: Option<&ArtifactEncodeCheckpointV1>,
    ) -> Result<ArtifactManifestV1, ArtifactError> {
        if retention_epochs == 0 {
            return Err(ArtifactError::InvalidManifest("zero retention"));
        }
        let start = source.stream_position()?;
        let mut payload_hasher = blake3::Hasher::new();
        payload_hasher.update(PAYLOAD_DOMAIN);
        let mut sha = Sha256::new();
        let mut scan = vec![0_u8; ARTIFACT_SHARE_BYTES];
        let mut source_length = 0_u64;
        loop {
            let n = source.read(&mut scan)?;
            if n == 0 {
                break;
            }
            source_length = source_length
                .checked_add(n as u64)
                .ok_or(ArtifactError::TooManyStripes)?;
            if source_length > ARTIFACT_MAX_SOURCE_BYTES {
                return Err(ArtifactError::TooManyStripes);
            }
            payload_hasher.update(&scan[..n]);
            sha.update(&scan[..n]);
        }
        if source_length == 0 {
            return Err(ArtifactError::Empty);
        }
        let stripe_count = source_length.div_ceil(ARTIFACT_STRIPE_BYTES as u64);
        if stripe_count > ARTIFACT_MAX_STRIPES as u64 {
            return Err(ArtifactError::TooManyStripes);
        }
        let protocol_payload_root = Hash32::from_bytes(*payload_hasher.finalize().as_bytes());
        let published_sha256: [u8; 32] = sha.finalize().into();
        let resumed = if let Some(saved) = checkpoint {
            saved.validate()?;
            if saved.source_length != source_length
                || saved.protocol_payload_root != protocol_payload_root
                || saved.published_sha256 != published_sha256
                || saved.retention_epochs != retention_epochs
            {
                return Err(ArtifactError::SourceLengthChanged);
            }
            saved.stripes.len()
        } else {
            0
        };
        sink.begin_artifact(
            source_length,
            &protocol_payload_root,
            &published_sha256,
            stripe_count as u32,
        )?;
        source.seek(SeekFrom::Start(start))?;

        let mut pass_two_payload = blake3::Hasher::new();
        pass_two_payload.update(PAYLOAD_DOMAIN);
        let mut pass_two_sha = Sha256::new();
        let mut stripes = checkpoint.map_or_else(
            || Vec::with_capacity(stripe_count as usize),
            |saved| {
                let mut rows = Vec::with_capacity(stripe_count as usize);
                rows.extend_from_slice(&saved.stripes);
                rows
            },
        );
        let mut consumed = 0_u64;
        for stripe_index in 0..stripe_count as u32 {
            let mut shards = (0..ARTIFACT_POSITIONS)
                .map(|_| vec![0_u8; ARTIFACT_SHARE_BYTES])
                .collect::<Vec<_>>();
            let remaining = source_length - consumed;
            let actual = remaining.min(ARTIFACT_STRIPE_BYTES as u64) as usize;
            let mut read_this = 0_usize;
            while read_this < actual {
                let data_position = read_this / ARTIFACT_SHARE_BYTES;
                let within = read_this % ARTIFACT_SHARE_BYTES;
                let wanted = (ARTIFACT_SHARE_BYTES - within).min(actual - read_this);
                let n = source.read(&mut shards[data_position][within..within + wanted])?;
                if n == 0 {
                    return Err(ArtifactError::SourceLengthChanged);
                }
                pass_two_payload.update(&shards[data_position][within..within + n]);
                pass_two_sha.update(&shards[data_position][within..within + n]);
                read_this += n;
            }
            let content = stripe_content_root(&shards[..ARTIFACT_DATA_POSITIONS]);
            if (stripe_index as usize) < resumed
                && content.as_bytes() != &stripes[stripe_index as usize].descriptor.content_root
            {
                return Err(ArtifactError::SourceLengthChanged);
            }
            self.rs
                .encode(&mut shards)
                .map_err(|_| ArtifactError::ReedSolomon)?;
            let mut commitments = [ArtifactShareCommitmentV1 {
                share_digest: Hash32::ZERO,
                probe_root: Hash32::ZERO,
            }; ARTIFACT_POSITIONS];
            for position in 0..ARTIFACT_POSITIONS {
                commitments[position] =
                    share_commitment(stripe_index, position as u8, &shards[position])?;
            }
            let row = ArtifactStripeV1 {
                stripe_index,
                descriptor: artifact_descriptor(content, retention_epochs),
                actual_source_bytes: actual as u32,
                padding_bytes: (ARTIFACT_STRIPE_BYTES - actual) as u32,
                shares: commitments,
            };
            if (stripe_index as usize) < resumed && row != stripes[stripe_index as usize] {
                return Err(ArtifactError::InvalidManifest("checkpoint stripe mismatch"));
            }
            for position in 0..ARTIFACT_POSITIONS {
                sink.stage_share(stripe_index, position as u8, &shards[position])?;
            }
            if (stripe_index as usize) >= resumed {
                sink.checkpoint_artifact_stripe(&row)?;
                stripes.push(row);
            }
            consumed += actual as u64;
        }
        if source.read(&mut scan[..1])? != 0
            || Hash32::from_bytes(*pass_two_payload.finalize().as_bytes()) != protocol_payload_root
            || <[u8; 32]>::from(pass_two_sha.finalize()) != published_sha256
        {
            return Err(ArtifactError::SourceLengthChanged);
        }
        let mut manifest = ArtifactManifestV1 {
            version: 1,
            profile_id: ARTIFACT_PROFILE_ID,
            source_length,
            protocol_payload_root,
            published_sha256,
            stripes,
            position_roots: [Hash32::ZERO; ARTIFACT_POSITIONS],
        };
        for position in 0..ARTIFACT_POSITIONS {
            manifest.position_roots[position] = position_root(&manifest.stripes, position as u8);
        }
        manifest.validate()?;
        debug_assert_eq!(
            manifest.canonical_bytes().len(),
            ARTIFACT_MANIFEST_FIXED_BYTES + manifest.stripes.len() * ARTIFACT_MANIFEST_STRIPE_BYTES,
        );
        sink.publish_manifest(&manifest)?;
        Ok(manifest)
    }
}

impl Default for ArtifactEncoderV1 {
    fn default() -> Self {
        Self::new().expect("fixed RS geometry")
    }
}

impl ArtifactDecoderV1 {
    pub fn new() -> Result<Self, ArtifactError> {
        Ok(Self {
            rs: ReedSolomon::new(ARTIFACT_DATA_POSITIONS, ARTIFACT_PARITY_POSITIONS)
                .map_err(|_| ArtifactError::ReedSolomon)?,
        })
    }

    pub fn decode<S: ArtifactShareSource, W: Write>(
        &self,
        manifest: &ArtifactManifestV1,
        source: &mut S,
        output: &mut W,
    ) -> Result<(), ArtifactError> {
        manifest.validate()?;
        let mut payload_hasher = blake3::Hasher::new();
        payload_hasher.update(PAYLOAD_DOMAIN);
        let mut sha = Sha256::new();
        let mut written = 0_u64;
        for stripe in &manifest.stripes {
            let shards = self.reconstruct_stripe(stripe, source)?;
            if stripe.padding_bytes != 0 {
                let start = stripe.actual_source_bytes as usize;
                if shards[..ARTIFACT_DATA_POSITIONS]
                    .iter()
                    .flatten()
                    .skip(start)
                    .any(|b| *b != 0)
                {
                    return Err(ArtifactError::NonZeroFinalPadding);
                }
            }
            let mut remaining = stripe.actual_source_bytes as usize;
            for shard in shards.iter().take(ARTIFACT_DATA_POSITIONS) {
                let n = remaining.min(ARTIFACT_SHARE_BYTES);
                if n == 0 {
                    break;
                }
                output.write_all(&shard[..n])?;
                payload_hasher.update(&shard[..n]);
                sha.update(&shard[..n]);
                remaining -= n;
                written += n as u64;
            }
        }
        if written != manifest.source_length {
            return Err(ArtifactError::OutputLength);
        }
        if Hash32::from_bytes(*payload_hasher.finalize().as_bytes())
            != manifest.protocol_payload_root
            || <[u8; 32]>::from(sha.finalize()) != manifest.published_sha256
        {
            return Err(ArtifactError::InvalidManifest("payload digest"));
        }
        Ok(())
    }

    fn reconstruct_stripe<S: ArtifactShareSource>(
        &self,
        stripe: &ArtifactStripeV1,
        source: &mut S,
    ) -> Result<Vec<Vec<u8>>, ArtifactError> {
        let mut slots: Vec<Option<Vec<u8>>> = (0..ARTIFACT_POSITIONS).map(|_| None).collect();
        let mut valid = 0_u8;
        for position in 0..ARTIFACT_POSITIONS {
            let mut bytes = vec![0_u8; ARTIFACT_SHARE_BYTES];
            if source.read_share(stripe.stripe_index, position as u8, &mut bytes)?
                && share_commitment(stripe.stripe_index, position as u8, &bytes)?
                    == stripe.shares[position]
            {
                slots[position] = Some(bytes);
                valid += 1;
            }
        }
        if valid < ARTIFACT_DATA_POSITIONS as u8 {
            return Err(ArtifactError::InsufficientShares {
                stripe: stripe.stripe_index,
                valid,
            });
        }
        self.rs
            .reconstruct(&mut slots)
            .map_err(|_| ArtifactError::ReedSolomon)?;
        let shards = slots
            .into_iter()
            .map(|s| s.expect("RS reconstructed every slot"))
            .collect::<Vec<_>>();
        if stripe_content_root(&shards[..ARTIFACT_DATA_POSITIONS]).as_bytes()
            != &stripe.descriptor.content_root
        {
            return Err(ArtifactError::InvalidManifest("stripe content root"));
        }
        for (position, shard) in shards.iter().enumerate() {
            if share_commitment(stripe.stripe_index, position as u8, shard)?
                != stripe.shares[position]
            {
                return Err(ArtifactError::InvalidShare {
                    stripe: stripe.stripe_index,
                    position: position as u8,
                });
            }
        }
        Ok(shards)
    }

    pub fn repair_position<S: ArtifactShareSource, K: ArtifactShareSink>(
        &self,
        manifest: &ArtifactManifestV1,
        missing_position: u8,
        source: &mut S,
        sink: &mut K,
    ) -> Result<(), ArtifactError> {
        manifest.validate()?;
        if missing_position as usize >= ARTIFACT_POSITIONS {
            return Err(ArtifactError::InvalidManifest("repair position"));
        }
        for stripe in &manifest.stripes {
            let shards = self.reconstruct_stripe(stripe, source)?;
            sink.stage_share(
                stripe.stripe_index,
                missing_position,
                &shards[missing_position as usize],
            )?;
            sink.checkpoint_stripe(stripe.stripe_index)?;
        }
        sink.publish_manifest(manifest)
    }
}

impl Default for ArtifactDecoderV1 {
    fn default() -> Self {
        Self::new().expect("fixed RS geometry")
    }
}

#[must_use]
pub fn artifact_global_share_index(stripe: u32, position: u8) -> Option<u32> {
    if position as usize >= ARTIFACT_POSITIONS {
        return None;
    }
    stripe
        .checked_mul(ARTIFACT_POSITIONS as u32)?
        .checked_add(position as u32)
}

pub fn share_commitment(
    stripe: u32,
    position: u8,
    share: &[u8],
) -> Result<ArtifactShareCommitmentV1, ArtifactError> {
    if position as usize >= ARTIFACT_POSITIONS || share.len() != ARTIFACT_SHARE_BYTES {
        return Err(ArtifactError::InvalidShare { stripe, position });
    }
    let share_digest = domain_hash(SHARE_DOMAIN, &[&stripe.to_le_bytes(), &[position], share]);
    let mut leaves = [Hash32::ZERO; ARTIFACT_PROBE_LEAVES];
    for (i, leaf) in leaves.iter_mut().enumerate() {
        *leaf = domain_hash(
            PROBE_LEAF_DOMAIN,
            &[
                &stripe.to_le_bytes(),
                &[position],
                &(i as u8).to_le_bytes(),
                &share[i * ARTIFACT_PROBE_LEAF_BYTES..(i + 1) * ARTIFACT_PROBE_LEAF_BYTES],
            ],
        );
    }
    Ok(ArtifactShareCommitmentV1 {
        share_digest,
        probe_root: fixed_merkle_root(leaves.to_vec(), PROBE_NODE_DOMAIN),
    })
}

pub fn probe_branch(
    stripe: u32,
    position: u8,
    share: &[u8],
    leaf_index: u8,
) -> Result<
    (
        [u8; ARTIFACT_PROBE_LEAF_BYTES],
        [Hash32; ARTIFACT_PROBE_DEPTH],
    ),
    ArtifactError,
> {
    if leaf_index as usize >= ARTIFACT_PROBE_LEAVES {
        return Err(ArtifactError::InvalidShare { stripe, position });
    }
    let commitment = share_commitment(stripe, position, share)?;
    let _ = commitment;
    let mut leaves = Vec::with_capacity(ARTIFACT_PROBE_LEAVES);
    for i in 0..ARTIFACT_PROBE_LEAVES {
        leaves.push(domain_hash(
            PROBE_LEAF_DOMAIN,
            &[
                &stripe.to_le_bytes(),
                &[position],
                &(i as u8).to_le_bytes(),
                &share[i * ARTIFACT_PROBE_LEAF_BYTES..(i + 1) * ARTIFACT_PROBE_LEAF_BYTES],
            ],
        ));
    }
    let mut branch = [Hash32::ZERO; ARTIFACT_PROBE_DEPTH];
    let mut pos = leaf_index as usize;
    let mut level = leaves;
    for sibling in &mut branch {
        *sibling = level[pos ^ 1];
        level = level
            .chunks_exact(2)
            .map(|p| domain_hash(PROBE_NODE_DOMAIN, &[p[0].as_bytes(), p[1].as_bytes()]))
            .collect();
        pos /= 2;
    }
    let mut bytes = [0_u8; ARTIFACT_PROBE_LEAF_BYTES];
    bytes.copy_from_slice(
        &share[leaf_index as usize * ARTIFACT_PROBE_LEAF_BYTES
            ..(leaf_index as usize + 1) * ARTIFACT_PROBE_LEAF_BYTES],
    );
    Ok((bytes, branch))
}

pub fn verify_probe(
    root: &Hash32,
    stripe: u32,
    position: u8,
    leaf_index: u8,
    bytes: &[u8],
    branch: &[Hash32; ARTIFACT_PROBE_DEPTH],
) -> bool {
    if position as usize >= ARTIFACT_POSITIONS
        || leaf_index as usize >= ARTIFACT_PROBE_LEAVES
        || bytes.len() != ARTIFACT_PROBE_LEAF_BYTES
    {
        return false;
    }
    let mut hash = domain_hash(
        PROBE_LEAF_DOMAIN,
        &[
            &stripe.to_le_bytes(),
            &[position],
            &leaf_index.to_le_bytes(),
            bytes,
        ],
    );
    let mut pos = leaf_index as usize;
    for sibling in branch {
        hash = if pos & 1 == 0 {
            domain_hash(PROBE_NODE_DOMAIN, &[hash.as_bytes(), sibling.as_bytes()])
        } else {
            domain_hash(PROBE_NODE_DOMAIN, &[sibling.as_bytes(), hash.as_bytes()])
        };
        pos /= 2;
    }
    &hash == root
}

fn take_array<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], ArtifactError> {
    let end = at
        .checked_add(N)
        .ok_or(ArtifactError::InvalidManifest("decode overflow"))?;
    let slice = bytes
        .get(*at..end)
        .ok_or(ArtifactError::InvalidManifest("truncated manifest"))?;
    *at = end;
    Ok(slice.try_into().expect("bounded array length"))
}
fn take_u8(bytes: &[u8], at: &mut usize) -> Result<u8, ArtifactError> {
    Ok(take_array::<1>(bytes, at)?[0])
}
fn take_u16(bytes: &[u8], at: &mut usize) -> Result<u16, ArtifactError> {
    Ok(u16::from_le_bytes(take_array(bytes, at)?))
}
fn take_u32(bytes: &[u8], at: &mut usize) -> Result<u32, ArtifactError> {
    Ok(u32::from_le_bytes(take_array(bytes, at)?))
}
fn take_u64(bytes: &[u8], at: &mut usize) -> Result<u64, ArtifactError> {
    Ok(u64::from_le_bytes(take_array(bytes, at)?))
}

fn artifact_descriptor(content_root: Hash32, retention_epochs: u32) -> BlobDescriptorV1 {
    BlobDescriptorV1 {
        namespace: 3,
        content_root: content_root.into_bytes(),
        original_bytes: ARTIFACT_STRIPE_BYTES as u64,
        shard_bytes: ARTIFACT_SHARE_BYTES as u32,
        data_shards: 8,
        parity_shards: 4,
        retention_epochs,
        codec_id: 1,
        encryption_descriptor: OptionalObject(None),
        access_policy_root: OptionalHash32(None),
    }
}

fn validate_stripe_geometry(
    stripe: &ArtifactStripeV1,
    final_stripe: bool,
    source_length: u64,
) -> Result<(), ArtifactError> {
    let d = &stripe.descriptor;
    if d.namespace != 3
        || d.original_bytes != ARTIFACT_STRIPE_BYTES as u64
        || d.shard_bytes != ARTIFACT_SHARE_BYTES as u32
        || d.data_shards != 8
        || d.parity_shards != 4
        || d.codec_id != 1
        || d.retention_epochs == 0
        || d.encryption_descriptor.0.is_some()
        || d.access_policy_root.0.is_some()
    {
        return Err(ArtifactError::InvalidManifest("descriptor geometry"));
    }
    if stripe.actual_source_bytes as usize + stripe.padding_bytes as usize != ARTIFACT_STRIPE_BYTES
        || stripe.actual_source_bytes == 0
    {
        return Err(ArtifactError::InvalidManifest("actual/padding sum"));
    }
    if !final_stripe
        && (stripe.actual_source_bytes as usize != ARTIFACT_STRIPE_BYTES
            || stripe.padding_bytes != 0)
    {
        return Err(ArtifactError::InvalidManifest("non-final padding"));
    }
    if final_stripe {
        let expected =
            (source_length - u64::from(stripe.stripe_index) * ARTIFACT_STRIPE_BYTES as u64) as u32;
        if stripe.actual_source_bytes != expected
            || stripe.padding_bytes != ARTIFACT_STRIPE_BYTES as u32 - expected
        {
            return Err(ArtifactError::InvalidManifest("final padding law"));
        }
    }
    Ok(())
}

fn stripe_content_root(data: &[Vec<u8>]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(STRIPE_DOMAIN);
    h.update(&(ARTIFACT_STRIPE_BYTES as u64).to_le_bytes());
    for shard in data {
        h.update(shard);
    }
    Hash32::from_bytes(*h.finalize().as_bytes())
}

fn position_root(stripes: &[ArtifactStripeV1], position: u8) -> Hash32 {
    let mut leaves = Vec::with_capacity(stripes.len().next_power_of_two());
    for stripe in stripes {
        let c = stripe.shares[position as usize];
        leaves.push(domain_hash(
            POSITION_LEAF_DOMAIN,
            &[
                &stripe.stripe_index.to_le_bytes(),
                &[position],
                c.share_digest.as_bytes(),
                c.probe_root.as_bytes(),
            ],
        ));
    }
    let width = leaves.len().next_power_of_two();
    for index in leaves.len()..width {
        leaves.push(domain_hash(
            POSITION_EMPTY_DOMAIN,
            &[&position.to_le_bytes(), &(index as u32).to_le_bytes()],
        ));
    }
    fixed_merkle_root(leaves, POSITION_NODE_DOMAIN)
}

fn fixed_merkle_root(mut level: Vec<Hash32>, domain: &[u8]) -> Hash32 {
    debug_assert!(!level.is_empty() && level.len().is_power_of_two());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|p| domain_hash(domain, &[p[0].as_bytes(), p[1].as_bytes()]))
            .collect();
    }
    level[0]
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    Hash32::from_bytes(*h.finalize().as_bytes())
}

fn encode_stripe(stripe: &ArtifactStripeV1, out: &mut Vec<u8>) {
    out.extend_from_slice(&stripe.stripe_index.to_le_bytes());
    encode_descriptor(&stripe.descriptor, out);
    out.extend_from_slice(&stripe.actual_source_bytes.to_le_bytes());
    out.extend_from_slice(&stripe.padding_bytes.to_le_bytes());
    for share in stripe.shares {
        out.extend_from_slice(share.share_digest.as_bytes());
        out.extend_from_slice(share.probe_root.as_bytes());
    }
}

fn decode_stripe(bytes: &[u8], at: &mut usize) -> Result<ArtifactStripeV1, ArtifactError> {
    let stripe_index = take_u32(bytes, at)?;
    let namespace = take_u32(bytes, at)?;
    let content_root = take_array::<32>(bytes, at)?;
    let original_bytes = take_u64(bytes, at)?;
    let shard_bytes = take_u32(bytes, at)?;
    let data_shards = take_u16(bytes, at)?;
    let parity_shards = take_u16(bytes, at)?;
    let retention_epochs = take_u32(bytes, at)?;
    let codec_id = take_u16(bytes, at)?;
    if take_u8(bytes, at)? != 0 || take_u8(bytes, at)? != 0 {
        return Err(ArtifactError::InvalidManifest("descriptor optional fields"));
    }
    let actual_source_bytes = take_u32(bytes, at)?;
    let padding_bytes = take_u32(bytes, at)?;
    let mut shares = [ArtifactShareCommitmentV1 {
        share_digest: Hash32::ZERO,
        probe_root: Hash32::ZERO,
    }; ARTIFACT_POSITIONS];
    for share in &mut shares {
        share.share_digest = Hash32::from_bytes(take_array::<32>(bytes, at)?);
        share.probe_root = Hash32::from_bytes(take_array::<32>(bytes, at)?);
    }
    Ok(ArtifactStripeV1 {
        stripe_index,
        descriptor: BlobDescriptorV1 {
            namespace,
            content_root,
            original_bytes,
            shard_bytes,
            data_shards,
            parity_shards,
            retention_epochs,
            codec_id,
            encryption_descriptor: OptionalObject(None),
            access_policy_root: OptionalHash32(None),
        },
        actual_source_bytes,
        padding_bytes,
        shares,
    })
}

fn encode_descriptor(d: &BlobDescriptorV1, out: &mut Vec<u8>) {
    out.extend_from_slice(&d.namespace.to_le_bytes());
    out.extend_from_slice(&d.content_root);
    out.extend_from_slice(&d.original_bytes.to_le_bytes());
    out.extend_from_slice(&d.shard_bytes.to_le_bytes());
    out.extend_from_slice(&d.data_shards.to_le_bytes());
    out.extend_from_slice(&d.parity_shards.to_le_bytes());
    out.extend_from_slice(&d.retention_epochs.to_le_bytes());
    out.extend_from_slice(&d.codec_id.to_le_bytes());
    // This profile forbids both optional descriptor fields; encode explicit absent tags.
    out.push(0);
    out.push(0);
}
