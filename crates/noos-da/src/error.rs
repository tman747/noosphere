//! Closed typed error law for the DA layer.
//!
//! Every rejection a full node, witness, or descriptor validator can emit is
//! one of these variants; conformance vectors cross-check rejections by the
//! stable [`DaError::class_name`] string (same convention as
//! `noos_codec::CodecError`).

use core::fmt;

/// Typed DA rejection. There is deliberately no "partial acceptance"
/// variant: reconstruction either yields the exact committed body or one of
/// these errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaError {
    /// Compressed DA form exceeds `MAX_BLOCK_DA_FORM_BYTES` (16 × 8 MiB).
    BodyTooLarge { len: u64 },
    /// A shard index is outside `0..BODY_TOTAL_SHARDS`.
    ShardIndexOutOfRange { index: u32 },
    /// A shard does not match the adaptive size derived from the body claim.
    WrongShardLength { index: u32, len: u64 },
    /// A shard's Merkle branch does not connect its leaf to the trusted
    /// shard root. The shard is rejected **individually**; reconstruction
    /// proceeds with the remaining candidates.
    ShardProofMismatch { index: u32 },
    /// Fewer than `BODY_DATA_SHARDS` distinct branch-valid shards survive:
    /// the body is unavailable from this candidate set.
    NotEnoughValidShards { valid: u32, needed: u32 },
    /// The erasure decoder failed even with enough shards (defensive; not
    /// reachable through the public API once the valid-count check passed).
    ReconstructionFailed,
    /// Re-encoding the reconstructed body does not reproduce the trusted
    /// shard root: the proposer committed to an inconsistent codeword.
    /// The whole body rejects — no partial acceptance.
    CommitmentMismatch,
    /// The reconstructed body does not hash to the content root bound
    /// inside every shard leaf (wrong claimed `content_root` or
    /// `original_bytes`).
    ContentRootMismatch,
    /// A reconstructed data byte beyond `original_bytes` is nonzero: the
    /// zero-padding law of the final data shard was violated at encode
    /// time, so the shard bytes were not canonical.
    NonZeroPadding,
    /// `BlobDescriptorV1.namespace` is not in the closed namespace registry.
    UnknownNamespace { namespace: u32 },
    /// `BlobDescriptorV1.codec_id` is not in the closed codec registry.
    UnknownCodec { codec_id: u16 },
    /// The descriptor names an artifact namespace where a consensus-body
    /// namespace is required (e.g. inside `consensus_blob_descriptors`).
    NamespaceNotConsensus { namespace: u32 },
    /// `original_bytes == 0`: an empty blob commits to nothing.
    EmptyBlob,
    /// `original_bytes` exceeds the namespace's blob limit.
    BlobTooLarge { original_bytes: u64, max: u64 },
    /// Shard geometry is invalid: zero shard size / counts, total shard
    /// count over the codec limit, shard size over the namespace limit,
    /// content overflowing capacity, or a non-minimal `data_shards`.
    ShardGeometry,
    /// `retention_epochs == 0`: a consensus blob must declare a horizon.
    ZeroRetention,
    /// A registered-domain hash primitive failed (wrong domain kind —
    /// unreachable through this crate's fixed call sites, kept typed).
    Crypto,
}

impl DaError {
    /// Stable class name used by conformance vectors.
    #[must_use]
    pub fn class_name(self) -> &'static str {
        match self {
            DaError::BodyTooLarge { .. } => "body_too_large",
            DaError::ShardIndexOutOfRange { .. } => "shard_index_out_of_range",
            DaError::WrongShardLength { .. } => "wrong_shard_length",
            DaError::ShardProofMismatch { .. } => "shard_proof_mismatch",
            DaError::NotEnoughValidShards { .. } => "not_enough_valid_shards",
            DaError::ReconstructionFailed => "reconstruction_failed",
            DaError::CommitmentMismatch => "commitment_mismatch",
            DaError::ContentRootMismatch => "content_root_mismatch",
            DaError::NonZeroPadding => "non_zero_padding",
            DaError::UnknownNamespace { .. } => "unknown_namespace",
            DaError::UnknownCodec { .. } => "unknown_codec",
            DaError::NamespaceNotConsensus { .. } => "namespace_not_consensus",
            DaError::EmptyBlob => "empty_blob",
            DaError::BlobTooLarge { .. } => "blob_too_large",
            DaError::ShardGeometry => "shard_geometry",
            DaError::ZeroRetention => "zero_retention",
            DaError::Crypto => "crypto",
        }
    }
}

impl fmt::Display for DaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaError::BodyTooLarge { len } => write!(f, "body of {len} bytes exceeds the maximum"),
            DaError::ShardIndexOutOfRange { index } => {
                write!(f, "shard index {index} out of range")
            }
            DaError::WrongShardLength { index, len } => {
                write!(f, "shard {index} has wrong length {len}")
            }
            DaError::ShardProofMismatch { index } => {
                write!(f, "shard {index} fails its Merkle branch")
            }
            DaError::NotEnoughValidShards { valid, needed } => {
                write!(f, "only {valid} valid shards of the {needed} needed")
            }
            DaError::ReconstructionFailed => f.write_str("erasure reconstruction failed"),
            DaError::CommitmentMismatch => {
                f.write_str("reconstructed shards do not reproduce the committed root")
            }
            DaError::ContentRootMismatch => {
                f.write_str("reconstructed body does not match the committed content root")
            }
            DaError::NonZeroPadding => f.write_str("nonzero byte in the zero-padding region"),
            DaError::UnknownNamespace { namespace } => {
                write!(f, "unknown blob namespace {namespace}")
            }
            DaError::UnknownCodec { codec_id } => write!(f, "unknown erasure codec {codec_id}"),
            DaError::NamespaceNotConsensus { namespace } => {
                write!(f, "namespace {namespace} is not a consensus-body namespace")
            }
            DaError::EmptyBlob => f.write_str("blob descriptor with zero original bytes"),
            DaError::BlobTooLarge {
                original_bytes,
                max,
            } => write!(
                f,
                "blob of {original_bytes} bytes exceeds namespace limit {max}"
            ),
            DaError::ShardGeometry => f.write_str("invalid shard geometry"),
            DaError::ZeroRetention => f.write_str("retention_epochs must be at least 1"),
            DaError::Crypto => f.write_str("registered-domain hash primitive failed"),
        }
    }
}

impl std::error::Error for DaError {}

impl From<noos_crypto::CryptoError> for DaError {
    fn from(_: noos_crypto::CryptoError) -> Self {
        DaError::Crypto
    }
}
