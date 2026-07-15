//! # noos-da — NOOSPHERE consensus data availability (plan §7.1-7.2)
//!
//! Everything a full node needs to *hold* a block body before accepting it,
//! and everything a validator needs to judge a `BlobDescriptorV1`:
//!
//! * [`encode_body`] — Reed-Solomon encode canonical `BlockBodyV1` bytes
//!   into 32 fixed 64 KiB shards (16 data + 16 parity, PROPOSED-G0) under a
//!   domain-separated Merkle commitment (`body_da_root`);
//! * [`reconstruct_and_verify`] — the full-node acceptance law: any 16
//!   branch-valid shards reconstruct the exact committed body or fail
//!   typed ([`DaError`]); corrupt shards are rejected individually; a
//!   mismatched commitment rejects the whole body — no partial acceptance;
//! * [`AvailabilityLedger`] — the `body_available(root)` primitive
//!   consensus consults so witnesses never vote a checkpoint containing an
//!   unreconstructed ancestor (ch01 §10.1);
//! * [`verify_shard_sample`] — the light-client sampling primitive: a
//!   probabilistic availability **opinion** only, never acceptance;
//! * [`validate_blob_descriptor`] / [`validate_consensus_blob_descriptor`]
//!   — closed namespace/codec registries, retention, geometry, and the
//!   consensus-body vs artifact storage boundary (see [`descriptor`]).
//!
//! Wire objects are reused, not redefined: `BlockBodyV1` and
//! `BlobDescriptorV1` come from `noos-braid` (frozen da.md widths).
//!
//! ## Non-goals
//!
//! Shard transport lives in `noos-p2p` (`/noos/blob/shard/1`); durable
//! segment storage lives in `noos-store` (this crate only *names* the two
//! segment namespaces that keep artifact IO off the consensus path); the
//! light-client sampling *protocol* is out of scope — only its verification
//! primitive is provided here.
//!
//! Conformance vectors live in `protocol/vectors/da/`; the shared generator
//! is [`vector_gen`] (emitted by `bin/gen_vectors.rs`, re-verified by the
//! crate tests, so vectors can never drift from the implementation).

#![forbid(unsafe_code)]

pub mod artifact;
mod body;
pub mod custody;
mod descriptor;
mod error;
mod merkle;

pub mod vector_gen;

#[cfg(test)]
mod artifact_tests;
#[cfg(test)]
mod custody_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vector_tests;

pub use artifact::{
    artifact_global_share_index, probe_branch, share_commitment, verify_probe, ArtifactDecoderV1,
    ArtifactEncodeCheckpointV1, ArtifactEncoderV1, ArtifactError, ArtifactManifestV1,
    ArtifactShareCommitmentV1, ArtifactShareSink, ArtifactShareSource, ArtifactStripeV1,
    ARTIFACT_CODEC_WORKING_SET_BYTES, ARTIFACT_DATA_POSITIONS, ARTIFACT_MANIFEST_FIXED_BYTES,
    ARTIFACT_MANIFEST_GLOBAL_INDEX, ARTIFACT_MANIFEST_STRIPE_BYTES, ARTIFACT_MAX_SOURCE_BYTES,
    ARTIFACT_MAX_STRIPES, ARTIFACT_PARITY_POSITIONS, ARTIFACT_POSITIONS, ARTIFACT_PROBE_DEPTH,
    ARTIFACT_PROBE_LEAF_BYTES, ARTIFACT_PROBE_LEAVES, ARTIFACT_PROFILE_ID, ARTIFACT_SHARE_BYTES,
    ARTIFACT_STRIPE_BYTES, BONSAI_FINAL_ACTUAL_BYTES, BONSAI_FINAL_PADDING_BYTES,
    BONSAI_POSITION_BYTES, BONSAI_SOURCE_BYTES, BONSAI_STRIPES,
};
pub use body::{
    commit_shards, content_root, encode_body, encode_padded_region, reconstruct_and_verify,
    verify_body_shard, verify_shard_sample, AvailabilityLedger, BodyDaClaimV1, EncodedBodyV1,
    ReconstructedBodyV1, ShardCandidateV1, BODY_DATA_SHARDS, BODY_PARITY_SHARDS, BODY_SHARD_BYTES,
    BODY_SHARD_DEPTH, BODY_TOTAL_SHARDS, MAX_BLOCK_BODY_BYTES,
};
pub use descriptor::{
    codec_by_id, namespace_by_id, validate_blob_descriptor, validate_consensus_blob_descriptor,
    ErasureCodecSpec, NamespaceSpec, StorageDomain, CODEC_RS_GF8_V1, ERASURE_CODECS, NAMESPACES,
    NAMESPACE_CONSENSUS_AUX, NAMESPACE_LOOM_EVIDENCE, NAMESPACE_MODEL_WEIGHTS, NAMESPACE_NEL_TRACE,
};
pub use error::DaError;
pub use merkle::{fold_branch, shard_leaf, ShardBranch};
