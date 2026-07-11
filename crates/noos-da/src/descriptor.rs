//! `BlobDescriptorV1` semantics (ch01 §10.2; schema-tables/da.md): closed
//! namespace and erasure-codec registries, retention, geometry, and the
//! consensus-body vs artifact storage boundary.
//!
//! The wire type itself is [`noos_braid::BlobDescriptorV1`] (frozen widths,
//! da.md); this module owns what the fields *mean* and which descriptors a
//! validator accepts.
//!
//! ## Storage boundary (plan §7.2)
//!
//! Consensus-body bytes (block bodies and fee-paid consensus blobs, fee
//! dimension D) and Work-Loom/model/evidence **artifacts** are distinct
//! storage domains so artifact traffic can never starve consensus IO:
//!
//! * distinct types — [`StorageDomain::ConsensusBody`] vs
//!   [`StorageDomain::Artifact`] is carried by every registered namespace
//!   and is not convertible;
//! * distinct `noos-store` segment namespaces — a node opens one blob
//!   segment store per domain, rooted at
//!   [`StorageDomain::segment_namespace`] (`segments/consensus-body` vs
//!   `segments/artifact` under the store root). Artifact blobs never enter
//!   the consensus segment files, its blob index, or its retention
//!   accounting, and vice versa.
//!
//! Retention: consensus blobs are fee-paid and retained through their
//! declared `retention_epochs` horizon; archival beyond the horizon is a
//! market, not consensus law. Artifacts follow the Work Loom availability
//! lifecycle (ch01 §10.1) and are **not** consensus data unless a
//! registered proof verifier requires them synchronously.

use noos_braid::BlobDescriptorV1;

use crate::error::DaError;

/// Which physically separated storage a namespace's bytes live in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageDomain {
    /// Consensus data: block bodies and fee-paid consensus blobs. All bytes
    /// required to validate a block before its deadline live here.
    ConsensusBody,
    /// Work-Loom / model / evidence artifacts (Loom availability
    /// lifecycle; never consensus data).
    Artifact,
}

impl StorageDomain {
    /// The `noos-store` segment namespace (directory under the store root)
    /// this domain's blob segments are rooted at. Two distinct stores keep
    /// artifact IO off the consensus path.
    #[must_use]
    pub const fn segment_namespace(self) -> &'static str {
        match self {
            StorageDomain::ConsensusBody => "segments/consensus-body",
            StorageDomain::Artifact => "segments/artifact",
        }
    }
}

/// One row of the closed namespace registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceSpec {
    pub id: u32,
    pub name: &'static str,
    pub domain: StorageDomain,
    /// Maximum `original_bytes` for a blob in this namespace.
    pub max_blob_bytes: u64,
    /// Maximum `shard_bytes` for a blob in this namespace.
    pub max_shard_bytes: u32,
}

/// Fee-paid auxiliary consensus blobs carried by
/// `BlockBodyV1.consensus_blob_descriptors` (da.md: `max_blob_bytes`
/// 262,144, PROPOSED-G0).
pub const NAMESPACE_CONSENSUS_AUX: u32 = 1;
/// NEL activation-trace namespace (ch05 §6; reveal-on-dispute artifacts).
pub const NAMESPACE_NEL_TRACE: u32 = 2;
/// Content-addressed model weight shards (ch05 §2.2: 4-16 MiB shards).
pub const NAMESPACE_MODEL_WEIGHTS: u32 = 3;
/// Work Loom job/evidence artifacts (ch01 §10.1).
pub const NAMESPACE_LOOM_EVIDENCE: u32 = 4;

/// The closed registry, ascending by id (deterministic iteration).
/// Artifact bounds are engineering PROPOSED-G0 values pending the G0
/// constants freeze; the consensus row carries the da.md numbers.
pub const NAMESPACES: [NamespaceSpec; 4] = [
    NamespaceSpec {
        id: NAMESPACE_CONSENSUS_AUX,
        name: "consensus-aux",
        domain: StorageDomain::ConsensusBody,
        max_blob_bytes: 262_144,
        max_shard_bytes: 65_536,
    },
    NamespaceSpec {
        id: NAMESPACE_NEL_TRACE,
        name: "nel-trace",
        domain: StorageDomain::Artifact,
        // Full activation trace is 21,504 B/token (constants-v1.toml [nel]);
        // 16 MiB bounds a 128-token job's full trace with headroom.
        max_blob_bytes: 16_777_216,
        max_shard_bytes: 1_048_576,
    },
    NamespaceSpec {
        id: NAMESPACE_MODEL_WEIGHTS,
        name: "model-weights",
        domain: StorageDomain::Artifact,
        // 4 GiB per manifest-referenced weight blob; 16 MiB shard ceiling
        // per ch05 §2.2 (4-16 MiB content-addressed weight shards).
        max_blob_bytes: 4_294_967_296,
        max_shard_bytes: 16_777_216,
    },
    NamespaceSpec {
        id: NAMESPACE_LOOM_EVIDENCE,
        name: "loom-evidence",
        domain: StorageDomain::Artifact,
        max_blob_bytes: 268_435_456,
        max_shard_bytes: 4_194_304,
    },
];

/// Looks a namespace up in the closed registry; unknown ids reject.
pub fn namespace_by_id(id: u32) -> Result<&'static NamespaceSpec, DaError> {
    NAMESPACES
        .iter()
        .find(|ns| ns.id == id)
        .ok_or(DaError::UnknownNamespace { namespace: id })
}

/// One row of the closed erasure-codec registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureCodecSpec {
    pub id: u16,
    pub name: &'static str,
    /// `data_shards + parity_shards` ceiling (GF(2^8): 256 symbols).
    pub max_total_shards: u32,
}

/// GF(2^8) Reed-Solomon, the only registered codec
/// (`reed-solomon-erasure` 6.0.0, pure Rust).
pub const CODEC_RS_GF8_V1: u16 = 1;

/// The closed codec registry, ascending by id.
pub const ERASURE_CODECS: [ErasureCodecSpec; 1] = [ErasureCodecSpec {
    id: CODEC_RS_GF8_V1,
    name: "rs-gf8-v1",
    max_total_shards: 256,
}];

/// Looks a codec up in the closed registry; unknown ids reject.
pub fn codec_by_id(id: u16) -> Result<&'static ErasureCodecSpec, DaError> {
    ERASURE_CODECS
        .iter()
        .find(|c| c.id == id)
        .ok_or(DaError::UnknownCodec { codec_id: id })
}

/// Semantic validation of a decoded `BlobDescriptorV1` (the wire decode is
/// `noos-braid`'s law; this is the registry/retention/geometry law).
///
/// Accepts and returns the namespace row so the caller learns the storage
/// domain. Rejections, in check order:
/// * unknown `namespace` / unknown `codec_id`;
/// * `retention_epochs == 0` (a blob must declare its horizon);
/// * `original_bytes == 0`;
/// * `original_bytes` over the namespace blob limit;
/// * geometry: zero `shard_bytes` / `data_shards` / `parity_shards`,
///   `shard_bytes` over the namespace ceiling, total shards over the codec
///   ceiling, content overflowing `data_shards * shard_bytes`, or a
///   non-minimal `data_shards` (the shard count must be exactly
///   `ceil(original_bytes / shard_bytes)` — one canonical geometry per
///   content).
pub fn validate_blob_descriptor(d: &BlobDescriptorV1) -> Result<&'static NamespaceSpec, DaError> {
    let ns = namespace_by_id(d.namespace)?;
    let codec = codec_by_id(d.codec_id)?;

    if d.retention_epochs == 0 {
        return Err(DaError::ZeroRetention);
    }
    if d.original_bytes == 0 {
        return Err(DaError::EmptyBlob);
    }
    if d.original_bytes > ns.max_blob_bytes {
        return Err(DaError::BlobTooLarge {
            original_bytes: d.original_bytes,
            max: ns.max_blob_bytes,
        });
    }

    if d.shard_bytes == 0 || d.data_shards == 0 || d.parity_shards == 0 {
        return Err(DaError::ShardGeometry);
    }
    if d.shard_bytes > ns.max_shard_bytes {
        return Err(DaError::ShardGeometry);
    }
    let total = u32::from(d.data_shards)
        .checked_add(u32::from(d.parity_shards))
        .ok_or(DaError::ShardGeometry)?;
    if total > codec.max_total_shards {
        return Err(DaError::ShardGeometry);
    }

    let capacity = u64::from(d.data_shards)
        .checked_mul(u64::from(d.shard_bytes))
        .ok_or(DaError::ShardGeometry)?;
    if d.original_bytes > capacity {
        return Err(DaError::ShardGeometry);
    }
    // Minimality: strictly more than (data_shards - 1) shards' worth of
    // content, so data_shards = ceil(original_bytes / shard_bytes).
    let prior_capacity = u64::from(d.data_shards)
        .checked_sub(1)
        .and_then(|n| n.checked_mul(u64::from(d.shard_bytes)))
        .ok_or(DaError::ShardGeometry)?;
    if d.original_bytes <= prior_capacity {
        return Err(DaError::ShardGeometry);
    }

    Ok(ns)
}

/// The stricter law for descriptors carried in
/// `BlockBodyV1.consensus_blob_descriptors`: everything in
/// [`validate_blob_descriptor`] plus the namespace must live in the
/// consensus-body storage domain — artifact namespaces cannot buy their
/// way into consensus retention or consensus IO.
pub fn validate_consensus_blob_descriptor(
    d: &BlobDescriptorV1,
) -> Result<&'static NamespaceSpec, DaError> {
    let ns = validate_blob_descriptor(d)?;
    if ns.domain != StorageDomain::ConsensusBody {
        return Err(DaError::NamespaceNotConsensus {
            namespace: d.namespace,
        });
    }
    Ok(ns)
}
