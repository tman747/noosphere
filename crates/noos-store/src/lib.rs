//! # noos-store — NOOSPHERE durable storage (plan §7.3)
//!
//! Storage adapter under `noos-lumen`: consumes the canonical ordered
//! [`noos_lumen::state::StateDelta`] and makes it durable. Consensus
//! semantics, networking, and the node supervisor live elsewhere.
//!
//! Normative companion document: `protocol/schemas/store-v1.md`.
//!
//! ## Architecture
//!
//! - **Engine** — pinned RocksDB (`rocksdb = 0.24.0`, bundled RocksDB
//!   library **10.4.2**) with column families for authenticated state
//!   nodes, headers, indices, receipts, metadata, and the blob index.
//!   The live engine at `<root>/live` is a *derived cache*: it is always
//!   reconstructible from the last verified snapshot generation plus the
//!   protocol WAL tail, and is rebuilt from them when unusable.
//! - **Protocol WAL** — a checksummed append-only log, *distinct from the
//!   engine's internal WAL*. Record = `len:u32-LE || blake3:32 || payload`.
//!   Every commit is `append → fsync → engine apply (carries applied_seq)`.
//!   Only a truncated FINAL record follows the EOF rule; any earlier or
//!   complete-record corruption is a typed fatal startup error.
//! - **Blob segments** — append-only bounded segment files under
//!   `<root>/segments`, indexed by a `blob_index` column family
//!   (`hash → segment/offset/len`), so blob IO cannot starve consensus IO.
//! - **Snapshot generations** — immutable verified checkpoints
//!   `<root>/gen-<N>` created under the exact snapshot law: write into a
//!   same-filesystem temp dir, fsync every file + manifest + directory,
//!   verify roots and proof samples, then durably flip the tiny `CURRENT`
//!   pointer (temp-write, fsync, atomic rename, parent-directory flush).
//!   Verified `N` and `N-1` plus the required WAL are retained until a
//!   fresh process proves snapshot+tail replay (`PROVEN` marker); the last
//!   verified generation is never deleted.
//!
//! ## Startup law
//!
//! Orphan temp generations are ignored; the pointed generation is
//! validated (manifest hash, per-file hashes, segment watermarks,
//! identity); fallback is permitted only to a retained previously
//! verified generation; conflicting pointers, complete-record WAL
//! corruption, and safety/history gaps STOP startup with a typed
//! [`FatalError`] — the store never auto-resets.
//!
//! ## Windows directory-flush caveat
//!
//! On Unix, directory-equivalents are flushed by `fsync` on an open
//! directory handle. On Windows the store opens directories with
//! `FILE_FLAG_BACKUP_SEMANTICS` and calls `FlushFileBuffers`
//! (`File::sync_all`), which flushes directory metadata on NTFS but is
//! documented **best-effort**: on filesystems that reject it the store
//! degrades to `sync_all` on the renamed file plus same-volume
//! `std::fs::rename` (see `store-v1.md` §6).

use std::fmt;
use std::path::PathBuf;

mod artifact_store;
mod blob;
mod engine;
mod manifest;
mod store;
mod vfs;
mod wal;

#[cfg(test)]
mod artifact_store_tests;
#[cfg(test)]
mod crash_tests;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod tests;

pub use artifact_store::{
    ArtifactFailpoint, ArtifactIngestSpec, ArtifactKey, ArtifactResumeState, ArtifactStore,
    ArtifactStoreConfig, ArtifactStoreError,
};
pub use blob::BlobLoc;
pub use engine::Cf;
pub use manifest::{CurrentPointerV1, FileEntryV1, ManifestV1, SegmentMarkV1};
pub use store::{Blob, FallbackInfo, OpenReport, PruneReport, Store, WriteSet};
pub use vfs::{FailpointVfs, Failpoints, RealVfs, Vfs, VfsFile};
pub use wal::{OpV1, WalRecordV1, MAX_WAL_RECORD};

/// Safety-record kind reserved for the Witness Ring beacon adapter
/// (`noos-witness` `DurabilityBarrier`; agreed via coordination, payload =
/// canonical `BeaconSafetyRecordV1` bytes).
pub const SAFETY_KIND_WITNESS_BEACON: u16 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed fatal startup conditions (plan §7.3). Each stops `Store::open`;
/// none may be "repaired" by auto-reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatalError {
    /// Generations exist but no `CURRENT` pointer does (and the state is
    /// not the unique interrupted-first-init signature).
    PointerMissing,
    /// `CURRENT` exists but fails its checksum or does not parse.
    PointerCorrupt { reason: String },
    /// The pointer and the pointed generation's manifest disagree about
    /// which generation this is.
    ConflictingPointers {
        pointer_generation: u64,
        manifest_generation: u64,
    },
    /// A generation or the live engine was written under a different
    /// protocol identity (chain id / genesis binding).
    IdentityMismatch,
    /// Neither the pointed generation nor any retained previously verified
    /// generation validates.
    NoValidGeneration {
        pointed: u64,
        pointed_reason: String,
        fallback_reason: Option<String>,
    },
    /// A complete WAL record (or non-final segment) is corrupt. Only a
    /// truncated FINAL record follows the EOF rule.
    WalCorrupt {
        segment: u64,
        offset: u64,
        reason: String,
    },
    /// The retained WAL does not join the chosen base state (missing or
    /// non-contiguous sequence numbers, or an engine ahead of the durable
    /// WAL end — silent acked-write loss).
    HistoryGap { detail: String },
    /// Fresh-process snapshot+tail replay produced a state that differs
    /// from the live engine.
    ReplayDivergence { detail: String },
}

impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FatalError::PointerMissing => write!(f, "CURRENT pointer missing"),
            FatalError::PointerCorrupt { reason } => {
                write!(f, "CURRENT pointer corrupt: {reason}")
            }
            FatalError::ConflictingPointers {
                pointer_generation,
                manifest_generation,
            } => write!(
                f,
                "conflicting pointers: CURRENT says generation {pointer_generation}, manifest says {manifest_generation}"
            ),
            FatalError::IdentityMismatch => write!(f, "protocol identity mismatch"),
            FatalError::NoValidGeneration {
                pointed,
                pointed_reason,
                fallback_reason,
            } => write!(
                f,
                "no valid generation: pointed gen {pointed} invalid ({pointed_reason}); fallback: {fallback_reason:?}"
            ),
            FatalError::WalCorrupt {
                segment,
                offset,
                reason,
            } => write!(
                f,
                "protocol WAL corrupt in segment {segment} at offset {offset}: {reason}"
            ),
            FatalError::HistoryGap { detail } => write!(f, "safety/history gap: {detail}"),
            FatalError::ReplayDivergence { detail } => {
                write!(f, "snapshot+tail replay divergence: {detail}")
            }
        }
    }
}

/// Store operation errors.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying file-system failure (includes injected crash faults in
    /// tests; those carry `ErrorKind::Other` with an "injected" message).
    Io {
        op: &'static str,
        path: String,
        source: std::io::Error,
    },
    /// RocksDB engine failure.
    Engine(String),
    /// Canonical decode failure of a store-owned object.
    Codec(noos_codec::CodecError),
    /// Caller handed an invalid write set (duplicate keys, oversized
    /// value, malformed blob).
    InvalidWriteSet(&'static str),
    /// Checked-arithmetic overflow — always a bug or corrupted input.
    Arithmetic(&'static str),
    /// Store root does not exist and `create_if_missing` is false.
    NotInitialized,
    /// A prior failed write left this handle in an unknown state; reopen
    /// to recover.
    Poisoned,
    /// A blob's stored bytes fail their record checksum or content hash.
    BlobCorrupt { segment: u32, offset: u64 },
    /// Snapshot verification (roots + proof samples) failed before the
    /// generation could be adopted; nothing was renamed or pointed at.
    SnapshotVerifyFailed(String),
    /// Typed fatal startup condition; never auto-reset.
    Fatal(FatalError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { op, path, source } => {
                write!(f, "io error during {op} on {path}: {source}")
            }
            StoreError::Engine(e) => write!(f, "engine error: {e}"),
            StoreError::Codec(e) => write!(f, "codec error: {e}"),
            StoreError::InvalidWriteSet(r) => write!(f, "invalid write set: {r}"),
            StoreError::Arithmetic(w) => write!(f, "checked arithmetic overflow: {w}"),
            StoreError::NotInitialized => write!(f, "store not initialized"),
            StoreError::Poisoned => write!(f, "store handle poisoned by earlier failure"),
            StoreError::BlobCorrupt { segment, offset } => {
                write!(f, "blob corrupt in segment {segment} at offset {offset}")
            }
            StoreError::SnapshotVerifyFailed(d) => {
                write!(f, "snapshot verification failed: {d}")
            }
            StoreError::Fatal(e) => write!(f, "fatal: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<noos_codec::CodecError> for StoreError {
    fn from(e: noos_codec::CodecError) -> Self {
        StoreError::Codec(e)
    }
}

impl StoreError {
    pub(crate) fn io(op: &'static str, path: &std::path::Path, source: std::io::Error) -> Self {
        StoreError::Io {
            op,
            path: path.display().to_string(),
            source,
        }
    }

    /// True when the error is an injected crash fault from a test
    /// failpoint (never occurs in production).
    pub fn is_injected(&self) -> bool {
        matches!(self, StoreError::Io { source, .. } if vfs::is_injected(source))
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Store configuration. All limits are bounds, checked — never trusted.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Store root directory (one filesystem; snapshots use same-fs temp dirs).
    pub root: PathBuf,
    /// Opaque protocol-identity binding (chain id + genesis hash bytes).
    /// Checked on every open; mismatch is fatal. Max 128 bytes.
    pub identity: Vec<u8>,
    /// Initialize an empty store when the root has no history.
    pub create_if_missing: bool,
    /// Protocol-WAL segment rotation threshold in bytes.
    pub wal_segment_bytes: u64,
    /// Blob segment size bound in bytes.
    pub blob_segment_bytes: u64,
    /// Maximum single blob size in bytes.
    pub max_blob_bytes: u32,
    /// Number of deterministic proof samples compared during snapshot
    /// verification and replay proof.
    pub proof_samples: u32,
    /// Prove snapshot+tail replay on open (scratch copy + replay + compare)
    /// before writing the generation's `PROVEN` marker.
    pub prove_replay_on_open: bool,
}

impl StoreConfig {
    pub fn new(root: PathBuf, identity: Vec<u8>) -> Self {
        StoreConfig {
            root,
            identity,
            create_if_missing: true,
            wal_segment_bytes: 4 * 1024 * 1024,
            blob_segment_bytes: 64 * 1024 * 1024,
            max_blob_bytes: 32 * 1024 * 1024,
            proof_samples: 16,
            prove_replay_on_open: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain-separated local hashing contexts (file formats, not consensus).
// ---------------------------------------------------------------------------

pub(crate) const CTX_WAL: &str = "NOOS/STORE/WAL/V1";
pub(crate) const CTX_FILE: &str = "NOOS/STORE/FILE/V1";
pub(crate) const CTX_MANIFEST: &str = "NOOS/STORE/MANIFEST/V1";
pub(crate) const CTX_CURRENT: &str = "NOOS/STORE/CURRENT/V1";
pub(crate) const CTX_SEGMENT: &str = "NOOS/STORE/SEGMENT/V1";
pub(crate) const CTX_SAMPLE: &str = "NOOS/STORE/SAMPLE/V1";
pub(crate) const CTX_SAFETY: &str = "NOOS/STORE/SAFETY/V1";

/// BLAKE3 derive-key hash under a store context. These are local file
/// integrity checksums, deliberately outside the closed consensus domain
/// registry (`crypto-domains-v1.csv`); they commit to nothing on-chain.
pub(crate) fn ctx_hash(ctx: &str, data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(ctx);
    h.update(data);
    *h.finalize().as_bytes()
}
