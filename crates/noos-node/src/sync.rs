//! Sync modes behind the thin [`NetworkEdge`] trait (ch01 §10.5;
//! plan §7.5; node-v1.md §6).
//!
//! `noos-p2p` is running in a sibling ticket; a later binding pass adapts
//! its `P2pHandle`/`ProtocolStore` onto these traits (certificates travel
//! inside `/noos/sync/range/1` payload bytes — agreed with the transport
//! owner). Until then [`NetworkEdge`] keeps the node testable against
//! in-process edges.
//!
//! * **Header-first full sync** — pull `(header, ticket)` ranges, verify
//!   tickets/work/retarget/ancestry through the ordinary stage-1/2 law,
//!   pull certificates, then pull bodies from the last trusted state and
//!   execute every transition (the same seven-stage pipeline; nothing is
//!   trusted from the peer).
//! * **Finalized snapshot sync** — fetch a store snapshot generation file
//!   set from several [`SnapshotSource`]s (any file may come from any
//!   source; every byte is verified by the store's own manifest/identity/
//!   proof-sample law on open), then replay + tail-sync.
//! * **Light sync** — headers + Ground work + finality certificates only.
//!
//! Weak-subjectivity checkpoints are SOCIAL INPUTS
//! ([`crate::consensus::NodeCore::apply_social_checkpoint`]) and never
//! override local finality.

use std::path::Path;

use noos_braid::{BlockHeaderV1, FinalityCertificateV1};
use noos_da::{BodyDaClaimV1, ShardCandidateV1};
use noos_ground::GroundTicketV1;
use noos_witness::vote::FinalityVoteV1;

use crate::consensus::{ImportOutcome, NodeCore, NodeMode};
use crate::store_port::StorePort;
use crate::{Hash32, NodeError};

/// Edge-layer failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeError {
    /// No peer could serve the request right now.
    Unavailable,
    /// A peer answered with malformed bytes (the peer is penalized by the
    /// transport; the sync layer just moves on).
    Malformed,
}

/// The node's network boundary. Deliberately thin: typed requests plus
/// fire-and-forget announces; every returned object is re-validated by the
/// consensus pipeline, never trusted.
pub trait NetworkEdge: Send {
    /// Sequential `(header, ticket)` range starting at `from_height`.
    fn request_headers(
        &mut self,
        from_height: u64,
        max: u32,
    ) -> Result<Vec<(BlockHeaderV1, GroundTicketV1)>, EdgeError>;

    /// DA claim + shard candidates for the body committed by
    /// `body_da_root`. Peers may return fewer than 16 valid shards; the
    /// pipeline parks the block and re-requests.
    fn request_body(
        &mut self,
        body_da_root: &Hash32,
    ) -> Result<(BodyDaClaimV1, Vec<ShardCandidateV1>), EdgeError>;

    /// Finality certificates targeting epochs strictly above `after_epoch`.
    fn request_certificates(
        &mut self,
        after_epoch: u64,
        max: u32,
    ) -> Result<Vec<FinalityCertificateV1>, EdgeError>;

    fn announce_header(&mut self, header: &BlockHeaderV1, ticket: &GroundTicketV1);
    fn announce_tx(&mut self, tx_bytes: &[u8], wit_bytes: &[u8]);
    fn announce_vote(&mut self, vote: &FinalityVoteV1);
}

/// A no-network edge (isolated node; `noosd` default until the noos-p2p
/// binding pass).
#[derive(Debug, Default)]
pub struct NullEdge;

impl NetworkEdge for NullEdge {
    fn request_headers(
        &mut self,
        _from_height: u64,
        _max: u32,
    ) -> Result<Vec<(BlockHeaderV1, GroundTicketV1)>, EdgeError> {
        Err(EdgeError::Unavailable)
    }
    fn request_body(
        &mut self,
        _body_da_root: &Hash32,
    ) -> Result<(BodyDaClaimV1, Vec<ShardCandidateV1>), EdgeError> {
        Err(EdgeError::Unavailable)
    }
    fn request_certificates(
        &mut self,
        _after_epoch: u64,
        _max: u32,
    ) -> Result<Vec<FinalityCertificateV1>, EdgeError> {
        Err(EdgeError::Unavailable)
    }
    fn announce_header(&mut self, _header: &BlockHeaderV1, _ticket: &GroundTicketV1) {}
    fn announce_tx(&mut self, _tx_bytes: &[u8], _wit_bytes: &[u8]) {}
    fn announce_vote(&mut self, _vote: &FinalityVoteV1) {}
}

/// One full-sync round: headers first, then certificates, then bodies.
/// Returns the number of blocks that reached the executed chain.
pub fn full_sync_round<P: StorePort>(
    core: &mut NodeCore<P>,
    edge: &mut dyn NetworkEdge,
    batch: u32,
) -> Result<u64, NodeError> {
    let mut progressed: u64 = 0;
    let (head_height, _) = core.head();

    // Header-first: verify tickets/work/retarget/ancestry.
    let headers = match edge.request_headers(head_height.saturating_add(1), batch) {
        Ok(h) => h,
        Err(_) => return Ok(0),
    };
    for (header, ticket) in headers {
        // Bodies from the last trusted state: request per header.
        let (claim, shards) = match edge.request_body(&header.body_da_root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        match core.import_block(&header, &ticket, &claim, &shards) {
            Ok(ImportOutcome::Executed { .. }) => progressed = progressed.saturating_add(1),
            Ok(_) => {}
            Err(NodeError::Dag(noos_braid::DagError::DuplicateBlock)) => {}
            Err(e) => return Err(e),
        }
    }

    // Certificates advance finality past what bodies carried.
    if let Ok(certs) = edge.request_certificates(core.finalized().epoch, 16) {
        for cert in certs {
            match core.queue_certificate(cert) {
                Ok(()) | Err(NodeError::Witness(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(progressed)
}

/// Light-mode sync round: headers + certificates only (ch01 §10.5).
pub fn light_sync_round<P: StorePort>(
    core: &mut NodeCore<P>,
    edge: &mut dyn NetworkEdge,
    batch: u32,
) -> Result<u64, NodeError> {
    debug_assert_eq!(core.cfg.mode, NodeMode::Light);
    let mut progressed = 0_u64;
    // Light mode never executes, so the executed head is pinned at
    // genesis; the header cursor is the best-known DAG tip instead.
    let head_height = core
        .dag()
        .select_head()
        .and_then(|tip| core.dag().get(&tip).map(|s| s.header.height))
        .unwrap_or_else(|| core.head().0);
    if let Ok(headers) = edge.request_headers(head_height.saturating_add(1), batch) {
        for (header, ticket) in headers {
            match core.import_header_light(&header, &ticket) {
                Ok(ImportOutcome::HeaderAccepted { .. }) => {
                    progressed = progressed.saturating_add(1);
                }
                Ok(_) => {}
                Err(NodeError::Dag(noos_braid::DagError::DuplicateBlock)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if let Ok(certs) = edge.request_certificates(core.finalized().epoch, 16) {
        for cert in certs {
            let _ = core.queue_certificate(cert);
        }
    }
    Ok(progressed)
}

// ---------------------------------------------------------------------------
// Finalized snapshot sync (multi-peer source abstraction)
// ---------------------------------------------------------------------------

/// A source of store-snapshot files (one peer). File names are relative
/// paths inside the store root (`CURRENT`, `gen-*/...`, `wal/*`,
/// `segments/*`). NOTHING a source returns is trusted: the store's open
/// law re-verifies manifest hashes, per-file hashes, identity, and proof
/// samples.
pub trait SnapshotSource {
    /// Relative paths of every file in the served snapshot root.
    fn list(&self) -> Result<Vec<String>, EdgeError>;
    fn fetch(&self, name: &str) -> Result<Vec<u8>, EdgeError>;
}

/// Snapshot-sync failures.
#[derive(Debug)]
pub enum SnapshotSyncError {
    /// No source produced a usable file set.
    NoUsableSource,
    /// Assembled bytes failed the store's verification law.
    Verification(NodeError),
    Io(std::io::Error),
}

/// Assembles a store root at `dest` from multiple snapshot sources: the
/// file LIST comes from the first source that answers; each file may come
/// from ANY source (round-robin on failure). Verification is entirely the
/// store's open law — a corrupt byte from a lying peer surfaces as a typed
/// open failure, never as accepted state.
pub fn fetch_snapshot_files(
    sources: &mut [Box<dyn SnapshotSource>],
    dest: &Path,
) -> Result<(), SnapshotSyncError> {
    let mut names: Option<Vec<String>> = None;
    for source in sources.iter() {
        if let Ok(list) = source.list() {
            names = Some(list);
            break;
        }
    }
    let names = names.ok_or(SnapshotSyncError::NoUsableSource)?;

    for name in &names {
        // Path hygiene: refuse absolute/parent components from a peer.
        let rel = Path::new(name);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(SnapshotSyncError::NoUsableSource);
        }
        let mut fetched = None;
        for source in sources.iter() {
            if let Ok(bytes) = source.fetch(name) {
                fetched = Some(bytes);
                break;
            }
        }
        let bytes = fetched.ok_or(SnapshotSyncError::NoUsableSource)?;
        let path = dest.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(SnapshotSyncError::Io)?;
        }
        std::fs::write(&path, bytes).map_err(SnapshotSyncError::Io)?;
    }
    Ok(())
}

/// Serves a local store root as a [`SnapshotSource`] (used by tests and by
/// the future p2p binding's `/noos/sync/snapshot/1` server side).
pub struct DirSnapshotSource {
    root: std::path::PathBuf,
    /// Corruption injection hook for tests: names this source lies about.
    pub corrupt: std::collections::BTreeSet<String>,
}

impl DirSnapshotSource {
    #[must_use]
    pub fn new(root: std::path::PathBuf) -> Self {
        DirSnapshotSource {
            root,
            corrupt: std::collections::BTreeSet::new(),
        }
    }

    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::walk(&path, base, out)?;
            } else if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
}

impl SnapshotSource for DirSnapshotSource {
    fn list(&self) -> Result<Vec<String>, EdgeError> {
        let mut out = Vec::new();
        Self::walk(&self.root, &self.root, &mut out).map_err(|_| EdgeError::Unavailable)?;
        out.sort();
        Ok(out)
    }

    fn fetch(&self, name: &str) -> Result<Vec<u8>, EdgeError> {
        let mut bytes = std::fs::read(self.root.join(name)).map_err(|_| EdgeError::Unavailable)?;
        if self.corrupt.contains(name) {
            if let Some(b) = bytes.first_mut() {
                *b ^= 0xFF;
            }
        }
        Ok(bytes)
    }
}
