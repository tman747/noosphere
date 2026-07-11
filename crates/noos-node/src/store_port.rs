//! Durable-store boundary for the consensus task (node-v1.md §5).
//!
//! The consensus single writer talks to storage through [`StorePort`], so
//! the same core runs against an in-process [`InProcStore`] (tests, and
//! inside the supervisor's dedicated store task) or the supervisor's
//! channel-backed [`crate::supervisor::StoreClient`].
//!
//! ## Key scheme (frozen in node-v1.md §5.1)
//!
//! ```text
//! Headers  CF:  b"h/" ++ block_hash(32)      -> canonical header ++ 76-byte ticket
//! Indices  CF:  b"n/" ++ height u64 BE       -> block hash (canonical chain index)
//!               b"c/" ++ epoch u64 BE ++ digest(32) -> canonical FinalityCertificateV1
//!               b"m/head"                    -> head block hash
//!               b"m/final"                   -> finalized CheckpointRef (canonical)
//!               b"m/just"                    -> justified CheckpointRef (canonical)
//! Receipts CF:  txid(32)                     -> height u64 LE ++ canonical ReceiptV1
//! Blobs      :  body_da_root                 -> served canonical body bytes
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use noos_lumen::state::LumenRoots;
use noos_store::{Cf, RealVfs, Store, StoreConfig, WriteSet};

use crate::{Hash32, NodeError};

/// Safety-record kind: Witness Ring beacon commit/reveal state
/// (`noos-store` reserves this constant for the barrier adapter).
pub const SAFETY_KIND_BEACON: u16 = noos_store::SAFETY_KIND_WITNESS_BEACON;
/// Safety-record kind: checkpoint votes (persist-before-vote).
pub const SAFETY_KIND_VOTE: u16 = 2;

/// Header-CF key for a block hash.
#[must_use]
pub fn key_header(hash: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(34);
    k.extend_from_slice(b"h/");
    k.extend_from_slice(hash);
    k
}

/// Index-CF key for the canonical chain height index.
#[must_use]
pub fn key_height(height: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(10);
    k.extend_from_slice(b"n/");
    k.extend_from_slice(&height.to_be_bytes());
    k
}

/// Index-CF key for an ingested finality certificate.
#[must_use]
pub fn key_certificate(epoch: u64, digest: &Hash32) -> Vec<u8> {
    let mut k = Vec::with_capacity(42);
    k.extend_from_slice(b"c/");
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(digest);
    k
}

/// Index-CF key of the canonical head pointer.
pub const KEY_HEAD: &[u8] = b"m/head";
/// Index-CF key of the finalized checkpoint.
pub const KEY_FINALIZED: &[u8] = b"m/final";
/// Index-CF key of the justified checkpoint.
pub const KEY_JUSTIFIED: &[u8] = b"m/just";

/// Storage surface the consensus core requires. Every mutation is
/// `&mut self`: the single-writer law extends through storage.
pub trait StorePort: Send {
    fn commit(&mut self, ws: &WriteSet) -> Result<u64, NodeError>;
    /// Fsync-backed safety record (persist-before-vote / beacon barrier).
    fn persist_safety(&mut self, kind: u16, payload: &[u8]) -> Result<u64, NodeError>;
    /// Durability barrier: previously acked writes survive a crash.
    fn barrier(&mut self) -> Result<(), NodeError>;
    fn safety_records(&self, kind: u16) -> Result<Vec<Vec<u8>>, NodeError>;
    fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError>;
    fn get_index(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError>;
    fn get_receipt(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError>;
    fn get_blob(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, NodeError>;
    fn scan_indices(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, NodeError>;
    fn roots(&self) -> Result<Option<LumenRoots>, NodeError>;
    fn create_snapshot(&mut self) -> Result<u64, NodeError>;
    fn applied_seq(&self) -> u64;
}

/// Direct wrapper over `noos_store::Store`.
pub struct InProcStore {
    store: Store,
}

impl InProcStore {
    /// Opens (or initializes) the store bound to the chain identity
    /// `chain_id ++ genesis_hash` (wrong identity is a typed fatal).
    pub fn open(root: PathBuf, chain_id: &Hash32, genesis_hash: &Hash32) -> Result<Self, NodeError> {
        let mut identity = Vec::with_capacity(64);
        identity.extend_from_slice(chain_id);
        identity.extend_from_slice(genesis_hash);
        let cfg = StoreConfig::new(root, identity);
        let store = Store::open(cfg, Arc::new(RealVfs)).map_err(map_open_err)?;
        Ok(InProcStore { store })
    }

    /// Opens with a caller-tuned configuration (identity already bound).
    pub fn open_with(cfg: StoreConfig) -> Result<Self, NodeError> {
        let store = Store::open(cfg, Arc::new(RealVfs)).map_err(map_open_err)?;
        Ok(InProcStore { store })
    }

    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }
}

fn map_open_err(e: noos_store::StoreError) -> NodeError {
    NodeError::Store(e)
}

impl StorePort for InProcStore {
    fn commit(&mut self, ws: &WriteSet) -> Result<u64, NodeError> {
        Ok(self.store.commit(ws)?)
    }
    fn persist_safety(&mut self, kind: u16, payload: &[u8]) -> Result<u64, NodeError> {
        Ok(self.store.persist_safety_record(kind, payload)?)
    }
    fn barrier(&mut self) -> Result<(), NodeError> {
        Ok(self.store.barrier()?)
    }
    fn safety_records(&self, kind: u16) -> Result<Vec<Vec<u8>>, NodeError> {
        Ok(self.store.safety_records(kind)?)
    }
    fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        Ok(self.store.get_header(key)?)
    }
    fn get_index(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        Ok(self.store.get_index(key)?)
    }
    fn get_receipt(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        Ok(self.store.get_receipt(key)?)
    }
    fn get_blob(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, NodeError> {
        Ok(self.store.get_blob(hash)?)
    }
    fn scan_indices(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, NodeError> {
        Ok(self.store.scan(Cf::Indices, prefix)?)
    }
    fn roots(&self) -> Result<Option<LumenRoots>, NodeError> {
        Ok(self.store.roots()?)
    }
    fn create_snapshot(&mut self) -> Result<u64, NodeError> {
        Ok(self.store.create_snapshot()?)
    }
    fn applied_seq(&self) -> u64 {
        self.store.applied_seq()
    }
}
