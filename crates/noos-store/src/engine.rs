//! Pinned-RocksDB engine wrapper.
//!
//! Backend pin (plan §7.3): crate `rocksdb = 0.24.0` → `librocksdb-sys
//! 0.17.3+10.4.2` → bundled RocksDB library **10.4.2**. The engine's
//! internal WAL stays enabled for batch atomicity but is never fsynced per
//! write (`sync = false`): recoverability of acked commits is owned by the
//! protocol WAL, which is fsynced BEFORE the engine apply, so the engine
//! can never be ahead of durable protocol history.
//!
//! Info logs are redirected outside the data directory
//! (`set_db_log_dir`) so snapshot generation directories stay pristine
//! after read-only verification opens.

use std::path::Path;

use rocksdb::{
    checkpoint::Checkpoint, ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB,
};

use crate::wal::OpV1;
use crate::StoreError;

/// Column families (closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Cf {
    /// Authenticated state nodes (Lumen sparse-tree entries).
    State = 0,
    /// Block headers (caller-keyed).
    Headers = 1,
    /// Secondary indices (caller-keyed).
    Indices = 2,
    /// Execution receipts (caller-keyed).
    Receipts = 3,
    /// Store + consensus-safety metadata.
    Meta = 4,
    /// Blob index: content hash → segment/offset/len/checksum.
    BlobIndex = 5,
}

impl Cf {
    pub const ALL: [Cf; 6] = [
        Cf::State,
        Cf::Headers,
        Cf::Indices,
        Cf::Receipts,
        Cf::Meta,
        Cf::BlobIndex,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Cf::State => "state",
            Cf::Headers => "headers",
            Cf::Indices => "indices",
            Cf::Receipts => "receipts",
            Cf::Meta => "meta",
            Cf::BlobIndex => "blob_index",
        }
    }

    pub fn from_u8(v: u8) -> Option<Cf> {
        match v {
            0 => Some(Cf::State),
            1 => Some(Cf::Headers),
            2 => Some(Cf::Indices),
            3 => Some(Cf::Receipts),
            4 => Some(Cf::Meta),
            5 => Some(Cf::BlobIndex),
            _ => None,
        }
    }
}

/// Reserved metadata keys.
pub(crate) const META_APPLIED_SEQ: &[u8] = b"applied_seq";
pub(crate) const META_IDENTITY: &[u8] = b"identity";
pub(crate) const META_SCHEMA: &[u8] = b"schema_version";
pub(crate) const META_ROOTS: &[u8] = b"lumen_roots";
/// Safety-record key prefix: `s/<kind:u16-LE><payload-hash:32>`.
pub(crate) const META_SAFETY_PREFIX: &[u8] = b"s/";

pub(crate) const SCHEMA_VERSION: u32 = 1;

fn eng<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Engine(e.to_string())
}

fn base_options(log_dir: &Path, create: bool) -> Options {
    let mut opts = Options::default();
    opts.create_if_missing(create);
    opts.create_missing_column_families(create);
    opts.set_db_log_dir(log_dir);
    opts.set_keep_log_file_num(4);
    opts
}

fn descriptors() -> Vec<ColumnFamilyDescriptor> {
    Cf::ALL
        .iter()
        .map(|cf| ColumnFamilyDescriptor::new(cf.name(), Options::default()))
        .collect()
}

/// Owned key/value pair returned by engine reads.
pub(crate) type KvPair = (Vec<u8>, Vec<u8>);

/// Live or scratch engine handle.
pub(crate) struct Engine {
    db: DB,
}

impl Engine {
    pub fn open(path: &Path, log_dir: &Path, create: bool) -> Result<Engine, StoreError> {
        let opts = base_options(log_dir, create);
        let db = DB::open_cf_descriptors(&opts, path, descriptors()).map_err(eng)?;
        Ok(Engine { db })
    }

    pub fn open_read_only(path: &Path, log_dir: &Path) -> Result<Engine, StoreError> {
        let opts = base_options(log_dir, false);
        let names: Vec<&str> = Cf::ALL.iter().map(|c| c.name()).collect();
        let db = DB::open_cf_for_read_only(&opts, path, names, false).map_err(eng)?;
        Ok(Engine { db })
    }

    fn handle(&self, cf: Cf) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db
            .cf_handle(cf.name())
            .ok_or_else(|| StoreError::Engine(format!("missing column family {}", cf.name())))
    }

    pub fn get(&self, cf: Cf, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.db.get_cf(self.handle(cf)?, key).map_err(eng)
    }

    /// Atomically apply one ordered op batch and mark it applied
    /// (`meta/applied_seq = seq` rides in the same batch).
    pub fn apply(&self, ops: &[OpV1], seq: u64) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        for op in ops {
            let h = self.handle(op.cf)?;
            match &op.value {
                Some(v) => batch.put_cf(h, &op.key, v),
                None => batch.delete_cf(h, &op.key),
            }
        }
        batch.put_cf(self.handle(Cf::Meta)?, META_APPLIED_SEQ, seq.to_le_bytes());
        self.db.write(batch).map_err(eng)
    }

    pub fn applied_seq(&self) -> Result<u64, StoreError> {
        match self.get(Cf::Meta, META_APPLIED_SEQ)? {
            None => Ok(0),
            Some(v) => {
                let arr: [u8; 8] = v
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Engine("malformed applied_seq".to_string()))?;
                Ok(u64::from_le_bytes(arr))
            }
        }
    }

    pub fn identity(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.get(Cf::Meta, META_IDENTITY)
    }

    pub fn schema_version(&self) -> Result<Option<u32>, StoreError> {
        match self.get(Cf::Meta, META_SCHEMA)? {
            None => Ok(None),
            Some(v) => {
                let arr: [u8; 4] = v
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Engine("malformed schema_version".to_string()))?;
                Ok(Some(u32::from_le_bytes(arr)))
            }
        }
    }

    pub fn roots_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.get(Cf::Meta, META_ROOTS)
    }

    /// RocksDB checkpoint (flushes the memtable, then hardlinks/copies
    /// immutable files) into `dst` — the snapshot-generation export.
    pub fn checkpoint(&self, dst: &Path) -> Result<(), StoreError> {
        let cp = Checkpoint::new(&self.db).map_err(eng)?;
        cp.create_checkpoint(dst).map_err(eng)
    }

    /// Deterministic proof sample: first entry at or after `target` in `cf`.
    pub fn sample_at(&self, cf: Cf, target: &[u8]) -> Result<Option<KvPair>, StoreError> {
        let h = self.handle(cf)?;
        let mode = IteratorMode::From(target, rocksdb::Direction::Forward);
        match self.db.iterator_cf(h, mode).next() {
            None => Ok(None),
            Some(Ok((k, v))) => Ok(Some((k.into_vec(), v.into_vec()))),
            Some(Err(e)) => Err(eng(e)),
        }
    }

    /// All entries whose key starts with `prefix`, ascending.
    pub fn prefix_scan(&self, cf: Cf, prefix: &[u8]) -> Result<Vec<KvPair>, StoreError> {
        let h = self.handle(cf)?;
        let mode = IteratorMode::From(prefix, rocksdb::Direction::Forward);
        let mut out = Vec::new();
        for item in self.db.iterator_cf(h, mode) {
            let (k, v) = item.map_err(eng)?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.into_vec(), v.into_vec()));
        }
        Ok(out)
    }
}
