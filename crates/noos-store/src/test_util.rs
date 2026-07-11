//! Test scaffolding: temp dirs, small configs, write-set builders.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use noos_lumen::state::{DeltaEntry, LumenRoots, StateDelta, TreeId};
use noos_lumen::Hash32;

use crate::{Blob, StoreConfig, WriteSet};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub const TEST_IDENTITY: &[u8] = b"NOOS-TEST/chain+genesis/v1";

/// One delta entry spec: (tree, key, sub_key, value).
pub type DeltaSpec = (TreeId, Hash32, Option<Hash32>, Option<Vec<u8>>);

/// Self-cleaning unique temp directory.
pub struct TestDir {
    pub path: PathBuf,
}

impl TestDir {
    pub fn new(tag: &str) -> TestDir {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("noos-store-{}-{tag}-{n}", std::process::id()));
        if path.exists() {
            let _ = std::fs::remove_dir_all(&path);
        }
        std::fs::create_dir_all(&path).unwrap();
        TestDir { path }
    }

    /// Store root as a child so "root does not exist" is testable.
    pub fn store_root(&self) -> PathBuf {
        self.path.join("store")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Small limits so rotation/segmentation paths are exercised constantly.
pub fn test_cfg(root: PathBuf) -> StoreConfig {
    let mut cfg = StoreConfig::new(root, TEST_IDENTITY.to_vec());
    cfg.wal_segment_bytes = 512;
    cfg.blob_segment_bytes = 300;
    cfg.max_blob_bytes = 4096;
    cfg.proof_samples = 4;
    cfg
}

pub fn h(n: u8) -> Hash32 {
    [n; 32]
}

pub fn val(n: u8) -> Vec<u8> {
    vec![n; 8]
}

pub fn delta(entries: Vec<DeltaSpec>) -> StateDelta {
    StateDelta {
        entries: entries
            .into_iter()
            .map(|(tree, key, sub_key, value)| DeltaEntry {
                tree,
                key,
                sub_key,
                value,
            })
            .collect(),
    }
}

pub fn roots(n: u8) -> LumenRoots {
    LumenRoots {
        notes_root: h(n),
        nullifiers_root: h(n.wrapping_add(1)),
        accounts_root: h(n.wrapping_add(2)),
        objects_root: h(n.wrapping_add(3)),
        receipts_root: h(n.wrapping_add(4)),
        params_root: h(n.wrapping_add(5)),
    }
}

/// The four crash-matrix write sets. `m` is the marker (1..=4).
pub fn ws(m: u8) -> WriteSet {
    match m {
        1 => WriteSet {
            delta: delta(vec![
                (TreeId::Notes, h(11), None, Some(val(1))),
                (TreeId::Notes, h(12), None, Some(val(2))),
                (TreeId::Accounts, h(13), Some(h(14)), Some(val(3))),
            ]),
            headers: vec![(b"h1".to_vec(), Some(val(101)))],
            blobs: vec![Blob {
                hash: h(201),
                bytes: b"blob-one-contents".to_vec(),
            }],
            ..WriteSet::default()
        },
        2 => WriteSet {
            delta: delta(vec![
                (TreeId::Notes, h(11), None, Some(val(21))), // overwrite
                (TreeId::Notes, h(12), None, None),          // delete
            ]),
            receipts: vec![(b"r2".to_vec(), Some(val(102)))],
            ..WriteSet::default()
        },
        3 => WriteSet {
            delta: delta(vec![(TreeId::Objects, h(15), None, Some(val(31)))]),
            indices: vec![(b"i3".to_vec(), Some(val(103)))],
            blobs: vec![Blob {
                hash: h(203),
                bytes: b"blob-three-contents-which-are-a-bit-longer".to_vec(),
            }],
            ..WriteSet::default()
        },
        4 => WriteSet {
            delta: delta(vec![(TreeId::Notes, h(16), None, Some(val(41)))]),
            roots: Some(roots(60)),
            ..WriteSet::default()
        },
        _ => unreachable!("unknown workload marker"),
    }
}
