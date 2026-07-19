//! Behavioral battery: commit/readback, WAL replay + EOF law, startup
//! decision tree (every typed fatal), snapshot law, retention/prune,
//! blobs, safety records.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use noos_lumen::state::TreeId;

use crate::test_util::{delta, h, roots, test_cfg, val, ws, TestDir};
use crate::{
    Blob, FatalError, RealVfs, Store, StoreError, Vfs, WriteSet, SAFETY_KIND_WITNESS_BEACON,
};

fn real() -> Arc<dyn Vfs> {
    Arc::new(RealVfs)
}

fn open(root: PathBuf) -> Result<Store, StoreError> {
    Store::open(test_cfg(root), real())
}

fn must_open(root: PathBuf) -> Store {
    open(root).expect("store open")
}

fn open_err(root: PathBuf) -> StoreError {
    match open(root) {
        Err(e) => e,
        Ok(_) => panic!("expected open to fail"),
    }
}

fn fatal(err: StoreError) -> FatalError {
    match err {
        StoreError::Fatal(f) => f,
        other => panic!("expected fatal error, got {other}"),
    }
}

/// Flip one byte of a file at `offset`.
fn flip_byte(path: &Path, offset: u64) {
    let mut bytes = std::fs::read(path).unwrap();
    let i = offset as usize;
    assert!(
        i < bytes.len(),
        "flip offset {i} beyond file len {}",
        bytes.len()
    );
    bytes[i] ^= 0xFF;
    std::fs::write(path, bytes).unwrap();
}

fn wal_segments(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(root.join("wal"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("wal-"))
        })
        .collect();
    out.sort();
    out
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Commit + readback
// ---------------------------------------------------------------------------

#[test]
fn init_commit_readback_across_reopen() {
    let td = TestDir::new("basic");
    {
        let mut s = must_open(td.store_root());
        assert!(s.open_report().initialized);
        assert_eq!(s.current_generation(), 1);
        assert_eq!(s.applied_seq(), 0);
        assert_eq!(s.commit(ws(1)).unwrap(), 1);
        assert_eq!(s.commit(ws(2)).unwrap(), 2);
        assert_eq!(s.commit(ws(4)).unwrap(), 3);
        // ws2 overwrote h(11) and deleted h(12).
        assert_eq!(
            s.get_state(TreeId::Notes, &h(11), None).unwrap(),
            Some(val(21))
        );
        assert_eq!(s.get_state(TreeId::Notes, &h(12), None).unwrap(), None);
        assert_eq!(
            s.get_state(TreeId::Accounts, &h(13), Some(&h(14))).unwrap(),
            Some(val(3))
        );
        assert_eq!(s.get_header(b"h1").unwrap(), Some(val(101)));
        assert_eq!(s.get_receipt(b"r2").unwrap(), Some(val(102)));
        assert_eq!(
            s.get_blob(&h(201)).unwrap(),
            Some(b"blob-one-contents".to_vec())
        );
        assert_eq!(s.roots().unwrap(), Some(roots(60)));
    }
    // Clean reopen: same state, no fallback, nothing replayed into a
    // rebuilt engine (live engine is current).
    let s = must_open(td.store_root());
    assert!(!s.open_report().initialized);
    assert!(s.open_report().fell_back.is_none());
    assert!(!s.open_report().live_rebuilt);
    assert_eq!(s.applied_seq(), 3);
    assert_eq!(
        s.get_state(TreeId::Notes, &h(11), None).unwrap(),
        Some(val(21))
    );
    assert_eq!(s.roots().unwrap(), Some(roots(60)));
}

#[test]
fn rejects_invalid_write_sets() {
    let td = TestDir::new("invalid-ws");
    let mut s = must_open(td.store_root());
    // Empty.
    assert!(matches!(
        s.commit(WriteSet::default()),
        Err(StoreError::InvalidWriteSet(_))
    ));
    // Unordered delta.
    let bad = WriteSet {
        delta: delta(vec![
            (TreeId::Notes, h(2), None, Some(val(1))),
            (TreeId::Notes, h(1), None, Some(val(1))),
        ]),
        ..WriteSet::default()
    };
    assert!(matches!(s.commit(bad), Err(StoreError::InvalidWriteSet(_))));
    // Duplicate section key.
    let bad = WriteSet {
        headers: vec![(b"k".to_vec(), Some(val(1))), (b"k".to_vec(), None)],
        ..WriteSet::default()
    };
    assert!(matches!(s.commit(bad), Err(StoreError::InvalidWriteSet(_))));
    // Oversized blob.
    let bad = WriteSet {
        blobs: vec![Blob {
            hash: h(9),
            bytes: vec![0u8; 5000],
        }],
        ..WriteSet::default()
    };
    assert!(matches!(s.commit(bad), Err(StoreError::InvalidWriteSet(_))));
    // Invalid write sets are rejected before IO and never poison the handle.
    assert!(s.commit(ws(1)).is_ok());
}

#[test]
fn not_initialized_without_create_flag() {
    let td = TestDir::new("no-create");
    let mut cfg = test_cfg(td.store_root());
    cfg.create_if_missing = false;
    assert!(matches!(
        Store::open(cfg, real()),
        Err(StoreError::NotInitialized)
    ));
}

// ---------------------------------------------------------------------------
// WAL replay + EOF law
// ---------------------------------------------------------------------------

#[test]
fn tail_replay_rebuilds_live_engine_from_snapshot() {
    let td = TestDir::new("replay");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.commit(ws(2)).unwrap();
        s.commit(ws(3)).unwrap();
    }
    // Simulate a lost/corrupt live engine: recovery = snapshot + tail replay.
    std::fs::remove_dir_all(td.store_root().join("live")).unwrap();
    let s = must_open(td.store_root());
    assert!(s.open_report().live_rebuilt);
    assert_eq!(s.open_report().replayed_records, 3);
    assert_eq!(s.applied_seq(), 3);
    assert_eq!(
        s.get_state(TreeId::Notes, &h(11), None).unwrap(),
        Some(val(21))
    );
    assert_eq!(
        s.get_state(TreeId::Objects, &h(15), None).unwrap(),
        Some(val(31))
    );
    assert_eq!(
        s.get_blob(&h(203)).unwrap(),
        Some(b"blob-three-contents-which-are-a-bit-longer".to_vec())
    );
}

#[test]
fn truncated_final_record_is_dropped_earlier_corruption_is_fatal() {
    let td = TestDir::new("wal-eof");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.commit(ws(2)).unwrap();
    }
    // Append a torn record to the last segment: header + partial payload.
    let seg = wal_segments(&td.store_root()).pop().unwrap();
    let clean_len = std::fs::metadata(&seg).unwrap().len();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&500u32.to_le_bytes()).unwrap();
        f.write_all(&[0xAB; 40]).unwrap(); // fake checksum + partial payload
    }
    {
        std::fs::remove_dir_all(td.store_root().join("live")).unwrap();
        let s = must_open(td.store_root());
        assert!(s.open_report().wal_truncated_bytes > 0);
        assert_eq!(s.applied_seq(), 2);
        assert_eq!(
            s.get_state(TreeId::Notes, &h(11), None).unwrap(),
            Some(val(21))
        );
    }
    // The EOF rule physically truncated the tail.
    assert_eq!(std::fs::metadata(&seg).unwrap().len(), clean_len);

    // Now corrupt a COMPLETE record (first of the two): startup stops.
    flip_byte(&seg, 40); // inside record 1's payload
    let err = open_err(td.store_root());
    assert!(matches!(fatal(err), FatalError::WalCorrupt { .. }));
}

#[test]
fn complete_final_record_corruption_is_fatal_not_truncated() {
    let td = TestDir::new("wal-final-corrupt");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.commit(ws(2)).unwrap();
    }
    let seg = wal_segments(&td.store_root()).pop().unwrap();
    let len = std::fs::metadata(&seg).unwrap().len();
    // Flip a byte inside the LAST record's payload (complete record).
    flip_byte(&seg, len - 3);
    let err = open_err(td.store_root());
    assert!(matches!(fatal(err), FatalError::WalCorrupt { .. }));
}

#[test]
fn missing_wal_history_is_a_gap() {
    let td = TestDir::new("wal-gap");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.commit(ws(2)).unwrap();
        s.commit(ws(3)).unwrap();
    }
    // Deleting the retained WAL leaves the snapshot behind the durable
    // history it claims: gen-1 reflects seq 0 but nothing joins it, and
    // the live engine sits ahead of the durable WAL end.
    for seg in wal_segments(&td.store_root()) {
        std::fs::remove_file(seg).unwrap();
    }
    let err = open_err(td.store_root());
    assert!(matches!(fatal(err), FatalError::HistoryGap { .. }));
}

// ---------------------------------------------------------------------------
// Pointer + generation decision tree
// ---------------------------------------------------------------------------

#[test]
fn pointer_corruption_and_absence_are_typed_fatals() {
    let td = TestDir::new("pointer");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
    }
    let current = td.store_root().join("CURRENT");
    // Wrong length.
    let good = std::fs::read(&current).unwrap();
    std::fs::write(&current, b"garbage").unwrap();
    assert!(matches!(
        fatal(open_err(td.store_root())),
        FatalError::PointerCorrupt { .. }
    ));
    // Right length, bad checksum.
    let mut bad = good.clone();
    bad[10] ^= 0xFF;
    std::fs::write(&current, &bad).unwrap();
    assert!(matches!(
        fatal(open_err(td.store_root())),
        FatalError::PointerCorrupt { .. }
    ));
    // Missing pointer on an established store (PROVEN exists): fatal,
    // never auto-adopted.
    std::fs::remove_file(&current).unwrap();
    assert!(matches!(
        fatal(open_err(td.store_root())),
        FatalError::PointerMissing
    ));
}

#[test]
fn interrupted_first_init_rolls_forward() {
    let td = TestDir::new("init-rollforward");
    {
        let _ = must_open(td.store_root());
    }
    // Reconstruct the unique pre-pointer crash signature: generation 1
    // exists, no pointer, no PROVEN, empty WAL.
    std::fs::remove_file(td.store_root().join("CURRENT")).unwrap();
    std::fs::remove_file(
        td.store_root()
            .join("gen-00000000000000000001")
            .join("PROVEN"),
    )
    .unwrap();
    let s = must_open(td.store_root());
    assert_eq!(s.current_generation(), 1);
    assert!(s.open_report().proved_generation == Some(1));
    assert!(td.store_root().join("CURRENT").exists());
}

#[test]
fn conflicting_pointers_stop_startup() {
    let td = TestDir::new("conflict");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.create_snapshot().unwrap(); // gen 2
    }
    let root = td.store_root();
    // Clone gen-2 as gen-3 (its manifest still says "generation 2"), then
    // point CURRENT at generation 3 with gen-2's manifest hash.
    let g2 = root.join("gen-00000000000000000002");
    let g3 = root.join("gen-00000000000000000003");
    copy_dir(&g2, &g3);
    let manifest_bytes = std::fs::read(g3.join("MANIFEST")).unwrap();
    let (_, manifest_hash) = crate::ManifestV1::from_file_bytes(&manifest_bytes).unwrap();
    let ptr = crate::CurrentPointerV1 {
        generation: 3,
        manifest_hash,
    };
    std::fs::write(root.join("CURRENT"), ptr.to_file_bytes()).unwrap();
    assert_eq!(
        fatal(open_err(root)),
        FatalError::ConflictingPointers {
            pointer_generation: 3,
            manifest_generation: 2
        }
    );
}

#[test]
fn identity_mismatch_is_fatal() {
    let td = TestDir::new("identity");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
    }
    let mut cfg = test_cfg(td.store_root());
    cfg.identity = b"WRONG-CHAIN".to_vec();
    let err = match Store::open(cfg, real()) {
        Err(e) => e,
        Ok(_) => panic!("expected open to fail"),
    };
    assert!(matches!(fatal(err), FatalError::IdentityMismatch));
}

#[test]
fn fallback_to_previous_verified_generation() {
    let td = TestDir::new("fallback");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.create_snapshot().unwrap(); // gen 2
        s.commit(ws(2)).unwrap();
    }
    let root = td.store_root();
    // Corrupt gen-2's manifest: pointed generation invalid.
    flip_byte(&root.join("gen-00000000000000000002").join("MANIFEST"), 12);
    let s = must_open(root.clone());
    let fb = s.open_report().fell_back.clone().expect("fallback taken");
    assert_eq!(fb.pointed, 2);
    assert_eq!(fb.adopted, 1);
    assert_eq!(s.current_generation(), 1);
    // Full state still recovered: gen-1 + complete WAL tail.
    assert_eq!(s.applied_seq(), 2);
    assert_eq!(
        s.get_state(TreeId::Notes, &h(11), None).unwrap(),
        Some(val(21))
    );
    drop(s);
    // The fallback was made durable: a second open is clean.
    let s = must_open(root);
    assert!(s.open_report().fell_back.is_none());
    assert_eq!(s.current_generation(), 1);
}

#[test]
fn no_valid_generation_is_fatal() {
    let td = TestDir::new("no-valid");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
        s.create_snapshot().unwrap(); // gen 2
    }
    let root = td.store_root();
    flip_byte(&root.join("gen-00000000000000000001").join("MANIFEST"), 12);
    flip_byte(&root.join("gen-00000000000000000002").join("MANIFEST"), 12);
    assert!(matches!(
        fatal(open_err(root)),
        FatalError::NoValidGeneration { pointed: 2, .. }
    ));
}

#[test]
fn orphan_temp_generations_are_ignored() {
    let td = TestDir::new("orphan-tmp");
    {
        let mut s = must_open(td.store_root());
        s.commit(ws(1)).unwrap();
    }
    let orphan = td
        .store_root()
        .join("tmp-gen-00000000000000000009-00000000000000000000");
    std::fs::create_dir_all(orphan.join("engine")).unwrap();
    std::fs::write(orphan.join("MANIFEST"), b"partial garbage").unwrap();
    let s = must_open(td.store_root());
    assert_eq!(s.current_generation(), 1);
    assert_eq!(s.applied_seq(), 1);
}

// ---------------------------------------------------------------------------
// Snapshot law + retention
// ---------------------------------------------------------------------------

#[test]
fn snapshot_creates_verified_generation_and_flips_pointer() {
    let td = TestDir::new("snapshot");
    let root = td.store_root();
    {
        let mut s = must_open(root.clone());
        s.commit(ws(1)).unwrap();
        assert_eq!(s.create_snapshot().unwrap(), 2);
        assert_eq!(s.current_generation(), 2);
        s.commit(ws(2)).unwrap();
    }
    assert!(root
        .join("gen-00000000000000000002")
        .join("MANIFEST")
        .exists());
    // No temp dirs remain.
    let leftovers: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "leftover temp dirs: {leftovers:?}");
    // Reopen from the snapshot alone (live gone): tail replay of ws2 only.
    std::fs::remove_dir_all(root.join("live")).unwrap();
    let s = must_open(root);
    assert_eq!(s.open_report().replayed_records, 1);
    assert_eq!(s.applied_seq(), 2);
    assert_eq!(
        s.get_state(TreeId::Notes, &h(11), None).unwrap(),
        Some(val(21))
    );
}

#[test]
fn retention_keeps_n_and_previous_until_fresh_process_proves_replay() {
    let td = TestDir::new("retention");
    let root = td.store_root();
    let gen_dir = |g: u64| root.join(format!("gen-{g:020}"));
    {
        let mut s = must_open(root.clone());
        s.commit(ws(1)).unwrap();
        s.create_snapshot().unwrap(); // gen 2
        s.commit(ws(2)).unwrap();
        s.create_snapshot().unwrap(); // gen 3
                                      // Same process: gens 2 and 3 are NOT yet proven by a fresh
                                      // process; only init-proven gen 1 is. Nothing may be pruned.
        let report = s.prune().unwrap();
        assert!(report.removed_generations.is_empty());
        assert!(gen_dir(1).exists() && gen_dir(2).exists() && gen_dir(3).exists());
    }
    {
        // Fresh process: proves gen 3 (snapshot + tail replay), then prune
        // may drop gen 1 — gen 3 (N) and gen 2 (N-1) are retained.
        let mut s = must_open(root.clone());
        assert_eq!(s.open_report().proved_generation, Some(3));
        let report = s.prune().unwrap();
        assert_eq!(report.removed_generations, vec![1]);
        assert!(!gen_dir(1).exists());
        assert!(gen_dir(2).exists() && gen_dir(3).exists());
    }
    // The last verified generation is never deleted, even after proof.
    {
        let mut s = must_open(root.clone());
        let report = s.prune().unwrap();
        assert!(report.removed_generations.is_empty());
        assert!(gen_dir(2).exists() && gen_dir(3).exists());
    }
}

#[test]
fn prune_respects_wal_needed_by_retained_generations() {
    let td = TestDir::new("wal-prune");
    let root = td.store_root();
    {
        let mut s = must_open(root.clone());
        // Many commits to force several WAL segments (512-byte rotation).
        for i in 0..12u8 {
            let w = WriteSet {
                delta: delta(vec![(TreeId::Notes, h(100 + i), None, Some(val(i)))]),
                ..WriteSet::default()
            };
            s.commit(w).unwrap();
        }
        assert!(wal_segments(&root).len() >= 2, "expected wal rotation");
        s.create_snapshot().unwrap();
        s.commit(ws(1)).unwrap();
    }
    {
        let mut s = must_open(root.clone());
        s.create_snapshot().unwrap();
        let _ = s.prune().unwrap();
    }
    // Whatever was pruned, a snapshot-only recovery must still work.
    std::fs::remove_dir_all(root.join("live")).unwrap();
    let s = must_open(root);
    assert_eq!(
        s.get_state(TreeId::Notes, &h(111), None).unwrap(),
        Some(val(11))
    );
    assert_eq!(
        s.get_state(TreeId::Notes, &h(11), None).unwrap(),
        Some(val(1))
    );
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

#[test]
fn blob_segments_rotate_and_verify() {
    let td = TestDir::new("blobs");
    let root = td.store_root();
    let mut s = must_open(root.clone());
    // 300-byte segments; each blob ~100 bytes => several segments.
    for i in 0..8u8 {
        let w = WriteSet {
            blobs: vec![Blob {
                hash: h(220 + i),
                bytes: vec![i; 100],
            }],
            ..WriteSet::default()
        };
        s.commit(w).unwrap();
    }
    for i in 0..8u8 {
        assert_eq!(s.get_blob(&h(220 + i)).unwrap(), Some(vec![i; 100]));
    }
    let segs: Vec<_> = std::fs::read_dir(root.join("segments"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(
        segs.len() >= 2,
        "expected blob segment rotation, got {}",
        segs.len()
    );
    // Every segment respects the bound (blob records here are 168 bytes).
    for seg in &segs {
        assert!(std::fs::metadata(seg).unwrap().len() <= 300);
    }
    drop(s);

    // Corrupt one blob's bytes (they sit beyond every snapshot watermark,
    // so startup validation does not cover them): the read fails typed.
    let s = must_open(root.clone());
    let mut seg_paths = segs.clone();
    seg_paths.sort();
    flip_byte(&seg_paths[0], 80); // inside first record's contents
    match s.get_blob(&h(220)) {
        Err(StoreError::BlobCorrupt { .. }) => {}
        other => panic!("expected BlobCorrupt, got {other:?}"),
    }
}

#[test]
fn blob_corruption_below_watermark_invalidates_generation() {
    let td = TestDir::new("blob-watermark");
    let root = td.store_root();
    {
        let mut s = must_open(root.clone());
        s.commit(ws(1)).unwrap(); // includes blob h(201)
        s.create_snapshot().unwrap(); // gen 2 pins the segment prefix
    }
    let seg = std::fs::read_dir(root.join("segments"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .next()
        .unwrap();
    flip_byte(&seg, 80);
    // Pointed gen 2 now fails its watermark check; gen 1 pinned no
    // segments and still validates: fallback.
    let s = must_open(root);
    assert_eq!(s.open_report().fell_back.clone().unwrap().adopted, 1);
}

// ---------------------------------------------------------------------------
// Safety records + barrier
// ---------------------------------------------------------------------------

#[test]
fn safety_records_survive_snapshot_plus_tail_recovery() {
    let td = TestDir::new("safety");
    let root = td.store_root();
    let payload = b"beacon-commit epoch=7 validator=3".to_vec();
    {
        let mut s = must_open(root.clone());
        s.commit(ws(1)).unwrap();
        let seq = s
            .persist_safety_record(SAFETY_KIND_WITNESS_BEACON, &payload)
            .unwrap();
        assert_eq!(seq, 2);
        s.barrier().unwrap();
        // Ok from persist_safety_record ⇒ durable NOW: no snapshot, no
        // clean shutdown required beyond this point.
    }
    std::fs::remove_dir_all(root.join("live")).unwrap();
    let s = must_open(root);
    let records = s.safety_records(SAFETY_KIND_WITNESS_BEACON).unwrap();
    assert_eq!(records, vec![payload]);
    assert!(s.safety_records(2).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Poisoning
// ---------------------------------------------------------------------------

#[test]
fn failed_commit_poisons_the_handle() {
    use crate::{FailpointVfs, Failpoints};
    let td = TestDir::new("poison");
    let root = td.store_root();
    let fp = Failpoints::new();
    let vfs: Arc<dyn Vfs> = Arc::new(FailpointVfs::new(Arc::new(RealVfs), Arc::clone(&fp)));
    let mut s = Store::open(test_cfg(root), vfs).unwrap();
    s.commit(ws(1)).unwrap();
    // Arm the 2nd boundary from here: inside the next commit's WAL write.
    fp.arm(2);
    let err = s.commit(ws(2)).unwrap_err();
    assert!(err.is_injected(), "expected injected fault, got {err}");
    assert!(matches!(s.commit(ws(3)), Err(StoreError::Poisoned)));
    assert!(matches!(s.barrier(), Err(StoreError::Poisoned)));
}
