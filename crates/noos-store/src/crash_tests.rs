//! Crash-injection matrix (plan §7.3: "inject crashes at every
//! write/fsync/rename/prune boundary").
//!
//! A scripted workload (init, commits with state/headers/receipts/
//! indices/blobs, a safety record, two snapshots, a prune, a final commit
//! and barrier) is first run once with a counting-only [`Failpoints`] to
//! number every durability boundary: WAL creates/appends/fsyncs, blob
//! segment appends/fsyncs, snapshot temp-dir creates, per-file fsyncs,
//! manifest writes, directory flushes, renames, `CURRENT` flips,
//! `PROVEN` writes, prune removals, and the bracketed engine
//! apply/checkpoint/open calls.
//!
//! Then, for EVERY boundary `k`, a fresh directory runs the same workload
//! with a crash injected at boundary `k` (data writes tear to a
//! deterministic prefix; everything after is dead). A fresh
//! `Store::open` over the real filesystem must then recover to the last
//! durable state — every acknowledged write present, no partial
//! generation adopted, functional for further commits — or stop with a
//! typed fatal error. Silent loss and silent partiality both fail the
//! property. For this workload's crash-only faults (no corruption beyond
//! the modeled torn tail), recovery must always SUCCEED.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::sync::Arc;

use noos_lumen::state::TreeId;

use crate::test_util::{h, roots, test_cfg, val, ws, TestDir};
use crate::{
    FailpointVfs, Failpoints, RealVfs, Store, StoreError, Vfs, WriteSet, SAFETY_KIND_WITNESS_BEACON,
};

const SAFETY_PAYLOAD: &[u8] = b"beacon-reveal epoch=9";

/// Facts the workload has been ACKNOWLEDGED for so far. Anything acked
/// must survive recovery; anything unacked may or may not.
#[derive(Debug, Default, Clone)]
struct Acked {
    markers: Vec<u8>,
    safety: bool,
    snapshots: Vec<u64>,
    last_seq: u64,
}

fn run_workload(vfs: Arc<dyn Vfs>, root: PathBuf, acked: &mut Acked) -> Result<(), StoreError> {
    let mut store = Store::open(test_cfg(root), vfs)?;
    for marker in [1u8, 2] {
        let seq = store.commit(&ws(marker))?;
        acked.markers.push(marker);
        acked.last_seq = seq;
    }
    let seq = store.persist_safety_record(SAFETY_KIND_WITNESS_BEACON, SAFETY_PAYLOAD)?;
    acked.safety = true;
    acked.last_seq = seq;
    acked.snapshots.push(store.create_snapshot()?);
    let seq = store.commit(&ws(3))?;
    acked.markers.push(3);
    acked.last_seq = seq;
    acked.snapshots.push(store.create_snapshot()?);
    store.prune()?;
    let seq = store.commit(&ws(4))?;
    acked.markers.push(4);
    acked.last_seq = seq;
    store.barrier()?;
    Ok(())
}

/// Assert recovery correctness.
///
/// Law: an ACKED step MUST be present; an in-flight (unacked) step MAY be
/// present — its WAL record can be durable without the ack — but only
/// ATOMICALLY (all effects or none) and only in commit order (the applied
/// steps form a prefix of the workload). Presence is derived from a
/// per-step canary key.
fn verify_acked(store: &Store, acked: &Acked, ctx: &str) {
    assert!(
        store.applied_seq() >= acked.last_seq,
        "{ctx}: applied_seq {} < last acked seq {}",
        store.applied_seq(),
        acked.last_seq
    );
    // Canaries: ws1 -> header h1, ws2 -> receipt r2, safety -> record,
    // ws3 -> index i3, ws4 -> state h(16).
    let p1 = store.get_header(b"h1").unwrap().is_some();
    let p2 = store.get_receipt(b"r2").unwrap().is_some();
    let ps = store
        .safety_records(SAFETY_KIND_WITNESS_BEACON)
        .unwrap()
        .iter()
        .any(|r| r == SAFETY_PAYLOAD);
    let p3 = store.get_index(b"i3").unwrap().is_some();
    let p4 = store
        .get_state(TreeId::Notes, &h(16), None)
        .unwrap()
        .is_some();

    // Applied steps form a prefix of the commit order.
    let chain = [p1, p2, ps, p3, p4];
    for w in chain.windows(2) {
        assert!(
            w[0] || !w[1],
            "{ctx}: applied steps are not a prefix: {chain:?}"
        );
    }
    // Every acked step is applied.
    let has = |m: u8| acked.markers.contains(&m);
    assert!(!has(1) || p1, "{ctx}: acked ws1 lost");
    assert!(!has(2) || p2, "{ctx}: acked ws2 lost");
    assert!(!acked.safety || ps, "{ctx}: acked safety record lost");
    assert!(!has(3) || p3, "{ctx}: acked ws3 lost");
    assert!(!has(4) || p4, "{ctx}: acked ws4 lost");

    // Atomicity: an applied step shows ALL its effects.
    if p1 && !p2 {
        assert_eq!(
            store.get_state(TreeId::Notes, &h(11), None).unwrap(),
            Some(val(1)),
            "{ctx}: ws1 partially applied"
        );
        assert_eq!(
            store.get_state(TreeId::Notes, &h(12), None).unwrap(),
            Some(val(2)),
            "{ctx}: ws1 partially applied"
        );
    }
    if p2 {
        assert_eq!(
            store.get_state(TreeId::Notes, &h(11), None).unwrap(),
            Some(val(21)),
            "{ctx}: ws2 overwrite missing"
        );
        assert_eq!(
            store.get_state(TreeId::Notes, &h(12), None).unwrap(),
            None,
            "{ctx}: ws2 delete missing"
        );
    }
    if p1 {
        assert_eq!(
            store
                .get_state(TreeId::Accounts, &h(13), Some(&h(14)))
                .unwrap(),
            Some(val(3)),
            "{ctx}: ws1 sub-key write missing"
        );
        assert_eq!(
            store.get_blob(&h(201)).unwrap(),
            Some(b"blob-one-contents".to_vec()),
            "{ctx}: ws1 blob missing"
        );
    }
    if p3 {
        assert_eq!(
            store.get_state(TreeId::Objects, &h(15), None).unwrap(),
            Some(val(31)),
            "{ctx}: ws3 partially applied"
        );
        assert_eq!(
            store.get_blob(&h(203)).unwrap(),
            Some(b"blob-three-contents-which-are-a-bit-longer".to_vec()),
            "{ctx}: ws3 blob missing"
        );
    }
    if p4 {
        assert_eq!(
            store.get_state(TreeId::Notes, &h(16), None).unwrap(),
            Some(val(41)),
            "{ctx}: ws4 partially applied"
        );
        assert_eq!(
            store.roots().unwrap(),
            Some(roots(60)),
            "{ctx}: ws4 roots missing"
        );
    }
    // Acked snapshots survive (rename + pointer flip + dir flush all
    // completed before the ack).
    if let Some(g) = acked.snapshots.last() {
        assert!(
            store.current_generation() >= *g,
            "{ctx}: acked snapshot generation {} lost (current {})",
            g,
            store.current_generation()
        );
    }
}

#[test]
fn crash_injection_matrix_recovers_at_every_boundary() {
    // Pass 1: number the boundaries.
    let total = {
        let td = TestDir::new("crash-count");
        let fp = Failpoints::new();
        let vfs: Arc<dyn Vfs> = Arc::new(FailpointVfs::new(Arc::new(RealVfs), Arc::clone(&fp)));
        let mut acked = Acked::default();
        run_workload(vfs, td.store_root(), &mut acked).expect("clean workload run");
        // Clean run sanity: everything acked, everything verifiable.
        let store = Store::open(test_cfg(td.store_root()), Arc::new(RealVfs)).unwrap();
        assert_eq!(acked.markers, vec![1, 2, 3, 4]);
        assert_eq!(acked.snapshots, vec![2, 3]);
        verify_acked(&store, &acked, "clean run");
        fp.boundaries_seen()
    };
    assert!(
        total >= 60,
        "workload exercised suspiciously few durability boundaries: {total}"
    );

    // Pass 2: crash at every boundary, recover, verify.
    let mut injected = 0u64;
    for k in 1..=total {
        let td = TestDir::new("crash");
        let fp = Failpoints::new();
        fp.arm(k);
        let vfs: Arc<dyn Vfs> = Arc::new(FailpointVfs::new(Arc::new(RealVfs), Arc::clone(&fp)));
        let mut acked = Acked::default();
        let result = run_workload(vfs, td.store_root(), &mut acked);
        if fp.triggered() {
            injected += 1;
            let err = result.expect_err("workload must fail once the fault fires");
            // The surfaced error must be the injected fault, possibly
            // wrapped — never a silent success and never a panic.
            assert!(
                err.is_injected() || matches!(err, StoreError::Engine(_)),
                "boundary {k}: unexpected error class: {err}"
            );
        } else {
            // Boundary count drifted below k for this run (engine file
            // sets can vary slightly): the workload simply completed.
            result.unwrap_or_else(|e| panic!("boundary {k}: untriggered run failed: {e}"));
        }

        // Fresh process over the real filesystem: recovery must reach the
        // last durable state. Crash-only faults never produce a fatal.
        let store = Store::open(test_cfg(td.store_root()), Arc::new(RealVfs))
            .unwrap_or_else(|e| panic!("boundary {k}: recovery failed: {e}"));
        verify_acked(&store, &acked, &format!("boundary {k}"));

        // No partial generation may be adopted: the pointed generation
        // fully validated during open (or open would have failed). The
        // store must remain fully functional.
        let mut store = store;
        let probe = WriteSet {
            delta: crate::test_util::delta(vec![(TreeId::Nullifiers, h(250), None, Some(val(99)))]),
            ..WriteSet::default()
        };
        store
            .commit(&probe)
            .unwrap_or_else(|e| panic!("boundary {k}: post-recovery commit failed: {e}"));
        assert_eq!(
            store.get_state(TreeId::Nullifiers, &h(250), None).unwrap(),
            Some(val(99))
        );
    }
    assert!(
        injected >= total.saturating_sub(5),
        "too few faults actually fired: {injected}/{total}"
    );
    println!(
        "crash-injection matrix: {total} boundaries, {injected} injected crashes, all recovered"
    );
}
