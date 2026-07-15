use std::sync::Arc;

use crate::artifact_store::*;
use crate::test_util::{test_cfg, TestDir};
use crate::{RealVfs, Store, Vfs};

fn config(td: &TestDir) -> ArtifactStoreConfig {
    let mut c = ArtifactStoreConfig::under(
        td.path.join("artifact"),
        td.path.join("consensus"),
        1_000_000,
    );
    c.segment_size_bytes = 1024;
    c.io_bytes_per_second = 4096;
    c
}
fn spec() -> ArtifactIngestSpec {
    ArtifactIngestSpec {
        artifact: [7; 32],
        stripe_count: 2,
        positions: vec![2, 9],
    }
}
fn stage_all(store: &mut ArtifactStore) {
    let s = spec();
    store.begin_ingest(s.clone()).unwrap();
    for stripe in 0..s.stripe_count {
        for position in &s.positions {
            store
                .stage_share(
                    &s.artifact,
                    stripe,
                    *position,
                    &[stripe as u8, *position, 4, 5],
                )
                .unwrap();
        }
        store.checkpoint_stripe(&s.artifact, stripe).unwrap();
    }
}

#[test]
fn rejects_equal_ancestor_descendant_and_internal_path_overlap() {
    let td = TestDir::new("artifact-paths");
    let mut c = config(&td);
    c.consensus_root = c.root.clone();
    assert!(matches!(
        ArtifactStore::open(c),
        Err(ArtifactStoreError::PathOverlap { .. })
    ));
    let mut c = config(&td);
    c.consensus_root = td.path.clone();
    assert!(matches!(
        ArtifactStore::open(c),
        Err(ArtifactStoreError::PathOverlap { .. })
    ));
    let mut c = config(&td);
    c.consensus_root = c.root.join("consensus-child");
    assert!(matches!(
        ArtifactStore::open(c),
        Err(ArtifactStoreError::PathOverlap { .. })
    ));
    let mut c = config(&td);
    c.index = c.segments.join("index-child");
    assert!(matches!(
        ArtifactStore::open(c),
        Err(ArtifactStoreError::PathOverlap { .. })
    ));
}

#[test]
fn crash_outcomes_are_resumable_or_fully_published() {
    for point in [
        ArtifactFailpoint::AfterSegmentSync,
        ArtifactFailpoint::AfterWalSync,
        ArtifactFailpoint::BeforeIndexRename,
    ] {
        let td = TestDir::new(&format!("artifact-crash-{point:?}"));
        let c = config(&td);
        let manifest = b"canonical manifest";
        let mut store = ArtifactStore::open(c.clone()).unwrap();
        stage_all(&mut store);
        store.set_failpoint(Some(point));
        let outcome = store.publish(&spec().artifact, manifest);
        assert!(
            matches!(outcome, Err(ArtifactStoreError::Injected(p)) if p == point),
            "{point:?}: {outcome:?}",
        );
        drop(store);
        let mut recovered = ArtifactStore::open(c).unwrap();
        if recovered.read_manifest(&spec().artifact).is_err() {
            recovered.begin_ingest(spec()).unwrap();
            recovered.publish(&spec().artifact, manifest).unwrap();
        }
        assert_eq!(recovered.read_manifest(&spec().artifact).unwrap(), manifest);
        let mut share = [0_u8; 4];
        recovered
            .read_share(&spec().artifact, 1, 9, &mut share)
            .unwrap();
        assert_eq!(share, [1, 9, 4, 5]);
    }
}

#[test]
fn publish_quota_accounting_matches_reopened_store() {
    let td = TestDir::new("artifact-publish-accounting");
    let c = config(&td);
    let mut store = ArtifactStore::open(c.clone()).unwrap();
    stage_all(&mut store);
    store.publish(&spec().artifact, b"canonical manifest").unwrap();
    let published_used = store.used_bytes();
    let stage = c.staging.join("07".repeat(32));
    assert!(!stage.exists());
    drop(store);

    let reopened = ArtifactStore::open(c).unwrap();
    assert_eq!(published_used, reopened.used_bytes());
}

#[test]
fn quota_corruption_resume_and_consensus_independence() {
    let td = TestDir::new("artifact-independent");
    let consensus_root = td.path.join("consensus");
    let vfs: Arc<dyn Vfs> = Arc::new(RealVfs);
    let _consensus = Store::open(test_cfg(consensus_root.clone()), vfs).unwrap();

    let mut c = config(&td);
    c.quota_bytes = 40;
    let mut artifact = ArtifactStore::open(c.clone()).unwrap();
    artifact.begin_ingest(spec()).unwrap();
    artifact
        .stage_share(&spec().artifact, 0, 2, &[1, 2, 3, 4])
        .unwrap();
    assert!(matches!(
        artifact.stage_share(&spec().artifact, 0, 9, &[0; 64]),
        Err(ArtifactStoreError::QuotaExceeded { .. })
    ));
    // Artifact failure is typed and does not touch or prevent reopening the
    // physically separate consensus store.
    drop(artifact);
    drop(_consensus);
    let _consensus_reopened = Store::open(test_cfg(consensus_root), Arc::new(RealVfs)).unwrap();

    std::fs::remove_dir_all(&c.root).unwrap();
    let mut c = config(&td);
    c.quota_bytes = 1_000_000;
    let mut artifact = ArtifactStore::open(c.clone()).unwrap();
    stage_all(&mut artifact);
    let state = artifact.resume_state(&spec().artifact).unwrap();
    assert_eq!(state.completed_stripes.len(), 2);
    assert!(!state.published);
    artifact.publish(&spec().artifact, b"m").unwrap();
    let index = c.index.join(format!("{}.idx", "07".repeat(32)));
    let mut bytes = std::fs::read(&index).unwrap();
    bytes[5] ^= 1;
    std::fs::write(&index, bytes).unwrap();
    assert!(matches!(
        artifact.read_manifest(&spec().artifact),
        Err(ArtifactStoreError::Corrupt { .. })
    ));
}
