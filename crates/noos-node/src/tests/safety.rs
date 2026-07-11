//! Safety battery (node-v1.md §10.4): persist-before-vote ordering
//! (durable BEFORE visible; a failed barrier emits nothing; a conflicting
//! vote is refused locally before any slashable message exists — and the
//! refusal survives restart), plus the SOCIAL-INPUT weak-subjectivity
//! checkpoint law (typed error, never an override of local finality,
//! enforced on the live node AND at restart).

use noos_braid::CheckpointRef;
use noos_codec::NoosDecode;
use noos_lumen::state::LumenRoots;
use noos_store::WriteSet;

use crate::consensus::NodeCore;
use crate::store_port::{InProcStore, StorePort, SAFETY_KIND_VOTE};
use crate::witness_role::{sign_and_release_vote, VoteRefused, VoteSafetyRecordV1};
use crate::{Hash32, NodeError};

use super::util::*;

fn cp(epoch: u64, byte: u8) -> CheckpointRef {
    CheckpointRef {
        epoch,
        checkpoint_hash: [byte; 32],
    }
}

fn open_store(dir: &std::path::Path) -> InProcStore {
    let built = spec().build().expect("genesis");
    InProcStore::open(dir.to_path_buf(), &built.chain_id, &built.genesis_hash).expect("store open")
}

#[test]
fn vote_is_released_only_after_its_record_is_durable() {
    let dir = test_dir("safety-vote");
    let mut port = open_store(&dir);
    let chain = [7; 32];
    let validator: Hash32 = [1; 32];
    let membership_root = [2; 32];
    let source = cp(0, 0x11);
    let target = cp(1, 0x22);

    let vote = sign_and_release_vote(
        &mut port,
        chain,
        1,
        source,
        target,
        validator,
        membership_root,
        &witness_secret(0),
    )
    .expect("vote released");
    assert_eq!(vote.epoch, 1);
    assert_eq!(vote.target, target);

    // The durable record exists and decodes to exactly the vote's tuple.
    let records = port.safety_records(SAFETY_KIND_VOTE).expect("records");
    assert_eq!(records.len(), 1);
    let rec = VoteSafetyRecordV1::decode_canonical(&records[0]).expect("record decodes");
    assert_eq!(rec.validator_id, validator);
    assert_eq!(rec.epoch, 1);
    assert_eq!(rec.source, source);
    assert_eq!(rec.target, target);

    // Re-releasing the SAME target is not double voting.
    sign_and_release_vote(
        &mut port,
        chain,
        1,
        source,
        target,
        validator,
        membership_root,
        &witness_secret(0),
    )
    .expect("idempotent re-release");

    // A DIFFERENT target for the same epoch is refused as slashable.
    let err = sign_and_release_vote(
        &mut port,
        chain,
        1,
        source,
        cp(1, 0x33),
        validator,
        membership_root,
        &witness_secret(0),
    )
    .unwrap_err();
    assert_eq!(
        err,
        VoteRefused::Slashable {
            existing_target: target
        }
    );

    // The refusal is durable: a fresh process over the same store still
    // refuses (restart replays the records, never forgets a vote).
    drop(port);
    let mut reopened = open_store(&dir);
    let err = sign_and_release_vote(
        &mut reopened,
        chain,
        1,
        source,
        cp(1, 0x44),
        validator,
        membership_root,
        &witness_secret(0),
    )
    .unwrap_err();
    assert!(matches!(err, VoteRefused::Slashable { existing_target } if existing_target == target));

    // A different epoch is unrelated and releases normally.
    sign_and_release_vote(
        &mut reopened,
        chain,
        2,
        target,
        cp(2, 0x55),
        validator,
        membership_root,
        &witness_secret(0),
    )
    .expect("next epoch vote");
}

/// Port whose safety barrier fails: proves the exact ordering — when the
/// persist step cannot ack, NO vote is returned to the caller.
struct FailingBarrier {
    inner: InProcStore,
}

impl StorePort for FailingBarrier {
    fn commit(&mut self, ws: &WriteSet) -> Result<u64, NodeError> {
        self.inner.commit(ws)
    }
    fn persist_safety(&mut self, _kind: u16, _payload: &[u8]) -> Result<u64, NodeError> {
        Err(NodeError::BarrierFailed("injected barrier fault".into()))
    }
    fn barrier(&mut self) -> Result<(), NodeError> {
        self.inner.barrier()
    }
    fn safety_records(&self, kind: u16) -> Result<Vec<Vec<u8>>, NodeError> {
        self.inner.safety_records(kind)
    }
    fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.inner.get_header(key)
    }
    fn get_index(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.inner.get_index(key)
    }
    fn get_receipt(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.inner.get_receipt(key)
    }
    fn get_blob(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, NodeError> {
        self.inner.get_blob(hash)
    }
    fn scan_indices(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, NodeError> {
        self.inner.scan_indices(prefix)
    }
    fn roots(&self) -> Result<Option<LumenRoots>, NodeError> {
        self.inner.roots()
    }
    fn create_snapshot(&mut self) -> Result<u64, NodeError> {
        self.inner.create_snapshot()
    }
    fn applied_seq(&self) -> u64 {
        self.inner.applied_seq()
    }
}

#[test]
fn failed_barrier_emits_nothing() {
    let dir = test_dir("safety-barrier");
    let mut port = FailingBarrier {
        inner: open_store(&dir),
    };
    let err = sign_and_release_vote(
        &mut port,
        [7; 32],
        1,
        cp(0, 0x11),
        cp(1, 0x22),
        [1; 32],
        [2; 32],
        &witness_secret(0),
    )
    .unwrap_err();
    assert!(matches!(err, VoteRefused::Barrier(_)));
    // Nothing durable, nothing emitted: the record set is empty.
    assert!(port
        .safety_records(SAFETY_KIND_VOTE)
        .expect("scan")
        .is_empty());
}

#[test]
fn social_checkpoint_never_overrides_local_finality() {
    let dir = test_dir("safety-social");
    let mut core = boot_node(&dir, node_config());
    let genesis_cp = core.finalized();

    // Consistent with local finality: accepted as a sync hint only.
    core.apply_social_checkpoint(genesis_cp)
        .expect("consistent social input");
    assert_eq!(core.finalized(), genesis_cp, "hint moved nothing");

    // Ahead of local finality: retained as a hint, finality unmoved.
    core.apply_social_checkpoint(cp(5, 0x77))
        .expect("future hint retained");
    assert_eq!(core.finalized(), genesis_cp);

    // Conflicting with locally finalized state: TYPED error, no motion.
    let bogus = cp(0, 0xEE);
    let err = core.apply_social_checkpoint(bogus).unwrap_err();
    match err {
        NodeError::SocialCheckpointConflictsLocalFinality { local, social } => {
            assert_eq!(local, genesis_cp);
            assert_eq!(social, bogus);
        }
        other => panic!("expected the social-conflict error, got {other}"),
    }
    assert_eq!(core.finalized(), genesis_cp, "finality never overridden");
}

#[test]
fn restart_refuses_a_social_checkpoint_conflicting_with_recovered_finality() {
    let dir = test_dir("safety-social-restart");
    // First boot writes genesis durably.
    drop(boot_node(&dir, node_config()));

    // Restart configured with a conflicting SOCIAL checkpoint: recovery
    // must fail typed rather than adopt it.
    let spec = spec();
    let built = spec.build().expect("genesis");
    let port =
        InProcStore::open(dir.clone(), &built.chain_id, &built.genesis_hash).expect("store open");
    let mut cfg = node_config();
    cfg.social_checkpoint = Some(cp(0, 0xEE));
    let result = NodeCore::boot(
        cfg,
        &spec,
        built,
        port,
        std::sync::Arc::new(crate::metrics::Metrics::default()),
    );
    match result {
        Err(NodeError::SocialCheckpointConflictsLocalFinality { .. }) => {}
        Err(other) => panic!("wrong refusal class: {other}"),
        Ok(_) => panic!("conflicting social checkpoint must refuse startup"),
    }
}
