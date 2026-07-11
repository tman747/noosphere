//! Sync battery (node-v1.md §10.5): header-first full sync, light sync,
//! and finalized snapshot sync over multiple untrusted sources — every
//! peer-supplied byte is re-validated (pipeline law for blocks; the
//! store's open law for snapshot files; a corrupt source surfaces as a
//! typed open failure, never as accepted state).

use std::collections::BTreeMap;

use noos_braid::{BlockHeaderV1, CheckpointRef, FinalityCertificateV1, EPOCH_LENGTH};
use noos_da::{BodyDaClaimV1, ShardCandidateV1};
use noos_ground::GroundTicketV1;
use noos_witness::vote::FinalityVoteV1;

use crate::consensus::NodeMode;
use crate::store_port::InProcStore;
use crate::sync::{
    fetch_snapshot_files, full_sync_round, light_sync_round, DirSnapshotSource, EdgeError,
    NetworkEdge, SnapshotSource,
};
use crate::Hash32;

use super::util::*;

/// An in-process edge replaying a recorded chain (the shape the noos-p2p
/// binding will drive over `/noos/braid/*` + `/noos/sync/range/1`).
#[derive(Default)]
struct RecordedEdge {
    headers: Vec<(BlockHeaderV1, GroundTicketV1)>,
    bodies: BTreeMap<Hash32, (BodyDaClaimV1, Vec<ShardCandidateV1>)>,
    certs: Vec<FinalityCertificateV1>,
}

impl RecordedEdge {
    fn record(&mut self, pb: &crate::consensus::ProducedBlock) {
        self.headers.push((pb.header.clone(), pb.ticket));
        self.bodies
            .insert(pb.header.body_da_root, (pb.claim, pb.shards.clone()));
    }
}

impl NetworkEdge for RecordedEdge {
    fn request_headers(
        &mut self,
        from_height: u64,
        max: u32,
    ) -> Result<Vec<(BlockHeaderV1, GroundTicketV1)>, EdgeError> {
        let start =
            usize::try_from(from_height.saturating_sub(1)).map_err(|_| EdgeError::Malformed)?;
        if start >= self.headers.len() {
            return Err(EdgeError::Unavailable);
        }
        Ok(self
            .headers
            .iter()
            .skip(start)
            .take(max as usize)
            .cloned()
            .collect())
    }

    fn request_body(
        &mut self,
        body_da_root: &Hash32,
    ) -> Result<(BodyDaClaimV1, Vec<ShardCandidateV1>), EdgeError> {
        self.bodies
            .get(body_da_root)
            .cloned()
            .ok_or(EdgeError::Unavailable)
    }

    fn request_certificates(
        &mut self,
        after_epoch: u64,
        max: u32,
    ) -> Result<Vec<FinalityCertificateV1>, EdgeError> {
        Ok(self
            .certs
            .iter()
            .filter(|c| c.target.epoch > after_epoch)
            .take(max as usize)
            .cloned()
            .collect())
    }

    fn announce_header(&mut self, _header: &BlockHeaderV1, _ticket: &GroundTicketV1) {}
    fn announce_tx(&mut self, _tx_bytes: &[u8], _wit_bytes: &[u8]) {}
    fn announce_vote(&mut self, _vote: &FinalityVoteV1) {}
}

/// Producer chain: one justified epoch (256 blocks, a transfer in block 1)
/// plus its certificate, recorded into an edge.
fn recorded_chain(tag: &str) -> (crate::consensus::NodeCore<InProcStore>, RecordedEdge) {
    let dir = test_dir(tag);
    let mut a = boot_node(&dir, node_config());
    let genesis_cp = a.finalized();
    let chain_id = a.chain_id();
    let (tx, wit, _) = signed_transfer(
        chain_id,
        2 * EPOCH_LENGTH,
        &faucet_key(),
        operator_account(1),
        123_456,
    );
    a.submit_tx(&tx, &wit, 7).expect("admit");

    let mut edge = RecordedEdge::default();
    for _ in 0..EPOCH_LENGTH {
        let pb = produce_full(&mut a);
        edge.record(&pb);
    }
    let (_, head) = a.head();
    let cp1 = CheckpointRef {
        epoch: 1,
        checkpoint_hash: a
            .dag()
            .ancestor_at_height(&head, EPOCH_LENGTH)
            .expect("cp1")
            .hash,
    };
    let cert = quorum_certificate(&mut a, genesis_cp, cp1);
    a.queue_certificate(cert.clone())
        .expect("producer ingests its own cert");
    edge.certs.push(cert);
    (a, edge)
}

#[test]
fn header_first_full_sync_reaches_the_producer_state() {
    let (a, mut edge) = recorded_chain("sync-full-a");
    let dir_b = test_dir("sync-full-b");
    let mut b = boot_node(&dir_b, node_config());
    b.set_now(GENESIS_TIME_MS + (EPOCH_LENGTH + 1) * 6000);

    let mut total = 0_u64;
    loop {
        let n = full_sync_round(&mut b, &mut edge, 64).expect("sync round");
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, EPOCH_LENGTH, "every block re-executed");
    assert_eq!(b.head(), a.head());
    assert_eq!(b.ledger().roots(), a.ledger().roots(), "exact state");
    assert_eq!(
        b.ledger()
            .balance(&operator_account(1), &noos_lumen::state::NOOS_ASSET),
        123_456
    );
    // Certificates pulled after bodies advanced finality to justified.
    assert_eq!(b.justified().epoch, 1);
    assert_eq!(b.justified(), a.justified());

    // A drained edge is silence, not an error.
    assert_eq!(
        full_sync_round(&mut b, &mut edge, 64).expect("idle round"),
        0
    );
}

#[test]
fn light_sync_accepts_headers_and_finality_without_bodies() {
    let (a, mut edge) = recorded_chain("sync-light-a");
    let dir_l = test_dir("sync-light-l");
    let mut cfg = node_config();
    cfg.mode = NodeMode::Light;
    let mut l = boot_node(&dir_l, cfg);
    l.set_now(GENESIS_TIME_MS + (EPOCH_LENGTH + 1) * 6000);

    let mut total = 0_u64;
    loop {
        let n = light_sync_round(&mut l, &mut edge, 64).expect("light round");
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, EPOCH_LENGTH, "all headers accepted");
    // No execution happened (headers + Ground work + finality only)…
    assert_eq!(l.head().0, 0, "light mode executes nothing");
    // …but the DAG holds the chain and finality advanced from certs.
    let (_, a_head) = a.head();
    assert!(l.dag().contains(&a_head));
    assert_eq!(l.justified().epoch, 1);
}

#[test]
fn snapshot_sync_assembles_from_multiple_sources_and_recovers_state() {
    // Producer with a short settled history.
    let dir_a = test_dir("snap-a");
    let mut a = boot_node(&dir_a, node_config());
    let chain_id = a.chain_id();
    let (tx, wit, _) = signed_transfer(chain_id, 40, &faucet_key(), operator_account(2), 9_999);
    a.submit_tx(&tx, &wit, 7).expect("admit");
    for _ in 0..8 {
        produce_next(&mut a);
    }
    let head = a.head();
    let roots = a.ledger().roots();
    drop(a); // close the store so the files are settled on disk

    // First source cannot even list; the second serves everything. Any
    // file may come from any source — the fetch must still assemble.
    let dead = DirSnapshotSource::new(test_dir("snap-dead").join("missing"));
    let good = DirSnapshotSource::new(dir_a.clone());
    let mut sources: Vec<Box<dyn SnapshotSource>> = vec![Box::new(dead), Box::new(good)];
    let dest = test_dir("snap-dest");
    fetch_snapshot_files(&mut sources, &dest).expect("assemble snapshot");

    // The assembled root passes the store's own open law and replays to
    // the exact producer state.
    let b = boot_node(&dest, node_config());
    assert_eq!(b.head(), head);
    assert_eq!(b.ledger().roots(), roots);
    assert_eq!(
        b.ledger()
            .balance(&operator_account(2), &noos_lumen::state::NOOS_ASSET),
        9_999
    );
}

#[test]
fn corrupt_snapshot_source_is_a_typed_open_failure_never_accepted_state() {
    let dir_a = test_dir("snap-corrupt-a");
    let mut a = boot_node(&dir_a, node_config());
    for _ in 0..3 {
        produce_next(&mut a);
    }
    drop(a);

    // A single lying source: every served file has its first byte flipped.
    let mut lying = DirSnapshotSource::new(dir_a.clone());
    for name in lying.list().expect("list") {
        lying.corrupt.insert(name);
    }
    let mut sources: Vec<Box<dyn SnapshotSource>> = vec![Box::new(lying)];
    let dest = test_dir("snap-corrupt-dest");
    fetch_snapshot_files(&mut sources, &dest).expect("bytes assemble; trust comes later");

    // Verification is entirely the store's open law: the corrupt root is
    // refused at open — it can never become node state.
    let built = spec().build().expect("genesis");
    assert!(
        InProcStore::open(dest, &built.chain_id, &built.genesis_hash).is_err(),
        "corrupt snapshot must fail the open law"
    );
}

#[test]
fn snapshot_fetch_refuses_path_escapes_and_silent_emptiness() {
    // A source offering parent-directory escapes is refused outright.
    struct EvilSource;
    impl SnapshotSource for EvilSource {
        fn list(&self) -> Result<Vec<String>, EdgeError> {
            Ok(vec!["../outside".into()])
        }
        fn fetch(&self, _name: &str) -> Result<Vec<u8>, EdgeError> {
            Ok(vec![1, 2, 3])
        }
    }
    let mut sources: Vec<Box<dyn SnapshotSource>> = vec![Box::new(EvilSource)];
    let dest = test_dir("snap-evil-dest");
    assert!(fetch_snapshot_files(&mut sources, &dest).is_err());

    // No usable source at all is typed, not an empty success.
    let mut none: Vec<Box<dyn SnapshotSource>> =
        vec![Box::new(DirSnapshotSource::new(dest.join("void")))];
    assert!(fetch_snapshot_files(&mut none, &test_dir("snap-none-dest")).is_err());
}
