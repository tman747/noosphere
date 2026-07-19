//! Import negative matrix (node-v1.md §10.2): every stage of the
//! seven-stage pipeline rejects (or PARKS) exactly as specified, a
//! rejection never dirties the importer's state, and reorgs below
//! finality roll back / replay deterministically while finalized
//! checkpoints are never reverted by work.

use noos_braid::{BlockHeaderV1, Bytes96, CheckpointRef, EPOCH_LENGTH};
use noos_crypto::{BlsSecretKey, DomainId};
use noos_da::{encode_body, DaError, MAX_BLOCK_DA_FORM_BYTES};
use noos_ground::{GroundError, GroundTicketV1};

use crate::consensus::{ImportOutcome, NodeCore};
use crate::genesis::{mine_ticket, DEVNET_PROPOSER_SEED};
use crate::roots::{body_ticket_root, body_tx_root, body_witness_root, da_form_bytes};
use crate::store_port::{key_header, InProcStore, StorePort};
use crate::view::ViewLookup;
use crate::NodeError;

use super::util::*;

/// Re-mines the Ground ticket and re-signs a (tampered) header so that a
/// mutation reaches the exact stage under test instead of dying at the
/// signature or ticket-binding checks. `parent` supplies the retarget
/// context; the proposer is the devnet fixture key.
fn reissue(
    chain_id: &crate::Hash32,
    parent: &BlockHeaderV1,
    header: &mut BlockHeaderV1,
) -> GroundTicketV1 {
    let commitment = header.proposal_commitment().expect("commitment");
    let parent_target = parent.ground_target_u256();
    let target = header.ground_target_u256();
    let ticket = mine_ticket(
        chain_id,
        &header.parent_hash,
        &parent_target,
        header.slot,
        &commitment,
        &header.proposer_key.0,
        &target,
    )
    .expect("mine ticket");
    header.ground_ticket_root = body_ticket_root(&ticket).expect("ticket root");
    let secret = BlsSecretKey::from_seed(DEVNET_PROPOSER_SEED).expect("proposer seed");
    let sig = secret
        .sign_domain(DomainId::BlsProposer, commitment.as_bytes())
        .expect("proposer sign");
    header.proposer_signature = Bytes96(sig.into_bytes());
    ticket
}

struct FailNextCommit {
    inner: InProcStore,
    fail_next: bool,
}

impl StorePort for FailNextCommit {
    fn commit(&mut self, writes: noos_store::WriteSet) -> Result<u64, NodeError> {
        if std::mem::take(&mut self.fail_next) {
            return Err(NodeError::Config("injected store commit failure".into()));
        }
        self.inner.commit(writes)
    }

    fn persist_safety(&mut self, kind: u16, payload: &[u8]) -> Result<u64, NodeError> {
        self.inner.persist_safety(kind, payload)
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

    fn get_blob(&self, hash: &crate::Hash32) -> Result<Option<Vec<u8>>, NodeError> {
        self.inner.get_blob(hash)
    }

    fn scan_indices(&self, prefix: &[u8]) -> Result<crate::store_port::ScanEntries, NodeError> {
        self.inner.scan_indices(prefix)
    }

    fn roots(&self) -> Result<Option<noos_lumen::state::LumenRoots>, NodeError> {
        self.inner.roots()
    }

    fn create_snapshot(&mut self) -> Result<u64, NodeError> {
        self.inner.create_snapshot()
    }

    fn applied_seq(&self) -> u64 {
        self.inner.applied_seq()
    }
}

fn boot_fail_next_commit_node(dir: &std::path::Path) -> NodeCore<FailNextCommit> {
    let cfg = node_config();
    let mut genesis_spec = spec();
    genesis_spec.contract_codes = cfg.contract_codes.clone();
    let built = genesis_spec.build().expect("genesis build");
    let inner = InProcStore::open(dir.to_path_buf(), &built.chain_id, &built.genesis_hash)
        .expect("store open");
    NodeCore::boot(
        cfg,
        &genesis_spec,
        built,
        FailNextCommit {
            inner,
            fail_next: false,
        },
        std::sync::Arc::new(crate::metrics::Metrics::default()),
    )
    .expect("node boot")
}

/// Producer A (one settled transfer in block 1) and a fresh importer B
/// over the same genesis. Returns `(a, b, produced_block_1)`.
fn producer_and_importer(
    tag: &str,
) -> (
    NodeCore<InProcStore>,
    NodeCore<InProcStore>,
    crate::consensus::ProducedBlock,
) {
    let dir_a = test_dir(&format!("{tag}-a"));
    let dir_b = test_dir(&format!("{tag}-b"));
    let mut a = boot_node(&dir_a, node_config());
    let mut b = boot_node(&dir_b, node_config());
    let chain_id = a.chain_id();
    let (tx, wit, _) = signed_transfer(chain_id, 40, &faucet_key(), operator_account(1), 777);
    a.submit_tx(&tx, &wit, 7).expect("admit transfer");
    let pb = produce_full(&mut a);
    b.set_now(pb.header.timestamp_ms);
    (a, b, pb)
}

#[test]
fn happy_import_then_duplicate_rejects() {
    let (a, mut b, pb) = producer_and_importer("im-dup");
    let outcome = b
        .import_block(&pb.header, &pb.ticket, &pb.claim, &pb.shards)
        .expect("import");
    assert_eq!(outcome, ImportOutcome::Executed { hash: pb.hash });
    assert_eq!(b.head(), a.head());
    assert_eq!(b.ledger().roots(), a.ledger().roots(), "same state");
    assert_eq!(
        b.ledger()
            .balance(&operator_account(1), &noos_lumen::state::NOOS_ASSET),
        777
    );

    // Importing the same block again is a duplicate, never corruption.
    let err = b
        .import_block(&pb.header, &pb.ticket, &pb.claim, &pb.shards)
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Dag(noos_braid::DagError::DuplicateBlock)
    ));
    assert_eq!(b.head(), a.head(), "duplicate moved nothing");
}

#[test]
fn replay_rejection_preserves_the_preexisting_settled_receipt() {
    let (mut producer, mut importer, first) = producer_and_importer("im-replay-receipt");
    importer
        .import_block(&first.header, &first.ticket, &first.claim, &first.shards)
        .expect("import first block");
    let first_txid = first
        .body
        .segregated_witnesses
        .iter()
        .next()
        .expect("first witnesses")
        .intents
        .iter()
        .next()
        .expect("first intent")
        .tx_commitment;
    let receipt_before = importer
        .ledger()
        .get_receipt(&first_txid)
        .expect("first receipt");
    let roots_before = importer.ledger().roots();

    let mut replay = produce_full(&mut producer);
    replay.body.transactions = first.body.transactions.clone();
    replay.body.segregated_witnesses = first.body.segregated_witnesses.clone();
    replay.header.tx_root =
        body_tx_root(&replay.body.transactions).expect("replay transaction root");
    replay.header.witness_root =
        body_witness_root(&replay.body.segregated_witnesses).expect("replay witness root");
    let encoded = encode_body(&da_form_bytes(&replay.body)).expect("encode replay body");
    replay.header.body_da_root = encoded.shard_root().into_bytes();
    let ticket = reissue(&importer.chain_id(), &first.header, &mut replay.header);
    replay.body.ground_ticket = noos_braid::GroundTicketWire(ticket);
    let claim = *encoded.claim();
    let shards = encoded.into_candidates().expect("replay shards");
    importer.set_now(replay.header.timestamp_ms);

    let error = importer
        .import_block(&replay.header, &ticket, &claim, &shards)
        .expect_err("settled transaction replay");
    assert!(matches!(
        error,
        NodeError::LumenReject(noos_lumen::state::RejectReason::TxAlreadySettled)
    ));
    assert_eq!(importer.head(), (1, first.hash));
    assert_eq!(importer.ledger().roots(), roots_before);
    assert_eq!(
        importer.ledger().get_receipt(&first_txid),
        Some(receipt_before)
    );
}

#[test]
fn store_commit_failure_restores_receipts_and_allows_retry() {
    let producer_dir = test_dir("im-store-failure-producer");
    let importer_dir = test_dir("im-store-failure-importer");
    let mut producer = boot_node(&producer_dir, node_config());
    let mut importer = boot_fail_next_commit_node(&importer_dir);
    let chain_id = producer.chain_id();

    let (first_tx, first_witnesses, first_txid) =
        signed_transfer(chain_id, 40, &faucet_key(), operator_account(1), 777);
    producer
        .submit_tx(&first_tx, &first_witnesses, 7)
        .expect("admit first transfer");
    let first = produce_full(&mut producer);
    importer.set_now(first.header.timestamp_ms);
    importer
        .import_block(&first.header, &first.ticket, &first.claim, &first.shards)
        .expect("import first block");

    let (second_tx, second_witnesses, second_txid) =
        signed_transfer(chain_id, 50, &faucet_key(), operator_account(2), 333);
    producer
        .submit_tx(&second_tx, &second_witnesses, 8)
        .expect("admit second transfer");
    let second = produce_full(&mut producer);
    importer.set_now(second.header.timestamp_ms);
    let head_before = importer.head();
    let roots_before = importer.ledger().roots();
    let first_receipt = importer
        .ledger()
        .get_receipt(&first_txid)
        .expect("first settled receipt");
    let store_seq_before = importer.port.applied_seq();
    importer.port.fail_next = true;

    let error = importer
        .import_block(
            &second.header,
            &second.ticket,
            &second.claim,
            &second.shards,
        )
        .expect_err("injected store failure");
    assert!(matches!(
        &error,
        NodeError::Config(message) if message == "injected store commit failure"
    ));
    assert_eq!(importer.head(), head_before);
    assert_eq!(importer.ledger().roots(), roots_before);
    assert_eq!(importer.port.applied_seq(), store_seq_before);
    assert_eq!(
        importer.ledger().get_receipt(&first_txid),
        Some(first_receipt)
    );
    assert_eq!(importer.ledger().get_receipt(&second_txid), None);

    let outcome = importer
        .import_block(
            &second.header,
            &second.ticket,
            &second.claim,
            &second.shards,
        )
        .expect("retry after store recovery");
    assert_eq!(outcome, ImportOutcome::Executed { hash: second.hash });
    assert_eq!(importer.head(), producer.head());
    assert_eq!(importer.ledger().roots(), producer.ledger().roots());
    assert!(importer.ledger().get_receipt(&second_txid).is_some());
}

#[test]
fn bad_ticket_root_binding_rejects() {
    let (_a, mut b, pb) = producer_and_importer("im-tkroot");
    // Gossiped ticket differs from the one bound by header field 24.
    let mut bad = pb.ticket;
    bad.nonce = bad.nonce.wrapping_add(1);
    let err = b
        .import_block(&pb.header, &bad, &pb.claim, &pb.shards)
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::BodyMismatch {
            what: "ground_ticket_root"
        }
    ));
    assert_eq!(b.head().0, 0, "rejected header never entered the chain");
}

#[test]
fn bad_ticket_digest_rejects_under_ground_law() {
    let (_a, mut b, pb) = producer_and_importer("im-tkdigest");
    // Bind the tampered ticket properly (field 24 is excluded from the
    // proposal commitment, so the signature stays valid) — the rejection
    // must now come from the Ground rule-3 digest recomputation.
    let mut bad = pb.ticket;
    bad.nonce = bad.nonce.wrapping_add(1);
    let mut header = pb.header.clone();
    header.ground_ticket_root = body_ticket_root(&bad).expect("ticket root");
    let err = b
        .import_block(&header, &bad, &pb.claim, &pb.shards)
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::Ground(GroundError::DigestMismatch)
    ));
    assert_eq!(b.head().0, 0);
}

#[test]
fn bad_state_root_rejects_and_leaves_importer_clean() {
    let (a, mut b, pb) = producer_and_importer("im-roots");
    let genesis_header = spec().build().expect("genesis").header;
    let roots_before = b.ledger().roots();

    let mut header = pb.header.clone();
    header.accounts_root = [0xAB; 32];
    let ticket = reissue(&b.chain_id(), &genesis_header, &mut header);
    let err = b
        .import_block(&header, &ticket, &pb.claim, &pb.shards)
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::RootMismatch {
            field: "accounts_root"
        }
    ));
    // Rejection is clean: head unmoved, ledger rebuilt to the exec head.
    assert_eq!(b.head().0, 0);
    assert_eq!(
        b.ledger().roots(),
        roots_before,
        "rejection left roots intact"
    );

    // The untampered block still imports afterwards.
    let outcome = b
        .import_block(&pb.header, &pb.ticket, &pb.claim, &pb.shards)
        .expect("valid import after rejection");
    assert_eq!(outcome, ImportOutcome::Executed { hash: pb.hash });
    assert_eq!(b.ledger().roots(), a.ledger().roots());
}

#[test]
fn bad_transaction_body_root_rejects_after_overlapped_validation() {
    let (a, mut b, pb) = producer_and_importer("im-body-tx-root");
    let genesis_header = spec().build().expect("genesis").header;
    let roots_before = b.ledger().roots();
    let mut header = pb.header.clone();
    header.tx_root = [0xCD; 32];
    let ticket = reissue(&b.chain_id(), &genesis_header, &mut header);

    let error = b
        .import_block(&header, &ticket, &pb.claim, &pb.shards)
        .expect_err("body transaction root mismatch");
    assert!(matches!(
        error,
        NodeError::RootMismatch { field: "tx_root" }
    ));
    assert_eq!(b.head().0, 0);
    assert_eq!(b.ledger().roots(), roots_before);

    let outcome = b
        .import_block(&pb.header, &pb.ticket, &pb.claim, &pb.shards)
        .expect("untampered block remains importable");
    assert_eq!(outcome, ImportOutcome::Executed { hash: pb.hash });
    assert_eq!(b.ledger().roots(), a.ledger().roots());
}

#[test]
fn bad_state_root_on_side_branch_is_rejected_before_visibility() {
    let side_dir = test_dir("im-side-root-side");
    let importer_dir = test_dir("im-side-root-importer");
    let mut side = boot_node(&side_dir, node_config());
    let mut importer = boot_node(&importer_dir, node_config());
    let genesis_header = spec().build().expect("genesis").header;

    // Keep the importer's two-block chain heavier so the candidate is
    // unambiguously a side branch rooted at genesis.
    produce_next(&mut importer);
    produce_next(&mut importer);
    let side_block = produce_full(&mut side);
    importer.set_now(side_block.header.timestamp_ms);
    let before_head = importer.head();
    let before_roots = importer.ledger().roots();
    let before_dag_len = importer.dag().len();
    let before_store_seq = importer.port.store().applied_seq();

    let mut header = side_block.header.clone();
    header.accounts_root = [0xBC; 32];
    let ticket = reissue(&importer.chain_id(), &genesis_header, &mut header);
    let hash = *header.block_hash().expect("hash").as_bytes();
    let err = importer
        .import_block(&header, &ticket, &side_block.claim, &side_block.shards)
        .expect_err("bad side-branch execution root");
    assert!(matches!(
        err,
        NodeError::RootMismatch {
            field: "accounts_root"
        }
    ));
    assert_eq!(importer.head(), before_head);
    assert_eq!(importer.ledger().roots(), before_roots);
    assert_eq!(importer.dag().len(), before_dag_len);
    assert_eq!(importer.port.store().applied_seq(), before_store_seq);
    assert!(importer
        .port
        .get_header(&key_header(&hash))
        .expect("header lookup")
        .is_none());
}

#[test]
fn receipt_root_interchange_rejects() {
    let (_a, mut b, pb) = producer_and_importer("im-interchange");
    let genesis_header = spec().build().expect("genesis").header;
    // The block carries one transfer, so the ordered execution receipt
    // root and the post-state settled-index root are distinct values.
    assert_ne!(
        pb.header.execution_receipt_root,
        pb.header.lumen_receipts_state_root
    );
    let mut header = pb.header.clone();
    header.execution_receipt_root = pb.header.lumen_receipts_state_root;
    header.lumen_receipts_state_root = pb.header.execution_receipt_root;
    let ticket = reissue(&b.chain_id(), &genesis_header, &mut header);
    let err = b
        .import_block(&header, &ticket, &pb.claim, &pb.shards)
        .unwrap_err();
    assert!(matches!(
        err,
        NodeError::RootMismatch {
            field: "lumen_receipts_state_root"
        }
    ));
    assert_eq!(b.head().0, 0);
}

#[test]
fn unavailable_da_body_parks_then_resumes() {
    let (a, mut b, pb) = producer_and_importer("im-park");
    // Fewer than BODY_DATA_SHARDS (16) valid shards: the block PARKS —
    // pausing is not rejection.
    let outcome = b
        .import_block(&pb.header, &pb.ticket, &pb.claim, &pb.shards[..10])
        .expect("park");
    assert_eq!(outcome, ImportOutcome::ParkedAwaitingBody { hash: pb.hash });
    assert_eq!(b.head().0, 0, "parked block did not execute");
    assert!(!b.body_available(&pb.header.body_da_root));

    // Still not enough after 4 more (14 < 16): stays parked, no error.
    let fed = b
        .feed_shards(&pb.hash, &pb.shards[10..14])
        .expect("feed partial");
    assert_eq!(fed, None);
    assert_eq!(b.head().0, 0);

    // Late shards resume the ordinary pipeline.
    let resumed = b
        .feed_shards(&pb.hash, &pb.shards[14..])
        .expect("feed rest")
        .expect("resumed");
    assert_eq!(resumed, ImportOutcome::Executed { hash: pb.hash });
    assert_eq!(b.head(), a.head());
    assert_eq!(b.ledger().roots(), a.ledger().roots());
    assert!(b.body_available(&pb.header.body_da_root));
}

#[test]
fn oversized_body_claim_rejects() {
    let (_a, mut b, pb) = producer_and_importer("im-oversize");
    let mut claim = pb.claim;
    claim.original_bytes = MAX_BLOCK_DA_FORM_BYTES as u64 + 1;
    let err = b
        .import_block(&pb.header, &pb.ticket, &claim, &pb.shards)
        .unwrap_err();
    assert!(matches!(err, NodeError::Da(DaError::BodyTooLarge { .. })));
    assert_eq!(b.head().0, 0);
}

#[test]
fn reorg_below_finality_rolls_back_and_replays() {
    let dir_a = test_dir("reorg-a");
    let dir_b = test_dir("reorg-b");
    let mut a = boot_node(&dir_a, node_config());
    let mut b = boot_node(&dir_b, node_config());
    let chain_id = a.chain_id();
    let alice = operator_account(1);

    // Branch A: one EMPTY block. Branch B: two blocks carrying a transfer.
    let a1 = produce_next(&mut a);
    let (tx, wit, txid) = signed_transfer(chain_id, 40, &faucet_key(), alice, 1_000_000);
    b.submit_tx(&tx, &wit, 7).expect("admit transfer on B");
    let b1 = produce_full(&mut b);
    let b2 = produce_full(&mut b);

    // Feed the heavier branch to A; fork choice must roll back the empty
    // block and replay B's bodies through the store.
    a.set_now(b2.header.timestamp_ms);
    a.import_block(&b1.header, &b1.ticket, &b1.claim, &b1.shards)
        .expect("import B1");
    a.import_block(&b2.header, &b2.ticket, &b2.claim, &b2.shards)
        .expect("import B2");

    assert_eq!(a.head(), (2, b2.hash), "reorged onto the heavier branch");
    assert_ne!(a1, b1.hash);
    assert_eq!(
        a.ledger().roots(),
        b.ledger().roots(),
        "replayed exact state"
    );
    assert_eq!(
        a.ledger().balance(&alice, &noos_lumen::state::NOOS_ASSET),
        1_000_000,
        "the replayed transfer settled on A"
    );
    // The canonical view now presents B's branch at height 1.
    match a.view.block_by_height(1) {
        ViewLookup::Found(summary) => assert_eq!(summary.hash, b1.hash),
        other => panic!("expected canonical block 1, got {other:?}"),
    }
    assert_eq!(
        a.tx_status(&txid),
        ViewLookup::Found(crate::view::TxStatus::Settled {
            height: 1,
            status: 0
        })
    );
}

#[test]
fn finalized_checkpoint_is_never_reverted_by_work() {
    let dir_a = test_dir("fin-a");
    let dir_c = test_dir("fin-c");
    let mut a = boot_node(&dir_a, node_config());
    let mut c = boot_node(&dir_c, node_config());
    let genesis_cp = a.finalized();

    // A: two epochs + certificates → epoch-1 checkpoint FINALIZED.
    for _ in 0..EPOCH_LENGTH {
        produce_next(&mut a);
    }
    let (_, head1) = a.head();
    let cp1 = CheckpointRef {
        epoch: 1,
        checkpoint_hash: a
            .dag()
            .ancestor_at_height(&head1, EPOCH_LENGTH)
            .expect("cp1")
            .hash,
    };
    let cert1 = quorum_certificate(&mut a, genesis_cp, cp1);
    a.queue_certificate(cert1).expect("cert1");
    for _ in 0..EPOCH_LENGTH {
        produce_next(&mut a);
    }
    let (_, head2) = a.head();
    let cp2 = CheckpointRef {
        epoch: 2,
        checkpoint_hash: a
            .dag()
            .ancestor_at_height(&head2, 2 * EPOCH_LENGTH)
            .expect("cp2")
            .hash,
    };
    let cert2 = quorum_certificate(&mut a, cp1, cp2);
    a.queue_certificate(cert2).expect("cert2");
    assert_eq!(a.finalized(), cp1);
    let head_before = a.head();
    let roots_before = a.ledger().roots();

    // C: a conflicting branch with MORE cumulative work (2 epochs + 8
    // blocks at the same per-block work). Feeding it to A must not move
    // the head, the finalized pointer, or one byte of state — finalized
    // checkpoints outrank work in fork choice, and a reorg plan across
    // finality is a typed refusal, never a rollback.
    let extra = 2 * EPOCH_LENGTH + 8;
    let mut c_blocks = Vec::with_capacity(extra as usize);
    for _ in 0..extra {
        c_blocks.push(produce_full(&mut c));
    }
    a.set_now(c_blocks.last().expect("blocks").header.timestamp_ms + 1);
    for pb in &c_blocks {
        match a.import_block(&pb.header, &pb.ticket, &pb.claim, &pb.shards) {
            // A conflicting block may sit on a side branch, orphan out of
            // the bounded pool, or be refused outright by the finality
            // laws — but it must NEVER execute onto the canonical chain.
            Ok(ImportOutcome::Executed { .. }) => {
                panic!("work reverted a finalized checkpoint")
            }
            Ok(_) | Err(NodeError::Dag(_)) => {}
            Err(e) => panic!("unexpected import failure class: {e}"),
        }
    }
    assert_eq!(a.head(), head_before, "head unmoved by conflicting work");
    assert_eq!(a.finalized(), cp1, "finalized pointer unmoved");
    assert_eq!(a.ledger().roots(), roots_before, "state untouched");
}
