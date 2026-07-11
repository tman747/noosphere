//! Import negative matrix (node-v1.md §10.2): every stage of the
//! seven-stage pipeline rejects (or PARKS) exactly as specified, a
//! rejection never dirties the importer's state, and reorgs below
//! finality roll back / replay deterministically while finalized
//! checkpoints are never reverted by work.

use noos_braid::{BlockHeaderV1, Bytes96, CheckpointRef, EPOCH_LENGTH};
use noos_crypto::{BlsSecretKey, DomainId};
use noos_da::{DaError, MAX_BLOCK_BODY_BYTES};
use noos_ground::{GroundError, GroundTicketV1};

use crate::consensus::{ImportOutcome, NodeCore};
use crate::genesis::{mine_ticket, DEVNET_PROPOSER_SEED};
use crate::roots::body_ticket_root;
use crate::store_port::InProcStore;
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
    claim.original_bytes = MAX_BLOCK_BODY_BYTES as u64 + 1;
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
        a.view.tx_status(&txid),
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
