//! Adversarial import-pipeline regressions: checkpoint evidence, certificate
//! transactionality, restart invisibility, and contextual orphan promotion.

use noos_braid::{
    BlockBodyV1, BlockHeaderV1, Bytes96, CheckpointRef, FinalityCertificateV1, GroundTicketWire,
    EPOCH_LENGTH,
};
use noos_crypto::{BlsSecretKey, DomainId};
use noos_da::{encode_body, BODY_TOTAL_SHARDS};
use noos_ground::{slot_from_timestamp, GroundTicketV1, MAX_SLOT_SKIP, SLOT_MS};
use noos_lumen::objects::BoundedList;
use noos_store::Cf;

use crate::consensus::{ImportOutcome, NodeCore, ProducedBlock};
use crate::genesis::{mine_ticket, DEVNET_PROPOSER_SEED};
use crate::roots::{body_cert_root, body_ticket_root, da_form_bytes};
use crate::store_port::{key_header, InProcStore, StorePort};
use crate::Hash32;

use super::util::*;

#[derive(Debug, PartialEq, Eq)]
struct ObservableState {
    head: (u64, Hash32),
    justified: CheckpointRef,
    finalized: CheckpointRef,
    roots: noos_lumen::state::LumenRoots,
    dag_len: usize,
    orphan_count: usize,
    view_blocks: usize,
    view_txs: usize,
    metrics: String,
    store_seq: u64,
    state_cf: Vec<(Vec<u8>, Vec<u8>)>,
    header_cf: Vec<(Vec<u8>, Vec<u8>)>,
    receipt_cf: Vec<(Vec<u8>, Vec<u8>)>,
    index_cf: Vec<(Vec<u8>, Vec<u8>)>,
}

fn observe(core: &NodeCore<InProcStore>) -> ObservableState {
    let store = core.port.store();
    ObservableState {
        head: core.head(),
        justified: core.justified(),
        finalized: core.finalized(),
        roots: core.ledger().roots(),
        dag_len: core.dag().len(),
        orphan_count: core.dag().orphan_count(),
        view_blocks: core.view.block_count(),
        view_txs: core.view.tx_record_count(),
        metrics: core.metrics.render(),
        store_seq: store.applied_seq(),
        state_cf: store.scan(Cf::State, b"").expect("scan state"),
        header_cf: store.scan(Cf::Headers, b"").expect("scan headers"),
        receipt_cf: store.scan(Cf::Receipts, b"").expect("scan receipts"),
        index_cf: store.scan(Cf::Indices, b"").expect("scan indices"),
    }
}

fn reissue(parent: &BlockHeaderV1, header: &mut BlockHeaderV1) -> GroundTicketV1 {
    let commitment = header.proposal_commitment().expect("commitment");
    let ticket = mine_ticket(
        &header.chain_id,
        &header.parent_hash,
        &parent.ground_target_u256(),
        header.slot,
        &commitment,
        &header.proposer_key.0,
        &header.ground_target_u256(),
    )
    .expect("mine ticket");
    header.ground_ticket_root = body_ticket_root(&ticket).expect("ticket root");
    resign(header);
    ticket
}

fn resign(header: &mut BlockHeaderV1) {
    let commitment = header.proposal_commitment().expect("commitment");
    let secret = BlsSecretKey::from_seed(DEVNET_PROPOSER_SEED).expect("proposer seed");
    header.proposer_signature = Bytes96(
        secret
            .sign_domain(DomainId::BlsProposer, commitment.as_bytes())
            .expect("sign")
            .into_bytes(),
    );
}

fn repack(
    parent: &BlockHeaderV1,
    mut header: BlockHeaderV1,
    mut body: BlockBodyV1,
) -> ProducedBlock {
    header.finality_certificate_root =
        body_cert_root(&body.finality_certificates).expect("certificate root");
    let encoded = encode_body(&da_form_bytes(&body)).expect("encode body");
    header.body_da_root = encoded.shard_root().into_bytes();
    let ticket = reissue(parent, &mut header);
    body.ground_ticket = GroundTicketWire(ticket);
    let hash = *header.block_hash().expect("block hash").as_bytes();
    let claim = *encoded.claim();
    let shards = (0..BODY_TOTAL_SHARDS)
        .map(|i| encoded.candidate(i as u32).expect("candidate"))
        .collect();
    ProducedBlock {
        hash,
        header,
        ticket,
        body,
        claim,
        shards,
    }
}

fn import(
    core: &mut NodeCore<InProcStore>,
    block: &ProducedBlock,
) -> Result<ImportOutcome, crate::NodeError> {
    core.import_block(&block.header, &block.ticket, &block.claim, &block.shards)
}

fn invalid_certificate(core: &mut NodeCore<InProcStore>) -> FinalityCertificateV1 {
    let cp = core.finalized();
    let mut cert = quorum_certificate(core, cp, cp);
    cert.aggregate_signature.0[0] ^= 0x80;
    cert
}

#[test]
fn header_checkpoint_claims_require_exact_certificate_evidence() {
    let producer_dir = test_dir("checkpoint-evidence-producer");
    let importer_dir = test_dir("checkpoint-evidence-importer");
    let mut producer = boot_node(&producer_dir, node_config());
    let mut importer = boot_node(&importer_dir, node_config());
    let block = produce_full(&mut producer);
    importer.set_now(block.header.timestamp_ms);
    let genesis = spec().build().expect("genesis").header;
    let genesis_cp = importer.finalized();
    let before = observe(&importer);

    let claims = [
        (
            CheckpointRef {
                epoch: u64::MAX,
                checkpoint_hash: genesis_cp.checkpoint_hash,
            },
            genesis_cp,
        ),
        (
            CheckpointRef {
                epoch: 1,
                checkpoint_hash: genesis_cp.checkpoint_hash,
            },
            genesis_cp,
        ),
        (
            CheckpointRef {
                epoch: 1,
                checkpoint_hash: [0xA5; 32],
            },
            CheckpointRef {
                epoch: 1,
                checkpoint_hash: genesis_cp.checkpoint_hash,
            },
        ),
    ];
    for (justified, finalized) in claims {
        let mut forged = block.header.clone();
        forged.justified_checkpoint = justified;
        forged.finalized_checkpoint = finalized;
        let ticket = reissue(&genesis, &mut forged);
        let forged_hash = *forged.block_hash().expect("hash").as_bytes();
        let error = importer
            .import_block(&forged, &ticket, &block.claim, &block.shards)
            .expect_err("unverified checkpoint claim");
        assert!(matches!(
            error,
            crate::NodeError::Dag(noos_braid::DagError::UnverifiedCheckpoint)
        ));
        assert_eq!(observe(&importer), before);
        assert!(importer
            .port
            .get_header(&key_header(&forged_hash))
            .expect("header lookup")
            .is_none());
    }
}

#[test]
fn invalid_embedded_certificate_is_transactionally_invisible() {
    let producer_dir = test_dir("bad-cert-producer");
    let importer_dir = test_dir("bad-cert-importer");
    let mut producer = boot_node(&producer_dir, node_config());
    let mut importer = boot_node(&importer_dir, node_config());
    let block = produce_full(&mut producer);
    let genesis = spec().build().expect("genesis").header;
    let cert = invalid_certificate(&mut producer);
    let mut body = block.body.clone();
    body.finality_certificates = BoundedList::new(vec![cert]).expect("one cert");
    let forged = repack(&genesis, block.header, body);
    importer.set_now(forged.header.timestamp_ms);
    let before = observe(&importer);

    import(&mut importer, &forged).expect_err("invalid certificate");
    assert_eq!(observe(&importer), before);
    assert!(importer
        .port
        .get_header(&key_header(&forged.hash))
        .expect("header lookup")
        .is_none());
    assert!(importer
        .port
        .get_blob(&forged.header.body_da_root)
        .expect("blob lookup")
        .is_none());

    drop(importer);
    let restarted = boot_node(&importer_dir, node_config());
    assert_eq!(observe(&restarted), before);
    assert!(restarted
        .port
        .get_header(&key_header(&forged.hash))
        .expect("header lookup")
        .is_none());
    assert!(restarted
        .port
        .get_blob(&forged.header.body_da_root)
        .expect("blob lookup")
        .is_none());
}

#[test]
fn second_invalid_certificate_rolls_back_first_and_restart_sees_no_block() {
    let producer_dir = test_dir("second-cert-producer");
    let importer_dir = test_dir("second-cert-importer");
    let mut producer = boot_node(&producer_dir, node_config());
    let mut importer = boot_node(&importer_dir, node_config());
    let mut chain = Vec::with_capacity(EPOCH_LENGTH as usize);
    for _ in 0..EPOCH_LENGTH {
        chain.push(produce_full(&mut producer));
    }
    for block in &chain {
        importer.set_now(block.header.timestamp_ms);
        import(&mut importer, block).expect("prefix import");
    }
    let checkpoint = CheckpointRef {
        epoch: 1,
        checkpoint_hash: chain.last().expect("checkpoint block").hash,
    };
    let source = producer.finalized();
    let valid = quorum_certificate(&mut producer, source, checkpoint);
    let mut invalid = valid.clone();
    invalid.aggregate_signature.0[0] ^= 0x40;
    let next = produce_full(&mut producer);
    let mut header = next.header;
    header.justified_checkpoint = checkpoint;
    header.finalized_checkpoint = source;
    let mut body = next.body;
    body.finality_certificates = BoundedList::new(vec![valid, invalid]).expect("two certs");
    let forged = repack(&chain.last().expect("parent").header, header, body);
    importer.set_now(forged.header.timestamp_ms);
    let before = observe(&importer);

    import(&mut importer, &forged).expect_err("second certificate invalid");
    assert_eq!(observe(&importer), before);
    assert!(importer
        .port
        .get_header(&key_header(&forged.hash))
        .expect("header lookup")
        .is_none());

    drop(importer);
    let restarted = boot_node(&importer_dir, node_config());
    assert_eq!(restarted.head(), before.head);
    assert_eq!(restarted.ledger().roots(), before.roots);
    assert_eq!(restarted.justified(), before.justified);
    assert_eq!(restarted.finalized(), before.finalized);
    assert_eq!(restarted.port.store().applied_seq(), before.store_seq);
    assert!(restarted
        .port
        .get_header(&key_header(&forged.hash))
        .expect("header lookup")
        .is_none());
}

fn orphan_variant(
    name: &str,
    parent: &BlockHeaderV1,
    block: &ProducedBlock,
    genesis_hash: Hash32,
) -> (String, BlockHeaderV1, GroundTicketV1) {
    let mut header = block.header.clone();
    let ticket = match name {
        "digest" => {
            let mut ticket = block.ticket;
            ticket.nonce = ticket.nonce.wrapping_add(1);
            header.ground_ticket_root = body_ticket_root(&ticket).expect("ticket root");
            ticket
        }
        "target_work" => {
            header.ground_target = [0xFF; 32];
            reissue(parent, &mut header)
        }
        "slot" => {
            header.slot = parent.slot + MAX_SLOT_SKIP + 1;
            header.timestamp_ms = GENESIS_TIME_MS + header.slot * SLOT_MS;
            reissue(parent, &mut header)
        }
        "future_drift" => {
            header.timestamp_ms = parent.timestamp_ms + 12_001;
            header.slot = slot_from_timestamp(header.timestamp_ms, GENESIS_TIME_MS).expect("slot");
            reissue(parent, &mut header)
        }
        "timestamp_mtp" => {
            header.timestamp_ms = parent.timestamp_ms;
            header.slot = parent.slot;
            reissue(parent, &mut header)
        }
        "proposal_binding" => {
            header.timestamp_ms += 1;
            resign(&mut header);
            block.ticket
        }
        "checkpoint" => {
            header.justified_checkpoint = CheckpointRef {
                epoch: 1,
                checkpoint_hash: genesis_hash,
            };
            reissue(parent, &mut header)
        }
        "execution_root" => {
            header.accounts_root = [0xC7; 32];
            reissue(parent, &mut header)
        }
        _ => unreachable!(),
    };
    (name.to_owned(), header, ticket)
}

#[test]
fn child_before_parent_revalidates_every_context_rule_and_drops_poison() {
    let producer_dir = test_dir("orphan-invalid-producer");
    let importer_dir = test_dir("orphan-invalid-importer");
    let mut producer = boot_node(&producer_dir, node_config());
    let parent = produce_full(&mut producer);
    let child = produce_full(&mut producer);
    let mut importer = boot_node(&importer_dir, node_config());
    importer.set_now(parent.header.timestamp_ms);
    let genesis_hash = importer.genesis_block_hash();
    let variants = [
        "digest",
        "target_work",
        "slot",
        "future_drift",
        "timestamp_mtp",
        "proposal_binding",
        "checkpoint",
        "execution_root",
    ];
    let mut hashes = Vec::new();
    for name in variants {
        let (_, header, ticket) = orphan_variant(name, &parent.header, &child, genesis_hash);
        let hash = *header.block_hash().expect("hash").as_bytes();
        let outcome = importer
            .import_block(&header, &ticket, &child.claim, &child.shards)
            .expect("unknown parent is inertly pooled");
        assert_eq!(outcome, ImportOutcome::Orphaned { hash });
        hashes.push(hash);
    }
    assert_eq!(importer.dag().orphan_count(), variants.len());

    import(&mut importer, &parent).expect("valid parent import");
    assert_eq!(importer.head(), (1, parent.hash));
    assert_eq!(importer.dag().len(), 2);
    assert_eq!(importer.dag().orphan_count(), 0);
    for hash in hashes {
        assert!(!importer.dag().contains(&hash));
        assert!(importer
            .port
            .get_header(&key_header(&hash))
            .expect("header lookup")
            .is_none());
    }
}

#[test]
fn valid_orphan_chain_connects_executes_and_restarts_deterministically() {
    let producer_dir = test_dir("orphan-valid-producer");
    let importer_dir = test_dir("orphan-valid-importer");
    let mut producer = boot_node(&producer_dir, node_config());
    let first = produce_full(&mut producer);
    let second = produce_full(&mut producer);
    let third = produce_full(&mut producer);
    let mut importer = boot_node(&importer_dir, node_config());
    importer.set_now(third.header.timestamp_ms);

    assert_eq!(
        import(&mut importer, &third).expect("third pooled"),
        ImportOutcome::Orphaned { hash: third.hash }
    );
    assert_eq!(
        import(&mut importer, &second).expect("second pooled"),
        ImportOutcome::Orphaned { hash: second.hash }
    );
    assert_eq!(importer.dag().orphan_count(), 2);
    assert_eq!(
        import(&mut importer, &first).expect("first promotes chain"),
        ImportOutcome::Executed { hash: first.hash }
    );
    assert_eq!(importer.head(), (3, third.hash));
    assert_eq!(importer.dag().orphan_count(), 0);
    assert_eq!(importer.ledger().roots(), producer.ledger().roots());
    let before_restart = observe(&importer);

    drop(importer);
    let restarted = boot_node(&importer_dir, node_config());
    assert_eq!(restarted.head(), before_restart.head);
    assert_eq!(restarted.ledger().roots(), before_restart.roots);
    assert_eq!(restarted.justified(), before_restart.justified);
    assert_eq!(restarted.finalized(), before_restart.finalized);
    assert_eq!(
        restarted.port.store().applied_seq(),
        before_restart.store_seq
    );
}
