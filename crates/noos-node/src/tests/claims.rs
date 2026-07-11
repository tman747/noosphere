//! Claim-cluster precursors over the real NodeCore and production P2P wire.

use std::sync::Arc;

use noos_braid::{KeylessConsensus, KeylessError, WorkloadKeyCustody, EPOCH_LENGTH};
use noos_ground::GroundError;
use noos_p2p::{message_digest, Delivery, DropReason, Protocol, WanCase};

use crate::consensus::{ImportOutcome, NodeConfig, NodeCore, NodeMode, ProducedBlock};
use crate::genesis::GenesisSpec;
use crate::metrics::Metrics;
use crate::network::{decode_header_announce, encode_header_announce};
use crate::store_port::InProcStore;
use crate::NodeError;

use super::util::*;

fn boot_with_spec(tag: &str, cfg: NodeConfig, spec: &GenesisSpec) -> NodeCore<InProcStore> {
    let dir = test_dir(tag);
    let built = spec.build().expect("genesis build");
    let port = InProcStore::open(dir, &built.chain_id, &built.genesis_hash).expect("store open");
    NodeCore::boot(cfg, spec, built, port, Arc::new(Metrics::default())).expect("node boot")
}

fn import_over_production_wire(
    core: &mut NodeCore<InProcStore>,
    block: &ProducedBlock,
    shards: &[noos_da::ShardCandidateV1],
    arrival_ms: u64,
) -> Result<ImportOutcome, NodeError> {
    let payload = encode_header_announce(&block.header, &block.ticket);
    let digest = message_digest(Protocol::BraidHeader, &payload);
    assert_ne!(digest, [0; 32], "production P2P digest must be bound");
    let (header, ticket) = decode_header_announce(&payload).expect("production wire decode");
    assert_eq!(header, block.header);
    assert_eq!(ticket, block.ticket);
    core.set_now(arrival_ms);
    core.import_block(&header, &ticket, &block.claim, shards)
}

#[test]
fn claim_e_base_unknown_fields_fail_closed_on_the_production_wire() {
    let dir = test_dir("claim-unknown-producer");
    let mut producer = boot_node(&dir, node_config());
    let block = produce_full(&mut producer);
    let mut payload = encode_header_announce(&block.header, &block.ticket);
    // version:u16 is followed by mandatory field tag 1.  Replacing that tag
    // with an unknown mandatory field must die in the ordinary wire decoder.
    payload[2..4].copy_from_slice(&0x7FFF_u16.to_le_bytes());
    assert!(decode_header_announce(&payload).is_err());
}

#[test]
fn claim_e_blackout_all_optional_controls_off_keeps_base_live() {
    let spec = spec();
    assert_eq!(
        spec.manifest().controls_bits,
        0,
        "every optional lane is disabled"
    );
    let mut cfg = node_config();
    cfg.devnet_fixture_finality = true;
    let mut core = boot_with_spec("claim-blackout", cfg, &spec);
    let chain_id = core.chain_id();
    let alice = operator_account(1);
    let mut submitted = 0_u128;
    let workload = [0x4B; 32];
    let mut key_policy = KeylessConsensus::default();
    key_policy
        .set_custody(
            workload,
            WorkloadKeyCustody::Threshold {
                key_epoch: 0,
                active_from_epoch: 0,
                expires_after_epoch: 0,
                threshold: 2,
                members: [[1; 32], [2; 32], [3; 32]].into_iter().collect(),
            },
        )
        .expect("initial narrow key epoch");
    assert!(key_policy
        .authorize(workload, 0, 0, &[[1; 32], [2; 32]])
        .is_ok());

    // Three epochs plus one block makes the first two epoch boundaries old
    // enough to be eligible under the one-epoch FFG finality lag.
    for height in 1..=(3 * EPOCH_LENGTH + 1) {
        if height == 1 || height == EPOCH_LENGTH + 1 || height == 2 * EPOCH_LENGTH + 1 {
            let amount = u128::from(height);
            let (tx, witness, _) = signed_transfer(
                chain_id,
                height + EPOCH_LENGTH,
                &faucet_key(),
                alice,
                amount,
            );
            core.submit_tx(&tx, &witness, 7)
                .expect("ordinary transfer admission");
            submitted = submitted.saturating_add(amount);
        }
        core.set_now(GENESIS_TIME_MS + height * 6_000);
        core.produce_block()
            .expect("base block production with lanes off");
        if height % EPOCH_LENGTH == 0 {
            assert!(core.devnet_finality_tick().expect("fixture finality"));
        }
        if height == EPOCH_LENGTH + 1 {
            assert_eq!(
                key_policy.authorize(workload, 0, 1, &[[1; 32], [2; 32]]),
                Err(KeylessError::Expired)
            );
            key_policy
                .set_custody(
                    workload,
                    WorkloadKeyCustody::Threshold {
                        key_epoch: 1,
                        active_from_epoch: 1,
                        expires_after_epoch: 2,
                        threshold: 2,
                        members: [[4; 32], [5; 32], [6; 32]].into_iter().collect(),
                    },
                )
                .expect("rotate narrow key epoch while base continues");
            assert!(key_policy
                .authorize(workload, 1, 1, &[[4; 32], [5; 32]])
                .is_ok());
        }
    }

    assert_eq!(core.finalized().epoch, 2);
    assert_eq!(
        core.ledger()
            .balance(&alice, &noos_lumen::state::NOOS_ASSET),
        submitted,
        "ordinary Lumen transfers settle with every optional lane off"
    );
    let eligible_height = core.head().0.saturating_sub(EPOCH_LENGTH + 1);
    let finalized_height = core.finalized().epoch.saturating_mul(EPOCH_LENGTH);
    assert!(
        finalized_height >= eligible_height,
        "all eligible base blocks finalized"
    );
}

#[test]
fn claim_e_wan_drift_sweep_selects_smallest_passing_genesis_value() {
    let mut passing = Vec::new();
    for drift in [12_000_u64, 18_000, 30_000] {
        let mut candidate = spec();
        candidate.params.max_future_drift_ms = drift;
        let mut producer = boot_with_spec(
            &format!("claim-drift-{drift}-producer"),
            node_config(),
            &candidate,
        );
        let block = produce_full(&mut producer);

        let mut light_cfg = node_config();
        light_cfg.mode = NodeMode::Light;
        let mut at_limit = boot_with_spec(
            &format!("claim-drift-{drift}-limit"),
            light_cfg.clone(),
            &candidate,
        );
        at_limit.set_now(block.header.timestamp_ms - drift);
        assert!(matches!(
            at_limit.import_header_light(&block.header, &block.ticket),
            Ok(ImportOutcome::HeaderAccepted { .. })
        ));

        let mut beyond = boot_with_spec(
            &format!("claim-drift-{drift}-beyond"),
            light_cfg,
            &candidate,
        );
        beyond.set_now(block.header.timestamp_ms - drift - 1);
        assert!(matches!(
            beyond.import_header_light(&block.header, &block.ticket),
            Err(NodeError::Ground(
                GroundError::TimestampTooFarInFuture { .. }
            ))
        ));
        passing.push(drift);
    }
    assert_eq!(passing.into_iter().min(), Some(12_000));
}

#[test]
fn claim_e_wan_partition_eclipse_da_withholding_heal_without_conflicting_finality() {
    let spec = spec();
    let mut cfg = node_config();
    cfg.witness_bonds = witness_bonds(10);
    cfg.devnet_fixture_finality = true;
    let mut producer = boot_with_spec("claim-wan-producer", cfg.clone(), &spec);
    let mut majority = boot_with_spec("claim-wan-majority", cfg.clone(), &spec);
    let mut eclipsed = boot_with_spec("claim-wan-eclipsed", cfg.clone(), &spec);
    let mut minority = boot_with_spec("claim-wan-minority", cfg, &spec);

    let chain_id = producer.chain_id();
    let (tx, witness, txid) =
        signed_transfer(chain_id, 100, &faucet_key(), operator_account(2), 999);
    producer
        .submit_tx(&tx, &witness, 8)
        .expect("WAN transfer admission");

    let mut blocks = Vec::new();
    for height in 1..=(2 * EPOCH_LENGTH + 1) {
        producer.set_now(GENESIS_TIME_MS + height * 6_000);
        blocks.push(producer.produce_block().expect("WAN producer block"));
        if height % EPOCH_LENGTH == 0 {
            assert!(producer
                .devnet_finality_tick()
                .expect("WAN fixture finality"));
        }
    }

    let mut case = WanCase::from_seed(42, 15);
    case.crashed_validator = 9;
    case.eclipsed_region = 2;
    case.minority_region = 3;
    case.loss_permille = 0;
    let fault_start = 32_u64;
    let fault_end = 64_u64;
    let mut majority_parked: Option<usize> = None;
    let mut majority_backlog = Vec::new();
    let mut eclipse_backlog = Vec::new();
    let mut minority_backlog = Vec::new();

    for (index, block) in blocks.iter().enumerate() {
        let height = block.header.height;
        let active = (fault_start..=fault_end).contains(&height);
        let now = block.header.timestamp_ms;
        if active {
            let header_route = case.route(
                Protocol::BraidHeader,
                height,
                height as usize % 10,
                0,
                1,
                now,
                true,
            );
            let shard_route = case.route(
                Protocol::BlobShard,
                height,
                height as usize % 10,
                0,
                1,
                now,
                true,
            );
            if majority_parked.is_none()
                && majority_backlog.is_empty()
                && matches!(header_route, Delivery::DeliverAtMs(_))
                && shard_route == Delivery::Drop(DropReason::DaWithholding)
            {
                let outcome = import_over_production_wire(&mut majority, block, &[], now)
                    .expect("unavailable block parks");
                assert_eq!(
                    outcome,
                    ImportOutcome::ParkedAwaitingBody { hash: block.hash }
                );
                assert_eq!(
                    majority.finalized().epoch,
                    0,
                    "unavailable block never finalizes"
                );
                majority_parked = Some(index);
            } else {
                majority_backlog.push(index);
            }
            assert_eq!(
                case.route(Protocol::BraidHeader, height, 0, 0, 2, now, true),
                Delivery::Drop(DropReason::RegionalEclipse)
            );
            eclipse_backlog.push(index);
            assert_eq!(
                case.route(Protocol::BraidHeader, height, 0, 0, 3, now, true),
                Delivery::Drop(DropReason::Partition)
            );
            minority_backlog.push(index);
            continue;
        }

        if height == fault_end + 1 {
            if let Some(parked_index) = majority_parked.take() {
                let parked = &blocks[parked_index];
                majority.set_now(now);
                let resumed = majority
                    .feed_shards(&parked.hash, &parked.shards)
                    .expect("late DA shards accepted");
                assert!(matches!(resumed, Some(ImportOutcome::Executed { .. })));
            }
            for repair in majority_backlog.drain(..) {
                let block = &blocks[repair];
                import_over_production_wire(&mut majority, block, &block.shards, now)
                    .expect("majority targeted repair");
            }
            for repair in eclipse_backlog.drain(..) {
                let block = &blocks[repair];
                import_over_production_wire(&mut eclipsed, block, &block.shards, now)
                    .expect("eclipse targeted repair");
            }
            for repair in minority_backlog.drain(..) {
                let block = &blocks[repair];
                import_over_production_wire(&mut minority, block, &block.shards, now)
                    .expect("partition targeted repair");
            }
        }

        for replica in [&mut majority, &mut eclipsed, &mut minority] {
            import_over_production_wire(replica, block, &block.shards, now)
                .expect("healed WAN delivery");
        }
    }

    assert!(majority_backlog.is_empty());
    assert!(eclipse_backlog.is_empty());
    assert!(minority_backlog.is_empty());
    for replica in [&majority, &eclipsed, &minority] {
        assert_eq!(replica.head(), producer.head());
        assert_eq!(replica.ledger().roots(), producer.ledger().roots());
        assert_eq!(replica.finalized(), producer.finalized());
        assert_eq!(replica.finalized().epoch, 1);
        assert!(replica.ledger().get_receipt(&txid).is_some());
    }
    // All three faulted views converge on the sole finalized checkpoint:
    // conflicting-finality count is therefore exactly zero.
    assert_eq!(majority.finalized(), eclipsed.finalized());
    assert_eq!(majority.finalized(), minority.finalized());
    assert!(2 * EPOCH_LENGTH - fault_end <= 2 * EPOCH_LENGTH);
}
