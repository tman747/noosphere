//! Focused coverage for the live-devnet fixture finality driver.

use noos_braid::{CheckpointRef, EPOCH_LENGTH};
use noos_witness::vote::FinalityVoteV1;

use super::util::*;

#[test]
fn devnet_finality_tick_advances_two_epoch_ladder_only_when_enabled() {
    let enabled_dir = test_dir("devnet-finality-enabled");
    let mut enabled_cfg = node_config();
    enabled_cfg.devnet_fixture_finality = true;
    let mut enabled = boot_node(&enabled_dir, enabled_cfg);

    for _ in 0..2 * EPOCH_LENGTH {
        produce_next(&mut enabled);
    }

    assert!(enabled.devnet_finality_tick().expect("justify epoch 1"));
    assert_eq!(enabled.justified().epoch, 1);
    assert_eq!(enabled.finalized().epoch, 0);

    assert!(enabled.devnet_finality_tick().expect("justify epoch 2"));
    assert_eq!(enabled.justified().epoch, 2);
    assert_eq!(enabled.finalized().epoch, 1);
    assert!(!enabled
        .devnet_finality_tick()
        .expect("epoch 3 boundary is not available"));

    let disabled_dir = test_dir("devnet-finality-disabled");
    let mut disabled = boot_node(&disabled_dir, node_config());
    for _ in 0..2 * EPOCH_LENGTH {
        produce_next(&mut disabled);
    }
    let justified_before = disabled.justified();
    let finalized_before = disabled.finalized();

    assert!(!disabled
        .devnet_finality_tick()
        .expect("disabled fixture finality is inert"));
    assert_eq!(disabled.justified(), justified_before);
    assert_eq!(disabled.finalized(), finalized_before);
}

#[test]
fn authenticated_future_source_votes_retry_after_justification_advances() {
    let dir = test_dir("devnet-finality-deferred-votes");
    let mut core = boot_node(&dir, node_config());
    let mut epoch_one_hash = None;
    let mut epoch_two_hash = None;
    for height in 1..=2 * EPOCH_LENGTH {
        let hash = produce_next(&mut core);
        if height == EPOCH_LENGTH {
            epoch_one_hash = Some(hash);
        } else if height == 2 * EPOCH_LENGTH {
            epoch_two_hash = Some(hash);
        }
    }

    let genesis = core.justified();
    let epoch_one = CheckpointRef {
        epoch: 1,
        checkpoint_hash: epoch_one_hash.expect("epoch one checkpoint"),
    };
    let epoch_two = CheckpointRef {
        epoch: 2,
        checkpoint_hash: epoch_two_hash.expect("epoch two checkpoint"),
    };
    let chain_id = core.chain_id();
    let votes = |source: CheckpointRef, target: CheckpointRef| {
        let snapshot = snapshot_for(target.epoch);
        (0..3)
            .map(|index| {
                FinalityVoteV1::sign(
                    chain_id,
                    target.epoch,
                    source,
                    target,
                    snapshot.members()[index].validator_id,
                    snapshot.root(),
                    &witness_secret(index),
                )
                .expect("fixture vote")
            })
            .collect::<Vec<_>>()
    };

    for vote in votes(epoch_one, epoch_two) {
        core.ingest_network_vote(vote)
            .expect("authenticated future vote is deferred");
    }
    assert_eq!(core.justified(), genesis);
    assert_eq!(core.pending_vote_count(), 3);

    for vote in votes(genesis, epoch_one) {
        core.ingest_network_vote(vote)
            .expect("source quorum advances and retries deferred votes");
    }
    assert_eq!(core.justified(), epoch_two);
    assert_eq!(core.finalized(), epoch_one);
    assert_eq!(core.pending_vote_count(), 0);
}

#[test]
fn witness_tick_regossips_historical_vote_after_local_finality_advances() {
    let dir = test_dir("devnet-finality-historical-regossip");
    let mut core = boot_node(&dir, node_config());
    let mut epoch_one_hash = None;
    for height in 1..=2 * EPOCH_LENGTH {
        let hash = produce_next(&mut core);
        if height == EPOCH_LENGTH {
            epoch_one_hash = Some(hash);
        }
    }

    let genesis = core.justified();
    let epoch_one = CheckpointRef {
        epoch: 1,
        checkpoint_hash: epoch_one_hash.expect("epoch one checkpoint"),
    };
    let first = core
        .devnet_witness_vote_tick(0)
        .expect("witness zero epoch one vote");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].target, epoch_one);

    let snapshot = snapshot_for(1);
    for index in 1..3 {
        let vote = FinalityVoteV1::sign(
            core.chain_id(),
            1,
            genesis,
            epoch_one,
            snapshot.members()[index].validator_id,
            snapshot.root(),
            &witness_secret(index),
        )
        .expect("remote fixture vote");
        core.ingest_network_vote(vote).expect("remote quorum vote");
    }
    assert_eq!(core.justified(), epoch_one);

    let mut outbound_epochs = core
        .devnet_witness_vote_tick(0)
        .expect("current and historical witness votes")
        .into_iter()
        .map(|vote| vote.epoch)
        .collect::<Vec<_>>();
    outbound_epochs.sort_unstable();
    assert_eq!(
        outbound_epochs,
        vec![1, 2],
        "the current vote and one bounded historical recovery vote are both emitted"
    );
}

#[test]
fn restart_reembeds_certificate_queued_after_epoch_boundary() {
    let dir = test_dir("devnet-finality-restart-pending");
    let mut cfg = node_config();
    cfg.devnet_fixture_finality = true;
    let mut producer = boot_node(&dir, cfg.clone());
    for _ in 0..EPOCH_LENGTH {
        produce_next(&mut producer);
    }
    assert!(producer
        .devnet_finality_tick()
        .expect("queue epoch-1 certificate"));
    assert_eq!(producer.justified().epoch, 1);
    drop(producer);

    let mut restarted = boot_node(&dir, cfg);
    assert_eq!(restarted.justified().epoch, 1);
    let next = produce_full(&mut restarted);
    assert_eq!(
        next.body.finality_certificates.as_slice().len(),
        1,
        "first post-restart body re-embeds the durable pending certificate"
    );
    assert_eq!(
        next.body.finality_certificates.as_slice()[0].target.epoch,
        1
    );
}
