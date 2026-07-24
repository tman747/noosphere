//! Focused coverage for the live-devnet fixture finality driver.

use crate::witness_role::sign_and_release_vote;
use noos_braid::{CheckpointRef, EPOCH_LENGTH, MAX_FINALITY_CERTIFICATES};
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
fn restart_replays_durable_certificate_newer_than_full_block_evidence() {
    let dir = test_dir("devnet-finality-restart-standalone");
    let cfg = node_config();
    let mut producer = boot_node(&dir, cfg.clone());
    let certificate_count = u64::from(MAX_FINALITY_CERTIFICATES) + 1;
    let mut checkpoints = Vec::with_capacity(certificate_count as usize + 1);
    checkpoints.push(CheckpointRef {
        epoch: 0,
        checkpoint_hash: producer.genesis_block_hash(),
    });

    for epoch in 1..=certificate_count {
        let mut checkpoint_hash = [0_u8; 32];
        for _ in 0..EPOCH_LENGTH {
            checkpoint_hash = produce_next(&mut producer);
        }
        checkpoints.push(CheckpointRef {
            epoch,
            checkpoint_hash,
        });
    }

    for window in checkpoints.windows(2) {
        let certificate = quorum_certificate(&mut producer, window[0], window[1]);
        producer
            .queue_certificate(certificate)
            .expect("ingest sequential certificate");
    }
    assert_eq!(
        producer.pending_certificate_count(),
        MAX_FINALITY_CERTIFICATES as usize,
        "the newest durable certificate does not fit in the next block"
    );
    assert_eq!(producer.justified().epoch, certificate_count);

    let next = produce_full(&mut producer);
    assert_eq!(
        next.body.finality_certificates.as_slice().len(),
        MAX_FINALITY_CERTIFICATES as usize
    );
    assert_eq!(next.header.justified_checkpoint.epoch, certificate_count);
    drop(producer);

    let restarted = boot_node(&dir, cfg);
    assert_eq!(restarted.head(), (next.header.height, next.hash));
    assert_eq!(restarted.justified().epoch, certificate_count);
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
fn witness_tick_regossips_durable_historical_vote_after_restart() {
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
    drop(core);
    let mut core = boot_node(&dir, node_config());
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
        "the current vote and one durable historical recovery vote are both emitted"
    );
}

#[test]
fn witness_ticks_align_historical_regossip_after_independent_restarts() {
    let aligned_now_ms = 12_000;
    let mut historical_epochs = Vec::new();

    for witness_index in 0..3 {
        let dir = test_dir(&format!("devnet-finality-aligned-regossip-{witness_index}"));
        let mut core = boot_node(&dir, node_config());
        for _ in 0..EPOCH_LENGTH {
            produce_next(&mut core);
        }
        let chain_id = core.chain_id();
        for epoch in 2_u64..=5 {
            let source = CheckpointRef {
                epoch: epoch - 1,
                checkpoint_hash: [u8::try_from(epoch - 1).unwrap(); 32],
            };
            let target = CheckpointRef {
                epoch,
                checkpoint_hash: [u8::try_from(epoch).unwrap(); 32],
            };
            let snapshot = snapshot_for(epoch);
            sign_and_release_vote(
                &mut core.port,
                chain_id,
                epoch,
                source,
                target,
                snapshot.members()[witness_index].validator_id,
                snapshot.root(),
                &witness_secret(witness_index),
            )
            .expect("persist historical fixture vote");
        }
        drop(core);

        let mut restarted = boot_node(&dir, node_config());
        restarted.set_now(aligned_now_ms);
        let votes = restarted
            .devnet_witness_vote_tick(witness_index)
            .expect("aligned current and historical votes");
        assert_eq!(votes.len(), 2);
        historical_epochs.push(
            votes
                .iter()
                .find(|vote| vote.epoch != 1)
                .expect("historical recovery vote")
                .epoch,
        );
    }

    assert_eq!(
        historical_epochs,
        vec![5, 5, 5],
        "absolute-time slots align the same historical rung across witnesses"
    );
}

#[test]
fn aligned_historical_votes_cascade_a_lagged_producer_after_restart() {
    const RECOVERY_EPOCH: u64 = 5;

    let producer_dir = test_dir("devnet-finality-aligned-regossip-producer");
    let mut producer = boot_node(&producer_dir, node_config());
    for _ in 0..RECOVERY_EPOCH * EPOCH_LENGTH {
        produce_next(&mut producer);
    }

    let mut witnesses = Vec::new();
    for witness_index in 0..3 {
        let dir = test_dir(&format!(
            "devnet-finality-aligned-regossip-cascade-{witness_index}"
        ));
        let mut witness = boot_node(&dir, node_config());
        let mut checkpoints = vec![witness.justified()];
        for height in 1..=RECOVERY_EPOCH * EPOCH_LENGTH {
            let hash = produce_next(&mut witness);
            if height % EPOCH_LENGTH == 0 {
                checkpoints.push(CheckpointRef {
                    epoch: height / EPOCH_LENGTH,
                    checkpoint_hash: hash,
                });
            }
        }
        let chain_id = witness.chain_id();
        for epoch in 1..=RECOVERY_EPOCH {
            let snapshot = snapshot_for(epoch);
            sign_and_release_vote(
                &mut witness.port,
                chain_id,
                epoch,
                checkpoints[usize::try_from(epoch - 1).unwrap()],
                checkpoints[usize::try_from(epoch).unwrap()],
                snapshot.members()[witness_index].validator_id,
                snapshot.root(),
                &witness_secret(witness_index),
            )
            .expect("persist recovery ladder vote");
        }
        drop(witness);
        witnesses.push(boot_node(&dir, node_config()));
    }

    for tick in 0..RECOVERY_EPOCH - 1 {
        for (witness_index, witness) in witnesses.iter_mut().enumerate() {
            witness.set_now(tick * 1_000);
            for vote in witness
                .devnet_witness_vote_tick(witness_index)
                .expect("aligned recovery votes")
            {
                producer
                    .ingest_network_vote(vote)
                    .expect("lagged producer accepts recovery vote");
            }
        }
    }

    assert_eq!(producer.justified().epoch, RECOVERY_EPOCH);
    assert_eq!(producer.finalized().epoch, RECOVERY_EPOCH - 1);
    assert_eq!(producer.pending_vote_count(), 0);
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
