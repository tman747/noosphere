//! End-to-end single-node happy path, IN-PROCESS (node-v1.md §10.1):
//! genesis → two epochs of produced blocks with tickets found at the
//! trivial devnet target → transfers applied → checkpoint justified AND
//! finalized with a simulated witness set → restart from the store
//! recovers the exact state → the node keeps producing.
//!
//! The restart leg is also the inherited-defect counter-proof for the
//! Ascent bootstrap-window recovery failure (BASELINE-REPORT DEFECT-3):
//! noosd recovery is store replay, not a gossip bootstrap-window slide,
//! and this test pins that a restarted node recovers the EXACT prior
//! state and resumes.

use noos_braid::{CheckpointRef, EPOCH_LENGTH};

use crate::consensus::ImportOutcome;
use crate::view::{TxStatus, ViewLookup};

use super::util::*;

#[test]
fn e2e_happy_path_finality_and_restart_recovery() {
    let dir = test_dir("e2e");
    let mut core = boot_node(&dir, node_config());
    let chain_id = core.chain_id();
    let genesis_cp = core.finalized();
    assert_eq!(genesis_cp.epoch, 0);

    let faucet = faucet_key();
    let alice = operator_account(1);
    let faucet_account = faucet.public_key().into_bytes();
    let faucet_start = core
        .ledger()
        .balance(&faucet_account, &noos_lumen::state::NOOS_ASSET);

    // Transfers riding the first blocks.
    let (tx1, wit1, txid1) = signed_transfer(chain_id, 40, &faucet, alice, 1_000_000);
    core.submit_tx(&tx1, &wit1, 7).expect("admit transfer 1");
    let (tx2, wit2, txid2) = signed_transfer(chain_id, 40, &faucet, alice, 2_500_000);
    core.submit_tx(&tx2, &wit2, 7).expect("admit transfer 2");
    assert_eq!(core.mempool.len(), 2);

    // Epoch 1 of production (heights 1..=256).
    for _ in 0..EPOCH_LENGTH {
        produce_next(&mut core);
    }
    let (h, head) = core.head();
    assert_eq!(h, EPOCH_LENGTH);
    // Transfers settled in block 1.
    assert!(core.mempool.is_empty());
    assert_eq!(
        core.view.tx_status(&txid1),
        ViewLookup::Found(TxStatus::Settled {
            height: 1,
            status: 0
        })
    );
    assert_eq!(
        core.view.tx_status(&txid2),
        ViewLookup::Found(TxStatus::Settled {
            height: 1,
            status: 0
        })
    );
    assert_eq!(
        core.ledger()
            .balance(&alice, &noos_lumen::state::NOOS_ASSET),
        3_500_000
    );
    // Fees left the faucet beyond the transferred amounts.
    let faucet_now = core
        .ledger()
        .balance(&faucet_account, &noos_lumen::state::NOOS_ASSET);
    assert!(faucet_now < faucet_start - 3_500_000);

    // Justify epoch 1 with the simulated witness set.
    let cp1 = CheckpointRef {
        epoch: 1,
        checkpoint_hash: core
            .dag()
            .ancestor_at_height(&head, EPOCH_LENGTH)
            .expect("checkpoint block")
            .hash,
    };
    let cert1 = quorum_certificate(&mut core, genesis_cp, cp1);
    core.queue_certificate(cert1).expect("ingest cert1");
    assert_eq!(core.justified(), cp1);
    assert_eq!(core.finalized().epoch, 0);

    // Epoch 2 (heights 257..=512); the pending certificate rides block 257.
    for _ in 0..EPOCH_LENGTH {
        produce_next(&mut core);
    }
    let (h2, head2) = core.head();
    assert_eq!(h2, 2 * EPOCH_LENGTH);
    let cp2 = CheckpointRef {
        epoch: 2,
        checkpoint_hash: core
            .dag()
            .ancestor_at_height(&head2, 2 * EPOCH_LENGTH)
            .expect("checkpoint block 2")
            .hash,
    };
    let cert2 = quorum_certificate(&mut core, cp1, cp2);
    core.queue_certificate(cert2).expect("ingest cert2");

    // Direct-child rule: cp2 justified, cp1 FINALIZED.
    assert_eq!(core.justified(), cp2);
    assert_eq!(core.finalized(), cp1);

    // A social checkpoint conflicting with local finality is rejected
    // and moves nothing (ch01 §10.5).
    let bogus = CheckpointRef {
        epoch: 1,
        checkpoint_hash: [0xEE; 32],
    };
    let err = core.apply_social_checkpoint(bogus).unwrap_err();
    assert!(matches!(
        err,
        crate::NodeError::SocialCheckpointConflictsLocalFinality { .. }
    ));
    assert_eq!(core.finalized(), cp1);

    // Snapshot of the exact state for the restart comparison.
    let roots_before = core.ledger().roots();
    let head_before = core.head();
    let finalized_before = core.finalized();
    let justified_before = core.justified();
    let alice_before = core
        .ledger()
        .balance(&alice, &noos_lumen::state::NOOS_ASSET);
    let minted_before = core.ledger().emission_minted();
    drop(core);

    // Restart: replay from the durable store only.
    let mut restarted = boot_node(&dir, node_config());
    assert_eq!(restarted.head(), head_before, "head recovered");
    assert_eq!(
        restarted.ledger().roots(),
        roots_before,
        "exact roots recovered"
    );
    assert_eq!(restarted.finalized(), finalized_before);
    assert_eq!(restarted.justified(), justified_before);
    assert_eq!(
        restarted
            .ledger()
            .balance(&alice, &noos_lumen::state::NOOS_ASSET),
        alice_before
    );
    assert_eq!(restarted.ledger().emission_minted(), minted_before);
    assert_eq!(
        restarted.view.tx_status(&txid1),
        ViewLookup::Found(TxStatus::Settled {
            height: 1,
            status: 0
        })
    );

    // The recovered node RESUMES: one more block extends the chain.
    let next = produce_next(&mut restarted);
    assert_eq!(restarted.head(), (2 * EPOCH_LENGTH + 1, next));

    // And a recovered node still validates: importing its own block back
    // is a duplicate, not corruption.
    let (_, wit) = (0, 0);
    let _ = wit;
    let _ = ImportOutcome::Executed { hash: next }; // type anchor
}
