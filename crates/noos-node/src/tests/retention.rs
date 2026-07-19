//! Chain-view retention battery (node-v1.md §8.2): the single-pass
//! eviction law over settlement heights. This is the independent re-proof
//! of the recorded Ascent inherited defect
//! (`chain_view_small_retention_prunes_maps_and_keeps_live_state`, where a
//! TERMINAL object survived under small retention):
//!
//! * a record settled below the horizon is ALWAYS evicted (the exact arm
//!   that failed in Ascent) and stays answerable as `Pruned`;
//! * LIVE (pending) records are never evicted by retention;
//! * every per-block map is bounded by the window;
//! * `retention_blocks = 0` keeps full history (archive mode).

use crate::consensus::NodeConfig;
use crate::view::{TxStatus, ViewLookup};

use super::util::*;

#[test]
fn retention_prunes_terminal_records_and_keeps_live_state() {
    let dir = test_dir("retention");
    let mut cfg = node_config();
    cfg.view_retention_blocks = 4;
    let mut core = boot_node(&dir, cfg);
    let chain_id = core.chain_id();

    // A transfer settled in block 1 — TERMINAL once below the horizon.
    let (tx1, wit1, txid1) = signed_transfer(chain_id, 40, &faucet_key(), operator_account(1), 100);
    core.submit_tx(&tx1, &wit1, 7).expect("admit settled tx");
    let block1 = produce_next(&mut core);
    assert_eq!(
        core.tx_status(&txid1),
        ViewLookup::Found(TxStatus::Settled {
            height: 1,
            status: 0
        })
    );

    // Advance far past the window (tip 12, horizon = 12 - 4 = 8).
    for _ in 0..11 {
        produce_next(&mut core);
    }
    assert_eq!(core.head().0, 12);

    // TERMINAL eviction arm: the settled record left every map and is
    // answerable as Pruned — never a silent NotFound.
    assert_eq!(core.tx_status(&txid1), ViewLookup::Pruned);
    assert!(matches!(core.view.block_by_height(1), ViewLookup::Pruned));
    assert!(matches!(
        core.view.block_by_hash(&block1),
        ViewLookup::Pruned
    ));

    // An identity that never existed is still NotFound, not Pruned.
    assert_eq!(core.tx_status(&[0xEE; 32]), ViewLookup::NotFound);
    assert!(matches!(
        core.view.block_by_hash(&[0xEE; 32]),
        ViewLookup::NotFound
    ));

    // Blocks inside the window remain fully served.
    match core.view.block_by_height(12) {
        ViewLookup::Found(b) => assert_eq!(b.height, 12),
        other => panic!("live tip missing: {other:?}"),
    }
    assert!(matches!(core.view.block_by_height(9), ViewLookup::Found(_)));

    // The per-block map is bounded by the window.
    assert!(
        core.view.block_count() <= 5,
        "blocks map exceeded the retention window: {}",
        core.view.block_count()
    );

    // LIVE record: a pending (mempool) transaction survives retention.
    let (tx2, wit2, txid2) = signed_transfer(chain_id, 40, &faucet_key(), operator_account(2), 200);
    core.submit_tx(&tx2, &wit2, 7).expect("admit pending tx");
    assert_eq!(core.tx_status(&txid2), ViewLookup::Found(TxStatus::Pending));
    // More production: the pending record settles (and the view keeps its
    // exact settlement), while the retention law keeps pruning terminals.
    produce_next(&mut core);
    assert_eq!(
        core.tx_status(&txid2),
        ViewLookup::Found(TxStatus::Settled {
            height: 13,
            status: 0
        })
    );

    // Restart replays through the same retention law: the recovered view
    // is identically bounded and identically answerable.
    drop(core);
    let mut cfg = node_config();
    cfg.view_retention_blocks = 4;
    let restarted = boot_node(&dir, cfg);
    assert_eq!(restarted.tx_status(&txid1), ViewLookup::Pruned);
    assert_eq!(
        restarted.tx_status(&txid2),
        ViewLookup::Found(TxStatus::Settled {
            height: 13,
            status: 0
        })
    );
    assert!(restarted.view.block_count() <= 5);
}

#[test]
fn archive_mode_keeps_full_presentation_history() {
    let dir = test_dir("retention-archive");
    let cfg = NodeConfig {
        view_retention_blocks: 0,
        ..node_config()
    };
    let mut core = boot_node(&dir, cfg);
    let chain_id = core.chain_id();
    let (tx, wit, txid) = signed_transfer(chain_id, 40, &faucet_key(), operator_account(1), 100);
    core.submit_tx(&tx, &wit, 7).expect("admit");
    let block1 = produce_next(&mut core);
    for _ in 0..12 {
        produce_next(&mut core);
    }
    // Nothing is ever pruned in archive mode.
    assert_eq!(
        core.tx_status(&txid),
        ViewLookup::Found(TxStatus::Settled {
            height: 1,
            status: 0
        })
    );
    assert!(matches!(core.view.block_by_height(1), ViewLookup::Found(_)));
    assert!(matches!(
        core.view.block_by_hash(&block1),
        ViewLookup::Found(_)
    ));
    assert_eq!(core.view.pruned_before_height(), 0);
    assert_eq!(core.view.block_count(), 13, "all 13 blocks retained");
}
