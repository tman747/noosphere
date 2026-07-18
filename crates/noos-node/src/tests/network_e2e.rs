//! Two real supervisors over loopback QUIC (no mocks): identity handshake,
//! peer-ready pull sync, outbound tx gossip into the remote mempool,
//! produced-block push propagation, and identity-mismatch rejection — the
//! production `noos-p2p` edge end to end.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::sync::mpsc::sync_channel;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::consensus::{NodeConfig, NodeMode};
use crate::mempool::AdmitError;
use crate::supervisor::{self, ConsensusMsg, NodeHandle, StatusSnapshot};
use crate::view::{TxStatus, ViewLookup};
use crate::Hash32;

use super::util::*;

const DEADLINE: Duration = Duration::from_secs(120);
const MULTI_PAGE_SYNC_DEADLINE: Duration = Duration::from_secs(600);
static NETWORK_TEST_LOCK: Mutex<()> = Mutex::new(());

fn network_test_guard() -> MutexGuard<'static, ()> {
    NETWORK_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn networked_config(seed: u8, bootstrap: Vec<noos_p2p::Multiaddr>) -> NodeConfig {
    let mut cfg = node_config();
    cfg.network.enabled = true;
    cfg.network.bootstrap = bootstrap;
    cfg.network.keypair_seed = Some([seed; 32]);
    cfg
}

fn status(handle: &NodeHandle) -> StatusSnapshot {
    handle.status().expect("status")
}

fn sync_head(handle: &NodeHandle) -> (u64, Hash32) {
    let (reply, rx) = sync_channel(1);
    handle
        .consensus_tx
        .send(ConsensusMsg::SyncHead { reply })
        .expect("consensus inbox");
    rx.recv_timeout(DEADLINE)
        .expect("sync-head reply before network-test deadline")
}

fn submit(handle: &NodeHandle, tx: Vec<u8>, wit: Vec<u8>) -> Result<Hash32, AdmitError> {
    let (reply, rx) = sync_channel(1);
    handle
        .consensus_tx
        .send(ConsensusMsg::SubmitTx {
            tx_bytes: tx,
            wit_bytes: wit,
            source: 7,
            reply,
        })
        .expect("consensus inbox");
    rx.recv_timeout(DEADLINE)
        .expect("submit reply before network-test deadline")
}

fn tx_status(handle: &NodeHandle, txid: Hash32) -> ViewLookup<TxStatus> {
    let (reply, rx) = sync_channel(1);
    handle
        .consensus_tx
        .send(ConsensusMsg::GetReceipt { txid, reply })
        .expect("consensus inbox");
    match rx
        .recv_timeout(DEADLINE)
        .expect("receipt reply before network-test deadline")
    {
        ViewLookup::Found((state, _)) => ViewLookup::Found(state),
        ViewLookup::Pruned => ViewLookup::Pruned,
        ViewLookup::NotFound => ViewLookup::NotFound,
    }
}

fn wait_until<T>(what: &str, probe: impl FnMut() -> Option<T>) -> T {
    wait_until_for(what, DEADLINE, probe)
}

fn wait_until_for<T>(what: &str, deadline: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(start.elapsed() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A full life cycle over real sockets: B dials A, pull-syncs A's existing
/// block (proving the handshake), receives A's mempool tx over the push
/// lane, and imports A's next produced block from the announce push.
#[test]
fn tx_and_block_propagate_between_two_real_nodes() {
    let _network_guard = network_test_guard();
    let dir_a = test_dir("net-e2e-a");
    let dir_b = test_dir("net-e2e-b");
    let a = supervisor::start(networked_config(0xA5, Vec::new()), spec(), dir_a).expect("start a");
    let addr_a = a.p2p_addr.clone().expect("a listens");

    // Block 1 exists BEFORE B boots: B's peer-ready pull sync importing it
    // is the deterministic signal that the identity handshake completed.
    a.set_now(GENESIS_TIME_MS + 6000).expect("clock");
    let block1 = a.produce_block().expect("produce 1");

    let b =
        supervisor::start(networked_config(0xB6, vec![addr_a]), spec(), dir_b).expect("start b");
    assert!(b.p2p_addr.is_some(), "b listens too");
    let chain_id = status(&a).chain_id;
    assert_eq!(chain_id, status(&b).chain_id, "same devnet genesis");
    let synced = wait_until("peer-ready pull sync of block 1", || {
        let s = status(&b);
        (s.head_height >= 1).then_some(s.head_hash)
    });
    assert_eq!(synced, block1, "B pulled exactly A's first block");

    // Push lane: a tx admitted on A must arrive in B's mempool without any
    // block in between (both edges are handshake-ready now).
    let (tx, wit, txid) = signed_transfer(chain_id, 50, &faucet_key(), operator_account(1), 250);
    assert_eq!(submit(&a, tx, wit).expect("A admits"), txid);
    wait_until("tx relay into remote mempool", || {
        matches!(tx_status(&b, txid), ViewLookup::Found(TxStatus::Pending)).then_some(())
    });

    // Announce lane: A's next produced block is pushed to B, which fetches
    // the body from A and executes it.
    a.set_now(GENESIS_TIME_MS + 12_000).expect("clock");
    let block2 = a.produce_block().expect("produce 2");
    let imported = wait_until("block push propagation to B", || {
        let s = status(&b);
        (s.head_height >= 2).then_some(s.head_hash)
    });
    assert_eq!(imported, block2, "B executed exactly A's second block");
    assert!(
        matches!(
            tx_status(&b, txid),
            ViewLookup::Found(TxStatus::Settled { .. })
        ),
        "relayed tx settled on B via the propagated block"
    );

    b.shutdown();
    a.shutdown();
}

/// A transaction accepted while no peer is connected must not be stranded.
/// Clock ticks cyclically retry bounded pending entries after a peer appears.
#[test]
fn pending_transaction_regossips_after_peer_connects() {
    let _network_guard = network_test_guard();
    let a = supervisor::start(
        networked_config(0xC7, Vec::new()),
        spec(),
        test_dir("net-tx-regossip-a"),
    )
    .expect("start transaction source");
    let addr_a = a.p2p_addr.clone().expect("source listens");
    let chain_id = status(&a).chain_id;
    let (tx, wit, txid) = signed_transfer(chain_id, 50, &faucet_key(), operator_account(1), 251);
    assert_eq!(submit(&a, tx, wit).expect("source admits"), txid);
    assert!(matches!(
        tx_status(&a, txid),
        ViewLookup::Found(TxStatus::Pending)
    ));
    std::thread::sleep(Duration::from_millis(250));

    let b = supervisor::start(
        networked_config(0xD8, vec![addr_a]),
        spec(),
        test_dir("net-tx-regossip-b"),
    )
    .expect("start late peer");
    let mut tick = 1_u64;
    wait_until_for(
        "pending transaction re-gossip after peer connection",
        Duration::from_secs(30),
        || {
            tick = tick.saturating_add(100);
            a.set_now(GENESIS_TIME_MS.saturating_add(tick))
                .expect("clock");
            matches!(tx_status(&b, txid), ViewLookup::Found(TxStatus::Pending)).then_some(())
        },
    );

    b.shutdown();
    a.shutdown();
}

/// Three independently persisted fixture witness roles reach a real 3-of-4
/// quorum over QUIC. The producer owns only witness 0; peers B and C own
/// witnesses 1 and 2, so no single process can manufacture the certificate.
#[test]
fn three_machine_fixture_witnesses_finalize_by_gossiped_quorum() {
    let _network_guard = network_test_guard();
    let a = supervisor::start(
        networked_config(0x71, Vec::new()),
        spec(),
        test_dir("net-three-validator-a"),
    )
    .expect("start producer/witness 0");
    let addr_a = a.p2p_addr.clone().expect("producer listens");
    let b = supervisor::start(
        networked_config(0x72, vec![addr_a.clone()]),
        spec(),
        test_dir("net-three-validator-b"),
    )
    .expect("start witness 1");
    let c = supervisor::start(
        networked_config(0x73, vec![addr_a]),
        spec(),
        test_dir("net-three-validator-c"),
    )
    .expect("start witness 2");

    // Let both remote handshakes become operational before the checkpoint.
    a.set_now(GENESIS_TIME_MS + 1).expect("clock");
    a.produce_block().expect("handshake block");
    wait_until("both witness peers import the handshake block", || {
        (status(&b).head_height == 1 && status(&c).head_height == 1).then_some(())
    });

    for height in 2..=noos_braid::EPOCH_LENGTH {
        a.set_now(GENESIS_TIME_MS + height).expect("clock");
        a.produce_block().expect("checkpoint chain block");
        wait_until("both witnesses follow checkpoint chain", || {
            (status(&b).head_height == height && status(&c).head_height == height).then_some(())
        });
    }
    assert!(a.devnet_witness_vote_tick(0).expect("witness 0 vote"));
    assert!(
        a.devnet_witness_vote_tick(0)
            .expect("witness 0 vote regossip"),
        "an unfinalized durable vote must be re-gossiped"
    );
    assert!(b.devnet_witness_vote_tick(1).expect("witness 1 vote"));
    assert!(c.devnet_witness_vote_tick(2).expect("witness 2 vote"));

    wait_until(
        "producer aggregates three independently gossiped votes",
        || (status(&a).justified.epoch == 1).then_some(()),
    );
    a.set_now(GENESIS_TIME_MS + noos_braid::EPOCH_LENGTH + 1)
        .expect("clock");
    a.produce_block().expect("certificate carrying block");
    wait_until("both witnesses verify the quorum certificate", || {
        (status(&b).justified.epoch == 1 && status(&c).justified.epoch == 1).then_some(())
    });

    c.shutdown();
    b.shutdown();
    a.shutdown();
}

/// Pull sync must continue across protocol-sized range pages. This guards
/// against recovering only the first page while reporting a healthy peer.
#[test]
fn peer_ready_pull_syncs_more_than_one_range_page() {
    let _network_guard = network_test_guard();
    let dir_a = test_dir("net-e2e-range-a");
    let dir_b = test_dir("net-e2e-range-b");
    let a = supervisor::start(networked_config(0xD1, Vec::new()), spec(), dir_a).expect("start a");
    let addr_a = a.p2p_addr.clone().expect("a listens");
    let target_height = u64::from(noos_p2p::MAX_RANGE_HEADERS) * 2 + 1;
    let mut target_hash = status(&a).head_hash;
    for height in 1..=target_height {
        a.set_now(GENESIS_TIME_MS + height).expect("advance clock");
        target_hash = a.produce_block().expect("produce range-sync block");
    }

    let b =
        supervisor::start(networked_config(0xD2, vec![addr_a]), spec(), dir_b).expect("start b");
    wait_until("first pull-sync page starts", || {
        let height = status(&b).head_height;
        (height > 0 && height < target_height).then_some(())
    });
    let chain_id = status(&a).chain_id;
    let (tx, wit, txid) = signed_transfer(
        chain_id,
        target_height + 100,
        &faucet_key(),
        operator_account(1),
        250,
    );
    assert_eq!(submit(&a, tx, wit).expect("A admits during catch-up"), txid);
    wait_until("tx gossip remains live between pull-sync pages", || {
        let height = status(&b).head_height;
        (height < target_height
            && matches!(tx_status(&b, txid), ViewLookup::Found(TxStatus::Pending)))
        .then_some(())
    });
    let imported = wait_until_for(
        "multi-page peer-ready pull sync",
        MULTI_PAGE_SYNC_DEADLINE,
        || {
            let s = status(&b);
            (s.head_height == target_height).then_some(s.head_hash)
        },
    );
    assert_eq!(imported, target_hash, "B imported every range page");

    b.shutdown();
    a.shutdown();
}

#[test]
fn light_peer_syncs_more_than_one_range_page() {
    let _network_guard = network_test_guard();
    let dir_a = test_dir("net-e2e-light-range-a");
    let dir_b = test_dir("net-e2e-light-range-b");
    let a = supervisor::start(networked_config(0xE1, Vec::new()), spec(), dir_a).expect("start a");
    let addr_a = a.p2p_addr.clone().expect("a listens");
    let target_height = u64::from(noos_p2p::MAX_RANGE_HEADERS) + 1;
    let mut target_hash = status(&a).head_hash;
    for height in 1..=target_height {
        a.set_now(GENESIS_TIME_MS + height).expect("advance clock");
        target_hash = a.produce_block().expect("produce light-sync block");
    }

    let mut light = networked_config(0xE2, vec![addr_a]);
    light.mode = NodeMode::Light;
    let b = supervisor::start(light, spec(), dir_b).expect("start light b");
    let imported = wait_until("multi-page light peer pull sync", || {
        let (height, hash) = sync_head(&b);
        (height == target_height).then_some(hash)
    });
    assert_eq!(imported, target_hash, "light B imported every range page");
    assert_eq!(status(&b).head_height, 0, "light mode executes no bodies");

    b.shutdown();
    a.shutdown();
}

/// A node with a different genesis identity must be rejected at the
/// handshake and never receive chain data.
#[test]
fn identity_mismatch_is_rejected_at_handshake() {
    let _network_guard = network_test_guard();
    let dir_a = test_dir("net-e2e-id-a");
    let dir_c = test_dir("net-e2e-id-c");
    let a = supervisor::start(networked_config(0xC1, Vec::new()), spec(), dir_a).expect("start a");
    let addr_a = a.p2p_addr.clone().expect("a listens");
    a.set_now(GENESIS_TIME_MS + 6000).expect("clock");
    a.produce_block().expect("produce 1");

    // Same manifest/chain_id, different accepted account allocation. The
    // state-bound genesis_hash must make ChainIdentity reject the handshake.
    let mut foreign_spec = spec();
    foreign_spec.extra_accounts.push(([0x77; 32], 1));
    let c = supervisor::start(networked_config(0xC2, vec![addr_a]), foreign_spec, dir_c)
        .expect("start c");
    assert_eq!(
        status(&a).chain_id,
        status(&c).chain_id,
        "the parameter manifest is intentionally identical"
    );
    assert_ne!(
        status(&a).genesis_hash,
        status(&c).genesis_hash,
        "different genesis accounts must change advertised identity"
    );

    // C must never import A's chain across the rejected handshake: its head
    // stays at genesis for the whole observation window (the honest node's
    // pull sync would land within milliseconds on loopback).
    a.set_now(GENESIS_TIME_MS + 12_000).expect("clock");
    a.produce_block().expect("produce 2");
    let observed_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < observed_until {
        assert_eq!(status(&c).head_height, 0, "foreign node must stay isolated");
        std::thread::sleep(Duration::from_millis(150));
    }

    c.shutdown();
    a.shutdown();
}
