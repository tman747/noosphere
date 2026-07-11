//! Loopback integration matrix (plan §7.4 acceptance): two in-process nodes
//! over 127.0.0.1 QUIC exercising the identity handshake in both directions,
//! all eight protocols, the oversize-frame law, rate-limit trips, duplicate
//! suppression, priority ordering under load, and closed-list negotiation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use noos_p2p::{
    write_raw_declared, BodyReplyV1, ChainIdentity, HeaderReplyV1, InboundItem, P2pConfig,
    P2pEvent, P2pHandle, P2pNode, PeerId, ProtocolStore, PushReplyV1, RejectCode, SendError,
    ShardReplyV1, SnapshotReplyV1, Violation,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(30);

fn chain_a() -> ChainIdentity {
    ChainIdentity {
        chain_id: [0xA1; 32],
        genesis_hash: [0xA2; 32],
        protocol_version: 1,
    }
}

fn chain_wrong() -> ChainIdentity {
    ChainIdentity {
        chain_id: [0xB1; 32],
        genesis_hash: [0xB2; 32],
        protocol_version: 1,
    }
}

#[derive(Default)]
struct MemStore {
    headers: HashMap<[u8; 32], Vec<u8>>,
    bodies: HashMap<[u8; 32], Vec<u8>>,
    range: Vec<Vec<u8>>,
    chunks: HashMap<([u8; 32], u32), (u32, Vec<u8>)>,
    shards: HashMap<([u8; 32], u32), Vec<u8>>,
}

impl ProtocolStore for MemStore {
    fn header(&self, header_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.headers.get(header_hash).cloned()
    }
    fn body(&self, block_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.bodies.get(block_hash).cloned()
    }
    fn header_range(&self, start_height: u64, max_headers: u32) -> (Vec<Vec<u8>>, bool) {
        let start = usize::try_from(start_height).unwrap_or(usize::MAX);
        if start >= self.range.len() {
            return (Vec::new(), false);
        }
        let end = start
            .saturating_add(max_headers as usize)
            .min(self.range.len());
        (self.range[start..end].to_vec(), end < self.range.len())
    }
    fn snapshot_chunk(&self, snapshot_root: &[u8; 32], chunk_index: u32) -> Option<(u32, Vec<u8>)> {
        self.chunks.get(&(*snapshot_root, chunk_index)).cloned()
    }
    fn shard(&self, content_root: &[u8; 32], shard_index: u32) -> Option<Vec<u8>> {
        self.shards.get(&(*content_root, shard_index)).cloned()
    }
}

fn spawn(
    seed: u8,
    identity: ChainIdentity,
    store: MemStore,
    tweak: impl FnOnce(&mut P2pConfig),
) -> (P2pHandle, mpsc::UnboundedReceiver<P2pEvent>) {
    let mut config = P2pConfig::loopback(identity, [seed; 32]);
    tweak(&mut config);
    P2pNode::spawn(config, Arc::new(store)).expect("spawn")
}

async fn wait_for(
    rx: &mut mpsc::UnboundedReceiver<P2pEvent>,
    what: &str,
    pred: impl Fn(&P2pEvent) -> bool,
) -> P2pEvent {
    timeout(WAIT, async {
        loop {
            match rx.recv().await {
                Some(ev) if pred(&ev) => return ev,
                Some(_) => {}
                None => panic!("event channel closed waiting for {what}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {what}"))
}

/// Dials `b` from `a` and waits for both PeerReady events.
async fn connect_ready(
    a: &P2pHandle,
    a_rx: &mut mpsc::UnboundedReceiver<P2pEvent>,
    b: &P2pHandle,
    b_rx: &mut mpsc::UnboundedReceiver<P2pEvent>,
) {
    let addr = b.listen_addr().await;
    a.connect(addr);
    wait_for(a_rx, "a PeerReady", |e| {
        matches!(e, P2pEvent::PeerReady { .. })
    })
    .await;
    wait_for(b_rx, "b PeerReady", |e| {
        matches!(e, P2pEvent::PeerReady { .. })
    })
    .await;
}

// ---------------------------------------------------------------------------
// Identity handshake
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn handshake_accepts_matching_chain_and_binds_attestation() {
    let (a, mut a_rx) = spawn(1, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(2, chain_a(), MemStore::default(), |_| {});

    let addr = b.listen_addr().await;
    a.connect(addr);

    let ev = wait_for(&mut a_rx, "a PeerReady", |e| {
        matches!(e, P2pEvent::PeerReady { .. })
    })
    .await;
    let P2pEvent::PeerReady { peer, attestation } = ev else {
        unreachable!()
    };
    assert_eq!(peer, b.local_peer_id());
    assert_eq!(attestation.chain_id, chain_a().chain_id);
    assert_eq!(attestation.genesis_hash, chain_a().genesis_hash);
    assert_eq!(attestation.protocol_version, 1);

    let ev = wait_for(&mut b_rx, "b PeerReady", |e| {
        matches!(e, P2pEvent::PeerReady { .. })
    })
    .await;
    let P2pEvent::PeerReady { peer, .. } = ev else {
        unreachable!()
    };
    assert_eq!(peer, a.local_peer_id());
}

async fn assert_wrong_chain_rejects(
    dialer: &P2pHandle,
    dialer_rx: &mut mpsc::UnboundedReceiver<P2pEvent>,
    listener: &P2pHandle,
    listener_rx: &mut mpsc::UnboundedReceiver<P2pEvent>,
) {
    let addr = listener.listen_addr().await;
    dialer.connect(addr);

    let ev = wait_for(dialer_rx, "dialer HandshakeRejected", |e| {
        matches!(e, P2pEvent::HandshakeRejected { .. })
    })
    .await;
    let P2pEvent::HandshakeRejected { peer, code, .. } = ev else {
        unreachable!()
    };
    assert_eq!(peer, listener.local_peer_id());
    assert_eq!(code, RejectCode::WrongProtocolIdentity);

    let ev = wait_for(listener_rx, "listener HandshakeRejected", |e| {
        matches!(e, P2pEvent::HandshakeRejected { .. })
    })
    .await;
    let P2pEvent::HandshakeRejected { peer, code, .. } = ev else {
        unreachable!()
    };
    assert_eq!(peer, dialer.local_peer_id());
    assert_eq!(code, RejectCode::WrongProtocolIdentity);

    // No protocol traffic is possible in either direction.
    let err = dialer
        .push_tx(listener.local_peer_id(), vec![1, 2, 3])
        .await
        .expect_err("rejected peer must not accept traffic");
    assert_eq!(err, SendError::PeerRejected);
    let err = listener
        .push_tx(dialer.local_peer_id(), vec![1, 2, 3])
        .await
        .expect_err("rejected peer must not accept traffic");
    assert_eq!(err, SendError::PeerRejected);
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_rejects_wrong_chain_when_wrong_node_dials() {
    let (good, mut good_rx) = spawn(3, chain_a(), MemStore::default(), |_| {});
    let (wrong, mut wrong_rx) = spawn(4, chain_wrong(), MemStore::default(), |_| {});
    // Direction 1: the mismatched node dials us.
    assert_wrong_chain_rejects(&wrong, &mut wrong_rx, &good, &mut good_rx).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_rejects_wrong_chain_when_we_dial_wrong_node() {
    let (good, mut good_rx) = spawn(5, chain_a(), MemStore::default(), |_| {});
    let (wrong, mut wrong_rx) = spawn(6, chain_wrong(), MemStore::default(), |_| {});
    // Direction 2: we dial a mismatched listener.
    assert_wrong_chain_rejects(&good, &mut good_rx, &wrong, &mut wrong_rx).await;
}

// ---------------------------------------------------------------------------
// Eight-protocol round trip
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn all_eight_protocols_round_trip_one_canonical_message() {
    let header_hash = [0x11; 32];

    let mut store = MemStore::default();
    let header = b"header-wire-object".to_vec();
    let body = b"body-wire-object".to_vec();
    store.headers.insert(header_hash, header.clone());
    store.bodies.insert([0x22; 32], body.clone());
    store.range = vec![b"h0".to_vec(), b"h1".to_vec(), b"h2".to_vec()];
    store
        .chunks
        .insert(([0x33; 32], 1), (4, b"snapshot-chunk-1".to_vec()));
    store.shards.insert(([0x44; 32], 7), b"da-shard-7".to_vec());

    let (a, mut a_rx) = spawn(7, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(8, chain_a(), store, |_| {});
    connect_ready(&a, &mut a_rx, &b, &mut b_rx).await;
    let bp = b.local_peer_id();

    // 1. /noos/braid/header/1 — announce (push) ...
    let reply = timeout(WAIT, a.announce_header(bp, header.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, HeaderReplyV1::Ack);
    let ev = wait_for(&mut b_rx, "header announce", |e| {
        matches!(
            e,
            P2pEvent::Inbound {
                item: InboundItem::HeaderAnnounce { .. },
                ..
            }
        )
    })
    .await;
    let P2pEvent::Inbound {
        peer,
        item: InboundItem::HeaderAnnounce { header: got },
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(peer, a.local_peer_id());
    assert_eq!(got, header);

    // ... and request/response.
    let reply = timeout(WAIT, a.request_header(bp, header_hash))
        .await
        .unwrap()
        .unwrap();
    match reply {
        HeaderReplyV1::Header(h) => assert_eq!(h.0, header),
        other => panic!("expected header, got {other:?}"),
    }
    let reply = timeout(WAIT, a.request_header(bp, [0xEE; 32]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, HeaderReplyV1::NotFound);

    // 2. /noos/braid/body/1 — request/transfer (targeted repair primitive).
    let reply = timeout(WAIT, a.request_body(bp, [0x22; 32]))
        .await
        .unwrap()
        .unwrap();
    match reply {
        BodyReplyV1::Body(got) => assert_eq!(got.0, body),
        other => panic!("expected body, got {other:?}"),
    }

    // 3. /noos/braid/vote/1 — push.
    let vote = b"checkpoint-vote".to_vec();
    let reply = timeout(WAIT, a.push_vote(bp, vote.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, PushReplyV1::Accepted);
    let ev = wait_for(&mut b_rx, "vote push", |e| {
        matches!(
            e,
            P2pEvent::Inbound {
                item: InboundItem::Vote { .. },
                ..
            }
        )
    })
    .await;
    let P2pEvent::Inbound {
        item: InboundItem::Vote { vote: got },
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(got, vote);

    // 4. /noos/lumen/tx/1 — push.
    let tx = b"signed-intent".to_vec();
    let reply = timeout(WAIT, a.push_tx(bp, tx.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, PushReplyV1::Accepted);
    let ev = wait_for(&mut b_rx, "tx push", |e| {
        matches!(
            e,
            P2pEvent::Inbound {
                item: InboundItem::Tx { .. },
                ..
            }
        )
    })
    .await;
    let P2pEvent::Inbound {
        item: InboundItem::Tx { tx: got },
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(got, tx);

    // 5. /noos/sync/range/1 — request/response with continuation flag.
    let reply = timeout(WAIT, a.request_range(bp, 1, 2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.headers.0.len(), 2);
    assert_eq!(reply.headers.0[0].0, b"h1".to_vec());
    assert_eq!(reply.headers.0[1].0, b"h2".to_vec());
    assert!(!reply.more.0);
    let reply = timeout(WAIT, a.request_range(bp, 0, 2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.headers.0.len(), 2);
    assert!(reply.more.0, "one more header remains past the page");

    // 6. /noos/sync/snapshot/1 — chunk request.
    let reply = timeout(WAIT, a.request_snapshot_chunk(bp, [0x33; 32], 1))
        .await
        .unwrap()
        .unwrap();
    match reply {
        SnapshotReplyV1::Chunk {
            total_chunks,
            chunk,
        } => {
            assert_eq!(total_chunks, 4);
            assert_eq!(chunk.0, b"snapshot-chunk-1".to_vec());
        }
        other => panic!("expected chunk, got {other:?}"),
    }

    // 7. /noos/blob/shard/1 — shard request/transfer.
    let reply = timeout(WAIT, a.request_shard(bp, [0x44; 32], 7))
        .await
        .unwrap()
        .unwrap();
    match reply {
        ShardReplyV1::Shard(got) => assert_eq!(got.0, b"da-shard-7".to_vec()),
        other => panic!("expected shard, got {other:?}"),
    }
    let reply = timeout(WAIT, a.request_shard(bp, [0x44; 32], 8))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, ShardReplyV1::NotFound);

    // 8. /noos/loom/receipt/1 — lane disabled at genesis: explicit
    //    feature_disabled, and the receipt is NOT dispatched.
    let reply = timeout(WAIT, a.push_loom_receipt(bp, b"loom-receipt".to_vec()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, PushReplyV1::FeatureDisabled);
}

// ---------------------------------------------------------------------------
// Oversize frame law
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn oversize_frame_is_violation_and_disconnects() {
    let (a, mut a_rx) = spawn(9, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(10, chain_a(), MemStore::default(), |_| {});
    connect_ready(&a, &mut a_rx, &b, &mut b_rx).await;

    // Misbehaving sender: declare 2 MiB on a tx stream.
    let mut s = a
        .open_raw_stream(b.local_peer_id(), "/noos/lumen/tx/1")
        .await
        .expect("raw stream");
    write_raw_declared(&mut s, 2 * 1024 * 1024, &[0u8; 1024])
        .await
        .expect("write mis-declared header");

    let ev = wait_for(&mut b_rx, "oversize violation", |e| {
        matches!(e, P2pEvent::Violation { .. })
    })
    .await;
    let P2pEvent::Violation { peer, violation } = ev else {
        unreachable!()
    };
    assert_eq!(peer, a.local_peer_id());
    assert_eq!(violation, Violation::OversizeFrame);

    wait_for(&mut b_rx, "disconnect after oversize", |e| {
        matches!(e, P2pEvent::PeerDisconnected { .. })
    })
    .await;
    wait_for(&mut a_rx, "sender sees disconnect", |e| {
        matches!(e, P2pEvent::PeerDisconnected { .. })
    })
    .await;
}

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_trips_score_and_disconnects() {
    let (a, mut a_rx) = spawn(11, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(12, chain_a(), MemStore::default(), |cfg| {
        // lumen/tx bucket: 2 requests, never refilled.
        cfg.limits.per_protocol[3].burst = 2;
        cfg.limits.per_protocol[3].per_second = 0;
    });
    connect_ready(&a, &mut a_rx, &b, &mut b_rx).await;
    let bp = b.local_peer_id();

    // Two in-budget pushes succeed.
    for i in 0..2u8 {
        let reply = timeout(WAIT, a.push_tx(bp, vec![i; 8]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, PushReplyV1::Accepted);
    }
    // The flood beyond the budget trips violations; fire-and-forget because
    // limited streams get no reply.
    let mut floods = Vec::new();
    for i in 2..16u8 {
        floods.push(tokio::spawn(a.push_tx(bp, vec![i; 8])));
    }

    let ev = wait_for(&mut b_rx, "rate-limit violation", |e| {
        matches!(e, P2pEvent::Violation { .. })
    })
    .await;
    let P2pEvent::Violation { peer, violation } = ev else {
        unreachable!()
    };
    assert_eq!(peer, a.local_peer_id());
    assert_eq!(violation, Violation::RateLimitExceeded);

    // Repeated trips cross DISCONNECT_SCORE and the peer is dropped.
    wait_for(&mut b_rx, "disconnect after repeated trips", |e| {
        matches!(e, P2pEvent::PeerDisconnected { .. })
    })
    .await;

    for f in floods {
        f.abort();
    }
}

// ---------------------------------------------------------------------------
// Duplicate suppression
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_push_is_suppressed_and_answered_duplicate() {
    let (a, mut a_rx) = spawn(13, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(14, chain_a(), MemStore::default(), |_| {});
    connect_ready(&a, &mut a_rx, &b, &mut b_rx).await;
    let bp = b.local_peer_id();

    let tx = b"same-tx-bytes".to_vec();
    let first = timeout(WAIT, a.push_tx(bp, tx.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, PushReplyV1::Accepted);
    let second = timeout(WAIT, a.push_tx(bp, tx.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second, PushReplyV1::Duplicate);

    // Exactly one Inbound Tx event; the sentinel push flushes the queue and
    // proves no second dispatch of the duplicate happened.
    let sentinel = b"different-tx".to_vec();
    let reply = timeout(WAIT, a.push_tx(bp, sentinel.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, PushReplyV1::Accepted);

    let mut seen = Vec::new();
    while seen.len() < 2 {
        let ev = wait_for(&mut b_rx, "inbound tx", |e| {
            matches!(
                e,
                P2pEvent::Inbound {
                    item: InboundItem::Tx { .. },
                    ..
                }
            )
        })
        .await;
        let P2pEvent::Inbound {
            item: InboundItem::Tx { tx: got },
            ..
        } = ev
        else {
            unreachable!()
        };
        seen.push(got);
    }
    assert_eq!(seen, vec![tx, sentinel], "duplicate never dispatched twice");
}

// ---------------------------------------------------------------------------
// Priority ordering under load (consensus-over-AI)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn queued_vote_drains_before_queued_tx_burst() {
    let (a, mut a_rx) = spawn(15, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(16, chain_a(), MemStore::default(), |_| {});
    let bp = b.local_peer_id();

    // Queue a burst of AI/application traffic FIRST, then one consensus
    // vote — all before the connection exists, so the outbox alone decides
    // the wire order.
    let mut pushes = Vec::new();
    for i in 0..16u8 {
        pushes.push(a.push_tx(bp, vec![i; 16]));
    }
    let vote_fut = a.push_vote(bp, b"the-vote".to_vec());

    connect_ready(&a, &mut a_rx, &b, &mut b_rx).await;

    let vote_reply = timeout(WAIT, vote_fut).await.unwrap().unwrap();
    assert_eq!(vote_reply, PushReplyV1::Accepted);
    for p in pushes {
        let reply = timeout(WAIT, p).await.unwrap().unwrap();
        assert_eq!(reply, PushReplyV1::Accepted);
    }

    // The FIRST push delivered to b must be the vote, although it was
    // enqueued after sixteen txs.
    let ev = wait_for(&mut b_rx, "first inbound push", |e| {
        matches!(
            e,
            P2pEvent::Inbound {
                item: InboundItem::Vote { .. } | InboundItem::Tx { .. },
                ..
            }
        )
    })
    .await;
    let P2pEvent::Inbound { item, .. } = ev else {
        unreachable!()
    };
    assert_eq!(
        item,
        InboundItem::Vote {
            vote: b"the-vote".to_vec()
        },
        "priority lane must drain before the normal lane"
    );
}

// ---------------------------------------------------------------------------
// Closed protocol list
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unknown_noos_protocol_is_refused_at_negotiation() {
    let (a, mut a_rx) = spawn(17, chain_a(), MemStore::default(), |_| {});
    let (b, mut b_rx) = spawn(18, chain_a(), MemStore::default(), |_| {});
    connect_ready(&a, &mut a_rx, &b, &mut b_rx).await;

    let res = a.open_raw_stream(b.local_peer_id(), "/noos/bogus/1").await;
    assert!(
        res.is_err(),
        "unknown /noos/ protocol must fail negotiation"
    );
}

fn _assert_send<T: Send>(_: &T) {}

#[allow(dead_code)]
fn _api_is_send(handle: &P2pHandle, peer: PeerId) {
    _assert_send(&handle.push_tx(peer, Vec::new()));
    _assert_send(&handle.request_body(peer, [0; 32]));
}
