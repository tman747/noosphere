//! Live-ingestion contracts: line-protocol wire compatibility, exact-height
//! resume, reorg-safe rollback, and the wrong-chain fail-closed invariant.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_indexer::ingest::{
    LineProtocolSource, NodeBlock, NodeReceipt, NodeSource, NodeStatus, SyncReport,
};
use noos_indexer::{Identity, Indexer, IndexerError};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Barrier};

fn hash(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}
fn identity() -> Identity {
    Identity {
        chain_id: hash('a'),
        genesis_hash: hash('b'),
        api_version: "v1".into(),
    }
}
/// Deterministic per-chain block hash: `<tag><height as hex nibble row>`.
fn block_hash(tag: u8, height: u64) -> String {
    let mut s = format!("{tag:02x}{height:016x}");
    while s.len() < 64 {
        s.push('e');
    }
    s
}
fn txid_for(tag: u8, height: u64, index: u64) -> String {
    let mut s = format!("f{tag:01x}{height:08x}{index:08x}");
    while s.len() < 64 {
        s.push('d');
    }
    s
}

/// Scripted in-memory chain speaking the NodeSource contract; records the
/// exact heights the driver requests (the resume falsifier).
struct ScriptedSource {
    status: NodeStatus,
    blocks: BTreeMap<u64, NodeBlock>,
    requested: Vec<u64>,
}

impl ScriptedSource {
    fn chain(
        tag: u8,
        genesis: &str,
        from: u64,
        to: u64,
        txs_per_block: u64,
    ) -> BTreeMap<u64, NodeBlock> {
        let mut out = BTreeMap::new();
        for h in from..=to {
            let parent_hash = if h == 1 {
                genesis.to_string()
            } else {
                block_hash(tag, h - 1)
            };
            out.insert(
                h,
                NodeBlock {
                    hash: block_hash(tag, h),
                    height: h,
                    slot: h,
                    timestamp_ms: 1_000 * h,
                    parent_hash,
                    txids: (0..txs_per_block).map(|i| txid_for(tag, h, i)).collect(),
                },
            );
        }
        out
    }
    fn new(id: &Identity, blocks: BTreeMap<u64, NodeBlock>) -> Self {
        let head = blocks.keys().max().copied().unwrap_or(0);
        let head_hash = blocks
            .get(&head)
            .map_or_else(|| id.genesis_hash.clone(), |b| b.hash.clone());
        Self {
            status: NodeStatus {
                chain_id: id.chain_id.clone(),
                genesis_hash: id.genesis_hash.clone(),
                head_height: head,
                head_hash,
                justified_epoch: 0,
                justified_hash: id.genesis_hash.clone(),
                finalized_epoch: 0,
                finalized_hash: id.genesis_hash.clone(),
            },
            blocks,
            requested: Vec::new(),
        }
    }
}

impl NodeSource for ScriptedSource {
    fn status(&mut self) -> noos_indexer::Result<NodeStatus> {
        Ok(self.status.clone())
    }
    fn block_by_height(&mut self, height: u64) -> noos_indexer::Result<Option<NodeBlock>> {
        self.requested.push(height);
        Ok(self.blocks.get(&height).cloned())
    }
    fn receipt(&mut self, _txid: &str) -> noos_indexer::Result<Option<NodeReceipt>> {
        Ok(Some(NodeReceipt {
            fee_charged: Some("7".into()),
            status_code: Some(0),
        }))
    }
}

struct BlockingSource {
    inner: ScriptedSource,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl NodeSource for BlockingSource {
    fn status(&mut self) -> noos_indexer::Result<NodeStatus> {
        self.inner.status()
    }

    fn block_by_height(&mut self, height: u64) -> noos_indexer::Result<Option<NodeBlock>> {
        self.entered.wait();
        self.release.wait();
        self.inner.block_by_height(height)
    }

    fn receipt(&mut self, txid: &str) -> noos_indexer::Result<Option<NodeReceipt>> {
        self.inner.receipt(txid)
    }
}

async fn stored_block_hash(indexer: &Indexer, height: u64) -> Option<String> {
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;
    let response = noos_indexer::router(indexer.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/blocks/{height}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != 200 {
        return None;
    }
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    Some(body["hash"].as_str().unwrap().to_string())
}

async fn stored_tx(indexer: &Indexer, txid: &str) -> Option<serde_json::Value> {
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;
    let response = noos_indexer::router(indexer.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/transactions/{txid}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != 200 {
        return None;
    }
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).ok()
}
async fn status_json(indexer: &Indexer) -> serde_json::Value {
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;
    let response = noos_indexer::router(indexer.clone())
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
async fn first_block_anchors_distinct_genesis_header_hash() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    let header_hash = hash('c');
    assert_ne!(header_hash, id.genesis_hash);
    let blocks = ScriptedSource::chain(0xaa, &header_hash, 1, 2, 0);
    let indexer = Indexer::open(dir.path(), id.clone(), id.clone()).unwrap();
    let mut source = ScriptedSource::new(&id, blocks);

    let report = indexer.sync_from_node(&id, &mut source, 16).await.unwrap();
    assert_eq!(report.ingested, 2);
    assert_eq!(report.next_height, 3);
    assert_eq!(
        stored_block_hash(&indexer, 1).await,
        Some(block_hash(0xaa, 1))
    );

    drop(indexer);
    let restored = Indexer::open(dir.path(), id.clone(), id).unwrap();
    assert_eq!(
        stored_block_hash(&restored, 2).await,
        Some(block_hash(0xaa, 2))
    );
}

#[tokio::test]
async fn explicit_node_finality_heads_are_indexed_and_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    let blocks = ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 600, 0);
    let indexer = Indexer::open(dir.path(), id.clone(), id.clone()).unwrap();
    let mut source = ScriptedSource::new(&id, blocks);
    source.status.justified_epoch = 2;
    source.status.justified_hash = hash('c');
    source.status.finalized_epoch = 1;
    source.status.finalized_hash = hash('d');

    indexer.sync_from_node(&id, &mut source, 600).await.unwrap();
    let status = status_json(&indexer).await;
    assert_eq!(status["justified"]["height"], "512");
    assert_eq!(status["justified"]["hash"], hash('c'));
    assert_eq!(status["finalized"]["height"], "256");
    assert_eq!(status["finalized"]["hash"], hash('d'));
    assert_eq!(status["readiness"], "ready");
    assert_eq!(status["ready"], true);
    assert!(
        status["freshness_ms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            < 5_000
    );

    drop(indexer);
    let restored = Indexer::open(dir.path(), id.clone(), id).unwrap();
    let status = status_json(&restored).await;
    assert_eq!(status["justified"]["height"], "512");
    assert_eq!(status["finalized"]["height"], "256");
    assert_eq!(status["readiness"], "starting");
    assert_eq!(status["ready"], false);
    assert_eq!(status["freshness_ms"], u64::MAX.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_indexer_stays_ready_during_bounded_tail_sync() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    let indexer = Indexer::open(dir.path(), id.clone(), id.clone()).unwrap();
    let mut initial =
        ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 1, 0));
    indexer.sync_from_node(&id, &mut initial, 16).await.unwrap();
    assert_eq!(status_json(&indexer).await["readiness"], "ready");

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let mut source = BlockingSource {
        inner: ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 2, 0)),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };
    let sync_indexer = indexer.clone();
    let sync_id = id.clone();
    let sync =
        tokio::spawn(async move { sync_indexer.sync_from_node(&sync_id, &mut source, 16).await });

    entered.wait();
    let during_sync = status_json(&indexer).await;
    assert_eq!(during_sync["readiness"], "ready");
    assert_eq!(during_sync["ready"], true);
    release.wait();

    let report = sync.await.unwrap().unwrap();
    assert_eq!(report.ingested, 1);
    assert_eq!(status_json(&indexer).await["unsafe_head"]["height"], "2");
}

#[tokio::test]
async fn fork_replaces_prior_head_rows_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let id = identity();

    // Chain A: heights 1..=5, two txs each.
    let mut a = ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 5, 2));
    let report = indexer.sync_from_node(&id, &mut a, u64::MAX).await.unwrap();
    assert_eq!(
        report,
        SyncReport {
            ingested: 5,
            rolled_back: 0,
            next_height: 6
        }
    );

    // Chain B forks at height 3: B keeps A1..A2, replaces 3..=5, extends to 6.
    let mut b_blocks = ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 2, 2);
    for h in 3..=6u64 {
        let parent_hash = if h == 3 {
            block_hash(0xaa, 2)
        } else {
            block_hash(0xbb, h - 1)
        };
        b_blocks.insert(
            h,
            NodeBlock {
                hash: block_hash(0xbb, h),
                height: h,
                slot: h + 100,
                timestamp_ms: 2_000 * h,
                parent_hash,
                txids: vec![txid_for(0xbb, h, 0)],
            },
        );
    }
    let mut b = ScriptedSource::new(&id, b_blocks);
    let report = indexer.sync_from_node(&id, &mut b, u64::MAX).await.unwrap();
    assert_eq!(report.rolled_back, 3, "exactly A3..A5 rolled back");
    assert_eq!(report.next_height, 7);

    // Prior head rows replaced EXACTLY: 1..2 untouched, 3..6 are B rows.
    for h in 1..=2u64 {
        assert_eq!(
            stored_block_hash(&indexer, h).await.unwrap(),
            block_hash(0xaa, h)
        );
    }
    for h in 3..=6u64 {
        assert_eq!(
            stored_block_hash(&indexer, h).await.unwrap(),
            block_hash(0xbb, h)
        );
    }
    assert!(stored_block_hash(&indexer, 7).await.is_none());

    // Orphaned A-branch txids are gone; retained A rows and B rows remain.
    for h in 3..=5u64 {
        for i in 0..2u64 {
            assert!(stored_tx(&indexer, &txid_for(0xaa, h, i)).await.is_none());
        }
    }
    let kept = stored_tx(&indexer, &txid_for(0xaa, 1, 0)).await.unwrap();
    assert_eq!(kept["state"], "INCLUDED");
    assert_eq!(kept["fee"], "7");
    assert_eq!(kept["inclusion"]["height"], "1");
    let new_row = stored_tx(&indexer, &txid_for(0xbb, 4, 0)).await.unwrap();
    assert_eq!(new_row["inclusion"]["hash"], block_hash(0xbb, 4));
}

#[tokio::test]
async fn resume_requests_exactly_the_next_height_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    {
        let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
        let mut src =
            ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 4, 1));
        let report = indexer
            .sync_from_node(&id, &mut src, u64::MAX)
            .await
            .unwrap();
        assert_eq!(report.next_height, 5);
    }
    // Restart: fresh Indexer instance over the same root.
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    assert_eq!(
        stored_block_hash(&indexer, 4).await.as_deref(),
        Some(block_hash(0xaa, 4).as_str()),
        "query block state survives with the cursor"
    );
    assert!(
        stored_tx(&indexer, &txid_for(0xaa, 4, 0)).await.is_some(),
        "query transaction state survives with the cursor"
    );
    let orphan_stage = dir
        .path()
        .join("index-generation-v2-00000000000000000002.stage");
    fs::write(&orphan_stage, b"interrupted generation").unwrap();
    let mut src = ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 7, 1));
    let report = indexer
        .sync_from_node(&id, &mut src, u64::MAX)
        .await
        .unwrap();
    assert_eq!(
        report,
        SyncReport {
            ingested: 3,
            rolled_back: 0,
            next_height: 8
        }
    );
    // Falsifier: a restart that re-scans or skips would request != [5,6,7].
    assert_eq!(src.requested, vec![5, 6, 7]);
    assert!(
        !orphan_stage.exists(),
        "a stale stage from an interrupted commit must not stall ingestion"
    );
}

#[tokio::test]
async fn corrupt_latest_generation_falls_back_without_skipping_rows() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    let indexer = Indexer::open(dir.path(), id.clone(), id.clone()).unwrap();
    let mut first =
        ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 3, 1));
    indexer
        .sync_from_node(&id, &mut first, u64::MAX)
        .await
        .unwrap();
    let mut second =
        ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 5, 1));
    indexer
        .sync_from_node(&id, &mut second, u64::MAX)
        .await
        .unwrap();
    drop(indexer);

    let mut generations: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("index-generation-v2-") && name.ends_with(".json")
                })
        })
        .collect();
    generations.sort();
    fs::write(generations.last().unwrap(), b"truncated generation").unwrap();

    let recovered = Indexer::open(dir.path(), id.clone(), id.clone()).unwrap();
    assert!(stored_block_hash(&recovered, 3).await.is_some());
    assert!(stored_block_hash(&recovered, 4).await.is_none());
    let mut source =
        ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 5, 1));
    recovered
        .sync_from_node(&id, &mut source, u64::MAX)
        .await
        .unwrap();
    assert_eq!(source.requested, vec![4, 5]);
    assert!(stored_tx(&recovered, &txid_for(0xaa, 5, 0)).await.is_some());
}

#[tokio::test]
async fn all_corrupt_generations_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let id = identity();
    let indexer = Indexer::open(dir.path(), id.clone(), id.clone()).unwrap();
    let mut source =
        ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 1, 1));
    indexer
        .sync_from_node(&id, &mut source, u64::MAX)
        .await
        .unwrap();
    drop(indexer);
    for entry in fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("index-generation-v2-"))
        {
            fs::write(path, b"corrupt").unwrap();
        }
    }
    let error = match Indexer::open(dir.path(), id.clone(), id) {
        Ok(_) => panic!("corrupt cursor/query generations must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error, IndexerError::StateDiverged);
}

#[tokio::test]
async fn wrong_chain_source_fails_closed_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let id = identity();
    let mut wrong = identity();
    wrong.chain_id = hash('c');
    let mut src = ScriptedSource::new(
        &wrong,
        ScriptedSource::chain(0xaa, &wrong.genesis_hash, 1, 3, 1),
    );
    let error = indexer
        .sync_from_node(&id, &mut src, u64::MAX)
        .await
        .unwrap_err();
    assert_eq!(error, IndexerError::WrongProtocolIdentity);
    assert!(
        src.requested.is_empty(),
        "no block fetched from a wrong chain"
    );
    assert!(stored_block_hash(&indexer, 1).await.is_none());
    assert!(
        !dir.path().join("ingest-checkpoint-v1.json").exists(),
        "fail-closed: no checkpoint written for a wrong-chain source"
    );
}

#[tokio::test]
async fn reorg_deeper_than_checkpoint_tail_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let id = identity();
    // 70 blocks: the 64-point tail retains heights 7..=70 only.
    let mut a = ScriptedSource::new(&id, ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 70, 0));
    indexer.sync_from_node(&id, &mut a, u64::MAX).await.unwrap();

    // A hostile chain that forked at height 2 — beyond the retained tail.
    let mut b_blocks = ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 2, 0);
    for h in 3..=71u64 {
        let parent_hash = if h == 3 {
            block_hash(0xaa, 2)
        } else {
            block_hash(0xbb, h - 1)
        };
        b_blocks.insert(
            h,
            NodeBlock {
                hash: block_hash(0xbb, h),
                height: h,
                slot: h,
                timestamp_ms: h,
                parent_hash,
                txids: vec![],
            },
        );
    }
    let mut b = ScriptedSource::new(&id, b_blocks);
    let error = indexer
        .sync_from_node(&id, &mut b, u64::MAX)
        .await
        .unwrap_err();
    assert_eq!(error, IndexerError::ReorgBeyondCheckpoint);
    // Nothing was replaced: height 70 still carries the A row.
    assert_eq!(
        stored_block_hash(&indexer, 70).await.unwrap(),
        block_hash(0xaa, 70)
    );
}

// ---------------------------------------------------------------------------
// Wire-format test: LineProtocolSource against a node-shaped TCP server
// ---------------------------------------------------------------------------

/// Minimal single-threaded server speaking the noos-node operator line
/// protocol (`rpc.rs` shapes: bearer auth, connection: close, node JSON).
fn spawn_node_shaped_server(
    token: &'static str,
    id: Identity,
    blocks: BTreeMap<u64, NodeBlock>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&req).to_string();
            let path = text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            if path == "/stop" {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                return;
            }
            let authorized = text.lines().any(|l| {
                l.to_ascii_lowercase().starts_with("authorization:")
                    && l.trim_end().ends_with(&format!("Bearer {token}"))
            });
            let body = if !authorized {
                r#"{"error":{"code":"unauthorized","detail":"missing or bad bearer token"}}"#
                    .to_string()
            } else if path == "/status" {
                let head = blocks.keys().max().copied().unwrap_or(0);
                let head_hash = blocks
                    .get(&head)
                    .map_or_else(|| id.genesis_hash.clone(), |b| b.hash.clone());
                format!(
                    concat!(
                        r#"{{"chain_id":"{}","genesis_hash":"{}","#,
                        r#""unsafe_head":{{"height":{},"hash":"{}"}},"#,
                        r#""justified":{{"epoch":0,"hash":"{}"}},"#,
                        r#""finalized":{{"epoch":0,"hash":"{}"}},"#,
                        r#""mempool":{{"txs":0,"bytes":0}},"observer":false}}"#
                    ),
                    id.chain_id, id.genesis_hash, head, head_hash, id.genesis_hash, id.genesis_hash
                )
            } else if let Some(rest) = path.strip_prefix("/blocks/") {
                let mut parts = rest.split('/');
                let start = parts.next().and_then(|value| value.parse::<u64>().ok());
                let limit = parts.next().and_then(|value| value.parse::<u32>().ok());
                let items: Vec<String> = match (start, limit) {
                    (Some(start), Some(limit)) => (0..u64::from(limit))
                        .filter_map(|offset| blocks.get(&start.saturating_add(offset)))
                        .map(|block| {
                            let txids: Vec<String> = block
                                .txids
                                .iter()
                                .map(|txid| format!("\"{txid}\""))
                                .collect();
                            format!(
                                r#"{{"hash":"{}","height":{},"slot":{},"timestamp_ms":{},"parent_hash":"{}","txids":[{}]}}"#,
                                block.hash,
                                block.height,
                                block.slot,
                                block.timestamp_ms,
                                block.parent_hash,
                                txids.join(",")
                            )
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                format!(r#"{{"items":[{}]}}"#, items.join(","))
            } else if let Some(rest) = path.strip_prefix("/block/") {
                match rest.parse::<u64>().ok().and_then(|h| blocks.get(&h)) {
                    Some(b) => {
                        let txids: Vec<String> =
                            b.txids.iter().map(|t| format!("\"{t}\"")).collect();
                        format!(
                            r#"{{"hash":"{}","height":{},"slot":{},"timestamp_ms":{},"parent_hash":"{}","txids":[{}]}}"#,
                            b.hash,
                            b.height,
                            b.slot,
                            b.timestamp_ms,
                            b.parent_hash,
                            txids.join(",")
                        )
                    }
                    None => r#"{"error":{"code":"not_found","detail":"unknown block"}}"#.into(),
                }
            } else if let Some(txid) = path.strip_prefix("/receipt/") {
                format!(
                    r#"{{"state":{{"settled_height":1,"status_code":0}},"receipt":{{"txid":"{txid}","status":0,"fee_charged":"42"}}}}"#
                )
            } else {
                r#"{"error":{"code":"unknown_route","detail":"no such operator route"}}"#.into()
            };
            let status = if !authorized {
                "401 Unauthorized"
            } else if body.contains("\"not_found\"") {
                "404 Not Found"
            } else {
                "200 OK"
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, handle)
}

fn stop_server(addr: &str, handle: std::thread::JoinHandle<()>) {
    if let Ok(mut s) = std::net::TcpStream::connect(addr) {
        let _ = s.write_all(b"GET /stop HTTP/1.1\r\n\r\n");
    }
    let _ = handle.join();
}

#[tokio::test(flavor = "multi_thread")]
async fn line_protocol_source_ingests_a_node_shaped_feed() {
    let id = identity();
    let blocks = ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 3, 1);
    let (addr, handle) = spawn_node_shaped_server("sekrit", id.clone(), blocks);

    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let mut source = LineProtocolSource::new(addr.clone(), "sekrit");
    let report = indexer
        .sync_from_node(&id, &mut source, u64::MAX)
        .await
        .unwrap();
    assert_eq!(
        report,
        SyncReport {
            ingested: 3,
            rolled_back: 0,
            next_height: 4
        }
    );
    assert_eq!(
        stored_block_hash(&indexer, 3).await.unwrap(),
        block_hash(0xaa, 3)
    );
    // Receipt lane consumed over the wire: fee_charged=42 lands on the row.
    let row = stored_tx(&indexer, &txid_for(0xaa, 2, 0)).await.unwrap();
    assert_eq!(row["fee"], "42");
    assert_eq!(row["state"], "INCLUDED");
    stop_server(&addr, handle);
}

#[tokio::test(flavor = "multi_thread")]
async fn line_protocol_source_with_bad_token_fails_closed() {
    let id = identity();
    let blocks = ScriptedSource::chain(0xaa, &id.genesis_hash, 1, 2, 0);
    let (addr, handle) = spawn_node_shaped_server("sekrit", id.clone(), blocks);

    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let mut source = LineProtocolSource::new(addr.clone(), "WRONG");
    let error = indexer
        .sync_from_node(&id, &mut source, u64::MAX)
        .await
        .unwrap_err();
    assert!(matches!(error, IndexerError::Source(_)), "got {error:?}");
    assert!(stored_block_hash(&indexer, 1).await.is_none());
    stop_server(&addr, handle);
}
