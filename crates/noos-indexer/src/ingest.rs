//! Live ingestion from a local noos-node over the operator line protocol.
//!
//! The node's minimal localhost RPC (`crates/noos-node/src/rpc.rs`) is the
//! ingestion source: `GET /status`, `GET /block/<height>`, and
//! `GET /receipt/<txid>`, every route behind `Authorization: Bearer <token>`.
//! [`LineProtocolSource`] speaks that exact wire format; [`NodeSource`] keeps
//! the sync driver testable against scripted chains.
//!
//! Invariants defended here (and by `tests/ingest.rs`):
//! - **Fail-closed wrong chain**: a source whose `/status` identity differs
//!   from the indexer identity is rejected before any row is written.
//! - **Reorg-safe rollback**: when a fetched block does not link onto the
//!   stored tip, ingestion walks back to the deepest retained common
//!   ancestor and deletes exactly the orphaned block and transaction rows
//!   before ingesting the fork branch. A fork older than the retained tail
//!   fails closed ([`IndexerError::ReorgBeyondCheckpoint`]).
//! - **Exact-height resume**: the checkpoint file persists `next_height`
//!   plus a bounded tail of `(height, hash)` points, so a restarted indexer
//!   asks the source for exactly the next un-ingested height.
//! - **No inferred finality**: ingestion advances only the *unsafe* head;
//!   justified/finalized move solely via explicit [`Indexer::ingest_head`]
//!   calls, preserving the independent-heads contract.

use crate::{
    atomic_write, is_hash, ChainPoint, Identity, IndexedBlock, Indexer, IndexerError, Result,
    ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Epoch length in block heights (ch01 §4.1; `noos-braid` `EPOCH_LENGTH`).
/// The line protocol does not carry the epoch, but it is pure law:
/// `epoch = height / 256`.
const EPOCH_LENGTH: u64 = 256;
/// Checkpoint tail size: the deepest offline reorg the indexer can roll
/// back without a resync.
const RETAINED_POINTS: usize = 64;
const CHECKPOINT_FILE: &str = "ingest-checkpoint-v1.json";
const CHECKPOINT_SCHEMA: &str = "noos-ingest-checkpoint-v1";

/// Node `/status` view (identity + unsafe head only; justified/finalized
/// are epoch-keyed there and deliberately not consumed by ingestion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub chain_id: String,
    pub genesis_hash: String,
    pub head_height: u64,
    pub head_hash: String,
}

/// Node `/block/<height>` view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBlock {
    pub hash: String,
    pub height: u64,
    pub slot: u64,
    pub timestamp_ms: u64,
    pub parent_hash: String,
    pub txids: Vec<String>,
}

/// Node `/receipt/<txid>` view for a settled transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeReceipt {
    /// `fee_charged` from the settled receipt, decimal string.
    pub fee_charged: Option<String>,
    /// Stable execution status code (0 = success).
    pub status_code: Option<u16>,
}

/// Abstract local-node source. [`LineProtocolSource`] is the production
/// implementation; tests script forks and record requested heights.
pub trait NodeSource {
    fn status(&mut self) -> Result<NodeStatus>;
    /// `Ok(None)` when the node does not (yet) serve the height.
    fn block_by_height(&mut self, height: u64) -> Result<Option<NodeBlock>>;
    /// Best-effort receipt lookup; `Ok(None)` when unknown or still pending.
    fn receipt(&mut self, txid: &str) -> Result<Option<NodeReceipt>>;
}

/// Outcome of one bounded sync pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub ingested: u64,
    pub rolled_back: u64,
    pub next_height: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct RecentPoint {
    height: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    schema: String,
    identity: Identity,
    next_height: String,
    recent: Vec<RecentPoint>,
}

impl Checkpoint {
    fn tip(&self) -> Result<(u64, &str)> {
        let last = self
            .recent
            .last()
            .ok_or_else(|| IndexerError::Source("empty checkpoint tail".into()))?;
        Ok((parse_u64(&last.height)?, &last.hash))
    }
}

fn parse_u64(s: &str) -> Result<u64> {
    s.parse()
        .map_err(|_| IndexerError::Source(format!("non-canonical height: {s}")))
}

impl Indexer {
    /// Ingests up to `max_blocks` new blocks (plus their transactions and
    /// receipts) from a live local node source, with exact-height resume
    /// and reorg-safe rollback. Advances only the unsafe head.
    pub async fn sync_from_node<S: NodeSource>(
        &self,
        identity: &Identity,
        source: &mut S,
        max_blocks: u64,
    ) -> Result<SyncReport> {
        self.identity.require(identity)?;
        let status = source.status()?;
        // Fail-closed BEFORE any row or checkpoint write.
        if status.chain_id != self.identity.chain_id
            || status.genesis_hash != self.identity.genesis_hash
        {
            return Err(IndexerError::WrongProtocolIdentity);
        }
        let mut cp = self.load_checkpoint()?;
        let mut next = parse_u64(&cp.next_height)?;
        let mut ingested = 0u64;
        let mut rolled_back = 0u64;
        while next <= status.head_height && ingested < max_blocks {
            let Some(block) = source.block_by_height(next)? else {
                break; // source lag: retry on the next pass, same height
            };
            if block.height != next
                || !is_hash(&block.hash)
                || !is_hash(&block.parent_hash)
                || block.txids.iter().any(|t| !is_hash(t))
            {
                return Err(IndexerError::Source(format!(
                    "malformed block frame at height {next}"
                )));
            }
            let (tip_height, tip_hash) = cp.tip()?;
            debug_assert_eq!(tip_height.saturating_add(1), next);
            if block.parent_hash != tip_hash {
                // Fork: find the deepest retained ancestor still on the
                // source's chain, then delete exactly the orphaned rows.
                let ancestor = find_ancestor(source, &cp)?;
                rolled_back = rolled_back.saturating_add(tip_height.saturating_sub(ancestor));
                self.rollback_to(ancestor, &mut cp).await;
                next = ancestor.saturating_add(1);
                continue;
            }
            self.apply_block(source, &block).await?;
            cp.recent.push(RecentPoint {
                height: block.height.to_string(),
                hash: block.hash.clone(),
            });
            if cp.recent.len() > RETAINED_POINTS {
                let overflow = cp.recent.len().saturating_sub(RETAINED_POINTS);
                cp.recent.drain(..overflow);
            }
            ingested = ingested.saturating_add(1);
            next = next.saturating_add(1);
        }
        cp.next_height = next.to_string();
        self.store_checkpoint(&cp)?;
        Ok(SyncReport {
            ingested,
            rolled_back,
            next_height: next,
        })
    }

    fn load_checkpoint(&self) -> Result<Checkpoint> {
        let path = self.root.join(CHECKPOINT_FILE);
        if !path.exists() {
            return Ok(Checkpoint {
                schema: CHECKPOINT_SCHEMA.into(),
                identity: self.identity.clone(),
                next_height: "1".into(),
                recent: vec![RecentPoint {
                    height: "0".into(),
                    hash: self.identity.genesis_hash.clone(),
                }],
            });
        }
        let bytes = std::fs::read(&path).map_err(|e| IndexerError::Io(e.to_string()))?;
        let cp: Checkpoint =
            serde_json::from_slice(&bytes).map_err(|_| IndexerError::SchemaMismatch)?;
        if cp.schema != CHECKPOINT_SCHEMA || cp.identity != self.identity || cp.recent.is_empty() {
            return Err(IndexerError::SchemaMismatch);
        }
        Ok(cp)
    }

    fn store_checkpoint(&self, cp: &Checkpoint) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(cp).map_err(|e| IndexerError::Io(e.to_string()))?;
        atomic_write(&self.root.join(CHECKPOINT_FILE), &bytes)
    }

    /// Deletes every block row above `ancestor` together with exactly the
    /// transaction rows those heights carried, then truncates the
    /// checkpoint tail to match.
    async fn rollback_to(&self, ancestor: u64, cp: &mut Checkpoint) {
        let cut = ancestor.saturating_add(1);
        let mut state = self.inner.write().await;
        state.blocks.split_off(&cut);
        let removed = state.block_txids.split_off(&cut);
        for txids in removed.values() {
            for txid in txids {
                state.transactions.remove(txid);
            }
        }
        drop(state);
        cp.recent
            .retain(|p| p.height.parse::<u64>().is_ok_and(|h| h <= ancestor));
    }

    async fn apply_block<S: NodeSource>(&self, source: &mut S, block: &NodeBlock) -> Result<()> {
        // Receipts first (transport may fail): no partial row set on error.
        let mut rows = Vec::with_capacity(block.txids.len());
        for (index, txid) in block.txids.iter().enumerate() {
            let receipt = source.receipt(txid)?.unwrap_or_default();
            let fee = receipt.fee_charged.unwrap_or_else(|| "0".into());
            // Frozen API tx law: INCLUDED carries exactly the `inclusion`
            // coordinate; finality states are NEVER inferred here.
            // The operator line protocol exposes only the txid, so the
            // wtxid field mirrors it until a witness lane exists.
            rows.push((
                txid.clone(),
                json!({
                    "txid": txid,
                    "wtxid": txid,
                    "state": "INCLUDED",
                    "fee": fee,
                    "resource_counters": {},
                    "inclusion": {
                        "height": block.height.to_string(),
                        "hash": block.hash,
                        "index": index.to_string(),
                    },
                }),
            ));
        }
        let indexed = IndexedBlock {
            hash: block.hash.clone(),
            height: block.height.to_string(),
            parent_hash: block.parent_hash.clone(),
            slot: block.slot.to_string(),
            // Pure protocol law (ch01 §4.1): 256 heights per epoch.
            epoch: block
                .height
                .checked_div(EPOCH_LENGTH)
                .unwrap_or_default()
                .to_string(),
            timestamp_ms: block.timestamp_ms.to_string(),
            // The operator line protocol does not carry lane roots; the
            // all-zero root is the canonical absent-root value.
            execution_receipt_root: ZERO_HASH.into(),
            lumen_receipts_state_root: ZERO_HASH.into(),
            transaction_count: block.txids.len().to_string(),
        };
        let mut state = self.inner.write().await;
        state.blocks.insert(block.height, indexed);
        state.block_txids.insert(block.height, block.txids.clone());
        for (txid, row) in rows {
            state.transactions.insert(txid, row);
        }
        // Advance ONLY the unsafe head, and only forward (a fork that ends
        // lower than a previously seen tip must not regress the head).
        let advance = match &state.unsafe_head {
            Some(point) => point.numeric_height().is_ok_and(|old| block.height >= old),
            None => true,
        };
        if advance {
            state.unsafe_head = Some(ChainPoint {
                height: block.height.to_string(),
                hash: block.hash.clone(),
                state_root: ZERO_HASH.into(),
            });
        }
        Ok(())
    }
}

/// Walks the retained tail newest→oldest and returns the highest retained
/// height whose hash the source still reports on its canonical chain.
fn find_ancestor<S: NodeSource>(source: &mut S, cp: &Checkpoint) -> Result<u64> {
    for point in cp.recent.iter().rev() {
        let height = parse_u64(&point.height)?;
        if height == 0 {
            // Genesis: identity equality was already enforced fail-closed.
            return Ok(0);
        }
        if let Some(block) = source.block_by_height(height)? {
            if block.hash == point.hash {
                return Ok(height);
            }
        }
    }
    Err(IndexerError::ReorgBeyondCheckpoint)
}

// ---------------------------------------------------------------------------
// Line-protocol client (the node's operator RPC wire format)
// ---------------------------------------------------------------------------

/// Blocking client for the noos-node operator line protocol on localhost.
/// One request per connection, `connection: close`, bearer auth — the exact
/// contract of `noos-node/src/rpc.rs`.
pub struct LineProtocolSource {
    addr: String,
    token: String,
    timeout: Duration,
}

impl LineProtocolSource {
    #[must_use]
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            token: token.into(),
            timeout: Duration::from_secs(5),
        }
    }

    fn get(&self, path: &str) -> Result<(u16, Value)> {
        let (code, body) = http_get(&self.addr, path, &self.token, self.timeout)?;
        let value = serde_json::from_str(&body)
            .map_err(|_| IndexerError::Source(format!("non-JSON body from {path}")))?;
        Ok((code, value))
    }
}

impl NodeSource for LineProtocolSource {
    fn status(&mut self) -> Result<NodeStatus> {
        let (code, v) = self.get("/status")?;
        if code != 200 {
            return Err(IndexerError::Source(format!("/status returned {code}")));
        }
        Ok(NodeStatus {
            chain_id: str_field(&v, "chain_id")?,
            genesis_hash: str_field(&v, "genesis_hash")?,
            head_height: u64_field(&v["unsafe_head"], "height")?,
            head_hash: str_field(&v["unsafe_head"], "hash")?,
        })
    }

    fn block_by_height(&mut self, height: u64) -> Result<Option<NodeBlock>> {
        let (code, v) = self.get(&format!("/block/{height}"))?;
        match code {
            200 => {}
            404 | 410 => return Ok(None),
            other => {
                return Err(IndexerError::Source(format!("/block returned {other}")));
            }
        }
        let txids = v["txids"]
            .as_array()
            .ok_or_else(|| IndexerError::Source("block without txids".into()))?
            .iter()
            .map(|t| {
                t.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| IndexerError::Source("non-string txid".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(NodeBlock {
            hash: str_field(&v, "hash")?,
            height: u64_field(&v, "height")?,
            slot: u64_field(&v, "slot")?,
            timestamp_ms: u64_field(&v, "timestamp_ms")?,
            parent_hash: str_field(&v, "parent_hash")?,
            txids,
        }))
    }

    fn receipt(&mut self, txid: &str) -> Result<Option<NodeReceipt>> {
        let (code, v) = self.get(&format!("/receipt/{txid}"))?;
        match code {
            200 => {}
            404 | 410 => return Ok(None),
            other => {
                return Err(IndexerError::Source(format!("/receipt returned {other}")));
            }
        }
        // Pending transactions report `"state":"MEMPOOL"` — not settled yet.
        if v["state"].as_str() == Some("MEMPOOL") {
            return Ok(None);
        }
        let receipt = &v["receipt"];
        Ok(Some(NodeReceipt {
            fee_charged: receipt["fee_charged"].as_str().map(str::to_owned),
            status_code: v["state"]["status_code"]
                .as_u64()
                .and_then(|c| u16::try_from(c).ok()),
        }))
    }
}

fn str_field(v: &Value, key: &str) -> Result<String> {
    v[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| IndexerError::Source(format!("missing field {key}")))
}

fn u64_field(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| IndexerError::Source(format!("missing numeric field {key}")))
}

fn http_get(addr: &str, path: &str, token: &str, timeout: Duration) -> Result<(u16, String)> {
    let source_err = |e: std::io::Error| IndexerError::Source(e.to_string());
    let mut stream = TcpStream::connect(addr).map_err(source_err)?;
    stream.set_read_timeout(Some(timeout)).map_err(source_err)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(source_err)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {token}\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).map_err(source_err)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(source_err)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| IndexerError::Source("truncated HTTP response".into()))?;
    let code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| IndexerError::Source("malformed status line".into()))?;
    Ok((code, body.to_string()))
}
