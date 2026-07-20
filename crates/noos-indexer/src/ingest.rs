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
    is_hash, ChainPoint, Identity, IndexReadiness, IndexState, IndexedBlock, Indexer, IndexerError,
    Result, TelemetryParser, ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Epoch length in block heights (ch01 §4.1; `noos-braid` `EPOCH_LENGTH`).
/// The line protocol does not carry the epoch, but it is pure law:
/// `epoch = height / 256`.
const EPOCH_LENGTH: u64 = 256;
/// Checkpoint tail size: the deepest offline reorg the indexer can roll
/// back without a resync.
const RETAINED_POINTS: usize = 64;
const GENERATION_PREFIX: &str = "index-generation-v2-";
const GENERATION_SCHEMA: &str = "noos-index-generation-v2";
const CHECKPOINT_SCHEMA: &str = "noos-index-checkpoint-v2";
const MAX_OPERATOR_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_OPERATOR_HEADER_BYTES: usize = 16 * 1024;

/// Node `/status` view with protocol identity and the three independently
/// reported consensus heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub chain_id: String,
    pub genesis_hash: String,
    pub head_height: u64,
    pub head_hash: String,
    pub justified_epoch: u64,
    pub justified_hash: String,
    pub finalized_epoch: u64,
    pub finalized_hash: String,
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
    /// Bounded contiguous block range. Production overrides this to avoid
    /// one TCP connection per historical block; scripted sources inherit
    /// the exact-height fallback.
    fn blocks_from(&mut self, start: u64, limit: u32) -> Result<Vec<NodeBlock>> {
        let mut blocks = Vec::with_capacity(limit as usize);
        for offset in 0..u64::from(limit) {
            let Some(height) = start.checked_add(offset) else {
                break;
            };
            let Some(block) = self.block_by_height(height)? else {
                break;
            };
            blocks.push(block);
        }
        Ok(blocks)
    }
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

#[derive(Clone, Serialize, Deserialize)]
struct Checkpoint {
    schema: String,
    identity: Identity,
    next_height: String,
    recent: Vec<RecentPoint>,
    generation: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedState {
    unsafe_head: Option<ChainPoint>,
    justified: Option<ChainPoint>,
    finalized: Option<ChainPoint>,
    blocks: BTreeMap<u64, IndexedBlock>,
    block_txids: BTreeMap<u64, Vec<String>>,
    transactions: BTreeMap<String, Value>,
    evidence: BTreeMap<String, Value>,
}

impl PersistedState {
    fn capture(state: &IndexState) -> Self {
        Self {
            unsafe_head: state.unsafe_head.clone(),
            justified: state.justified.clone(),
            finalized: state.finalized.clone(),
            blocks: state.blocks.clone(),
            block_txids: state.block_txids.clone(),
            transactions: state
                .transactions
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            evidence: state
                .evidence
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    fn restore(self) -> IndexState {
        IndexState {
            unsafe_head: self.unsafe_head,
            justified: self.justified,
            finalized: self.finalized,
            blocks: self.blocks,
            block_txids: self.block_txids,
            transactions: self.transactions.into_iter().collect(),
            evidence: self.evidence.into_iter().collect(),
            telemetry: TelemetryParser::default(),
            readiness: IndexReadiness::Starting,
            generation: 0,
            last_sync_unix_ms: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct GenerationPayload {
    schema: String,
    identity: Identity,
    sequence: u64,
    checkpoint: Checkpoint,
    state: PersistedState,
}

#[derive(Serialize, Deserialize)]
struct GenerationEnvelope {
    payload: GenerationPayload,
    sha256: String,
}

fn payload_digest(payload: &GenerationPayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload).map_err(|error| IndexerError::Io(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn generation_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| IndexerError::Io(error.to_string()))? {
        let path = entry
            .map_err(|error| IndexerError::Io(error.to_string()))?
            .path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(GENERATION_PREFIX) && name.ends_with(".json"))
        {
            paths.push(path);
        }
    }
    paths.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    Ok(paths)
}

fn generation_consistent(payload: &GenerationPayload) -> bool {
    if payload.schema != GENERATION_SCHEMA
        || payload.sequence == 0
        || payload.checkpoint.generation != payload.sequence
        || payload.checkpoint.identity != payload.identity
    {
        return false;
    }
    let Ok((tip_height, tip_hash)) = payload.checkpoint.tip() else {
        return false;
    };
    let state_tip = payload
        .state
        .unsafe_head
        .as_ref()
        .and_then(|point| point.numeric_height().ok());
    if state_tip != Some(tip_height) {
        return false;
    }
    if tip_height == 0 {
        return payload.state.blocks.is_empty() && is_hash(tip_hash);
    }
    payload
        .state
        .blocks
        .get(&tip_height)
        .is_some_and(|block| block.hash == tip_hash)
        && payload.state.blocks.keys().next_back().copied() == Some(tip_height)
}

fn load_latest_generation(root: &Path, identity: &Identity) -> Result<Option<GenerationPayload>> {
    let paths = generation_paths(root)?;
    if paths.is_empty() {
        return Ok(None);
    }
    for path in paths {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(envelope) = serde_json::from_slice::<GenerationEnvelope>(&bytes) else {
            continue;
        };
        let Ok(digest) = payload_digest(&envelope.payload) else {
            continue;
        };
        if envelope.sha256 == digest
            && envelope.payload.identity == *identity
            && generation_consistent(&envelope.payload)
        {
            return Ok(Some(envelope.payload));
        }
    }
    Err(IndexerError::StateDiverged)
}

pub(super) fn restore_index_state(root: &Path, identity: &Identity) -> Result<Option<IndexState>> {
    Ok(load_latest_generation(root, identity)?.map(|generation| {
        let sequence = generation.sequence;
        let mut state = generation.state.restore();
        state.generation = sequence;
        state
    }))
}

fn durable_store_generation(root: &Path, payload: GenerationPayload) -> Result<()> {
    let sha256 = payload_digest(&payload)?;
    let envelope = GenerationEnvelope { payload, sha256 };
    let bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|error| IndexerError::Io(error.to_string()))?;
    let sequence = envelope.payload.sequence;
    let final_path = root.join(format!("{GENERATION_PREFIX}{sequence:020}.json"));
    let stage_path = root.join(format!("{GENERATION_PREFIX}{sequence:020}.stage"));
    match fs::remove_file(&stage_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(IndexerError::Io(error.to_string())),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage_path)
        .map_err(|error| IndexerError::Io(error.to_string()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| IndexerError::Io(error.to_string()))?;
    fs::rename(&stage_path, &final_path).map_err(|error| IndexerError::Io(error.to_string()))?;
    for obsolete in generation_paths(root)?.into_iter().skip(3) {
        let _ = fs::remove_file(obsolete);
    }
    Ok(())
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
        {
            let mut state = self.inner.write().await;
            state.generation = cp.generation;
            // A ready index remains available while one bounded tail pass runs.
            // Otherwise every ordinary block briefly flaps public readiness.
            if next <= status.head_height
                && status.head_height.saturating_sub(next).saturating_add(1) > max_blocks
            {
                state.readiness = IndexReadiness::CatchingUp;
            }
        }
        let mut ingested = 0u64;
        let mut rolled_back = 0u64;
        'fetch: while next <= status.head_height && ingested < max_blocks {
            let available = status.head_height.saturating_sub(next).saturating_add(1);
            let remaining = max_blocks.saturating_sub(ingested).min(available).min(64);
            let limit = u32::try_from(remaining)
                .map_err(|_| IndexerError::Source("block range overflow".into()))?;
            let blocks = source.blocks_from(next, limit)?;
            if blocks.is_empty() {
                break; // source lag: retry on the next pass, same height
            }
            if blocks.len() > limit as usize {
                return Err(IndexerError::Source("oversized block range".into()));
            }
            for block in blocks {
                if block.height != next
                    || !is_hash(&block.hash)
                    || !is_hash(&block.parent_hash)
                    || block.txids.iter().any(|txid| !is_hash(txid))
                {
                    return Err(IndexerError::Source(format!(
                        "malformed block frame at height {next}"
                    )));
                }
                let (tip_height, tip_hash) = {
                    let (height, hash) = cp.tip()?;
                    (height, hash.to_owned())
                };
                debug_assert_eq!(tip_height.saturating_add(1), next);
                // The protocol identity's `genesis_hash` commits the genesis
                // body, while block 1 links to the canonical genesis header
                // hash. Anchor a fresh checkpoint from that authenticated
                // first block instead of assuming those distinct hashes match.
                if block.height == 1 && tip_height == 0 && cp.generation == 0 {
                    cp.recent[0].hash.clone_from(&block.parent_hash);
                }
                if block.parent_hash != tip_hash {
                    // Fork: find the deepest retained ancestor still on the
                    // source's chain, then delete exactly the orphaned rows.
                    let ancestor = find_ancestor(source, &cp)?;
                    rolled_back = rolled_back.saturating_add(tip_height.saturating_sub(ancestor));
                    self.rollback_to(ancestor, &mut cp).await;
                    next = ancestor.saturating_add(1);
                    continue 'fetch;
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
        }
        let justified_height = status
            .justified_epoch
            .checked_mul(EPOCH_LENGTH)
            .ok_or_else(|| IndexerError::Source("justified checkpoint height overflow".into()))?;
        let finalized_height = status
            .finalized_epoch
            .checked_mul(EPOCH_LENGTH)
            .ok_or_else(|| IndexerError::Source("finalized checkpoint height overflow".into()))?;
        if justified_height > status.head_height
            || finalized_height > justified_height
            || !is_hash(&status.justified_hash)
            || !is_hash(&status.finalized_hash)
        {
            return Err(IndexerError::Source("malformed finality checkpoint".into()));
        }
        self.ingest_head(
            identity,
            crate::HeadKind::Justified,
            ChainPoint {
                height: justified_height.to_string(),
                hash: status.justified_hash,
                state_root: ZERO_HASH.into(),
            },
        )
        .await?;
        self.ingest_head(
            identity,
            crate::HeadKind::Finalized,
            ChainPoint {
                height: finalized_height.to_string(),
                hash: status.finalized_hash,
                state_root: ZERO_HASH.into(),
            },
        )
        .await?;
        cp.next_height = next.to_string();
        if ingested > 0 || rolled_back > 0 || cp.generation == 0 {
            self.store_generation(&mut cp).await?;
        }
        {
            let mut state = self.inner.write().await;
            state.generation = cp.generation;
            state.last_sync_unix_ms = crate::unix_time_ms();
            state.readiness = if next > status.head_height {
                IndexReadiness::Ready
            } else {
                IndexReadiness::CatchingUp
            };
        }
        Ok(SyncReport {
            ingested,
            rolled_back,
            next_height: next,
        })
    }

    fn load_checkpoint(&self) -> Result<Checkpoint> {
        if let Some(generation) = load_latest_generation(&self.root, &self.identity)? {
            let checkpoint = generation.checkpoint;
            if checkpoint.schema != CHECKPOINT_SCHEMA
                || checkpoint.identity != self.identity
                || checkpoint.recent.is_empty()
            {
                return Err(IndexerError::StateDiverged);
            }
            return Ok(checkpoint);
        }
        Ok(Checkpoint {
            schema: CHECKPOINT_SCHEMA.into(),
            identity: self.identity.clone(),
            next_height: "1".into(),
            recent: vec![RecentPoint {
                height: "0".into(),
                hash: self.identity.genesis_hash.clone(),
            }],
            generation: 0,
        })
    }

    async fn store_generation(&self, checkpoint: &mut Checkpoint) -> Result<()> {
        checkpoint.generation = checkpoint
            .generation
            .checked_add(1)
            .ok_or(IndexerError::StateDiverged)?;
        let state_guard = self.inner.read().await;
        let state = PersistedState::capture(&state_guard);
        drop(state_guard);
        durable_store_generation(
            &self.root,
            GenerationPayload {
                schema: GENERATION_SCHEMA.into(),
                identity: self.identity.clone(),
                sequence: checkpoint.generation,
                checkpoint: checkpoint.clone(),
                state,
            },
        )
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
#[derive(Clone)]
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
        let (code, body) = http_request(&self.addr, "GET", path, &self.token, None, self.timeout)?;
        let value = serde_json::from_str(&body)
            .map_err(|_| IndexerError::Source(format!("non-JSON body from {path}")))?;
        Ok((code, value))
    }

    /// Checks the configured node identity immediately before forwarding the
    /// caller's exact canonical submission envelope. This deliberately does
    /// not mutate index state: only the ingestion path owns indexed truth.
    pub fn forward_submission(
        &self,
        expected: &Identity,
        envelope: &[u8],
    ) -> std::result::Result<NodeSubmission, ForwardError> {
        let (status_code, status_body) = http_request(
            &self.addr,
            "GET",
            "/status",
            &self.token,
            None,
            self.timeout,
        )
        .map_err(|_| ForwardError::Unavailable)?;
        if status_code != 200 {
            return Err(ForwardError::Unavailable);
        }
        let status: Value =
            serde_json::from_str(&status_body).map_err(|_| ForwardError::MalformedResponse)?;
        let actual = Identity {
            chain_id: status["chain_id"]
                .as_str()
                .ok_or(ForwardError::MalformedResponse)?
                .to_owned(),
            genesis_hash: status["genesis_hash"]
                .as_str()
                .ok_or(ForwardError::MalformedResponse)?
                .to_owned(),
            api_version: crate::API_VERSION.to_owned(),
        };
        expected
            .require(&actual)
            .map_err(|_| ForwardError::WrongProtocolIdentity)?;

        let (code, body) = http_request(
            &self.addr,
            "POST",
            "/submit_tx",
            &self.token,
            Some(envelope),
            self.timeout,
        )
        .map_err(|_| ForwardError::Unavailable)?;
        if code != 200 && code != 202 {
            let (node_code, detail) = node_error(&body);
            return Err(ForwardError::Refused {
                status: code,
                node_code,
                detail,
            });
        }
        let value: Value =
            serde_json::from_str(&body).map_err(|_| ForwardError::MalformedResponse)?;
        if value["accepted"].as_bool() != Some(true) {
            return Err(ForwardError::MalformedResponse);
        }
        let txid = value["txid"]
            .as_str()
            .filter(|value| is_hash(value))
            .ok_or(ForwardError::MalformedResponse)?
            .to_owned();
        Ok(NodeSubmission { txid })
    }

    /// Identity-gated non-mutating transaction simulation. The node executes
    /// the exact envelope against a discardable overlay and returns its
    /// predicted receipt without mempool insertion or state mutation.
    pub fn forward_simulation(
        &self,
        expected: &Identity,
        envelope: &[u8],
    ) -> std::result::Result<Value, ForwardError> {
        let (status_code, status_body) = http_request(
            &self.addr,
            "GET",
            "/status",
            &self.token,
            None,
            self.timeout,
        )
        .map_err(|_| ForwardError::Unavailable)?;
        if status_code != 200 {
            return Err(ForwardError::Unavailable);
        }
        let status: Value =
            serde_json::from_str(&status_body).map_err(|_| ForwardError::MalformedResponse)?;
        let actual = Identity {
            chain_id: status["chain_id"]
                .as_str()
                .ok_or(ForwardError::MalformedResponse)?
                .to_owned(),
            genesis_hash: status["genesis_hash"]
                .as_str()
                .ok_or(ForwardError::MalformedResponse)?
                .to_owned(),
            api_version: crate::API_VERSION.to_owned(),
        };
        expected
            .require(&actual)
            .map_err(|_| ForwardError::WrongProtocolIdentity)?;
        let (code, body) = http_request(
            &self.addr,
            "POST",
            "/simulate_tx",
            &self.token,
            Some(envelope),
            self.timeout,
        )
        .map_err(|_| ForwardError::Unavailable)?;
        if code != 200 {
            let (node_code, detail) = node_error(&body);
            return Err(ForwardError::Refused {
                status: code,
                node_code,
                detail,
            });
        }
        serde_json::from_str(&body).map_err(|_| ForwardError::MalformedResponse)
    }

    /// Identity-gated read-through for consensus-owned application state.
    /// The indexer never fabricates market records from incomplete events.
    pub fn forward_query(
        &self,
        expected: &Identity,
        path: &str,
    ) -> std::result::Result<Value, ForwardError> {
        let (status_code, status_body) = http_request(
            &self.addr,
            "GET",
            "/status",
            &self.token,
            None,
            self.timeout,
        )
        .map_err(|_| ForwardError::Unavailable)?;
        if status_code != 200 {
            return Err(ForwardError::Unavailable);
        }
        let status: Value =
            serde_json::from_str(&status_body).map_err(|_| ForwardError::MalformedResponse)?;
        let actual = Identity {
            chain_id: status["chain_id"]
                .as_str()
                .ok_or(ForwardError::MalformedResponse)?
                .to_owned(),
            genesis_hash: status["genesis_hash"]
                .as_str()
                .ok_or(ForwardError::MalformedResponse)?
                .to_owned(),
            api_version: crate::API_VERSION.to_owned(),
        };
        expected
            .require(&actual)
            .map_err(|_| ForwardError::WrongProtocolIdentity)?;
        let (code, body) = http_request(&self.addr, "GET", path, &self.token, None, self.timeout)
            .map_err(|_| ForwardError::Unavailable)?;
        if code != 200 {
            let (node_code, detail) = node_error(&body);
            return Err(ForwardError::Refused {
                status: code,
                node_code,
                detail,
            });
        }
        serde_json::from_str(&body).map_err(|_| ForwardError::MalformedResponse)
    }
}

/// Successful noosd protocol admission. The public API exposes this txid but
/// does not claim an indexed mempool state until ingestion observes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSubmission {
    pub txid: String,
}

/// Fail-closed forwarding outcomes safe to translate to the public API. No
/// variant contains the configured bearer token or transaction bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardError {
    Unavailable,
    WrongProtocolIdentity,
    Refused {
        status: u16,
        node_code: String,
        detail: String,
    },
    MalformedResponse,
}

fn decode_node_block(value: &Value) -> Result<NodeBlock> {
    let txids = value["txids"]
        .as_array()
        .ok_or_else(|| IndexerError::Source("block without txids".into()))?
        .iter()
        .map(|txid| {
            txid.as_str()
                .map(str::to_owned)
                .ok_or_else(|| IndexerError::Source("non-string txid".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(NodeBlock {
        hash: str_field(value, "hash")?,
        height: u64_field(value, "height")?,
        slot: u64_field(value, "slot")?,
        timestamp_ms: u64_field(value, "timestamp_ms")?,
        parent_hash: str_field(value, "parent_hash")?,
        txids,
    })
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
            justified_epoch: u64_field(&v["justified"], "epoch")?,
            justified_hash: str_field(&v["justified"], "hash")?,
            finalized_epoch: u64_field(&v["finalized"], "epoch")?,
            finalized_hash: str_field(&v["finalized"], "hash")?,
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
        Ok(Some(decode_node_block(&v)?))
    }

    fn blocks_from(&mut self, start: u64, limit: u32) -> Result<Vec<NodeBlock>> {
        if !(1..=64).contains(&limit) {
            return Err(IndexerError::Source(
                "block range limit must be 1..64".into(),
            ));
        }
        let (code, value) = self.get(&format!("/blocks/{start}/{limit}"))?;
        match code {
            200 => {}
            404 | 410 => return Ok(Vec::new()),
            other => {
                return Err(IndexerError::Source(format!("/blocks returned {other}")));
            }
        }
        value["items"]
            .as_array()
            .ok_or_else(|| IndexerError::Source("block range without items".into()))?
            .iter()
            .map(decode_node_block)
            .collect()
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

fn node_error(body: &str) -> (String, String) {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return (
            "malformed_node_error".into(),
            "node refused submission".into(),
        );
    };
    let error = &value["error"];
    let code = error["code"]
        .as_str()
        .filter(|value| value.len() <= 128)
        .unwrap_or("unknown_node_error")
        .to_owned();
    let detail = error["detail"]
        .as_str()
        .filter(|value| value.len() <= 512)
        .unwrap_or("node refused submission")
        .to_owned();
    (code, detail)
}

fn http_request(
    endpoint: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, String)> {
    let source_err = |e: std::io::Error| IndexerError::Source(e.to_string());
    let addr = endpoint
        .strip_prefix("http://")
        .unwrap_or(endpoint)
        .trim_end_matches('/');
    if addr.is_empty()
        || addr.contains(['/', '\r', '\n'])
        || token.is_empty()
        || token.contains(['\r', '\n'])
    {
        return Err(IndexerError::Source(
            "invalid operator RPC configuration".into(),
        ));
    }
    let socket = addr
        .to_socket_addrs()
        .map_err(source_err)?
        .next()
        .ok_or_else(|| IndexerError::Source("operator RPC did not resolve".into()))?;
    let mut stream = TcpStream::connect_timeout(&socket, timeout).map_err(source_err)?;
    stream.set_read_timeout(Some(timeout)).map_err(source_err)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(source_err)?;
    let content_length = body.map_or(0, <[u8]>::len);
    let request = format!(
        "{method} {path} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {content_length}\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).map_err(source_err)?;
    if let Some(body) = body {
        stream.write_all(body).map_err(source_err)?;
    }

    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).map_err(source_err)?;
        if read == 0 {
            return Err(IndexerError::Source("truncated HTTP response".into()));
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(end) = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .and_then(|position| position.checked_add(4))
        {
            break end;
        }
        if raw.len() > MAX_OPERATOR_HEADER_BYTES {
            return Err(IndexerError::Source(
                "operator response headers too large".into(),
            ));
        }
    };
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| IndexerError::Source("malformed HTTP response headers".into()))?;
    let code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| IndexerError::Source("malformed status line".into()))?;
    let response_length = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    if response_length.is_some_and(|length| length > MAX_OPERATOR_RESPONSE_BYTES) {
        return Err(IndexerError::Source(
            "operator response body too large".into(),
        ));
    }
    let target = response_length.map(|length| header_end.saturating_add(length));
    loop {
        if target.is_some_and(|target| raw.len() >= target) {
            break;
        }
        let read = stream.read(&mut chunk).map_err(source_err)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len().saturating_sub(header_end) > MAX_OPERATOR_RESPONSE_BYTES {
            return Err(IndexerError::Source(
                "operator response body too large".into(),
            ));
        }
    }
    if target.is_some_and(|target| raw.len() < target) {
        return Err(IndexerError::Source("truncated HTTP response body".into()));
    }
    let body_end = target.unwrap_or(raw.len());
    let body = std::str::from_utf8(&raw[header_end..body_end])
        .map_err(|_| IndexerError::Source("non-UTF-8 operator response".into()))?;
    Ok((code, body.to_owned()))
}
