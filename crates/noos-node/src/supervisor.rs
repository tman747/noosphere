//! The bounded task topology (plan §7.5; ch01 §3.1; node-v1.md §7).
//!
//! ```text
//! noosd supervisor
//! ├── consensus   single-writer task: HeaderDag + LumenLedger + finality
//! │               (NodeCore) — ALL mutations flow through its inbox
//! ├── store       dedicated task owning noos_store::Store; consensus
//! │               reaches it only through the bounded StoreClient channel
//! ├── rpc         localhost operator RPC (never shares consensus state;
//! │               talks over the same bounded inbox)
//! ├── p2p/sync   async noos-p2p event loop; bounded consensus/store bridge
//! └── pool        bounded proof-check verdict pool (crate::pool)
//! ```
//!
//! Channels are bounded (`sync_channel`); a full inbox applies
//! backpressure, never unbounded growth. A consensus-task panic is
//! CONTAINED: the task catches the unwind, drops the poisoned in-memory
//! state, and rebuilds it from the durable store (the same replay as a
//! process restart) — the persist-before-vote barrier guarantees nothing
//! unpersisted was ever emitted, so a crash can lose only unacked work,
//! never corrupt consensus state.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use noos_braid::{BlockHeaderV1, CheckpointRef, FinalityCertificateV1, MAX_FINALITY_CERTIFICATES};
use noos_codec::NoosDecode;
use noos_da::{encode_body, BodyDaClaimV1, ShardCandidateV1, BODY_TOTAL_SHARDS};
use noos_ground::GroundTicketV1;
use noos_lumen::objects::{
    AccountV1, AssetV1, BoundedList, ComputeJobV1, ComputeWorkerV1, DebtPositionV1,
    LendingMarketV1, LiquidityPositionV1, OracleFeedV1, OracleReportV1, PoolV1, PrivatePaymentV1,
    ReceiptV1, StableAssetV1, StableSafetyV1,
};
use noos_lumen::state::LumenRoots;
use noos_lumen::wwm::{FinalizedModelResolutionV1, ResolutionSelectorV1};
use noos_p2p::{
    BodyReplyV1, ChainIdentity, InboundItem, Multiaddr, P2pConfig, P2pEvent, P2pHandle, P2pNode,
};
use noos_store::WriteSet;
use noos_witness::vote::FinalityVoteV1;
use tokio::runtime::Handle;

use crate::consensus::{ImportOutcome, NodeConfig, NodeCore, NodeMode};
use crate::genesis::GenesisSpec;
use crate::mempool::AdmitError;
use crate::metrics::Metrics;
use crate::network::{decode_header_announce, decode_tx_push, NodeProtocolStore, P2pNetworkEdge};
use crate::store_port::{key_header, key_height, InProcStore, StorePort};
use crate::view::{BlockSummary, TxStatus, ViewLookup};
use crate::{Hash32, NodeError};

/// Bounded inbox capacities (node-v1.md §7.1).
pub const CONSENSUS_INBOX: usize = 1024;
pub const STORE_INBOX: usize = 64;
const STORE_PRIORITY_INBOX: usize = 16;
const STORE_PRIORITY_BURST: usize = 4;
/// Pending transactions are retried after queue pressure and peer reconnects.
/// Forty pushes/second stays below the default per-peer Lumen rate limit.
const TX_REGOSSIP_INTERVAL_MS: u64 = 100;
const TX_REGOSSIP_BATCH: usize = 4;
/// Full-node pull sync stays below the default eight-body-requests/second
/// peer limit, including low-latency LAN links where transport time is tiny.
const FULL_SYNC_BODY_REQUEST_PACING: Duration = Duration::from_millis(125);
/// Keep a range reply below the live store-backed server's request deadline.
/// Protocol peers may serve up to `MAX_RANGE_HEADERS`; the recovery client
/// deliberately uses smaller pages so one synchronous store lane cannot turn
/// a healthy peer into a repeated 25-second timeout.
const SYNC_RANGE_PAGE_HEADERS: u32 = 16;

const fn smaller_sync_range_page(current: u32) -> Option<u32> {
    if current <= 1 {
        None
    } else {
        Some(current / 2)
    }
}

// ---------------------------------------------------------------------------
// Store task
// ---------------------------------------------------------------------------

type Reply<T> = SyncSender<T>;

enum StoreMsg {
    Commit(Box<WriteSet>, Reply<Result<u64, String>>),
    PersistSafety(u16, Vec<u8>, Reply<Result<u64, String>>),
    Barrier(Reply<Result<(), String>>),
    SafetyRecords(u16, Reply<Result<Vec<Vec<u8>>, String>>),
    GetHeader(Vec<u8>, Reply<Result<Option<Vec<u8>>, String>>),
    GetIndex(Vec<u8>, Reply<Result<Option<Vec<u8>>, String>>),
    GetReceipt(Vec<u8>, Reply<Result<Option<Vec<u8>>, String>>),
    GetBlob(Hash32, Reply<Result<Option<Vec<u8>>, String>>),
    ProtocolHeaderRange(u64, u32, Reply<(Vec<Vec<u8>>, bool)>),
    ScanIndices(
        Vec<u8>,
        Reply<Result<crate::store_port::ScanEntries, String>>,
    ),
    Roots(Reply<Result<Option<LumenRoots>, String>>),
    CreateSnapshot(Reply<Result<u64, String>>),
    AppliedSeq(Reply<u64>),
    Shutdown,
}

/// Channel-backed [`StorePort`]: the consensus task's view of the store
/// task. Cloneable; every call is one bounded round trip.
#[derive(Clone)]
pub struct StoreClient {
    tx: SyncSender<StoreMsg>,
    priority_tx: SyncSender<StoreMsg>,
}

fn store_err(msg: String) -> NodeError {
    NodeError::BarrierFailed(msg)
}

impl StoreClient {
    fn round_trip<T>(&self, build: impl FnOnce(Reply<T>) -> StoreMsg) -> Result<T, NodeError> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(build(reply_tx))
            .map_err(|_| NodeError::ChannelClosed("store inbox"))?;
        reply_rx
            .recv()
            .map_err(|_| NodeError::ChannelClosed("store reply"))
    }

    fn priority_round_trip<T>(
        &self,
        build: impl FnOnce(Reply<T>) -> StoreMsg,
    ) -> Result<T, NodeError> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.priority_tx
            .send(build(reply_tx))
            .map_err(|_| NodeError::ChannelClosed("priority store inbox"))?;
        reply_rx
            .recv()
            .map_err(|_| NodeError::ChannelClosed("priority store reply"))
    }

    pub(crate) fn protocol_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.priority_round_trip(|r| StoreMsg::GetHeader(key.to_vec(), r))?
            .map_err(store_err)
    }

    pub(crate) fn protocol_blob(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, NodeError> {
        self.priority_round_trip(|r| StoreMsg::GetBlob(*hash, r))?
            .map_err(store_err)
    }

    pub(crate) fn protocol_header_range(
        &self,
        start_height: u64,
        max_headers: u32,
    ) -> Result<(Vec<Vec<u8>>, bool), NodeError> {
        self.priority_round_trip(|r| StoreMsg::ProtocolHeaderRange(start_height, max_headers, r))
    }
}

impl StorePort for StoreClient {
    fn commit(&mut self, ws: &WriteSet) -> Result<u64, NodeError> {
        self.round_trip(|r| StoreMsg::Commit(Box::new(ws.clone()), r))?
            .map_err(store_err)
    }
    fn persist_safety(&mut self, kind: u16, payload: &[u8]) -> Result<u64, NodeError> {
        self.round_trip(|r| StoreMsg::PersistSafety(kind, payload.to_vec(), r))?
            .map_err(store_err)
    }
    fn barrier(&mut self) -> Result<(), NodeError> {
        self.round_trip(StoreMsg::Barrier)?.map_err(store_err)
    }
    fn safety_records(&self, kind: u16) -> Result<Vec<Vec<u8>>, NodeError> {
        self.round_trip(|r| StoreMsg::SafetyRecords(kind, r))?
            .map_err(store_err)
    }
    fn get_header(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.round_trip(|r| StoreMsg::GetHeader(key.to_vec(), r))?
            .map_err(store_err)
    }
    fn get_index(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.round_trip(|r| StoreMsg::GetIndex(key.to_vec(), r))?
            .map_err(store_err)
    }
    fn get_receipt(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NodeError> {
        self.round_trip(|r| StoreMsg::GetReceipt(key.to_vec(), r))?
            .map_err(store_err)
    }
    fn get_blob(&self, hash: &Hash32) -> Result<Option<Vec<u8>>, NodeError> {
        self.round_trip(|r| StoreMsg::GetBlob(*hash, r))?
            .map_err(store_err)
    }
    fn scan_indices(&self, prefix: &[u8]) -> Result<crate::store_port::ScanEntries, NodeError> {
        self.round_trip(|r| StoreMsg::ScanIndices(prefix.to_vec(), r))?
            .map_err(store_err)
    }
    fn roots(&self) -> Result<Option<LumenRoots>, NodeError> {
        self.round_trip(StoreMsg::Roots)?.map_err(store_err)
    }
    fn create_snapshot(&mut self) -> Result<u64, NodeError> {
        self.round_trip(StoreMsg::CreateSnapshot)?
            .map_err(store_err)
    }
    fn applied_seq(&self) -> u64 {
        self.round_trip(StoreMsg::AppliedSeq).unwrap_or(0)
    }
}

fn read_protocol_header_range(
    store: &InProcStore,
    start_height: u64,
    max_headers: u32,
) -> (Vec<Vec<u8>>, bool) {
    let mut headers = Vec::new();
    for offset in 0..u64::from(max_headers) {
        let Some(height) = start_height.checked_add(offset) else {
            break;
        };
        let Ok(Some(hash)) = store.get_index(&key_height(height)) else {
            break;
        };
        let Ok(hash) = <[u8; 32]>::try_from(hash.as_slice()) else {
            break;
        };
        let Ok(Some(header)) = store.get_header(&key_header(&hash)) else {
            break;
        };
        headers.push(header);
    }
    let next = start_height.saturating_add(headers.len() as u64);
    let more = store.get_index(&key_height(next)).ok().flatten().is_some();
    (headers, more)
}

fn recv_store_msg(
    rx: &Receiver<StoreMsg>,
    priority_rx: &Receiver<StoreMsg>,
    priority_streak: &mut usize,
) -> Option<StoreMsg> {
    loop {
        if *priority_streak < STORE_PRIORITY_BURST {
            match priority_rx.try_recv() {
                Ok(msg) => {
                    *priority_streak += 1;
                    return Some(msg);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
            }
        }
        match rx.try_recv() {
            Ok(msg) => {
                *priority_streak = 0;
                return Some(msg);
            }
            Err(TryRecvError::Disconnected) => return priority_rx.try_recv().ok(),
            Err(TryRecvError::Empty) => {}
        }
        match priority_rx.try_recv() {
            Ok(msg) => {
                *priority_streak = priority_streak.saturating_add(1);
                return Some(msg);
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
        }
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(msg) => {
                *priority_streak = 0;
                return Some(msg);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return priority_rx.try_recv().ok();
            }
        }
    }
}

fn store_task(mut store: InProcStore, rx: &Receiver<StoreMsg>, priority_rx: &Receiver<StoreMsg>) {
    let mut priority_streak = 0;
    while let Some(msg) = recv_store_msg(rx, priority_rx, &mut priority_streak) {
        match msg {
            StoreMsg::Commit(ws, reply) => {
                let _ = reply.send(store.commit(&ws).map_err(|e| e.to_string()));
            }
            StoreMsg::PersistSafety(kind, payload, reply) => {
                let _ = reply.send(
                    store
                        .persist_safety(kind, &payload)
                        .map_err(|e| e.to_string()),
                );
            }
            StoreMsg::Barrier(reply) => {
                let _ = reply.send(store.barrier().map_err(|e| e.to_string()));
            }
            StoreMsg::SafetyRecords(kind, reply) => {
                let _ = reply.send(store.safety_records(kind).map_err(|e| e.to_string()));
            }
            StoreMsg::GetHeader(key, reply) => {
                let _ = reply.send(store.get_header(&key).map_err(|e| e.to_string()));
            }
            StoreMsg::GetIndex(key, reply) => {
                let _ = reply.send(store.get_index(&key).map_err(|e| e.to_string()));
            }
            StoreMsg::GetReceipt(key, reply) => {
                let _ = reply.send(store.get_receipt(&key).map_err(|e| e.to_string()));
            }
            StoreMsg::GetBlob(hash, reply) => {
                let _ = reply.send(store.get_blob(&hash).map_err(|e| e.to_string()));
            }
            StoreMsg::ProtocolHeaderRange(start_height, max_headers, reply) => {
                let _ = reply.send(read_protocol_header_range(
                    &store,
                    start_height,
                    max_headers,
                ));
            }
            StoreMsg::ScanIndices(prefix, reply) => {
                let _ = reply.send(store.scan_indices(&prefix).map_err(|e| e.to_string()));
            }
            StoreMsg::Roots(reply) => {
                let _ = reply.send(store.roots().map_err(|e| e.to_string()));
            }
            StoreMsg::CreateSnapshot(reply) => {
                let _ = reply.send(store.create_snapshot().map_err(|e| e.to_string()));
            }
            StoreMsg::AppliedSeq(reply) => {
                let _ = reply.send(store.applied_seq());
            }
            StoreMsg::Shutdown => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Consensus task
// ---------------------------------------------------------------------------

/// Point-in-time status snapshot (the RPC `/status` payload source).
#[derive(Debug, Clone)]
pub struct StatusSnapshot {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub head_height: u64,
    pub head_hash: Hash32,
    pub justified: CheckpointRef,
    pub finalized: CheckpointRef,
    pub pending_votes: usize,
    pub pending_certificates: usize,
    pub inbound_votes_accepted: u64,
    pub inbound_votes_rejected: u64,
    pub mempool_txs: usize,
    pub mempool_bytes: usize,
    pub observer: bool,
}

/// Block lookup key for the RPC.
#[derive(Debug, Clone)]
pub enum BlockId {
    Height(u64),
    Hash(Hash32),
}

/// Consensus-task inbox messages.
pub enum ConsensusMsg {
    SubmitTx {
        tx_bytes: Vec<u8>,
        wit_bytes: Vec<u8>,
        source: u64,
        reply: Reply<Result<Hash32, AdmitError>>,
    },
    SimulateTx {
        tx_bytes: Vec<u8>,
        wit_bytes: Vec<u8>,
        reply: Reply<Result<noos_lumen::state::SimulationOutcome, noos_lumen::state::RejectReason>>,
    },
    ImportBlock {
        header: Box<BlockHeaderV1>,
        ticket: GroundTicketV1,
        claim: BodyDaClaimV1,
        shards: Vec<ShardCandidateV1>,
        regossip: bool,
        reply: Reply<Result<ImportOutcome, String>>,
    },
    ImportHeader {
        header: Box<BlockHeaderV1>,
        ticket: GroundTicketV1,
        certificates: BoundedList<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>,
        reply: Reply<Result<ImportOutcome, String>>,
    },
    ProduceBlock {
        reply: Reply<Result<Hash32, String>>,
    },
    QueueCertificate {
        cert: Box<FinalityCertificateV1>,
        reply: Reply<Result<(), String>>,
    },
    InboundVote {
        vote: Box<FinalityVoteV1>,
    },
    /// Devnet fixture finality driver tick (TEST NETWORKS ONLY; no-op
    /// unless `NodeConfig::devnet_fixture_finality`).
    DevnetFinalityTick {
        reply: Reply<Result<bool, String>>,
    },
    /// One independently operated fixture witness vote. The core persists its
    /// anti-double-vote record before the p2p task can observe the result.
    DevnetWitnessVoteTick {
        witness_index: usize,
        reply: Reply<Result<bool, String>>,
    },
    ResolveModel {
        selector: ResolutionSelectorV1,
        freshness_bound: u64,
        reply: Reply<Result<FinalizedModelResolutionV1, String>>,
    },
    GetWwmRecord {
        kind: noos_lumen::wwm::WwmLeafKind,
        id: Hash32,
        reply: Reply<Result<(u64, Hash32, noos_lumen::wwm::ResolutionProofV1), String>>,
    },
    Status {
        reply: Reply<StatusSnapshot>,
    },
    SyncHead {
        reply: Reply<(u64, Hash32)>,
    },
    Mode {
        reply: Reply<NodeMode>,
    },
    GetBlock {
        id: BlockId,
        reply: Reply<ViewLookup<BlockSummary>>,
    },
    GetReceipt {
        txid: Hash32,
        reply: Reply<ViewLookup<(TxStatus, Option<ReceiptV1>)>>,
    },
    GetAssets {
        reply: Reply<Vec<AssetV1>>,
    },
    GetPools {
        reply: Reply<Vec<PoolV1>>,
    },
    GetLiquidityPositions {
        reply: Reply<Vec<LiquidityPositionV1>>,
    },
    GetOracleFeeds {
        reply: Reply<Vec<OracleFeedV1>>,
    },
    GetOracleReports {
        reply: Reply<Vec<OracleReportV1>>,
    },
    GetLendingMarkets {
        reply: Reply<Vec<LendingMarketV1>>,
    },
    GetStableAssets {
        reply: Reply<Vec<StableAssetV1>>,
    },
    GetStableSafety {
        reply: Reply<Vec<StableSafetyV1>>,
    },
    GetDebtPositions {
        reply: Reply<Vec<DebtPositionV1>>,
    },
    GetPrivatePayments {
        reply: Reply<Vec<PrivatePaymentV1>>,
    },
    GetComputeWorkers {
        reply: Reply<Vec<ComputeWorkerV1>>,
    },
    GetComputeJobs {
        reply: Reply<Vec<ComputeJobV1>>,
    },
    GetAccount {
        account: Hash32,
        reply: Reply<Option<AccountV1>>,
    },
    GetBalance {
        account: Hash32,
        asset: Hash32,
        reply: Reply<u128>,
    },
    SetNow(u64),
    /// Test hook: panic the consensus task to prove containment.
    InjectCrash,
    Shutdown,
}

/// Outbound gossip from the consensus task to the p2p edge. Best-effort:
/// a full channel drops the push (peers recover via the pull sync path).
pub enum OutboundGossip {
    Header(Box<BlockHeaderV1>, GroundTicketV1),
    Tx(Vec<u8>, Vec<u8>),
    Vote(FinalityVoteV1),
}

fn status_of<P: StorePort>(
    core: &NodeCore<P>,
    observer: bool,
    inbound_votes_accepted: u64,
    inbound_votes_rejected: u64,
) -> StatusSnapshot {
    let (head_height, head_hash) = core.head();
    StatusSnapshot {
        chain_id: core.chain_id(),
        genesis_hash: core.genesis_hash(),
        head_height,
        head_hash,
        justified: core.justified(),
        finalized: core.finalized(),
        pending_votes: core.pending_vote_count(),
        pending_certificates: core.pending_certificate_count(),
        inbound_votes_accepted,
        inbound_votes_rejected,
        mempool_txs: core.mempool.len(),
        mempool_bytes: core.mempool.total_bytes(),
        observer,
    }
}

/// Runs the message loop until Shutdown; panics propagate to the
/// containment wrapper.
fn core_loop<P: StorePort>(
    core: &mut NodeCore<P>,
    observer: bool,
    rx: &Receiver<ConsensusMsg>,
    gossip: Option<&tokio::sync::mpsc::Sender<OutboundGossip>>,
) -> bool {
    let mut inbound_votes_accepted = 0_u64;
    let mut inbound_votes_rejected = 0_u64;
    let mut last_vote_error: Option<String> = None;
    let mut last_tx_regossip_ms = 0_u64;
    let mut tx_regossip_cursor = 0_usize;
    while let Ok(msg) = rx.recv() {
        match msg {
            ConsensusMsg::SubmitTx {
                tx_bytes,
                wit_bytes,
                source,
                reply,
            } => {
                let result = core.submit_tx(&tx_bytes, &wit_bytes, source);
                if result.is_ok() {
                    if let Some(gossip) = gossip {
                        let _ = gossip.try_send(OutboundGossip::Tx(tx_bytes, wit_bytes));
                    }
                }
                let _ = reply.send(result);
            }
            ConsensusMsg::SimulateTx {
                tx_bytes,
                wit_bytes,
                reply,
            } => {
                let _ = reply.send(core.simulate_tx(&tx_bytes, &wit_bytes));
            }
            ConsensusMsg::ImportBlock {
                header,
                ticket,
                claim,
                shards,
                regossip,
                reply,
            } => {
                let result = core
                    .import_block(&header, &ticket, &claim, &shards)
                    .map_err(|e| e.to_string());
                // Live next-block gossip may cross one more hop. Pull recovery
                // must not amplify historical pages into rate-limited gossip.
                if regossip {
                    if let (Ok(ImportOutcome::Executed { .. }), Some(gossip)) = (&result, gossip) {
                        let _ = gossip.try_send(OutboundGossip::Header(header, ticket));
                    }
                }
                let _ = reply.send(result);
            }
            ConsensusMsg::ImportHeader {
                header,
                ticket,
                certificates,
                reply,
            } => {
                let result = core
                    .import_header_for_light_sync(&header, &ticket, &certificates)
                    .map_err(|error| error.to_string());
                let _ = reply.send(result);
            }
            ConsensusMsg::ProduceBlock { reply } => {
                let result = core.produce_block().map_err(|e| e.to_string());
                let result = match result {
                    Ok(produced) => {
                        if let Some(gossip) = gossip {
                            let _ = gossip.try_send(OutboundGossip::Header(
                                Box::new(produced.header),
                                produced.ticket,
                            ));
                        }
                        Ok(produced.hash)
                    }
                    Err(e) => Err(e),
                };
                let _ = reply.send(result);
            }
            ConsensusMsg::QueueCertificate { cert, reply } => {
                let _ = reply.send(core.queue_certificate(*cert).map_err(|e| e.to_string()));
            }
            ConsensusMsg::InboundVote { vote } => match core.ingest_network_vote(*vote) {
                Ok(()) => inbound_votes_accepted = inbound_votes_accepted.saturating_add(1),
                Err(error) => {
                    inbound_votes_rejected = inbound_votes_rejected.saturating_add(1);
                    let message = error.to_string();
                    if last_vote_error.as_deref() != Some(message.as_str()) {
                        eprintln!("inbound finality vote rejected: {message}");
                        last_vote_error = Some(message);
                    }
                }
            },
            ConsensusMsg::DevnetFinalityTick { reply } => {
                let _ = reply.send(core.devnet_finality_tick().map_err(|e| e.to_string()));
            }
            ConsensusMsg::DevnetWitnessVoteTick {
                witness_index,
                reply,
            } => {
                let result = core
                    .devnet_witness_vote_tick(witness_index)
                    .map_err(|error| error.to_string());
                if let (Ok(votes), Some(gossip)) = (&result, gossip) {
                    for vote in votes {
                        let _ = gossip.try_send(OutboundGossip::Vote(vote.clone()));
                    }
                }
                let _ = reply.send(result.map(|votes| !votes.is_empty()));
            }
            ConsensusMsg::ResolveModel {
                selector,
                freshness_bound,
                reply,
            } => {
                let _ = reply.send(
                    core.finalized_model_resolution(selector, freshness_bound)
                        .map_err(|error| error.to_string()),
                );
            }
            ConsensusMsg::GetWwmRecord { kind, id, reply } => {
                let _ = reply.send(
                    core.finalized_wwm_record(kind, id)
                        .map_err(|error| error.to_string()),
                );
            }
            ConsensusMsg::Status { reply } => {
                let _ = reply.send(status_of(
                    core,
                    observer,
                    inbound_votes_accepted,
                    inbound_votes_rejected,
                ));
            }
            ConsensusMsg::SyncHead { reply } => {
                let _ = reply.send(core.sync_head());
            }
            ConsensusMsg::Mode { reply } => {
                let _ = reply.send(core.mode());
            }
            ConsensusMsg::GetBlock { id, reply } => {
                let lookup = match id {
                    BlockId::Height(h) => core.view.block_by_height(h),
                    BlockId::Hash(hash) => core.view.block_by_hash(&hash),
                };
                let _ = reply.send(match lookup {
                    ViewLookup::Found(b) => ViewLookup::Found(b.clone()),
                    ViewLookup::Pruned => ViewLookup::Pruned,
                    ViewLookup::NotFound => ViewLookup::NotFound,
                });
            }
            ConsensusMsg::GetReceipt { txid, reply } => {
                let lookup = match core.view.tx_status(&txid) {
                    ViewLookup::Found(status) => {
                        let receipt = match core.view.receipt(&txid) {
                            ViewLookup::Found(r) => Some(r.clone()),
                            _ => None,
                        };
                        ViewLookup::Found((status, receipt))
                    }
                    ViewLookup::Pruned => ViewLookup::Pruned,
                    ViewLookup::NotFound => ViewLookup::NotFound,
                };
                let _ = reply.send(lookup);
            }
            ConsensusMsg::GetAssets { reply } => {
                let _ = reply.send(core.ledger().assets());
            }
            ConsensusMsg::GetPools { reply } => {
                let _ = reply.send(core.ledger().pools());
            }
            ConsensusMsg::GetLiquidityPositions { reply } => {
                let _ = reply.send(core.ledger().liquidity_positions());
            }
            ConsensusMsg::GetOracleFeeds { reply } => {
                let _ = reply.send(core.ledger().oracle_feeds());
            }
            ConsensusMsg::GetOracleReports { reply } => {
                let _ = reply.send(core.ledger().oracle_reports());
            }
            ConsensusMsg::GetLendingMarkets { reply } => {
                let _ = reply.send(core.ledger().lending_markets());
            }
            ConsensusMsg::GetStableAssets { reply } => {
                let _ = reply.send(core.ledger().stable_assets());
            }
            ConsensusMsg::GetStableSafety { reply } => {
                let _ = reply.send(core.ledger().stable_safeties());
            }
            ConsensusMsg::GetDebtPositions { reply } => {
                let _ = reply.send(core.ledger().debt_positions());
            }
            ConsensusMsg::GetPrivatePayments { reply } => {
                let _ = reply.send(core.ledger().private_payments());
            }
            ConsensusMsg::GetComputeWorkers { reply } => {
                let _ = reply.send(core.ledger().compute_workers());
            }
            ConsensusMsg::GetComputeJobs { reply } => {
                let _ = reply.send(core.ledger().compute_jobs());
            }
            ConsensusMsg::GetAccount { account, reply } => {
                let _ = reply.send(core.ledger().get_account(&account));
            }
            ConsensusMsg::GetBalance {
                account,
                asset,
                reply,
            } => {
                let _ = reply.send(core.ledger().balance(&account, &asset));
            }
            ConsensusMsg::SetNow(t) => {
                core.set_now(t);
                if let Some(gossip) = gossip {
                    if t.saturating_sub(last_tx_regossip_ms) >= TX_REGOSSIP_INTERVAL_MS {
                        last_tx_regossip_ms = t;
                        for (tx_bytes, wit_bytes) in core
                            .mempool
                            .regossip_batch(&mut tx_regossip_cursor, TX_REGOSSIP_BATCH)
                        {
                            if gossip
                                .try_send(OutboundGossip::Tx(tx_bytes, wit_bytes))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            }
            ConsensusMsg::InjectCrash => panic!("injected consensus crash (containment test)"),
            ConsensusMsg::Shutdown => return true,
        }
    }
    true // inbox closed: orderly stop
}

async fn import_wire_block(
    consensus: &SyncSender<ConsensusMsg>,
    p2p: &P2pHandle,
    peer: noos_p2p::PeerId,
    announced: &[u8],
    regossip: bool,
) -> Result<ImportOutcome, String> {
    let (header, ticket) = decode_header_announce(announced)
        .map_err(|error| format!("decode header announce: {error:?}"))?;
    let BodyReplyV1::Body(body) = p2p
        .request_body(peer, header.body_da_root)
        .await
        .map_err(|error| format!("request body: {error}"))?
    else {
        return Err("body not found".to_owned());
    };
    // The blob lane serves the CANONICAL body encoding; the DA commitment
    // is over the padded DA form (ch01 §4.3 step 5) — re-derive it exactly.
    let body_v1 = noos_braid::BlockBodyV1::decode_canonical(&body.0)
        .map_err(|error| format!("decode canonical body: {error}"))?;
    let encoded = encode_body(&crate::roots::da_form_bytes(&body_v1))
        .map_err(|error| format!("encode DA body: {error}"))?;
    if encoded.shard_root().as_bytes() != &header.body_da_root {
        return Err("DA root mismatch".to_owned());
    }
    let mut shards = Vec::with_capacity(BODY_TOTAL_SHARDS);
    for index in 0..u32::try_from(BODY_TOTAL_SHARDS).unwrap_or(0) {
        shards.push(
            encoded
                .candidate(index)
                .map_err(|error| format!("build DA candidate: {error}"))?,
        );
    }
    let (reply, reply_rx) = sync_channel(1);
    // Pull sync is the recovery path for best-effort gossip. It must apply
    // backpressure and observe every result; dropping either silently loses
    // blocks once the bounded consensus inbox fills.
    consensus
        .send(ConsensusMsg::ImportBlock {
            header: Box::new(header),
            ticket,
            claim: *encoded.claim(),
            shards,
            regossip,
            reply,
        })
        .map_err(|_| "consensus inbox closed".to_owned())?;
    reply_rx
        .recv()
        .map_err(|_| "consensus reply closed".to_owned())?
}

async fn import_wire_header(
    consensus: &SyncSender<ConsensusMsg>,
    p2p: &P2pHandle,
    peer: noos_p2p::PeerId,
    announced: &[u8],
) -> Result<ImportOutcome, String> {
    let (header, ticket) = decode_header_announce(announced)
        .map_err(|error| format!("decode header announce: {error:?}"))?;
    let empty = BoundedList::<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>::default();
    let empty_root = crate::roots::body_cert_root(&empty)
        .map_err(|error| format!("empty certificate root: {error}"))?;
    let certificates = if header.finality_certificate_root == empty_root {
        empty
    } else {
        let BodyReplyV1::Body(body) = p2p
            .request_body(peer, header.body_da_root)
            .await
            .map_err(|error| format!("request certificate body: {error}"))?
        else {
            return Err("certificate body not found".to_owned());
        };
        noos_braid::BlockBodyV1::decode_canonical(&body.0)
            .map_err(|error| format!("decode certificate body: {error}"))?
            .finality_certificates
    };
    let (reply, reply_rx) = sync_channel(1);
    consensus
        .send(ConsensusMsg::ImportHeader {
            header: Box::new(header),
            ticket,
            certificates,
            reply,
        })
        .map_err(|_| "consensus inbox closed".to_owned())?;
    reply_rx
        .recv()
        .map_err(|_| "consensus reply closed".to_owned())?
}

fn consensus_mode(consensus: &SyncSender<ConsensusMsg>) -> Option<NodeMode> {
    let (reply, reply_rx) = sync_channel(1);
    consensus.send(ConsensusMsg::Mode { reply }).ok()?;
    reply_rx.recv().ok()
}

fn consensus_sync_head(consensus: &SyncSender<ConsensusMsg>) -> Option<(u64, Hash32)> {
    let (reply, reply_rx) = sync_channel(1);
    consensus.send(ConsensusMsg::SyncHead { reply }).ok()?;
    reply_rx.recv().ok()
}

async fn sync_ready_peer(
    consensus: &SyncSender<ConsensusMsg>,
    p2p: &P2pHandle,
    edge: &P2pNetworkEdge,
    peer: noos_p2p::PeerId,
) {
    let Some(mode) = consensus_mode(consensus) else {
        return;
    };
    let mut page_headers = SYNC_RANGE_PAGE_HEADERS;
    'sync: loop {
        let Some(before) = consensus_sync_head(consensus) else {
            return;
        };
        let Some(start_height) = before.0.checked_add(1) else {
            return;
        };
        let range = match p2p.request_range(peer, start_height, page_headers).await {
            Ok(range) => range,
            Err(error) => {
                if !edge.is_peer_ready(&peer) {
                    eprintln!(
                        "range-sync peer unavailable after request failure for {peer} \
                         at height {start_height}: {error}"
                    );
                    return;
                }
                match smaller_sync_range_page(page_headers) {
                    Some(smaller_page) => {
                        eprintln!(
                            "range-sync page backoff for peer {peer} at height {start_height}: \
                             {error} (page_headers={page_headers}->{smaller_page})"
                        );
                        page_headers = smaller_page;
                        continue;
                    }
                    None => {
                        eprintln!(
                            "range-sync request failed from peer {peer} at height {start_height}: \
                             {error} (page_headers={page_headers})"
                        );
                        return;
                    }
                }
            }
        };
        if range.headers.0.is_empty() {
            return;
        }
        for header in range.headers.0 {
            let result = if mode == NodeMode::Light {
                import_wire_header(consensus, p2p, peer, &header.0).await
            } else {
                import_wire_block(consensus, p2p, peer, &header.0, false).await
            };
            if let Err(error) = result {
                // Gossip may execute this height while the range body is in
                // flight. Resume from the advanced cursor instead of
                // permanently abandoning an otherwise ready peer.
                if consensus_sync_head(consensus)
                    .is_some_and(|after_error| after_error.0 > before.0)
                {
                    continue 'sync;
                }
                let height = decode_header_announce(&header.0)
                    .ok()
                    .map(|(decoded, _)| decoded.height);
                eprintln!("range-sync import stopped from peer {peer} at {height:?}: {error}");
                return;
            }
            if mode != NodeMode::Light {
                tokio::time::sleep(FULL_SYNC_BODY_REQUEST_PACING).await;
            }
        }
        let Some(after) = consensus_sync_head(consensus) else {
            return;
        };
        if after.0 <= before.0 || !range.more.0 {
            return;
        }
    }
}

fn load_or_create_p2p_seed(data_dir: &Path) -> Result<[u8; 32], NodeError> {
    let path = data_dir.join("p2p-key");
    match std::fs::read(&path) {
        Ok(bytes) => {
            return <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| NodeError::Config("p2p-key must be exactly 32 bytes".into()))
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(NodeError::Config(format!("read p2p-key: {error}")));
        }
        Err(_) => {}
    }
    std::fs::create_dir_all(data_dir)
        .map_err(|error| NodeError::Config(format!("create data directory: {error}")))?;
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| NodeError::Config(format!("OS CSPRNG for p2p-key: {error}")))?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            file.write_all(&seed)
                .and_then(|()| file.sync_all())
                .map_err(|error| NodeError::Config(format!("persist p2p-key: {error}")))?;
            Ok(seed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = std::fs::read(&path).map_err(|read_error| {
                NodeError::Config(format!("read raced p2p-key: {read_error}"))
            })?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| NodeError::Config("p2p-key must be exactly 32 bytes".into()))
        }
        Err(error) => Err(NodeError::Config(format!("create p2p-key: {error}"))),
    }
}

fn enqueue_inbound_vote(consensus: &SyncSender<ConsensusMsg>, vote: FinalityVoteV1) -> bool {
    consensus
        .send(ConsensusMsg::InboundVote {
            vote: Box::new(vote),
        })
        .is_ok()
}

fn spawn_network(
    settings: crate::network::NetworkSettings,
    chain_id: Hash32,
    genesis_hash: Hash32,
    store: StoreClient,
    consensus: SyncSender<ConsensusMsg>,
    mut gossip_rx: tokio::sync::mpsc::Receiver<OutboundGossip>,
) -> Result<(tokio::sync::oneshot::Sender<()>, JoinHandle<()>, Multiaddr), NodeError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (startup_tx, startup_rx) = sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("noos-p2p".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = startup_tx.send(Err(format!("runtime: {error}")));
                    return;
                }
            };
            runtime.block_on(async move {
                let identity = ChainIdentity {
                    chain_id,
                    genesis_hash,
                    protocol_version: 2,
                };
                let Some(keypair_seed) = settings.keypair_seed else {
                    let _ = startup_tx.send(Err("missing p2p identity seed".into()));
                    return;
                };
                let mut config = P2pConfig::loopback(identity, keypair_seed);
                config.listen_addr = settings.listen;
                let protocol_store = Arc::new(NodeProtocolStore::new(store));
                let (p2p, mut events) = match P2pNode::spawn(config, protocol_store) {
                    Ok(pair) => pair,
                    Err(error) => {
                        let _ = startup_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let address = p2p.listen_addr().await;
                let _ = startup_tx.send(Ok(address));
                for peer in settings.bootstrap {
                    p2p.connect(peer);
                }

                let edge = P2pNetworkEdge::new(p2p.clone(), Handle::current());
                // Recovery pulls run independently so body downloads never
                // stall transaction, vote, or live-header gossip processing.
                let sync_edge = edge.clone();
                let sync_p2p = p2p.clone();
                let sync_consensus = consensus.clone();
                let sync_task = tokio::spawn(async move {
                    let mut sync_interval = tokio::time::interval(Duration::from_secs(5));
                    sync_interval
                        .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    let mut sync_cursor = 0_usize;
                    loop {
                        sync_interval.tick().await;
                        let peers = sync_edge.peers();
                        if peers.is_empty() {
                            continue;
                        }
                        let peer = peers[sync_cursor % peers.len()];
                        sync_cursor = sync_cursor.wrapping_add(1);
                        sync_ready_peer(&sync_consensus, &sync_p2p, &sync_edge, peer).await;
                    }
                });
                let mut shutdown_rx = shutdown_rx;
                let mut gossip_open = true;
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        gossip = gossip_rx.recv(), if gossip_open => {
                            match gossip {
                                Some(OutboundGossip::Header(header, ticket)) => {
                                    edge.push_header(&header, &ticket).await;
                                }
                                Some(OutboundGossip::Tx(tx_bytes, wit_bytes)) => {
                                    edge.push_tx(&tx_bytes, &wit_bytes).await;
                                }
                                Some(OutboundGossip::Vote(vote)) => {
                                    edge.push_vote(&vote).await;
                                }
                                None => gossip_open = false,
                            }
                        }
                        event = events.recv() => {
                            let Some(event) = event else { break };
                            match event {
                                P2pEvent::PeerReady { peer, .. } => {
                                    eprintln!("p2p peer ready: {peer}");
                                    edge.peer_ready(peer);
                                }
                                P2pEvent::PeerDisconnected { peer } => {
                                    eprintln!("p2p peer disconnected: {peer}");
                                    edge.peer_gone(&peer);
                                }
                                P2pEvent::HandshakeRejected {
                                    peer,
                                    code,
                                    by_remote,
                                } => {
                                    eprintln!(
                                        "p2p handshake rejected: peer={peer} code={code:?} by_remote={by_remote}"
                                    );
                                    edge.peer_gone(&peer);
                                }
                                P2pEvent::Inbound { peer, item } => match item {
                                    InboundItem::HeaderAnnounce { header } => {
                                        let heights = decode_header_announce(&header)
                                            .ok()
                                            .and_then(|(announced, _)| {
                                                consensus_sync_head(&consensus).map(|local| {
                                                    (announced.height, local.0)
                                                })
                                            });
                                        match heights {
                                            Some((announced, local)) if announced <= local => {}
                                            Some((announced, local))
                                                if local
                                                    .checked_add(1)
                                                    .is_some_and(|next| announced > next) => {}
                                            Some(_) => {
                                                if consensus_mode(&consensus)
                                                    == Some(NodeMode::Light)
                                                {
                                                    let _ = import_wire_header(
                                                        &consensus, &p2p, peer, &header,
                                                    )
                                                    .await;
                                                } else {
                                                    let _ = import_wire_block(
                                                        &consensus, &p2p, peer, &header, true,
                                                    )
                                                    .await;
                                                }
                                            }
                                            None => {}
                                        }
                                    }
                                    InboundItem::Tx { tx } => {
                                        if let Ok((tx_bytes, wit_bytes)) = decode_tx_push(&tx) {
                                            let (reply, _) = sync_channel(1);
                                            let source = peer
                                                .to_bytes()
                                                .get(..8)
                                                .and_then(|bytes| bytes.try_into().ok())
                                                .map(u64::from_le_bytes)
                                                .unwrap_or(0);
                                            let _ = consensus.try_send(ConsensusMsg::SubmitTx {
                                                tx_bytes: tx_bytes.to_vec(),
                                                wit_bytes: wit_bytes.to_vec(),
                                                source,
                                                reply,
                                            });
                                        }
                                    }
                                    InboundItem::Vote { vote } => {
                                        if let Ok(vote) = FinalityVoteV1::decode_canonical(&vote) {
                                            let _ = tokio::task::block_in_place(|| {
                                                enqueue_inbound_vote(&consensus, vote)
                                            });
                                        }
                                    }
                                    InboundItem::LoomReceipt { .. } => {}
                                },
                                P2pEvent::Listening { .. }
                                | P2pEvent::Violation { .. }
                                | P2pEvent::CooldownRefused { .. }
                                | P2pEvent::OutgoingConnectionFailed { .. } => {}
                            }
                        }
                    }
                }
                sync_task.abort();
                p2p.shutdown();
            });
        })
        .map_err(|error| NodeError::Config(format!("spawn p2p task: {error}")))?;
    let address = startup_rx
        .recv()
        .map_err(|_| NodeError::ChannelClosed("p2p startup"))?
        .map_err(|error| NodeError::Config(format!("p2p startup: {error}")))?;
    Ok((shutdown_tx, thread, address))
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Handle to a running node. Dropping it does NOT stop the node; call
/// [`NodeHandle::shutdown`].
pub struct NodeHandle {
    pub consensus_tx: SyncSender<ConsensusMsg>,
    pub metrics: Arc<Metrics>,
    /// Live QUIC listen address when networking is enabled.
    pub p2p_addr: Option<Multiaddr>,
    consensus_handle: Option<JoinHandle<()>>,
    store_tx: SyncSender<StoreMsg>,
    store_handle: Option<JoinHandle<()>>,
    network_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    network_handle: Option<JoinHandle<()>>,
}

impl NodeHandle {
    fn round_trip<T>(&self, build: impl FnOnce(Reply<T>) -> ConsensusMsg) -> Result<T, NodeError> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.consensus_tx
            .send(build(reply_tx))
            .map_err(|_| NodeError::ChannelClosed("consensus inbox"))?;
        reply_rx
            .recv()
            .map_err(|_| NodeError::ChannelClosed("consensus reply"))
    }

    pub fn status(&self) -> Result<StatusSnapshot, NodeError> {
        self.round_trip(|reply| ConsensusMsg::Status { reply })
    }

    pub fn produce_block(&self) -> Result<Hash32, NodeError> {
        self.round_trip(|reply| ConsensusMsg::ProduceBlock { reply })?
            .map_err(NodeError::Config)
    }

    /// Devnet fixture finality driver tick (TEST NETWORKS ONLY): `Ok(true)`
    /// when an epoch-boundary certificate was signed and queued.
    pub fn devnet_finality_tick(&self) -> Result<bool, NodeError> {
        self.round_trip(|reply| ConsensusMsg::DevnetFinalityTick { reply })?
            .map_err(NodeError::Config)
    }

    /// Signs and gossips one vote as a single fixture witness operator.
    pub fn devnet_witness_vote_tick(&self, witness_index: usize) -> Result<bool, NodeError> {
        self.round_trip(|reply| ConsensusMsg::DevnetWitnessVoteTick {
            witness_index,
            reply,
        })?
        .map_err(NodeError::Config)
    }

    pub fn set_now(&self, now_ms: u64) -> Result<(), NodeError> {
        self.consensus_tx
            .send(ConsensusMsg::SetNow(now_ms))
            .map_err(|_| NodeError::ChannelClosed("consensus inbox"))
    }

    /// Non-blocking crash injection (containment test hook).
    pub fn inject_crash(&self) -> Result<(), NodeError> {
        match self.consensus_tx.try_send(ConsensusMsg::InjectCrash) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(NodeError::ChannelClosed("consensus inbox full")),
            Err(TrySendError::Disconnected(_)) => Err(NodeError::ChannelClosed("consensus inbox")),
        }
    }

    /// Orderly shutdown of every task.
    pub fn shutdown(mut self) {
        if let Some(stop) = self.network_shutdown.take() {
            let _ = stop.send(());
        }
        if let Some(h) = self.network_handle.take() {
            let _ = h.join();
        }
        let _ = self.consensus_tx.send(ConsensusMsg::Shutdown);
        if let Some(h) = self.consensus_handle.take() {
            let _ = h.join();
        }
        let _ = self.store_tx.send(StoreMsg::Shutdown);
        if let Some(h) = self.store_handle.take() {
            let _ = h.join();
        }
    }
}

/// Boots the full task topology over a data directory.
pub fn start(
    cfg: NodeConfig,
    spec: GenesisSpec,
    data_dir: PathBuf,
) -> Result<NodeHandle, NodeError> {
    let metrics = Arc::new(Metrics::default());
    let built = spec.build()?;
    let mut network_settings = cfg.network.clone();
    if network_settings.enabled && network_settings.keypair_seed.is_none() {
        network_settings.keypair_seed = Some(load_or_create_p2p_seed(&data_dir)?);
    }

    // Store task.
    let store = InProcStore::open(data_dir, &built.chain_id, &built.genesis_hash)?;
    let (store_tx, store_rx) = sync_channel::<StoreMsg>(STORE_INBOX);
    let (priority_store_tx, priority_store_rx) = sync_channel::<StoreMsg>(STORE_PRIORITY_INBOX);
    let store_handle = std::thread::Builder::new()
        .name("noos-store".into())
        .spawn(move || store_task(store, &store_rx, &priority_store_rx))
        .map_err(|e| NodeError::Config(format!("spawn store task: {e}")))?;

    // Consensus task with contained-crash restart.
    let (consensus_tx, consensus_rx) = sync_channel::<ConsensusMsg>(CONSENSUS_INBOX);
    let store_client = StoreClient {
        tx: store_tx.clone(),
        priority_tx: priority_store_tx,
    };
    let network_store = store_client.clone();
    let network_chain_id = built.chain_id;
    let network_genesis_hash = built.genesis_hash;
    let observer = cfg.observer;
    let (gossip_sender, gossip_rx) = tokio::sync::mpsc::channel::<OutboundGossip>(256);
    let gossip_tx = network_settings.enabled.then_some(gossip_sender);
    let task_metrics = Arc::clone(&metrics);
    let consensus_handle = std::thread::Builder::new()
        .name("noos-consensus".into())
        .spawn(move || {
            loop {
                // (Re)build the single-writer state from the durable store.
                let built = match spec.build() {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let mut core = match NodeCore::boot(
                    cfg.clone(),
                    &spec,
                    built,
                    store_client.clone(),
                    Arc::clone(&task_metrics),
                ) {
                    Ok(c) => c,
                    Err(error) => {
                        eprintln!("fatal consensus boot error: {error}");
                        return; // typed fatal: store refused startup
                    }
                };
                let done = catch_unwind(AssertUnwindSafe(|| {
                    core_loop(&mut core, observer, &consensus_rx, gossip_tx.as_ref())
                }));
                match done {
                    Ok(_) => return, // orderly shutdown or closed inbox
                    Err(_) => {
                        // Contained crash: poisoned in-memory state is
                        // dropped; the loop rebuilds it from the store.
                        task_metrics.inc(&task_metrics.task_restarts_total);
                    }
                }
            }
        })
        .map_err(|e| NodeError::Config(format!("spawn consensus task: {e}")))?;

    let (network_shutdown, network_handle, p2p_addr) = if network_settings.enabled {
        let (shutdown, thread, address) = spawn_network(
            network_settings,
            network_chain_id,
            network_genesis_hash,
            network_store,
            consensus_tx.clone(),
            gossip_rx,
        )?;
        (Some(shutdown), Some(thread), Some(address))
    } else {
        (None, None, None)
    };

    Ok(NodeHandle {
        consensus_tx,
        metrics,
        p2p_addr,
        consensus_handle: Some(consensus_handle),
        store_tx,
        store_handle: Some(store_handle),
        network_shutdown,
        network_handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noos_crypto::BlsSecretKey;
    use std::sync::mpsc::RecvTimeoutError;
    use std::thread;

    fn test_vote() -> FinalityVoteV1 {
        let secret = BlsSecretKey::from_seed([7; 32]).expect("test BLS key");
        FinalityVoteV1::sign(
            [1; 32],
            1,
            CheckpointRef {
                epoch: 0,
                checkpoint_hash: [2; 32],
            },
            CheckpointRef {
                epoch: 1,
                checkpoint_hash: [3; 32],
            },
            [7; 32],
            [4; 32],
            &secret,
        )
        .expect("signed test vote")
    }

    #[test]
    fn range_sync_page_backoff_reaches_single_header_floor() {
        let mut page = SYNC_RANGE_PAGE_HEADERS;
        let mut pages = vec![page];
        while let Some(smaller) = smaller_sync_range_page(page) {
            pages.push(smaller);
            page = smaller;
        }

        assert_eq!(pages, vec![16, 8, 4, 2, 1]);
        assert_eq!(smaller_sync_range_page(1), None);
    }

    #[test]
    fn priority_store_lane_preempts_normal_backlog() {
        let (store_tx, store_rx) = sync_channel(1);
        let (priority_tx, priority_rx) = sync_channel(1);
        let (normal_reply, _) = sync_channel(1);
        let (priority_reply, _) = sync_channel(1);
        store_tx
            .send(StoreMsg::AppliedSeq(normal_reply))
            .expect("queue normal store work");
        priority_tx
            .send(StoreMsg::ProtocolHeaderRange(42, 16, priority_reply))
            .expect("queue protocol range work");

        let mut priority_streak = 0;
        match recv_store_msg(&store_rx, &priority_rx, &mut priority_streak).expect("priority work")
        {
            StoreMsg::ProtocolHeaderRange(42, 16, _) => {}
            _ => panic!("protocol range work did not preempt normal backlog"),
        }
        assert!(matches!(
            recv_store_msg(&store_rx, &priority_rx, &mut priority_streak),
            Some(StoreMsg::AppliedSeq(_))
        ));
    }

    #[test]
    fn priority_store_lane_yields_after_bounded_burst() {
        let (store_tx, store_rx) = sync_channel(1);
        let (priority_tx, priority_rx) = sync_channel(STORE_PRIORITY_BURST + 1);
        let (normal_reply, _) = sync_channel(1);
        store_tx
            .send(StoreMsg::AppliedSeq(normal_reply))
            .expect("queue normal store work");
        for height in 0..=STORE_PRIORITY_BURST as u64 {
            let (reply, _) = sync_channel(1);
            priority_tx
                .send(StoreMsg::ProtocolHeaderRange(height, 1, reply))
                .expect("queue priority store work");
        }

        let mut priority_streak = 0;
        for expected_height in 0..STORE_PRIORITY_BURST as u64 {
            match recv_store_msg(&store_rx, &priority_rx, &mut priority_streak)
                .expect("priority burst work")
            {
                StoreMsg::ProtocolHeaderRange(height, 1, _) => {
                    assert_eq!(height, expected_height);
                }
                _ => panic!("normal work interrupted the bounded priority burst"),
            }
        }
        assert!(matches!(
            recv_store_msg(&store_rx, &priority_rx, &mut priority_streak),
            Some(StoreMsg::AppliedSeq(_))
        ));
    }

    #[test]
    fn protocol_header_range_uses_one_priority_round_trip() {
        let (store_tx, store_rx) = sync_channel(1);
        let (priority_tx, priority_rx) = sync_channel(1);
        let client = StoreClient {
            tx: store_tx,
            priority_tx,
        };
        let responder = thread::spawn(move || {
            match priority_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("protocol range request")
            {
                StoreMsg::ProtocolHeaderRange(7, 2, reply) => {
                    reply
                        .send((vec![vec![1], vec![2]], true))
                        .expect("protocol range reply");
                }
                _ => panic!("protocol range was not batched"),
            }
        });

        assert_eq!(
            client
                .protocol_header_range(7, 2)
                .expect("protocol range result"),
            (vec![vec![1], vec![2]], true)
        );
        assert!(matches!(store_rx.try_recv(), Err(TryRecvError::Empty)));
        responder.join().expect("protocol range responder");
    }

    #[test]
    fn inbound_vote_waits_for_consensus_capacity_instead_of_dropping() {
        let (consensus_tx, consensus_rx) = sync_channel(1);
        consensus_tx
            .send(ConsensusMsg::SetNow(7))
            .expect("fill consensus inbox");

        let sender = consensus_tx.clone();
        let (done_tx, done_rx) = sync_channel(1);
        let vote_sender = thread::spawn(move || {
            done_tx
                .send(enqueue_inbound_vote(&sender, test_vote()))
                .expect("report vote delivery");
        });

        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert!(matches!(
            consensus_rx.recv_timeout(Duration::from_secs(1)),
            Ok(ConsensusMsg::SetNow(7))
        ));
        assert!(done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("vote delivery result"));
        match consensus_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("queued inbound vote")
        {
            ConsensusMsg::InboundVote { vote } => assert_eq!(vote.epoch, 1),
            _ => panic!("unexpected consensus message"),
        }
        vote_sender.join().expect("vote sender");
    }
}
