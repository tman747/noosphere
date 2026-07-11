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
//! ├── sync        NetworkEdge driver (optional until the noos-p2p bind)
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
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use noos_braid::{BlockHeaderV1, CheckpointRef, FinalityCertificateV1};
use noos_da::{BodyDaClaimV1, ShardCandidateV1};
use noos_ground::GroundTicketV1;
use noos_lumen::objects::ReceiptV1;
use noos_lumen::state::LumenRoots;
use noos_store::WriteSet;

use crate::consensus::{ImportOutcome, NodeConfig, NodeCore};
use crate::genesis::GenesisSpec;
use crate::mempool::AdmitError;
use crate::metrics::Metrics;
use crate::store_port::{InProcStore, StorePort};
use crate::view::{BlockSummary, TxStatus, ViewLookup};
use crate::{Hash32, NodeError};

/// Bounded inbox capacities (node-v1.md §7.1).
pub const CONSENSUS_INBOX: usize = 1024;
pub const STORE_INBOX: usize = 64;

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
    ScanIndices(Vec<u8>, Reply<Result<Vec<(Vec<u8>, Vec<u8>)>, String>>),
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
}

fn store_err(msg: String) -> NodeError {
    NodeError::BarrierFailed(msg)
}

impl StoreClient {
    fn round_trip<T>(
        &self,
        build: impl FnOnce(Reply<T>) -> StoreMsg,
    ) -> Result<T, NodeError> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(build(reply_tx))
            .map_err(|_| NodeError::ChannelClosed("store inbox"))?;
        reply_rx
            .recv()
            .map_err(|_| NodeError::ChannelClosed("store reply"))
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
    fn scan_indices(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, NodeError> {
        self.round_trip(|r| StoreMsg::ScanIndices(prefix.to_vec(), r))?
            .map_err(store_err)
    }
    fn roots(&self) -> Result<Option<LumenRoots>, NodeError> {
        self.round_trip(StoreMsg::Roots)?.map_err(store_err)
    }
    fn create_snapshot(&mut self) -> Result<u64, NodeError> {
        self.round_trip(StoreMsg::CreateSnapshot)?.map_err(store_err)
    }
    fn applied_seq(&self) -> u64 {
        self.round_trip(StoreMsg::AppliedSeq).unwrap_or(0)
    }
}

fn store_task(mut store: InProcStore, rx: &Receiver<StoreMsg>) {
    while let Ok(msg) = rx.recv() {
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
    ImportBlock {
        header: Box<BlockHeaderV1>,
        ticket: GroundTicketV1,
        claim: BodyDaClaimV1,
        shards: Vec<ShardCandidateV1>,
        reply: Reply<Result<ImportOutcome, String>>,
    },
    ProduceBlock {
        reply: Reply<Result<Hash32, String>>,
    },
    QueueCertificate {
        cert: Box<FinalityCertificateV1>,
        reply: Reply<Result<(), String>>,
    },
    Status {
        reply: Reply<StatusSnapshot>,
    },
    GetBlock {
        id: BlockId,
        reply: Reply<ViewLookup<BlockSummary>>,
    },
    GetReceipt {
        txid: Hash32,
        reply: Reply<ViewLookup<(TxStatus, Option<ReceiptV1>)>>,
    },
    SetNow(u64),
    /// Test hook: panic the consensus task to prove containment.
    InjectCrash,
    Shutdown,
}

fn status_of<P: StorePort>(core: &NodeCore<P>, observer: bool) -> StatusSnapshot {
    let (head_height, head_hash) = core.head();
    StatusSnapshot {
        chain_id: core.chain_id(),
        genesis_hash: core.genesis_hash(),
        head_height,
        head_hash,
        justified: core.justified(),
        finalized: core.finalized(),
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
) -> bool {
    while let Ok(msg) = rx.recv() {
        match msg {
            ConsensusMsg::SubmitTx {
                tx_bytes,
                wit_bytes,
                source,
                reply,
            } => {
                let _ = reply.send(core.submit_tx(&tx_bytes, &wit_bytes, source));
            }
            ConsensusMsg::ImportBlock {
                header,
                ticket,
                claim,
                shards,
                reply,
            } => {
                let result = core
                    .import_block(&header, &ticket, &claim, &shards)
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            ConsensusMsg::ProduceBlock { reply } => {
                let result = core
                    .produce_block()
                    .map(|p| p.hash)
                    .map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            ConsensusMsg::QueueCertificate { cert, reply } => {
                let _ = reply.send(core.queue_certificate(*cert).map_err(|e| e.to_string()));
            }
            ConsensusMsg::Status { reply } => {
                let _ = reply.send(status_of(core, observer));
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
            ConsensusMsg::SetNow(t) => core.set_now(t),
            ConsensusMsg::InjectCrash => panic!("injected consensus crash (containment test)"),
            ConsensusMsg::Shutdown => return true,
        }
    }
    true // inbox closed: orderly stop
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Handle to a running node. Dropping it does NOT stop the node; call
/// [`NodeHandle::shutdown`].
pub struct NodeHandle {
    pub consensus_tx: SyncSender<ConsensusMsg>,
    pub metrics: Arc<Metrics>,
    consensus_handle: Option<JoinHandle<()>>,
    store_tx: SyncSender<StoreMsg>,
    store_handle: Option<JoinHandle<()>>,
}

impl NodeHandle {
    fn round_trip<T>(
        &self,
        build: impl FnOnce(Reply<T>) -> ConsensusMsg,
    ) -> Result<T, NodeError> {
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
            Err(TrySendError::Disconnected(_)) => {
                Err(NodeError::ChannelClosed("consensus inbox"))
            }
        }
    }

    /// Orderly shutdown of every task.
    pub fn shutdown(mut self) {
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

    // Store task.
    let store = InProcStore::open(data_dir, &built.chain_id, &built.genesis_hash)?;
    let (store_tx, store_rx) = sync_channel::<StoreMsg>(STORE_INBOX);
    let store_handle = std::thread::Builder::new()
        .name("noos-store".into())
        .spawn(move || store_task(store, &store_rx))
        .map_err(|e| NodeError::Config(format!("spawn store task: {e}")))?;

    // Consensus task with contained-crash restart.
    let (consensus_tx, consensus_rx) = sync_channel::<ConsensusMsg>(CONSENSUS_INBOX);
    let store_client = StoreClient {
        tx: store_tx.clone(),
    };
    let observer = cfg.observer;
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
                    Err(_) => return, // typed fatal: store refused startup
                };
                let done = catch_unwind(AssertUnwindSafe(|| {
                    core_loop(&mut core, observer, &consensus_rx)
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

    Ok(NodeHandle {
        consensus_tx,
        metrics,
        consensus_handle: Some(consensus_handle),
        store_tx,
        store_handle: Some(store_handle),
    })
}
