//! The transport node: libp2p QUIC swarm, chain-identity handshake driver,
//! the eight protocol substream servers, per-peer outbound workers, and the
//! anti-DoS enforcement point (p2p-v1.md §§5–8).
//!
//! Architecture: one swarm task owns the [`libp2p::Swarm`]; one accept task
//! per registered protocol serves inbound substreams; one worker task per
//! peer drains the two-lane outbox with a single in-flight request (so lane
//! order is wire order). All shared state lives in [`Shared`] behind
//! non-async mutexes that are never held across an `.await`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity as p2p_identity, Multiaddr, PeerId, StreamProtocol};
use libp2p_stream as stream;
use noos_codec::{NoosDecode, NoosEncode};
use tokio::sync::{mpsc, oneshot, watch, Notify};

use crate::backoff::ReconnectBackoff;
use crate::envelope::{
    message_digest, BodyReplyV1, BodyRequestV1, Bounded, BoundedList, ChainAttestationV1, Flag,
    HandshakeMsgV1, HeaderMsgV1, HeaderReplyV1, LoomReceiptPushV1, Protocol, PushReplyV1,
    RangeReplyV1, RangeRequestV1, RejectCode, ShardReplyV1, ShardRequestV1, SnapshotChunkRequestV1,
    SnapshotReplyV1, TxPushV1, VotePushV1, APP_PROTOCOLS, MAX_RANGE_HEADERS,
    RANGE_REPLY_BYTE_BUDGET,
};
use crate::frame::{
    read_frame, write_frame, FrameError, MAX_FRAME_BYTES, MAX_HANDSHAKE_FRAME_BYTES,
};
use crate::identity::{sign_attestation, verify_attestation, ChainIdentity};
use crate::limits::{
    CooldownLedger, DupCache, LimitsConfig, TokenBucket, Violation, DISCONNECT_SCORE,
};
use crate::queue::{OutboundItem, Outbox};

/// Grace a not-yet-ready peer gets on an early application stream before it
/// counts as a violation (covers the Ack-in-flight handshake race).
const READY_GRACE_MS: u64 = 3_000;

/// Delivery attempts per queued request across reconnects.
const SEND_ATTEMPTS: u8 = 2;

// ---------------------------------------------------------------------------
// Public configuration and surface types
// ---------------------------------------------------------------------------

/// Node configuration. Every constant has a PROPOSED-G0 default.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Chain identity attested in every handshake.
    pub identity: ChainIdentity,
    /// Ed25519 seed backing BOTH the libp2p TLS identity and the D-SIG-PEER
    /// attestation key. Caller-supplied; production feeds OS-CSPRNG output.
    pub keypair_seed: [u8; 32],
    /// QUIC listen address, e.g. `/ip4/127.0.0.1/udp/0/quic-v1`.
    pub listen_addr: Multiaddr,
    /// Per-peer per-protocol inbound rate limits.
    pub limits: LimitsConfig,
    /// Work Loom receipt lane; `false` at genesis (plan §6.8) — pushes are
    /// answered `FeatureDisabled` without dispatch.
    pub loom_lane_enabled: bool,
    /// Seed for the deterministic reconnect-jitter stream.
    pub backoff_seed: u64,
    /// Outbox depth per lane per peer.
    pub outbox_capacity_per_lane: usize,
    /// Handshake completion deadline.
    pub handshake_timeout_ms: u64,
    /// Duplicate-cache capacity per push lane.
    pub dup_cache_capacity: usize,
}

impl P2pConfig {
    /// Loopback defaults for a given chain identity and key seed.
    pub fn loopback(identity: ChainIdentity, keypair_seed: [u8; 32]) -> Self {
        P2pConfig {
            identity,
            keypair_seed,
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .unwrap_or_else(|_| unreachable!("static multiaddr parses")),
            limits: LimitsConfig::default(),
            loom_lane_enabled: false,
            backoff_seed: 0,
            outbox_capacity_per_lane: 1024,
            handshake_timeout_ms: 5_000,
            dup_cache_capacity: 4096,
        }
    }
}

/// Request substream answers supplied by the embedder (noos-node/sync later).
/// Defaults answer "not found" so a transport-only node is servable.
pub trait ProtocolStore: Send + Sync + 'static {
    fn header(&self, _header_hash: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    fn body(&self, _block_hash: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    /// Ascending encoded headers from `start_height`, plus a `more` flag.
    fn header_range(&self, _start_height: u64, _max_headers: u32) -> (Vec<Vec<u8>>, bool) {
        (Vec::new(), false)
    }
    /// `(total_chunks, chunk_bytes)` for a finalized snapshot root.
    fn snapshot_chunk(
        &self,
        _snapshot_root: &[u8; 32],
        _chunk_index: u32,
    ) -> Option<(u32, Vec<u8>)> {
        None
    }
    fn shard(&self, _content_root: &[u8; 32], _shard_index: u32) -> Option<Vec<u8>> {
        None
    }
}

/// A transport-only store: every request answers "not found".
pub struct EmptyStore;
impl ProtocolStore for EmptyStore {}

/// Push payloads delivered to the embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundItem {
    HeaderAnnounce { header: Vec<u8> },
    Vote { vote: Vec<u8> },
    Tx { tx: Vec<u8> },
    LoomReceipt { receipt: Vec<u8> },
}

/// Node events.
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A listen address is live.
    Listening { address: Multiaddr },
    /// Handshake completed; application traffic is now permitted.
    PeerReady {
        peer: PeerId,
        attestation: ChainAttestationV1,
    },
    /// Handshake rejected. `by_remote` = the remote sent the reject frame.
    HandshakeRejected {
        peer: PeerId,
        code: RejectCode,
        by_remote: bool,
    },
    /// A push arrived (post rate-limit, duplicate, and chain checks).
    Inbound { peer: PeerId, item: InboundItem },
    /// A protocol violation was recorded against a peer.
    Violation { peer: PeerId, violation: Violation },
    /// All connections to the peer are gone.
    PeerDisconnected { peer: PeerId },
    /// An inbound connection was refused because the peer is cooling down.
    CooldownRefused { peer: PeerId },
    /// An outbound dial failed (reconnect backoff continues if scheduled).
    OutgoingConnectionFailed { peer: Option<PeerId> },
}

/// Outbound send failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The lane is full; sender backpressure.
    QueueFull,
    /// The peer's chain identity was rejected; nothing will ever be sent.
    PeerRejected,
    /// Connection lost and delivery attempts exhausted.
    Disconnected,
    /// The reply failed canonical decode.
    BadReply,
    /// The node is shutting down.
    NodeShutdown,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            SendError::QueueFull => "queue_full",
            SendError::PeerRejected => "peer_rejected",
            SendError::Disconnected => "disconnected",
            SendError::BadReply => "bad_reply",
            SendError::NodeShutdown => "node_shutdown",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SendError {}

/// Node spawn failure.
#[derive(Debug)]
pub struct SpawnError(pub String);

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "p2p spawn: {}", self.0)
    }
}

impl std::error::Error for SpawnError {}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyState {
    Pending,
    Ready,
    Rejected,
}

struct PeerEntry {
    ready_tx: watch::Sender<ReadyState>,
    outbox: Arc<Mutex<Outbox>>,
    notify: Arc<Notify>,
    score: u32,
    limiters: [TokenBucket; 8],
    attestation: Option<ChainAttestationV1>,
    connected: bool,
    dial_addr: Option<Multiaddr>,
    backoff: ReconnectBackoff,
    reconnecting: bool,
}

enum SwarmCmd {
    Dial(Multiaddr),
    DialPeer(PeerId, Multiaddr),
    Disconnect(PeerId),
    Shutdown,
}

/// Duplicate-cache lanes (push protocols only).
const DUP_LANES: usize = 4;

const fn dup_lane(protocol: Protocol) -> Option<usize> {
    match protocol {
        Protocol::BraidHeader => Some(0),
        Protocol::BraidVote => Some(1),
        Protocol::LumenTx => Some(2),
        Protocol::LoomReceipt => Some(3),
        _ => None,
    }
}

struct Shared {
    config: P2pConfig,
    local_attestation: ChainAttestationV1,
    local_peer_id: PeerId,
    control: stream::Control,
    peers: Mutex<HashMap<PeerId, PeerEntry>>,
    cooldowns: Mutex<CooldownLedger>,
    dups: Mutex<[DupCache; DUP_LANES]>,
    events: mpsc::UnboundedSender<P2pEvent>,
    cmds: mpsc::UnboundedSender<SwarmCmd>,
    store: Arc<dyn ProtocolStore>,
    start: Instant,
    listen_tx: watch::Sender<Option<Multiaddr>>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn emit(&self, ev: P2pEvent) {
        let _ = self.events.send(ev);
    }

    fn cmd(&self, cmd: SwarmCmd) {
        let _ = self.cmds.send(cmd);
    }
}

fn sp(protocol: Protocol) -> StreamProtocol {
    StreamProtocol::new(protocol.id())
}

/// PeerId corresponding to an attested Ed25519 public key.
fn attested_peer_id(pubkey: &[u8; 32]) -> Option<PeerId> {
    let pk = p2p_identity::ed25519::PublicKey::try_from_bytes(pubkey).ok()?;
    Some(p2p_identity::PublicKey::from(pk).to_peer_id())
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Constructor namespace for the transport node.
pub struct P2pNode;

impl P2pNode {
    /// Builds the swarm, registers the nine protocols, starts listening, and
    /// spawns the swarm/accept tasks onto the current tokio runtime.
    pub fn spawn(
        config: P2pConfig,
        store: Arc<dyn ProtocolStore>,
    ) -> Result<(P2pHandle, mpsc::UnboundedReceiver<P2pEvent>), SpawnError> {
        let mut seed = config.keypair_seed;
        let libp2p_key = p2p_identity::Keypair::ed25519_from_bytes(&mut seed)
            .map_err(|e| SpawnError(format!("keypair: {e}")))?;
        let noos_key = noos_crypto::Keypair::from_seed(config.keypair_seed);
        let local_attestation = sign_attestation(&config.identity, &noos_key);
        debug_assert_eq!(
            attested_peer_id(&local_attestation.peer_pubkey),
            Some(libp2p_key.public().to_peer_id()),
            "libp2p and noos-crypto must derive the same Ed25519 identity"
        );

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_key)
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| stream::Behaviour::new())
            .map_err(|e| SpawnError(format!("behaviour: {e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        let local_peer_id = *swarm.local_peer_id();
        let control = swarm.behaviour().new_control();

        // Register every accepted protocol BEFORE listening; anything else —
        // any unknown /noos/ string included — is refused at negotiation by
        // libp2p (identity-v1.md §3 closed-list law).
        let mut incoming = Vec::with_capacity(9);
        for protocol in core::iter::once(Protocol::Handshake).chain(APP_PROTOCOLS) {
            let streams = control
                .clone()
                .accept(sp(protocol))
                .map_err(|e| SpawnError(format!("accept {}: {e}", protocol.id())))?;
            incoming.push((protocol, streams));
        }

        swarm
            .listen_on(config.listen_addr.clone())
            .map_err(|e| SpawnError(format!("listen: {e}")))?;

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (listen_tx, _) = watch::channel(None);
        let dup_cap = config.dup_cache_capacity;

        let shared = Arc::new(Shared {
            config,
            local_attestation,
            local_peer_id,
            control,
            peers: Mutex::new(HashMap::new()),
            cooldowns: Mutex::new(CooldownLedger::new()),
            dups: Mutex::new([
                DupCache::new(dup_cap),
                DupCache::new(dup_cap),
                DupCache::new(dup_cap),
                DupCache::new(dup_cap),
            ]),
            events: event_tx,
            cmds: cmd_tx,
            store,
            start: Instant::now(),
            listen_tx,
        });

        for (protocol, streams) in incoming {
            let sh = Arc::clone(&shared);
            tokio::spawn(accept_loop(sh, protocol, streams));
        }

        let sh = Arc::clone(&shared);
        tokio::spawn(swarm_loop(sh, swarm, cmd_rx));

        Ok((P2pHandle { shared }, event_rx))
    }
}

/// Cloneable handle: dialing, typed protocol sends, and shutdown.
#[derive(Clone)]
pub struct P2pHandle {
    shared: Arc<Shared>,
}

impl P2pHandle {
    pub fn local_peer_id(&self) -> PeerId {
        self.shared.local_peer_id
    }

    pub fn chain_id(&self) -> [u8; 32] {
        self.shared.config.identity.chain_id
    }

    /// Dials a QUIC multiaddr (fire-and-forget; watch for `PeerReady`).
    pub fn connect(&self, addr: Multiaddr) {
        self.shared.cmd(SwarmCmd::Dial(addr));
    }

    /// The live listen address (waits for the listener to bind).
    pub async fn listen_addr(&self) -> Multiaddr {
        let mut rx = self.shared.listen_tx.subscribe();
        loop {
            if let Some(addr) = rx.borrow().clone() {
                return addr;
            }
            if rx.changed().await.is_err() {
                // Node gone; return an empty addr rather than hang.
                return Multiaddr::empty();
            }
        }
    }

    /// Stops the swarm task; connections close, queued sends fail.
    pub fn shutdown(&self) {
        self.shared.cmd(SwarmCmd::Shutdown);
    }

    // -- typed protocol surface ---------------------------------------------

    /// Announce a header (push on `/noos/braid/header/1`, priority lane).
    pub fn announce_header(
        &self,
        peer: PeerId,
        header: Vec<u8>,
    ) -> impl Future<Output = Result<HeaderReplyV1, SendError>> {
        let env = HeaderMsgV1::Announce {
            chain_id: self.chain_id(),
            header: Bounded(header),
        };
        let rx = self.enqueue(peer, Protocol::BraidHeader, env.encode_canonical());
        async move { decode_reply::<HeaderReplyV1>(rx.await) }
    }

    /// Request a header by hash.
    pub fn request_header(
        &self,
        peer: PeerId,
        header_hash: [u8; 32],
    ) -> impl Future<Output = Result<HeaderReplyV1, SendError>> {
        let env = HeaderMsgV1::Request {
            chain_id: self.chain_id(),
            header_hash,
        };
        let rx = self.enqueue(peer, Protocol::BraidHeader, env.encode_canonical());
        async move { decode_reply::<HeaderReplyV1>(rx.await) }
    }

    /// Targeted repair: ask THIS peer for THIS body hash
    /// (`/noos/braid/body/1`, priority lane).
    pub fn request_body(
        &self,
        peer: PeerId,
        block_hash: [u8; 32],
    ) -> impl Future<Output = Result<BodyReplyV1, SendError>> {
        let env = BodyRequestV1 {
            chain_id: self.chain_id(),
            block_hash,
        };
        let rx = self.enqueue(peer, Protocol::BraidBody, env.encode_canonical());
        async move { decode_reply::<BodyReplyV1>(rx.await) }
    }

    /// Push a checkpoint vote (priority lane).
    pub fn push_vote(
        &self,
        peer: PeerId,
        vote: Vec<u8>,
    ) -> impl Future<Output = Result<PushReplyV1, SendError>> {
        let env = VotePushV1 {
            chain_id: self.chain_id(),
            vote: Bounded(vote),
        };
        let rx = self.enqueue(peer, Protocol::BraidVote, env.encode_canonical());
        async move { decode_reply::<PushReplyV1>(rx.await) }
    }

    /// Push a transaction (normal lane).
    pub fn push_tx(
        &self,
        peer: PeerId,
        tx: Vec<u8>,
    ) -> impl Future<Output = Result<PushReplyV1, SendError>> {
        let env = TxPushV1 {
            chain_id: self.chain_id(),
            tx: Bounded(tx),
        };
        let rx = self.enqueue(peer, Protocol::LumenTx, env.encode_canonical());
        async move { decode_reply::<PushReplyV1>(rx.await) }
    }

    /// Request an ascending header range (priority lane).
    pub fn request_range(
        &self,
        peer: PeerId,
        start_height: u64,
        max_headers: u32,
    ) -> impl Future<Output = Result<RangeReplyV1, SendError>> {
        let env = RangeRequestV1 {
            chain_id: self.chain_id(),
            start_height,
            max_headers,
        };
        let rx = self.enqueue(peer, Protocol::SyncRange, env.encode_canonical());
        async move { decode_reply::<RangeReplyV1>(rx.await) }
    }

    /// Request one snapshot chunk (priority lane).
    pub fn request_snapshot_chunk(
        &self,
        peer: PeerId,
        snapshot_root: [u8; 32],
        chunk_index: u32,
    ) -> impl Future<Output = Result<SnapshotReplyV1, SendError>> {
        let env = SnapshotChunkRequestV1 {
            chain_id: self.chain_id(),
            snapshot_root,
            chunk_index,
        };
        let rx = self.enqueue(peer, Protocol::SyncSnapshot, env.encode_canonical());
        async move { decode_reply::<SnapshotReplyV1>(rx.await) }
    }

    /// Request one DA shard (normal lane).
    pub fn request_shard(
        &self,
        peer: PeerId,
        content_root: [u8; 32],
        shard_index: u32,
    ) -> impl Future<Output = Result<ShardReplyV1, SendError>> {
        let env = ShardRequestV1 {
            chain_id: self.chain_id(),
            content_root,
            shard_index,
        };
        let rx = self.enqueue(peer, Protocol::BlobShard, env.encode_canonical());
        async move { decode_reply::<ShardReplyV1>(rx.await) }
    }

    /// Push a Work Loom receipt (normal lane). While the lane is disabled the
    /// remote answers `FeatureDisabled`.
    pub fn push_loom_receipt(
        &self,
        peer: PeerId,
        receipt: Vec<u8>,
    ) -> impl Future<Output = Result<PushReplyV1, SendError>> {
        let env = LoomReceiptPushV1 {
            chain_id: self.chain_id(),
            receipt: Bounded(receipt),
        };
        let rx = self.enqueue(peer, Protocol::LoomReceipt, env.encode_canonical());
        async move { decode_reply::<PushReplyV1>(rx.await) }
    }

    /// Opens a raw substream, bypassing envelopes and lanes — conformance
    /// testing only (the loopback matrix injects mis-framed bytes with this).
    pub async fn open_raw_stream(
        &self,
        peer: PeerId,
        protocol_id: &'static str,
    ) -> Result<libp2p::Stream, SendError> {
        self.shared
            .control
            .clone()
            .open_stream(peer, StreamProtocol::new(protocol_id))
            .await
            .map_err(|_| SendError::Disconnected)
    }

    /// Synchronously enqueues into the peer's lane-ordered outbox. The
    /// returned receiver resolves with the raw reply frame.
    fn enqueue(
        &self,
        peer: PeerId,
        protocol: Protocol,
        payload: Vec<u8>,
    ) -> oneshot::Receiver<Result<Vec<u8>, SendError>> {
        let (tx, rx) = oneshot::channel();
        ensure_peer(&self.shared, peer);
        let peers = lock(&self.shared.peers);
        if let Some(entry) = peers.get(&peer) {
            if *entry.ready_tx.borrow() == ReadyState::Rejected {
                let _ = tx.send(Err(SendError::PeerRejected));
                return rx;
            }
            lock(&entry.outbox).push(OutboundItem {
                protocol,
                payload,
                reply: tx,
                attempts_left: SEND_ATTEMPTS,
            });
            entry.notify.notify_one();
        } else {
            let _ = tx.send(Err(SendError::NodeShutdown));
        }
        rx
    }
}

fn decode_reply<T: NoosDecode>(
    raw: Result<Result<Vec<u8>, SendError>, oneshot::error::RecvError>,
) -> Result<T, SendError> {
    let bytes = raw.map_err(|_| SendError::Disconnected)??;
    T::decode_canonical(&bytes).map_err(|_| SendError::BadReply)
}

/// Non-poisoning lock: this crate never panics while holding a mutex, and a
/// poisoned peer table is unrecoverable anyway.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// Peer registry
// ---------------------------------------------------------------------------

fn ensure_peer(shared: &Arc<Shared>, peer: PeerId) {
    let mut peers = lock(&shared.peers);
    if peers.contains_key(&peer) {
        return;
    }
    let now = shared.now_ms();
    let (ready_tx, ready_rx) = watch::channel(ReadyState::Pending);
    let outbox = Arc::new(Mutex::new(Outbox::new(
        shared.config.outbox_capacity_per_lane,
    )));
    let notify = Arc::new(Notify::new());
    let limiters: [TokenBucket; 8] = core::array::from_fn(|i| {
        let protocol = APP_PROTOCOLS[i];
        shared
            .config
            .limits
            .bucket_for(protocol, now)
            .unwrap_or_else(|| TokenBucket::new(1, 1, now))
    });
    // Per-peer jitter stream: seed mixed with the peer identity so two peers
    // never share a schedule, while staying reproducible per (seed, peer).
    let peer_bytes = peer.to_bytes();
    let mut mix = shared.config.backoff_seed;
    for (i, b) in peer_bytes.iter().enumerate() {
        mix ^= u64::from(*b) << ((i % 8).wrapping_mul(8));
    }
    let entry = PeerEntry {
        ready_tx,
        outbox: Arc::clone(&outbox),
        notify: Arc::clone(&notify),
        score: 0,
        limiters,
        attestation: None,
        connected: false,
        dial_addr: None,
        backoff: ReconnectBackoff::new(
            ReconnectBackoff::DEFAULT_BASE_MS,
            ReconnectBackoff::DEFAULT_MAX_MS,
            mix,
        ),
        reconnecting: false,
    };
    peers.insert(peer, entry);
    drop(peers);
    tokio::spawn(outbox_worker(
        Arc::clone(shared),
        peer,
        outbox,
        notify,
        ready_rx,
    ));
}

fn set_ready_state(shared: &Arc<Shared>, peer: PeerId, state: ReadyState) {
    let peers = lock(&shared.peers);
    if let Some(entry) = peers.get(&peer) {
        let _ = entry.ready_tx.send_replace(state);
        entry.notify.notify_one();
    }
}

fn mark_ready(shared: &Arc<Shared>, peer: PeerId, attestation: ChainAttestationV1) {
    {
        let mut peers = lock(&shared.peers);
        if let Some(entry) = peers.get_mut(&peer) {
            entry.attestation = Some(attestation.clone());
            entry.backoff.reset();
        }
    }
    set_ready_state(shared, peer, ReadyState::Ready);
    shared.emit(P2pEvent::PeerReady { peer, attestation });
}

fn mark_rejected(shared: &Arc<Shared>, peer: PeerId, code: RejectCode, by_remote: bool) {
    {
        let peers = lock(&shared.peers);
        if let Some(entry) = peers.get(&peer) {
            lock(&entry.outbox).fail_all(SendError::PeerRejected);
        }
    }
    set_ready_state(shared, peer, ReadyState::Rejected);
    // Strike a cooldown so a wrong-chain peer cannot hot-loop reconnects.
    let now = shared.now_ms();
    lock(&shared.cooldowns).strike(&peer.to_bytes(), now);
    shared.emit(P2pEvent::HandshakeRejected {
        peer,
        code,
        by_remote,
    });
    // Delay the connection teardown: a QUIC application close can outrun the
    // in-flight Reject frame, and the remote deserves to learn WHY it was
    // dropped (`wrong_protocol_identity`, not a silent reset). The session is
    // already `Rejected`, so no application traffic passes meanwhile.
    let sh = Arc::clone(shared);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        sh.cmd(SwarmCmd::Disconnect(peer));
    });
}

/// Records a violation; disconnects at the threshold or immediately.
fn record_violation(shared: &Arc<Shared>, peer: PeerId, violation: Violation) {
    let (penalty, immediate) = violation.penalty();
    let disconnect = {
        let mut peers = lock(&shared.peers);
        match peers.get_mut(&peer) {
            Some(entry) => {
                entry.score = entry.score.saturating_add(penalty);
                immediate || entry.score >= DISCONNECT_SCORE
            }
            None => immediate,
        }
    };
    shared.emit(P2pEvent::Violation { peer, violation });
    if disconnect {
        let now = shared.now_ms();
        lock(&shared.cooldowns).strike(&peer.to_bytes(), now);
        shared.cmd(SwarmCmd::Disconnect(peer));
    }
}

// ---------------------------------------------------------------------------
// Swarm loop
// ---------------------------------------------------------------------------

async fn swarm_loop(
    shared: Arc<Shared>,
    mut swarm: libp2p::Swarm<stream::Behaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<SwarmCmd>,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                None | Some(SwarmCmd::Shutdown) => break,
                Some(SwarmCmd::Dial(addr)) => {
                    let _ = swarm.dial(addr);
                }
                Some(SwarmCmd::DialPeer(peer, addr)) => {
                    let _ = swarm.dial(
                        DialOpts::peer_id(peer)
                            .addresses(vec![addr])
                            .condition(PeerCondition::Disconnected)
                            .build(),
                    );
                }
                Some(SwarmCmd::Disconnect(peer)) => {
                    let _ = swarm.disconnect_peer_id(peer);
                }
            },
            event = swarm.select_next_some() => {
                handle_swarm_event(&shared, event);
            }
        }
    }
}

fn handle_swarm_event(shared: &Arc<Shared>, event: SwarmEvent<()>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let _ = shared.listen_tx.send_replace(Some(address.clone()));
            shared.emit(P2pEvent::Listening { address });
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            let now = shared.now_ms();
            if lock(&shared.cooldowns).active(&peer_id.to_bytes(), now) {
                shared.emit(P2pEvent::CooldownRefused { peer: peer_id });
                shared.cmd(SwarmCmd::Disconnect(peer_id));
                return;
            }
            ensure_peer(shared, peer_id);
            let is_dialer = endpoint.is_dialer();
            {
                let mut peers = lock(&shared.peers);
                if let Some(entry) = peers.get_mut(&peer_id) {
                    entry.connected = true;
                    entry.reconnecting = false;
                    entry.score = 0;
                    if is_dialer {
                        entry.dial_addr = Some(endpoint.get_remote_address().clone());
                    }
                    // A fresh connection gets a fresh handshake verdict.
                    if *entry.ready_tx.borrow() == ReadyState::Rejected {
                        let _ = entry.ready_tx.send_replace(ReadyState::Pending);
                    }
                }
            }
            if is_dialer {
                tokio::spawn(handshake_dialer(Arc::clone(shared), peer_id));
            }
            tokio::spawn(handshake_watchdog(Arc::clone(shared), peer_id));
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            if num_established > 0 {
                return;
            }
            let mut rejected = false;
            {
                let mut peers = lock(&shared.peers);
                if let Some(entry) = peers.get_mut(&peer_id) {
                    entry.connected = false;
                    entry.attestation = None;
                    entry.score = 0;
                    rejected = *entry.ready_tx.borrow() == ReadyState::Rejected;
                    if !rejected {
                        let _ = entry.ready_tx.send_replace(ReadyState::Pending);
                    }
                }
            }
            shared.emit(P2pEvent::PeerDisconnected { peer: peer_id });
            if !rejected {
                schedule_reconnect(shared, peer_id);
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, .. } => {
            shared.emit(P2pEvent::OutgoingConnectionFailed { peer: peer_id });
            if let Some(peer) = peer_id {
                {
                    let mut peers = lock(&shared.peers);
                    if let Some(entry) = peers.get_mut(&peer) {
                        entry.reconnecting = false;
                    }
                }
                schedule_reconnect(shared, peer);
            }
        }
        _ => {}
    }
}

/// Schedules a redial after a deterministic-jitter exponential delay.
fn schedule_reconnect(shared: &Arc<Shared>, peer: PeerId) {
    let (delay_ms, addr) = {
        let mut peers = lock(&shared.peers);
        let Some(entry) = peers.get_mut(&peer) else {
            return;
        };
        if entry.reconnecting || entry.connected || *entry.ready_tx.borrow() == ReadyState::Rejected
        {
            return;
        }
        let Some(addr) = entry.dial_addr.clone() else {
            return; // inbound-only peer: it redials us
        };
        let now = shared.now_ms();
        if lock(&shared.cooldowns).active(&peer.to_bytes(), now) {
            return;
        }
        entry.reconnecting = true;
        (entry.backoff.next_delay_ms(), addr)
    };
    let sh = Arc::clone(shared);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        let still_wanted = {
            let peers = lock(&sh.peers);
            peers
                .get(&peer)
                .is_some_and(|e| !e.connected && *e.ready_tx.borrow() != ReadyState::Rejected)
        };
        if still_wanted {
            sh.cmd(SwarmCmd::DialPeer(peer, addr));
        } else {
            let mut peers = lock(&sh.peers);
            if let Some(entry) = peers.get_mut(&peer) {
                entry.reconnecting = false;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Handshake (session gate; p2p-v1.md §5)
// ---------------------------------------------------------------------------

/// Chain-first validation of a remote attestation, then TLS binding.
fn validate_remote(
    shared: &Shared,
    remote: PeerId,
    att: &ChainAttestationV1,
) -> Result<(), RejectCode> {
    verify_attestation(&shared.config.identity, &att.peer_pubkey, att)?;
    // Bind the attested key to the TLS-authenticated connection identity.
    if attested_peer_id(&att.peer_pubkey) != Some(remote) {
        return Err(RejectCode::AttestationInvalid);
    }
    Ok(())
}

async fn handshake_dialer(shared: Arc<Shared>, peer: PeerId) {
    let mut control = shared.control.clone();
    let Ok(mut s) = control.open_stream(peer, sp(Protocol::Handshake)).await else {
        shared.cmd(SwarmCmd::Disconnect(peer));
        return;
    };
    let attest = HandshakeMsgV1::Attest(shared.local_attestation.clone());
    if write_frame(
        &mut s,
        &attest.encode_canonical(),
        MAX_HANDSHAKE_FRAME_BYTES,
    )
    .await
    .is_err()
    {
        shared.cmd(SwarmCmd::Disconnect(peer));
        return;
    }
    let Ok(reply) = read_frame(&mut s, MAX_HANDSHAKE_FRAME_BYTES).await else {
        shared.cmd(SwarmCmd::Disconnect(peer));
        return;
    };
    match HandshakeMsgV1::decode_canonical(&reply) {
        Ok(HandshakeMsgV1::Attest(att)) => match validate_remote(&shared, peer, &att) {
            Ok(()) => {
                let ack = HandshakeMsgV1::Ack.encode_canonical();
                if write_frame(&mut s, &ack, MAX_HANDSHAKE_FRAME_BYTES)
                    .await
                    .is_ok()
                {
                    let _ = futures::io::AsyncWriteExt::close(&mut s).await;
                    mark_ready(&shared, peer, att);
                } else {
                    shared.cmd(SwarmCmd::Disconnect(peer));
                }
            }
            Err(code) => {
                let rej = HandshakeMsgV1::Reject { code: code.wire() }.encode_canonical();
                let _ = write_frame(&mut s, &rej, MAX_HANDSHAKE_FRAME_BYTES).await;
                let _ = futures::io::AsyncWriteExt::close(&mut s).await;
                mark_rejected(&shared, peer, code, false);
            }
        },
        Ok(HandshakeMsgV1::Reject { code }) => {
            let code = RejectCode::from_wire(code).unwrap_or(RejectCode::Malformed);
            mark_rejected(&shared, peer, code, true);
        }
        _ => {
            mark_rejected(&shared, peer, RejectCode::Malformed, false);
        }
    }
}

async fn serve_handshake(shared: Arc<Shared>, peer: PeerId, mut s: libp2p::Stream) {
    let Ok(bytes) = read_frame(&mut s, MAX_HANDSHAKE_FRAME_BYTES).await else {
        shared.cmd(SwarmCmd::Disconnect(peer));
        return;
    };
    let att = match HandshakeMsgV1::decode_canonical(&bytes) {
        Ok(HandshakeMsgV1::Attest(att)) => att,
        _ => {
            let rej = HandshakeMsgV1::Reject {
                code: RejectCode::Malformed.wire(),
            }
            .encode_canonical();
            let _ = write_frame(&mut s, &rej, MAX_HANDSHAKE_FRAME_BYTES).await;
            mark_rejected(&shared, peer, RejectCode::Malformed, false);
            return;
        }
    };
    match validate_remote(&shared, peer, &att) {
        Err(code) => {
            let rej = HandshakeMsgV1::Reject { code: code.wire() }.encode_canonical();
            let _ = write_frame(&mut s, &rej, MAX_HANDSHAKE_FRAME_BYTES).await;
            let _ = futures::io::AsyncWriteExt::close(&mut s).await;
            mark_rejected(&shared, peer, code, false);
        }
        Ok(()) => {
            let own = HandshakeMsgV1::Attest(shared.local_attestation.clone()).encode_canonical();
            if write_frame(&mut s, &own, MAX_HANDSHAKE_FRAME_BYTES)
                .await
                .is_err()
            {
                shared.cmd(SwarmCmd::Disconnect(peer));
                return;
            }
            let Ok(fin) = read_frame(&mut s, MAX_HANDSHAKE_FRAME_BYTES).await else {
                shared.cmd(SwarmCmd::Disconnect(peer));
                return;
            };
            match HandshakeMsgV1::decode_canonical(&fin) {
                Ok(HandshakeMsgV1::Ack) => mark_ready(&shared, peer, att),
                Ok(HandshakeMsgV1::Reject { code }) => {
                    let code = RejectCode::from_wire(code).unwrap_or(RejectCode::Malformed);
                    mark_rejected(&shared, peer, code, true);
                }
                _ => mark_rejected(&shared, peer, RejectCode::Malformed, false),
            }
        }
    }
}

/// Disconnects peers whose handshake never completes.
async fn handshake_watchdog(shared: Arc<Shared>, peer: PeerId) {
    tokio::time::sleep(Duration::from_millis(shared.config.handshake_timeout_ms)).await;
    let pending = {
        let peers = lock(&shared.peers);
        peers
            .get(&peer)
            .is_some_and(|e| e.connected && *e.ready_tx.borrow() == ReadyState::Pending)
    };
    if pending {
        record_violation(&shared, peer, Violation::HandshakeTimeout);
    }
}

// ---------------------------------------------------------------------------
// Inbound protocol serving
// ---------------------------------------------------------------------------

async fn accept_loop(
    shared: Arc<Shared>,
    protocol: Protocol,
    mut streams: stream::IncomingStreams,
) {
    while let Some((peer, stream)) = streams.next().await {
        let sh = Arc::clone(&shared);
        if protocol == Protocol::Handshake {
            tokio::spawn(serve_handshake(sh, peer, stream));
        } else {
            tokio::spawn(serve_app_stream(sh, protocol, peer, stream));
        }
    }
}

/// Waits (with grace) for the peer's handshake to complete.
async fn wait_ready(shared: &Arc<Shared>, peer: PeerId) -> bool {
    let rx = {
        let peers = lock(&shared.peers);
        peers.get(&peer).map(|e| e.ready_tx.subscribe())
    };
    let Some(mut rx) = rx else {
        return false;
    };
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(READY_GRACE_MS))
        .unwrap_or_else(tokio::time::Instant::now);
    loop {
        match *rx.borrow() {
            ReadyState::Ready => return true,
            ReadyState::Rejected => return false,
            ReadyState::Pending => {}
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => {}
            _ => return false,
        }
    }
}

async fn serve_app_stream(
    shared: Arc<Shared>,
    protocol: Protocol,
    peer: PeerId,
    mut s: libp2p::Stream,
) {
    // 1. Session gate: no application traffic before handshake completion.
    if !wait_ready(&shared, peer).await {
        record_violation(&shared, peer, Violation::StreamBeforeHandshake);
        return;
    }
    // 2. Per-peer per-protocol rate limit.
    let allowed = {
        let now = shared.now_ms();
        let mut peers = lock(&shared.peers);
        match (peers.get_mut(&peer), protocol.app_index()) {
            (Some(entry), Some(idx)) => entry.limiters[idx].try_take(now),
            _ => false,
        }
    };
    if !allowed {
        record_violation(&shared, peer, Violation::RateLimitExceeded);
        return;
    }
    // 3. Bounded frame read: an oversize declaration disconnects.
    let payload = match read_frame(&mut s, MAX_FRAME_BYTES).await {
        Ok(p) => p,
        Err(FrameError::Oversize { .. }) => {
            record_violation(&shared, peer, Violation::OversizeFrame);
            return;
        }
        Err(_) => return, // transport teardown; not a violation
    };
    // 4. Decode, chain-check, dispatch, reply.
    match dispatch(&shared, protocol, peer, &payload) {
        Ok(reply) => {
            let _ = write_frame(&mut s, &reply, MAX_FRAME_BYTES).await;
            let _ = futures::io::AsyncWriteExt::close(&mut s).await;
        }
        Err(violation) => {
            record_violation(&shared, peer, violation);
        }
    }
}

/// Chain-ID law shared by every envelope (ch01 §10.4).
fn check_chain(shared: &Shared, chain_id: &[u8; 32]) -> Result<(), Violation> {
    if chain_id == &shared.config.identity.chain_id {
        Ok(())
    } else {
        Err(Violation::WrongChainEnvelope)
    }
}

/// Duplicate-cache insert; `true` = first sight.
fn dup_fresh(shared: &Shared, protocol: Protocol, payload: &[u8]) -> bool {
    let Some(lane) = dup_lane(protocol) else {
        return true;
    };
    let digest = message_digest(protocol, payload);
    lock(&shared.dups)[lane].insert(digest)
}

fn dispatch(
    shared: &Arc<Shared>,
    protocol: Protocol,
    peer: PeerId,
    payload: &[u8],
) -> Result<Vec<u8>, Violation> {
    match protocol {
        Protocol::Handshake => Err(Violation::MalformedEnvelope), // unreachable: routed earlier
        Protocol::BraidHeader => {
            let msg =
                HeaderMsgV1::decode_canonical(payload).map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, msg.chain_id())?;
            match msg {
                HeaderMsgV1::Announce { header, .. } => {
                    if dup_fresh(shared, protocol, payload) {
                        shared.emit(P2pEvent::Inbound {
                            peer,
                            item: InboundItem::HeaderAnnounce { header: header.0 },
                        });
                    }
                    Ok(HeaderReplyV1::Ack.encode_canonical())
                }
                HeaderMsgV1::Request { header_hash, .. } => {
                    let reply = match shared.store.header(&header_hash) {
                        Some(bytes) => HeaderReplyV1::Header(Bounded(bytes)),
                        None => HeaderReplyV1::NotFound,
                    };
                    Ok(reply.encode_canonical())
                }
            }
        }
        Protocol::BraidBody => {
            let req = BodyRequestV1::decode_canonical(payload)
                .map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            let reply = match shared.store.body(&req.block_hash) {
                Some(bytes) => BodyReplyV1::Body(Bounded(bytes)),
                None => BodyReplyV1::NotFound,
            };
            Ok(reply.encode_canonical())
        }
        Protocol::BraidVote => {
            let req =
                VotePushV1::decode_canonical(payload).map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            if dup_fresh(shared, protocol, payload) {
                shared.emit(P2pEvent::Inbound {
                    peer,
                    item: InboundItem::Vote { vote: req.vote.0 },
                });
                Ok(PushReplyV1::Accepted.encode_canonical())
            } else {
                Ok(PushReplyV1::Duplicate.encode_canonical())
            }
        }
        Protocol::LumenTx => {
            let req =
                TxPushV1::decode_canonical(payload).map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            if dup_fresh(shared, protocol, payload) {
                shared.emit(P2pEvent::Inbound {
                    peer,
                    item: InboundItem::Tx { tx: req.tx.0 },
                });
                Ok(PushReplyV1::Accepted.encode_canonical())
            } else {
                Ok(PushReplyV1::Duplicate.encode_canonical())
            }
        }
        Protocol::SyncRange => {
            let req = RangeRequestV1::decode_canonical(payload)
                .map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            let max = req.max_headers.min(MAX_RANGE_HEADERS);
            let (headers, more) = shared.store.header_range(req.start_height, max);
            let mut list: Vec<Bounded<{ crate::envelope::MAX_HEADER_BYTES }>> = headers
                .into_iter()
                .take(max as usize)
                .map(Bounded)
                .collect();
            list.truncate(MAX_RANGE_HEADERS as usize);
            let mut reply = RangeReplyV1 {
                chain_id: shared.config.identity.chain_id,
                headers: BoundedList(list),
                more: Flag(more),
            };
            // Never emit an undeliverable oversize frame (Ascent W7 law).
            reply.fit_to_budget(RANGE_REPLY_BYTE_BUDGET);
            Ok(reply.encode_canonical())
        }
        Protocol::SyncSnapshot => {
            let req = SnapshotChunkRequestV1::decode_canonical(payload)
                .map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            let reply = match shared
                .store
                .snapshot_chunk(&req.snapshot_root, req.chunk_index)
            {
                Some((total_chunks, chunk)) => SnapshotReplyV1::Chunk {
                    total_chunks,
                    chunk: Bounded(chunk),
                },
                None => SnapshotReplyV1::NotFound,
            };
            Ok(reply.encode_canonical())
        }
        Protocol::BlobShard => {
            let req = ShardRequestV1::decode_canonical(payload)
                .map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            let reply = match shared.store.shard(&req.content_root, req.shard_index) {
                Some(bytes) => ShardReplyV1::Shard(Bounded(bytes)),
                None => ShardReplyV1::NotFound,
            };
            Ok(reply.encode_canonical())
        }
        Protocol::LoomReceipt => {
            let req = LoomReceiptPushV1::decode_canonical(payload)
                .map_err(|_| Violation::MalformedEnvelope)?;
            check_chain(shared, &req.chain_id)?;
            if !shared.config.loom_lane_enabled {
                // Lane OFF at genesis: explicit disabled answer, no dispatch
                // (plan §7.7: never empty success).
                return Ok(PushReplyV1::FeatureDisabled.encode_canonical());
            }
            if dup_fresh(shared, protocol, payload) {
                shared.emit(P2pEvent::Inbound {
                    peer,
                    item: InboundItem::LoomReceipt {
                        receipt: req.receipt.0,
                    },
                });
                Ok(PushReplyV1::Accepted.encode_canonical())
            } else {
                Ok(PushReplyV1::Duplicate.encode_canonical())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound worker (one per peer): single in-flight, priority-first
// ---------------------------------------------------------------------------

async fn outbox_worker(
    shared: Arc<Shared>,
    peer: PeerId,
    outbox: Arc<Mutex<Outbox>>,
    notify: Arc<Notify>,
    mut ready_rx: watch::Receiver<ReadyState>,
) {
    loop {
        // Wait until the session is handshake-complete.
        loop {
            match *ready_rx.borrow() {
                ReadyState::Ready => break,
                ReadyState::Rejected => {
                    lock(&outbox).fail_all(SendError::PeerRejected);
                }
                ReadyState::Pending => {}
            }
            if ready_rx.changed().await.is_err() {
                lock(&outbox).fail_all(SendError::NodeShutdown);
                return;
            }
        }
        // Dequeue (priority lane strictly first).
        let item = lock(&outbox).pop();
        let Some(mut item) = item else {
            tokio::select! {
                _ = notify.notified() => {}
                changed = ready_rx.changed() => {
                    if changed.is_err() {
                        lock(&outbox).fail_all(SendError::NodeShutdown);
                        return;
                    }
                }
            }
            continue;
        };
        // One in-flight request: open, write, await reply.
        let mut control = shared.control.clone();
        let outcome: Result<Vec<u8>, SendError> = async {
            let mut s = control
                .open_stream(peer, sp(item.protocol))
                .await
                .map_err(|_| SendError::Disconnected)?;
            write_frame(&mut s, &item.payload, MAX_FRAME_BYTES)
                .await
                .map_err(|_| SendError::Disconnected)?;
            let reply = read_frame(&mut s, MAX_FRAME_BYTES)
                .await
                .map_err(|_| SendError::Disconnected)?;
            let _ = futures::io::AsyncWriteExt::close(&mut s).await;
            Ok(reply)
        }
        .await;
        match outcome {
            Ok(reply) => {
                let _ = item.reply.send(Ok(reply));
            }
            Err(err) => {
                item.attempts_left = item.attempts_left.saturating_sub(1);
                if item.attempts_left == 0 {
                    let _ = item.reply.send(Err(err));
                } else {
                    lock(&outbox).push_front(item);
                }
                // Do not hot-loop against a broken session; yield until the
                // ready state changes or a short retry pause elapses.
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    changed = ready_rx.changed() => {
                        if changed.is_err() {
                            lock(&outbox).fail_all(SendError::NodeShutdown);
                            return;
                        }
                    }
                }
            }
        }
    }
}
