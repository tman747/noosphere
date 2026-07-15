//! Production binding between the synchronous node seams and `noos-p2p`.
//!
//! The transport remains asynchronous; callers cross a bounded command
//! bridge owned by the supervisor. Peer selection is deterministic round
//! robin over handshake-complete peers, while pushes fan out to every ready
//! peer. Returned bytes are always decoded and then revalidated by consensus.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use noos_braid::{BlockHeaderV1, FinalityCertificateV1};
use noos_codec::{NoosDecode, NoosEncode};
use noos_da::{encode_body, BodyDaClaimV1, ShardCandidateV1, BODY_TOTAL_SHARDS};
use noos_ground::GroundTicketV1;
use noos_p2p::{
    BodyReplyV1, LightUpdateReplyV1, Multiaddr, P2pHandle, PeerId, ProtocolStore, RangeReplyV1,
};
use noos_witness::vote::FinalityVoteV1;
use tokio::runtime::Handle;

use crate::store_port::{key_header, key_height, StorePort};
use crate::supervisor::StoreClient;
use crate::sync::{EdgeError, NetworkEdge};
use crate::Hash32;

/// Production transport settings. Networking is enabled by default; an
/// empty bootstrap list means listen-and-serve until another peer dials.
#[derive(Debug, Clone)]
pub struct NetworkSettings {
    pub enabled: bool,
    pub listen: Multiaddr,
    pub bootstrap: Vec<Multiaddr>,
    /// Explicit identity seed. `None` loads/creates `p2p-key` in the data
    /// directory using the OS CSPRNG.
    pub keypair_seed: Option<[u8; 32]>,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .unwrap_or_else(|_| unreachable!("static multiaddr parses")),
            bootstrap: Vec::new(),
            keypair_seed: None,
        }
    }
}

const TICKET_BYTES: usize = 76;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn decode_header_ticket(bytes: &[u8]) -> Result<(BlockHeaderV1, GroundTicketV1), EdgeError> {
    let split = bytes
        .len()
        .checked_sub(TICKET_BYTES)
        .ok_or(EdgeError::Malformed)?;
    let header =
        BlockHeaderV1::decode_canonical(&bytes[..split]).map_err(|_| EdgeError::Malformed)?;
    let ticket = GroundTicketV1::decode(&bytes[split..]).ok_or(EdgeError::Malformed)?;
    Ok((header, ticket))
}

/// Encodes the production header-announcement payload consumed by
/// [`decode_header_announce`].  Deterministic fault harnesses use this exact
/// boundary rather than inventing a simulation-only message shape.
pub fn encode_header_announce(header: &BlockHeaderV1, ticket: &GroundTicketV1) -> Vec<u8> {
    let mut bytes = header.encode_canonical();
    bytes.extend_from_slice(&ticket.encode());
    bytes
}

/// Read-only protocol view over the supervisor's sole store-writer task.
///
/// This adapter never opens the database and never owns a second `Store`.
/// Every lookup is a bounded channel round trip to the existing store task.
/// The shard cache is derived, immutable chain data and contains no durable
/// state.
pub struct NodeProtocolStore {
    store: StoreClient,
    shards: Mutex<BTreeMap<(Hash32, u32), Vec<u8>>>,
}

impl NodeProtocolStore {
    #[must_use]
    pub fn new(store: StoreClient) -> Self {
        Self {
            store,
            shards: Mutex::new(BTreeMap::new()),
        }
    }

    fn cache_body_shards(&self, body: &[u8]) {
        let Ok(encoded) = encode_body(body) else {
            return;
        };
        let content_root = *encoded.claim().content_root.as_bytes();
        let mut cache = lock(&self.shards);
        for index in 0..u32::try_from(BODY_TOTAL_SHARDS).unwrap_or(0) {
            if let Some(bytes) = encoded.shards().get(index as usize) {
                cache.insert((content_root, index), bytes.clone());
            }
        }
    }
}

impl ProtocolStore for NodeProtocolStore {
    fn header(&self, header_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.store
            .get_header(&key_header(header_hash))
            .ok()
            .flatten()
    }

    fn body(&self, block_hash: &[u8; 32]) -> Option<Vec<u8>> {
        let body = self.store.get_blob(block_hash).ok().flatten()?;
        self.cache_body_shards(&body);
        Some(body)
    }

    fn header_range(&self, start_height: u64, max_headers: u32) -> (Vec<Vec<u8>>, bool) {
        let mut headers = Vec::new();
        for offset in 0..u64::from(max_headers) {
            let Some(height) = start_height.checked_add(offset) else {
                break;
            };
            let Ok(Some(hash)) = self.store.get_index(&key_height(height)) else {
                break;
            };
            let Ok(hash) = <[u8; 32]>::try_from(hash.as_slice()) else {
                break;
            };
            let Ok(Some(header)) = self.store.get_header(&key_header(&hash)) else {
                break;
            };
            headers.push(header);
        }
        let next = start_height.saturating_add(headers.len() as u64);
        let more = self
            .store
            .get_index(&key_height(next))
            .ok()
            .flatten()
            .is_some();
        (headers, more)
    }

    fn shard(&self, content_root: &[u8; 32], shard_index: u32) -> Option<Vec<u8>> {
        lock(&self.shards)
            .get(&(*content_root, shard_index))
            .cloned()
    }
}

/// `NetworkEdge` backed by a live [`P2pHandle`].
#[derive(Clone)]
pub struct P2pNetworkEdge {
    handle: P2pHandle,
    runtime: Handle,
    peers: Arc<Mutex<Vec<PeerId>>>,
    cursor: Arc<AtomicUsize>,
}

impl P2pNetworkEdge {
    #[must_use]
    pub fn new(handle: P2pHandle, runtime: Handle) -> Self {
        Self {
            handle,
            runtime,
            peers: Arc::new(Mutex::new(Vec::new())),
            cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Marks a handshake-complete peer eligible for requests and gossip.
    pub fn peer_ready(&self, peer: PeerId) {
        let mut peers = lock(&self.peers);
        if !peers.contains(&peer) {
            peers.push(peer);
            peers.sort_by_key(ToString::to_string);
        }
    }

    /// Removes a disconnected/rejected peer from selection immediately.
    pub fn peer_gone(&self, peer: &PeerId) {
        lock(&self.peers).retain(|candidate| candidate != peer);
    }

    fn select_peer(&self) -> Result<PeerId, EdgeError> {
        let peers = lock(&self.peers);
        if peers.is_empty() {
            return Err(EdgeError::Unavailable);
        }
        let index = self
            .cursor
            .fetch_add(1, Ordering::Relaxed)
            .checked_rem(peers.len())
            .unwrap_or(0);
        Ok(peers[index])
    }

    fn peers(&self) -> Vec<PeerId> {
        lock(&self.peers).clone()
    }

    /// Async header push to every ready peer (p2p-task context; the sync
    /// [`NetworkEdge::announce_header`] wraps the same wire form for the
    /// consensus thread).
    pub async fn push_header(&self, header: &BlockHeaderV1, ticket: &GroundTicketV1) {
        let bytes = encode_header_announce(header, ticket);
        for peer in self.peers() {
            let _ = self.handle.announce_header(peer, bytes.clone()).await;
        }
    }

    /// Async tx push to every ready peer (same framing as `announce_tx`).
    pub async fn push_tx(&self, tx_bytes: &[u8], wit_bytes: &[u8]) {
        if !noos_lumen::wwm::carrier_len_valid(tx_bytes.len(), wit_bytes.len()) {
            return;
        }
        let Ok(tx_len) = u32::try_from(tx_bytes.len()) else {
            return;
        };
        let mut bytes = Vec::with_capacity(
            tx_bytes
                .len()
                .saturating_add(wit_bytes.len())
                .saturating_add(4),
        );
        bytes.extend_from_slice(&tx_len.to_le_bytes());
        bytes.extend_from_slice(tx_bytes);
        bytes.extend_from_slice(wit_bytes);
        for peer in self.peers() {
            let _ = self.handle.push_tx(peer, bytes.clone()).await;
        }
    }

    /// Async finality-vote push to every ready peer.
    pub async fn push_vote(&self, vote: &FinalityVoteV1) {
        let bytes = vote.encode_canonical();
        for peer in self.peers() {
            let _ = self.handle.push_vote(peer, bytes.clone()).await;
        }
    }
}

impl NetworkEdge for P2pNetworkEdge {
    fn request_headers(
        &mut self,
        from_height: u64,
        max: u32,
    ) -> Result<Vec<(BlockHeaderV1, GroundTicketV1)>, EdgeError> {
        let peer = self.select_peer()?;
        let reply = self
            .runtime
            .block_on(self.handle.request_range(peer, from_height, max))
            .map_err(|_| EdgeError::Unavailable)?;
        let RangeReplyV1 { headers, .. } = reply;
        headers
            .0
            .iter()
            .map(|item| decode_header_ticket(&item.0))
            .collect()
    }

    fn request_body(
        &mut self,
        body_da_root: &Hash32,
    ) -> Result<(BodyDaClaimV1, Vec<ShardCandidateV1>), EdgeError> {
        let peer = self.select_peer()?;
        let reply = self
            .runtime
            .block_on(self.handle.request_body(peer, *body_da_root))
            .map_err(|_| EdgeError::Unavailable)?;
        let BodyReplyV1::Body(body) = reply else {
            return Err(EdgeError::Unavailable);
        };
        let encoded = encode_body(&body.0).map_err(|_| EdgeError::Malformed)?;
        if encoded.shard_root().as_bytes() != body_da_root {
            return Err(EdgeError::Malformed);
        }
        let mut shards = Vec::with_capacity(BODY_TOTAL_SHARDS);
        for index in 0..u32::try_from(BODY_TOTAL_SHARDS).map_err(|_| EdgeError::Malformed)? {
            shards.push(encoded.candidate(index).map_err(|_| EdgeError::Malformed)?);
        }
        Ok((*encoded.claim(), shards))
    }

    fn request_certificates(
        &mut self,
        _after_epoch: u64,
        _max: u32,
    ) -> Result<Vec<FinalityCertificateV1>, EdgeError> {
        // Certificates are carried in block bodies/range validation; there is
        // no ninth application protocol and the eight-protocol list is closed.
        Ok(Vec::new())
    }

    fn request_light_updates(
        &mut self,
        from_height: u64,
        max: u32,
    ) -> Result<LightUpdateReplyV1, EdgeError> {
        let peer = self.select_peer()?;
        self.runtime
            .block_on(self.handle.request_light_updates(peer, from_height, max))
            .map_err(|_| EdgeError::Malformed)
    }

    fn announce_header(&mut self, header: &BlockHeaderV1, ticket: &GroundTicketV1) {
        let bytes = encode_header_announce(header, ticket);
        for peer in self.peers() {
            let _ = self
                .runtime
                .block_on(self.handle.announce_header(peer, bytes.clone()));
        }
    }

    fn announce_tx(&mut self, tx_bytes: &[u8], wit_bytes: &[u8]) {
        if !noos_lumen::wwm::carrier_len_valid(tx_bytes.len(), wit_bytes.len()) {
            return;
        }
        let Ok(tx_len) = u32::try_from(tx_bytes.len()) else {
            return;
        };
        let mut bytes = Vec::with_capacity(
            tx_bytes
                .len()
                .saturating_add(wit_bytes.len())
                .saturating_add(4),
        );
        bytes.extend_from_slice(&tx_len.to_le_bytes());
        bytes.extend_from_slice(tx_bytes);
        bytes.extend_from_slice(wit_bytes);
        for peer in self.peers() {
            let _ = self
                .runtime
                .block_on(self.handle.push_tx(peer, bytes.clone()));
        }
    }

    fn announce_vote(&mut self, vote: &FinalityVoteV1) {
        let bytes = vote.encode_canonical();
        for peer in self.peers() {
            let _ = self
                .runtime
                .block_on(self.handle.push_vote(peer, bytes.clone()));
        }
    }
}

/// Decodes the bounded tx+witness push payload used by `announce_tx`.
pub fn decode_tx_push(bytes: &[u8]) -> Result<(&[u8], &[u8]), EdgeError> {
    let raw_len = bytes.get(..4).ok_or(EdgeError::Malformed)?;
    let tx_len = u32::from_le_bytes(raw_len.try_into().map_err(|_| EdgeError::Malformed)?) as usize;
    let split = 4usize.checked_add(tx_len).ok_or(EdgeError::Malformed)?;
    if split > bytes.len() {
        return Err(EdgeError::Malformed);
    }
    Ok((&bytes[4..split], &bytes[split..]))
}

/// Decodes an inbound header announce into the ordinary consensus pair.
pub fn decode_header_announce(bytes: &[u8]) -> Result<(BlockHeaderV1, GroundTicketV1), EdgeError> {
    decode_header_ticket(bytes)
}
