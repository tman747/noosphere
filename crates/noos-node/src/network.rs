//! Production binding between the synchronous node seams and `noos-p2p`.
//!
//! The transport remains asynchronous; callers cross a bounded command
//! bridge owned by the supervisor. Peer selection is deterministic round
//! robin over handshake-complete peers, while pushes fan out to every ready
//! peer. Returned bytes are always decoded and then revalidated by consensus.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use noos_braid::{BlockHeaderV1, FinalityCertificateV1};
use noos_codec::{NoosDecode, NoosEncode};
use noos_da::{content_root, encode_body, BodyDaClaimV1, ShardCandidateV1};
use noos_ground::GroundTicketV1;
use noos_p2p::{
    LightUpdateReplyV1, Multiaddr, P2pHandle, PeerId, ProtocolStore, RangeReplyV1, MAX_TX_BYTES,
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
const TX_BATCH_SENTINEL: u32 = u32::MAX;
const TX_BATCH_HEADER_BYTES: usize = 6;
const TX_BATCH_ITEM_HEADER_BYTES: usize = 8;

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

fn encode_tx_push(tx_bytes: &[u8], wit_bytes: &[u8]) -> Result<Vec<u8>, EdgeError> {
    if !noos_lumen::wwm::carrier_len_valid(tx_bytes.len(), wit_bytes.len()) {
        return Err(EdgeError::Malformed);
    }
    let tx_len = u32::try_from(tx_bytes.len()).map_err(|_| EdgeError::Malformed)?;
    let capacity = tx_bytes
        .len()
        .checked_add(wit_bytes.len())
        .and_then(|length| length.checked_add(4))
        .ok_or(EdgeError::Malformed)?;
    if capacity > MAX_TX_BYTES as usize {
        return Err(EdgeError::Malformed);
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&tx_len.to_le_bytes());
    bytes.extend_from_slice(tx_bytes);
    bytes.extend_from_slice(wit_bytes);
    Ok(bytes)
}

fn encode_tx_batch_push(envelopes: &[(&[u8], &[u8])]) -> Result<Vec<u8>, EdgeError> {
    let count = u16::try_from(envelopes.len()).map_err(|_| EdgeError::Malformed)?;
    if count == 0 {
        return Err(EdgeError::Malformed);
    }
    let mut capacity = TX_BATCH_HEADER_BYTES;
    for (tx_bytes, wit_bytes) in envelopes {
        if !noos_lumen::wwm::carrier_len_valid(tx_bytes.len(), wit_bytes.len()) {
            return Err(EdgeError::Malformed);
        }
        capacity = capacity
            .checked_add(TX_BATCH_ITEM_HEADER_BYTES)
            .and_then(|length| length.checked_add(tx_bytes.len()))
            .and_then(|length| length.checked_add(wit_bytes.len()))
            .ok_or(EdgeError::Malformed)?;
    }
    if capacity > MAX_TX_BYTES as usize {
        return Err(EdgeError::Malformed);
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&TX_BATCH_SENTINEL.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    for (tx_bytes, wit_bytes) in envelopes {
        let tx_len = u32::try_from(tx_bytes.len()).map_err(|_| EdgeError::Malformed)?;
        let wit_len = u32::try_from(wit_bytes.len()).map_err(|_| EdgeError::Malformed)?;
        bytes.extend_from_slice(&tx_len.to_le_bytes());
        bytes.extend_from_slice(&wit_len.to_le_bytes());
        bytes.extend_from_slice(tx_bytes);
        bytes.extend_from_slice(wit_bytes);
    }
    Ok(bytes)
}

/// Read-only protocol view over the supervisor's sole store-writer task.
///
/// This adapter never opens the database and never owns a second `Store`.
/// Every lookup is a bounded channel round trip to the existing store task.
/// The shard cache is derived, immutable chain data and contains no durable
/// state.
struct CachedBody {
    block_hash: Hash32,
    content_root: Hash32,
    bytes: Vec<u8>,
    shards: Option<Vec<Vec<u8>>>,
}

impl CachedBody {
    fn chunk(&self, offset: u64, max_bytes: u32) -> Option<(u64, Vec<u8>)> {
        let total = u64::try_from(self.bytes.len()).ok()?;
        let start = usize::try_from(offset).ok()?;
        if start > self.bytes.len() {
            return None;
        }
        let end = start
            .saturating_add(max_bytes as usize)
            .min(self.bytes.len());
        Some((total, self.bytes[start..end].to_vec()))
    }
}

pub struct NodeProtocolStore {
    store: StoreClient,
    body: Mutex<Option<CachedBody>>,
}

impl NodeProtocolStore {
    #[must_use]
    pub fn new(store: StoreClient) -> Self {
        Self {
            store,
            body: Mutex::new(None),
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

    fn body_chunk(
        &self,
        block_hash: &[u8; 32],
        offset: u64,
        max_bytes: u32,
    ) -> Option<(u64, Vec<u8>)> {
        {
            let cached = lock(&self.body);
            if let Some(body) = cached
                .as_ref()
                .filter(|body| body.block_hash == *block_hash)
            {
                return body.chunk(offset, max_bytes);
            }
        }

        let bytes = self.store.get_blob(block_hash).ok().flatten()?;
        let cached = CachedBody {
            block_hash: *block_hash,
            content_root: content_root(&bytes).ok()?.into_bytes(),
            bytes,
            shards: None,
        };
        let chunk = cached.chunk(offset, max_bytes)?;
        *lock(&self.body) = Some(cached);
        Some(chunk)
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
        let mut cached = lock(&self.body);
        let body = cached
            .as_mut()
            .filter(|body| body.content_root == *content_root)?;
        if body.shards.is_none() {
            body.shards = Some(encode_body(&body.bytes).ok()?.into_shards());
        }
        body.shards.as_ref()?.get(shard_index as usize).cloned()
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

    pub(crate) fn peers(&self) -> Vec<PeerId> {
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
        let Ok(bytes) = encode_tx_push(tx_bytes, wit_bytes) else {
            return;
        };
        for peer in self.peers() {
            let _ = self.handle.push_tx(peer, bytes.clone()).await;
        }
    }

    /// Packs accepted transactions into bounded frames on the existing
    /// transaction protocol. Input order is preserved within and across
    /// frames; no additional application protocol is introduced.
    pub async fn push_tx_batch(&self, envelopes: &[(Vec<u8>, Vec<u8>)]) {
        let peers = self.peers();
        let mut start = 0_usize;
        while start < envelopes.len() {
            let (first_tx, first_wit) = &envelopes[start];
            if !noos_lumen::wwm::carrier_len_valid(first_tx.len(), first_wit.len()) {
                start = start.saturating_add(1);
                continue;
            }
            let mut end = start;
            let mut frame_bytes = TX_BATCH_HEADER_BYTES;
            while let Some((tx_bytes, wit_bytes)) = envelopes.get(end) {
                if !noos_lumen::wwm::carrier_len_valid(tx_bytes.len(), wit_bytes.len()) {
                    break;
                }
                let Some(item_bytes) = TX_BATCH_ITEM_HEADER_BYTES
                    .checked_add(tx_bytes.len())
                    .and_then(|length| length.checked_add(wit_bytes.len()))
                else {
                    break;
                };
                if frame_bytes
                    .checked_add(item_bytes)
                    .is_none_or(|length| length > MAX_TX_BYTES as usize)
                    || end.saturating_sub(start) >= u16::MAX as usize
                {
                    break;
                }
                frame_bytes += item_bytes;
                end += 1;
            }
            if end == start {
                start = start.saturating_add(1);
                continue;
            }
            let frame = if end == start.saturating_add(1) {
                encode_tx_push(&envelopes[start].0, &envelopes[start].1)
            } else {
                let batch = envelopes[start..end]
                    .iter()
                    .map(|(tx_bytes, wit_bytes)| (tx_bytes.as_slice(), wit_bytes.as_slice()))
                    .collect::<Vec<_>>();
                encode_tx_batch_push(&batch)
            };
            if let Ok(frame) = frame {
                for peer in &peers {
                    let _ = self.handle.push_tx(*peer, frame.clone()).await;
                }
            }
            start = end;
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
        let body = self
            .runtime
            .block_on(self.handle.request_body(peer, *body_da_root))
            .map_err(|_| EdgeError::Unavailable)?
            .ok_or(EdgeError::Unavailable)?;
        let encoded = encode_body(&body).map_err(|_| EdgeError::Malformed)?;
        if encoded.shard_root().as_bytes() != body_da_root {
            return Err(EdgeError::Malformed);
        }
        let claim = *encoded.claim();
        let shards = encoded
            .into_candidates()
            .map_err(|_| EdgeError::Malformed)?;
        Ok((claim, shards))
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
        let Ok(bytes) = encode_tx_push(tx_bytes, wit_bytes) else {
            return;
        };
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

/// Decodes either the legacy one-envelope frame or a bounded batch frame.
pub fn decode_tx_pushes(bytes: &[u8]) -> Result<Vec<(&[u8], &[u8])>, EdgeError> {
    let raw_prefix = bytes.get(..4).ok_or(EdgeError::Malformed)?;
    let prefix = u32::from_le_bytes(raw_prefix.try_into().map_err(|_| EdgeError::Malformed)?);
    if prefix != TX_BATCH_SENTINEL {
        return decode_tx_push(bytes).map(|envelope| vec![envelope]);
    }
    let raw_count = bytes
        .get(4..TX_BATCH_HEADER_BYTES)
        .ok_or(EdgeError::Malformed)?;
    let count =
        u16::from_le_bytes(raw_count.try_into().map_err(|_| EdgeError::Malformed)?) as usize;
    if count == 0 {
        return Err(EdgeError::Malformed);
    }
    let mut cursor = TX_BATCH_HEADER_BYTES;
    let mut envelopes = Vec::with_capacity(count);
    for _ in 0..count {
        let header_end = cursor
            .checked_add(TX_BATCH_ITEM_HEADER_BYTES)
            .ok_or(EdgeError::Malformed)?;
        let header = bytes.get(cursor..header_end).ok_or(EdgeError::Malformed)?;
        let tx_len =
            u32::from_le_bytes(header[..4].try_into().map_err(|_| EdgeError::Malformed)?) as usize;
        let wit_len =
            u32::from_le_bytes(header[4..].try_into().map_err(|_| EdgeError::Malformed)?) as usize;
        let tx_end = header_end.checked_add(tx_len).ok_or(EdgeError::Malformed)?;
        let wit_end = tx_end.checked_add(wit_len).ok_or(EdgeError::Malformed)?;
        let tx_bytes = bytes.get(header_end..tx_end).ok_or(EdgeError::Malformed)?;
        let wit_bytes = bytes.get(tx_end..wit_end).ok_or(EdgeError::Malformed)?;
        if !noos_lumen::wwm::carrier_len_valid(tx_bytes.len(), wit_bytes.len()) {
            return Err(EdgeError::Malformed);
        }
        envelopes.push((tx_bytes, wit_bytes));
        cursor = wit_end;
    }
    if cursor != bytes.len() {
        return Err(EdgeError::Malformed);
    }
    Ok(envelopes)
}

/// Decodes an inbound header announce into the ordinary consensus pair.
pub fn decode_header_announce(bytes: &[u8]) -> Result<(BlockHeaderV1, GroundTicketV1), EdgeError> {
    decode_header_ticket(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_push_batch_round_trips_in_order() {
        let inputs = [
            (b"transaction-a".as_slice(), b"witness-a".as_slice()),
            (b"transaction-b".as_slice(), b"witness-b".as_slice()),
            (b"transaction-c".as_slice(), b"witness-c".as_slice()),
        ];
        let encoded = encode_tx_batch_push(&inputs).unwrap();
        assert_eq!(decode_tx_pushes(&encoded).unwrap(), inputs);
        let single = encode_tx_push(inputs[0].0, inputs[0].1).unwrap();
        assert_eq!(decode_tx_pushes(&single).unwrap(), vec![inputs[0]]);
    }

    #[test]
    fn transaction_push_batch_rejects_noncanonical_framing() {
        let inputs = [(b"transaction".as_slice(), b"witness".as_slice())];
        let encoded = encode_tx_batch_push(&inputs).unwrap();
        assert!(decode_tx_pushes(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_tx_pushes(&trailing).is_err());
        let mut empty = Vec::from(TX_BATCH_SENTINEL.to_le_bytes());
        empty.extend_from_slice(&0_u16.to_le_bytes());
        assert!(decode_tx_pushes(&empty).is_err());
    }
}
