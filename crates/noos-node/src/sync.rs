//! Sync modes behind the thin [`NetworkEdge`] trait (ch01 §10.5;
//! plan §7.5; node-v1.md §6).
//! Production nodes bind this seam to [`crate::network::P2pNetworkEdge`].
//! Tests retain an explicit no-network fixture so the sync state machine can
//! be exercised without opening sockets.
//!
//! * **Header-first full sync** — pull `(header, ticket)` ranges, verify
//!   tickets/work/retarget/ancestry through the ordinary stage-1/2 law,
//!   pull certificates, then pull bodies from the last trusted state and
//!   execute every transition (the same seven-stage pipeline; nothing is
//!   trusted from the peer).
//! * **Finalized snapshot sync** — fetch a store snapshot generation file
//!   set from several [`SnapshotSource`]s (any file may come from any
//!   source; every byte is verified by the store's own manifest/identity/
//!   proof-sample law on open), then replay + tail-sync.
//! * **Light sync** — headers + Ground work + finality certificates only.
//!
//! Weak-subjectivity checkpoints are SOCIAL INPUTS
//! ([`crate::consensus::NodeCore::apply_social_checkpoint`]) and never
//! override local finality.

use std::path::Path;

use noos_braid::{
    BlockHeaderV1, CheckpointRef, FinalityCertificateV1, EPOCH_LENGTH, MAX_FINALITY_CERTIFICATES,
};
use noos_codec::NoosDecode;
use noos_crypto::{BlsPublicKey, BlsSignature};
use noos_da::{BodyDaClaimV1, ShardCandidateV1};
use noos_ground::{GroundTicketV1, TICKET_ENCODED_BYTES};
use noos_lumen::objects::BoundedList;
use noos_p2p::{
    LightBytes48, LightMemberV1, LightMembershipHandoverV1, LightMembershipSnapshotV1,
    LightMembershipTransitionKind, LightMembershipWitnessV1, LightUpdateItemV1, LightUpdateReplyV1,
    MAX_LIGHT_UPDATE_ITEMS,
};
use noos_witness::finality::{
    bitmap_indices, quorum_threshold, verify_handover_attestation, HandoverBindingV1,
};
use noos_witness::vote::FinalityVoteV1;

use crate::consensus::{ImportOutcome, NodeCore, NodeMode};
use crate::roots::{body_cert_root, body_ticket_root};
use crate::store_port::StorePort;
use crate::{Hash32, NodeError};

/// Edge-layer failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeError {
    /// No peer could serve the request right now.
    Unavailable,
    /// A peer answered with malformed bytes (the peer is penalized by the
    /// transport; the sync layer just moves on).
    Malformed,
}

/// The node's network boundary. Deliberately thin: typed requests plus
/// fire-and-forget announces; every returned object is re-validated by the
/// consensus pipeline, never trusted.
pub trait NetworkEdge: Send {
    /// Sequential `(header, ticket)` range starting at `from_height`.
    fn request_headers(
        &mut self,
        from_height: u64,
        max: u32,
    ) -> Result<Vec<(BlockHeaderV1, GroundTicketV1)>, EdgeError>;

    /// DA claim + shard candidates for the body committed by
    /// `body_da_root`. Peers may return fewer than 16 valid shards; the
    /// pipeline parks the block and re-requests.
    fn request_body(
        &mut self,
        body_da_root: &Hash32,
    ) -> Result<(BodyDaClaimV1, Vec<ShardCandidateV1>), EdgeError>;

    /// Finality certificates targeting epochs strictly above `after_epoch`.
    fn request_certificates(
        &mut self,
        after_epoch: u64,
        max: u32,
    ) -> Result<Vec<FinalityCertificateV1>, EdgeError>;

    /// Finalized light-client history page. Implementations must preserve the
    /// reply's chain/genesis/start bindings; the sync verifier still treats
    /// every byte and compact witness as untrusted.
    fn request_light_updates(
        &mut self,
        _from_height: u64,
        _max: u32,
    ) -> Result<LightUpdateReplyV1, EdgeError> {
        Err(EdgeError::Unavailable)
    }

    fn announce_header(&mut self, header: &BlockHeaderV1, ticket: &GroundTicketV1);
    fn announce_tx(&mut self, tx_bytes: &[u8], wit_bytes: &[u8]);
    fn announce_vote(&mut self, vote: &FinalityVoteV1);
}

/// Explicit no-network test fixture.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct NullEdge;

#[cfg(test)]
impl NetworkEdge for NullEdge {
    fn request_headers(
        &mut self,
        _from_height: u64,
        _max: u32,
    ) -> Result<Vec<(BlockHeaderV1, GroundTicketV1)>, EdgeError> {
        Err(EdgeError::Unavailable)
    }
    fn request_body(
        &mut self,
        _body_da_root: &Hash32,
    ) -> Result<(BodyDaClaimV1, Vec<ShardCandidateV1>), EdgeError> {
        Err(EdgeError::Unavailable)
    }
    fn request_certificates(
        &mut self,
        _after_epoch: u64,
        _max: u32,
    ) -> Result<Vec<FinalityCertificateV1>, EdgeError> {
        Err(EdgeError::Unavailable)
    }
    fn announce_header(&mut self, _header: &BlockHeaderV1, _ticket: &GroundTicketV1) {}
    fn announce_tx(&mut self, _tx_bytes: &[u8], _wit_bytes: &[u8]) {}
    fn announce_vote(&mut self, _vote: &FinalityVoteV1) {}
}

/// One full-sync round: headers first, then certificates, then bodies.
/// Returns the number of blocks that reached the executed chain.
pub fn full_sync_round<P: StorePort>(
    core: &mut NodeCore<P>,
    edge: &mut dyn NetworkEdge,
    batch: u32,
) -> Result<u64, NodeError> {
    let mut progressed: u64 = 0;
    let (head_height, _) = core.head();

    // Header-first: verify tickets/work/retarget/ancestry.
    let headers = match edge.request_headers(head_height.saturating_add(1), batch) {
        Ok(h) => h,
        Err(_) => return Ok(0),
    };
    for (header, ticket) in headers {
        // Bodies from the last trusted state: request per header.
        let (claim, shards) = match edge.request_body(&header.body_da_root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        match core.import_block_owned(&header, &ticket, &claim, shards) {
            Ok(ImportOutcome::Executed { .. }) => progressed = progressed.saturating_add(1),
            Ok(_) => {}
            Err(NodeError::Dag(noos_braid::DagError::DuplicateBlock)) => {}
            Err(e) => return Err(e),
        }
    }

    // Certificates advance finality past what bodies carried.
    if let Ok(certs) = edge.request_certificates(core.finalized().epoch, 16) {
        for cert in certs {
            match core.queue_certificate(cert) {
                Ok(()) | Err(NodeError::Witness(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(progressed)
}

/// Decoded, root-bound material from one compact light update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLightUpdateV1 {
    pub header: BlockHeaderV1,
    pub ticket: GroundTicketV1,
    pub certificates: Vec<FinalityCertificateV1>,
}

/// Decodes all nested lengths and verifies the header commitments to the
/// ticket, certificate list, and compact consensus membership root.
pub fn decode_light_update_item(
    item: &LightUpdateItemV1,
) -> Result<DecodedLightUpdateV1, EdgeError> {
    item.verify_bounds().map_err(|_| EdgeError::Malformed)?;
    let header =
        BlockHeaderV1::decode_canonical(&item.header.0).map_err(|_| EdgeError::Malformed)?;
    if header.height != item.height || item.ground_ticket.0.len() != TICKET_ENCODED_BYTES {
        return Err(EdgeError::Malformed);
    }
    let ticket = GroundTicketV1::decode(&item.ground_ticket.0).ok_or(EdgeError::Malformed)?;
    if body_ticket_root(&ticket).map_err(|_| EdgeError::Malformed)? != header.ground_ticket_root {
        return Err(EdgeError::Malformed);
    }
    let certificates =
        BoundedList::<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>::decode_canonical(
            &item.finality.0,
        )
        .map_err(|_| EdgeError::Malformed)?;
    if body_cert_root(&certificates).map_err(|_| EdgeError::Malformed)?
        != header.finality_certificate_root
        || item.membership.snapshot.root() != header.witness_membership_root
        || certificates
            .iter()
            .any(|certificate| certificate.membership_root != item.membership.snapshot.root())
    {
        return Err(EdgeError::Malformed);
    }
    Ok(DecodedLightUpdateV1 {
        header,
        ticket,
        certificates: certificates.as_slice().to_vec(),
    })
}

/// Compact membership-history failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactMembershipHistoryError {
    EpochRegression,
    MissingHandover,
    UnexpectedHandover,
    HandoverMalformed,
    HandoverBinding,
    WeightMismatch,
    QuorumNotMet,
    AggregateInvalid,
    InvalidEmergencyContinuation,
    FinalityHalted,
}

/// Stateful verifier for compact membership rotation evidence. State is kept
/// across pages; no endpoint can reset it by returning a new snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactMembershipHistoryV1 {
    chain_id: Hash32,
    current: LightMembershipSnapshotV1,
    previous_was_emergency: bool,
}

impl CompactMembershipHistoryV1 {
    #[must_use]
    pub fn new(chain_id: Hash32, trusted: LightMembershipSnapshotV1) -> Self {
        Self {
            chain_id,
            current: trusted,
            previous_was_emergency: false,
        }
    }

    #[must_use]
    pub fn current(&self) -> &LightMembershipSnapshotV1 {
        &self.current
    }

    /// Verifies an old-set quorum handover before installing the new compact
    /// snapshot. Same-epoch items must repeat byte-identical membership and
    /// carry no handover.
    pub fn verify_next(
        &mut self,
        witness: &LightMembershipWitnessV1,
        finalized_checkpoint: CheckpointRef,
    ) -> Result<(), CompactMembershipHistoryError> {
        let next = &witness.snapshot;
        if next.epoch() == self.current.epoch() {
            if next != &self.current {
                return Err(CompactMembershipHistoryError::EpochRegression);
            }
            if !witness.handover.0.is_empty() {
                return Err(CompactMembershipHistoryError::UnexpectedHandover);
            }
            return Ok(());
        }
        if next.epoch() != self.current.epoch().saturating_add(1) {
            return Err(CompactMembershipHistoryError::EpochRegression);
        }
        if witness.handover.0.is_empty() {
            return Err(CompactMembershipHistoryError::MissingHandover);
        }
        let handover = LightMembershipHandoverV1::decode_canonical(&witness.handover.0)
            .map_err(|_| CompactMembershipHistoryError::HandoverMalformed)?;
        if handover.chain_id != self.chain_id
            || handover.old_epoch != self.current.epoch()
            || handover.new_epoch != next.epoch()
            || handover.old_membership_root != self.current.root()
            || handover.new_membership_root != next.root()
            || handover.finalized_checkpoint_epoch != finalized_checkpoint.epoch
            || handover.finalized_checkpoint_hash != finalized_checkpoint.checkpoint_hash
        {
            return Err(CompactMembershipHistoryError::HandoverBinding);
        }
        if handover.kind == LightMembershipTransitionKind::Halt {
            return Err(CompactMembershipHistoryError::FinalityHalted);
        }

        let signer_indices = bitmap_indices(
            &handover.participation_bitmap.0,
            self.current.members().len(),
        )
        .map_err(|_| CompactMembershipHistoryError::HandoverMalformed)?;
        let mut raw = 0_u128;
        let mut effective = 0_u128;
        let mut keys = Vec::with_capacity(signer_indices.len());
        for index in signer_indices {
            let member = self
                .current
                .members()
                .get(index)
                .ok_or(CompactMembershipHistoryError::HandoverMalformed)?;
            raw = raw
                .checked_add(member.raw_weight)
                .ok_or(CompactMembershipHistoryError::WeightMismatch)?;
            effective = effective
                .checked_add(member.effective_weight)
                .ok_or(CompactMembershipHistoryError::WeightMismatch)?;
            keys.push(BlsPublicKey::from_bytes(member.consensus_bls_key.0));
        }
        if raw != handover.raw_weight_sum || effective != handover.effective_weight_sum {
            return Err(CompactMembershipHistoryError::WeightMismatch);
        }
        if raw < quorum_threshold(self.current.total_raw_weight())
            || effective < quorum_threshold(self.current.total_effective_weight())
        {
            return Err(CompactMembershipHistoryError::QuorumNotMet);
        }
        let signature_bytes: [u8; 96] = handover
            .aggregate_signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| CompactMembershipHistoryError::HandoverMalformed)?;
        let binding = HandoverBindingV1 {
            chain_id: self.chain_id,
            epoch: next.epoch(),
            old_membership_root: self.current.root(),
            new_membership_root: next.root(),
            finalized_checkpoint,
        };
        verify_handover_attestation(&binding, &keys, &BlsSignature::from_bytes(signature_bytes))
            .map_err(|_| CompactMembershipHistoryError::AggregateInvalid)?;

        let emergency = handover.kind == LightMembershipTransitionKind::EmergencyContinuation;
        if emergency
            && (self.previous_was_emergency
                || next.root() != self.current.root()
                || next.members() != self.current.members())
        {
            return Err(CompactMembershipHistoryError::InvalidEmergencyContinuation);
        }
        self.current = next.clone();
        self.previous_was_emergency = emergency;
        Ok(())
    }
}

fn project_membership(
    snapshot: &noos_witness::membership::MembershipSnapshotV1,
) -> Result<LightMembershipSnapshotV1, EdgeError> {
    let members = snapshot
        .members()
        .iter()
        .map(|member| LightMemberV1 {
            validator_id: member.validator_id,
            consensus_bls_key: LightBytes48(member.consensus_bls_key.0),
            raw_weight: member.raw_weight,
            effective_weight: member.effective_weight,
        })
        .collect();
    let compact = LightMembershipSnapshotV1::from_members(snapshot.epoch(), members)
        .map_err(|_| EdgeError::Malformed)?;
    if compact.root() != snapshot.root() {
        return Err(EdgeError::Malformed);
    }
    Ok(compact)
}

/// Light-mode sync round: headers + certificates only (ch01 §10.5).
pub fn light_sync_round<P: StorePort>(
    core: &mut NodeCore<P>,
    edge: &mut dyn NetworkEdge,
    batch: u32,
) -> Result<u64, NodeError> {
    debug_assert_eq!(core.cfg.mode, NodeMode::Light);
    let mut progressed = 0_u64;
    // Light mode never executes, so the executed head is pinned at
    // genesis; the header cursor is the best-known DAG tip instead.
    let head_height = core
        .dag()
        .select_head()
        .and_then(|tip| core.dag().get(&tip).map(|s| s.header.height))
        .unwrap_or_else(|| core.head().0);
    let start_height = head_height.saturating_add(1);
    let max_items = batch.clamp(1, MAX_LIGHT_UPDATE_ITEMS);
    if let Ok(reply) = edge.request_light_updates(start_height, max_items) {
        if reply.chain_id != core.chain_id()
            || reply.genesis_hash != core.genesis_hash()
            || reply.requested_start != start_height
            || reply.items.0.len() > max_items as usize
        {
            return Ok(0);
        }
        let mut membership_history: Option<CompactMembershipHistoryV1> = None;
        for item in reply.items.0 {
            let Ok(decoded) = decode_light_update_item(&item) else {
                return Ok(progressed);
            };
            let epoch = decoded.header.height / EPOCH_LENGTH;
            let Ok(expected_full) = core.membership_snapshot(epoch) else {
                return Ok(progressed);
            };
            let Ok(expected_compact) = project_membership(&expected_full) else {
                return Ok(progressed);
            };
            if expected_compact != item.membership.snapshot {
                return Ok(progressed);
            }

            if membership_history.is_none() {
                if epoch == 0 {
                    if !item.membership.handover.0.is_empty() {
                        return Ok(progressed);
                    }
                    membership_history = Some(CompactMembershipHistoryV1::new(
                        core.chain_id(),
                        expected_compact,
                    ));
                } else {
                    let Ok(previous_full) = core.membership_snapshot(epoch.saturating_sub(1))
                    else {
                        return Ok(progressed);
                    };
                    let Ok(previous) = project_membership(&previous_full) else {
                        return Ok(progressed);
                    };
                    membership_history =
                        Some(CompactMembershipHistoryV1::new(core.chain_id(), previous));
                }
            }
            let history = membership_history
                .as_mut()
                .unwrap_or_else(|| unreachable!("initialized above"));
            if history.current().epoch() != item.membership.snapshot.epoch()
                || history.current() != &item.membership.snapshot
            {
                if history
                    .verify_next(&item.membership, decoded.header.finalized_checkpoint)
                    .is_err()
                {
                    return Ok(progressed);
                }
            } else if !item.membership.handover.0.is_empty() {
                return Ok(progressed);
            }

            match core.import_header_light_with_certificates(
                &decoded.header,
                &decoded.ticket,
                &decoded.certificates,
            ) {
                Ok(ImportOutcome::HeaderAccepted { .. }) => {
                    progressed = progressed.saturating_add(1);
                }
                Ok(_) => {}
                Err(NodeError::Dag(noos_braid::DagError::DuplicateBlock)) => {}
                Err(e) => return Err(e),
            }
        }
        return Ok(progressed);
    }

    // Legacy header/range fallback remains valid for protocol-v1 peers and
    // headers with an empty certificate commitment.
    if let Ok(headers) = edge.request_headers(start_height, batch) {
        for (header, ticket) in headers {
            match core.import_header_light(&header, &ticket) {
                Ok(ImportOutcome::HeaderAccepted { .. }) => {
                    progressed = progressed.saturating_add(1);
                }
                Ok(_) => {}
                Err(NodeError::Dag(noos_braid::DagError::DuplicateBlock)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if let Ok(certs) = edge.request_certificates(core.finalized().epoch, 16) {
        for cert in certs {
            let _ = core.queue_certificate(cert);
        }
    }
    Ok(progressed)
}

// ---------------------------------------------------------------------------
// Finalized snapshot sync (multi-peer source abstraction)
// ---------------------------------------------------------------------------

/// A source of store-snapshot files (one peer). File names are relative
/// paths inside the store root (`CURRENT`, `gen-*/...`, `wal/*`,
/// `segments/*`). NOTHING a source returns is trusted: the store's open
/// law re-verifies manifest hashes, per-file hashes, identity, and proof
/// samples.
pub trait SnapshotSource {
    /// Relative paths of every file in the served snapshot root.
    fn list(&self) -> Result<Vec<String>, EdgeError>;
    fn fetch(&self, name: &str) -> Result<Vec<u8>, EdgeError>;
}

/// Snapshot-sync failures.
#[derive(Debug)]
pub enum SnapshotSyncError {
    /// No source produced a usable file set.
    NoUsableSource,
    /// Assembled bytes failed the store's verification law.
    Verification(NodeError),
    Io(std::io::Error),
}

/// Assembles a store root at `dest` from multiple snapshot sources: the
/// file LIST comes from the first source that answers; each file may come
/// from ANY source (round-robin on failure). Verification is entirely the
/// store's open law — a corrupt byte from a lying peer surfaces as a typed
/// open failure, never as accepted state.
pub fn fetch_snapshot_files(
    sources: &mut [Box<dyn SnapshotSource>],
    dest: &Path,
) -> Result<(), SnapshotSyncError> {
    let mut names: Option<Vec<String>> = None;
    for source in sources.iter() {
        if let Ok(list) = source.list() {
            names = Some(list);
            break;
        }
    }
    let names = names.ok_or(SnapshotSyncError::NoUsableSource)?;

    for name in &names {
        // Path hygiene: refuse absolute/parent components from a peer.
        let rel = Path::new(name);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(SnapshotSyncError::NoUsableSource);
        }
        let mut fetched = None;
        for source in sources.iter() {
            if let Ok(bytes) = source.fetch(name) {
                fetched = Some(bytes);
                break;
            }
        }
        let bytes = fetched.ok_or(SnapshotSyncError::NoUsableSource)?;
        let path = dest.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(SnapshotSyncError::Io)?;
        }
        std::fs::write(&path, bytes).map_err(SnapshotSyncError::Io)?;
    }
    Ok(())
}

/// Serves a local store root as a [`SnapshotSource`] (used by tests and by
/// the future p2p binding's `/noos/sync/snapshot/1` server side).
pub struct DirSnapshotSource {
    root: std::path::PathBuf,
    /// Corruption injection hook for tests: names this source lies about.
    pub corrupt: std::collections::BTreeSet<String>,
}

impl DirSnapshotSource {
    #[must_use]
    pub fn new(root: std::path::PathBuf) -> Self {
        DirSnapshotSource {
            root,
            corrupt: std::collections::BTreeSet::new(),
        }
    }

    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::walk(&path, base, out)?;
            } else if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
}

impl SnapshotSource for DirSnapshotSource {
    fn list(&self) -> Result<Vec<String>, EdgeError> {
        let mut out = Vec::new();
        Self::walk(&self.root, &self.root, &mut out).map_err(|_| EdgeError::Unavailable)?;
        out.sort();
        Ok(out)
    }

    fn fetch(&self, name: &str) -> Result<Vec<u8>, EdgeError> {
        let mut bytes = std::fs::read(self.root.join(name)).map_err(|_| EdgeError::Unavailable)?;
        if self.corrupt.contains(name) {
            if let Some(b) = bytes.first_mut() {
                *b ^= 0xFF;
            }
        }
        Ok(bytes)
    }
}
