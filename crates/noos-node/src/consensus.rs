//! The deterministic single-writer consensus core (plan §7.5-7.6;
//! ch01 §3.1, §9.3; node-v1.md §4).
//!
//! ONE owner of ledger + DAG state: every mutation flows through
//! [`NodeCore`] methods on `&mut self`; the supervisor runs it on the
//! dedicated consensus task and every other task talks to it over bounded
//! channels.
//!
//! ## Import pipeline (exact stage order)
//!
//! ```text
//! 0. canonical header decode        (receipt-root interchange dies HERE)
//! 1. header validation              (noos-braid structure + proposer sig)
//! 2. ticket validation              (noos-ground; DAG DuplicateSet; Pulse)
//! 3. DA reconstruction              (noos-da; insufficiency PARKS, never
//!                                    rejects) + body/header cross-check
//! 4. body execution                 (noos-lumen normative order; system
//!                                    transitions first: param activation,
//!                                    emission)
//! 5. root comparison                (six Lumen roots + execution_receipt_
//!                                    root + lumen_receipts_state_root +
//!                                    gas/prices; mismatch = typed invalid)
//! 6. fork choice update             (ForkScore; reorg rollback/replay
//!                                    through the store)
//! 7. finality processing            (noos-witness certificates; finalized
//!                                    pointer advance; anchor refresh)
//! ```
//!
//! ## Pulse anchor law (node-v1.md §4.4)
//!
//! Rule 5 needs "the most recent finalized checkpoint on that branch". The
//! node anchors on the checkpoint NAMED BY THE PARENT HEADER
//! (`parent.finalized_checkpoint`): on-chain data, deterministic across
//! nodes and across time (header-first sync revalidates identically).

use std::collections::BTreeMap;
use std::sync::Arc;

use noos_braid::{
    BlockBodyV1, BlockHeaderV1, Bytes48, Bytes96, CheckpointRef, FinalityCertificateV1,
    GroundTicketWire, HeaderDag, InsertOutcome, ResourcePriceVectorV1, ResourceVectorV1,
    EPOCH_LENGTH, MAX_FINALITY_CERTIFICATES, ZERO_ROOT,
};
use noos_codec::{NoosDecode, NoosEncode};
use noos_crypto::{bls_verify, BlsPublicKey, BlsSecretKey, BlsSignature, DomainId};
use noos_da::{
    encode_body, reconstruct_and_verify, AvailabilityLedger, BodyDaClaimV1, DaError,
    ShardCandidateV1,
};
use noos_ground::{
    median_time_past_ms, pulse_target_v1, slot_from_timestamp, validate_ticket, GroundTicketV1,
    PulseAnchor, TicketContext, U256,
};
use noos_lumen::fees;
use noos_lumen::objects::{BoundedList, ReceiptV1, TransactionWitnessesV1};
use noos_lumen::state::{BlockContext, DeltaEntry, LumenLedger, LumenRoots, StateDelta, TreeId};
use noos_store::{Blob, WriteSet};
use noos_witness::bond::WitnessBondV1;
use noos_witness::finality::{Ancestry, FinalityTracker, IngestOutcome, SnapshotRegistry};
use noos_witness::membership::{build_snapshot, SnapshotOutcome};

use crate::auth::{DeferredEngine, NodeAuthVerifier};
use crate::genesis::{
    BuiltGenesis, GenesisSpec, DEVNET_PROPOSER_SEED, PROPOSER_POOL_ACCOUNT, TREASURY_ACCOUNT,
    WITNESS_POOL_ACCOUNT,
};
use crate::mempool::{AdmitError, Mempool, MempoolConfig, SourceId};
use crate::metrics::Metrics;
use crate::roots::{
    body_cert_root, body_receipt_root, body_ticket_root, body_tx_root, body_witness_root,
    check_blob_descriptors, da_form_bytes, sum_usage,
};
use crate::store_port::{
    key_certificate, key_header, key_height, StorePort, KEY_FINALIZED, KEY_HEAD, KEY_JUSTIFIED,
};
use crate::view::ChainView;
use crate::{Hash32, NodeError};

/// Devnet beacon-randomness fixture feeding reserve sampling until the
/// live beacon output is wired through membership (node-v1.md §9 gap G3).
pub const DEVNET_BEACON_RANDOMNESS: [u8; 32] = [0x5A; 32];

/// Node operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Full validation: headers, tickets, DA, execution, finality.
    Full,
    /// Headers + Ground work + finality certificates only (ch01 §10.5).
    Light,
}

/// Node configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub mode: NodeMode,
    /// Observer mode: transaction submission is a disabled feature.
    pub observer: bool,
    pub view_retention_blocks: u64,
    pub mempool: MempoolConfig,
    /// Weak-subjectivity checkpoint. SOCIAL INPUT (ch01 §10.5): obtained
    /// from social sources, labeled, and NEVER able to override local
    /// finality — see [`NodeCore::apply_social_checkpoint`].
    pub social_checkpoint: Option<CheckpointRef>,
    /// Devnet fixture witness bonds backing the epoch snapshot registry.
    pub witness_bonds: Vec<WitnessBondV1>,
    /// Minimum bond for snapshot eligibility (devnet fixture value).
    pub min_bond: u128,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            mode: NodeMode::Full,
            observer: false,
            view_retention_blocks: 0,
            mempool: MempoolConfig::default(),
            social_checkpoint: None,
            witness_bonds: Vec::new(),
            min_bond: 1,
        }
    }
}

/// Import outcome. Parking is NOT rejection: an unavailable body pauses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Extended the canonical executed chain (or triggered a reorg onto it).
    Executed { hash: Hash32 },
    /// Valid header on a side branch; body stored; not (yet) canonical.
    SideChain { hash: Hash32 },
    /// Header valid, DA insufficient: parked awaiting shards
    /// (`feed_shards` resumes it).
    ParkedAwaitingBody { hash: Hash32 },
    /// Parent unknown: pooled in the bounded orphan pool.
    Orphaned { hash: Hash32 },
    /// Light mode: header + ticket accepted (no body work).
    HeaderAccepted { hash: Hash32 },
}

struct ParkedBlock {
    header: BlockHeaderV1,
    ticket: GroundTicketV1,
    claim: BodyDaClaimV1,
    shards: Vec<ShardCandidateV1>,
}

/// A produced block ready for gossip.
pub struct ProducedBlock {
    pub hash: Hash32,
    pub header: BlockHeaderV1,
    pub ticket: GroundTicketV1,
    pub body: BlockBodyV1,
    pub claim: BodyDaClaimV1,
    pub shards: Vec<ShardCandidateV1>,
}

struct ExecResult {
    receipts: Vec<ReceiptV1>,
    merged_delta: StateDelta,
    roots: LumenRoots,
}

/// DAG-backed checkpoint ancestry oracle for the finality tracker.
struct DagAncestry<'a> {
    dag: &'a HeaderDag,
}

impl Ancestry for DagAncestry<'_> {
    fn descends(&self, source: &CheckpointRef, target: &CheckpointRef) -> bool {
        let Some(target_stored) = self.dag.get(&target.checkpoint_hash) else {
            return false;
        };
        if target_stored.header.height != target.epoch.saturating_mul(EPOCH_LENGTH) {
            return false;
        }
        let source_height = source.epoch.saturating_mul(EPOCH_LENGTH);
        self.dag
            .ancestor_at_height(&target.checkpoint_hash, source_height)
            .is_some_and(|a| a.hash == source.checkpoint_hash)
    }
}

/// The single-writer consensus core.
pub struct NodeCore<P: StorePort> {
    pub cfg: NodeConfig,
    chain_id: Hash32,
    genesis_hash: Hash32,
    genesis_block_hash: Hash32,
    genesis_time_ms: u64,
    dag: HeaderDag,
    ledger: LumenLedger,
    /// Rollback anchor: `(block hash, height, state at that block)`,
    /// refreshed when finality advances. The ONE bounded whole-state
    /// materialization in the node (one clone per finality advance), the
    /// price of below-finality rollback/replay through the store.
    anchor: (Hash32, u64, LumenLedger),
    exec_head: Hash32,
    exec_height: u64,
    tracker: FinalityTracker,
    registry: SnapshotRegistry,
    availability: AvailabilityLedger,
    parked: BTreeMap<Hash32, ParkedBlock>,
    pending_certs: Vec<FinalityCertificateV1>,
    pub mempool: Mempool,
    pub view: ChainView,
    pub port: P,
    /// Adjusted network time, milliseconds. Supplied by the supervisor
    /// clock task or the test; never read ambiently inside a transition.
    now_ms: u64,
    proposer_secret: BlsSecretKey,
    pub metrics: Arc<Metrics>,
}

impl<P: StorePort> NodeCore<P> {
    /// Boots a node: installs genesis when the store is fresh, otherwise
    /// replays the durable chain and recovers the exact state.
    pub fn boot(
        cfg: NodeConfig,
        spec: &GenesisSpec,
        built: BuiltGenesis,
        port: P,
        metrics: Arc<Metrics>,
    ) -> Result<Self, NodeError> {
        let genesis_block_hash = *built
            .header
            .block_hash()
            .map_err(|_| NodeError::Crypto)?
            .as_bytes();
        let genesis_checkpoint = CheckpointRef {
            epoch: 0,
            checkpoint_hash: genesis_block_hash,
        };
        let dag = HeaderDag::new(built.header.clone(), &built.ticket, 1024)?;
        let tracker = FinalityTracker::genesis(built.chain_id, genesis_checkpoint);
        let mut availability = AvailabilityLedger::new();
        // The node holds the genesis body it just built.
        let encoded = encode_body(&da_form_bytes(&built.body))?;
        availability.record_encoded(&encoded);

        let proposer_secret =
            BlsSecretKey::from_seed(DEVNET_PROPOSER_SEED).map_err(|_| NodeError::Crypto)?;

        let mut core = NodeCore {
            view: ChainView::new(cfg.view_retention_blocks),
            mempool: Mempool::new(cfg.mempool.clone()),
            cfg,
            chain_id: built.chain_id,
            genesis_hash: built.genesis_hash,
            genesis_block_hash,
            genesis_time_ms: spec.genesis_time_ms,
            dag,
            anchor: (genesis_block_hash, 0, built.ledger.clone()),
            ledger: built.ledger,
            exec_head: genesis_block_hash,
            exec_height: 0,
            tracker,
            registry: SnapshotRegistry::new(),
            availability,
            parked: BTreeMap::new(),
            pending_certs: Vec::new(),
            port,
            now_ms: spec.genesis_time_ms,
            proposer_secret,
            metrics,
        };
        core.view.heads.unsafe_head_hash = genesis_block_hash;
        core.view.heads.finalized = genesis_checkpoint;
        core.view.heads.justified = genesis_checkpoint;

        if core.port.get_index(KEY_HEAD)?.is_none() {
            // Fresh store: persist genesis.
            let mut ws = WriteSet::default();
            let mut header_bytes = built.header.encode_canonical();
            header_bytes.extend_from_slice(&built.ticket.encode());
            ws.headers
                .push((key_header(&genesis_block_hash), Some(header_bytes)));
            ws.indices
                .push((key_height(0), Some(genesis_block_hash.to_vec())));
            ws.indices
                .push((KEY_HEAD.to_vec(), Some(genesis_block_hash.to_vec())));
            ws.indices.push((
                KEY_FINALIZED.to_vec(),
                Some(genesis_checkpoint.encode_canonical()),
            ));
            ws.indices.push((
                KEY_JUSTIFIED.to_vec(),
                Some(genesis_checkpoint.encode_canonical()),
            ));
            ws.roots = Some(core.ledger.roots());
            ws.blobs.push(Blob {
                hash: built.header.body_da_root,
                bytes: built.body_bytes.clone(),
            });
            let seq = core.port.commit(&ws)?;
            core.metrics.set(&core.metrics.store_seq, seq);
        } else {
            core.replay_from_store()?;
        }
        Ok(core)
    }

    // -- accessors ----------------------------------------------------------

    #[must_use]
    pub fn chain_id(&self) -> Hash32 {
        self.chain_id
    }

    #[must_use]
    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    #[must_use]
    pub fn genesis_block_hash(&self) -> Hash32 {
        self.genesis_block_hash
    }

    #[must_use]
    pub fn head(&self) -> (u64, Hash32) {
        (self.exec_height, self.exec_head)
    }

    #[must_use]
    pub fn justified(&self) -> CheckpointRef {
        self.tracker.justified_head()
    }

    #[must_use]
    pub fn finalized(&self) -> CheckpointRef {
        self.tracker.finalized_head()
    }

    #[must_use]
    pub fn ledger(&self) -> &LumenLedger {
        &self.ledger
    }

    #[must_use]
    pub fn dag(&self) -> &HeaderDag {
        &self.dag
    }

    #[must_use]
    pub fn body_available(&self, body_da_root: &Hash32) -> bool {
        self.availability
            .body_available(&noos_crypto::Hash32::from_bytes(*body_da_root))
    }

    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Queues a verified-shape certificate for the next produced block and
    /// ingests it into local finality immediately.
    pub fn queue_certificate(&mut self, cert: FinalityCertificateV1) -> Result<(), NodeError> {
        self.process_certificate(&cert)?;
        if self.pending_certs.len() < MAX_FINALITY_CERTIFICATES as usize {
            self.pending_certs.push(cert);
        }
        Ok(())
    }

    // -- SOCIAL INPUT checkpoints (ch01 §10.5) --------------------------------

    /// Applies a weak-subjectivity checkpoint. SOCIAL INPUT: it may narrow
    /// sync candidates but NEVER overrides local finality; a conflict with
    /// locally finalized state is a typed error and changes nothing.
    pub fn apply_social_checkpoint(&mut self, social: CheckpointRef) -> Result<(), NodeError> {
        let local = self.tracker.finalized_head();
        if social.epoch <= local.epoch {
            let local_at = if social.epoch == local.epoch {
                local.checkpoint_hash
            } else {
                // The finalized chain at that epoch's checkpoint height.
                match self.dag.ancestor_at_height(
                    &local.checkpoint_hash,
                    social.epoch.saturating_mul(EPOCH_LENGTH),
                ) {
                    Some(s) => s.hash,
                    None => local.checkpoint_hash,
                }
            };
            if local_at != social.checkpoint_hash {
                return Err(NodeError::SocialCheckpointConflictsLocalFinality { local, social });
            }
        }
        // Consistent (or ahead of local finality): retained as a sync hint
        // only. It never moves the finalized pointer.
        self.cfg.social_checkpoint = Some(social);
        Ok(())
    }

    // -- witness snapshots ----------------------------------------------------

    /// Ensures the epoch snapshot exists in the registry (devnet fixture
    /// candidate source; node-v1.md §9 gap G3 for the live bond path).
    pub fn ensure_snapshot(&mut self, epoch: u64) -> Result<(), NodeError> {
        if self.registry.get(epoch).is_some() || self.cfg.witness_bonds.is_empty() {
            return Ok(());
        }
        let prev = self.registry.get(epoch.wrapping_sub(1)).cloned();
        let outcome = build_snapshot(
            epoch,
            &self.cfg.witness_bonds,
            &DEVNET_BEACON_RANDOMNESS,
            self.cfg.min_bond,
            prev.as_ref(),
            false,
        )?;
        match outcome {
            SnapshotOutcome::Normal(s) | SnapshotOutcome::EmergencyContinuation(s) => {
                self.registry
                    .insert(s)
                    .map_err(|_| NodeError::Witness(noos_witness::WitnessError::UnknownSnapshot))?;
                Ok(())
            }
            SnapshotOutcome::Halt => {
                Err(NodeError::Witness(noos_witness::WitnessError::QuorumNotMet))
            }
        }
    }

    #[must_use]
    pub fn snapshot_root(&mut self, epoch: u64) -> Hash32 {
        if self.ensure_snapshot(epoch).is_err() {
            return ZERO_ROOT;
        }
        self.registry.get(epoch).map_or(ZERO_ROOT, |s| s.root())
    }

    // -- import pipeline -------------------------------------------------------

    /// Stages 0-2 + DAG insertion, shared by every mode.
    fn import_header_stages(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<InsertOutcome, NodeError> {
        // Stage 1: structural law + proposer signature.
        header
            .validate_structure(&self.chain_id, false)
            .map_err(|e| NodeError::Dag(noos_braid::DagError::Header(e)))?;
        let commitment = header
            .proposal_commitment()
            .map_err(|_| NodeError::Crypto)?;
        let key = BlsPublicKey::from_bytes(header.proposer_key.0);
        let sig = BlsSignature::from_bytes(header.proposer_signature.0);
        bls_verify(DomainId::BlsProposer, &key, commitment.as_bytes(), &sig).map_err(|_| {
            NodeError::BodyMismatch {
                what: "proposer signature",
            }
        })?;

        // Ticket root binding (header field 24 <-> the gossiped ticket).
        if body_ticket_root(ticket)? != header.ground_ticket_root {
            return Err(NodeError::BodyMismatch {
                what: "ground_ticket_root",
            });
        }

        // Parent unknown → bounded orphan pool (ticket law needs context).
        if !self.dag.contains(&header.parent_hash) {
            return Ok(self.dag.insert(header.clone(), ticket)?);
        }

        // Stage 2: the eight-rule ticket law.
        self.validate_ticket_in_context(header, ticket)?;

        Ok(self.dag.insert(header.clone(), ticket)?)
    }

    fn validate_ticket_in_context(
        &self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<(), NodeError> {
        let parent = self
            .dag
            .get(&header.parent_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let parent_target = parent.header.ground_target_u256();
        let expected = self.expected_target(&parent.hash, header.height)?;
        let parent_timestamps = self
            .dag
            .parent_timestamps(&parent.hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS);
        let chain = noos_crypto::Hash32::from_bytes(self.chain_id);
        let parent_hash = noos_crypto::Hash32::from_bytes(parent.hash);
        let commitment = header
            .proposal_commitment()
            .map_err(|_| NodeError::Crypto)?;
        let claimed = header.ground_target_u256();
        let ctx = TicketContext {
            chain_id: &chain,
            parent_hash: &parent_hash,
            parent_ground_target: &parent_target,
            slot: header.slot,
            timestamp_ms: header.timestamp_ms,
            genesis_time_ms: self.genesis_time_ms,
            parent_slot: parent.header.slot,
            parent_timestamps_ms: &parent_timestamps,
            adjusted_now_ms: self.now_ms,
            max_future_drift_ms: noos_ground::DEVNET_MAX_FUTURE_DRIFT_MS,
            ground_target: &claimed,
            expected_target: &expected,
            proposal_commitment: &commitment,
            proposer_pubkey: &header.proposer_key.0,
        };
        validate_ticket(&ctx, ticket, &self.dag.duplicate_scan(&parent.hash))?;
        Ok(())
    }

    /// Deterministic Pulse output for a child of `parent_hash` at
    /// `child_height`, anchored on the finalized checkpoint NAMED BY the
    /// parent header (node-v1.md §4.4).
    pub fn expected_target(
        &self,
        parent_hash: &Hash32,
        child_height: u64,
    ) -> Result<U256, NodeError> {
        let parent = self
            .dag
            .get(parent_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let anchor_ref = parent.header.finalized_checkpoint;
        let anchor_hash = if anchor_ref.checkpoint_hash == ZERO_ROOT {
            // Genesis header names the zero checkpoint: anchor on genesis.
            self.genesis_block_hash
        } else {
            anchor_ref.checkpoint_hash
        };
        let anchor = self
            .dag
            .get(&anchor_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let anchor_mtp_ms = median_time_past_ms(
            &self
                .dag
                .parent_timestamps(&anchor_hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS),
        )
        .unwrap_or(anchor.header.timestamp_ms);
        let parent_mtp_ms = median_time_past_ms(
            &self
                .dag
                .parent_timestamps(parent_hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS),
        )
        .unwrap_or(parent.header.timestamp_ms);
        let pulse_anchor = PulseAnchor {
            height: anchor.header.height,
            median_time_past_s: anchor_mtp_ms / 1000,
            target: anchor.header.ground_target_u256(),
        };
        Ok(pulse_target_v1(
            &pulse_anchor,
            parent_mtp_ms / 1000,
            child_height,
        )?)
    }

    /// Light-mode import: stages 0-2 only (ch01 §10.5 light sync).
    pub fn import_header_light(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<ImportOutcome, NodeError> {
        let outcome = self.import_header_stages(header, ticket)?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash, .. } => hash,
            InsertOutcome::Orphaned { hash, .. } => return Ok(ImportOutcome::Orphaned { hash }),
        };
        Ok(ImportOutcome::HeaderAccepted { hash })
    }

    /// Full import: the complete seven-stage pipeline.
    pub fn import_block(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        claim: &BodyDaClaimV1,
        shards: &[ShardCandidateV1],
    ) -> Result<ImportOutcome, NodeError> {
        if self.cfg.mode == NodeMode::Light {
            return self.import_header_light(header, ticket);
        }
        let outcome = self
            .import_header_stages(header, ticket)
            .inspect_err(|_| self.metrics.inc(&self.metrics.blocks_rejected_total))?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash, .. } => hash,
            InsertOutcome::Orphaned { hash, .. } => return Ok(ImportOutcome::Orphaned { hash }),
        };

        // Stage 3: DA reconstruction. Insufficient shards PARK the block.
        let body = match self.reconstruct_body(header, ticket, claim, shards) {
            Ok(body) => body,
            Err(NodeError::Da(DaError::NotEnoughValidShards { .. })) => {
                self.parked.insert(
                    hash,
                    ParkedBlock {
                        header: header.clone(),
                        ticket: *ticket,
                        claim: *claim,
                        shards: shards.to_vec(),
                    },
                );
                self.metrics
                    .set(&self.metrics.blocks_parked, self.parked.len() as u64);
                return Ok(ImportOutcome::ParkedAwaitingBody { hash });
            }
            Err(e) => {
                self.metrics.inc(&self.metrics.blocks_rejected_total);
                return Err(e);
            }
        };

        self.accept_body(hash, header, ticket, &body)
    }

    /// Feeds late shards to a parked block; resumes the pipeline when
    /// reconstruction succeeds.
    pub fn feed_shards(
        &mut self,
        block_hash: &Hash32,
        more: &[ShardCandidateV1],
    ) -> Result<Option<ImportOutcome>, NodeError> {
        let Some(mut parked) = self.parked.remove(block_hash) else {
            return Ok(None);
        };
        parked.shards.extend_from_slice(more);
        match self.reconstruct_body(
            &parked.header,
            &parked.ticket,
            &parked.claim,
            &parked.shards,
        ) {
            Ok(body) => {
                self.metrics
                    .set(&self.metrics.blocks_parked, self.parked.len() as u64);
                let header = parked.header.clone();
                let ticket = parked.ticket;
                self.accept_body(*block_hash, &header, &ticket, &body)
                    .map(Some)
            }
            Err(NodeError::Da(DaError::NotEnoughValidShards { .. })) => {
                self.parked.insert(*block_hash, parked);
                Ok(None)
            }
            Err(e) => {
                self.metrics.inc(&self.metrics.blocks_rejected_total);
                Err(e)
            }
        }
    }

    /// Stage-3 body work: reconstruct, decode the DA form, substitute the
    /// validated ticket, cross-check every body-derived header root.
    fn reconstruct_body(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        claim: &BodyDaClaimV1,
        shards: &[ShardCandidateV1],
    ) -> Result<BlockBodyV1, NodeError> {
        let da_root = noos_crypto::Hash32::from_bytes(header.body_da_root);
        let reconstructed = reconstruct_and_verify(&da_root, claim, shards)?;
        // Stage 0 for the body: canonical decode of the DA form. The
        // receipt-root interchange impossibility is a HEADER decode law;
        // body collection bounds (incl. hard-zero Loom claims) die here.
        let mut body = BlockBodyV1::decode_canonical(reconstructed.bytes())?;
        body.ground_ticket = GroundTicketWire(*ticket);

        // Body/header cross-checks (node-v1.md §3).
        if body_tx_root(&body.transactions)? != header.tx_root {
            return Err(NodeError::RootMismatch { field: "tx_root" });
        }
        if body_witness_root(&body.segregated_witnesses)? != header.witness_root {
            return Err(NodeError::RootMismatch {
                field: "witness_root",
            });
        }
        if body_cert_root(&body.finality_certificates)? != header.finality_certificate_root {
            return Err(NodeError::RootMismatch {
                field: "finality_certificate_root",
            });
        }
        if header.evidence_root != ZERO_ROOT {
            return Err(NodeError::RootMismatch {
                field: "evidence_root",
            });
        }
        if !body.system_transitions.is_empty() {
            return Err(NodeError::SystemTransitionsUnfrozen);
        }
        if body.transactions.len() != body.segregated_witnesses.len() {
            return Err(NodeError::BodyMismatch {
                what: "witness alignment",
            });
        }
        check_blob_descriptors(body.consensus_blob_descriptors.as_slice())?;
        self.availability.record_reconstructed(&reconstructed);
        Ok(body)
    }

    /// Stages 4-7 for a connected header whose body is now available.
    fn accept_body(
        &mut self,
        hash: Hash32,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        body: &BlockBodyV1,
    ) -> Result<ImportOutcome, NodeError> {
        let extends_exec_head = header.parent_hash == self.exec_head;
        let outcome = if extends_exec_head {
            // Stage 4-5: execute against the live single-writer ledger.
            match self.execute_and_verify(header, body) {
                Ok(exec) => {
                    self.commit_executed_block(hash, header, ticket, body, &exec)?;
                    ImportOutcome::Executed { hash }
                }
                Err(e) => {
                    // The ledger may be dirty: rebuild from the finalized
                    // anchor along the canonical path (recovery law).
                    self.metrics.inc(&self.metrics.blocks_rejected_total);
                    self.rebuild_ledger_to(self.exec_head)?;
                    return Err(e);
                }
            }
        } else {
            // Side branch: persist header + body; execution deferred to
            // fork choice.
            let mut ws = WriteSet::default();
            let mut header_bytes = header.encode_canonical();
            header_bytes.extend_from_slice(&ticket.encode());
            ws.headers.push((key_header(&hash), Some(header_bytes)));
            ws.blobs.push(Blob {
                hash: header.body_da_root,
                bytes: body.encode_canonical(),
            });
            let seq = self.port.commit(&ws)?;
            self.metrics.set(&self.metrics.store_seq, seq);
            ImportOutcome::SideChain { hash }
        };

        // Stage 7: finality processing from the body's certificates.
        for cert in body.finality_certificates.as_slice() {
            self.process_certificate(cert)?;
        }

        // Stage 6: fork choice (finality may have re-ranked branches).
        self.apply_fork_choice()?;
        self.refresh_finalized_anchor()?;
        Ok(outcome)
    }

    // -- execution --------------------------------------------------------------

    /// Stage 4-5: normative-order execution + full root comparison.
    fn execute_and_verify(
        &mut self,
        header: &BlockHeaderV1,
        body: &BlockBodyV1,
    ) -> Result<ExecResult, NodeError> {
        let mut deltas: Vec<StateDelta> = Vec::new();

        // System transitions first (ch01 §9.3): parameter activation, then
        // the deterministic emission for this height.
        deltas.push(self.ledger.activate_pending_params(header.height));
        let prices = self
            .ledger
            .fee_state()
            .map(|s| s.prices())
            .ok_or(NodeError::RootMismatch { field: "fee_state" })?;
        // Header base prices must equal the block-start controller state.
        let hp = &header.base_prices;
        let claimed = [
            hp.p_bytes,
            hp.p_grain_steps,
            hp.p_proof_units,
            hp.p_state_word_epochs,
            hp.p_blob_bytes,
        ];
        for i in 0..fees::DIMENSIONS {
            if u128::from(claimed[i]) != prices[i] {
                return Err(NodeError::RootMismatch {
                    field: "base_prices",
                });
            }
        }
        deltas.push(
            self.ledger
                .apply_emission(
                    header.height,
                    &PROPOSER_POOL_ACCOUNT,
                    &WITNESS_POOL_ACCOUNT,
                    &TREASURY_ACCOUNT,
                )
                .map_err(NodeError::Emission)?,
        );

        // Ordered transactions (Lumen normative order per transaction).
        let ctx = BlockContext {
            chain_id: self.chain_id,
            height: header.height,
        };
        let engine = DeferredEngine;
        let auth = NodeAuthVerifier;
        let mut receipts: Vec<ReceiptV1> = Vec::with_capacity(body.transactions.len());
        for (tx, wits) in body
            .transactions
            .iter()
            .zip(body.segregated_witnesses.iter())
        {
            let tx_bytes = tx.encode_canonical();
            let wit_bytes = wits.encode_canonical();
            let outcome = self
                .ledger
                .apply_transaction(&ctx, &tx_bytes, &wit_bytes, &engine, &auth)
                .map_err(NodeError::LumenReject)?;
            receipts.push(outcome.receipt().clone());
            match outcome {
                noos_lumen::state::ApplyOutcome::Applied { delta, .. }
                | noos_lumen::state::ApplyOutcome::Failed { delta, .. } => deltas.push(delta),
            }
        }

        // Resource totals, then the end-of-block controller step.
        let usage = sum_usage(&receipts)?;
        let gu = &header.gas_used;
        if [
            gu.bytes,
            gu.grain_steps,
            gu.proof_units,
            gu.state_word_epochs,
            gu.blob_bytes,
        ] != usage
        {
            return Err(NodeError::RootMismatch { field: "gas_used" });
        }
        deltas.push(
            self.ledger
                .end_block_fee_update(&usage)
                .map_err(NodeError::LumenReject)?,
        );

        // Stage 5: ALL claimed roots (six Lumen + both receipt roots).
        let roots = self.ledger.roots();
        let checks: [(&'static str, Hash32, Hash32); 7] = [
            ("notes_root", header.notes_root, roots.notes_root),
            (
                "nullifiers_root",
                header.nullifiers_root,
                roots.nullifiers_root,
            ),
            ("accounts_root", header.accounts_root, roots.accounts_root),
            ("objects_root", header.objects_root, roots.objects_root),
            ("params_root", header.params_root, roots.params_root),
            // The header's six Lumen roots include the post-state settled
            // index; the block's ORDERED receipts are the separate field
            // below — interchange of the two VALUES is caught right here.
            (
                "lumen_receipts_state_root",
                header.lumen_receipts_state_root,
                roots.receipts_root,
            ),
            (
                "execution_receipt_root",
                header.execution_receipt_root,
                body_receipt_root(&receipts)?,
            ),
        ];
        for (field, claimed, actual) in checks {
            if claimed != actual {
                return Err(NodeError::RootMismatch { field });
            }
        }

        Ok(ExecResult {
            receipts,
            merged_delta: merge_deltas(deltas),
            roots,
        })
    }

    /// Commits an executed canonical block: one atomic store write set,
    /// then view/mempool/metrics housekeeping.
    fn commit_executed_block(
        &mut self,
        hash: Hash32,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        body: &BlockBodyV1,
        exec: &ExecResult,
    ) -> Result<(), NodeError> {
        let mut ws = WriteSet {
            delta: exec.merged_delta.clone(),
            roots: Some(exec.roots),
            ..WriteSet::default()
        };
        let mut header_bytes = header.encode_canonical();
        header_bytes.extend_from_slice(&ticket.encode());
        ws.headers.push((key_header(&hash), Some(header_bytes)));
        ws.indices
            .push((key_height(header.height), Some(hash.to_vec())));
        ws.indices.push((KEY_HEAD.to_vec(), Some(hash.to_vec())));
        for r in &exec.receipts {
            let mut value = header.height.to_le_bytes().to_vec();
            value.extend_from_slice(&r.encode_canonical());
            ws.receipts.push((r.txid.to_vec(), Some(value)));
        }
        ws.blobs.push(Blob {
            hash: header.body_da_root,
            bytes: body.encode_canonical(),
        });
        let seq = self.port.commit(&ws)?;

        self.exec_head = hash;
        self.exec_height = header.height;
        let settled: Vec<Hash32> = exec.receipts.iter().map(|r| r.txid).collect();
        let next_height = header.height.saturating_add(1);
        self.mempool.on_block_connected(&settled, next_height);
        self.view.connect_block(header, hash, &exec.receipts);
        let m = &self.metrics;
        m.set(&m.height, header.height);
        m.set(&m.store_seq, seq);
        m.inc(&m.blocks_imported_total);
        m.set(&m.mempool_txs, self.mempool.len() as u64);
        m.set(&m.mempool_bytes, self.mempool.total_bytes() as u64);
        for _ in &settled {
            m.inc(&m.txs_settled_total);
        }
        Ok(())
    }

    // -- fork choice + reorg ------------------------------------------------------

    /// Applies fork choice; performs a rollback/replay reorg when the
    /// selected head is not the executed head.
    pub fn apply_fork_choice(&mut self) -> Result<(), NodeError> {
        let Some(best) = self.dag.select_head() else {
            return Ok(());
        };
        if best == self.exec_head {
            return Ok(());
        }
        // Only reorg onto heads whose full body chain is available.
        if !self.branch_bodies_available(&best) {
            return Ok(());
        }
        self.reorg_to(best)
    }

    fn branch_bodies_available(&self, tip: &Hash32) -> bool {
        for anc in self.dag.ancestors(tip) {
            if anc.hash == self.exec_head || anc.header.height == 0 {
                return true;
            }
            if anc.header.height <= self.exec_height
                && self
                    .dag
                    .ancestor_at_height(&self.exec_head, anc.header.height)
                    .is_some_and(|a| a.hash == anc.hash)
            {
                return true; // joined the executed chain
            }
            if !self
                .availability
                .body_available(&noos_crypto::Hash32::from_bytes(anc.header.body_da_root))
            {
                return false;
            }
        }
        true
    }

    /// Deterministic rollback/replay through the store (ch01 §4.5): roll
    /// back to the finalized anchor, then replay stored bodies along the
    /// new canonical path.
    fn reorg_to(&mut self, new_head: Hash32) -> Result<(), NodeError> {
        let plan = self.dag.plan_reorg(&self.exec_head, &new_head)?;
        // Disconnect view state (newest first, as planned).
        for hash in &plan.disconnect {
            if let Some(stored) = self.dag.get(hash) {
                self.view.disconnect_block(stored.header.height);
            }
        }
        self.metrics.inc(&self.metrics.reorgs_total);
        self.rebuild_ledger_to(new_head)?;

        // Repoint the canonical height index at the replayed branch.
        let mut ws = WriteSet::default();
        let mut cursor = new_head;
        loop {
            let stored = self
                .dag
                .get(&cursor)
                .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
            ws.indices
                .push((key_height(stored.header.height), Some(cursor.to_vec())));
            if cursor == plan.common_ancestor || stored.header.height == 0 {
                break;
            }
            cursor = stored.header.parent_hash;
        }
        ws.indices
            .push((KEY_HEAD.to_vec(), Some(new_head.to_vec())));
        let seq = self.port.commit(&ws)?;
        self.metrics.set(&self.metrics.store_seq, seq);
        Ok(())
    }

    /// Rebuilds the live ledger to `target` by cloning the finalized
    /// anchor and replaying stored bodies (the store is the replay
    /// source; roots re-verified block by block).
    fn rebuild_ledger_to(&mut self, target: Hash32) -> Result<(), NodeError> {
        // Path anchor → target (exclusive of anchor).
        let mut path: Vec<Hash32> = Vec::new();
        let mut cursor = target;
        loop {
            if cursor == self.anchor.0 {
                break;
            }
            let stored = self
                .dag
                .get(&cursor)
                .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
            if stored.header.height <= self.anchor.1 {
                // Target does not descend from the anchor: prohibited
                // (reorg across finality).
                return Err(NodeError::Dag(noos_braid::DagError::ReorgAcrossFinality));
            }
            path.push(cursor);
            cursor = stored.header.parent_hash;
        }
        path.reverse();

        self.ledger = self.anchor.2.clone();
        self.exec_head = self.anchor.0;
        self.exec_height = self.anchor.1;
        for hash in path {
            let (header, ticket) = self.load_header(&hash)?;
            let body = self.load_body(&header, &ticket)?;
            let exec = self.execute_and_verify(&header, &body)?;
            // Replay updates memory + receipts/indices; the state delta is
            // recommitted so the state CF converges to the replayed branch.
            self.commit_executed_block(hash, &header, &ticket, &body, &exec)?;
        }
        Ok(())
    }

    // -- finality -------------------------------------------------------------------

    fn process_certificate(&mut self, cert: &FinalityCertificateV1) -> Result<(), NodeError> {
        self.ensure_snapshot(cert.target.epoch)?;
        let ancestry = DagAncestry { dag: &self.dag };
        let outcome = self
            .tracker
            .ingest_certificate(cert, &self.registry, &ancestry)?;
        let digest =
            noos_witness::finality::certificate_digest(cert).map_err(NodeError::Witness)?;

        let mut ws = WriteSet::default();
        ws.indices.push((
            key_certificate(cert.target.epoch, &digest),
            Some(cert.encode_canonical()),
        ));
        match outcome {
            IngestOutcome::Duplicate => return Ok(()),
            IngestOutcome::Justified => {
                let j = self.tracker.justified_head();
                self.dag.set_justified(j)?;
                ws.indices
                    .push((KEY_JUSTIFIED.to_vec(), Some(j.encode_canonical())));
            }
            IngestOutcome::Finalized(cp) => {
                let j = self.tracker.justified_head();
                self.dag.set_finalized(cp)?;
                self.dag.set_justified(j)?;
                ws.indices
                    .push((KEY_JUSTIFIED.to_vec(), Some(j.encode_canonical())));
                ws.indices
                    .push((KEY_FINALIZED.to_vec(), Some(cp.encode_canonical())));
            }
        }
        let seq = self.port.commit(&ws)?;
        let m = &self.metrics;
        m.set(&m.store_seq, seq);
        m.set(&m.justified_epoch, self.tracker.justified_head().epoch);
        m.set(&m.finalized_epoch, self.tracker.finalized_head().epoch);
        self.view.heads.justified = self.tracker.justified_head();
        self.view.heads.finalized = self.tracker.finalized_head();
        Ok(())
    }

    /// Moves the rollback anchor up to the finalized checkpoint once it
    /// lies on the executed canonical path.
    fn refresh_finalized_anchor(&mut self) -> Result<(), NodeError> {
        let finalized = self.tracker.finalized_head();
        let height = finalized.epoch.saturating_mul(EPOCH_LENGTH);
        if height <= self.anchor.1 || height > self.exec_height {
            return Ok(());
        }
        let on_path = self
            .dag
            .ancestor_at_height(&self.exec_head, height)
            .is_some_and(|a| a.hash == finalized.checkpoint_hash);
        if !on_path {
            return Ok(());
        }
        // Replay anchor → checkpoint into a fresh anchor state.
        let mut path: Vec<Hash32> = Vec::new();
        let mut cursor = finalized.checkpoint_hash;
        while cursor != self.anchor.0 {
            let stored = self
                .dag
                .get(&cursor)
                .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
            path.push(cursor);
            if stored.header.height == 0 {
                break;
            }
            cursor = stored.header.parent_hash;
        }
        path.reverse();
        let mut anchor_ledger = self.anchor.2.clone();
        let mut anchor_exec = AnchorExec {
            ledger: &mut anchor_ledger,
            chain_id: self.chain_id,
        };
        for hash in path {
            let (header, ticket) = self.load_header(&hash)?;
            let body = self.load_body(&header, &ticket)?;
            anchor_exec.replay(&header, &body)?;
        }
        self.anchor = (finalized.checkpoint_hash, height, anchor_ledger);
        Ok(())
    }

    // -- store loading -----------------------------------------------------------

    fn load_header(&self, hash: &Hash32) -> Result<(BlockHeaderV1, GroundTicketV1), NodeError> {
        let bytes = self
            .port
            .get_header(&key_header(hash))?
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        decode_header_record(&bytes)
    }

    fn load_body(
        &self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<BlockBodyV1, NodeError> {
        let bytes = self
            .port
            .get_blob(&header.body_da_root)?
            .ok_or(NodeError::BodyMismatch {
                what: "body blob missing",
            })?;
        let mut body = BlockBodyV1::decode_canonical(&bytes)?;
        body.ground_ticket = GroundTicketWire(*ticket);
        Ok(body)
    }

    // -- restart recovery ----------------------------------------------------------

    /// Replays the durable chain: headers/tickets/bodies from the store
    /// through the ordinary execution pipeline, certificates afterwards,
    /// the anchor snapshotted at the recorded finalized height. Recovered
    /// state is EXACT: every block's roots re-verify or startup fails.
    fn replay_from_store(&mut self) -> Result<(), NodeError> {
        // Recorded finalized checkpoint (for the anchor snapshot).
        let recorded_finalized = match self.port.get_index(KEY_FINALIZED)? {
            Some(bytes) => CheckpointRef::decode_canonical(&bytes)?,
            None => CheckpointRef {
                epoch: 0,
                checkpoint_hash: self.genesis_block_hash,
            },
        };
        let finalized_height = recorded_finalized.epoch.saturating_mul(EPOCH_LENGTH);

        // Canonical chain replay through the height index.
        let entries = self.port.scan_indices(b"n/")?;
        for (key, value) in entries {
            if key.len() != 10 {
                return Err(NodeError::BodyMismatch {
                    what: "height index key",
                });
            }
            let mut he = [0_u8; 8];
            he.copy_from_slice(&key[2..10]);
            let height = u64::from_be_bytes(he);
            if height == 0 {
                continue; // genesis installed by boot
            }
            let hash: Hash32 =
                value
                    .as_slice()
                    .try_into()
                    .map_err(|_| NodeError::BodyMismatch {
                        what: "height index value",
                    })?;
            let (header, ticket) = self.load_header(&hash)?;
            let body = self.load_body(&header, &ticket)?;

            // Replay observes each block "at its time": the future-drift
            // rule compares against adjusted time, which for a durable
            // block is at least its own timestamp.
            self.now_ms = self.now_ms.max(header.timestamp_ms);
            // Trusted-store replay still re-validates: structure, ticket,
            // execution, roots. (Certificates replay separately below.)
            self.import_header_stages(&header, &ticket)?;
            let exec = self.execute_and_verify(&header, &body).inspect_err(|_| {
                // A replay failure is a corrupt/foreign store: startup stops.
            })?;
            // Memory-side bookkeeping only; the store already holds this
            // block (no re-commit).
            self.exec_head = hash;
            self.exec_height = header.height;
            let encoded = encode_body(&da_form_bytes(&body))?;
            self.availability.record_encoded(&encoded);
            self.view.connect_block(&header, hash, &exec.receipts);
            if header.height == finalized_height {
                self.anchor = (hash, height, self.ledger.clone());
            }
        }

        // Certificates in epoch order.
        let certs = self.port.scan_indices(b"c/")?;
        for (_, value) in certs {
            let cert = FinalityCertificateV1::decode_canonical(&value)?;
            self.ensure_snapshot(cert.target.epoch)?;
            let ancestry = DagAncestry { dag: &self.dag };
            let outcome = self
                .tracker
                .ingest_certificate(&cert, &self.registry, &ancestry)?;
            match outcome {
                IngestOutcome::Finalized(cp) => {
                    self.dag.set_finalized(cp)?;
                    self.dag.set_justified(self.tracker.justified_head())?;
                }
                IngestOutcome::Justified => {
                    self.dag.set_justified(self.tracker.justified_head())?;
                }
                IngestOutcome::Duplicate => {}
            }
        }

        let m = &self.metrics;
        m.set(&m.height, self.exec_height);
        m.set(&m.justified_epoch, self.tracker.justified_head().epoch);
        m.set(&m.finalized_epoch, self.tracker.finalized_head().epoch);
        m.set(&m.store_seq, self.port.applied_seq());
        self.view.heads.justified = self.tracker.justified_head();
        self.view.heads.finalized = self.tracker.finalized_head();

        // SOCIAL INPUT check against recovered local finality.
        if let Some(social) = self.cfg.social_checkpoint {
            self.apply_social_checkpoint(social)?;
        }
        Ok(())
    }

    // -- mempool + submission ---------------------------------------------------------

    /// Transaction submission (RPC path). Observer mode is enforced at the
    /// RPC layer with a `feature_disabled` error; the core stays capable.
    pub fn submit_tx(
        &mut self,
        tx_bytes: &[u8],
        wit_bytes: &[u8],
        source: SourceId,
    ) -> Result<Hash32, AdmitError> {
        let prices = self
            .ledger
            .fee_state()
            .map(|s| s.prices())
            .ok_or(AdmitError::Malformed)?;
        let next_height = self.exec_height.saturating_add(1);
        let id = self.mempool.admit(
            tx_bytes,
            wit_bytes,
            source,
            next_height,
            &self.chain_id,
            &prices,
            &self.ledger,
        )?;
        self.view.note_pending(id);
        let m = &self.metrics;
        m.set(&m.mempool_txs, self.mempool.len() as u64);
        m.set(&m.mempool_bytes, self.mempool.total_bytes() as u64);
        Ok(id)
    }

    // -- block production ---------------------------------------------------------------

    /// Produces, executes, commits, and returns the next canonical block
    /// (ch01 §4.3 production order; the ticket search binds the fixed
    /// proposal commitment).
    pub fn produce_block(&mut self) -> Result<ProducedBlock, NodeError> {
        self.apply_fork_choice()?;
        let parent_hash = self.exec_head;
        let parent = self
            .dag
            .get(&parent_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let parent_header = parent.header.clone();
        let height = parent_header
            .height
            .checked_add(1)
            .ok_or(NodeError::BodyMismatch {
                what: "height overflow",
            })?;

        // Timestamp/slot: > parent MTP, slot in [parent_slot, parent+20].
        let parent_timestamps = self
            .dag
            .parent_timestamps(&parent_hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS);
        let mtp = median_time_past_ms(&parent_timestamps).unwrap_or(parent_header.timestamp_ms);
        let mut ts = self.now_ms.max(mtp.saturating_add(1));
        let parent_slot_start = self
            .genesis_time_ms
            .saturating_add(parent_header.slot.saturating_mul(noos_ground::SLOT_MS));
        ts = ts.max(parent_slot_start);
        let max_slot = parent_header
            .slot
            .saturating_add(noos_ground::MAX_SLOT_SKIP);
        let mut slot =
            slot_from_timestamp(ts, self.genesis_time_ms).ok_or(NodeError::BodyMismatch {
                what: "timestamp before genesis",
            })?;
        if slot > max_slot {
            slot = max_slot;
            ts = self
                .genesis_time_ms
                .saturating_add(slot.saturating_mul(noos_ground::SLOT_MS))
                .max(mtp.saturating_add(1));
        }

        // System transitions first, mirroring the import order exactly.
        let mut deltas: Vec<StateDelta> = Vec::new();
        deltas.push(self.ledger.activate_pending_params(height));
        let prices = self
            .ledger
            .fee_state()
            .map(|s| s.prices())
            .ok_or(NodeError::RootMismatch { field: "fee_state" })?;
        deltas.push(
            self.ledger
                .apply_emission(
                    height,
                    &PROPOSER_POOL_ACCOUNT,
                    &WITNESS_POOL_ACCOUNT,
                    &TREASURY_ACCOUNT,
                )
                .map_err(NodeError::Emission)?,
        );

        // Deterministic template, executed on the live ledger; entries the
        // state rejects are dropped from the pool (invalid at this state).
        let capacity =
            self.ledger
                .fee_params()
                .map(|p| p.capacity())
                .ok_or(NodeError::RootMismatch {
                    field: "fee_params",
                })?;
        let template: Vec<(Hash32, Vec<u8>, Vec<u8>)> = self
            .mempool
            .template(&capacity)
            .into_iter()
            .map(|e| (e.txid, e.tx_bytes.clone(), e.wit_bytes.clone()))
            .collect();
        let ctx = BlockContext {
            chain_id: self.chain_id,
            height,
        };
        let engine = DeferredEngine;
        let auth = NodeAuthVerifier;
        let mut receipts: Vec<ReceiptV1> = Vec::new();
        let mut included: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut dropped: Vec<Hash32> = Vec::new();
        for (txid, tx_bytes, wit_bytes) in template {
            match self
                .ledger
                .apply_transaction(&ctx, &tx_bytes, &wit_bytes, &engine, &auth)
            {
                Ok(outcome) => {
                    receipts.push(outcome.receipt().clone());
                    match outcome {
                        noos_lumen::state::ApplyOutcome::Applied { delta, .. }
                        | noos_lumen::state::ApplyOutcome::Failed { delta, .. } => {
                            deltas.push(delta);
                        }
                    }
                    included.push((tx_bytes, wit_bytes));
                }
                Err(_) => dropped.push(txid),
            }
        }
        for txid in &dropped {
            self.mempool.remove(txid);
            self.view.drop_pending(txid);
        }

        let usage = sum_usage(&receipts)?;
        deltas.push(
            self.ledger
                .end_block_fee_update(&usage)
                .map_err(NodeError::LumenReject)?,
        );
        let roots = self.ledger.roots();

        // Assemble the body (ticket = canonical zero until mined).
        let mut txs = Vec::with_capacity(included.len());
        let mut wits = Vec::with_capacity(included.len());
        for (tx_bytes, wit_bytes) in &included {
            txs.push(noos_lumen::objects::TransactionV1::decode_canonical(
                tx_bytes,
            )?);
            wits.push(TransactionWitnessesV1::decode_canonical(wit_bytes)?);
        }
        let certs: Vec<FinalityCertificateV1> = std::mem::take(&mut self.pending_certs);
        let mut body = BlockBodyV1 {
            transactions: BoundedList::new(txs)
                .ok_or(NodeError::BodyMismatch { what: "tx count" })?,
            segregated_witnesses: BoundedList::new(wits).ok_or(NodeError::BodyMismatch {
                what: "witness count",
            })?,
            system_transitions: BoundedList::new(vec![]).unwrap_or_default(),
            finality_certificates: BoundedList::new(certs)
                .ok_or(NodeError::BodyMismatch { what: "cert count" })?,
            ground_ticket: GroundTicketWire(crate::roots::zero_ticket()),
            loom_credit_claims: BoundedList::new(vec![]).unwrap_or_default(),
            consensus_blob_descriptors: BoundedList::new(vec![]).unwrap_or_default(),
        };

        let expected_target = self.expected_target(&parent_hash, height)?;
        let epoch = height / EPOCH_LENGTH;
        let membership_root = self.snapshot_root(epoch);
        let proposer_key = Bytes48(self.proposer_secret.public_key().into_bytes());

        let mut header = BlockHeaderV1 {
            chain_id: self.chain_id,
            height,
            slot,
            timestamp_ms: ts,
            parent_hash,
            proposer_key,
            tx_root: body_tx_root(&body.transactions)?,
            witness_root: body_witness_root(&body.segregated_witnesses)?,
            execution_receipt_root: body_receipt_root(&receipts)?,
            evidence_root: ZERO_ROOT,
            body_da_root: ZERO_ROOT,
            notes_root: roots.notes_root,
            nullifiers_root: roots.nullifiers_root,
            accounts_root: roots.accounts_root,
            objects_root: roots.objects_root,
            lumen_receipts_state_root: roots.receipts_root,
            params_root: roots.params_root,
            justified_checkpoint: self.dag.justified(),
            finalized_checkpoint: self.dag.finalized(),
            finality_certificate_root: body_cert_root(&body.finality_certificates)?,
            witness_membership_root: membership_root,
            ground_profile_id: noos_ground::GROUND_PROFILE_ID_V1,
            ground_target: expected_target.to_le_bytes(),
            ground_ticket_root: ZERO_ROOT,
            loom_credit_root: ZERO_ROOT,
            loom_credit: 0,
            gas_used: ResourceVectorV1 {
                bytes: usage[0],
                grain_steps: usage[1],
                proof_units: usage[2],
                state_word_epochs: usage[3],
                blob_bytes: usage[4],
            },
            base_prices: ResourcePriceVectorV1 {
                p_bytes: u64::try_from(prices[0]).unwrap_or(u64::MAX),
                p_grain_steps: u64::try_from(prices[1]).unwrap_or(u64::MAX),
                p_proof_units: u64::try_from(prices[2]).unwrap_or(u64::MAX),
                p_state_word_epochs: u64::try_from(prices[3]).unwrap_or(u64::MAX),
                p_blob_bytes: u64::try_from(prices[4]).unwrap_or(u64::MAX),
            },
            proposer_signature: Bytes96([0; 96]),
        };

        // DA commitment BEFORE the search (ch01 §4.3 steps 5-6).
        let da_bytes = da_form_bytes(&body);
        let encoded = encode_body(&da_bytes)?;
        header.body_da_root = encoded.shard_root().into_bytes();

        let commitment = header
            .proposal_commitment()
            .map_err(|_| NodeError::Crypto)?;
        let parent_target = parent_header.ground_target_u256();
        let ticket = crate::genesis::mine_ticket(
            &self.chain_id,
            &parent_hash,
            &parent_target,
            slot,
            &commitment,
            &proposer_key.0,
            &expected_target,
        )?;
        header.ground_ticket_root = body_ticket_root(&ticket)?;
        body.ground_ticket = GroundTicketWire(ticket);
        let sig = self
            .proposer_secret
            .sign_domain(DomainId::BlsProposer, commitment.as_bytes())
            .map_err(|_| NodeError::Crypto)?;
        header.proposer_signature = Bytes96(sig.into_bytes());

        // Connect + commit through the ordinary paths.
        let outcome = self.import_header_stages(&header, &ticket)?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash, .. } => hash,
            InsertOutcome::Orphaned { .. } => {
                return Err(NodeError::Dag(noos_braid::DagError::UnknownBlock))
            }
        };
        self.availability.record_encoded(&encoded);
        let exec = ExecResult {
            receipts,
            merged_delta: merge_deltas(deltas),
            roots,
        };
        self.commit_executed_block(hash, &header, &ticket, &body, &exec)?;
        self.metrics.inc(&self.metrics.blocks_produced_total);

        let mut shards = Vec::with_capacity(noos_da::BODY_TOTAL_SHARDS);
        for i in 0..noos_da::BODY_TOTAL_SHARDS {
            shards.push(encoded.candidate(i as u32)?);
        }
        Ok(ProducedBlock {
            hash,
            header,
            ticket,
            body,
            claim: *encoded.claim(),
            shards,
        })
    }

    /// Whether every body from the finalized checkpoint up to `cp` is held
    /// (witnesses MUST NOT vote a checkpoint containing an unreconstructed
    /// ancestor, ch01 §10.1).
    #[must_use]
    pub fn checkpoint_available(&self, cp: &CheckpointRef) -> bool {
        let Some(stored) = self.dag.get(&cp.checkpoint_hash) else {
            return false;
        };
        let floor = self
            .tracker
            .finalized_head()
            .epoch
            .saturating_mul(EPOCH_LENGTH);
        let mut cursor = stored.hash;
        loop {
            let Some(s) = self.dag.get(&cursor) else {
                return false;
            };
            if s.header.height <= floor {
                return true;
            }
            if !self
                .availability
                .body_available(&noos_crypto::Hash32::from_bytes(s.header.body_da_root))
            {
                return false;
            }
            cursor = s.header.parent_hash;
        }
    }
}

/// Decodes a stored `header ++ ticket` record.
pub fn decode_header_record(bytes: &[u8]) -> Result<(BlockHeaderV1, GroundTicketV1), NodeError> {
    let split = bytes
        .len()
        .checked_sub(noos_ground::TICKET_ENCODED_BYTES)
        .ok_or(NodeError::BodyMismatch {
            what: "header record",
        })?;
    let header = BlockHeaderV1::decode_canonical(&bytes[..split])?;
    let ticket = GroundTicketV1::decode(&bytes[split..]).ok_or(NodeError::BodyMismatch {
        what: "ticket record",
    })?;
    Ok((header, ticket))
}

/// Merges per-step deltas into one canonical ordered delta
/// (last-write-wins per `(tree, key, sub_key)` slot).
#[must_use]
pub fn merge_deltas(deltas: Vec<StateDelta>) -> StateDelta {
    let mut map: BTreeMap<(TreeId, Hash32, Option<Hash32>), Option<Vec<u8>>> = BTreeMap::new();
    for delta in deltas {
        for e in delta.entries {
            map.insert((e.tree, e.key, e.sub_key), e.value);
        }
    }
    StateDelta {
        entries: map
            .into_iter()
            .map(|((tree, key, sub_key), value)| DeltaEntry {
                tree,
                key,
                sub_key,
                value,
            })
            .collect(),
    }
}

/// Anchor-side replay executor: same normative order, no store writes.
struct AnchorExec<'a> {
    ledger: &'a mut LumenLedger,
    chain_id: Hash32,
}

impl AnchorExec<'_> {
    fn replay(&mut self, header: &BlockHeaderV1, body: &BlockBodyV1) -> Result<(), NodeError> {
        self.ledger.activate_pending_params(header.height);
        self.ledger
            .apply_emission(
                header.height,
                &PROPOSER_POOL_ACCOUNT,
                &WITNESS_POOL_ACCOUNT,
                &TREASURY_ACCOUNT,
            )
            .map_err(NodeError::Emission)?;
        let ctx = BlockContext {
            chain_id: self.chain_id,
            height: header.height,
        };
        let engine = DeferredEngine;
        let auth = NodeAuthVerifier;
        let mut receipts = Vec::with_capacity(body.transactions.len());
        for (tx, wits) in body
            .transactions
            .iter()
            .zip(body.segregated_witnesses.iter())
        {
            let outcome = self
                .ledger
                .apply_transaction(
                    &ctx,
                    &tx.encode_canonical(),
                    &wits.encode_canonical(),
                    &engine,
                    &auth,
                )
                .map_err(NodeError::LumenReject)?;
            receipts.push(outcome.receipt().clone());
        }
        let usage = sum_usage(&receipts)?;
        self.ledger
            .end_block_fee_update(&usage)
            .map_err(NodeError::LumenReject)?;
        let roots = self.ledger.roots();
        if roots.accounts_root != header.accounts_root {
            return Err(NodeError::RootMismatch {
                field: "anchor accounts_root",
            });
        }
        Ok(())
    }
}
