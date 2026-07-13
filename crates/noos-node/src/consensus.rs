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
//! 4. prospective finality           (all body certificates, in wire order;
//!                                    header checkpoints must exactly bind
//!                                    the resulting verified tracker state)
//! 5. body execution + roots         (noos-lumen normative order against a
//!                                    staged ledger; every claimed root)
//! 6. orphan promotion + fork choice (full contextual revalidation; staged
//!                                    rollback/replay below finality)
//! 7. one atomic commit              (block/body/state/receipts/certificates/
//!                                    pointers), then install staged memory
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
    ReconstructedBodyV1, ShardCandidateV1,
};
use noos_ground::{
    median_time_past_ms, pulse_target_v1, slot_from_timestamp, validate_ticket, GroundTicketV1,
    PulseAnchor, TicketContext, U256,
};
use noos_lumen::engine::AuthVerifier;
use noos_lumen::fees;
use noos_lumen::objects::{txid, BoundedList, ReceiptV1, TransactionV1, TransactionWitnessesV1};
use noos_lumen::state::{BlockContext, DeltaEntry, LumenLedger, LumenRoots, StateDelta, TreeId};
use noos_store::{Blob, WriteSet};
use noos_witness::bond::WitnessBondV1;
use noos_witness::finality::{
    build_certificate, Ancestry, FinalityTracker, IngestOutcome, SnapshotRegistry,
};
use noos_witness::membership::{build_snapshot, SnapshotOutcome};
use noos_witness::vote::{validate_vote, CheckpointView, FinalityVoteV1};

use crate::auth::{GrainContractEngine, NodeAuthVerifier, PreverifiedSignatureAuth};
use crate::devnet_fixture::fixture_witness_secret;
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
use crate::witness_role::sign_and_release_vote;
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
    /// Immutable Grain formula registry keyed by the object `code_hash`.
    /// Every execution path (admission simulation, proposal, import, replay,
    /// and sync) uses this same registry.
    pub contract_codes: BTreeMap<Hash32, Vec<u8>>,
    /// Production libp2p transport settings.
    pub network: crate::network::NetworkSettings,
    /// Weak-subjectivity checkpoint. SOCIAL INPUT (ch01 §10.5): obtained
    /// from social sources, labeled, and NEVER able to override local
    /// finality — see [`NodeCore::apply_social_checkpoint`].
    pub social_checkpoint: Option<CheckpointRef>,
    /// Devnet fixture witness bonds backing the epoch snapshot registry.
    pub witness_bonds: Vec<WitnessBondV1>,
    /// Minimum bond for snapshot eligibility (devnet fixture value).
    pub min_bond: u128,
    /// Devnet fixture finality (TEST NETWORKS ONLY): when set, the node
    /// signs the 3-of-4 fixture witness quorum itself at each epoch
    /// boundary (`devnet_fixture` seed law) instead of waiting for live
    /// witnesses. `noosd` enables this only for `--validator` runs against
    /// parameters with `is_test_network = true`.
    pub devnet_fixture_finality: bool,
    /// Height at which every legacy lending market is deterministically
    /// backfilled with a zero-funded StableSafetyV1 object.
    pub stable_safety_activation_height: Option<u64>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            mode: NodeMode::Full,
            observer: false,
            view_retention_blocks: 0,
            mempool: MempoolConfig::default(),
            contract_codes: BTreeMap::new(),
            network: crate::network::NetworkSettings::default(),
            social_checkpoint: None,
            witness_bonds: Vec::new(),
            min_bond: 1,
            devnet_fixture_finality: false,
            stable_safety_activation_height: None,
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

#[derive(Clone)]
struct ParkedBlock {
    header: BlockHeaderV1,
    ticket: GroundTicketV1,
    claim: BodyDaClaimV1,
    shards: Vec<ShardCandidateV1>,
}
struct ReconstructedBlockBody {
    body: BlockBodyV1,
    availability: ReconstructedBodyV1,
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

const PARALLEL_SIGNATURE_MIN_TRANSACTIONS: usize = 32;

#[derive(Clone)]
struct SignaturePrecheck {
    authorizations: Vec<(Hash32, Vec<u8>)>,
}

fn verify_transaction_signatures(
    ledger: &LumenLedger,
    transaction: &TransactionV1,
    witnesses: &TransactionWitnessesV1,
) -> Option<SignaturePrecheck> {
    if transaction.account_inputs.len() != witnesses.intents.len() {
        return None;
    }
    let id = txid(transaction);
    let verifier = NodeAuthVerifier;
    let mut authorizations = Vec::with_capacity(transaction.account_inputs.len());
    for (account_id, intent) in transaction
        .account_inputs
        .iter()
        .zip(witnesses.intents.iter())
    {
        if intent.tx_commitment != id {
            return None;
        }
        let account = ledger.get_account(account_id)?;
        if !verifier.verify_signature(
            intent.signature_suite,
            account.auth_descriptor.as_slice(),
            &id,
            intent.signature.as_slice(),
        ) {
            return None;
        }
        authorizations.push((*account_id, account.auth_descriptor.as_slice().to_vec()));
    }
    Some(SignaturePrecheck { authorizations })
}

#[allow(clippy::arithmetic_side_effects)]
fn parallel_signature_prechecks(
    ledger: &LumenLedger,
    body: &BlockBodyV1,
) -> Vec<Option<SignaturePrecheck>> {
    let transaction_count = body.transactions.len();
    let mut checks = vec![None; transaction_count];
    if transaction_count < PARALLEL_SIGNATURE_MIN_TRANSACTIONS {
        return checks;
    }
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(transaction_count);
    let chunk_size = transaction_count.div_ceil(workers);
    std::thread::scope(|scope| {
        for (chunk_index, check_chunk) in checks.chunks_mut(chunk_size).enumerate() {
            let start = chunk_index * chunk_size;
            scope.spawn(move || {
                for (offset, check) in check_chunk.iter_mut().enumerate() {
                    let index = start + offset;
                    let transaction = &body.transactions.as_slice()[index];
                    let witnesses = &body.segregated_witnesses.as_slice()[index];
                    *check = verify_transaction_signatures(ledger, transaction, witnesses);
                }
            });
        }
    });
    checks
}

struct ExecResult {
    receipts: Vec<ReceiptV1>,
    merged_delta: StateDelta,
    roots: LumenRoots,
}

#[derive(Clone)]
struct StagedConsensus {
    dag: HeaderDag,
    ledger: LumenLedger,
    anchor: (Hash32, u64, LumenLedger),
    exec_head: Hash32,
    exec_height: u64,
    tracker: FinalityTracker,
    registry: SnapshotRegistry,
    availability: AvailabilityLedger,
    orphan_blocks: BTreeMap<Hash32, ParkedBlock>,
    mempool: Mempool,
    view: ChainView,
}

#[derive(Clone)]
struct StagedBody {
    header: BlockHeaderV1,
    body: BlockBodyV1,
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

struct VoteCheckpointView<'a> {
    dag: &'a HeaderDag,
    justified: CheckpointRef,
}

impl CheckpointView for VoteCheckpointView<'_> {
    fn is_justified(&self, checkpoint: &CheckpointRef) -> bool {
        *checkpoint == self.justified
    }

    fn descends(&self, source: &CheckpointRef, target: &CheckpointRef) -> bool {
        DagAncestry { dag: self.dag }.descends(source, target)
    }
}

/// The single-writer consensus core.
pub struct NodeCore<P: StorePort> {
    pub cfg: NodeConfig,
    chain_id: Hash32,
    genesis_hash: Hash32,
    genesis_block_hash: Hash32,
    genesis_time_ms: u64,
    max_future_drift_ms: u64,
    dag: HeaderDag,
    ledger: LumenLedger,
    engine: GrainContractEngine,
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
    orphan_blocks: BTreeMap<Hash32, ParkedBlock>,
    pending_votes: Vec<FinalityVoteV1>,
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
    fn staged_consensus(&self) -> StagedConsensus {
        StagedConsensus {
            dag: self.dag.clone(),
            ledger: self.ledger.clone(),
            anchor: self.anchor.clone(),
            exec_head: self.exec_head,
            exec_height: self.exec_height,
            tracker: self.tracker.clone(),
            registry: self.registry.clone(),
            availability: self.availability.clone(),
            orphan_blocks: self.orphan_blocks.clone(),
            mempool: self.mempool.clone(),
            view: self.view.clone(),
        }
    }

    fn install_staged_consensus(&mut self, staged: StagedConsensus) {
        self.dag = staged.dag;
        self.ledger = staged.ledger;
        self.anchor = staged.anchor;
        self.exec_head = staged.exec_head;
        self.exec_height = staged.exec_height;
        self.tracker = staged.tracker;
        self.registry = staged.registry;
        self.availability = staged.availability;
        self.orphan_blocks = staged.orphan_blocks;
        self.mempool = staged.mempool;
        self.view = staged.view;
    }

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

        if cfg.contract_codes != spec.contract_codes {
            return Err(NodeError::Config(
                "node contract registry differs from genesis commitment".into(),
            ));
        }
        let proposer_secret =
            BlsSecretKey::from_seed(DEVNET_PROPOSER_SEED).map_err(|_| NodeError::Crypto)?;

        let engine = GrainContractEngine::new(
            built.chain_id,
            built.genesis_hash,
            spec.contract_codes.clone(),
        );
        let mut core = NodeCore {
            view: ChainView::new(cfg.view_retention_blocks),
            mempool: Mempool::new(cfg.mempool.clone()),
            cfg,
            chain_id: built.chain_id,
            genesis_hash: built.genesis_hash,
            genesis_block_hash,
            genesis_time_ms: spec.genesis_time_ms,
            max_future_drift_ms: spec.params.max_future_drift_ms,
            dag,
            anchor: (genesis_block_hash, 0, built.ledger.clone()),
            ledger: built.ledger,
            engine,
            exec_head: genesis_block_hash,
            exec_height: 0,
            tracker,
            registry: SnapshotRegistry::new(),
            availability,
            parked: BTreeMap::new(),
            orphan_blocks: BTreeMap::new(),
            pending_votes: Vec::new(),
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
    pub fn mode(&self) -> NodeMode {
        self.cfg.mode
    }

    /// Highest accepted chain position for network synchronization. Full
    /// nodes advance this through execution; light nodes advance it through
    /// validated header import.
    #[must_use]
    pub fn sync_head(&self) -> (u64, Hash32) {
        if self.cfg.mode == NodeMode::Full {
            return self.head();
        }
        self.dag
            .select_head()
            .and_then(|hash| {
                self.dag
                    .get(&hash)
                    .map(|stored| (stored.header.height, hash))
            })
            .unwrap_or_else(|| self.head())
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

    /// Devnet fixture finality driver (TEST NETWORKS ONLY; see
    /// [`NodeConfig::devnet_fixture_finality`]). Advances the FFG ladder by
    /// at most one rung: when the executed head has crossed the boundary of
    /// epoch `justified + 1`, signs the fixture 3-of-4 quorum over
    /// `justified -> next` and queues the certificate (which also rides the
    /// next produced block). Returns `true` when a certificate was queued.
    ///
    /// # Errors
    /// Snapshot construction, vote signing, or certificate ingestion
    /// failures; disabled or not-yet-eligible states are `Ok(false)`.
    pub fn devnet_finality_tick(&mut self) -> Result<bool, NodeError> {
        if !self.cfg.devnet_fixture_finality {
            return Ok(false);
        }
        let source = self.tracker.justified_head();
        let next_epoch = source.epoch.saturating_add(1);
        let boundary_height = next_epoch.saturating_mul(EPOCH_LENGTH);
        if self.exec_height < boundary_height {
            return Ok(false);
        }
        let target = CheckpointRef {
            epoch: next_epoch,
            checkpoint_hash: self
                .dag
                .ancestor_at_height(&self.exec_head, boundary_height)
                .ok_or(NodeError::BodyMismatch {
                    what: "epoch boundary block missing from dag",
                })?
                .hash,
        };
        self.ensure_snapshot(next_epoch)?;
        let snapshot = self
            .registry
            .get(next_epoch)
            .cloned()
            .ok_or(NodeError::Witness(
                noos_witness::WitnessError::UnknownSnapshot,
            ))?;
        let quorum = (snapshot.members().len().saturating_mul(2) / 3).saturating_add(1);
        let votes = snapshot.members()[..quorum]
            .iter()
            .map(|member| {
                // Fixture seed law: the BLS seed IS the validator id bytes.
                let secret =
                    BlsSecretKey::from_seed(member.validator_id).map_err(|_| NodeError::Crypto)?;
                FinalityVoteV1::sign(
                    self.chain_id,
                    next_epoch,
                    source,
                    target,
                    member.validator_id,
                    snapshot.root(),
                    &secret,
                )
                .map_err(NodeError::Witness)
            })
            .collect::<Result<Vec<_>, NodeError>>()?;
        let cert =
            build_certificate(&votes, &self.chain_id, &snapshot).map_err(NodeError::Witness)?;
        self.queue_certificate(cert)?;
        Ok(true)
    }
    /// Emits one independently signed fixture witness vote for a distributed
    /// engineering testnet. Unlike [`Self::devnet_finality_tick`], this signs
    /// only the selected member and relies on votes from distinct network
    /// peers to reach quorum. The vote safety record is durable before return.
    ///
    /// `witness_index` is intentionally restricted to the frozen four-member
    /// test fixture and is refused by `noosd` for non-test parameters.
    pub fn devnet_witness_vote_tick(
        &mut self,
        witness_index: usize,
    ) -> Result<Option<FinalityVoteV1>, NodeError> {
        let source = self.tracker.justified_head();
        let next_epoch = source.epoch.saturating_add(1);
        let boundary_height = next_epoch.saturating_mul(EPOCH_LENGTH);
        if self.exec_height < boundary_height {
            return Ok(None);
        }
        let target = CheckpointRef {
            epoch: next_epoch,
            checkpoint_hash: self
                .dag
                .ancestor_at_height(&self.exec_head, boundary_height)
                .ok_or(NodeError::BodyMismatch {
                    what: "epoch boundary block missing from dag",
                })?
                .hash,
        };
        self.ensure_snapshot(next_epoch)?;
        let snapshot = self
            .registry
            .get(next_epoch)
            .cloned()
            .ok_or(NodeError::Witness(
                noos_witness::WitnessError::UnknownSnapshot,
            ))?;
        let member = snapshot
            .members()
            .get(witness_index)
            .ok_or_else(|| NodeError::Config("devnet witness index outside fixture set".into()))?;
        if self.pending_votes.iter().any(|known| {
            known.epoch == next_epoch
                && known.source == source
                && known.target == target
                && known.validator_id == member.validator_id
        }) {
            return Ok(None);
        }
        let secret = fixture_witness_secret(witness_index).map_err(|_| NodeError::Crypto)?;
        let vote = sign_and_release_vote(
            &mut self.port,
            self.chain_id,
            next_epoch,
            source,
            target,
            member.validator_id,
            snapshot.root(),
            &secret,
        )
        .map_err(|error| NodeError::Config(format!("devnet witness vote refused: {error:?}")))?;
        self.ingest_network_vote(vote.clone())?;
        Ok(Some(vote))
    }

    /// Validates and aggregates an inbound checkpoint vote. A quorum is
    /// converted through the witness crate's sole certificate constructor
    /// and enters the same certificate path as block-carried certificates.
    pub fn ingest_network_vote(&mut self, vote: FinalityVoteV1) -> Result<(), NodeError> {
        let snapshot = self
            .registry
            .get(vote.epoch)
            .cloned()
            .ok_or(NodeError::Witness(
                noos_witness::WitnessError::UnknownSnapshot,
            ))?;
        let view = VoteCheckpointView {
            dag: &self.dag,
            justified: self.tracker.justified_head(),
        };
        validate_vote(&vote, &self.chain_id, &snapshot, &view)?;
        if self.pending_votes.iter().any(|known| {
            known.epoch == vote.epoch
                && known.source == vote.source
                && known.target == vote.target
                && known.validator_id == vote.validator_id
        }) {
            return Ok(());
        }
        if self.pending_votes.len() >= 1024 {
            self.pending_votes.remove(0);
        }
        self.pending_votes.push(vote.clone());
        let quorum: Vec<_> = self
            .pending_votes
            .iter()
            .filter(|known| {
                known.epoch == vote.epoch
                    && known.source == vote.source
                    && known.target == vote.target
                    && known.membership_root == vote.membership_root
            })
            .cloned()
            .collect();
        match build_certificate(&quorum, &self.chain_id, &snapshot) {
            Ok(cert) => {
                self.pending_votes.retain(|known| {
                    known.epoch != vote.epoch
                        || known.source != vote.source
                        || known.target != vote.target
                });
                self.queue_certificate(cert)
            }
            Err(noos_witness::WitnessError::QuorumNotMet) => Ok(()),
            Err(error) => Err(NodeError::Witness(error)),
        }
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
        let mut registry = self.registry.clone();
        self.ensure_snapshot_for(&mut registry, epoch)?;
        self.registry = registry;
        Ok(())
    }

    fn ensure_snapshot_for(
        &self,
        registry: &mut SnapshotRegistry,
        epoch: u64,
    ) -> Result<(), NodeError> {
        if registry.get(epoch).is_some() || self.cfg.witness_bonds.is_empty() {
            return Ok(());
        }
        let prev = registry.get(epoch.wrapping_sub(1)).cloned();
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
                registry
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

    /// Stages 0-2 + DAG insertion. Body certificates, when available, are
    /// applied in canonical order before the header checkpoint pair is
    /// compared with the prospective verified finality state.
    fn import_header_stages(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        certificates: Option<&[FinalityCertificateV1]>,
    ) -> Result<InsertOutcome, NodeError> {
        self.validate_header_non_context(header, ticket)?;
        let mut staged = self.staged_consensus();
        if !staged.dag.contains(&header.parent_hash) {
            let outcome = staged.dag.insert(header.clone(), ticket)?;
            self.dag = staged.dag;
            return Ok(outcome);
        }
        self.validate_ticket_in_context_for(&staged.dag, header, ticket)?;
        let outcome = staged.dag.insert(header.clone(), ticket)?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash } => hash,
            InsertOutcome::Orphaned { .. } => {
                return Err(NodeError::Dag(noos_braid::DagError::UnknownBlock));
            }
        };
        if certificates.is_none() && header.finality_certificate_root != ZERO_ROOT {
            return Err(NodeError::BodyMismatch {
                what: "finality certificate evidence absent",
            });
        }
        self.stage_certificates(&mut staged, certificates.unwrap_or_default(), None)?;
        Self::validate_checkpoint_binding(&staged, header, &hash)?;
        self.dag = staged.dag;
        self.tracker = staged.tracker;
        self.registry = staged.registry;
        Ok(outcome)
    }

    fn validate_header_non_context(
        &self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<(), NodeError> {
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
        if body_ticket_root(ticket)? != header.ground_ticket_root {
            return Err(NodeError::BodyMismatch {
                what: "ground_ticket_root",
            });
        }
        Ok(())
    }

    fn validate_ticket_in_context_for(
        &self,
        dag: &HeaderDag,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<(), NodeError> {
        let parent = dag
            .get(&header.parent_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let parent_target = parent.header.ground_target_u256();
        let expected = self.expected_target_for(dag, &parent.hash, header.height)?;
        let parent_timestamps =
            dag.parent_timestamps(&parent.hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS);
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
            max_future_drift_ms: self.max_future_drift_ms,
            ground_target: &claimed,
            expected_target: &expected,
            proposal_commitment: &commitment,
            proposer_pubkey: &header.proposer_key.0,
        };
        validate_ticket(&ctx, ticket, &dag.duplicate_scan(&parent.hash))?;
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
        self.expected_target_for(&self.dag, parent_hash, child_height)
    }

    fn expected_target_for(
        &self,
        dag: &HeaderDag,
        parent_hash: &Hash32,
        child_height: u64,
    ) -> Result<U256, NodeError> {
        let parent = dag
            .get(parent_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let anchor_ref = parent.header.finalized_checkpoint;
        let anchor_hash = if anchor_ref.checkpoint_hash == ZERO_ROOT {
            // Genesis header names the zero checkpoint: anchor on genesis.
            self.genesis_block_hash
        } else {
            anchor_ref.checkpoint_hash
        };
        let anchor = dag
            .get(&anchor_hash)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
        let anchor_mtp_ms = median_time_past_ms(
            &dag.parent_timestamps(&anchor_hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS),
        )
        .unwrap_or(anchor.header.timestamp_ms);
        let parent_mtp_ms = median_time_past_ms(
            &dag.parent_timestamps(parent_hash, noos_ground::MEDIAN_TIME_PAST_BLOCKS),
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

    /// Network light-sync entry point. Full nodes must import complete bodies.
    pub fn import_header_for_light_sync(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        certificates: &BoundedList<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>,
    ) -> Result<ImportOutcome, NodeError> {
        if self.cfg.mode != NodeMode::Light {
            return Err(NodeError::Config(
                "header-only import is restricted to light mode".into(),
            ));
        }
        if body_cert_root(certificates)? != header.finality_certificate_root {
            return Err(NodeError::BodyMismatch {
                what: "finality_certificate_root",
            });
        }
        let outcome = self.import_header_stages(header, ticket, Some(certificates.as_slice()))?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash } => hash,
            InsertOutcome::Orphaned { hash, .. } => return Ok(ImportOutcome::Orphaned { hash }),
        };
        self.promote_light_orphans(hash);
        Ok(ImportOutcome::HeaderAccepted { hash })
    }

    /// Light-mode import: stages 0-2 only (ch01 §10.5 light sync).
    pub fn import_header_light(
        &mut self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<ImportOutcome, NodeError> {
        let certificates =
            BoundedList::<FinalityCertificateV1, MAX_FINALITY_CERTIFICATES>::default();
        self.import_header_for_light_sync(header, ticket, &certificates)
    }

    fn promote_light_orphans(&mut self, root: Hash32) {
        let mut queue = vec![root];
        let mut cursor = 0;
        let empty_cert_root = body_cert_root(&BoundedList::<
            FinalityCertificateV1,
            MAX_FINALITY_CERTIFICATES,
        >::default())
        .ok();
        while cursor < queue.len() {
            let parent = queue[cursor];
            cursor = cursor.saturating_add(1);
            for orphan in self.dag.take_orphans_waiting_on(&parent) {
                let mut candidate = self.staged_consensus();
                let result = if Some(orphan.header.finality_certificate_root) != empty_cert_root {
                    Err(NodeError::BodyMismatch {
                        what: "finality certificate evidence absent",
                    })
                } else {
                    self.validate_header_non_context(&orphan.header, &orphan.ticket)
                        .and_then(|()| {
                            self.validate_ticket_in_context_for(
                                &candidate.dag,
                                &orphan.header,
                                &orphan.ticket,
                            )
                        })
                        .and_then(|()| {
                            candidate
                                .dag
                                .insert(orphan.header.clone(), &orphan.ticket)
                                .map_err(NodeError::Dag)
                                .map(|_| ())
                        })
                        .and_then(|()| {
                            Self::validate_checkpoint_binding(
                                &candidate,
                                &orphan.header,
                                &orphan.hash,
                            )
                        })
                };
                if result.is_ok() {
                    self.dag = candidate.dag;
                    queue.push(orphan.hash);
                } else {
                    self.dag.drop_orphan_subtree(&orphan.hash);
                }
            }
        }
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
        self.validate_header_non_context(header, ticket)?;
        let hash = *header
            .block_hash()
            .map_err(|_| NodeError::Crypto)?
            .as_bytes();

        // Unknown-parent blocks remain inert. Their full payload is retained
        // only inside the same bounded orphan cache so parent arrival can
        // rerun the ordinary full import law before connection.
        if !self.dag.contains(&header.parent_hash) {
            let mut staged = self.staged_consensus();
            let outcome = staged.dag.insert(header.clone(), ticket)?;
            let retained = matches!(outcome, InsertOutcome::Orphaned { retained: true, .. });
            staged
                .orphan_blocks
                .retain(|known, _| staged.dag.is_orphan(known));
            if retained {
                staged.orphan_blocks.insert(
                    hash,
                    ParkedBlock {
                        header: header.clone(),
                        ticket: *ticket,
                        claim: *claim,
                        shards: shards.to_vec(),
                    },
                );
            }
            self.dag = staged.dag;
            self.orphan_blocks = staged.orphan_blocks;
            return Ok(ImportOutcome::Orphaned { hash });
        }

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
                return Err(e);
            }
        };
        self.validate_stage_commit(hash, header, ticket, body)
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
        let original = parked.clone();
        parked.shards.extend_from_slice(more);
        match self.reconstruct_body(
            &parked.header,
            &parked.ticket,
            &parked.claim,
            &parked.shards,
        ) {
            Ok(body) => {
                let header = parked.header.clone();
                let ticket = parked.ticket;
                match self.validate_stage_commit(*block_hash, &header, &ticket, body) {
                    Ok(outcome) => {
                        self.metrics
                            .set(&self.metrics.blocks_parked, self.parked.len() as u64);
                        Ok(Some(outcome))
                    }
                    Err(error) => {
                        self.parked.insert(*block_hash, original);
                        Err(error)
                    }
                }
            }
            Err(NodeError::Da(DaError::NotEnoughValidShards { .. })) => {
                self.parked.insert(*block_hash, parked);
                Ok(None)
            }
            Err(e) => {
                self.parked.insert(*block_hash, original);
                Err(e)
            }
        }
    }

    /// Stage-3 body work: reconstruct, decode the DA form, substitute the
    /// validated ticket, cross-check every body-derived header root.
    fn reconstruct_body(
        &self,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        claim: &BodyDaClaimV1,
        shards: &[ShardCandidateV1],
    ) -> Result<ReconstructedBlockBody, NodeError> {
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
        Ok(ReconstructedBlockBody {
            body,
            availability: reconstructed,
        })
    }

    fn validate_stage_commit(
        &mut self,
        hash: Hash32,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        body: ReconstructedBlockBody,
    ) -> Result<ImportOutcome, NodeError> {
        let mut staged = self.staged_consensus();
        let mut writes = WriteSet::default();
        let mut bodies = BTreeMap::new();
        self.stage_connected_block(
            &mut staged,
            &mut writes,
            &mut bodies,
            hash,
            header,
            ticket,
            body,
            true,
        )?;
        self.stage_reachable_orphans(&mut staged, &mut writes, &mut bodies, hash);
        let (reorged, connected_blocks, settled_txs) =
            self.stage_fork_choice(&mut staged, &mut writes, &bodies)?;
        self.stage_refresh_anchor(&mut staged, &bodies)?;

        let justified = staged.tracker.justified_head();
        let finalized = staged.tracker.finalized_head();
        writes
            .indices
            .push((KEY_JUSTIFIED.to_vec(), Some(justified.encode_canonical())));
        writes
            .indices
            .push((KEY_FINALIZED.to_vec(), Some(finalized.encode_canonical())));
        staged.view.heads.justified = justified;
        staged.view.heads.finalized = finalized;

        let canonical = staged
            .dag
            .ancestor_at_height(&staged.exec_head, header.height)
            .is_some_and(|ancestor| ancestor.hash == hash);
        let outcome = if canonical {
            ImportOutcome::Executed { hash }
        } else {
            ImportOutcome::SideChain { hash }
        };
        let seq = self.port.commit(&writes)?;
        self.install_staged_consensus(staged);

        let m = &self.metrics;
        m.set(&m.store_seq, seq);
        m.set(&m.height, self.exec_height);
        m.set(&m.justified_epoch, justified.epoch);
        m.set(&m.finalized_epoch, finalized.epoch);
        m.set(&m.mempool_txs, self.mempool.len() as u64);
        m.set(&m.mempool_bytes, self.mempool.total_bytes() as u64);
        for _ in 0..connected_blocks {
            m.inc(&m.blocks_imported_total);
        }
        for _ in 0..settled_txs {
            m.inc(&m.txs_settled_total);
        }
        if reorged {
            m.inc(&m.reorgs_total);
        }
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_connected_block(
        &self,
        staged: &mut StagedConsensus,
        writes: &mut WriteSet,
        bodies: &mut BTreeMap<Hash32, StagedBody>,
        expected_hash: Hash32,
        header: &BlockHeaderV1,
        ticket: &GroundTicketV1,
        reconstructed: ReconstructedBlockBody,
        defer_selected_validation: bool,
    ) -> Result<(), NodeError> {
        let ReconstructedBlockBody { body, availability } = reconstructed;
        self.validate_header_non_context(header, ticket)?;
        self.validate_ticket_in_context_for(&staged.dag, header, ticket)?;
        let outcome = staged.dag.insert(header.clone(), ticket)?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash } => hash,
            InsertOutcome::Orphaned { .. } => {
                return Err(NodeError::Dag(noos_braid::DagError::UnknownBlock));
            }
        };
        if hash != expected_hash {
            return Err(NodeError::BodyMismatch {
                what: "block hash changed during staging",
            });
        }

        self.stage_certificates(staged, body.finality_certificates.as_slice(), Some(writes))?;
        Self::validate_checkpoint_binding(staged, header, &hash)?;
        // The selected head is executed and root-verified by
        // `stage_fork_choice` before any write commits. Validate inert
        // side-chain bodies here; avoid executing the canonical candidate
        // twice.
        if !defer_selected_validation || staged.dag.select_head() != Some(hash) {
            self.validate_body_at_parent(staged, bodies, header, &body)?;
        }

        // `reconstruct_and_verify` already rebuilt the unique codeword and
        // checked its full shard tree against the trusted header root. Record
        // that proof-bearing result directly; re-encoding it here would repeat
        // Reed-Solomon and Merkle work without adding a check.
        staged.availability.record_reconstructed(&availability);
        let mut header_bytes = header.encode_canonical();
        header_bytes.extend_from_slice(&ticket.encode());
        writes.headers.push((key_header(&hash), Some(header_bytes)));
        if !writes
            .blobs
            .iter()
            .any(|blob| blob.hash == header.body_da_root)
        {
            writes.blobs.push(Blob {
                hash: header.body_da_root,
                bytes: body.encode_canonical(),
            });
        }
        staged.orphan_blocks.remove(&hash);
        bodies.insert(
            hash,
            StagedBody {
                header: header.clone(),
                body,
            },
        );
        Ok(())
    }

    fn validate_body_at_parent(
        &self,
        staged: &StagedConsensus,
        bodies: &BTreeMap<Hash32, StagedBody>,
        header: &BlockHeaderV1,
        body: &BlockBodyV1,
    ) -> Result<(), NodeError> {
        let mut ledger = if header.parent_hash == staged.exec_head {
            staged.ledger.clone()
        } else {
            let mut path = Vec::new();
            let mut cursor = header.parent_hash;
            while cursor != staged.anchor.0 {
                let stored = staged
                    .dag
                    .get(&cursor)
                    .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
                if stored.header.height <= staged.anchor.1 {
                    return Err(NodeError::Dag(noos_braid::DagError::ReorgAcrossFinality));
                }
                path.push(cursor);
                cursor = stored.header.parent_hash;
            }
            path.reverse();
            let mut ledger = staged.anchor.2.clone();
            for hash in path {
                let ancestor = self.staged_body(bodies, &hash)?;
                Self::execute_and_verify_on(
                    &mut ledger,
                    self.chain_id,
                    &self.engine,
                    self.cfg.stable_safety_activation_height,
                    &ancestor.header,
                    &ancestor.body,
                )?;
            }
            ledger
        };
        Self::execute_and_verify_on(
            &mut ledger,
            self.chain_id,
            &self.engine,
            self.cfg.stable_safety_activation_height,
            header,
            body,
        )?;
        Ok(())
    }

    fn stage_reachable_orphans(
        &self,
        staged: &mut StagedConsensus,
        writes: &mut WriteSet,
        bodies: &mut BTreeMap<Hash32, StagedBody>,
        root: Hash32,
    ) {
        let mut queue = vec![root];
        let mut cursor = 0;
        while cursor < queue.len() {
            let parent = queue[cursor];
            cursor = cursor.saturating_add(1);
            for orphan in staged.dag.take_orphans_waiting_on(&parent) {
                let hash = orphan.hash;
                let parked = staged.orphan_blocks.get(&hash).cloned();
                let mut candidate = staged.clone();
                candidate.orphan_blocks.remove(&hash);
                let mut candidate_writes = writes.clone();
                let mut candidate_bodies = bodies.clone();
                let result = if let Some(parked) = parked {
                    self.reconstruct_body(
                        &parked.header,
                        &parked.ticket,
                        &parked.claim,
                        &parked.shards,
                    )
                    .and_then(|body| {
                        self.stage_connected_block(
                            &mut candidate,
                            &mut candidate_writes,
                            &mut candidate_bodies,
                            hash,
                            &parked.header,
                            &parked.ticket,
                            body,
                            false,
                        )
                    })
                } else if orphan.header.finality_certificate_root != ZERO_ROOT {
                    Err(NodeError::BodyMismatch {
                        what: "finality certificate evidence absent",
                    })
                } else {
                    self.validate_header_non_context(&orphan.header, &orphan.ticket)
                        .and_then(|()| {
                            self.validate_ticket_in_context_for(
                                &candidate.dag,
                                &orphan.header,
                                &orphan.ticket,
                            )
                        })
                        .and_then(|()| {
                            candidate
                                .dag
                                .insert(orphan.header.clone(), &orphan.ticket)
                                .map_err(NodeError::Dag)
                                .map(|_| ())
                        })
                        .and_then(|()| {
                            Self::validate_checkpoint_binding(&candidate, &orphan.header, &hash)
                        })
                };
                if result.is_ok() {
                    *staged = candidate;
                    *writes = candidate_writes;
                    *bodies = candidate_bodies;
                    queue.push(hash);
                } else {
                    let mut dropped = staged.dag.drop_orphan_subtree(&hash);
                    dropped.push(hash);
                    for dropped_hash in dropped {
                        staged.orphan_blocks.remove(&dropped_hash);
                    }
                }
            }
        }
    }

    fn staged_body(
        &self,
        bodies: &BTreeMap<Hash32, StagedBody>,
        hash: &Hash32,
    ) -> Result<StagedBody, NodeError> {
        if let Some(body) = bodies.get(hash) {
            return Ok(body.clone());
        }
        let (header, ticket) = self.load_header(hash)?;
        let body = self.load_body(&header, &ticket)?;
        Ok(StagedBody { header, body })
    }

    fn stage_fork_choice(
        &self,
        staged: &mut StagedConsensus,
        writes: &mut WriteSet,
        bodies: &BTreeMap<Hash32, StagedBody>,
    ) -> Result<(bool, u64, u64), NodeError> {
        let Some(best) = staged.dag.select_head() else {
            return Ok((false, 0, 0));
        };
        if best == staged.exec_head {
            return Ok((false, 0, 0));
        }
        for ancestor in staged.dag.ancestors(&best) {
            if ancestor.hash == staged.exec_head || ancestor.header.height == 0 {
                break;
            }
            if !staged
                .availability
                .body_available(&noos_crypto::Hash32::from_bytes(
                    ancestor.header.body_da_root,
                ))
            {
                return Ok((false, 0, 0));
            }
        }

        let plan = staged.dag.plan_reorg(&staged.exec_head, &best)?;
        let reorged = !plan.disconnect.is_empty();
        let execution_path = if reorged {
            let mut path = Vec::new();
            let mut cursor = best;
            while cursor != staged.anchor.0 {
                let stored = staged
                    .dag
                    .get(&cursor)
                    .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
                if stored.header.height <= staged.anchor.1 {
                    return Err(NodeError::Dag(noos_braid::DagError::ReorgAcrossFinality));
                }
                path.push(cursor);
                cursor = stored.header.parent_hash;
            }
            path.reverse();
            staged.ledger = staged.anchor.2.clone();
            path
        } else {
            plan.connect.clone()
        };

        let mut deltas = Vec::new();
        let mut executed = BTreeMap::new();
        for hash in execution_path {
            let block = self.staged_body(bodies, &hash)?;
            let exec = Self::execute_and_verify_on(
                &mut staged.ledger,
                self.chain_id,
                &self.engine,
                self.cfg.stable_safety_activation_height,
                &block.header,
                &block.body,
            )?;
            deltas.push(exec.merged_delta.clone());
            executed.insert(hash, (block, exec));
        }

        for hash in &plan.disconnect {
            if let Some(stored) = staged.dag.get(hash) {
                staged.view.disconnect_block(stored.header.height);
            }
        }
        let mut settled_txs = 0_u64;
        for hash in &plan.connect {
            let (block, exec) = executed.get(hash).ok_or(NodeError::BodyMismatch {
                what: "staged execution result missing",
            })?;
            let settled: Vec<Hash32> = exec.receipts.iter().map(|r| r.txid).collect();
            settled_txs = settled_txs.saturating_add(exec.receipts.len() as u64);
            staged
                .mempool
                .on_block_connected(&settled, block.header.height.saturating_add(1));
            staged
                .view
                .connect_block(&block.header, *hash, &exec.receipts);
            writes
                .indices
                .push((key_height(block.header.height), Some(hash.to_vec())));
            for receipt in &exec.receipts {
                let mut value = block.header.height.to_le_bytes().to_vec();
                value.extend_from_slice(&receipt.encode_canonical());
                writes.receipts.push((receipt.txid.to_vec(), Some(value)));
            }
        }
        staged.exec_head = best;
        staged.exec_height = staged
            .dag
            .get(&best)
            .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?
            .header
            .height;
        writes.delta = merge_deltas(deltas);
        writes.roots = Some(staged.ledger.roots());
        writes
            .indices
            .push((KEY_HEAD.to_vec(), Some(best.to_vec())));
        Ok((reorged, plan.connect.len() as u64, settled_txs))
    }

    fn stage_refresh_anchor(
        &self,
        staged: &mut StagedConsensus,
        bodies: &BTreeMap<Hash32, StagedBody>,
    ) -> Result<(), NodeError> {
        let finalized = staged.tracker.finalized_head();
        let height = finalized
            .expected_height()
            .ok_or(NodeError::Dag(noos_braid::DagError::NotACheckpointHeight))?;
        if height <= staged.anchor.1 || height > staged.exec_height {
            return Ok(());
        }
        if staged
            .dag
            .ancestor_at_height(&staged.exec_head, height)
            .is_none_or(|ancestor| ancestor.hash != finalized.checkpoint_hash)
        {
            return Ok(());
        }
        let mut path = Vec::new();
        let mut cursor = finalized.checkpoint_hash;
        while cursor != staged.anchor.0 {
            let stored = staged
                .dag
                .get(&cursor)
                .ok_or(NodeError::Dag(noos_braid::DagError::UnknownBlock))?;
            path.push(cursor);
            cursor = stored.header.parent_hash;
        }
        path.reverse();
        let mut ledger = staged.anchor.2.clone();
        for hash in path {
            let block = self.staged_body(bodies, &hash)?;
            Self::execute_and_verify_on(
                &mut ledger,
                self.chain_id,
                &self.engine,
                self.cfg.stable_safety_activation_height,
                &block.header,
                &block.body,
            )?;
        }
        staged.anchor = (finalized.checkpoint_hash, height, ledger);
        Ok(())
    }

    // -- execution --------------------------------------------------------------

    /// Stage 4-5: normative-order execution + full root comparison.
    fn execute_and_verify(
        &mut self,
        header: &BlockHeaderV1,
        body: &BlockBodyV1,
    ) -> Result<ExecResult, NodeError> {
        Self::execute_and_verify_on(
            &mut self.ledger,
            self.chain_id,
            &self.engine,
            self.cfg.stable_safety_activation_height,
            header,
            body,
        )
    }

    fn execute_and_verify_on(
        ledger: &mut LumenLedger,
        chain_id: Hash32,
        engine: &GrainContractEngine,
        stable_safety_activation_height: Option<u64>,
        header: &BlockHeaderV1,
        body: &BlockBodyV1,
    ) -> Result<ExecResult, NodeError> {
        let mut deltas: Vec<StateDelta> = Vec::new();
        if let Some(activation_height) = stable_safety_activation_height {
            deltas.push(
                ledger
                    .activate_stable_safety_upgrade(header.height, activation_height)
                    .map_err(NodeError::Migration)?,
            );
        }

        // System transitions first (ch01 §9.3): parameter activation, then
        // the deterministic emission for this height.
        deltas.push(ledger.activate_pending_params(header.height));
        let prices = ledger
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
            ledger
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
            chain_id,
            height: header.height,
        };
        let signature_prechecks = parallel_signature_prechecks(ledger, body);
        let auth = NodeAuthVerifier;
        let preverified_auth = PreverifiedSignatureAuth;
        let mut receipts: Vec<ReceiptV1> = Vec::with_capacity(body.transactions.len());
        for (index, (tx, wits)) in body
            .transactions
            .iter()
            .zip(body.segregated_witnesses.iter())
            .enumerate()
        {
            let signatures_unchanged = signature_prechecks[index].as_ref().is_some_and(|check| {
                check.authorizations.iter().all(|(account_id, descriptor)| {
                    ledger.get_account(account_id).is_some_and(|account| {
                        account.auth_descriptor.as_slice() == descriptor.as_slice()
                    })
                })
            });
            let verifier: &dyn AuthVerifier = if signatures_unchanged {
                &preverified_auth
            } else {
                &auth
            };
            let tx_bytes = tx.encode_canonical();
            let wit_bytes = wits.encode_canonical();
            let encoded_len =
                tx_bytes
                    .len()
                    .checked_add(wit_bytes.len())
                    .ok_or(NodeError::LumenReject(
                        noos_lumen::state::RejectReason::OversizedEncoding,
                    ))?;
            let outcome = ledger
                .apply_canonical_decoded_transaction(&ctx, tx, wits, encoded_len, engine, verifier)
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
            ledger
                .end_block_fee_update(&usage)
                .map_err(NodeError::LumenReject)?,
        );

        // Stage 5: ALL claimed roots (six Lumen + both receipt roots).
        let roots = ledger.roots();
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

    fn stage_certificates(
        &self,
        staged: &mut StagedConsensus,
        certificates: &[FinalityCertificateV1],
        mut writes: Option<&mut WriteSet>,
    ) -> Result<(), NodeError> {
        for cert in certificates {
            self.ensure_snapshot_for(&mut staged.registry, cert.target.epoch)?;
            let ancestry = DagAncestry { dag: &staged.dag };
            let outcome = staged
                .tracker
                .ingest_certificate(cert, &staged.registry, &ancestry)?;
            let digest =
                noos_witness::finality::certificate_digest(cert).map_err(NodeError::Witness)?;
            if !matches!(outcome, IngestOutcome::Duplicate) {
                if let Some(ws) = writes.as_deref_mut() {
                    ws.indices.push((
                        key_certificate(cert.target.epoch, &digest),
                        Some(cert.encode_canonical()),
                    ));
                }
            }
            match outcome {
                IngestOutcome::Duplicate => {}
                IngestOutcome::Justified => {
                    staged.dag.set_justified(staged.tracker.justified_head())?;
                }
                IngestOutcome::Finalized(cp) => {
                    staged.dag.set_finalized(cp)?;
                    staged.dag.set_justified(staged.tracker.justified_head())?;
                }
            }
        }
        Ok(())
    }

    /// A header is a snapshot of the finality state *after* its body
    /// certificates have been applied in wire order. This exact ordering is
    /// what permits a same-block certificate transition while making absent,
    /// reordered, or mismatched evidence fail closed.
    fn validate_checkpoint_binding(
        staged: &StagedConsensus,
        header: &BlockHeaderV1,
        hash: &Hash32,
    ) -> Result<(), NodeError> {
        let justified = staged.tracker.justified_head();
        let finalized = staged.tracker.finalized_head();
        if header.justified_checkpoint != justified || header.finalized_checkpoint != finalized {
            return Err(NodeError::Dag(noos_braid::DagError::UnverifiedCheckpoint));
        }
        for checkpoint in [finalized, justified] {
            let Some(height) = checkpoint.expected_height() else {
                return Err(NodeError::Dag(noos_braid::DagError::UnverifiedCheckpoint));
            };
            if height > header.height
                || staged
                    .dag
                    .get(&checkpoint.checkpoint_hash)
                    .is_none_or(|stored| stored.header.height != height)
                || staged
                    .dag
                    .ancestor_at_height(hash, height)
                    .is_none_or(|ancestor| ancestor.hash != checkpoint.checkpoint_hash)
            {
                return Err(NodeError::Dag(noos_braid::DagError::UnverifiedCheckpoint));
            }
        }
        if !(DagAncestry { dag: &staged.dag }).descends(&finalized, &justified) {
            return Err(NodeError::Dag(noos_braid::DagError::UnverifiedCheckpoint));
        }
        Ok(())
    }

    fn process_certificate(&mut self, cert: &FinalityCertificateV1) -> Result<(), NodeError> {
        let mut staged = self.staged_consensus();
        let mut ws = WriteSet::default();
        self.stage_certificates(&mut staged, std::slice::from_ref(cert), Some(&mut ws))?;
        if ws.indices.is_empty() {
            return Ok(());
        }
        let justified = staged.tracker.justified_head();
        let finalized = staged.tracker.finalized_head();
        ws.indices
            .push((KEY_JUSTIFIED.to_vec(), Some(justified.encode_canonical())));
        ws.indices
            .push((KEY_FINALIZED.to_vec(), Some(finalized.encode_canonical())));
        let seq = self.port.commit(&ws)?;
        staged.view.heads.justified = justified;
        staged.view.heads.finalized = finalized;
        self.install_staged_consensus(staged);
        let m = &self.metrics;
        m.set(&m.store_seq, seq);
        m.set(&m.justified_epoch, justified.epoch);
        m.set(&m.finalized_epoch, finalized.epoch);
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
            // execution, roots, and the same-block certificate/checkpoint
            // ordering used during live import.
            self.import_header_stages(
                &header,
                &ticket,
                Some(body.finality_certificates.as_slice()),
            )?;
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

        // A certificate can be durably ingested immediately after the last
        // block and therefore be newer than every certificate embedded in
        // the replayed bodies. Preserve that boundary so such certificates
        // are re-embedded in the first post-restart block for peers that did
        // not receive the standalone certificate.
        let embedded_justified_epoch = self.tracker.justified_head().epoch;

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
            if cert.target.epoch > embedded_justified_epoch
                && self.pending_certs.len() < MAX_FINALITY_CERTIFICATES as usize
            {
                self.pending_certs.push(cert);
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

    /// Execute a transaction against a discardable Lumen overlay at the next
    /// block height. This performs full canonical decoding, witness and
    /// signature checks, fee calculation, action execution, and postconditions
    /// without inserting into the mempool or mutating ledger state.
    pub fn simulate_tx(
        &self,
        tx_bytes: &[u8],
        wit_bytes: &[u8],
    ) -> Result<noos_lumen::state::SimulationOutcome, noos_lumen::state::RejectReason> {
        let ctx = BlockContext {
            chain_id: self.chain_id,
            height: self.exec_height.saturating_add(1),
        };
        self.ledger
            .simulate_transaction(&ctx, tx_bytes, wit_bytes, &self.engine, &NodeAuthVerifier)
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
        if let Some(activation_height) = self.cfg.stable_safety_activation_height {
            deltas.push(
                self.ledger
                    .activate_stable_safety_upgrade(height, activation_height)
                    .map_err(NodeError::Migration)?,
            );
        }
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
        let template: Vec<(Hash32, TransactionV1, TransactionWitnessesV1, usize, bool)> = self
            .mempool
            .template(&capacity)
            .into_iter()
            .map(|entry| {
                let signatures_preverified =
                    entry
                        .signature_authorizations
                        .iter()
                        .all(|(account_id, descriptor)| {
                            self.ledger.get_account(account_id).is_some_and(|account| {
                                account.auth_descriptor.as_slice() == descriptor.as_slice()
                            })
                        });
                (
                    entry.txid,
                    entry.tx.clone(),
                    entry.witnesses.clone(),
                    entry.encoded_len(),
                    signatures_preverified,
                )
            })
            .collect();
        let ctx = BlockContext {
            chain_id: self.chain_id,
            height,
        };
        let engine = self.engine.clone();
        let auth = NodeAuthVerifier;
        let preverified_auth = PreverifiedSignatureAuth;
        let mut receipts: Vec<ReceiptV1> = Vec::new();
        let mut included: Vec<(TransactionV1, TransactionWitnessesV1)> = Vec::new();
        let mut dropped: Vec<Hash32> = Vec::new();
        for (txid, tx, witnesses, encoded_len, signatures_preverified) in template {
            let verifier: &dyn noos_lumen::engine::AuthVerifier = if signatures_preverified {
                &preverified_auth
            } else {
                &auth
            };
            match self.ledger.apply_canonical_decoded_transaction(
                &ctx,
                &tx,
                &witnesses,
                encoded_len,
                &engine,
                verifier,
            ) {
                Ok(outcome) => {
                    receipts.push(outcome.receipt().clone());
                    match outcome {
                        noos_lumen::state::ApplyOutcome::Applied { delta, .. }
                        | noos_lumen::state::ApplyOutcome::Failed { delta, .. } => {
                            deltas.push(delta);
                        }
                    }
                    included.push((tx, witnesses));
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

        // Assemble the body directly from the canonical typed values retained
        // at admission; no encode/decode round trip occurs on the hot path.
        let (txs, wits): (Vec<_>, Vec<_>) = included.into_iter().unzip();
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
        let outcome = self.import_header_stages(
            &header,
            &ticket,
            Some(body.finality_certificates.as_slice()),
        )?;
        let hash = match outcome {
            InsertOutcome::Inserted { hash } => hash,
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
