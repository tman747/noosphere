//! Deterministic in-memory header DAG (plan §6.1, §6.4).
//!
//! * Insert-validated headers keyed by block hash, with parent/children
//!   links and height/slot indices — every map is a `BTreeMap`/`BTreeSet`,
//!   so iteration order is a function of content only.
//! * Duplicate-ticket exclusion (ch01 §4.2 rule 8): the store keeps each
//!   block's `(proposer_pubkey, nonce, extra_nonce)` tuple and scans the
//!   ancestor path strictly above the local finalized checkpoint, both at
//!   insert time and through the [`noos_ground::DuplicateSet`] adapter
//!   returned by [`HeaderDag::duplicate_scan`]. The window resets when the
//!   finalized checkpoint advances.
//! * Bounded orphan pool: headers whose parent is unknown wait, keyed by
//!   block hash and indexed by awaited parent. At capacity the orphan with
//!   the numerically LARGEST block hash is evicted (the direction the fork
//!   choice's final tiebreak already disfavors) — fully deterministic.
//! * Checkpoint state: the local `(justified, finalized)` pair. Finality
//!   never regresses; a chain conflicting with the local finalized
//!   checkpoint is invalid regardless of work (ch01 §4.5).
//! * Reorg planning below finality: [`HeaderDag::plan_reorg`] emits the
//!   deterministic disconnect/connect block lists.

use std::collections::{BTreeMap, BTreeSet};

use noos_ground::{
    ground_work, DuplicateSet, GroundTicketV1, EXTRA_NONCE_BYTES, PROPOSER_PUBKEY_BYTES, U256,
};

use crate::fork::{u256_saturating_add, ForkScore};
use crate::header::{BlockHeaderV1, CheckpointRef, HeaderError, EPOCH_LENGTH, ZERO_ROOT};

/// Default orphan-pool capacity.
pub const DEFAULT_ORPHAN_CAPACITY: usize = 1024;

/// The duplicate-exclusion key of ch01 §4.2 rule 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TicketTuple {
    pub proposer_pubkey: [u8; PROPOSER_PUBKEY_BYTES],
    pub nonce: u64,
    pub extra_nonce: [u8; EXTRA_NONCE_BYTES],
}

/// A connected, structurally validated header.
#[derive(Clone, Debug)]
pub struct StoredHeader {
    pub header: BlockHeaderV1,
    pub hash: [u8; 32],
    /// Normalized proposal work of THIS block: `G(b) + L(b)` with `L = 0`
    /// while `work_loom_credit_enabled = false` (plan §6.3-6.4).
    pub work: U256,
    /// Rule-8 duplicate-scan key.
    pub ticket: TicketTuple,
}

#[derive(Clone, Debug)]
struct OrphanEntry {
    header: BlockHeaderV1,
    ticket: GroundTicketV1,
}

/// Result of [`HeaderDag::insert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Connected to the DAG; `connected_orphans` lists formerly orphaned
    /// descendants connected in the same call, in connection order.
    Inserted {
        hash: [u8; 32],
        connected_orphans: Vec<[u8; 32]>,
    },
    /// Parent unknown; pooled (or deterministically evicted when
    /// `retained == false`).
    Orphaned { hash: [u8; 32], retained: bool },
}

/// DAG-layer failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DagError {
    /// Structural header violation (chain id, ground profile, Loom zero,
    /// checkpoint sanity).
    Header(HeaderError),
    /// Registered-domain hashing failed: build defect, never a data error.
    Crypto,
    /// Block hash already known (connected or orphaned).
    DuplicateBlock,
    /// Referenced block is not in the store.
    UnknownBlock,
    /// `height != parent.height + 1`.
    BadHeight { got: u64, expected: u64 },
    /// `slot < parent.slot` (ch01 §4.2 rule 6 lower bound).
    SlotRegression,
    /// Child claims a lower justified/finalized checkpoint epoch than its
    /// parent: checkpoint views only grow along a chain.
    CheckpointRegression,
    /// Ticket `profile_id` differs from the header's `ground_profile_id`.
    TicketProfileMismatch,
    /// `(proposer_pubkey, nonce, extra_nonce)` already appears in an
    /// ancestor above the local finalized checkpoint (ch01 §4.2 rule 8).
    DuplicateTicketTuple,
    /// Block does not descend from the local finalized checkpoint
    /// (ch01 §4.5: invalid regardless of work).
    ConflictsWithFinality,
    /// Checkpoint height is not `epoch * 256` (ch01 §4.1).
    NotACheckpointHeight,
    /// Finalized/justified checkpoint may never move backwards or sideways.
    FinalityRegression,
    /// A reorg plan would disconnect a finalized block.
    ReorgAcrossFinality,
}

impl core::fmt::Display for DagError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DagError::Header(e) => write!(f, "header: {e}"),
            DagError::Crypto => f.write_str("domain registry misuse (build defect)"),
            DagError::DuplicateBlock => f.write_str("duplicate block hash"),
            DagError::UnknownBlock => f.write_str("unknown block"),
            DagError::BadHeight { got, expected } => {
                write!(f, "bad height {got} (expected {expected})")
            }
            DagError::SlotRegression => f.write_str("slot below parent slot"),
            DagError::CheckpointRegression => f.write_str("checkpoint view regresses below parent"),
            DagError::TicketProfileMismatch => {
                f.write_str("ticket profile_id differs from header ground_profile_id")
            }
            DagError::DuplicateTicketTuple => {
                f.write_str("duplicate (proposer, nonce, extra_nonce) above finalized checkpoint")
            }
            DagError::ConflictsWithFinality => {
                f.write_str("chain conflicts with the local finalized checkpoint")
            }
            DagError::NotACheckpointHeight => f.write_str("height is not epoch * 256"),
            DagError::FinalityRegression => f.write_str("checkpoint regression"),
            DagError::ReorgAcrossFinality => {
                f.write_str("reorg plan would disconnect a finalized block")
            }
        }
    }
}

impl std::error::Error for DagError {}

impl From<HeaderError> for DagError {
    fn from(e: HeaderError) -> Self {
        DagError::Header(e)
    }
}

/// Deterministic in-memory header DAG with checkpoint state.
#[derive(Clone, Debug)]
pub struct HeaderDag {
    chain_id: [u8; 32],
    headers: BTreeMap<[u8; 32], StoredHeader>,
    children: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    by_height: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    by_slot: BTreeMap<u64, BTreeSet<[u8; 32]>>,
    orphans: BTreeMap<[u8; 32], OrphanEntry>,
    orphans_by_parent: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    orphan_capacity: usize,
    genesis_hash: [u8; 32],
    justified: CheckpointRef,
    finalized: CheckpointRef,
}

impl HeaderDag {
    /// Roots the DAG at a genesis header (height 0, zero parent hash).
    /// The genesis block is checkpoint epoch 0, immediately justified and
    /// finalized.
    ///
    /// # Errors
    /// Structural violations of the genesis header, [`DagError`].
    pub fn new(
        genesis: BlockHeaderV1,
        genesis_ticket: &GroundTicketV1,
        orphan_capacity: usize,
    ) -> Result<Self, DagError> {
        genesis.validate_structure(&genesis.chain_id, false)?;
        if genesis.height != 0 || genesis.parent_hash != ZERO_ROOT {
            return Err(DagError::BadHeight {
                got: genesis.height,
                expected: 0,
            });
        }
        let hash = genesis.block_hash().map_err(|_| DagError::Crypto)?;
        let hash = *hash.as_bytes();
        let checkpoint = CheckpointRef {
            epoch: 0,
            checkpoint_hash: hash,
        };
        let stored = StoredHeader {
            work: ground_work(&genesis.ground_target_u256()),
            ticket: TicketTuple {
                proposer_pubkey: genesis.proposer_key.0,
                nonce: genesis_ticket.nonce,
                extra_nonce: genesis_ticket.extra_nonce,
            },
            hash,
            header: genesis,
        };
        let mut dag = HeaderDag {
            chain_id: stored.header.chain_id,
            headers: BTreeMap::new(),
            children: BTreeMap::new(),
            by_height: BTreeMap::new(),
            by_slot: BTreeMap::new(),
            orphans: BTreeMap::new(),
            orphans_by_parent: BTreeMap::new(),
            orphan_capacity,
            genesis_hash: hash,
            justified: checkpoint,
            finalized: checkpoint,
        };
        dag.index(stored);
        Ok(dag)
    }

    fn index(&mut self, stored: StoredHeader) {
        self.by_height
            .entry(stored.header.height)
            .or_default()
            .insert(stored.hash);
        self.by_slot
            .entry(stored.header.slot)
            .or_default()
            .insert(stored.hash);
        self.children
            .entry(stored.header.parent_hash)
            .or_default()
            .insert(stored.hash);
        self.headers.insert(stored.hash, stored);
    }

    // -- queries ------------------------------------------------------------

    #[must_use]
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    #[must_use]
    pub fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    #[must_use]
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.headers.contains_key(hash)
    }

    #[must_use]
    pub fn get(&self, hash: &[u8; 32]) -> Option<&StoredHeader> {
        self.headers.get(hash)
    }

    #[must_use]
    pub fn justified(&self) -> CheckpointRef {
        self.justified
    }

    #[must_use]
    pub fn finalized(&self) -> CheckpointRef {
        self.finalized
    }

    /// Connected block hashes at `height`, ascending by hash.
    pub fn hashes_at_height(&self, height: u64) -> impl Iterator<Item = &[u8; 32]> {
        self.by_height.get(&height).into_iter().flatten()
    }

    /// Connected block hashes at `slot`, ascending by hash.
    pub fn hashes_at_slot(&self, slot: u64) -> impl Iterator<Item = &[u8; 32]> {
        self.by_slot.get(&slot).into_iter().flatten()
    }

    /// Ancestor walk starting AT `from` (inclusive), ending at genesis.
    /// Empty iterator when `from` is unknown.
    pub fn ancestors<'a>(&'a self, from: &[u8; 32]) -> AncestorIter<'a> {
        AncestorIter {
            dag: self,
            next: self.headers.get(from).map(|s| s.hash),
        }
    }

    /// The ancestor of `from` (inclusive) at exactly `height`.
    #[must_use]
    pub fn ancestor_at_height(&self, from: &[u8; 32], height: u64) -> Option<&StoredHeader> {
        self.ancestors(from).find(|s| s.header.height == height)
    }

    /// Most recent `n` timestamps on the chain ending at `from` (inclusive),
    /// newest first — the median-time-past window feed for
    /// `noos_ground::median_time_past_ms`.
    #[must_use]
    pub fn parent_timestamps(&self, from: &[u8; 32], n: usize) -> Vec<u64> {
        self.ancestors(from)
            .take(n)
            .map(|s| s.header.timestamp_ms)
            .collect()
    }

    /// Tips: connected headers with no connected children, descending from
    /// the local finalized checkpoint (or the checkpoint block itself),
    /// ascending by hash.
    #[must_use]
    pub fn tips(&self) -> Vec<[u8; 32]> {
        self.headers
            .values()
            .filter(|s| !self.children.contains_key(&s.hash))
            .filter(|s| self.descends_from_finalized(&s.hash))
            .map(|s| s.hash)
            .collect()
    }

    fn finalized_height(&self) -> u64 {
        // Alignment was enforced when the checkpoint was set (genesis epoch
        // is 0), so the multiplication cannot overflow.
        self.finalized.epoch.saturating_mul(EPOCH_LENGTH)
    }

    /// True when `hash` is the finalized checkpoint block or one of its
    /// descendants.
    #[must_use]
    pub fn descends_from_finalized(&self, hash: &[u8; 32]) -> bool {
        let Some(stored) = self.headers.get(hash) else {
            return false;
        };
        if stored.header.height < self.finalized_height() {
            return false;
        }
        self.ancestor_at_height(hash, self.finalized_height())
            .is_some_and(|a| a.hash == self.finalized.checkpoint_hash)
    }

    // -- duplicate-ticket scan (ch01 §4.2 rule 8) ----------------------------

    /// True when `tuple` appears on the ancestor path of `parent`
    /// (inclusive) strictly ABOVE the local finalized checkpoint block.
    /// The window therefore resets whenever finality advances.
    #[must_use]
    pub fn tuple_seen_above_finalized(&self, parent: &[u8; 32], tuple: &TicketTuple) -> bool {
        for anc in self.ancestors(parent) {
            if anc.hash == self.finalized.checkpoint_hash {
                return false;
            }
            if anc.ticket == *tuple {
                return true;
            }
        }
        false
    }

    /// [`DuplicateSet`] view over the ancestors of `parent`, for composing
    /// `noos_ground::validate_ticket`.
    #[must_use]
    pub fn duplicate_scan<'a>(&'a self, parent: &[u8; 32]) -> AncestorTicketScan<'a> {
        AncestorTicketScan {
            dag: self,
            parent: *parent,
        }
    }

    // -- insertion ------------------------------------------------------------

    /// Inserts a structurally validated header and its Ground ticket.
    ///
    /// Checks, in order: structural header law
    /// ([`BlockHeaderV1::validate_structure`], with the Loom lane disabled),
    /// ticket/header profile agreement, duplicate block hash, parent
    /// presence (else the bounded orphan pool), height/slot linkage,
    /// checkpoint-view monotonicity, descent from the local finalized
    /// checkpoint, and the rule-8 duplicate-tuple window. The FULL Ground
    /// law (challenge/digest/target/timestamp) is `noos_ground::
    /// validate_ticket`, composed by the consensus layer with
    /// [`HeaderDag::duplicate_scan`]; this store never re-derives Pulse
    /// context.
    ///
    /// # Errors
    /// First violated rule as a [`DagError`].
    pub fn insert(
        &mut self,
        header: BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<InsertOutcome, DagError> {
        header.validate_structure(&self.chain_id, false)?;
        if ticket.profile_id != header.ground_profile_id {
            return Err(DagError::TicketProfileMismatch);
        }
        let hash = *header
            .block_hash()
            .map_err(|_| DagError::Crypto)?
            .as_bytes();
        if self.headers.contains_key(&hash) || self.orphans.contains_key(&hash) {
            return Err(DagError::DuplicateBlock);
        }
        if !self.headers.contains_key(&header.parent_hash) {
            let retained = self.pool_orphan(hash, header, ticket);
            return Ok(InsertOutcome::Orphaned { hash, retained });
        }
        self.connect(hash, header, ticket)?;
        let connected_orphans = self.connect_orphans(hash);
        Ok(InsertOutcome::Inserted {
            hash,
            connected_orphans,
        })
    }

    fn connect(
        &mut self,
        hash: [u8; 32],
        header: BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> Result<(), DagError> {
        let parent = self
            .headers
            .get(&header.parent_hash)
            .ok_or(DagError::UnknownBlock)?;
        let expected = parent
            .header
            .height
            .checked_add(1)
            .ok_or(DagError::BadHeight {
                got: header.height,
                expected: u64::MAX,
            })?;
        if header.height != expected {
            return Err(DagError::BadHeight {
                got: header.height,
                expected,
            });
        }
        if header.slot < parent.header.slot {
            return Err(DagError::SlotRegression);
        }
        if header.justified_checkpoint.epoch < parent.header.justified_checkpoint.epoch
            || header.finalized_checkpoint.epoch < parent.header.finalized_checkpoint.epoch
        {
            return Err(DagError::CheckpointRegression);
        }
        // ch01 §4.5: a chain conflicting with the local finalized
        // checkpoint is invalid regardless of work. The parent is connected,
        // so it suffices to check the parent's descent.
        if header.height > self.finalized_height()
            && !self.descends_from_finalized(&header.parent_hash)
        {
            return Err(DagError::ConflictsWithFinality);
        }
        let tuple = TicketTuple {
            proposer_pubkey: header.proposer_key.0,
            nonce: ticket.nonce,
            extra_nonce: ticket.extra_nonce,
        };
        if self.tuple_seen_above_finalized(&header.parent_hash, &tuple) {
            return Err(DagError::DuplicateTicketTuple);
        }
        let work = ground_work(&header.ground_target_u256());
        self.index(StoredHeader {
            header,
            hash,
            work,
            ticket: tuple,
        });
        Ok(())
    }

    /// Pools an orphan; at capacity evicts the numerically largest block
    /// hash (which may be the incoming orphan itself). Deterministic.
    fn pool_orphan(
        &mut self,
        hash: [u8; 32],
        header: BlockHeaderV1,
        ticket: &GroundTicketV1,
    ) -> bool {
        if self.orphans.len() >= self.orphan_capacity {
            let largest = match self.orphans.keys().next_back() {
                Some(k) => *k,
                None => return false, // capacity 0: nothing pooled
            };
            if hash >= largest {
                return false;
            }
            self.remove_orphan(&largest);
        }
        self.orphans_by_parent
            .entry(header.parent_hash)
            .or_default()
            .insert(hash);
        self.orphans.insert(
            hash,
            OrphanEntry {
                header,
                ticket: *ticket,
            },
        );
        true
    }

    fn remove_orphan(&mut self, hash: &[u8; 32]) -> Option<OrphanEntry> {
        let entry = self.orphans.remove(hash)?;
        if let Some(set) = self.orphans_by_parent.get_mut(&entry.header.parent_hash) {
            set.remove(hash);
            if set.is_empty() {
                self.orphans_by_parent.remove(&entry.header.parent_hash);
            }
        }
        Some(entry)
    }

    /// Connects every pooled orphan now reachable from `root`, walking the
    /// awaiting sets in deterministic order (per-parent ascending hash).
    /// Orphans that fail connection rules are dropped (their proposer can
    /// resubmit; the pool is a cache, not a promise).
    fn connect_orphans(&mut self, root: [u8; 32]) -> Vec<[u8; 32]> {
        let mut connected = Vec::new();
        let mut queue: Vec<[u8; 32]> = vec![root];
        while let Some(parent) = queue.pop() {
            let Some(waiting) = self.orphans_by_parent.get(&parent).cloned() else {
                continue;
            };
            for child_hash in waiting {
                let Some(entry) = self.remove_orphan(&child_hash) else {
                    continue;
                };
                if self
                    .connect(child_hash, entry.header, &entry.ticket)
                    .is_ok()
                {
                    connected.push(child_hash);
                    queue.push(child_hash);
                }
            }
        }
        connected
    }

    // -- checkpoints ----------------------------------------------------------

    /// Advances the local justified checkpoint. The block must be connected,
    /// at height `epoch * 256`, descend from the finalized checkpoint, and
    /// not regress.
    ///
    /// # Errors
    /// [`DagError`] naming the violated rule.
    pub fn set_justified(&mut self, checkpoint: CheckpointRef) -> Result<(), DagError> {
        if checkpoint.epoch < self.justified.epoch
            || (checkpoint.epoch == self.justified.epoch
                && checkpoint.checkpoint_hash != self.justified.checkpoint_hash)
        {
            return Err(DagError::FinalityRegression);
        }
        self.check_checkpoint(&checkpoint)?;
        self.justified = checkpoint;
        Ok(())
    }

    /// Advances the local finalized checkpoint (never reverted by work,
    /// plan §6.4). The block must be connected, at height `epoch * 256`,
    /// descend from the current finalized checkpoint, and not regress.
    /// Justification is pulled up to at least the new finalized checkpoint.
    ///
    /// # Errors
    /// [`DagError`] naming the violated rule.
    pub fn set_finalized(&mut self, checkpoint: CheckpointRef) -> Result<(), DagError> {
        if checkpoint.epoch < self.finalized.epoch
            || (checkpoint.epoch == self.finalized.epoch
                && checkpoint.checkpoint_hash != self.finalized.checkpoint_hash)
        {
            return Err(DagError::FinalityRegression);
        }
        self.check_checkpoint(&checkpoint)?;
        self.finalized = checkpoint;
        if self.justified.epoch < checkpoint.epoch {
            self.justified = checkpoint;
        }
        Ok(())
    }

    fn check_checkpoint(&self, checkpoint: &CheckpointRef) -> Result<(), DagError> {
        let stored = self
            .headers
            .get(&checkpoint.checkpoint_hash)
            .ok_or(DagError::UnknownBlock)?;
        let expected = checkpoint
            .epoch
            .checked_mul(EPOCH_LENGTH)
            .ok_or(DagError::NotACheckpointHeight)?;
        if stored.header.height != expected {
            return Err(DagError::NotACheckpointHeight);
        }
        if !self.descends_from_finalized(&checkpoint.checkpoint_hash) {
            return Err(DagError::ConflictsWithFinality);
        }
        Ok(())
    }

    // -- fork choice -----------------------------------------------------------

    /// Fork score of a connected tip (plan §6.4; ch01 §4.5): the tip
    /// header's claimed finalized/justified checkpoint epochs, cumulative
    /// normalized `G+L` on the path strictly above the local finalized
    /// checkpoint (saturating at `U256::MAX`), and the block hash for the
    /// inverse final tiebreak.
    #[must_use]
    pub fn fork_score(&self, tip: &[u8; 32]) -> Option<ForkScore> {
        let stored = self.headers.get(tip)?;
        let mut work = U256::ZERO;
        for anc in self.ancestors(tip) {
            if anc.hash == self.finalized.checkpoint_hash {
                break;
            }
            work = u256_saturating_add(&work, &anc.work);
        }
        Some(ForkScore {
            finalized_epoch: stored.header.finalized_checkpoint.epoch,
            justified_epoch: stored.header.justified_checkpoint.epoch,
            work_since_finalized: work,
            block_hash: stored.hash,
        })
    }

    /// Selects the canonical head: the [`ForkScore`]-maximal tip among tips
    /// descending from the local finalized checkpoint. Deterministic; ties
    /// are impossible because block hashes are distinct.
    #[must_use]
    pub fn select_head(&self) -> Option<[u8; 32]> {
        let mut best: Option<ForkScore> = None;
        for tip in self.tips() {
            let Some(score) = self.fork_score(&tip) else {
                continue;
            };
            best = match best {
                None => Some(score),
                Some(cur) if score > cur => Some(score),
                Some(cur) => Some(cur),
            };
        }
        best.map(|s| s.block_hash)
    }

    // -- reorg planning ----------------------------------------------------------

    /// Deterministic rollback/replay plan from head `from` to head `to`:
    /// `disconnect` lists `from`-side blocks newest-first down to (exclusive)
    /// the common ancestor; `connect` lists `to`-side blocks oldest-first
    /// from just above the common ancestor. Both empty when `from == to`.
    ///
    /// # Errors
    /// [`DagError::UnknownBlock`] for an unconnected endpoint;
    /// [`DagError::ReorgAcrossFinality`] when the plan would disconnect the
    /// finalized checkpoint block or anything below it.
    pub fn plan_reorg(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<ReorgPlan, DagError> {
        let mut a = self.headers.get(from).ok_or(DagError::UnknownBlock)?;
        let mut b = self.headers.get(to).ok_or(DagError::UnknownBlock)?;
        let mut disconnect = Vec::new();
        let mut connect_rev = Vec::new();
        while a.header.height > b.header.height {
            disconnect.push(a.hash);
            a = self
                .headers
                .get(&a.header.parent_hash)
                .ok_or(DagError::UnknownBlock)?;
        }
        while b.header.height > a.header.height {
            connect_rev.push(b.hash);
            b = self
                .headers
                .get(&b.header.parent_hash)
                .ok_or(DagError::UnknownBlock)?;
        }
        while a.hash != b.hash {
            disconnect.push(a.hash);
            connect_rev.push(b.hash);
            if a.header.height == 0 {
                // Distinct roots cannot happen inside one rooted DAG.
                return Err(DagError::UnknownBlock);
            }
            a = self
                .headers
                .get(&a.header.parent_hash)
                .ok_or(DagError::UnknownBlock)?;
            b = self
                .headers
                .get(&b.header.parent_hash)
                .ok_or(DagError::UnknownBlock)?;
        }
        // `a` is now the common ancestor. Disconnecting at or below the
        // finalized checkpoint is prohibited (finality is irreversible).
        if a.header.height < self.finalized_height() || !self.descends_from_finalized(&a.hash) {
            return Err(DagError::ReorgAcrossFinality);
        }
        connect_rev.reverse();
        Ok(ReorgPlan {
            common_ancestor: a.hash,
            disconnect,
            connect: connect_rev,
        })
    }
}

/// Deterministic rollback/replay plan (ch01 §4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    pub common_ancestor: [u8; 32],
    /// Old-branch blocks to disconnect, newest first.
    pub disconnect: Vec<[u8; 32]>,
    /// New-branch blocks to connect, oldest first.
    pub connect: Vec<[u8; 32]>,
}

/// Ancestor iterator over connected headers (inclusive of the start).
pub struct AncestorIter<'a> {
    dag: &'a HeaderDag,
    next: Option<[u8; 32]>,
}

impl<'a> Iterator for AncestorIter<'a> {
    type Item = &'a StoredHeader;

    fn next(&mut self) -> Option<Self::Item> {
        let hash = self.next.take()?;
        let stored = self.dag.headers.get(&hash)?;
        if stored.header.height > 0 {
            self.next = Some(stored.header.parent_hash);
        }
        Some(stored)
    }
}

/// [`DuplicateSet`] over the post-finalized ancestors of a prospective
/// block's parent — plugs the DAG into `noos_ground::validate_ticket`
/// rule 8.
pub struct AncestorTicketScan<'a> {
    dag: &'a HeaderDag,
    parent: [u8; 32],
}

impl DuplicateSet for AncestorTicketScan<'_> {
    fn contains(
        &self,
        proposer_pubkey: &[u8; PROPOSER_PUBKEY_BYTES],
        nonce: u64,
        extra_nonce: &[u8; EXTRA_NONCE_BYTES],
    ) -> bool {
        self.dag.tuple_seen_above_finalized(
            &self.parent,
            &TicketTuple {
                proposer_pubkey: *proposer_pubkey,
                nonce,
                extra_nonce: *extra_nonce,
            },
        )
    }
}
