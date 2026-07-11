//! Bounded RPC chain view with retention pruning (node-v1.md §8).
//!
//! The Ascent chain-view retention pruning is a recorded INHERITED DEFECT
//! (`chain_view_small_retention_prunes_maps_and_keeps_live_state`: a
//! terminal object survived in the `objects` map under small retention).
//! This re-implementation makes eviction a single-pass law over settlement
//! heights and is proven by
//! `tests::retention_prunes_terminal_records_and_keeps_live_state`:
//!
//! * every per-block map (`blocks`, and each block's txid list) is bounded
//!   by the retention window;
//! * a TERMINAL record (settled at a height below the horizon) is ALWAYS
//!   evicted — the exact arm that failed in Ascent;
//! * LIVE records (pending transactions) are never evicted by retention;
//! * pruned identities stay answerable as `Pruned` (never a silent
//!   `NotFound`) through bounded marker sets.
//!
//! `retention_blocks = 0` keeps full presentation history (archive mode).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use noos_braid::{BlockHeaderV1, CheckpointRef};
use noos_lumen::objects::ReceiptV1;

use crate::Hash32;

/// Bounded FIFO marker set: remembers up to `cap` identities.
#[derive(Debug, Clone, Default)]
pub struct MarkerSet {
    cap: usize,
    order: VecDeque<Hash32>,
    set: BTreeSet<Hash32>,
}

impl MarkerSet {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        MarkerSet {
            cap,
            order: VecDeque::new(),
            set: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, id: Hash32) {
        if self.cap == 0 || !self.set.insert(id) {
            return;
        }
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }

    #[must_use]
    pub fn contains(&self, id: &Hash32) -> bool {
        self.set.contains(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Presentation summary of one connected block.
#[derive(Debug, Clone)]
pub struct BlockSummary {
    pub hash: Hash32,
    pub height: u64,
    pub slot: u64,
    pub timestamp_ms: u64,
    pub parent_hash: Hash32,
    pub txids: Vec<Hash32>,
}

/// Transaction presentation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    /// In the mempool (live: retention never evicts it).
    Pending,
    /// Settled in a connected block (terminal once below the horizon).
    /// `status` is the receipt status code (0 = success).
    Settled { height: u64, status: u16 },
}

/// Lookup outcome distinguishing retention pruning from absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewLookup<T> {
    Found(T),
    /// Was known, evicted by the retention horizon (explicit, never a
    /// silent NotFound).
    Pruned,
    NotFound,
}

/// The three head pointers, always reported SEPARATELY (never a merged
/// "latest" — plan §13.3 law applied to the operator RPC).
#[derive(Debug, Clone, Copy, Default)]
pub struct Heads {
    pub unsafe_head_height: u64,
    pub unsafe_head_hash: Hash32,
    pub justified: CheckpointRef,
    pub finalized: CheckpointRef,
}

/// Bounded chain view feeding the operator RPC.
#[derive(Debug, Default)]
pub struct ChainView {
    retention_blocks: u64,
    pruned_before_height: u64,
    blocks: BTreeMap<u64, BlockSummary>,
    by_hash: BTreeMap<Hash32, u64>,
    tx_records: BTreeMap<Hash32, TxStatus>,
    receipts: BTreeMap<Hash32, ReceiptV1>,
    pruned_blocks: MarkerSet,
    pruned_txs: MarkerSet,
    pub heads: Heads,
}

impl ChainView {
    #[must_use]
    pub fn new(retention_blocks: u64) -> Self {
        ChainView {
            retention_blocks,
            pruned_before_height: 0,
            blocks: BTreeMap::new(),
            by_hash: BTreeMap::new(),
            tx_records: BTreeMap::new(),
            receipts: BTreeMap::new(),
            pruned_blocks: MarkerSet::new(65_536),
            pruned_txs: MarkerSet::new(262_144),
            heads: Heads::default(),
        }
    }

    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn tx_record_count(&self) -> usize {
        self.tx_records.len()
    }

    #[must_use]
    pub fn pruned_before_height(&self) -> u64 {
        self.pruned_before_height
    }

    /// Records a pending (mempool) transaction.
    pub fn note_pending(&mut self, txid: Hash32) {
        self.tx_records.entry(txid).or_insert(TxStatus::Pending);
    }

    /// Drops a pending record (mempool rejection/eviction) if still pending.
    pub fn drop_pending(&mut self, txid: &Hash32) {
        if self.tx_records.get(txid) == Some(&TxStatus::Pending) {
            self.tx_records.remove(txid);
        }
    }

    /// Records a connected block and its settled receipts, then applies the
    /// retention law.
    pub fn connect_block(&mut self, header: &BlockHeaderV1, hash: Hash32, receipts: &[ReceiptV1]) {
        let txids: Vec<Hash32> = receipts.iter().map(|r| r.txid).collect();
        for r in receipts {
            self.tx_records.insert(
                r.txid,
                TxStatus::Settled {
                    height: header.height,
                    status: r.status,
                },
            );
            self.receipts.insert(r.txid, r.clone());
        }
        self.by_hash.insert(hash, header.height);
        self.blocks.insert(
            header.height,
            BlockSummary {
                hash,
                height: header.height,
                slot: header.slot,
                timestamp_ms: header.timestamp_ms,
                parent_hash: header.parent_hash,
                txids,
            },
        );
        self.heads.unsafe_head_height = header.height;
        self.heads.unsafe_head_hash = hash;
        self.evict(header.height);
    }

    /// Disconnects a block during a reorg: its settled records revert to
    /// pending (their transactions may re-enter the mempool).
    pub fn disconnect_block(&mut self, height: u64) {
        if let Some(summary) = self.blocks.remove(&height) {
            self.by_hash.remove(&summary.hash);
            for txid in summary.txids {
                self.tx_records.insert(txid, TxStatus::Pending);
                self.receipts.remove(&txid);
            }
        }
    }

    /// The retention law. Single pass, driven by settlement heights:
    /// everything terminal below the horizon is evicted and marked; live
    /// (pending) records are untouchable.
    fn evict(&mut self, tip_height: u64) {
        if self.retention_blocks == 0 {
            return;
        }
        let prune_before = tip_height.saturating_sub(self.retention_blocks);
        self.pruned_before_height = self.pruned_before_height.max(prune_before);

        let evict_heights: Vec<u64> = self.blocks.range(..prune_before).map(|(h, _)| *h).collect();
        for h in evict_heights {
            if let Some(summary) = self.blocks.remove(&h) {
                self.by_hash.remove(&summary.hash);
                self.pruned_blocks.insert(summary.hash);
                for txid in summary.txids {
                    // TERMINAL eviction arm (the Ascent defect): a record
                    // settled below the horizon MUST leave the maps.
                    if matches!(self.tx_records.get(&txid), Some(TxStatus::Settled { .. })) {
                        self.tx_records.remove(&txid);
                        self.receipts.remove(&txid);
                        self.pruned_txs.insert(txid);
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn block_by_height(&self, height: u64) -> ViewLookup<&BlockSummary> {
        match self.blocks.get(&height) {
            Some(b) => ViewLookup::Found(b),
            None if height < self.pruned_before_height => ViewLookup::Pruned,
            None => ViewLookup::NotFound,
        }
    }

    #[must_use]
    pub fn block_by_hash(&self, hash: &Hash32) -> ViewLookup<&BlockSummary> {
        if let Some(h) = self.by_hash.get(hash) {
            if let Some(b) = self.blocks.get(h) {
                return ViewLookup::Found(b);
            }
        }
        if self.pruned_blocks.contains(hash) {
            ViewLookup::Pruned
        } else {
            ViewLookup::NotFound
        }
    }

    #[must_use]
    pub fn tx_status(&self, txid: &Hash32) -> ViewLookup<TxStatus> {
        match self.tx_records.get(txid) {
            Some(s) => ViewLookup::Found(*s),
            None if self.pruned_txs.contains(txid) => ViewLookup::Pruned,
            None => ViewLookup::NotFound,
        }
    }

    #[must_use]
    pub fn receipt(&self, txid: &Hash32) -> ViewLookup<&ReceiptV1> {
        match self.receipts.get(txid) {
            Some(r) => ViewLookup::Found(r),
            None if self.pruned_txs.contains(txid) => ViewLookup::Pruned,
            None => ViewLookup::NotFound,
        }
    }
}
