//! Versioned depth-256 sparse Merkle tree (plan §4.2, arch §6.1).
//!
//! Law (frozen in `protocol/schemas/lumen-v1.md` §2):
//! - Keys are exactly 32 bytes. Bit `d` of a key (`d` in `0..256`, depth from
//!   the root) is `(key[d / 8] >> (7 - d % 8)) & 1`; bit 0 selects the left
//!   (`0`) or right (`1`) child of the root. Lexicographic key order therefore
//!   equals MSB-first path order.
//! - Leaf hash: `H("NOOS/SMT/LEAF/V1" || key || value)` (D-SMT-LEAF).
//! - Node hash: `H("NOOS/SMT/NODE/V1" || left || right)` (D-SMT-NODE).
//! - Empty roots are derived recursively: `E[0] = H("NOOS/SMT/LEAF/V1")`
//!   (context only — no key, no value), `E[h] = H(node_ctx || E[h-1] || E[h-1])`.
//!   `E[h]` is the root of an empty subtree of height `h`; the empty tree root
//!   is `E[256]`.
//! - A key is either absent or bound to a non-empty value record; inserting an
//!   existing key replaces its value (duplicate-key update). Zero-length
//!   values are permitted at this layer; higher layers define per-tree value
//!   canonicality.
//! - Roots are a pure function of the key→value map: insertion order never
//!   affects a root.
//!
//! Capacity: the key space is 2^256; practical capacity is bounded by the
//! per-tree collection maxima frozen in `lumen-v1.md`, never by this
//! structure.

use crate::objects::ReceiptV1;
use crate::{domain_hash, domains, Hash32};
use noos_codec::{CodecError, NoosDecode, NoosEncode, Reader, Writer};
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

/// Tree depth in bits (= key bits).
pub const DEPTH: usize = 256;
const PARALLEL_ROOT_MIN_LEAVES: usize = 512;
const ROOT_PREFIX_BITS: usize = 8;
const ROOT_PREFIX_BUCKETS: usize = 1 << ROOT_PREFIX_BITS;
const INCREMENTAL_PREFIX_BITS: usize = 24;
const INCREMENTAL_PREFIX_HEIGHT: usize = DEPTH - INCREMENTAL_PREFIX_BITS;
const PARALLEL_DIRTY_BUCKET_MIN: usize = 512;

/// `EMPTY_ROOTS[h]` = root of an empty subtree of height `h` (`0..=256`).
static EMPTY_ROOTS: LazyLock<[Hash32; DEPTH + 1]> = LazyLock::new(|| {
    let mut table = [[0u8; 32]; DEPTH + 1];
    table[0] = domain_hash(domains::SMT_LEAF, &[]);
    for h in 1..=DEPTH {
        let below = table[h - 1];
        table[h] = node_hash(&below, &below);
    }
    table
});

/// Root of an empty subtree of height `h` (`0..=256`). `empty_root(256)` is
/// the canonical root of every empty Lumen map.
#[must_use]
pub fn empty_root(height: usize) -> Hash32 {
    EMPTY_ROOTS[height]
}

/// Domain-separated leaf hash binding key and value.
#[must_use]
pub fn leaf_hash(key: &Hash32, value: &[u8]) -> Hash32 {
    domain_hash(domains::SMT_LEAF, &[key, value])
}

/// Domain-separated internal node hash. This is the byte-identical
/// single-buffer form of `domain_hash(SMT_NODE, [left, right])`; avoiding
/// three incremental hasher updates matters across millions of SMT nodes.
#[inline]
#[must_use]
pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut input = [0_u8; domains::SMT_NODE.len() + 64];
    let (context, hashes) = input.split_at_mut(domains::SMT_NODE.len());
    context.copy_from_slice(domains::SMT_NODE.as_bytes());
    let (left_bytes, right_bytes) = hashes.split_at_mut(32);
    left_bytes.copy_from_slice(left);
    right_bytes.copy_from_slice(right);
    *blake3::hash(&input).as_bytes()
}

/// Bit `d` of `key`, depth-from-root order (MSB-first within each byte).
// Structural index math only: every operand is bounded by `d < DEPTH`
// (0 <= d/8 < 32, 0 <= d%8 < 8), so overflow is impossible by construction.
// Value/state arithmetic elsewhere in this crate is checked.
#[allow(clippy::arithmetic_side_effects)]
#[inline]
#[must_use]
pub fn key_bit(key: &Hash32, d: usize) -> bool {
    debug_assert!(d < DEPTH);
    (key[d / 8] >> (7 - (d % 8))) & 1 == 1
}

// All index arithmetic is bounded by fixed 256-bucket arrays and slices
// returned by `chunks_mut`; the loop invariants make overflow impossible.
#[allow(clippy::arithmetic_side_effects)]
fn root_from_sorted_entries(entries: &[(&Hash32, &Vec<u8>)]) -> Hash32 {
    if entries.len() < PARALLEL_ROOT_MIN_LEAVES {
        return subtree_root(entries, 0);
    }

    // Split at a fixed byte boundary so each worker owns a disjoint,
    // lexicographically contiguous subtree. The 256 bucket roots are folded
    // back through the first eight levels in canonical left/right order.
    let mut ranges = [(0_usize, 0_usize); ROOT_PREFIX_BUCKETS];
    let mut cursor = 0_usize;
    for (prefix, range) in ranges.iter_mut().enumerate() {
        let start = cursor;
        while cursor < entries.len() && usize::from(entries[cursor].0[0]) == prefix {
            cursor += 1;
        }
        *range = (start, cursor);
    }
    debug_assert_eq!(cursor, entries.len());

    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(ROOT_PREFIX_BUCKETS);
    if workers == 1 {
        return subtree_root(entries, 0);
    }
    let chunk_size = ROOT_PREFIX_BUCKETS.div_ceil(workers);
    let mut roots = [[0_u8; 32]; ROOT_PREFIX_BUCKETS];
    std::thread::scope(|scope| {
        for (chunk_index, root_chunk) in roots.chunks_mut(chunk_size).enumerate() {
            let range_start = chunk_index * chunk_size;
            let ranges = &ranges;
            scope.spawn(move || {
                for (offset, root) in root_chunk.iter_mut().enumerate() {
                    let (lo, hi) = ranges[range_start + offset];
                    *root = subtree_root(&entries[lo..hi], ROOT_PREFIX_BITS);
                }
            });
        }
    });

    let mut width = ROOT_PREFIX_BUCKETS;
    while width > 1 {
        for index in 0..(width / 2) {
            roots[index] = node_hash(&roots[index * 2], &roots[index * 2 + 1]);
        }
        width /= 2;
    }
    roots[0]
}

#[derive(Debug, Clone, Default)]
struct IncrementalRootCache {
    bucket_roots: Arc<Vec<(u32, Hash32)>>,
    dirty_prefixes: Vec<u32>,
}

#[inline]
fn incremental_prefix(key: &Hash32) -> u32 {
    u32::from_be_bytes([0, key[0], key[1], key[2]])
}

fn incremental_prefix_bounds(prefix: u32) -> (Hash32, Hash32) {
    let bytes = prefix.to_be_bytes();
    let mut lower = [0_u8; 32];
    lower[..3].copy_from_slice(&bytes[1..]);
    let mut upper = [u8::MAX; 32];
    upper[..3].copy_from_slice(&bytes[1..]);
    (lower, upper)
}

#[allow(clippy::arithmetic_side_effects)]
fn single_entry_subtree_root(key: &Hash32, value: &[u8], depth: usize) -> Hash32 {
    let mut root = leaf_hash(key, value);
    for current_depth in (depth..DEPTH).rev() {
        let empty = empty_root(DEPTH - current_depth - 1);
        root = if key_bit(key, current_depth) {
            node_hash(&empty, &root)
        } else {
            node_hash(&root, &empty)
        };
    }
    root
}

fn incremental_bucket_root(leaves: &BTreeMap<Hash32, Vec<u8>>, prefix: u32) -> Hash32 {
    let (lower, upper) = incremental_prefix_bounds(prefix);
    let mut entries = leaves.range(lower..=upper);
    let Some(first) = entries.next() else {
        return empty_root(INCREMENTAL_PREFIX_HEIGHT);
    };
    let Some(second) = entries.next() else {
        return single_entry_subtree_root(first.0, first.1, INCREMENTAL_PREFIX_BITS);
    };
    let mut bucket = Vec::with_capacity(2);
    bucket.push((first.0, first.1));
    bucket.push((second.0, second.1));
    bucket.extend(entries);
    subtree_root(&bucket, INCREMENTAL_PREFIX_BITS)
}

#[allow(clippy::arithmetic_side_effects)]
fn recompute_dirty_buckets(
    leaves: &BTreeMap<Hash32, Vec<u8>>,
    dirty_prefixes: &[u32],
) -> Vec<(u32, Hash32)> {
    let mut roots = dirty_prefixes
        .iter()
        .map(|prefix| (*prefix, [0_u8; 32]))
        .collect::<Vec<_>>();
    if roots.len() < PARALLEL_DIRTY_BUCKET_MIN {
        for (prefix, root) in &mut roots {
            *root = incremental_bucket_root(leaves, *prefix);
        }
        return roots;
    }

    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .saturating_sub(2)
        .max(1)
        .min(roots.len());
    let chunk_size = roots.len().div_ceil(workers);
    std::thread::scope(|scope| {
        for chunk in roots.chunks_mut(chunk_size) {
            scope.spawn(move || {
                for (prefix, root) in chunk {
                    *root = incremental_bucket_root(leaves, *prefix);
                }
            });
        }
    });
    roots
}

#[allow(clippy::arithmetic_side_effects)]
fn incremental_prefix_bit(prefix: u32, depth: usize) -> bool {
    debug_assert!(depth < INCREMENTAL_PREFIX_BITS);
    (prefix >> (INCREMENTAL_PREFIX_BITS - depth - 1)) & 1 == 1
}

#[allow(clippy::arithmetic_side_effects)]
fn incremental_prefix_subtree(entries: &[(u32, Hash32)], depth: usize) -> Hash32 {
    if entries.is_empty() {
        return empty_root(DEPTH - depth);
    }
    if depth == INCREMENTAL_PREFIX_BITS {
        debug_assert_eq!(entries.len(), 1);
        return entries[0].1;
    }
    let split = entries.partition_point(|(prefix, _)| !incremental_prefix_bit(*prefix, depth));
    let left = incremental_prefix_subtree(&entries[..split], depth + 1);
    let right = incremental_prefix_subtree(&entries[split..], depth + 1);
    node_hash(&left, &right)
}

#[allow(clippy::arithmetic_side_effects)]
fn root_from_incremental_buckets(bucket_roots: &[(u32, Hash32)]) -> Hash32 {
    if bucket_roots.is_empty() {
        return empty_root(DEPTH);
    }
    if bucket_roots.len() < PARALLEL_ROOT_MIN_LEAVES {
        return incremental_prefix_subtree(bucket_roots, 0);
    }

    let mut ranges = [(0_usize, 0_usize); ROOT_PREFIX_BUCKETS];
    let mut cursor = 0_usize;
    for (prefix, range) in ranges.iter_mut().enumerate() {
        let start = cursor;
        while cursor < bucket_roots.len() && ((bucket_roots[cursor].0 >> 16) as usize) == prefix {
            cursor += 1;
        }
        *range = (start, cursor);
    }
    debug_assert_eq!(cursor, bucket_roots.len());

    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .saturating_sub(2)
        .max(1)
        .min(ROOT_PREFIX_BUCKETS);
    let chunk_size = ROOT_PREFIX_BUCKETS.div_ceil(workers);
    let mut roots = [[0_u8; 32]; ROOT_PREFIX_BUCKETS];
    std::thread::scope(|scope| {
        for (chunk_index, root_chunk) in roots.chunks_mut(chunk_size).enumerate() {
            let range_start = chunk_index * chunk_size;
            let ranges = &ranges;
            let bucket_roots = bucket_roots;
            scope.spawn(move || {
                for (offset, root) in root_chunk.iter_mut().enumerate() {
                    let (lo, hi) = ranges[range_start + offset];
                    *root = incremental_prefix_subtree(&bucket_roots[lo..hi], ROOT_PREFIX_BITS);
                }
            });
        }
    });
    let mut width = ROOT_PREFIX_BUCKETS;
    while width > 1 {
        for index in 0..(width / 2) {
            roots[index] = node_hash(&roots[index * 2], &roots[index * 2 + 1]);
        }
        width /= 2;
    }
    roots[0]
}

#[allow(clippy::arithmetic_side_effects)]
fn merge_incremental_buckets(
    current: &mut Vec<(u32, Hash32)>,
    updates: Vec<(u32, Hash32)>,
    empty_bucket: Hash32,
) {
    let existing = std::mem::take(current);
    let mut merged = Vec::with_capacity(existing.len().saturating_add(updates.len()));
    let mut old_index = 0_usize;
    let mut update_index = 0_usize;
    while old_index < existing.len() || update_index < updates.len() {
        match (existing.get(old_index), updates.get(update_index)) {
            (Some(old), Some(update)) if old.0 < update.0 => {
                merged.push(*old);
                old_index += 1;
            }
            (Some(old), Some(update)) if old.0 == update.0 => {
                if update.1 != empty_bucket {
                    merged.push(*update);
                }
                old_index += 1;
                update_index += 1;
            }
            (_, Some(update)) => {
                if update.1 != empty_bucket {
                    merged.push(*update);
                }
                update_index += 1;
            }
            (Some(old), None) => {
                merged.push(*old);
                old_index += 1;
            }
            (None, None) => break,
        }
    }
    *current = merged;
}

fn refresh_incremental_root(
    leaves: &BTreeMap<Hash32, Vec<u8>>,
    cache: &mut IncrementalRootCache,
) -> Hash32 {
    let mut dirty_prefixes = std::mem::take(&mut cache.dirty_prefixes);
    dirty_prefixes.sort_unstable();
    dirty_prefixes.dedup();
    let updates = recompute_dirty_buckets(leaves, &dirty_prefixes);
    let empty_bucket = empty_root(INCREMENTAL_PREFIX_HEIGHT);
    merge_incremental_buckets(
        Arc::make_mut(&mut cache.bucket_roots),
        updates,
        empty_bucket,
    );
    root_from_incremental_buckets(&cache.bucket_roots)
}

/// In-memory sparse Merkle tree. Deterministic: leaves live in a `BTreeMap`;
/// the root is a pure function of the map.
#[derive(Debug)]
pub struct Smt {
    leaves: Arc<BTreeMap<Hash32, Vec<u8>>>,
    cached_root: OnceLock<Hash32>,
    incremental_root: Mutex<IncrementalRootCache>,
}

impl Clone for Smt {
    fn clone(&self) -> Self {
        let cached_root = OnceLock::new();
        if let Some(root) = self.cached_root.get() {
            let _ = cached_root.set(*root);
        }
        let incremental_root = match self.incremental_root.lock() {
            Ok(cache) => cache.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Self {
            leaves: self.leaves.clone(),
            cached_root,
            incremental_root: Mutex::new(incremental_root),
        }
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Smt {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves
    }
}

impl Eq for Smt {}

impl Smt {
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaves: Arc::new(BTreeMap::new()),
            cached_root: OnceLock::new(),
            incremental_root: Mutex::new(IncrementalRootCache::default()),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    #[must_use]
    pub fn get(&self, key: &Hash32) -> Option<&[u8]> {
        self.leaves.get(key).map(Vec::as_slice)
    }

    #[must_use]
    pub fn contains(&self, key: &Hash32) -> bool {
        self.leaves.contains_key(key)
    }

    /// Insert or update (duplicate-key update semantics). Returns the prior
    /// value when the key already existed.
    pub fn insert(&mut self, key: Hash32, value: Vec<u8>) -> Option<Vec<u8>> {
        let previous = Arc::make_mut(&mut self.leaves).insert(key, value);
        let _ = self.cached_root.take();
        let cache = match self.incremental_root.get_mut() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.dirty_prefixes.push(incremental_prefix(&key));
        previous
    }

    /// Remove a key. Returns the prior value when present.
    pub fn remove(&mut self, key: &Hash32) -> Option<Vec<u8>> {
        let removed = Arc::make_mut(&mut self.leaves).remove(key);
        if removed.is_some() {
            let _ = self.cached_root.take();
            let cache = match self.incremental_root.get_mut() {
                Ok(cache) => cache,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.dirty_prefixes.push(incremental_prefix(key));
        }
        removed
    }

    /// Deterministic iteration in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.leaves.iter()
    }

    /// Current root. Pure function of the leaf map. Changed 24-bit subtrees
    /// are rehashed in parallel and unchanged subtree roots are reused; the
    /// canonical top fold remains byte-identical to the sequential definition.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        if let Some(root) = self.cached_root.get() {
            return *root;
        }
        let mut cache = match self.incremental_root.lock() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(root) = self.cached_root.get() {
            return *root;
        }
        let root = refresh_incremental_root(&self.leaves, &mut cache);
        let _ = self.cached_root.set(root);
        root
    }

    /// Merkle proof for `key` (inclusion when present, non-inclusion when
    /// absent). Siblings are recorded root→leaf; empty siblings are elided
    /// via the bitmap.
    // Index math bounded by DEPTH and by `lo <= split <= hi <= entries.len()`
    // (partition_point invariants); no value arithmetic.
    #[allow(clippy::arithmetic_side_effects)]
    #[must_use]
    pub fn prove(&self, key: &Hash32) -> SmtProof {
        let entries: Vec<(&Hash32, &Vec<u8>)> = self.leaves.iter().collect();
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        // Descend the key path, recording the off-path subtree root per depth.
        let mut path_slices: Vec<(usize, usize)> = Vec::with_capacity(DEPTH);
        let mut lo = 0usize;
        let mut hi = entries.len();
        for d in 0..DEPTH {
            let split = lo + entries[lo..hi].partition_point(|(k, _)| !key_bit(k, d));
            let (on_lo, on_hi, off_lo, off_hi) = if key_bit(key, d) {
                (split, hi, lo, split)
            } else {
                (lo, split, split, hi)
            };
            path_slices.push((off_lo, off_hi));
            lo = on_lo;
            hi = on_hi;
        }
        // Compute off-path sibling roots (height of sibling at depth d is
        // DEPTH - d - 1).
        for (d, (off_lo, off_hi)) in path_slices.iter().enumerate() {
            let sib = subtree_root(&entries[*off_lo..*off_hi], d + 1);
            let height = DEPTH - d - 1;
            if sib != empty_root(height) {
                bitmap[d / 8] |= 1 << (7 - (d % 8));
                siblings.push(sib);
            }
        }
        SmtProof { bitmap, siblings }
    }
}

const RECEIPT_VALUE_BYTES: usize = 108;

fn encode_receipt_value(receipt: &ReceiptV1) -> [u8; RECEIPT_VALUE_BYTES] {
    let mut bytes = [0_u8; RECEIPT_VALUE_BYTES];
    bytes[0..2].copy_from_slice(&ReceiptV1::VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
    bytes[4..36].copy_from_slice(&receipt.txid);
    bytes[36..38].copy_from_slice(&2_u16.to_le_bytes());
    bytes[38..40].copy_from_slice(&receipt.status.to_le_bytes());
    bytes[40..42].copy_from_slice(&3_u16.to_le_bytes());
    bytes[42..58].copy_from_slice(&receipt.fee_charged.to_le_bytes());
    bytes[58..60].copy_from_slice(&4_u16.to_le_bytes());
    bytes[60..68].copy_from_slice(&receipt.resources_used.bytes.to_le_bytes());
    bytes[68..76].copy_from_slice(&receipt.resources_used.grain_steps.to_le_bytes());
    bytes[76..84].copy_from_slice(&receipt.resources_used.proof_units.to_le_bytes());
    bytes[84..92].copy_from_slice(&receipt.resources_used.state_reads.to_le_bytes());
    bytes[92..100].copy_from_slice(&receipt.resources_used.state_writes.to_le_bytes());
    bytes[100..108].copy_from_slice(&receipt.resources_used.blob_bytes.to_le_bytes());
    bytes
}

fn receipt_subtree_root(entries: &[(&Hash32, [u8; RECEIPT_VALUE_BYTES])], depth: usize) -> Hash32 {
    if entries.is_empty() {
        return empty_root(DEPTH - depth);
    }
    if depth == DEPTH {
        debug_assert_eq!(entries.len(), 1, "duplicate 256-bit key is impossible");
        let (key, value) = &entries[0];
        return leaf_hash(key, value);
    }
    let split = entries.partition_point(|(key, _)| !key_bit(key, depth));
    let left = receipt_subtree_root(&entries[..split], depth + 1);
    let right = receipt_subtree_root(&entries[split..], depth + 1);
    node_hash(&left, &right)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SettledReceipt {
    receipt: ReceiptV1,
    height: u64,
}

type ReceiptBucket = SmallVec<[SettledReceipt; 1]>;

fn receipt_bucket_root(bucket: Option<&ReceiptBucket>) -> Hash32 {
    let Some(entries) = bucket else {
        return empty_root(INCREMENTAL_PREFIX_HEIGHT);
    };
    let Some(first) = entries.first() else {
        return empty_root(INCREMENTAL_PREFIX_HEIGHT);
    };
    if entries.len() == 1 {
        let value = encode_receipt_value(&first.receipt);
        return single_entry_subtree_root(&first.receipt.txid, &value, INCREMENTAL_PREFIX_BITS);
    }
    let encoded = entries
        .iter()
        .map(|entry| (&entry.receipt.txid, encode_receipt_value(&entry.receipt)))
        .collect::<Vec<_>>();
    receipt_subtree_root(&encoded, INCREMENTAL_PREFIX_BITS)
}

fn recompute_receipt_dirty_buckets(
    buckets: &HashMap<u32, ReceiptBucket>,
    dirty_prefixes: &[u32],
) -> Vec<(u32, Hash32)> {
    let mut roots = dirty_prefixes
        .iter()
        .map(|prefix| (*prefix, [0_u8; 32]))
        .collect::<Vec<_>>();
    if roots.len() < PARALLEL_DIRTY_BUCKET_MIN {
        for (prefix, root) in &mut roots {
            *root = receipt_bucket_root(buckets.get(prefix));
        }
        return roots;
    }

    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .saturating_sub(2)
        .max(1)
        .min(roots.len());
    let chunk_size = roots.len().div_ceil(workers);
    std::thread::scope(|scope| {
        for chunk in roots.chunks_mut(chunk_size) {
            scope.spawn(move || {
                for (prefix, root) in chunk {
                    *root = receipt_bucket_root(buckets.get(prefix));
                }
            });
        }
    });
    roots
}

fn refresh_receipt_incremental_root(
    buckets: &HashMap<u32, ReceiptBucket>,
    cache: &mut IncrementalRootCache,
) -> Hash32 {
    let mut dirty_prefixes = std::mem::take(&mut cache.dirty_prefixes);
    dirty_prefixes.sort_unstable();
    dirty_prefixes.dedup();
    let updates = recompute_receipt_dirty_buckets(buckets, &dirty_prefixes);
    merge_incremental_buckets(
        Arc::make_mut(&mut cache.bucket_roots),
        updates,
        empty_root(INCREMENTAL_PREFIX_HEIGHT),
    );
    root_from_incremental_buckets(&cache.bucket_roots)
}

/// Settled-receipt SMT grouped by the same 24-bit prefixes used by its
/// incremental Merkle cache. Txid lookup and insertion touch one hash bucket;
/// canonical ordering is confined to the normally single-entry prefix.
#[derive(Debug)]
pub struct ReceiptSmt {
    buckets: Arc<HashMap<u32, ReceiptBucket>>,
    cached_root: OnceLock<Hash32>,
    incremental_root: Mutex<IncrementalRootCache>,
}

impl Clone for ReceiptSmt {
    fn clone(&self) -> Self {
        let cached_root = OnceLock::new();
        if let Some(root) = self.cached_root.get() {
            let _ = cached_root.set(*root);
        }
        let incremental_root = match self.incremental_root.lock() {
            Ok(cache) => cache.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Self {
            buckets: self.buckets.clone(),
            cached_root,
            incremental_root: Mutex::new(incremental_root),
        }
    }
}

impl Default for ReceiptSmt {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for ReceiptSmt {
    fn eq(&self, other: &Self) -> bool {
        self.buckets == other.buckets
    }
}

impl Eq for ReceiptSmt {}

impl ReceiptSmt {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(HashMap::new()),
            cached_root: OnceLock::new(),
            incremental_root: Mutex::new(IncrementalRootCache::default()),
        }
    }

    #[must_use]
    pub fn get(&self, key: &Hash32) -> Option<&ReceiptV1> {
        let bucket = self.buckets.get(&incremental_prefix(key))?;
        let index = bucket
            .binary_search_by(|entry| entry.receipt.txid.cmp(key))
            .ok()?;
        bucket.get(index).map(|entry| &entry.receipt)
    }

    #[must_use]
    pub fn settlement(&self, key: &Hash32) -> Option<(u64, u16)> {
        let bucket = self.buckets.get(&incremental_prefix(key))?;
        let index = bucket
            .binary_search_by(|entry| entry.receipt.txid.cmp(key))
            .ok()?;
        bucket
            .get(index)
            .map(|entry| (entry.height, entry.receipt.status))
    }

    #[must_use]
    pub fn contains(&self, key: &Hash32) -> bool {
        self.get(key).is_some()
    }

    pub fn insert(&mut self, key: Hash32, value: ReceiptV1, height: u64) -> Option<ReceiptV1> {
        debug_assert_eq!(key, value.txid);
        let prefix = incremental_prefix(&key);
        let bucket = Arc::make_mut(&mut self.buckets).entry(prefix).or_default();
        let value = SettledReceipt {
            receipt: value,
            height,
        };
        let previous = match bucket.binary_search_by(|entry| entry.receipt.txid.cmp(&key)) {
            Ok(index) => Some(std::mem::replace(&mut bucket[index], value).receipt),
            Err(index) => {
                bucket.insert(index, value);
                None
            }
        };
        let _ = self.cached_root.take();
        let cache = match self.incremental_root.get_mut() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.dirty_prefixes.push(prefix);
        previous
    }

    pub fn remove(&mut self, key: &Hash32) -> Option<ReceiptV1> {
        let prefix = incremental_prefix(key);
        let buckets = Arc::make_mut(&mut self.buckets);
        let (removed, empty) = {
            let bucket = buckets.get_mut(&prefix)?;
            let index = bucket
                .binary_search_by(|entry| entry.receipt.txid.cmp(key))
                .ok()?;
            let removed = bucket.remove(index);
            (removed, bucket.is_empty())
        };
        if empty {
            buckets.remove(&prefix);
        }
        let _ = self.cached_root.take();
        let cache = match self.incremental_root.get_mut() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.dirty_prefixes.push(prefix);
        Some(removed.receipt)
    }

    pub(crate) fn remove_if_settled_after(
        &mut self,
        key: &Hash32,
        settled_height: u64,
    ) -> Option<ReceiptV1> {
        self.settlement(key)
            .is_some_and(|(height, _)| height > settled_height)
            .then(|| self.remove(key))
            .flatten()
    }

    #[must_use]
    pub fn root(&self) -> Hash32 {
        if let Some(root) = self.cached_root.get() {
            return *root;
        }
        let mut cache = match self.incremental_root.lock() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(root) = self.cached_root.get() {
            return *root;
        }
        let root = refresh_receipt_incremental_root(&self.buckets, &mut cache);
        let _ = self.cached_root.set(root);
        root
    }
}

// Recursion depth bounded by DEPTH; `split <= entries.len()`.
#[allow(clippy::arithmetic_side_effects)]
/// Root of the subtree at `depth` containing exactly the given sorted
/// entries (whose keys all share the first `depth` path bits).
fn subtree_root(entries: &[(&Hash32, &Vec<u8>)], depth: usize) -> Hash32 {
    if entries.is_empty() {
        return empty_root(DEPTH - depth);
    }
    if depth == DEPTH {
        debug_assert_eq!(entries.len(), 1, "duplicate 256-bit key is impossible");
        let (k, v) = entries[0];
        return leaf_hash(k, v);
    }
    let split = entries.partition_point(|(k, _)| !key_bit(k, depth));
    let left = subtree_root(&entries[..split], depth + 1);
    let right = subtree_root(&entries[split..], depth + 1);
    node_hash(&left, &right)
}

/// Compact Merkle proof: 256-bit presence bitmap (bit `d`, MSB-first, set =
/// the sibling at depth `d` is non-empty and carried explicitly) plus the
/// non-empty siblings in root→leaf order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtProof {
    pub bitmap: [u8; 32],
    pub siblings: Vec<Hash32>,
}

impl SmtProof {
    pub const VERSION: u16 = 1;

    /// Number of set bits in the bitmap.
    #[must_use]
    fn bitmap_count(&self) -> usize {
        self.bitmap.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Fold the proof from a leaf digest up to a candidate root.
    // Index math bounded by `d < DEPTH`; sibling cursor uses checked_sub.
    #[allow(clippy::arithmetic_side_effects)]
    #[must_use]
    fn fold(&self, key: &Hash32, leaf: Hash32) -> Option<Hash32> {
        if self.bitmap_count() != self.siblings.len() {
            return None;
        }
        let mut acc = leaf;
        let mut next_sibling = self.siblings.len();
        for d in (0..DEPTH).rev() {
            let sib = if self.bitmap[d / 8] >> (7 - (d % 8)) & 1 == 1 {
                next_sibling = next_sibling.checked_sub(1)?;
                self.siblings[next_sibling]
            } else {
                empty_root(DEPTH - d - 1)
            };
            acc = if key_bit(key, d) {
                node_hash(&sib, &acc)
            } else {
                node_hash(&acc, &sib)
            };
        }
        if next_sibling != 0 {
            return None;
        }
        Some(acc)
    }

    /// Verify that `key` maps to `value` under `root`.
    #[must_use]
    pub fn verify_inclusion(&self, root: &Hash32, key: &Hash32, value: &[u8]) -> bool {
        self.fold(key, leaf_hash(key, value)) == Some(*root)
    }

    /// Verify that `key` is absent under `root` (the leaf position is empty).
    #[must_use]
    pub fn verify_non_inclusion(&self, root: &Hash32, key: &Hash32) -> bool {
        self.fold(key, empty_root(0)) == Some(*root)
    }
}

impl NoosEncode for SmtProof {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(Self::VERSION);
        w.put_array32(&self.bitmap);
        w.put_list(&self.siblings, DEPTH as u32);
    }
}

impl NoosDecode for SmtProof {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[Self::VERSION])?;
        let bitmap = r.get_array32()?;
        let siblings: Vec<Hash32> = r.get_list(DEPTH as u32)?;
        Ok(Self { bitmap, siblings })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_util::SplitMix64;

    #[test]
    fn empty_roots_are_recursively_derived() {
        assert_eq!(empty_root(0), domain_hash(domains::SMT_LEAF, &[]));
        for h in 1..=DEPTH {
            assert_eq!(
                empty_root(h),
                node_hash(&empty_root(h - 1), &empty_root(h - 1)),
                "empty root at height {h} must be H(node || E[h-1] || E[h-1])"
            );
        }
        assert_eq!(Smt::new().root(), empty_root(DEPTH));
    }

    #[test]
    fn kat_domain_hash_smt_contexts_match_registry_vectors() {
        // protocol/vectors/crypto/domain-hash.json (independently generated
        // with Python blake3): empty-payload digests for the SMT contexts.
        fn hx(s: &str) -> Hash32 {
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        }
        assert_eq!(
            domain_hash(domains::SMT_LEAF, &[]),
            hx("ba597d9f2fcb2e302d8852f0bbf34c2548b72fd43707d33aba758886490e00d9")
        );
        assert_eq!(
            domain_hash(domains::SMT_NODE, &[]),
            hx("0873b0fbb974f8ec0418dfb0d24ea2b01377a6d27a4aa8beb4719990932f440b")
        );
        // 68-byte shared payload KATs.
        let payload: Vec<u8> = (0u8..=0x43).collect();
        assert_eq!(
            domain_hash(domains::SMT_LEAF, &[&payload]),
            hx("ed20bce6a0510adc5716f9d1b96c5b6d439003f75fc013fad88d5b48d91efc8b")
        );
        assert_eq!(
            domain_hash(domains::SMT_NODE, &[&payload]),
            hx("5086208f50eda031efe65e5e8ad138a9e108980c925bc8236c6ccd5cd7fabdc1")
        );
        // Negative KAT (d-tx-wid-mismatch-under-txid-context): a digest
        // computed under D-TX-ID must not verify as D-TX-WID.
        let under_txid = domain_hash(domains::TX_ID, &[&payload]);
        assert_eq!(
            under_txid,
            hx("c778c81de2cfa37714bcf2df91c49879269198e5e037a34715ca922637564975")
        );
        assert_ne!(domain_hash(domains::TX_WID, &[&payload]), under_txid);
    }

    #[test]
    fn parallel_root_is_identical_to_the_sequential_definition() {
        let mut rng = SplitMix64(0x0050_4152_524F_4F54_u64);
        let mut tree = Smt::new();
        for index in 0..2_048_u32 {
            tree.insert(rng.next_hash(), index.to_le_bytes().to_vec());
        }
        let entries: Vec<(&Hash32, &Vec<u8>)> = tree.leaves.iter().collect();
        assert_eq!(
            root_from_sorted_entries(&entries),
            subtree_root(&entries, 0)
        );
    }

    #[test]
    fn incremental_cache_matches_full_rebuild_after_clone_updates_and_removals() {
        fn sequential(tree: &Smt) -> Hash32 {
            let entries = tree.leaves.iter().collect::<Vec<_>>();
            subtree_root(&entries, 0)
        }

        let mut rng = SplitMix64(0x494E_4352_454D_454E);
        let mut tree = Smt::new();
        let mut keys = Vec::new();
        for index in 0..2_048_u32 {
            let mut key = rng.next_hash();
            if index < 32 {
                key[..3].copy_from_slice(&[0xAB, 0xCD, 0xEF]);
            }
            tree.insert(key, index.to_le_bytes().to_vec());
            keys.push(key);
        }
        assert_eq!(tree.root(), sequential(&tree));

        let mut cloned = tree.clone();
        for index in 2_048..4_096_u32 {
            let key = rng.next_hash();
            tree.insert(key, index.to_le_bytes().to_vec());
            keys.push(key);
        }
        for key in keys.iter().step_by(7) {
            tree.remove(key);
        }
        assert_eq!(tree.root(), sequential(&tree));

        cloned.insert(keys[3], b"clone-only-update".to_vec());
        cloned.remove(&keys[5]);
        assert_eq!(cloned.root(), sequential(&cloned));
        assert_ne!(tree.root(), cloned.root());
    }

    #[test]
    fn receipt_tree_matches_canonical_encoding_across_clones_and_removals() {
        let mut rng = SplitMix64(0x5245_4345_4950_5453);
        let mut canonical = Smt::new();
        let mut receipts = ReceiptSmt::new();
        let mut values = Vec::new();
        for index in 0..4_096_u64 {
            let receipt = ReceiptV1 {
                txid: rng.next_hash(),
                status: u16::try_from(index % 17).unwrap(),
                fee_charged: u128::from(index),
                resources_used: crate::objects::ResourceVector {
                    bytes: index,
                    grain_steps: index.saturating_add(1),
                    proof_units: index.saturating_add(2),
                    state_reads: index.saturating_add(3),
                    state_writes: index.saturating_add(4),
                    blob_bytes: index.saturating_add(5),
                },
            };
            assert_eq!(
                encode_receipt_value(&receipt).as_slice(),
                receipt.encode_canonical()
            );
            canonical.insert(receipt.txid, receipt.encode_canonical());
            receipts.insert(receipt.txid, receipt.clone(), index);
            values.push(receipt);
        }
        assert_eq!(receipts.root(), canonical.root());

        let receipts_clone = receipts.clone();
        let canonical_clone = canonical.clone();
        for receipt in values.iter().step_by(11) {
            assert_eq!(
                receipts.remove(&receipt.txid),
                ReceiptV1::decode_canonical(&canonical.remove(&receipt.txid).unwrap()).ok()
            );
        }
        assert_eq!(receipts.root(), canonical.root());
        assert_eq!(receipts_clone.root(), canonical_clone.root());
        assert_ne!(receipts.root(), receipts_clone.root());
    }

    #[test]
    fn shuffled_insertion_sets_give_identical_roots() {
        let mut rng = SplitMix64(0x004C_554D_454E_u64); // "LUMEN"
        let mut pairs: Vec<(Hash32, Vec<u8>)> = (0..200u32)
            .map(|i| (rng.next_hash(), i.to_le_bytes().to_vec()))
            .collect();
        let mut a = Smt::new();
        for (k, v) in &pairs {
            a.insert(*k, v.clone());
        }
        // Three deterministic shuffles.
        for round in 0..3u64 {
            let mut rng = SplitMix64(round.wrapping_mul(0x9E37).wrapping_add(7));
            let mut shuffled = pairs.clone();
            for i in (1..shuffled.len()).rev() {
                let j = (rng.next_u64() as usize) % (i + 1);
                shuffled.swap(i, j);
            }
            let mut b = Smt::new();
            for (k, v) in &shuffled {
                b.insert(*k, v.clone());
            }
            assert_eq!(a.root(), b.root(), "insertion order affected the root");
        }
        // Root differs from empty and reacts to updates.
        assert_ne!(a.root(), empty_root(DEPTH));
        let (k0, _) = pairs[0].clone();
        let before = a.root();
        a.insert(k0, b"replacement".to_vec());
        assert_ne!(
            a.root(),
            before,
            "duplicate-key update must change the root"
        );
        pairs[0].1 = b"replacement".to_vec();
        let mut fresh = Smt::new();
        for (k, v) in &pairs {
            fresh.insert(*k, v.clone());
        }
        assert_eq!(a.root(), fresh.root(), "update must equal fresh build");
    }

    #[test]
    fn inclusion_and_non_inclusion_proofs_verify() {
        let mut rng = SplitMix64(42);
        let mut smt = Smt::new();
        let mut keys = Vec::new();
        for i in 0..64u32 {
            let k = rng.next_hash();
            smt.insert(k, i.to_le_bytes().to_vec());
            keys.push(k);
        }
        let root = smt.root();
        for (i, k) in keys.iter().enumerate() {
            let proof = smt.prove(k);
            let value = (i as u32).to_le_bytes();
            assert!(proof.verify_inclusion(&root, k, &value));
            assert!(!proof.verify_inclusion(&root, k, b"wrong-value"));
            assert!(
                !proof.verify_non_inclusion(&root, k),
                "present key cannot prove absence"
            );
        }
        // Absent keys.
        for _ in 0..16 {
            let absent = rng.next_hash();
            assert!(!smt.contains(&absent));
            let proof = smt.prove(&absent);
            assert!(proof.verify_non_inclusion(&root, &absent));
            assert!(!proof.verify_inclusion(&root, &absent, b"anything"));
        }
        // Wrong root rejects.
        let proof = smt.prove(&keys[0]);
        assert!(!proof.verify_inclusion(&empty_root(DEPTH), &keys[0], &0u32.to_le_bytes()));
        // Tampered sibling rejects.
        let mut tampered = smt.prove(&keys[0]);
        if let Some(s) = tampered.siblings.first_mut() {
            s[0] ^= 0xFF;
        }
        assert!(!tampered.verify_inclusion(&root, &keys[0], &0u32.to_le_bytes()));
        // Bitmap/sibling count mismatch rejects.
        let mut short = smt.prove(&keys[0]);
        short.siblings.pop();
        assert!(!short.verify_inclusion(&root, &keys[0], &0u32.to_le_bytes()));
    }

    #[test]
    fn proof_roundtrips_through_codec() {
        let mut smt = Smt::new();
        let mut rng = SplitMix64(7);
        for i in 0..8u32 {
            smt.insert(rng.next_hash(), i.to_le_bytes().to_vec());
        }
        let mut rng = SplitMix64(7);
        let k = rng.next_hash();
        let proof = smt.prove(&k);
        let bytes = proof.encode_canonical();
        let back = SmtProof::decode_canonical(&bytes).unwrap();
        assert_eq!(proof, back);
        // Trailing byte rejects.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            SmtProof::decode_canonical(&trailing),
            Err(CodecError::TrailingBytes)
        );
    }

    #[test]
    fn adjacent_key_pair_deep_split() {
        // Two keys differing only in the last bit force a full-depth split.
        let mut a = [0xAAu8; 32];
        let mut b = [0xAAu8; 32];
        a[31] = 0xA0;
        b[31] = 0xA1;
        let mut smt = Smt::new();
        smt.insert(a, b"left".to_vec());
        smt.insert(b, b"right".to_vec());
        let root = smt.root();
        assert!(smt.prove(&a).verify_inclusion(&root, &a, b"left"));
        assert!(smt.prove(&b).verify_inclusion(&root, &b, b"right"));
        // Removing one restores the other's single-leaf tree root.
        let mut single = Smt::new();
        single.insert(a, b"left".to_vec());
        smt.remove(&b);
        assert_eq!(smt.root(), single.root());
    }
}
