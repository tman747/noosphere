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

use crate::{domain_hash, domains, Hash32};
use noos_codec::{CodecError, NoosDecode, NoosEncode, Reader, Writer};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Tree depth in bits (= key bits).
pub const DEPTH: usize = 256;

/// `EMPTY_ROOTS[h]` = root of an empty subtree of height `h` (`0..=256`).
static EMPTY_ROOTS: LazyLock<[Hash32; DEPTH + 1]> = LazyLock::new(|| {
    let mut table = [[0u8; 32]; DEPTH + 1];
    table[0] = domain_hash(domains::SMT_LEAF, &[]);
    for h in 1..=DEPTH {
        let below = table[h - 1];
        table[h] = domain_hash(domains::SMT_NODE, &[&below, &below]);
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

/// Domain-separated internal node hash.
#[must_use]
pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    domain_hash(domains::SMT_NODE, &[left, right])
}

/// Bit `d` of `key`, depth-from-root order (MSB-first within each byte).
#[inline]
#[must_use]
pub fn key_bit(key: &Hash32, d: usize) -> bool {
    debug_assert!(d < DEPTH);
    (key[d / 8] >> (7 - (d % 8))) & 1 == 1
}

/// In-memory sparse Merkle tree. Deterministic: leaves live in a `BTreeMap`;
/// the root is a pure function of the map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Smt {
    leaves: BTreeMap<Hash32, Vec<u8>>,
}

impl Smt {
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: BTreeMap::new() }
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
        self.leaves.insert(key, value)
    }

    /// Remove a key. Returns the prior value when present.
    pub fn remove(&mut self, key: &Hash32) -> Option<Vec<u8>> {
        self.leaves.remove(key)
    }

    /// Deterministic iteration in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.leaves.iter()
    }

    /// Current root. Pure function of the leaf map; O(n·depth) hashing.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let entries: Vec<(&Hash32, &Vec<u8>)> = self.leaves.iter().collect();
        subtree_root(&entries, 0)
    }

    /// Merkle proof for `key` (inclusion when present, non-inclusion when
    /// absent). Siblings are recorded root→leaf; empty siblings are elided
    /// via the bitmap.
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
            let split = lo
                + entries[lo..hi]
                    .partition_point(|(k, _)| !key_bit(k, d));
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
    fn shuffled_insertion_sets_give_identical_roots() {
        let mut rng = SplitMix64(0x4C55_4D45_4E_u64); // "LUMEN"
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
        assert_ne!(a.root(), before, "duplicate-key update must change the root");
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
            assert!(!proof.verify_non_inclusion(&root, k), "present key cannot prove absence");
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
