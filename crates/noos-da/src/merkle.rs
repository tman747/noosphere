//! Domain-separated Merkle commitment over the 32 consensus-body shard
//! leaves (perfect binary tree, depth [`BODY_SHARD_DEPTH`]).
//!
//! Laws (crypto-domains-v1.csv):
//! * leaf  = `H(NOOS/DA/SHARD/V1 || content_root || shard_index_le_u32 || shard_bytes)`
//! * node  = `H(NOOS/DA/NODE/V1  || left || right)`
//!
//! Leaves and nodes use distinct registered domains, so a leaf can never be
//! replayed as an internal node (second-preimage/extension separation).
//! The branch for leaf `i` lists the sibling hash at every level, level 0
//! (leaf level) first; bit `l` of `i` selects the side at level `l`.

use noos_crypto::{hash_domain, DomainId, Hash32};

use crate::error::DaError;
use crate::{BODY_SHARD_DEPTH, BODY_TOTAL_SHARDS};

/// Merkle branch from a shard leaf to `body_da_root` (sibling per level,
/// leaf level first).
pub type ShardBranch = [Hash32; BODY_SHARD_DEPTH];

/// Shard leaf hash: binds the pre-coding content identity, the shard's
/// position, and the exact (zero-padded) shard bytes.
pub fn shard_leaf(content_root: &Hash32, index: u32, shard: &[u8]) -> Result<Hash32, DaError> {
    Ok(hash_domain(
        DomainId::DaShard,
        &[content_root.as_bytes(), &index.to_le_bytes(), shard],
    )?)
}

/// Internal node hash.
pub fn node(left: &Hash32, right: &Hash32) -> Result<Hash32, DaError> {
    Ok(hash_domain(
        DomainId::DaNode,
        &[left.as_bytes(), right.as_bytes()],
    )?)
}

/// All tree levels bottom-up: `levels[0]` = the 32 leaves, ...,
/// `levels[BODY_SHARD_DEPTH]` = `[root]`.
pub(crate) fn build_levels(leaves: Vec<Hash32>) -> Result<Vec<Vec<Hash32>>, DaError> {
    debug_assert_eq!(leaves.len(), BODY_TOTAL_SHARDS);
    let mut levels = Vec::with_capacity(BODY_SHARD_DEPTH.wrapping_add(1));
    levels.push(leaves);
    for _ in 0..BODY_SHARD_DEPTH {
        let below = levels.last().ok_or(DaError::Crypto)?;
        let mut above = Vec::with_capacity(below.len() / 2);
        for pair in below.chunks_exact(2) {
            above.push(node(&pair[0], &pair[1])?);
        }
        levels.push(above);
    }
    Ok(levels)
}

/// Sibling branch for leaf `index` out of prebuilt levels.
pub(crate) fn branch(levels: &[Vec<Hash32>], index: u32) -> Result<ShardBranch, DaError> {
    if index as usize >= BODY_TOTAL_SHARDS {
        return Err(DaError::ShardIndexOutOfRange { index });
    }
    let mut out = [Hash32::ZERO; BODY_SHARD_DEPTH];
    let mut pos = index as usize;
    for (level, slot) in out.iter_mut().enumerate() {
        *slot = levels[level][pos ^ 1];
        pos >>= 1;
    }
    Ok(out)
}

/// Folds a leaf up its branch; returns the implied root.
pub fn fold_branch(leaf: &Hash32, index: u32, branch: &ShardBranch) -> Result<Hash32, DaError> {
    if index as usize >= BODY_TOTAL_SHARDS {
        return Err(DaError::ShardIndexOutOfRange { index });
    }
    let mut cur = *leaf;
    for (level, sibling) in branch.iter().enumerate() {
        cur = if (index >> level) & 1 == 1 {
            node(sibling, &cur)?
        } else {
            node(&cur, sibling)?
        };
    }
    Ok(cur)
}
