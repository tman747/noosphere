//! Consensus-body Reed-Solomon coding and reconstruction-before-acceptance
//! (ch01 §10.1; plan §7.1; schema-tables/da.md PROPOSED-G0 parameters).
//!
//! ## Coding law
//!
//! The canonical `BlockBodyV1` byte string (at most [`MAX_BLOCK_BODY_BYTES`])
//! is split into [`BODY_DATA_SHARDS`] fixed [`BODY_SHARD_BYTES`] data shards,
//! the final data shard zero-padded; [`BODY_PARITY_SHARDS`] parity shards are
//! computed with the registered `RS-GF8-V1` codec (GF(2^8) Reed-Solomon,
//! rate 1/2). Any [`BODY_DATA_SHARDS`] of the [`BODY_TOTAL_SHARDS`] shards
//! reconstruct the unique codeword.
//!
//! Commitments (crypto-domains-v1.csv):
//! * `content_root = H(NOOS/DA/CONTENT/V1 || original_bytes_le_u64 || body)`
//! * `leaf_i = H(NOOS/DA/SHARD/V1 || content_root || i_le_u32 || shard_i)`
//! * `body_da_root` = depth-5 `NOOS/DA/NODE/V1` Merkle root over the leaves
//!   (header field 11, header-body.md).
//!
//! ## Acceptance law
//!
//! A full node accepts a body only through [`reconstruct_and_verify`]:
//! branch-invalid shards are rejected **individually**; fewer than 16
//! surviving shards is a typed unavailability error; the reconstructed
//! codeword must reproduce the trusted root, honor the zero-padding law, and
//! hash back to the leaf-bound content root. There is no partial acceptance.
//! Witness refusal to vote an unreconstructed ancestor is enforced by
//! consensus through the [`AvailabilityLedger`](crate::AvailabilityLedger)
//! primitive.

use noos_crypto::{hash_domain, DomainId, Hash32};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::error::DaError;
use crate::merkle::{branch, build_levels, fold_branch, shard_leaf, ShardBranch};

/// Fixed consensus-body shard size (PROPOSED-G0, da.md / ODR-DA-001).
pub const BODY_SHARD_BYTES: usize = 65_536;
/// Data shards per body (PROPOSED-G0).
pub const BODY_DATA_SHARDS: usize = 16;
/// Parity shards per body (PROPOSED-G0; rate 1/2).
pub const BODY_PARITY_SHARDS: usize = 16;
/// Total shards; any [`BODY_DATA_SHARDS`] of them reconstruct.
pub const BODY_TOTAL_SHARDS: usize = BODY_DATA_SHARDS + BODY_PARITY_SHARDS;
/// Depth of the perfect shard Merkle tree (`2^5 = 32` leaves).
pub const BODY_SHARD_DEPTH: usize = 5;
/// Maximum canonical body size: exactly the data capacity
/// (PROPOSED-G0, da.md / ODR-DA-002; co-freezes with fee capacity).
pub const MAX_BLOCK_BODY_BYTES: usize = BODY_DATA_SHARDS * BODY_SHARD_BYTES;

/// The proposer-claimed reconstruction context for one body. Both fields
/// are **untrusted** wire inputs: `content_root` is validated against the
/// leaf binding under the trusted shard root, and `original_bytes` is
/// validated through the `content_root` preimage, so neither can be forged
/// without breaking the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyDaClaimV1 {
    /// `H(NOOS/DA/CONTENT/V1 || original_bytes_le_u64 || body)`.
    pub content_root: Hash32,
    /// Pre-coding body length in bytes.
    pub original_bytes: u64,
}

/// One shard as it arrives from transport: index, fixed-size bytes, and the
/// Merkle branch connecting its leaf to the committed root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardCandidateV1 {
    pub index: u32,
    pub bytes: Vec<u8>,
    pub branch: ShardBranch,
}

/// A fully coded body as produced by a proposer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBodyV1 {
    claim: BodyDaClaimV1,
    shard_root: Hash32,
    shards: Vec<Vec<u8>>,
    levels: Vec<Vec<Hash32>>,
}

impl EncodedBodyV1 {
    /// The commitment root (`body_da_root`, header field 11).
    #[must_use]
    pub fn shard_root(&self) -> &Hash32 {
        &self.shard_root
    }

    /// The reconstruction claim to publish alongside the shards.
    #[must_use]
    pub fn claim(&self) -> &BodyDaClaimV1 {
        &self.claim
    }

    /// All 32 shards in index order (data `0..16`, parity `16..32`).
    #[must_use]
    pub fn shards(&self) -> &[Vec<u8>] {
        &self.shards
    }

    /// Merkle branch for shard `index`.
    pub fn branch(&self, index: u32) -> Result<ShardBranch, DaError> {
        branch(&self.levels, index)
    }

    /// Transport-ready candidate for shard `index`.
    pub fn candidate(&self, index: u32) -> Result<ShardCandidateV1, DaError> {
        let bytes = self
            .shards
            .get(index as usize)
            .ok_or(DaError::ShardIndexOutOfRange { index })?
            .clone();
        Ok(ShardCandidateV1 {
            index,
            bytes,
            branch: self.branch(index)?,
        })
    }
}

/// A body that passed the full reconstruction-and-verification law. The
/// only constructors are [`encode_body`] (proposer side, trivially
/// self-consistent) and [`reconstruct_and_verify`], so holding one *is*
/// the availability proof for its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedBodyV1 {
    shard_root: Hash32,
    content_root: Hash32,
    bytes: Vec<u8>,
}

impl ReconstructedBodyV1 {
    /// The commitment root this body was verified against.
    #[must_use]
    pub fn shard_root(&self) -> &Hash32 {
        &self.shard_root
    }

    /// The verified content root.
    #[must_use]
    pub fn content_root(&self) -> &Hash32 {
        &self.content_root
    }

    /// The exact canonical body bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes into the body bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// `H(NOOS/DA/CONTENT/V1 || original_bytes_le_u64 || body)`.
pub fn content_root(body: &[u8]) -> Result<Hash32, DaError> {
    let len = body.len() as u64;
    Ok(hash_domain(
        DomainId::DaContent,
        &[&len.to_le_bytes(), body],
    )?)
}

fn coder() -> Result<ReedSolomon, DaError> {
    ReedSolomon::new(BODY_DATA_SHARDS, BODY_PARITY_SHARDS)
        .map_err(|_| DaError::ReconstructionFailed)
}

/// Splits `body` into 16 zero-padded data shards. Deterministic: the same
/// body always yields the same shard bytes.
fn data_shards(body: &[u8]) -> Vec<Vec<u8>> {
    let mut shards = vec![vec![0_u8; BODY_SHARD_BYTES]; BODY_DATA_SHARDS];
    for (i, chunk) in body.chunks(BODY_SHARD_BYTES).enumerate() {
        shards[i][..chunk.len()].copy_from_slice(chunk);
    }
    shards
}

fn commit(claim: BodyDaClaimV1, shards: Vec<Vec<u8>>) -> Result<EncodedBodyV1, DaError> {
    let mut leaves = Vec::with_capacity(BODY_TOTAL_SHARDS);
    for (i, shard) in shards.iter().enumerate() {
        leaves.push(shard_leaf(&claim.content_root, i as u32, shard)?);
    }
    let levels = build_levels(leaves)?;
    let shard_root = *levels
        .last()
        .and_then(|top| top.first())
        .ok_or(DaError::Crypto)?;
    Ok(EncodedBodyV1 {
        claim,
        shard_root,
        shards,
        levels,
    })
}

/// Proposer side: Reed-Solomon encode canonical body bytes into the 32
/// committed shards.
pub fn encode_body(body: &[u8]) -> Result<EncodedBodyV1, DaError> {
    if body.len() > MAX_BLOCK_BODY_BYTES {
        return Err(DaError::BodyTooLarge {
            len: body.len() as u64,
        });
    }
    let claim = BodyDaClaimV1 {
        content_root: content_root(body)?,
        original_bytes: body.len() as u64,
    };
    let mut shards = data_shards(body);
    shards.extend(std::iter::repeat_with(|| vec![0_u8; BODY_SHARD_BYTES]).take(BODY_PARITY_SHARDS));
    coder()?
        .encode(&mut shards)
        .map_err(|_| DaError::ReconstructionFailed)?;
    commit(claim, shards)
}

/// Test/adversary-side constructor: commits to an **arbitrary padded data
/// region** (16 x 64 KiB) without the padding-zero law, so tests and the
/// vector generator can produce proposer misbehavior (nonzero padding)
/// that honest [`encode_body`] never emits.
#[doc(hidden)]
pub fn encode_padded_region(
    claim: BodyDaClaimV1,
    data_region: &[u8],
) -> Result<EncodedBodyV1, DaError> {
    if data_region.len() != MAX_BLOCK_BODY_BYTES {
        return Err(DaError::BodyTooLarge {
            len: data_region.len() as u64,
        });
    }
    let mut shards = data_shards(data_region);
    shards.extend(std::iter::repeat_with(|| vec![0_u8; BODY_SHARD_BYTES]).take(BODY_PARITY_SHARDS));
    coder()?
        .encode(&mut shards)
        .map_err(|_| DaError::ReconstructionFailed)?;
    commit(claim, shards)
}

/// Test/adversary-side constructor: commits a Merkle tree over an
/// **arbitrary** 32-shard set that need not be a Reed-Solomon codeword,
/// so tests and the vector generator can produce the inconsistent
/// committed-codeword misbehavior that [`reconstruct_and_verify`] must
/// reject with [`DaError::CommitmentMismatch`].
#[doc(hidden)]
pub fn commit_shards(claim: BodyDaClaimV1, shards: Vec<Vec<u8>>) -> Result<EncodedBodyV1, DaError> {
    if shards.len() != BODY_TOTAL_SHARDS || shards.iter().any(|s| s.len() != BODY_SHARD_BYTES) {
        return Err(DaError::ShardGeometry);
    }
    commit(claim, shards)
}

fn verified_shard_leaf(
    shard_root: &Hash32,
    content_root: &Hash32,
    candidate: &ShardCandidateV1,
) -> Result<Hash32, DaError> {
    if candidate.index as usize >= BODY_TOTAL_SHARDS {
        return Err(DaError::ShardIndexOutOfRange {
            index: candidate.index,
        });
    }
    if candidate.bytes.len() != BODY_SHARD_BYTES {
        return Err(DaError::WrongShardLength {
            index: candidate.index,
            len: candidate.bytes.len() as u64,
        });
    }
    let leaf = shard_leaf(content_root, candidate.index, &candidate.bytes)?;
    let implied = fold_branch(&leaf, candidate.index, &candidate.branch)?;
    if implied != *shard_root {
        return Err(DaError::ShardProofMismatch {
            index: candidate.index,
        });
    }
    Ok(leaf)
}

/// Verifies one shard candidate against the trusted root: index range,
/// exact fixed length, and the Merkle branch. This is the *individual*
/// rejection law: a failing shard never poisons its siblings.
pub fn verify_body_shard(
    shard_root: &Hash32,
    content_root: &Hash32,
    candidate: &ShardCandidateV1,
) -> Result<(), DaError> {
    verified_shard_leaf(shard_root, content_root, candidate).map(|_| ())
}

/// Light-client sampling primitive (ch01 §10.1).
///
/// Verifies that `(index, shard, branch)` is a member of the committed
/// shard tree `shard_root` under the claimed `content_root`.
///
/// **This is a probabilistic availability OPINION only.** A passing sample
/// never makes an unavailable body valid for a full node, never
/// constitutes acceptance, and never substitutes for
/// [`reconstruct_and_verify`]; witnesses MUST NOT vote a checkpoint whose
/// ancestor bodies they have not fully reconstructed.
pub fn verify_shard_sample(
    shard_root: &Hash32,
    content_root: &Hash32,
    index: u32,
    shard: &[u8],
    branch: &ShardBranch,
) -> Result<(), DaError> {
    verify_body_shard(
        shard_root,
        content_root,
        &ShardCandidateV1 {
            index,
            bytes: shard.to_vec(),
            branch: *branch,
        },
    )
}

/// Full-node acceptance law: reconstruct the exact committed body from any
/// [`BODY_DATA_SHARDS`] branch-valid shards, or fail typed.
///
/// 1. every candidate is verified individually; failures are skipped
///    (rejected shards never block valid siblings);
/// 2. fewer than 16 distinct valid shards →
///    [`DaError::NotEnoughValidShards`];
/// 3. the erasure decoder completes the unique codeword;
/// 4. the full 32-leaf tree is recomputed — any deviation from
///    `shard_root` rejects the whole body ([`DaError::CommitmentMismatch`]);
/// 5. data bytes beyond `original_bytes` must be zero
///    ([`DaError::NonZeroPadding`]);
/// 6. the body must hash back to the leaf-bound content root
///    ([`DaError::ContentRootMismatch`]).
pub fn reconstruct_and_verify(
    shard_root: &Hash32,
    claim: &BodyDaClaimV1,
    candidates: &[ShardCandidateV1],
) -> Result<ReconstructedBodyV1, DaError> {
    if claim.original_bytes > MAX_BLOCK_BODY_BYTES as u64 {
        return Err(DaError::BodyTooLarge {
            len: claim.original_bytes,
        });
    }

    // (1) individual shard law: first valid candidate per index wins; two
    // branch-valid candidates at one index are byte-identical by collision
    // resistance of the leaf hash.
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; BODY_TOTAL_SHARDS];
    let mut verified_leaves: Vec<Option<Hash32>> = vec![None; BODY_TOTAL_SHARDS];
    let mut valid: u32 = 0;
    for candidate in candidates {
        let Ok(leaf) = verified_shard_leaf(shard_root, &claim.content_root, candidate) else {
            continue;
        };
        let slot = &mut slots[candidate.index as usize];
        if slot.is_none() {
            *slot = Some(candidate.bytes.clone());
            verified_leaves[candidate.index as usize] = Some(leaf);
            valid = valid.saturating_add(1);
        }
    }

    // (2) unavailability is typed, never partial.
    if (valid as usize) < BODY_DATA_SHARDS {
        return Err(DaError::NotEnoughValidShards {
            valid,
            needed: BODY_DATA_SHARDS as u32,
        });
    }

    // (3) complete the unique codeword.
    coder()?
        .reconstruct(&mut slots)
        .map_err(|_| DaError::ReconstructionFailed)?;
    let mut shards = Vec::with_capacity(BODY_TOTAL_SHARDS);
    for slot in slots {
        shards.push(slot.ok_or(DaError::ReconstructionFailed)?);
    }

    // (4) reconstruction-before-acceptance: recompute the whole tree from
    // the verified leaf hashes plus hashes of reconstructed missing shards.
    // Reusing already verified leaves avoids hashing every 64 KiB shard twice.
    let mut leaves = Vec::with_capacity(BODY_TOTAL_SHARDS);
    for (index, shard) in shards.iter().enumerate() {
        let leaf = match verified_leaves[index] {
            Some(leaf) => leaf,
            None => shard_leaf(&claim.content_root, index as u32, shard)?,
        };
        leaves.push(leaf);
    }
    let levels = build_levels(leaves)?;
    let recomputed_root = *levels
        .last()
        .and_then(|top| top.first())
        .ok_or(DaError::Crypto)?;
    if recomputed_root != *shard_root {
        return Err(DaError::CommitmentMismatch);
    }

    // (5) zero-padding law over the reconstructed data region.
    let original = claim.original_bytes as usize;
    let mut data = Vec::with_capacity(MAX_BLOCK_BODY_BYTES);
    for shard in shards.iter().take(BODY_DATA_SHARDS) {
        data.extend_from_slice(shard);
    }
    if data[original..].iter().any(|&b| b != 0) {
        return Err(DaError::NonZeroPadding);
    }

    // (6) the body must be the exact committed content.
    let body = &data[..original];
    if content_root(body)? != claim.content_root {
        return Err(DaError::ContentRootMismatch);
    }

    Ok(ReconstructedBodyV1 {
        shard_root: *shard_root,
        content_root: claim.content_root,
        bytes: body.to_vec(),
    })
}

/// Deterministic availability ledger: the `body_available(root)` primitive
/// consensus consults before voting (witnesses MUST NOT vote a checkpoint
/// containing an unreconstructed ancestor). Entry is possible only through
/// a [`ReconstructedBodyV1`] (full verification) or a locally produced
/// [`EncodedBodyV1`] (the proposer trivially holds the body).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AvailabilityLedger {
    available: std::collections::BTreeSet<Hash32>,
}

impl AvailabilityLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a fully reconstructed-and-verified body.
    pub fn record_reconstructed(&mut self, body: &ReconstructedBodyV1) {
        self.available.insert(body.shard_root);
    }

    /// Records a locally encoded body (proposer path).
    pub fn record_encoded(&mut self, encoded: &EncodedBodyV1) {
        self.available.insert(encoded.shard_root);
    }

    /// The consensus availability primitive: `true` iff the body committed
    /// by `shard_root` has been held in full by this node.
    #[must_use]
    pub fn body_available(&self, shard_root: &Hash32) -> bool {
        self.available.contains(shard_root)
    }

    /// Deterministic (byte-ordered) iteration over available roots.
    pub fn available_roots(&self) -> impl Iterator<Item = &Hash32> {
        self.available.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.available.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.available.is_empty()
    }
}
