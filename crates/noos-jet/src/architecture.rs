//! Proof-relevant model and commitment declarations.
//!
//! These are binding mechanics, not hardware or efficiency evidence. A
//! profile id changes if any numeric, checkpoint, activation, projection, MoE,
//! or tolerance choice changes. The commitment reference path keeps stable
//! content addressing (`ArtifactId`) separate from challenge-bound work
//! (`WorkCommit`). GPU implementations may reproduce these bytes exactly, but
//! are never inferred from this CPU reference implementation.

use core::fmt;

const CTX_PROFILE: &[u8] = b"noosphere.jet.proof-architecture.v1";
const CTX_ARTIFACT: &[u8] = b"noosphere.jet.artifact.v1";
const CTX_WORK: &[u8] = b"noosphere.jet.work-commit.v1";
const CTX_CPU_LEAF: &[u8] = b"noosphere.jet.cpu-commit.leaf.v1";
const CTX_CPU_NODE: &[u8] = b"noosphere.jet.cpu-commit.node.v1";
const CTX_CPU_ODD: &[u8] = b"noosphere.jet.cpu-commit.odd.v1";
const CTX_CPU_ROOT: &[u8] = b"noosphere.jet.cpu-commit.root.v1";

pub const PROOF_ARCHITECTURE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofArchitectureManifest {
    pub numeric_profile: [u8; 32],
    pub checkpoint: [u8; 32],
    pub activation_commitment: [u8; 32],
    pub projection_hook: [u8; 32],
    pub moe_route_policy: [u8; 32],
    pub tolerance_ppm: u32,
}

impl ProofArchitectureManifest {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 5 * 32 + 4);
        out.extend_from_slice(&PROOF_ARCHITECTURE_VERSION.to_le_bytes());
        out.extend_from_slice(&self.numeric_profile);
        out.extend_from_slice(&self.checkpoint);
        out.extend_from_slice(&self.activation_commitment);
        out.extend_from_slice(&self.projection_hook);
        out.extend_from_slice(&self.moe_route_policy);
        out.extend_from_slice(&self.tolerance_ppm.to_le_bytes());
        out
    }

    #[must_use]
    pub fn profile_id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(CTX_PROFILE);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkCommit(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitmentDeclaration {
    pub artifact_id: ArtifactId,
    pub profile_id: [u8; 32],
    pub challenge: [u8; 32],
    pub trace_root: [u8; 32],
    pub fused_relation_id: [u8; 32],
    pub work_commit: WorkCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentError {
    WorkCommitMismatch,
    InvalidChunkSize,
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitmentError::WorkCommitMismatch => f.write_str("work commitment mismatch"),
            CommitmentError::InvalidChunkSize => f.write_str("commitment chunk size must be nonzero"),
        }
    }
}

impl std::error::Error for CommitmentError {}

impl CommitmentDeclaration {
    pub fn validate(&self) -> Result<(), CommitmentError> {
        let expected = work_commit(
            self.artifact_id,
            self.profile_id,
            self.challenge,
            self.trace_root,
            self.fused_relation_id,
        );
        if expected != self.work_commit {
            return Err(CommitmentError::WorkCommitMismatch);
        }
        Ok(())
    }
}

#[must_use]
pub fn artifact_id(canonical_tensor: &[u8]) -> ArtifactId {
    let mut h = blake3::Hasher::new();
    h.update(CTX_ARTIFACT);
    h.update(
        &u64::try_from(canonical_tensor.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    h.update(canonical_tensor);
    ArtifactId(*h.finalize().as_bytes())
}
/// Canonical CPU/reference Merkle root for tensor-resident commitment bytes.
///
/// Leaves bind their zero-based index, actual byte length, and bytes. This
/// makes a short final chunk unambiguous. Internal nodes distinguish paired
/// children from an unpaired right-edge child, so imperfect trees do not rely
/// on implicit duplication or padding. The final root additionally binds the
/// total byte length, requested chunk size, and leaf count. GPU implementations
/// must reproduce this exact relation; this function is not GPU evidence.
pub fn cpu_commitment_root(
    canonical_tensor: &[u8],
    chunk_size: usize,
) -> Result<[u8; 32], CommitmentError> {
    if chunk_size == 0 {
        return Err(CommitmentError::InvalidChunkSize);
    }

    let leaf_count = canonical_tensor.len().div_ceil(chunk_size).max(1);
    let mut level = Vec::with_capacity(leaf_count);
    if canonical_tensor.is_empty() {
        level.push(cpu_leaf_hash(0, &[]));
    } else {
        for (index, chunk) in canonical_tensor.chunks(chunk_size).enumerate() {
            level.push(cpu_leaf_hash(index, chunk));
        }
    }

    while level.len() > 1 {
        let previous_len = level.len();
        let mut write = 0;
        let mut read = 0;
        while read < previous_len {
            let mut h = blake3::Hasher::new();
            if read + 1 < previous_len {
                h.update(CTX_CPU_NODE);
                h.update(&level[read]);
                h.update(&level[read + 1]);
            } else {
                h.update(CTX_CPU_ODD);
                h.update(&level[read]);
            }
            level[write] = *h.finalize().as_bytes();
            write += 1;
            read += 2;
        }
        level.truncate(write);
    }

    let mut root = blake3::Hasher::new();
    root.update(CTX_CPU_ROOT);
    root.update(
        &u64::try_from(canonical_tensor.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    root.update(
        &u64::try_from(chunk_size)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    root.update(&u64::try_from(leaf_count).unwrap_or(u64::MAX).to_le_bytes());
    root.update(&level[0]);
    Ok(*root.finalize().as_bytes())
}

fn cpu_leaf_hash(index: usize, chunk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CTX_CPU_LEAF);
    h.update(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
    h.update(&u64::try_from(chunk.len()).unwrap_or(u64::MAX).to_le_bytes());
    h.update(chunk);
    *h.finalize().as_bytes()
}

#[must_use]
pub fn work_commit(
    artifact_id: ArtifactId,
    profile_id: [u8; 32],
    challenge: [u8; 32],
    trace_root: [u8; 32],
    fused_relation_id: [u8; 32],
) -> WorkCommit {
    let mut h = blake3::Hasher::new();
    h.update(CTX_WORK);
    h.update(&artifact_id.0);
    h.update(&profile_id);
    h.update(&challenge);
    h.update(&trace_root);
    h.update(&fused_relation_id);
    WorkCommit(*h.finalize().as_bytes())
}
