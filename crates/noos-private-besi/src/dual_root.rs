//! P1 / S-DUAL-ROOT local contract: a stable content root `ArtifactID = BLAKE3(canonical_tensor)`
//! is separated from a fresh challenge-bound work root
//! `WorkCommit = BLAKE3_challenge(ArtifactID, profile, trace_root)`. Content may be reused across
//! challenges without silently reusing seed-dependent security work: the artifact root never moves,
//! the work root never survives a challenge change, and every challenge is consumed exactly once.

use crate::Matrix;
use std::collections::BTreeSet;

pub const ARTIFACT_DOMAIN: &[u8] = b"NOOS/BESI/ARTIFACT-ID/V1";
pub const WORK_DOMAIN: &[u8] = b"NOOS/BESI/WORK-COMMIT/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DualRootError {
    /// The stable content root does not match the canonical tensor encoding.
    ArtifactMismatch,
    /// The work root was not produced under this challenge/profile/trace binding.
    WorkCommitMismatch,
    /// The challenge was already consumed; fresh work may not be replayed.
    ChallengeReplay,
}

/// Canonical injective tensor encoding: domain, dimensions, then row-major words, all little endian.
/// Two tensors with the same flat data but different shapes encode differently.
#[must_use]
pub fn canonical_tensor_bytes(tensor: &Matrix) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ARTIFACT_DOMAIN
            .len()
            .saturating_add(16)
            .saturating_add(tensor.data.len().saturating_mul(8)),
    );
    out.extend_from_slice(ARTIFACT_DOMAIN);
    out.extend_from_slice(&(tensor.rows as u64).to_le_bytes());
    out.extend_from_slice(&(tensor.cols as u64).to_le_bytes());
    for value in &tensor.data {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Stable content root. Independent of any challenge, profile, or trace.
#[must_use]
pub fn artifact_id(tensor: &Matrix) -> [u8; 32] {
    *blake3::hash(&canonical_tensor_bytes(tensor)).as_bytes()
}

/// Fresh work root, keyed by the challenge so precomputed roots cannot survive a new challenge.
#[must_use]
pub fn work_commit(
    artifact: &[u8; 32],
    profile: &[u8; 32],
    trace_root: &[u8; 32],
    challenge: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(WORK_DOMAIN.len().saturating_add(96));
    payload.extend_from_slice(WORK_DOMAIN);
    payload.extend_from_slice(artifact);
    payload.extend_from_slice(profile);
    payload.extend_from_slice(trace_root);
    *blake3::keyed_hash(challenge, &payload).as_bytes()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualRoot {
    pub artifact_id: [u8; 32],
    pub work_commit: [u8; 32],
}

#[must_use]
pub fn commit_dual_root(
    tensor: &Matrix,
    profile: &[u8; 32],
    trace_root: &[u8; 32],
    challenge: &[u8; 32],
) -> DualRoot {
    let artifact = artifact_id(tensor);
    DualRoot {
        artifact_id: artifact,
        work_commit: work_commit(&artifact, profile, trace_root, challenge),
    }
}

/// Consistency proof check: both roots must be recomputable from the same canonical tensor and the
/// named challenge binding. Divergent roots reject with the divergent side identified.
pub fn verify_dual_root(
    tensor: &Matrix,
    profile: &[u8; 32],
    trace_root: &[u8; 32],
    challenge: &[u8; 32],
    root: &DualRoot,
) -> Result<(), DualRootError> {
    let artifact = artifact_id(tensor);
    if artifact != root.artifact_id {
        return Err(DualRootError::ArtifactMismatch);
    }
    if work_commit(&artifact, profile, trace_root, challenge) != root.work_commit {
        return Err(DualRootError::WorkCommitMismatch);
    }
    Ok(())
}

/// Consumes challenges exactly once so fresh work cannot be replayed under a stale challenge.
#[derive(Clone, Debug, Default)]
pub struct WorkRegistry {
    consumed_challenges: BTreeSet<[u8; 32]>,
}

impl WorkRegistry {
    pub fn admit(
        &mut self,
        tensor: &Matrix,
        profile: &[u8; 32],
        trace_root: &[u8; 32],
        challenge: &[u8; 32],
        root: &DualRoot,
    ) -> Result<(), DualRootError> {
        verify_dual_root(tensor, profile, trace_root, challenge, root)?;
        if !self.consumed_challenges.insert(*challenge) {
            return Err(DualRootError::ChallengeReplay);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn tensor() -> Matrix {
        Matrix::new(2, 3, vec![1, 2, 3, 4, 5, u64::MAX]).unwrap()
    }

    #[test]
    fn content_root_is_stable_and_work_root_is_challenge_fresh() {
        let t = tensor();
        let (profile, trace) = ([7u8; 32], [9u8; 32]);
        let r1 = commit_dual_root(&t, &profile, &trace, &[1u8; 32]);
        let r2 = commit_dual_root(&t, &profile, &trace, &[2u8; 32]);
        // Content reuse: the artifact root is identical across challenges.
        assert_eq!(r1.artifact_id, r2.artifact_id);
        // Fresh work: the work root never survives a challenge change.
        assert_ne!(r1.work_commit, r2.work_commit);
        let mut reg = WorkRegistry::default();
        assert_eq!(reg.admit(&t, &profile, &trace, &[1u8; 32], &r1), Ok(()));
        assert_eq!(reg.admit(&t, &profile, &trace, &[2u8; 32], &r2), Ok(()));
    }

    #[test]
    fn falsifier_challenge_replay_rejects() {
        let t = tensor();
        let (profile, trace, ch) = ([7u8; 32], [9u8; 32], [1u8; 32]);
        let root = commit_dual_root(&t, &profile, &trace, &ch);
        let mut reg = WorkRegistry::default();
        assert_eq!(reg.admit(&t, &profile, &trace, &ch, &root), Ok(()));
        assert_eq!(
            reg.admit(&t, &profile, &trace, &ch, &root),
            Err(DualRootError::ChallengeReplay)
        );
    }

    #[test]
    fn falsifier_precomputed_work_root_fails_fresh_challenge() {
        let t = tensor();
        let (profile, trace) = ([7u8; 32], [9u8; 32]);
        let precomputed = commit_dual_root(&t, &profile, &trace, &[1u8; 32]);
        // A precomputed work root submitted against a fresh challenge diverges.
        assert_eq!(
            verify_dual_root(&t, &profile, &trace, &[2u8; 32], &precomputed),
            Err(DualRootError::WorkCommitMismatch)
        );
    }

    #[test]
    fn falsifier_alternate_encodings_do_not_collide() {
        let flat = vec![1u64, 2, 3, 4, 5, 6];
        let a = Matrix::new(2, 3, flat.clone()).unwrap();
        let b = Matrix::new(3, 2, flat.clone()).unwrap();
        let c = Matrix::new(1, 6, flat).unwrap();
        assert_ne!(artifact_id(&a), artifact_id(&b));
        assert_ne!(artifact_id(&a), artifact_id(&c));
        assert_ne!(artifact_id(&b), artifact_id(&c));
        // Any value mutation moves the content root.
        let mut mutated = tensor();
        mutated.data[0] ^= 1;
        assert_ne!(artifact_id(&tensor()), artifact_id(&mutated));
    }

    #[test]
    fn falsifier_profile_or_trace_substitution_rejects() {
        let t = tensor();
        let (profile, trace, ch) = ([7u8; 32], [9u8; 32], [1u8; 32]);
        let root = commit_dual_root(&t, &profile, &trace, &ch);
        assert_eq!(
            verify_dual_root(&t, &[8u8; 32], &trace, &ch, &root),
            Err(DualRootError::WorkCommitMismatch)
        );
        assert_eq!(
            verify_dual_root(&t, &profile, &[8u8; 32], &ch, &root),
            Err(DualRootError::WorkCommitMismatch)
        );
        let other = Matrix::new(2, 3, vec![9, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(
            verify_dual_root(&other, &profile, &trace, &ch, &root),
            Err(DualRootError::ArtifactMismatch)
        );
    }
}
