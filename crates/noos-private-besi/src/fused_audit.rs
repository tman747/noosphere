//! P2 / S-FUSED-AUDIT local contract: a post-commit approximate audit over private state
//! transitions reuses a seeded randomized HD projection. The deterministic blockwise-H profile is
//! a distinct, weaker profile and never substitutes for the randomized one. Approximate acceptance
//! never improves or replaces exact-Z Freivalds soundness: a fused acceptance is a separate type
//! that the exact requantization admission path rejects.

use crate::Matrix;
use std::collections::BTreeSet;

pub const FUSED_AUDIT_DOMAIN: &[u8] = b"NOOS/BESI/FUSED-AUDIT/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditProfile {
    /// Seeded randomized HD projection; the seed is single-use and drawn post-commit.
    RandomizedHd { seed: [u8; 32] },
    /// Deterministic blockwise H digest. A different, weaker profile: never a substitute.
    DeterministicBlockH,
}

impl AuditProfile {
    fn tag(&self) -> u8 {
        match self {
            AuditProfile::RandomizedHd { .. } => 1,
            AuditProfile::DeterministicBlockH => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    Shape,
    Overflow,
    /// A previously consumed seed was replayed; commit-before-challenge is mandatory.
    StaleSeed,
    /// A transition diverged beyond the declared quantization tolerance.
    Tampered {
        transition: usize,
    },
    /// A blockwise-H transcript was presented where the randomized HD profile is required.
    ProfileSubstitution,
    /// A fused (approximate) acceptance was presented on the exact admission path.
    NotExact,
}

/// One private state transition: committed post-state versus the observed post-state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    pub committed: Matrix,
    pub observed: Matrix,
}

/// Approximate acceptance. Deliberately not convertible into exact-Freivalds acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusedAcceptance {
    pub profile_tag: u8,
    pub transcript: [u8; 32],
}

impl FusedAcceptance {
    /// The fused audit never upgrades to exact soundness (non-claim honored in code).
    #[must_use]
    pub fn is_exact(&self) -> bool {
        false
    }
}

/// The exact admission path: only exact-Z Freivalds acceptance may unlock requantization.
pub fn admit_for_requantization(acceptance: &FusedAcceptance) -> Result<(), AuditError> {
    if acceptance.is_exact() {
        return Ok(());
    }
    Err(AuditError::NotExact)
}

/// Dense odd projection coefficients in {1,3,5,7} signed, derived from the seed and the
/// transition index. Odd nonzero coefficients make every basis-aligned error visible.
fn projection_row(seed: &[u8; 32], transition: usize, len: usize) -> Vec<i128> {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(FUSED_AUDIT_DOMAIN);
    hasher.update(&(transition as u64).to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = Vec::with_capacity(len);
    let mut buf = [0u8; 1];
    for _ in 0..len {
        reader.fill(&mut buf);
        let magnitude = i128::from((buf[0] & 6).saturating_add(1));
        let coefficient = if buf[0] & 8 == 0 {
            magnitude
        } else {
            magnitude.saturating_neg()
        };
        out.push(coefficient);
    }
    out
}

fn signed_residual(committed: &Matrix, observed: &Matrix) -> Result<Vec<i128>, AuditError> {
    if committed.rows != observed.rows || committed.cols != observed.cols {
        return Err(AuditError::Shape);
    }
    Ok(committed
        .data
        .iter()
        .zip(&observed.data)
        .map(|(c, o)| i128::from(*o as i64).wrapping_sub(i128::from(*c as i64)))
        .collect())
}

/// Runs the fused approximate audit over the transition sequence. Every accepted transition
/// contributes its projection value to a chained transcript binding profile, seed, and index.
pub fn fused_audit(
    profile: &AuditProfile,
    transitions: &[Transition],
    tolerance: u64,
) -> Result<FusedAcceptance, AuditError> {
    let mut transcript = blake3::Hasher::new();
    transcript.update(FUSED_AUDIT_DOMAIN);
    transcript.update(&[profile.tag()]);
    match profile {
        AuditProfile::RandomizedHd { seed } => {
            transcript.update(seed);
            for (index, transition) in transitions.iter().enumerate() {
                let residual = signed_residual(&transition.committed, &transition.observed)?;
                let row = projection_row(seed, index, residual.len());
                let mut acc: i128 = 0;
                let mut weight: i128 = 0;
                for (r, d) in row.iter().zip(&residual) {
                    acc = acc
                        .checked_add(r.checked_mul(*d).ok_or(AuditError::Overflow)?)
                        .ok_or(AuditError::Overflow)?;
                    weight = weight
                        .checked_add(r.checked_abs().ok_or(AuditError::Overflow)?)
                        .ok_or(AuditError::Overflow)?;
                }
                let bound = i128::from(tolerance)
                    .checked_mul(weight)
                    .ok_or(AuditError::Overflow)?;
                if acc.checked_abs().ok_or(AuditError::Overflow)? > bound {
                    return Err(AuditError::Tampered { transition: index });
                }
                transcript.update(&(index as u64).to_le_bytes());
                transcript.update(&acc.to_le_bytes());
            }
        }
        AuditProfile::DeterministicBlockH => {
            for (index, transition) in transitions.iter().enumerate() {
                let residual = signed_residual(&transition.committed, &transition.observed)?;
                if residual
                    .iter()
                    .any(|d| d.checked_abs().is_none_or(|a| a > i128::from(tolerance)))
                {
                    return Err(AuditError::Tampered { transition: index });
                }
                transcript.update(&(index as u64).to_le_bytes());
                for value in &transition.observed.data {
                    transcript.update(&value.to_le_bytes());
                }
            }
        }
    }
    Ok(FusedAcceptance {
        profile_tag: profile.tag(),
        transcript: *transcript.finalize().as_bytes(),
    })
}

/// Requires a randomized-HD acceptance. A deterministic blockwise-H transcript is a weaker
/// profile and rejects here (H/HD substitution kill threshold).
pub fn require_randomized_hd(acceptance: &FusedAcceptance) -> Result<(), AuditError> {
    if acceptance.profile_tag != 1 {
        return Err(AuditError::ProfileSubstitution);
    }
    Ok(())
}

/// Single-use seed ledger: commit-before-challenge means a seed is consumed by its first audit.
#[derive(Clone, Debug, Default)]
pub struct SeedLedger {
    consumed: BTreeSet<[u8; 32]>,
}

impl SeedLedger {
    pub fn audit(
        &mut self,
        seed: [u8; 32],
        transitions: &[Transition],
        tolerance: u64,
    ) -> Result<FusedAcceptance, AuditError> {
        if !self.consumed.insert(seed) {
            return Err(AuditError::StaleSeed);
        }
        fused_audit(&AuditProfile::RandomizedHd { seed }, transitions, tolerance)
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

    fn state(values: &[i64]) -> Matrix {
        Matrix::new(1, values.len(), values.iter().map(|v| *v as u64).collect()).unwrap()
    }

    fn honest(values: &[i64]) -> Transition {
        Transition {
            committed: state(values),
            observed: state(values),
        }
    }

    #[test]
    fn honest_sequence_accepts_and_transcript_is_deterministic() {
        let seed = [3u8; 32];
        let transitions = vec![honest(&[1, -2, 3, 4]), honest(&[-9, 8, 7, i64::MAX])];
        let a = fused_audit(&AuditProfile::RandomizedHd { seed }, &transitions, 0).unwrap();
        let b = fused_audit(&AuditProfile::RandomizedHd { seed }, &transitions, 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn falsifier_basis_aligned_error_is_detected() {
        let seed = [3u8; 32];
        let mut transitions = vec![honest(&[1, -2, 3, 4]), honest(&[5, 6, 7, 8])];
        // Single-coordinate (basis-aligned) error: odd projection coefficients expose it.
        transitions[1].observed.data[2] = 9;
        assert_eq!(
            fused_audit(&AuditProfile::RandomizedHd { seed }, &transitions, 0),
            Err(AuditError::Tampered { transition: 1 })
        );
    }

    #[test]
    fn falsifier_quantization_threshold_error_is_detected() {
        let seed = [5u8; 32];
        let tolerance = 2u64;
        // Derive the smallest single-coordinate error the projection is guaranteed to reject:
        // detection needs |error| * |r_j| > tolerance * sum(|r|), so target the largest |r_j|.
        let row = projection_row(&seed, 0, 4);
        let weight: i128 = row.iter().map(|r| r.abs()).sum();
        let (target, coefficient) = row
            .iter()
            .enumerate()
            .max_by_key(|(_, r)| r.abs())
            .map(|(j, r)| (j, r.abs()))
            .unwrap();
        let error = (i128::from(tolerance) * weight / coefficient + 1) as u64;
        let mut transitions = vec![honest(&[10, 10, 10, 10])];
        transitions[0].observed.data[target] =
            transitions[0].observed.data[target].wrapping_add(error);
        assert_eq!(
            fused_audit(
                &AuditProfile::RandomizedHd { seed },
                &transitions,
                tolerance
            ),
            Err(AuditError::Tampered { transition: 0 })
        );
        // Errors within the declared tolerance stay accepted (approximate profile): a uniform
        // +1 shift satisfies |sum(r)| <= sum(|r|) < tolerance * sum(|r|).
        let mut inside = vec![honest(&[10, 10, 10, 10])];
        for value in &mut inside[0].observed.data {
            *value = value.wrapping_add(1);
        }
        assert!(fused_audit(&AuditProfile::RandomizedHd { seed }, &inside, tolerance).is_ok());
    }

    #[test]
    fn falsifier_stale_seed_is_rejected_even_for_orthogonal_errors() {
        let seed = [7u8; 32];
        let mut ledger = SeedLedger::default();
        let transitions = vec![honest(&[1, 2, 3, 4])];
        ledger.audit(seed, &transitions, 0).unwrap();
        // An adversary who learned the seed could craft a projection-orthogonal error; the
        // ledger rejects the stale seed before any projection runs.
        let row = projection_row(&seed, 0, 4);
        let mut crafted = honest(&[1, 2, 3, 4]);
        // d = (r1, -r0, 0, 0) is orthogonal to r: r0*r1 - r1*r0 = 0.
        crafted.observed.data[0] = crafted.observed.data[0].wrapping_add(row[1] as u64);
        crafted.observed.data[1] = crafted.observed.data[1].wrapping_sub(row[0] as u64);
        assert!(
            fused_audit(&AuditProfile::RandomizedHd { seed }, &[crafted.clone()], 0).is_ok(),
            "orthogonal error evades a known seed, which is exactly why seeds are single-use"
        );
        assert_eq!(
            ledger.audit(seed, &[crafted], 0),
            Err(AuditError::StaleSeed)
        );
    }

    #[test]
    fn falsifier_blockwise_h_never_substitutes_for_randomized_hd() {
        let transitions = vec![honest(&[1, 2, 3, 4])];
        let weak = fused_audit(&AuditProfile::DeterministicBlockH, &transitions, 0).unwrap();
        assert_eq!(
            require_randomized_hd(&weak),
            Err(AuditError::ProfileSubstitution)
        );
        let strong = fused_audit(
            &AuditProfile::RandomizedHd { seed: [1u8; 32] },
            &transitions,
            0,
        )
        .unwrap();
        assert_eq!(require_randomized_hd(&strong), Ok(()));
    }

    #[test]
    fn fused_acceptance_never_unlocks_exact_requantization() {
        let transitions = vec![honest(&[1, 2, 3, 4])];
        let acceptance = fused_audit(
            &AuditProfile::RandomizedHd { seed: [1u8; 32] },
            &transitions,
            0,
        )
        .unwrap();
        assert!(!acceptance.is_exact());
        assert_eq!(
            admit_for_requantization(&acceptance),
            Err(AuditError::NotExact)
        );
    }

    #[test]
    fn shape_mismatch_fails_closed() {
        let bad = Transition {
            committed: state(&[1, 2]),
            observed: state(&[1, 2, 3]),
        };
        assert_eq!(
            fused_audit(&AuditProfile::RandomizedHd { seed: [1u8; 32] }, &[bad], 0),
            Err(AuditError::Shape)
        );
    }
}
