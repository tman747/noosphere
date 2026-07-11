//! Exact random-residue verification for `M-RESIDUE`.
//!
//! The relation is exact prime-field matrix multiplication.  The claim and
//! every challenge are bound to canonical field encodings before the beacon;
//! challenge coordinates use rejection sampling rather than biased `% q`.

#![allow(clippy::arithmetic_side_effects)]

use crate::Hash32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const RESIDUE_CLAIM_DOMAIN: &[u8] = b"NOOS/RESIDUE/CLAIM/V1";
pub const RESIDUE_CHALLENGE_DOMAIN: &[u8] = b"NOOS/RESIDUE/CHALLENGE/V1";

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ResidueError {
    #[error("the residue profile is invalid or the modulus is not prime")]
    InvalidProfile,
    #[error("matrix dimensions or canonical field elements are invalid")]
    InvalidMatrix,
    #[error("matrix product shapes do not compose")]
    Shape,
    #[error("challenge was not finalized after the committed claim")]
    ChallengeTiming,
    #[error("challenge vector is reused, missing, or not canonically derived")]
    ChallengeMismatch,
    #[error("checked arithmetic overflow")]
    Overflow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidueProfile {
    pub profile_id: Hash32,
    pub modulus: u64,
    pub rounds: u16,
    pub challenge_domain: Hash32,
}

impl ResidueProfile {
    pub fn validate(&self) -> Result<(), ResidueError> {
        if self.profile_id == [0; 32]
            || self.challenge_domain == [0; 32]
            || self.rounds == 0
            || !is_prime(self.modulus)
        {
            return Err(ResidueError::InvalidProfile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldMatrix {
    pub rows: u32,
    pub cols: u32,
    /// Canonical row-major representatives in `[0, q)`.
    pub values: Vec<u64>,
}

impl FieldMatrix {
    pub fn validate(&self, modulus: u64) -> Result<(), ResidueError> {
        let expected = usize::try_from(self.rows)
            .ok()
            .and_then(|rows| {
                usize::try_from(self.cols)
                    .ok()
                    .and_then(|cols| rows.checked_mul(cols))
            })
            .ok_or(ResidueError::Overflow)?;
        if self.rows == 0
            || self.cols == 0
            || self.values.len() != expected
            || self.values.iter().any(|value| *value >= modulus)
        {
            return Err(ResidueError::InvalidMatrix);
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.rows.to_le_bytes());
        out.extend_from_slice(&self.cols.to_le_bytes());
        out.extend_from_slice(&(self.values.len() as u64).to_le_bytes());
        for value in &self.values {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedProduct {
    pub profile: ResidueProfile,
    pub a: FieldMatrix,
    pub b: FieldMatrix,
    pub c: FieldMatrix,
    pub committed_height: u64,
    pub claim_commitment: Hash32,
}

impl CommittedProduct {
    pub fn new(
        profile: ResidueProfile,
        a: FieldMatrix,
        b: FieldMatrix,
        c: FieldMatrix,
        committed_height: u64,
    ) -> Result<Self, ResidueError> {
        let mut claim = Self {
            profile,
            a,
            b,
            c,
            committed_height,
            claim_commitment: [0; 32],
        };
        claim.validate_relation_shape()?;
        claim.claim_commitment = claim.derive_commitment();
        Ok(claim)
    }

    pub fn validate(&self) -> Result<(), ResidueError> {
        self.validate_relation_shape()?;
        if self.claim_commitment != self.derive_commitment() {
            return Err(ResidueError::ChallengeMismatch);
        }
        Ok(())
    }

    fn validate_relation_shape(&self) -> Result<(), ResidueError> {
        self.profile.validate()?;
        self.a.validate(self.profile.modulus)?;
        self.b.validate(self.profile.modulus)?;
        self.c.validate(self.profile.modulus)?;
        if self.a.cols != self.b.rows || self.c.rows != self.a.rows || self.c.cols != self.b.cols {
            return Err(ResidueError::Shape);
        }
        Ok(())
    }

    fn derive_commitment(&self) -> Hash32 {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(RESIDUE_CLAIM_DOMAIN);
        encoded.extend_from_slice(&self.profile.profile_id);
        encoded.extend_from_slice(&self.profile.modulus.to_le_bytes());
        encoded.extend_from_slice(&self.profile.rounds.to_le_bytes());
        encoded.extend_from_slice(&self.profile.challenge_domain);
        encoded.extend_from_slice(&self.committed_height.to_le_bytes());
        self.a.encode_into(&mut encoded);
        self.b.encode_into(&mut encoded);
        self.c.encode_into(&mut encoded);
        *blake3::hash(&encoded).as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidueChallenges {
    pub claim_commitment: Hash32,
    pub beacon: Hash32,
    pub beacon_height: u64,
    pub vectors: Vec<Vec<u64>>,
}

impl ResidueChallenges {
    pub fn derive(
        claim: &CommittedProduct,
        beacon: Hash32,
        beacon_height: u64,
    ) -> Result<Self, ResidueError> {
        claim.validate()?;
        if beacon_height <= claim.committed_height {
            return Err(ResidueError::ChallengeTiming);
        }
        let width = usize::try_from(claim.c.cols).map_err(|_| ResidueError::Overflow)?;
        let vectors = (0..claim.profile.rounds)
            .map(|round| derive_vector(claim, beacon, beacon_height, round, width))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            claim_commitment: claim.claim_commitment,
            beacon,
            beacon_height,
            vectors,
        })
    }
}

/// Fast `A(Br) == Cr` verifier.  The independently structured residual-dot
/// oracle below is intentionally retained for differential evidence.
pub fn verify_product(
    claim: &CommittedProduct,
    challenges: &ResidueChallenges,
) -> Result<bool, ResidueError> {
    validate_challenges(claim, challenges)?;
    for vector in &challenges.vectors {
        if !verify_vector_fast(claim, vector)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Slow independent-style oracle: explicitly constructs every entry of
/// `D = AB-C` and then evaluates `D r`.  It shares only the field primitives,
/// not the fast verifier's evaluation order.
pub fn verify_product_reference(
    claim: &CommittedProduct,
    challenges: &ResidueChallenges,
) -> Result<bool, ResidueError> {
    validate_challenges(claim, challenges)?;
    let modulus = claim.profile.modulus;
    let rows = usize::try_from(claim.a.rows).map_err(|_| ResidueError::Overflow)?;
    let inner = usize::try_from(claim.a.cols).map_err(|_| ResidueError::Overflow)?;
    let cols = usize::try_from(claim.b.cols).map_err(|_| ResidueError::Overflow)?;
    for vector in &challenges.vectors {
        for row in 0..rows {
            let mut dot = 0_u64;
            for (col, challenge_value) in vector.iter().copied().enumerate().take(cols) {
                let mut product = 0_u64;
                for pivot in 0..inner {
                    product = add_mod(
                        product,
                        mul_mod(
                            claim.a.values[row * inner + pivot],
                            claim.b.values[pivot * cols + col],
                            modulus,
                        ),
                        modulus,
                    );
                }
                let residual = sub_mod(product, claim.c.values[row * cols + col], modulus);
                dot = add_mod(dot, mul_mod(residual, challenge_value, modulus), modulus);
            }
            if dot != 0 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn validate_challenges(
    claim: &CommittedProduct,
    challenges: &ResidueChallenges,
) -> Result<(), ResidueError> {
    claim.validate()?;
    if challenges.claim_commitment != claim.claim_commitment
        || challenges.beacon_height <= claim.committed_height
        || challenges.vectors.len() != usize::from(claim.profile.rounds)
    {
        return Err(ResidueError::ChallengeMismatch);
    }
    let width = usize::try_from(claim.c.cols).map_err(|_| ResidueError::Overflow)?;
    for (round, vector) in challenges.vectors.iter().enumerate() {
        let round = u16::try_from(round).map_err(|_| ResidueError::Overflow)?;
        let expected = derive_vector(
            claim,
            challenges.beacon,
            challenges.beacon_height,
            round,
            width,
        )?;
        if vector != &expected {
            return Err(ResidueError::ChallengeMismatch);
        }
    }
    Ok(())
}

fn verify_vector_fast(claim: &CommittedProduct, vector: &[u64]) -> Result<bool, ResidueError> {
    let modulus = claim.profile.modulus;
    let rows = usize::try_from(claim.a.rows).map_err(|_| ResidueError::Overflow)?;
    let inner = usize::try_from(claim.a.cols).map_err(|_| ResidueError::Overflow)?;
    let cols = usize::try_from(claim.b.cols).map_err(|_| ResidueError::Overflow)?;
    let mut br = vec![0_u64; inner];
    for (pivot, value) in br.iter_mut().enumerate() {
        for (col, challenge_value) in vector.iter().copied().enumerate().take(cols) {
            *value = add_mod(
                *value,
                mul_mod(claim.b.values[pivot * cols + col], challenge_value, modulus),
                modulus,
            );
        }
    }
    for row in 0..rows {
        let mut left = 0_u64;
        let mut right = 0_u64;
        for (pivot, value) in br.iter().enumerate() {
            left = add_mod(
                left,
                mul_mod(claim.a.values[row * inner + pivot], *value, modulus),
                modulus,
            );
        }
        for (col, challenge_value) in vector.iter().copied().enumerate().take(cols) {
            right = add_mod(
                right,
                mul_mod(claim.c.values[row * cols + col], challenge_value, modulus),
                modulus,
            );
        }
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn derive_vector(
    claim: &CommittedProduct,
    beacon: Hash32,
    beacon_height: u64,
    round: u16,
    width: usize,
) -> Result<Vec<u64>, ResidueError> {
    let mut vector = Vec::with_capacity(width);
    for coordinate in 0..width {
        vector.push(draw_uniform(
            claim,
            beacon,
            beacon_height,
            round,
            u32::try_from(coordinate).map_err(|_| ResidueError::Overflow)?,
        )?);
    }
    Ok(vector)
}

fn draw_uniform(
    claim: &CommittedProduct,
    beacon: Hash32,
    beacon_height: u64,
    round: u16,
    coordinate: u32,
) -> Result<u64, ResidueError> {
    let modulus = claim.profile.modulus;
    let zone = u64::MAX - (u64::MAX % modulus);
    for attempt in 0_u32..=u32::MAX {
        let mut hash = blake3::Hasher::new();
        hash.update(RESIDUE_CHALLENGE_DOMAIN);
        hash.update(&claim.profile.challenge_domain);
        hash.update(&claim.profile.profile_id);
        hash.update(&claim.claim_commitment);
        hash.update(&beacon);
        hash.update(&beacon_height.to_le_bytes());
        hash.update(&round.to_le_bytes());
        hash.update(&coordinate.to_le_bytes());
        hash.update(&attempt.to_le_bytes());
        let digest = hash.finalize();
        let mut word = [0_u8; 8];
        word.copy_from_slice(&digest.as_bytes()[..8]);
        let candidate = u64::from_le_bytes(word);
        if candidate < zone {
            return Ok(candidate % modulus);
        }
    }
    Err(ResidueError::Overflow)
}

fn add_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn sub_mod(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut out = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            out = mul_mod(out, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    out
}

fn is_prime(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    for prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if value == prime {
            return true;
        }
        if value.is_multiple_of(prime) {
            return false;
        }
    }
    let mut odd = value - 1;
    let shifts = odd.trailing_zeros();
    odd >>= shifts;
    // Deterministic Miller-Rabin bases for all u64 values.
    for base in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let reduced = base % value;
        if reduced == 0 {
            continue;
        }
        let mut witness = pow_mod(reduced, odd, value);
        if witness == 1 || witness == value - 1 {
            continue;
        }
        let mut composite = true;
        for _ in 1..shifts {
            witness = mul_mod(witness, witness, value);
            if witness == value - 1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(modulus: u64, rounds: u16) -> ResidueProfile {
        ResidueProfile {
            profile_id: [1; 32],
            modulus,
            rounds,
            challenge_domain: [2; 32],
        }
    }

    fn matrix(rows: u32, cols: u32, values: Vec<u64>) -> FieldMatrix {
        FieldMatrix { rows, cols, values }
    }

    fn product(modulus: u64, rounds: u16) -> CommittedProduct {
        CommittedProduct::new(
            profile(modulus, rounds),
            matrix(2, 3, vec![1, 2, 3, 4, 5, 6]),
            matrix(3, 2, vec![7, 8, 9, 10, 11, 12]),
            matrix(2, 2, vec![58, 64, 38, 53]),
            10,
        )
        .unwrap()
    }

    #[test]
    fn fast_and_reference_verifiers_agree_on_seeded_sweep() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for case in 0..1_024_u64 {
            state ^= state << 7;
            state ^= state >> 9;
            state ^= state << 8;
            let mut claim = product(101, 4);
            if case % 3 != 0 {
                let index = (state as usize) % claim.c.values.len();
                claim.c.values[index] = (claim.c.values[index] + 1 + case % 100) % 101;
                claim.claim_commitment = claim.derive_commitment();
            }
            let challenges = ResidueChallenges::derive(
                &claim,
                state.to_le_bytes().repeat(4).try_into().unwrap(),
                11,
            )
            .unwrap();
            assert_eq!(
                verify_product(&claim, &challenges).unwrap(),
                verify_product_reference(&claim, &challenges).unwrap()
            );
        }
    }

    #[test]
    fn exhaustive_f3_rank_bound_and_exact_probability() {
        let p = profile(3, 1);
        let zero = matrix(2, 2, vec![0; 4]);
        for encoded in 1_u64..81 {
            let mut cursor = encoded;
            let mut values = Vec::with_capacity(4);
            for _ in 0..4 {
                values.push(cursor % 3);
                cursor /= 3;
            }
            let rank = if (values[0] * values[3] + 3 - values[1] * values[2] % 3) % 3 != 0 {
                2_u32
            } else {
                1_u32
            };
            let claim = CommittedProduct::new(
                p.clone(),
                matrix(2, 2, values.clone()),
                matrix(2, 2, vec![1, 0, 0, 1]),
                zero.clone(),
                1,
            )
            .unwrap();
            let accepted = (0_u64..9)
                .filter(|vector| {
                    let r = [vector % 3, vector / 3];
                    (0..2).all(|row| (values[row * 2] * r[0] + values[row * 2 + 1] * r[1]) % 3 == 0)
                })
                .count();
            assert_eq!(accepted, 3_usize.pow(2 - rank));
            assert!(accepted <= 3);
            assert!(claim.validate().is_ok());
        }
    }

    #[test]
    fn characteristic_two_is_an_exact_field_not_an_hdf_claim() {
        let claim = CommittedProduct::new(
            profile(2, 3),
            matrix(1, 2, vec![1, 1]),
            matrix(2, 1, vec![1, 0]),
            matrix(1, 1, vec![1]),
            4,
        )
        .unwrap();
        let challenges = ResidueChallenges::derive(&claim, [9; 32], 5).unwrap();
        assert!(verify_product(&claim, &challenges).unwrap());
        assert!(verify_product_reference(&claim, &challenges).unwrap());
    }

    #[test]
    fn aliases_composites_timing_and_challenge_tamper_reject() {
        assert_eq!(profile(15, 1).validate(), Err(ResidueError::InvalidProfile));
        let mut claim = product(101, 2);
        claim.c.values[0] += 101;
        assert_eq!(claim.validate(), Err(ResidueError::InvalidMatrix));

        let claim = product(101, 2);
        assert_eq!(
            ResidueChallenges::derive(&claim, [3; 32], 10),
            Err(ResidueError::ChallengeTiming)
        );
        let mut challenges = ResidueChallenges::derive(&claim, [3; 32], 11).unwrap();
        challenges.vectors[0][0] = (challenges.vectors[0][0] + 1) % 101;
        assert_eq!(
            verify_product(&claim, &challenges),
            Err(ResidueError::ChallengeMismatch)
        );
    }

    #[test]
    fn prechallenge_adaptive_error_is_a_real_falsifier() {
        let honest = product(101, 1);
        let challenges = ResidueChallenges::derive(&honest, [8; 32], 11).unwrap();
        let r = &challenges.vectors[0];
        let mut adaptive = honest.clone();
        // d=(r1,-r0) is nonzero and orthogonal to the known challenge.
        adaptive.c.values[0] = (adaptive.c.values[0] + r[1]) % 101;
        adaptive.c.values[1] = (adaptive.c.values[1] + 101 - r[0]) % 101;
        adaptive.claim_commitment = adaptive.derive_commitment();
        let forged = ResidueChallenges {
            claim_commitment: adaptive.claim_commitment,
            ..challenges
        };
        // Canonical post-commit derivation changes when the claim changes, so
        // replaying the known vector is rejected before the algebraic check.
        assert_eq!(
            verify_product(&adaptive, &forged),
            Err(ResidueError::ChallengeMismatch)
        );
    }
}
