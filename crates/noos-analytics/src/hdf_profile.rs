//! Profile-bound wrapper for the surviving `M-HDF-ENERGY` theorem.
//!
//! `M-HDF` and `S-HDF` remain retired.  This wrapper only exposes a
//! precommitted, shadow-mode energy observation for one immutable model and
//! numeric profile; challenges are derived after commitment and cannot be
//! caller-selected or spliced between profiles.

#![allow(clippy::arithmetic_side_effects)]

use crate::{
    estimate_hdf_energy, AnalyticsError, EnergyChallenge, EnergyEstimate, Hash32, IntegerResidual,
    ShadowObservation,
};
use serde::{Deserialize, Serialize};

pub const S_HDF_STATUS: &str = "RETIRED";
pub const HDF_ENERGY_MODE: &str = "SHADOW_ONLY";
pub const HDF_PROFILE_DOMAIN: &[u8] = b"NOOS/ANALYTICS/HDF-PROFILE/V1";
pub const HDF_ROW_SIGN_DOMAIN: &[u8] = b"NOOS/ANALYTICS/HDF-ROW-SIGN/V1";
pub const HDF_COL_SIGN_DOMAIN: &[u8] = b"NOOS/ANALYTICS/HDF-COL-SIGN/V1";
pub const HDF_SAMPLE_DOMAIN: &[u8] = b"NOOS/ANALYTICS/HDF-SAMPLE/V1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivingModelHdfProfile {
    pub profile_id: Hash32,
    pub model_root: Hash32,
    pub numeric_profile: Hash32,
    pub rows: u32,
    pub cols: u32,
    pub sample_count: u32,
    /// Must be the exact literal `SHADOW_ONLY`.
    pub mode: String,
}

impl LivingModelHdfProfile {
    pub fn validate(&self) -> Result<(), AnalyticsError> {
        if self.profile_id == [0; 32]
            || self.model_root == [0; 32]
            || self.numeric_profile == [0; 32]
            || self.rows == 0
            || self.cols == 0
            || !self.rows.is_power_of_two()
            || !self.cols.is_power_of_two()
            || self.sample_count == 0
            || self.mode != HDF_ENERGY_MODE
            || self.profile_id != self.derive_id()
        {
            return Err(AnalyticsError::InvalidDimensions);
        }
        Ok(())
    }

    #[must_use]
    pub fn derive_id(&self) -> Hash32 {
        let mut hash = blake3::Hasher::new();
        hash.update(HDF_PROFILE_DOMAIN);
        hash.update(&self.model_root);
        hash.update(&self.numeric_profile);
        hash.update(&self.rows.to_le_bytes());
        hash.update(&self.cols.to_le_bytes());
        hash.update(&self.sample_count.to_le_bytes());
        hash.update(HDF_ENERGY_MODE.as_bytes());
        *hash.finalize().as_bytes()
    }

    #[must_use]
    pub fn new(
        model_root: Hash32,
        numeric_profile: Hash32,
        rows: u32,
        cols: u32,
        sample_count: u32,
    ) -> Self {
        let mut profile = Self {
            profile_id: [0; 32],
            model_root,
            numeric_profile,
            rows,
            cols,
            sample_count,
            mode: HDF_ENERGY_MODE.to_owned(),
        };
        profile.profile_id = profile.derive_id();
        profile
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfiledResidual {
    pub profile_id: Hash32,
    pub model_root: Hash32,
    pub numeric_profile: Hash32,
    pub residual: IntegerResidual,
    pub residual_commitment: Hash32,
    pub committed_height: u64,
}

impl ProfiledResidual {
    pub fn new(
        profile: &LivingModelHdfProfile,
        residual: IntegerResidual,
        committed_height: u64,
    ) -> Result<Self, AnalyticsError> {
        profile.validate()?;
        if residual.rows != profile.rows || residual.cols != profile.cols {
            return Err(AnalyticsError::InvalidDimensions);
        }
        let residual_commitment = residual.commitment()?;
        Ok(Self {
            profile_id: profile.profile_id,
            model_root: profile.model_root,
            numeric_profile: profile.numeric_profile,
            residual,
            residual_commitment,
            committed_height,
        })
    }

    fn validate(&self, profile: &LivingModelHdfProfile) -> Result<(), AnalyticsError> {
        profile.validate()?;
        if self.profile_id != profile.profile_id
            || self.model_root != profile.model_root
            || self.numeric_profile != profile.numeric_profile
            || self.residual.rows != profile.rows
            || self.residual.cols != profile.cols
            || self.residual.commitment()? != self.residual_commitment
        {
            return Err(AnalyticsError::Precommitment);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfiledEnergyChallenge {
    pub profile_id: Hash32,
    pub residual_commitment: Hash32,
    pub beacon: Hash32,
    pub beacon_height: u64,
    pub challenge: EnergyChallenge,
}

impl ProfiledEnergyChallenge {
    pub fn derive(
        profile: &LivingModelHdfProfile,
        residual: &ProfiledResidual,
        beacon: Hash32,
        beacon_height: u64,
    ) -> Result<Self, AnalyticsError> {
        residual.validate(profile)?;
        if beacon == [0; 32] || beacon_height <= residual.committed_height {
            return Err(AnalyticsError::Precommitment);
        }
        let row_signs = (0..profile.rows)
            .map(|index| {
                derive_sign(
                    HDF_ROW_SIGN_DOMAIN,
                    profile,
                    residual,
                    beacon,
                    beacon_height,
                    index,
                )
            })
            .collect();
        let col_signs = (0..profile.cols)
            .map(|index| {
                derive_sign(
                    HDF_COL_SIGN_DOMAIN,
                    profile,
                    residual,
                    beacon,
                    beacon_height,
                    index,
                )
            })
            .collect();
        let samples = (0..profile.sample_count)
            .map(|index| {
                (
                    derive_index(
                        profile,
                        residual,
                        beacon,
                        beacon_height,
                        index,
                        0,
                        profile.rows,
                    ),
                    derive_index(
                        profile,
                        residual,
                        beacon,
                        beacon_height,
                        index,
                        1,
                        profile.cols,
                    ),
                )
            })
            .collect();
        Ok(Self {
            profile_id: profile.profile_id,
            residual_commitment: residual.residual_commitment,
            beacon,
            beacon_height,
            challenge: EnergyChallenge {
                residual_commitment: residual.residual_commitment,
                row_signs,
                col_signs,
                samples,
            },
        })
    }
}

pub fn audit_living_model_energy(
    profile: &LivingModelHdfProfile,
    residual: &ProfiledResidual,
    challenge: &ProfiledEnergyChallenge,
) -> Result<ShadowObservation<EnergyEstimate>, AnalyticsError> {
    residual.validate(profile)?;
    let expected = ProfiledEnergyChallenge::derive(
        profile,
        residual,
        challenge.beacon,
        challenge.beacon_height,
    )?;
    if challenge != &expected {
        return Err(AnalyticsError::Precommitment);
    }
    estimate_hdf_energy(&residual.residual, &challenge.challenge)
}

fn derive_sign(
    domain: &[u8],
    profile: &LivingModelHdfProfile,
    residual: &ProfiledResidual,
    beacon: Hash32,
    beacon_height: u64,
    index: u32,
) -> i8 {
    let digest = derive_digest(domain, profile, residual, beacon, beacon_height, index, 0);
    if digest[0] & 1 == 0 {
        -1
    } else {
        1
    }
}

fn derive_index(
    profile: &LivingModelHdfProfile,
    residual: &ProfiledResidual,
    beacon: Hash32,
    beacon_height: u64,
    sample: u32,
    axis: u8,
    bound: u32,
) -> u32 {
    // Power-of-two dimensions make low-bit reduction exactly uniform under a
    // uniform digest; there is no modulo bias.
    let digest = derive_digest(
        HDF_SAMPLE_DOMAIN,
        profile,
        residual,
        beacon,
        beacon_height,
        sample,
        axis,
    );
    let mut word = [0_u8; 4];
    word.copy_from_slice(&digest[..4]);
    u32::from_le_bytes(word) & (bound - 1)
}

fn derive_digest(
    domain: &[u8],
    profile: &LivingModelHdfProfile,
    residual: &ProfiledResidual,
    beacon: Hash32,
    beacon_height: u64,
    index: u32,
    axis: u8,
) -> Hash32 {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(&profile.profile_id);
    hash.update(&profile.model_root);
    hash.update(&profile.numeric_profile);
    hash.update(&residual.residual_commitment);
    hash.update(&beacon);
    hash.update(&beacon_height.to_le_bytes());
    hash.update(&index.to_le_bytes());
    hash.update(&[axis]);
    *hash.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(samples: u32) -> LivingModelHdfProfile {
        LivingModelHdfProfile::new([1; 32], [2; 32], 4, 4, samples)
    }

    fn residual(values: Vec<i64>) -> IntegerResidual {
        IntegerResidual {
            rows: 4,
            cols: 4,
            values,
        }
    }

    #[test]
    fn profile_challenge_is_deterministic_and_postcommit() {
        let profile = profile(8);
        let committed = ProfiledResidual::new(&profile, residual((0..16).collect()), 9).unwrap();
        let first = ProfiledEnergyChallenge::derive(&profile, &committed, [3; 32], 10).unwrap();
        let second = ProfiledEnergyChallenge::derive(&profile, &committed, [3; 32], 10).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            ProfiledEnergyChallenge::derive(&profile, &committed, [3; 32], 9),
            Err(AnalyticsError::Precommitment)
        );
    }

    #[test]
    fn model_numeric_profile_and_challenge_splices_reject() {
        let profile = profile(4);
        let committed = ProfiledResidual::new(&profile, residual(vec![1; 16]), 1).unwrap();
        let mut challenge =
            ProfiledEnergyChallenge::derive(&profile, &committed, [3; 32], 2).unwrap();
        let other_profile = LivingModelHdfProfile::new([9; 32], [2; 32], 4, 4, 4);
        assert_eq!(
            audit_living_model_energy(&other_profile, &committed, &challenge),
            Err(AnalyticsError::Precommitment)
        );
        challenge.challenge.samples[0].0 ^= 1;
        assert_eq!(
            audit_living_model_energy(&profile, &committed, &challenge),
            Err(AnalyticsError::Precommitment)
        );
    }

    #[test]
    fn exact_integer_transform_conserves_energy_for_seeded_sign_sweep() {
        let profile = profile(16);
        let committed = ProfiledResidual::new(
            &profile,
            residual(vec![
                1, -2, 3, -4, 5, 6, -7, 8, 9, -10, 11, 12, -13, 14, 15, -16,
            ]),
            20,
        )
        .unwrap();
        let expected_energy = committed
            .residual
            .values
            .iter()
            .map(|value| i128::from(*value).unsigned_abs().pow(2))
            .sum::<u128>();
        // Replace the derived coordinate multiset with every coordinate while
        // retaining independently derived signs; this test is inside the slow
        // theorem oracle, not the public wrapper.
        for seed in 1_u8..=64 {
            let mut challenge =
                ProfiledEnergyChallenge::derive(&profile, &committed, [seed; 32], 21).unwrap();
            challenge.challenge.samples = (0..4)
                .flat_map(|row| (0..4).map(move |col| (row, col)))
                .collect();
            let observed = estimate_hdf_energy(&committed.residual, &challenge.challenge).unwrap();
            assert_eq!(observed.value.numerator / 16, expected_energy);
        }
    }

    #[test]
    fn retired_specialized_claim_cannot_be_confused_with_survivor() {
        assert_eq!(S_HDF_STATUS, "RETIRED");
        assert_eq!(HDF_ENERGY_MODE, "SHADOW_ONLY");
        let profile = profile(4);
        let committed = ProfiledResidual::new(&profile, residual(vec![1; 16]), 1).unwrap();
        let challenge = ProfiledEnergyChallenge::derive(&profile, &committed, [7; 32], 2).unwrap();
        let observation = audit_living_model_energy(&profile, &committed, &challenge).unwrap();
        assert!(!observation.value.universal_dominance);
        assert!(!observation.value.exact_freivalds_amplification);
    }

    #[test]
    fn exhaustive_two_by_two_unbiasedness_and_variance_boundary() {
        for encoded in 0_u32..81 {
            let mut cursor = encoded;
            let values = (0..4)
                .map(|_| {
                    let value = i64::from(cursor % 3) - 1;
                    cursor /= 3;
                    value
                })
                .collect::<Vec<_>>();
            if values.iter().all(|value| *value == 0) {
                continue;
            }
            let residual = IntegerResidual {
                rows: 2,
                cols: 2,
                values,
            };
            let commitment = residual.commitment().unwrap();
            let energy = residual
                .values
                .iter()
                .map(|value| i128::from(*value).unsigned_abs().pow(2))
                .sum::<u128>();
            let mut observations = Vec::with_capacity(64);
            for sign_bits in 0_u8..16 {
                let row_signs = vec![
                    if sign_bits & 1 == 0 { -1 } else { 1 },
                    if sign_bits & 2 == 0 { -1 } else { 1 },
                ];
                let col_signs = vec![
                    if sign_bits & 4 == 0 { -1 } else { 1 },
                    if sign_bits & 8 == 0 { -1 } else { 1 },
                ];
                for sample in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                    let challenge = EnergyChallenge {
                        residual_commitment: commitment,
                        row_signs: row_signs.clone(),
                        col_signs: col_signs.clone(),
                        samples: vec![sample],
                    };
                    observations.push(
                        estimate_hdf_energy(&residual, &challenge)
                            .unwrap()
                            .value
                            .numerator,
                    );
                }
            }
            let count = observations.len() as u128;
            let sum = observations.iter().sum::<u128>();
            let sum_squares = observations.iter().map(|value| value.pow(2)).sum::<u128>();
            assert_eq!(sum, energy * count, "unbiasedness must be exact");
            let variance_numerator = sum_squares * count - sum.pow(2);
            assert!(
                variance_numerator <= 8 * energy.pow(2) * count.pow(2),
                "the frozen dimension-free variance boundary must hold"
            );
        }
    }
}
