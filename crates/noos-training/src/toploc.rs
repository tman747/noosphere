use noos_species::{domain_hash, Hash32};

use crate::TrainingError;

const SEED_DOMAIN: &str = "NOOS/TOPLOC/SEED/V1";
const PROJECTION_DOMAIN: &str = "NOOS/TOPLOC/PROJECTION/V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToplocProfile {
    pub model_id: Hash32,
    pub numeric_profile: Hash32,
    pub seed_commitment: Hash32,
    pub projection_count: u16,
    pub maximum_mismatches: u16,
    pub false_positive_sla_bps: u16,
}

impl ToplocProfile {
    pub fn validate(&self) -> Result<(), TrainingError> {
        if self.model_id == [0; 32]
            || self.numeric_profile == [0; 32]
            || self.seed_commitment == [0; 32]
            || self.projection_count == 0
            || self.projection_count > 256
            || self.maximum_mismatches >= self.projection_count
            || self.false_positive_sla_bps > 10_000
        {
            Err(TrainingError::InvalidToplocProfile)
        } else {
            Ok(())
        }
    }
}

#[must_use]
pub fn commit_seed(seed: Hash32) -> Hash32 {
    domain_hash(SEED_DOMAIN, &[&seed])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToplocFingerprint {
    pub model_id: Hash32,
    pub numeric_profile: Hash32,
    pub seed_commitment: Hash32,
    pub hidden_width: u32,
    pub projection_count: u16,
    pub projection_bits: [u8; 32],
}

pub fn fingerprint(
    profile: ToplocProfile,
    revealed_seed: Hash32,
    hidden_state: &[i16],
) -> Result<ToplocFingerprint, TrainingError> {
    profile.validate()?;
    if commit_seed(revealed_seed) != profile.seed_commitment || hidden_state.is_empty() {
        return Err(TrainingError::ToplocSeedSubstitution);
    }
    let hidden_width = u32::try_from(hidden_state.len()).map_err(|_| TrainingError::ToplocWidth)?;
    let mut projection_bits = [0_u8; 32];
    for projection in 0..profile.projection_count {
        let mut sum = 0_i128;
        for (index, activation) in hidden_state.iter().enumerate() {
            let coefficient = domain_hash(
                PROJECTION_DOMAIN,
                &[
                    &revealed_seed,
                    &projection.to_be_bytes(),
                    &u32::try_from(index)
                        .map_err(|_| TrainingError::ToplocWidth)?
                        .to_be_bytes(),
                ],
            );
            let sign = if coefficient[0] & 1 == 0 {
                -1_i128
            } else {
                1_i128
            };
            sum = sum
                .checked_add(sign.saturating_mul(i128::from(*activation)))
                .ok_or(TrainingError::ToplocArithmetic)?;
        }
        if sum >= 0 {
            let byte = usize::from(projection / 8);
            let bit = u8::try_from(projection % 8).map_err(|_| TrainingError::ToplocWidth)?;
            projection_bits[byte] |= 1_u8 << bit;
        }
    }
    Ok(ToplocFingerprint {
        model_id: profile.model_id,
        numeric_profile: profile.numeric_profile,
        seed_commitment: profile.seed_commitment,
        hidden_width,
        projection_count: profile.projection_count,
        projection_bits,
    })
}

pub fn mismatch_count(
    profile: ToplocProfile,
    expected: &ToplocFingerprint,
    observed: &ToplocFingerprint,
) -> Result<u16, TrainingError> {
    profile.validate()?;
    if expected.model_id != profile.model_id
        || observed.model_id != profile.model_id
        || expected.numeric_profile != profile.numeric_profile
        || observed.numeric_profile != profile.numeric_profile
        || expected.seed_commitment != profile.seed_commitment
        || observed.seed_commitment != profile.seed_commitment
        || expected.hidden_width != observed.hidden_width
        || expected.projection_count != profile.projection_count
        || observed.projection_count != profile.projection_count
    {
        return Err(TrainingError::ToplocProfileSubstitution);
    }
    let mismatches = expected
        .projection_bits
        .iter()
        .zip(observed.projection_bits)
        .map(|(left, right)| (left ^ right).count_ones())
        .sum::<u32>();
    u16::try_from(mismatches).map_err(|_| TrainingError::ToplocArithmetic)
}

pub fn verifies_execution(
    profile: ToplocProfile,
    expected: &ToplocFingerprint,
    observed: &ToplocFingerprint,
) -> Result<bool, TrainingError> {
    Ok(mismatch_count(profile, expected, observed)? <= profile.maximum_mismatches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn profile(seed: Hash32) -> ToplocProfile {
        ToplocProfile {
            model_id: h(1),
            numeric_profile: h(2),
            seed_commitment: commit_seed(seed),
            projection_count: 128,
            maximum_mismatches: 4,
            false_positive_sla_bps: 100,
        }
    }

    #[test]
    fn claim_toploc_seed_is_fixed_after_commitment_and_profiles_are_bound() {
        let seed = h(3);
        let profile = profile(seed);
        let expected = fingerprint(profile, seed, &[10, -3, 9, 2, -7, 4]).unwrap();
        assert!(verifies_execution(profile, &expected, &expected).unwrap());
        assert_eq!(
            fingerprint(profile, h(4), &[10, -3, 9, 2, -7, 4]),
            Err(TrainingError::ToplocSeedSubstitution)
        );
        let mut substituted = expected.clone();
        substituted.model_id = h(9);
        assert_eq!(
            verifies_execution(profile, &expected, &substituted),
            Err(TrainingError::ToplocProfileSubstitution)
        );
    }

    #[test]
    fn claim_toploc_cheaper_generation_plus_target_prefill_is_detected_locally() {
        let seed = h(5);
        let profile = profile(seed);
        // The first two coordinates model copied target-prefill state while the
        // remaining named-model hidden state is substituted.
        let named_model = fingerprint(
            profile,
            seed,
            &[1, -1, 900, 800, 700, 600, 500, 400, 300, 200],
        )
        .unwrap();
        let cheaper_with_prefill = fingerprint(
            profile,
            seed,
            &[1, -1, -900, -800, -700, -600, -500, -400, -300, -200],
        )
        .unwrap();
        let mismatches = mismatch_count(profile, &named_model, &cheaper_with_prefill).unwrap();
        assert!(mismatches > profile.maximum_mismatches);
        assert!(!verifies_execution(profile, &named_model, &cheaper_with_prefill).unwrap());
    }
}
