//! Experimental analytics with no authority over base consensus.
//!
//! `M-HDF` is retired. This crate exposes only the narrower
//! `M-HDF-ENERGY` estimator and shadow-only algorithm calibration. Outputs are
//! observations, never state-transition, issuance, proposal, or finality inputs.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub mod hdf_profile;
pub mod residue;
pub mod tensor;

pub type Hash32 = [u8; 32];

pub const M_HDF_STATUS: &str = "RETIRED";
pub const M_HDF_ENERGY_PROFILE: &str = "M-HDF-ENERGY";
pub const M_OMEGA_MODE: &str = "SHADOW_ONLY";
pub const STALE_PROFILE_CREDIT: &str = "ZERO_SHADOW_CREDIT";
pub const HDF_COMMIT_DOMAIN: &[u8] = b"NOOS/ANALYTICS/HDF-RESIDUAL/V1";
pub const CALIBRATION_DOMAIN: &[u8] = b"NOOS/ANALYTICS/FMM-CALIBRATION/V1";

/// An experimental observation. There is deliberately no conversion from this
/// type to any consensus weight, token amount, or state delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowObservation<T> {
    pub experiment_id: Hash32,
    pub value: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AnalyticsError {
    #[error("M-HDF is RETIRED; only M-HDF-ENERGY is implemented")]
    RetiredUniversalHdf,
    #[error("residual dimensions must be nonzero powers of two")]
    InvalidDimensions,
    #[error("residual size does not match dimensions")]
    ResidualSize,
    #[error("challenge signs must be independent complete Rademacher vectors")]
    InvalidSigns,
    #[error("sample set is empty or contains an out-of-range coordinate")]
    InvalidSamples,
    #[error("challenge does not follow the committed residual")]
    Precommitment,
    #[error("checked integer arithmetic overflow")]
    Overflow,
    #[error("measurement must be nonzero")]
    ZeroMeasurement,
    #[error("duplicate implementation-family reproduction")]
    DuplicateReproducer,
    #[error("reproductions differ by more than ten percent")]
    ReproductionMismatch,
    #[error("profile IDs are immutable and cannot be recalibrated in place")]
    DuplicateProfile,
    #[error("unknown profile")]
    UnknownProfile,
    #[error("submission ID already exists in this immutable profile")]
    DuplicateSubmission,
    #[error("reproduction does not bind the challenged profile, strategy, or whole attempt")]
    ReproductionBindingMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerResidual {
    pub rows: u32,
    pub cols: u32,
    /// Canonical row-major signed integer residuals, fixed before challenge.
    pub values: Vec<i64>,
}

impl IntegerResidual {
    pub fn validate(&self) -> Result<(), AnalyticsError> {
        if self.rows == 0
            || self.cols == 0
            || !self.rows.is_power_of_two()
            || !self.cols.is_power_of_two()
        {
            return Err(AnalyticsError::InvalidDimensions);
        }
        let expected = usize::try_from(self.rows)
            .ok()
            .and_then(|r| {
                usize::try_from(self.cols)
                    .ok()
                    .and_then(|c| r.checked_mul(c))
            })
            .ok_or(AnalyticsError::Overflow)?;
        if self.values.len() != expected {
            return Err(AnalyticsError::ResidualSize);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, AnalyticsError> {
        self.validate()?;
        let mut h = blake3::Hasher::new();
        h.update(HDF_COMMIT_DOMAIN);
        h.update(&self.rows.to_le_bytes());
        h.update(&self.cols.to_le_bytes());
        for value in &self.values {
            h.update(&value.to_le_bytes());
        }
        Ok(*h.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnergyChallenge {
    pub residual_commitment: Hash32,
    /// Must contain only -1 or +1 and be generated independently per axis.
    pub row_signs: Vec<i8>,
    pub col_signs: Vec<i8>,
    /// Independent uniform samples with replacement.
    pub samples: Vec<(u32, u32)>,
}

/// Exact rational estimate `numerator / denominator` of residual energy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnergyEstimate {
    pub numerator: u128,
    pub denominator: u64,
    pub residual_energy: u128,
    /// The proved dimension-free upper bound numerator in
    /// `variance <= variance_bound_numerator / variance_bound_denominator`.
    pub variance_bound_numerator: u128,
    pub variance_bound_denominator: u64,
    pub claim: String,
    pub universal_dominance: bool,
    pub exact_freivalds_amplification: bool,
}

/// Evaluate the proved `M-HDF-ENERGY` profile with an exact unnormalized
/// integer Walsh-Hadamard transform. Since normalized `Z` divides transformed
/// values by `sqrt(rows*cols)`, the theorem's `rows*cols` factor cancels and
/// the energy estimate is exactly `sum(sample_square) / sample_count`.
pub(crate) fn estimate_hdf_energy(
    residual: &IntegerResidual,
    challenge: &EnergyChallenge,
) -> Result<ShadowObservation<EnergyEstimate>, AnalyticsError> {
    residual.validate()?;
    if residual.commitment()? != challenge.residual_commitment {
        return Err(AnalyticsError::Precommitment);
    }
    let rows = usize::try_from(residual.rows).map_err(|_| AnalyticsError::Overflow)?;
    let cols = usize::try_from(residual.cols).map_err(|_| AnalyticsError::Overflow)?;
    if challenge.row_signs.len() != rows
        || challenge.col_signs.len() != cols
        || challenge.row_signs.iter().any(|s| !matches!(s, -1 | 1))
        || challenge.col_signs.iter().any(|s| !matches!(s, -1 | 1))
    {
        return Err(AnalyticsError::InvalidSigns);
    }
    if challenge.samples.is_empty()
        || challenge
            .samples
            .iter()
            .any(|(r, c)| *r >= residual.rows || *c >= residual.cols)
    {
        return Err(AnalyticsError::InvalidSamples);
    }

    let mut transformed: Vec<i128> = residual.values.iter().map(|v| i128::from(*v)).collect();
    for r in 0..rows {
        for c in 0..cols {
            let index = r
                .checked_mul(cols)
                .and_then(|v| v.checked_add(c))
                .ok_or(AnalyticsError::Overflow)?;
            let signed = transformed[index]
                .checked_mul(i128::from(challenge.row_signs[r]))
                .and_then(|v| v.checked_mul(i128::from(challenge.col_signs[c])))
                .ok_or(AnalyticsError::Overflow)?;
            transformed[index] = signed;
        }
    }
    for r in 0..rows {
        let start = r.checked_mul(cols).ok_or(AnalyticsError::Overflow)?;
        let end = start.checked_add(cols).ok_or(AnalyticsError::Overflow)?;
        fwht(&mut transformed[start..end])?;
    }
    for c in 0..cols {
        let mut column = Vec::with_capacity(rows);
        for r in 0..rows {
            let index = r
                .checked_mul(cols)
                .and_then(|v| v.checked_add(c))
                .ok_or(AnalyticsError::Overflow)?;
            column.push(transformed[index]);
        }
        fwht(&mut column)?;
        for (r, value) in column.into_iter().enumerate() {
            let index = r
                .checked_mul(cols)
                .and_then(|v| v.checked_add(c))
                .ok_or(AnalyticsError::Overflow)?;
            transformed[index] = value;
        }
    }

    let mut sampled_squares = 0_u128;
    for (r, c) in &challenge.samples {
        let index = usize::try_from(*r)
            .ok()
            .and_then(|rr| rr.checked_mul(cols))
            .and_then(|base| usize::try_from(*c).ok().and_then(|cc| base.checked_add(cc)))
            .ok_or(AnalyticsError::Overflow)?;
        let absolute = transformed[index].unsigned_abs();
        let square = absolute
            .checked_mul(absolute)
            .ok_or(AnalyticsError::Overflow)?;
        sampled_squares = sampled_squares
            .checked_add(square)
            .ok_or(AnalyticsError::Overflow)?;
    }
    let residual_energy = residual
        .values
        .iter()
        .try_fold(0_u128, |sum, value| {
            let absolute = i128::from(*value).unsigned_abs();
            sum.checked_add(absolute.checked_mul(absolute)?)
        })
        .ok_or(AnalyticsError::Overflow)?;
    let variance_numerator = residual_energy
        .checked_mul(residual_energy)
        .and_then(|v| v.checked_mul(8))
        .ok_or(AnalyticsError::Overflow)?;
    let sample_count =
        u64::try_from(challenge.samples.len()).map_err(|_| AnalyticsError::Overflow)?;

    let mut id = blake3::Hasher::new();
    id.update(HDF_COMMIT_DOMAIN);
    id.update(&challenge.residual_commitment);
    for sign in &challenge.row_signs {
        id.update(&sign.to_le_bytes());
    }
    for sign in &challenge.col_signs {
        id.update(&sign.to_le_bytes());
    }
    for (r, c) in &challenge.samples {
        id.update(&r.to_le_bytes());
        id.update(&c.to_le_bytes());
    }

    Ok(ShadowObservation {
        experiment_id: *id.finalize().as_bytes(),
        value: EnergyEstimate {
            numerator: sampled_squares,
            denominator: sample_count,
            residual_energy,
            variance_bound_numerator: variance_numerator,
            variance_bound_denominator: sample_count,
            claim: M_HDF_ENERGY_PROFILE.to_owned(),
            universal_dominance: false,
            exact_freivalds_amplification: false,
        },
    })
}

fn fwht(values: &mut [i128]) -> Result<(), AnalyticsError> {
    let mut width = 1_usize;
    while width < values.len() {
        let stride = width.checked_mul(2).ok_or(AnalyticsError::Overflow)?;
        for base in (0..values.len()).step_by(stride) {
            for offset in 0..width {
                let left = base.checked_add(offset).ok_or(AnalyticsError::Overflow)?;
                let right = left.checked_add(width).ok_or(AnalyticsError::Overflow)?;
                let a = values[left];
                let b = values[right];
                values[left] = a.checked_add(b).ok_or(AnalyticsError::Overflow)?;
                values[right] = a.checked_sub(b).ok_or(AnalyticsError::Overflow)?;
            }
        }
        width = stride;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlgorithmFamily {
    Naive,
    Tiled,
    StrassenFamily,
    FftFmm,
    CachedOperand,
    SparseStructured,
    DiagonalStructured,
    LowRankStructured,
    OutputOnly,
    CustomHardware,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WholeAttemptMeasurement {
    pub profile_id: Hash32,
    pub submission_id: Hash32,
    pub family: AlgorithmFamily,
    pub implementation_family: String,
    pub credited_work: u128,
    pub energy_microjoules: u128,
    pub latency_micros: u64,
    pub commitment_and_proof_included: bool,
    pub deliverable_materialized: bool,
}

impl WholeAttemptMeasurement {
    fn validate(&self) -> Result<(), AnalyticsError> {
        if self.credited_work == 0 || self.energy_microjoules == 0 || self.latency_micros == 0 {
            return Err(AnalyticsError::ZeroMeasurement);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowCredit {
    Calibrated,
    Zero {
        literal: String,
        reason: CreditZeroReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditZeroReason {
    MaterialChallenge,
    MoreThanOnePointZeroFiveAdvantage,
    MissingWholeAttempt,
    DemandStarvation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationProfile {
    pub profile_id: Hash32,
    pub baseline: WholeAttemptMeasurement,
    pub measurements: BTreeMap<Hash32, WholeAttemptMeasurement>,
    pub independent_reproducers: BTreeMap<Hash32, BTreeSet<String>>,
    pub credit: ShadowCredit,
}

#[derive(Default)]
pub struct ShadowAuction {
    profiles: BTreeMap<Hash32, CalibrationProfile>,
}

impl ShadowAuction {
    pub fn register_profile(
        &mut self,
        baseline: WholeAttemptMeasurement,
    ) -> Result<(), AnalyticsError> {
        baseline.validate()?;
        let profile_id = baseline.profile_id;
        if self.profiles.contains_key(&profile_id) {
            return Err(AnalyticsError::DuplicateProfile);
        }
        self.profiles.insert(
            profile_id,
            CalibrationProfile {
                profile_id,
                baseline,
                measurements: BTreeMap::new(),
                independent_reproducers: BTreeMap::new(),
                credit: ShadowCredit::Calibrated,
            },
        );
        Ok(())
    }

    pub fn submit(
        &mut self,
        measurement: WholeAttemptMeasurement,
    ) -> Result<ShadowCredit, AnalyticsError> {
        measurement.validate()?;
        let profile = self
            .profiles
            .get_mut(&measurement.profile_id)
            .ok_or(AnalyticsError::UnknownProfile)?;
        if profile
            .measurements
            .contains_key(&measurement.submission_id)
        {
            return Err(AnalyticsError::DuplicateSubmission);
        }
        let missing_whole_attempt =
            !measurement.commitment_and_proof_included || !measurement.deliverable_materialized;
        let advantage = ratio_exceeds_105(&measurement, &profile.baseline)?;
        profile
            .measurements
            .insert(measurement.submission_id, measurement);
        if missing_whole_attempt {
            profile.credit = zero_credit(CreditZeroReason::MissingWholeAttempt);
        } else if advantage {
            profile.credit = zero_credit(CreditZeroReason::MoreThanOnePointZeroFiveAdvantage);
        } else {
            profile.credit = zero_credit(CreditZeroReason::MaterialChallenge);
        }
        Ok(profile.credit.clone())
    }

    /// Record an independent reproduction. Two distinct implementation
    /// families within 10% are required before a successor can be reported as
    /// calibrated; this never restores production or consensus credit.
    pub fn reproduce(
        &mut self,
        profile_id: Hash32,
        submission_id: Hash32,
        reproduction: WholeAttemptMeasurement,
    ) -> Result<bool, AnalyticsError> {
        reproduction.validate()?;
        let profile = self
            .profiles
            .get_mut(&profile_id)
            .ok_or(AnalyticsError::UnknownProfile)?;
        let winner = profile
            .measurements
            .get(&submission_id)
            .ok_or(AnalyticsError::UnknownProfile)?;
        if reproduction.profile_id != profile_id
            || reproduction.submission_id == submission_id
            || reproduction.family != winner.family
            || reproduction.credited_work != winner.credited_work
            || !reproduction.commitment_and_proof_included
            || !reproduction.deliverable_materialized
            || reproduction.implementation_family == winner.implementation_family
        {
            return Err(AnalyticsError::ReproductionBindingMismatch);
        }
        if !within_ten_percent(reproduction.energy_microjoules, winner.energy_microjoules)? {
            return Err(AnalyticsError::ReproductionMismatch);
        }
        let families = profile
            .independent_reproducers
            .entry(submission_id)
            .or_default();
        if !families.insert(reproduction.implementation_family) {
            return Err(AnalyticsError::DuplicateReproducer);
        }
        Ok(families.len() >= 2)
    }

    pub fn demand_starved(&mut self, profile_id: Hash32) -> Result<(), AnalyticsError> {
        let profile = self
            .profiles
            .get_mut(&profile_id)
            .ok_or(AnalyticsError::UnknownProfile)?;
        profile.credit = zero_credit(CreditZeroReason::DemandStarvation);
        Ok(())
    }

    #[must_use]
    pub fn profile(&self, profile_id: Hash32) -> Option<&CalibrationProfile> {
        self.profiles.get(&profile_id)
    }
}

fn zero_credit(reason: CreditZeroReason) -> ShadowCredit {
    ShadowCredit::Zero {
        literal: STALE_PROFILE_CREDIT.to_owned(),
        reason,
    }
}

fn ratio_exceeds_105(
    candidate: &WholeAttemptMeasurement,
    baseline: &WholeAttemptMeasurement,
) -> Result<bool, AnalyticsError> {
    // candidate_work/candidate_joules > 1.05 * baseline_work/baseline_joules
    let left = candidate
        .credited_work
        .checked_mul(baseline.energy_microjoules)
        .and_then(|v| v.checked_mul(100))
        .ok_or(AnalyticsError::Overflow)?;
    let right = baseline
        .credited_work
        .checked_mul(candidate.energy_microjoules)
        .and_then(|v| v.checked_mul(105))
        .ok_or(AnalyticsError::Overflow)?;
    Ok(left > right)
}

fn within_ten_percent(a: u128, b: u128) -> Result<bool, AnalyticsError> {
    let high = a.max(b);
    let low = a.min(b);
    let left = high.checked_mul(100).ok_or(AnalyticsError::Overflow)?;
    let right = low.checked_mul(110).ok_or(AnalyticsError::Overflow)?;
    Ok(left <= right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn residual(values: Vec<i64>, rows: u32, cols: u32) -> IntegerResidual {
        IntegerResidual { rows, cols, values }
    }

    fn challenge(r: &IntegerResidual, samples: Vec<(u32, u32)>) -> EnergyChallenge {
        EnergyChallenge {
            residual_commitment: r.commitment().unwrap(),
            row_signs: vec![1; r.rows as usize],
            col_signs: vec![1; r.cols as usize],
            samples,
        }
    }

    fn measurement(
        profile: u8,
        id: u8,
        family: AlgorithmFamily,
        work: u128,
        energy: u128,
        implementation: &str,
    ) -> WholeAttemptMeasurement {
        WholeAttemptMeasurement {
            profile_id: [profile; 32],
            submission_id: [id; 32],
            family,
            implementation_family: implementation.into(),
            credited_work: work,
            energy_microjoules: energy,
            latency_micros: 1,
            commitment_and_proof_included: true,
            deliverable_materialized: true,
        }
    }

    #[test]
    fn retired_literal_and_narrow_claim_are_exact() {
        assert_eq!(M_HDF_STATUS, "RETIRED");
        assert_eq!(M_HDF_ENERGY_PROFILE, "M-HDF-ENERGY");
        assert_eq!(M_OMEGA_MODE, "SHADOW_ONLY");
        assert_eq!(STALE_PROFILE_CREDIT, "ZERO_SHADOW_CREDIT");
        assert_ne!(M_HDF_STATUS, M_HDF_ENERGY_PROFILE);
    }

    #[test]
    fn exact_energy_for_full_coordinate_average() {
        let r = residual(vec![1, 2, 3, 4], 2, 2);
        let out =
            estimate_hdf_energy(&r, &challenge(&r, vec![(0, 0), (0, 1), (1, 0), (1, 1)])).unwrap();
        assert_eq!(out.value.numerator, 120);
        assert_eq!(out.value.denominator, 4);
        assert_eq!(out.value.residual_energy, 30);
        assert_eq!(out.value.variance_bound_numerator, 7200);
        assert!(!out.value.universal_dominance);
        assert!(!out.value.exact_freivalds_amplification);
    }

    #[test]
    fn flat_error_counterexample_is_permanent() {
        let r = residual(vec![1, 1, 1, 1], 2, 2);
        let c = challenge(&r, vec![(0, 1)]);
        let out = estimate_hdf_energy(&r, &c).unwrap();
        assert_eq!(
            out.value.numerator, 0,
            "three transformed coordinates are zero"
        );
        let hit = estimate_hdf_energy(&r, &challenge(&r, vec![(0, 0)])).unwrap();
        assert_eq!(hit.value.numerator, 16);
    }

    #[test]
    fn spike_flat_duality_is_not_universal_dominance() {
        let r = residual(vec![1, 0, 0, 0], 2, 2);
        for coordinate in [(0, 0), (0, 1), (1, 0), (1, 1)] {
            assert_eq!(
                estimate_hdf_energy(&r, &challenge(&r, vec![coordinate]))
                    .unwrap()
                    .value
                    .numerator,
                1
            );
        }
    }

    #[test]
    fn characteristic_two_collapse_regression() {
        let mut v = vec![0_i128; 4];
        v[0] = 1;
        v[1] = 1;
        fwht(&mut v).unwrap();
        let modulo_two: Vec<i128> = v.into_iter().map(|x| x.rem_euclid(2)).collect();
        assert_eq!(modulo_two, vec![0, 0, 0, 0]);
    }

    #[test]
    fn commitment_prevents_post_challenge_adaptation() {
        let committed = residual(vec![1, 0, 0, 0], 2, 2);
        let changed = residual(vec![0, 1, 0, 0], 2, 2);
        let c = challenge(&committed, vec![(0, 0)]);
        assert_eq!(
            estimate_hdf_energy(&changed, &c),
            Err(AnalyticsError::Precommitment)
        );
    }

    #[test]
    fn quantization_floor_is_not_hidden_by_integer_audit() {
        // A 4x4 unit spike transforms to sixteen ±1 integer coordinates.
        // Normalization divides each by 4, so post-transform rounding at
        // quantum 1 erases all coordinates; exact integer squares do not.
        let mut values = vec![0; 16];
        values[0] = 1;
        let r = residual(values, 4, 4);
        for row in 0..4 {
            for col in 0..4 {
                let out = estimate_hdf_energy(&r, &challenge(&r, vec![(row, col)])).unwrap();
                assert_eq!(out.value.numerator, 1);
                assert_eq!(out.value.residual_energy, 1);
            }
        }
    }

    #[test]
    fn malformed_profiles_fail_closed() {
        for r in [
            residual(vec![], 0, 1),
            residual(vec![1; 6], 2, 3),
            residual(vec![1; 3], 2, 2),
        ] {
            assert!(r.validate().is_err());
        }
        let r = residual(vec![1; 4], 2, 2);
        let mut c = challenge(&r, vec![(0, 0)]);
        c.row_signs[0] = 0;
        assert_eq!(
            estimate_hdf_energy(&r, &c),
            Err(AnalyticsError::InvalidSigns)
        );
        let mut c = challenge(&r, vec![(2, 0)]);
        assert_eq!(
            estimate_hdf_energy(&r, &c),
            Err(AnalyticsError::InvalidSamples)
        );
        c.samples.clear();
        assert_eq!(
            estimate_hdf_energy(&r, &c),
            Err(AnalyticsError::InvalidSamples)
        );
    }

    #[test]
    fn every_required_fmm_family_is_distinct() {
        let families = BTreeSet::from([
            AlgorithmFamily::Naive,
            AlgorithmFamily::Tiled,
            AlgorithmFamily::StrassenFamily,
            AlgorithmFamily::FftFmm,
            AlgorithmFamily::CachedOperand,
            AlgorithmFamily::SparseStructured,
            AlgorithmFamily::DiagonalStructured,
            AlgorithmFamily::LowRankStructured,
            AlgorithmFamily::OutputOnly,
            AlgorithmFamily::CustomHardware,
        ]);
        assert_eq!(families.len(), 10);
    }

    #[test]
    fn over_five_percent_advantage_zeroes_only_shadow_credit() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let fast = measurement(1, 1, AlgorithmFamily::StrassenFamily, 100, 94, "fast-a");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        assert_eq!(
            auction.submit(fast).unwrap(),
            zero_credit(CreditZeroReason::MoreThanOnePointZeroFiveAdvantage)
        );
    }

    #[test]
    fn exact_five_percent_boundary_does_not_trigger_advantage() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 105, "baseline");
        let candidate = measurement(1, 1, AlgorithmFamily::Tiled, 100, 100, "candidate");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        assert_eq!(
            auction.submit(candidate).unwrap(),
            zero_credit(CreditZeroReason::MaterialChallenge)
        );
    }

    #[test]
    fn missing_deliverable_zeroes_shadow_credit() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let mut shortcut = measurement(1, 1, AlgorithmFamily::CachedOperand, 100, 50, "shortcut");
        shortcut.deliverable_materialized = false;
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        assert_eq!(
            auction.submit(shortcut).unwrap(),
            zero_credit(CreditZeroReason::MissingWholeAttempt)
        );
    }

    #[test]
    fn two_independent_reproductions_required() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let winner = measurement(1, 1, AlgorithmFamily::CustomHardware, 100, 90, "winner");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        auction.submit(winner).unwrap();
        assert!(!auction
            .reproduce(
                [1; 32],
                [1; 32],
                measurement(1, 2, AlgorithmFamily::CustomHardware, 100, 95, "lab-a")
            )
            .unwrap());
        assert!(auction
            .reproduce(
                [1; 32],
                [1; 32],
                measurement(1, 3, AlgorithmFamily::CustomHardware, 100, 99, "lab-b")
            )
            .unwrap());
        assert_eq!(
            auction.reproduce(
                [1; 32],
                [1; 32],
                measurement(1, 4, AlgorithmFamily::CustomHardware, 100, 99, "lab-b")
            ),
            Err(AnalyticsError::DuplicateReproducer)
        );
    }

    #[test]
    fn reproduction_cost_must_be_within_ten_percent() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let winner = measurement(1, 1, AlgorithmFamily::FftFmm, 100, 80, "winner");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        auction.submit(winner).unwrap();
        assert_eq!(
            auction.reproduce(
                [1; 32],
                [1; 32],
                measurement(1, 2, AlgorithmFamily::FftFmm, 100, 89, "lab-a")
            ),
            Err(AnalyticsError::ReproductionMismatch)
        );
    }

    #[test]
    fn reproduction_profile_strategy_and_whole_attempt_are_bound() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let winner = measurement(1, 1, AlgorithmFamily::FftFmm, 100, 80, "winner");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        auction.submit(winner).unwrap();

        let wrong_profile = measurement(2, 2, AlgorithmFamily::FftFmm, 100, 80, "lab-a");
        assert_eq!(
            auction.reproduce([1; 32], [1; 32], wrong_profile),
            Err(AnalyticsError::ReproductionBindingMismatch)
        );
        let wrong_family = measurement(1, 2, AlgorithmFamily::Naive, 100, 80, "lab-a");
        assert_eq!(
            auction.reproduce([1; 32], [1; 32], wrong_family),
            Err(AnalyticsError::ReproductionBindingMismatch)
        );
        let mut incomplete = measurement(1, 2, AlgorithmFamily::FftFmm, 100, 80, "lab-a");
        incomplete.commitment_and_proof_included = false;
        assert_eq!(
            auction.reproduce([1; 32], [1; 32], incomplete),
            Err(AnalyticsError::ReproductionBindingMismatch)
        );
    }

    #[test]
    fn immutable_submission_ids_do_not_overwrite_evidence() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let candidate = measurement(1, 1, AlgorithmFamily::Tiled, 100, 100, "candidate");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        auction.submit(candidate.clone()).unwrap();
        assert_eq!(
            auction.submit(candidate),
            Err(AnalyticsError::DuplicateSubmission)
        );
    }

    #[test]
    fn starvation_is_explicit_zero() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base).unwrap();
        auction.demand_starved([1; 32]).unwrap();
        assert_eq!(
            auction.profile([1; 32]).unwrap().credit,
            zero_credit(CreditZeroReason::DemandStarvation)
        );
    }

    #[test]
    fn challenged_profile_cannot_be_reset_in_place() {
        let base = measurement(1, 0, AlgorithmFamily::Naive, 100, 100, "baseline");
        let fast = measurement(1, 1, AlgorithmFamily::FftFmm, 100, 90, "fast");
        let mut auction = ShadowAuction::default();
        auction.register_profile(base.clone()).unwrap();
        auction.submit(fast).unwrap();
        assert_eq!(
            auction.register_profile(base),
            Err(AnalyticsError::DuplicateProfile)
        );
        assert_eq!(
            auction.profile([1; 32]).unwrap().credit,
            zero_credit(CreditZeroReason::MoreThanOnePointZeroFiveAdvantage)
        );
    }
}
