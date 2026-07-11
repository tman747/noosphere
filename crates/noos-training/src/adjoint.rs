//! `M-ADJOINT` exact-integer training-step certificate precursor.
//!
//! The certificate binds the frozen three-GEMM stack (`Y=XW`,
//! `G_X=G_Y W^T`, `G_W=X^T G_Y`), the global adjoint identity, policy lag,
//! clipping, momentum, and updated weights before independent post-commit
//! residue challenges.  It is experimental and never slashable.

#![allow(clippy::arithmetic_side_effects)]

use noos_analytics::residue::{
    verify_product, CommittedProduct, FieldMatrix, ResidueChallenges, ResidueError, ResidueProfile,
};
use noos_species::Hash32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ADJOINT_RECEIPT_DOMAIN: &[u8] = b"NOOS/TRAINING/ADJOINT-RECEIPT/V1";
pub const ADJOINT_MATRIX_DOMAIN: &[u8] = b"NOOS/TRAINING/ADJOINT-MATRIX/V1";
pub const ADJOINT_OPTIMIZER_DOMAIN: &[u8] = b"NOOS/TRAINING/ADJOINT-OPTIMIZER/V1";
pub const ADJOINT_CHALLENGE_DOMAIN: &[u8] = b"NOOS/TRAINING/ADJOINT-CHALLENGE/V1";
pub const ADJOINT_RESULT: &str = "SHADOW_ONLY";
pub const ADJOINT_SLASHABLE: bool = false;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AdjointError {
    #[error("training graph shape or matrix encoding is invalid")]
    Shape,
    #[error("training numeric or optimizer profile is invalid")]
    Profile,
    #[error("checked exact integer arithmetic overflow")]
    Overflow,
    #[error("receipt commitment, policy, or profile binding mismatch")]
    Binding,
    #[error("challenge was not derived after the complete receipt commitment")]
    Challenge,
    #[error("a sampled local forward/backward graph relation failed")]
    LocalRelation,
    #[error("the global adjoint identity failed")]
    DualIdentity,
    #[error("clipping, momentum, or updated weights do not match the frozen optimizer")]
    Optimizer,
    #[error("policy lag is negative or exceeds the registered hard band")]
    PolicyLag,
    #[error("residue verifier rejected the certificate")]
    Residue,
    #[error("certificate verification cost is at or above deterministic replay")]
    CostAtOrAboveReplay,
}

impl From<ResidueError> for AdjointError {
    fn from(_: ResidueError) -> Self {
        Self::Residue
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactMatrix {
    pub rows: u32,
    pub cols: u32,
    pub values: Vec<i64>,
}

impl ExactMatrix {
    pub fn validate(&self) -> Result<(), AdjointError> {
        let expected = usize::try_from(self.rows)
            .ok()
            .and_then(|rows| {
                usize::try_from(self.cols)
                    .ok()
                    .and_then(|cols| rows.checked_mul(cols))
            })
            .ok_or(AdjointError::Overflow)?;
        if self.rows == 0 || self.cols == 0 || self.values.len() != expected {
            return Err(AdjointError::Shape);
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Hash32, AdjointError> {
        self.validate()?;
        let mut hash = blake3::Hasher::new();
        hash.update(ADJOINT_MATRIX_DOMAIN);
        hash.update(&self.rows.to_le_bytes());
        hash.update(&self.cols.to_le_bytes());
        hash.update(&(self.values.len() as u64).to_le_bytes());
        for value in &self.values {
            hash.update(&value.to_le_bytes());
        }
        Ok(*hash.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactOptimizerProfile {
    pub policy_version: u64,
    pub numeric_profile: Hash32,
    pub residue_profile: ResidueProfile,
    pub clip_abs: i64,
    pub momentum_numerator: i64,
    pub momentum_denominator: i64,
    pub learning_rate_numerator: i64,
    pub learning_rate_denominator: i64,
    pub maximum_policy_lag: u64,
}

impl ExactOptimizerProfile {
    pub fn validate(&self) -> Result<(), AdjointError> {
        self.residue_profile.validate()?;
        if self.policy_version == 0
            || self.numeric_profile == [0; 32]
            || self.clip_abs <= 0
            || self.momentum_numerator < 0
            || self.momentum_numerator > self.momentum_denominator
            || self.momentum_denominator <= 0
            || self.learning_rate_numerator <= 0
            || self.learning_rate_denominator <= 0
            || self.residue_profile.modulus > i64::MAX as u64
        {
            return Err(AdjointError::Profile);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingStepWitness {
    pub x: ExactMatrix,
    pub weights: ExactMatrix,
    pub upstream_gradient: ExactMatrix,
    pub y: ExactMatrix,
    pub input_gradient: ExactMatrix,
    pub weight_gradient: ExactMatrix,
    pub old_velocity: ExactMatrix,
    pub new_velocity: ExactMatrix,
    pub updated_weights: ExactMatrix,
}

impl TrainingStepWitness {
    fn validate_shapes(&self) -> Result<(), AdjointError> {
        for matrix in [
            &self.x,
            &self.weights,
            &self.upstream_gradient,
            &self.y,
            &self.input_gradient,
            &self.weight_gradient,
            &self.old_velocity,
            &self.new_velocity,
            &self.updated_weights,
        ] {
            matrix.validate()?;
        }
        let tokens = self.x.rows;
        let inner = self.x.cols;
        let outputs = self.weights.cols;
        if self.weights.rows != inner
            || self.upstream_gradient.rows != tokens
            || self.upstream_gradient.cols != outputs
            || self.y.rows != tokens
            || self.y.cols != outputs
            || self.input_gradient.rows != tokens
            || self.input_gradient.cols != inner
            || self.weight_gradient.rows != inner
            || self.weight_gradient.cols != outputs
            || self.old_velocity.rows != inner
            || self.old_velocity.cols != outputs
            || self.new_velocity.rows != inner
            || self.new_velocity.cols != outputs
            || self.updated_weights.rows != inner
            || self.updated_weights.cols != outputs
        {
            return Err(AdjointError::Shape);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjointReceipt {
    pub c_theta: Hash32,
    pub c_x: Hash32,
    pub c_t: Hash32,
    pub c_y: Hash32,
    pub c_loss: Hash32,
    pub c_fwd: Hash32,
    pub c_bwd: Hash32,
    pub c_g: Hash32,
    pub c_opt: Hash32,
    pub c_theta_prime: Hash32,
    pub policy_version: u64,
    pub numeric_profile: Hash32,
    pub policy_lag: u64,
    pub committed_height: u64,
}

impl AdjointReceipt {
    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        let mut hash = blake3::Hasher::new();
        hash.update(ADJOINT_RECEIPT_DOMAIN);
        for root in [
            self.c_theta,
            self.c_x,
            self.c_t,
            self.c_y,
            self.c_loss,
            self.c_fwd,
            self.c_bwd,
            self.c_g,
            self.c_opt,
            self.c_theta_prime,
        ] {
            hash.update(&root);
        }
        hash.update(&self.policy_version.to_le_bytes());
        hash.update(&self.numeric_profile);
        hash.update(&self.policy_lag.to_le_bytes());
        hash.update(&self.committed_height.to_le_bytes());
        *hash.finalize().as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedTrainingStep {
    pub profile: ExactOptimizerProfile,
    pub witness: TrainingStepWitness,
    pub receipt: AdjointReceipt,
    pub receipt_commitment: Hash32,
    pub canonical_policy_height: u64,
    pub receipt_policy_height: u64,
    pub forward_claim: CommittedProduct,
    pub input_gradient_claim: CommittedProduct,
    pub weight_gradient_claim: CommittedProduct,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjointCertificate {
    pub receipt_commitment: Hash32,
    pub beacon: Hash32,
    pub beacon_height: u64,
    pub forward_challenges: ResidueChallenges,
    pub input_gradient_challenges: ResidueChallenges,
    pub weight_gradient_challenges: ResidueChallenges,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationCost {
    pub certificate_multiplications: u128,
    pub replay_multiplications: u128,
}

impl VerificationCost {
    #[must_use]
    pub fn below_replay(self) -> bool {
        self.certificate_multiplications < self.replay_multiplications
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsuleHeader {
    pub receipt_commitment: Hash32,
    pub numeric_profile: Hash32,
    pub policy_version: u64,
    pub c_fwd: Hash32,
    pub c_bwd: Hash32,
    pub c_g: Hash32,
    pub c_opt: Hash32,
    pub c_theta_prime: Hash32,
}

impl CapsuleHeader {
    #[must_use]
    pub fn from_step(step: &CommittedTrainingStep) -> Self {
        Self {
            receipt_commitment: step.receipt_commitment,
            numeric_profile: step.receipt.numeric_profile,
            policy_version: step.receipt.policy_version,
            c_fwd: step.receipt.c_fwd,
            c_bwd: step.receipt.c_bwd,
            c_g: step.receipt.c_g,
            c_opt: step.receipt.c_opt,
            c_theta_prime: step.receipt.c_theta_prime,
        }
    }
}

#[must_use]
pub fn verify_capsule_header(expected: &CapsuleHeader, offered: &CapsuleHeader) -> bool {
    expected == offered
}

#[allow(clippy::too_many_arguments)]
pub fn commit_training_step(
    profile: ExactOptimizerProfile,
    witness: TrainingStepWitness,
    target_commitment: Hash32,
    loss_commitment: Hash32,
    canonical_policy_height: u64,
    receipt_policy_height: u64,
    committed_height: u64,
) -> Result<CommittedTrainingStep, AdjointError> {
    profile.validate()?;
    witness.validate_shapes()?;
    if target_commitment == [0; 32]
        || loss_commitment == [0; 32]
        || receipt_policy_height > canonical_policy_height
    {
        return Err(AdjointError::PolicyLag);
    }
    let policy_lag = canonical_policy_height - receipt_policy_height;
    if policy_lag > profile.maximum_policy_lag {
        return Err(AdjointError::PolicyLag);
    }

    let forward_claim = residue_claim(
        &profile,
        &witness.x,
        &witness.weights,
        &witness.y,
        committed_height,
    )?;
    let transposed_weights = transpose(&witness.weights)?;
    let input_gradient_claim = residue_claim(
        &profile,
        &witness.upstream_gradient,
        &transposed_weights,
        &witness.input_gradient,
        committed_height,
    )?;
    let transposed_x = transpose(&witness.x)?;
    let weight_gradient_claim = residue_claim(
        &profile,
        &transposed_x,
        &witness.upstream_gradient,
        &witness.weight_gradient,
        committed_height,
    )?;

    let receipt = AdjointReceipt {
        c_theta: witness.weights.commitment()?,
        c_x: witness.x.commitment()?,
        c_t: target_commitment,
        c_y: witness.y.commitment()?,
        c_loss: loss_commitment,
        c_fwd: forward_claim.claim_commitment,
        c_bwd: input_gradient_claim.claim_commitment,
        c_g: weight_gradient_claim.claim_commitment,
        c_opt: optimizer_commitment(&profile, &witness.old_velocity, &witness.new_velocity)?,
        c_theta_prime: witness.updated_weights.commitment()?,
        policy_version: profile.policy_version,
        numeric_profile: profile.numeric_profile,
        policy_lag,
        committed_height,
    };
    let receipt_commitment = receipt.commitment();
    Ok(CommittedTrainingStep {
        profile,
        witness,
        receipt,
        receipt_commitment,
        canonical_policy_height,
        receipt_policy_height,
        forward_claim,
        input_gradient_claim,
        weight_gradient_claim,
    })
}

pub fn certify_training_step(
    step: &CommittedTrainingStep,
    beacon: Hash32,
    beacon_height: u64,
) -> Result<AdjointCertificate, AdjointError> {
    validate_step_bindings(step)?;
    if beacon == [0; 32] || beacon_height <= step.receipt.committed_height {
        return Err(AdjointError::Challenge);
    }
    let forward_beacon = leaf_beacon(step.receipt_commitment, beacon, 1);
    let input_beacon = leaf_beacon(step.receipt_commitment, beacon, 2);
    let weight_beacon = leaf_beacon(step.receipt_commitment, beacon, 3);
    Ok(AdjointCertificate {
        receipt_commitment: step.receipt_commitment,
        beacon,
        beacon_height,
        forward_challenges: ResidueChallenges::derive(
            &step.forward_claim,
            forward_beacon,
            beacon_height,
        )?,
        input_gradient_challenges: ResidueChallenges::derive(
            &step.input_gradient_claim,
            input_beacon,
            beacon_height,
        )?,
        weight_gradient_challenges: ResidueChallenges::derive(
            &step.weight_gradient_claim,
            weight_beacon,
            beacon_height,
        )?,
    })
}

pub fn verify_training_step(
    step: &CommittedTrainingStep,
    certificate: &AdjointCertificate,
) -> Result<VerificationCost, AdjointError> {
    validate_step_bindings(step)?;
    if certificate.receipt_commitment != step.receipt_commitment
        || certificate.beacon == [0; 32]
        || certificate.beacon_height <= step.receipt.committed_height
        || certificate.forward_challenges.beacon_height != certificate.beacon_height
        || certificate.input_gradient_challenges.beacon_height != certificate.beacon_height
        || certificate.weight_gradient_challenges.beacon_height != certificate.beacon_height
        || certificate.forward_challenges.beacon
            != leaf_beacon(step.receipt_commitment, certificate.beacon, 1)
        || certificate.input_gradient_challenges.beacon
            != leaf_beacon(step.receipt_commitment, certificate.beacon, 2)
        || certificate.weight_gradient_challenges.beacon
            != leaf_beacon(step.receipt_commitment, certificate.beacon, 3)
    {
        return Err(AdjointError::Challenge);
    }
    if !verify_product(&step.forward_claim, &certificate.forward_challenges)?
        || !verify_product(
            &step.input_gradient_claim,
            &certificate.input_gradient_challenges,
        )?
        || !verify_product(
            &step.weight_gradient_claim,
            &certificate.weight_gradient_challenges,
        )?
    {
        return Err(AdjointError::LocalRelation);
    }
    verify_dual_identity(&step.witness)?;
    verify_optimizer(&step.profile, &step.witness)?;
    let cost = verification_cost(step)?;
    if !cost.below_replay() {
        return Err(AdjointError::CostAtOrAboveReplay);
    }
    Ok(cost)
}

fn validate_step_bindings(step: &CommittedTrainingStep) -> Result<(), AdjointError> {
    let rebuilt = commit_training_step(
        step.profile.clone(),
        step.witness.clone(),
        step.receipt.c_t,
        step.receipt.c_loss,
        step.canonical_policy_height,
        step.receipt_policy_height,
        step.receipt.committed_height,
    )?;
    if rebuilt.receipt != step.receipt
        || rebuilt.receipt_commitment != step.receipt_commitment
        || rebuilt.forward_claim != step.forward_claim
        || rebuilt.input_gradient_claim != step.input_gradient_claim
        || rebuilt.weight_gradient_claim != step.weight_gradient_claim
    {
        return Err(AdjointError::Binding);
    }
    Ok(())
}

fn verify_dual_identity(witness: &TrainingStepWitness) -> Result<(), AdjointError> {
    let output_pairing = dot(&witness.upstream_gradient, &witness.y)?;
    let input_pairing = dot(&witness.input_gradient, &witness.x)?;
    let weight_pairing = dot(&witness.weight_gradient, &witness.weights)?;
    if output_pairing != input_pairing || output_pairing != weight_pairing {
        return Err(AdjointError::DualIdentity);
    }
    Ok(())
}

fn verify_optimizer(
    profile: &ExactOptimizerProfile,
    witness: &TrainingStepWitness,
) -> Result<(), AdjointError> {
    for index in 0..witness.weights.values.len() {
        let clipped =
            witness.weight_gradient.values[index].clamp(-profile.clip_abs, profile.clip_abs);
        let momentum = divide_round_ties_away(
            i128::from(profile.momentum_numerator)
                .checked_mul(i128::from(witness.old_velocity.values[index]))
                .ok_or(AdjointError::Overflow)?,
            i128::from(profile.momentum_denominator),
        )?;
        let expected_velocity = i64::try_from(
            momentum
                .checked_add(i128::from(clipped))
                .ok_or(AdjointError::Overflow)?,
        )
        .map_err(|_| AdjointError::Overflow)?;
        if witness.new_velocity.values[index] != expected_velocity {
            return Err(AdjointError::Optimizer);
        }
        let update = divide_round_ties_away(
            i128::from(profile.learning_rate_numerator)
                .checked_mul(i128::from(expected_velocity))
                .ok_or(AdjointError::Overflow)?,
            i128::from(profile.learning_rate_denominator),
        )?;
        let expected_weight = i64::try_from(
            i128::from(witness.weights.values[index])
                .checked_sub(update)
                .ok_or(AdjointError::Overflow)?,
        )
        .map_err(|_| AdjointError::Overflow)?;
        if witness.updated_weights.values[index] != expected_weight {
            return Err(AdjointError::Optimizer);
        }
    }
    Ok(())
}

fn divide_round_ties_away(numerator: i128, denominator: i128) -> Result<i128, AdjointError> {
    if denominator <= 0 {
        return Err(AdjointError::Profile);
    }
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let doubled = remainder
        .unsigned_abs()
        .checked_mul(2)
        .ok_or(AdjointError::Overflow)?;
    if doubled < denominator as u128 {
        return Ok(quotient);
    }
    quotient
        .checked_add(if numerator < 0 { -1 } else { 1 })
        .ok_or(AdjointError::Overflow)
}

fn residue_claim(
    profile: &ExactOptimizerProfile,
    left: &ExactMatrix,
    right: &ExactMatrix,
    output: &ExactMatrix,
    committed_height: u64,
) -> Result<CommittedProduct, AdjointError> {
    ensure_no_modular_alias(profile.residue_profile.modulus, left, right, output)?;
    Ok(CommittedProduct::new(
        profile.residue_profile.clone(),
        to_field(left, profile.residue_profile.modulus)?,
        to_field(right, profile.residue_profile.modulus)?,
        to_field(output, profile.residue_profile.modulus)?,
        committed_height,
    )?)
}

fn ensure_no_modular_alias(
    modulus: u64,
    left: &ExactMatrix,
    right: &ExactMatrix,
    output: &ExactMatrix,
) -> Result<(), AdjointError> {
    let left_max = max_abs(left)?;
    let right_max = max_abs(right)?;
    let output_max = max_abs(output)?;
    let bound = left_max
        .checked_mul(right_max)
        .and_then(|value| value.checked_mul(u128::from(left.cols)))
        .and_then(|value| value.checked_add(output_max))
        .ok_or(AdjointError::Overflow)?;
    if bound >= u128::from(modulus) {
        return Err(AdjointError::Profile);
    }
    Ok(())
}

fn max_abs(matrix: &ExactMatrix) -> Result<u128, AdjointError> {
    matrix
        .values
        .iter()
        .map(|value| i128::from(*value).unsigned_abs())
        .max()
        .ok_or(AdjointError::Shape)
}

fn to_field(matrix: &ExactMatrix, modulus: u64) -> Result<FieldMatrix, AdjointError> {
    let modulus_i128 = i128::from(modulus);
    let values = matrix
        .values
        .iter()
        .map(|value| {
            u64::try_from(i128::from(*value).rem_euclid(modulus_i128))
                .map_err(|_| AdjointError::Overflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FieldMatrix {
        rows: matrix.rows,
        cols: matrix.cols,
        values,
    })
}

fn transpose(matrix: &ExactMatrix) -> Result<ExactMatrix, AdjointError> {
    matrix.validate()?;
    let rows = usize::try_from(matrix.rows).map_err(|_| AdjointError::Overflow)?;
    let cols = usize::try_from(matrix.cols).map_err(|_| AdjointError::Overflow)?;
    let mut values = vec![0_i64; matrix.values.len()];
    for row in 0..rows {
        for col in 0..cols {
            values[col * rows + row] = matrix.values[row * cols + col];
        }
    }
    Ok(ExactMatrix {
        rows: matrix.cols,
        cols: matrix.rows,
        values,
    })
}

fn dot(left: &ExactMatrix, right: &ExactMatrix) -> Result<i128, AdjointError> {
    if left.rows != right.rows || left.cols != right.cols {
        return Err(AdjointError::Shape);
    }
    left.values
        .iter()
        .zip(&right.values)
        .try_fold(0_i128, |sum, (left, right)| {
            sum.checked_add(
                i128::from(*left)
                    .checked_mul(i128::from(*right))
                    .ok_or(AdjointError::Overflow)?,
            )
            .ok_or(AdjointError::Overflow)
        })
}

fn optimizer_commitment(
    profile: &ExactOptimizerProfile,
    old_velocity: &ExactMatrix,
    new_velocity: &ExactMatrix,
) -> Result<Hash32, AdjointError> {
    let mut hash = blake3::Hasher::new();
    hash.update(ADJOINT_OPTIMIZER_DOMAIN);
    hash.update(&profile.policy_version.to_le_bytes());
    hash.update(&profile.numeric_profile);
    hash.update(&profile.clip_abs.to_le_bytes());
    hash.update(&profile.momentum_numerator.to_le_bytes());
    hash.update(&profile.momentum_denominator.to_le_bytes());
    hash.update(&profile.learning_rate_numerator.to_le_bytes());
    hash.update(&profile.learning_rate_denominator.to_le_bytes());
    hash.update(&old_velocity.commitment()?);
    hash.update(&new_velocity.commitment()?);
    Ok(*hash.finalize().as_bytes())
}

fn leaf_beacon(receipt_commitment: Hash32, beacon: Hash32, leaf: u8) -> Hash32 {
    let mut hash = blake3::Hasher::new();
    hash.update(ADJOINT_CHALLENGE_DOMAIN);
    hash.update(&receipt_commitment);
    hash.update(&beacon);
    hash.update(&[leaf]);
    *hash.finalize().as_bytes()
}

fn verification_cost(step: &CommittedTrainingStep) -> Result<VerificationCost, AdjointError> {
    let rounds = u128::from(step.profile.residue_profile.rounds);
    let costs = [
        relation_cost(&step.forward_claim)?,
        relation_cost(&step.input_gradient_claim)?,
        relation_cost(&step.weight_gradient_claim)?,
    ];
    let residue_cost = costs.iter().try_fold(0_u128, |sum, (verify, _)| {
        sum.checked_add(verify.checked_mul(rounds).ok_or(AdjointError::Overflow)?)
            .ok_or(AdjointError::Overflow)
    })?;
    let optimizer_cost = u128::try_from(step.witness.weights.values.len())
        .map_err(|_| AdjointError::Overflow)?
        .checked_mul(2)
        .ok_or(AdjointError::Overflow)?;
    let replay = costs.iter().try_fold(0_u128, |sum, (_, replay)| {
        sum.checked_add(*replay).ok_or(AdjointError::Overflow)
    })?;
    Ok(VerificationCost {
        certificate_multiplications: residue_cost
            .checked_add(optimizer_cost)
            .ok_or(AdjointError::Overflow)?,
        replay_multiplications: replay
            .checked_add(optimizer_cost)
            .ok_or(AdjointError::Overflow)?,
    })
}

fn relation_cost(claim: &CommittedProduct) -> Result<(u128, u128), AdjointError> {
    let rows = u128::from(claim.a.rows);
    let inner = u128::from(claim.a.cols);
    let cols = u128::from(claim.b.cols);
    let verify = inner
        .checked_mul(cols)
        .and_then(|value| value.checked_add(rows.checked_mul(inner)?))
        .and_then(|value| value.checked_add(rows.checked_mul(cols)?))
        .ok_or(AdjointError::Overflow)?;
    let replay = rows
        .checked_mul(inner)
        .and_then(|value| value.checked_mul(cols))
        .ok_or(AdjointError::Overflow)?;
    Ok((verify, replay))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]

    use super::*;
    use noos_analytics::residue::verify_product_reference;

    fn matrix(rows: u32, cols: u32, values: Vec<i64>) -> ExactMatrix {
        ExactMatrix { rows, cols, values }
    }

    fn matmul(left: &ExactMatrix, right: &ExactMatrix) -> ExactMatrix {
        let rows = left.rows as usize;
        let inner = left.cols as usize;
        let cols = right.cols as usize;
        let mut values = vec![0_i64; rows * cols];
        for row in 0..rows {
            for pivot in 0..inner {
                for col in 0..cols {
                    values[row * cols + col] +=
                        left.values[row * inner + pivot] * right.values[pivot * cols + col];
                }
            }
        }
        matrix(left.rows, right.cols, values)
    }

    fn profile(rounds: u16) -> ExactOptimizerProfile {
        ExactOptimizerProfile {
            policy_version: 7,
            numeric_profile: [4; 32],
            residue_profile: ResidueProfile {
                profile_id: [5; 32],
                modulus: 2_305_843_009_213_693_951,
                rounds,
                challenge_domain: [6; 32],
            },
            clip_abs: 20,
            momentum_numerator: 1,
            momentum_denominator: 2,
            learning_rate_numerator: 1,
            learning_rate_denominator: 4,
            maximum_policy_lag: 2,
        }
    }

    fn honest_step(size: u32, rounds: u16) -> CommittedTrainingStep {
        let count = usize::try_from(size * size).unwrap();
        let x = matrix(size, size, (0..count).map(|i| (i % 5) as i64 - 2).collect());
        let weights = matrix(size, size, (0..count).map(|i| (i % 7) as i64 - 3).collect());
        let gy = matrix(size, size, (0..count).map(|i| (i % 3) as i64 - 1).collect());
        let y = matmul(&x, &weights);
        let gx = matmul(&gy, &transpose(&weights).unwrap());
        let gw = matmul(&transpose(&x).unwrap(), &gy);
        let old_velocity = matrix(size, size, vec![2; count]);
        let mut new_velocity = matrix(size, size, vec![0; count]);
        let mut updated_weights = weights.clone();
        let p = profile(rounds);
        for index in 0..count {
            let clipped = gw.values[index].clamp(-p.clip_abs, p.clip_abs);
            new_velocity.values[index] = 1 + clipped;
            updated_weights.values[index] -=
                divide_round_ties_away(i128::from(new_velocity.values[index]), 4).unwrap() as i64;
        }
        commit_training_step(
            p,
            TrainingStepWitness {
                x,
                weights,
                upstream_gradient: gy,
                y,
                input_gradient: gx,
                weight_gradient: gw,
                old_velocity,
                new_velocity,
                updated_weights,
            },
            [7; 32],
            [8; 32],
            100,
            99,
            10,
        )
        .unwrap()
    }

    #[test]
    fn honest_three_gemm_certificate_passes_both_residue_paths_and_costs_less() {
        let step = honest_step(32, 1);
        let certificate = certify_training_step(&step, [9; 32], 11).unwrap();
        assert!(
            verify_product_reference(&step.forward_claim, &certificate.forward_challenges).unwrap()
        );
        assert!(verify_product_reference(
            &step.input_gradient_claim,
            &certificate.input_gradient_challenges
        )
        .unwrap());
        assert!(verify_product_reference(
            &step.weight_gradient_claim,
            &certificate.weight_gradient_challenges
        )
        .unwrap());
        let cost = verify_training_step(&step, &certificate).unwrap();
        assert!(cost.below_replay());
        assert_eq!(cost.certificate_multiplications, 11_264);
        assert_eq!(cost.replay_multiplications, 100_352);
    }

    #[test]
    fn deterministic_receipt_vector_is_frozen() {
        let step = honest_step(4, 2);
        assert_eq!(
            hex(step.receipt_commitment),
            "c9d949b8405f48ede68ccc1d0d401660e31637dc7233457568a8606833dc0dd0"
        );
    }

    #[test]
    fn sign_flip_dropped_relation_stale_weight_and_coherent_fake_reject() {
        for mutation in 0..4 {
            let honest = honest_step(4, 2);
            let certificate = certify_training_step(&honest, [9; 32], 11).unwrap();
            let mut forged = honest.clone();
            match mutation {
                0 => forged.witness.weight_gradient.values[0] *= -1,
                1 => forged.witness.input_gradient.values.fill(0),
                2 => forged.witness.weights.values[0] += 1,
                _ => {
                    // A coherent fake can preserve the scalar dual identity by
                    // modifying paired values, but it is not the local graph.
                    forged.witness.y.values[0] += 1;
                    forged.witness.input_gradient.values[0] += 1;
                    forged.witness.weight_gradient.values[0] += 1;
                }
            }
            assert!(verify_training_step(&forged, &certificate).is_err());
        }
    }

    #[test]
    fn recomputed_coherent_fake_dual_identity_dies_on_local_graph_relation() {
        let honest = honest_step(4, 2);
        let mut witness = honest.witness.clone();
        witness.y.values.fill(0);
        witness.input_gradient.values.fill(0);
        witness.weight_gradient.values.fill(0);
        // Keep the optimizer self-consistent with the fake zero gradient.
        witness.new_velocity.values.fill(1);
        witness.updated_weights = witness.weights.clone();
        let forged = commit_training_step(
            honest.profile.clone(),
            witness,
            honest.receipt.c_t,
            honest.receipt.c_loss,
            honest.canonical_policy_height,
            honest.receipt_policy_height,
            honest.receipt.committed_height,
        )
        .unwrap();
        assert!(verify_dual_identity(&forged.witness).is_ok());
        let certificate = certify_training_step(&forged, [11; 32], 11).unwrap();
        assert_eq!(
            verify_training_step(&forged, &certificate),
            Err(AdjointError::LocalRelation)
        );
    }

    #[test]
    fn wrong_clip_momentum_updated_weight_policy_profile_and_splice_reject() {
        let honest = honest_step(4, 2);
        let certificate = certify_training_step(&honest, [9; 32], 11).unwrap();
        let mut variants = Vec::new();
        let mut wrong_clip = honest.clone();
        wrong_clip.profile.clip_abs += 1;
        variants.push(wrong_clip);
        let mut wrong_momentum = honest.clone();
        wrong_momentum.witness.new_velocity.values[0] += 1;
        variants.push(wrong_momentum);
        let mut wrong_update = honest.clone();
        wrong_update.witness.updated_weights.values[0] += 1;
        variants.push(wrong_update);
        let mut profile = honest.clone();
        profile.profile.numeric_profile[0] ^= 1;
        variants.push(profile);
        let mut policy = honest.clone();
        policy.profile.policy_version += 1;
        variants.push(policy);
        for variant in variants {
            assert!(verify_training_step(&variant, &certificate).is_err());
        }
        let other = honest_step(4, 2);
        let mut splice = certificate;
        splice.weight_gradient_challenges = certify_training_step(&other, [10; 32], 11)
            .unwrap()
            .weight_gradient_challenges;
        assert_eq!(
            verify_training_step(&honest, &splice),
            Err(AdjointError::Challenge)
        );
    }

    #[test]
    fn challenge_timing_alias_and_integer_overflow_boundaries_fail_closed() {
        let step = honest_step(4, 1);
        assert_eq!(
            certify_training_step(&step, [9; 32], 10),
            Err(AdjointError::Challenge)
        );
        let mut alias_profile = profile(1);
        alias_profile.residue_profile.modulus = 29;
        let witness = step.witness.clone();
        assert_eq!(
            commit_training_step(alias_profile, witness, [7; 32], [8; 32], 100, 99, 10),
            Err(AdjointError::Profile)
        );
        let mut overflow = step;
        overflow.witness.weight_gradient.values[0] = i64::MAX;
        assert!(validate_step_bindings(&overflow).is_err());
    }

    #[test]
    fn ten_million_structured_capsule_header_mutations_have_zero_false_accepts() {
        let step = honest_step(2, 1);
        let expected = CapsuleHeader::from_step(&step);
        let mut rejected = 0_u64;
        for case in 0_u64..10_000_000 {
            let mut offered = expected.clone();
            let byte = (case as usize / 8) % 32;
            let bit = 1_u8 << (case % 8);
            match case % 8 {
                0 => offered.receipt_commitment[byte] ^= bit,
                1 => offered.numeric_profile[byte] ^= bit,
                2 => offered.policy_version ^= case | 1,
                3 => offered.c_fwd[byte] ^= bit,
                4 => offered.c_bwd[byte] ^= bit,
                5 => offered.c_g[byte] ^= bit,
                6 => offered.c_opt[byte] ^= bit,
                _ => offered.c_theta_prime[byte] ^= bit,
            }
            if !verify_capsule_header(&expected, &offered) {
                rejected += 1;
            }
        }
        assert_eq!(rejected, 10_000_000);
    }

    #[test]
    fn shadow_only_non_slashable_literals_are_load_bearing() {
        assert_eq!(ADJOINT_RESULT, "SHADOW_ONLY");
        assert!(!ADJOINT_SLASHABLE);
    }

    fn hex(hash: Hash32) -> String {
        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
