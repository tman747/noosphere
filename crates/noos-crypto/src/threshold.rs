//! Feldman commitment verification and threshold-signature combination.
//!
//! Pure functions over caller-supplied bytes. Index convention (frozen for
//! NOOSPHERE; the historical port source mixed 0- and 1-based indices):
//!
//! * share indices are 1-based `u16`; the polynomial is evaluated at the
//!   index value **directly**; index 0 is rejected — it would evaluate the
//!   polynomial at the group secret;
//! * threshold combination interpolates at zero using the index values
//!   as-is.
//!
//! All group arithmetic is constant-degree modular field/curve math over
//! `blstrs`; it cannot overflow, so the checked-arithmetic consensus rule
//! does not apply inside the annotated functions.

use crate::bls::{blst_public_key, blst_signature, BlsPublicKey, BlsSecretKey, BlsSignature};
use crate::error::BlsError;

/// Expected share public key at `share_index` from one contributor's
/// Feldman commitment vector: `sum_j C_j * x^j`.
#[allow(clippy::arithmetic_side_effects)] // modular group/field arithmetic
pub fn feldman_share_public_key(
    commitments: &[BlsPublicKey],
    share_index: u16,
) -> Result<BlsPublicKey, BlsError> {
    if commitments.is_empty() {
        return Err(BlsError::EmptyCommitments);
    }
    if share_index == 0 {
        return Err(BlsError::InvalidShareIndex);
    }
    let x = blstrs::Scalar::from(u64::from(share_index));
    let mut power = blstrs::Scalar::from(1_u64);
    let mut acc = blstrs::G1Projective::from(blstrs::G1Affine::default());
    for commitment in commitments {
        acc += public_key_to_g1(commitment)? * power;
        power *= x;
    }
    g1_to_public_key(acc)
}

/// Verifies a received share secret against every contributor's Feldman
/// commitment vector: `G1 * share == sum_contributors sum_j C_j * x^j`.
pub fn feldman_verify_share(
    share_index: u16,
    share: &BlsSecretKey,
    commitments_all: &[Vec<BlsPublicKey>],
) -> Result<(), BlsError> {
    let expected = derive_share_public_key(commitments_all, share_index)?;
    if share.public_key() == expected {
        Ok(())
    } else {
        Err(BlsError::InvalidCommitment)
    }
}

/// Derives the aggregate share public key at `share_index` across all
/// contributors' commitment vectors.
#[allow(clippy::arithmetic_side_effects)] // modular group arithmetic
pub fn derive_share_public_key(
    commitments_all: &[Vec<BlsPublicKey>],
    share_index: u16,
) -> Result<BlsPublicKey, BlsError> {
    if commitments_all.is_empty() {
        return Err(BlsError::EmptyCommitments);
    }
    let mut acc = blstrs::G1Projective::from(blstrs::G1Affine::default());
    for commitments in commitments_all {
        acc += public_key_to_g1(&feldman_share_public_key(commitments, share_index)?)?;
    }
    g1_to_public_key(acc)
}

/// Derives the group public key: the sum of every contributor's constant
/// term `C_0`.
#[allow(clippy::arithmetic_side_effects)] // modular group arithmetic
pub fn feldman_group_public_key(
    commitments_all: &[Vec<BlsPublicKey>],
) -> Result<BlsPublicKey, BlsError> {
    if commitments_all.is_empty() {
        return Err(BlsError::EmptyCommitments);
    }
    let mut acc = blstrs::G1Projective::from(blstrs::G1Affine::default());
    for commitments in commitments_all {
        let Some(first) = commitments.first() else {
            return Err(BlsError::EmptyCommitments);
        };
        acc += public_key_to_g1(first)?;
    }
    g1_to_public_key(acc)
}

/// Combines at least `threshold` partial signatures into the group
/// signature by Lagrange interpolation at zero.
///
/// Exactly the first `threshold` entries are used; every index in that
/// subset must be unique and non-zero.
#[allow(clippy::arithmetic_side_effects)] // modular group/field arithmetic
pub fn bls_threshold_combine(
    entries: &[(u16, &BlsSignature)],
    threshold: u16,
) -> Result<BlsSignature, BlsError> {
    let need = usize::from(threshold);
    if threshold == 0 || entries.len() < need {
        return Err(BlsError::ThresholdTooFewShares);
    }
    let subset = &entries[..need];
    for (pos, (index, _)) in subset.iter().enumerate() {
        if *index == 0 {
            return Err(BlsError::InvalidShareIndex);
        }
        if subset
            .iter()
            .skip(pos.saturating_add(1))
            .any(|(other, _)| other == index)
        {
            return Err(BlsError::DuplicateShareIndex);
        }
    }

    let mut acc = blstrs::G2Projective::from(blstrs::G2Affine::default());
    for (pos, (_, signature)) in subset.iter().enumerate() {
        blst_signature(signature)?;
        let point = blstrs::G2Affine::from_compressed(signature.as_bytes())
            .into_option()
            .ok_or(BlsError::InvalidSignature)?;
        let coeff = lagrange_at_zero(pos, subset)?;
        acc += point * coeff;
    }
    let affine = blstrs::G2Affine::from(acc);
    let combined = BlsSignature::from_bytes(affine.to_compressed());
    blst_signature(&combined)?;
    Ok(combined)
}

#[allow(clippy::arithmetic_side_effects)] // modular field arithmetic
fn lagrange_at_zero(pos: usize, entries: &[(u16, &BlsSignature)]) -> Result<blstrs::Scalar, BlsError> {
    let xi = blstrs::Scalar::from(u64::from(entries[pos].0));
    let mut numerator = blstrs::Scalar::from(1_u64);
    let mut denominator = blstrs::Scalar::from(1_u64);
    for (other_pos, (index, _)) in entries.iter().enumerate() {
        if other_pos == pos {
            continue;
        }
        let xj = blstrs::Scalar::from(u64::from(*index));
        if xj == xi {
            return Err(BlsError::DuplicateShareIndex);
        }
        numerator *= xj;
        denominator *= xj - xi;
    }
    if denominator == blstrs::Scalar::from(0_u64) {
        return Err(BlsError::InterpolationFailed);
    }
    Ok(numerator * scalar_inverse(denominator))
}

/// Fermat inverse `v^(r-2)` over the BLS12-381 scalar field (reviewed
/// pattern; avoids pulling the `ff` trait crate into the dependency set).
#[allow(clippy::arithmetic_side_effects)] // modular field arithmetic
fn scalar_inverse(value: blstrs::Scalar) -> blstrs::Scalar {
    const MODULUS_MINUS_2: [u64; 4] = [
        0xffff_fffe_ffff_ffff,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];
    scalar_pow(value, MODULUS_MINUS_2)
}

#[allow(clippy::arithmetic_side_effects)] // modular field arithmetic
fn scalar_pow(mut base: blstrs::Scalar, exponent: [u64; 4]) -> blstrs::Scalar {
    let mut acc = blstrs::Scalar::from(1_u64);
    for limb in exponent {
        for bit in 0..64 {
            if ((limb >> bit) & 1) == 1 {
                acc *= base;
            }
            base.square_assign();
        }
    }
    acc
}

pub(crate) fn public_key_to_g1(
    public_key: &BlsPublicKey,
) -> Result<blstrs::G1Projective, BlsError> {
    blst_public_key(public_key)?;
    let affine = blstrs::G1Affine::from_compressed(public_key.as_bytes())
        .into_option()
        .ok_or(BlsError::InvalidCommitment)?;
    Ok(blstrs::G1Projective::from(affine))
}

pub(crate) fn g1_to_public_key(point: blstrs::G1Projective) -> Result<BlsPublicKey, BlsError> {
    let affine = blstrs::G1Affine::from(point);
    let public_key = BlsPublicKey::from_bytes(affine.to_compressed());
    blst_public_key(&public_key)?;
    Ok(public_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_share_index_is_rejected() {
        let sk = BlsSecretKey::from_seed([5; 32]).unwrap();
        let commitments = vec![sk.public_key()];
        assert_eq!(
            feldman_share_public_key(&commitments, 0).unwrap_err(),
            BlsError::InvalidShareIndex
        );
    }

    #[test]
    fn empty_commitments_are_rejected() {
        assert_eq!(
            feldman_share_public_key(&[], 1).unwrap_err(),
            BlsError::EmptyCommitments
        );
        assert_eq!(
            feldman_group_public_key(&[Vec::new()]).unwrap_err(),
            BlsError::EmptyCommitments
        );
    }

    #[test]
    fn combine_rejects_non_adjacent_duplicates_and_short_sets() {
        let sk = BlsSecretKey::from_seed([6; 32]).unwrap();
        let sig = sk
            .sign_domain(crate::DomainId::BlsDkg, b"partial")
            .unwrap();
        // Duplicate hidden at non-adjacent positions.
        let entries = [(1_u16, &sig), (2_u16, &sig), (1_u16, &sig)];
        assert_eq!(
            bls_threshold_combine(&entries, 3).unwrap_err(),
            BlsError::DuplicateShareIndex
        );
        assert_eq!(
            bls_threshold_combine(&entries[..1], 2).unwrap_err(),
            BlsError::ThresholdTooFewShares
        );
        assert_eq!(
            bls_threshold_combine(&entries, 0).unwrap_err(),
            BlsError::ThresholdTooFewShares
        );
        let zero_indexed = [(0_u16, &sig)];
        assert_eq!(
            bls_threshold_combine(&zero_indexed, 1).unwrap_err(),
            BlsError::InvalidShareIndex
        );
    }
}
