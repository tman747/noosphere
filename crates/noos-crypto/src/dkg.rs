//! DKG transcript validation and share-transport key agreement — pure
//! functions over caller-supplied bytes.
//!
//! This crate validates transcripts; it does **not** run ceremonies. There
//! is no share issuance, no deterministic seed expansion, and no embedded
//! genesis material here (excluded by plan section 3.2). The consensus
//! layer owns beacon logic and transcript-root derivation.
//!
//! ## Inherited-defect repair
//!
//! The reviewed port source carried `clippy::double_must_use` on its
//! X25519 shared-secret function: a bare `#[must_use]` on a function that
//! already returns `Result` (itself `#[must_use]`). Per the plan's
//! inherited-defect rule the NOOSPHERE port repairs it: the attribute is
//! kept only on [`dkg_x25519_public_key`] (plain array return) and dropped
//! from [`dkg_x25519_shared_secret`], whose `Result` already enforces use.
//! `tests/inherited_defect.rs` guards the repair and the contract.

use crate::bls::BlsPublicKey;
use crate::error::{BlsError, DkgError};
use crate::threshold::{derive_share_public_key, feldman_group_public_key};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// One contributor's public transcript entry: a 1-based index and its
/// Feldman commitment vector (degree `t-1`, so exactly `t` commitments).
#[derive(Clone, Debug)]
pub struct DkgContribution<'a> {
    /// 1-based contributor index, unique within the transcript.
    pub contributor_index: u16,
    /// Compressed G1 commitments `[G1*a_0, ..., G1*a_(t-1)]`.
    pub commitments: &'a [BlsPublicKey],
}

/// The deterministic public outcome of a valid transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgTranscriptSummary {
    /// Group public key: sum of every contributor's constant term.
    pub group_public_key: BlsPublicKey,
    /// Aggregate share public keys for indices `1..=participants`,
    /// in index order.
    pub share_public_keys: Vec<BlsPublicKey>,
}

/// Validates a DKG transcript's public structure and derives its keys.
///
/// Checks, in order: threshold bounds (`1 <= t <= n`), non-empty
/// contribution set, per-contribution commitment degree (`== t`),
/// contributor-index uniqueness and range (`1..=n`), validity of every
/// commitment point (subgroup member, not infinity), and derivability of
/// the group key and all `n` share keys.
pub fn validate_dkg_transcript(
    threshold: u16,
    participants: u16,
    contributions: &[DkgContribution<'_>],
) -> Result<DkgTranscriptSummary, DkgError> {
    if threshold == 0 || threshold > participants {
        return Err(DkgError::InvalidThreshold);
    }
    if contributions.is_empty() {
        return Err(DkgError::EmptyTranscript);
    }
    for (pos, contribution) in contributions.iter().enumerate() {
        let index = contribution.contributor_index;
        if index == 0 || index > participants {
            return Err(DkgError::ContributorOutOfRange(index));
        }
        if contributions
            .iter()
            .skip(pos.saturating_add(1))
            .any(|other| other.contributor_index == index)
        {
            return Err(DkgError::DuplicateContributor(index));
        }
        if contribution.commitments.len() != usize::from(threshold) {
            return Err(DkgError::CommitmentDegreeMismatch {
                contributor: index,
                got: contribution.commitments.len(),
                expected: usize::from(threshold),
            });
        }
        for commitment in contribution.commitments {
            commitment
                .validate()
                .map_err(DkgError::InvalidGroupElement)?;
        }
    }

    let commitments_all: Vec<Vec<BlsPublicKey>> = contributions
        .iter()
        .map(|c| c.commitments.to_vec())
        .collect();
    let group_public_key =
        feldman_group_public_key(&commitments_all).map_err(DkgError::InvalidGroupElement)?;
    let share_public_keys = (1..=participants)
        .map(|x| derive_share_public_key(&commitments_all, x))
        .collect::<Result<Vec<_>, BlsError>>()
        .map_err(DkgError::InvalidGroupElement)?;

    Ok(DkgTranscriptSummary {
        group_public_key,
        share_public_keys,
    })
}

/// Derives the X25519 public key for a DKG share-transport channel.
#[must_use]
pub fn dkg_x25519_public_key(secret: [u8; 32]) -> [u8; 32] {
    X25519_BASEPOINT.mul_clamped(secret).to_bytes()
}

/// X25519 key agreement for encrypted share transport.
///
/// Contributory-behavior contract: an all-zero shared secret (the peer
/// supplied the identity or another small-order point) is rejected, never
/// returned as key material. The `Result` return is inherently
/// `#[must_use]`; no extra attribute (inherited-defect repair).
pub fn dkg_x25519_shared_secret(
    secret: [u8; 32],
    peer_public: [u8; 32],
) -> Result<[u8; 32], DkgError> {
    let shared_secret = MontgomeryPoint(peer_public).mul_clamped(secret);
    // MontgomeryPoint equality is constant-time.
    if shared_secret == MontgomeryPoint([0_u8; 32]) {
        return Err(DkgError::InvalidSharedSecret);
    }
    Ok(shared_secret.to_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bls::BlsSecretKey;

    fn commitments(seed_base: u8, t: u16) -> Vec<BlsPublicKey> {
        (0..t)
            .map(|i| {
                #[allow(clippy::unwrap_used)]
                let sk =
                    BlsSecretKey::from_seed([seed_base.wrapping_add(i as u8); 32]).unwrap();
                sk.public_key()
            })
            .collect()
    }

    #[test]
    fn structural_errors_are_reported_in_order() {
        let comm = commitments(1, 2);
        let one = [DkgContribution {
            contributor_index: 1,
            commitments: &comm,
        }];
        assert_eq!(
            validate_dkg_transcript(0, 3, &one).unwrap_err(),
            DkgError::InvalidThreshold
        );
        assert_eq!(
            validate_dkg_transcript(4, 3, &one).unwrap_err(),
            DkgError::InvalidThreshold
        );
        assert_eq!(
            validate_dkg_transcript(2, 3, &[]).unwrap_err(),
            DkgError::EmptyTranscript
        );
        let out_of_range = [DkgContribution {
            contributor_index: 4,
            commitments: &comm,
        }];
        assert_eq!(
            validate_dkg_transcript(2, 3, &out_of_range).unwrap_err(),
            DkgError::ContributorOutOfRange(4)
        );
        let duplicated = [
            DkgContribution {
                contributor_index: 1,
                commitments: &comm,
            },
            DkgContribution {
                contributor_index: 1,
                commitments: &comm,
            },
        ];
        assert_eq!(
            validate_dkg_transcript(2, 3, &duplicated).unwrap_err(),
            DkgError::DuplicateContributor(1)
        );
        let short = [DkgContribution {
            contributor_index: 1,
            commitments: &comm[..1],
        }];
        assert_eq!(
            validate_dkg_transcript(2, 3, &short).unwrap_err(),
            DkgError::CommitmentDegreeMismatch {
                contributor: 1,
                got: 1,
                expected: 2
            }
        );
    }

    #[test]
    fn invalid_commitment_point_is_rejected() {
        let mut comm = commitments(1, 2);
        comm[1] = BlsPublicKey::from_bytes([0xff; 48]);
        let bad = [DkgContribution {
            contributor_index: 1,
            commitments: &comm,
        }];
        assert!(matches!(
            validate_dkg_transcript(2, 3, &bad).unwrap_err(),
            DkgError::InvalidGroupElement(BlsError::InvalidPublicKey)
        ));
    }

    #[test]
    fn valid_transcript_derives_deterministic_keys() {
        let comm_a = commitments(1, 2);
        let comm_b = commitments(11, 2);
        let transcript = [
            DkgContribution {
                contributor_index: 1,
                commitments: &comm_a,
            },
            DkgContribution {
                contributor_index: 2,
                commitments: &comm_b,
            },
        ];
        let summary = validate_dkg_transcript(2, 3, &transcript).unwrap();
        assert_eq!(summary.share_public_keys.len(), 3);
        // Deterministic: same transcript, same outcome.
        let again = validate_dkg_transcript(2, 3, &transcript).unwrap();
        assert_eq!(summary, again);
    }
}
