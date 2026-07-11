//! Closed error enums. Consensus callers match on these; variants are
//! append-only within a protocol version.

use crate::domains::DomainKind;
use thiserror::Error;

/// Errors from domain-bound hashing, Ed25519, and HKDF operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The supplied domain exists in the registry but binds a different
    /// primitive kind than the API invoked.
    #[error("domain {domain} has kind {actual:?}; this operation requires {expected:?}")]
    WrongDomainKind {
        /// `domain_id` column of the offending registry row.
        domain: &'static str,
        /// Kind required by the invoked operation.
        expected: DomainKind,
        /// Kind actually registered for the domain.
        actual: DomainKind,
    },
    /// Ed25519 public key bytes do not decode to a valid point.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// Ed25519 strict verification failed.
    #[error("Ed25519 signature verification failed")]
    SignatureVerificationFailed,
    /// HKDF expansion failed (unreachable for the fixed 32-byte output).
    #[error("HKDF derivation failed")]
    DerivationFailed,
}

/// Errors from BLS12-381 operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BlsError {
    /// The supplied domain is not a `BLS_DST` registry row.
    #[error("domain {domain} has kind {actual:?}; BLS operations require BlsDst")]
    WrongDomainKind {
        /// `domain_id` column of the offending registry row.
        domain: &'static str,
        /// Kind actually registered for the domain.
        actual: DomainKind,
    },
    /// Secret scalar is zero, not reduced, or otherwise invalid.
    #[error("invalid BLS secret key")]
    InvalidSecretKey,
    /// Public key bytes are not a valid, non-infinity G1 subgroup point.
    #[error("invalid BLS public key")]
    InvalidPublicKey,
    /// Signature bytes are not a valid, non-infinity G2 subgroup point.
    #[error("invalid BLS signature")]
    InvalidSignature,
    /// Aggregation over an empty signature set.
    #[error("BLS aggregate requires at least one signature")]
    EmptyAggregate,
    /// Aggregate verification with mismatched or empty key/message sets.
    #[error("BLS aggregate verification requires matching non-empty public keys and messages")]
    AggregateLengthMismatch,
    /// Aggregate verification with duplicate messages (rogue-key surface).
    #[error("BLS aggregate messages must be distinct")]
    DuplicateMessage,
    /// Pairing check failed.
    #[error("BLS signature verification failed")]
    SignatureVerificationFailed,
    /// Threshold combine invoked with fewer than `threshold` entries.
    #[error("BLS threshold combine requires at least t shares")]
    ThresholdTooFewShares,
    /// Threshold combine invoked with a repeated share index.
    #[error("BLS threshold share indices must be unique")]
    DuplicateShareIndex,
    /// Share index 0 would evaluate the polynomial at the group secret.
    #[error("BLS share index must be >= 1")]
    InvalidShareIndex,
    /// Lagrange interpolation degenerated (coincident evaluation points).
    #[error("BLS threshold interpolation failed")]
    InterpolationFailed,
    /// Feldman verification over an empty commitment vector.
    #[error("BLS Feldman commitments must be non-empty")]
    EmptyCommitments,
    /// A Feldman commitment did not decode to a valid G1 point.
    #[error("invalid BLS Feldman commitment")]
    InvalidCommitment,
}

/// Errors from DKG transcript validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DkgError {
    /// Threshold must satisfy `1 <= t <= n`.
    #[error("DKG threshold must satisfy 1 <= t <= n")]
    InvalidThreshold,
    /// A transcript must carry at least one contribution.
    #[error("DKG transcript has no contributions")]
    EmptyTranscript,
    /// A contribution's commitment vector length must equal the threshold.
    #[error("DKG contribution {contributor} has {got} commitments; expected {expected}")]
    CommitmentDegreeMismatch {
        /// 1-based contributor index.
        contributor: u16,
        /// Commitments carried by the contribution.
        got: usize,
        /// Required commitment count (the threshold `t`).
        expected: usize,
    },
    /// Contributor indices must be unique.
    #[error("DKG contributor index {0} appears more than once")]
    DuplicateContributor(u16),
    /// Contributor indices must lie in `1..=participants`.
    #[error("DKG contributor index {0} is outside 1..=participants")]
    ContributorOutOfRange(u16),
    /// X25519 key agreement produced the all-zero shared secret
    /// (identity / small-order peer point).
    #[error("X25519 key agreement produced an invalid all-zero shared secret")]
    InvalidSharedSecret,
    /// A commitment or derived key failed group validation.
    #[error("DKG transcript carries invalid group elements: {0}")]
    InvalidGroupElement(BlsError),
}
