//! # noos-crypto — NOOSPHERE L0 cryptography
//!
//! Fresh implementation (plan section 3.2-3.4) of the reviewed primitive
//! set under the NOOSPHERE identity: domain-bound BLAKE3-256 hashing,
//! Ed25519 with strict verification, BLS12-381 signatures/aggregation,
//! Feldman/threshold verification, DKG transcript validation, and
//! HKDF-SHA-256 derivations.
//!
//! ## Domain discipline
//!
//! `protocol/spec/crypto-domains-v1.csv` is a **closed** registry. The
//! build script generates [`DomainId`] from it; every public hash, sign,
//! verify, and derive entry point takes a `DomainId`, never a raw string,
//! and rejects a domain of the wrong kind before any cryptographic work.
//! There is no generic unkeyed commitment API.
//!
//! ## BLS ciphersuite
//!
//! `blst` 0.3.16, `min_pk` layout: 48-byte G1 public keys, 96-byte G2
//! signatures, hash-to-G2 per the registered
//! `NOOS-BLS-*-V1_BLS12381G2_XMD:SHA-256_SSWU_RO_` DSTs. See `bls`
//! module docs for the full rationale.
//!
//! ## Exclusions (plan section 3.2)
//!
//! No ceremony tooling, no deterministic share issuance, no simulated
//! randomness, no embedded genesis secret material. Key types are built
//! only from caller-supplied bytes; production entropy comes from OS
//! CSPRNGs at the ceremony layer. A source-scan test enforces the
//! exclusion list.

mod bls;
mod dkg;
mod domains;
mod ed25519;
mod error;
mod hash;
mod hkdf;
mod threshold;

#[cfg(test)]
mod vector_tests;

pub use bls::{
    bls_aggregate, bls_aggregate_verify, bls_fast_aggregate_verify, bls_pop_prove,
    bls_pop_verify, bls_verify, BlsPublicKey, BlsSecretKey, BlsSignature,
};
pub use dkg::{
    dkg_x25519_public_key, dkg_x25519_shared_secret, validate_dkg_transcript, DkgContribution,
    DkgTranscriptSummary,
};
pub use domains::{DomainId, DomainKind, DOMAIN_COUNT};
pub use ed25519::{verify_domain, Keypair, PublicKey, Signature};
pub use error::{BlsError, CryptoError, DkgError};
pub use hash::{hash_domain, keyed_hash_domain, Hash32};
pub use hkdf::{hkdf_derive, HKDF_OUTPUT_LEN};
pub use threshold::{
    bls_threshold_combine, derive_share_public_key, feldman_group_public_key,
    feldman_share_public_key, feldman_verify_share,
};
