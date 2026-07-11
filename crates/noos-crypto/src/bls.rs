//! BLS12-381 signatures over `blst` (v0.3.16), `min_pk` layout.
//!
//! # Ciphersuite choice
//!
//! Every registered `BLS_DST` row ends in `..._BLS12381G2_XMD:SHA-256_SSWU_RO_`:
//! messages hash to **G2**, so signatures live in G2 (96 bytes) and public
//! keys in G1 (48 bytes). In `blst` naming that is the `min_pk` module —
//! the same variant the reviewed Ascent-era code used and the same shape as
//! the widely deployed Ethereum ciphersuite family. Small public keys keep
//! certificate aggregation over hundreds of witness keys cheap. (The
//! registry's `algorithm` label "G2 min-sig" is descriptive prose meaning
//! "signatures on G2"; the DST suffix is the authoritative wire constant.)
//!
//! # Validation policy (retained from the reviewed port source)
//!
//! * public keys: `key_validate` — subgroup check, infinity rejected;
//! * signatures: `sig_validate(_, true)` — subgroup check, infinity rejected;
//! * aggregate over an empty set is an error;
//! * aggregate verification requires distinct messages and matching lengths.

use crate::domains::{DomainId, DomainKind};
use crate::error::BlsError;
use crate::hash::write_hex;
use core::fmt;

/// A compressed 48-byte G1 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlsPublicKey([u8; 48]);

impl BlsPublicKey {
    /// Wraps compressed public-key bytes (validated on use).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    /// Borrows the compressed bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Consumes into the compressed bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 48] {
        self.0
    }

    /// Full validation: decode, subgroup check, infinity rejected.
    pub fn validate(&self) -> Result<(), BlsError> {
        blst_public_key(self).map(|_| ())
    }
}

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlsPublicKey(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// A compressed 96-byte G2 signature.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlsSignature([u8; 96]);

impl BlsSignature {
    /// Wraps compressed signature bytes (validated on use).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 96]) -> Self {
        Self(bytes)
    }

    /// Borrows the compressed bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }

    /// Consumes into the compressed bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 96] {
        self.0
    }

    /// Full validation: decode, subgroup check, infinity rejected.
    pub fn validate(&self) -> Result<(), BlsError> {
        blst_signature(self).map(|_| ())
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlsSignature(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// A BLS secret scalar.
///
/// Constructed only from caller-supplied bytes; this crate never draws
/// entropy and ships no deterministic share-issuance helpers (excluded by
/// plan section 3.2). Ceremony participants use OS CSPRNGs.
#[derive(Clone)]
pub struct BlsSecretKey(blst::min_pk::SecretKey);

impl BlsSecretKey {
    /// Derives a secret key from >= 32 bytes of caller entropy via the
    /// RFC 9380 `KeyGen` path.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, BlsError> {
        blst::min_pk::SecretKey::key_gen(&seed, &[])
            .map(Self)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    /// Deserializes a big-endian scalar; zero and non-reduced scalars are
    /// rejected.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BlsError> {
        if bytes == [0_u8; 32] {
            return Err(BlsError::InvalidSecretKey);
        }
        blst::min_pk::SecretKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    /// Serializes the big-endian scalar.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The corresponding G1 public key.
    #[must_use]
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk().to_bytes())
    }

    /// Signs `msg` under a registered `BLS_DST` domain.
    pub fn sign_domain(&self, domain: DomainId, msg: &[u8]) -> Result<BlsSignature, BlsError> {
        let dst = domain_dst(domain)?;
        Ok(BlsSignature(self.0.sign(msg, dst, &[]).to_bytes()))
    }

    /// Raw-DST signing, for standard-vector conformance only.
    #[cfg(test)]
    pub(crate) fn sign_with_dst(&self, msg: &[u8], dst: &[u8]) -> BlsSignature {
        BlsSignature(self.0.sign(msg, dst, &[]).to_bytes())
    }
}

impl fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsSecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

fn domain_dst(domain: DomainId) -> Result<&'static [u8], BlsError> {
    if domain.kind() == DomainKind::BlsDst {
        Ok(domain.context().as_bytes())
    } else {
        Err(BlsError::WrongDomainKind {
            domain: domain.registry_id(),
            actual: domain.kind(),
        })
    }
}

/// Verifies a single signature under a registered `BLS_DST` domain.
pub fn bls_verify(
    domain: DomainId,
    public_key: &BlsPublicKey,
    msg: &[u8],
    signature: &BlsSignature,
) -> Result<(), BlsError> {
    let dst = domain_dst(domain)?;
    verify_with_dst(public_key, msg, signature, dst)
}

pub(crate) fn verify_with_dst(
    public_key: &BlsPublicKey,
    msg: &[u8],
    signature: &BlsSignature,
    dst: &[u8],
) -> Result<(), BlsError> {
    let public_key = blst_public_key(public_key)?;
    let signature = blst_signature(signature)?;
    bls_verify_result(signature.verify(false, msg, dst, &[], &public_key, true))
}

/// Aggregates one or more validated signatures; the empty set is an error.
pub fn bls_aggregate(signatures: &[BlsSignature]) -> Result<BlsSignature, BlsError> {
    if signatures.is_empty() {
        return Err(BlsError::EmptyAggregate);
    }
    let parsed = signatures
        .iter()
        .map(blst_signature)
        .collect::<Result<Vec<_>, _>>()?;
    let refs = parsed.iter().collect::<Vec<_>>();
    let aggregate = blst::min_pk::AggregateSignature::aggregate(&refs, false)
        .map_err(|_| BlsError::InvalidSignature)?;
    Ok(BlsSignature(aggregate.to_signature().to_bytes()))
}

/// Verifies an aggregate over pairwise-distinct messages under a registered
/// `BLS_DST` domain.
pub fn bls_aggregate_verify(
    domain: DomainId,
    public_keys: &[BlsPublicKey],
    messages: &[&[u8]],
    signature: &BlsSignature,
) -> Result<(), BlsError> {
    let dst = domain_dst(domain)?;
    aggregate_verify_with_dst(public_keys, messages, signature, dst)
}

pub(crate) fn aggregate_verify_with_dst(
    public_keys: &[BlsPublicKey],
    messages: &[&[u8]],
    signature: &BlsSignature,
    dst: &[u8],
) -> Result<(), BlsError> {
    if public_keys.is_empty() || public_keys.len() != messages.len() {
        return Err(BlsError::AggregateLengthMismatch);
    }
    ensure_distinct_messages(messages)?;
    let parsed_keys = public_keys
        .iter()
        .map(blst_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    let key_refs = parsed_keys.iter().collect::<Vec<_>>();
    let signature = blst_signature(signature)?;
    bls_verify_result(signature.aggregate_verify(false, messages, dst, &key_refs, false))
}

/// Verifies an aggregate where every signer signed the same message
/// (finality-certificate shape) under a registered `BLS_DST` domain.
pub fn bls_fast_aggregate_verify(
    domain: DomainId,
    public_keys: &[BlsPublicKey],
    msg: &[u8],
    signature: &BlsSignature,
) -> Result<(), BlsError> {
    let dst = domain_dst(domain)?;
    fast_aggregate_verify_with_dst(public_keys, msg, signature, dst)
}

pub(crate) fn fast_aggregate_verify_with_dst(
    public_keys: &[BlsPublicKey],
    msg: &[u8],
    signature: &BlsSignature,
    dst: &[u8],
) -> Result<(), BlsError> {
    if public_keys.is_empty() {
        return Err(BlsError::AggregateLengthMismatch);
    }
    let parsed_keys = public_keys
        .iter()
        .map(blst_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    let key_refs = parsed_keys.iter().collect::<Vec<_>>();
    let signature = blst_signature(signature)?;
    bls_verify_result(signature.fast_aggregate_verify(false, msg, dst, &key_refs))
}

/// Produces a proof of possession: the key signs its own compressed public
/// key under the `D-BLS-POP` domain.
pub fn bls_pop_prove(secret: &BlsSecretKey) -> Result<BlsSignature, BlsError> {
    let public_key = secret.public_key();
    secret.sign_domain(DomainId::BlsPop, public_key.as_bytes())
}

/// Verifies a proof of possession under the `D-BLS-POP` domain.
pub fn bls_pop_verify(
    public_key: &BlsPublicKey,
    proof: &BlsSignature,
) -> Result<(), BlsError> {
    bls_verify(DomainId::BlsPop, public_key, public_key.as_bytes(), proof)
}

pub(crate) fn blst_public_key(
    public_key: &BlsPublicKey,
) -> Result<blst::min_pk::PublicKey, BlsError> {
    blst::min_pk::PublicKey::key_validate(public_key.as_bytes())
        .map_err(|_| BlsError::InvalidPublicKey)
}

pub(crate) fn blst_signature(
    signature: &BlsSignature,
) -> Result<blst::min_pk::Signature, BlsError> {
    blst::min_pk::Signature::sig_validate(signature.as_bytes(), true)
        .map_err(|_| BlsError::InvalidSignature)
}

fn bls_verify_result(error: blst::BLST_ERROR) -> Result<(), BlsError> {
    if error == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(BlsError::SignatureVerificationFailed)
    }
}

fn ensure_distinct_messages(messages: &[&[u8]]) -> Result<(), BlsError> {
    for (index, message) in messages.iter().enumerate() {
        for other in messages.iter().skip(index.saturating_add(1)) {
            if message == other {
                return Err(BlsError::DuplicateMessage);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn key(byte: u8) -> BlsSecretKey {
        BlsSecretKey::from_seed([byte; 32]).unwrap()
    }

    #[test]
    fn sign_verify_and_cross_domain_rejection() {
        let sk = key(1);
        let sig = sk.sign_domain(DomainId::BlsVote, b"checkpoint").unwrap();
        bls_verify(DomainId::BlsVote, &sk.public_key(), b"checkpoint", &sig).unwrap();
        assert_eq!(
            bls_verify(DomainId::BlsCert, &sk.public_key(), b"checkpoint", &sig).unwrap_err(),
            BlsError::SignatureVerificationFailed
        );
    }

    #[test]
    fn non_bls_domains_are_rejected() {
        let sk = key(1);
        assert!(matches!(
            sk.sign_domain(DomainId::TxId, b"m").unwrap_err(),
            BlsError::WrongDomainKind { .. }
        ));
        let sig = sk.sign_domain(DomainId::BlsVote, b"m").unwrap();
        assert!(matches!(
            bls_verify(DomainId::SigTx, &sk.public_key(), b"m", &sig).unwrap_err(),
            BlsError::WrongDomainKind { .. }
        ));
    }

    #[test]
    fn empty_aggregate_is_rejected() {
        assert_eq!(bls_aggregate(&[]).unwrap_err(), BlsError::EmptyAggregate);
    }

    #[test]
    fn duplicate_messages_are_rejected() {
        let (a, b) = (key(1), key(2));
        let s1 = a.sign_domain(DomainId::BlsVote, b"same").unwrap();
        let s2 = b.sign_domain(DomainId::BlsVote, b"same").unwrap();
        let agg = bls_aggregate(&[s1, s2]).unwrap();
        assert_eq!(
            bls_aggregate_verify(
                DomainId::BlsVote,
                &[a.public_key(), b.public_key()],
                &[b"same", b"same"],
                &agg,
            )
            .unwrap_err(),
            BlsError::DuplicateMessage
        );
    }

    #[test]
    fn length_mismatch_is_rejected() {
        let a = key(1);
        let s = a.sign_domain(DomainId::BlsVote, b"m").unwrap();
        assert_eq!(
            bls_aggregate_verify(DomainId::BlsVote, &[a.public_key()], &[], &s).unwrap_err(),
            BlsError::AggregateLengthMismatch
        );
        assert_eq!(
            bls_fast_aggregate_verify(DomainId::BlsVote, &[], b"m", &s).unwrap_err(),
            BlsError::AggregateLengthMismatch
        );
    }

    #[test]
    fn malformed_and_infinity_keys_are_rejected() {
        let mut inf = [0_u8; 48];
        inf[0] = 0xc0;
        assert_eq!(
            BlsPublicKey::from_bytes(inf).validate().unwrap_err(),
            BlsError::InvalidPublicKey
        );
        assert_eq!(
            BlsPublicKey::from_bytes([0xff; 48]).validate().unwrap_err(),
            BlsError::InvalidPublicKey
        );
        let mut sig_inf = [0_u8; 96];
        sig_inf[0] = 0xc0;
        assert_eq!(
            BlsSignature::from_bytes(sig_inf).validate().unwrap_err(),
            BlsError::InvalidSignature
        );
    }

    #[test]
    fn zero_secret_scalar_is_rejected() {
        assert_eq!(
            BlsSecretKey::from_bytes([0; 32]).unwrap_err(),
            BlsError::InvalidSecretKey
        );
    }

    #[test]
    fn proof_of_possession_roundtrip() {
        let sk = key(9);
        let pop = bls_pop_prove(&sk).unwrap();
        bls_pop_verify(&sk.public_key(), &pop).unwrap();
        // A different key's proof must not transfer.
        let other = key(10);
        assert_eq!(
            bls_pop_verify(&other.public_key(), &pop).unwrap_err(),
            BlsError::SignatureVerificationFailed
        );
    }

    #[test]
    fn fast_aggregate_verify_same_message() {
        let (a, b) = (key(3), key(4));
        let s1 = a.sign_domain(DomainId::BlsCert, b"cert").unwrap();
        let s2 = b.sign_domain(DomainId::BlsCert, b"cert").unwrap();
        let agg = bls_aggregate(&[s1, s2]).unwrap();
        bls_fast_aggregate_verify(
            DomainId::BlsCert,
            &[a.public_key(), b.public_key()],
            b"cert",
            &agg,
        )
        .unwrap();
    }
}
