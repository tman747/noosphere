//! Domain-prefixed Ed25519 signatures (ed25519-dalek v2, strict verification).
//!
//! Signing input is always `context_string || parts...` where the context is
//! an `ED25519_PREFIX` registry row. Verification uses `verify_strict`, which
//! additionally rejects small-order/mixed-order public keys and
//! non-canonical `R` encodings.

use crate::domains::{DomainId, DomainKind};
use crate::error::CryptoError;
use crate::hash::write_hex;
use core::fmt;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{verify_batch, Signature as DalekSignature, Signer, SigningKey, VerifyingKey};

/// A 32-byte Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps raw public-key bytes (validated at verification time).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes into the key bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// Canonical, non-weak Ed25519 key with its Edwards point decoded once.
/// Construction is fallible and the inner verifier type is never exposed.
#[derive(Clone)]
pub struct PreparedPublicKey(VerifyingKey);

impl fmt::Debug for PreparedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedPublicKey(")?;
        write_hex(f, &self.0.to_bytes())?;
        f.write_str(")")
    }
}

/// Validates and decodes an Ed25519 public key for repeated verification.
pub fn prepare_public_key(public_key: &PublicKey) -> Result<PreparedPublicKey, CryptoError> {
    let key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    if key.is_weak() || key.to_bytes() != *public_key.as_bytes() {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    Ok(PreparedPublicKey(key))
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wraps raw signature bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrows the signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Consumes into the signature bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// An Ed25519 signing keypair.
///
/// Constructed only from caller-supplied seed bytes; this crate never draws
/// entropy itself. Production participants feed OS-CSPRNG output.
#[derive(Clone)]
pub struct Keypair(SigningKey);

impl Keypair {
    /// Deterministic keypair from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// The verifying key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs `context_string || parts...` under a registered
    /// `ED25519_PREFIX` domain.
    pub fn sign_domain(&self, domain: DomainId, parts: &[&[u8]]) -> Result<Signature, CryptoError> {
        domain.require_kind(DomainKind::Ed25519Prefix)?;
        Ok(Signature(
            self.0.sign(&domain_message(domain, parts)).to_bytes(),
        ))
    }

    /// Raw (un-prefixed) signing, for standard-vector conformance only.
    #[cfg(test)]
    pub(crate) fn sign_raw(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

fn domain_message(domain: DomainId, parts: &[&[u8]]) -> Vec<u8> {
    let context = domain.context().as_bytes();
    let total = parts
        .iter()
        .fold(context.len(), |acc, p| acc.saturating_add(p.len()));
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(context);
    for part in parts {
        msg.extend_from_slice(part);
    }
    msg
}

/// Strictly verifies a domain-prefixed signature over
/// `context_string || parts...`.
pub fn verify_domain(
    domain: DomainId,
    public_key: &PublicKey,
    parts: &[&[u8]],
    signature: &Signature,
) -> Result<(), CryptoError> {
    domain.require_kind(DomainKind::Ed25519Prefix)?;
    verify_raw(public_key, &domain_message(domain, parts), signature)
}

/// Strictly verifies a batch of domain-prefixed signatures where each entry
/// signs one byte slice (`context_string || part`). The batch equation uses
/// deterministic transcript-derived coefficients. Public keys and signature
/// `R` points receive the same canonical/small-order rejection checks as
/// [`verify_domain`].
pub fn verify_domain_batch(
    domain: DomainId,
    public_keys: &[PublicKey],
    parts: &[&[u8]],
    signatures: &[Signature],
) -> Result<(), CryptoError> {
    let prepared = public_keys
        .iter()
        .map(prepare_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    verify_domain_batch_prepared(domain, &prepared, parts, signatures)
}

/// Batch verification using public keys validated and decoded by
/// [`prepare_public_key`]. This is byte-for-byte the same signature law as
/// [`verify_domain_batch`] without repeating public-key decompression.
pub fn verify_domain_batch_prepared(
    domain: DomainId,
    public_keys: &[PreparedPublicKey],
    parts: &[&[u8]],
    signatures: &[Signature],
) -> Result<(), CryptoError> {
    domain.require_kind(DomainKind::Ed25519Prefix)?;
    if public_keys.len() != parts.len() || public_keys.len() != signatures.len() {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    if public_keys.is_empty() {
        return Ok(());
    }

    let verifying_keys = public_keys
        .iter()
        .map(|public_key| public_key.0)
        .collect::<Vec<_>>();
    let mut dalek_signatures = Vec::with_capacity(signatures.len());
    for signature in signatures {
        let dalek_signature = DalekSignature::from_bytes(signature.as_bytes());
        let mut r_bytes = [0_u8; 32];
        r_bytes.copy_from_slice(&signature.as_bytes()[..32]);
        let compressed_r = CompressedEdwardsY(r_bytes);
        let r = compressed_r
            .decompress()
            .ok_or(CryptoError::SignatureVerificationFailed)?;
        if r.is_small_order() || r.compress() != compressed_r {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        dalek_signatures.push(dalek_signature);
    }

    let context = domain.context().as_bytes();
    let encoded_len = parts.iter().fold(0_usize, |total, part| {
        total
            .saturating_add(context.len())
            .saturating_add(part.len())
    });
    let mut encoded_messages = Vec::with_capacity(encoded_len);
    let mut ranges = Vec::with_capacity(parts.len());
    for part in parts {
        let start = encoded_messages.len();
        encoded_messages.extend_from_slice(context);
        encoded_messages.extend_from_slice(part);
        ranges.push((start, encoded_messages.len()));
    }
    let messages = ranges
        .iter()
        .map(|(start, end)| &encoded_messages[*start..*end])
        .collect::<Vec<_>>();
    verify_batch(&messages, &dalek_signatures, &verifying_keys)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Raw strict verification (no domain prefix); crate-internal so that every
/// public verification path stays domain-bound.
pub(crate) fn verify_raw(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature = DalekSignature::from_bytes(signature.as_bytes());
    key.verify_strict(msg, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip_per_domain() {
        let kp = Keypair::from_seed([7; 32]);
        let sig = kp.sign_domain(DomainId::SigTx, &[b"payload"]).unwrap();
        verify_domain(DomainId::SigTx, &kp.public_key(), &[b"payload"], &sig).unwrap();
        // The same signature must not verify under a sibling domain.
        let err =
            verify_domain(DomainId::SigHeader, &kp.public_key(), &[b"payload"], &sig).unwrap_err();
        assert_eq!(err, CryptoError::SignatureVerificationFailed);
    }

    #[test]
    fn non_signature_domain_kinds_are_rejected() {
        let kp = Keypair::from_seed([7; 32]);
        assert!(matches!(
            kp.sign_domain(DomainId::TxId, &[b"x"]).unwrap_err(),
            CryptoError::WrongDomainKind { .. }
        ));
        let sig = kp.sign_domain(DomainId::SigTx, &[b"x"]).unwrap();
        assert!(matches!(
            verify_domain(DomainId::BlsVote, &kp.public_key(), &[b"x"], &sig).unwrap_err(),
            CryptoError::WrongDomainKind { .. }
        ));
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        let kp = Keypair::from_seed([7; 32]);
        let sig = kp.sign_domain(DomainId::SigTx, &[b"x"]).unwrap();
        // y = 2 is not on the curve: decompression fails.
        let mut bad_bytes = [0_u8; 32];
        bad_bytes[0] = 2;
        let bad = PublicKey::from_bytes(bad_bytes);
        assert_eq!(
            verify_domain(DomainId::SigTx, &bad, &[b"x"], &sig).unwrap_err(),
            CryptoError::InvalidPublicKey
        );
    }

    #[test]
    fn strict_batch_verification_matches_individual_results() {
        let keypairs = (0_u8..64)
            .map(|seed| Keypair::from_seed([seed; 32]))
            .collect::<Vec<_>>();
        let messages = (0_u8..64).map(|value| [value; 32]).collect::<Vec<_>>();
        let public_keys = keypairs.iter().map(Keypair::public_key).collect::<Vec<_>>();
        let mut signatures = keypairs
            .iter()
            .zip(&messages)
            .map(|(keypair, message)| keypair.sign_domain(DomainId::SigTx, &[message]).unwrap())
            .collect::<Vec<_>>();
        let parts = messages
            .iter()
            .map(<[u8; 32]>::as_slice)
            .collect::<Vec<_>>();

        verify_domain_batch(DomainId::SigTx, &public_keys, &parts, &signatures).unwrap();
        let replacement = keypairs[0]
            .sign_domain(DomainId::SigTx, &[&messages[1]])
            .unwrap();
        signatures[1] = replacement;
        assert_eq!(
            verify_domain_batch(DomainId::SigTx, &public_keys, &parts, &signatures).unwrap_err(),
            CryptoError::SignatureVerificationFailed
        );
    }

    #[test]
    fn batch_verification_rejects_weak_signature_points() {
        let keypair = Keypair::from_seed([9; 32]);
        let public_key = keypair.public_key();
        let message = [3_u8; 32];
        let mut weak_signature = [0_u8; 64];
        weak_signature[0] = 1;
        let signature = Signature::from_bytes(weak_signature);
        assert_eq!(
            verify_domain_batch(
                DomainId::SigTx,
                &[public_key],
                &[message.as_slice()],
                &[signature],
            )
            .unwrap_err(),
            CryptoError::SignatureVerificationFailed
        );
    }
}
