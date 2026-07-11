//! Closed domain registry generated from `protocol/spec/crypto-domains-v1.csv`.
//!
//! Every public hashing, signing, verification, and key-derivation entry
//! point in this crate takes a [`DomainId`], never a raw context string.
//! The registry is closed: unknown domains cannot be expressed, and a
//! domain of the wrong kind is rejected before any cryptographic work.

/// The `kind` column of the registry: which primitive a domain binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainKind {
    /// BLAKE3-256 over `context_string || parts`.
    Blake3Context,
    /// Keyed BLAKE3-256 over `context_string || parts` with a caller key.
    Blake3Keyed,
    /// Ed25519 signature over `context_string || parts`.
    Ed25519Prefix,
    /// BLS12-381 hash-to-G2 domain-separation tag.
    BlsDst,
    /// HKDF-SHA-256 derivation: fixed salt, `info = context_string || suffix`.
    HkdfInfo,
}

include!(concat!(env!("OUT_DIR"), "/domain_registry.rs"));

impl DomainId {
    /// Ensures this domain is of `expected` kind before any primitive runs.
    pub(crate) fn require_kind(self, expected: DomainKind) -> Result<(), crate::CryptoError> {
        if self.kind() == expected {
            Ok(())
        } else {
            Err(crate::CryptoError::WrongDomainKind {
                domain: self.registry_id(),
                expected,
                actual: self.kind(),
            })
        }
    }
}
