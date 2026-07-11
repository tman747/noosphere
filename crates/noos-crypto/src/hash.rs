//! Domain-bound BLAKE3-256 hashing.
//!
//! Construction (plan section 2.4): `H(ctx || parts...)` where `ctx` is the
//! exact `context_string` bytes of a registered `BLAKE3_CONTEXT` row and
//! `parts` are caller-supplied canonical fixed-width encodings. The registry
//! is prefix-free by CI law, so the concatenation is unambiguous.
//!
//! There is deliberately **no** generic unkeyed hash entry point: every
//! commitment binds a registered domain (chain / object / version context).

use crate::domains::{DomainId, DomainKind};
use crate::error::CryptoError;
use core::fmt;

/// A 32-byte BLAKE3-256 digest.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// The all-zero digest (sparse-tree placeholder semantics live upstream).
    pub const ZERO: Self = Self([0_u8; 32]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes into the digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash32(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::LowerHex for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

pub(crate) fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// Domain-bound hash: `BLAKE3-256(context_string || parts[0] || parts[1] || ...)`.
///
/// `domain` must be a `BLAKE3_CONTEXT` registry row; any other kind is
/// rejected before hashing.
pub fn hash_domain(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, CryptoError> {
    domain.require_kind(DomainKind::Blake3Context)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.context().as_bytes());
    for part in parts {
        hasher.update(part);
    }
    Ok(Hash32(*hasher.finalize().as_bytes()))
}

/// Keyed domain-bound hash:
/// `BLAKE3-256-keyed(key, context_string || parts[0] || ...)`.
///
/// `domain` must be a `BLAKE3_KEYED` registry row (e.g. the Ground ticket,
/// keyed by the Ground challenge).
pub fn keyed_hash_domain(
    domain: DomainId,
    key: &Hash32,
    parts: &[&[u8]],
) -> Result<Hash32, CryptoError> {
    domain.require_kind(DomainKind::Blake3Keyed)?;
    let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
    hasher.update(domain.context().as_bytes());
    for part in parts {
        hasher.update(part);
    }
    Ok(Hash32(*hasher.finalize().as_bytes()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn wrong_kind_is_rejected_before_hashing() {
        let err = hash_domain(DomainId::BlsVote, &[b"payload"]).unwrap_err();
        assert!(matches!(err, CryptoError::WrongDomainKind { .. }));
        let err = keyed_hash_domain(DomainId::TxId, &Hash32::ZERO, &[b"payload"]).unwrap_err();
        assert!(matches!(err, CryptoError::WrongDomainKind { .. }));
        let err = hash_domain(DomainId::GroundTicket, &[b"payload"]).unwrap_err();
        assert!(matches!(err, CryptoError::WrongDomainKind { .. }));
    }

    #[test]
    fn parts_are_order_sensitive_and_domain_separated() {
        let a = hash_domain(DomainId::TxId, &[b"ab", b"cd"]).unwrap();
        let b = hash_domain(DomainId::TxId, &[b"cd", b"ab"]).unwrap();
        let c = hash_domain(DomainId::TxWid, &[b"ab", b"cd"]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        // Concatenation across part boundaries is the defined semantics.
        let d = hash_domain(DomainId::TxId, &[b"abcd"]).unwrap();
        assert_eq!(a, d);
    }

    #[test]
    fn keyed_hash_depends_on_key() {
        let k1 = Hash32::from_bytes([1; 32]);
        let k2 = Hash32::from_bytes([2; 32]);
        let a = keyed_hash_domain(DomainId::GroundTicket, &k1, &[b"nonce"]).unwrap();
        let b = keyed_hash_domain(DomainId::GroundTicket, &k2, &[b"nonce"]).unwrap();
        assert_ne!(a, b);
    }
}
