//! Domain-bound HKDF-SHA-256 derivations.
//!
//! Every `HKDF_INFO` registry row fixes: hash = SHA-256, a literal salt
//! string, `info = context_string || suffix parts`, and `L = 32`. Callers
//! supply only the input key material and the row-specific info suffix
//! (path bytes, suite/epoch identifiers, ...).

use crate::domains::{DomainId, DomainKind};
use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

/// Fixed output length for every registered derivation.
pub const HKDF_OUTPUT_LEN: usize = 32;

/// Derives 32 bytes under a registered `HKDF_INFO` domain:
/// `HKDF-SHA-256(salt = row salt, ikm, info = context_string || suffix...)`.
pub fn hkdf_derive(
    domain: DomainId,
    ikm: &[u8],
    info_suffix: &[&[u8]],
) -> Result<[u8; HKDF_OUTPUT_LEN], CryptoError> {
    domain.require_kind(DomainKind::HkdfInfo)?;
    // The kind check guarantees the salt row exists for HKDF_INFO rows.
    let salt = domain.hkdf_salt().ok_or(CryptoError::DerivationFailed)?;

    let context = domain.context().as_bytes();
    let total = info_suffix
        .iter()
        .fold(context.len(), |acc, p| acc.saturating_add(p.len()));
    let mut info = Vec::with_capacity(total);
    info.extend_from_slice(context);
    for part in info_suffix {
        info.extend_from_slice(part);
    }

    let mut okm = [0_u8; HKDF_OUTPUT_LEN];
    // expand only fails for output lengths > 255 * 32; 32 always succeeds.
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm);
    if hk.expand(&info, &mut okm).is_err() {
        return Err(CryptoError::DerivationFailed);
    }
    Ok(okm)
}

/// Raw RFC 5869 HKDF-SHA-256, for standard-vector conformance only.
#[cfg(test)]
pub(crate) fn hkdf_sha256_raw(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm)
        .map_err(|_| CryptoError::DerivationFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn non_hkdf_domains_are_rejected() {
        assert!(matches!(
            hkdf_derive(DomainId::TxId, b"ikm", &[]).unwrap_err(),
            CryptoError::WrongDomainKind { .. }
        ));
        assert!(matches!(
            hkdf_derive(DomainId::BlsVote, b"ikm", &[]).unwrap_err(),
            CryptoError::WrongDomainKind { .. }
        ));
    }

    #[test]
    fn derivations_are_domain_and_suffix_separated() {
        let a = hkdf_derive(DomainId::HkdfWallet, b"ikm", &[b"path"]).unwrap();
        let b = hkdf_derive(DomainId::HkdfUmbra, b"ikm", &[b"path"]).unwrap();
        let c = hkdf_derive(DomainId::HkdfWallet, b"ikm", &[b"other"]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
