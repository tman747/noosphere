//! Strict BIP-350 Bech32m address validation and display per
//! `protocol/schemas/identity-v1.md` §2.
//!
//! The version/type/payload byte layout is OWNER_BLOCKED (identity-v1 §2.1):
//! this module NEVER interprets or defaults the payload. It validates the
//! canonical form (lowercase-only, strict `noos` HRP, Bech32m checksum) and
//! treats the 5-bit payload as opaque. Historical-protocol HRPs reject with
//! `wrong_protocol_identity` and are never auto-converted.

use thiserror::Error;

/// The only human-readable part any NOOSPHERE surface accepts.
pub const HRP: &str = "noos";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Data-part length bounds (checksum included) from the frozen API pattern
/// `^noos1[023456789acdefghjklmnpqrstuvwxyz]{6,83}$`.
const DATA_MIN: usize = 6;
const DATA_MAX: usize = 83;
/// Historical HRP of the predecessor protocol, assembled from bytes so the
/// identifier never appears literally (identity gate; see identity-v1 §5).
const HISTORICAL_HRP_BYTES: [u8; 4] = [0x6d, 0x69, 0x6e, 0x64];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Any uppercase character, including all-uppercase display form.
    #[error("noncanonical_address")]
    NonCanonicalCase,
    #[error("wrong_hrp")]
    WrongHrp,
    /// Historical predecessor-protocol address; terminal reject, no conversion.
    #[error("wrong_protocol_identity")]
    WrongProtocolIdentity,
    #[error("bad_charset")]
    BadCharset,
    #[error("bad_length")]
    BadLength,
    /// Checksum failure is terminal; no error correction is ever attempted.
    #[error("bad_checksum")]
    BadChecksum,
}

/// A checksum-verified address whose payload stays opaque (OWNER_BLOCKED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAddress {
    /// 5-bit groups between separator and checksum, uninterpreted.
    pub payload5: Vec<u8>,
}

#[allow(clippy::arithmetic_side_effects)] // masked 30-bit polynomial arithmetic cannot overflow u32
fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

#[allow(clippy::arithmetic_side_effects)] // 3-bit shifts and 5-bit masks on ASCII bytes
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2).saturating_add(1));
    for b in bytes {
        out.push(b >> 5);
    }
    out.push(0);
    for b in bytes {
        out.push(b & 31);
    }
    out
}

fn charset_index(c: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|&x| x == c)
        .and_then(|i| u8::try_from(i).ok())
}

fn split(address: &str) -> Result<(&str, &str), AddressError> {
    // Canonical output is lowercase; ANY uppercase character is a terminal
    // reject (mixed case AND the BIP-173 all-uppercase display form).
    if address.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(AddressError::NonCanonicalCase);
    }
    let sep = address.rfind('1').ok_or(AddressError::WrongHrp)?;
    let hrp = address.get(..sep).ok_or(AddressError::WrongHrp)?;
    let data = address
        .get(sep.saturating_add(1)..)
        .ok_or(AddressError::WrongHrp)?;
    if hrp.is_empty() {
        return Err(AddressError::WrongHrp);
    }
    Ok((hrp, data))
}

fn require_hrp(hrp: &str) -> Result<(), AddressError> {
    if hrp.as_bytes() == HISTORICAL_HRP_BYTES {
        return Err(AddressError::WrongProtocolIdentity);
    }
    if hrp != HRP {
        return Err(AddressError::WrongHrp);
    }
    Ok(())
}

/// Validate a NOOSPHERE address: canonical case, strict HRP, charset, length,
/// and Bech32m checksum. The payload is returned opaque; interpreting it is
/// PROHIBITED until the identity-v1 amendment 1 layout table lands.
pub fn validate(address: &str) -> Result<VerifiedAddress, AddressError> {
    let (hrp, data) = split(address)?;
    require_hrp(hrp)?;
    if !(DATA_MIN..=DATA_MAX).contains(&data.len()) {
        return Err(AddressError::BadLength);
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        values.push(charset_index(c).ok_or(AddressError::BadCharset)?);
    }
    let checkable = hrp_expand(hrp).into_iter().chain(values.iter().copied());
    if polymod(checkable) != BECH32M_CONST {
        return Err(AddressError::BadChecksum);
    }
    let payload_len = values.len().saturating_sub(6);
    values.truncate(payload_len);
    Ok(VerifiedAddress { payload5: values })
}

/// Re-encode an opaque 5-bit payload under the strict `noos` HRP. Used only
/// for canonical round-trip display of an already-validated address; this
/// function defines NO payload layout and refuses any other HRP.
pub fn encode(payload5: &[u8]) -> Result<String, AddressError> {
    if payload5.iter().any(|&v| v >= 32) {
        return Err(AddressError::BadCharset);
    }
    // payload + 6 checksum chars must stay within the frozen data bounds.
    let data_len = payload5.len().saturating_add(6);
    if !(DATA_MIN..=DATA_MAX).contains(&data_len) {
        return Err(AddressError::BadLength);
    }
    let expanded = hrp_expand(HRP);
    let with_template = expanded
        .iter()
        .copied()
        .chain(payload5.iter().copied())
        .chain([0u8; 6]);
    let pm = polymod(with_template) ^ BECH32M_CONST;
    let mut out = String::with_capacity(HRP.len().saturating_add(1).saturating_add(data_len));
    out.push_str(HRP);
    out.push('1');
    for &v in payload5 {
        out.push(char::from(CHARSET[usize::from(v)]));
    }
    #[allow(clippy::arithmetic_side_effects)] // 30-bit value sliced into six 5-bit groups
    for i in 0..6u32 {
        let idx = ((pm >> (5 * (5 - i))) & 31) as usize;
        out.push(char::from(CHARSET[idx]));
    }
    Ok(out)
}
