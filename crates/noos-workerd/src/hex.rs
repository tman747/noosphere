//! Lowercase hex encode/decode helpers (no external dependency).

/// Encodes bytes as lowercase hex.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // nibble math is bounded to 0..=15
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// Decodes exactly 64 lowercase/uppercase-free hex chars into 32 bytes.
///
/// Uppercase digits are rejected: the wire protocol is canonical lowercase.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // nibble math is bounded to 0..=15
pub fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(raw.chunks_exact(2)) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn round_trips_and_rejects_forgeries() {
        let bytes: Vec<u8> = (0..32).collect();
        let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
        let text = encode_hex(&arr);
        assert_eq!(decode_hex32(&text), Some(arr));
        // Wrong length, non-hex, and uppercase are all rejected.
        assert_eq!(decode_hex32(&text[..62]), None);
        assert_eq!(decode_hex32(&format!("zz{}", &text[2..])), None);
        assert_eq!(decode_hex32(&text.to_uppercase()), None);
    }
}
