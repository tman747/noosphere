//! Minimal exact unsigned 256-bit (and internal 512-bit) integers for
//! Ground/Pulse consensus arithmetic.
//!
//! ## Why not `ruint` / `primitive-types`
//!
//! Plan §6.2 allows pinning `ruint` or `primitive-types` or a minimal exact
//! u256. This crate implements the minimal type because:
//!
//! * The operation set Ground/Pulse needs is tiny and fully enumerable:
//!   LE byte round-trip, comparison, `+1`, one long division for `G(b)`,
//!   shifts, and a widening multiply-then-`>>64` step for the exp2 table
//!   walk. Auditing ~300 lines here is cheaper than auditing a general
//!   bignum crate's codegen for consensus bit-exactness.
//! * Every sibling consensus crate (`noos-codec`, `noos-grain`,
//!   `noos-lumen`) is dependency-free; keeping the consensus dependency
//!   surface at zero matches the SBOM/supply-chain posture of plan §3.4.
//! * All arithmetic is checked or explicitly wrapping with proven bounds;
//!   there are no floats and no `unsafe` (workspace `unsafe_code = deny`).

use core::cmp::Ordering;
use core::fmt;

/// Unsigned 256-bit integer, four little-endian `u64` limbs.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct U256 {
    /// `limbs[0]` is least significant.
    limbs: [u64; 4],
}

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self { limbs: [0; 4] };
    /// One.
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };
    /// `2^256 - 1` (Pulse `T_max`).
    pub const MAX: Self = Self {
        limbs: [u64::MAX; 4],
    };

    /// Constructs from little-endian limbs.
    #[must_use]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Little-endian limbs.
    #[must_use]
    pub const fn limbs(&self) -> &[u64; 4] {
        &self.limbs
    }

    /// Constructs from a `u64`.
    #[must_use]
    pub const fn from_u64(v: u64) -> Self {
        Self {
            limbs: [v, 0, 0, 0],
        }
    }

    /// Constructs from a `u128`.
    #[must_use]
    pub const fn from_u128(v: u128) -> Self {
        Self {
            limbs: [v as u64, (v >> 64) as u64, 0, 0],
        }
    }

    /// Interprets 32 bytes as little-endian (`uint256_le`, ch01 §4.2 rule 4).
    #[must_use]
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0_u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut chunk = [0_u8; 8];
            let start = i.wrapping_mul(8);
            chunk.copy_from_slice(&bytes[start..start.wrapping_add(8)]);
            *limb = u64::from_le_bytes(chunk);
        }
        Self { limbs }
    }

    /// Canonical 32-byte little-endian encoding (`*_target_le` wire fields).
    #[must_use]
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (i, limb) in self.limbs.iter().enumerate() {
            let start = i.wrapping_mul(8);
            out[start..start.wrapping_add(8)].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// Parses a big-endian hex string of at most 64 digits (vector aid).
    #[must_use]
    pub fn from_be_hex(hex: &str) -> Option<Self> {
        let hex = hex.as_bytes();
        if hex.is_empty() || hex.len() > 64 {
            return None;
        }
        let mut value = Self::ZERO;
        for &c in hex {
            let digit = match c {
                b'0'..=b'9' => u64::from(c.wrapping_sub(b'0')),
                b'a'..=b'f' => u64::from(c.wrapping_sub(b'a').wrapping_add(10)),
                _ => return None,
            };
            value = value.shl_small(4)?;
            value.limbs[0] |= digit;
        }
        Some(value)
    }

    /// True iff zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.limbs == [0; 4]
    }

    /// `self + 1`, `None` on overflow (i.e. `self == U256::MAX`).
    #[must_use]
    pub fn checked_add_one(&self) -> Option<Self> {
        let mut limbs = self.limbs;
        for limb in &mut limbs {
            let (sum, carry) = limb.overflowing_add(1);
            *limb = sum;
            if !carry {
                return Some(Self { limbs });
            }
        }
        None
    }

    /// Exact floor division; `None` when `divisor` is zero.
    ///
    /// Bitwise shift-subtract long division: exact, allocation-free, and
    /// trivially auditable. Ground uses it once per block for `G(b)`.
    #[must_use]
    pub fn checked_div(&self, divisor: &Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for i in (0..256_u32).rev() {
            remainder = remainder.shl1_unchecked();
            if self.bit(i) {
                remainder.limbs[0] |= 1;
            }
            if remainder >= *divisor {
                remainder = remainder.sub_unchecked(divisor);
                quotient.set_bit(i);
            }
        }
        Some(quotient)
    }

    /// Bit `i` (0 = least significant); `i < 256`.
    fn bit(&self, i: u32) -> bool {
        let limb = self.limbs[(i / 64) as usize];
        (limb >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: u32) {
        self.limbs[(i / 64) as usize] |= 1_u64.wrapping_shl(i % 64);
    }

    /// `self << 1`, discarding the carried-out bit (callers guarantee none).
    fn shl1_unchecked(&self) -> Self {
        let mut limbs = [0_u64; 4];
        let mut carry = 0_u64;
        for (out, limb) in limbs.iter_mut().zip(self.limbs.iter()) {
            *out = (limb << 1) | carry;
            carry = limb >> 63;
        }
        Self { limbs }
    }

    /// Checked left shift by `n < 64` bits; `None` if bits shift out.
    fn shl_small(&self, n: u32) -> Option<Self> {
        if n == 0 {
            return Some(*self);
        }
        if self.limbs[3] >> 64_u32.wrapping_sub(n) != 0 {
            return None;
        }
        let mut limbs = [0_u64; 4];
        let mut carry = 0_u64;
        for (out, limb) in limbs.iter_mut().zip(self.limbs.iter()) {
            *out = (limb << n) | carry;
            carry = limb >> 64_u32.wrapping_sub(n);
        }
        Some(Self { limbs })
    }

    /// `self - rhs`; callers guarantee `self >= rhs`.
    fn sub_unchecked(&self, rhs: &Self) -> Self {
        let mut limbs = [0_u64; 4];
        let mut borrow = false;
        for ((out, a), b) in limbs
            .iter_mut()
            .zip(self.limbs.iter())
            .zip(rhs.limbs.iter())
        {
            let (d1, b1) = a.overflowing_sub(*b);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            *out = d2;
            borrow = b1 || b2;
        }
        debug_assert!(!borrow, "sub_unchecked underflow");
        Self { limbs }
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "U256(0x{:016x}{:016x}{:016x}{:016x})",
            self.limbs[3], self.limbs[2], self.limbs[1], self.limbs[0]
        )
    }
}

/// Internal 512-bit accumulator for the Pulse exp2 walk, eight LE limbs.
///
/// Bounds (proven in `pulse`): the fractional phase keeps the value below
/// `2^257`; the subsequent integer shift is at most 255, so every
/// intermediate fits in 512 bits. All paths remain checked regardless.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct U512 {
    limbs: [u64; 8],
}

impl U512 {
    pub(crate) fn from_u256(v: &U256) -> Self {
        let mut limbs = [0_u64; 8];
        limbs[..4].copy_from_slice(v.limbs());
        Self { limbs }
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.limbs == [0; 8]
    }

    /// `Some(value)` iff the value fits in 256 bits.
    pub(crate) fn try_into_u256(self) -> Option<U256> {
        if self.limbs[4..].iter().any(|&l| l != 0) {
            return None;
        }
        let mut low = [0_u64; 4];
        low.copy_from_slice(&self.limbs[..4]);
        Some(U256::from_limbs(low))
    }

    /// `floor(self * factor / 2^64)` — one exp2-table step. `None` if the
    /// result exceeds 512 bits (unreachable under the documented bounds).
    ///
    /// Schoolbook 8x2-limb multiply into a 10-limb buffer with `u128`
    /// carries; the `>> 64` drops the lowest limb, which is truncation
    /// toward zero == toward negative infinity for unsigned values.
    pub(crate) fn mul_shr64(&self, factor: u128) -> Option<Self> {
        let f = [factor as u64, (factor >> 64) as u64];
        let mut prod = [0_u64; 10];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0_u128;
            for (j, &b) in f.iter().enumerate() {
                let idx = i.wrapping_add(j);
                let acc = (prod[idx] as u128)
                    .wrapping_add((a as u128).wrapping_mul(b as u128))
                    .wrapping_add(carry);
                prod[idx] = acc as u64;
                carry = acc >> 64;
            }
            // Propagate the final carry (fits: total product < 2^(512+65)).
            let mut idx = i.wrapping_add(2);
            while carry != 0 {
                let acc = (prod[idx] as u128).wrapping_add(carry);
                prod[idx] = acc as u64;
                carry = acc >> 64;
                idx = idx.wrapping_add(1);
            }
        }
        if prod[9] != 0 {
            return None;
        }
        let mut limbs = [0_u64; 8];
        limbs.copy_from_slice(&prod[1..9]);
        Some(Self { limbs })
    }

    /// Checked left shift by `n <= 255`; `None` if any bit shifts out.
    pub(crate) fn checked_shl(&self, n: u32) -> Option<Self> {
        debug_assert!(n < 512);
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        // Reject lost bits: everything at or above bit (512 - n) must be 0.
        let mut probe = *self;
        probe = probe.shr(512_u32.wrapping_sub(n));
        if !probe.is_zero() {
            return None;
        }
        let mut limbs = [0_u64; 8];
        for i in (0_usize..8).rev() {
            let src = i.checked_sub(limb_shift);
            let mut v = match src {
                Some(s) => self.limbs[s].wrapping_shl(bit_shift),
                None => 0,
            };
            if bit_shift != 0 {
                if let Some(s) = src.and_then(|s| s.checked_sub(1)) {
                    v |= self.limbs[s] >> 64_u32.wrapping_sub(bit_shift);
                }
            }
            limbs[i] = v;
        }
        Some(Self { limbs })
    }

    /// Right shift by `n` bits (floor); `n >= 512` yields zero.
    pub(crate) fn shr(&self, n: u32) -> Self {
        if n >= 512 {
            return Self { limbs: [0; 8] };
        }
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let mut limbs = [0_u64; 8];
        for (i, out) in limbs.iter_mut().enumerate() {
            let src = i.wrapping_add(limb_shift);
            if src >= 8 {
                break;
            }
            let mut v = self.limbs[src].wrapping_shr(bit_shift);
            if bit_shift != 0 && src.wrapping_add(1) < 8 {
                v |= self.limbs[src.wrapping_add(1)] << 64_u32.wrapping_sub(bit_shift);
            }
            *out = v;
        }
        Self { limbs }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn le_bytes_round_trip() {
        let mut bytes = [0_u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let v = U256::from_le_bytes(&bytes);
        assert_eq!(v.to_le_bytes(), bytes);
        assert_eq!(U256::MAX.to_le_bytes(), [0xff_u8; 32]);
        assert_eq!(U256::ZERO.to_le_bytes(), [0_u8; 32]);
    }

    #[test]
    fn ordering_is_big_endian_limbwise() {
        assert!(U256::from_u64(1) < U256::from_u128(1 << 64));
        assert!(U256::MAX > U256::from_u128(u128::MAX));
        assert_eq!(U256::from_u64(7).cmp(&U256::from_u64(7)), Ordering::Equal);
    }

    #[test]
    fn add_one_edges() {
        assert_eq!(U256::ZERO.checked_add_one().unwrap(), U256::ONE);
        assert!(U256::MAX.checked_add_one().is_none());
        let carry = U256::from_u128(u128::MAX).checked_add_one().unwrap();
        assert_eq!(*carry.limbs(), [0, 0, 1, 0]);
    }

    #[test]
    fn division_edges() {
        assert!(U256::ONE.checked_div(&U256::ZERO).is_none());
        assert_eq!(U256::MAX.checked_div(&U256::ONE).unwrap(), U256::MAX);
        assert_eq!(U256::MAX.checked_div(&U256::MAX).unwrap(), U256::ONE);
        // (2^256-1) / 2 = 2^255 - 1
        let half = U256::MAX.checked_div(&U256::from_u64(2)).unwrap();
        let expected = {
            let mut limbs = [u64::MAX; 4];
            limbs[3] = u64::MAX >> 1;
            U256::from_limbs(limbs)
        };
        assert_eq!(half, expected);
        // Small exact case: 1000 / 7 = 142.
        assert_eq!(
            U256::from_u64(1000)
                .checked_div(&U256::from_u64(7))
                .unwrap(),
            U256::from_u64(142)
        );
    }

    #[test]
    fn be_hex_parses() {
        assert_eq!(U256::from_be_hex("ff").unwrap(), U256::from_u64(255));
        assert_eq!(U256::from_be_hex(&"f".repeat(64)).unwrap(), U256::MAX);
        assert!(U256::from_be_hex("").is_none());
        assert!(U256::from_be_hex("0x1").is_none());
        assert!(U256::from_be_hex(&"f".repeat(65)).is_none());
    }

    #[test]
    fn u512_mul_shr64_matches_u128_math() {
        // (2^64) * factor >> 64 == factor for 65-bit factors.
        let acc = U512::from_u256(&U256::from_u128(1 << 64));
        let factor = (1_u128 << 64) | 0xdead_beef;
        let out = acc.mul_shr64(factor).unwrap();
        assert_eq!(out.try_into_u256().unwrap(), U256::from_u128(factor));
        // Truncation: 3 * (2^64 + 1) >> 64 = floor(3 + 3*2^-64) = 3.
        let out = U512::from_u256(&U256::from_u64(3))
            .mul_shr64((1 << 64) | 1)
            .unwrap();
        assert_eq!(out.try_into_u256().unwrap(), U256::from_u64(3));
    }

    #[test]
    fn u512_shifts() {
        let one = U512::from_u256(&U256::ONE);
        let shifted = one.checked_shl(511).unwrap();
        assert!(shifted.checked_shl(1).is_none());
        assert_eq!(shifted.shr(511).try_into_u256().unwrap(), U256::ONE);
        assert!(one.shr(1).is_zero());
        assert!(one.shr(512).is_zero());
        assert_eq!(
            one.checked_shl(0).unwrap().try_into_u256().unwrap(),
            U256::ONE
        );
        // 256-bit overflow detection via try_into_u256.
        assert!(one.checked_shl(256).unwrap().try_into_u256().is_none());
    }
}
