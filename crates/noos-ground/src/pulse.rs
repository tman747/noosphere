//! Pulse v1 — the deterministic ASERT retarget for Ground targets.
//!
//! Interface law (ch01 §4.2/§4.3; plan §6.2):
//!
//! ```text
//! T_h = clamp(T_min, T_max, floor(T_a * 2^((t - t_a - Δ(h - h_a)) / τ)))
//! ```
//!
//! with target spacing `Δ = 6 s`, half-life `τ = 3600 s`, `T_min = 1`,
//! `T_max = 2^256 - 1`; `t` is the **parent** median-time-past in seconds
//! and the anchor `(h_a, t_a, T_a)` is the most recent finalized checkpoint
//! on the branch (its already-validated height, median-time-past, and
//! target — never local arrival time; the function is pure).
//!
//! ## Exact evaluation law (frozen; Go must reproduce bit-for-bit)
//!
//! The full rounding-order law is specified in
//! `protocol/spec/pulse-exp2-v1.md`; summary:
//!
//! 1. `n = t - t_a - 6*(h - h_a)` in signed exact integer seconds.
//! 2. Q64.64 exponent rounded toward negative infinity:
//!    `q = n div_euclid 3600`, `r = n rem_euclid 3600` (`0 <= r < 3600`),
//!    `f = floor(r * 2^64 / 3600)`; the exponent is `q + f * 2^-64`.
//! 3. Short circuits (exactly equivalent to the long computation):
//!    `q >= 256` yields `T_max`; `q <= -257` yields `T_min`.
//! 4. Accumulator `acc = T_a` as a 512-bit integer. For `k = 0..63` in
//!    ascending order (most-significant fractional bit first), if bit
//!    `63 - k` of `f` is set: `acc = floor(acc * EXP2_Q64_TABLE_V1[k] / 2^64)`.
//! 5. Integer part after the fractional walk: `q >= 0` shifts left by `q`,
//!    `q < 0` shifts right by `-q` (floor).
//! 6. Clamp into `[T_min, T_max]`.

use crate::exp2_table::EXP2_Q64_TABLE_V1;
use crate::u256::{U256, U512};
use core::fmt;

/// Pulse v1 target spacing `Δ` in seconds (constants-v1.toml `[pulse]`).
pub const TARGET_SPACING_SECONDS: u64 = 6;
/// Pulse v1 half-life `τ` in seconds.
pub const HALF_LIFE_SECONDS: u64 = 3600;
/// Minimum target `T_min = 1`.
pub const T_MIN: U256 = U256::ONE;
/// Maximum target `T_max = 2^256 - 1`.
pub const T_MAX: U256 = U256::MAX;

/// The retarget anchor: the most recent finalized checkpoint on the branch.
///
/// All three fields come from that checkpoint's already-validated header
/// chain (ch01 §4.3: rolling the anchor on finality "does not consult local
/// arrival time").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PulseAnchor {
    /// Checkpoint height `h_a`.
    pub height: u64,
    /// Checkpoint median-time-past `t_a`, seconds.
    pub median_time_past_s: u64,
    /// Checkpoint Ground target `T_a`; must lie in `[T_min, T_max]`.
    pub target: U256,
}

/// Pulse evaluation errors. All are caller-contract violations; a valid
/// finalized checkpoint and a descendant height never produce one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PulseError {
    /// `child_height <= anchor.height`: the child must descend from the
    /// anchor checkpoint.
    ChildNotAfterAnchor {
        /// Anchor height `h_a`.
        anchor_height: u64,
        /// Offending child height `h`.
        child_height: u64,
    },
    /// The anchor target is zero (below `T_min`); no valid checkpoint
    /// carries it.
    AnchorTargetZero,
    /// Internal width overflow. Unreachable under the documented bounds;
    /// kept as a checked error rather than a panic path.
    Overflow,
}

impl fmt::Display for PulseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildNotAfterAnchor {
                anchor_height,
                child_height,
            } => write!(
                f,
                "child height {child_height} does not descend from anchor height {anchor_height}"
            ),
            Self::AnchorTargetZero => f.write_str("anchor target is zero (below T_min)"),
            Self::Overflow => f.write_str("internal width overflow (bounds violated)"),
        }
    }
}

/// Signed Q64.64 exponent `(t - t_a - Δ(h - h_a)) / τ`, rounded toward
/// negative infinity, split into integer part `q` and fractional part
/// `f ∈ [0, 2^64)` such that the exponent equals `q + f * 2^-64`.
fn exponent_q64(
    anchor: &PulseAnchor,
    parent_median_time_past_s: u64,
    child_height: u64,
) -> Result<(i128, u64), PulseError> {
    let dh = child_height
        .checked_sub(anchor.height)
        .filter(|&dh| dh > 0)
        .ok_or(PulseError::ChildNotAfterAnchor {
            anchor_height: anchor.height,
            child_height,
        })?;
    // All terms fit i128 comfortably: u64 values and 6 * 2^64 < 2^67.
    let drift = i128::from(parent_median_time_past_s)
        .checked_sub(i128::from(anchor.median_time_past_s))
        .and_then(|d| {
            i128::from(TARGET_SPACING_SECONDS)
                .checked_mul(i128::from(dh))
                .and_then(|spacing| d.checked_sub(spacing))
        })
        .ok_or(PulseError::Overflow)?;
    let tau = i128::from(HALF_LIFE_SECONDS);
    // floor(n * 2^64 / 3600) == q * 2^64 + floor(r * 2^64 / 3600) with
    // n = 3600q + r, 0 <= r < 3600: Euclidean division rounds q toward
    // negative infinity and the fractional term is exact in u128
    // (r * 2^64 < 2^76).
    let q = drift.div_euclid(tau);
    let r = drift.rem_euclid(tau) as u128;
    // Divisor is the nonzero constant 3600; the fallback is unreachable.
    let f = (r << 64)
        .checked_div(u128::from(HALF_LIFE_SECONDS))
        .unwrap_or(0) as u64;
    Ok((q, f))
}

/// Deterministic Pulse v1 output: the Ground target every child of this
/// parent must carry (ch01 §4.2 rule 5).
///
/// Pure function of `(anchor, parent median-time-past, child height)`;
/// see the module docs for the frozen evaluation and rounding-order law.
pub fn pulse_target_v1(
    anchor: &PulseAnchor,
    parent_median_time_past_s: u64,
    child_height: u64,
) -> Result<U256, PulseError> {
    if anchor.target.is_zero() {
        return Err(PulseError::AnchorTargetZero);
    }
    let (q, f) = exponent_q64(anchor, parent_median_time_past_s, child_height)?;

    // Short circuits — exact equivalences, not approximations:
    // * every table entry is >= 2^64, so each fractional step is
    //   non-decreasing and acc >= T_a >= 1 after the walk; `acc << q`
    //   with q >= 256 is >= 2^256 > T_max, hence clamps to T_max.
    // * each fractional factor is < 2^65, so acc < 2*T_a <= 2^257 after
    //   the walk; `acc >> 257` (or more) is 0, hence clamps to T_min.
    if q >= 256 {
        return Ok(T_MAX);
    }
    if q <= -257 {
        return Ok(T_MIN);
    }

    // Fractional walk, most-significant exponent bit first.
    let mut acc = U512::from_u256(&anchor.target);
    for (k, &entry) in EXP2_Q64_TABLE_V1.iter().enumerate() {
        let bit = 63_u32.wrapping_sub(k as u32);
        if (f >> bit) & 1 == 1 {
            acc = acc.mul_shr64(entry).ok_or(PulseError::Overflow)?;
        }
    }

    // Integer shift, then clamp.
    let shifted = if q >= 0 {
        // q in [0, 255] and acc < 2^257: fits 512 bits by construction,
        // but stay checked.
        acc.checked_shl(q as u32).ok_or(PulseError::Overflow)?
    } else {
        // q in [-256, -1]: right shift floors.
        acc.shr(q.unsigned_abs() as u32)
    };
    if shifted.is_zero() {
        return Ok(T_MIN);
    }
    Ok(shifted.try_into_u256().unwrap_or(T_MAX))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn anchor(target: U256) -> PulseAnchor {
        PulseAnchor {
            height: 1024,
            median_time_past_s: 100_000_000,
            target,
        }
    }

    /// parent MTP that makes the exponent exactly `seconds / 3600`.
    fn mtp_for(anchor: &PulseAnchor, child_height: u64, seconds: i64) -> u64 {
        let on_schedule =
            anchor.median_time_past_s + TARGET_SPACING_SECONDS * (child_height - anchor.height);
        on_schedule.checked_add_signed(seconds).unwrap()
    }

    #[test]
    fn exponent_zero_is_identity() {
        let a = anchor(U256::from_u128(0xdead_beef_cafe_f00d_1234));
        let h = a.height + 100;
        let t = mtp_for(&a, h, 0);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), a.target);
    }

    #[test]
    fn exponent_plus_one_doubles_exactly() {
        let a = anchor(U256::from_u128(12345678901234567890));
        let h = a.height + 1;
        let t = mtp_for(&a, h, 3600);
        assert_eq!(
            pulse_target_v1(&a, t, h).unwrap(),
            U256::from_u128(2 * 12345678901234567890)
        );
    }

    #[test]
    fn exponent_minus_one_halves_with_floor() {
        let odd = U256::from_u64(0xffff_ffff_ffff_fff1); // odd value
        let a = anchor(odd);
        let h = a.height + 1;
        let t = mtp_for(&a, h, -3600);
        assert_eq!(
            pulse_target_v1(&a, t, h).unwrap(),
            U256::from_u64(0xffff_ffff_ffff_fff1 / 2)
        );
    }

    #[test]
    fn clamps_at_t_max() {
        let a = anchor(U256::MAX);
        let h = a.height + 1;
        // +1 exponent on T_max must clamp, not wrap.
        let t = mtp_for(&a, h, 3600);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MAX);
        // Enormous positive exponent short-circuit.
        let t = mtp_for(&a, h, 3600 * 10_000);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MAX);
    }

    #[test]
    fn clamps_at_t_min() {
        let a = anchor(U256::ONE);
        let h = a.height + 1;
        let t = mtp_for(&a, h, -3600);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MIN);
        // Deep negative exponent short-circuit.
        let t = mtp_for(&a, h, -3600 * 10_000);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MIN);
        // Large target driven all the way down.
        let a = anchor(U256::MAX);
        let t = mtp_for(&a, h, -3600 * 300);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MIN);
    }

    #[test]
    fn short_circuit_boundaries_match_long_path() {
        // q = 255 (long path) vs q = 256 (short circuit): both T_max for a
        // large anchor target; and the q = -256 long path vs q = -257 short
        // circuit agree for T_a = 1.
        let a = anchor(U256::from_u64(1));
        let h = a.height + 1;
        let t = mtp_for(&a, h, 3600 * 256);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MAX);
        let t = mtp_for(&a, h, 3600 * 255);
        // 1 << 255 fits: exact power of two.
        let mut limbs = [0_u64; 4];
        limbs[3] = 1 << 63;
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), U256::from_limbs(limbs));
        let t = mtp_for(&a, h, -3600 * 256);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MIN);
        let t = mtp_for(&a, h, -3600 * 257);
        assert_eq!(pulse_target_v1(&a, t, h).unwrap(), T_MIN);
    }

    #[test]
    fn half_exponent_multiplies_by_sqrt2_entry() {
        // n = +1800 s => q = 0, f = 2^63 => acc = floor(T_a * table[0] / 2^64).
        let ta = 1_u128 << 64;
        let a = anchor(U256::from_u128(ta));
        let h = a.height + 1;
        let t = mtp_for(&a, h, 1800);
        assert_eq!(
            pulse_target_v1(&a, t, h).unwrap(),
            U256::from_u128(crate::exp2_table::EXP2_Q64_TABLE_V1[0])
        );
    }

    #[test]
    fn fractional_rounding_is_toward_negative_infinity() {
        // n = -1 s: exponent = -1/3600, i.e. q = -1, r = 3599.
        // Result must be strictly below T_a and >= floor(T_a * 2^-1):
        // exact value cross-checked against the Python oracle in the
        // conformance vectors; here we pin the floor direction.
        let ta = U256::from_u128((1 << 100) + 12345);
        let a = anchor(ta);
        let h = a.height + 1;
        let t = mtp_for(&a, h, -1);
        let out = pulse_target_v1(&a, t, h).unwrap();
        assert!(out < ta);
        // 2^-1/3600 > 0.9998; output must be above 0.999 * T_a:
        // floor(T_a * 999 / 1000) as a coarse lower bound.
        let coarse = U512::from_u256(&ta)
            .mul_shr64(((999_u128) << 64) / 1000)
            .unwrap()
            .try_into_u256()
            .unwrap();
        assert!(out > coarse);
    }

    #[test]
    fn determinism_and_arrival_time_independence() {
        // Pure function: repeated evaluation and permuted evaluation order
        // give identical bytes; there is no clock input at all.
        let a = anchor(U256::from_u128(0xabcdef0123456789));
        let h = a.height + 7;
        let t = mtp_for(&a, h, 12_345);
        let first = pulse_target_v1(&a, t, h).unwrap();
        for _ in 0..10 {
            assert_eq!(pulse_target_v1(&a, t, h).unwrap(), first);
        }
    }

    #[test]
    fn contract_violations_error() {
        let a = anchor(U256::from_u64(5));
        assert_eq!(
            pulse_target_v1(&a, 0, a.height),
            Err(PulseError::ChildNotAfterAnchor {
                anchor_height: a.height,
                child_height: a.height
            })
        );
        let z = anchor(U256::ZERO);
        assert_eq!(
            pulse_target_v1(&z, 0, z.height + 1),
            Err(PulseError::AnchorTargetZero)
        );
    }
}
