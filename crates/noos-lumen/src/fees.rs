//! Five-dimensional integer fees (arch §6.9, plan §4.5).
//!
//! `Fee = p_B*B + p_G*G + p_V*V + p_R*R + p_D*D`, all integer micro-NOOS,
//! checked multiplication/addition, explicit per-dimension maxima, bounded
//! per-block price controllers.
//!
//! Controller coefficients, per-dimension capacity, and the failure-fee value
//! are UNRESOLVED_SOURCE in `protocol/spec/constants-v1.toml` [fees]
//! (ODR-FEES-001/002/003). They are therefore PARAMETERS carried by
//! [`FeeParamsV1`] records in the params tree — never developer defaults in
//! code. [`FeeParamsV1::testnet_fixture`] is a valueless NOOS_TEST
//! engineering fixture (plan §2.5), not production economics.

use noos_codec::define_object;

use crate::objects::ResourceVector;

/// Fee dimension order (frozen): B, G, V, R, D.
pub const DIMENSIONS: usize = 5;

/// Per-dimension usage: `[B, G, V, R, D]` = `[canonical bytes, grain steps,
/// proof-verification units, persistent state-word epochs, consensus blob
/// bytes]`.
pub type Usage = [u64; DIMENSIONS];

/// Per-dimension prices in micro-NOOS per unit.
pub type Prices = [u128; DIMENSIONS];

define_object! {
    /// Static fee parameters (params tree, key `noos.params.fees.v1`).
    pub struct FeeParamsV1 {
        version: 1;
        /// Lower clamp for every controller-driven price (>= 1).
        1 => min_price: u128,
        /// Upper clamp for every controller-driven price (explicit maximum).
        2 => max_price: u128,
        /// Bounded per-block relative price change, parts per million.
        3 => max_change_ppm: u32,
        /// Per-block capacity per dimension: [B, G, V, R, D].
        4 => capacity_b: u64,
        5 => capacity_g: u64,
        6 => capacity_v: u64,
        7 => capacity_r: u64,
        8 => capacity_d: u64,
        /// Frozen deterministic failure fee (charged from the reservation on
        /// trap/failed postcondition; ODR-FEES-003).
        9 => failure_fee: u128,
        /// Minimum governance activation delay in heights (plan §4.7).
        10 => min_activation_delay: u64,
    }
}

define_object! {
    /// Evolving controller state (params tree, key `noos.params.feestate.v1`):
    /// current block-level base prices [p_B, p_G, p_V, p_R, p_D].
    pub struct FeeStateV1 {
        version: 1;
        1 => p_b: u128,
        2 => p_g: u128,
        3 => p_v: u128,
        4 => p_r: u128,
        5 => p_d: u128,
    }
}

impl FeeParamsV1 {
    /// Per-block capacity vector `[B, G, V, R, D]`.
    #[must_use]
    pub fn capacity(&self) -> Usage {
        [self.capacity_b, self.capacity_g, self.capacity_v, self.capacity_r, self.capacity_d]
    }

    /// Valueless NOOS_TEST fixture (plan §2.5; is_test_fixture semantics —
    /// MUST NOT load on mainnet). Magnitudes are engineering choices only.
    #[must_use]
    pub fn testnet_fixture() -> Self {
        Self {
            min_price: 1,
            max_price: 1_000_000,
            max_change_ppm: 125_000, // ±12.5% per block
            capacity_b: 1_048_576,   // 1 MiB canonical bytes
            capacity_g: 100_000_000, // grain steps
            capacity_v: 100_000,     // proof units
            capacity_r: 1_000_000,   // state-word epochs
            capacity_d: 4_194_304,   // 4 MiB blob bytes
            failure_fee: 1_000,      // micro-NOOS_TEST
            min_activation_delay: 16,
        }
    }
}

impl FeeStateV1 {
    #[must_use]
    pub fn prices(&self) -> Prices {
        [self.p_b, self.p_g, self.p_v, self.p_r, self.p_d]
    }

    #[must_use]
    pub fn from_prices(p: Prices) -> Self {
        Self { p_b: p[0], p_g: p[1], p_v: p[2], p_r: p[3], p_d: p[4] }
    }

    /// Valueless NOOS_TEST initial prices.
    #[must_use]
    pub fn testnet_fixture() -> Self {
        Self::from_prices([1, 1, 10, 2, 1])
    }
}

/// Map a six-axis resource vector onto the five fee dimensions
/// (lumen-v1.md §6.2): `B = bytes`, `G = grain_steps`, `V = proof_units`,
/// `R = state_writes` (v1 word-epoch approximation, ODR-FEES-002),
/// `D = blob_bytes`. Declared `state_reads` are bounded separately but
/// priced inside `G` in v1.
#[must_use]
pub fn usage_from_resources(r: &ResourceVector) -> Usage {
    [r.bytes, r.grain_steps, r.proof_units, r.state_writes, r.blob_bytes]
}

/// `Fee = Σ p_i * u_i`, checked. `None` on u128 overflow.
#[must_use]
pub fn fee(prices: &Prices, usage: &Usage) -> Option<u128> {
    let mut total: u128 = 0;
    for i in 0..DIMENSIONS {
        let term = prices[i].checked_mul(u128::from(usage[i]))?;
        total = total.checked_add(term)?;
    }
    Some(total)
}

/// Bounded per-block controller for one dimension (frozen law,
/// lumen-v1.md §6.3):
///
/// - `target = capacity / 2` (capacity MUST be ≥ 2);
/// - `used == target` → price unchanged;
/// - otherwise `adj = p * |used - target| * max_change_ppm / (target * 10^6)`
///   (integer floor), stepped by at least 1;
/// - increase clamps to `max_price`, decrease clamps to `min_price`.
///
/// Because `used ≤ capacity = 2*target`, the relative change is bounded by
/// `max_change_ppm` per block. All arithmetic checked; `None` = overflow
/// (rejected by the caller, never wrapped).
#[must_use]
pub fn next_price(
    price: u128,
    used: u64,
    capacity: u64,
    params: &FeeParamsV1,
) -> Option<u128> {
    if capacity < 2 {
        return None;
    }
    let target = u128::from(capacity / 2);
    let used = u128::from(used.min(capacity));
    if used == target {
        return Some(price.clamp(params.min_price, params.max_price));
    }
    let gap = used.abs_diff(target);
    let adj = price
        .checked_mul(gap)?
        .checked_mul(u128::from(params.max_change_ppm))?
        .checked_div(target.checked_mul(1_000_000)?)?
        .max(1);
    let next = if used > target {
        price.checked_add(adj)?.min(params.max_price)
    } else {
        price.saturating_sub(adj).max(params.min_price)
    };
    Some(next)
}

/// Advance all five prices from block usage totals.
#[must_use]
pub fn next_prices(prices: &Prices, usage: &Usage, params: &FeeParamsV1) -> Option<Prices> {
    let cap = params.capacity();
    let mut out = *prices;
    for i in 0..DIMENSIONS {
        out[i] = next_price(prices[i], usage[i], cap[i], params)?;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn params() -> FeeParamsV1 {
        FeeParamsV1::testnet_fixture()
    }

    #[test]
    fn fee_is_exact_integer_dot_product() {
        let prices: Prices = [2, 3, 5, 7, 11];
        let usage: Usage = [1, 10, 100, 1000, 10000];
        assert_eq!(fee(&prices, &usage), Some(2 + 30 + 500 + 7000 + 110_000));
        assert_eq!(fee(&prices, &[0; 5]), Some(0));
    }

    #[test]
    fn fee_overflow_is_detected_not_wrapped() {
        let prices: Prices = [u128::MAX, 0, 0, 0, 0];
        assert_eq!(fee(&prices, &[2, 0, 0, 0, 0]), None);
        let prices: Prices = [u128::MAX / 2, u128::MAX / 2, 0, 0, 0];
        assert_eq!(fee(&prices, &[2, 2, 0, 0, 0]), None, "sum overflow must be caught");
    }

    #[test]
    fn controller_change_is_bounded_per_block() {
        let p = params();
        let price = 1_000u128;
        // Full block (used == capacity): max upward step.
        let up = next_price(price, p.capacity_b, p.capacity_b, &p).unwrap();
        assert!(up > price);
        let max_step = price * u128::from(p.max_change_ppm) / 1_000_000;
        assert!(up - price <= max_step.max(1), "upward change exceeded ppm bound");
        // Empty block: max downward step, floored at min_price.
        let down = next_price(price, 0, p.capacity_b, &p).unwrap();
        assert!(down < price);
        assert!(price - down <= max_step.max(1));
        // At target: unchanged.
        assert_eq!(next_price(price, p.capacity_b / 2, p.capacity_b, &p), Some(price));
    }

    #[test]
    fn controller_clamps_to_explicit_maxima() {
        let p = params();
        // Repeated full blocks converge to max_price, never beyond.
        let mut price = 1u128;
        for _ in 0..2_000 {
            price = next_price(price, p.capacity_b, p.capacity_b, &p).unwrap();
            assert!(price <= p.max_price);
            assert!(price >= p.min_price);
        }
        assert_eq!(price, p.max_price);
        // Repeated empty blocks converge to min_price, never below.
        for _ in 0..2_000 {
            price = next_price(price, 0, p.capacity_b, &p).unwrap();
        }
        assert_eq!(price, p.min_price);
    }

    #[test]
    fn controller_moves_by_at_least_one_off_target() {
        let p = params();
        // Tiny price + tiny imbalance: floor(adj)=0 would stall; law says step >= 1.
        let up = next_price(1, p.capacity_b / 2 + 1, p.capacity_b, &p).unwrap();
        assert_eq!(up, 2);
        let down = next_price(2, p.capacity_b / 2 - 1, p.capacity_b, &p).unwrap();
        assert_eq!(down, 1);
    }

    #[test]
    fn usage_mapping_is_the_frozen_axis_order() {
        let r = ResourceVector {
            bytes: 1,
            grain_steps: 2,
            proof_units: 3,
            state_reads: 99,
            state_writes: 4,
            blob_bytes: 5,
        };
        assert_eq!(usage_from_resources(&r), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn params_roundtrip() {
        use noos_codec::{NoosDecode, NoosEncode};
        let p = params();
        assert_eq!(FeeParamsV1::decode_canonical(&p.encode_canonical()).unwrap(), p);
        let s = FeeStateV1::testnet_fixture();
        assert_eq!(FeeStateV1::decode_canonical(&s.encode_canonical()).unwrap(), s);
    }
}
