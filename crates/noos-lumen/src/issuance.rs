//! Fixed-envelope issuance (arch §13.2, plan §4.6).
//!
//! Genesis fixes a maximum supply, an integer per-height emission function,
//! recipient shares, a rounding rule, and a terminal height. For height `h`,
//! exactly `E_h` may be minted by the unique finalized block at `h`;
//! missed/orphaned emissions are NEVER recreated. `Σ E_h ≤ max_supply`.
//!
//! There is NO useful-work mint: the only mint entry point in this crate is
//! [`crate::state::LumenLedger::apply_emission`], which is driven purely by
//! this schedule. Loom incentives may only REDIRECT a governance-bounded
//! portion of already-scheduled amounts (never implemented as extra mint);
//! duplex reallocation is hard-zero under E-DEMAND-WASH-01.
//!
//! Production values (max supply, curve, terminal height, shares, rounding)
//! are OWNER_BLOCKED in constants-v1.toml [emission]; this module is fully
//! parameterized and ships only a valueless NOOS_TEST fixture.

use noos_codec::define_object;

define_object! {
    /// Issuance parameters (params tree, key `noos.params.issuance.v1`).
    ///
    /// Emission law (frozen form, lumen-v1.md §8): heights are 1-based;
    /// era `k = (h - 1) / era_length`; `e_0 = initial_per_height`;
    /// `e_{k+1} = floor(e_k * decay_numerator / decay_denominator)`;
    /// `E_h = e_k` for `1 <= h <= terminal_height`, else `E_h = 0`.
    pub struct IssuanceParamsV1 {
        version: 1;
        1 => max_supply: u128,
        2 => initial_per_height: u128,
        3 => era_length: u64,
        4 => decay_numerator: u32,
        5 => decay_denominator: u32,
        6 => terminal_height: u64,
    }
}

define_object! {
    /// Recipient shares in parts per million (params tree, key
    /// `noos.params.shares.v1`). MUST sum to exactly 1_000_000.
    /// Rounding rule (frozen): witness and treasury shares round down;
    /// the proposer share takes the exact remainder, so every split
    /// conserves `E_h` to the micro-NOOS.
    pub struct EmissionSharesV1 {
        version: 1;
        1 => proposer_ppm: u32,
        2 => witness_ppm: u32,
        3 => treasury_ppm: u32,
    }
}

/// One block's conserved emission split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionSplit {
    pub proposer: u128,
    pub witness: u128,
    pub treasury: u128,
}

impl EmissionSplit {
    #[must_use]
    pub fn total(&self) -> Option<u128> {
        self.proposer
            .checked_add(self.witness)?
            .checked_add(self.treasury)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceError {
    /// Parameters are internally inconsistent (zero denominator, shares not
    /// summing to 1e6, era_length zero, or the full schedule exceeds
    /// max_supply).
    InvalidParams,
    /// Arithmetic overflow (checked everywhere; never wrapped).
    Overflow,
}

impl IssuanceParamsV1 {
    /// Validate internal consistency, including the conservation bound
    /// `Σ_{h=1}^{terminal} E_h ≤ max_supply` computed era-by-era in closed
    /// form (exact, checked).
    pub fn validate(&self) -> Result<(), IssuanceError> {
        if self.era_length == 0
            || self.decay_denominator == 0
            || u64::from(self.decay_numerator) >= u64::from(self.decay_denominator)
        {
            return Err(IssuanceError::InvalidParams);
        }
        let total = self.total_scheduled()?;
        if total > self.max_supply {
            return Err(IssuanceError::InvalidParams);
        }
        Ok(())
    }

    /// Per-era emission `e_k` (integer floor decay, checked).
    pub fn era_emission(&self, era: u64) -> Result<u128, IssuanceError> {
        let mut e = self.initial_per_height;
        let mut k = 0u64;
        while k < era {
            if e == 0 {
                return Ok(0);
            }
            e = e
                .checked_mul(u128::from(self.decay_numerator))
                .ok_or(IssuanceError::Overflow)?
                .checked_div(u128::from(self.decay_denominator))
                .ok_or(IssuanceError::Overflow)?;
            k = k.checked_add(1).ok_or(IssuanceError::Overflow)?;
        }
        Ok(e)
    }

    /// `E_h`: scheduled emission at height `h` (1-based). Height 0 (genesis)
    /// and every height past `terminal_height` emit exactly zero.
    pub fn emission_at(&self, height: u64) -> Result<u128, IssuanceError> {
        if height == 0 || height > self.terminal_height {
            return Ok(0);
        }
        let era = height
            .checked_sub(1)
            .ok_or(IssuanceError::Overflow)?
            .checked_div(self.era_length)
            .ok_or(IssuanceError::Overflow)?;
        self.era_emission(era)
    }

    /// Exact `Σ_{h=1}^{terminal_height} E_h`, era-by-era (checked).
    pub fn total_scheduled(&self) -> Result<u128, IssuanceError> {
        let mut total: u128 = 0;
        let mut e = self.initial_per_height;
        let mut start: u64 = 1; // first height of the current era
        while start <= self.terminal_height {
            if e == 0 {
                break;
            }
            let end = start
                .checked_add(
                    self.era_length
                        .checked_sub(1)
                        .ok_or(IssuanceError::Overflow)?,
                )
                .ok_or(IssuanceError::Overflow)?
                .min(self.terminal_height);
            let heights = u128::from(end.checked_sub(start).ok_or(IssuanceError::Overflow)?)
                .checked_add(1)
                .ok_or(IssuanceError::Overflow)?;
            total = total
                .checked_add(e.checked_mul(heights).ok_or(IssuanceError::Overflow)?)
                .ok_or(IssuanceError::Overflow)?;
            e = e
                .checked_mul(u128::from(self.decay_numerator))
                .ok_or(IssuanceError::Overflow)?
                .checked_div(u128::from(self.decay_denominator))
                .ok_or(IssuanceError::Overflow)?;
            start = match end.checked_add(1) {
                Some(s) => s,
                None => break, // terminal_height == u64::MAX and fully covered
            };
        }
        Ok(total)
    }

    /// Valueless NOOS_TEST fixture (plan §2.5): NOT production tokenomics.
    /// 10^12 micro initial, halving every 100_000 heights, terminal at
    /// 2_000_000, cap comfortably above the exact scheduled total.
    #[must_use]
    pub fn testnet_fixture() -> Self {
        Self {
            max_supply: 250_000_000_000_000_000, // 2.5e17 micro-NOOS_TEST
            initial_per_height: 1_000_000_000_000,
            era_length: 100_000,
            decay_numerator: 1,
            decay_denominator: 2,
            terminal_height: 2_000_000,
        }
    }
}

impl EmissionSharesV1 {
    pub const PPM: u32 = 1_000_000;

    pub fn validate(&self) -> Result<(), IssuanceError> {
        let sum = u64::from(self.proposer_ppm)
            .checked_add(u64::from(self.witness_ppm))
            .and_then(|s| s.checked_add(u64::from(self.treasury_ppm)))
            .ok_or(IssuanceError::Overflow)?;
        if sum == u64::from(Self::PPM) {
            Ok(())
        } else {
            Err(IssuanceError::InvalidParams)
        }
    }

    /// Split `emission` conservatively: witness/treasury floor, proposer
    /// takes the exact remainder (frozen rounding rule).
    pub fn split(&self, emission: u128) -> Result<EmissionSplit, IssuanceError> {
        self.validate()?;
        let ppm = u128::from(Self::PPM);
        let witness = emission
            .checked_mul(u128::from(self.witness_ppm))
            .ok_or(IssuanceError::Overflow)?
            .checked_div(ppm)
            .ok_or(IssuanceError::Overflow)?;
        let treasury = emission
            .checked_mul(u128::from(self.treasury_ppm))
            .ok_or(IssuanceError::Overflow)?
            .checked_div(ppm)
            .ok_or(IssuanceError::Overflow)?;
        let proposer = emission
            .checked_sub(witness)
            .and_then(|p| p.checked_sub(treasury))
            .ok_or(IssuanceError::Overflow)?;
        Ok(EmissionSplit {
            proposer,
            witness,
            treasury,
        })
    }

    /// Valueless NOOS_TEST fixture.
    #[must_use]
    pub fn testnet_fixture() -> Self {
        Self {
            proposer_ppm: 500_000,
            witness_ppm: 350_000,
            treasury_ppm: 150_000,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_util::SplitMix64;

    #[test]
    fn fixture_validates_and_total_is_bounded_by_cap() {
        let p = IssuanceParamsV1::testnet_fixture();
        p.validate().unwrap();
        let total = p.total_scheduled().unwrap();
        assert!(total <= p.max_supply);
        assert!(total > 0);
    }

    #[test]
    fn emission_is_zero_at_genesis_and_after_terminal() {
        let p = IssuanceParamsV1::testnet_fixture();
        assert_eq!(p.emission_at(0).unwrap(), 0);
        assert_eq!(p.emission_at(p.terminal_height + 1).unwrap(), 0);
        assert_eq!(p.emission_at(u64::MAX).unwrap(), 0);
        assert!(p.emission_at(1).unwrap() > 0);
        assert!(p.emission_at(p.terminal_height).unwrap() > 0 || p.era_emission(19).unwrap() == 0);
    }

    #[test]
    fn emission_is_monotone_nonincreasing_across_eras() {
        let p = IssuanceParamsV1::testnet_fixture();
        let mut prev = p.era_emission(0).unwrap();
        for era in 1..(p.terminal_height / p.era_length + 1) {
            let e = p.era_emission(era).unwrap();
            assert!(e <= prev, "era {era} emission increased");
            prev = e;
        }
    }

    #[test]
    fn conservation_over_sampled_heights_1e5() {
        // Property test (plan §4.6): 10^5 sampled heights agree with the
        // era table, and the exact era-by-era total never exceeds the cap.
        let p = IssuanceParamsV1::testnet_fixture();
        let total = p.total_scheduled().unwrap();
        assert!(total <= p.max_supply);
        let mut rng = SplitMix64(0x0013_557A_11CE_u64);
        for _ in 0..100_000 {
            let h = rng.next_u64() % (p.terminal_height * 2);
            let e = p.emission_at(h).unwrap();
            if h == 0 || h > p.terminal_height {
                assert_eq!(e, 0, "no emission outside (0, terminal]");
            } else {
                let era = (h - 1) / p.era_length;
                assert_eq!(e, p.era_emission(era).unwrap(), "height {h} mismatch");
            }
        }
    }

    /// Full-path battery stand-in for the later gate script: iterate 10^7
    /// heights, accumulate with checked arithmetic, and prove the envelope.
    /// Run with:
    /// `cargo test -p noos-lumen --release -- --ignored issuance_conservation_10e7`
    #[test]
    #[ignore = "10^7-height battery; run explicitly in release"]
    fn issuance_conservation_10e7() {
        let p = IssuanceParamsV1 {
            max_supply: 250_000_000_000_000_000,
            initial_per_height: 1_000_000_000_000,
            era_length: 100_000,
            decay_numerator: 1,
            decay_denominator: 2,
            terminal_height: 10_000_000,
        };
        p.validate().unwrap();
        let mut sum: u128 = 0;
        let mut era_cache_era = 0u64;
        let mut era_cache_val = p.era_emission(0).unwrap();
        for h in 1..=10_000_000u64 {
            let era = (h - 1) / p.era_length;
            if era != era_cache_era {
                era_cache_era = era;
                era_cache_val = p.era_emission(era).unwrap();
            }
            sum = sum.checked_add(era_cache_val).unwrap();
            assert!(
                sum <= p.max_supply,
                "cumulative emission pierced the cap at height {h}"
            );
        }
        assert_eq!(
            sum,
            p.total_scheduled().unwrap(),
            "path sum must equal closed form"
        );
    }

    #[test]
    fn invalid_params_reject() {
        let mut p = IssuanceParamsV1::testnet_fixture();
        p.era_length = 0;
        assert_eq!(p.validate(), Err(IssuanceError::InvalidParams));
        let mut p = IssuanceParamsV1::testnet_fixture();
        p.decay_numerator = 2;
        p.decay_denominator = 2; // no decay => schedule may exceed cap and ratio >= 1 is invalid
        assert_eq!(p.validate(), Err(IssuanceError::InvalidParams));
        let mut p = IssuanceParamsV1::testnet_fixture();
        p.max_supply = 1; // schedule exceeds cap
        assert_eq!(p.validate(), Err(IssuanceError::InvalidParams));
    }

    #[test]
    fn shares_split_conserves_exactly() {
        let s = EmissionSharesV1::testnet_fixture();
        s.validate().unwrap();
        let mut rng = SplitMix64(99);
        for _ in 0..10_000 {
            let e = u128::from(rng.next_u64());
            let split = s.split(e).unwrap();
            assert_eq!(
                split.total().unwrap(),
                e,
                "split must conserve to the micro"
            );
        }
        // Shares not summing to 1e6 reject.
        let bad = EmissionSharesV1 {
            proposer_ppm: 1,
            witness_ppm: 1,
            treasury_ppm: 1,
        };
        assert_eq!(bad.validate(), Err(IssuanceError::InvalidParams));
    }
}
