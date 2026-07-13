//! Conserved safety-reserve, protocol-liquidation, and PSM transitions.
//! Callers apply the returned supply/debt deltas atomically with ledger balance
//! changes; every mint or burn is paired with the same debt transition.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PRICE_SCALE: u128 = 1_000_000_000;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SafetyError {
    #[error("invalid_parameter")]
    InvalidParameter,
    #[error("insufficient_reserve")]
    InsufficientReserve,
    #[error("insufficient_psm_liquidity")]
    InsufficientPsmLiquidity,
    #[error("position_is_healthy")]
    PositionHealthy,
    #[error("arithmetic_overflow")]
    Overflow,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyState {
    /// Stable tokens held by protocol custody and available to burn against debt.
    pub stable_reserve: u128,
    /// Collateral seized by protocol liquidations or paid into the PSM.
    pub collateral_reserve: u128,
    /// Stable debt minted only against PSM collateral.
    pub psm_debt: u128,
    /// Debt left after exhausting the funded reserve; never silently forgiven.
    pub uncovered_bad_debt: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafetyPolicy {
    pub liquidation_threshold_bps: u16,
    pub liquidation_bonus_bps: u16,
    pub psm_fee_bps: u16,
}

impl SafetyPolicy {
    pub fn validate(self) -> Result<(), SafetyError> {
        if !(1..=9_500).contains(&self.liquidation_threshold_bps)
            || self.liquidation_bonus_bps > 1_500
            || self.psm_fee_bps > 500
        {
            return Err(SafetyError::InvalidParameter);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebtPosition {
    pub collateral: u128,
    pub debt: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackstopResult {
    pub stable_burned: u128,
    pub collateral_seized: u128,
    pub remaining_position: DebtPosition,
    pub newly_uncovered_bad_debt: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsmMintResult {
    pub stable_to_user: u128,
    pub stable_fee_to_reserve: u128,
    pub supply_and_debt_increase: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsmRedeemResult {
    pub collateral_to_user: u128,
    pub stable_fee_to_reserve: u128,
    pub supply_and_debt_decrease: u128,
}

impl SafetyState {
    pub fn fund_stable_reserve(&mut self, amount: u128) -> Result<(), SafetyError> {
        if amount == 0 {
            return Err(SafetyError::InvalidParameter);
        }
        self.stable_reserve = self
            .stable_reserve
            .checked_add(amount)
            .ok_or(SafetyError::Overflow)?;
        Ok(())
    }

    /// Permissionless keeper computation for the protocol-owned liquidator.
    /// The reserve burns stable debt and takes collateral; it may repay beyond
    /// collateral value to prevent accounting insolvency, recording any debt
    /// it cannot fund rather than hiding it.
    pub fn backstop_liquidate(
        &mut self,
        policy: SafetyPolicy,
        position: DebtPosition,
        price_q9: u128,
    ) -> Result<BackstopResult, SafetyError> {
        policy.validate()?;
        if price_q9 == 0 || position.debt == 0 {
            return Err(SafetyError::InvalidParameter);
        }
        let collateral_value = mul_div(position.collateral, price_q9, PRICE_SCALE)?;
        let threshold_value = mul_div(
            collateral_value,
            u128::from(policy.liquidation_threshold_bps),
            10_000,
        )?;
        if position.debt <= threshold_value {
            return Err(SafetyError::PositionHealthy);
        }

        let stable_burned = self.stable_reserve.min(position.debt);
        let remaining_debt = position
            .debt
            .checked_sub(stable_burned)
            .ok_or(SafetyError::Overflow)?;
        let bonus = 10_000u128
            .checked_add(u128::from(policy.liquidation_bonus_bps))
            .ok_or(SafetyError::Overflow)?;
        let requested_collateral = mul_div_ceil(
            stable_burned,
            PRICE_SCALE
                .checked_mul(bonus)
                .ok_or(SafetyError::Overflow)?,
            price_q9.checked_mul(10_000).ok_or(SafetyError::Overflow)?,
        )?;
        let collateral_seized = requested_collateral.min(position.collateral);
        self.stable_reserve = self
            .stable_reserve
            .checked_sub(stable_burned)
            .ok_or(SafetyError::Overflow)?;
        self.collateral_reserve = self
            .collateral_reserve
            .checked_add(collateral_seized)
            .ok_or(SafetyError::Overflow)?;
        let newly_uncovered = remaining_debt;
        self.uncovered_bad_debt = self
            .uncovered_bad_debt
            .checked_add(newly_uncovered)
            .ok_or(SafetyError::Overflow)?;
        Ok(BackstopResult {
            stable_burned,
            collateral_seized,
            remaining_position: DebtPosition {
                collateral: position
                    .collateral
                    .checked_sub(collateral_seized)
                    .ok_or(SafetyError::Overflow)?,
                debt: remaining_debt,
            },
            newly_uncovered_bad_debt: newly_uncovered,
        })
    }

    /// Deposit collateral and mint stable directly at the bounded oracle price.
    /// Gross mint equals PSM debt growth; the fee is protocol-held stable, not
    /// an unaccounted supply difference.
    pub fn psm_mint(
        &mut self,
        policy: SafetyPolicy,
        collateral_in: u128,
        price_q9: u128,
    ) -> Result<PsmMintResult, SafetyError> {
        policy.validate()?;
        if collateral_in == 0 || price_q9 == 0 {
            return Err(SafetyError::InvalidParameter);
        }
        let gross = mul_div(collateral_in, price_q9, PRICE_SCALE)?;
        let fee = mul_div(gross, u128::from(policy.psm_fee_bps), 10_000)?;
        let user = gross.checked_sub(fee).ok_or(SafetyError::Overflow)?;
        if user == 0 {
            return Err(SafetyError::InvalidParameter);
        }
        self.collateral_reserve = self
            .collateral_reserve
            .checked_add(collateral_in)
            .ok_or(SafetyError::Overflow)?;
        self.psm_debt = self
            .psm_debt
            .checked_add(gross)
            .ok_or(SafetyError::Overflow)?;
        self.stable_reserve = self
            .stable_reserve
            .checked_add(fee)
            .ok_or(SafetyError::Overflow)?;
        Ok(PsmMintResult {
            stable_to_user: user,
            stable_fee_to_reserve: fee,
            supply_and_debt_increase: gross,
        })
    }

    /// Burn stable against PSM debt and return collateral. The fee remains a
    /// funded stable reserve balance and therefore is not reported as burned.
    pub fn psm_redeem(
        &mut self,
        policy: SafetyPolicy,
        stable_in: u128,
        price_q9: u128,
    ) -> Result<PsmRedeemResult, SafetyError> {
        policy.validate()?;
        if stable_in == 0 || price_q9 == 0 {
            return Err(SafetyError::InvalidParameter);
        }
        let fee = mul_div(stable_in, u128::from(policy.psm_fee_bps), 10_000)?;
        let burn = stable_in.checked_sub(fee).ok_or(SafetyError::Overflow)?;
        if burn == 0 || burn > self.psm_debt {
            return Err(SafetyError::InsufficientPsmLiquidity);
        }
        let collateral_out = mul_div(burn, PRICE_SCALE, price_q9)?;
        if collateral_out == 0 || collateral_out > self.collateral_reserve {
            return Err(SafetyError::InsufficientPsmLiquidity);
        }
        self.psm_debt = self
            .psm_debt
            .checked_sub(burn)
            .ok_or(SafetyError::Overflow)?;
        self.collateral_reserve = self
            .collateral_reserve
            .checked_sub(collateral_out)
            .ok_or(SafetyError::Overflow)?;
        self.stable_reserve = self
            .stable_reserve
            .checked_add(fee)
            .ok_or(SafetyError::Overflow)?;
        Ok(PsmRedeemResult {
            collateral_to_user: collateral_out,
            stable_fee_to_reserve: fee,
            supply_and_debt_decrease: burn,
        })
    }
}

fn mul_div(value: u128, multiplier: u128, divisor: u128) -> Result<u128, SafetyError> {
    value
        .checked_mul(multiplier)
        .and_then(|product| product.checked_div(divisor))
        .ok_or(SafetyError::Overflow)
}

fn mul_div_ceil(value: u128, multiplier: u128, divisor: u128) -> Result<u128, SafetyError> {
    let product = value.checked_mul(multiplier).ok_or(SafetyError::Overflow)?;
    Ok(product.div_ceil(divisor))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: SafetyPolicy = SafetyPolicy {
        liquidation_threshold_bps: 7_500,
        liquidation_bonus_bps: 500,
        psm_fee_bps: 20,
    };

    #[test]
    fn funded_backstop_burns_debt_and_never_invents_reserve() {
        let mut state = SafetyState::default();
        state.fund_stable_reserve(80_000).unwrap();
        let result = state
            .backstop_liquidate(
                POLICY,
                DebtPosition {
                    collateral: 50_000,
                    debt: 80_000,
                },
                1_000_000_000,
            )
            .unwrap();
        assert_eq!(result.stable_burned, 80_000);
        assert_eq!(result.remaining_position.debt, 0);
        assert_eq!(state.stable_reserve, 0);
        assert!(state.collateral_reserve > 0);
        assert_eq!(state.uncovered_bad_debt, 0);
    }

    #[test]
    fn reserve_shortfall_is_explicit_bad_debt() {
        let mut state = SafetyState {
            stable_reserve: 10_000,
            ..SafetyState::default()
        };
        let result = state
            .backstop_liquidate(
                POLICY,
                DebtPosition {
                    collateral: 1_000,
                    debt: 50_000,
                },
                1_000_000_000,
            )
            .unwrap();
        assert_eq!(result.stable_burned, 10_000);
        assert_eq!(result.newly_uncovered_bad_debt, 40_000);
        assert_eq!(state.uncovered_bad_debt, 40_000);
    }

    #[test]
    fn psm_round_trip_conserves_supply_debt_and_collects_fees() {
        let mut state = SafetyState::default();
        let mint = state.psm_mint(POLICY, 100_000, 1_000_000_000).unwrap();
        assert_eq!(mint.supply_and_debt_increase, 100_000);
        assert_eq!(mint.stable_to_user + mint.stable_fee_to_reserve, 100_000);
        let redeem = state
            .psm_redeem(POLICY, mint.stable_to_user, 1_000_000_000)
            .unwrap();
        assert_eq!(
            state.psm_debt,
            mint.supply_and_debt_increase - redeem.supply_and_debt_decrease
        );
        assert_eq!(
            state.collateral_reserve,
            100_000 - redeem.collateral_to_user
        );
        assert_eq!(
            state.stable_reserve,
            mint.stable_fee_to_reserve + redeem.stable_fee_to_reserve
        );
    }

    #[test]
    fn healthy_position_cannot_be_backstop_liquidated() {
        let mut state = SafetyState {
            stable_reserve: 100_000,
            ..SafetyState::default()
        };
        assert_eq!(
            state.backstop_liquidate(
                POLICY,
                DebtPosition {
                    collateral: 200_000,
                    debt: 100_000
                },
                1_000_000_000,
            ),
            Err(SafetyError::PositionHealthy)
        );
        assert_eq!(state.stable_reserve, 100_000);
    }
}
