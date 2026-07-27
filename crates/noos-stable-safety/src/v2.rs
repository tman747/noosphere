//! Protocol-v2 stable reserve with segregated redemption and liquidation
//! inventories, independent activity caps, and pause-with-redemption semantics.

use serde::{Deserialize, Serialize};

pub const PRICE_SCALE: u128 = 1_000_000_000;
const BASIS_POINTS: u128 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StableV2Error {
    InvalidPolicy,
    InvalidAmount,
    PositionHealthy,
    RiskIncreasingPaused,
    InsufficientBackstopReserve,
    InsufficientRedemptionInventory,
    CapExceeded,
    ConservationFailure,
    HeightRegression,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StableReservePolicyV2 {
    pub liquidation_threshold_bps: u16,
    pub liquidation_bonus_bps: u16,
    pub psm_fee_bps: u16,
    pub max_psm_debt: u128,
    pub max_psm_mint_per_epoch: u128,
    pub max_psm_redeem_per_epoch: u128,
    pub max_backstop_burn_per_epoch: u128,
    pub max_uncovered_bad_debt: u128,
    pub epoch_blocks: u64,
}

impl StableReservePolicyV2 {
    pub fn validate(self) -> Result<(), StableV2Error> {
        if !(1..=9_500).contains(&self.liquidation_threshold_bps)
            || self.liquidation_bonus_bps > 1_500
            || self.psm_fee_bps > 500
            || self.max_psm_debt == 0
            || self.max_psm_mint_per_epoch == 0
            || self.max_psm_redeem_per_epoch == 0
            || self.max_backstop_burn_per_epoch == 0
            || self.max_uncovered_bad_debt == 0
            || self.epoch_blocks == 0
        {
            return Err(StableV2Error::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableReserveStateV2 {
    /// Stable inventory that can be burned against liquidations or bad debt.
    pub stable_backstop_reserve: u128,
    /// Collateral paid into the PSM and reserved for direct redemption.
    pub psm_collateral_inventory: u128,
    /// Collateral seized by protocol liquidations. Never counted as PSM stock.
    pub seized_collateral_inventory: u128,
    /// Outstanding stable supply issued by the PSM.
    pub psm_debt: u128,
    /// Closed position debt that remains explicitly unresolved.
    pub uncovered_bad_debt: u128,
    /// Risk-increasing mint operations are disabled while exits remain open.
    pub risk_increasing_paused: bool,

    pub psm_minted_total: u128,
    pub psm_burned_total: u128,
    pub psm_collateral_in_total: u128,
    pub psm_collateral_out_total: u128,
    pub backstop_stable_in_total: u128,
    pub psm_fee_stable_total: u128,
    pub backstop_stable_burned_total: u128,
    pub seized_collateral_total: u128,

    pub usage_epoch: u64,
    pub psm_minted_in_epoch: u128,
    pub psm_redeemed_in_epoch: u128,
    pub backstop_burned_in_epoch: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StableDebtPositionV2 {
    pub collateral: u128,
    pub debt: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsmMintV2 {
    pub stable_to_user: u128,
    pub stable_fee_to_backstop: u128,
    pub supply_and_debt_increase: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsmRedeemV2 {
    pub collateral_to_user: u128,
    pub stable_fee_to_backstop: u128,
    pub supply_and_debt_decrease: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackstopLiquidationV2 {
    pub stable_burned: u128,
    pub collateral_seized: u128,
    pub newly_uncovered_bad_debt: u128,
    pub remaining_position: StableDebtPositionV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedemptionHealthV2 {
    pub psm_debt: u128,
    pub collateral_inventory: u128,
    pub collateral_value_q9: u128,
    pub maximum_redeemable_debt: u128,
    pub fully_collateralized: bool,
}

impl StableReserveStateV2 {
    pub fn validate(self, policy: StableReservePolicyV2) -> Result<(), StableV2Error> {
        policy.validate()?;
        let psm_uses = self
            .psm_burned_total
            .checked_add(self.psm_debt)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        let collateral_uses = self
            .psm_collateral_out_total
            .checked_add(self.psm_collateral_inventory)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        let stable_sources = self
            .backstop_stable_in_total
            .checked_add(self.psm_fee_stable_total)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        let stable_uses = self
            .stable_backstop_reserve
            .checked_add(self.backstop_stable_burned_total)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if self.psm_minted_total != psm_uses
            || self.psm_collateral_in_total != collateral_uses
            || stable_sources != stable_uses
            || self.seized_collateral_total != self.seized_collateral_inventory
            || self.psm_debt > policy.max_psm_debt
            || self.uncovered_bad_debt > policy.max_uncovered_bad_debt
            || self.psm_minted_in_epoch > policy.max_psm_mint_per_epoch
            || self.psm_redeemed_in_epoch > policy.max_psm_redeem_per_epoch
            || self.backstop_burned_in_epoch > policy.max_backstop_burn_per_epoch
        {
            return Err(StableV2Error::ConservationFailure);
        }
        Ok(())
    }

    pub fn set_risk_increasing_pause(&mut self, paused: bool) {
        self.risk_increasing_paused = paused;
    }

    pub fn fund_backstop(
        &mut self,
        policy: StableReservePolicyV2,
        amount: u128,
    ) -> Result<(), StableV2Error> {
        if amount == 0 {
            return Err(StableV2Error::InvalidAmount);
        }
        let mut candidate = *self;
        candidate.stable_backstop_reserve = candidate
            .stable_backstop_reserve
            .checked_add(amount)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.backstop_stable_in_total = candidate
            .backstop_stable_in_total
            .checked_add(amount)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.validate(policy)?;
        *self = candidate;
        Ok(())
    }

    pub fn psm_mint(
        &mut self,
        policy: StableReservePolicyV2,
        collateral_in: u128,
        price_q9: u128,
        current_height: u64,
    ) -> Result<PsmMintV2, StableV2Error> {
        policy.validate()?;
        if collateral_in == 0 || price_q9 == 0 {
            return Err(StableV2Error::InvalidAmount);
        }
        if self.risk_increasing_paused {
            return Err(StableV2Error::RiskIncreasingPaused);
        }
        let gross = mul_div(collateral_in, price_q9, PRICE_SCALE)?;
        let fee = mul_div(gross, u128::from(policy.psm_fee_bps), BASIS_POINTS)?;
        let stable_to_user = gross
            .checked_sub(fee)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if stable_to_user == 0 {
            return Err(StableV2Error::InvalidAmount);
        }

        let mut candidate = *self;
        candidate.roll_epoch(policy, current_height)?;
        candidate.psm_debt = candidate
            .psm_debt
            .checked_add(gross)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_minted_in_epoch = candidate
            .psm_minted_in_epoch
            .checked_add(gross)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if candidate.psm_debt > policy.max_psm_debt
            || candidate.psm_minted_in_epoch > policy.max_psm_mint_per_epoch
        {
            return Err(StableV2Error::CapExceeded);
        }
        candidate.psm_collateral_inventory = candidate
            .psm_collateral_inventory
            .checked_add(collateral_in)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.stable_backstop_reserve = candidate
            .stable_backstop_reserve
            .checked_add(fee)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_minted_total = candidate
            .psm_minted_total
            .checked_add(gross)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_collateral_in_total = candidate
            .psm_collateral_in_total
            .checked_add(collateral_in)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_fee_stable_total = candidate
            .psm_fee_stable_total
            .checked_add(fee)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.validate(policy)?;
        *self = candidate;
        Ok(PsmMintV2 {
            stable_to_user,
            stable_fee_to_backstop: fee,
            supply_and_debt_increase: gross,
        })
    }

    /// Direct redemption remains available while risk-increasing operations are
    /// paused. It is limited only by dedicated PSM inventory, PSM debt, and the
    /// independent per-epoch redemption cap.
    pub fn psm_redeem(
        &mut self,
        policy: StableReservePolicyV2,
        stable_in: u128,
        price_q9: u128,
        current_height: u64,
    ) -> Result<PsmRedeemV2, StableV2Error> {
        policy.validate()?;
        if stable_in == 0 || price_q9 == 0 {
            return Err(StableV2Error::InvalidAmount);
        }
        let fee = mul_div(stable_in, u128::from(policy.psm_fee_bps), BASIS_POINTS)?;
        let burn = stable_in
            .checked_sub(fee)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if burn == 0 || burn > self.psm_debt {
            return Err(StableV2Error::InsufficientRedemptionInventory);
        }
        let collateral_out = mul_div(burn, PRICE_SCALE, price_q9)?;
        if collateral_out == 0 || collateral_out > self.psm_collateral_inventory {
            return Err(StableV2Error::InsufficientRedemptionInventory);
        }

        let mut candidate = *self;
        candidate.roll_epoch(policy, current_height)?;
        candidate.psm_redeemed_in_epoch = candidate
            .psm_redeemed_in_epoch
            .checked_add(burn)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if candidate.psm_redeemed_in_epoch > policy.max_psm_redeem_per_epoch {
            return Err(StableV2Error::CapExceeded);
        }
        candidate.psm_debt = candidate
            .psm_debt
            .checked_sub(burn)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_collateral_inventory = candidate
            .psm_collateral_inventory
            .checked_sub(collateral_out)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.stable_backstop_reserve = candidate
            .stable_backstop_reserve
            .checked_add(fee)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_burned_total = candidate
            .psm_burned_total
            .checked_add(burn)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_collateral_out_total = candidate
            .psm_collateral_out_total
            .checked_add(collateral_out)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.psm_fee_stable_total = candidate
            .psm_fee_stable_total
            .checked_add(fee)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.validate(policy)?;
        *self = candidate;
        Ok(PsmRedeemV2 {
            collateral_to_user: collateral_out,
            stable_fee_to_backstop: fee,
            supply_and_debt_decrease: burn,
        })
    }

    /// Closes one unhealthy position. The independently capped funded portion
    /// burns reserve stable; any remainder is preserved as explicit bad debt.
    /// All seized collateral enters a non-redemption inventory.
    pub fn backstop_liquidate(
        &mut self,
        policy: StableReservePolicyV2,
        position: StableDebtPositionV2,
        price_q9: u128,
        current_height: u64,
    ) -> Result<BackstopLiquidationV2, StableV2Error> {
        policy.validate()?;
        if price_q9 == 0 || position.debt == 0 {
            return Err(StableV2Error::InvalidAmount);
        }
        let collateral_value = mul_div(position.collateral, price_q9, PRICE_SCALE)?;
        let threshold_value = mul_div(
            collateral_value,
            u128::from(policy.liquidation_threshold_bps),
            BASIS_POINTS,
        )?;
        if position.debt <= threshold_value {
            return Err(StableV2Error::PositionHealthy);
        }

        let mut candidate = *self;
        candidate.roll_epoch(policy, current_height)?;
        let remaining_epoch_capacity = policy
            .max_backstop_burn_per_epoch
            .checked_sub(candidate.backstop_burned_in_epoch)
            .ok_or(StableV2Error::ConservationFailure)?;
        let stable_burned = candidate
            .stable_backstop_reserve
            .min(position.debt)
            .min(remaining_epoch_capacity);
        let newly_uncovered_bad_debt = position
            .debt
            .checked_sub(stable_burned)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.uncovered_bad_debt = candidate
            .uncovered_bad_debt
            .checked_add(newly_uncovered_bad_debt)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if candidate.uncovered_bad_debt > policy.max_uncovered_bad_debt {
            return Err(StableV2Error::CapExceeded);
        }
        candidate.stable_backstop_reserve = candidate
            .stable_backstop_reserve
            .checked_sub(stable_burned)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.backstop_stable_burned_total = candidate
            .backstop_stable_burned_total
            .checked_add(stable_burned)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.backstop_burned_in_epoch = candidate
            .backstop_burned_in_epoch
            .checked_add(stable_burned)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.seized_collateral_inventory = candidate
            .seized_collateral_inventory
            .checked_add(position.collateral)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.seized_collateral_total = candidate
            .seized_collateral_total
            .checked_add(position.collateral)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.validate(policy)?;
        *self = candidate;
        Ok(BackstopLiquidationV2 {
            stable_burned,
            collateral_seized: position.collateral,
            newly_uncovered_bad_debt,
            remaining_position: StableDebtPositionV2 {
                collateral: 0,
                debt: 0,
            },
        })
    }

    /// Burns funded reserve stable against previously recorded bad debt. This
    /// risk-reducing transition remains available during a pause and shares the
    /// independent backstop burn cap.
    pub fn resolve_bad_debt(
        &mut self,
        policy: StableReservePolicyV2,
        amount: u128,
        current_height: u64,
    ) -> Result<(), StableV2Error> {
        if amount == 0 || amount > self.uncovered_bad_debt || amount > self.stable_backstop_reserve
        {
            return Err(StableV2Error::InsufficientBackstopReserve);
        }
        let mut candidate = *self;
        candidate.roll_epoch(policy, current_height)?;
        candidate.backstop_burned_in_epoch = candidate
            .backstop_burned_in_epoch
            .checked_add(amount)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        if candidate.backstop_burned_in_epoch > policy.max_backstop_burn_per_epoch {
            return Err(StableV2Error::CapExceeded);
        }
        candidate.stable_backstop_reserve = candidate
            .stable_backstop_reserve
            .checked_sub(amount)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.uncovered_bad_debt = candidate
            .uncovered_bad_debt
            .checked_sub(amount)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.backstop_stable_burned_total = candidate
            .backstop_stable_burned_total
            .checked_add(amount)
            .ok_or(StableV2Error::ArithmeticOverflow)?;
        candidate.validate(policy)?;
        *self = candidate;
        Ok(())
    }

    pub fn redemption_health(self, price_q9: u128) -> Result<RedemptionHealthV2, StableV2Error> {
        if price_q9 == 0 {
            return Err(StableV2Error::InvalidAmount);
        }
        let collateral_value_q9 = mul_div(self.psm_collateral_inventory, price_q9, PRICE_SCALE)?;
        Ok(RedemptionHealthV2 {
            psm_debt: self.psm_debt,
            collateral_inventory: self.psm_collateral_inventory,
            collateral_value_q9,
            maximum_redeemable_debt: self.psm_debt.min(collateral_value_q9),
            fully_collateralized: collateral_value_q9 >= self.psm_debt,
        })
    }

    fn roll_epoch(
        &mut self,
        policy: StableReservePolicyV2,
        current_height: u64,
    ) -> Result<(), StableV2Error> {
        let epoch = current_height
            .checked_div(policy.epoch_blocks)
            .ok_or(StableV2Error::InvalidPolicy)?;
        if epoch < self.usage_epoch {
            return Err(StableV2Error::HeightRegression);
        }
        if epoch > self.usage_epoch {
            self.usage_epoch = epoch;
            self.psm_minted_in_epoch = 0;
            self.psm_redeemed_in_epoch = 0;
            self.backstop_burned_in_epoch = 0;
        }
        Ok(())
    }
}

fn mul_div(value: u128, multiplier: u128, divisor: u128) -> Result<u128, StableV2Error> {
    if divisor == 0 {
        return Err(StableV2Error::InvalidAmount);
    }
    value
        .checked_mul(multiplier)
        .and_then(|product| product.checked_div(divisor))
        .ok_or(StableV2Error::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: StableReservePolicyV2 = StableReservePolicyV2 {
        liquidation_threshold_bps: 7_500,
        liquidation_bonus_bps: 500,
        psm_fee_bps: 20,
        max_psm_debt: 1_000_000,
        max_psm_mint_per_epoch: 500_000,
        max_psm_redeem_per_epoch: 500_000,
        max_backstop_burn_per_epoch: 100_000,
        max_uncovered_bad_debt: 500_000,
        epoch_blocks: 100,
    };

    #[test]
    fn psm_round_trip_conserves_segregated_inventory() {
        let mut state = StableReserveStateV2::default();
        let mint = state.psm_mint(POLICY, 100_000, PRICE_SCALE, 1).unwrap();
        assert_eq!(mint.supply_and_debt_increase, 100_000);
        assert_eq!(mint.stable_to_user, 99_800);
        assert_eq!(state.psm_collateral_inventory, 100_000);
        assert_eq!(state.seized_collateral_inventory, 0);
        assert_eq!(state.stable_backstop_reserve, 200);

        let redeem = state
            .psm_redeem(POLICY, mint.stable_to_user, PRICE_SCALE, 2)
            .unwrap();
        assert_eq!(redeem.supply_and_debt_decrease, 99_601);
        assert_eq!(redeem.collateral_to_user, 99_601);
        assert_eq!(state.psm_debt, 399);
        assert_eq!(state.psm_collateral_inventory, 399);
        assert_eq!(state.stable_backstop_reserve, 399);
        state.validate(POLICY).unwrap();
        assert!(
            state
                .redemption_health(PRICE_SCALE)
                .unwrap()
                .fully_collateralized
        );
    }

    #[test]
    fn pause_blocks_mint_but_preserves_direct_redemption() {
        let mut state = StableReserveStateV2::default();
        let mint = state.psm_mint(POLICY, 100_000, PRICE_SCALE, 1).unwrap();
        state.set_risk_increasing_pause(true);
        let paused = state;
        assert_eq!(
            state.psm_mint(POLICY, 1_000, PRICE_SCALE, 2),
            Err(StableV2Error::RiskIncreasingPaused)
        );
        assert_eq!(state, paused);
        assert!(state
            .psm_redeem(POLICY, mint.stable_to_user, PRICE_SCALE, 2)
            .is_ok());
        state.validate(POLICY).unwrap();
    }

    #[test]
    fn independent_caps_fail_atomically_and_reset_by_epoch() {
        let mut policy = POLICY;
        policy.max_psm_debt = 100_000;
        policy.max_psm_mint_per_epoch = 100_000;
        let mut state = StableReserveStateV2::default();
        state.psm_mint(policy, 100_000, PRICE_SCALE, 1).unwrap();
        let capped = state;
        assert_eq!(
            state.psm_mint(policy, 1, PRICE_SCALE, 2),
            Err(StableV2Error::CapExceeded)
        );
        assert_eq!(state, capped);
        state.psm_redeem(policy, 50_000, PRICE_SCALE, 100).unwrap();
        assert_eq!(state.usage_epoch, 1);
        state.validate(policy).unwrap();
    }

    #[test]
    fn backstop_separates_seized_inventory_and_explicit_bad_debt() {
        let mut state = StableReserveStateV2::default();
        state.fund_backstop(POLICY, 40_000).unwrap();
        let result = state
            .backstop_liquidate(
                POLICY,
                StableDebtPositionV2 {
                    collateral: 50_000,
                    debt: 100_000,
                },
                PRICE_SCALE,
                1,
            )
            .unwrap();
        assert_eq!(result.stable_burned, 40_000);
        assert_eq!(result.newly_uncovered_bad_debt, 60_000);
        assert_eq!(result.collateral_seized, 50_000);
        assert_eq!(state.psm_collateral_inventory, 0);
        assert_eq!(state.seized_collateral_inventory, 50_000);
        assert_eq!(state.uncovered_bad_debt, 60_000);

        state.fund_backstop(POLICY, 60_000).unwrap();
        state.set_risk_increasing_pause(true);
        state.resolve_bad_debt(POLICY, 60_000, 100).unwrap();
        assert_eq!(state.uncovered_bad_debt, 0);
        state.validate(POLICY).unwrap();
    }

    #[test]
    fn healthy_positions_and_bad_debt_cap_reject_without_mutation() {
        let mut state = StableReserveStateV2::default();
        state.fund_backstop(POLICY, 100_000).unwrap();
        let funded = state;
        assert_eq!(
            state.backstop_liquidate(
                POLICY,
                StableDebtPositionV2 {
                    collateral: 200_000,
                    debt: 100_000,
                },
                PRICE_SCALE,
                1,
            ),
            Err(StableV2Error::PositionHealthy)
        );
        assert_eq!(state, funded);

        let mut capped_policy = POLICY;
        capped_policy.max_uncovered_bad_debt = 10;
        let empty = StableReserveStateV2::default();
        let mut capped = empty;
        assert_eq!(
            capped.backstop_liquidate(
                capped_policy,
                StableDebtPositionV2 {
                    collateral: 1,
                    debt: 11,
                },
                PRICE_SCALE,
                1,
            ),
            Err(StableV2Error::CapExceeded)
        );
        assert_eq!(capped, empty);
    }
}
