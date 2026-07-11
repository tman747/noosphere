//! M-CLOCK admission and rollback around Braid's canonical [`ForkScore`].
//!
//! This module does not invent a third clock. Checkpoint height is the
//! finality hand; normalized Ground plus optional capped Loom work is the
//! production hand. Wall-clock timestamps have no fork-choice authority.

use crate::Hash32;
use noos_braid::{u256_saturating_add, ForkScore};
use noos_ground::U256;
use std::collections::BTreeSet;
use thiserror::Error;

/// `L / (G + L) <= 0.10`, written without division as `9L <= G`.
pub const MAX_LOOM_SHARE_BPS: u16 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoomReceipt {
    pub eligibility_epoch: u64,
    pub nullifier: Hash32,
    pub normalized_work: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockBlock {
    pub epoch: u64,
    pub finalized_height: u64,
    pub justified_height: u64,
    pub ground_work: U256,
    pub loom_receipts: Vec<LoomReceipt>,
    pub block_hash: Hash32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockConfig {
    /// First epoch at which Loom receipts may enter a block. `None` is the
    /// mandatory blackout/rollback profile (`c_L = 0`).
    pub loom_activation_epoch: Option<u64>,
}

/// Fork-local M-CLOCK state. Cloning at a fork copies the ancestor
/// nullifier set, so replay of an ancestor receipt rejects on every child.
#[derive(Clone, Debug)]
pub struct TwoHandedClock {
    config: ClockConfig,
    finalized_height: u64,
    justified_height: u64,
    last_epoch: Option<u64>,
    ground_work: U256,
    loom_work: U256,
    receipt_nullifiers: BTreeSet<Hash32>,
}

impl TwoHandedClock {
    #[must_use]
    pub fn new(config: ClockConfig) -> Self {
        Self {
            config,
            finalized_height: 0,
            justified_height: 0,
            last_epoch: None,
            ground_work: U256::ZERO,
            loom_work: U256::ZERO,
            receipt_nullifiers: BTreeSet::new(),
        }
    }

    /// Admit one block atomically and return its exact Braid fork tuple.
    pub fn admit(&mut self, block: &ClockBlock) -> Result<ForkScore, ClockError> {
        if block.finalized_height < self.finalized_height
            || block.justified_height < self.justified_height
            || block.justified_height < block.finalized_height
        {
            return Err(ClockError::CheckpointRollback);
        }
        if self.last_epoch.is_some_and(|epoch| block.epoch < epoch) {
            return Err(ClockError::EpochRollback);
        }

        let mut fresh = BTreeSet::new();
        let mut loom = 0_u128;
        for receipt in &block.loom_receipts {
            let activation = self
                .config
                .loom_activation_epoch
                .ok_or(ClockError::LoomDisabled)?;
            if block.epoch < activation {
                return Err(ClockError::LoomDisabled);
            }
            if receipt.eligibility_epoch > block.epoch {
                return Err(ClockError::FutureReceipt);
            }
            if receipt.nullifier == [0; 32]
                || self.receipt_nullifiers.contains(&receipt.nullifier)
                || !fresh.insert(receipt.nullifier)
            {
                return Err(ClockError::ReceiptReplay);
            }
            loom = loom
                .checked_add(receipt.normalized_work)
                .ok_or(ClockError::WorkOverflow)?;
        }

        let nine_loom = loom.checked_mul(9).ok_or(ClockError::WorkOverflow)?;
        if U256::from_u128(nine_loom) > block.ground_work {
            return Err(ClockError::LoomCap);
        }
        let next_ground = u256_saturating_add(&self.ground_work, &block.ground_work);
        let next_loom = u256_saturating_add(&self.loom_work, &U256::from_u128(loom));
        // Enforce the cap over the complete fork as well as each block.
        let cumulative_nine_loom = multiply_small_saturating(next_loom, 9);
        if cumulative_nine_loom > next_ground {
            return Err(ClockError::LoomCap);
        }

        self.finalized_height = block.finalized_height;
        self.justified_height = block.justified_height;
        self.last_epoch = Some(block.epoch);
        self.ground_work = next_ground;
        self.loom_work = next_loom;
        self.receipt_nullifiers.extend(fresh);
        Ok(self.score(block.block_hash))
    }

    /// Universal M-CLOCK rollback: remove all Loom influence and reject new
    /// receipts while Ground production continues from the same chain state.
    pub fn force_ground_only(&mut self) {
        self.config.loom_activation_epoch = None;
        self.loom_work = U256::ZERO;
    }

    #[must_use]
    pub fn score(&self, block_hash: Hash32) -> ForkScore {
        ForkScore {
            finalized_epoch: self.finalized_height,
            justified_epoch: self.justified_height,
            work_since_finalized: u256_saturating_add(&self.ground_work, &self.loom_work),
            block_hash,
        }
    }

    #[must_use]
    pub const fn effective_loom_work(&self) -> U256 {
        self.loom_work
    }

    #[must_use]
    pub const fn ground_work(&self) -> U256 {
        self.ground_work
    }
}

fn multiply_small_saturating(value: U256, factor: u8) -> U256 {
    let mut out = U256::ZERO;
    for _ in 0..factor {
        out = u256_saturating_add(&out, &value);
    }
    out
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClockError {
    #[error("finalized or justified checkpoint rollback")]
    CheckpointRollback,
    #[error("block epoch rollback")]
    EpochRollback,
    #[error("Loom receipt admitted while c_L is zero")]
    LoomDisabled,
    #[error("future-epoch Loom receipt")]
    FutureReceipt,
    #[error("replayed Loom receipt nullifier")]
    ReceiptReplay,
    #[error("Loom work exceeds the ten-percent cap")]
    LoomCap,
    #[error("normalized work overflow")]
    WorkOverflow,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

    use super::*;
    use core::cmp::Ordering;

    fn block(epoch: u64, finality: u64, justified: u64, ground: u64, hash: u8) -> ClockBlock {
        ClockBlock {
            epoch,
            finalized_height: finality,
            justified_height: justified,
            ground_work: U256::from_u64(ground),
            loom_receipts: Vec::new(),
            block_hash: [hash; 32],
        }
    }

    #[test]
    fn rollback_skew_future_receipts_and_activation_boundary_reject() {
        let mut clock = TwoHandedClock::new(ClockConfig {
            loom_activation_epoch: Some(3),
        });
        clock.admit(&block(2, 1, 1, 90, 1)).unwrap();

        let mut before_activation = block(2, 1, 1, 90, 2);
        before_activation.loom_receipts.push(LoomReceipt {
            eligibility_epoch: 2,
            nullifier: [1; 32],
            normalized_work: 10,
        });
        assert_eq!(
            clock.admit(&before_activation),
            Err(ClockError::LoomDisabled)
        );

        let mut boundary = block(3, 2, 2, 90, 3);
        boundary.loom_receipts.push(LoomReceipt {
            eligibility_epoch: 3,
            nullifier: [2; 32],
            normalized_work: 10,
        });
        clock.admit(&boundary).unwrap();

        let mut future = block(4, 2, 2, 90, 4);
        future.loom_receipts.push(LoomReceipt {
            eligibility_epoch: 5,
            nullifier: [3; 32],
            normalized_work: 1,
        });
        assert_eq!(clock.admit(&future), Err(ClockError::FutureReceipt));
        assert_eq!(
            clock.admit(&block(2, 2, 2, 90, 5)),
            Err(ClockError::EpochRollback)
        );
        assert_eq!(
            clock.admit(&block(4, 1, 2, 90, 6)),
            Err(ClockError::CheckpointRollback)
        );
    }

    #[test]
    fn cap_replay_across_descendant_forks_and_ground_only_rollback() {
        let mut clock = TwoHandedClock::new(ClockConfig {
            loom_activation_epoch: Some(0),
        });
        let mut accepted = block(1, 1, 1, 90, 1);
        accepted.loom_receipts.push(LoomReceipt {
            eligibility_epoch: 1,
            nullifier: [7; 32],
            normalized_work: 10,
        });
        clock.admit(&accepted).unwrap();

        let mut left = clock.clone();
        let mut right = clock.clone();
        let mut replay = block(2, 1, 1, 90, 2);
        replay.loom_receipts = accepted.loom_receipts.clone();
        assert_eq!(left.admit(&replay), Err(ClockError::ReceiptReplay));
        replay.block_hash = [3; 32];
        assert_eq!(right.admit(&replay), Err(ClockError::ReceiptReplay));

        let mut above_cap = block(2, 1, 1, 89, 4);
        above_cap.loom_receipts.push(LoomReceipt {
            eligibility_epoch: 2,
            nullifier: [8; 32],
            normalized_work: 10,
        });
        assert_eq!(clock.admit(&above_cap), Err(ClockError::LoomCap));

        let before_ground = clock.ground_work();
        clock.force_ground_only();
        assert_eq!(clock.effective_loom_work(), U256::ZERO);
        clock.admit(&block(2, 1, 1, 5, 5)).unwrap();
        assert!(clock.ground_work() > before_ground);
    }

    fn reference_cmp(a: &ForkScore, b: &ForkScore) -> Ordering {
        a.finalized_epoch
            .cmp(&b.finalized_epoch)
            .then(a.justified_epoch.cmp(&b.justified_epoch))
            .then(a.work_since_finalized.cmp(&b.work_since_finalized))
            .then(b.block_hash.cmp(&a.block_hash))
    }

    #[test]
    fn generated_fork_orderings_match_independent_reference() {
        let mut x = 0x5eed_c10c_2026_0710_u64;
        for _ in 0..100_000 {
            let mut next = || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            let a = ForkScore {
                finalized_epoch: next() % 8,
                justified_epoch: next() % 12,
                work_since_finalized: U256::from_limbs([next(), next(), next(), next()]),
                block_hash: [next() as u8; 32],
            };
            let b = ForkScore {
                finalized_epoch: next() % 8,
                justified_epoch: next() % 12,
                work_since_finalized: U256::from_limbs([next(), next(), next(), next()]),
                block_hash: [next() as u8; 32],
            };
            assert_eq!(a.cmp(&b), reference_cmp(&a, &b));
            if a.finalized_epoch > b.finalized_epoch {
                assert!(a > b, "work can never reverse the finality hand");
            } else if a.finalized_epoch == b.finalized_epoch
                && a.justified_epoch > b.justified_epoch
            {
                assert!(a > b, "work can never reverse the justification hand");
            }
        }
    }
}
