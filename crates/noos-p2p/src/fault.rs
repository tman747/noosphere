//! Deterministic WAN fault scheduling for executable protocol experiments.
//!
//! This module decides only whether and when a real P2P protocol payload is
//! delivered.  It never fabricates consensus outcomes.  Experiment harnesses
//! feed delivered bytes through the ordinary decoder and `NodeCore` import
//! path, and replay dropped/withheld payloads through targeted repair after
//! the fault window heals.

use crate::{Protocol, SplitMix64};

pub const WAN_REGION_COUNT: usize = 4;
pub const WAN_VALIDATOR_COUNT: usize = 10;
pub const WAN_FAULT_BOUND: usize = 3;
pub const WAN_LATENCY_SWEEP_MS: [u64; 4] = [50, 200, 400, 800];
pub const WAN_LOSS_SWEEP_PERMILLE: [u16; 4] = [0, 20, 50, 100];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    RandomLoss,
    Partition,
    RegionalEclipse,
    ValidatorCrash,
    DaWithholding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    DeliverAtMs(u64),
    Drop(DropReason),
}

/// One deterministic point in the frozen WAN sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WanCase {
    pub seed: u64,
    pub latency_ms: u64,
    pub loss_permille: u16,
    pub reorder: bool,
    pub asymmetric_bandwidth: bool,
    pub crashed_validator: usize,
    pub eclipsed_region: usize,
    pub minority_region: usize,
    pub withhold_da: bool,
    pub ai_reachable_only_on_minority: bool,
}

impl WanCase {
    /// Maps corpus ordinal to the complete latency/loss cross-product.  The
    /// seed controls all individual fault decisions, not sweep coverage.
    pub fn from_seed(seed: u64, ordinal: usize) -> Self {
        let latency_index = ordinal.rem_euclid(WAN_LATENCY_SWEEP_MS.len());
        let latency_ms = WAN_LATENCY_SWEEP_MS[latency_index];
        let loss_index = ordinal
            .checked_div(WAN_LATENCY_SWEEP_MS.len())
            .unwrap_or_default()
            .rem_euclid(WAN_LOSS_SWEEP_PERMILLE.len());
        let mut rng = SplitMix64::new(seed ^ 0x5741_4E2D_3031);
        Self {
            seed,
            latency_ms,
            loss_permille: WAN_LOSS_SWEEP_PERMILLE[loss_index],
            reorder: true,
            asymmetric_bandwidth: true,
            crashed_validator: (rng.next_u64() as usize).rem_euclid(WAN_VALIDATOR_COUNT),
            eclipsed_region: (rng.next_u64() as usize).rem_euclid(WAN_REGION_COUNT),
            minority_region: WAN_REGION_COUNT - 1,
            withhold_da: true,
            ai_reachable_only_on_minority: true,
        }
    }

    /// Deterministically routes one real protocol message.
    #[allow(clippy::too_many_arguments)]
    pub fn route(
        &self,
        protocol: Protocol,
        message_index: u64,
        sender_validator: usize,
        from_region: usize,
        to_region: usize,
        now_ms: u64,
        fault_active: bool,
    ) -> Delivery {
        if fault_active && sender_validator == self.crashed_validator {
            return Delivery::Drop(DropReason::ValidatorCrash);
        }
        if fault_active && to_region == self.eclipsed_region && from_region != to_region {
            return Delivery::Drop(DropReason::RegionalEclipse);
        }
        if fault_active
            && (from_region == self.minority_region) != (to_region == self.minority_region)
        {
            return Delivery::Drop(DropReason::Partition);
        }
        if fault_active && self.withhold_da && protocol == Protocol::BlobShard {
            return Delivery::Drop(DropReason::DaWithholding);
        }

        let mut rng = SplitMix64::new(
            self.seed
                ^ message_index.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                ^ (from_region as u64).wrapping_shl(8)
                ^ (to_region as u64).wrapping_shl(16)
                ^ protocol.app_index().map_or(8, |index| index) as u64,
        );
        if rng.next_u64().rem_euclid(1000) < u64::from(self.loss_permille) {
            return Delivery::Drop(DropReason::RandomLoss);
        }

        let reorder_jitter = if self.reorder {
            rng.next_u64().rem_euclid(self.latency_ms.saturating_add(1))
        } else {
            0
        };
        let asymmetric_delay = if self.asymmetric_bandwidth && from_region > to_region {
            self.latency_ms / 2
        } else {
            0
        };
        Delivery::DeliverAtMs(
            now_ms
                .saturating_add(self.latency_ms)
                .saturating_add(reorder_jitter)
                .saturating_add(asymmetric_delay),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn sixteen_seed_ordinals_cover_the_exact_frozen_sweep() {
        let cases = (0..16)
            .map(|ordinal| WanCase::from_seed(ordinal as u64, ordinal))
            .collect::<Vec<_>>();
        let latencies = cases
            .iter()
            .map(|case| case.latency_ms)
            .collect::<BTreeSet<_>>();
        let losses = cases
            .iter()
            .map(|case| case.loss_permille)
            .collect::<BTreeSet<_>>();
        assert_eq!(latencies, BTreeSet::from(WAN_LATENCY_SWEEP_MS));
        assert_eq!(losses, BTreeSet::from(WAN_LOSS_SWEEP_PERMILLE));
        assert!(cases.iter().all(|case| {
            case.crashed_validator < WAN_VALIDATOR_COUNT
                && case.eclipsed_region < WAN_REGION_COUNT
                && case.ai_reachable_only_on_minority
        }));
    }

    #[test]
    fn fault_decisions_are_reproducible_and_heal() {
        let mut case = WanCase::from_seed(42, 7);
        case.eclipsed_region = 2;
        case.minority_region = 3;
        case.crashed_validator = 9;
        let args = (Protocol::BraidHeader, 11, 0, 0, 3, 1_000);
        assert_eq!(
            case.route(args.0, args.1, args.2, args.3, args.4, args.5, true),
            Delivery::Drop(DropReason::Partition)
        );
        let healed = case.route(args.0, args.1, args.2, args.3, args.4, args.5, false);
        assert!(matches!(healed, Delivery::DeliverAtMs(_)));
        assert_eq!(
            healed,
            case.route(args.0, args.1, args.2, args.3, args.4, args.5, false)
        );
        assert_eq!(
            case.route(Protocol::BlobShard, 12, 0, 0, 1, 1_000, true),
            Delivery::Drop(DropReason::DaWithholding)
        );
    }
}
