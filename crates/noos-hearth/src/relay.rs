//! DCUtR-class traversal accounting, funded relay fallback, and locality honesty.
#![allow(clippy::arithmetic_side_effects)]

use noos_species::Hash32;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RttClass {
    Local,
    Regional,
    Continental,
    Intercontinental,
}

impl RttClass {
    #[must_use]
    pub const fn from_millis(rtt_ms: u32) -> Self {
        match rtt_ms {
            0..=10 => Self::Local,
            11..=50 => Self::Regional,
            51..=120 => Self::Continental,
            _ => Self::Intercontinental,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPath {
    Direct,
    FundedRelay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalAttempt {
    pub pair_id: Hash32,
    pub direct_connected: bool,
    pub relay_reachable: bool,
    pub relay_cost: u128,
    pub routed_job_revenue: u128,
    pub measured_rtt_ms: u32,
    pub advertised_rtt_class: RttClass,
}

impl TraversalAttempt {
    pub fn select_path(self) -> Result<OverlayPath, RelayError> {
        if self.direct_connected {
            return Ok(OverlayPath::Direct);
        }
        if !self.relay_reachable {
            return Err(RelayError::Unreachable);
        }
        if self.relay_cost > self.routed_job_revenue {
            return Err(RelayError::RelayUnfunded);
        }
        Ok(OverlayPath::FundedRelay)
    }

    #[must_use]
    pub fn locality_honest(self) -> bool {
        RttClass::from_millis(self.measured_rtt_ms) == self.advertised_rtt_class
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayMeasurement {
    pub attempts: Vec<TraversalAttempt>,
    pub locality_served_rtts_ms: Vec<u32>,
    pub random_served_rtts_ms: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlaySummary {
    pub direct_success_bps: u16,
    pub reachability_bps: u16,
    pub relay_cost_share_bps: u16,
    pub locality_average_rtt_ms: u64,
    pub random_average_rtt_ms: u64,
    pub dishonest_locality_claims: u64,
}

impl OverlayMeasurement {
    pub fn summarize(&self) -> Result<OverlaySummary, RelayError> {
        if self.attempts.is_empty()
            || self.locality_served_rtts_ms.is_empty()
            || self.locality_served_rtts_ms.len() != self.random_served_rtts_ms.len()
        {
            return Err(RelayError::IncompleteMeasurement);
        }
        let attempts = self.attempts.len() as u128;
        let direct = self
            .attempts
            .iter()
            .filter(|attempt| attempt.direct_connected)
            .count() as u128;
        let reachable = self
            .attempts
            .iter()
            .filter(|attempt| attempt.direct_connected || attempt.relay_reachable)
            .count() as u128;
        let relay_cost = self.attempts.iter().try_fold(0u128, |sum, attempt| {
            sum.checked_add(if attempt.direct_connected {
                0
            } else {
                attempt.relay_cost
            })
            .ok_or(RelayError::ArithmeticOverflow)
        })?;
        let revenue = self.attempts.iter().try_fold(0u128, |sum, attempt| {
            sum.checked_add(attempt.routed_job_revenue)
                .ok_or(RelayError::ArithmeticOverflow)
        })?;
        let locality_sum = self
            .locality_served_rtts_ms
            .iter()
            .map(|&value| u64::from(value))
            .sum::<u64>();
        let random_sum = self
            .random_served_rtts_ms
            .iter()
            .map(|&value| u64::from(value))
            .sum::<u64>();
        Ok(OverlaySummary {
            direct_success_bps: u16::try_from(direct.saturating_mul(10_000) / attempts)
                .map_err(|_| RelayError::ArithmeticOverflow)?,
            reachability_bps: u16::try_from(reachable.saturating_mul(10_000) / attempts)
                .map_err(|_| RelayError::ArithmeticOverflow)?,
            relay_cost_share_bps: relay_cost
                .saturating_mul(10_000)
                .checked_div(revenue)
                .and_then(|value| u16::try_from(value).ok())
                .unwrap_or(u16::MAX),
            locality_average_rtt_ms: locality_sum / self.locality_served_rtts_ms.len() as u64,
            random_average_rtt_ms: random_sum / self.random_served_rtts_ms.len() as u64,
            dishonest_locality_claims: self
                .attempts
                .iter()
                .filter(|attempt| !attempt.locality_honest())
                .count() as u64,
        })
    }
}

impl OverlaySummary {
    #[must_use]
    pub fn deployed_threshold_met(self) -> bool {
        self.direct_success_bps >= 6_000
            && self.reachability_bps == 10_000
            && self.relay_cost_share_bps <= 2_000
            && self.locality_average_rtt_ms < self.random_average_rtt_ms
    }

    #[must_use]
    pub fn economic_kill_fired(self) -> bool {
        self.direct_success_bps < 5_000 || self.relay_cost_share_bps > 2_000
    }
}

/// Selects the lowest measured RTT among eligible whole-job replicas.
pub fn locality_route(
    measured_rtts: &BTreeMap<Hash32, u32>,
    eligible: &[Hash32],
) -> Result<Hash32, RelayError> {
    eligible
        .iter()
        .filter_map(|hearth| measured_rtts.get(hearth).map(|rtt| (*rtt, *hearth)))
        .min()
        .map(|(_, hearth)| hearth)
        .ok_or(RelayError::Unreachable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    Unreachable,
    RelayUnfunded,
    IncompleteMeasurement,
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    #[test]
    fn failed_traversal_always_uses_a_funded_relay_or_rejects_reachability() {
        let fallback = TraversalAttempt {
            pair_id: h(1),
            direct_connected: false,
            relay_reachable: true,
            relay_cost: 10,
            routed_job_revenue: 100,
            measured_rtt_ms: 70,
            advertised_rtt_class: RttClass::Continental,
        };
        assert_eq!(fallback.select_path().unwrap(), OverlayPath::FundedRelay);
        assert_eq!(
            TraversalAttempt {
                relay_reachable: false,
                ..fallback
            }
            .select_path(),
            Err(RelayError::Unreachable)
        );
        assert_eq!(
            TraversalAttempt {
                relay_cost: 101,
                ..fallback
            }
            .select_path(),
            Err(RelayError::RelayUnfunded)
        );
    }

    #[test]
    fn exact_overlay_thresholds_and_locality_benefit_are_evaluated() {
        let attempts = (0u8..10)
            .map(|index| TraversalAttempt {
                pair_id: h(index),
                direct_connected: index < 6,
                relay_reachable: true,
                relay_cost: if index < 6 { 0 } else { 10 },
                routed_job_revenue: 25,
                measured_rtt_ms: 40,
                advertised_rtt_class: RttClass::Regional,
            })
            .collect();
        let summary = OverlayMeasurement {
            attempts,
            locality_served_rtts_ms: vec![10, 20, 30],
            random_served_rtts_ms: vec![30, 40, 50],
        }
        .summarize()
        .unwrap();
        assert_eq!(summary.direct_success_bps, 6_000);
        assert_eq!(summary.reachability_bps, 10_000);
        assert_eq!(summary.relay_cost_share_bps, 1_600);
        assert!(summary.deployed_threshold_met());
    }

    #[test]
    fn dishonest_rtt_class_is_detected_independently() {
        let attempt = TraversalAttempt {
            pair_id: h(1),
            direct_connected: true,
            relay_reachable: true,
            relay_cost: 0,
            routed_job_revenue: 1,
            measured_rtt_ms: 140,
            advertised_rtt_class: RttClass::Local,
        };
        assert!(!attempt.locality_honest());
    }
}
