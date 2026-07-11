//! Replica/batch WAN federation and the interactive-pipeline autopsy model.
#![allow(clippy::arithmetic_side_effects)]

use noos_species::Hash32;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaCandidate {
    pub hearth_id: Hash32,
    pub locality_rtt_ms: u32,
    pub availability_bps: u16,
    pub price_per_million_tokens: u64,
    pub capacity_tokens_per_second: u64,
    pub failure_domain: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaPlacement {
    pub selected: Vec<Hash32>,
    pub cross_replica_bytes_per_token: u64,
    pub aggregate_tokens_per_second: u64,
}

/// Places whole-job replicas by locality and then price. It never constructs
/// a cross-replica token channel; each selected hearth owns a complete job.
pub fn place_replicas(
    candidates: &[ReplicaCandidate],
    replicas: usize,
    minimum_availability_bps: u16,
) -> Result<ReplicaPlacement, FederationError> {
    if replicas == 0 {
        return Err(FederationError::NoCapacity);
    }
    let mut eligible = candidates
        .iter()
        .filter(|candidate| candidate.availability_bps >= minimum_availability_bps)
        .collect::<Vec<_>>();
    eligible.sort_by_key(|candidate| {
        (
            candidate.locality_rtt_ms,
            candidate.price_per_million_tokens,
            candidate.hearth_id,
        )
    });
    let mut domains = BTreeSet::new();
    let selected = eligible
        .into_iter()
        .filter(|candidate| domains.insert(candidate.failure_domain))
        .take(replicas)
        .collect::<Vec<_>>();
    if selected.len() != replicas {
        return Err(FederationError::InsufficientFailureDomains);
    }
    let aggregate_tokens_per_second = selected.iter().try_fold(0u64, |sum, candidate| {
        sum.checked_add(candidate.capacity_tokens_per_second)
            .ok_or(FederationError::ArithmeticOverflow)
    })?;
    Ok(ReplicaPlacement {
        selected: selected
            .iter()
            .map(|candidate| candidate.hearth_id)
            .collect(),
        cross_replica_bytes_per_token: 0,
        aggregate_tokens_per_second,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModelClass {
    B8,
    B70,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WanCell {
    pub model: ModelClass,
    pub hops: u8,
    pub rtt_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyDecomposition {
    pub compute_us: u64,
    pub serialization_us_per_hop: u64,
    pub rtt_wait_us: u64,
    pub queue_us: u64,
}

impl LatencyDecomposition {
    pub fn token_latency_us(self, hops: u8) -> Result<u64, FederationError> {
        self.compute_us
            .checked_add(self.queue_us)
            .and_then(|base| {
                base.checked_add(
                    u64::from(hops).checked_mul(
                        self.rtt_wait_us
                            .checked_add(self.serialization_us_per_hop)?,
                    )?,
                )
            })
            .ok_or(FederationError::ArithmeticOverflow)
    }

    pub fn tokens_per_second_milli(self, hops: u8) -> Result<u64, FederationError> {
        let latency = self.token_latency_us(hops)?;
        if latency == 0 {
            return Err(FederationError::ArithmeticOverflow);
        }
        Ok(1_000_000_000 / latency)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanAutopsy {
    pub modeled_milli_tokens_per_second: BTreeMap<WanCell, u64>,
    pub measured_milli_tokens_per_second: BTreeMap<WanCell, u64>,
    pub public_artifact_root: Option<Hash32>,
}

impl WanAutopsy {
    pub fn evaluate(&self) -> Result<WanVerdict, FederationError> {
        if self.modeled_milli_tokens_per_second.is_empty()
            || self
                .modeled_milli_tokens_per_second
                .keys()
                .collect::<BTreeSet<_>>()
                != self
                    .measured_milli_tokens_per_second
                    .keys()
                    .collect::<BTreeSet<_>>()
        {
            return Err(FederationError::IncompleteAutopsy);
        }
        let mut refutation = false;
        for (cell, modeled) in &self.modeled_milli_tokens_per_second {
            let measured = self.measured_milli_tokens_per_second[cell];
            let lower = modeled.saturating_mul(70) / 100;
            let upper = modeled.saturating_mul(130).div_ceil(100);
            if measured < lower || measured > upper {
                return Ok(WanVerdict::OutsideModeledBand);
            }
            if cell.hops >= 2 && cell.rtt_ms >= 50 && measured >= 10_000 {
                refutation = true;
            }
        }
        if refutation {
            return Ok(WanVerdict::RefutedRelaxProhibition);
        }
        if self.public_artifact_root.is_none() {
            return Ok(WanVerdict::LocalOnlyPublicationBlocked);
        }
        Ok(WanVerdict::ConfirmedPublishedNegative)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanVerdict {
    ConfirmedPublishedNegative,
    LocalOnlyPublicationBlocked,
    OutsideModeledBand,
    RefutedRelaxProhibition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalingObservation {
    pub hearths: u32,
    pub single_hearth_tokens_per_second: u64,
    pub aggregate_tokens_per_second: u64,
    pub coordination_bytes_per_token: u64,
}

impl ScalingObservation {
    #[must_use]
    pub fn at_least_eighty_percent_linear(self) -> bool {
        let linear = u128::from(self.hearths)
            .saturating_mul(u128::from(self.single_hearth_tokens_per_second));
        u128::from(self.aggregate_tokens_per_second).saturating_mul(10) >= linear.saturating_mul(8)
            && self.coordination_bytes_per_token == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationError {
    NoCapacity,
    InsufficientFailureDomains,
    ArithmeticOverflow,
    IncompleteAutopsy,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    #[test]
    fn replica_federation_is_locality_routed_and_token_independent() {
        let candidates = [
            ReplicaCandidate {
                hearth_id: h(1),
                locality_rtt_ms: 30,
                availability_bps: 9_000,
                price_per_million_tokens: 5,
                capacity_tokens_per_second: 34,
                failure_domain: h(11),
            },
            ReplicaCandidate {
                hearth_id: h(2),
                locality_rtt_ms: 10,
                availability_bps: 9_000,
                price_per_million_tokens: 9,
                capacity_tokens_per_second: 34,
                failure_domain: h(12),
            },
            ReplicaCandidate {
                hearth_id: h(3),
                locality_rtt_ms: 20,
                availability_bps: 8_000,
                price_per_million_tokens: 2,
                capacity_tokens_per_second: 34,
                failure_domain: h(13),
            },
        ];
        let placement = place_replicas(&candidates, 2, 8_500).unwrap();
        assert_eq!(placement.selected, vec![h(2), h(1)]);
        assert_eq!(placement.cross_replica_bytes_per_token, 0);
        assert_eq!(placement.aggregate_tokens_per_second, 68);
    }

    #[test]
    fn autopsy_requires_real_publication_even_when_local_model_matches() {
        let cell = WanCell {
            model: ModelClass::B8,
            hops: 2,
            rtt_ms: 50,
        };
        let autopsy = WanAutopsy {
            modeled_milli_tokens_per_second: BTreeMap::from([(cell, 15_500)]),
            measured_milli_tokens_per_second: BTreeMap::from([(cell, 15_000)]),
            public_artifact_root: None,
        };
        assert_eq!(
            autopsy.evaluate().unwrap(),
            WanVerdict::RefutedRelaxProhibition
        );
        let non_refuting = WanAutopsy {
            modeled_milli_tokens_per_second: BTreeMap::from([(cell, 8_700)]),
            measured_milli_tokens_per_second: BTreeMap::from([(cell, 8_600)]),
            public_artifact_root: None,
        };
        assert_eq!(
            non_refuting.evaluate().unwrap(),
            WanVerdict::LocalOnlyPublicationBlocked
        );
    }

    #[test]
    fn scaling_threshold_is_exact_integer_arithmetic() {
        assert!(ScalingObservation {
            hearths: 1_000,
            single_hearth_tokens_per_second: 34,
            aggregate_tokens_per_second: 27_200,
            coordination_bytes_per_token: 0,
        }
        .at_least_eighty_percent_linear());
        assert!(!ScalingObservation {
            hearths: 1_000,
            single_hearth_tokens_per_second: 34,
            aggregate_tokens_per_second: 27_199,
            coordination_bytes_per_token: 0,
        }
        .at_least_eighty_percent_linear());
    }
}
