//! Application-only Swarm routing and payments. Swarm influence is bond-only:
//! neither work, payment, nor diversity changes proposal or finality weight.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub const LIFECYCLE: &str = "EXPERIMENTAL";
pub const RESULT: &str = "SHADOW_ONLY";
pub const INFLUENCE_MODE: &str = "BOND_ONLY";
pub const SLASHABLE: bool = false;
pub const MAX_CONCENTRATION_BPS: u16 = 3_333;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentState {
    Proposed,
    Escrowed,
    Earned,
    Refunded,
    Paid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationPayment {
    pub payment_id: Hash32,
    pub job_id: Hash32,
    pub payer: Hash32,
    pub worker: Hash32,
    pub amount: u128,
    pub opportunity_cost: u128,
    pub state: PaymentState,
}
impl ApplicationPayment {
    pub fn fund(&mut self) -> Result<(), SwarmError> {
        if self.state != PaymentState::Proposed || self.amount == 0 {
            return Err(SwarmError::InvalidTransition);
        }
        self.state = PaymentState::Escrowed;
        Ok(())
    }
    pub fn earn(&mut self, objective_receipt: bool) -> Result<(), SwarmError> {
        if self.state != PaymentState::Escrowed || !objective_receipt {
            return Err(SwarmError::InvalidTransition);
        }
        self.state = PaymentState::Earned;
        Ok(())
    }
    pub fn settle(&mut self) -> Result<(), SwarmError> {
        if self.state != PaymentState::Earned {
            return Err(SwarmError::InvalidTransition);
        }
        self.state = PaymentState::Paid;
        Ok(())
    }
    pub fn refund(&mut self) -> Result<(), SwarmError> {
        if self.state != PaymentState::Escrowed {
            return Err(SwarmError::InvalidTransition);
        }
        self.state = PaymentState::Refunded;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerQuote {
    pub worker: Hash32,
    pub operator: Hash32,
    pub control_cluster: Hash32,
    pub hardware_family: Hash32,
    pub price: u128,
    pub opportunity_cost: u128,
    pub capacity: u64,
    pub bonded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePlan {
    pub workers: Vec<Hash32>,
    pub total_price: u128,
}

/// Selects cheapest eligible quotes while taking at most one worker from each
/// declared control cluster. Ties are stable by worker id.
pub fn route(
    mut quotes: Vec<WorkerQuote>,
    required_capacity: u64,
    budget: u128,
) -> Result<RoutePlan, SwarmError> {
    quotes.sort_by_key(|q| (q.price, q.worker));
    let mut clusters = BTreeSet::new();
    let mut workers = Vec::new();
    let mut capacity = 0_u64;
    let mut total = 0_u128;
    for quote in quotes {
        if !quote.bonded
            || quote.price < quote.opportunity_cost
            || !clusters.insert(quote.control_cluster)
        {
            continue;
        }
        let next_total = total.checked_add(quote.price).ok_or(SwarmError::Overflow)?;
        if next_total > budget {
            continue;
        }
        total = next_total;
        capacity = capacity
            .checked_add(quote.capacity)
            .ok_or(SwarmError::Overflow)?;
        workers.push(quote.worker);
        if capacity >= required_capacity {
            return Ok(RoutePlan {
                workers,
                total_price: total,
            });
        }
    }
    Err(SwarmError::InsufficientRoute)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcentrationReport {
    pub total: u64,
    pub largest_cluster_bps: u16,
    pub hhi_millionths: u32,
    pub manufactured_diversity: bool,
    pub demand_covers_opportunity_cost: bool,
}

pub fn concentration(
    assignments: &[(Hash32, u64)],
    manufactured_links: &BTreeSet<(Hash32, Hash32)>,
    demand_covers_opportunity_cost: bool,
) -> Result<ConcentrationReport, SwarmError> {
    let mut by_cluster: BTreeMap<Hash32, u64> = BTreeMap::new();
    let mut total = 0_u64;
    for (cluster, work) in assignments {
        total = total.checked_add(*work).ok_or(SwarmError::Overflow)?;
        let entry = by_cluster.entry(*cluster).or_default();
        *entry = entry.checked_add(*work).ok_or(SwarmError::Overflow)?;
    }
    if total == 0 {
        return Err(SwarmError::EmptyTelemetry);
    }
    let largest = by_cluster.values().copied().max().unwrap_or(0);
    let largest_scaled = u128::from(largest)
        .checked_mul(10_000)
        .ok_or(SwarmError::Overflow)?
        .checked_div(u128::from(total))
        .ok_or(SwarmError::Overflow)?;
    let largest_bps = u16::try_from(largest_scaled).map_err(|_| SwarmError::Overflow)?;
    let mut hhi = 0_u128;
    for value in by_cluster.values() {
        let share = u128::from(*value)
            .checked_mul(1_000_000)
            .ok_or(SwarmError::Overflow)?
            .checked_div(u128::from(total))
            .ok_or(SwarmError::Overflow)?;
        let square = share.checked_mul(share).ok_or(SwarmError::Overflow)?;
        hhi = hhi
            .checked_add(square.checked_div(1_000_000).ok_or(SwarmError::Overflow)?)
            .ok_or(SwarmError::Overflow)?;
    }
    Ok(ConcentrationReport {
        total,
        largest_cluster_bps: largest_bps,
        hhi_millionths: u32::try_from(hhi).map_err(|_| SwarmError::Overflow)?,
        manufactured_diversity: !manufactured_links.is_empty(),
        demand_covers_opportunity_cost,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerVerdict {
    HealthyBondOnly,
    ConcentrationBreach,
    ManufacturedDiversity,
    DemandFailure,
}
pub fn control(report: &ConcentrationReport) -> ControllerVerdict {
    if report.manufactured_diversity {
        ControllerVerdict::ManufacturedDiversity
    } else if !report.demand_covers_opportunity_cost {
        ControllerVerdict::DemandFailure
    } else if report.largest_cluster_bps >= MAX_CONCENTRATION_BPS {
        ControllerVerdict::ConcentrationBreach
    } else {
        ControllerVerdict::HealthyBondOnly
    }
}
#[must_use]
pub const fn proposal_weight(_report: &ConcentrationReport) -> u64 {
    0
}
#[must_use]
pub const fn finality_weight(_report: &ConcentrationReport) -> u64 {
    0
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SwarmError {
    #[error("invalid payment lifecycle transition")]
    InvalidTransition,
    #[error("insufficient diverse bonded route")]
    InsufficientRoute,
    #[error("empty concentration telemetry")]
    EmptyTelemetry,
    #[error("integer overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    fn h(v: u8) -> Hash32 {
        [v; 32]
    }
    fn quote(worker: u8, cluster: u8, price: u128) -> WorkerQuote {
        WorkerQuote {
            worker: h(worker),
            operator: h(worker),
            control_cluster: h(cluster),
            hardware_family: h(worker),
            price,
            opportunity_cost: 5,
            capacity: 10,
            bonded: true,
        }
    }
    #[test]
    fn lifecycle_is_exact_and_no_double_settle() {
        let mut p = ApplicationPayment {
            payment_id: h(1),
            job_id: h(2),
            payer: h(3),
            worker: h(4),
            amount: 9,
            opportunity_cost: 5,
            state: PaymentState::Proposed,
        };
        p.fund().unwrap();
        p.earn(true).unwrap();
        p.settle().unwrap();
        assert_eq!(p.settle(), Err(SwarmError::InvalidTransition));
        assert_eq!(
            (LIFECYCLE, RESULT, INFLUENCE_MODE),
            ("EXPERIMENTAL", "SHADOW_ONLY", "BOND_ONLY")
        );
    }
    #[test]
    fn route_enforces_bond_cost_budget_and_cluster_quotient() {
        let mut bad = quote(1, 1, 2);
        bad.bonded = false;
        let plan = route(
            vec![bad, quote(2, 1, 5), quote(3, 1, 6), quote(4, 2, 7)],
            20,
            12,
        )
        .unwrap();
        assert_eq!(plan.workers, vec![h(2), h(4)]);
        assert_eq!(plan.total_price, 12);
    }
    #[test]
    fn concentration_and_falsifiers_never_create_weight() {
        let r = concentration(
            &[(h(1), 34), (h(2), 33), (h(3), 33)],
            &BTreeSet::new(),
            true,
        )
        .unwrap();
        assert_eq!(control(&r), ControllerVerdict::ConcentrationBreach);
        assert_eq!((proposal_weight(&r), finality_weight(&r)), (0, 0));
        let r2 = concentration(&[(h(1), 1)], &BTreeSet::from([(h(1), h(2))]), true).unwrap();
        assert_eq!(control(&r2), ControllerVerdict::ManufacturedDiversity);
    }
    #[test]
    fn payment_below_opportunity_cost_is_not_routed() {
        assert_eq!(
            route(vec![quote(1, 1, 4)], 1, 10),
            Err(SwarmError::InsufficientRoute)
        );
    }
    #[test]
    fn combined_vector_gate_has_at_least_35_unique_cases() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/experimental-lanes-v1.json"
        ))
        .unwrap();
        let cases = document["cases"].as_array().unwrap();
        assert!(cases.len() >= 35);
        let names = cases
            .iter()
            .map(|case| case["name"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), cases.len());
        let lanes = cases
            .iter()
            .map(|case| case["lane"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        for required in [
            "A-CLASS-GATE.v2",
            "A-REFLEX",
            "E-ORACLE-01",
            "E-GRAD-01",
            "I-PENTAGON",
            "NOOS-CHORUS",
            "NOOS-SWARM",
            "FORESIGHT",
        ] {
            assert!(lanes.contains(required));
        }
    }
}
