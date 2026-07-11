//! Deterministic shadow economics for the frozen ch04 economics claims.
//!
//! These types deliberately cannot change proposal weight, finality weight, or
//! issuance. They provide executable local precursors for demand
//! classification, bounded Omega credit, Duplex conservation, and Proofpower
//! maturity/accounting while all production controls remain hard-zero.

use crate::{DemandClassification, Hash32};
use std::collections::{BTreeMap, BTreeSet};

pub const PPM: u32 = 1_000_000;
pub const MAX_OMEGA_PPM: u32 = 100_000;
pub const MAX_PROOFPOWER_PPM: u32 = 200_000;
pub const MIN_PROOFPOWER_MATURITY_DAYS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlEvidence {
    Independent,
    CommonControl,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingEvidence {
    ExternalNoCircularDetected,
    SubsidizedOrRebated,
    Circular,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionEvidence {
    RequesterAccepted,
    DisputeCompleted,
    Pending,
}

/// Challengeable evidence only. `Independent` is conservative public-evidence
/// classification, never a claim about hidden beneficial ownership or quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandEvidence {
    pub on_chain_escrow: bool,
    pub delivered: bool,
    pub requester_worker_control: ControlEvidence,
    pub requester_evaluator_control: ControlEvidence,
    pub completion: CompletionEvidence,
    pub funding: FundingEvidence,
}

impl DemandEvidence {
    #[must_use]
    pub fn classify(self) -> DemandClassification {
        if self.requester_worker_control == ControlEvidence::CommonControl
            || self.requester_evaluator_control == ControlEvidence::CommonControl
            || self.funding == FundingEvidence::Circular
        {
            return DemandClassification::Related;
        }
        if self.funding == FundingEvidence::SubsidizedOrRebated {
            return DemandClassification::Subsidized;
        }
        if !self.on_chain_escrow
            || !self.delivered
            || self.completion == CompletionEvidence::Pending
            || self.requester_worker_control != ControlEvidence::Independent
            || self.requester_evaluator_control != ControlEvidence::Independent
            || self.funding != FundingEvidence::ExternalNoCircularDetected
        {
            return DemandClassification::Unknown;
        }
        DemandClassification::Independent
    }

    #[must_use]
    pub fn qualifies(self) -> bool {
        self.classify() == DemandClassification::Independent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandObservation {
    pub day: u64,
    pub credited_compute_value: u128,
    pub requester_cluster: Hash32,
    pub operator_cluster: Hash32,
    pub hardware_class: u32,
    pub evidence: DemandEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandWindowReport {
    pub total_value: u128,
    pub qualified_value: u128,
    pub requester_clusters: usize,
    pub operator_clusters: usize,
    pub hardware_classes: usize,
    pub largest_cluster_value: u128,
    pub public_useful_threshold_met: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicsError {
    InvalidPolicy,
    Overflow,
    DuplicateHeight,
    DuplicateReceipt,
    InvalidReceiptCommitment,
}

pub fn evaluate_demand_window(
    end_day: u64,
    observations: &[DemandObservation],
) -> Result<DemandWindowReport, EconomicsError> {
    let first_day = end_day.saturating_sub(29);
    let mut total = 0u128;
    let mut qualified = 0u128;
    let mut requesters = BTreeSet::new();
    let mut operators = BTreeSet::new();
    let mut hardware = BTreeSet::new();
    let mut cluster_value = BTreeMap::<Hash32, u128>::new();
    for observation in observations
        .iter()
        .filter(|o| o.day >= first_day && o.day <= end_day)
    {
        total = total
            .checked_add(observation.credited_compute_value)
            .ok_or(EconomicsError::Overflow)?;
        if observation.evidence.qualifies() {
            qualified = qualified
                .checked_add(observation.credited_compute_value)
                .ok_or(EconomicsError::Overflow)?;
            requesters.insert(observation.requester_cluster);
            operators.insert(observation.operator_cluster);
            hardware.insert(observation.hardware_class);
            for cluster in [observation.requester_cluster, observation.operator_cluster] {
                let prior = cluster_value.get(&cluster).copied().unwrap_or(0);
                cluster_value.insert(
                    cluster,
                    prior
                        .checked_add(observation.credited_compute_value)
                        .ok_or(EconomicsError::Overflow)?,
                );
            }
        }
    }
    let largest = cluster_value.values().copied().max().unwrap_or(0);
    let threshold = total > 0
        && at_least_percent(qualified, total, 80)?
        && requesters.len() >= 10
        && operators.len() >= 20
        && hardware.len() >= 4
        && at_most_percent(largest, qualified, 20)?;
    Ok(DemandWindowReport {
        total_value: total,
        qualified_value: qualified,
        requester_clusters: requesters.len(),
        operator_clusters: operators.len(),
        hardware_classes: hardware.len(),
        largest_cluster_value: largest,
        public_useful_threshold_met: threshold,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmegaPolicy {
    pub cap_ppm_of_total_weight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmegaZeroReason {
    NonqualifyingDemand,
    MissingDeliverable,
    StaleCalibration,
    RolledBackClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmegaQuote {
    pub counterfactual_credit: u128,
    pub production_credit: u128,
    pub zero_reason: Option<OmegaZeroReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmegaRequest {
    pub class_id: u32,
    pub ground_weight: u128,
    pub measured_work: u128,
    pub deliverable_materialized: bool,
    pub calibration_valid_through: u64,
    pub height: u64,
    pub demand: DemandEvidence,
}

#[derive(Debug, Clone)]
pub struct OmegaShadowBook {
    policy: OmegaPolicy,
    rolled_back_classes: BTreeSet<u32>,
}

impl OmegaShadowBook {
    pub fn new(policy: OmegaPolicy) -> Result<Self, EconomicsError> {
        if policy.cap_ppm_of_total_weight > MAX_OMEGA_PPM {
            return Err(EconomicsError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            rolled_back_classes: BTreeSet::new(),
        })
    }

    pub fn rollback_class(&mut self, class_id: u32) {
        self.rolled_back_classes.insert(class_id);
    }

    pub fn quote(&self, request: OmegaRequest) -> Result<OmegaQuote, EconomicsError> {
        let reason = if self.rolled_back_classes.contains(&request.class_id) {
            Some(OmegaZeroReason::RolledBackClass)
        } else if !request.deliverable_materialized {
            Some(OmegaZeroReason::MissingDeliverable)
        } else if request.height > request.calibration_valid_through {
            Some(OmegaZeroReason::StaleCalibration)
        } else if !request.demand.qualifies() {
            Some(OmegaZeroReason::NonqualifyingDemand)
        } else {
            None
        };
        let cap = weight_share_cap(request.ground_weight, self.policy.cap_ppm_of_total_weight)?;
        Ok(OmegaQuote {
            counterfactual_credit: if reason.is_none() {
                request.measured_work.min(cap)
            } else {
                0
            },
            production_credit: 0,
            zero_reason: reason,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplexPolicy {
    pub reallocation_cap_ppm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplexAllocation {
    pub scheduled: u128,
    pub counterfactual_base: u128,
    pub counterfactual_work: u128,
    pub production_base: u128,
    pub production_work: u128,
}

#[derive(Debug, Clone)]
pub struct DuplexShadowBook {
    policy: DuplexPolicy,
    heights: BTreeSet<u64>,
    receipts: BTreeSet<Hash32>,
    rolled_back: bool,
}

impl DuplexShadowBook {
    pub fn new(policy: DuplexPolicy) -> Result<Self, EconomicsError> {
        if policy.reallocation_cap_ppm > PPM {
            return Err(EconomicsError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            heights: BTreeSet::new(),
            receipts: BTreeSet::new(),
            rolled_back: false,
        })
    }

    pub fn rollback(&mut self) {
        self.rolled_back = true;
    }

    pub fn allocate(
        &mut self,
        height: u64,
        receipt_id: Hash32,
        scheduled: u128,
        requested: u128,
        demand: DemandEvidence,
    ) -> Result<DuplexAllocation, EconomicsError> {
        if self.heights.contains(&height) {
            return Err(EconomicsError::DuplicateHeight);
        }
        if self.receipts.contains(&receipt_id) {
            return Err(EconomicsError::DuplicateReceipt);
        }
        let cap = mul_div_floor(scheduled, self.policy.reallocation_cap_ppm, PPM)?;
        let work = if !self.rolled_back && demand.qualifies() {
            requested.min(cap)
        } else {
            0
        };
        let base = scheduled
            .checked_sub(work)
            .ok_or(EconomicsError::Overflow)?;
        self.heights.insert(height);
        self.receipts.insert(receipt_id);
        Ok(DuplexAllocation {
            scheduled,
            counterfactual_base: base,
            counterfactual_work: work,
            production_base: scheduled,
            production_work: 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofpowerPolicy {
    pub cap_ppm_of_effective_ring: u32,
    pub cluster_weight_limit_ppm: u32,
    pub concentration_coefficient_ppm: u32,
    pub maturity_days: u64,
    pub linear_decay_days: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofpowerReceipt {
    pub receipt_id: Hash32,
    pub control_cluster: Hash32,
    pub funded_value: u128,
    pub settled_day: u64,
    pub proposal_credit_day: Option<u64>,
    pub demand: DemandEvidence,
    pub commitment: Hash32,
}

impl ProofpowerReceipt {
    #[must_use]
    pub fn seal(
        receipt_id: Hash32,
        control_cluster: Hash32,
        funded_value: u128,
        settled_day: u64,
        proposal_credit_day: Option<u64>,
        demand: DemandEvidence,
    ) -> Self {
        let mut receipt = Self {
            receipt_id,
            control_cluster,
            funded_value,
            settled_day,
            proposal_credit_day,
            demand,
            commitment: [0; 32],
        };
        receipt.commitment = receipt_commitment(&receipt);
        receipt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofpowerMeasurement {
    pub eligible_population: usize,
    pub beta_active: bool,
    pub counterfactual_bonus_by_cluster: BTreeMap<Hash32, u128>,
    pub production_bonus_by_cluster: BTreeMap<Hash32, u128>,
    pub production_effective_ring: BTreeMap<Hash32, u128>,
    pub rejected_immature_or_decayed: usize,
    pub rejected_nonindependent: usize,
    pub rejected_proposal_overlap: usize,
}

#[derive(Debug, Clone)]
pub struct ProofpowerShadowBook {
    policy: ProofpowerPolicy,
    receipts: BTreeMap<Hash32, ProofpowerReceipt>,
    rolled_back: bool,
}

impl ProofpowerShadowBook {
    pub fn new(policy: ProofpowerPolicy) -> Result<Self, EconomicsError> {
        if policy.cap_ppm_of_effective_ring > MAX_PROOFPOWER_PPM
            || policy.cluster_weight_limit_ppm >= 333_334
            || policy.concentration_coefficient_ppm == 0
            || policy.concentration_coefficient_ppm > PPM
            || policy.maturity_days < MIN_PROOFPOWER_MATURITY_DAYS
            || policy.linear_decay_days == 0
        {
            return Err(EconomicsError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            receipts: BTreeMap::new(),
            rolled_back: false,
        })
    }

    pub fn admit(&mut self, receipt: ProofpowerReceipt) -> Result<(), EconomicsError> {
        if receipt.commitment != receipt_commitment(&receipt) {
            return Err(EconomicsError::InvalidReceiptCommitment);
        }
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err(EconomicsError::DuplicateReceipt);
        }
        self.receipts.insert(receipt.receipt_id, receipt);
        Ok(())
    }

    pub fn rollback(&mut self) {
        self.rolled_back = true;
    }

    pub fn measure(
        &self,
        day: u64,
        raw_ring: &BTreeMap<Hash32, u128>,
    ) -> Result<ProofpowerMeasurement, EconomicsError> {
        let raw_total = sum_values(raw_ring.values().copied())?;
        let mut candidates = BTreeMap::<Hash32, u128>::new();
        let mut eligible_clusters = BTreeSet::new();
        let mut immature = 0usize;
        let mut nonindependent = 0usize;
        let mut overlap = 0usize;
        for receipt in self.receipts.values() {
            if !receipt.demand.qualifies() {
                nonindependent = nonindependent
                    .checked_add(1)
                    .ok_or(EconomicsError::Overflow)?;
                continue;
            }
            let age = day.saturating_sub(receipt.settled_day);
            if day < receipt.settled_day || age < self.policy.maturity_days {
                immature = immature.checked_add(1).ok_or(EconomicsError::Overflow)?;
                continue;
            }
            if receipt.proposal_credit_day.is_some_and(|proposal_day| {
                proposal_day <= day && day.saturating_sub(proposal_day) < self.policy.maturity_days
            }) {
                overlap = overlap.checked_add(1).ok_or(EconomicsError::Overflow)?;
                continue;
            }
            let decay_age = age
                .checked_sub(self.policy.maturity_days)
                .ok_or(EconomicsError::Overflow)?;
            if decay_age >= self.policy.linear_decay_days {
                immature = immature.checked_add(1).ok_or(EconomicsError::Overflow)?;
                continue;
            }
            let remaining = self
                .policy
                .linear_decay_days
                .checked_sub(decay_age)
                .ok_or(EconomicsError::Overflow)?;
            let value = mul_div_floor_u64(
                receipt.funded_value,
                remaining,
                self.policy.linear_decay_days,
            )?;
            if value == 0 {
                immature = immature.checked_add(1).ok_or(EconomicsError::Overflow)?;
                continue;
            }
            eligible_clusters.insert(receipt.control_cluster);
            let prior = candidates
                .get(&receipt.control_cluster)
                .copied()
                .unwrap_or(0);
            candidates.insert(
                receipt.control_cluster,
                prior.checked_add(value).ok_or(EconomicsError::Overflow)?,
            );
        }

        let population = eligible_clusters.len();
        let population_product = u128::try_from(population)
            .map_err(|_| EconomicsError::Overflow)?
            .checked_mul(u128::from(self.policy.concentration_coefficient_ppm))
            .ok_or(EconomicsError::Overflow)?;
        let population_allows_beta = population_product > u128::from(PPM);
        let mut beta = !self.rolled_back && population_allows_beta && raw_total > 0;
        let cap = weight_share_cap(raw_total, self.policy.cap_ppm_of_effective_ring)?;
        let mut bonuses = BTreeMap::new();
        let mut remaining_cap = cap;
        if beta {
            for (cluster, candidate) in candidates {
                let allocation = candidate.min(remaining_cap);
                if allocation > 0 {
                    bonuses.insert(cluster, allocation);
                    remaining_cap = remaining_cap
                        .checked_sub(allocation)
                        .ok_or(EconomicsError::Overflow)?;
                }
            }
            let bonus_total = sum_values(bonuses.values().copied())?;
            let effective_total = raw_total
                .checked_add(bonus_total)
                .ok_or(EconomicsError::Overflow)?;
            for cluster in raw_ring.keys().chain(bonuses.keys()) {
                let effective = raw_ring
                    .get(cluster)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(bonuses.get(cluster).copied().unwrap_or(0))
                    .ok_or(EconomicsError::Overflow)?;
                if !below_fraction_ppm(
                    effective,
                    effective_total,
                    self.policy.cluster_weight_limit_ppm,
                )? {
                    beta = false;
                    bonuses.clear();
                    break;
                }
            }
        }

        Ok(ProofpowerMeasurement {
            eligible_population: population,
            beta_active: beta,
            counterfactual_bonus_by_cluster: bonuses,
            production_bonus_by_cluster: BTreeMap::new(),
            production_effective_ring: raw_ring.clone(),
            rejected_immature_or_decayed: immature,
            rejected_nonindependent: nonindependent,
            rejected_proposal_overlap: overlap,
        })
    }
}

fn receipt_commitment(receipt: &ProofpowerReceipt) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/LOOM/PROOFPOWER-SHADOW/V1");
    hasher.update(&receipt.receipt_id);
    hasher.update(&receipt.control_cluster);
    hasher.update(&receipt.funded_value.to_le_bytes());
    hasher.update(&receipt.settled_day.to_le_bytes());
    match receipt.proposal_credit_day {
        Some(day) => {
            hasher.update(&[1]);
            hasher.update(&day.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&[receipt.demand.on_chain_escrow.into()]);
    hasher.update(&[receipt.demand.delivered.into()]);
    hasher.update(&[control_tag(receipt.demand.requester_worker_control)]);
    hasher.update(&[control_tag(receipt.demand.requester_evaluator_control)]);
    hasher.update(&[completion_tag(receipt.demand.completion)]);
    hasher.update(&[funding_tag(receipt.demand.funding)]);
    *hasher.finalize().as_bytes()
}

const fn control_tag(value: ControlEvidence) -> u8 {
    match value {
        ControlEvidence::Independent => 0,
        ControlEvidence::CommonControl => 1,
        ControlEvidence::Unknown => 2,
    }
}

const fn completion_tag(value: CompletionEvidence) -> u8 {
    match value {
        CompletionEvidence::RequesterAccepted => 0,
        CompletionEvidence::DisputeCompleted => 1,
        CompletionEvidence::Pending => 2,
    }
}

const fn funding_tag(value: FundingEvidence) -> u8 {
    match value {
        FundingEvidence::ExternalNoCircularDetected => 0,
        FundingEvidence::SubsidizedOrRebated => 1,
        FundingEvidence::Circular => 2,
        FundingEvidence::Unknown => 3,
    }
}

fn weight_share_cap(raw: u128, share_ppm: u32) -> Result<u128, EconomicsError> {
    if share_ppm >= PPM {
        return Err(EconomicsError::InvalidPolicy);
    }
    let complement = PPM
        .checked_sub(share_ppm)
        .ok_or(EconomicsError::InvalidPolicy)?;
    mul_div_floor(raw, share_ppm, complement)
}

fn mul_div_floor(value: u128, numerator: u32, denominator: u32) -> Result<u128, EconomicsError> {
    mul_div_floor_u128(value, u128::from(numerator), u128::from(denominator))
}

fn mul_div_floor_u64(
    value: u128,
    numerator: u64,
    denominator: u64,
) -> Result<u128, EconomicsError> {
    mul_div_floor_u128(value, u128::from(numerator), u128::from(denominator))
}

fn mul_div_floor_u128(
    value: u128,
    numerator: u128,
    denominator: u128,
) -> Result<u128, EconomicsError> {
    if denominator == 0 {
        return Err(EconomicsError::InvalidPolicy);
    }
    let quotient = value
        .checked_div(denominator)
        .ok_or(EconomicsError::Overflow)?;
    let remainder = value
        .checked_rem(denominator)
        .ok_or(EconomicsError::Overflow)?;
    quotient
        .checked_mul(numerator)
        .and_then(|whole| {
            remainder
                .checked_mul(numerator)
                .and_then(|part| part.checked_div(denominator))
                .and_then(|part| whole.checked_add(part))
        })
        .ok_or(EconomicsError::Overflow)
}

fn at_least_percent(part: u128, total: u128, percent: u32) -> Result<bool, EconomicsError> {
    if percent > 100 {
        return Err(EconomicsError::InvalidPolicy);
    }
    let floor = mul_div_floor(total, percent, 100)?;
    let remainder = total.checked_rem(100).ok_or(EconomicsError::Overflow)?;
    let exact = remainder == 0
        || remainder
            .checked_mul(u128::from(percent))
            .and_then(|value| value.checked_rem(100))
            .ok_or(EconomicsError::Overflow)?
            == 0;
    let required = if exact {
        floor
    } else {
        floor.checked_add(1).ok_or(EconomicsError::Overflow)?
    };
    Ok(part >= required)
}

fn at_most_percent(part: u128, total: u128, percent: u32) -> Result<bool, EconomicsError> {
    Ok(part <= mul_div_floor(total, percent, 100)?)
}

fn below_fraction_ppm(part: u128, total: u128, ppm: u32) -> Result<bool, EconomicsError> {
    Ok(part <= mul_div_floor(total, ppm, PPM)?)
}

fn sum_values(values: impl IntoIterator<Item = u128>) -> Result<u128, EconomicsError> {
    values.into_iter().try_fold(0u128, |sum, value| {
        sum.checked_add(value).ok_or(EconomicsError::Overflow)
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn independent() -> DemandEvidence {
        DemandEvidence {
            on_chain_escrow: true,
            delivered: true,
            requester_worker_control: ControlEvidence::Independent,
            requester_evaluator_control: ControlEvidence::Independent,
            completion: CompletionEvidence::RequesterAccepted,
            funding: FundingEvidence::ExternalNoCircularDetected,
        }
    }

    #[test]
    fn demand_predicate_truth_table_is_conservative() {
        let controls = [
            ControlEvidence::Independent,
            ControlEvidence::CommonControl,
            ControlEvidence::Unknown,
        ];
        let completions = [
            CompletionEvidence::RequesterAccepted,
            CompletionEvidence::DisputeCompleted,
            CompletionEvidence::Pending,
        ];
        let funding = [
            FundingEvidence::ExternalNoCircularDetected,
            FundingEvidence::SubsidizedOrRebated,
            FundingEvidence::Circular,
            FundingEvidence::Unknown,
        ];
        for escrow in [false, true] {
            for delivered in [false, true] {
                for worker in controls {
                    for evaluator in controls {
                        for completion in completions {
                            for funding in funding {
                                let evidence = DemandEvidence {
                                    on_chain_escrow: escrow,
                                    delivered,
                                    requester_worker_control: worker,
                                    requester_evaluator_control: evaluator,
                                    completion,
                                    funding,
                                };
                                let expected = escrow
                                    && delivered
                                    && worker == ControlEvidence::Independent
                                    && evaluator == ControlEvidence::Independent
                                    && completion != CompletionEvidence::Pending
                                    && funding == FundingEvidence::ExternalNoCircularDetected;
                                assert_eq!(evidence.qualifies(), expected, "{evidence:?}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn wash_mutations_never_classify_independent() {
        let mut circular = independent();
        circular.funding = FundingEvidence::Circular;
        assert_eq!(circular.classify(), DemandClassification::Related);
        let mut rebate = independent();
        rebate.funding = FundingEvidence::SubsidizedOrRebated;
        assert_eq!(rebate.classify(), DemandClassification::Subsidized);
        let mut shell = independent();
        shell.requester_worker_control = ControlEvidence::Unknown;
        assert_eq!(shell.classify(), DemandClassification::Unknown);
        let mut common = independent();
        common.requester_evaluator_control = ControlEvidence::CommonControl;
        assert_eq!(common.classify(), DemandClassification::Related);
    }

    #[test]
    fn demand_window_uses_exact_thresholds() {
        let mut observations = Vec::new();
        for i in 0..20u8 {
            observations.push(DemandObservation {
                day: 30,
                credited_compute_value: 4,
                requester_cluster: h((i % 10) + 1),
                operator_cluster: h(i + 40),
                hardware_class: u32::from(i % 4),
                evidence: independent(),
            });
        }
        observations.push(DemandObservation {
            day: 30,
            credited_compute_value: 20,
            requester_cluster: h(99),
            operator_cluster: h(98),
            hardware_class: 9,
            evidence: DemandEvidence {
                funding: FundingEvidence::Circular,
                ..independent()
            },
        });
        let report = evaluate_demand_window(30, &observations).unwrap();
        assert_eq!((report.qualified_value, report.total_value), (80, 100));
        assert!(report.public_useful_threshold_met);
    }

    #[test]
    fn omega_cap_stale_calibration_and_rollback_are_exact() {
        let mut book = OmegaShadowBook::new(OmegaPolicy {
            cap_ppm_of_total_weight: 100_000,
        })
        .unwrap();
        let quote = book
            .quote(OmegaRequest {
                class_id: 7,
                ground_weight: 900,
                measured_work: 1_000,
                deliverable_materialized: true,
                calibration_valid_through: 20,
                height: 20,
                demand: independent(),
            })
            .unwrap();
        assert_eq!(quote.counterfactual_credit, 100);
        assert_eq!(quote.production_credit, 0);
        assert_eq!(
            book.quote(OmegaRequest {
                class_id: 7,
                ground_weight: 900,
                measured_work: 1_000,
                deliverable_materialized: true,
                calibration_valid_through: 20,
                height: 21,
                demand: independent(),
            })
            .unwrap()
            .zero_reason,
            Some(OmegaZeroReason::StaleCalibration)
        );
        book.rollback_class(7);
        assert_eq!(
            book.quote(OmegaRequest {
                class_id: 7,
                ground_weight: 900,
                measured_work: 1_000,
                deliverable_materialized: true,
                calibration_valid_through: 99,
                height: 21,
                demand: independent(),
            })
            .unwrap()
            .zero_reason,
            Some(OmegaZeroReason::RolledBackClass)
        );
    }

    #[test]
    fn duplex_never_adds_mint_or_counts_height_or_receipt_twice() {
        let mut book = DuplexShadowBook::new(DuplexPolicy {
            reallocation_cap_ppm: 250_000,
        })
        .unwrap();
        let allocation = book.allocate(10, h(1), 101, 100, independent()).unwrap();
        assert_eq!(allocation.counterfactual_work, 25);
        assert_eq!(allocation.counterfactual_base, 76);
        assert_eq!(
            allocation.counterfactual_base + allocation.counterfactual_work,
            allocation.scheduled
        );
        assert_eq!(
            (allocation.production_base, allocation.production_work),
            (101, 0)
        );
        assert_eq!(
            book.allocate(10, h(2), 101, 1, independent()),
            Err(EconomicsError::DuplicateHeight)
        );
        assert_eq!(
            book.allocate(11, h(1), 101, 1, independent()),
            Err(EconomicsError::DuplicateReceipt)
        );
    }

    #[test]
    fn duplex_rollback_and_wash_zero_only_reallocation() {
        let mut book = DuplexShadowBook::new(DuplexPolicy {
            reallocation_cap_ppm: 500_000,
        })
        .unwrap();
        let mut wash = independent();
        wash.funding = FundingEvidence::Circular;
        let washed = book.allocate(1, h(1), 9, 9, wash).unwrap();
        assert_eq!(
            (washed.counterfactual_base, washed.counterfactual_work),
            (9, 0)
        );
        book.rollback();
        let rolled = book.allocate(2, h(2), 9, 9, independent()).unwrap();
        assert_eq!(
            (rolled.counterfactual_base, rolled.counterfactual_work),
            (9, 0)
        );
    }

    fn proof_policy() -> ProofpowerPolicy {
        ProofpowerPolicy {
            cap_ppm_of_effective_ring: 200_000,
            cluster_weight_limit_ppm: 333_333,
            concentration_coefficient_ppm: 200_000,
            maturity_days: 30,
            linear_decay_days: 100,
        }
    }

    #[test]
    fn proofpower_maturity_decay_cap_and_no_consensus_leakage() {
        let mut book = ProofpowerShadowBook::new(proof_policy()).unwrap();
        let raw = (1..=6u8)
            .map(|i| (h(i), 100u128))
            .collect::<BTreeMap<_, _>>();
        for i in 1..=6u8 {
            book.admit(ProofpowerReceipt::seal(
                h(i + 20),
                h(i),
                100,
                0,
                None,
                independent(),
            ))
            .unwrap();
        }
        let immature = book.measure(29, &raw).unwrap();
        assert!(!immature.beta_active);
        assert!(immature.counterfactual_bonus_by_cluster.is_empty());
        let mature = book.measure(30, &raw).unwrap();
        assert!(mature.beta_active);
        assert_eq!(
            sum_values(mature.counterfactual_bonus_by_cluster.values().copied()).unwrap(),
            150
        );
        assert!(mature.production_bonus_by_cluster.is_empty());
        assert_eq!(mature.production_effective_ring, raw);
        let decayed = book.measure(80, &raw).unwrap();
        assert!(
            sum_values(decayed.counterfactual_bonus_by_cluster.values().copied()).unwrap() <= 150
        );
    }

    #[test]
    fn proofpower_population_boundary_and_proposal_overlap_zero_beta() {
        let raw = (1..=6u8)
            .map(|i| (h(i), 100u128))
            .collect::<BTreeMap<_, _>>();
        let mut book = ProofpowerShadowBook::new(proof_policy()).unwrap();
        for i in 1..=5u8 {
            book.admit(ProofpowerReceipt::seal(
                h(i + 20),
                h(i),
                10,
                0,
                None,
                independent(),
            ))
            .unwrap();
        }
        assert!(!book.measure(30, &raw).unwrap().beta_active);
        book.admit(ProofpowerReceipt::seal(
            h(99),
            h(6),
            10,
            0,
            Some(29),
            independent(),
        ))
        .unwrap();
        let overlap = book.measure(30, &raw).unwrap();
        assert_eq!(overlap.rejected_proposal_overlap, 1);
        assert!(!overlap.beta_active);
    }

    #[test]
    fn proofpower_forgery_duplicate_and_cluster_capture_fail_closed() {
        let mut forged = ProofpowerReceipt::seal(h(1), h(2), 10, 0, None, independent());
        forged.funded_value = u128::MAX;
        let mut book = ProofpowerShadowBook::new(proof_policy()).unwrap();
        assert_eq!(
            book.admit(forged),
            Err(EconomicsError::InvalidReceiptCommitment)
        );
        let valid = ProofpowerReceipt::seal(h(3), h(2), 1_000, 0, None, independent());
        book.admit(valid).unwrap();
        assert_eq!(book.admit(valid), Err(EconomicsError::DuplicateReceipt));

        for i in 4..=9u8 {
            book.admit(ProofpowerReceipt::seal(
                h(i),
                h(i),
                100,
                0,
                None,
                independent(),
            ))
            .unwrap();
        }
        let raw = BTreeMap::from([
            (h(2), 400),
            (h(4), 100),
            (h(5), 100),
            (h(6), 100),
            (h(7), 100),
            (h(8), 100),
            (h(9), 100),
        ]);
        let measurement = book.measure(30, &raw).unwrap();
        assert!(!measurement.beta_active, "cluster at >=1/3 disables beta");
        assert!(measurement.counterfactual_bonus_by_cluster.is_empty());
        assert_eq!(measurement.production_effective_ring, raw);
    }
}
