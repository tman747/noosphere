//! Hearth admission, physical-diversity signals, and conservative payment eligibility.

use crate::{domain_hash, RttClass};
use noos_species::Hash32;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdmissionAttack {
    VirtualMachine,
    GpuSpoof,
    ReplayedConformance,
    ColocatedCollusion,
    CloudBoxAsHousehold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionEvidence {
    pub hearth_id: Hash32,
    pub controller_cluster: Hash32,
    pub bond: u128,
    pub vendor_roots: BTreeSet<Hash32>,
    pub architecture_roots: BTreeSet<Hash32>,
    pub conformance_transcript: Hash32,
    pub conformance_challenge: Hash32,
    pub advertised_rtt_class: RttClass,
    pub probe_rtts_ms: BTreeMap<Hash32, u32>,
    pub availability_bps: u16,
    pub failure_domains: BTreeSet<Hash32>,
    pub virtualization_detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub admitted: bool,
    pub conformance_consistent: bool,
    pub latency_consistent: bool,
    pub physical_diversity_advisory: bool,
    pub detected_attacks: BTreeSet<AdmissionAttack>,
}

#[derive(Debug, Default)]
pub struct AdmissionRegistry {
    used_transcripts: BTreeSet<Hash32>,
    used_challenges: BTreeSet<Hash32>,
}

impl AdmissionRegistry {
    pub fn evaluate(
        &mut self,
        evidence: &AdmissionEvidence,
        minimum_bond: u128,
    ) -> Result<AdmissionDecision, PaymentError> {
        if evidence.hearth_id == [0; 32]
            || evidence.controller_cluster == [0; 32]
            || evidence.bond < minimum_bond
            || evidence.conformance_transcript == [0; 32]
            || evidence.conformance_challenge == [0; 32]
            || evidence.probe_rtts_ms.len() < 2
            || evidence.availability_bps > 10_000
        {
            return Err(PaymentError::InvalidAdmissionEvidence);
        }
        let transcript_fresh = !self
            .used_transcripts
            .contains(&evidence.conformance_transcript)
            && !self
                .used_challenges
                .contains(&evidence.conformance_challenge);
        let conformance_consistent = transcript_fresh
            && evidence.vendor_roots.len() >= 2
            && evidence.architecture_roots.len() >= 2;
        let latency_consistent = evidence
            .probe_rtts_ms
            .values()
            .all(|rtt| RttClass::from_millis(*rtt) == evidence.advertised_rtt_class);
        let physical_diversity_advisory =
            evidence.failure_domains.len() >= 2 && conformance_consistent && latency_consistent;
        let mut detected_attacks = BTreeSet::new();
        if evidence.virtualization_detected {
            detected_attacks.insert(AdmissionAttack::VirtualMachine);
        }
        if evidence.vendor_roots.len() < 2 || evidence.architecture_roots.len() < 2 {
            detected_attacks.insert(AdmissionAttack::GpuSpoof);
        }
        if !transcript_fresh {
            detected_attacks.insert(AdmissionAttack::ReplayedConformance);
        }
        if evidence.failure_domains.len() < 2 {
            detected_attacks.insert(AdmissionAttack::ColocatedCollusion);
        }
        if !latency_consistent {
            detected_attacks.insert(AdmissionAttack::CloudBoxAsHousehold);
        }
        self.used_transcripts
            .insert(evidence.conformance_transcript);
        self.used_challenges.insert(evidence.conformance_challenge);
        Ok(AdmissionDecision {
            admitted: conformance_consistent && latency_consistent && evidence.bond >= minimum_bond,
            conformance_consistent,
            latency_consistent,
            physical_diversity_advisory,
            detected_attacks,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SybilCohortObservation {
    pub apparent_diversity: u32,
    pub manufactured_diversity: u32,
    pub attack_cost: u128,
    pub corresponding_bonds: u128,
    pub latency_check_caught_declared_class: bool,
    pub conformance_check_caught_declared_class: bool,
}

impl SybilCohortObservation {
    #[must_use]
    pub fn red_team_threshold_met(self) -> bool {
        self.apparent_diversity > 0
            && (u128::from(self.manufactured_diversity).saturating_mul(3)
                < u128::from(self.apparent_diversity)
                || self.attack_cost >= self.corresponding_bonds)
            && self.latency_check_caught_declared_class
            && self.conformance_check_caught_declared_class
    }

    #[must_use]
    pub fn kill_fired(self) -> bool {
        self.apparent_diversity > 0
            && u128::from(self.manufactured_diversity).saturating_mul(3)
                >= u128::from(self.apparent_diversity)
            && self.attack_cost < self.corresponding_bonds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandSource {
    Independent,
    Circular,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentEligibility {
    pub demand: DemandSource,
    pub delivered: bool,
    pub paid_delivery_certificate: bool,
    pub challenge_window_closed: bool,
    pub payer_worker_clusters_disjoint: bool,
    pub fee_cycle_detected: bool,
    pub same_window_proposal_credit: bool,
}

impl PaymentEligibility {
    #[must_use]
    pub fn proofpower_eligible(self) -> bool {
        self.demand == DemandSource::Independent
            && self.delivered
            && self.paid_delivery_certificate
            && self.challenge_window_closed
            && self.payer_worker_clusters_disjoint
            && !self.fee_cycle_detected
            && !self.same_window_proposal_credit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HearthPaymentPlan {
    pub executor: u128,
    pub chorus: u128,
    pub evaluator: u128,
    pub availability_and_relay: u128,
}

impl HearthPaymentPlan {
    pub fn validate(self, escrow: u128) -> Result<(), PaymentError> {
        let total = self
            .executor
            .checked_add(self.chorus)
            .and_then(|sum| sum.checked_add(self.evaluator))
            .and_then(|sum| sum.checked_add(self.availability_and_relay))
            .ok_or(PaymentError::ArithmeticOverflow)?;
        if total != escrow {
            return Err(PaymentError::ConservationViolation);
        }
        Ok(())
    }

    #[must_use]
    pub fn commitment(self, job_id: Hash32) -> Hash32 {
        domain_hash(
            "NOOS/HEARTH/PAYMENT-PLAN/V1",
            &[
                &job_id,
                &self.executor.to_le_bytes(),
                &self.chorus.to_le_bytes(),
                &self.evaluator.to_le_bytes(),
                &self.availability_and_relay.to_le_bytes(),
            ],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentError {
    InvalidAdmissionEvidence,
    ArithmeticOverflow,
    ConservationViolation,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn evidence() -> AdmissionEvidence {
        AdmissionEvidence {
            hearth_id: h(1),
            controller_cluster: h(2),
            bond: 100,
            vendor_roots: BTreeSet::from([h(3), h(4)]),
            architecture_roots: BTreeSet::from([h(5), h(6)]),
            conformance_transcript: h(7),
            conformance_challenge: h(8),
            advertised_rtt_class: RttClass::Regional,
            probe_rtts_ms: BTreeMap::from([(h(9), 20), (h(10), 40)]),
            availability_bps: 9_000,
            failure_domains: BTreeSet::from([h(11), h(12)]),
            virtualization_detected: false,
        }
    }

    #[test]
    fn conformance_and_latency_checks_detect_independent_attack_classes() {
        let mut registry = AdmissionRegistry::default();
        let decision = registry.evaluate(&evidence(), 100).unwrap();
        assert!(decision.admitted && decision.physical_diversity_advisory);

        let replay = registry.evaluate(&evidence(), 100).unwrap();
        assert!(!replay.admitted);
        assert!(replay
            .detected_attacks
            .contains(&AdmissionAttack::ReplayedConformance));

        let mut cloud = evidence();
        cloud.conformance_transcript = h(20);
        cloud.conformance_challenge = h(21);
        cloud.probe_rtts_ms = BTreeMap::from([(h(9), 140), (h(10), 150)]);
        let cloud = registry.evaluate(&cloud, 100).unwrap();
        assert!(cloud.conformance_consistent);
        assert!(!cloud.latency_consistent);
        assert!(cloud
            .detected_attacks
            .contains(&AdmissionAttack::CloudBoxAsHousehold));
    }

    #[test]
    fn wash_or_unmatured_receipts_never_accrue_proofpower() {
        let eligible = PaymentEligibility {
            demand: DemandSource::Independent,
            delivered: true,
            paid_delivery_certificate: true,
            challenge_window_closed: true,
            payer_worker_clusters_disjoint: true,
            fee_cycle_detected: false,
            same_window_proposal_credit: false,
        };
        assert!(eligible.proofpower_eligible());
        assert!(!PaymentEligibility {
            demand: DemandSource::Circular,
            ..eligible
        }
        .proofpower_eligible());
        assert!(!PaymentEligibility {
            challenge_window_closed: false,
            ..eligible
        }
        .proofpower_eligible());
        assert!(!PaymentEligibility {
            same_window_proposal_credit: true,
            ..eligible
        }
        .proofpower_eligible());
    }

    #[test]
    fn payment_plan_conserves_escrow_exactly() {
        let plan = HearthPaymentPlan {
            executor: 70,
            chorus: 10,
            evaluator: 10,
            availability_and_relay: 10,
        };
        assert!(plan.validate(100).is_ok());
        assert_eq!(plan.validate(99), Err(PaymentError::ConservationViolation));
    }

    #[test]
    fn one_third_sybil_threshold_is_strict_and_bond_relative() {
        let pass = SybilCohortObservation {
            apparent_diversity: 100,
            manufactured_diversity: 32,
            attack_cost: 100,
            corresponding_bonds: 100,
            latency_check_caught_declared_class: true,
            conformance_check_caught_declared_class: true,
        };
        assert!(pass.red_team_threshold_met());
        let kill = SybilCohortObservation {
            manufactured_diversity: 34,
            attack_cost: 99,
            ..pass
        };
        assert!(kill.kill_fired());
    }
}
