//! P3 / S-ALGORITHM-TRANSITION local contract: challengers submit executable cost evidence for a
//! new matmul strategy; a prospective profile activates only after two independent reproductions
//! of the best attack within 10%. The rules fail closed: withheld artifacts reject at submission,
//! governance cannot activate past a cheaper fully-reproduced challenger, activation is strictly
//! prospective, and past credit is never reinterpreted. All losing artifacts stay public.

use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    /// Executable or artifact roots are withheld: the challenge cannot be reproduced, so it is
    /// rejected fail-closed at submission instead of lingering unreproducible.
    WithheldArtifacts,
    ZeroCost,
    DuplicateAlgorithm,
    UnknownAlgorithm,
    /// Reproductions must come from distinct reproducers.
    DuplicateReproducer,
    /// The reproduction disagrees with the claimed cost by more than 10%.
    OutOfTolerance,
    /// Fewer than two independent in-tolerance reproductions exist.
    InsufficientReproduction,
    /// A cheaper fully-reproduced challenge is pending; activating anything else would suppress it.
    CheaperEvidencePending,
    /// The candidate is not cheaper than the active profile; recalibration only moves down.
    NotCheaper,
}

/// Executable cost evidence. Artifact and executable roots are mandatory (no withheld artifacts).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostEvidence {
    pub algorithm_id: [u8; 32],
    pub claimed_cost: u64,
    pub artifact_root: Option<[u8; 32]>,
    pub executable_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reproduction {
    pub reproducer: [u8; 32],
    pub measured_cost: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub algorithm_id: [u8; 32],
    pub cost: u64,
    /// First epoch at which this profile prices work. Always strictly in the future at activation.
    pub active_from_epoch: u64,
}

#[derive(Clone, Debug)]
struct Challenge {
    evidence: CostEvidence,
    reproductions: Vec<Reproduction>,
}

/// `|measured - claimed| <= claimed / 10`, computed without overflow or floats.
fn within_ten_percent(claimed: u64, measured: u64) -> bool {
    let claimed = u128::from(claimed);
    let measured = u128::from(measured);
    let diff = claimed.abs_diff(measured);
    diff.saturating_mul(10) <= claimed
}

#[derive(Clone, Debug)]
pub struct TransitionRegistry {
    current_epoch: u64,
    /// Profile history ordered by activation epoch; entries are append-only and never rewritten.
    profiles: Vec<Profile>,
    challenges: BTreeMap<[u8; 32], Challenge>,
    /// Every submission ever made, winners and losers alike, stays public here.
    archive: Vec<CostEvidence>,
}

impl TransitionRegistry {
    #[must_use]
    pub fn genesis(genesis_algorithm: [u8; 32], genesis_cost: u64) -> Self {
        Self {
            current_epoch: 0,
            profiles: vec![Profile {
                algorithm_id: genesis_algorithm,
                cost: genesis_cost,
                active_from_epoch: 0,
            }],
            challenges: BTreeMap::new(),
            archive: Vec::new(),
        }
    }

    pub fn advance_epoch(&mut self) {
        self.current_epoch = self.current_epoch.saturating_add(1);
    }

    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// The cost profile that priced work at `epoch`. History is immutable: activations never
    /// change the answer for any epoch at or before the activation epoch.
    #[must_use]
    pub fn cost_at_epoch(&self, epoch: u64) -> u64 {
        self.profiles
            .iter()
            .filter(|p| p.active_from_epoch <= epoch)
            .max_by_key(|p| p.active_from_epoch)
            .map_or(0, |p| p.cost)
    }

    /// All submitted evidence, including losing artifacts. Never pruned.
    #[must_use]
    pub fn archive(&self) -> &[CostEvidence] {
        &self.archive
    }

    pub fn submit_challenge(&mut self, evidence: CostEvidence) -> Result<(), TransitionError> {
        if evidence.artifact_root.is_none() || evidence.executable_hash.is_none() {
            return Err(TransitionError::WithheldArtifacts);
        }
        if evidence.claimed_cost == 0 {
            return Err(TransitionError::ZeroCost);
        }
        if self.challenges.contains_key(&evidence.algorithm_id) {
            return Err(TransitionError::DuplicateAlgorithm);
        }
        self.archive.push(evidence.clone());
        self.challenges.insert(
            evidence.algorithm_id,
            Challenge {
                evidence,
                reproductions: Vec::new(),
            },
        );
        Ok(())
    }

    pub fn record_reproduction(
        &mut self,
        algorithm_id: [u8; 32],
        reproduction: Reproduction,
    ) -> Result<(), TransitionError> {
        let challenge = self
            .challenges
            .get_mut(&algorithm_id)
            .ok_or(TransitionError::UnknownAlgorithm)?;
        if challenge
            .reproductions
            .iter()
            .any(|r| r.reproducer == reproduction.reproducer)
        {
            return Err(TransitionError::DuplicateReproducer);
        }
        if !within_ten_percent(challenge.evidence.claimed_cost, reproduction.measured_cost) {
            return Err(TransitionError::OutOfTolerance);
        }
        challenge.reproductions.push(reproduction);
        Ok(())
    }

    fn is_reproduced(challenge: &Challenge) -> bool {
        challenge.reproductions.len() >= 2
    }

    /// Cheapest fully-reproduced pending challenge, if any.
    fn best_pending(&self) -> Option<&Challenge> {
        self.challenges
            .values()
            .filter(|c| Self::is_reproduced(c))
            .min_by_key(|c| c.evidence.claimed_cost)
    }

    /// Activates a fully-reproduced challenge prospectively (from the next epoch). Fails closed:
    /// an under-reproduced candidate, a non-cheapest candidate while cheaper reproduced evidence
    /// is pending, or a candidate not cheaper than the active profile all reject.
    pub fn activate(&mut self, algorithm_id: [u8; 32]) -> Result<Profile, TransitionError> {
        let candidate = self
            .challenges
            .get(&algorithm_id)
            .ok_or(TransitionError::UnknownAlgorithm)?;
        if !Self::is_reproduced(candidate) {
            return Err(TransitionError::InsufficientReproduction);
        }
        let candidate_cost = candidate.evidence.claimed_cost;
        if let Some(best) = self.best_pending() {
            if best.evidence.claimed_cost < candidate_cost {
                return Err(TransitionError::CheaperEvidencePending);
            }
        }
        if candidate_cost >= self.cost_at_epoch(self.current_epoch) {
            return Err(TransitionError::NotCheaper);
        }
        let profile = Profile {
            algorithm_id,
            cost: candidate_cost,
            active_from_epoch: self.current_epoch.saturating_add(1),
        };
        self.profiles.push(profile.clone());
        self.challenges.remove(&algorithm_id);
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn evidence(id: u8, cost: u64) -> CostEvidence {
        CostEvidence {
            algorithm_id: [id; 32],
            claimed_cost: cost,
            artifact_root: Some([id ^ 0xAA; 32]),
            executable_hash: Some([id ^ 0x55; 32]),
        }
    }

    fn repro(who: u8, cost: u64) -> Reproduction {
        Reproduction {
            reproducer: [who; 32],
            measured_cost: cost,
        }
    }

    #[test]
    fn two_independent_reproductions_activate_prospectively() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        reg.advance_epoch();
        reg.advance_epoch();
        reg.submit_challenge(evidence(1, 60)).unwrap();
        reg.record_reproduction([1u8; 32], repro(10, 58)).unwrap();
        reg.record_reproduction([1u8; 32], repro(11, 65)).unwrap();
        let profile = reg.activate([1u8; 32]).unwrap();
        assert_eq!(profile.active_from_epoch, 3);
        // Prospective only: past and current epochs keep the old cost.
        assert_eq!(reg.cost_at_epoch(0), 100);
        assert_eq!(reg.cost_at_epoch(2), 100);
        assert_eq!(reg.cost_at_epoch(3), 60);
    }

    #[test]
    fn falsifier_withheld_artifacts_reject_fail_closed() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        let mut hidden = evidence(1, 60);
        hidden.executable_hash = None;
        assert_eq!(
            reg.submit_challenge(hidden),
            Err(TransitionError::WithheldArtifacts)
        );
        let mut hidden = evidence(1, 60);
        hidden.artifact_root = None;
        assert_eq!(
            reg.submit_challenge(hidden),
            Err(TransitionError::WithheldArtifacts)
        );
    }

    #[test]
    fn falsifier_single_or_dependent_reproduction_never_activates() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        reg.submit_challenge(evidence(1, 60)).unwrap();
        reg.record_reproduction([1u8; 32], repro(10, 60)).unwrap();
        assert_eq!(
            reg.activate([1u8; 32]),
            Err(TransitionError::InsufficientReproduction)
        );
        // The same reproducer cannot count twice.
        assert_eq!(
            reg.record_reproduction([1u8; 32], repro(10, 61)),
            Err(TransitionError::DuplicateReproducer)
        );
        assert_eq!(
            reg.activate([1u8; 32]),
            Err(TransitionError::InsufficientReproduction)
        );
    }

    #[test]
    fn falsifier_out_of_tolerance_reproduction_does_not_count() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        reg.submit_challenge(evidence(1, 60)).unwrap();
        // 67 is >10% above 60; 53 is >10% below.
        assert_eq!(
            reg.record_reproduction([1u8; 32], repro(10, 67)),
            Err(TransitionError::OutOfTolerance)
        );
        assert_eq!(
            reg.record_reproduction([1u8; 32], repro(11, 53)),
            Err(TransitionError::OutOfTolerance)
        );
        // Boundary: exactly 10% off counts.
        reg.record_reproduction([1u8; 32], repro(12, 66)).unwrap();
        reg.record_reproduction([1u8; 32], repro(13, 54)).unwrap();
        assert!(reg.activate([1u8; 32]).is_ok());
    }

    #[test]
    fn falsifier_governance_cannot_suppress_cheaper_evidence() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        reg.submit_challenge(evidence(1, 80)).unwrap();
        reg.submit_challenge(evidence(2, 50)).unwrap();
        for (algo, r) in [(1u8, 10u8), (1, 11), (2, 12), (2, 13)] {
            let cost = if algo == 1 { 80 } else { 50 };
            reg.record_reproduction([algo; 32], repro(r, cost)).unwrap();
        }
        // Activating the more expensive challenger while a cheaper reproduced one is pending
        // is suppression and fails closed.
        assert_eq!(
            reg.activate([1u8; 32]),
            Err(TransitionError::CheaperEvidencePending)
        );
        assert!(reg.activate([2u8; 32]).is_ok());
        // Losing artifacts stay public.
        assert!(reg.archive().iter().any(|e| e.algorithm_id == [1u8; 32]));
        assert_eq!(reg.archive().len(), 2);
    }

    #[test]
    fn falsifier_no_retroactive_reinterpretation_of_credit() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        reg.advance_epoch();
        let before: Vec<u64> = (0..=1).map(|e| reg.cost_at_epoch(e)).collect();
        reg.submit_challenge(evidence(1, 40)).unwrap();
        reg.record_reproduction([1u8; 32], repro(10, 40)).unwrap();
        reg.record_reproduction([1u8; 32], repro(11, 42)).unwrap();
        reg.activate([1u8; 32]).unwrap();
        let after: Vec<u64> = (0..=1).map(|e| reg.cost_at_epoch(e)).collect();
        assert_eq!(before, after);
    }

    #[test]
    fn falsifier_more_expensive_profile_never_activates() {
        let mut reg = TransitionRegistry::genesis([0u8; 32], 100);
        reg.submit_challenge(evidence(1, 100)).unwrap();
        reg.record_reproduction([1u8; 32], repro(10, 100)).unwrap();
        reg.record_reproduction([1u8; 32], repro(11, 100)).unwrap();
        assert_eq!(reg.activate([1u8; 32]), Err(TransitionError::NotCheaper));
    }
}
