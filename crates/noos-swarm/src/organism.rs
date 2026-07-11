use crate::{Hash32, SwarmError};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentEvidence {
    pub component_id: Hash32,
    pub observations: u64,
    pub useful_work_units: u128,
    pub rights_violations: u64,
    pub semantic_continuity_bps: u16,
    pub control_concentration_bps: u16,
    pub decision_benefit_millionths: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganismAggregate {
    component_ids: BTreeSet<Hash32>,
    pub observations: u64,
    pub useful_work_units: u128,
    pub rights_violations: u64,
    pub minimum_semantic_continuity_bps: u16,
    pub maximum_control_concentration_bps: u16,
    weighted_decision_benefit: i128,
}

impl OrganismAggregate {
    pub fn from_components(components: &[ComponentEvidence]) -> Result<Self, SwarmError> {
        if components.is_empty() {
            return Err(SwarmError::EmptyOrganismEvidence);
        }
        let mut aggregate = Self {
            component_ids: BTreeSet::new(),
            observations: 0,
            useful_work_units: 0,
            rights_violations: 0,
            minimum_semantic_continuity_bps: 10_000,
            maximum_control_concentration_bps: 0,
            weighted_decision_benefit: 0,
        };
        for component in components {
            if component.component_id == [0; 32]
                || component.observations == 0
                || component.semantic_continuity_bps > 10_000
                || component.control_concentration_bps > 10_000
                || !aggregate.component_ids.insert(component.component_id)
            {
                return Err(SwarmError::InvalidOrganismEvidence);
            }
            aggregate.observations = aggregate
                .observations
                .checked_add(component.observations)
                .ok_or(SwarmError::Overflow)?;
            aggregate.useful_work_units = aggregate
                .useful_work_units
                .checked_add(component.useful_work_units)
                .ok_or(SwarmError::Overflow)?;
            aggregate.rights_violations = aggregate
                .rights_violations
                .checked_add(component.rights_violations)
                .ok_or(SwarmError::Overflow)?;
            aggregate.minimum_semantic_continuity_bps = aggregate
                .minimum_semantic_continuity_bps
                .min(component.semantic_continuity_bps);
            aggregate.maximum_control_concentration_bps = aggregate
                .maximum_control_concentration_bps
                .max(component.control_concentration_bps);
            let contribution = i128::from(component.decision_benefit_millionths)
                .checked_mul(i128::from(component.observations))
                .ok_or(SwarmError::Overflow)?;
            aggregate.weighted_decision_benefit = aggregate
                .weighted_decision_benefit
                .checked_add(contribution)
                .ok_or(SwarmError::Overflow)?;
        }
        Ok(aggregate)
    }

    pub fn merge(self, other: Self) -> Result<Self, SwarmError> {
        if !self.component_ids.is_disjoint(&other.component_ids) {
            return Err(SwarmError::DuplicateOrganismComponent);
        }
        let mut component_ids = self.component_ids;
        component_ids.extend(other.component_ids);
        Ok(Self {
            component_ids,
            observations: self
                .observations
                .checked_add(other.observations)
                .ok_or(SwarmError::Overflow)?,
            useful_work_units: self
                .useful_work_units
                .checked_add(other.useful_work_units)
                .ok_or(SwarmError::Overflow)?,
            rights_violations: self
                .rights_violations
                .checked_add(other.rights_violations)
                .ok_or(SwarmError::Overflow)?,
            minimum_semantic_continuity_bps: self
                .minimum_semantic_continuity_bps
                .min(other.minimum_semantic_continuity_bps),
            maximum_control_concentration_bps: self
                .maximum_control_concentration_bps
                .max(other.maximum_control_concentration_bps),
            weighted_decision_benefit: self
                .weighted_decision_benefit
                .checked_add(other.weighted_decision_benefit)
                .ok_or(SwarmError::Overflow)?,
        })
    }

    #[must_use]
    pub fn decision_benefit_millionths(&self) -> i64 {
        let denominator = i128::from(self.observations);
        let value = self
            .weighted_decision_benefit
            .checked_div(denominator)
            .unwrap_or(0);
        i64::try_from(value).unwrap_or_else(|_| {
            if value.is_negative() {
                i64::MIN
            } else {
                i64::MAX
            }
        })
    }

    /// Frozen S-GLOBAL-ORGANISM has no production threshold. Finite component
    /// evidence therefore never establishes the global claim.
    #[must_use]
    pub const fn establishes_global_organism(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn proposal_weight(&self) -> u64 {
        0
    }

    #[must_use]
    pub const fn finality_weight(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn component(id: u8, observations: u64, work: u128, benefit: i64) -> ComponentEvidence {
        ComponentEvidence {
            component_id: h(id),
            observations,
            useful_work_units: work,
            rights_violations: u64::from(id == 3),
            semantic_continuity_bps: 9_000_u16.saturating_sub(u16::from(id)),
            control_concentration_bps: 1_000_u16.saturating_add(u16::from(id)),
            decision_benefit_millionths: benefit,
        }
    }

    #[test]
    fn claim_global_organism_aggregation_conserves_partitioned_evidence() {
        let components = vec![
            component(1, 10, 100, 10),
            component(2, 20, 200, 20),
            component(3, 30, 300, -10),
        ];
        let all = OrganismAggregate::from_components(&components).unwrap();
        let left = OrganismAggregate::from_components(&components[..1]).unwrap();
        let right = OrganismAggregate::from_components(&components[1..]).unwrap();
        let merged = left.merge(right).unwrap();
        assert_eq!(merged, all);
        assert_eq!(
            (
                all.observations,
                all.useful_work_units,
                all.rights_violations
            ),
            (60, 600, 1)
        );
        assert_eq!(all.decision_benefit_millionths(), 3);
    }

    #[test]
    fn claim_global_organism_stays_g0_non_authoritative_and_rejects_double_count() {
        let evidence = component(1, 1, 1, 1);
        let left = OrganismAggregate::from_components(std::slice::from_ref(&evidence)).unwrap();
        let right = OrganismAggregate::from_components(&[evidence]).unwrap();
        assert_eq!(
            left.merge(right),
            Err(SwarmError::DuplicateOrganismComponent)
        );
        let aggregate = OrganismAggregate::from_components(&[component(2, 1, 1, 1)]).unwrap();
        assert!(!aggregate.establishes_global_organism());
        assert_eq!(
            (aggregate.proposal_weight(), aggregate.finality_weight()),
            (0, 0)
        );
    }
}
