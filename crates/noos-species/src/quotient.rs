use crate::canonical::strictly_sorted;
use crate::{Hash32, SpeciesError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteMember {
    pub member: Hash32,
    pub suite: Hash32,
    pub numeric_profile: Hash32,
    pub observations_millionths: Vec<i64>,
    pub critical_safety_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonTransitiveCounterexample {
    pub left: Hash32,
    pub middle: Hash32,
    pub right: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiniteQuotient {
    pub suite: Hash32,
    pub numeric_profile: Hash32,
    pub tolerance_millionths: u64,
    pub classes: Vec<Vec<Hash32>>,
}

fn divergence(left: &SuiteMember, right: &SuiteMember) -> Result<u64, SpeciesError> {
    if left.observations_millionths.len() != right.observations_millionths.len()
        || left.observations_millionths.is_empty()
    {
        return Err(SpeciesError::InvalidQuotientInput);
    }
    left.observations_millionths
        .iter()
        .zip(&right.observations_millionths)
        .try_fold(0_u64, |maximum, (left, right)| {
            let delta = left.abs_diff(*right);
            Ok(maximum.max(delta))
        })
}

pub fn build_finite_quotient(
    members: &[SuiteMember],
    tolerance_millionths: u64,
) -> Result<FiniteQuotient, SpeciesError> {
    if members.is_empty()
        || !strictly_sorted(
            &members
                .iter()
                .map(|member| member.member)
                .collect::<Vec<_>>(),
        )
    {
        return Err(SpeciesError::InvalidQuotientInput);
    }
    let suite = members[0].suite;
    let numeric_profile = members[0].numeric_profile;
    let observation_count = members[0].observations_millionths.len();
    if suite == [0; 32]
        || numeric_profile == [0; 32]
        || observation_count == 0
        || members.iter().any(|member| {
            member.suite != suite
                || member.numeric_profile != numeric_profile
                || member.observations_millionths.len() != observation_count
                || !member.critical_safety_passed
        })
    {
        return Err(SpeciesError::CriticalSafetyDivergence);
    }
    let count = members.len();
    let mut related = vec![vec![false; count]; count];
    for left in 0..count {
        for right in 0..count {
            related[left][right] =
                divergence(&members[left], &members[right])? <= tolerance_millionths;
        }
    }
    for left in 0..count {
        for middle in 0..count {
            if !related[left][middle] {
                continue;
            }
            for right in 0..count {
                if related[middle][right] && !related[left][right] {
                    return Err(SpeciesError::NonTransitiveQuotient(
                        NonTransitiveCounterexample {
                            left: members[left].member,
                            middle: members[middle].member,
                            right: members[right].member,
                        },
                    ));
                }
            }
        }
    }
    let mut assigned = vec![false; count];
    let mut classes = Vec::new();
    for left in 0..count {
        if assigned[left] {
            continue;
        }
        let mut class = Vec::new();
        for right in 0..count {
            if related[left][right] {
                assigned[right] = true;
                class.push(members[right].member);
            }
        }
        classes.push(class);
    }
    Ok(FiniteQuotient {
        suite,
        numeric_profile,
        tolerance_millionths,
        classes,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn member(id: u8, observation: i64) -> SuiteMember {
        SuiteMember {
            member: h(id),
            suite: h(10),
            numeric_profile: h(11),
            observations_millionths: vec![observation],
            critical_safety_passed: true,
        }
    }

    #[test]
    fn claim_quotient_rejects_non_transitivity_counterexample() {
        let error = build_finite_quotient(&[member(1, 0), member(2, 6), member(3, 12)], 10);
        assert_eq!(
            error,
            Err(SpeciesError::NonTransitiveQuotient(
                NonTransitiveCounterexample {
                    left: h(1),
                    middle: h(2),
                    right: h(3),
                }
            ))
        );
    }

    #[test]
    fn claim_quotient_builds_only_finite_pairwise_classes() {
        let quotient = build_finite_quotient(
            &[member(1, 0), member(2, 3), member(3, 100), member(4, 104)],
            5,
        )
        .unwrap();
        assert_eq!(quotient.classes, vec![vec![h(1), h(2)], vec![h(3), h(4)]]);
        let mut unsafe_member = member(2, 3);
        unsafe_member.critical_safety_passed = false;
        assert_eq!(
            build_finite_quotient(&[member(1, 0), unsafe_member], 5),
            Err(SpeciesError::CriticalSafetyDivergence)
        );
    }
}
