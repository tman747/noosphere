use noos_species::Hash32;

use crate::TrainingError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RolloutVersions {
    pub policy: u64,
    pub tokenizer: Hash32,
    pub environment: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LagPolicy {
    pub accept_through: u64,
    pub downweight_through: u64,
    pub hard_maximum: u64,
    pub minimum_weight_bps: u16,
}

impl LagPolicy {
    pub fn validate(&self) -> Result<(), TrainingError> {
        if self.accept_through >= self.downweight_through
            || self.downweight_through >= self.hard_maximum
            || self.minimum_weight_bps == 0
            || self.minimum_weight_bps >= 10_000
        {
            Err(TrainingError::InvalidLagPolicy)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagClass {
    Accept,
    Downweight { weight_bps: u16 },
    Reject,
    CancelGroup,
}

pub fn classify_rollout(
    policy: LagPolicy,
    current: RolloutVersions,
    rollout: RolloutVersions,
) -> Result<LagClass, TrainingError> {
    policy.validate()?;
    if rollout.tokenizer != current.tokenizer || rollout.environment != current.environment {
        return Ok(LagClass::CancelGroup);
    }
    let lag = current
        .policy
        .checked_sub(rollout.policy)
        .ok_or(TrainingError::FuturePolicyVersion)?;
    if lag <= policy.accept_through {
        return Ok(LagClass::Accept);
    }
    if lag <= policy.downweight_through {
        let span = policy
            .downweight_through
            .checked_sub(policy.accept_through)
            .ok_or(TrainingError::InvalidLagPolicy)?;
        let position = lag
            .checked_sub(policy.accept_through)
            .ok_or(TrainingError::InvalidLagPolicy)?;
        let range = u64::from(10_000_u16 - policy.minimum_weight_bps);
        let reduction = range
            .checked_mul(position)
            .ok_or(TrainingError::LagArithmetic)?
            .checked_div(span)
            .ok_or(TrainingError::LagArithmetic)?;
        let weight = 10_000_u64
            .checked_sub(reduction)
            .ok_or(TrainingError::LagArithmetic)?;
        return Ok(LagClass::Downweight {
            weight_bps: u16::try_from(weight).map_err(|_| TrainingError::LagArithmetic)?,
        });
    }
    if lag <= policy.hard_maximum {
        Ok(LagClass::Reject)
    } else {
        Ok(LagClass::CancelGroup)
    }
}

pub fn classify_group(
    policy: LagPolicy,
    current: RolloutVersions,
    rollouts: &[RolloutVersions],
) -> Result<Vec<LagClass>, TrainingError> {
    if rollouts.is_empty() {
        return Err(TrainingError::EmptyRolloutGroup);
    }
    let mut classes = rollouts
        .iter()
        .map(|rollout| classify_rollout(policy, current, *rollout))
        .collect::<Result<Vec<_>, _>>()?;
    if classes.contains(&LagClass::CancelGroup) {
        classes.fill(LagClass::CancelGroup);
    }
    Ok(classes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn versions(policy: u64) -> RolloutVersions {
        RolloutVersions {
            policy,
            tokenizer: h(1),
            environment: h(2),
        }
    }

    fn policy() -> LagPolicy {
        LagPolicy {
            accept_through: 2,
            downweight_through: 5,
            hard_maximum: 8,
            minimum_weight_bps: 4_000,
        }
    }

    #[test]
    fn claim_rl_lag_every_boundary_and_generated_trace_is_exact() {
        let current = versions(100);
        assert_eq!(
            classify_rollout(policy(), current, versions(98)).unwrap(),
            LagClass::Accept
        );
        assert_eq!(
            classify_rollout(policy(), current, versions(97)).unwrap(),
            LagClass::Downweight { weight_bps: 8_000 }
        );
        assert_eq!(
            classify_rollout(policy(), current, versions(95)).unwrap(),
            LagClass::Downweight { weight_bps: 4_000 }
        );
        assert_eq!(
            classify_rollout(policy(), current, versions(92)).unwrap(),
            LagClass::Reject
        );
        assert_eq!(
            classify_rollout(policy(), current, versions(91)).unwrap(),
            LagClass::CancelGroup
        );
        for current_policy in 0..1_000_u64 {
            let current = versions(current_policy);
            for rollout_policy in 0..=current_policy {
                let lag = current_policy - rollout_policy;
                let class = classify_rollout(policy(), current, versions(rollout_policy)).unwrap();
                assert_eq!(
                    matches!(class, LagClass::Accept | LagClass::Downweight { .. }),
                    lag <= policy().downweight_through
                );
                if lag > policy().hard_maximum {
                    assert_eq!(class, LagClass::CancelGroup);
                }
            }
        }
    }

    #[test]
    fn claim_rl_lag_version_spoof_and_one_stale_member_cancel_group() {
        let current = versions(10);
        assert_eq!(
            classify_rollout(policy(), current, versions(11)),
            Err(TrainingError::FuturePolicyVersion)
        );
        let mut wrong_environment = versions(10);
        wrong_environment.environment = h(9);
        assert_eq!(
            classify_rollout(policy(), current, wrong_environment).unwrap(),
            LagClass::CancelGroup
        );
        assert_eq!(
            classify_group(policy(), current, &[versions(10), versions(1)]).unwrap(),
            vec![LagClass::CancelGroup, LagClass::CancelGroup]
        );
    }
}
