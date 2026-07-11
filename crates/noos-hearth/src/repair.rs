//! Availability classes, deterministic churn controls, and committed-state repair.
#![allow(clippy::arithmetic_side_effects)]

use noos_species::Hash32;

const PROBABILITY_SCALE: u128 = 1_000_000_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AvailabilityClass {
    P30,
    P60,
    P80,
    P90,
}

impl AvailabilityClass {
    #[must_use]
    pub const fn floor_bps(self) -> u16 {
        match self {
            Self::P30 => 3_000,
            Self::P60 => 6_000,
            Self::P80 => 8_000,
            Self::P90 => 9_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvailabilityRecord {
    pub hearth_id: Hash32,
    pub window_start: u64,
    pub window_end: u64,
    pub served_heartbeats: u32,
    pub probe_responses: u32,
    pub probe_assignments: u32,
    pub failover_events: u32,
}

impl AvailabilityRecord {
    pub fn measured_bps(self) -> Result<u16, RepairError> {
        if self.window_start >= self.window_end || self.probe_assignments == 0 {
            return Err(RepairError::InvalidAvailabilityRecord);
        }
        let served_denominator = self
            .served_heartbeats
            .checked_add(self.failover_events)
            .ok_or(RepairError::ArithmeticOverflow)?;
        if served_denominator == 0 || self.probe_responses > self.probe_assignments {
            return Err(RepairError::InvalidAvailabilityRecord);
        }
        let served_bps = u64::from(self.served_heartbeats).saturating_mul(10_000)
            / u64::from(served_denominator);
        let probe_bps = u64::from(self.probe_responses).saturating_mul(10_000)
            / u64::from(self.probe_assignments);
        // Served work and unpredictable retrieval probes have equal weight.
        u16::try_from((served_bps + probe_bps) / 2).map_err(|_| RepairError::ArithmeticOverflow)
    }

    pub fn class(self) -> Result<AvailabilityClass, RepairError> {
        match self.measured_bps()? {
            9_000..=10_000 => Ok(AvailabilityClass::P90),
            8_000..=8_999 => Ok(AvailabilityClass::P80),
            6_000..=7_999 => Ok(AvailabilityClass::P60),
            3_000..=5_999 => Ok(AvailabilityClass::P30),
            _ => Err(RepairError::BelowCasualFloor),
        }
    }
}

/// Minimum independent replicas such that at least one k-device hearth is
/// online with the requested probability. All arithmetic is deterministic
/// fixed point and rounds failure upward (conservative).
pub fn required_replicas(
    per_device_availability_bps: u16,
    devices_per_hearth: u8,
    completion_target_bps: u16,
) -> Result<u32, RepairError> {
    if per_device_availability_bps > 10_000
        || per_device_availability_bps == 0
        || devices_per_hearth == 0
        || completion_target_bps >= 10_000
    {
        return Err(RepairError::InvalidProbability);
    }
    let mut hearth_online = 10_000u128;
    for _ in 0..devices_per_hearth {
        hearth_online =
            hearth_online.saturating_mul(u128::from(per_device_availability_bps)) / 10_000;
    }
    let hearth_online = hearth_online.min(10_000);
    let offline = 10_000 - hearth_online;
    let maximum_failure =
        PROBABILITY_SCALE.saturating_mul(u128::from(10_000 - completion_target_bps)) / 10_000;
    let mut failure = PROBABILITY_SCALE;
    for replicas in 1..=100_000u32 {
        failure = failure.saturating_mul(offline).div_ceil(10_000);
        if failure <= maximum_failure {
            return Ok(replicas);
        }
    }
    Err(RepairError::ReplicationUnbounded)
}

/// Exact binomial probability for at least `required` available holders,
/// returned in basis points. Inputs are holder availability in basis points.
pub fn reconstruction_probability_bps(
    holders: u8,
    required: u8,
    holder_availability_bps: u16,
) -> Result<u16, RepairError> {
    if holders == 0 || required == 0 || required > holders || holder_availability_bps > 10_000 {
        return Err(RepairError::InvalidProbability);
    }
    let p = u128::from(holder_availability_bps);
    let q = 10_000u128 - p;
    let mut distribution = vec![0u128; usize::from(holders) + 1];
    distribution[0] = PROBABILITY_SCALE;
    for trial in 0..usize::from(holders) {
        let mut next = vec![0u128; distribution.len()];
        for successes in 0..=trial {
            next[successes] =
                next[successes].saturating_add(distribution[successes].saturating_mul(q) / 10_000);
            next[successes + 1] = next[successes + 1]
                .saturating_add(distribution[successes].saturating_mul(p) / 10_000);
        }
        distribution = next;
    }
    let probability = distribution[usize::from(required)..]
        .iter()
        .copied()
        .sum::<u128>();
    u16::try_from(
        probability
            .saturating_mul(10_000)
            .saturating_add(PROBABILITY_SCALE / 2)
            / PROBABILITY_SCALE,
    )
    .map_err(|_| RepairError::ArithmeticOverflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairStage {
    CommitmentCheck,
    ReplicaPromotion,
    ChunkReplay,
    Reseed,
    Recovered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairSession {
    pub job_id: Hash32,
    pub committed_state_root: Hash32,
    pub promoted_replica: Option<Hash32>,
    pub replay_root: Option<Hash32>,
    pub orphaned_shards: u16,
    pub reseeded_shards: u16,
    pub stage: RepairStage,
}

impl RepairSession {
    #[must_use]
    pub fn new(job_id: Hash32, committed_state_root: Hash32, orphaned_shards: u16) -> Self {
        Self {
            job_id,
            committed_state_root,
            promoted_replica: None,
            replay_root: None,
            orphaned_shards,
            reseeded_shards: 0,
            stage: RepairStage::CommitmentCheck,
        }
    }

    pub fn check_departed_commitment(&mut self, observed: Hash32) -> Result<(), RepairError> {
        if self.stage != RepairStage::CommitmentCheck || observed != self.committed_state_root {
            return Err(RepairError::StateCommitmentMismatch);
        }
        self.stage = RepairStage::ReplicaPromotion;
        Ok(())
    }

    pub fn promote_replica(&mut self, replica: Hash32) -> Result<(), RepairError> {
        if self.stage != RepairStage::ReplicaPromotion || replica == [0; 32] {
            return Err(RepairError::InvalidRepairTransition);
        }
        self.promoted_replica = Some(replica);
        self.stage = RepairStage::ChunkReplay;
        Ok(())
    }

    pub fn record_replay(&mut self, replay_root: Hash32) -> Result<(), RepairError> {
        if self.stage != RepairStage::ChunkReplay || replay_root != self.committed_state_root {
            return Err(RepairError::StateCommitmentMismatch);
        }
        self.replay_root = Some(replay_root);
        self.stage = if self.orphaned_shards == 0 {
            RepairStage::Recovered
        } else {
            RepairStage::Reseed
        };
        Ok(())
    }

    pub fn record_reseed(&mut self, shards: u16) -> Result<(), RepairError> {
        if self.stage != RepairStage::Reseed {
            return Err(RepairError::InvalidRepairTransition);
        }
        self.reseeded_shards = self
            .reseeded_shards
            .checked_add(shards)
            .ok_or(RepairError::ArithmeticOverflow)?;
        if self.reseeded_shards >= self.orphaned_shards {
            self.stage = RepairStage::Recovered;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChurnReplayObservation {
    pub availability_bps: u16,
    pub devices_per_hearth: u8,
    pub replicas_used: u32,
    pub modeled_replicas: u32,
    pub jobs: u64,
    pub completed_jobs: u64,
    pub repair_cost: u128,
    pub job_revenue: u128,
}

impl ChurnReplayObservation {
    #[must_use]
    pub fn local_threshold_met(self) -> bool {
        self.jobs > 0
            && self.completed_jobs.saturating_mul(10_000) >= self.jobs.saturating_mul(9_990)
            && self.replicas_used <= self.modeled_replicas.saturating_mul(2)
            && self.repair_cost.saturating_mul(2) <= self.job_revenue.saturating_mul(3)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairError {
    InvalidAvailabilityRecord,
    BelowCasualFloor,
    InvalidProbability,
    ReplicationUnbounded,
    ArithmeticOverflow,
    StateCommitmentMismatch,
    InvalidRepairTransition,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    #[test]
    fn frozen_p03_p06_p09_replication_controls_match_the_ledger() {
        let rows = [
            (3_000, 1, 20),
            (3_000, 2, 74),
            (3_000, 4, 850),
            (6_000, 1, 8),
            (6_000, 2, 16),
            (6_000, 4, 50),
            (9_000, 1, 3),
            (9_000, 2, 5),
            (9_000, 4, 7),
        ];
        for (availability, devices, expected) in rows {
            assert_eq!(
                required_replicas(availability, devices, 9_990).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn custody_probability_matches_the_committed_single_device_case() {
        assert_eq!(reconstruction_probability_bps(12, 8, 9_000).unwrap(), 9_957);
        assert!(reconstruction_probability_bps(12, 8, 6_000).unwrap() < 9_900);
    }

    #[test]
    fn departure_path_is_ordered_and_replay_is_bit_exact() {
        let mut repair = RepairSession::new(h(1), h(2), 3);
        assert_eq!(
            repair.promote_replica(h(3)),
            Err(RepairError::InvalidRepairTransition)
        );
        repair.check_departed_commitment(h(2)).unwrap();
        repair.promote_replica(h(3)).unwrap();
        assert_eq!(
            repair.record_replay(h(9)),
            Err(RepairError::StateCommitmentMismatch)
        );
        repair.record_replay(h(2)).unwrap();
        repair.record_reseed(2).unwrap();
        assert_eq!(repair.stage, RepairStage::Reseed);
        repair.record_reseed(1).unwrap();
        assert_eq!(repair.stage, RepairStage::Recovered);
    }

    #[test]
    fn availability_is_evidence_weighted_and_failovers_decay_class() {
        let strong = AvailabilityRecord {
            hearth_id: h(1),
            window_start: 1,
            window_end: 100,
            served_heartbeats: 99,
            probe_responses: 99,
            probe_assignments: 100,
            failover_events: 1,
        };
        assert_eq!(strong.class().unwrap(), AvailabilityClass::P90);
        let decayed = AvailabilityRecord {
            served_heartbeats: 30,
            failover_events: 70,
            probe_responses: 30,
            ..strong
        };
        assert_eq!(decayed.class().unwrap(), AvailabilityClass::P30);
    }
}
