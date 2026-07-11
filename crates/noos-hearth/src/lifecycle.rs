//! Hearth membership, partitioning, boundary commitments, and exit lifecycle.
#![allow(clippy::arithmetic_side_effects)]

use crate::{domain_hash, DeviceProfile, DeviceRole, HearthError, HearthManifest, HearthState};
use noos_species::Hash32;
use std::collections::{BTreeMap, BTreeSet};

/// One whole transformer layer. Cuts inside a layer are deliberately impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerEnvelope {
    pub weight_bytes: u64,
    pub working_set_bytes: u64,
    pub boundary_bytes: u32,
}

/// A deterministic auto-plan result. `bottleneck_time_units` is proportional
/// to bytes/bandwidth and is compared without floating point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoPartition {
    pub stage_devices: Vec<Hash32>,
    pub cuts: Vec<(u32, u32)>,
    pub bottleneck_time_units: u128,
    pub referee_devices: BTreeSet<Hash32>,
}

/// Exhaustively finds the best contiguous whole-layer assignment for the
/// declared device order. This is scheduler policy, not a consensus rule.
pub fn auto_partition(
    layers: &[LayerEnvelope],
    devices: &[DeviceProfile],
) -> Result<AutoPartition, HearthError> {
    if layers.is_empty() || devices.is_empty() || devices.len() > layers.len() {
        return Err(HearthError::InvalidPartition);
    }
    let stage_devices = devices
        .iter()
        .filter(|d| d.roles.contains(&DeviceRole::Stage) && d.measured_bandwidth_bps > 0)
        .collect::<Vec<_>>();
    if stage_devices.is_empty() || stage_devices.len() > layers.len() {
        return Err(HearthError::InvalidPartition);
    }
    let mut best: Option<(u128, Vec<(u32, u32)>)> = None;
    search_cuts(layers, &stage_devices, 0, 0, &mut Vec::new(), &mut best)?;
    let (bottleneck_time_units, cuts) = best.ok_or(HearthError::InvalidPartition)?;
    let used = stage_devices
        .iter()
        .map(|d| d.device_id)
        .collect::<BTreeSet<_>>();
    let referee_devices = devices
        .iter()
        .filter(|d| !used.contains(&d.device_id) || d.roles.contains(&DeviceRole::Referee))
        .map(|d| d.device_id)
        .collect();
    Ok(AutoPartition {
        stage_devices: stage_devices.iter().map(|d| d.device_id).collect(),
        cuts,
        bottleneck_time_units,
        referee_devices,
    })
}

fn search_cuts(
    layers: &[LayerEnvelope],
    devices: &[&DeviceProfile],
    device_index: usize,
    layer_start: usize,
    cuts: &mut Vec<(u32, u32)>,
    best: &mut Option<(u128, Vec<(u32, u32)>)>,
) -> Result<(), HearthError> {
    let remaining_devices = devices.len() - device_index;
    if remaining_devices == 1 {
        let end = layers.len() - 1;
        if let Some(cost) = stage_cost(&layers[layer_start..=end], devices[device_index]) {
            cuts.push((
                u32::try_from(layer_start).map_err(|_| HearthError::InvalidPartition)?,
                u32::try_from(end).map_err(|_| HearthError::InvalidPartition)?,
            ));
            let bottleneck = plan_cost(layers, devices, cuts)?;
            if best.as_ref().is_none_or(|(prior, _)| bottleneck < *prior) {
                *best = Some((bottleneck, cuts.clone()));
            }
            cuts.pop();
            let _ = cost;
        }
        return Ok(());
    }
    let last_end = layers.len() - remaining_devices;
    for end in layer_start..=last_end {
        if stage_cost(&layers[layer_start..=end], devices[device_index]).is_none() {
            continue;
        }
        cuts.push((
            u32::try_from(layer_start).map_err(|_| HearthError::InvalidPartition)?,
            u32::try_from(end).map_err(|_| HearthError::InvalidPartition)?,
        ));
        search_cuts(layers, devices, device_index + 1, end + 1, cuts, best)?;
        cuts.pop();
    }
    Ok(())
}

fn stage_cost(layers: &[LayerEnvelope], device: &DeviceProfile) -> Option<u128> {
    let bytes = layers.iter().try_fold(0u64, |sum, layer| {
        sum.checked_add(layer.weight_bytes)?
            .checked_add(layer.working_set_bytes)
    })?;
    if bytes > device.memory_bytes || device.measured_bandwidth_bps == 0 {
        return None;
    }
    Some(
        u128::from(bytes)
            .saturating_mul(1_000_000_000)
            .div_ceil(u128::from(device.measured_bandwidth_bps)),
    )
}

fn plan_cost(
    layers: &[LayerEnvelope],
    devices: &[&DeviceProfile],
    cuts: &[(u32, u32)],
) -> Result<u128, HearthError> {
    cuts.iter()
        .zip(devices)
        .map(|(&(start, end), device)| {
            let start = usize::try_from(start).map_err(|_| HearthError::InvalidPartition)?;
            let end = usize::try_from(end).map_err(|_| HearthError::InvalidPartition)?;
            stage_cost(&layers[start..=end], device).ok_or(HearthError::InvalidPartition)
        })
        .try_fold(0, |max, cost| cost.map(|value| max.max(value)))
}

/// Integer boundary commitment bound to the plan generation and exact bytes.
#[must_use]
pub fn boundary_commitment(
    hearth_id: Hash32,
    generation: u64,
    boundary_layer: u32,
    activation: &[u8],
) -> Hash32 {
    domain_hash(
        "NOOS/HEARTH/BOUNDARY/V1",
        &[
            &hearth_id,
            &generation.to_le_bytes(),
            &boundary_layer.to_le_bytes(),
            &(activation.len() as u64).to_le_bytes(),
            activation,
        ],
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceRun {
    pub profile_root: Hash32,
    pub model_root: Hash32,
    pub device_roots: BTreeMap<Hash32, Hash32>,
    pub operator_instances: u64,
    pub boundary_mismatches: u64,
    pub fp16_control_diverged: bool,
    pub profile_time_ns: u64,
    pub fp16_time_ns: u64,
    pub auto_plan_time_ns: u64,
    pub hand_tuned_time_ns: u64,
}

impl ConformanceRun {
    pub fn validate_local_precursor(&self) -> Result<(), LifecycleError> {
        if self.profile_root == [0; 32]
            || self.model_root == [0; 32]
            || self.device_roots.len() < 2
            || self.device_roots.values().any(|root| *root == [0; 32])
            || self.operator_instances == 0
        {
            return Err(LifecycleError::IncompleteConformance);
        }
        if self.boundary_mismatches != 0 {
            return Err(LifecycleError::IntegerMismatch);
        }
        if !self.fp16_control_diverged {
            return Err(LifecycleError::PowerlessNegativeControl);
        }
        if self.profile_time_ns > self.fp16_time_ns.saturating_mul(2) {
            return Err(LifecycleError::ThroughputEconomicsFailed);
        }
        // Throughput is inverse time: >=70% of best means auto time <= hand/0.7.
        if u128::from(self.auto_plan_time_ns).saturating_mul(7)
            > u128::from(self.hand_tuned_time_ns).saturating_mul(10)
        {
            return Err(LifecycleError::PartitionQualityFailed);
        }
        Ok(())
    }

    #[must_use]
    pub fn external_threshold_met(&self) -> bool {
        self.operator_instances >= 1_000_000_000
            && self.device_roots.len() >= 3
            && self.validate_local_precursor().is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScheduleKey {
    pub placement: Vec<Hash32>,
    pub split_k: u16,
    pub batch_size: u16,
    pub thread_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleObservation {
    pub boundary_roots: Vec<Hash32>,
    pub final_root: Hash32,
    pub operator_instances: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceMatrix {
    pub devices: Vec<Hash32>,
    pub split_k_values: Vec<u16>,
    pub batch_sizes: Vec<u16>,
    pub thread_counts: Vec<u16>,
    pub cpu_reference: ScheduleObservation,
    pub observations: BTreeMap<ScheduleKey, ScheduleObservation>,
    pub fp16_final_roots: BTreeSet<Hash32>,
}

impl ConformanceMatrix {
    pub fn validate_complete(&self) -> Result<u64, LifecycleError> {
        if self.devices.len() < 3
            || self.split_k_values.is_empty()
            || self.batch_sizes.is_empty()
            || self.thread_counts.is_empty()
            || self.cpu_reference.boundary_roots.is_empty()
        {
            return Err(LifecycleError::IncompleteConformance);
        }
        let placements = permutations(&self.devices);
        let expected_cells = placements
            .len()
            .saturating_mul(self.split_k_values.len())
            .saturating_mul(self.batch_sizes.len())
            .saturating_mul(self.thread_counts.len());
        if self.observations.len() != expected_cells {
            return Err(LifecycleError::IncompleteConformance);
        }
        let mut instances = 0u64;
        for placement in placements {
            for &split_k in &self.split_k_values {
                for &batch_size in &self.batch_sizes {
                    for &thread_count in &self.thread_counts {
                        let key = ScheduleKey {
                            placement: placement.clone(),
                            split_k,
                            batch_size,
                            thread_count,
                        };
                        let observation = self
                            .observations
                            .get(&key)
                            .ok_or(LifecycleError::IncompleteConformance)?;
                        if observation.boundary_roots != self.cpu_reference.boundary_roots
                            || observation.final_root != self.cpu_reference.final_root
                        {
                            return Err(LifecycleError::IntegerMismatch);
                        }
                        instances = instances
                            .checked_add(observation.operator_instances)
                            .ok_or(LifecycleError::IncompleteConformance)?;
                    }
                }
            }
        }
        if self.fp16_final_roots.len() < 2 {
            return Err(LifecycleError::PowerlessNegativeControl);
        }
        Ok(instances)
    }
}

fn permutations(values: &[Hash32]) -> Vec<Vec<Hash32>> {
    fn visit(prefix: &mut Vec<Hash32>, remaining: &mut Vec<Hash32>, out: &mut Vec<Vec<Hash32>>) {
        if remaining.is_empty() {
            out.push(prefix.clone());
            return;
        }
        for index in 0..remaining.len() {
            let value = remaining.remove(index);
            prefix.push(value);
            visit(prefix, remaining, out);
            prefix.pop();
            remaining.insert(index, value);
        }
    }
    let mut out = Vec::new();
    visit(&mut Vec::new(), &mut values.to_vec(), &mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lifecycle {
    pub state: HearthState,
    pub generation: u64,
    pub plan_id: Hash32,
    pub attested_devices: BTreeSet<Hash32>,
    pub departing_devices: BTreeSet<Hash32>,
    pub last_challenge_end: Option<u64>,
    pub custody_obligations: u32,
    pub bond_posted: bool,
}

impl Lifecycle {
    pub fn forming(manifest: &HearthManifest) -> Result<Self, LifecycleError> {
        manifest.validate().map_err(LifecycleError::Manifest)?;
        Ok(Self {
            state: HearthState::Forming,
            generation: manifest.generation,
            plan_id: manifest.partition.plan_id,
            attested_devices: BTreeSet::new(),
            departing_devices: BTreeSet::new(),
            last_challenge_end: None,
            custody_obligations: 0,
            bond_posted: false,
        })
    }

    pub fn begin_attestation(
        &mut self,
        manifest: &HearthManifest,
        bond_posted: bool,
    ) -> Result<(), LifecycleError> {
        if !matches!(self.state, HearthState::Forming | HearthState::Degraded)
            || manifest.generation < self.generation
        {
            return Err(LifecycleError::InvalidTransition);
        }
        manifest.validate().map_err(LifecycleError::Manifest)?;
        if self.state == HearthState::Degraded && manifest.generation <= self.generation {
            return Err(LifecycleError::StalePlan);
        }
        self.generation = manifest.generation;
        self.plan_id = manifest.partition.plan_id;
        self.bond_posted = bond_posted;
        self.attested_devices.clear();
        self.state = HearthState::Attesting;
        Ok(())
    }

    pub fn attest_device(
        &mut self,
        device: &DeviceProfile,
        observed_root: Hash32,
    ) -> Result<(), LifecycleError> {
        if self.state != HearthState::Attesting || device.conformance_root != observed_root {
            return Err(LifecycleError::ConformanceFailed);
        }
        self.attested_devices.insert(device.device_id);
        Ok(())
    }

    pub fn activate(&mut self, manifest: &HearthManifest) -> Result<(), LifecycleError> {
        let required = manifest
            .partition
            .assignments
            .iter()
            .map(|stage| stage.device_id)
            .collect::<BTreeSet<_>>();
        if self.state != HearthState::Attesting
            || !self.bond_posted
            || self.generation != manifest.generation
            || !required.is_subset(&self.attested_devices)
        {
            return Err(LifecycleError::IncompleteConformance);
        }
        self.departing_devices.clear();
        self.state = HearthState::Active;
        Ok(())
    }

    pub fn degrade(&mut self, departed: Hash32) -> Result<(), LifecycleError> {
        if self.state != HearthState::Active {
            return Err(LifecycleError::InvalidTransition);
        }
        self.departing_devices.insert(departed);
        self.state = HearthState::Degraded;
        Ok(())
    }

    pub fn record_obligations(&mut self, challenge_end: u64, custody: u32) {
        self.last_challenge_end = Some(
            self.last_challenge_end
                .map_or(challenge_end, |prior| prior.max(challenge_end)),
        );
        self.custody_obligations = self.custody_obligations.saturating_add(custody);
    }

    pub fn handoff_custody(&mut self, count: u32) -> Result<(), LifecycleError> {
        self.custody_obligations = self
            .custody_obligations
            .checked_sub(count)
            .ok_or(LifecycleError::CustodyOutstanding)?;
        Ok(())
    }

    pub fn retire(&mut self, height: u64) -> Result<(), LifecycleError> {
        if !matches!(self.state, HearthState::Active | HearthState::Degraded)
            || self.custody_obligations != 0
            || self.last_challenge_end.is_some_and(|end| height <= end)
        {
            return Err(LifecycleError::CustodyOutstanding);
        }
        self.state = HearthState::Retired;
        self.bond_posted = false;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    Manifest(HearthError),
    InvalidTransition,
    StalePlan,
    ConformanceFailed,
    IncompleteConformance,
    IntegerMismatch,
    PowerlessNegativeControl,
    ThroughputEconomicsFailed,
    PartitionQualityFailed,
    CustodyOutstanding,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{HearthVersion, PartitionPlan, StageAssignment};

    fn h(byte: u8) -> Hash32 {
        [byte; 32]
    }

    fn device(id: u8, bandwidth: u64, memory: u64, roles: &[DeviceRole]) -> DeviceProfile {
        DeviceProfile {
            device_id: h(id),
            vendor_root: h(id + 20),
            architecture_root: h(id + 30),
            memory_bytes: memory,
            measured_bandwidth_bps: bandwidth,
            measured_int8_ops: bandwidth,
            conformance_root: h(id + 40),
            roles: roles.iter().copied().collect(),
        }
    }

    fn manifest(generation: u64) -> HearthManifest {
        let devices = BTreeMap::from([
            (h(1), device(1, 100, 1_000, &[DeviceRole::Stage])),
            (h(2), device(2, 200, 1_000, &[DeviceRole::Stage])),
        ]);
        HearthManifest {
            hearth_id: h(9),
            external_identity: h(9),
            bond_account: h(10),
            fault_stream: h(11),
            payout_stream: h(12),
            version: HearthVersion::V1,
            devices,
            partition: PartitionPlan {
                plan_id: h(generation as u8),
                hearth_id: h(9),
                generation,
                assignments: vec![
                    StageAssignment {
                        start_layer: 0,
                        end_layer: 0,
                        device_id: h(1),
                        memory_required: 100,
                        boundary_bytes: 64,
                    },
                    StageAssignment {
                        start_layer: 1,
                        end_layer: 1,
                        device_id: h(2),
                        memory_required: 100,
                        boundary_bytes: 64,
                    },
                ],
                signer: h(13),
                signature: [1; 64],
            },
            profile_root: h(14),
            model_roots: BTreeSet::from([h(15)]),
            availability_bps: 9_000,
            boundary_commitment_policy: h(16),
            uplink_bps: 20_000_000,
            locality_rtt_ms: 10,
            state: HearthState::Forming,
            generation,
            signer: h(13),
            signature: [2; 64],
        }
    }

    #[test]
    fn optimal_partitioner_respects_memory_and_keeps_referee_out_of_pipeline() {
        let layers = vec![
            LayerEnvelope {
                weight_bytes: 90,
                working_set_bytes: 10,
                boundary_bytes: 64,
            },
            LayerEnvelope {
                weight_bytes: 90,
                working_set_bytes: 10,
                boundary_bytes: 64,
            },
            LayerEnvelope {
                weight_bytes: 190,
                working_set_bytes: 10,
                boundary_bytes: 64,
            },
        ];
        let devices = vec![
            device(1, 100, 250, &[DeviceRole::Stage]),
            device(2, 200, 250, &[DeviceRole::Stage]),
            device(3, 20, 250, &[DeviceRole::Referee]),
        ];
        let plan = auto_partition(&layers, &devices).unwrap();
        assert_eq!(plan.cuts, vec![(0, 1), (2, 2)]);
        assert!(plan.referee_devices.contains(&h(3)));
    }

    #[test]
    fn conformance_falsifiers_are_separate_from_economics() {
        let mut run = ConformanceRun {
            profile_root: h(1),
            model_root: h(2),
            device_roots: BTreeMap::from([(h(3), h(4)), (h(5), h(6)), (h(7), h(8))]),
            operator_instances: 10_000,
            boundary_mismatches: 0,
            fp16_control_diverged: true,
            profile_time_ns: 150,
            fp16_time_ns: 100,
            auto_plan_time_ns: 120,
            hand_tuned_time_ns: 100,
        };
        assert!(run.validate_local_precursor().is_ok());
        assert!(!run.external_threshold_met());
        run.boundary_mismatches = 1;
        assert_eq!(
            run.validate_local_precursor(),
            Err(LifecycleError::IntegerMismatch)
        );
        run.boundary_mismatches = 0;
        run.fp16_control_diverged = false;
        assert_eq!(
            run.validate_local_precursor(),
            Err(LifecycleError::PowerlessNegativeControl)
        );
    }

    #[test]
    fn conformance_matrix_requires_every_placement_and_adversarial_schedule_cell() {
        let devices = vec![h(1), h(2), h(3)];
        let reference = ScheduleObservation {
            boundary_roots: vec![h(10), h(11)],
            final_root: h(12),
            operator_instances: 0,
        };
        let mut observations = BTreeMap::new();
        for placement in permutations(&devices) {
            for split_k in [1, 7] {
                for batch_size in [1, 8] {
                    for thread_count in [1, 16] {
                        observations.insert(
                            ScheduleKey {
                                placement: placement.clone(),
                                split_k,
                                batch_size,
                                thread_count,
                            },
                            ScheduleObservation {
                                operator_instances: 100,
                                ..reference.clone()
                            },
                        );
                    }
                }
            }
        }
        let mut matrix = ConformanceMatrix {
            devices,
            split_k_values: vec![1, 7],
            batch_sizes: vec![1, 8],
            thread_counts: vec![1, 16],
            cpu_reference: reference,
            observations,
            fp16_final_roots: BTreeSet::from([h(20), h(21)]),
        };
        assert_eq!(matrix.validate_complete().unwrap(), 4_800);
        let first = matrix.observations.values_mut().next().unwrap();
        first.boundary_roots[0] = h(99);
        assert_eq!(
            matrix.validate_complete(),
            Err(LifecycleError::IntegerMismatch)
        );
    }

    #[test]
    fn lifecycle_requires_replan_reattest_challenge_close_and_custody_handoff() {
        let first = manifest(1);
        let mut lifecycle = Lifecycle::forming(&first).unwrap();
        lifecycle.begin_attestation(&first, true).unwrap();
        for device in first.devices.values() {
            lifecycle
                .attest_device(device, device.conformance_root)
                .unwrap();
        }
        lifecycle.activate(&first).unwrap();
        lifecycle.record_obligations(50, 2);
        lifecycle.degrade(h(2)).unwrap();
        assert_eq!(
            lifecycle.retire(51),
            Err(LifecycleError::CustodyOutstanding)
        );
        let second = manifest(2);
        lifecycle.begin_attestation(&second, true).unwrap();
        for device in second.devices.values() {
            lifecycle
                .attest_device(device, device.conformance_root)
                .unwrap();
        }
        lifecycle.activate(&second).unwrap();
        lifecycle.handoff_custody(2).unwrap();
        assert_eq!(
            lifecycle.retire(50),
            Err(LifecycleError::CustodyOutstanding)
        );
        lifecycle.retire(51).unwrap();
        assert_eq!(lifecycle.state, HearthState::Retired);
    }

    #[test]
    fn boundary_commitment_binds_generation_layer_and_bytes() {
        let base = boundary_commitment(h(1), 3, 7, &[1, 2, 3]);
        assert_ne!(base, boundary_commitment(h(1), 4, 7, &[1, 2, 3]));
        assert_ne!(base, boundary_commitment(h(1), 3, 8, &[1, 2, 3]));
        assert_ne!(base, boundary_commitment(h(1), 3, 7, &[1, 2, 4]));
    }
}
