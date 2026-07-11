//! Non-slashable Hearth V0/V1 household execution, custody, learning, and sealed notebooks.
#![forbid(unsafe_code)]
use noos_species::{Hash32, SpeciesRevision, UpdatePacket};
use std::collections::{BTreeMap, BTreeSet};

pub const WAN_PER_TOKEN_PIPELINE_ENABLED: bool = false;
pub const GENERAL_DREAM_MARKET_ENABLED: bool = false;
pub const FORESIGHT_LIFECYCLE: &str = "EXPERIMENTAL";
pub const FORESIGHT_RESULT: &str = "PAYOUT_FREE_NONAUTHORITATIVE";
pub const FORESIGHT_ENABLED: bool = false;
pub const STATEFUL_PRODUCTION_MIN_AVAILABILITY_BPS: u16 = 9_000;
pub const CASUAL_AVAILABILITY_BPS: u16 = 3_000;
#[must_use]
pub fn domain_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HearthVersion {
    V0,
    V1,
}
impl HearthVersion {
    #[must_use]
    pub fn slashable(self) -> bool {
        false
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HearthState {
    Forming,
    Attesting,
    Active,
    Degraded,
    Retired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    Stage,
    Referee,
    Custody,
    Seeder,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProfile {
    pub device_id: Hash32,
    pub vendor_root: Hash32,
    pub architecture_root: Hash32,
    pub memory_bytes: u64,
    pub measured_bandwidth_bps: u64,
    pub measured_int8_ops: u64,
    pub conformance_root: Hash32,
    pub roles: BTreeSet<DeviceRole>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageAssignment {
    pub start_layer: u32,
    pub end_layer: u32,
    pub device_id: Hash32,
    pub memory_required: u64,
    pub boundary_bytes: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionPlan {
    pub plan_id: Hash32,
    pub hearth_id: Hash32,
    pub generation: u64,
    pub assignments: Vec<StageAssignment>,
    pub signer: Hash32,
    pub signature: [u8; 64],
}
impl PartitionPlan {
    pub fn validate(&self, devices: &BTreeMap<Hash32, DeviceProfile>) -> Result<(), HearthError> {
        if self.assignments.is_empty() || self.signature == [0; 64] {
            return Err(HearthError::InvalidSignedPlan);
        }
        let mut expected = 0;
        for a in &self.assignments {
            let d = devices
                .get(&a.device_id)
                .ok_or(HearthError::UnknownDevice)?;
            if a.start_layer != expected
                || a.end_layer < a.start_layer
                || a.memory_required > d.memory_bytes
                || a.boundary_bytes > 8192
            {
                return Err(HearthError::InvalidPartition);
            }
            expected = a
                .end_layer
                .checked_add(1)
                .ok_or(HearthError::InvalidPartition)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HearthManifest {
    pub hearth_id: Hash32,
    pub external_identity: Hash32,
    pub bond_account: Hash32,
    pub fault_stream: Hash32,
    pub payout_stream: Hash32,
    pub version: HearthVersion,
    pub devices: BTreeMap<Hash32, DeviceProfile>,
    pub partition: PartitionPlan,
    pub profile_root: Hash32,
    pub model_roots: BTreeSet<Hash32>,
    pub availability_bps: u16,
    pub boundary_commitment_policy: Hash32,
    pub uplink_bps: u64,
    pub locality_rtt_ms: u32,
    pub state: HearthState,
    pub generation: u64,
    pub signer: Hash32,
    pub signature: [u8; 64],
}
impl HearthManifest {
    pub fn validate(&self) -> Result<(), HearthError> {
        if self.hearth_id != self.external_identity
            || self.signature == [0; 64]
            || self.availability_bps > 10_000
        {
            return Err(HearthError::OneHouseholdOneStreamViolation);
        }
        if self.bond_account == [0; 32]
            || self.fault_stream == [0; 32]
            || self.payout_stream == [0; 32]
        {
            return Err(HearthError::OneHouseholdOneStreamViolation);
        }
        if self.partition.hearth_id != self.hearth_id
            || self.partition.generation != self.generation
            || self.partition.signer != self.signer
        {
            return Err(HearthError::InvalidSignedPlan);
        }
        self.partition.validate(&self.devices)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobShape {
    Interactive,
    Replica,
    WanBatch,
    Stateless,
    Reissueable,
    StatefulCustody,
    ChorusAdvisory,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    LanInteractive,
    WanReplica,
    WanBatch,
    RelayFallback,
    ManySourceSeeding,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConditions {
    pub hops: u8,
    pub rtt_ms: u32,
    pub direct_reachable: bool,
    pub is_seeding: bool,
}
pub fn route(job: JobShape, net: NetworkConditions) -> Result<Route, HearthError> {
    if net.is_seeding {
        return Ok(Route::ManySourceSeeding);
    }
    match job {
        JobShape::Interactive if net.hops == 0 => Ok(Route::LanInteractive),
        JobShape::Interactive if net.hops >= 2 && net.rtt_ms >= 50 => {
            Err(HearthError::FeatureDisabled {
                feature: "wan_per_token_pipeline",
                evidence: "E-HEARTH-05",
            })
        }
        JobShape::Interactive => Err(HearthError::InteractiveMustRemainLan),
        JobShape::Replica => {
            if net.direct_reachable {
                Ok(Route::WanReplica)
            } else {
                Ok(Route::RelayFallback)
            }
        }
        JobShape::WanBatch => {
            if net.direct_reachable {
                Ok(Route::WanBatch)
            } else {
                Ok(Route::RelayFallback)
            }
        }
        JobShape::Stateless | JobShape::Reissueable | JobShape::ChorusAdvisory => {
            if net.direct_reachable {
                Ok(Route::WanReplica)
            } else {
                Ok(Route::RelayFallback)
            }
        }
        JobShape::StatefulCustody => {
            if net.direct_reachable {
                Ok(Route::WanBatch)
            } else {
                Ok(Route::RelayFallback)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyRole {
    StatefulProduction,
    StatelessReissueable,
    ChorusAdvisory,
}
pub fn admit_custody(
    availability_bps: u16,
    role: CustodyRole,
    hearth03_gate_passed: bool,
) -> Result<(), HearthError> {
    if availability_bps > 10_000 {
        return Err(HearthError::InvalidAvailability);
    }
    match role {
        CustodyRole::StatefulProduction
            if !hearth03_gate_passed
                && availability_bps < STATEFUL_PRODUCTION_MIN_AVAILABILITY_BPS =>
        {
            Err(HearthError::AvailabilityClassIneligible)
        }
        CustodyRole::StatelessReissueable | CustodyRole::ChorusAdvisory
            if availability_bps >= CASUAL_AVAILABILITY_BPS =>
        {
            Ok(())
        }
        CustodyRole::StatefulProduction => Ok(()),
        _ => Err(HearthError::AvailabilityClassIneligible),
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentShard {
    pub artifact_root: Hash32,
    pub shard_index: u16,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub bytes_root: Hash32,
    pub holder_hearth: Hash32,
}
#[derive(Debug, Default)]
pub struct CustodySet {
    shards: BTreeMap<(Hash32, u16), ContentShard>,
    corrupt: BTreeSet<(Hash32, u16)>,
}
impl CustodySet {
    pub fn insert(&mut self, s: ContentShard) -> Result<(), HearthError> {
        if s.data_shards == 0
            || s.shard_index
                >= s.data_shards
                    .checked_add(s.parity_shards)
                    .ok_or(HearthError::InvalidShard)?
        {
            return Err(HearthError::InvalidShard);
        }
        let key = (s.artifact_root, s.shard_index);
        if self.shards.contains_key(&key) {
            return Err(HearthError::DuplicateShard);
        }
        self.shards.insert(key, s);
        Ok(())
    }
    pub fn mark_corrupt(
        &mut self,
        root: Hash32,
        index: u16,
        observed: Hash32,
    ) -> Result<(), HearthError> {
        let key = (root, index);
        let shard = self.shards.get(&key).ok_or(HearthError::InvalidShard)?;
        if shard.bytes_root == observed {
            return Err(HearthError::FalseCorruptionReport);
        }
        self.corrupt.insert(key);
        Err(HearthError::CorruptShardRejected)
    }
    #[must_use]
    pub fn reconstructible(&self, root: Hash32) -> bool {
        let Some(sample) = self.shards.values().find(|s| s.artifact_root == root) else {
            return false;
        };
        self.shards
            .keys()
            .filter(|(r, i)| *r == root && !self.corrupt.contains(&(*r, *i)))
            .count()
            >= usize::from(sample.data_shards)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableLearningRecord {
    pub record_id: Hash32,
    pub packet_id: Hash32,
    pub base_revision: Hash32,
    pub evidence_root: Hash32,
    pub promoted_revision: Hash32,
}
pub fn validate_promotion(
    packet: &UpdatePacket,
    base: &SpeciesRevision,
    promoted: &SpeciesRevision,
    record: &ImmutableLearningRecord,
) -> Result<(), HearthError> {
    if packet.packet_id != record.packet_id
        || base.revision_id != record.base_revision
        || promoted.revision_id != record.promoted_revision
        || base.revision_id == promoted.revision_id
        || base.species_id != promoted.species_id
        || !packet.base_members.contains(&base.revision_id)
    {
        return Err(HearthError::PromotionRequiresNewSpeciesRevision);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotebookState {
    Preregistered,
    Committed,
    Revealed,
    Invalidated,
    Expired,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedNotebook {
    pub notebook_id: Hash32,
    pub owner: Hash32,
    pub trial_root: Hash32,
    pub outcome_definition_root: Hash32,
    pub branch_commitment: Hash32,
    pub realization_nullifier: Hash32,
    pub reveal_deadline: u64,
    pub payout: u128,
    pub authoritative: bool,
    pub causally_insulated: bool,
    pub firewall_root: Hash32,
    pub state: NotebookState,
}
impl SealedNotebook {
    pub fn validate(&self) -> Result<(), HearthError> {
        if self.payout != 0 || self.authoritative {
            return Err(HearthError::DreamMarketKilled);
        }
        if !self.causally_insulated
            || self.firewall_root == [0; 32]
            || self.trial_root == [0; 32]
            || self.outcome_definition_root == [0; 32]
            || self.branch_commitment == [0; 32]
            || self.realization_nullifier == [0; 32]
        {
            return Err(HearthError::CausalInsulationRequired);
        }
        Ok(())
    }
    pub fn reveal(
        &mut self,
        nullifiers: &mut BTreeSet<Hash32>,
        height: u64,
    ) -> Result<(), HearthError> {
        self.validate()?;
        if self.state != NotebookState::Committed || height > self.reveal_deadline {
            return Err(HearthError::RevealDeadline);
        }
        if !nullifiers.insert(self.realization_nullifier) {
            self.state = NotebookState::Invalidated;
            return Err(HearthError::RealizationAlreadyUsed);
        }
        self.state = NotebookState::Revealed;
        Ok(())
    }
    pub fn influence_action(&mut self) -> Result<(), HearthError> {
        self.state = NotebookState::Invalidated;
        Err(HearthError::ActionFirewall)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HouseholdStreams {
    external_identity: Hash32,
    bond_account: Hash32,
    fault_stream: Hash32,
    payout_stream: Hash32,
}

#[derive(Debug, Default)]
pub struct HearthRegistry {
    manifests: BTreeMap<(Hash32, u64), HearthManifest>,
    household_streams: BTreeMap<Hash32, HouseholdStreams>,
}

impl HearthRegistry {
    pub fn register_manifest(&mut self, manifest: HearthManifest) -> Result<(), HearthError> {
        manifest.validate()?;
        let streams = HouseholdStreams {
            external_identity: manifest.external_identity,
            bond_account: manifest.bond_account,
            fault_stream: manifest.fault_stream,
            payout_stream: manifest.payout_stream,
        };
        if self
            .household_streams
            .get(&manifest.hearth_id)
            .is_some_and(|existing| *existing != streams)
        {
            return Err(HearthError::OneHouseholdOneStreamViolation);
        }
        let key = (manifest.hearth_id, manifest.generation);
        if self.manifests.contains_key(&key) {
            return Err(HearthError::ImmutableManifest);
        }
        self.household_streams
            .entry(manifest.hearth_id)
            .or_insert(streams);
        self.manifests.insert(key, manifest);
        Ok(())
    }

    #[must_use]
    pub fn manifest(&self, hearth_id: Hash32, generation: u64) -> Option<&HearthManifest> {
        self.manifests.get(&(hearth_id, generation))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HearthError {
    OneHouseholdOneStreamViolation,
    ImmutableManifest,
    InvalidSignedPlan,
    InvalidPartition,
    UnknownDevice,
    InvalidAvailability,
    AvailabilityClassIneligible,
    InvalidShard,
    DuplicateShard,
    CorruptShardRejected,
    FalseCorruptionReport,
    PromotionRequiresNewSpeciesRevision,
    DreamMarketKilled,
    CausalInsulationRequired,
    RevealDeadline,
    RealizationAlreadyUsed,
    ActionFirewall,
    InteractiveMustRemainLan,
    FeatureDisabled {
        feature: &'static str,
        evidence: &'static str,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants)]
    use super::*;
    fn h(n: u8) -> Hash32 {
        [n; 32]
    }
    #[test]
    fn v0_v1_are_non_slashable() {
        assert!(!HearthVersion::V0.slashable());
        assert!(!HearthVersion::V1.slashable());
    }
    #[test]
    fn wan_interactive_pipeline_fails_explicitly() {
        assert_eq!(
            route(
                JobShape::Interactive,
                NetworkConditions {
                    hops: 2,
                    rtt_ms: 50,
                    direct_reachable: true,
                    is_seeding: false
                }
            ),
            Err(HearthError::FeatureDisabled {
                feature: "wan_per_token_pipeline",
                evidence: "E-HEARTH-05"
            })
        );
    }
    #[test]
    fn lan_interactive_and_wan_replica_route() {
        assert_eq!(
            route(
                JobShape::Interactive,
                NetworkConditions {
                    hops: 0,
                    rtt_ms: 1,
                    direct_reachable: true,
                    is_seeding: false
                }
            ),
            Ok(Route::LanInteractive)
        );
        assert_eq!(
            route(
                JobShape::Replica,
                NetworkConditions {
                    hops: 3,
                    rtt_ms: 80,
                    direct_reachable: true,
                    is_seeding: false
                }
            ),
            Ok(Route::WanReplica)
        );
    }
    #[test]
    fn relay_and_seeding_are_real_routes() {
        assert_eq!(
            route(
                JobShape::WanBatch,
                NetworkConditions {
                    hops: 2,
                    rtt_ms: 50,
                    direct_reachable: false,
                    is_seeding: false
                }
            ),
            Ok(Route::RelayFallback)
        );
        assert_eq!(
            route(
                JobShape::WanBatch,
                NetworkConditions {
                    hops: 2,
                    rtt_ms: 50,
                    direct_reachable: false,
                    is_seeding: true
                }
            ),
            Ok(Route::ManySourceSeeding)
        );
    }
    #[test]
    fn casual_is_not_stateful_before_gate() {
        assert_eq!(
            admit_custody(3_000, CustodyRole::StatefulProduction, false),
            Err(HearthError::AvailabilityClassIneligible)
        );
        assert!(admit_custody(3_000, CustodyRole::StatelessReissueable, false).is_ok());
        assert!(admit_custody(9_000, CustodyRole::StatefulProduction, false).is_ok());
    }
    #[test]
    fn corrupt_shard_is_rejected() {
        let mut c = CustodySet::default();
        assert!(c
            .insert(ContentShard {
                artifact_root: h(1),
                shard_index: 0,
                data_shards: 1,
                parity_shards: 1,
                bytes_root: h(2),
                holder_hearth: h(3)
            })
            .is_ok());
        assert_eq!(
            c.mark_corrupt(h(1), 0, h(9)),
            Err(HearthError::CorruptShardRejected)
        );
        assert!(!c.reconstructible(h(1)));
    }
    fn notebook() -> SealedNotebook {
        SealedNotebook {
            notebook_id: h(1),
            owner: h(2),
            trial_root: h(3),
            outcome_definition_root: h(4),
            branch_commitment: h(5),
            realization_nullifier: h(6),
            reveal_deadline: 10,
            payout: 0,
            authoritative: false,
            causally_insulated: true,
            firewall_root: h(7),
            state: NotebookState::Committed,
        }
    }
    #[test]
    fn dream_market_payout_is_killed() {
        let mut n = notebook();
        n.payout = 1;
        assert_eq!(n.validate(), Err(HearthError::DreamMarketKilled));
    }
    #[test]
    fn realization_nullifier_is_one_shot() {
        let mut n = notebook();
        let mut used = BTreeSet::new();
        assert!(n.reveal(&mut used, 5).is_ok());
        let mut other = notebook();
        assert_eq!(
            other.reveal(&mut used, 5),
            Err(HearthError::RealizationAlreadyUsed)
        );
    }
    #[test]
    fn notebook_cannot_authorize_action() {
        let mut n = notebook();
        assert_eq!(n.influence_action(), Err(HearthError::ActionFirewall));
        assert_eq!(n.state, NotebookState::Invalidated);
    }
    #[test]
    fn foresight_is_payout_free_nonauthoritative_and_disabled() {
        assert_eq!(FORESIGHT_LIFECYCLE, "EXPERIMENTAL");
        assert_eq!(FORESIGHT_RESULT, "PAYOUT_FREE_NONAUTHORITATIVE");
        assert!(!FORESIGHT_ENABLED);
        let mut n = notebook();
        n.branch_commitment = [0; 32];
        assert_eq!(n.validate(), Err(HearthError::CausalInsulationRequired));
    }
}
