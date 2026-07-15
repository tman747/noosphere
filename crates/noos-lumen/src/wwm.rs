//! Protocol-v2 World Wide Model (WWM) consensus objects and payload codecs.
//!
//! These types contain bounded identities, policy, custody, receipts, controls,
//! and settlement only. Model weights, prompts, token streams, and model output
//! are deliberately not representable here.

use crate::{
    domain_hash,
    objects::{BoundedBytes, BoundedList, OptionalHash32, OptionalObject},
    smt::SmtProof,
    Hash32,
};
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};

pub const MAX_PROFILE_BYTES: usize = 512;
pub const MAX_CAPABILITY_SET_BYTES: usize = 18_432;
pub const MAX_AUTHORIZED_CONFIG_BYTES: usize = 20_480;
pub const MAX_OPERATIONAL_RECONFIG_BYTES: usize = 47_104;
pub const MAX_FINALIZED_RESOLUTION_BYTES: usize = 262_144;
pub const MAX_AUTHORIZED_RESOLUTION_BYTES: usize = 393_216;
pub const MAX_TX_WITNESS_BYTES: usize = 65_532;
pub const MAX_RESOLUTION_PROOFS: u32 = 17;
pub const MAX_AUTHORIZED_CONFIG_PROOFS: u32 = 3;
pub const FUND_BUCKET_COUNT: usize = 5;

macro_rules! closed_u8_enum {
    ($name:ident, $count:expr, { $($variant:ident = $value:expr),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum $name { $($variant = $value),+ }
        impl NoosEncode for $name { fn encode(&self, w: &mut Writer) { w.put_u8(*self as u8); } }
        impl NoosDecode for $name {
            fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
                match r.get_u8()? { $($value => Ok(Self::$variant),)+ _ => Err(CodecError::UnknownDiscriminant) }
            }
        }
        impl $name { pub const VARIANT_COUNT: u8 = $count; }
    };
}

closed_u8_enum!(CapabilityStatus, 3, { Active = 0, Suspended = 1, Retired = 2 });
closed_u8_enum!(WwmControlMode, 5, { Disabled = 0, Testnet = 1, Canary = 2, Production = 3, EmergencyDisabled = 4 });
closed_u8_enum!(FundBucketTag, 5, { Job = 0, CustodyRetention = 1, Repair = 2, ChallengeReferee = 3, Sponsor = 4 });
closed_u8_enum!(FundLedgerStatus, 4, { Staged = 0, Current = 1, Superseded = 2, Closed = 3 });
closed_u8_enum!(FundMutationOperation, 2, { Activate = 0, Close = 1 });
closed_u8_enum!(FundMutationLockStatus, 3, { Pending = 0, Completed = 1, Expired = 2 });
closed_u8_enum!(ResolutionSelectorKind, 2, { Alias = 0, Capsule = 1 });
closed_u8_enum!(ResolutionValueKind, 2, { Absent = 0, Present = 1 });
closed_u8_enum!(WwmEvidenceTier, 4, { LocalVerified = 0, SignedSingle = 1, MatchedQuorum = 2, NoQuorum = 3 });
closed_u8_enum!(WwmTerminalCode, 5, { Complete = 0, Cancelled = 1, Deadline = 2, NoQuorum = 3, Rejected = 4 });

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalU64(pub Option<u64>);
impl NoosEncode for OptionalU64 {
    fn encode(&self, w: &mut Writer) {
        match self.0 {
            None => w.put_u8(0),
            Some(v) => {
                w.put_u8(1);
                w.put_u64(v);
            }
        }
    }
}
impl NoosDecode for OptionalU64 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_u8()? {
            0 => Ok(Self(None)),
            1 => Ok(Self(Some(r.get_u64()?))),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntryV1 {
    pub signer_id: Hash32,
    pub signature: BoundedBytes<96>,
}
impl NoosEncode for SignatureEntryV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_array32(&self.signer_id);
        self.signature.encode(w);
    }
}
impl NoosDecode for SignatureEntryV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            signer_id: r.get_array32()?,
            signature: BoundedBytes::decode(r)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProofV1 {
    pub authority_epoch: u64,
    pub nonce: u64,
    pub signature: BoundedBytes<96>,
}
impl NoosEncode for AuthorityProofV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u64(self.authority_epoch);
        w.put_u64(self.nonce);
        self.signature.encode(w);
    }
}
impl NoosDecode for AuthorityProofV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            authority_epoch: r.get_u64()?,
            nonce: r.get_u64()?,
            signature: BoundedBytes::decode(r)?,
        })
    }
}

define_object! {
    /// Immutable artifact identity. It commits bytes by roots and SHA-256; it never embeds them.
    pub struct ArtifactDescriptorV1 {
        version: 1;
        1 => artifact_id: [u8; 32],
        2 => media_type: u16,
        3 => source_bytes: u64,
        4 => payload_root: [u8; 32],
        5 => published_sha256: [u8; 32],
        6 => manifest_root: [u8; 32],
        7 => codec_profile_id: u16,
        8 => stripe_count: u32,
        9 => license_root: [u8; 32],
        10 => rights_root: [u8; 32],
        11 => provenance_root: [u8; 32],
        12 => publisher_key: [u8; 32],
        13 => publisher_height: u64,
        14 => signatures: BoundedList<SignatureEntryV1, 32>,
    }
}

define_object! {
    pub struct CapabilityProfileV1 {
        version: 1;
        1 => profile_id: [u8; 32],
        2 => status: CapabilityStatus,
        3 => beneficial_control_root: [u8; 32],
        4 => region_id: [u8; 32],
        5 => asn: u32,
        6 => provider_root: [u8; 32],
        7 => software_lineage_root: [u8; 32],
        8 => attestation_epoch: u64,
        9 => attestation_expiry: u64,
        10 => capability_bitmap: u64,
        11 => selection_weight: u64,
        12 => endpoint_root: [u8; 32],
        13 => staging_bytes: u64,
        14 => capacity_bytes: u64,
        15 => headroom_bytes: u64,
        16 => operator_id: [u8; 32],
        17 => signing_key: [u8; 32],
        18 => reviewer_id: [u8; 32],
        19 => reviewer_signature: BoundedBytes<96>,
    }
}
define_object! {
    pub struct CustodianProfileV2 {
        version: 2;
        1=>profile_id:[u8;32],2=>status:CapabilityStatus,3=>beneficial_control_root:[u8;32],
        4=>region_id:[u8;32],5=>asn:u32,6=>provider_root:[u8;32],7=>software_lineage_root:[u8;32],
        8=>attestation_epoch:u64,9=>attestation_expiry:u64,10=>capability_bitmap:u64,
        11=>selection_weight:u64,12=>endpoint_root:[u8;32],13=>staging_bytes:u64,
        14=>capacity_bytes:u64,15=>headroom_bytes:u64,16=>operator_id:[u8;32],
        17=>signing_key:[u8;32],18=>reviewer_id:[u8;32],19=>reviewer_signature:BoundedBytes<96>,
    }
}
pub type ExecutorProfileV1 = CapabilityProfileV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySetV1 {
    pub set_id: Hash32,
    pub prior_set_id: Hash32,
    pub epoch: u64,
    pub entries: BoundedList<CapabilityProfileV1, 32>,
}
impl CapabilitySetV1 {
    pub fn validate(&self) -> bool {
        self.entries
            .as_slice()
            .windows(2)
            .all(|w| w[0].profile_id < w[1].profile_id)
            && self
                .entries
                .iter()
                .all(|p| p.encode_canonical().len() <= MAX_PROFILE_BYTES)
            && self.encode_canonical().len() <= MAX_CAPABILITY_SET_BYTES
    }
}
impl NoosEncode for CapabilitySetV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_array32(&self.set_id);
        w.put_array32(&self.prior_set_id);
        w.put_u64(self.epoch);
        self.entries.encode(w);
    }
}
impl NoosDecode for CapabilitySetV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        let value = Self {
            set_id: r.get_array32()?,
            prior_set_id: r.get_array32()?,
            epoch: r.get_u64()?,
            entries: BoundedList::decode(r)?,
        };
        if value.validate() {
            Ok(value)
        } else {
            Err(CodecError::LengthExceedsBound)
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianCapabilitySetV1 {
    pub set_id: Hash32,
    pub prior_set_id: Hash32,
    pub epoch: u64,
    pub entries: BoundedList<CustodianProfileV2, 32>,
}
impl CustodianCapabilitySetV1 {
    pub fn validate(&self) -> bool {
        self.entries
            .as_slice()
            .windows(2)
            .all(|w| w[0].profile_id < w[1].profile_id)
            && self
                .entries
                .iter()
                .all(|p| p.encode_canonical().len() <= MAX_PROFILE_BYTES)
            && self.encode_canonical().len() <= MAX_CAPABILITY_SET_BYTES
    }
}
impl NoosEncode for CustodianCapabilitySetV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_array32(&self.set_id);
        w.put_array32(&self.prior_set_id);
        w.put_u64(self.epoch);
        self.entries.encode(w)
    }
}
impl NoosDecode for CustodianCapabilitySetV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        let value = Self {
            set_id: r.get_array32()?,
            prior_set_id: r.get_array32()?,
            epoch: r.get_u64()?,
            entries: BoundedList::decode(r)?,
        };
        if value.validate() {
            Ok(value)
        } else {
            Err(CodecError::LengthExceedsBound)
        }
    }
}
pub type ExecutorCapabilitySetV1 = CapabilitySetV1;

define_object! {
    pub struct AvailabilityPolicyV2 {
        version: 2;
        1 => policy_id: [u8; 32],
        2 => artifact_id: [u8; 32],
        3 => manifest_root: [u8; 32],
        4 => assignment_root: [u8; 32],
        5 => geometry_root: [u8; 32],
        6 => position_count: u8,
        7 => reconstruction_threshold: u8,
        8 => schedulable_minimum: u8,
        9 => required_regions: u8,
        10 => max_positions_per_region: u8,
        11 => max_positions_per_asn: u8,
        12 => max_positions_per_provider: u8,
        13 => challenge_period: u64,
        14 => response_deadline: u64,
        15 => max_probe_age: u64,
        16 => repair_horizon: u64,
        17 => evidence_retention_horizon: u64,
        18 => samples_per_challenge: u8,
        19 => verifier_sample_size: u8,
        20 => verifier_threshold: u8,
        21 => verifier_capability_bitmap: u64,
        22 => reconstructor_sample_size: u8,
        23 => reconstructor_threshold: u8,
        24 => policy_start_height: u64,
        25 => policy_end_height: u64,
    }
}

define_object! { pub struct CustodyPositionCommitmentV2 { version: 2; 1=>commitment_id:[u8;32],2=>policy_id:[u8;32],3=>artifact_id:[u8;32],4=>position:u8,5=>custodian_profile_id:[u8;32],6=>custodian_set_id:[u8;32],7=>custodian_set_epoch:u64,8=>position_root:[u8;32],9=>committed_bytes:u64,10=>valid_from:u64,11=>valid_until:u64,12=>nonce:u64,13=>signature:BoundedBytes<96>, } }
define_object! { pub struct CustodyChallengeV2 { version: 2; 1=>challenge_id:[u8;32],2=>policy_id:[u8;32],3=>commitment_id:[u8;32],4=>beacon_root:[u8;32],5=>finalized_beacon_height:u64,6=>probe_indices:BoundedList<u32,32>,7=>issued_height:u64,8=>response_deadline_height:u64, } }
define_object! { pub struct CustodyProbeV2 { version: 2; 1=>probe_id:[u8;32],2=>challenge_id:[u8;32],3=>custodian_profile_id:[u8;32],4=>leaf_digests_root:[u8;32],5=>branch_root:[u8;32],6=>result_root:[u8;32],7=>observed_height:u64,8=>custodian_signature:BoundedBytes<96>, } }
define_object! { pub struct AvailabilityCertificateV2 { version: 2; 1=>certificate_id:[u8;32],2=>policy_id:[u8;32],3=>artifact_id:[u8;32],4=>custodian_set_id:[u8;32],5=>custodian_set_root:[u8;32],6=>custodian_set_epoch:u64,7=>executor_set_id:[u8;32],8=>executor_set_root:[u8;32],9=>executor_set_epoch:u64,10=>assignment_root:[u8;32],11=>diversity_root:[u8;32],12=>challenge_root:[u8;32],13=>selected_verifiers:BoundedList<[u8;32],8>,14=>signer_ids:BoundedList<[u8;32],5>,15=>result_root:[u8;32],16=>availability_state:u8,17=>issued_height:u64,18=>valid_until:u64,19=>signatures:BoundedList<SignatureEntryV1,5>, } }
define_object! { pub struct ArtifactRepairOrderV1 { version:1; 1=>order_id:[u8;32],2=>policy_id:[u8;32],3=>artifact_id:[u8;32],4=>position:u8,5=>prior_commitment_id:[u8;32],6=>replacement_profile_id:[u8;32],7=>source_commitment_ids:BoundedList<[u8;32],8>,8=>source_positions:BoundedList<u8,8>,9=>source_positions_root:[u8;32],10=>expected_position_root:[u8;32],11=>issued_height:u64,12=>deadline_height:u64,13=>authority_epoch:u64,14=>nonce:u64,15=>signature:BoundedBytes<96>, } }
define_object! { pub struct ArtifactRepairReceiptV1 { version:1; 1=>repair_id:[u8;32],2=>order_id:[u8;32],3=>policy_id:[u8;32],4=>artifact_id:[u8;32],5=>position:u8,6=>prior_commitment_id:[u8;32],7=>new_commitment_id:[u8;32],8=>source_positions_root:[u8;32],9=>new_position_root:[u8;32],10=>durable_commit_root:[u8;32],11=>certificate_id:[u8;32],12=>bytes_read:u64,13=>bytes_written:u64,14=>evidence_root:[u8;32],15=>signer_id:[u8;32],16=>completed_height:u64,17=>signature:BoundedBytes<96>, } }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRepairPayloadV1 {
    Order(ArtifactRepairOrderV1),
    Receipt(ArtifactRepairReceiptV1),
}
impl NoosEncode for ArtifactRepairPayloadV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Order(v) => {
                w.put_u16(0);
                v.encode(w)
            }
            Self::Receipt(v) => {
                w.put_u16(1);
                v.encode(w)
            }
        }
    }
}
impl NoosDecode for ArtifactRepairPayloadV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(2)? {
            0 => Ok(Self::Order(ArtifactRepairOrderV1::decode(r)?)),
            1 => Ok(Self::Receipt(ArtifactRepairReceiptV1::decode(r)?)),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

define_object! {
    pub struct ModelCapsuleV2 {
        version: 2;
        1 => capsule_id:[u8;32], 2 => artifact_id:[u8;32], 3 => payload_root:[u8;32],
        4 => manifest_root:[u8;32], 5 => weight_manifest_root:[u8;32], 6 => tokenizer_root:[u8;32],
        7 => template_root:[u8;32], 8 => runtime_root:[u8;32], 9 => build_root:[u8;32],
        10 => sbom_root:[u8;32], 11 => execution_profile_ids:BoundedList<[u8;32],16>,
        12 => query_policy_id:[u8;32], 13 => availability_policy_id:[u8;32], 14 => license_root:[u8;32],
        15 => rights_root:[u8;32], 16 => provenance_root:[u8;32], 17 => lifecycle:u8,
        18 => rollback_capsule_id:OptionalHash32, 19 => publisher_threshold:u8, 20 => publisher_signatures:BoundedList<SignatureEntryV1,32>,
    }
}

define_object! { pub struct ExecutionProfileV1 { version:1; 1=>profile_id:[u8;32],2=>capsule_id:[u8;32],3=>runtime_root:[u8;32],4=>tokenizer_root:[u8;32],5=>template_root:[u8;32],6=>max_context_tokens:u32,7=>max_output_tokens:u32,8=>temperature_milli:u16,9=>top_p_milli:u16,10=>top_k:u16,11=>tie_rule:u8,12=>seed_required:u8,13=>attachments_allowed:u8, } }
define_object! { pub struct FeePolicyV1 { version:1; 1=>policy_id:[u8;32],2=>quote_asset:[u8;32],3=>base_fee:u128,4=>input_token_fee:u128,5=>output_token_fee:u128,6=>maximum_fee:u128,7=>refund_policy_root:[u8;32],8=>authority_epoch:u64,9=>signature:BoundedBytes<96>, } }
define_object! { pub struct QueryPolicyV1 { version:1; 1=>policy_id:[u8;32],2=>capsule_id:[u8;32],3=>max_input_tokens:u32,4=>max_output_tokens:u32,5=>max_total_tokens:u32,6=>max_deadline_blocks:u64,7=>permitted_evidence_tiers:u8,8=>privacy_mode:u8,9=>attachments_allowed:u8,10=>policy_root:[u8;32], } }
define_object! { pub struct ServiceDirectoryV1 { version:1; 1=>directory_id:[u8;32],2=>epoch:u64,3=>endpoint_records:BoundedList<BoundedBytes<512>,16>,4=>tls_key_root:[u8;32],5=>signing_key_root:[u8;32],6=>not_before_height:u64,7=>not_after_height:u64,8=>authority_epoch:u64,9=>signatures:BoundedList<SignatureEntryV1,32>, } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveragePolicyRowV1 {
    pub bucket: FundBucketTag,
    pub baseline_liability_at_origin: u128,
    pub liability_rate_per_height: u128,
    pub coverage_origin_height: u64,
    pub coverage_end_height: u64,
    pub minimum_coverage_heights: u64,
    pub per_reservation_cap: u128,
    pub exposure_cap: u128,
}
impl NoosEncode for CoveragePolicyRowV1 {
    fn encode(&self, w: &mut Writer) {
        self.bucket.encode(w);
        w.put_u128(self.baseline_liability_at_origin);
        w.put_u128(self.liability_rate_per_height);
        w.put_u64(self.coverage_origin_height);
        w.put_u64(self.coverage_end_height);
        w.put_u64(self.minimum_coverage_heights);
        w.put_u128(self.per_reservation_cap);
        w.put_u128(self.exposure_cap)
    }
}
impl NoosDecode for CoveragePolicyRowV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            bucket: FundBucketTag::decode(r)?,
            baseline_liability_at_origin: r.get_u128()?,
            liability_rate_per_height: r.get_u128()?,
            coverage_origin_height: r.get_u64()?,
            coverage_end_height: r.get_u64()?,
            minimum_coverage_heights: r.get_u64()?,
            per_reservation_cap: r.get_u128()?,
            exposure_cap: r.get_u128()?,
        })
    }
}

define_object! { pub struct FundProfileV1 { version:1; 1=>profile_id:[u8;32],2=>settlement_asset:[u8;32],3=>authority_root:[u8;32],4=>recovery_root:[u8;32],5=>route_root:[u8;32],6=>coverage_policy_rows:BoundedList<CoveragePolicyRowV1,5>,7=>authority_epoch:u64,8=>signatures:BoundedList<SignatureEntryV1,32>, } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundLedgerRowV1 {
    pub bucket: FundBucketTag,
    pub deposits: u128,
    pub migrated_in: u128,
    pub spent: u128,
    pub migrated_out: u128,
    pub reserved: u128,
    pub free: u128,
    pub live_liability: u128,
    pub funded_through_height: OptionalU64,
    pub settlement_index: u64,
}
impl NoosEncode for FundLedgerRowV1 {
    fn encode(&self, w: &mut Writer) {
        self.bucket.encode(w);
        w.put_u128(self.deposits);
        w.put_u128(self.migrated_in);
        w.put_u128(self.spent);
        w.put_u128(self.migrated_out);
        w.put_u128(self.reserved);
        w.put_u128(self.free);
        w.put_u128(self.live_liability);
        self.funded_through_height.encode(w);
        w.put_u64(self.settlement_index)
    }
}
impl NoosDecode for FundLedgerRowV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            bucket: FundBucketTag::decode(r)?,
            deposits: r.get_u128()?,
            migrated_in: r.get_u128()?,
            spent: r.get_u128()?,
            migrated_out: r.get_u128()?,
            reserved: r.get_u128()?,
            free: r.get_u128()?,
            live_liability: r.get_u128()?,
            funded_through_height: OptionalU64::decode(r)?,
            settlement_index: r.get_u64()?,
        })
    }
}

define_object! { pub struct FundMutationLockRefV1 { version:1; 1=>lock_id:[u8;32],2=>operation:FundMutationOperation,3=>peer_profile_id:[u8;32],4=>execute_before_height:u64, } }
define_object! { pub struct WwmFundLedgerV1 { version:1; 1=>profile_id:[u8;32],2=>status:FundLedgerStatus,3=>rows:BoundedList<FundLedgerRowV1,5>,4=>topup_permit_epoch:u64,5=>lock_ref:OptionalObject<FundMutationLockRefV1>, } }
define_object! { pub struct FundMutationLockV1 { version:1; 1=>lock_id:[u8;32],2=>operation:FundMutationOperation,3=>profile_id_0:[u8;32],4=>profile_id_1:[u8;32],5=>post_ref_root_0:[u8;32],6=>post_ref_root_1:[u8;32],7=>permit_epoch_0:u64,8=>permit_epoch_1:u64,9=>authority_epoch:u64,10=>execute_before_height:u64,11=>status:FundMutationLockStatus,12=>signature:BoundedBytes<96>, } }
define_object! { pub struct FundTopUpPermitV1 { version:1; 1=>chain_id:[u8;32],2=>genesis_hash:[u8;32],3=>permit_epoch:u64,4=>payer:[u8;32],5=>prior_account_nonce:u64,6=>profile_id:[u8;32],7=>bucket:FundBucketTag,8=>amount:u128,9=>issued_height:u64,10=>not_before_height:u64,11=>expiry_height:u64,12=>authority_epoch:u64,13=>signature:BoundedBytes<96>, } }

impl FundProfileV1 {
    pub fn validate(&self) -> bool {
        let r = self.coverage_policy_rows.as_slice();
        r.len() == FUND_BUCKET_COUNT
            && r.iter().enumerate().all(|(i, x)| {
                x.bucket as usize == i && x.coverage_origin_height <= x.coverage_end_height
            })
    }
}
impl WwmFundLedgerV1 {
    pub fn validate(&self) -> bool {
        let r = self.rows.as_slice();
        r.len() == FUND_BUCKET_COUNT
            && r.iter().enumerate().all(|(i, x)| {
                x.bucket as usize == i
                    && x.live_liability == x.reserved
                    && x.deposits
                        .checked_add(x.migrated_in)
                        .and_then(|v| v.checked_sub(x.spent))
                        .and_then(|v| v.checked_sub(x.migrated_out))
                        .map(|v| v == x.free + x.reserved)
                        .unwrap_or(false)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityInstallV1 {
    pub profile: CapabilityProfileV1,
    pub prior_set_id: Hash32,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityTransitionV1 {
    pub profile_id: Hash32,
    pub prior_set_id: Hash32,
    pub prior_status: CapabilityStatus,
    pub new_status: CapabilityStatus,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityMutationV1 {
    InstallProfile(CapabilityInstallV1),
    TransitionCapability(CapabilityTransitionV1),
}
impl NoosEncode for CapabilityMutationV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::InstallProfile(v) => {
                w.put_u16(0);
                v.profile.encode(w);
                w.put_array32(&v.prior_set_id);
                v.authority.encode(w)
            }
            Self::TransitionCapability(v) => {
                w.put_u16(1);
                w.put_array32(&v.profile_id);
                w.put_array32(&v.prior_set_id);
                v.prior_status.encode(w);
                v.new_status.encode(w);
                v.authority.encode(w)
            }
        }
    }
}
impl NoosDecode for CapabilityMutationV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(2)? {
            0 => Ok(Self::InstallProfile(CapabilityInstallV1 {
                profile: CapabilityProfileV1::decode(r)?,
                prior_set_id: r.get_array32()?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            1 => Ok(Self::TransitionCapability(CapabilityTransitionV1 {
                profile_id: r.get_array32()?,
                prior_set_id: r.get_array32()?,
                prior_status: CapabilityStatus::decode(r)?,
                new_status: CapabilityStatus::decode(r)?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianCapabilityInstallV2 {
    pub profile: CustodianProfileV2,
    pub prior_set_id: Hash32,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodianCapabilityMutationV2 {
    InstallProfile(CustodianCapabilityInstallV2),
    TransitionCapability(CapabilityTransitionV1),
}
impl NoosEncode for CustodianCapabilityMutationV2 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::InstallProfile(v) => {
                w.put_u16(0);
                v.profile.encode(w);
                w.put_array32(&v.prior_set_id);
                v.authority.encode(w)
            }
            Self::TransitionCapability(v) => {
                w.put_u16(1);
                w.put_array32(&v.profile_id);
                w.put_array32(&v.prior_set_id);
                v.prior_status.encode(w);
                v.new_status.encode(w);
                v.authority.encode(w)
            }
        }
    }
}
impl NoosDecode for CustodianCapabilityMutationV2 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(2)? {
            0 => Ok(Self::InstallProfile(CustodianCapabilityInstallV2 {
                profile: CustodianProfileV2::decode(r)?,
                prior_set_id: r.get_array32()?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            1 => Ok(Self::TransitionCapability(CapabilityTransitionV1 {
                profile_id: r.get_array32()?,
                prior_set_id: r.get_array32()?,
                prior_status: CapabilityStatus::decode(r)?,
                new_status: CapabilityStatus::decode(r)?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageFundProfileV1 {
    pub profile: FundProfileV1,
    pub prior_current_id: Hash32,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockFundMutationV1 {
    pub operation: FundMutationOperation,
    pub source_profile_id: Hash32,
    pub other_profile_id: Hash32,
    pub prior_source_permit_epoch: u64,
    pub prior_other_permit_epoch: u64,
    pub execute_before_height: u64,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateFundProfileV1 {
    pub profile_id: Hash32,
    pub prior_current_id: Hash32,
    pub lock_id: Hash32,
    pub locked_current_ledger_root: Hash32,
    pub locked_candidate_ledger_root: Hash32,
    pub minimum_horizon: u64,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFundProfileV1 {
    pub profile_id: Hash32,
    pub current_profile_id: Hash32,
    pub lock_id: Hash32,
    pub locked_source_ledger_root: Hash32,
    pub locked_current_ledger_root: Hash32,
    pub authority: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterFundProfilePayloadV1 {
    StageFundProfile(StageFundProfileV1),
    LockFundMutation(LockFundMutationV1),
    ActivateFundProfile(ActivateFundProfileV1),
    CloseFundProfile(CloseFundProfileV1),
}
impl NoosEncode for RegisterFundProfilePayloadV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::StageFundProfile(v) => {
                w.put_u16(0);
                v.profile.encode(w);
                w.put_array32(&v.prior_current_id);
                v.authority.encode(w)
            }
            Self::LockFundMutation(v) => {
                w.put_u16(1);
                v.operation.encode(w);
                w.put_array32(&v.source_profile_id);
                w.put_array32(&v.other_profile_id);
                w.put_u64(v.prior_source_permit_epoch);
                w.put_u64(v.prior_other_permit_epoch);
                w.put_u64(v.execute_before_height);
                v.authority.encode(w)
            }
            Self::ActivateFundProfile(v) => {
                w.put_u16(2);
                w.put_array32(&v.profile_id);
                w.put_array32(&v.prior_current_id);
                w.put_array32(&v.lock_id);
                w.put_array32(&v.locked_current_ledger_root);
                w.put_array32(&v.locked_candidate_ledger_root);
                w.put_u64(v.minimum_horizon);
                v.authority.encode(w)
            }
            Self::CloseFundProfile(v) => {
                w.put_u16(3);
                w.put_array32(&v.profile_id);
                w.put_array32(&v.current_profile_id);
                w.put_array32(&v.lock_id);
                w.put_array32(&v.locked_source_ledger_root);
                w.put_array32(&v.locked_current_ledger_root);
                v.authority.encode(w)
            }
        }
    }
}
impl NoosDecode for RegisterFundProfilePayloadV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(4)? {
            0 => Ok(Self::StageFundProfile(StageFundProfileV1 {
                profile: FundProfileV1::decode(r)?,
                prior_current_id: r.get_array32()?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            1 => Ok(Self::LockFundMutation(LockFundMutationV1 {
                operation: FundMutationOperation::decode(r)?,
                source_profile_id: r.get_array32()?,
                other_profile_id: r.get_array32()?,
                prior_source_permit_epoch: r.get_u64()?,
                prior_other_permit_epoch: r.get_u64()?,
                execute_before_height: r.get_u64()?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            2 => Ok(Self::ActivateFundProfile(ActivateFundProfileV1 {
                profile_id: r.get_array32()?,
                prior_current_id: r.get_array32()?,
                lock_id: r.get_array32()?,
                locked_current_ledger_root: r.get_array32()?,
                locked_candidate_ledger_root: r.get_array32()?,
                minimum_horizon: r.get_u64()?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            3 => Ok(Self::CloseFundProfile(CloseFundProfileV1 {
                profile_id: r.get_array32()?,
                current_profile_id: r.get_array32()?,
                lock_id: r.get_array32()?,
                locked_source_ledger_root: r.get_array32()?,
                locked_current_ledger_root: r.get_array32()?,
                authority: AuthorityProofV1::decode(r)?,
            })),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

define_object! { pub struct WwmJobV1 { version:1; 1=>job_id:[u8;32],2=>chain_id:[u8;32],3=>genesis_hash:[u8;32],4=>quote_id:[u8;32],5=>registry_epoch:u64,6=>client_commitment:[u8;32],7=>capsule_id:[u8;32],8=>execution_profile_id:[u8;32],9=>query_policy_id:[u8;32],10=>max_input_tokens:u32,11=>max_output_tokens:u32,12=>deadline_height:u64,13=>selected_executor_ids:BoundedList<[u8;32],3>,14=>availability_certificate_id:[u8;32],15=>fund_profile_id:[u8;32],16=>reserved_amount:u128,17=>offchain_envelope_root:[u8;32], } }
define_object! { pub struct WwmReceiptV1 { version:1; 1=>receipt_id:[u8;32],2=>job_id:[u8;32],3=>capsule_id:[u8;32],4=>artifact_id:[u8;32],5=>tokenizer_root:[u8;32],6=>template_root:[u8;32],7=>runtime_root:[u8;32],8=>sbom_root:[u8;32],9=>execution_profile_id:[u8;32],10=>input_tokens:u32,11=>output_tokens:u32,12=>token_history_root:[u8;32],13=>output_root:[u8;32],14=>signer_ids:BoundedList<[u8;32],3>,15=>control_cluster_ids:BoundedList<[u8;32],3>,16=>evidence_tier:WwmEvidenceTier,17=>availability_until:u64,18=>evidence_until:u64,19=>anchor_height:u64,20=>anchor_block:[u8;32],21=>metered_amount:u128,22=>paid_amount:u128,23=>refunded_amount:u128,24=>terminal_code:WwmTerminalCode,25=>signatures:BoundedList<SignatureEntryV1,3>, } }
define_object! { pub struct WwmSettlementV1 { version:1; 1=>settlement_id:[u8;32],2=>job_id:[u8;32],3=>receipt_id:[u8;32],4=>fund_profile_id:[u8;32],5=>bucket:FundBucketTag,6=>prior_settlement_index:u64,7=>paid_amount:u128,8=>refunded_amount:u128,9=>released_amount:u128,10=>settled_height:u64,11=>authority_epoch:u64,12=>signature:BoundedBytes<96>, } }

define_object! { pub struct ServingAliasTransitionV1 { version:1; 1=>transition_id:[u8;32],2=>alias:BoundedBytes<64>,3=>prior_transition_id:OptionalHash32,4=>prior_capsule_id:OptionalHash32,5=>new_capsule_id:[u8;32],6=>expected_control_state:WwmControlMode,7=>authority_epoch:u64,8=>nonce:u64,9=>signature:BoundedBytes<96>, } }
define_object! { pub struct WwmAuthorizedConfigV1 { version:1; 1=>config_id:[u8;32],2=>parent_config_id:OptionalHash32,3=>tier:WwmControlMode,4=>release_root:[u8;32],5=>capsule_id:[u8;32],6=>artifact_id:[u8;32],7=>availability_policy_id:[u8;32],8=>execution_profile_id:[u8;32],9=>query_policy_id:[u8;32],10=>fee_policy_id:[u8;32],11=>fund_profile_id:[u8;32],12=>service_directory_id:[u8;32],13=>executor_allowlist:BoundedList<[u8;32],32>,14=>custodian_allowlist:BoundedList<[u8;32],32>,15=>runway_body:BoundedBytes<1024>,16=>runway_root:[u8;32],17=>cutover_body:BoundedBytes<10240>,18=>cutover_root:[u8;32],19=>compatibility_root:[u8;32],20=>liability_continuity_root:[u8;32],21=>signer_set_root:[u8;32],22=>signer_set_epoch:u64,23=>activation_height:u64,24=>signatures:BoundedList<SignatureEntryV1,32>, } }
define_object! { pub struct OperationalReconfigurationV1 { version:1; 1=>authorization_id:[u8;32],2=>chain_id:[u8;32],3=>genesis_hash:[u8;32],4=>prior_authorized_config_id:[u8;32],5=>prior_active_config_id:[u8;32],6=>prior_control_transition_id:[u8;32],7=>parent_resolution_height:u64,8=>parent_transcript_root:[u8;32],9=>candidate_config:WwmAuthorizedConfigV1,10=>changed_fee_policy:OptionalObject<FeePolicyV1>,11=>changed_service_directory:OptionalObject<ServiceDirectoryV1>,12=>new_profiles:BoundedList<CapabilityProfileV1,8>,13=>change_bitmap:u8,14=>issued_height:u64,15=>not_before_height:u64,16=>expiry_height:u64,17=>activation_height:u64,18=>rollback_of:OptionalHash32,19=>authority_epoch:u64,20=>signatures:BoundedList<SignatureEntryV1,32>, } }
define_object! { pub struct RecoveryAuthorizationV1 { version:1; 1=>authorization_id:[u8;32],2=>target_tier:WwmControlMode,3=>target_preimage_root:[u8;32],4=>emergency_transition_id:[u8;32],5=>direct_prior_transition_id:[u8;32],6=>direct_prior_config_id:[u8;32],7=>selected_config_id:[u8;32],8=>incident_root:[u8;32],9=>recovery_evidence_root:[u8;32],10=>signer_set_root:[u8;32],11=>signer_set_epoch:u64,12=>issued_height:u64,13=>not_before_height:u64,14=>expiry_height:u64,15=>activation_height:u64,16=>signatures:BoundedList<SignatureEntryV1,32>, } }
define_object! { pub struct WwmActivationTransitionV1 { version:1; 1=>transition_id:[u8;32],2=>source:WwmControlMode,3=>target:WwmControlMode,4=>expected_active_config_id:OptionalHash32,5=>config_id:[u8;32],6=>activation_height:u64,7=>authority_epoch:u64,8=>nonce:u64,9=>signatures:BoundedList<SignatureEntryV1,32>, } }
define_object! { pub struct WwmControlStateV1 { version:1; 1=>mode:WwmControlMode,2=>active_capsule_id:OptionalHash32,3=>last_transition_id:OptionalHash32,4=>last_transition_height:u64,5=>direct_prior_live_mode:WwmControlMode,6=>direct_prior_config_id:OptionalHash32,7=>active_config_id:OptionalHash32,8=>latest_authorized_config_id:OptionalHash32,9=>resolution_config_id:OptionalHash32,10=>release_root:[u8;32],11=>promotion_ledger_root:[u8;32],12=>capsule_id:[u8;32],13=>artifact_id:[u8;32],14=>availability_policy_id:[u8;32],15=>execution_profile_id:[u8;32],16=>query_policy_id:[u8;32],17=>runway_root:[u8;32], } }

impl WwmControlStateV1 {
    pub fn separation_valid(&self) -> bool {
        self.resolution_config_id == self.active_config_id
            && (self.mode != WwmControlMode::EmergencyDisabled
                || self.direct_prior_config_id == self.active_config_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyDisableV1 {
    pub expected_state: WwmControlMode,
    pub expected_config: OptionalHash32,
    pub incident_root: Hash32,
    pub authorization: AuthorityProofV1,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOperationalConfigV1 {
    pub authorization_id: Hash32,
    pub expected_active_config_id: Hash32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionWwmControlPayloadV1 {
    Activate {
        transition: WwmActivationTransitionV1,
        config: WwmAuthorizedConfigV1,
    },
    EmergencyDisable(EmergencyDisableV1),
    AuthorizeOperationalConfig(OperationalReconfigurationV1),
    ApplyOperationalConfig(ApplyOperationalConfigV1),
    Recover(RecoveryAuthorizationV1),
}
impl NoosEncode for TransitionWwmControlPayloadV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Activate { transition, config } => {
                w.put_u16(0);
                transition.encode(w);
                config.encode(w)
            }
            Self::EmergencyDisable(v) => {
                w.put_u16(1);
                v.expected_state.encode(w);
                v.expected_config.encode(w);
                w.put_array32(&v.incident_root);
                v.authorization.encode(w)
            }
            Self::AuthorizeOperationalConfig(v) => {
                w.put_u16(2);
                v.encode(w)
            }
            Self::ApplyOperationalConfig(v) => {
                w.put_u16(3);
                w.put_array32(&v.authorization_id);
                w.put_array32(&v.expected_active_config_id)
            }
            Self::Recover(v) => {
                w.put_u16(4);
                v.encode(w)
            }
        }
    }
}
impl NoosDecode for TransitionWwmControlPayloadV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(5)? {
            0 => Ok(Self::Activate {
                transition: WwmActivationTransitionV1::decode(r)?,
                config: WwmAuthorizedConfigV1::decode(r)?,
            }),
            1 => Ok(Self::EmergencyDisable(EmergencyDisableV1 {
                expected_state: WwmControlMode::decode(r)?,
                expected_config: OptionalHash32::decode(r)?,
                incident_root: r.get_array32()?,
                authorization: AuthorityProofV1::decode(r)?,
            })),
            2 => Ok(Self::AuthorizeOperationalConfig(
                OperationalReconfigurationV1::decode(r)?,
            )),
            3 => Ok(Self::ApplyOperationalConfig(ApplyOperationalConfigV1 {
                authorization_id: r.get_array32()?,
                expected_active_config_id: r.get_array32()?,
            })),
            4 => Ok(Self::Recover(RecoveryAuthorizationV1::decode(r)?)),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

#[must_use]
pub fn runway_body_root(body: &BoundedBytes<1024>) -> Hash32 {
    domain_hash("NOOS/WWM/RUNWAY-REQUIREMENT/V1", &[body.as_slice()])
}
#[must_use]
pub fn cutover_body_root(body: &BoundedBytes<10240>) -> Hash32 {
    domain_hash("NOOS/WWM/CUTOVER-SNAPSHOT/V1", &[body.as_slice()])
}
impl WwmAuthorizedConfigV1 {
    #[must_use]
    pub fn validate(&self) -> bool {
        self.runway_root == runway_body_root(&self.runway_body)
            && self.cutover_root == cutover_body_root(&self.cutover_body)
            && self
                .executor_allowlist
                .as_slice()
                .windows(2)
                .all(|w| w[0] < w[1])
            && self
                .custodian_allowlist
                .as_slice()
                .windows(2)
                .all(|w| w[0] < w[1])
            && self.encode_canonical().len() <= MAX_AUTHORIZED_CONFIG_BYTES
    }
}
define_object! { pub struct RegistryEpochVectorV1 { version:1; 1=>vector_id:[u8;32],2=>executor_set_id:[u8;32],3=>executor_epoch:u64,4=>custodian_set_id:[u8;32],5=>custodian_epoch:u64,6=>fee_policy_id:[u8;32],7=>fee_epoch:u64,8=>fund_profile_id:[u8;32],9=>fund_epoch:u64,10=>service_directory_id:[u8;32],11=>service_epoch:u64, } }

/// Complete, explicitly test-network-only model registration installed at
/// genesis. Production registration must use ordinary signed state
/// transitions; this aggregate exists so an isolated devnet can exercise the
/// same proof graph without pretending that fixture operators are independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestnetModelRegistrationV1 {
    pub alias: ServingAliasTransitionV1,
    pub control: WwmControlStateV1,
    pub config: WwmAuthorizedConfigV1,
    pub capsule: ModelCapsuleV2,
    pub artifact: ArtifactDescriptorV1,
    pub availability_policy: AvailabilityPolicyV2,
    pub availability_certificate: AvailabilityCertificateV2,
    pub registry: RegistryEpochVectorV1,
    pub executor_set: CapabilitySetV1,
    pub custodian_set: CustodianCapabilitySetV1,
    pub execution_profile: ExecutionProfileV1,
    pub query_policy: QueryPolicyV1,
    pub fee_policy: FeePolicyV1,
    pub service_directory: ServiceDirectoryV1,
}

impl TestnetModelRegistrationV1 {
    /// Validates the complete active 17-leaf resolver graph before genesis
    /// state is touched. Signatures remain fixture material and therefore do
    /// not satisfy any production authority or custody claim.
    #[must_use]
    pub fn validate(&self, fund_profile: &FundProfileV1, fund_ledger: &WwmFundLedgerV1) -> bool {
        let executor_ids: Vec<Hash32> = self
            .executor_set
            .entries
            .iter()
            .map(|profile| profile.profile_id)
            .collect();
        let custodian_ids: Vec<Hash32> = self
            .custodian_set
            .entries
            .iter()
            .map(|profile| profile.profile_id)
            .collect();
        let selected = self.availability_certificate.selected_verifiers.as_slice();
        let signers = self.availability_certificate.signer_ids.as_slice();
        let signature_ids: Vec<Hash32> = self
            .availability_certificate
            .signatures
            .iter()
            .map(|signature| signature.signer_id)
            .collect();
        let executor_root = domain_hash(
            "NOOS/WWM/CAPABILITY-SET-ROOT/V1",
            &[&self.executor_set.encode_canonical()],
        );
        let custodian_root = domain_hash(
            "NOOS/WWM/CUSTODIAN-CAPABILITY-SET-ROOT/V1",
            &[&self.custodian_set.encode_canonical()],
        );
        let mut registry_body = self.registry.clone();
        registry_body.vector_id = [0; 32];
        let registry_id = domain_hash(
            "NOOS/WWM/REGISTRY-EPOCH-VECTOR/V1",
            &[&registry_body.encode_canonical()],
        );

        self.control.mode == WwmControlMode::Testnet
            && self.control.separation_valid()
            && self.control.active_capsule_id.0 == Some(self.capsule.capsule_id)
            && self.control.active_config_id.0 == Some(self.config.config_id)
            && self.control.latest_authorized_config_id.0 == Some(self.config.config_id)
            && self.control.resolution_config_id.0 == Some(self.config.config_id)
            && self.control.capsule_id == self.capsule.capsule_id
            && self.control.artifact_id == self.artifact.artifact_id
            && self.control.availability_policy_id == self.availability_policy.policy_id
            && self.control.execution_profile_id == self.execution_profile.profile_id
            && self.control.query_policy_id == self.query_policy.policy_id
            && self.control.release_root == self.config.release_root
            && self.control.runway_root == self.config.runway_root
            && self.alias.expected_control_state == WwmControlMode::Testnet
            && self.alias.prior_transition_id.0.is_none()
            && self.alias.prior_capsule_id.0.is_none()
            && !self.alias.alias.is_empty()
            && self.alias.new_capsule_id == self.capsule.capsule_id
            && self.config.tier == WwmControlMode::Testnet
            && self.config.validate()
            && self.config.capsule_id == self.capsule.capsule_id
            && self.config.artifact_id == self.artifact.artifact_id
            && self.config.availability_policy_id == self.availability_policy.policy_id
            && self.config.execution_profile_id == self.execution_profile.profile_id
            && self.config.query_policy_id == self.query_policy.policy_id
            && self.config.fee_policy_id == self.fee_policy.policy_id
            && self.config.fund_profile_id == fund_profile.profile_id
            && self.config.service_directory_id == self.service_directory.directory_id
            && self.config.executor_allowlist.as_slice() == executor_ids.as_slice()
            && self.config.custodian_allowlist.as_slice() == custodian_ids.as_slice()
            && self.artifact.artifact_id != [0; 32]
            && self.artifact.source_bytes != 0
            && self.artifact.payload_root != [0; 32]
            && self.artifact.manifest_root != [0; 32]
            && self.capsule.artifact_id == self.artifact.artifact_id
            && self.capsule.payload_root == self.artifact.payload_root
            && self.capsule.manifest_root == self.artifact.manifest_root
            && self.capsule.availability_policy_id == self.availability_policy.policy_id
            && self.capsule.query_policy_id == self.query_policy.policy_id
            && self
                .capsule
                .execution_profile_ids
                .as_slice()
                .contains(&self.execution_profile.profile_id)
            && self.availability_policy.artifact_id == self.artifact.artifact_id
            && self.availability_policy.manifest_root == self.artifact.manifest_root
            && self.availability_policy.position_count == 12
            && self.availability_policy.reconstruction_threshold == 8
            && self.availability_policy.schedulable_minimum == 9
            && self.availability_policy.verifier_sample_size == 8
            && self.availability_policy.verifier_threshold == 5
            && self.availability_policy.reconstructor_sample_size == 5
            && self.availability_policy.reconstructor_threshold == 3
            && self.availability_policy.policy_start_height
                < self.availability_policy.policy_end_height
            && self.executor_set.entries.len() == 8
            && self.custodian_set.entries.len() == 12
            && self.executor_set.validate()
            && self.custodian_set.validate()
            && self
                .executor_set
                .entries
                .iter()
                .all(|profile| profile.status == CapabilityStatus::Active)
            && self
                .custodian_set
                .entries
                .iter()
                .all(|profile| profile.status == CapabilityStatus::Active)
            && selected == executor_ids.as_slice()
            && signers == &executor_ids[..5]
            && signature_ids.as_slice() == signers
            && self.availability_certificate.policy_id == self.availability_policy.policy_id
            && self.availability_certificate.artifact_id == self.artifact.artifact_id
            && self.availability_certificate.custodian_set_id == self.custodian_set.set_id
            && self.availability_certificate.custodian_set_epoch == self.custodian_set.epoch
            && self.availability_certificate.custodian_set_root == custodian_root
            && self.availability_certificate.executor_set_id == self.executor_set.set_id
            && self.availability_certificate.executor_set_epoch == self.executor_set.epoch
            && self.availability_certificate.executor_set_root == executor_root
            && self.availability_certificate.assignment_root
                == self.availability_policy.assignment_root
            && self.availability_certificate.selected_verifiers.len() == 8
            && self.availability_certificate.signer_ids.len() == 5
            && self.availability_certificate.signatures.len() == 5
            && self.availability_certificate.availability_state <= 2
            && self.availability_certificate.issued_height
                < self.availability_certificate.valid_until
            && self.execution_profile.capsule_id == self.capsule.capsule_id
            && self.execution_profile.runtime_root == self.capsule.runtime_root
            && self.execution_profile.tokenizer_root == self.capsule.tokenizer_root
            && self.execution_profile.template_root == self.capsule.template_root
            && self.execution_profile.max_context_tokens != 0
            && self.execution_profile.max_output_tokens != 0
            && self.execution_profile.max_output_tokens <= self.execution_profile.max_context_tokens
            && self.execution_profile.attachments_allowed == 0
            && self.query_policy.capsule_id == self.capsule.capsule_id
            && self.query_policy.max_total_tokens != 0
            && self
                .query_policy
                .max_input_tokens
                .checked_add(self.query_policy.max_output_tokens)
                .is_some_and(|total| total <= self.query_policy.max_total_tokens)
            && self.query_policy.attachments_allowed == 0
            && !self.service_directory.endpoint_records.is_empty()
            && self.service_directory.not_before_height < self.service_directory.not_after_height
            && self.registry.vector_id == registry_id
            && self.registry.executor_set_id == self.executor_set.set_id
            && self.registry.executor_epoch == self.executor_set.epoch
            && self.registry.custodian_set_id == self.custodian_set.set_id
            && self.registry.custodian_epoch == self.custodian_set.epoch
            && self.registry.fee_policy_id == self.fee_policy.policy_id
            && self.registry.fund_profile_id == fund_profile.profile_id
            && self.registry.service_directory_id == self.service_directory.directory_id
            && fund_profile.validate()
            && fund_ledger.profile_id == fund_profile.profile_id
            && fund_ledger.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionValueV1 {
    Absent,
    Present(BoundedBytes<47104>),
}
impl NoosEncode for ResolutionValueV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Absent => w.put_u16(0),
            Self::Present(v) => {
                w.put_u16(1);
                v.encode(w)
            }
        }
    }
}
impl NoosDecode for ResolutionValueV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(2)? {
            0 => Ok(Self::Absent),
            1 => Ok(Self::Present(BoundedBytes::decode(r)?)),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionProofV1 {
    pub state_key: Hash32,
    pub value: ResolutionValueV1,
    pub proof: SmtProof,
    pub objects_root: Hash32,
}
impl ResolutionProofV1 {
    pub fn verify(&self) -> bool {
        match &self.value {
            ResolutionValueV1::Absent => self
                .proof
                .verify_non_inclusion(&self.objects_root, &self.state_key),
            ResolutionValueV1::Present(v) => {
                self.proof
                    .verify_inclusion(&self.objects_root, &self.state_key, v.as_slice())
            }
        }
    }
}
impl NoosEncode for ResolutionProofV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_array32(&self.state_key);
        self.value.encode(w);
        self.proof.encode(w);
        w.put_array32(&self.objects_root)
    }
}
impl NoosDecode for ResolutionProofV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        Ok(Self {
            state_key: r.get_array32()?,
            value: ResolutionValueV1::decode(r)?,
            proof: SmtProof::decode(r)?,
            objects_root: r.get_array32()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionSelectorV1 {
    pub kind: ResolutionSelectorKind,
    pub value: BoundedBytes<64>,
}
impl NoosEncode for ResolutionSelectorV1 {
    fn encode(&self, w: &mut Writer) {
        self.kind.encode(w);
        self.value.encode(w)
    }
}
impl NoosDecode for ResolutionSelectorV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            kind: ResolutionSelectorKind::decode(r)?,
            value: BoundedBytes::decode(r)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedModelResolutionV1 {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub selector: ResolutionSelectorV1,
    pub freshness_bound: u64,
    pub resolution_height: u64,
    pub terminal_material: BoundedBytes<24576>,
    pub proofs: BoundedList<ResolutionProofV1, 17>,
}
impl FinalizedModelResolutionV1 {
    pub fn validate(&self) -> bool {
        self.proofs
            .as_slice()
            .windows(2)
            .all(|w| w[0].state_key < w[1].state_key)
            && self.proofs.iter().all(ResolutionProofV1::verify)
            && self.encode_canonical().len() <= MAX_FINALIZED_RESOLUTION_BYTES
    }
}
impl NoosEncode for FinalizedModelResolutionV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        w.put_array32(&self.chain_id);
        w.put_array32(&self.genesis_hash);
        self.selector.encode(w);
        w.put_u64(self.freshness_bound);
        w.put_u64(self.resolution_height);
        self.terminal_material.encode(w);
        self.proofs.encode(w)
    }
}
impl NoosDecode for FinalizedModelResolutionV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        let v = Self {
            chain_id: r.get_array32()?,
            genesis_hash: r.get_array32()?,
            selector: ResolutionSelectorV1::decode(r)?,
            freshness_bound: r.get_u64()?,
            resolution_height: r.get_u64()?,
            terminal_material: BoundedBytes::decode(r)?,
            proofs: BoundedList::decode(r)?,
        };
        if v.proofs
            .as_slice()
            .windows(2)
            .all(|w| w[0].state_key < w[1].state_key)
        {
            Ok(v)
        } else {
            Err(CodecError::LengthExceedsBound)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedConfigResolutionV1 {
    pub parent: FinalizedModelResolutionV1,
    pub current_terminal_material: BoundedBytes<24576>,
    pub candidate: OperationalReconfigurationV1,
    pub proofs: BoundedList<ResolutionProofV1, 3>,
}
impl AuthorizedConfigResolutionV1 {
    pub fn validate(&self) -> bool {
        self.parent.validate()
            && self
                .proofs
                .as_slice()
                .windows(2)
                .all(|w| w[0].state_key < w[1].state_key)
            && self.proofs.iter().all(ResolutionProofV1::verify)
            && self.encode_canonical().len() <= MAX_AUTHORIZED_RESOLUTION_BYTES
    }
}
impl NoosEncode for AuthorizedConfigResolutionV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1);
        self.parent.encode(w);
        self.current_terminal_material.encode(w);
        self.candidate.encode(w);
        self.proofs.encode(w)
    }
}
impl NoosDecode for AuthorizedConfigResolutionV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        r.expect_version(&[1])?;
        let v = Self {
            parent: FinalizedModelResolutionV1::decode(r)?,
            current_terminal_material: BoundedBytes::decode(r)?,
            candidate: OperationalReconfigurationV1::decode(r)?,
            proofs: BoundedList::decode(r)?,
        };
        if v.proofs
            .as_slice()
            .windows(2)
            .all(|w| w[0].state_key < w[1].state_key)
        {
            Ok(v)
        } else {
            Err(CodecError::LengthExceedsBound)
        }
    }
}

/// Fixed/profile-keyed leaves all live directly in the Lumen objects SMT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WwmLeafKind {
    ServingAlias = 0,
    Control = 1,
    AuthorizedConfig = 2,
    Capsule = 3,
    Artifact = 4,
    AvailabilityPolicy = 5,
    CurrentCertificatePointer = 6,
    Certificate = 7,
    RegistryEpochVector = 8,
    ExecutorCapabilitySet = 9,
    CustodianCapabilitySet = 10,
    ExecutionProfile = 11,
    QueryPolicy = 12,
    FeePolicy = 13,
    FundProfile = 14,
    FundLedger = 15,
    ServiceDirectory = 16,
    Job = 17,
    Receipt = 18,
    Settlement = 19,
    OperationalAuthorization = 20,
    FundMutationLock = 21,
    CustodyCommitment = 22,
    CustodyChallenge = 23,
    CustodyProbe = 24,
    ArtifactRepair = 25,
}
#[must_use]
pub fn wwm_fixed_key(kind: WwmLeafKind) -> Hash32 {
    domain_hash("NOOS/WWM/OBJECT-KEY/V2", &[&[kind as u8]])
}
#[must_use]
pub fn wwm_profile_key(kind: WwmLeafKind, id: &Hash32) -> Hash32 {
    domain_hash("NOOS/WWM/OBJECT-KEY/V2", &[&[kind as u8], id])
}
#[must_use]
pub fn fund_route_key(profile_id: &Hash32, bucket: FundBucketTag) -> Hash32 {
    domain_hash("NOOS/WWM/FUND-ROUTE/V1", &[profile_id, &[bucket as u8]])
}
#[must_use]
pub fn serving_alias_key() -> Hash32 {
    wwm_fixed_key(WwmLeafKind::ServingAlias)
}
#[must_use]
pub fn current_certificate_pointer_key() -> Hash32 {
    wwm_fixed_key(WwmLeafKind::CurrentCertificatePointer)
}
#[must_use]
pub fn capsule_key(capsule_id: &Hash32) -> Hash32 {
    wwm_profile_key(WwmLeafKind::Capsule, capsule_id)
}
#[must_use]
pub fn certificate_key(certificate_id: &Hash32) -> Hash32 {
    wwm_profile_key(WwmLeafKind::Certificate, certificate_id)
}
#[must_use]
pub fn decode_certificate_pointer(value: &[u8]) -> Option<Hash32> {
    value.try_into().ok()
}
impl ResolutionSelectorV1 {
    /// Resolve only the first selector leaf. Alias is a fixed singleton whose
    /// decoded alias bytes must be checked by the caller; capsule is ID-keyed.
    #[must_use]
    pub fn first_state_key(&self) -> Option<Hash32> {
        match self.kind {
            ResolutionSelectorKind::Alias => Some(serving_alias_key()),
            ResolutionSelectorKind::Capsule => {
                let id: Hash32 = self.value.as_slice().try_into().ok()?;
                Some(capsule_key(&id))
            }
        }
    }
}

/// Canonical zero-money, policy-bearing genesis ledger.
pub fn genesis_fund_ledger(profile: &FundProfileV1) -> Option<WwmFundLedgerV1> {
    if !profile.validate() {
        return None;
    }
    let rows = profile
        .coverage_policy_rows
        .iter()
        .map(|p| FundLedgerRowV1 {
            bucket: p.bucket,
            deposits: 0,
            migrated_in: 0,
            spent: 0,
            migrated_out: 0,
            reserved: 0,
            free: 0,
            live_liability: 0,
            funded_through_height: OptionalU64(None),
            settlement_index: 0,
        })
        .collect();
    Some(WwmFundLedgerV1 {
        profile_id: profile.profile_id,
        status: FundLedgerStatus::Current,
        rows: BoundedList::new(rows)?,
        topup_permit_epoch: 0,
        lock_ref: OptionalObject(None),
    })
}

/// The four-byte TxPush length prefix is outside this shared aggregate bound.
#[must_use]
pub fn carrier_len_valid(tx_bytes: usize, witness_bytes: usize) -> bool {
    tx_bytes
        .checked_add(witness_bytes)
        .is_some_and(|n| n <= MAX_TX_WITNESS_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_and_payload_tags_are_closed() {
        for tag in 0u8..5 {
            let bytes = [tag];
            let mut r = Reader::new(&bytes);
            assert!(WwmControlMode::decode(&mut r).is_ok());
        }
        let bytes = [5];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            WwmControlMode::decode(&mut r),
            Err(CodecError::UnknownDiscriminant)
        );
    }
    #[test]
    fn carrier_edges_are_exact() {
        assert!(carrier_len_valid(0, 65_532));
        assert!(carrier_len_valid(65_532, 0));
        assert!(!carrier_len_valid(65_533, 0));
        assert!(!carrier_len_valid(usize::MAX, 1));
    }
    #[test]
    fn genesis_anchor_has_policy_and_zero_money() {
        let rows = (0..5)
            .map(|i| CoveragePolicyRowV1 {
                bucket: match i {
                    0 => FundBucketTag::Job,
                    1 => FundBucketTag::CustodyRetention,
                    2 => FundBucketTag::Repair,
                    3 => FundBucketTag::ChallengeReferee,
                    _ => FundBucketTag::Sponsor,
                },
                baseline_liability_at_origin: 1,
                liability_rate_per_height: 1,
                coverage_origin_height: 0,
                coverage_end_height: 100,
                minimum_coverage_heights: 10,
                per_reservation_cap: 10,
                exposure_cap: 100,
            })
            .collect();
        let p = FundProfileV1 {
            profile_id: [1; 32],
            settlement_asset: [2; 32],
            authority_root: [3; 32],
            recovery_root: [4; 32],
            route_root: [5; 32],
            coverage_policy_rows: BoundedList::new(rows).unwrap(),
            authority_epoch: 0,
            signatures: BoundedList::default(),
        };
        let l = genesis_fund_ledger(&p).unwrap();
        assert!(l.validate());
        assert_eq!(l.status, FundLedgerStatus::Current);
        assert!(l
            .rows
            .iter()
            .all(|r| r.free == 0 && r.funded_through_height.0.is_none()));
    }
    #[test]
    fn strict_whole_input_and_plus_one_reject() {
        let v = ResolutionSelectorV1 {
            kind: ResolutionSelectorKind::Alias,
            value: BoundedBytes::new(b"bonsai".to_vec()).unwrap(),
        };
        let mut b = v.encode_canonical();
        b.push(0);
        assert_eq!(
            ResolutionSelectorV1::decode_canonical(&b),
            Err(CodecError::TrailingBytes)
        );
        let mut r = Reader::new(&[2]);
        assert_eq!(
            ResolutionSelectorKind::decode(&mut r),
            Err(CodecError::UnknownDiscriminant)
        );
    }
    #[test]
    fn resolution_values_use_the_canonical_u16_discriminant() {
        let values = [
            ResolutionValueV1::Absent,
            ResolutionValueV1::Present(BoundedBytes::new(b"bonsai".to_vec()).unwrap()),
        ];
        for value in values {
            let encoded = value.encode_canonical();
            assert_eq!(
                &encoded[..2],
                &[u8::from(matches!(&value, ResolutionValueV1::Present(_))), 0]
            );
            assert_eq!(
                ResolutionValueV1::decode_canonical(&encoded).unwrap(),
                value
            );
        }
    }
}
