use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "noos/wwm-web-capacity/v1";
pub const SHARE_BYTES: u64 = 1_047_552;
pub const MAX_ASSIGNMENT_ROWS: usize = 256;
pub const MAX_INVENTORY_ROWS: usize = 5_448;
pub const JSON_BODY_LIMIT: usize = 64 * 1024;
pub const ACCESS_LOG_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const HOST_VERIFICATION_MAX_AGE_SECONDS: u64 = 60;
pub const HOST_MANIFEST_SIGNATURE_DOMAIN: &str = "NOOS/SIG/WWM-WEB-HOST-MANIFEST/V1";
pub const ASSIGNMENT_SIGNATURE_DOMAIN: &str = "NOOS/SIG/WWM-WEB-ASSIGNMENT/V1";
pub const RESTORE_TASK_SIGNATURE_DOMAIN: &str = "NOOS/SIG/WWM-WEB-RESTORE-TASK/V1";
pub const RESTORE_IMPORT_INDEX_SIGNATURE_DOMAIN: &str =
    "NOOS/SIG/WWM-WEB-RESTORE-IMPORT-INDEX/V1";
pub const RESTORE_IMPORT_INDEX_RECORD_KIND: &str =
    "WEB_RESTORED_POSITION_IMPORT_INDEX";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainBinding {
    pub chain_id: String,
    pub genesis_hash: String,
    pub artifact_id: String,
    pub manifest_root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Geometry {
    pub source_bytes: u64,
    pub encoded_bytes: u64,
    pub stripes: u32,
    pub positions: u8,
    pub reconstruction_threshold: u8,
    pub schedulable_minimum: u8,
    pub share_bytes: u64,
    pub position_bytes: u64,
    pub coordinate_count: u32,
}

impl Geometry {
    #[must_use]
    pub const fn bonsai() -> Self {
        Self {
            source_bytes: 3_803_452_480,
            encoded_bytes: 5_707_063_296,
            stripes: 454,
            positions: 12,
            reconstruction_threshold: 8,
            schedulable_minimum: 9,
            share_bytes: SHARE_BYTES,
            position_bytes: 475_588_608,
            coordinate_count: 5_448,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperimentState {
    Disabled,
    LocalFixture,
    Devnet,
    PublicTestnetPilot,
    Closed,
}

impl ExperimentState {
    #[must_use]
    pub const fn is_test_only(self) -> bool {
        matches!(
            self,
            Self::Disabled
                | Self::LocalFixture
                | Self::Devnet
                | Self::PublicTestnetPilot
                | Self::Closed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivacyDisclosure {
    pub normal_telemetry_fields: [&'static str; 3],
    pub forbidden_telemetry_fields: [&'static str; 7],
    pub access_log_ip_prefix_bits_v4: u8,
    pub access_log_ip_prefix_bits_v6: u8,
    pub access_log_retention_seconds: u64,
    pub participant_token_storage: &'static str,
    pub cross_site_linking: bool,
    pub offline_local_deletion: bool,
}

impl PrivacyDisclosure {
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            normal_telemetry_fields: [
                "aggregate_counters",
                "coordinate_digests",
                "coarse_error_codes",
            ],
            forbidden_telemetry_fields: [
                "raw_participant_token",
                "ip_address",
                "user_agent",
                "prompt",
                "browsing_data",
                "wallet",
                "cross_site_identity",
            ],
            access_log_ip_prefix_bits_v4: 24,
            access_log_ip_prefix_bits_v6: 48,
            access_log_retention_seconds: ACCESS_LOG_RETENTION_SECONDS,
            participant_token_storage: "HASHED_ONLY",
            cross_site_linking: false,
            offline_local_deletion: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StaticCacheLifecycleDisclosure {
    pub host_refresh_max_seconds: u64,
    pub expiry_effect: &'static str,
    pub public_share_license: &'static str,
    pub cached_bytes_may_remain_public: bool,
    pub third_party_cache_erasure_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoordinatorConfigResponse {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub chain_binding: ChainBinding,
    pub geometry: Geometry,
    pub experiment_state: ExperimentState,
    pub coordinator_key: String,
    pub source_allowlist: Vec<String>,
    pub quota_choices_shares: [u16; 3],
    pub privacy: PrivacyDisclosure,
    pub static_cache_lifecycle: StaticCacheLifecycleDisclosure,
    pub participant_classes: [&'static str; 2],
    pub production_custody: bool,
    pub rewards: bool,
    pub browser_execution: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519Signature {
    pub suite: String,
    pub domain: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportPolicy {
    pub cors_allow_origin: String,
    pub credentials: String,
    pub redirects: String,
    pub range_requests: bool,
    pub immutable_cache: bool,
    pub content_encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryBinding {
    pub url: String,
    pub bytes: u64,
    pub sha256: String,
    pub inventory_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseBinding {
    pub spdx: String,
    pub license_url: String,
    pub license_sha256: String,
    pub notice_url: String,
    pub notice_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticHostManifest {
    pub schema: String,
    pub record_kind: String,
    pub participant_class: String,
    pub admission_class: String,
    pub canonical_origin: String,
    pub chain_binding: ChainBinding,
    pub host_signing_key: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_url: String,
    pub inventory: InventoryBinding,
    pub license: LicenseBinding,
    pub transport_policy: TransportPolicy,
    pub production_custody: bool,
    pub rewards: bool,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRow {
    pub stripe: u32,
    pub position: u8,
    pub bytes: u64,
    pub transport_sha256: String,
    pub protocol_share_digest: String,
    pub probe_root: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticInventory {
    pub schema: String,
    pub record_kind: String,
    pub canonical_origin: String,
    pub chain_binding: ChainBinding,
    pub generated_at: u64,
    pub expires_at: u64,
    pub rows: Vec<InventoryRow>,
    pub inventory_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRegistrationRequest {
    pub schema: String,
    pub record_kind: String,
    pub canonical_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostRegistrationResponse {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub host_id: String,
    pub canonical_origin: String,
    pub participant_class: &'static str,
    pub admission_class: &'static str,
    pub inventory_root: String,
    pub verified_rows: usize,
    pub expires_at: u64,
    pub production_custody: bool,
    pub rewards: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum StorageClass {
    Opfs,
    Indexeddb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadPolicy {
    pub enabled: bool,
    pub daily_egress_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferRequest {
    pub schema: String,
    pub record_kind: String,
    pub canonical_origin: String,
    pub consent_version: String,
    pub quota_shares: u16,
    pub effective_bytes: u64,
    pub storage_class: StorageClass,
    pub upload_policy: UploadPolicy,
    pub page_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserSession {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub participant_class: &'static str,
    pub admission_class: &'static str,
    pub session_token: String,
    pub participant_id: String,
    pub canonical_origin: String,
    pub quota_shares: u16,
    pub effective_bytes: u64,
    pub storage_class: StorageClass,
    pub upload_policy: UploadPolicy,
    pub issued_at: u64,
    pub expires_at: u64,
    pub production_custody: bool,
    pub rewards: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub schema: String,
    pub record_kind: String,
    pub session_token: String,
    pub canonical_origin: String,
    pub page_active: bool,
    pub stored_coordinate_digests: Vec<String>,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentRow {
    pub stripe: u32,
    pub position: u8,
    pub bytes: u64,
    pub transport_sha256: String,
    pub protocol_share_digest: String,
    pub probe_root: String,
    pub url: String,
    pub source_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareAssignment {
    pub schema: String,
    pub record_kind: String,
    pub assignment_id: String,
    pub participant_id: String,
    pub canonical_origin: String,
    pub chain_binding: ChainBinding,
    pub issued_at: u64,
    pub expires_at: u64,
    pub rows: Vec<AssignmentRow>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueRestoreAdminRequest {
    pub schema: String,
    pub record_kind: String,
    pub session_token: String,
    pub canonical_origin: String,
    pub source_origin: String,
    pub expires_at: u64,
    pub coordinate: InventoryRow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreTask {
    pub schema: String,
    pub record_kind: String,
    pub task_id: String,
    pub participant_id: String,
    pub canonical_origin: String,
    pub chain_binding: ChainBinding,
    pub coordinate: InventoryRow,
    pub expected_bytes: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Ed25519Signature,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueRestoreAdminReport {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub task: RestoreTask,
    pub source_origin: String,
    pub production_custody: bool,
    pub rewards: bool,
    pub insert_once: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeartbeatResponse {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub server_time: u64,
    pub assignment: Option<ShareAssignment>,
    pub restore_task: Option<RestoreTask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantReport {
    pub schema: String,
    pub record_kind: String,
    pub session_token: String,
    pub canonical_origin: String,
    pub page_active: bool,
    pub window_started_at: u64,
    pub window_ended_at: u64,
    pub stored_count: u16,
    pub evicted_count: u16,
    pub error_count: u32,
    pub uploaded_bytes: u64,
    pub coordinate_digests: Vec<String>,
    pub error_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    pub schema: String,
    pub record_kind: String,
    pub task_id: String,
    pub coordinate_digest: String,
    pub bytes: u64,
    pub quarantine_id: String,
    pub canonical_verified: bool,
    pub accepted_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredPositionImportPair {
    pub source_origin: String,
    pub task: RestoreTask,
    pub receipt: RestoreReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRestoredPositionImportIndex {
    pub schema: String,
    pub record_kind: String,
    pub coordinator_public_key: String,
    pub chain_binding: ChainBinding,
    pub target_position: u8,
    pub generated_at: u64,
    pub expires_at: u64,
    pub rows: Vec<RestoredPositionImportPair>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRestoredPositionImportEvidence {
    pub schema: String,
    pub coordinator_public_key: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub artifact_id: String,
    pub manifest_root: String,
    pub protocol_payload_root: String,
    pub published_sha256: String,
    pub position_root: String,
    pub import_index_sha256: String,
    pub target_position: u8,
    pub stripe_count: u32,
    pub imported_share_count: u32,
    pub imported_bytes: u64,
    pub production_custody: bool,
    pub availability_certificate_effect: bool,
    pub rewards: bool,
    pub insert_once: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoredPositionReleaseReport {
    pub schema: &'static str,
    pub artifact_id: String,
    pub manifest_root: String,
    pub import_index_sha256: String,
    pub target_position: u8,
    pub released_share_count: u32,
    pub released_bytes: u64,
    pub released_at: u64,
    pub production_custody: bool,
    pub availability_certificate_effect: bool,
    pub rewards: bool,
    pub insert_once: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub schema: String,
    pub record_kind: String,
    pub session_token: String,
    pub canonical_origin: String,
    pub local_deletion_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationResponse {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub revoked: bool,
    pub assignments_expired: bool,
    pub local_deletion_authority: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Acknowledgement {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub accepted: bool,
    pub server_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorResponse {
    pub schema: &'static str,
    pub record_kind: &'static str,
    pub error: ErrorBody,
}

#[cfg(test)]
mod admin_tests {
    use super::*;

    fn request_json() -> serde_json::Value {
        serde_json::json!({
            "schema": SCHEMA,
            "record_kind": "QUEUE_RESTORE_REQUEST",
            "session_token": "secret-session-token",
            "canonical_origin": "https://participant.example",
            "source_origin": "https://source.example",
            "expires_at": 1_000,
            "coordinate": {
                "stripe": 0,
                "position": 0,
                "bytes": SHARE_BYTES,
                "transport_sha256": "01".repeat(32),
                "protocol_share_digest": "02".repeat(32),
                "probe_root": "03".repeat(32),
                "url": "https://source.example/shares/000000/00.share"
            }
        })
    }

    #[test]
    fn admin_restore_request_is_closed_and_report_omits_session_secret() {
        let request: QueueRestoreAdminRequest =
            serde_json::from_value(request_json()).expect("closed request");
        let mut unknown = request_json();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<QueueRestoreAdminRequest>(unknown).is_err());

        let report = QueueRestoreAdminReport {
            schema: SCHEMA,
            record_kind: "QUEUE_RESTORE_REPORT",
            source_origin: request.source_origin,
            task: RestoreTask {
                schema: SCHEMA.to_owned(),
                record_kind: "RESTORE_TASK".to_owned(),
                task_id: "04".repeat(32),
                participant_id: "05".repeat(32),
                canonical_origin: request.canonical_origin,
                chain_binding: ChainBinding {
                    chain_id: "06".repeat(32),
                    genesis_hash: "07".repeat(32),
                    artifact_id: "08".repeat(32),
                    manifest_root: "09".repeat(32),
                },
                coordinate: request.coordinate,
                expected_bytes: SHARE_BYTES,
                issued_at: 900,
                expires_at: request.expires_at,
                signature: Ed25519Signature {
                    suite: "Ed25519".to_owned(),
                    domain: RESTORE_TASK_SIGNATURE_DOMAIN.to_owned(),
                    public_key: "0a".repeat(32),
                    signature: "0b".repeat(64),
                },
            },
            production_custody: false,
            rewards: false,
            insert_once: true,
        };
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("secret-session-token"));
        assert!(!encoded.contains("coordinator_seed"));
    }
}
