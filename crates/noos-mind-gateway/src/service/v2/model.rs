use serde::{Deserialize, Serialize};

pub const API_SCHEMA: &str = "noos/wwm-gateway/v2";
pub const MAX_PROMPT_BYTES: usize = 48_000;
pub const MAX_OUTPUT_TOKENS: u32 = 512;
pub const EVENT_TTL_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationState {
    Active,
    AuthorizedNotActive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapsuleResolution {
    pub capsule_id: String,
    pub model_name: String,
    pub artifact_sha256: String,
    pub artifact_length: u64,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub activation_state: ActivationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorRegistration {
    pub executor_id: String,
    pub control_cluster_id: String,
    pub region: String,
    pub https_origin: String,
    pub protocol_version: u16,
    pub registry_epoch: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateObjectProof {
    pub object_kind: String,
    pub object_id: String,
    pub canonical_value_hex: String,
    pub smt_siblings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedResolution {
    pub schema: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub objects_root: String,
    pub pin_id: String,
    pub proofs_verified: bool,
    pub canonical_resolution_body_hex: String,
    pub finality_evidence_hex: String,
    pub state_object_proofs: Vec<StateObjectProof>,
    pub active: CapsuleResolution,
    #[serde(default)]
    pub candidates: Vec<CapsuleResolution>,
    pub executors: Vec<ExecutorRegistration>,
    pub fee_schedule_id: String,
    pub fund_profile_id: String,
    pub service_directory_id: String,
    pub registry_vector_id: String,
}

impl FinalizedResolution {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != "noos/finalized-model-resolution/v1"
            || !self.proofs_verified
            || self.finalized_height == 0
            || !is_hash(&self.chain_id)
            || !is_hash(&self.genesis_hash)
            || !is_hash(&self.finalized_hash)
            || !is_hash(&self.objects_root)
            || !is_hash(&self.pin_id)
            || !is_even_hex(&self.canonical_resolution_body_hex)
            || !is_even_hex(&self.finality_evidence_hex)
            || self.state_object_proofs.is_empty()
            || self.state_object_proofs.iter().any(|proof| {
                proof.object_kind.is_empty()
                    || !is_hash(&proof.object_id)
                    || !is_even_hex(&proof.canonical_value_hex)
                    || proof.smt_siblings.is_empty()
                    || proof.smt_siblings.iter().any(|sibling| !is_hash(sibling))
            })
            || !self.state_object_proofs.iter().any(|proof| {
                proof.object_kind == "MODEL_CAPSULE" && proof.object_id == self.active.capsule_id
            })
            || self.active.activation_state != ActivationState::Active
            || self.candidates.iter().any(|candidate| {
                candidate.activation_state != ActivationState::AuthorizedNotActive
                    || candidate.capsule_id == self.active.capsule_id
            })
            || self.executors.is_empty()
            || self.executors.iter().any(|edge| {
                edge.protocol_version != 2
                    || edge.registry_epoch == 0
                    || edge.executor_id.is_empty()
                    || edge.control_cluster_id.is_empty()
                    || edge.region.is_empty()
            })
        {
            return Err("invalid proof-carrying finalized resolution");
        }
        Ok(())
    }

    pub fn capsule(&self, id: &str) -> Option<&CapsuleResolution> {
        if self.active.capsule_id == id {
            Some(&self.active)
        } else {
            self.candidates
                .iter()
                .find(|candidate| candidate.capsule_id == id)
        }
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_even_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentMode {
    Sponsored,
    Paid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaymentAuthorization {
    pub mode: PaymentMode,
    pub authorization: String,
}

impl PaymentAuthorization {
    pub fn reference(&self) -> &str {
        &self.authorization
    }

    pub fn mode(&self) -> &'static str {
        match self.mode {
            PaymentMode::Sponsored => "SPONSORED",
            PaymentMode::Paid => "PAID",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRequest {
    pub request_id: String,
    pub pin_id: String,
    pub capsule_id: String,
    pub prompt_commitment: String,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub input_tokens: u32,
    pub maximum_output_tokens: u32,
    pub client_nonce: String,
    pub payment: PaymentAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuoteResponse {
    pub schema: String,
    pub quote_id: String,
    pub request_id: String,
    pub pin_id: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub prompt_commitment: String,
    pub input_tokens: u32,
    pub maximum_output_tokens: u32,
    pub payment_mode: String,
    pub payment_reference: String,
    pub expires_at_height: u64,
    pub maximum_fee_micro_noos: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub quote_id: String,
    pub prompt: String,
    pub prompt_commitment: String,
    pub prompt_salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobView {
    pub schema: String,
    pub job_id: String,
    pub status: JobStatus,
    pub replayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStatus {
    Queued,
    Running,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
    NoQuorum,
}

impl JobStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Failed | Self::NoQuorum
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    None,
    ProvisionalSigned,
    MatchedQuorum,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SettlementState {
    PendingChain,
    FinalizedPaid,
    FinalizedRefunded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub schema: String,
    pub receipt_id: String,
    pub job_id: String,
    pub tenant_id: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub prompt_commitment: String,
    pub output_commitment: String,
    pub output_tokens: u32,
    pub terminal_status: JobStatus,
    pub evidence_state: EvidenceState,
    pub chain_anchor: Option<String>,
    pub settlement_state: SettlementState,
    pub payment_mode: String,
    pub payment_reference: String,
    pub executor_id: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamEvent {
    pub id: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    pub job_id: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub prompt: String,
    pub maximum_output_tokens: u32,
    pub prompt_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub output: String,
    pub output_tokens: u32,
    pub ordered_token_ids_hash: String,
    pub token_history_root: String,
    pub evidence_state: EvidenceState,
    pub executor_id: String,
    pub executor_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
}
