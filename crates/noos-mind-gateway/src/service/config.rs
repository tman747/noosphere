use super::{Result, ServiceError};
use crate::{FeeSchedule, RatePolicy, SponsorAccount};
use noos_nel::Hash32;
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashSet},
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

pub const TEST_ONLY_ACK_ENV: &str = "NOOS_WWM_TEST_ONLY_ACK";
pub const TEST_ONLY_ACK_VALUE: &str = "I_UNDERSTAND_WWM_IS_TEST_ONLY";
const CONFIG_SCHEMA: &str = "noos/wwm-test-gateway/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PinMode {
    StrictIndependent,
    TestSingleNode,
}

#[derive(Debug, Clone)]
pub struct StateEndpoint {
    pub url: String,
    pub endpoint_id: Hash32,
    pub control_cluster: Hash32,
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Activation {
    pub capsule_id: Hash32,
    pub query_policy_id: Hash32,
    pub knowledge_snapshot_id: Hash32,
    pub executor_registry_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelApi {
    OpenAi,
    Ollama,
}

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub api: ModelApi,
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub system_prompt: String,
    pub timeout_ms: u64,
    pub num_gpu: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub listen: SocketAddr,
    pub site_dir: PathBuf,
    pub data_path: PathBuf,
    pub gateway_seed: [u8; 32],
    pub credential_key: [u8; 32],
    pub expected_chain_id: Hash32,
    pub expected_genesis_hash: Hash32,
    pub pin_mode: PinMode,
    pub state_endpoints: Vec<StateEndpoint>,
    pub activation: Activation,
    pub fee_schedule: FeeSchedule,
    pub rate_policy: RatePolicy,
    pub sponsor: Option<SponsorAccount>,
    pub model: ModelConfig,
    pub quote_lifetime_blocks: u32,
    pub maximum_prompt_bytes: usize,
    pub maximum_pending_jobs: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema: String,
    activation_scope: ActivationScope,
    listen: String,
    site_dir: PathBuf,
    data_path: PathBuf,
    gateway_seed_env: String,
    credential_key_env: String,
    expected_chain_id: String,
    expected_genesis_hash: String,
    pin_mode: PinMode,
    state_endpoints: Vec<StateEndpointDocument>,
    activation: ActivationDocument,
    fee_schedule: FeeScheduleDocument,
    rate_policy: RatePolicyDocument,
    sponsor: Option<SponsorDocument>,
    model: ModelDocument,
    quote_lifetime_blocks: u32,
    maximum_prompt_bytes: usize,
    maximum_pending_jobs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ActivationScope {
    TestOnly,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateEndpointDocument {
    url: String,
    endpoint_id: String,
    control_cluster: String,
    bearer_token_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationDocument {
    capsule_id: String,
    query_policy_id: String,
    knowledge_snapshot_id: String,
    executor_registry_epoch: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeeScheduleDocument {
    schedule_id: String,
    base_micro_noos: u64,
    input_token_micro_noos: u64,
    retrieval_token_micro_noos: u64,
    output_token_micro_noos: u64,
    anchored_surcharge_micro_noos: u64,
    assured_surcharge_micro_noos: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RatePolicyDocument {
    window_blocks: u64,
    maximum_requests: u32,
    maximum_output_tokens: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SponsorDocument {
    sponsor_id: String,
    remaining_micro_noos: u64,
    per_job_cap_micro_noos: u64,
    allowed_capsule_only: bool,
    expires_height: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelDocument {
    api: ModelApi,
    base_url: String,
    model: String,
    api_key_env: Option<String>,
    system_prompt: String,
    timeout_ms: u64,
    num_gpu: Option<u32>,
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        require_test_ack()?;
        let bytes = fs::read(path).map_err(|error| {
            ServiceError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let document: ConfigDocument = serde_json::from_slice(&bytes).map_err(|error| {
            ServiceError::Config(format!("invalid {}: {error}", path.display()))
        })?;
        if document.schema != CONFIG_SCHEMA
            || document.activation_scope != ActivationScope::TestOnly
        {
            return Err(ServiceError::Config(
                "only the explicit noos/wwm-test-gateway/v1 TEST_ONLY profile is supported"
                    .to_owned(),
            ));
        }

        let listen = document
            .listen
            .parse::<SocketAddr>()
            .map_err(|_| ServiceError::Config("listen must be a socket address".to_owned()))?;
        if !listen.ip().is_loopback() {
            return Err(ServiceError::Config(
                "the test-only gateway must bind to a loopback address".to_owned(),
            ));
        }

        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let site_dir = resolve_path(base_dir, document.site_dir);
        if !site_dir.is_dir() {
            return Err(ServiceError::Config(format!(
                "site_dir is not a directory: {}",
                site_dir.display()
            )));
        }
        let data_path = resolve_path(base_dir, document.data_path);
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ServiceError::Config(format!("cannot create {}: {error}", parent.display()))
            })?;
        }

        let gateway_seed = secret_from_env(&document.gateway_seed_env)?;
        let credential_key = secret_from_env(&document.credential_key_env)?;
        let expected_chain_id = decode_hash(&document.expected_chain_id, "expected_chain_id")?;
        let expected_genesis_hash =
            decode_hash(&document.expected_genesis_hash, "expected_genesis_hash")?;

        let mut endpoint_ids = BTreeSet::new();
        let mut endpoint_urls = HashSet::new();
        let mut control_clusters = BTreeSet::new();
        let mut state_endpoints = Vec::with_capacity(document.state_endpoints.len());
        for value in document.state_endpoints {
            validate_http_url(&value.url, false)?;
            let endpoint_id = decode_hash(&value.endpoint_id, "state endpoint id")?;
            let control_cluster = decode_hash(&value.control_cluster, "control cluster")?;
            if !endpoint_ids.insert(endpoint_id) || !endpoint_urls.insert(value.url.clone()) {
                return Err(ServiceError::Config(
                    "state endpoint IDs and URLs must be unique".to_owned(),
                ));
            }
            control_clusters.insert(control_cluster);
            let bearer_token = value
                .bearer_token_env
                .as_deref()
                .map(required_env)
                .transpose()?;
            state_endpoints.push(StateEndpoint {
                url: value.url,
                endpoint_id,
                control_cluster,
                bearer_token,
            });
        }
        match document.pin_mode {
            PinMode::StrictIndependent
                if state_endpoints.len() < crate::MIN_STATE_ENDPOINTS
                    || control_clusters.len() < crate::STATE_QUORUM =>
            {
                return Err(ServiceError::Config(
                    "STRICT_INDEPENDENT requires at least three unique URLs in two control clusters"
                        .to_owned(),
                ));
            }
            PinMode::TestSingleNode if state_endpoints.len() != 1 => {
                return Err(ServiceError::Config(
                    "TEST_SINGLE_NODE requires exactly one state endpoint".to_owned(),
                ));
            }
            _ => {}
        }

        let activation = Activation {
            capsule_id: decode_hash(&document.activation.capsule_id, "capsule_id")?,
            query_policy_id: decode_hash(&document.activation.query_policy_id, "query_policy_id")?,
            knowledge_snapshot_id: decode_hash(
                &document.activation.knowledge_snapshot_id,
                "knowledge_snapshot_id",
            )?,
            executor_registry_epoch: document.activation.executor_registry_epoch,
        };
        if activation.executor_registry_epoch == 0 {
            return Err(ServiceError::Config(
                "executor_registry_epoch must be nonzero".to_owned(),
            ));
        }

        let fee_schedule = FeeSchedule {
            schedule_id: decode_hash(&document.fee_schedule.schedule_id, "fee schedule id")?,
            base_micro_noos: document.fee_schedule.base_micro_noos,
            input_token_micro_noos: document.fee_schedule.input_token_micro_noos,
            retrieval_token_micro_noos: document.fee_schedule.retrieval_token_micro_noos,
            output_token_micro_noos: document.fee_schedule.output_token_micro_noos,
            anchored_surcharge_micro_noos: document.fee_schedule.anchored_surcharge_micro_noos,
            assured_surcharge_micro_noos: document.fee_schedule.assured_surcharge_micro_noos,
        };
        if fee_schedule.base_micro_noos == 0
            || fee_schedule.input_token_micro_noos == 0
            || fee_schedule.output_token_micro_noos == 0
        {
            return Err(ServiceError::Config(
                "base, input, and output fees must be nonzero".to_owned(),
            ));
        }

        let rate_policy = RatePolicy {
            window_blocks: document.rate_policy.window_blocks,
            maximum_requests: document.rate_policy.maximum_requests,
            maximum_output_tokens: document.rate_policy.maximum_output_tokens,
        };
        if rate_policy.window_blocks == 0
            || rate_policy.maximum_requests == 0
            || rate_policy.maximum_output_tokens == 0
        {
            return Err(ServiceError::Config(
                "rate policy fields must be nonzero".to_owned(),
            ));
        }

        let sponsor = document
            .sponsor
            .map(|value| -> Result<SponsorAccount> {
                Ok(SponsorAccount {
                    sponsor_id: decode_hash(&value.sponsor_id, "sponsor id")?,
                    remaining_micro_noos: value.remaining_micro_noos,
                    per_job_cap_micro_noos: value.per_job_cap_micro_noos,
                    allowed_capsule_id: value.allowed_capsule_only.then_some(activation.capsule_id),
                    expires_height: value.expires_height,
                })
            })
            .transpose()?;

        validate_http_url(&document.model.base_url, true)?;
        if document.model.model.trim().is_empty()
            || document.model.system_prompt.trim().is_empty()
            || document.model.timeout_ms == 0
        {
            return Err(ServiceError::Config(
                "model name, system prompt, and timeout must be nonempty".to_owned(),
            ));
        }
        if document.model.api == ModelApi::OpenAi && document.model.num_gpu.is_some() {
            return Err(ServiceError::Config(
                "num_gpu is only supported by the OLLAMA model API".to_owned(),
            ));
        }
        let api_key = document
            .model
            .api_key_env
            .as_deref()
            .map(required_env)
            .transpose()?;
        let model = ModelConfig {
            api: document.model.api,
            base_url: document.model.base_url.trim_end_matches('/').to_owned(),
            model: document.model.model,
            api_key,
            system_prompt: document.model.system_prompt,
            timeout_ms: document.model.timeout_ms,
            num_gpu: document.model.num_gpu,
        };

        if document.quote_lifetime_blocks == 0
            || document.maximum_prompt_bytes == 0
            || document.maximum_prompt_bytes > 1_000_000
            || document.maximum_pending_jobs == 0
            || document.maximum_pending_jobs > 4_096
        {
            return Err(ServiceError::Config(
                "quote lifetime, prompt bound, or pending-job bound is invalid".to_owned(),
            ));
        }

        Ok(Self {
            listen,
            site_dir,
            data_path,
            gateway_seed,
            credential_key,
            expected_chain_id,
            expected_genesis_hash,
            pin_mode: document.pin_mode,
            state_endpoints,
            activation,
            fee_schedule,
            rate_policy,
            sponsor,
            model,
            quote_lifetime_blocks: document.quote_lifetime_blocks,
            maximum_prompt_bytes: document.maximum_prompt_bytes,
            maximum_pending_jobs: document.maximum_pending_jobs,
        })
    }
}

pub fn decode_hash(value: &str, field: &str) -> Result<Hash32> {
    let bytes = hex::decode(value).map_err(|_| {
        ServiceError::Config(format!("{field} must be 64 lowercase hex characters"))
    })?;
    let hash: Hash32 = bytes
        .try_into()
        .map_err(|_| ServiceError::Config(format!("{field} must be exactly 32 bytes")))?;
    if hash == [0; 32] || value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ServiceError::Config(format!(
            "{field} must be a nonzero canonical lowercase hash"
        )));
    }
    Ok(hash)
}

fn require_test_ack() -> Result<()> {
    if env::var(TEST_ONLY_ACK_ENV).as_deref() != Ok(TEST_ONLY_ACK_VALUE) {
        return Err(ServiceError::Config(format!(
            "{TEST_ONLY_ACK_ENV} must equal {TEST_ONLY_ACK_VALUE}"
        )));
    }
    Ok(())
}

fn secret_from_env(name: &str) -> Result<[u8; 32]> {
    let value = required_env(name)?;
    let bytes = hex::decode(value.trim()).map_err(|_| {
        ServiceError::Config(format!("secret environment variable {name} is not hex"))
    })?;
    bytes.try_into().map_err(|_| {
        ServiceError::Config(format!(
            "secret environment variable {name} must contain exactly 32 bytes"
        ))
    })
}

fn required_env(name: &str) -> Result<String> {
    if name.trim().is_empty() {
        return Err(ServiceError::Config(
            "environment variable name cannot be empty".to_owned(),
        ));
    }
    env::var(name).map_err(|_| {
        ServiceError::Config(format!("required environment variable {name} is missing"))
    })
}

fn resolve_path(base: &Path, value: PathBuf) -> PathBuf {
    if value.is_absolute() {
        value
    } else {
        base.join(value)
    }
}

fn validate_http_url(value: &str, require_loopback: bool) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| ServiceError::Config(format!("invalid HTTP URL: {value}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ServiceError::Config(format!(
            "URL must be credential-free HTTP(S) without a fragment: {value}"
        )));
    }
    if require_loopback {
        let host = url
            .host_str()
            .ok_or_else(|| ServiceError::Config("model URL has no host".to_owned()))?;
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !loopback {
            return Err(ServiceError::Config(
                "the test-only model backend must be loopback-local".to_owned(),
            ));
        }
    }
    Ok(())
}
