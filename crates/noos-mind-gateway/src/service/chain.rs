use super::{
    config::{decode_hash, Activation, PinMode, StateEndpoint},
    Result, ServiceError,
};
use crate::{pin_state, PinnedState, StateObservation};
use noos_braid::EPOCH_LENGTH;
use noos_crypto::{hash_domain, DomainId};
use noos_nel::Hash32;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_STATUS_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ChainPin {
    pub pinned_state: PinnedState,
    pub current_height: u64,
    pub observed_endpoints: usize,
    pub pin_mode: PinMode,
    pub observed_at: Instant,
}

#[derive(Clone)]
pub struct ChainReader {
    client: reqwest::Client,
    expected_chain_id: Hash32,
    expected_genesis_hash: Hash32,
    activation: Activation,
    fee_schedule_id: Hash32,
    pin_mode: PinMode,
    endpoints: Arc<Vec<StateEndpoint>>,
}

struct FetchedObservation {
    observation: StateObservation,
    head_height: u64,
}

impl ChainReader {
    pub fn new(
        expected_chain_id: Hash32,
        expected_genesis_hash: Hash32,
        activation: Activation,
        fee_schedule_id: Hash32,
        pin_mode: PinMode,
        endpoints: Vec<StateEndpoint>,
        timeout_ms: u64,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .map_err(|error| ServiceError::Chain(format!("HTTP client: {error}")))?;
        Ok(Self {
            client,
            expected_chain_id,
            expected_genesis_hash,
            activation,
            fee_schedule_id,
            pin_mode,
            endpoints: Arc::new(endpoints),
        })
    }

    pub async fn pin(&self) -> Result<ChainPin> {
        let fetched = futures_util::future::join_all(
            self.endpoints
                .iter()
                .map(|endpoint| self.fetch_endpoint(endpoint)),
        )
        .await;
        let mut observations = Vec::new();
        let mut failures = Vec::new();
        for (index, result) in fetched.into_iter().enumerate() {
            match result {
                Ok(value) => observations.push(value),
                Err(error) => failures.push(format!("endpoint {index}: {error}")),
            }
        }

        match self.pin_mode {
            PinMode::StrictIndependent => {
                if observations.len() < crate::MIN_STATE_ENDPOINTS {
                    return Err(ServiceError::Chain(format!(
                        "strict state quorum unavailable: {}",
                        failures.join("; ")
                    )));
                }
                let raw = observations
                    .iter()
                    .map(|value| value.observation.clone())
                    .collect::<Vec<_>>();
                let pinned_state = pin_state(&raw).map_err(ServiceError::Gateway)?;
                let current_height = observations
                    .iter()
                    .filter(|value| observation_matches(&value.observation, &pinned_state))
                    .map(|value| value.head_height)
                    .min()
                    .ok_or_else(|| {
                        ServiceError::Chain("no current height for pinned quorum".to_owned())
                    })?;
                Ok(ChainPin {
                    pinned_state,
                    current_height,
                    observed_endpoints: observations.len(),
                    pin_mode: self.pin_mode,
                    observed_at: Instant::now(),
                })
            }
            PinMode::TestSingleNode => {
                if observations.len() != 1 {
                    return Err(ServiceError::Chain(format!(
                        "test-only state endpoint unavailable: {}",
                        failures.join("; ")
                    )));
                }
                let value = observations.remove(0);
                let pinned_state = test_only_pin(&value.observation)?;
                Ok(ChainPin {
                    pinned_state,
                    current_height: value.head_height,
                    observed_endpoints: 1,
                    pin_mode: self.pin_mode,
                    observed_at: Instant::now(),
                })
            }
        }
    }

    async fn fetch_endpoint(&self, endpoint: &StateEndpoint) -> Result<FetchedObservation> {
        let mut request = self
            .client
            .get(&endpoint.url)
            .header(ACCEPT, "application/json");
        if let Some(token) = &endpoint.bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|error| ServiceError::Chain(format!("state request failed: {error}")))?;
        if !response.status().is_success() {
            return Err(ServiceError::Chain(format!(
                "state endpoint returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| ServiceError::Chain(format!("state response body: {error}")))?;
        if body.len() > MAX_STATUS_BYTES {
            return Err(ServiceError::Chain(
                "state response exceeded 64 KiB".to_owned(),
            ));
        }
        let status: Value = serde_json::from_slice(&body)
            .map_err(|error| ServiceError::Chain(format!("invalid state JSON: {error}")))?;
        if status.get("ready").and_then(Value::as_bool) == Some(false) {
            return Err(ServiceError::Chain(
                "indexer reports that it is not ready".to_owned(),
            ));
        }

        let chain_id = status_hash(&status, "chain_id")?;
        let genesis_hash = status_hash(&status, "genesis_hash")?;
        if chain_id != self.expected_chain_id || genesis_hash != self.expected_genesis_hash {
            return Err(ServiceError::Chain(
                "state endpoint returned the wrong chain identity".to_owned(),
            ));
        }
        let head_height = point_number(&status, "unsafe_head", "height")?;
        let finalized = status
            .get("finalized")
            .ok_or_else(|| ServiceError::Chain("missing finalized point".to_owned()))?;
        let finalized_hash = value_hash(
            finalized
                .get("hash")
                .ok_or_else(|| ServiceError::Chain("missing finalized hash".to_owned()))?,
            "finalized hash",
        )?;
        let finalized_height = match finalized.get("height") {
            Some(value) => number(value, "finalized height")?,
            None => number(
                finalized.get("epoch").ok_or_else(|| {
                    ServiceError::Chain("missing finalized height/epoch".to_owned())
                })?,
                "finalized epoch",
            )?
            .checked_mul(EPOCH_LENGTH)
            .ok_or_else(|| ServiceError::Chain("finalized height overflow".to_owned()))?,
        };
        if finalized_height == 0 || head_height < finalized_height {
            return Err(ServiceError::Chain(
                "state endpoint has no non-genesis finalized checkpoint".to_owned(),
            ));
        }

        Ok(FetchedObservation {
            observation: StateObservation {
                endpoint_id: endpoint.endpoint_id,
                control_cluster: endpoint.control_cluster,
                chain_id,
                genesis_hash,
                finalized_height,
                finalized_hash,
                capsule_id: self.activation.capsule_id,
                query_policy_id: self.activation.query_policy_id,
                knowledge_snapshot_id: self.activation.knowledge_snapshot_id,
                executor_registry_epoch: self.activation.executor_registry_epoch,
                fee_schedule_id: self.fee_schedule_id,
            },
            head_height,
        })
    }
}

fn status_hash(status: &Value, field: &str) -> Result<Hash32> {
    value_hash(
        status
            .get(field)
            .ok_or_else(|| ServiceError::Chain(format!("missing {field}")))?,
        field,
    )
}

fn value_hash(value: &Value, field: &str) -> Result<Hash32> {
    let text = value
        .as_str()
        .ok_or_else(|| ServiceError::Chain(format!("{field} is not a string")))?;
    decode_hash(text, field).map_err(|_| ServiceError::Chain(format!("invalid {field}")))
}

fn point_number(status: &Value, point: &str, field: &str) -> Result<u64> {
    number(
        status
            .get(point)
            .and_then(|value| value.get(field))
            .ok_or_else(|| ServiceError::Chain(format!("missing {point}.{field}")))?,
        &format!("{point}.{field}"),
    )
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or_else(|| ServiceError::Chain(format!("{field} is not a canonical u64")))
}

fn observation_matches(observation: &StateObservation, pin: &PinnedState) -> bool {
    observation.chain_id == pin.chain_id
        && observation.genesis_hash == pin.genesis_hash
        && observation.finalized_height == pin.finalized_height
        && observation.finalized_hash == pin.finalized_hash
        && observation.capsule_id == pin.capsule_id
        && observation.query_policy_id == pin.query_policy_id
        && observation.knowledge_snapshot_id == pin.knowledge_snapshot_id
        && observation.executor_registry_epoch == pin.executor_registry_epoch
        && observation.fee_schedule_id == pin.fee_schedule_id
}

fn test_only_pin(observation: &StateObservation) -> Result<PinnedState> {
    let mut body = Vec::new();
    body.extend(1_u16.to_le_bytes());
    body.extend(observation.endpoint_id);
    body.extend(observation.control_cluster);
    body.extend(observation.chain_id);
    body.extend(observation.genesis_hash);
    body.extend(observation.finalized_height.to_le_bytes());
    body.extend(observation.finalized_hash);
    body.extend(observation.capsule_id);
    body.extend(observation.query_policy_id);
    body.extend(observation.knowledge_snapshot_id);
    body.extend(observation.executor_registry_epoch.to_le_bytes());
    body.extend(observation.fee_schedule_id);
    let pin_id = hash_domain(
        DomainId::WwmPublicQuote,
        &[b"TEST-ONLY-SINGLE-NODE-PIN", &body],
    )
    .map_err(ServiceError::Crypto)?
    .into_bytes();
    Ok(PinnedState {
        chain_id: observation.chain_id,
        genesis_hash: observation.genesis_hash,
        finalized_height: observation.finalized_height,
        finalized_hash: observation.finalized_hash,
        capsule_id: observation.capsule_id,
        query_policy_id: observation.query_policy_id,
        knowledge_snapshot_id: observation.knowledge_snapshot_id,
        executor_registry_epoch: observation.executor_registry_epoch,
        fee_schedule_id: observation.fee_schedule_id,
        agreeing_endpoints: vec![observation.endpoint_id],
        agreeing_control_clusters: vec![observation.control_cluster],
        pin_id,
    })
}
