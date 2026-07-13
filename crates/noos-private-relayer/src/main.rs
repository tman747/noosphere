#![forbid(unsafe_code)]

use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use noos_private_relayer::{
    Hash32, RelayError, RelayIntent, RelayPolicy, RelayUpstream, Relayer, Simulation,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct AppState {
    relayer: Arc<Mutex<Relayer>>,
    policy: RelayPolicy,
    simulation_url: String,
    submission_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayRequest {
    intent: RelayIntent,
    signature_hex: String,
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
}

struct HttpUpstream {
    client: reqwest::blocking::Client,
    simulation_url: String,
    submission_url: String,
}

impl RelayUpstream for HttpUpstream {
    fn simulate(&mut self, transaction: &[u8]) -> Result<Simulation, RelayError> {
        let response = self
            .client
            .post(&self.simulation_url)
            .json(&json!({"transaction": hex::encode(transaction)}))
            .send()
            .map_err(|_| RelayError::UpstreamRejected)?;
        if !response.status().is_success() {
            return Err(RelayError::UpstreamRejected);
        }
        let value: Value = response.json().map_err(|_| RelayError::UpstreamRejected)?;
        Ok(Simulation {
            payment_id: json_hash(&value, "payment_id")?,
            destination: json_hash(&value, "destination")?,
            relay_fee: value
                .get("relay_fee")
                .and_then(Value::as_u64)
                .ok_or(RelayError::UpstreamRejected)?,
            transaction_id: json_hash(&value, "transaction_id")?,
        })
    }

    fn submit(&mut self, transaction: &[u8]) -> Result<Hash32, RelayError> {
        let response = self
            .client
            .post(&self.submission_url)
            .json(&json!({"transaction": hex::encode(transaction)}))
            .send()
            .map_err(|_| RelayError::UpstreamRejected)?;
        if !response.status().is_success() {
            return Err(RelayError::UpstreamRejected);
        }
        let value: Value = response.json().map_err(|_| RelayError::UpstreamRejected)?;
        json_hash(&value, "transaction_id")
    }
}

fn json_hash(value: &Value, key: &str) -> Result<Hash32, RelayError> {
    parse_hash(
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or(RelayError::UpstreamRejected)?,
    )
    .map_err(|_| RelayError::UpstreamRejected)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "schema": "noos/private-relayer-health/v1",
        "chain_id": hex::encode(state.policy.chain_id),
        "genesis_hash": hex::encode(state.policy.genesis_hash),
    }))
}

async fn relay(
    State(state): State<AppState>,
    request: Result<Json<RelayRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    error: "invalid_request",
                }),
            )
                .into_response()
        }
    };
    let signature = match parse_signature(&request.signature_hex) {
        Ok(value) => value,
        Err(error) => return api_error(error).into_response(),
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_secs(),
        Err(_) => return api_error(RelayError::InvalidIntent).into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut upstream = HttpUpstream {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|_| RelayError::UpstreamRejected)?,
            simulation_url: state.simulation_url,
            submission_url: state.submission_url,
        };
        let mut relayer = state
            .relayer
            .lock()
            .map_err(|_| RelayError::UpstreamRejected)?;
        relayer.relay(
            &state.policy,
            now,
            &request.intent,
            &signature,
            &mut upstream,
        )
    })
    .await;
    match result {
        Ok(Ok(receipt)) => (StatusCode::OK, Json(receipt)).into_response(),
        Ok(Err(error)) => api_error(error).into_response(),
        Err(_) => api_error(RelayError::UpstreamRejected).into_response(),
    }
}

fn api_error(error: RelayError) -> (StatusCode, Json<ApiError>) {
    let (status, code) = match error {
        RelayError::InvalidSignature | RelayError::InvalidIntent | RelayError::WrongChain => {
            (StatusCode::BAD_REQUEST, "invalid_relay_intent")
        }
        RelayError::NotActive => (StatusCode::TOO_EARLY, "relay_not_active"),
        RelayError::Expired => (StatusCode::GONE, "relay_expired"),
        RelayError::FeeExceeded | RelayError::SimulationMismatch => {
            (StatusCode::UNPROCESSABLE_ENTITY, "relay_policy_mismatch")
        }
        RelayError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "relay_rate_limited"),
        RelayError::Replay => (StatusCode::CONFLICT, "relay_replay"),
        RelayError::UpstreamRejected => (StatusCode::BAD_GATEWAY, "relay_upstream_rejected"),
        RelayError::RandomnessUnavailable | RelayError::Overflow => {
            (StatusCode::INTERNAL_SERVER_ERROR, "relay_internal_error")
        }
    };
    (status, Json(ApiError { error: code }))
}

fn parse_signature(value: &str) -> Result<[u8; 64], RelayError> {
    let decoded = hex::decode(value).map_err(|_| RelayError::InvalidSignature)?;
    decoded.try_into().map_err(|_| RelayError::InvalidSignature)
}

fn parse_hash(value: &str) -> Result<Hash32, String> {
    let decoded = hex::decode(value).map_err(|_| "invalid hash".to_owned())?;
    decoded
        .try_into()
        .map_err(|_| "invalid hash length".to_owned())
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing {name}"))
}

fn number<T: std::str::FromStr>(name: &str, default: &str) -> Result<T, String> {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .map_err(|_| format!("invalid {name}"))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let chain_id = parse_hash(&required("NOOS_RELAYER_CHAIN_ID")?)?;
    let genesis_hash = parse_hash(&required("NOOS_RELAYER_GENESIS_HASH")?)?;
    let state = AppState {
        relayer: Arc::new(Mutex::new(Relayer::default())),
        policy: RelayPolicy {
            chain_id,
            genesis_hash,
            maximum_relay_fee: number("NOOS_RELAYER_MAX_FEE", "100000")?,
            maximum_transaction_bytes: number("NOOS_RELAYER_MAX_TX_BYTES", "1048576")?,
            maximum_lifetime_seconds: number("NOOS_RELAYER_MAX_LIFETIME", "3600")?,
            requests_per_window: number("NOOS_RELAYER_RATE_LIMIT", "20")?,
            rate_window_seconds: number("NOOS_RELAYER_RATE_WINDOW", "60")?,
        },
        simulation_url: required("NOOS_RELAYER_SIMULATION_URL")?,
        submission_url: required("NOOS_RELAYER_SUBMISSION_URL")?,
    };
    let listen: SocketAddr = env::var("NOOS_RELAYER_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:18140".to_owned())
        .parse()
        .map_err(|_| "invalid NOOS_RELAYER_LISTEN".to_owned())?;
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/v1/relay", post(relay))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| error.to_string())?;
    axum::serve(listener, app)
        .await
        .map_err(|error| error.to_string())
}
