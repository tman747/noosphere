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
use rusqlite::{params, Connection, ErrorCode};
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
    database: Arc<Mutex<Connection>>,
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

fn open_database(path: &str) -> Result<Connection, String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS relay_attempts (
                signer BLOB NOT NULL,
                nonce BLOB NOT NULL,
                payment_id BLOB NOT NULL,
                destination BLOB NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('RESERVED','UNKNOWN','SUBMITTED')),
                receipt_json TEXT,
                created_unix INTEGER NOT NULL,
                updated_unix INTEGER NOT NULL,
                PRIMARY KEY (signer, nonce),
                UNIQUE (payment_id)
            );
            ",
        )
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

fn reserve_intent(
    database: &Mutex<Connection>,
    intent: &RelayIntent,
    now_unix: u64,
) -> Result<(), RelayError> {
    let created = i64::try_from(now_unix).map_err(|_| RelayError::Overflow)?;
    let connection = database
        .lock()
        .map_err(|_| RelayError::UpstreamRejected)?;
    match connection.execute(
        "INSERT INTO relay_attempts
         (signer, nonce, payment_id, destination, status, created_unix, updated_unix)
         VALUES (?1, ?2, ?3, ?4, 'RESERVED', ?5, ?5)",
        params![
            intent.signer.as_slice(),
            intent.nonce.to_le_bytes().as_slice(),
            intent.payment_id.as_slice(),
            intent.destination.as_slice(),
            created,
        ],
    ) {
        Ok(_) => Ok(()),
        Err(error) if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) => {
            Err(RelayError::Replay)
        }
        Err(_) => Err(RelayError::UpstreamRejected),
    }
}

fn complete_intent(
    database: &Mutex<Connection>,
    intent: &RelayIntent,
    receipt: &noos_private_relayer::RelayReceipt,
    now_unix: u64,
) -> Result<(), RelayError> {
    let updated = i64::try_from(now_unix).map_err(|_| RelayError::Overflow)?;
    let receipt_json =
        serde_json::to_string(receipt).map_err(|_| RelayError::UpstreamRejected)?;
    let connection = database
        .lock()
        .map_err(|_| RelayError::UpstreamRejected)?;
    let changed = connection
        .execute(
            "UPDATE relay_attempts
             SET status = 'SUBMITTED', receipt_json = ?1, updated_unix = ?2
             WHERE signer = ?3 AND nonce = ?4 AND payment_id = ?5",
            params![
                receipt_json,
                updated,
                intent.signer.as_slice(),
                intent.nonce.to_le_bytes().as_slice(),
                intent.payment_id.as_slice(),
            ],
        )
        .map_err(|_| RelayError::UpstreamRejected)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RelayError::UpstreamRejected)
    }
}

fn resolve_failed_intent(
    database: &Mutex<Connection>,
    intent: &RelayIntent,
    error: RelayError,
    now_unix: u64,
) -> Result<(), RelayError> {
    let connection = database
        .lock()
        .map_err(|_| RelayError::UpstreamRejected)?;
    if error == RelayError::UpstreamRejected {
        let updated = i64::try_from(now_unix).map_err(|_| RelayError::Overflow)?;
        connection
            .execute(
                "UPDATE relay_attempts SET status = 'UNKNOWN', updated_unix = ?1
                 WHERE signer = ?2 AND nonce = ?3 AND payment_id = ?4",
                params![
                    updated,
                    intent.signer.as_slice(),
                    intent.nonce.to_le_bytes().as_slice(),
                    intent.payment_id.as_slice(),
                ],
            )
            .map_err(|_| RelayError::UpstreamRejected)?;
    } else {
        connection
            .execute(
                "DELETE FROM relay_attempts
                 WHERE signer = ?1 AND nonce = ?2 AND payment_id = ?3 AND status = 'RESERVED'",
                params![
                    intent.signer.as_slice(),
                    intent.nonce.to_le_bytes().as_slice(),
                    intent.payment_id.as_slice(),
                ],
            )
            .map_err(|_| RelayError::UpstreamRejected)?;
    }
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    let database_ok = state
        .database
        .lock()
        .ok()
        .and_then(|connection| connection.query_row("SELECT 1", [], |_| Ok(())).ok())
        .is_some();
    Json(json!({
        "ok": database_ok,
        "schema": "noos/private-relayer-health/v1",
        "chain_id": hex::encode(state.policy.chain_id),
        "genesis_hash": hex::encode(state.policy.genesis_hash),
        "database": if database_ok { "ready" } else { "unavailable" },
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
    if let Err(error) = request.intent.validate_policy(&state.policy, now) {
        return api_error(error).into_response();
    }
    if let Err(error) = request.intent.verify_signature(&signature) {
        return api_error(error).into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        reserve_intent(&state.database, &request.intent, now)?;
        let mut upstream = HttpUpstream {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|_| RelayError::UpstreamRejected)?,
            simulation_url: state.simulation_url.clone(),
            submission_url: state.submission_url.clone(),
        };
        let relay_result = {
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
        };
        match relay_result {
            Ok(receipt) => {
                complete_intent(&state.database, &request.intent, &receipt, now)?;
                Ok(receipt)
            }
            Err(error) => {
                resolve_failed_intent(&state.database, &request.intent, error.clone(), now)?;
                Err(error)
            }
        }
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
    let database = open_database(&required("NOOS_RELAYER_DATABASE")?)?;
    let state = AppState {
        relayer: Arc::new(Mutex::new(Relayer::default())),
        database: Arc::new(Mutex::new(database)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use noos_private_relayer::RelayReceipt;

    fn database_path(name: &str) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("noos-relayer-{name}-{nonce}.sqlite3"))
            .to_string_lossy()
            .into_owned()
    }

    fn intent() -> RelayIntent {
        RelayIntent {
            version: 1,
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            signer: [3; 32],
            payment_id: [4; 32],
            destination: [5; 32],
            max_relay_fee: 10,
            nonce: 7,
            earliest_unix: 100,
            expires_unix: 200,
            claim_transaction: vec![6],
        }
    }

    #[test]
    fn submitted_intent_remains_replay_protected_after_reopen() {
        let path = database_path("recovery");
        let relay_intent = intent();
        let connection = open_database(&path).unwrap();
        reserve_intent(&Mutex::new(connection), &relay_intent, 150).unwrap();
        let receipt = RelayReceipt {
            version: 1,
            payment_id: relay_intent.payment_id,
            destination: relay_intent.destination,
            transaction_id: [8; 32],
            relay_fee: 9,
            accepted_unix: 150,
            receipt_hash: [9; 32],
        };
        let connection = open_database(&path).unwrap();
        complete_intent(&Mutex::new(connection), &relay_intent, &receipt, 151).unwrap();
        let reopened = open_database(&path).unwrap();
        assert_eq!(
            reserve_intent(&Mutex::new(reopened), &relay_intent, 152),
            Err(RelayError::Replay)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn deterministic_validation_failure_releases_reservation() {
        let path = database_path("release");
        let relay_intent = intent();
        let database = Mutex::new(open_database(&path).unwrap());
        reserve_intent(&database, &relay_intent, 150).unwrap();
        resolve_failed_intent(
            &database,
            &relay_intent,
            RelayError::SimulationMismatch,
            151,
        )
        .unwrap();
        reserve_intent(&database, &relay_intent, 152).unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn ambiguous_upstream_failure_stays_reserved() {
        let path = database_path("unknown");
        let relay_intent = intent();
        let database = Mutex::new(open_database(&path).unwrap());
        reserve_intent(&database, &relay_intent, 150).unwrap();
        resolve_failed_intent(
            &database,
            &relay_intent,
            RelayError::UpstreamRejected,
            151,
        )
        .unwrap();
        assert_eq!(
            reserve_intent(&database, &relay_intent, 152),
            Err(RelayError::Replay)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }
}
