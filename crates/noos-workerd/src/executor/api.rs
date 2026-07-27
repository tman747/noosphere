//! Authenticated private protocol-v2 executor sidecar.

use crate::config::ExecutorConfig;
use crate::executor::availability::{AvailabilityGate, AvailabilitySnapshot};
use crate::executor::neural_oracle::NeuralOracleJob;
use crate::executor::residency::{Residency, ResidencyState};
use crate::executor::scheduler::{AdmissionError, Cancellation, Scheduler};
use crate::executor::security::token_matches;
use crate::hex::{decode_hex32, encode_hex};
use crate::runtime::llama_cpp::LlamaCppAdapter;
use crate::runtime::process::run_child;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::Request;
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures_util::stream::{self, Stream, StreamExt};
use noos_lumen::neural_oracle::{
    MAX_NEURAL_ORACLE_REPORTERS, MAX_NEURAL_ORACLE_RESPONSE_BYTES, NEURAL_ORACLE_QUORUM_THRESHOLD,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::BroadcastStream;
use zeroize::Zeroize;

const MAX_JOB_BODY: usize = 1_048_576;

#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<ExecutorConfig>,
    pub scheduler: Scheduler,
    pub residency: Arc<RwLock<Residency>>,
    availability: AvailabilityGate,
    jobs: Arc<Mutex<HashMap<String, JobEntry>>>,
}

#[derive(Clone)]
struct JobEntry {
    cancellation: Cancellation,
    events: Arc<Mutex<Vec<String>>>,
    sender: broadcast::Sender<String>,
}

impl ApiState {
    pub fn new(config: ExecutorConfig, residency: Residency) -> Result<Self, String> {
        let availability = AvailabilityGate::load(&config)?;
        Ok(Self::with_availability(config, residency, availability))
    }

    fn with_availability(
        config: ExecutorConfig,
        residency: Residency,
        availability: AvailabilityGate,
    ) -> Self {
        let scheduler = Scheduler::new(
            config.scheduler.max_concurrent,
            config.scheduler.max_queue,
            config.scheduler.max_context_tokens,
            config.scheduler.max_output_tokens,
        );
        Self {
            config: Arc::new(config),
            scheduler,
            residency: Arc::new(RwLock::new(residency)),
            availability,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    fn new_for_tests(config: ExecutorConfig, residency: Residency) -> Self {
        Self::with_availability(config, residency, AvailabilityGate::schedulable_fixture())
    }
}

pub fn router(state: ApiState) -> Router {
    let auth_state = state.clone();
    Router::new()
        .route("/internal/wwm/v1/capabilities", get(capabilities))
        .route("/internal/wwm/v1/capacity-quotes", post(capacity_quote))
        .route("/internal/wwm/v1/jobs", post(submit_job))
        .route("/internal/wwm/v1/jobs/{id}/stream", get(stream_job))
        .route("/internal/wwm/v1/jobs/{id}", delete(cancel_job))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(MAX_JOB_BODY))
        .with_state(state)
        .layer(middleware::from_fn_with_state(auth_state, authenticate))
}

async fn authenticate(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Err(error) = authorize(&state, request.headers()) {
        return error.into_response();
    }
    next.run(request).await
}

fn authorize(state: &ApiState, headers: &HeaderMap) -> Result<(), ApiError> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(decode_hex32)
        .ok_or(ApiError::Unauthorized)?;
    if token_matches(&state.config.sidecar_token(), &presented) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    NotReady,
    BadRequest,
    Backpressure,
    NotFound,
    Conflict,
    Availability(AvailabilitySnapshot),
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Availability(snapshot) => {
                let live_count = snapshot.live_positions.len();
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "availability_not_schedulable",
                        "live_positions": snapshot.live_positions,
                        "offline_positions": snapshot.offline_positions,
                        "live_count": live_count,
                        "schedulable_minimum": 9,
                        "reconstruction_threshold": 8,
                    })),
                )
                    .into_response()
            }
            other => {
                let (status, code) = match other {
                    Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
                    Self::NotReady => (StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
                    Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
                    Self::Backpressure => (StatusCode::TOO_MANY_REQUESTS, "backpressure"),
                    Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
                    Self::Conflict => (StatusCode::CONFLICT, "conflict"),
                    Self::Availability(_) => unreachable!("matched above"),
                };
                (status, Json(json!({"error": code}))).into_response()
            }
        }
    }
}

async fn capabilities(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&state, &headers)?;
    let residency = state
        .residency
        .read()
        .map_err(|_| ApiError::NotReady)?
        .state();
    Ok(Json(json!({
        "protocol":"wwm-sidecar-v1", "model_name":state.config.model.name,
        "artifact_id":state.config.model.artifact_id_hex,
        "runtime_commit":state.config.runtime.source_commit,
        "runtime_build_id":state.config.runtime.build_id_hex,
        "text_only":true, "attachments_allowed":false,
        "residency":residency, "max_context_tokens":state.config.scheduler.max_context_tokens,
        "max_output_tokens":state.config.scheduler.max_output_tokens,
        "max_concurrent":state.config.scheduler.max_concurrent,
        "neural_oracle":{
            "schema":"noos/neural-oracle-worker-artifacts/v1",
            "commit_reveal":true,
            "reporters":MAX_NEURAL_ORACLE_REPORTERS,
            "threshold":NEURAL_ORACLE_QUORUM_THRESHOLD,
            "max_response_bytes":MAX_NEURAL_ORACLE_RESPONSE_BYTES,
        },
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest {
    prompt_tokens: u32,
    max_output_tokens: u32,
}

async fn capacity_quote(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<QuoteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&state, &headers)?;
    require_ready(&state)?;
    if request
        .prompt_tokens
        .checked_add(request.max_output_tokens)
        .is_none_or(|total| total > state.config.scheduler.max_context_tokens)
        || request.max_output_tokens > state.config.scheduler.max_output_tokens
    {
        return Err(ApiError::BadRequest);
    }
    let custody = require_schedulable(&state).await?;
    let available = state.scheduler.available_concurrency();
    Ok(Json(json!({
        "artifact_id":state.config.model.artifact_id_hex,
        "capsule_id":state.config.model.capsule_id_hex,
        "resident":true,
        "available_concurrency":available,
        "queue_available":state.config.scheduler.max_concurrent.saturating_add(state.config.scheduler.max_queue).saturating_sub(state.scheduler.admitted()),
        "prompt_tokens":request.prompt_tokens,
        "max_output_tokens":request.max_output_tokens,
        "live_custodian_positions":custody.live_positions,
        "schedulable_minimum":9,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeuralOracleRequest {
    query_id: String,
    reporter_profile_id: String,
    nonce_hex: String,
    max_response_bytes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobRequest {
    job_id: String,
    prompt: String,
    prompt_token_ids: Vec<u32>,
    runtime_token_ids: Vec<u32>,
    max_output_tokens: u32,
    neural_oracle: Option<NeuralOracleRequest>,
}

async fn submit_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(mut request): Json<JobRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    authorize(&state, &headers)?;
    require_ready(&state)?;
    let job_id_bytes = decode_hex32(&request.job_id).ok_or(ApiError::BadRequest)?;
    let neural_oracle = if let Some(context) = request.neural_oracle.as_mut() {
        let query_id = decode_hex32(&context.query_id).ok_or(ApiError::BadRequest)?;
        let reporter_profile_id =
            decode_hex32(&context.reporter_profile_id).ok_or(ApiError::BadRequest)?;
        let nonce = decode_hex32(&context.nonce_hex);
        context.nonce_hex.zeroize();
        Some(
            NeuralOracleJob::new(
                job_id_bytes,
                query_id,
                reporter_profile_id,
                nonce.ok_or(ApiError::BadRequest)?,
                context.max_response_bytes,
            )
            .map_err(|_| ApiError::BadRequest)?,
        )
    } else {
        None
    };
    LlamaCppAdapter::require_tokenizer_match(&request.prompt_token_ids, &request.runtime_token_ids)
        .map_err(|_| ApiError::BadRequest)?;
    let prompt_tokens =
        u32::try_from(request.prompt_token_ids.len()).map_err(|_| ApiError::BadRequest)?;
    require_schedulable(&state).await?;
    let queued = state
        .scheduler
        .try_admit(
            request.job_id.clone(),
            prompt_tokens,
            request.max_output_tokens,
        )
        .map_err(map_admission)?;
    let cancellation = queued.cancellation();
    let (sender, _) = broadcast::channel(128);
    let events = Arc::new(Mutex::new(Vec::new()));
    {
        let mut jobs = state.jobs.lock().map_err(|_| ApiError::Conflict)?;
        if jobs.contains_key(&request.job_id) {
            return Err(ApiError::Conflict);
        }
        jobs.insert(
            request.job_id.clone(),
            JobEntry {
                cancellation,
                events: events.clone(),
                sender: sender.clone(),
            },
        );
    }
    let job_id = request.job_id.clone();
    let config = state.config.clone();
    let accepted_id = request.job_id.clone();
    tokio::spawn(async move {
        emit(
            &events,
            &sender,
            json!({"type":"queued","job_id":job_id}).to_string(),
        );
        let running = match queued.start().await {
            Ok(running) => running,
            Err(_) => {
                emit(
                    &events,
                    &sender,
                    json!({"type":"terminal","code":"cancelled"}).to_string(),
                );
                return;
            }
        };
        emit(&events, &sender, json!({"type":"started"}).to_string());
        let adapter = LlamaCppAdapter::new(
            config.scheduler.max_context_tokens,
            config.scheduler.max_output_tokens,
        );
        let spec = match adapter.child_spec(
            &config,
            &request.prompt_token_ids,
            request.max_output_tokens,
        ) {
            Ok(spec) => spec,
            Err(_) => {
                emit(
                    &events,
                    &sender,
                    json!({"type":"terminal","code":"rejected"}).to_string(),
                );
                return;
            }
        };
        let (chunks_tx, mut chunks_rx) = mpsc::channel(16);
        let child_cancel = running.cancellation();
        let overflow_cancel = child_cancel.clone();
        let mut prompt = request.prompt.into_bytes();
        let execution = tokio::spawn(async move {
            let result = run_child(&spec, &prompt, child_cancel, chunks_tx).await;
            prompt.zeroize();
            result
        });
        let mut neural_response = neural_oracle
            .as_ref()
            .map(|context| Vec::with_capacity(context.max_response_bytes()));
        let mut neural_response_oversized = false;
        while let Some(chunk) = chunks_rx.recv().await {
            if let (Some(context), Some(response)) =
                (neural_oracle.as_ref(), neural_response.as_mut())
            {
                if response
                    .len()
                    .checked_add(chunk.bytes.len())
                    .is_none_or(|len| len > context.max_response_bytes())
                {
                    neural_response_oversized = true;
                    overflow_cancel.cancel();
                } else if !neural_response_oversized {
                    response.extend_from_slice(&chunk.bytes);
                }
            }
            emit(&events, &sender, json!({"type":"token_bytes","sequence":chunk.sequence,"bytes_hex":encode_hex(&chunk.bytes),"incremental_root":encode_hex(&chunk.incremental_root)}).to_string());
        }
        let execution_result = execution.await;
        let terminal = if neural_response_oversized {
            json!({"type":"terminal","code":"neural_response_oversized","output_root":null})
        } else {
            match execution_result {
                Ok(Ok(root)) => match (neural_oracle.as_ref(), neural_response.as_deref()) {
                    (Some(context), Some(response)) => match context.actions(response) {
                        Ok(artifacts) if artifacts.output_root == root => json!({
                            "type":"terminal",
                            "code":"completed",
                            "output_root":encode_hex(&root),
                            "neural_oracle":{
                                "schema":"noos/neural-oracle-worker-artifacts/v1",
                                "raw_response_hex":encode_hex(response),
                                "response_bytes":response.len(),
                                "transcript_root":encode_hex(&artifacts.transcript_root),
                                "commit_action_hex":encode_hex(&artifacts.commit_action),
                                "reveal_action_hex":encode_hex(&artifacts.reveal_action),
                            }
                        }),
                        Ok(_) => {
                            json!({"type":"terminal","code":"runtime_output_mismatch","output_root":null})
                        }
                        Err(_) => {
                            json!({"type":"terminal","code":"neural_artifact_failed","output_root":null})
                        }
                    },
                    (None, None) => {
                        json!({"type":"terminal","code":"completed","output_root":encode_hex(&root)})
                    }
                    _ => {
                        json!({"type":"terminal","code":"neural_artifact_failed","output_root":null})
                    }
                },
                Ok(Err(crate::runtime::process::ChildError::Cancelled)) => {
                    json!({"type":"terminal","code":"cancelled","output_root":null})
                }
                Ok(Err(crate::runtime::process::ChildError::Timeout)) => {
                    json!({"type":"terminal","code":"runtime_timeout","output_root":null})
                }
                _ => json!({"type":"terminal","code":"runtime_crash","output_root":null}),
            }
        };
        emit(&events, &sender, terminal.to_string());
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"job_id":accepted_id,"stream":format!("/internal/wwm/v1/jobs/{accepted_id}/stream")}),
        ),
    ))
}

fn emit(events: &Arc<Mutex<Vec<String>>>, sender: &broadcast::Sender<String>, event: String) {
    if let Ok(mut stored) = events.lock() {
        stored.push(event.clone());
    }
    let _ = sender.send(event);
}

fn map_admission(error: AdmissionError) -> ApiError {
    match error {
        AdmissionError::Backpressure => ApiError::Backpressure,
        AdmissionError::DuplicateJob => ApiError::Conflict,
        AdmissionError::ContextOverflow => ApiError::BadRequest,
        AdmissionError::Draining | AdmissionError::Closed => ApiError::NotReady,
    }
}

fn require_ready(state: &ApiState) -> Result<(), ApiError> {
    let ready = state
        .residency
        .read()
        .map_err(|_| ApiError::NotReady)?
        .state()
        == ResidencyState::Ready;
    if ready && !state.scheduler.is_draining() {
        Ok(())
    } else {
        Err(ApiError::NotReady)
    }
}
async fn require_schedulable(state: &ApiState) -> Result<AvailabilitySnapshot, ApiError> {
    let gate = state.availability.clone();
    let snapshot = tokio::task::spawn_blocking(move || gate.snapshot())
        .await
        .map_err(|_| ApiError::NotReady)?;
    if snapshot.schedulable() {
        Ok(snapshot)
    } else {
        Err(ApiError::Availability(snapshot))
    }
}

async fn stream_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    authorize(&state, &headers)?;
    let entry = state
        .jobs
        .lock()
        .map_err(|_| ApiError::Conflict)?
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let history = entry.events.lock().map_err(|_| ApiError::Conflict)?.clone();
    let past = stream::iter(
        history
            .into_iter()
            .map(|data| Ok(Event::default().data(data))),
    );
    let future = BroadcastStream::new(entry.sender.subscribe()).filter_map(|item| async move {
        match item {
            Ok(data) => Some(Ok(Event::default().data(data))),
            Err(_) => None,
        }
    });
    Ok(Sse::new(past.chain(future)).keep_alive(KeepAlive::default()))
}

async fn cancel_job(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&state, &headers)?;
    let entry = state
        .jobs
        .lock()
        .map_err(|_| ApiError::Conflict)?
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    entry.cancellation.cancel();
    Ok(StatusCode::ACCEPTED)
}

async fn live(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&state, &headers)?;
    Ok(Json(json!({"live":true})))
}
async fn ready(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&state, &headers)?;
    require_ready(&state)?;
    Ok(Json(json!({"ready":true})))
}
async fn metrics(State(state): State<ApiState>, headers: HeaderMap) -> Result<String, ApiError> {
    authorize(&state, &headers)?;
    Ok(format!(
        "noos_wwm_admitted_jobs {}\nnoos_wwm_available_concurrency {}\n",
        state.scheduler.admitted(),
        state.scheduler.available_concurrency()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ExecutorWorkerConfig, IdentityConfig, ModelConfig, RuntimeConfig, SchedulerConfig,
        BONSAI_MANIFEST_ROOT, BONSAI_MODEL_ALIAS, BONSAI_MODEL_BYTES, BONSAI_MODEL_NAME,
        BONSAI_MODEL_SHA256, PRISM_LLAMA_COMMIT,
    };
    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn test_state() -> ApiState {
        let config = ExecutorConfig {
            worker: ExecutorWorkerConfig {
                seed_hex: "11".repeat(32),
                chain_id_hex: "22".repeat(32),
                genesis_hash_hex: "33".repeat(32),
                sidecar_token_hex: "44".repeat(32),
                listen: "tcp://127.0.0.1:9807".into(),
                scratch_dir: PathBuf::from("scratch"),
                drain_file: PathBuf::from("drain"),
            },
            model: ModelConfig {
                name: BONSAI_MODEL_NAME.into(),
                path: PathBuf::from("model.gguf"),
                manifest_path: PathBuf::from("manifest.bin"),
                custodian_map_path: PathBuf::from("custodians.json"),
                bytes: BONSAI_MODEL_BYTES,
                sha256_hex: BONSAI_MODEL_SHA256.into(),
                manifest_root_hex: BONSAI_MANIFEST_ROOT.into(),
                artifact_id_hex: "55".repeat(32),
                capsule_id_hex: "66".repeat(32),
                tokenizer_id_hex: "77".repeat(32),
                template_id_hex: "88".repeat(32),
            },
            runtime: RuntimeConfig {
                executable: PathBuf::from("llama-cli"),
                source_commit: PRISM_LLAMA_COMMIT.into(),
                target_triple: "x86_64-pc-windows-msvc".into(),
                toolchain: "msvc-19.44".into(),
                build_flags: vec!["LLAMA_CURL=OFF".into()],
                binary_sha256_hex: "99".repeat(32),
                runtime_root_hex: "98".repeat(32),
                build_root_hex: "97".repeat(32),
                sbom_root_hex: "aa".repeat(32),
                build_id_hex: "bb".repeat(32),
                extra_args: vec![],
            },
            scheduler: SchedulerConfig {
                max_concurrent: 1,
                max_queue: 1,
                max_context_tokens: 4096,
                max_output_tokens: 512,
                job_timeout_ms: 1000,
                cancel_grace_ms: 20,
            },
            identity: IdentityConfig {
                finalized_resolution_path: PathBuf::from("resolution.json"),
                model_alias: BONSAI_MODEL_ALIAS.into(),
                trusted_checkpoint_epoch: 1,
                trusted_checkpoint_height: 1,
                trusted_checkpoint_hash_hex: "ce".repeat(32),
                current_finalized_height: 1,
                worker_id_hex: "cc".repeat(32),
                certificate_id_hex: "dd".repeat(32),
                executor_set_epoch: 1,
                custodian_set_epoch: 1,
                service_directory_epoch: 1,
            },
        };
        let mut residency = Residency::default();
        residency.transition(ResidencyState::Verifying).unwrap();
        residency.transition(ResidencyState::Loading).unwrap();
        residency.transition(ResidencyState::Warming).unwrap();
        residency.transition(ResidencyState::Ready).unwrap();
        ApiState::new_for_tests(config, residency)
    }

    #[tokio::test]
    async fn every_route_authenticates_before_extracting_a_body() {
        for (method, path) in [
            (Method::GET, "/internal/wwm/v1/capabilities"),
            (Method::POST, "/internal/wwm/v1/capacity-quotes"),
            (Method::POST, "/internal/wwm/v1/jobs"),
            (Method::GET, "/internal/wwm/v1/jobs/00/stream"),
            (Method::DELETE, "/internal/wwm/v1/jobs/00"),
            (Method::GET, "/health/live"),
            (Method::GET, "/health/ready"),
            (Method::GET, "/metrics"),
        ] {
            let response = router(test_state())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[tokio::test]
    async fn capabilities_are_private_and_never_expose_secrets() {
        let response = router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/internal/wwm/v1/capabilities")
                    .header(header::AUTHORIZATION, format!("Bearer {}", "44".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 32_768).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(!text.contains(&"11".repeat(32)));
        assert!(!text.contains(&"44".repeat(32)));
        assert!(!text.contains("prompt"));
        assert!(text.contains(BONSAI_MODEL_NAME));
        assert!(text.contains("noos/neural-oracle-worker-artifacts/v1"));
        assert!(text.contains(r#""reporters":3"#));
        assert!(text.contains(r#""threshold":2"#));
    }

    #[tokio::test]
    async fn neural_oracle_context_is_job_bound_before_admission() {
        let job_id = "ab".repeat(32);
        let request_body = |query_id: String| {
            json!({
                "job_id": job_id,
                "prompt": "hello",
                "prompt_token_ids": [1],
                "runtime_token_ids": [1],
                "max_output_tokens": 1,
                "neural_oracle": {
                    "query_id": query_id,
                    "reporter_profile_id": "bc".repeat(32),
                    "nonce_hex": "cd".repeat(32),
                    "max_response_bytes": 64
                }
            })
            .to_string()
        };
        let invalid_state = test_state();
        let invalid = router(invalid_state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/internal/wwm/v1/jobs")
                    .header(header::AUTHORIZATION, format!("Bearer {}", "44".repeat(32)))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body("ac".repeat(32))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(invalid_state.scheduler.admitted(), 0);

        let valid_state = test_state();
        let valid = router(valid_state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/internal/wwm/v1/jobs")
                    .header(header::AUTHORIZATION, format!("Bearer {}", "44".repeat(32)))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request_body(job_id.clone())))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(valid.status(), StatusCode::ACCEPTED);
        let body = to_bytes(valid.into_body(), 32_768).await.unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains(&job_id), "{body}");
        assert!(body.contains("/internal/wwm/v1/jobs/"), "{body}");
    }
}
