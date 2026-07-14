mod backend;
mod chain;
pub mod config;
mod store;

use crate::{
    FeeSchedule, Gateway, GatewayError, GatewayManifest, PublicQueryRequest, PublicQuote,
    QueryBounds, ReceiptView,
};
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive},
        IntoResponse, Response, Sse,
    },
    routing::{get, post},
    Json, Router,
};
use backend::ModelBackend;
use chain::{ChainPin, ChainReader};
use config::{PinMode, RuntimeConfig};
use futures_util::stream::unfold;
use noos_crypto::{hash_domain, CryptoError, DomainId, Keypair};
use noos_nel::{FinalityClass, Hash32};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap, convert::Infallible, error::Error, fmt, sync::Arc, time::Duration,
};
use store::GatewayStore;
use tokio::sync::{mpsc, Mutex, RwLock};
use tower_http::services::ServeDir;
use zeroize::Zeroizing;

pub type Result<T, E = ServiceError> = std::result::Result<T, E>;

const CREDENTIAL_COOKIE: &str = "wwm_test_credential";
const MAX_QUOTES: usize = 4_096;
const STREAM_CHANNEL_CAPACITY: usize = 64;
const STREAM_CHUNK_CHARACTERS: usize = 24;
const MAX_CACHED_PIN_AGE: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum ServiceError {
    Config(String),
    Chain(String),
    Backend(String),
    Store(String),
    Gateway(GatewayError),
    Crypto(CryptoError),
    Internal(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration: {message}"),
            Self::Chain(message) => write!(formatter, "chain state: {message}"),
            Self::Backend(message) => write!(formatter, "model backend: {message}"),
            Self::Store(message) => write!(formatter, "gateway store: {message}"),
            Self::Gateway(error) => write!(formatter, "gateway core: {error:?}"),
            Self::Crypto(error) => write!(formatter, "cryptography: {error}"),
            Self::Internal(message) => write!(formatter, "internal: {message}"),
        }
    }
}

impl Error for ServiceError {}

impl From<CryptoError> for ServiceError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Clone)]
pub struct GatewayService {
    inner: Arc<ServiceState>,
}

struct ServiceState {
    config: RuntimeConfig,
    chain: ChainReader,
    backend: ModelBackend,
    store: GatewayStore,
    gateway: Mutex<Option<Gateway>>,
    latest_pin: RwLock<Option<ChainPin>>,
    quotes: Mutex<BTreeMap<Hash32, StoredQuote>>,
    pending_jobs: Mutex<BTreeMap<Hash32, PendingJob>>,
}

#[derive(Clone)]
struct StoredQuote {
    quote: PublicQuote,
    requester_credential: Hash32,
    quoted_input_tokens: u32,
}

struct PendingJob {
    job_id: Hash32,
    quote: PublicQuote,
    requester_credential: Hash32,
    input_tokens: u32,
    prompt: Zeroizing<String>,
    pin: ChainPin,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuoteRequest {
    pin_id: String,
    prompt_commitment: String,
    client_nonce: String,
    compute_profile: String,
    requested_finality: String,
    input_tokens: u32,
    maximum_output_tokens: u32,
    sponsor_requested: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobRequest {
    quote_id: String,
    prompt: String,
    prompt_commitment: String,
    client_nonce: String,
}

impl GatewayService {
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        let chain = ChainReader::new(
            config.expected_chain_id,
            config.expected_genesis_hash,
            config.activation.clone(),
            config.fee_schedule.schedule_id,
            config.pin_mode,
            config.state_endpoints.clone(),
            15_000,
        )?;
        let backend = ModelBackend::new(&config.model)?;
        let store = GatewayStore::open(&config.data_path)?;
        Ok(Self {
            inner: Arc::new(ServiceState {
                config,
                chain,
                backend,
                store,
                gateway: Mutex::new(None),
                latest_pin: RwLock::new(None),
                quotes: Mutex::new(BTreeMap::new()),
                pending_jobs: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    pub fn router(&self) -> Router {
        let body_limit = self
            .inner
            .config
            .maximum_prompt_bytes
            .saturating_add(16 * 1024);
        Router::new()
            .route("/api/wwm/v1/state", get(state_handler))
            .route("/api/wwm/v1/quotes", post(quote_handler))
            .route("/api/wwm/v1/jobs", post(job_handler))
            .route("/api/wwm/v1/jobs/{job_id}/stream", get(stream_handler))
            .route("/api/wwm/v1/jobs/{job_id}/receipt", get(receipt_handler))
            .layer(DefaultBodyLimit::max(body_limit))
            .fallback_service(
                ServeDir::new(self.inner.config.site_dir.clone())
                    .append_index_html_on_directories(true),
            )
            .with_state(self.clone())
    }

    pub async fn run(self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(self.inner.config.listen)
            .await
            .map_err(|error| ServiceError::Internal(format!("bind listener: {error}")))?;
        axum::serve(listener, self.router())
            .await
            .map_err(|error| ServiceError::Internal(format!("serve gateway: {error}")))
    }

    async fn refresh_chain(&self) -> Result<ChainPin> {
        let pin = self.inner.chain.pin().await?;
        let mut gateway = self.inner.gateway.lock().await;
        match gateway.as_mut() {
            Some(existing) => existing
                .update_pinned_state(pin.pinned_state.clone())
                .map_err(ServiceError::Gateway)?,
            None => {
                let signer = Keypair::from_seed(self.inner.config.gateway_seed);
                let mut pairs = self
                    .inner
                    .config
                    .state_endpoints
                    .iter()
                    .map(|endpoint| (endpoint.endpoint_id, endpoint.control_cluster))
                    .collect::<Vec<_>>();
                pairs.sort_by_key(|(endpoint_id, _)| *endpoint_id);
                let manifest = GatewayManifest {
                    gateway_key: signer.public_key().into_bytes(),
                    state_endpoint_ids: pairs.iter().map(|(id, _)| *id).collect(),
                    state_control_clusters: pairs.iter().map(|(_, cluster)| *cluster).collect(),
                    api_version: 1,
                    maximum_quote_lifetime_blocks: self.inner.config.quote_lifetime_blocks,
                };
                let mut created = match self.inner.config.pin_mode {
                    PinMode::StrictIndependent => Gateway::new(
                        signer,
                        manifest,
                        pin.pinned_state.clone(),
                        self.inner.config.fee_schedule,
                        self.inner.config.rate_policy,
                    ),
                    PinMode::TestSingleNode => Gateway::new_test_only(
                        signer,
                        manifest,
                        pin.pinned_state.clone(),
                        self.inner.config.fee_schedule,
                        self.inner.config.rate_policy,
                    ),
                }
                .map_err(ServiceError::Gateway)?;
                if let Some(sponsor) = &self.inner.config.sponsor {
                    created
                        .register_sponsor(sponsor.clone())
                        .map_err(ServiceError::Gateway)?;
                }
                *gateway = Some(created);
            }
        }
        *self.inner.latest_pin.write().await = Some(pin.clone());
        Ok(pin)
    }

    async fn current_or_refresh_pin(&self) -> Result<ChainPin> {
        if let Some(pin) = self.inner.latest_pin.read().await.clone() {
            if pin.observed_at.elapsed() <= MAX_CACHED_PIN_AGE {
                return Ok(pin);
            }
        }
        self.refresh_chain().await
    }
}

async fn state_handler(State(service): State<GatewayService>, headers: HeaderMap) -> Response {
    let credential = match credential_or_issue(&headers, &service.inner.config.credential_key) {
        Ok(value) => value,
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential_unavailable",
                &error.to_string(),
            )
        }
    };
    let (chain_result, model_result) = tokio::join!(
        service.current_or_refresh_pin(),
        service.inner.backend.health()
    );
    let model_ready = model_result.is_ok();
    let (pin, chain_error) = match chain_result {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let enabled = pin.is_some() && model_ready;
    let minimum_state_endpoints = match service.inner.config.pin_mode {
        PinMode::StrictIndependent => crate::MIN_STATE_ENDPOINTS,
        PinMode::TestSingleNode => 1,
    };
    let disclosure = if enabled {
        match service.inner.config.pin_mode {
            PinMode::StrictIndependent => {
                "TEST ONLY. The model is bound to an independent finalized-state read quorum, but inference uses one local model with no executor committee match; no WWM evidence gate or production control is enabled."
            }
            PinMode::TestSingleNode => {
                "TEST ONLY. A single node pins chain identity and finalized state, and one local model executes without an executor committee match. This is not independent quorum, production activation, or external evidence."
            }
        }
    } else if let Some(error) = chain_error {
        return state_response(
            credential,
            json!({
                "enabled": false,
                "test_only": true,
                "activation_scope": "TEST_ONLY",
                "evidence_gates_passed": false,
                "controls_enabled": false,
                "model_ready": model_ready,
                "model": service.inner.backend.model_name(),
                "minimum_state_endpoints": minimum_state_endpoints,
                "pin": Value::Null,
                "disclosure": format!("Fail closed: {error}"),
                "available_finality": ["SOFT"],
                "chain_write": "NONE"
            }),
        );
    } else {
        "Fail closed: the configured model backend is unavailable or the model is not installed."
    };
    let pin_json = pin.as_ref().map_or(Value::Null, pin_json);
    state_response(
        credential,
        json!({
            "enabled": enabled,
            "test_only": true,
            "activation_scope": "TEST_ONLY",
            "evidence_gates_passed": false,
            "controls_enabled": false,
            "model_ready": model_ready,
            "model": service.inner.backend.model_name(),
            "execution_mode": "LOCAL_SINGLE_MODEL",
            "executor_claim_count": 1,
            "soft_committee_quorum_met": false,
            "minimum_state_endpoints": minimum_state_endpoints,
            "pin": pin_json,
            "disclosure": disclosure,
            "available_finality": ["SOFT"],
            "chain_write": "PIN_READ_ONLY_NO_RECEIPT_SUBMISSION"
        }),
    )
}

async fn quote_handler(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<QuoteRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(value) => value,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_quote_request",
                "The quote request is malformed.",
            )
        }
    };
    let requester_credential =
        match credential_from_headers(&headers, &service.inner.config.credential_key) {
            Ok(value) => value,
            Err(failure) => return failure.into_response(),
        };
    if request.compute_profile != "P0_OPEN"
        || request.requested_finality != "SOFT"
        || request.input_tokens == 0
        || request.maximum_output_tokens == 0
        || request.maximum_output_tokens > crate::MAX_OUTPUT_TOKENS
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "unsupported_query_profile",
            "Only bounded P0_OPEN/SOFT test queries are available.",
        );
    }
    let pin_id = match api_hash(&request.pin_id) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let prompt_commitment = match api_hash(&request.prompt_commitment) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let client_nonce = match api_hash(&request.client_nonce) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let pin = match service.current_or_refresh_pin().await {
        Ok(value) => value,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_not_ready",
                "The finalized-state pin is unavailable or stale.",
            )
        }
    };
    if service.inner.backend.health().await.is_err() {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "model_not_ready",
            "The configured local model is unavailable.",
        );
    }
    if pin_id != pin.pinned_state.pin_id {
        return api_error(
            StatusCode::CONFLICT,
            "stale_state_pin",
            "Refresh state and request a quote against the current pin.",
        );
    }
    let sponsor_id = if request.sponsor_requested {
        match &service.inner.config.sponsor {
            Some(sponsor) => Some(sponsor.sponsor_id),
            None => {
                return api_error(
                    StatusCode::PAYMENT_REQUIRED,
                    "test_sponsor_unavailable",
                    "No test-network sponsor is configured.",
                )
            }
        }
    } else {
        None
    };
    let public_request = PublicQueryRequest {
        requester_credential,
        prompt_commitment,
        bounds: QueryBounds {
            input_tokens: request.input_tokens,
            retrieved_context_tokens: 0,
            maximum_output_tokens: request.maximum_output_tokens,
            requested_finality: FinalityClass::Soft,
        },
        sponsor_id,
        client_nonce,
    };
    let quote = {
        let mut gateway = service.inner.gateway.lock().await;
        let Some(gateway) = gateway.as_mut() else {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_not_ready",
                "The gateway core is unavailable.",
            );
        };
        match gateway.issue_quote(
            &public_request,
            pin.current_height,
            service.inner.config.quote_lifetime_blocks,
        ) {
            Ok(value) => value,
            Err(error) => return gateway_error(error),
        }
    };
    let wire = quote_json(&quote);
    if let Err(error) = service.inner.store.insert_quote(quote.quote_id, &wire) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "quote_persistence_failed",
            &error.to_string(),
        );
    }
    let mut quotes = service.inner.quotes.lock().await;
    quotes.retain(|_, value| value.quote.expires_height > pin.current_height);
    if quotes.len() >= MAX_QUOTES {
        return api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "quote_capacity_reached",
            "Too many unexpired test quotes are open.",
        );
    }
    quotes.insert(
        quote.quote_id,
        StoredQuote {
            quote,
            requester_credential,
            quoted_input_tokens: request.input_tokens,
        },
    );
    json_response(StatusCode::OK, wire)
}

async fn job_handler(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<JobRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(value) => value,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_job_request",
                "The job request is malformed.",
            )
        }
    };
    let requester_credential =
        match credential_from_headers(&headers, &service.inner.config.credential_key) {
            Ok(value) => value,
            Err(failure) => return failure.into_response(),
        };
    if request.prompt.trim().is_empty()
        || request.prompt.len() > service.inner.config.maximum_prompt_bytes
        || request.prompt.as_bytes().contains(&0)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_prompt",
            "The prompt is empty, contains NUL, or exceeds the configured byte bound.",
        );
    }
    let quote_id = match api_hash(&request.quote_id) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let prompt_commitment = match api_hash(&request.prompt_commitment) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let client_nonce = match api_hash(&request.client_nonce) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    if sha256(request.prompt.as_bytes()) != prompt_commitment {
        return api_error(
            StatusCode::BAD_REQUEST,
            "prompt_commitment_mismatch",
            "The plaintext prompt does not match the quoted commitment.",
        );
    }
    let stored = {
        let quotes = service.inner.quotes.lock().await;
        match quotes.get(&quote_id) {
            Some(value) => value.clone(),
            None => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "unknown_quote",
                    "The quote is unknown, expired, or already opened.",
                )
            }
        }
    };
    if stored.requester_credential != requester_credential
        || stored.quote.prompt_commitment != prompt_commitment
        || stored.quote.client_nonce != client_nonce
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "quote_binding_mismatch",
            "The quote is not bound to this credential, prompt, and nonce.",
        );
    }
    let input_tokens = estimate_tokens(&request.prompt);
    if input_tokens > stored.quoted_input_tokens {
        return api_error(
            StatusCode::BAD_REQUEST,
            "input_bound_exceeded",
            "The prompt exceeds the input-token bound declared at quote time.",
        );
    }
    {
        let pending = service.inner.pending_jobs.lock().await;
        if pending.len() >= service.inner.config.maximum_pending_jobs {
            return api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "job_capacity_reached",
                "The bounded test job queue is full.",
            );
        }
    }
    let job_id = match hash_domain(
        DomainId::WwmPublicQuote,
        &[b"JOB", &stored.quote.quote_id, &stored.quote.client_nonce],
    ) {
        Ok(value) => value.into_bytes(),
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "job_id_failed",
                &error.to_string(),
            )
        }
    };
    if let Err(error) = service.inner.store.insert_job(
        job_id,
        stored.quote.quote_id,
        prompt_commitment,
        requester_credential,
    ) {
        return api_error(
            StatusCode::CONFLICT,
            "job_persistence_failed",
            &error.to_string(),
        );
    }
    let current_height = current_height(&service).await;
    let opened = {
        let mut gateway = service.inner.gateway.lock().await;
        match gateway.as_mut() {
            Some(gateway) => gateway.open_job(&stored.quote, current_height),
            None => Err(GatewayError::InvalidManifest),
        }
    };
    match opened {
        Ok(value) if value == job_id => {}
        Ok(_) => {
            let _ = service.inner.store.fail_job(job_id, "JOB_ID_DIVERGENCE");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "job_id_divergence",
                "The gateway core produced a different job identifier.",
            );
        }
        Err(error) => {
            let _ = service.inner.store.fail_job(job_id, "CORE_OPEN_REJECTED");
            return gateway_error(error);
        }
    }
    service.inner.quotes.lock().await.remove(&quote_id);
    let pin = match service.inner.latest_pin.read().await.clone() {
        Some(value) => value,
        None => {
            let _ = service.inner.store.fail_job(job_id, "PIN_UNAVAILABLE");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "pin_unavailable",
                "The pinned state disappeared before job admission.",
            );
        }
    };
    service.inner.pending_jobs.lock().await.insert(
        job_id,
        PendingJob {
            job_id,
            quote: stored.quote,
            requester_credential,
            input_tokens,
            prompt: Zeroizing::new(request.prompt),
            pin,
        },
    );
    json_response(
        StatusCode::ACCEPTED,
        json!({
            "job_id": hex_hash(&job_id),
            "stream_url": format!("/api/wwm/v1/jobs/{}/stream", hex_hash(&job_id)),
            "test_only": true,
            "chain_write": "NONE"
        }),
    )
}

async fn stream_handler(
    State(service): State<GatewayService>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let requester_credential =
        match credential_from_headers(&headers, &service.inner.config.credential_key) {
            Ok(value) => value,
            Err(failure) => return failure.into_response(),
        };
    let job_id = match api_hash(&job_id) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let pending = {
        let mut pending_jobs = service.inner.pending_jobs.lock().await;
        match pending_jobs.remove(&job_id) {
            Some(value) if value.requester_credential == requester_credential => Some(value),
            Some(value) => {
                pending_jobs.insert(job_id, value);
                None
            }
            None => None,
        }
    };
    let Some(pending) = pending else {
        return match service
            .inner
            .store
            .receipt_for_job(job_id, requester_credential)
        {
            Ok(Some(receipt)) => single_event_stream("receipt", receipt),
            Ok(None) => api_error(
                StatusCode::NOT_FOUND,
                "unknown_job",
                "The job is unknown or not owned by this credential.",
            ),
            Err(error) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "receipt_lookup_failed",
                &error.to_string(),
            ),
        };
    };
    match service.inner.store.claim_job(job_id) {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::CONFLICT,
                "job_already_claimed",
                "The job stream has already been opened.",
            )
        }
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "job_claim_failed",
                &error.to_string(),
            )
        }
    }
    let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let runner = service.clone();
    tokio::spawn(async move {
        execute_job(runner, pending, sender).await;
    });
    sse_response(receiver)
}

async fn receipt_handler(
    State(service): State<GatewayService>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let requester_credential =
        match credential_from_headers(&headers, &service.inner.config.credential_key) {
            Ok(value) => value,
            Err(failure) => return failure.into_response(),
        };
    let job_id = match api_hash(&job_id) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    match service
        .inner
        .store
        .receipt_for_job(job_id, requester_credential)
    {
        Ok(Some(receipt)) => json_response(StatusCode::OK, receipt),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "receipt_not_found",
            "No receipt exists for this credential and job.",
        ),
        Err(error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "receipt_lookup_failed",
            &error.to_string(),
        ),
    }
}

async fn execute_job(service: GatewayService, pending: PendingJob, sender: mpsc::Sender<Event>) {
    if let Err(error) = execute_job_inner(&service, &pending, &sender).await {
        let _ = service.inner.store.fail_job(pending.job_id, error.code());
        let _ = send_event(
            &sender,
            "gateway-error",
            json!({
                "error": "The test model stopped before a signed receipt was committed.",
                "code": error.code()
            }),
        )
        .await;
    }
}

async fn execute_job_inner(
    service: &GatewayService,
    pending: &PendingJob,
    sender: &mpsc::Sender<Event>,
) -> Result<()> {
    let completion = service
        .inner
        .backend
        .complete(&pending.prompt, pending.quote.bounds.maximum_output_tokens)
        .await?;
    for chunk in text_chunks(&completion.text, STREAM_CHUNK_CHARACTERS) {
        let _ = send_event(sender, "token", json!({"token": chunk})).await;
    }
    let token_history_root = hash_domain(
        DomainId::WwmPublicReceipt,
        &[
            b"TEST-ONLY-TOKEN-HISTORY",
            &pending.job_id,
            completion.text.as_bytes(),
        ],
    )?
    .into_bytes();
    let settlement_id = hash_domain(
        DomainId::WwmPublicReceipt,
        &[
            b"TEST-ONLY-SETTLEMENT",
            &pending.job_id,
            &pending.pin.pinned_state.pin_id,
            &token_history_root,
        ],
    )?
    .into_bytes();
    let charged_micro_noos = actual_fee(
        service.inner.config.fee_schedule,
        pending.input_tokens,
        completion.completion_tokens,
        pending.quote.maximum_fee_micro_noos,
    )?;
    let (receipt_id, receipt) = {
        let mut gateway = service.inner.gateway.lock().await;
        let gateway = gateway
            .as_mut()
            .ok_or_else(|| ServiceError::Internal("gateway disappeared".to_owned()))?;
        let receipt_id = gateway
            .record_receipt(
                pending.job_id,
                token_history_root,
                None,
                Vec::new(),
                FinalityClass::Soft,
                settlement_id,
                charged_micro_noos,
            )
            .map_err(ServiceError::Gateway)?;
        let receipt = gateway
            .receipt(&receipt_id)
            .cloned()
            .ok_or_else(|| ServiceError::Internal("receipt disappeared".to_owned()))?;
        receipt.validate().map_err(ServiceError::Gateway)?;
        (receipt_id, receipt)
    };
    let wire = receipt_json(&receipt, &pending.pin, service.inner.backend.model_name());
    service
        .inner
        .store
        .complete_job(pending.job_id, receipt_id, &wire)?;
    let _ = send_event(
        sender,
        "finality",
        json!({
            "actual_finality": "SOFT",
            "execution_mode": "LOCAL_SINGLE_MODEL",
            "executor_claim_count": 1,
            "soft_committee_quorum_met": false
        }),
    )
    .await;
    let _ = send_event(sender, "receipt", wire).await;
    Ok(())
}

impl ServiceError {
    fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "CONFIGURATION",
            Self::Chain(_) => "CHAIN_STATE",
            Self::Backend(_) => "MODEL_BACKEND",
            Self::Store(_) => "PERSISTENCE",
            Self::Gateway(_) => "GATEWAY_CORE",
            Self::Crypto(_) => "CRYPTOGRAPHY",
            Self::Internal(_) => "INTERNAL",
        }
    }
}

fn pin_json(pin: &ChainPin) -> Value {
    json!({
        "pin_id": hex_hash(&pin.pinned_state.pin_id),
        "chain_id": hex_hash(&pin.pinned_state.chain_id),
        "genesis_hash": hex_hash(&pin.pinned_state.genesis_hash),
        "finalized_height": pin.pinned_state.finalized_height,
        "finalized_hash": hex_hash(&pin.pinned_state.finalized_hash),
        "capsule_id": hex_hash(&pin.pinned_state.capsule_id),
        "query_policy_id": hex_hash(&pin.pinned_state.query_policy_id),
        "knowledge_snapshot_id": hex_hash(&pin.pinned_state.knowledge_snapshot_id),
        "executor_registry_epoch": pin.pinned_state.executor_registry_epoch,
        "fee_schedule_id": hex_hash(&pin.pinned_state.fee_schedule_id),
        "agreeing_endpoints": pin.pinned_state.agreeing_endpoints.iter().map(hex_hash).collect::<Vec<_>>(),
        "agreeing_control_clusters": pin.pinned_state.agreeing_control_clusters.iter().map(hex_hash).collect::<Vec<_>>(),
        "observed_endpoints": pin.observed_endpoints,
        "pin_mode": match pin.pin_mode {
            PinMode::StrictIndependent => "STRICT_INDEPENDENT",
            PinMode::TestSingleNode => "TEST_SINGLE_NODE"
        }
    })
}

fn quote_json(quote: &PublicQuote) -> Value {
    json!({
        "quote_id": hex_hash(&quote.quote_id),
        "gateway_key": hex_hash(&quote.gateway_key),
        "signature": hex::encode(quote.signature),
        "pin_id": hex_hash(&quote.pin_id),
        "chain_id": hex_hash(&quote.chain_id),
        "genesis_hash": hex_hash(&quote.genesis_hash),
        "capsule_id": hex_hash(&quote.capsule_id),
        "knowledge_snapshot_id": hex_hash(&quote.knowledge_snapshot_id),
        "query_policy_id": hex_hash(&quote.query_policy_id),
        "fee_schedule_id": hex_hash(&quote.fee_schedule_id),
        "executor_registry_epoch": quote.executor_registry_epoch,
        "prompt_commitment": hex_hash(&quote.prompt_commitment),
        "client_nonce": hex_hash(&quote.client_nonce),
        "maximum_fee_micro_noos": quote.maximum_fee_micro_noos,
        "expires_height": quote.expires_height,
        "sponsor_id": quote.sponsor_id.as_ref().map(hex_hash),
        "requested_finality": "SOFT",
        "test_only": true
    })
}

fn receipt_json(receipt: &ReceiptView, pin: &ChainPin, model: &str) -> Value {
    json!({
        "receipt_id": hex_hash(&receipt.receipt_id),
        "gateway_key": hex_hash(&receipt.gateway_key),
        "signature": hex::encode(receipt.signature),
        "job_id": hex_hash(&receipt.job_id),
        "quote_id": hex_hash(&receipt.quote_id),
        "capsule_id": hex_hash(&receipt.capsule_id),
        "knowledge_snapshot_id": hex_hash(&receipt.knowledge_snapshot_id),
        "token_history_root": hex_hash(&receipt.token_history_root),
        "retrieval_receipt_id": receipt.retrieval_receipt_id.as_ref().map(hex_hash),
        "sources": receipt.source_mindlink_ids.iter().map(|id| json!({"mindlink_id": hex_hash(id)})).collect::<Vec<_>>(),
        "actual_finality": receipt.assurance_label,
        "execution_mode": "LOCAL_SINGLE_MODEL",
        "executor_claim_count": 1,
        "soft_committee_quorum_met": false,
        "settlement_id": hex_hash(&receipt.settlement_id),
        "charged_micro_noos": receipt.charged_micro_noos,
        "refunded_micro_noos": receipt.refunded_micro_noos,
        "pin_id": hex_hash(&pin.pinned_state.pin_id),
        "finalized_height": pin.pinned_state.finalized_height,
        "finalized_hash": hex_hash(&pin.pinned_state.finalized_hash),
        "model": model,
        "test_only": true,
        "evidence_gates_passed": false,
        "on_chain_receipt": false,
        "chain_anchor_status": "PINNED_FINALIZED_STATE_ONLY",
        "disclosure": "One local model executed this test job; no executor committee match was performed. The gateway signature does not establish factual accuracy, and this receipt was not submitted as a chain transaction."
    })
}

fn actual_fee(
    schedule: FeeSchedule,
    input_tokens: u32,
    output_tokens: u32,
    maximum: u64,
) -> Result<u64> {
    let input = schedule
        .input_token_micro_noos
        .checked_mul(u64::from(input_tokens))
        .ok_or_else(|| ServiceError::Internal("input fee overflow".to_owned()))?;
    let output = schedule
        .output_token_micro_noos
        .checked_mul(u64::from(output_tokens))
        .ok_or_else(|| ServiceError::Internal("output fee overflow".to_owned()))?;
    schedule
        .base_micro_noos
        .checked_add(input)
        .and_then(|value| value.checked_add(output))
        .map(|value| value.min(maximum))
        .ok_or_else(|| ServiceError::Internal("actual fee overflow".to_owned()))
}

async fn current_height(service: &GatewayService) -> u64 {
    service
        .inner
        .latest_pin
        .read()
        .await
        .as_ref()
        .map_or(0, |pin| pin.current_height)
}

fn estimate_tokens(prompt: &str) -> u32 {
    let estimated = prompt.chars().count().div_ceil(4).max(1);
    u32::try_from(estimated).unwrap_or(u32::MAX)
}

fn text_chunks(text: &str, maximum_characters: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut count = 0;
    for (index, _) in text.char_indices() {
        if count == maximum_characters {
            chunks.push(text[start..index].to_owned());
            start = index;
            count = 0;
        }
        count = count.saturating_add(1);
    }
    if start < text.len() {
        chunks.push(text[start..].to_owned());
    }
    chunks
}

async fn send_event(sender: &mpsc::Sender<Event>, name: &str, value: Value) -> bool {
    let event = Event::default().event(name).data(value.to_string());
    sender.send(event).await.is_ok()
}

fn sse_response(receiver: mpsc::Receiver<Event>) -> Response {
    let stream = unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|event| (Ok::<Event, Infallible>(event), receiver))
    });
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

fn single_event_stream(name: &'static str, value: Value) -> Response {
    let (sender, receiver) = mpsc::channel(1);
    let _ = sender.try_send(Event::default().event(name).data(value.to_string()));
    drop(sender);
    sse_response(receiver)
}

fn state_response(credential: Credential, value: Value) -> Response {
    let mut response = json_response(StatusCode::OK, value);
    if credential.newly_issued {
        if let Ok(cookie) = HeaderValue::from_str(&format!(
            "{CREDENTIAL_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400",
            credential.token
        )) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
    }
    response
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, json!({"error": message, "code": code}))
}

#[derive(Debug, Clone, Copy)]
struct ApiFailure {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiFailure {
    fn into_response(self) -> Response {
        api_error(self.status, self.code, self.message)
    }
}

fn gateway_error(error: GatewayError) -> Response {
    match error {
        GatewayError::RateLimited => api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "The test credential exceeded its bounded request allowance.",
        ),
        GatewayError::SponsorExpired
        | GatewayError::SponsorExhausted
        | GatewayError::SponsorPolicy
        | GatewayError::UnknownSponsor => api_error(
            StatusCode::PAYMENT_REQUIRED,
            "sponsor_unavailable",
            "The test sponsor cannot fund this quote.",
        ),
        GatewayError::QuoteExpired => api_error(
            StatusCode::CONFLICT,
            "quote_expired",
            "The quote expired or its finalized-state pin changed.",
        ),
        _ => api_error(
            StatusCode::BAD_REQUEST,
            "gateway_rejected",
            "The gateway core rejected the bounded request.",
        ),
    }
}

struct Credential {
    token: String,
    newly_issued: bool,
}

fn credential_or_issue(headers: &HeaderMap, key: &Hash32) -> Result<Credential> {
    if let Some(token) = cookie_value(headers, CREDENTIAL_COOKIE) {
        if verify_credential(&token, key).is_some() {
            return Ok(Credential {
                token,
                newly_issued: false,
            });
        }
    }
    issue_credential(key)
}

fn credential_from_headers(
    headers: &HeaderMap,
    key: &Hash32,
) -> std::result::Result<Hash32, ApiFailure> {
    let Some(token) = cookie_value(headers, CREDENTIAL_COOKIE) else {
        return Err(ApiFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "credential_required",
            message: "Load gateway state first to receive a test credential.",
        });
    };
    verify_credential(&token, key).ok_or(ApiFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_credential",
        message: "The test credential is invalid.",
    })
}

fn issue_credential(key: &Hash32) -> Result<Credential> {
    let mut nonce = [0_u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| ServiceError::Internal(format!("credential entropy: {error}")))?;
    let mac = credential_mac(key, &nonce);
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&nonce);
    bytes[32..].copy_from_slice(mac.as_bytes());
    let token = hex::encode(bytes);
    Ok(Credential {
        token,
        newly_issued: true,
    })
}

fn verify_credential(token: &str, key: &Hash32) -> Option<Hash32> {
    if token.len() != 128 || token.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let bytes = hex::decode(token).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&bytes[..32]);
    let expected = credential_mac(key, &nonce);
    if !constant_time_eq(expected.as_bytes(), &bytes[32..]) {
        return None;
    }
    Some(*blake3::hash(&bytes).as_bytes())
}

fn credential_mac(key: &Hash32, nonce: &Hash32) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"NOOS/WWM/TEST-CREDENTIAL/V1");
    hasher.update(nonce);
    hasher.finalize()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    value.split(';').find_map(|entry| {
        let (key, value) = entry.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn api_hash(value: &str) -> std::result::Result<Hash32, ApiFailure> {
    config::decode_hash(value, "hash").map_err(|_| ApiFailure {
        status: StatusCode::BAD_REQUEST,
        code: "invalid_hash",
        message: "A required identifier is not canonical lowercase hex.",
    })
}

fn sha256(bytes: &[u8]) -> Hash32 {
    Sha256::digest(bytes).into()
}

fn hex_hash(hash: &Hash32) -> String {
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::unwrap_used
    )]

    use super::*;
    use crate::{RatePolicy, SponsorAccount};
    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request},
    };
    use config::{Activation, ModelApi, ModelConfig, StateEndpoint};
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn api_request(
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&value).unwrap())
            }
            None => Body::empty(),
        };
        builder.body(body).unwrap()
    }

    async fn body_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn api_streams_model_answer_and_persists_no_raw_prompt() {
        let chain_id = h(1);
        let genesis_hash = h(2);
        let finalized_hash = h(3);
        let app = Router::new()
            .route(
                "/status",
                get(move || async move {
                    Json(json!({
                        "ready": true,
                        "chain_id": hex_hash(&chain_id),
                        "genesis_hash": hex_hash(&genesis_hash),
                        "unsafe_head": {"height": 100},
                        "finalized": {
                            "height": 99,
                            "hash": hex_hash(&finalized_hash)
                        }
                    }))
                }),
            )
            .route(
                "/api/tags",
                get(|| async {
                    Json(json!({
                        "models": [{"name": "test-model"}]
                    }))
                }),
            )
            .route(
                "/api/chat",
                post(|| async {
                    Json(json!({
                        "message": {"content": "bounded test-only answer"},
                        "eval_count": 4
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = listener.local_addr().unwrap();
        let backend_server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let directory = tempdir().unwrap();
        let service = GatewayService::new(RuntimeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            site_dir: directory.path().to_path_buf(),
            data_path: directory.path().join("gateway.sqlite3"),
            gateway_seed: h(10),
            credential_key: h(11),
            expected_chain_id: chain_id,
            expected_genesis_hash: genesis_hash,
            pin_mode: PinMode::TestSingleNode,
            state_endpoints: vec![StateEndpoint {
                url: format!("http://{backend_address}/status"),
                endpoint_id: h(12),
                control_cluster: h(13),
                bearer_token: None,
            }],
            activation: Activation {
                capsule_id: h(14),
                query_policy_id: h(15),
                knowledge_snapshot_id: h(16),
                executor_registry_epoch: 1,
            },
            fee_schedule: FeeSchedule {
                schedule_id: h(17),
                base_micro_noos: 10,
                input_token_micro_noos: 1,
                retrieval_token_micro_noos: 1,
                output_token_micro_noos: 2,
                anchored_surcharge_micro_noos: 0,
                assured_surcharge_micro_noos: 0,
            },
            rate_policy: RatePolicy {
                window_blocks: 256,
                maximum_requests: 100,
                maximum_output_tokens: 100_000,
            },
            sponsor: Some(SponsorAccount {
                sponsor_id: h(18),
                remaining_micro_noos: 1_000_000,
                per_job_cap_micro_noos: 100_000,
                allowed_capsule_id: Some(h(14)),
                expires_height: 10_000,
            }),
            model: ModelConfig {
                api: ModelApi::Ollama,
                base_url: format!("http://{backend_address}"),
                model: "test-model".to_owned(),
                api_key: None,
                system_prompt: "test-only system".to_owned(),
                timeout_ms: 5_000,
                num_gpu: Some(0),
            },
            quote_lifetime_blocks: 64,
            maximum_prompt_bytes: 48_000,
            maximum_pending_jobs: 64,
        })
        .unwrap();
        let router = service.router();

        let state_response = router
            .clone()
            .oneshot(api_request(Method::GET, "/api/wwm/v1/state", None, None))
            .await
            .unwrap();
        assert_eq!(state_response.status(), StatusCode::OK);
        let cookie = state_response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let state = body_json(state_response).await;
        assert_eq!(state["test_only"], true);
        assert_eq!(state["pin"]["pin_mode"], "TEST_SINGLE_NODE");
        assert_eq!(state["execution_mode"], "LOCAL_SINGLE_MODEL");
        assert_eq!(state["executor_claim_count"], 1);
        assert_eq!(state["soft_committee_quorum_met"], false);
        let pin_id = state["pin"]["pin_id"].as_str().unwrap().to_owned();

        let prompt = "private raw question";
        let prompt_commitment = hex_hash(&sha256(prompt.as_bytes()));
        let client_nonce = hex_hash(&h(19));
        let quote_response = router
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/api/wwm/v1/quotes",
                Some(&cookie),
                Some(json!({
                    "pin_id": pin_id,
                    "prompt_commitment": prompt_commitment,
                    "client_nonce": client_nonce,
                    "compute_profile": "P0_OPEN",
                    "requested_finality": "SOFT",
                    "input_tokens": 5,
                    "maximum_output_tokens": 64,
                    "sponsor_requested": true
                })),
            ))
            .await
            .unwrap();
        assert_eq!(quote_response.status(), StatusCode::OK);
        let quote = body_json(quote_response).await;
        let quote_id = quote["quote_id"].as_str().unwrap().to_owned();

        let job_response = router
            .clone()
            .oneshot(api_request(
                Method::POST,
                "/api/wwm/v1/jobs",
                Some(&cookie),
                Some(json!({
                    "quote_id": quote_id,
                    "prompt": prompt,
                    "prompt_commitment": prompt_commitment,
                    "client_nonce": client_nonce
                })),
            ))
            .await
            .unwrap();
        assert_eq!(job_response.status(), StatusCode::ACCEPTED);
        let job = body_json(job_response).await;
        let job_id = job["job_id"].as_str().unwrap().to_owned();
        let stream_url = job["stream_url"].as_str().unwrap();
        let stream_response = router
            .clone()
            .oneshot(api_request(Method::GET, stream_url, Some(&cookie), None))
            .await
            .unwrap();
        assert_eq!(stream_response.status(), StatusCode::OK);
        let stream = to_bytes(stream_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let stream = String::from_utf8(stream.to_vec()).unwrap();
        assert!(stream.contains("event: token"));
        assert!(stream.contains("bounded test-only answer"));
        assert!(stream.contains("event: receipt"));

        let receipt_response = router
            .oneshot(api_request(
                Method::GET,
                &format!("/api/wwm/v1/jobs/{job_id}/receipt"),
                Some(&cookie),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(receipt_response.status(), StatusCode::OK);
        let receipt = body_json(receipt_response).await;
        assert_eq!(receipt["actual_finality"], "SOFT");
        assert_eq!(receipt["execution_mode"], "LOCAL_SINGLE_MODEL");
        assert_eq!(receipt["executor_claim_count"], 1);
        assert_eq!(receipt["soft_committee_quorum_met"], false);
        assert_eq!(receipt["on_chain_receipt"], false);
        assert_eq!(
            receipt["chain_anchor_status"],
            "PINNED_FINALIZED_STATE_ONLY"
        );
        assert_eq!(receipt["test_only"], true);
        assert_eq!(receipt["signature"].as_str().unwrap().len(), 128);
        assert!(!service.inner.store.persisted_prompt(prompt).unwrap());
        backend_server.abort();
    }
}
