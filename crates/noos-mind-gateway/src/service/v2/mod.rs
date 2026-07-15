pub mod auth;
pub mod executor;
pub mod model;
pub mod store;

use async_trait::async_trait;
use auth::{AuthError, SecurityConfig, TenantIdentity};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{sse::Event, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use executor::{select_registered_executor, DispatchError, ExecutorDispatcher};
use futures_util::stream;
use model::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, RwLock},
};
use store::{DurabilityClass, GatewayV2Store, OutboxKind, StoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentAssurance {
    TestOnly,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Error {
    Configuration(&'static str),
    Resolution(String),
    Unauthorized,
    Forbidden(&'static str),
    Invalid(&'static str),
    Conflict(&'static str),
    NotFound,
    Dispatch(String),
    Store(String),
    Settlement(String),
    Internal(String),
}

#[async_trait]
pub trait FinalizedResolver: Send + Sync {
    async fn resolve(&self) -> Result<FinalizedResolution, V2Error>;
}

pub trait GatewaySigner: Send + Sync {
    fn assurance(&self) -> ComponentAssurance;
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<String, V2Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementResult {
    pub chain_anchor: String,
    pub state: SettlementState,
}

#[async_trait]
pub trait SettlementSubmitter: Send + Sync {
    fn assurance(&self) -> ComponentAssurance;
    async fn settle(&self, receipt: &Receipt, refund: bool) -> Result<SettlementResult, V2Error>;
}

#[async_trait]
pub trait PaymentVerifier: Send + Sync {
    fn assurance(&self) -> ComponentAssurance;
    async fn verify(
        &self,
        tenant: &str,
        payment: &PaymentAuthorization,
        resolution: &FinalizedResolution,
        maximum_fee_micro_noos: u64,
    ) -> Result<String, V2Error>;
}

#[derive(Debug, Clone)]
pub struct V2Config {
    pub allow_test_components: bool,
    pub auto_reconcile: bool,
    pub maximum_prompt_bytes: usize,
    pub quote_lifetime_blocks: u64,
    pub maximum_fee_base_micro_noos: u64,
    pub maximum_fee_per_token_micro_noos: u64,
}

impl Default for V2Config {
    fn default() -> Self {
        Self {
            allow_test_components: false,
            auto_reconcile: true,
            maximum_prompt_bytes: MAX_PROMPT_BYTES,
            quote_lifetime_blocks: 20,
            maximum_fee_base_micro_noos: 10_000,
            maximum_fee_per_token_micro_noos: 10,
        }
    }
}

#[derive(Clone)]
pub struct GatewayV2Service {
    inner: Arc<V2State>,
}

struct V2State {
    config: V2Config,
    security: SecurityConfig,
    resolver: Arc<dyn FinalizedResolver>,
    dispatcher: Arc<dyn ExecutorDispatcher>,
    store: Arc<dyn GatewayV2Store>,
    signer: Arc<dyn GatewaySigner>,
    settlement: Arc<dyn SettlementSubmitter>,
    payments: Arc<dyn PaymentVerifier>,
}

impl GatewayV2Service {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: V2Config,
        security: SecurityConfig,
        resolver: Arc<dyn FinalizedResolver>,
        dispatcher: Arc<dyn ExecutorDispatcher>,
        store: Arc<dyn GatewayV2Store>,
        signer: Arc<dyn GatewaySigner>,
        settlement: Arc<dyn SettlementSubmitter>,
        payments: Arc<dyn PaymentVerifier>,
    ) -> Result<Self, V2Error> {
        if config.maximum_prompt_bytes == 0
            || config.maximum_prompt_bytes > MAX_PROMPT_BYTES
            || config.quote_lifetime_blocks == 0
            || config.maximum_fee_base_micro_noos == 0
            || config.maximum_fee_per_token_micro_noos == 0
        {
            return Err(V2Error::Configuration("invalid gateway bounds"));
        }
        if !config.allow_test_components
            && (store.durability() != DurabilityClass::SynchronousReplicated
                || signer.assurance() != ComponentAssurance::Production
                || settlement.assurance() != ComponentAssurance::Production
                || payments.assurance() != ComponentAssurance::Production)
        {
            return Err(V2Error::Configuration(
                "production requires synchronous replicated storage, KMS/HSM signing, chain settlement, and payment verification",
            ));
        }
        if signer.key_id().trim().is_empty() {
            return Err(V2Error::Configuration("signer key id is required"));
        }
        Ok(Self {
            inner: Arc::new(V2State {
                config,
                security,
                resolver,
                dispatcher,
                store,
                signer,
                settlement,
                payments,
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/api/wwm/v2/state", get(state_handler))
            .route("/api/wwm/v2/capsules/{capsule_id}", get(capsule_handler))
            .route("/api/wwm/v2/quotes", post(quote_handler))
            .route("/api/wwm/v2/jobs", post(job_handler))
            .route("/api/wwm/v2/jobs/{job_id}/stream", get(stream_handler))
            .route("/api/wwm/v2/jobs/{job_id}/cancel", post(cancel_handler))
            .route("/api/wwm/v2/jobs/{job_id}/receipt", get(receipt_handler))
            .route("/v1/models", get(models_handler))
            .route("/v1/chat/completions", post(openai_chat_handler))
            .route("/v1/responses", post(openai_responses_handler))
            .layer(DefaultBodyLimit::max(
                self.inner
                    .config
                    .maximum_prompt_bytes
                    .saturating_add(32 * 1024),
            ))
            .with_state(self.clone())
    }

    async fn resolution(&self) -> Result<FinalizedResolution, V2Error> {
        let resolution = self.inner.resolver.resolve().await?;
        resolution
            .validate()
            .map_err(|message| V2Error::Resolution(message.to_owned()))?;
        Ok(resolution)
    }

    async fn issue_quote(
        &self,
        tenant: &TenantIdentity,
        request: QuoteRequest,
    ) -> Result<QuoteResponse, V2Error> {
        validate_identifier(&request.request_id, 128)?;
        validate_identifier(&request.client_nonce, 256)?;
        validate_commitment(&request.prompt_commitment)?;
        if request.maximum_output_tokens == 0
            || request.maximum_output_tokens > MAX_OUTPUT_TOKENS
            || request.input_tokens == 0
            || (request.payment.mode == PaymentMode::Paid
                && request.payment.authorization.trim().is_empty())
        {
            return Err(V2Error::Invalid(
                "invalid quote bounds or payment authorization",
            ));
        }
        let resolution = self.resolution().await?;
        if request.pin_id != resolution.pin_id {
            return Err(V2Error::Conflict("stale or unverified pin"));
        }
        let capsule = resolution
            .capsule(&request.capsule_id)
            .ok_or(V2Error::NotFound)?;
        if capsule.activation_state != ActivationState::Active {
            return Err(V2Error::Conflict(
                "AUTHORIZED_NOT_ACTIVE capsules cannot dispatch",
            ));
        }
        if request.execution_profile_id != capsule.execution_profile_id
            || request.query_profile_id != capsule.query_profile_id
        {
            return Err(V2Error::Conflict("profile substitution rejected"));
        }
        let tokens = u64::from(request.input_tokens)
            .checked_add(u64::from(request.maximum_output_tokens))
            .ok_or(V2Error::Invalid("token overflow"))?;
        let maximum_fee = self
            .inner
            .config
            .maximum_fee_per_token_micro_noos
            .checked_mul(tokens)
            .and_then(|value| value.checked_add(self.inner.config.maximum_fee_base_micro_noos))
            .ok_or(V2Error::Invalid("fee overflow"))?;
        let payment_reference = self
            .inner
            .payments
            .verify(
                tenant.tenant_id.as_str(),
                &request.payment,
                &resolution,
                maximum_fee,
            )
            .await?;
        let request_hash = canonical_hash(&(
            tenant.tenant_id.as_str(),
            &request,
            resolution.finalized_hash.as_str(),
        ))?;
        let quote_id = domain_hash("WWM-QUOTE-V2", request_hash.as_bytes());
        let mut quote = QuoteResponse {
            schema: "noos/wwm-quote/v2".to_owned(),
            quote_id,
            request_id: request.request_id,
            pin_id: request.pin_id,
            capsule_id: request.capsule_id,
            execution_profile_id: request.execution_profile_id,
            query_profile_id: request.query_profile_id,
            prompt_commitment: request.prompt_commitment,
            input_tokens: request.input_tokens,
            maximum_output_tokens: request.maximum_output_tokens,
            payment_mode: request.payment.mode().to_owned(),
            payment_reference,
            expires_at_height: resolution
                .finalized_height
                .checked_add(self.inner.config.quote_lifetime_blocks)
                .ok_or(V2Error::Invalid("quote height overflow"))?,
            maximum_fee_micro_noos: maximum_fee,
            signature: String::new(),
        };
        quote.signature = self
            .inner
            .signer
            .sign(&serde_json::to_vec(&quote).map_err(internal_json)?)?;
        self.inner
            .store
            .put_quote(&tenant.tenant_id, &request_hash, &quote)
            .map_err(store_error)
    }

    async fn submit_job(
        &self,
        tenant: &TenantIdentity,
        idempotency_key: &str,
        request: JobRequest,
    ) -> Result<JobView, V2Error> {
        validate_identifier(idempotency_key, 256)?;
        validate_commitment(&request.prompt_commitment)?;
        if request.prompt.is_empty()
            || request.prompt.len() > self.inner.config.maximum_prompt_bytes
            || request.prompt_salt.len() < 16
            || request.prompt_salt.len() > 256
        {
            return Err(V2Error::Invalid("invalid prompt or salt bounds"));
        }
        let calculated = prompt_commitment(&request.prompt_salt, &request.prompt);
        if calculated != request.prompt_commitment {
            return Err(V2Error::Invalid("prompt commitment mismatch"));
        }
        let request_hash = canonical_hash(&(
            tenant.tenant_id.as_str(),
            idempotency_key,
            request.quote_id.as_str(),
            request.prompt_commitment.as_str(),
        ))?;
        let job_id = domain_hash("WWM-JOB-V2", request_hash.as_bytes());
        let inserted = self
            .inner
            .store
            .create_job(
                &tenant.tenant_id,
                idempotency_key,
                &request_hash,
                &job_id,
                &request.quote_id,
                &request.prompt,
                &request.prompt_salt,
            )
            .map_err(store_error)?;
        if !inserted.replayed && self.inner.config.auto_reconcile {
            for _ in 0..3 {
                if self.reconcile_once().await? == 0 {
                    break;
                }
            }
        }
        let status = self
            .inner
            .store
            .status(&tenant.tenant_id, &inserted.job_id)
            .map_err(store_error)?;
        Ok(JobView {
            schema: "noos/wwm-job/v2".to_owned(),
            job_id: inserted.job_id,
            status,
            replayed: inserted.replayed,
        })
    }

    pub async fn reconcile_once(&self) -> Result<usize, V2Error> {
        let items = self.inner.store.pending_outbox(128).map_err(store_error)?;
        let mut completed = 0_usize;
        for item in items {
            match item.kind {
                OutboxKind::Dispatch => self.reconcile_dispatch(&item.job_id).await?,
                OutboxKind::Cancel => self.reconcile_cancel(&item.job_id).await?,
                OutboxKind::SettlePaid => self.reconcile_settlement(&item.job_id, false).await?,
                OutboxKind::SettleRefund => self.reconcile_settlement(&item.job_id, true).await?,
            }
            self.inner
                .store
                .finish_outbox(item.id)
                .map_err(store_error)?;
            completed = completed.saturating_add(1);
        }
        Ok(completed)
    }

    async fn reconcile_dispatch(&self, job_id: &str) -> Result<(), V2Error> {
        let job = match self.job_by_id(job_id) {
            Ok(job) => job,
            Err(V2Error::Conflict(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        if job.status == JobStatus::CancelRequested || job.status.is_terminal() {
            return Ok(());
        }
        let resolution = self.resolution().await?;
        if job.quote.capsule_id != resolution.active.capsule_id
            || job.quote.execution_profile_id != resolution.active.execution_profile_id
            || job.quote.query_profile_id != resolution.active.query_profile_id
            || job.quote.pin_id != resolution.pin_id
        {
            return Err(V2Error::Conflict(
                "active resolution changed before dispatch",
            ));
        }
        let registration = select_registered_executor(&resolution, job_id)
            .map_err(|error| V2Error::Dispatch(format!("{error:?}")))?;
        if !self
            .inner
            .store
            .begin_running(job_id)
            .map_err(store_error)?
        {
            return Ok(());
        }
        let result = self
            .inner
            .dispatcher
            .execute(
                &registration,
                &ExecutionRequest {
                    job_id: job_id.to_owned(),
                    capsule_id: job.quote.capsule_id.clone(),
                    execution_profile_id: job.quote.execution_profile_id.clone(),
                    prompt: job.prompt,
                    maximum_output_tokens: job.quote.maximum_output_tokens,
                    prompt_commitment: job.quote.prompt_commitment.clone(),
                },
            )
            .await
            .map_err(dispatch_error)?;
        if result.output_tokens > job.quote.maximum_output_tokens
            || result.executor_id != registration.executor_id
            || !matches!(
                result.evidence_state,
                EvidenceState::ProvisionalSigned | EvidenceState::MatchedQuorum
            )
        {
            return Err(V2Error::Dispatch(
                "executor returned invalid bounded result".to_owned(),
            ));
        }
        let terminal = if result.evidence_state == EvidenceState::MatchedQuorum
            || result.evidence_state == EvidenceState::ProvisionalSigned
        {
            JobStatus::Completed
        } else {
            JobStatus::NoQuorum
        };
        let mut receipt = Receipt {
            schema: "noos/wwm-receipt/v2".to_owned(),
            receipt_id: domain_hash("WWM-RECEIPT-V2", job_id.as_bytes()),
            job_id: job_id.to_owned(),
            tenant_id: job.tenant_id,
            capsule_id: job.quote.capsule_id,
            execution_profile_id: job.quote.execution_profile_id,
            prompt_commitment: job.quote.prompt_commitment,
            output_commitment: domain_hash("WWM-OUTPUT-V2", result.output.as_bytes()),
            output_tokens: result.output_tokens,
            terminal_status: terminal,
            evidence_state: result.evidence_state,
            chain_anchor: None,
            settlement_state: SettlementState::PendingChain,
            payment_mode: job.quote.payment_mode,
            payment_reference: job.quote.payment_reference,
            executor_id: Some(result.executor_id),
            signature: String::new(),
        };
        receipt.signature = self
            .inner
            .signer
            .sign(&serde_json::to_vec(&receipt).map_err(internal_json)?)?;
        self.inner
            .store
            .complete_execution(job_id, &result.output, &receipt)
            .map_err(store_error)
    }

    async fn reconcile_cancel(&self, job_id: &str) -> Result<(), V2Error> {
        let job = self.job_by_id(job_id)?;
        if job.status == JobStatus::Cancelled {
            return Ok(());
        }
        if job.status != JobStatus::CancelRequested {
            return Ok(());
        }
        let resolution = self.resolution().await?;
        let registration = select_registered_executor(&resolution, job_id)
            .map_err(|error| V2Error::Dispatch(format!("{error:?}")))?;
        self.inner
            .dispatcher
            .cancel(&registration, job_id)
            .await
            .map_err(dispatch_error)?;
        let mut receipt = Receipt {
            schema: "noos/wwm-receipt/v2".to_owned(),
            receipt_id: domain_hash("WWM-RECEIPT-V2", job_id.as_bytes()),
            job_id: job_id.to_owned(),
            tenant_id: job.tenant_id,
            capsule_id: job.quote.capsule_id,
            execution_profile_id: job.quote.execution_profile_id,
            prompt_commitment: job.quote.prompt_commitment,
            output_commitment: domain_hash("WWM-OUTPUT-V2", b""),
            output_tokens: 0,
            terminal_status: JobStatus::Cancelled,
            evidence_state: EvidenceState::None,
            chain_anchor: None,
            settlement_state: SettlementState::PendingChain,
            payment_mode: job.quote.payment_mode,
            payment_reference: job.quote.payment_reference,
            executor_id: Some(registration.executor_id),
            signature: String::new(),
        };
        receipt.signature = self
            .inner
            .signer
            .sign(&serde_json::to_vec(&receipt).map_err(internal_json)?)?;
        self.inner
            .store
            .complete_cancel(job_id, &receipt)
            .map_err(store_error)
    }

    async fn reconcile_settlement(&self, job_id: &str, refund: bool) -> Result<(), V2Error> {
        let job = self.job_by_id(job_id)?;
        let receipt = self
            .inner
            .store
            .receipt(&job.tenant_id, job_id)
            .map_err(store_error)?
            .ok_or(V2Error::NotFound)?;
        if receipt.settlement_state != SettlementState::PendingChain {
            return Ok(());
        }
        let settled = self.inner.settlement.settle(&receipt, refund).await?;
        let expected = if refund {
            SettlementState::FinalizedRefunded
        } else {
            SettlementState::FinalizedPaid
        };
        if settled.state != expected || settled.chain_anchor.len() != 64 {
            return Err(V2Error::Settlement(
                "settlement result overstates chain state".to_owned(),
            ));
        }
        self.inner
            .store
            .mark_settled(job_id, settled.state, &settled.chain_anchor)
            .map_err(store_error)?;
        Ok(())
    }

    fn job_by_id(&self, job_id: &str) -> Result<store::StoredJob, V2Error> {
        let tenant = self
            .inner
            .store
            .pending_outbox(512)
            .map_err(store_error)?
            .into_iter()
            .find(|item| item.job_id == job_id)
            .map(|item| item.tenant_id)
            .ok_or(V2Error::NotFound)?;
        self.inner.store.job(&tenant, job_id).map_err(store_error)
    }
}

async fn state_handler(State(service): State<GatewayV2Service>, headers: HeaderMap) -> Response {
    let result = async {
        service
            .inner
            .security
            .validate_public_headers(&headers)
            .map_err(auth_error)?;
        let resolution = service.resolution().await?;
        Ok::<_, V2Error>(json!({
            "schema": API_SCHEMA,
            "enabled": true,
            "resolution": resolution,
            "signing_key_id": service.inner.signer.key_id(),
            "execution": "REGISTERED_EXECUTOR_EDGE_ONLY",
        }))
    }
    .await;
    json_response(&service, &headers, result)
}

async fn capsule_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Path(capsule_id): Path<String>,
) -> Response {
    let result = async {
        service
            .inner
            .security
            .validate_public_headers(&headers)
            .map_err(auth_error)?;
        let resolution = service.resolution().await?;
        let capsule = resolution
            .capsule(&capsule_id)
            .cloned()
            .ok_or(V2Error::NotFound)?;
        Ok::<_, V2Error>(json!({
            "schema": "noos/wwm-capsule-resolution/v2",
            "capsule": capsule,
            "resolution": resolution,
            "dispatchable": capsule_id == resolution.active.capsule_id,
        }))
    }
    .await;
    json_response(&service, &headers, result)
}

async fn quote_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Json(request): Json<QuoteRequest>,
) -> Response {
    let result = async {
        let tenant = service
            .inner
            .security
            .authenticate(&Method::POST, &headers)
            .map_err(auth_error)?;
        serde_json::to_value(service.issue_quote(&tenant, request).await?).map_err(internal_json)
    }
    .await;
    json_response(&service, &headers, result)
}

async fn job_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Json(request): Json<JobRequest>,
) -> Response {
    let result = async {
        let tenant = service
            .inner
            .security
            .authenticate(&Method::POST, &headers)
            .map_err(auth_error)?;
        let idempotency = headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .ok_or(V2Error::Invalid("Idempotency-Key is required"))?;
        serde_json::to_value(service.submit_job(&tenant, idempotency, request).await?)
            .map_err(internal_json)
    }
    .await;
    json_response(&service, &headers, result)
}

async fn stream_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let result = (|| {
        let tenant = service
            .inner
            .security
            .authenticate(&Method::GET, &headers)
            .map_err(auth_error)?;
        let after = headers
            .get("last-event-id")
            .map(|value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|text| text.parse::<u64>().ok())
                    .ok_or(V2Error::Invalid("invalid Last-Event-ID"))
            })
            .transpose()?
            .unwrap_or(0);
        service
            .inner
            .store
            .events_after(&tenant.tenant_id, &job_id, after)
            .map_err(store_error)
    })();
    match result {
        Ok(events) => {
            let stream = stream::iter(events.into_iter().map(|event| {
                Ok::<_, Infallible>(
                    Event::default()
                        .id(event.id.to_string())
                        .event(&event.event_type)
                        .json_data(&event)
                        .unwrap_or_else(|_| Event::default().event("error")),
                )
            }));
            let mut response = Sse::new(stream).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                "no-store"
                    .parse()
                    .unwrap_or_else(|_| header::HeaderValue::from_static("no-store")),
            );
            service
                .inner
                .security
                .apply_cors(&headers, response.headers_mut());
            response
        }
        Err(error) => error_response(&service, &headers, error),
    }
}

async fn cancel_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let result = async {
        let tenant = service
            .inner
            .security
            .authenticate(&Method::POST, &headers)
            .map_err(auth_error)?;
        let status = service
            .inner
            .store
            .request_cancel(&tenant.tenant_id, &job_id)
            .map_err(store_error)?;
        if status == JobStatus::CancelRequested && service.inner.config.auto_reconcile {
            for _ in 0..3 {
                if service.reconcile_once().await? == 0 {
                    break;
                }
            }
        }
        let status = service
            .inner
            .store
            .status(&tenant.tenant_id, &job_id)
            .map_err(store_error)?;
        Ok::<_, V2Error>(json!({"schema":"noos/wwm-cancel/v2","job_id":job_id,"status":status}))
    }
    .await;
    json_response(&service, &headers, result)
}

async fn receipt_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let result = (|| {
        let tenant = service
            .inner
            .security
            .authenticate(&Method::GET, &headers)
            .map_err(auth_error)?;
        let receipt = service
            .inner
            .store
            .receipt(&tenant.tenant_id, &job_id)
            .map_err(store_error)?
            .ok_or(V2Error::NotFound)?;
        serde_json::to_value(receipt).map_err(internal_json)
    })();
    json_response(&service, &headers, result)
}

async fn models_handler(State(service): State<GatewayV2Service>, headers: HeaderMap) -> Response {
    let result = async {
        service.inner.security.validate_public_headers(&headers).map_err(auth_error)?;
        let resolution = service.resolution().await?;
        Ok::<_, V2Error>(json!({"object":"list","data":[{"id":resolution.active.capsule_id,"object":"model","owned_by":"mindchain","resolution":resolution}]}))
    }.await;
    json_response(&service, &headers, result)
}

#[derive(Debug, Deserialize)]
struct OpenAiChatRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(default)]
    stream: bool,
    max_tokens: Option<u32>,
}
#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}
#[derive(Debug, Deserialize)]
struct OpenAiResponsesRequest {
    model: String,
    input: String,
    #[serde(default)]
    stream: bool,
    max_output_tokens: Option<u32>,
}

async fn openai_chat_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Json(request): Json<OpenAiChatRequest>,
) -> Response {
    let prompt = request
        .messages
        .iter()
        .map(|message| format!("{}: {}", message.role, message.content))
        .collect::<Vec<_>>()
        .join("\n");
    openai_execute(
        service,
        headers,
        request.model,
        prompt,
        request.stream,
        request.max_tokens.unwrap_or(256),
        false,
    )
    .await
}

async fn openai_responses_handler(
    State(service): State<GatewayV2Service>,
    headers: HeaderMap,
    Json(request): Json<OpenAiResponsesRequest>,
) -> Response {
    openai_execute(
        service,
        headers,
        request.model,
        request.input,
        request.stream,
        request.max_output_tokens.unwrap_or(256),
        true,
    )
    .await
}

async fn openai_execute(
    service: GatewayV2Service,
    headers: HeaderMap,
    model: String,
    prompt: String,
    wants_stream: bool,
    maximum_output_tokens: u32,
    responses_api: bool,
) -> Response {
    let result = async {
        let tenant = service
            .inner
            .security
            .authenticate(&Method::POST, &headers)
            .map_err(auth_error)?;
        let resolution = service.resolution().await?;
        if model != resolution.active.capsule_id {
            return Err(V2Error::Conflict("model is not the active capsule"));
        }
        let idem = headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .ok_or(V2Error::Invalid("Idempotency-Key is required"))?;
        let mode = headers
            .get("x-wwm-payment-mode")
            .and_then(|value| value.to_str().ok())
            .ok_or(V2Error::Invalid("X-WWM-Payment-Mode is required"))?;
        let payment_mode = match mode {
            "SPONSORED" => PaymentMode::Sponsored,
            "PAID" => PaymentMode::Paid,
            _ => return Err(V2Error::Invalid("payment mode must be SPONSORED or PAID")),
        };
        let authorization = headers
            .get("x-wwm-payment-authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let salt = headers
            .get("x-wwm-prompt-salt")
            .and_then(|value| value.to_str().ok())
            .ok_or(V2Error::Invalid("X-WWM-Prompt-Salt is required"))?
            .to_owned();
        let commitment = prompt_commitment(&salt, &prompt);
        let quote = service
            .issue_quote(
                &tenant,
                QuoteRequest {
                    request_id: domain_hash("WWM-OAI-REQUEST-V2", idem.as_bytes()),
                    pin_id: resolution.pin_id,
                    capsule_id: resolution.active.capsule_id.clone(),
                    prompt_commitment: commitment.clone(),
                    execution_profile_id: resolution.active.execution_profile_id,
                    query_profile_id: resolution.active.query_profile_id,
                    input_tokens: u32::try_from(prompt.split_whitespace().count())
                        .unwrap_or(u32::MAX)
                        .max(1),
                    maximum_output_tokens,
                    client_nonce: idem.to_owned(),
                    payment: PaymentAuthorization {
                        mode: payment_mode,
                        authorization,
                    },
                },
            )
            .await?;
        let job = service
            .submit_job(
                &tenant,
                idem,
                JobRequest {
                    quote_id: quote.quote_id,
                    prompt,
                    prompt_commitment: commitment,
                    prompt_salt: salt,
                },
            )
            .await?;
        let events = service
            .inner
            .store
            .events_after(&tenant.tenant_id, &job.job_id, 0)
            .map_err(store_error)?;
        let output = events
            .iter()
            .filter(|event| event.event_type == "output.delta")
            .filter_map(|event| event.data.get("delta").and_then(Value::as_str))
            .collect::<String>();
        Ok::<_, V2Error>((job.job_id, output, events))
    }
    .await;
    let Ok((job_id, output, events)) = result else {
        return error_response(
            &service,
            &headers,
            result
                .err()
                .unwrap_or(V2Error::Internal("unknown".to_owned())),
        );
    };
    if wants_stream {
        let chunks = events.into_iter().filter(|event| event.event_type == "output.delta").map(move |event| {
            let delta = event.data.get("delta").and_then(Value::as_str).unwrap_or_default();
            let payload = if responses_api { json!({"type":"response.output_text.delta","response_id":job_id,"delta":delta}) } else { json!({"id":job_id,"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":delta},"finish_reason":Value::Null}]}) };
            Ok::<_, Infallible>(Event::default().id(event.id.to_string()).data(payload.to_string()))
        });
        let mut response = Sse::new(stream::iter(chunks)).into_response();
        service
            .inner
            .security
            .apply_cors(&headers, response.headers_mut());
        response
    } else {
        let value = if responses_api {
            json!({"id":job_id,"object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":output}]}]})
        } else {
            json!({"id":job_id,"object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":output},"finish_reason":"stop"}]})
        };
        json_response(&service, &headers, Ok(value))
    }
}

fn json_response(
    service: &GatewayV2Service,
    request_headers: &HeaderMap,
    result: Result<Value, V2Error>,
) -> Response {
    match result {
        Ok(value) => {
            let mut response = Json(value).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            service
                .inner
                .security
                .apply_cors(request_headers, response.headers_mut());
            response
        }
        Err(error) => error_response(service, request_headers, error),
    }
}

fn error_response(
    service: &GatewayV2Service,
    request_headers: &HeaderMap,
    error: V2Error,
) -> Response {
    let (status, code, message) = match error {
        V2Error::Configuration(message) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "configuration",
            message.to_owned(),
        ),
        V2Error::Resolution(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "resolution_unavailable",
            "finalized resolution unavailable".to_owned(),
        ),
        V2Error::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required".to_owned(),
        ),
        V2Error::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message.to_owned()),
        V2Error::Invalid(message) => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            message.to_owned(),
        ),
        V2Error::Conflict(message) => (StatusCode::CONFLICT, "conflict", message.to_owned()),
        V2Error::NotFound => (
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found".to_owned(),
        ),
        V2Error::Dispatch(_) => (
            StatusCode::BAD_GATEWAY,
            "executor_unavailable",
            "registered executor unavailable".to_owned(),
        ),
        V2Error::Store(_) | V2Error::Settlement(_) | V2Error::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal service error".to_owned(),
        ),
    };
    let mut response = (
        status,
        Json(ApiErrorBody {
            error: ApiErrorDetail {
                code: code.to_owned(),
                message,
            },
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    service
        .inner
        .security
        .apply_cors(request_headers, response.headers_mut());
    response
}

fn auth_error(error: AuthError) -> V2Error {
    match error {
        AuthError::Unauthorized => V2Error::Unauthorized,
        AuthError::Csrf => V2Error::Forbidden("CSRF validation failed"),
        AuthError::Cors => V2Error::Forbidden("origin is not allowed"),
        AuthError::UntrustedProxy => V2Error::Forbidden("untrusted proxy headers"),
        AuthError::RequestSmuggling => V2Error::Invalid("ambiguous request framing"),
        AuthError::InvalidTenant => V2Error::Unauthorized,
    }
}

fn store_error(error: StoreError) -> V2Error {
    match error {
        StoreError::Conflict => {
            V2Error::Conflict("idempotency key conflicts with an earlier request")
        }
        StoreError::NotFound | StoreError::TenantMismatch => V2Error::NotFound,
        StoreError::InvalidState => V2Error::Conflict("invalid job state transition"),
        other => V2Error::Store(format!("{other:?}")),
    }
}

fn dispatch_error(error: DispatchError) -> V2Error {
    V2Error::Dispatch(format!("{error:?}"))
}
fn internal_json(error: serde_json::Error) -> V2Error {
    V2Error::Internal(error.to_string())
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), V2Error> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(V2Error::Invalid("invalid identifier"))
    } else {
        Ok(())
    }
}
fn validate_commitment(value: &str) -> Result<(), V2Error> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(V2Error::Invalid("commitment must be 32-byte lowercase hex"))
    }
}
fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<String, V2Error> {
    Ok(domain_hash(
        "WWM-CANONICAL-V2",
        &serde_json::to_vec(value).map_err(internal_json)?,
    ))
}
fn domain_hash(domain: &str, body: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(body);
    hasher.finalize().to_hex().to_string()
}
pub fn prompt_commitment(salt: &str, prompt: &str) -> String {
    let mut body = Vec::with_capacity(salt.len().saturating_add(prompt.len()).saturating_add(1));
    body.extend_from_slice(salt.as_bytes());
    body.push(0);
    body.extend_from_slice(prompt.as_bytes());
    domain_hash("WWM-PROMPT-V2", &body)
}

#[derive(Clone)]
pub struct StaticResolver {
    resolution: Arc<RwLock<FinalizedResolution>>,
}
impl StaticResolver {
    pub fn new(resolution: FinalizedResolution) -> Self {
        Self {
            resolution: Arc::new(RwLock::new(resolution)),
        }
    }
    pub fn replace(&self, resolution: FinalizedResolution) {
        if let Ok(mut guard) = self.resolution.write() {
            *guard = resolution;
        }
    }
}
#[async_trait]
impl FinalizedResolver for StaticResolver {
    async fn resolve(&self) -> Result<FinalizedResolution, V2Error> {
        self.resolution
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| V2Error::Resolution("resolver poisoned".to_owned()))
    }
}

#[derive(Clone)]
pub struct TestSigner {
    key_id: String,
    key: [u8; 32],
}
impl TestSigner {
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            key,
        }
    }
}
impl GatewaySigner for TestSigner {
    fn assurance(&self) -> ComponentAssurance {
        ComponentAssurance::TestOnly
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, message: &[u8]) -> Result<String, V2Error> {
        Ok(blake3::keyed_hash(&self.key, message).to_hex().to_string())
    }
}

#[derive(Clone, Default)]
pub struct TestPaymentVerifier;
#[async_trait]
impl PaymentVerifier for TestPaymentVerifier {
    fn assurance(&self) -> ComponentAssurance {
        ComponentAssurance::TestOnly
    }
    async fn verify(
        &self,
        tenant: &str,
        payment: &PaymentAuthorization,
        _resolution: &FinalizedResolution,
        _maximum_fee: u64,
    ) -> Result<String, V2Error> {
        if payment.mode == PaymentMode::Paid && payment.authorization.is_empty() {
            Err(V2Error::Invalid("paid authorization is empty"))
        } else if payment.mode == PaymentMode::Sponsored && payment.authorization.is_empty() {
            Ok(format!("test-grant:{tenant}"))
        } else {
            Ok(payment.authorization.clone())
        }
    }
}

#[derive(Clone, Default)]
pub struct TestSettlement {
    anchors: Arc<RwLock<BTreeMap<String, SettlementResult>>>,
}
impl TestSettlement {
    pub fn count(&self) -> usize {
        self.anchors.read().map(|value| value.len()).unwrap_or(0)
    }
}
#[async_trait]
impl SettlementSubmitter for TestSettlement {
    fn assurance(&self) -> ComponentAssurance {
        ComponentAssurance::TestOnly
    }
    async fn settle(&self, receipt: &Receipt, refund: bool) -> Result<SettlementResult, V2Error> {
        let mut guard = self
            .anchors
            .write()
            .map_err(|_| V2Error::Settlement("test settlement poisoned".to_owned()))?;
        Ok(guard
            .entry(receipt.job_id.clone())
            .or_insert_with(|| SettlementResult {
                chain_anchor: domain_hash("WWM-CHAIN-ANCHOR-V2", receipt.job_id.as_bytes()),
                state: if refund {
                    SettlementState::FinalizedRefunded
                } else {
                    SettlementState::FinalizedPaid
                },
            })
            .clone())
    }
}

#[cfg(test)]
mod tests;
