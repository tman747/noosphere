#![forbid(unsafe_code)]

use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use noos_mind_gateway::service::v2::{
    executor::{DispatchError, ExecutorDispatcher},
    model::{EvidenceState, ExecutionRequest, ExecutionResult, ExecutorRegistration},
    ComponentAssurance, GatewayV2Service, V2Error,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use std::{
    path::Path as FsPath,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeError {
    Configuration(&'static str),
    Unauthorized,
    Conflict,
    Cancelled,
    Engine(String),
    Store(String),
}

#[async_trait]
pub trait ExecutionEngine: Send + Sync {
    fn assurance(&self) -> ComponentAssurance;
    async fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, EdgeError>;
    async fn cancel(&self, job_id: &str) -> Result<(), EdgeError>;
}

pub trait ExecutionCache: Send + Sync {
    fn assurance(&self) -> ComponentAssurance;
    fn get(&self, job_id: &str, request_hash: &str) -> Result<Option<ExecutionResult>, EdgeError>;
    fn put(
        &self,
        job_id: &str,
        request_hash: &str,
        result: &ExecutionResult,
    ) -> Result<(), EdgeError>;
    fn cancel(&self, job_id: &str) -> Result<(), EdgeError>;
    fn is_cancelled(&self, job_id: &str) -> Result<bool, EdgeError>;
}

#[derive(Clone)]
pub struct SqliteTestExecutionCache {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteTestExecutionCache {
    pub fn open(path: &FsPath) -> Result<Self, EdgeError> {
        let connection = Connection::open(path).map_err(db)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS edge_results(
                job_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                result_json TEXT,
                cancelled INTEGER NOT NULL CHECK(cancelled IN (0,1))
             ) STRICT;",
            )
            .map_err(db)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }
}

impl ExecutionCache for SqliteTestExecutionCache {
    fn assurance(&self) -> ComponentAssurance {
        ComponentAssurance::TestOnly
    }

    fn get(&self, job_id: &str, request_hash: &str) -> Result<Option<ExecutionResult>, EdgeError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| EdgeError::Store("cache mutex poisoned".to_owned()))?;
        let row: Option<(String, Option<String>, i64)> = guard
            .query_row(
                "SELECT request_hash,result_json,cancelled FROM edge_results WHERE job_id=?1",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((stored_hash, body, cancelled)) = row else {
            return Ok(None);
        };
        if stored_hash != request_hash {
            return Err(EdgeError::Conflict);
        }
        if cancelled != 0 {
            return Err(EdgeError::Cancelled);
        }
        body.map(|json| {
            serde_json::from_str(&json).map_err(|error| EdgeError::Store(error.to_string()))
        })
        .transpose()
    }

    fn put(
        &self,
        job_id: &str,
        request_hash: &str,
        result: &ExecutionResult,
    ) -> Result<(), EdgeError> {
        let body =
            serde_json::to_string(result).map_err(|error| EdgeError::Store(error.to_string()))?;
        let guard = self
            .connection
            .lock()
            .map_err(|_| EdgeError::Store("cache mutex poisoned".to_owned()))?;
        let changed = guard.execute(
            "INSERT INTO edge_results(job_id,request_hash,result_json,cancelled) VALUES(?1,?2,?3,0)
             ON CONFLICT(job_id) DO UPDATE SET result_json=CASE WHEN request_hash=excluded.request_hash THEN COALESCE(edge_results.result_json,excluded.result_json) ELSE edge_results.result_json END
             WHERE request_hash=excluded.request_hash AND cancelled=0",
            params![job_id, request_hash, body],
        ).map_err(db)?;
        if changed == 0 {
            Err(EdgeError::Conflict)
        } else {
            Ok(())
        }
    }

    fn cancel(&self, job_id: &str) -> Result<(), EdgeError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| EdgeError::Store("cache mutex poisoned".to_owned()))?;
        guard.execute(
            "INSERT INTO edge_results(job_id,request_hash,result_json,cancelled) VALUES(?1,'CANCELLED',NULL,1)
             ON CONFLICT(job_id) DO UPDATE SET cancelled=1",
            params![job_id],
        ).map_err(db)?;
        Ok(())
    }

    fn is_cancelled(&self, job_id: &str) -> Result<bool, EdgeError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| EdgeError::Store("cache mutex poisoned".to_owned()))?;
        guard
            .query_row(
                "SELECT cancelled FROM edge_results WHERE job_id=?1",
                params![job_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|value| value.unwrap_or(0) != 0)
            .map_err(db)
    }
}

#[derive(Clone)]
pub struct ExecutorEdge {
    registration: ExecutorRegistration,
    engine: Arc<dyn ExecutionEngine>,
    cache: Arc<dyn ExecutionCache>,
    internal_token_hash: [u8; 32],
}

impl ExecutorEdge {
    pub fn new(
        registration: ExecutorRegistration,
        engine: Arc<dyn ExecutionEngine>,
        cache: Arc<dyn ExecutionCache>,
        internal_token: &str,
        allow_test_components: bool,
    ) -> Result<Self, EdgeError> {
        if !registration.active
            || registration.protocol_version != 2
            || registration.registry_epoch == 0
        {
            return Err(EdgeError::Configuration(
                "edge is not actively registered for protocol v2",
            ));
        }
        if internal_token.len() < 32 {
            return Err(EdgeError::Configuration(
                "internal dispatch token must contain at least 32 bytes",
            ));
        }
        if !allow_test_components
            && (engine.assurance() != ComponentAssurance::Production
                || cache.assurance() != ComponentAssurance::Production)
        {
            return Err(EdgeError::Configuration("production edge requires a registered production engine and replicated idempotency cache"));
        }
        Ok(Self {
            registration,
            engine,
            cache,
            internal_token_hash: *blake3::hash(internal_token.as_bytes()).as_bytes(),
        })
    }

    pub fn internal_router(&self) -> Router {
        Router::new()
            .route("/internal/wwm/v2/execute", post(internal_execute))
            .route(
                "/internal/wwm/v2/jobs/{job_id}/cancel",
                post(internal_cancel),
            )
            .with_state(self.clone())
    }

    pub fn direct_router(&self, direct: GatewayV2Service) -> Router {
        direct.router()
    }

    async fn execute_idempotent(
        &self,
        request: ExecutionRequest,
    ) -> Result<ExecutionResult, EdgeError> {
        if request.capsule_id.is_empty()
            || request.execution_profile_id.is_empty()
            || request.prompt.is_empty()
            || request.maximum_output_tokens == 0
            || request.prompt_commitment.len() != 64
        {
            return Err(EdgeError::Configuration("invalid bounded dispatch"));
        }
        if self.cache.is_cancelled(&request.job_id)? {
            return Err(EdgeError::Cancelled);
        }
        let request_hash = dispatch_hash(&request);
        if let Some(result) = self.cache.get(&request.job_id, &request_hash)? {
            return Ok(result);
        }
        let result = self.engine.execute(&request).await?;
        if result.executor_id != self.registration.executor_id
            || result.output_tokens > request.maximum_output_tokens
            || result.executor_signature.is_empty()
        {
            return Err(EdgeError::Engine(
                "engine returned an invalid receipt fragment".to_owned(),
            ));
        }
        self.cache.put(&request.job_id, &request_hash, &result)?;
        Ok(result)
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), EdgeError> {
        let id = headers
            .get("x-noos-executor-id")
            .and_then(|value| value.to_str().ok())
            .ok_or(EdgeError::Unauthorized)?;
        let token = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(EdgeError::Unauthorized)?;
        if id != self.registration.executor_id
            || *blake3::hash(token.as_bytes()).as_bytes() != self.internal_token_hash
        {
            return Err(EdgeError::Unauthorized);
        }
        Ok(())
    }
}

#[async_trait]
impl ExecutorDispatcher for ExecutorEdge {
    async fn execute(
        &self,
        registration: &ExecutorRegistration,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, DispatchError> {
        if registration != &self.registration {
            return Err(DispatchError::NoRegisteredExecutor);
        }
        self.execute_idempotent(request.clone())
            .await
            .map_err(edge_dispatch_error)
    }

    async fn cancel(
        &self,
        registration: &ExecutorRegistration,
        job_id: &str,
    ) -> Result<(), DispatchError> {
        if registration != &self.registration {
            return Err(DispatchError::NoRegisteredExecutor);
        }
        self.engine
            .cancel(job_id)
            .await
            .map_err(edge_dispatch_error)?;
        self.cache.cancel(job_id).map_err(edge_dispatch_error)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalExecuteRequest {
    schema: String,
    job_id: String,
    capsule_id: String,
    execution_profile_id: String,
    prompt: String,
    maximum_output_tokens: u32,
    prompt_commitment: String,
}

async fn internal_execute(
    State(edge): State<ExecutorEdge>,
    headers: HeaderMap,
    Json(request): Json<InternalExecuteRequest>,
) -> Response {
    let result = async {
        edge.authorize(&headers)?;
        if request.schema != "noos/executor-dispatch/v2" {
            return Err(EdgeError::Configuration("wrong dispatch schema"));
        }
        edge.execute_idempotent(ExecutionRequest {
            job_id: request.job_id,
            capsule_id: request.capsule_id,
            execution_profile_id: request.execution_profile_id,
            prompt: request.prompt,
            maximum_output_tokens: request.maximum_output_tokens,
            prompt_commitment: request.prompt_commitment,
        })
        .await
    }
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => edge_error_response(error),
    }
}

async fn internal_cancel(
    State(edge): State<ExecutorEdge>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let result = async {
        edge.authorize(&headers)?;
        edge.engine.cancel(&job_id).await?;
        edge.cache.cancel(&job_id)
    }
    .await;
    match result {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"job_id":job_id,"status":"CANCELLED"})),
        )
            .into_response(),
        Err(error) => edge_error_response(error),
    }
}

fn edge_error_response(error: EdgeError) -> Response {
    let (status, code) = match error {
        EdgeError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
        EdgeError::Conflict => (StatusCode::CONFLICT, "idempotency_conflict"),
        EdgeError::Cancelled => (StatusCode::CONFLICT, "cancelled"),
        EdgeError::Configuration(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        EdgeError::Engine(_) | EdgeError::Store(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    };
    (status, Json(serde_json::json!({"error":code}))).into_response()
}

fn edge_dispatch_error(error: EdgeError) -> DispatchError {
    match error {
        EdgeError::Conflict | EdgeError::Cancelled => DispatchError::Rejected(format!("{error:?}")),
        other => DispatchError::Transport(format!("{other:?}")),
    }
}

fn dispatch_hash(request: &ExecutionRequest) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS-EDGE-DISPATCH-V2\0");
    hasher.update(request.job_id.as_bytes());
    hasher.update(request.capsule_id.as_bytes());
    hasher.update(request.execution_profile_id.as_bytes());
    hasher.update(request.prompt_commitment.as_bytes());
    hasher.update(&(request.prompt.len() as u64).to_le_bytes());
    hasher.update(request.prompt.as_bytes());
    hasher.update(&request.maximum_output_tokens.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

fn db(error: rusqlite::Error) -> EdgeError {
    EdgeError::Store(error.to_string())
}

#[derive(Clone)]
pub struct DeterministicTestEngine {
    executor_id: String,
    calls: Arc<Mutex<usize>>,
}

impl DeterministicTestEngine {
    pub fn new(executor_id: impl Into<String>) -> Self {
        Self {
            executor_id: executor_id.into(),
            calls: Arc::new(Mutex::new(0)),
        }
    }
    pub fn calls(&self) -> usize {
        self.calls.lock().map(|value| *value).unwrap_or(0)
    }
}

#[async_trait]
impl ExecutionEngine for DeterministicTestEngine {
    fn assurance(&self) -> ComponentAssurance {
        ComponentAssurance::TestOnly
    }
    async fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, EdgeError> {
        if let Ok(mut calls) = self.calls.lock() {
            *calls = calls.saturating_add(1);
        }
        let output = format!("Bonsai: {}", request.prompt);
        Ok(ExecutionResult {
            output_tokens: u32::try_from(output.split_whitespace().count()).unwrap_or(u32::MAX),
            ordered_token_ids_hash: blake3::hash(output.as_bytes()).to_hex().to_string(),
            token_history_root: blake3::hash(format!("history:{output}").as_bytes())
                .to_hex()
                .to_string(),
            executor_signature: blake3::hash(format!("signature:{output}").as_bytes())
                .to_hex()
                .to_string(),
            output,
            evidence_state: EvidenceState::ProvisionalSigned,
            executor_id: self.executor_id.clone(),
        })
    }
    async fn cancel(&self, _job_id: &str) -> Result<(), EdgeError> {
        Ok(())
    }
}

pub fn production_unavailable_reason(error: &V2Error) -> &'static str {
    match error {
        V2Error::Configuration(_) => "KMS/HSM, synchronous Postgres-compatible storage, chain credentials, and production payment verification must be injected",
        _ => "executor edge is not production ready",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn registration() -> ExecutorRegistration {
        ExecutorRegistration {
            executor_id: "executor-01".to_owned(),
            control_cluster_id: "cluster-01".to_owned(),
            region: "us-east".to_owned(),
            https_origin: "https://executor.example".to_owned(),
            protocol_version: 2,
            registry_epoch: 7,
            active: true,
        }
    }

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            job_id: "job-01".to_owned(),
            capsule_id: "11".repeat(32),
            execution_profile_id: "22".repeat(32),
            prompt: "Explain custody quorum.".to_owned(),
            maximum_output_tokens: 64,
            prompt_commitment: "33".repeat(32),
        }
    }

    fn edge(
        dir: &tempfile::TempDir,
    ) -> (
        ExecutorEdge,
        Arc<DeterministicTestEngine>,
        ExecutorRegistration,
    ) {
        let registration = registration();
        let engine = Arc::new(DeterministicTestEngine::new(
            registration.executor_id.clone(),
        ));
        let cache =
            Arc::new(SqliteTestExecutionCache::open(&dir.path().join("edge.sqlite")).unwrap());
        let edge = ExecutorEdge::new(
            registration.clone(),
            engine.clone(),
            cache,
            "0123456789abcdef0123456789abcdef",
            true,
        )
        .unwrap();
        (edge, engine, registration)
    }

    #[tokio::test]
    async fn direct_dispatch_replays_without_gateway_or_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let (edge, engine, registration) = edge(&dir);
        let first = ExecutorDispatcher::execute(&edge, &registration, &request())
            .await
            .unwrap();
        let second = ExecutorDispatcher::execute(&edge, &registration, &request())
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(engine.calls(), 1);

        let mut substituted = request();
        substituted.prompt = "Different raw prompt.".to_owned();
        assert!(matches!(
            ExecutorDispatcher::execute(&edge, &registration, &substituted).await,
            Err(DispatchError::Rejected(_))
        ));
        assert_eq!(engine.calls(), 1);
    }

    #[tokio::test]
    async fn internal_route_requires_both_executor_id_and_token() {
        let dir = tempfile::tempdir().unwrap();
        let (edge, engine, _) = edge(&dir);
        let body = serde_json::json!({
            "schema": "noos/executor-dispatch/v2",
            "job_id": "job-02",
            "capsule_id": "11".repeat(32),
            "execution_profile_id": "22".repeat(32),
            "prompt": "Bounded request",
            "maximum_output_tokens": 64,
            "prompt_commitment": "33".repeat(32),
        })
        .to_string();

        let unauthorized = edge
            .internal_router()
            .oneshot(
                Request::post("/internal/wwm/v2/execute")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(engine.calls(), 0);

        let authorized = edge
            .internal_router()
            .oneshot(
                Request::post("/internal/wwm/v2/execute")
                    .header("content-type", "application/json")
                    .header("x-noos-executor-id", "executor-01")
                    .header("authorization", "Bearer 0123456789abcdef0123456789abcdef")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        assert_eq!(engine.calls(), 1);
    }
}
