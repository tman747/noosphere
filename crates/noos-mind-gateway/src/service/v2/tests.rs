use super::*;
use crate::service::v2::{
    auth::TenantCredential,
    executor::{DispatchError, RegisteredHttpDispatcher},
    store::SqliteTestStore,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Clone, Default)]
struct MockDispatcher {
    calls: Arc<Mutex<usize>>,
    cancels: Arc<Mutex<usize>>,
}

impl MockDispatcher {
    fn calls(&self) -> usize {
        self.calls.lock().map(|value| *value).unwrap_or(0)
    }
    fn cancels(&self) -> usize {
        self.cancels.lock().map(|value| *value).unwrap_or(0)
    }
}

#[async_trait]
impl ExecutorDispatcher for MockDispatcher {
    async fn execute(
        &self,
        registration: &ExecutorRegistration,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, DispatchError> {
        if let Ok(mut value) = self.calls.lock() {
            *value = value.saturating_add(1);
        }
        let output = format!("Bonsai: {}", request.prompt);
        Ok(ExecutionResult {
            output_tokens: u32::try_from(output.split_whitespace().count()).unwrap_or(u32::MAX),
            ordered_token_ids_hash: hash(&format!("tokens:{output}")),
            token_history_root: hash(&format!("history:{output}")),
            evidence_state: EvidenceState::ProvisionalSigned,
            executor_id: registration.executor_id.clone(),
            executor_signature: hash(&format!("signature:{output}")),
            output,
        })
    }

    async fn cancel(
        &self,
        _registration: &ExecutorRegistration,
        _job_id: &str,
    ) -> Result<(), DispatchError> {
        if let Ok(mut value) = self.cancels.lock() {
            *value = value.saturating_add(1);
        }
        Ok(())
    }
}

struct Fixture {
    _directory: TempDir,
    service: GatewayV2Service,
    store: Arc<SqliteTestStore>,
    dispatcher: Arc<MockDispatcher>,
    settlement: Arc<TestSettlement>,
    resolution: FinalizedResolution,
}

fn fixture(auto_reconcile: bool) -> Fixture {
    let directory = tempfile::tempdir().expect("temporary gateway directory");
    let store = Arc::new(
        SqliteTestStore::open(&directory.path().join("gateway.sqlite"), [9; 32])
            .expect("test store"),
    );
    let dispatcher = Arc::new(MockDispatcher::default());
    let settlement = Arc::new(TestSettlement::default());
    let resolution = resolution();
    let security = SecurityConfig::new(
        vec![
            TenantCredential {
                tenant_id: "tenant-a".to_owned(),
                bearer_token: token_a().to_owned(),
                csrf_token: Some("csrf-a-012345678901234567890123456789".to_owned()),
            },
            TenantCredential {
                tenant_id: "tenant-b".to_owned(),
                bearer_token: token_b().to_owned(),
                csrf_token: Some("csrf-b-012345678901234567890123456789".to_owned()),
            },
        ],
        ["https://app.example".to_owned()],
        false,
    )
    .expect("security config");
    let service = GatewayV2Service::new(
        V2Config {
            allow_test_components: true,
            auto_reconcile,
            ..V2Config::default()
        },
        security,
        Arc::new(StaticResolver::new(resolution.clone())),
        dispatcher.clone(),
        store.clone(),
        Arc::new(TestSigner::new("test-key", [7; 32])),
        settlement.clone(),
        Arc::new(TestPaymentVerifier),
    )
    .expect("test service");
    Fixture {
        _directory: directory,
        service,
        store,
        dispatcher,
        settlement,
        resolution,
    }
}

fn resolution() -> FinalizedResolution {
    let capsule_id = hash("active-capsule");
    FinalizedResolution {
        schema: "noos/finalized-model-resolution/v1".to_owned(),
        chain_id: hash("chain"),
        genesis_hash: hash("genesis"),
        finalized_height: 100,
        finalized_hash: hash("block-100"),
        objects_root: hash("objects"),
        pin_id: hash("pin"),
        proofs_verified: true,
        canonical_resolution_body_hex: "01020304".to_owned(),
        finality_evidence_hex: "05060708".to_owned(),
        state_object_proofs: vec![StateObjectProof {
            object_kind: "MODEL_CAPSULE".to_owned(),
            object_id: capsule_id.clone(),
            canonical_value_hex: "090a".to_owned(),
            smt_siblings: vec![hash("sibling")],
        }],
        active: CapsuleResolution {
            capsule_id,
            model_name: "Bonsai-27B-Q1_0.gguf".to_owned(),
            artifact_sha256: "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
                .to_owned(),
            artifact_length: 3_803_452_480,
            execution_profile_id: hash("execution-profile"),
            query_profile_id: hash("query-profile"),
            activation_state: ActivationState::Active,
        },
        candidates: vec![CapsuleResolution {
            capsule_id: hash("candidate-capsule"),
            model_name: "successor".to_owned(),
            artifact_sha256: hash("candidate-artifact"),
            artifact_length: 1,
            execution_profile_id: hash("candidate-execution"),
            query_profile_id: hash("candidate-query"),
            activation_state: ActivationState::AuthorizedNotActive,
        }],
        executors: vec![ExecutorRegistration {
            executor_id: "executor-a".to_owned(),
            control_cluster_id: "cluster-a".to_owned(),
            region: "region-a".to_owned(),
            https_origin: "https://edge.example/".to_owned(),
            protocol_version: 2,
            registry_epoch: 3,
            active: true,
        }],
        fee_schedule_id: hash("fees"),
        fund_profile_id: hash("fund"),
        service_directory_id: hash("directory"),
        registry_vector_id: hash("vector"),
    }
}

fn token_a() -> &'static str {
    "tenant-a-bearer-token-012345678901234567890123"
}
fn token_b() -> &'static str {
    "tenant-b-bearer-token-012345678901234567890123"
}
fn hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}
fn salt() -> &'static str {
    "0123456789abcdef0123456789abcdef"
}

fn quote_request(
    resolution: &FinalizedResolution,
    capsule: &CapsuleResolution,
    request_id: &str,
    prompt: &str,
) -> QuoteRequest {
    QuoteRequest {
        request_id: request_id.to_owned(),
        pin_id: resolution.pin_id.clone(),
        capsule_id: capsule.capsule_id.clone(),
        prompt_commitment: prompt_commitment(salt(), prompt),
        execution_profile_id: capsule.execution_profile_id.clone(),
        query_profile_id: capsule.query_profile_id.clone(),
        input_tokens: 4,
        maximum_output_tokens: 64,
        client_nonce: format!("nonce-{request_id}"),
        payment: PaymentAuthorization {
            mode: PaymentMode::Sponsored,
            authorization: String::new(),
        },
    }
}

fn json_request(method: &str, uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).expect("request")
}

async fn response_json(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON response")
    };
    (status, value)
}

async fn issue_quote(fixture: &Fixture, prompt: &str, request_id: &str) -> QuoteResponse {
    let request = quote_request(
        &fixture.resolution,
        &fixture.resolution.active,
        request_id,
        prompt,
    );
    let response = fixture
        .service
        .router()
        .oneshot(json_request(
            "POST",
            "/api/wwm/v2/quotes",
            Some(token_a()),
            serde_json::to_value(request).expect("quote JSON"),
        ))
        .await
        .expect("quote response");
    let (status, value) = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    serde_json::from_value(value).expect("quote")
}

async fn submit_job(fixture: &Fixture, quote: &QuoteResponse, prompt: &str, idem: &str) -> JobView {
    let request = JobRequest {
        quote_id: quote.quote_id.clone(),
        prompt: prompt.to_owned(),
        prompt_commitment: prompt_commitment(salt(), prompt),
        prompt_salt: salt().to_owned(),
    };
    let http = Request::builder()
        .method("POST")
        .uri("/api/wwm/v2/jobs")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token_a()))
        .header("idempotency-key", idem)
        .body(Body::from(serde_json::to_vec(&request).expect("job JSON")))
        .expect("job request");
    let response = fixture
        .service
        .router()
        .oneshot(http)
        .await
        .expect("job response");
    let (status, value) = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    serde_json::from_value(value).expect("job")
}

#[tokio::test]
async fn candidate_is_visible_but_never_dispatchable() {
    let fixture = fixture(true);
    let candidate = &fixture.resolution.candidates[0];
    let capsule = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .uri(format!("/api/wwm/v2/capsules/{}", candidate.capsule_id))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("capsule response");
    let (status, value) = response_json(capsule).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["capsule"]["activation_state"],
        "AUTHORIZED_NOT_ACTIVE"
    );
    assert_eq!(value["dispatchable"], false);

    let quote = quote_request(&fixture.resolution, candidate, "candidate", "secret prompt");
    let response = fixture
        .service
        .router()
        .oneshot(json_request(
            "POST",
            "/api/wwm/v2/quotes",
            Some(token_a()),
            serde_json::to_value(quote).expect("JSON"),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(fixture.dispatcher.calls(), 0);
}

#[tokio::test]
async fn idempotency_replay_stream_and_nonstream_are_equivalent_without_rerun() {
    let fixture = fixture(true);
    let prompt = "Why does the bonsai grow?";
    let quote = issue_quote(&fixture, prompt, "equivalence").await;
    assert_eq!(quote.payment_reference, "test-grant:tenant-a");
    let first = submit_job(&fixture, &quote, prompt, "idem-equivalence").await;
    assert_eq!(first.status, JobStatus::Completed);
    assert!(!first.replayed);
    let duplicate = submit_job(&fixture, &quote, prompt, "idem-equivalence").await;
    assert!(duplicate.replayed);
    assert_eq!(duplicate.job_id, first.job_id);
    assert_eq!(fixture.dispatcher.calls(), 1);

    let receipt_response = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .uri(format!("/api/wwm/v2/jobs/{}/receipt", first.job_id))
                .header("authorization", format!("Bearer {}", token_a()))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("receipt");
    let (status, receipt_json) = response_json(receipt_response).await;
    assert_eq!(status, StatusCode::OK);
    let receipt: Receipt = serde_json::from_value(receipt_json).expect("receipt body");
    assert_eq!(receipt.settlement_state, SettlementState::FinalizedPaid);

    let stream_uri = format!("/api/wwm/v2/jobs/{}/stream", first.job_id);
    let stream_one = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .uri(&stream_uri)
                .header("authorization", format!("Bearer {}", token_a()))
                .body(Body::empty())
                .expect("stream request"),
        )
        .await
        .expect("stream");
    let body_one = to_bytes(stream_one.into_body(), usize::MAX)
        .await
        .expect("SSE body");
    let text_one = String::from_utf8(body_one.to_vec()).expect("SSE UTF-8");
    assert!(text_one.contains(&format!("Bonsai: {prompt}")));
    assert!(text_one.contains("PROVISIONAL_SIGNED"));
    let stream_two = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .uri(&stream_uri)
                .header("authorization", format!("Bearer {}", token_a()))
                .header("last-event-id", "0")
                .body(Body::empty())
                .expect("stream request"),
        )
        .await
        .expect("stream");
    let text_two = String::from_utf8(
        to_bytes(stream_two.into_body(), usize::MAX)
            .await
            .expect("SSE")
            .to_vec(),
    )
    .expect("UTF-8");
    assert_eq!(text_one, text_two);
    assert_eq!(fixture.dispatcher.calls(), 1);
    assert_eq!(
        receipt.output_commitment,
        super::domain_hash("WWM-OUTPUT-V2", format!("Bonsai: {prompt}").as_bytes())
    );
}

#[tokio::test]
async fn cancellation_prevents_dispatch_and_finalizes_refund() {
    let fixture = fixture(false);
    let prompt = "cancel this request";
    let quote = issue_quote(&fixture, prompt, "cancel").await;
    let job = submit_job(&fixture, &quote, prompt, "idem-cancel").await;
    assert_eq!(job.status, JobStatus::Queued);
    let response = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/wwm/v2/jobs/{}/cancel", job.job_id))
                .header("authorization", format!("Bearer {}", token_a()))
                .body(Body::empty())
                .expect("cancel request"),
        )
        .await
        .expect("cancel response");
    assert_eq!(response.status(), StatusCode::OK);
    for _ in 0..3 {
        let _ = fixture
            .service
            .reconcile_once()
            .await
            .expect("reconcile cancel");
    }
    assert_eq!(fixture.dispatcher.calls(), 0);
    assert_eq!(fixture.dispatcher.cancels(), 1);
    let receipt = fixture
        .store
        .receipt("tenant-a", &job.job_id)
        .expect("receipt query")
        .expect("cancel receipt");
    assert_eq!(receipt.terminal_status, JobStatus::Cancelled);
    assert_eq!(receipt.settlement_state, SettlementState::FinalizedRefunded);
    assert_eq!(fixture.settlement.count(), 1);
}

#[derive(Clone, Default)]
struct CrashWindowSettlement {
    calls: Arc<Mutex<usize>>,
    submitted: Arc<Mutex<bool>>,
}

#[async_trait]
impl SettlementSubmitter for CrashWindowSettlement {
    fn assurance(&self) -> ComponentAssurance {
        ComponentAssurance::TestOnly
    }
    async fn settle(&self, receipt: &Receipt, refund: bool) -> Result<SettlementResult, V2Error> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| V2Error::Settlement("poisoned".to_owned()))?;
        *calls = calls.saturating_add(1);
        let mut submitted = self
            .submitted
            .lock()
            .map_err(|_| V2Error::Settlement("poisoned".to_owned()))?;
        let result = SettlementResult {
            chain_anchor: hash(&format!("anchor:{}", receipt.job_id)),
            state: if refund {
                SettlementState::FinalizedRefunded
            } else {
                SettlementState::FinalizedPaid
            },
        };
        if !*submitted {
            *submitted = true;
            return Err(V2Error::Settlement(
                "simulated crash after chain acceptance".to_owned(),
            ));
        }
        Ok(result)
    }
}

#[tokio::test]
async fn transactional_outbox_reconciles_chain_acceptance_crash_window() {
    let mut fixture = fixture(false);
    let crash = Arc::new(CrashWindowSettlement::default());
    fixture.service = GatewayV2Service::new(
        V2Config {
            allow_test_components: true,
            auto_reconcile: false,
            ..V2Config::default()
        },
        SecurityConfig::new(
            vec![TenantCredential {
                tenant_id: "tenant-a".to_owned(),
                bearer_token: token_a().to_owned(),
                csrf_token: None,
            }],
            Vec::<String>::new(),
            false,
        )
        .expect("security"),
        Arc::new(StaticResolver::new(fixture.resolution.clone())),
        fixture.dispatcher.clone(),
        fixture.store.clone(),
        Arc::new(TestSigner::new("test-key", [7; 32])),
        crash.clone(),
        Arc::new(TestPaymentVerifier),
    )
    .expect("service");
    let prompt = "crash window";
    let quote = issue_quote(&fixture, prompt, "crash").await;
    let job = submit_job(&fixture, &quote, prompt, "idem-crash").await;
    assert_eq!(fixture.service.reconcile_once().await.expect("dispatch"), 1);
    assert!(fixture.service.reconcile_once().await.is_err());
    assert_eq!(
        fixture
            .service
            .reconcile_once()
            .await
            .expect("settlement retry"),
        1
    );
    let receipt = fixture
        .store
        .receipt("tenant-a", &job.job_id)
        .expect("query")
        .expect("receipt");
    assert_eq!(receipt.settlement_state, SettlementState::FinalizedPaid);
    assert_eq!(*crash.calls.lock().expect("calls"), 2);
    assert_eq!(fixture.dispatcher.calls(), 1);
}

#[tokio::test]
async fn auth_csrf_cors_proxy_tenant_and_ssrf_negatives_fail_closed() {
    let fixture = fixture(true);
    let prompt = "tenant secret";
    let quote = issue_quote(&fixture, prompt, "security").await;
    let job = submit_job(&fixture, &quote, prompt, "idem-security").await;

    let unauthenticated = fixture
        .service
        .router()
        .oneshot(json_request(
            "POST",
            "/api/wwm/v2/quotes",
            None,
            serde_json::to_value(quote_request(
                &fixture.resolution,
                &fixture.resolution.active,
                "unauth",
                prompt,
            ))
            .expect("JSON"),
        ))
        .await
        .expect("response");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let bad_origin = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/wwm/v2/quotes")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token_a()))
                .header("origin", "https://evil.example")
                .body(Body::from(
                    serde_json::to_vec(&quote_request(
                        &fixture.resolution,
                        &fixture.resolution.active,
                        "cors",
                        prompt,
                    ))
                    .expect("JSON"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    let proxy = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/wwm/v2/state")
                .header("x-forwarded-for", "127.0.0.1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(proxy.status(), StatusCode::FORBIDDEN);

    let csrf = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/wwm/v2/quotes")
                .header("content-type", "application/json")
                .header("cookie", format!("wwm_session={}", token_a()))
                .header("origin", "https://app.example")
                .body(Body::from(
                    serde_json::to_vec(&quote_request(
                        &fixture.resolution,
                        &fixture.resolution.active,
                        "csrf",
                        prompt,
                    ))
                    .expect("JSON"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(csrf.status(), StatusCode::FORBIDDEN);

    let cross_tenant = fixture
        .service
        .router()
        .oneshot(
            Request::builder()
                .uri(format!("/api/wwm/v2/jobs/{}/receipt", job.job_id))
                .header("authorization", format!("Bearer {}", token_b()))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);

    let private_edge = ExecutorRegistration {
        https_origin: "http://169.254.169.254/".to_owned(),
        ..fixture.resolution.executors[0].clone()
    };
    assert_eq!(
        RegisteredHttpDispatcher::new(&[private_edge], Duration::from_secs(1), false).err(),
        Some(DispatchError::InvalidRegisteredOrigin)
    );
}

#[tokio::test]
async fn prompt_is_only_persisted_as_authenticated_ciphertext() {
    let fixture = fixture(false);
    let prompt = "raw-prompt-must-never-appear-0ddba11";
    let quote = issue_quote(&fixture, prompt, "privacy").await;
    let _job = submit_job(&fixture, &quote, prompt, "idem-privacy").await;
    assert!(!fixture.store.raw_storage_contains(prompt));
}

#[test]
fn production_constructor_rejects_sqlite_and_test_keys() {
    let fixture = fixture(false);
    let result = GatewayV2Service::new(
        V2Config::default(),
        SecurityConfig::new(
            vec![TenantCredential {
                tenant_id: "tenant-a".to_owned(),
                bearer_token: token_a().to_owned(),
                csrf_token: None,
            }],
            Vec::<String>::new(),
            false,
        )
        .expect("security"),
        Arc::new(StaticResolver::new(fixture.resolution)),
        fixture.dispatcher,
        fixture.store,
        Arc::new(TestSigner::new("test", [1; 32])),
        fixture.settlement,
        Arc::new(TestPaymentVerifier),
    );
    assert!(matches!(result, Err(V2Error::Configuration(_))));
}
