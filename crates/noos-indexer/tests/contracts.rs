#![allow(clippy::unwrap_used)]

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use noos_indexer::{
    router, ChainPoint, HeadKind, Identity, Indexer, MetricSample, TelemetryValue, UnknownReason,
};
use std::collections::BTreeMap;
use tower::ServiceExt;

fn hash(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}
fn identity() -> Identity {
    Identity {
        chain_id: hash('a'),
        genesis_hash: hash('b'),
        api_version: "v1".into(),
    }
}

#[test]
fn wrong_chain_fails_before_touching_root() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("must-not-exist");
    let mut wrong = identity();
    wrong.chain_id = hash('c');
    let error = Indexer::open(&root, identity(), wrong).err().unwrap();
    assert_eq!(error.to_string(), "wrong_protocol_identity");
    assert!(
        !root.exists(),
        "identity rejection must precede filesystem access"
    );
}

#[tokio::test]
async fn independent_heads_never_infer_finality() {
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    indexer
        .ingest_head(
            &identity(),
            HeadKind::Unsafe,
            ChainPoint {
                height: "9".into(),
                hash: hash('c'),
                state_root: hash('d'),
            },
        )
        .await
        .unwrap();
    indexer
        .ingest_head(
            &identity(),
            HeadKind::Justified,
            ChainPoint {
                height: "7".into(),
                hash: hash('e'),
                state_root: hash('f'),
            },
        )
        .await
        .unwrap();
    let response = router(indexer)
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["unsafe_head"]["height"], "9");
    assert_eq!(body["justified"]["height"], "7");
    assert_eq!(body["finalized"]["height"], "0");
    assert_eq!(body["readiness"], "starting");
    assert_eq!(body["ready"], false);
    assert_eq!(body["indexed_generation"], "0");
    assert_eq!(body["freshness_ms"], u64::MAX.to_string());
}

#[tokio::test]
async fn disabled_routes_and_unconfigured_submission_match_contract() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(Indexer::open(dir.path(), identity(), identity()).unwrap());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/models")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(error["code"], "feature_disabled");
    assert_eq!(error["mechanism_id"], "M-NEL");

    let request = serde_json::json!({"tx":"00","witnesses":"00"});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transactions")
                .header("content-type", "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(error["code"], "unavailable");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/addresses/mind1historical/notes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(error["code"], "wrong_protocol_identity");
}

#[tokio::test]
async fn pagination_cursor_is_opaque_unpadded_and_query_bound() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(Indexer::open(dir.path(), identity(), identity()).unwrap());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/blocks?limit=1&cursor=eyJ2IjoyfQ")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/blocks?limit=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn telemetry_unknown_is_not_a_healthy_zero() {
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let stale = indexer
        .telemetry_sample(
            100,
            MetricSample {
                name: "noos_p2p_peers".into(),
                value: 4.0,
                labels: BTreeMap::new(),
                observed_at: 10,
                freshness_deadline: 45,
                cardinality_ceiling: 1,
            },
        )
        .await;
    assert_eq!(stale, TelemetryValue::Unknown(UnknownReason::Stale));
    let malformed = indexer
        .telemetry_sample(
            100,
            MetricSample {
                name: "old_peers".into(),
                value: 0.0,
                labels: BTreeMap::new(),
                observed_at: 100,
                freshness_deadline: 45,
                cardinality_ceiling: 1,
            },
        )
        .await;
    assert_eq!(malformed, TelemetryValue::Unknown(UnknownReason::Malformed));
}
