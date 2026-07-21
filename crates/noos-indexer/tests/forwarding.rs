#![allow(clippy::unwrap_used)]

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use noos_indexer::{
    ingest::LineProtocolSource, router, router_with_operator, Identity, Indexer,
    MAX_SUBMISSION_REQUEST_BYTES,
};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tower::ServiceExt;

const TOKEN: &str = "test-operator-token";

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

fn status_body(id: &Identity) -> String {
    serde_json::json!({
        "chain_id": id.chain_id,
        "genesis_hash": id.genesis_hash,
        "unsafe_head": {"height": 0, "hash": id.genesis_hash},
        "justified": {"epoch": 0, "hash": id.genesis_hash},
        "finalized": {"epoch": 0, "hash": id.genesis_hash},
        "mempool": {"txs": 0, "bytes": 0},
        "observer": false
    })
    .to_string()
}

struct FakeNode {
    addr: String,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeNode {
    fn spawn(responses: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let thread_seen = Arc::clone(&seen);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let mut responses: VecDeque<_> = responses.into();
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => return,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request = read_request(&mut stream);
                thread_seen.lock().unwrap().push(request);
                let (status, body) = responses
                    .pop_front()
                    .unwrap_or((500, r#"{"error":{"code":"unexpected_request"}}"#.into()));
                let reason = match status {
                    200 => "OK",
                    202 => "Accepted",
                    409 => "Conflict",
                    503 => "Service Unavailable",
                    _ => "Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            addr,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .and_then(|position| position.checked_add(4))
        else {
            continue;
        };
        let head = String::from_utf8_lossy(&request[..header_end]);
        let content_length = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        });
        if request.len() >= header_end.saturating_add(content_length.unwrap_or(0)) {
            break;
        }
    }
    request
}

fn configured_app(node: &FakeNode) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let source = LineProtocolSource::new(format!("http://{}/", node.addr), TOKEN);
    (dir, router_with_operator(indexer, source))
}

async fn post_to(app: Router, path: &str, body: Vec<u8>) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn post(app: Router, body: Vec<u8>) -> axum::response::Response {
    post_to(app, "/api/v1/transactions", body).await
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

async fn assert_not_indexed(app: Router, txid: &str) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/transactions/{txid}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn forwards_exact_envelope_and_waits_for_ingestion_to_create_truth() {
    let txid = hash('9');
    let node = FakeNode::spawn(vec![
        (200, status_body(&identity())),
        (
            200,
            serde_json::json!({"accepted": true, "txid": txid}).to_string(),
        ),
    ]);
    let (_dir, app) = configured_app(&node);
    let envelope = br#"{ "tx":"00aa", "witnesses":"11bb" }"#.to_vec();
    let response = post(app.clone(), envelope.clone()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response_json(response).await;
    assert_eq!(
        body,
        serde_json::json!({"txid": hash('9'), "state": "MEMPOOL"})
    );
    assert_not_indexed(app, &hash('9')).await;

    let requests = node.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(b"GET /status HTTP/1.1\r\n"));
    assert!(requests[1].starts_with(b"POST /submit_tx HTTP/1.1\r\n"));
    assert!(requests[1]
        .windows(format!("authorization: Bearer {TOKEN}").len())
        .any(|window| window == format!("authorization: Bearer {TOKEN}").as_bytes()));
    let forwarded = requests[1]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| &requests[1][position + 4..])
        .unwrap();
    assert_eq!(forwarded, envelope);
}

#[tokio::test]
async fn identity_mismatch_stops_before_submission_and_creates_no_row() {
    let mut wrong = identity();
    wrong.chain_id = hash('c');
    let node = FakeNode::spawn(vec![(200, status_body(&wrong))]);
    let (_dir, app) = configured_app(&node);
    let response = post(app.clone(), br#"{"tx":"00","witnesses":"11"}"#.to_vec()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response).await;
    assert_eq!(body["code"], "wrong_protocol_identity");
    assert_not_indexed(app, &hash('9')).await;
    let requests = node.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(b"GET /status HTTP/1.1\r\n"));
}

#[tokio::test]
async fn node_rejection_is_propagated_and_creates_no_row() {
    let node = FakeNode::spawn(vec![
        (200, status_body(&identity())),
        (
            409,
            r#"{"error":{"code":"duplicate_pending","detail":"admission refused"}}"#.into(),
        ),
    ]);
    let (_dir, app) = configured_app(&node);
    let response = post(app.clone(), br#"{"tx":"00","witnesses":"11"}"#.to_vec()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = response_json(response).await;
    assert_eq!(body["code"], "node_refused");
    assert_eq!(body["details"]["node_code"], "duplicate_pending");
    assert_eq!(body["details"]["node_status"], 409);
    assert_not_indexed(app, &hash('9')).await;
    assert_eq!(node.requests().len(), 2);
}

#[tokio::test]
async fn unavailable_and_malformed_node_responses_fail_closed() {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = unused.local_addr().unwrap().to_string();
    drop(unused);
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity(), identity()).unwrap();
    let app = router_with_operator(indexer, LineProtocolSource::new(addr, TOKEN));
    let response = post(app.clone(), br#"{"tx":"00","witnesses":"11"}"#.to_vec()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_json(response).await["code"], "unavailable");
    assert_not_indexed(app, &hash('9')).await;

    let node = FakeNode::spawn(vec![(200, "not-json".into())]);
    let (_dir, app) = configured_app(&node);
    let response = post(app.clone(), br#"{"tx":"00","witnesses":"11"}"#.to_vec()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_json(response).await["code"], "unavailable");
    assert_not_indexed(app, &hash('9')).await;
}

#[tokio::test]
async fn lending_state_is_identity_checked_and_forwarded_read_only() {
    let item = serde_json::json!({
        "items": [{
            "market_id": hash('1'),
            "stable_asset": hash('2'),
            "total_debt": "7000"
        }]
    });
    let node = FakeNode::spawn(vec![
        (200, status_body(&identity())),
        (200, item.to_string()),
    ]);
    let (_dir, app) = configured_app(&node);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/lending-markets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, item);
    let requests = node.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(b"GET /status HTTP/1.1\r\n"));
    assert!(requests[1].starts_with(b"GET /lending/markets HTTP/1.1\r\n"));
}

#[tokio::test]
async fn simulation_forwards_exact_envelope_without_creating_indexed_truth() {
    let prediction = serde_json::json!({
        "accepted": true,
        "txid": hash('8'),
        "receipt": {"status": "success", "fee_charged": "12"}
    });
    let node = FakeNode::spawn(vec![
        (200, status_body(&identity())),
        (200, prediction.to_string()),
    ]);
    let (_dir, app) = configured_app(&node);
    let envelope = br#"{"tx":"00aa","witnesses":"11bb"}"#.to_vec();
    let response = post_to(
        app.clone(),
        "/api/v1/transactions/simulate",
        envelope.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, prediction);
    assert_not_indexed(app, &hash('8')).await;

    let requests = node.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(b"GET /status HTTP/1.1\r\n"));
    assert!(requests[1].starts_with(b"POST /simulate_tx HTTP/1.1\r\n"));
    let forwarded = requests[1]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| &requests[1][position + 4..])
        .unwrap();
    assert_eq!(forwarded, envelope);
}

#[tokio::test]
async fn reserve_safety_and_account_state_are_identity_checked_read_throughs() {
    let account = hash('6');
    let safety = serde_json::json!({
        "items": [{
            "market_id": hash('1'),
            "reserve_account": account,
            "reserve_balance": "9000",
            "psm_minted": "4000"
        }]
    });
    let account_state = serde_json::json!({
        "account": account,
        "nonce": "17",
        "authorization": {"kind": "single_key"}
    });
    let node = FakeNode::spawn(vec![
        (200, status_body(&identity())),
        (200, safety.to_string()),
        (200, status_body(&identity())),
        (200, account_state.to_string()),
    ]);
    let (_dir, app) = configured_app(&node);

    let safety_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/stable-safety")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(safety_response.status(), StatusCode::OK);
    assert_eq!(response_json(safety_response).await, safety);

    let account_response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/accounts/{account}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(account_response.status(), StatusCode::OK);
    assert_eq!(response_json(account_response).await, account_state);

    let requests = node.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].starts_with(b"GET /stable/safety HTTP/1.1\r\n"));
    assert!(requests[3].starts_with(format!("GET /account/{account} HTTP/1.1\r\n").as_bytes()));
}

#[tokio::test]
async fn private_payments_are_identity_checked_and_forwarded_read_only() {
    let item = serde_json::json!({
        "items": [{
            "payment_id": hash('4'),
            "stable_asset": hash('5'),
            "amount": "7000",
            "status": 0
        }]
    });
    let node = FakeNode::spawn(vec![
        (200, status_body(&identity())),
        (200, item.to_string()),
    ]);
    let (_dir, app) = configured_app(&node);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/private-payments")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, item);
    let requests = node.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(b"GET /status HTTP/1.1\r\n"));
    assert!(requests[1].starts_with(b"GET /payments/private HTTP/1.1\r\n"));
}

#[tokio::test]
async fn malformed_and_oversize_public_inputs_never_reach_a_node_or_index() {
    let node = FakeNode::spawn(Vec::new());
    let (_dir, app) = configured_app(&node);
    let malformed = post(
        app.clone(),
        br#"{"tx":"AA","witnesses":"11","extra":true}"#.to_vec(),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(malformed).await["code"], "invalid_request");

    let noncanonical = post(app.clone(), br#"{"tx":"AA","witnesses":"11"}"#.to_vec()).await;
    assert_eq!(noncanonical.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(noncanonical).await["code"],
        "validation_failed"
    );

    let oversize = post(app.clone(), vec![b' '; MAX_SUBMISSION_REQUEST_BYTES + 1]).await;
    assert_eq!(oversize.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response_json(oversize).await["code"], "payload_too_large");
    assert_not_indexed(app, &hash('9')).await;
    assert!(node.requests().is_empty());

    let dir = tempfile::tempdir().unwrap();
    let app = router(Indexer::open(dir.path(), identity(), identity()).unwrap());
    let response = post(app.clone(), br#"{"tx":"00","witnesses":"11"}"#.to_vec()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response_json(response).await["code"], "unavailable");
    assert_not_indexed(app, &hash('9')).await;
}
