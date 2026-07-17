//! Supervisor topology + operator RPC battery (node-v1.md §7/§8/§10.6):
//! the three heads are reported SEPARATELY (never a merged "latest"),
//! observer mode refuses submission with an explicit `feature_disabled`
//! carrying a mechanism id (never empty success), bearer auth gates every
//! non-metrics route, and a consensus-task crash is CONTAINED (state is
//! rebuilt from the durable store while the process keeps serving).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::rpc::{self, hex, RpcConfig};
use crate::supervisor::{self, NodeHandle};

use super::util::*;

/// One bounded HTTP/1.1 round trip (connection: close).
fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect rpc");
    let body = body.unwrap_or("");
    let auth = token
        .map(|t| format!("authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nhost: localhost\r\n{auth}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    let payload = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, payload)
}

fn start_node(tag: &str, observer: bool) -> (NodeHandle, rpc::RpcHandle) {
    let dir = test_dir(tag);
    let mut cfg = node_config();
    cfg.observer = observer;
    let handle = supervisor::start(cfg, spec(), dir).expect("supervisor start");
    let rpc_handle = rpc::start(
        RpcConfig {
            bind: "127.0.0.1:0".parse().expect("loopback"),
            token: "operator-secret".into(),
            observer,
        },
        handle.consensus_tx.clone(),
        Arc::clone(&handle.metrics),
    )
    .expect("rpc start");
    (handle, rpc_handle)
}

#[test]
fn rpc_status_reports_the_three_heads_separately_and_auth_gates_routes() {
    let (handle, rpc_handle) = start_node("rpc-status", false);
    let addr = rpc_handle.addr;
    let token = Some("operator-secret");

    // Bearer auth gates every non-metrics route.
    let (unauth, body) = http_request(addr, "GET", "/status", None, None);
    assert_eq!(unauth, 401);
    assert!(body.contains(r#""code":"unauthorized""#));
    let (bad, _) = http_request(addr, "GET", "/status", Some("wrong"), None);
    assert_eq!(bad, 401);

    // /metrics is the read-only exception, every series noos_*.
    let (mstatus, metrics_text) = http_request(addr, "GET", "/metrics", None, None);
    assert_eq!(mstatus, 200);
    assert!(metrics_text.contains("noos_head_height"));
    assert!(metrics_text.contains("noos_finalized_epoch"));

    // The three heads are SEPARATE fields; a merged "latest" must not exist.
    let (status, body) = http_request(addr, "GET", "/status", token, None);
    assert_eq!(status, 200);
    assert!(
        body.contains(r#""unsafe_head""#),
        "unsafe head present: {body}"
    );
    assert!(body.contains(r#""justified""#), "justified present: {body}");
    assert!(body.contains(r#""finalized""#), "finalized present: {body}");
    assert!(
        body.contains(
            r#""finality_gossip":{"pending_votes":0,"pending_certificates":0,"accepted":0,"rejected":0}"#
        ),
        "finality gossip diagnostics present: {body}"
    );
    assert!(!body.contains(r#""latest""#), "merged latest is prohibited");
    assert!(body.contains(r#""observer":false"#));

    // Consensus-owned reserve state is served directly; genesis has no markets.
    let (safety_status, safety_body) = http_request(addr, "GET", "/stable/safety", token, None);
    assert_eq!(safety_status, 200, "{safety_body}");
    assert!(safety_body.contains(r#""items":[]"#), "{safety_body}");

    // Wallets can resolve the authoritative nonce and authorization descriptor.
    let faucet = hex(&faucet_key().public_key().into_bytes());
    let (account_status, account_body) =
        http_request(addr, "GET", &format!("/account/{faucet}"), token, None);
    assert_eq!(account_status, 200, "{account_body}");
    assert!(account_body.contains(r#""nonce":"0""#), "{account_body}");
    assert!(
        account_body.contains(r#""auth_descriptor""#),
        "{account_body}"
    );

    // Unknown routes are typed 404s.
    let (nf, body) = http_request(addr, "GET", "/nope", token, None);
    assert_eq!(nf, 404);
    assert!(body.contains(r#""code":"unknown_route""#));

    rpc_handle.shutdown();
    handle.shutdown();
}

#[test]
fn rpc_submission_settles_and_receipts_are_served() {
    let (handle, rpc_handle) = start_node("rpc-submit", false);
    let addr = rpc_handle.addr;
    let token = Some("operator-secret");

    let status = handle.status().expect("status");
    let (tx, wit, txid) = signed_transfer(
        status.chain_id,
        40,
        &faucet_key(),
        operator_account(1),
        4_242,
    );
    let payload = format!(r#"{{"tx":"{}","witnesses":"{}"}}"#, hex(&tx), hex(&wit));
    let (code, body) = http_request(addr, "POST", "/simulate_tx", token, Some(&payload));
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(r#""accepted":true"#), "{body}");
    assert!(body.contains(&hex(&txid)), "{body}");
    let (code, repeated) = http_request(addr, "POST", "/simulate_tx", token, Some(&payload));
    assert_eq!(code, 200, "{repeated}");
    assert!(repeated.contains(r#""accepted":true"#), "{repeated}");
    let (code, _) = http_request(
        addr,
        "GET",
        &format!("/receipt/{}", hex(&txid)),
        token,
        None,
    );
    assert_eq!(code, 404, "simulation must not persist a receipt");
    let (code, body) = http_request(addr, "POST", "/submit_tx", token, Some(&payload));
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(r#""accepted":true"#));
    assert!(body.contains(&hex(&txid)));

    // Malformed submissions are typed 400s, never phantom acceptance.
    let (code, body) = http_request(addr, "POST", "/submit_tx", token, Some("{}"));
    assert_eq!(code, 400);
    assert!(body.contains(r#""code":"malformed""#));
    // A duplicate is a typed admission conflict.
    let (code, body) = http_request(addr, "POST", "/submit_tx", token, Some(&payload));
    assert_eq!(code, 409);
    assert!(body.contains(r#""code":"duplicate_pending""#));

    // Produce the block over the supervisor inbox, then read it back.
    handle.set_now(GENESIS_TIME_MS + 6000).expect("set now");
    let block_hash = handle.produce_block().expect("produce");
    let (code, body) = http_request(addr, "GET", "/block/1", token, None);
    assert_eq!(code, 200);
    assert!(body.contains(&hex(&block_hash)));
    assert!(body.contains(&hex(&txid)));
    let (code, body) = http_request(
        addr,
        "GET",
        &format!("/block/{}", hex(&block_hash)),
        token,
        None,
    );
    assert_eq!(code, 200, "{body}");
    let (code, body) = http_request(addr, "GET", "/blocks/1/64", token, None);
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(r#""items":["#), "{body}");
    assert!(body.contains(&hex(&block_hash)), "{body}");
    assert!(body.contains(&hex(&txid)), "{body}");
    let (code, body) = http_request(addr, "GET", "/blocks/1/65", token, None);
    assert_eq!(code, 400, "{body}");

    let (code, body) = http_request(
        addr,
        "GET",
        &format!("/receipt/{}", hex(&txid)),
        token,
        None,
    );
    assert_eq!(code, 200);
    assert!(body.contains(r#""settled_height":1"#), "{body}");
    assert!(body.contains(r#""status_code":0"#), "{body}");

    let (code, body) = http_request(
        addr,
        "GET",
        &format!("/receipt/{}", hex(&[0xEE; 32])),
        token,
        None,
    );
    assert_eq!(code, 404);
    assert!(body.contains(r#""code":"not_found""#));

    rpc_handle.shutdown();
    handle.shutdown();
}

#[test]
fn observer_mode_disables_submission_with_an_explicit_mechanism_id() {
    let (handle, rpc_handle) = start_node("rpc-observer", true);
    let addr = rpc_handle.addr;
    let token = Some("operator-secret");

    let status = handle.status().expect("status");
    assert!(status.observer);
    let (tx, wit, _) = signed_transfer(
        status.chain_id,
        40,
        &faucet_key(),
        operator_account(1),
        1_000,
    );
    let payload = format!(r#"{{"tx":"{}","witnesses":"{}"}}"#, hex(&tx), hex(&wit));
    let (code, body) = http_request(addr, "POST", "/submit_tx", token, Some(&payload));
    assert_eq!(code, 409, "disabled feature is a conflict, not success");
    assert!(
        body.contains(r#""code":"feature_disabled""#),
        "explicit feature_disabled: {body}"
    );
    assert!(
        body.contains(r#""mechanism":"node.tx_submission.observer""#),
        "mechanism id present: {body}"
    );
    // The mempool stayed empty: never an empty success.
    assert_eq!(handle.status().expect("status").mempool_txs, 0);

    // Read routes keep working in observer mode.
    let (code, _) = http_request(addr, "GET", "/status", token, None);
    assert_eq!(code, 200);

    rpc_handle.shutdown();
    handle.shutdown();
}

#[test]
fn consensus_crash_is_contained_and_state_recovers_from_the_store() {
    let (handle, rpc_handle) = start_node("rpc-crash", false);

    handle.set_now(GENESIS_TIME_MS + 6000).expect("set now");
    handle.produce_block().expect("block 1");
    let before = handle.status().expect("status");
    assert_eq!(before.head_height, 1);

    // Panic the consensus task; the supervisor must contain the unwind,
    // drop the poisoned state, and rebuild from the durable store.
    handle.inject_crash().expect("inject");
    let after = handle.status().expect("status after crash");
    assert_eq!(after.head_height, before.head_height, "state recovered");
    assert_eq!(after.head_hash, before.head_hash);
    assert!(
        handle
            .metrics
            .task_restarts_total
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1,
        "the restart was counted"
    );

    // The recovered task keeps producing.
    handle.set_now(GENESIS_TIME_MS + 12_000).expect("set now");
    handle.produce_block().expect("block 2 after recovery");
    assert_eq!(handle.status().expect("status").head_height, 2);

    rpc_handle.shutdown();
    handle.shutdown();
}
