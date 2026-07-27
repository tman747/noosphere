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
use noos_braid::EPOCH_LENGTH;
use noos_lumen::neural_oracle::{neural_program_id, EvaluateNeuralProgramV1, NeuralProgramV1};
use noos_lumen::objects::{ActionV1, BoundedBytes};

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
        body.contains(&format!(
            r#""release_version":"{}","source_revision":"{}""#,
            crate::RELEASE_VERSION,
            crate::SOURCE_REVISION
        )),
        "release identity present: {body}"
    );
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

    // Neural-oracle reads are finalized-state only. A missing result returns
    // typed 404 after its local sparse-Merkle non-membership proof verifies.
    let query_id = hex(&[0x6a; 32]);
    let (neural_status, neural_body) = http_request(
        addr,
        "GET",
        &format!("/neural-oracle/{query_id}"),
        token,
        None,
    );
    assert_eq!(neural_status, 404, "{neural_body}");
    assert!(
        neural_body.contains(r#""code":"not_found""#),
        "{neural_body}"
    );
    let (malformed_status, malformed_body) =
        http_request(addr, "GET", "/neural-oracle/not-hex", token, None);
    assert_eq!(malformed_status, 400, "{malformed_body}");
    assert!(
        malformed_body.contains(r#""code":"malformed""#),
        "{malformed_body}"
    );

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
fn finalized_neural_evaluation_exposes_exact_program_and_replay_proof() {
    let dir = test_dir("rpc-neural-evaluation");
    let key = faucet_key();
    let mut genesis = spec();
    genesis.wwm_bonsai_fixture = true;
    genesis.gov_authority = key.public_key().into_bytes();
    let mut cfg = node_config();
    cfg.devnet_fixture_finality = true;
    let handle = supervisor::start(cfg, genesis, dir).expect("supervisor start");
    let rpc_handle = rpc::start(
        RpcConfig {
            bind: "127.0.0.1:0".parse().expect("loopback"),
            token: "operator-secret".into(),
            observer: false,
        },
        handle.consensus_tx.clone(),
        Arc::clone(&handle.metrics),
    )
    .expect("rpc start");
    let addr = rpc_handle.addr;
    let token = Some("operator-secret");

    let mut program = NeuralProgramV1 {
        program_id: [0; 32],
        input_width: 2,
        hidden_width: 2,
        output_width: 1,
        hidden_weights: BoundedBytes::new(vec![2, 0, 0, 2]).expect("hidden weights"),
        hidden_biases: BoundedBytes::new(vec![0, 0]).expect("hidden biases"),
        output_weights: BoundedBytes::new(vec![2, 2]).expect("output weights"),
        output_biases: BoundedBytes::new(vec![0]).expect("output biases"),
    };
    program.program_id = neural_program_id(&program);
    let query_id = [0x6b; 32];
    let actions = vec![
        ActionV1::RegisterNeuralProgram(program.clone()),
        ActionV1::EvaluateNeuralProgram(EvaluateNeuralProgramV1 {
            query_id,
            program_id: program.program_id,
            requester: key.public_key().into_bytes(),
            input: BoundedBytes::new(vec![2, 0]).expect("input"),
        }),
    ];
    let status = handle.status().expect("status");
    let (tx, witnesses, txid) = build_signed_tx(status.chain_id, 1_000, &key, actions, vec![]);
    let payload = format!(
        r#"{{"tx":"{}","witnesses":"{}"}}"#,
        hex(&tx),
        hex(&witnesses)
    );
    let (submit_status, submit_body) =
        http_request(addr, "POST", "/submit_tx", token, Some(&payload));
    assert_eq!(submit_status, 200, "{submit_body}");
    assert!(submit_body.contains(&hex(&txid)), "{submit_body}");

    for height in 1..=EPOCH_LENGTH.saturating_mul(2) {
        handle
            .set_now(GENESIS_TIME_MS.saturating_add(height.saturating_mul(6_000)))
            .expect("advance clock");
        handle.produce_block().expect("produce block");
        if height == 1 {
            let (receipt_status, receipt_body) = http_request(
                addr,
                "GET",
                &format!("/receipt/{}", hex(&txid)),
                token,
                None,
            );
            assert_eq!(receipt_status, 200, "{receipt_body}");
            assert!(
                receipt_body.contains(r#""status_code":0"#),
                "{receipt_body}"
            );
        }
        if height.is_multiple_of(EPOCH_LENGTH) {
            assert!(handle.devnet_finality_tick().expect("finality tick"));
        }
    }

    let path = format!("/neural-evaluation/{}/0200", hex(&query_id));
    let (evaluation_status, evaluation_body) = http_request(addr, "GET", &path, token, None);
    assert_eq!(evaluation_status, 200, "{evaluation_body}");
    let value: serde_json::Value = serde_json::from_str(&evaluation_body).expect("evaluation JSON");
    assert_eq!(value["schema"], "noos/finalized-neural-evaluation/v1");
    assert_eq!(value["program_id"], hex(&program.program_id));
    assert_eq!(value["query_id"], hex(&query_id));
    assert_eq!(
        value["shape"],
        serde_json::json!({"input":2,"hidden":2,"output":1})
    );
    assert_eq!(
        value["evaluation"]["input_encoded"],
        serde_json::json!([2, 0])
    );
    assert_eq!(value["evaluation"]["operations"], 9);
    assert_eq!(value["evaluation"]["replay_verified"], true);
    assert_eq!(value["proofs_verified"], true);
    assert_eq!(value["weights_on_chain"], true);

    let wrong_input_path = format!("/neural-evaluation/{}/0000", hex(&query_id));
    let (wrong_status, wrong_body) = http_request(addr, "GET", &wrong_input_path, token, None);
    assert_eq!(wrong_status, 422, "{wrong_body}");
    assert!(
        wrong_body.contains(r#""code":"input_commitment_mismatch""#),
        "{wrong_body}"
    );

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
fn rpc_batch_submission_returns_input_aligned_results() {
    let (handle, rpc_handle) = start_node("rpc-submit-batch", false);
    let addr = rpc_handle.addr;
    let token = Some("operator-secret");
    let chain_id = handle.status().expect("status").chain_id;
    let (tx_a, wit_a, txid_a) =
        signed_transfer(chain_id, 40, &faucet_key(), operator_account(1), 1_001);
    let (tx_b, wit_b, txid_b) =
        signed_transfer(chain_id, 40, &faucet_key(), operator_account(2), 1_002);
    let payload = format!(
        concat!(
            r#"{{"transactions":["#,
            r#"{{"tx":"{}","witnesses":"{}"}},"#,
            r#"{{"tx":"{}","witnesses":"{}"}}"#,
            r#"]}}"#
        ),
        hex(&tx_a),
        hex(&wit_a),
        hex(&tx_b),
        hex(&wit_b),
    );
    let (code, body) = http_request(addr, "POST", "/submit_tx_batch", token, Some(&payload));
    assert_eq!(code, 200, "{body}");
    assert!(body.contains(r#""accepted":2"#), "{body}");
    assert!(body.contains(r#""rejected":0"#), "{body}");
    assert!(body.contains(&hex(&txid_a)), "{body}");
    assert!(body.contains(&hex(&txid_b)), "{body}");
    assert_eq!(handle.status().expect("status").mempool_txs, 2);

    let (code, body) = http_request(
        addr,
        "POST",
        "/submit_tx_batch",
        token,
        Some(r#"{"transactions":[]}"#),
    );
    assert_eq!(code, 400, "{body}");
    assert!(body.contains(r#""code":"malformed""#), "{body}");

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
