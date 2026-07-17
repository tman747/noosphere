//! Minimal localhost operator RPC (plan §7.7; node-v1.md §8).
//!
//! Deliberately NOT the public REST API v1 (that product phase freezes
//! `openapi-v1.yaml`). Surface:
//!
//! ```text
//! GET  /status      chain_id, genesis_hash, and the THREE heads
//!                   SEPARATELY (unsafe/justified/finalized — a merged
//!                   "latest" does not exist here)
//! POST /submit_tx   {"tx":"<hex>","witnesses":"<hex>"} → txid;
//!                   observer mode → 409 feature_disabled with the
//!                   mechanism id, never empty success
//! GET  /model-resolution/<alias>
//!                   finalized 17-leaf WWM graph plus canonical proof bytes;
//!                   full model weights are never returned or stored on chain
//! GET  /block/<height|hash-hex>
//! GET  /wwm-record/<job|receipt|settlement>/<id>
//!                   one canonical lifecycle record and its finalized object proof
//! GET  /blocks/<start-height>/<limit> (authenticated, limit 1..64)
//! GET  /receipt/<txid-hex>
//! GET  /assets      fixed-supply user asset registry
//! GET  /pools       constant-product pool registry
//! GET  /balance/<account>/<asset>
//!                   liquid account balance for one asset
//! GET  /metrics     Prometheus text, every series `noos_*` (no auth,
//!                   read-only, localhost)
//! ```
//!
//! Every non-metrics route requires `Authorization: Bearer <token>`.
//! Unsupported or disabled features return an explicit
//! `{"error":{"code":"feature_disabled","mechanism":"..."}}` — never an
//! empty success (plan §7.7).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::metrics::Metrics;
use crate::supervisor::{BlockId, ConsensusMsg, StatusSnapshot};
use crate::view::{TxStatus, ViewLookup};
use crate::Hash32;
use noos_braid::EPOCH_LENGTH;
use noos_codec::{NoosDecode, NoosEncode};
use noos_lumen::objects::BoundedBytes;
use noos_lumen::wwm::{
    carrier_len_valid, ResolutionSelectorKind, ResolutionSelectorV1, ResolutionValueV1,
    WwmControlMode, WwmJobV1, WwmLeafKind, WwmReceiptV1, WwmSettlementV1,
    MAX_TX_WITNESS_BYTES,
};

/// RPC configuration.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Bind address; MUST be a loopback address (operator RPC is
    /// localhost-only by law; a non-loopback bind is refused).
    pub bind: SocketAddr,
    /// Bearer token required on every non-metrics route.
    pub token: String,
    /// Observer mode: submission is a disabled feature.
    pub observer: bool,
}

/// Handle to the RPC task.
pub struct RpcHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RpcHandle {
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Nudge the accept loop.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Starts the RPC server task.
pub fn start(
    cfg: RpcConfig,
    consensus_tx: SyncSender<ConsensusMsg>,
    metrics: Arc<Metrics>,
) -> std::io::Result<RpcHandle> {
    if !cfg.bind.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "operator RPC binds loopback only",
        ));
    }
    let listener = TcpListener::bind(cfg.bind)?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("noos-rpc".into())
        .spawn(move || {
            for stream in listener.incoming() {
                if stop_flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let response = handle_connection(&mut stream, &cfg, &consensus_tx, &metrics);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        })?;
    Ok(RpcHandle {
        addr,
        stop,
        handle: Some(handle),
    })
}

// ---------------------------------------------------------------------------
// HTTP plumbing (bounded, single request per connection)
// ---------------------------------------------------------------------------

const MAX_REQUEST_BYTES: usize = 512 * 1024;

fn http(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn json_error(status: &str, code: &str, detail: &str) -> String {
    http(
        status,
        "application/json",
        &format!(r#"{{"error":{{"code":"{code}","detail":"{detail}"}}}}"#),
    )
}

fn feature_disabled(mechanism: &str, detail: &str) -> String {
    http(
        "409 Conflict",
        "application/json",
        &format!(
            r#"{{"error":{{"code":"feature_disabled","mechanism":"{mechanism}","detail":"{detail}"}}}}"#
        ),
    )
}

fn handle_connection(
    stream: &mut TcpStream,
    cfg: &RpcConfig,
    consensus_tx: &SyncSender<ConsensusMsg>,
    metrics: &Arc<Metrics>,
) -> String {
    metrics.inc(&metrics.rpc_requests_total);
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let header_end;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return json_error("400 Bad Request", "truncated", "connection closed"),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_header_end(&buf) {
                    header_end = pos;
                    break;
                }
                if buf.len() > MAX_REQUEST_BYTES {
                    return json_error("413 Payload Too Large", "oversized", "request too large");
                }
            }
            Err(_) => return json_error("408 Request Timeout", "timeout", "read timed out"),
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0_usize;
    let mut bearer_ok = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().unwrap_or(0);
        } else if name == "authorization" {
            if let Some(token) = value.strip_prefix("Bearer ") {
                bearer_ok = constant_time_eq(token.as_bytes(), cfg.token.as_bytes());
            }
        }
    }
    if content_length > MAX_REQUEST_BYTES {
        return json_error("413 Payload Too Large", "oversized", "body too large");
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return json_error("408 Request Timeout", "timeout", "read timed out"),
        }
    }

    // /metrics is the unauthenticated read-only exception.
    if method == "GET" && path == "/metrics" {
        return http("200 OK", "text/plain; version=0.0.4", &metrics.render());
    }
    if !bearer_ok {
        metrics.inc(&metrics.rpc_unauthorized_total);
        return json_error(
            "401 Unauthorized",
            "unauthorized",
            "missing or bad bearer token",
        );
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/status") => status_route(consensus_tx),
        ("POST", "/submit_tx") => submit_route(cfg, consensus_tx, &body),
        ("POST", "/simulate_tx") => simulate_route(consensus_tx, &body),
        _ if method == "GET" && path.starts_with("/model-resolution/") => {
            model_resolution_route(consensus_tx, &path["/model-resolution/".len()..])
        }
        _ if method == "GET" && path.starts_with("/wwm-record/") => {
            wwm_record_route(consensus_tx, &path["/wwm-record/".len()..])
        }
        _ if method == "GET" && path.starts_with("/blocks/") => {
            blocks_route(consensus_tx, &path["/blocks/".len()..])
        }
        _ if method == "GET" && path.starts_with("/block/") => {
            block_route(consensus_tx, &path["/block/".len()..])
        }
        _ if method == "GET" && path.starts_with("/receipt/") => {
            receipt_route(consensus_tx, &path["/receipt/".len()..])
        }
        ("GET", "/assets") => assets_route(consensus_tx),
        ("GET", "/pools") => pools_route(consensus_tx),
        ("GET", "/liquidity/positions") => liquidity_positions_route(consensus_tx),
        ("GET", "/oracle/feeds") => oracle_feeds_route(consensus_tx),
        ("GET", "/oracle/reports") => oracle_reports_route(consensus_tx),
        ("GET", "/lending/markets") => lending_markets_route(consensus_tx),
        ("GET", "/stable/assets") => stable_assets_route(consensus_tx),
        ("GET", "/stable/safety") => stable_safety_route(consensus_tx),
        ("GET", "/lending/positions") => debt_positions_route(consensus_tx),
        ("GET", "/payments/private") => private_payments_route(consensus_tx),
        ("GET", "/compute/workers") => compute_workers_route(consensus_tx),
        ("GET", "/compute/jobs") => compute_jobs_route(consensus_tx),
        _ if method == "GET" && path.starts_with("/account/") => {
            account_route(consensus_tx, &path["/account/".len()..])
        }
        _ if method == "GET" && path.starts_with("/balance/") => {
            balance_route(consensus_tx, &path["/balance/".len()..])
        }
        _ => json_error("404 Not Found", "unknown_route", "no such operator route"),
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p.saturating_add(4))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

fn round_trip<T>(
    consensus_tx: &SyncSender<ConsensusMsg>,
    build: impl FnOnce(SyncSender<T>) -> ConsensusMsg,
) -> Option<T> {
    let (reply_tx, reply_rx) = sync_channel(1);
    consensus_tx.send(build(reply_tx)).ok()?;
    reply_rx.recv_timeout(Duration::from_secs(10)).ok()
}

fn status_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(s): Option<StatusSnapshot> =
        round_trip(consensus_tx, |reply| ConsensusMsg::Status { reply })
    else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no status",
        );
    };
    // The three heads are SEPARATE fields by law; no merged "latest".
    let body = format!(
        concat!(
            r#"{{"chain_id":"{}","genesis_hash":"{}","#,
            r#""unsafe_head":{{"height":{},"hash":"{}"}},"#,
            r#""justified":{{"epoch":{},"hash":"{}"}},"#,
            r#""finalized":{{"epoch":{},"hash":"{}"}},"#,
            r#""finality_gossip":{{"pending_votes":{},"pending_certificates":{},"accepted":{},"rejected":{}}},"#,
            r#""mempool":{{"txs":{},"bytes":{}}},"observer":{}}}"#
        ),
        hex(&s.chain_id),
        hex(&s.genesis_hash),
        s.head_height,
        hex(&s.head_hash),
        s.justified.epoch,
        hex(&s.justified.checkpoint_hash),
        s.finalized.epoch,
        hex(&s.finalized.checkpoint_hash),
        s.pending_votes,
        s.pending_certificates,
        s.inbound_votes_accepted,
        s.inbound_votes_rejected,
        s.mempool_txs,
        s.mempool_bytes,
        s.observer,
    );
    http("200 OK", "application/json", &body)
}

fn model_resolution_route(consensus_tx: &SyncSender<ConsensusMsg>, alias: &str) -> String {
    if alias.is_empty()
        || alias.len() > 64
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return json_error(
            "400 Bad Request",
            "invalid_selector",
            "alias must contain 1..64 ASCII letters, digits, '-' or '_'",
        );
    }
    let Some(value) = BoundedBytes::new(alias.as_bytes().to_vec()) else {
        return json_error(
            "400 Bad Request",
            "invalid_selector",
            "alias exceeds the canonical bound",
        );
    };
    let selector = ResolutionSelectorV1 {
        kind: ResolutionSelectorKind::Alias,
        value,
    };
    let result = round_trip(consensus_tx, |reply| ConsensusMsg::ResolveModel {
        selector: selector.clone(),
        freshness_bound: EPOCH_LENGTH.saturating_mul(2),
        reply,
    });
    let response = match result {
        Some(Ok(response)) => response,
        Some(Err(error)) => {
            let body = serde_json::json!({
                "error": {
                    "code": "finalized_resolution_unavailable",
                    "detail": error,
                }
            })
            .to_string();
            return http("503 Service Unavailable", "application/json", &body);
        }
        None => {
            return json_error(
                "503 Service Unavailable",
                "consensus_unavailable",
                "no model-resolution reply",
            )
        }
    };
    let terminal = match crate::resolver::FinalizedResolutionTerminalV1::decode_canonical(
        response.terminal_material.as_slice(),
    ) {
        Ok(terminal) => terminal,
        Err(_) => {
            return json_error(
                "500 Internal Server Error",
                "invalid_local_resolution",
                "terminal material failed canonical decoding",
            )
        }
    };
    let trusted = crate::resolver::TrustedFinalizedCheckpointV1 {
        checkpoint: terminal.checkpoint,
        height: response.resolution_height,
    };
    let verified = match crate::resolver::verify_finalized_model_resolution(
        &response,
        response.chain_id,
        response.genesis_hash,
        &selector,
        trusted,
        response.resolution_height,
    ) {
        Ok(verified) => verified,
        Err(_) => {
            return json_error(
                "500 Internal Server Error",
                "invalid_local_resolution",
                "the local full-node verifier rejected its resolution graph",
            )
        }
    };
    let (
        Some(config),
        Some(capsule),
        Some(artifact),
        Some(policy),
        Some(certificate),
        Some(execution),
        Some(query),
        Some(fund),
        Some(service),
        Some(executor_set),
        Some(custodian_set),
    ) = (
        verified.config,
        verified.capsule,
        verified.artifact,
        verified.availability_policy,
        verified.availability_certificate,
        verified.execution_profile,
        verified.query_policy,
        verified.fund_profile,
        verified.service_directory,
        verified.executor_set,
        verified.custodian_set,
    )
    else {
        return json_error(
            "404 Not Found",
            "model_not_active",
            "selector does not resolve an active model graph",
        );
    };
    const BONSAI_SHA256: &str = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0";
    const BONSAI_MANIFEST: &str =
        "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7";
    if alias != "bonsai-q1"
        || artifact.source_bytes != 3_803_452_480
        || hex(&artifact.published_sha256) != BONSAI_SHA256
        || hex(&artifact.manifest_root) != BONSAI_MANIFEST
        || verified.control.mode != WwmControlMode::Testnet
    {
        return json_error(
            "409 Conflict",
            "wrong_bonsai_identity",
            "active graph does not match the exact Bonsai testnet identity",
        );
    }
    let endpoint = service
        .endpoint_records
        .as_slice()
        .first()
        .map(|value| String::from_utf8_lossy(value.as_slice()).into_owned())
        .unwrap_or_default();
    let active = serde_json::json!({
        "model_name": "Bonsai-27B-Q1_0.gguf",
        "capsule_id": hex(&capsule.capsule_id),
        "artifact_id": hex(&artifact.artifact_id),
        "artifact_bytes": artifact.source_bytes,
        "artifact_sha256": BONSAI_SHA256,
        "payload_root": hex(&artifact.payload_root),
        "manifest_root": BONSAI_MANIFEST,
        "codec_profile_id": artifact.codec_profile_id,
        "stripe_count": artifact.stripe_count,
        "availability_policy_id": hex(&policy.policy_id),
        "availability_certificate_id": hex(&certificate.certificate_id),
        "certificate_issued_height": certificate.issued_height,
        "certificate_valid_until": certificate.valid_until,
        "certificate_availability_state": certificate.availability_state,
        "certificate_assignment_root": hex(&certificate.assignment_root),
        "certificate_result_root": hex(&certificate.result_root),
        "custodian_set_id": hex(&custodian_set.set_id),
        "custodian_set_root": hex(&noos_lumen::domain_hash(
            "NOOS/WWM/CUSTODIAN-CAPABILITY-SET-ROOT/V1",
            &[&custodian_set.encode_canonical()],
        )),
        "custodian_set_epoch": custodian_set.epoch,
        "executor_set_id": hex(&executor_set.set_id),
        "executor_set_root": hex(&noos_lumen::domain_hash(
            "NOOS/WWM/CAPABILITY-SET-ROOT/V1",
            &[&executor_set.encode_canonical()],
        )),
        "executor_set_epoch": executor_set.epoch,
        "selected_verifiers": certificate.selected_verifiers.iter().map(|id| hex(id)).collect::<Vec<_>>(),
        "certificate_signer_ids": certificate.signer_ids.iter().map(|id| hex(id)).collect::<Vec<_>>(),
        "custodian_profiles": custodian_set.entries.iter().map(|profile| serde_json::json!({
            "profile_id": hex(&profile.profile_id),
            "endpoint_root": hex(&profile.endpoint_root),
            "status": profile.status as u8,
        })).collect::<Vec<_>>(),
        "availability_claim": "TESTNET_FIXTURE_ONLY",
        "runtime_root": hex(&capsule.runtime_root),
        "sbom_root": hex(&capsule.sbom_root),
        "fund_profile_id": hex(&fund.profile_id),
        "executor_profile_ids": executor_set.entries.iter().map(|profile| hex(&profile.profile_id)).collect::<Vec<_>>(),
        "build_root": hex(&capsule.build_root),
        "tokenizer_root": hex(&capsule.tokenizer_root),
        "template_root": hex(&capsule.template_root),
        "execution_profile_id": hex(&execution.profile_id),
        "query_policy_id": hex(&query.policy_id),
        "authorized_config_id": hex(&config.config_id),
        "service_endpoint": endpoint,
    });
    let body = serde_json::json!({
        "schema": "noos/finalized-model-resolution/v1",
        "registration_state": "ACTIVE_TESTNET",
        "production_effect": "NONE",
        "trust_scope": "LOCAL_FULL_NODE_FINALIZED_STATE",
        "proofs_verified": true,
        "weights_on_chain": false,
        "chain_id": hex(&response.chain_id),
        "genesis_hash": hex(&response.genesis_hash),
        "finalized_height": response.resolution_height,
        "finalized_hash": hex(&terminal.checkpoint.checkpoint_hash),
        "objects_root": hex(&terminal.header.objects_root),
        "selector": alias,
        "control_mode": "TESTNET",
        "proof_count": response.proofs.len(),
        "canonical_resolution_body_hex": hex(&response.encode_canonical()),
        "finality_evidence_hex": hex(&terminal.finality.encode_canonical()),
        "active": active,
        "disclosure": "Finalized descriptor/capsule/policy/control/proofs are on chain. The 3.8 GB GGUF remains in local artifact storage. Fixture operators and signatures are not production custody evidence."
    });
    match serde_json::to_string(&body) {
        Ok(body) => http("200 OK", "application/json", &body),
        Err(_) => json_error(
            "500 Internal Server Error",
            "serialization_failed",
            "model resolution serialization failed",
        ),
    }
}

fn wwm_record_route(consensus_tx: &SyncSender<ConsensusMsg>, raw: &str) -> String {
    let mut parts = raw.split('/');
    let (Some(kind_raw), Some(id_raw), None) = (parts.next(), parts.next(), parts.next()) else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "expected /wwm-record/<job|receipt|settlement>/<hex32>",
        );
    };
    let kind = match kind_raw {
        "job" => WwmLeafKind::Job,
        "receipt" => WwmLeafKind::Receipt,
        "settlement" => WwmLeafKind::Settlement,
        _ => {
            return json_error(
                "400 Bad Request",
                "malformed",
                "unknown WWM record kind",
            )
        }
    };
    let Some(id) = unhex32(id_raw) else {
        return json_error("400 Bad Request", "malformed", "bad WWM record id");
    };
    let Some(result) = round_trip(consensus_tx, |reply| ConsensusMsg::GetWwmRecord {
        kind,
        id,
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "consensus task did not answer",
        );
    };
    let Ok((height, finalized_hash, proof)) = result else {
        return json_error(
            "409 Conflict",
            "finalized_state_unavailable",
            "finalized WWM record lookup failed",
        );
    };
    if !proof.verify()
        || proof.state_key != noos_lumen::wwm::wwm_profile_key(kind, &id)
    {
        return json_error(
            "500 Internal Server Error",
            "invalid_local_proof",
            "local finalized WWM record proof failed verification",
        );
    }
    let ResolutionValueV1::Present(value) = &proof.value else {
        return json_error("404 Not Found", "not_found", "WWM record is not finalized");
    };
    let record = match kind {
        WwmLeafKind::Job => match WwmJobV1::decode_canonical(value.as_slice()) {
            Ok(job) if job.job_id == id => serde_json::json!({
                "job_id": hex(&job.job_id),
                "capsule_id": hex(&job.capsule_id),
                "execution_profile_id": hex(&job.execution_profile_id),
                "availability_certificate_id": hex(&job.availability_certificate_id),
                "fund_profile_id": hex(&job.fund_profile_id),
                "deadline_height": job.deadline_height,
            }),
            _ => return json_error("500 Internal Server Error", "invalid_local_record", "job decode failed"),
        },
        WwmLeafKind::Receipt => match WwmReceiptV1::decode_canonical(value.as_slice()) {
            Ok(receipt) if receipt.receipt_id == id => serde_json::json!({
                "receipt_id": hex(&receipt.receipt_id),
                "job_id": hex(&receipt.job_id),
                "capsule_id": hex(&receipt.capsule_id),
                "artifact_id": hex(&receipt.artifact_id),
                "execution_profile_id": hex(&receipt.execution_profile_id),
                "output_root": hex(&receipt.output_root),
                "token_history_root": hex(&receipt.token_history_root),
                "anchor_height": receipt.anchor_height,
                "anchor_block": hex(&receipt.anchor_block),
                "terminal_code": receipt.terminal_code as u8,
            }),
            _ => return json_error("500 Internal Server Error", "invalid_local_record", "receipt decode failed"),
        },
        WwmLeafKind::Settlement => {
            match WwmSettlementV1::decode_canonical(value.as_slice()) {
                Ok(settlement) if settlement.settlement_id == id => serde_json::json!({
                    "settlement_id": hex(&settlement.settlement_id),
                    "job_id": hex(&settlement.job_id),
                    "receipt_id": hex(&settlement.receipt_id),
                    "fund_profile_id": hex(&settlement.fund_profile_id),
                    "settled_height": settlement.settled_height,
                }),
                _ => return json_error("500 Internal Server Error", "invalid_local_record", "settlement decode failed"),
            }
        }
        _ => unreachable!("kind is closed above"),
    };
    let body = serde_json::json!({
        "schema": "noos/finalized-wwm-record/v1",
        "trust_scope": "LOCAL_FULL_NODE_FINALIZED_STATE",
        "kind": kind_raw,
        "id": id_raw,
        "finalized_height": height,
        "finalized_hash": hex(&finalized_hash),
        "objects_root": hex(&proof.objects_root),
        "canonical_record_hex": hex(value.as_slice()),
        "proof_hex": hex(&proof.encode_canonical()),
        "record": record,
    });
    match serde_json::to_string(&body) {
        Ok(body) => http("200 OK", "application/json", &body),
        Err(_) => json_error(
            "500 Internal Server Error",
            "serialization_failed",
            "WWM record serialization failed",
        ),
    }
}


fn submit_route(cfg: &RpcConfig, consensus_tx: &SyncSender<ConsensusMsg>, body: &[u8]) -> String {
    if cfg.observer {
        return feature_disabled(
            "node.tx_submission.observer",
            "observer mode: transaction submission is disabled on this node",
        );
    }
    let Ok((tx_bytes, wit_bytes)) = decode_envelope(body) else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "expected canonical hex {\"tx\",\"witnesses\"}",
        );
    };
    let result = round_trip(consensus_tx, |reply| ConsensusMsg::SubmitTx {
        tx_bytes,
        wit_bytes,
        source: 1, // localhost operator source class
        reply,
    });
    match result {
        Some(Ok(txid)) => http(
            "200 OK",
            "application/json",
            &format!(r#"{{"accepted":true,"txid":"{}"}}"#, hex(&txid)),
        ),
        Some(Err(e)) => json_error("409 Conflict", e.code(), "admission refused"),
        None => json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no reply",
        ),
    }
}

fn simulate_route(consensus_tx: &SyncSender<ConsensusMsg>, body: &[u8]) -> String {
    let Ok((tx_bytes, wit_bytes)) = decode_envelope(body) else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "expected canonical hex {\"tx\",\"witnesses\"}",
        );
    };
    let result = round_trip(consensus_tx, |reply| ConsensusMsg::SimulateTx {
        tx_bytes,
        wit_bytes,
        reply,
    });
    match result {
        Some(Ok(outcome)) => {
            let receipt = outcome.receipt();
            let applied = matches!(
                outcome,
                noos_lumen::state::SimulationOutcome::Applied { .. }
            );
            let body = format!(
                concat!(
                    r#"{{"accepted":{},"txid":"{}","status":{},"fee_charged":"{}","#,
                    r#""resources":{{"bytes":"{}","grain_steps":"{}","proof_units":"{}","#,
                    r#""state_reads":"{}","state_writes":"{}","blob_bytes":"{}"}}}}"#
                ),
                applied,
                hex(&receipt.txid),
                receipt.status,
                receipt.fee_charged,
                receipt.resources_used.bytes,
                receipt.resources_used.grain_steps,
                receipt.resources_used.proof_units,
                receipt.resources_used.state_reads,
                receipt.resources_used.state_writes,
                receipt.resources_used.blob_bytes,
            );
            http("200 OK", "application/json", &body)
        }
        Some(Err(reason)) => json_error(
            "409 Conflict",
            "simulation_rejected",
            &format!("pre-reservation rejection {}", reason as u16),
        ),
        None => json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no reply",
        ),
    }
}

fn decode_envelope(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let text = std::str::from_utf8(body).map_err(|_| ())?;
    let tx_hex = json_str_field(text, "tx").ok_or(())?;
    let witness_hex = json_str_field(text, "witnesses").ok_or(())?;
    if tx_hex
        .len()
        .checked_add(witness_hex.len())
        .is_none_or(|hex_len| hex_len > MAX_TX_WITNESS_BYTES.saturating_mul(2))
    {
        return Err(());
    }
    let tx_bytes = unhex(&tx_hex).ok_or(())?;
    let witness_bytes = unhex(&witness_hex).ok_or(())?;
    if !carrier_len_valid(tx_bytes.len(), witness_bytes.len()) {
        return Err(());
    }
    Ok((tx_bytes, witness_bytes))
}

fn block_route(consensus_tx: &SyncSender<ConsensusMsg>, id_raw: &str) -> String {
    let id = if id_raw.len() == 64 {
        match unhex32(id_raw) {
            Some(hash) => BlockId::Hash(hash),
            None => return json_error("400 Bad Request", "malformed", "bad block hash"),
        }
    } else {
        match id_raw.parse::<u64>() {
            Ok(h) => BlockId::Height(h),
            Err(_) => return json_error("400 Bad Request", "malformed", "bad block id"),
        }
    };
    let Some(lookup) = round_trip(consensus_tx, |reply| ConsensusMsg::GetBlock { id, reply })
    else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no reply",
        );
    };
    match lookup {
        ViewLookup::Found(b) => {
            let txids: Vec<String> = b.txids.iter().map(|t| format!("\"{}\"", hex(t))).collect();
            let body = format!(
                r#"{{"hash":"{}","height":{},"slot":{},"timestamp_ms":{},"parent_hash":"{}","txids":[{}]}}"#,
                hex(&b.hash),
                b.height,
                b.slot,
                b.timestamp_ms,
                hex(&b.parent_hash),
                txids.join(",")
            );
            http("200 OK", "application/json", &body)
        }
        ViewLookup::Pruned => json_error("410 Gone", "pruned", "outside the retention window"),
        ViewLookup::NotFound => json_error("404 Not Found", "not_found", "unknown block"),
    }
}

fn blocks_route(consensus_tx: &SyncSender<ConsensusMsg>, range_raw: &str) -> String {
    let mut parts = range_raw.split('/');
    let (Some(start_raw), Some(limit_raw), None) = (parts.next(), parts.next(), parts.next())
    else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "expected /blocks/<start-height>/<limit>",
        );
    };
    let (Ok(start), Ok(limit)) = (start_raw.parse::<u64>(), limit_raw.parse::<usize>()) else {
        return json_error("400 Bad Request", "malformed", "bad block range");
    };
    if !(1..=64).contains(&limit) {
        return json_error(
            "400 Bad Request",
            "malformed",
            "block range limit must be 1..64",
        );
    }
    let mut items = Vec::with_capacity(limit);
    for offset in 0..limit {
        let Ok(offset) = u64::try_from(offset) else {
            return json_error("400 Bad Request", "malformed", "block range overflow");
        };
        let Some(height) = start.checked_add(offset) else {
            return json_error("400 Bad Request", "malformed", "block range overflow");
        };
        let Some(lookup) = round_trip(consensus_tx, |reply| ConsensusMsg::GetBlock {
            id: BlockId::Height(height),
            reply,
        }) else {
            return json_error(
                "503 Service Unavailable",
                "consensus_unavailable",
                "no reply",
            );
        };
        match lookup {
            ViewLookup::Found(block) => {
                let txids: Vec<String> = block
                    .txids
                    .iter()
                    .map(|txid| format!("\"{}\"", hex(txid)))
                    .collect();
                items.push(format!(
                    r#"{{"hash":"{}","height":{},"slot":{},"timestamp_ms":{},"parent_hash":"{}","txids":[{}]}}"#,
                    hex(&block.hash),
                    block.height,
                    block.slot,
                    block.timestamp_ms,
                    hex(&block.parent_hash),
                    txids.join(",")
                ));
            }
            ViewLookup::NotFound => break,
            ViewLookup::Pruned => {
                return json_error("410 Gone", "pruned", "outside the retention window");
            }
        }
    }
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{}]}}"#, items.join(",")),
    )
}

fn receipt_route(consensus_tx: &SyncSender<ConsensusMsg>, txid_raw: &str) -> String {
    let Some(txid) = unhex32(txid_raw) else {
        return json_error("400 Bad Request", "malformed", "bad txid");
    };
    let Some(lookup) = round_trip(consensus_tx, |reply| ConsensusMsg::GetReceipt {
        txid,
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no reply",
        );
    };
    match lookup {
        ViewLookup::Found((status, receipt)) => {
            let status_json = match status {
                TxStatus::Pending => r#""MEMPOOL""#.to_string(),
                TxStatus::Settled { height, status } => {
                    format!(r#"{{"settled_height":{height},"status_code":{status}}}"#)
                }
            };
            let receipt_json = match receipt {
                Some(r) => format!(
                    r#"{{"txid":"{}","status":{},"fee_charged":"{}"}}"#,
                    hex(&r.txid),
                    r.status,
                    r.fee_charged
                ),
                None => "null".to_string(),
            };
            http(
                "200 OK",
                "application/json",
                &format!(r#"{{"state":{status_json},"receipt":{receipt_json}}}"#),
            )
        }
        ViewLookup::Pruned => json_error("410 Gone", "pruned", "outside the retention window"),
        ViewLookup::NotFound => json_error("404 Not Found", "not_found", "unknown transaction"),
    }
}

fn json_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            value if value.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", u32::from(value));
            }
            value => escaped.push(value),
        }
    }
    escaped
}

fn assets_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(assets) = round_trip(consensus_tx, |reply| ConsensusMsg::GetAssets { reply }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no asset registry reply",
        );
    };
    let entries = assets
        .iter()
        .map(|asset| {
            let symbol = std::str::from_utf8(asset.symbol.as_slice()).unwrap_or_default();
            let name = std::str::from_utf8(asset.name.as_slice()).unwrap_or_default();
            format!(
                r#"{{"asset_id":"{}","issuer":"{}","symbol":"{}","name":"{}","decimals":{},"total_supply":"{}"}}"#,
                hex(&asset.asset_id),
                hex(&asset.issuer),
                json_escape(symbol),
                json_escape(name),
                asset.decimals,
                asset.total_supply,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn pools_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(pools) = round_trip(consensus_tx, |reply| ConsensusMsg::GetPools { reply }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no pool registry reply",
        );
    };
    let entries = pools
        .iter()
        .map(|pool| {
            format!(
                r#"{{"pool_id":"{}","asset_0":"{}","asset_1":"{}","reserve_0":"{}","reserve_1":"{}","fee_bps":{},"creator":"{}","total_shares":"{}"}}"#,
                hex(&pool.pool_id),
                hex(&pool.asset_0),
                hex(&pool.asset_1),
                pool.reserve_0,
                pool.reserve_1,
                pool.fee_bps,
                hex(&pool.creator),
                pool.total_shares,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn liquidity_positions_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetLiquidityPositions {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no liquidity position reply",
        );
    };
    let entries = items
        .iter()
        .map(|position| {
            format!(
                r#"{{"position_id":"{}","pool_id":"{}","provider":"{}","shares":"{}"}}"#,
                hex(&position.position_id),
                hex(&position.pool_id),
                hex(&position.provider),
                position.shares
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn oracle_feeds_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetOracleFeeds { reply })
    else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no oracle feed reply",
        );
    };
    let entries = items
        .iter()
        .map(|feed| format!(
            r#"{{"feed_id":"{}","base_asset":"{}","quote_asset":"{}","reporters":["{}","{}","{}"],"max_age_blocks":"{}"}}"#,
            hex(&feed.feed_id), hex(&feed.base_asset), hex(&feed.quote_asset),
            hex(&feed.reporter_0), hex(&feed.reporter_1), hex(&feed.reporter_2), feed.max_age_blocks
        ))
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn oracle_reports_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetOracleReports {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no oracle report reply",
        );
    };
    let entries = items
        .iter()
        .map(|report| format!(
            r#"{{"report_id":"{}","feed_id":"{}","reporter":"{}","price_q9":"{}","confidence_bps":{},"sequence":"{}","observed_height":"{}"}}"#,
            hex(&report.report_id), hex(&report.feed_id), hex(&report.reporter), report.price_q9,
            report.confidence_bps, report.sequence, report.observed_height
        ))
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn lending_markets_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetLendingMarkets {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no lending market reply",
        );
    };
    let entries = items
        .iter()
        .map(|market| format!(
            r#"{{"market_id":"{}","collateral_asset":"{}","stable_asset":"{}","oracle_feed_id":"{}","collateral_factor_bps":{},"liquidation_threshold_bps":{},"liquidation_bonus_bps":{},"debt_ceiling":"{}","min_debt":"{}","total_debt":"{}"}}"#,
            hex(&market.market_id), hex(&market.collateral_asset), hex(&market.stable_asset),
            hex(&market.oracle_feed_id), market.collateral_factor_bps, market.liquidation_threshold_bps,
            market.liquidation_bonus_bps, market.debt_ceiling, market.min_debt, market.total_debt
        ))
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn stable_assets_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetStableAssets {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no stable asset reply",
        );
    };
    let entries = items
        .iter()
        .filter(|asset| asset.kind == 1)
        .map(|asset| {
            let symbol = std::str::from_utf8(asset.symbol.as_slice()).unwrap_or_default();
            let name = std::str::from_utf8(asset.name.as_slice()).unwrap_or_default();
            format!(
                r#"{{"asset_id":"{}","market_id":"{}","symbol":"{}","name":"{}","decimals":{},"minted_supply":"{}"}}"#,
                hex(&asset.asset_id), hex(&asset.market_id), json_escape(symbol), json_escape(name),
                asset.decimals, asset.minted_supply
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn stable_safety_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetStableSafety {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no stable safety reply",
        );
    };
    let entries = items
        .iter()
        .map(|safety| {
            format!(
                r#"{{"safety_id":"{}","market_id":"{}","stable_reserve":"{}","collateral_reserve":"{}","psm_debt":"{}","uncovered_bad_debt":"{}","psm_fee_bps":{}}}"#,
                hex(&safety.safety_id),
                hex(&safety.market_id),
                safety.stable_reserve,
                safety.collateral_reserve,
                safety.psm_debt,
                safety.uncovered_bad_debt,
                safety.psm_fee_bps,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn debt_positions_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetDebtPositions {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no debt position reply",
        );
    };
    let entries = items
        .iter()
        .map(|position| format!(
            r#"{{"position_id":"{}","market_id":"{}","owner":"{}","collateral":"{}","debt":"{}"}}"#,
            hex(&position.position_id), hex(&position.market_id), hex(&position.owner),
            position.collateral, position.debt
        ))
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn private_payments_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(items) = round_trip(consensus_tx, |reply| ConsensusMsg::GetPrivatePayments {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no private payment reply",
        );
    };
    let entries = items
        .iter()
        .map(|payment| {
            let settled_account = payment
                .settled_account
                .0
                .map(|account| format!(r#""{}""#, hex(&account)))
                .unwrap_or_else(|| "null".to_owned());
            format!(
                r#"{{"payment_id":"{}","payer":"{}","stable_asset":"{}","recipient_commitment":"{}","memo_commitment":"{}","reference_commitment":"{}","amount":"{}","expiry_height":"{}","payment_kind":{},"status":{},"settled_account":{},"settled_height":"{}"}}"#,
                hex(&payment.payment_id),
                hex(&payment.payer),
                hex(&payment.stable_asset),
                hex(&payment.recipient_commitment),
                hex(&payment.memo_commitment),
                hex(&payment.reference_commitment),
                payment.amount,
                payment.expiry_height,
                payment.payment_kind,
                payment.status,
                settled_account,
                payment.settled_height,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn compute_workers_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(workers) = round_trip(consensus_tx, |reply| ConsensusMsg::GetComputeWorkers {
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no compute worker registry reply",
        );
    };
    let entries = workers
        .iter()
        .map(|worker| {
            format!(
                r#"{{"worker":"{}","capabilities":{},"cpu_threads":{},"memory_mb":{},"gpu_memory_mb":{},"price_per_unit":"{}","endpoint_commitment":"{}","active":{},"jobs_completed":"{}","units_completed":"{}"}}"#,
                hex(&worker.worker),
                worker.capabilities,
                worker.cpu_threads,
                worker.memory_mb,
                worker.gpu_memory_mb,
                worker.price_per_unit,
                hex(&worker.endpoint_commitment),
                worker.active,
                worker.jobs_completed,
                worker.units_completed,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn compute_jobs_route(consensus_tx: &SyncSender<ConsensusMsg>) -> String {
    let Some(jobs) = round_trip(consensus_tx, |reply| ConsensusMsg::GetComputeJobs { reply })
    else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no compute job registry reply",
        );
    };
    let entries = jobs
        .iter()
        .map(|job| {
            let worker = job
                .worker
                .0
                .as_ref()
                .map(|value| format!(r#""{}""#, hex(value)))
                .unwrap_or_else(|| "null".into());
            format!(
                r#"{{"job_id":"{}","requester":"{}","worker":{},"workload_kind":{},"input_root":"{}","units":"{}","unit_size":{},"max_price_per_unit":"{}","agreed_price_per_unit":"{}","escrow":"{}","deadline_height":"{}","state":{},"result_root":"{}","completed_units":"{}"}}"#,
                hex(&job.job_id),
                hex(&job.requester),
                worker,
                job.workload_kind,
                hex(&job.input_root),
                job.units,
                job.unit_size,
                job.max_price_per_unit,
                job.agreed_price_per_unit,
                job.escrow,
                job.deadline_height,
                job.state,
                hex(&job.result_root),
                job.completed_units,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    http(
        "200 OK",
        "application/json",
        &format!(r#"{{"items":[{entries}]}}"#),
    )
}

fn account_route(consensus_tx: &SyncSender<ConsensusMsg>, raw: &str) -> String {
    let Some(account) = unhex32(raw) else {
        return json_error("400 Bad Request", "malformed", "bad account id");
    };
    let Some(value) = round_trip(consensus_tx, |reply| ConsensusMsg::GetAccount {
        account,
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no account reply",
        );
    };
    let Some(account) = value else {
        return json_error("404 Not Found", "not_found", "account not found");
    };
    http(
        "200 OK",
        "application/json",
        &format!(
            r#"{{"account_id":"{}","nonce":"{}","auth_descriptor":"{}","liquid_balances_root":"{}","bond_refs_root":"{}","metadata_commitment":"{}","recovery_policy_root":"{}"}}"#,
            hex(&account.account_id),
            account.nonce,
            hex(account.auth_descriptor.as_slice()),
            hex(&account.liquid_balances_root),
            hex(&account.bond_refs_root),
            hex(&account.metadata_commitment),
            hex(&account.recovery_policy_root),
        ),
    )
}

fn balance_route(consensus_tx: &SyncSender<ConsensusMsg>, raw: &str) -> String {
    let mut parts = raw.split('/');
    let (Some(account_raw), Some(asset_raw), None) = (parts.next(), parts.next(), parts.next())
    else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "expected /balance/<account>/<asset>",
        );
    };
    let (Some(account), Some(asset)) = (unhex32(account_raw), unhex32(asset_raw)) else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "account and asset must be 32-byte hex",
        );
    };
    let Some(balance) = round_trip(consensus_tx, |reply| ConsensusMsg::GetBalance {
        account,
        asset,
        reply,
    }) else {
        return json_error(
            "503 Service Unavailable",
            "consensus_unavailable",
            "no balance reply",
        );
    };
    http(
        "200 OK",
        "application/json",
        &format!(
            r#"{{"account":"{}","asset":"{}","balance":"{}"}}"#,
            hex(&account),
            hex(&asset),
            balance
        ),
    )
}

// ---------------------------------------------------------------------------
// Hex + minimal JSON field extraction
// ---------------------------------------------------------------------------

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
    }
    s
}

#[must_use]
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[must_use]
pub fn unhex32(s: &str) -> Option<Hash32> {
    let v = unhex(s)?;
    v.as_slice().try_into().ok()
}

/// Extracts a top-level string field from a tiny flat JSON object
/// (`{"k":"v",...}`). Strict enough for the operator surface; anything
/// fancier belongs to the later public API phase.
fn json_str_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?.saturating_add(needle.len());
    let rest = text.get(start..)?;
    let colon = rest.find(':')?;
    let rest = rest.get(colon.saturating_add(1)..)?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
