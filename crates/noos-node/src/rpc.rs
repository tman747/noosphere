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
//! GET  /block/<height|hash-hex>
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
        _ if method == "GET" && path.starts_with("/block/") => {
            block_route(consensus_tx, &path["/block/".len()..])
        }
        _ if method == "GET" && path.starts_with("/receipt/") => {
            receipt_route(consensus_tx, &path["/receipt/".len()..])
        }
        ("GET", "/assets") => assets_route(consensus_tx),
        ("GET", "/pools") => pools_route(consensus_tx),
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
        s.mempool_txs,
        s.mempool_bytes,
        s.observer,
    );
    http("200 OK", "application/json", &body)
}

fn submit_route(cfg: &RpcConfig, consensus_tx: &SyncSender<ConsensusMsg>, body: &[u8]) -> String {
    if cfg.observer {
        return feature_disabled(
            "node.tx_submission.observer",
            "observer mode: transaction submission is disabled on this node",
        );
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return json_error("400 Bad Request", "malformed", "body is not utf-8");
    };
    let (Some(tx_hex), Some(wit_hex)) = (
        json_str_field(text, "tx"),
        json_str_field(text, "witnesses"),
    ) else {
        return json_error(
            "400 Bad Request",
            "malformed",
            "expected {\"tx\",\"witnesses\"}",
        );
    };
    let (Some(tx_bytes), Some(wit_bytes)) = (unhex(&tx_hex), unhex(&wit_hex)) else {
        return json_error("400 Bad Request", "malformed", "bad hex payload");
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
                r#"{{"pool_id":"{}","asset_0":"{}","asset_1":"{}","reserve_0":"{}","reserve_1":"{}","fee_bps":{},"creator":"{}"}}"#,
                hex(&pool.pool_id),
                hex(&pool.asset_0),
                hex(&pool.asset_1),
                pool.reserve_0,
                pool.reserve_1,
                pool.fee_bps,
                hex(&pool.creator),
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
