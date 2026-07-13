//! Deterministic golden and falsifier tests for the noos-cli workflows:
//! keygen against the frozen wallet derivation vectors, tx build/sign
//! against the frozen lumen tx vectors, and live line-protocol / indexer
//! round trips against in-test servers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_cli::{from_hex, to_hex, CliError};
use noos_codec::{NoosDecode, NoosEncode};
use noos_lumen::objects::{
    asset_id, lending_market_id, object_id, oracle_feed_id, pool_id, stable_asset_id, ActionV1,
    BoundedBytes, TransactionV1,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;

fn repo_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn vectors(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(repo_path(rel)).unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// keygen — ODR-WALLET-001 derivation vectors
// ---------------------------------------------------------------------------

#[test]
fn keygen_matches_every_frozen_derivation_vector() {
    let doc = vectors("protocol/vectors/wallet/derivation-v1.json");
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 30);
    for case in cases {
        assert_eq!(case["kind"], "positive");
        let purpose = match case["purpose"].as_str().unwrap() {
            "umbra" => format!("umbra:{}", case["suite"].as_u64().unwrap()),
            p => p.to_string(),
        };
        let out = noos_cli::keygen(
            case["seed"].as_str().unwrap(),
            &purpose,
            u32::try_from(case["account"].as_u64().unwrap()).unwrap(),
            u32::try_from(case["index"].as_u64().unwrap()).unwrap(),
        )
        .unwrap();
        // Path must equal the frozen vector path exactly.
        let path: Vec<&str> = out["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let expected_path: Vec<&str> = case["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(path, expected_path, "{}", case["name"]);
        // public_id == blake3(derived_secret): a full-strength check of the
        // derivation chain that never exposes the secret itself.
        let secret: [u8; 32] = hex::decode(case["derived_secret"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            out["public_id"].as_str().unwrap(),
            blake3::hash(&secret).to_hex().as_str(),
            "{}",
            case["name"]
        );
        // Spending purpose additionally exposes the ed25519 verifying key.
        if case["purpose"] == "sign" {
            let expected_vk = ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key();
            assert_eq!(
                out["verifying_key"].as_str().unwrap(),
                to_hex(&expected_vk.to_bytes()),
                "{}",
                case["name"]
            );
        } else {
            assert!(out.get("verifying_key").is_none());
        }
    }
}

#[test]
fn keygen_rejects_forged_inputs() {
    let seed = "00".repeat(64);
    // Hardened-overflow account: the derivation law forbids it.
    assert!(matches!(
        noos_cli::keygen(&seed, "sign", 1 << 31, 0),
        Err(CliError::Wallet(_))
    ));
    // Unknown purpose string.
    assert!(matches!(
        noos_cli::keygen(&seed, "spend", 0, 0),
        Err(CliError::Usage(_))
    ));
    // Non-hex seed.
    assert!(matches!(
        noos_cli::keygen("zz", "sign", 0, 0),
        Err(CliError::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// tx build — lumen-tx-v1 golden bytes
// ---------------------------------------------------------------------------

fn h(fill: u8) -> String {
    to_hex(&[fill; 32])
}

/// The spec that must reproduce `minimal_tx([0x11;32])` byte-for-byte.
fn minimal_spec() -> Value {
    json!({
        "chain_id": h(0x11),
        "expiry_height": 10,
        "fee_payer": h(0x0f),
    })
}

/// The spec that must reproduce `sample_tx([0x11;32], expiry)`.
fn full_spec(expiry: Value, with_sponsor: bool) -> Value {
    let mut spec = json!({
        "chain_id": h(0x11),
        "expiry_height": expiry,
        "fee_payer": h(0x0f),
        "resource_limits": {
            "bytes": 65536, "grain_steps": 10000, "proof_units": 4,
            "state_reads": 32, "state_writes": 32, "blob_bytes": 0
        },
        "note_inputs": [h(0x44)],
        "account_inputs": [h(0x0f)],
        "object_access_list": [{"object_id": h(0x55), "mode": "read_write"}],
        "outputs": [{
            "asset_id": h(0x00), "amount": "100", "lock_root": h(0x66),
            "datum_root": h(0x67), "birth_height": 7, "relative_timelock": 0,
            "memo_commitment": h(0x68)
        }],
        "evidence_refs": [h(0x77)],
        "lock_reveals": ["010203"],
    });
    if with_sponsor {
        spec["fee_authorization"] = json!({
            "amount": "5000",
            "resource_ceiling": {
                "bytes": 4096, "grain_steps": 0, "proof_units": 0,
                "state_reads": 8, "state_writes": 8, "blob_bytes": 0
            },
            "expiry_height": 100,
            "tx_commitment": h(0x22),
            "sponsor": h(0x33),
            "signature_suite": 1,
            "signature": "cd".repeat(64),
        });
    }
    spec
}

fn vector_case(doc: &Value, name: &str) -> Value {
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("missing vector case {name}"))
        .clone()
}

#[test]
fn tx_build_reproduces_frozen_lumen_vectors_byte_for_byte() {
    let doc = vectors("protocol/vectors/lumen/lumen-tx-v1.json");
    for (name, spec) in [
        ("tx_minimal_roundtrip", minimal_spec()),
        ("tx_full_roundtrip", full_spec(json!(100), true)),
        (
            "tx_no_sponsor_max_expiry",
            full_spec(json!(u64::MAX.to_string()), false),
        ),
    ] {
        let expected = vector_case(&doc, name);
        let out = noos_cli::tx_build(&spec.to_string()).unwrap();
        assert_eq!(
            out["tx"].as_str().unwrap(),
            expected["bytes"].as_str().unwrap(),
            "{name}: canonical bytes must match the frozen vector"
        );
    }
}

#[test]
fn tx_build_encodes_structured_contract_actions_canonically() {
    let mut spec = minimal_spec();
    spec["actions"] = json!([
        {
            "type": "create_object",
            "class_id": 7,
            "owner_or_policy_root": h(0x21),
            "code_hash": h(0x22),
            "state_root": h(0x23),
            "storage_words": "4096",
            "rent_deposit": "9000",
            "flags": 3
        },
        {
            "type": "call_object",
            "object_id": h(0x31),
            "input": "deadbeef"
        }
    ]);
    let built = noos_cli::tx_build(&spec.to_string()).unwrap();
    let tx =
        TransactionV1::decode_canonical(&from_hex(built["tx"].as_str().unwrap()).unwrap()).unwrap();
    let txid: [u8; 32] = from_hex(built["txid"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        built["created_objects"][0]["object_id"],
        to_hex(&object_id(&txid, 0, 7))
    );
    assert_eq!(
        tx.actions.as_slice()[0].as_slice(),
        ActionV1::CreateObject {
            class_id: 7,
            owner_or_policy_root: [0x21; 32],
            code_hash: [0x22; 32],
            state_root: [0x23; 32],
            storage_words: 4096,
            rent_deposit: 9000,
            flags: 3,
        }
        .encode_canonical()
        .as_slice()
    );
    assert_eq!(
        ActionV1::decode_canonical(tx.actions.as_slice()[1].as_slice()).unwrap(),
        ActionV1::CallObject {
            object_id: [0x31; 32],
            input: BoundedBytes::new(vec![0xde, 0xad, 0xbe, 0xef]).unwrap(),
        }
    );
}

#[test]
fn tx_build_encodes_launch_and_swap_actions() {
    let issuer = h(0x41);
    let paired_asset = h(0x42);
    let mut spec = minimal_spec();
    spec["actions"] = json!([{
        "type": "create_asset",
        "issuer": issuer,
        "symbol": "MIND",
        "name": "Mind Launch",
        "decimals": 6,
        "total_supply": "1000000000"
    }]);
    let built = noos_cli::tx_build(&spec.to_string()).unwrap();
    let txid: [u8; 32] = from_hex(built["txid"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let launched = asset_id(&txid, 0);
    assert_eq!(built["created_assets"][0]["asset_id"], to_hex(&launched));
    assert_eq!(built["created_assets"][0]["symbol"], "MIND");

    spec["actions"] = json!([{
        "type": "create_pool",
        "provider": issuer,
        "asset_a": to_hex(&launched),
        "asset_b": paired_asset,
        "amount_a": "100000000",
        "amount_b": "10000000",
        "fee_bps": 30
    }, {
        "type": "swap_exact_in",
        "trader": issuer,
        "pool_id": to_hex(&pool_id(&launched, &[0x42; 32])),
        "asset_in": paired_asset,
        "amount_in": "1000",
        "min_amount_out": "1"
    }]);
    let built = noos_cli::tx_build(&spec.to_string()).unwrap();
    assert_eq!(
        built["created_pools"][0]["pool_id"],
        to_hex(&pool_id(&launched, &[0x42; 32]))
    );
    let tx =
        TransactionV1::decode_canonical(&from_hex(built["tx"].as_str().unwrap()).unwrap()).unwrap();
    assert!(matches!(
        ActionV1::decode_canonical(tx.actions.as_slice()[0].as_slice()).unwrap(),
        ActionV1::CreatePool { fee_bps: 30, .. }
    ));
    assert!(matches!(
        ActionV1::decode_canonical(tx.actions.as_slice()[1].as_slice()).unwrap(),
        ActionV1::SwapExactIn {
            amount_in: 1000,
            min_amount_out: 1,
            ..
        }
    ));
}

#[test]
fn tx_build_encodes_oracle_and_lending_market_actions() {
    let collateral = [0x51; 32];
    let quote = [0x52; 32];
    let feed = oracle_feed_id(&collateral, &quote);
    let market = lending_market_id(&collateral, &feed);
    let mut spec = minimal_spec();
    spec["actions"] = json!([
        {
            "type": "create_oracle_feed",
            "base_asset": to_hex(&collateral),
            "quote_asset": to_hex(&quote),
            "reporter_0": h(0x61),
            "reporter_1": h(0x62),
            "reporter_2": h(0x63),
            "max_age_blocks": "64"
        },
        {
            "type": "create_lending_market",
            "collateral_asset": to_hex(&collateral),
            "oracle_feed_id": to_hex(&feed),
            "symbol": "MUSD",
            "name": "Mind USD",
            "decimals": 9,
            "collateral_factor_bps": 5000,
            "liquidation_threshold_bps": 7500,
            "liquidation_bonus_bps": 500,
            "debt_ceiling": "1000000000",
            "min_debt": "1000"
        }
    ]);
    let built = noos_cli::tx_build(&spec.to_string()).unwrap();
    assert_eq!(built["created_oracle_feeds"][0]["feed_id"], to_hex(&feed));
    assert_eq!(
        built["created_lending_markets"][0]["market_id"],
        to_hex(&market)
    );
    assert_eq!(
        built["created_lending_markets"][0]["stable_asset"],
        to_hex(&stable_asset_id(&market))
    );
    let tx =
        TransactionV1::decode_canonical(&from_hex(built["tx"].as_str().unwrap()).unwrap()).unwrap();
    assert!(matches!(
        ActionV1::decode_canonical(tx.actions.as_slice()[0].as_slice()).unwrap(),
        ActionV1::CreateOracleFeed {
            max_age_blocks: 64,
            ..
        }
    ));
    assert!(matches!(
        ActionV1::decode_canonical(tx.actions.as_slice()[1].as_slice()).unwrap(),
        ActionV1::CreateLendingMarket {
            collateral_factor_bps: 5000,
            liquidation_threshold_bps: 7500,
            ..
        }
    ));
}

#[test]
fn tx_build_rejects_malformed_structured_actions() {
    let mut unknown = minimal_spec();
    unknown["actions"] = json!([{"type": "deploy_magic"}]);
    assert!(matches!(
        noos_cli::tx_build(&unknown.to_string()),
        Err(CliError::Malformed(_))
    ));

    let mut overflow = minimal_spec();
    overflow["actions"] = json!([{
        "type": "create_object",
        "class_id": u64::from(u32::MAX) + 1,
        "owner_or_policy_root": h(0x21),
        "code_hash": h(0x22),
        "state_root": h(0x23),
        "storage_words": 1,
        "rent_deposit": "1",
        "flags": 0
    }]);
    assert!(matches!(
        noos_cli::tx_build(&overflow.to_string()),
        Err(CliError::Malformed(_))
    ));
}

#[test]
fn tx_build_rejects_forged_specs() {
    // A witness_root cannot be smuggled in: it is computed from reveals.
    let out = noos_cli::tx_build(&minimal_spec().to_string()).unwrap();
    let mut forged = minimal_spec();
    forged["lock_reveals"] = json!(["ff"]);
    let forged_out = noos_cli::tx_build(&forged.to_string()).unwrap();
    assert_ne!(out["witness_root"], forged_out["witness_root"]);
    assert_ne!(out["txid"], forged_out["txid"], "txid covers witness_root");

    // Oversized collections reject.
    let mut over = minimal_spec();
    over["note_inputs"] = json!(vec![h(0x01); 257]);
    assert!(matches!(
        noos_cli::tx_build(&over.to_string()),
        Err(CliError::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// tx sign — decode law + deterministic signature
// ---------------------------------------------------------------------------

const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

#[test]
fn tx_sign_rejects_every_negative_lumen_vector() {
    let doc = vectors("protocol/vectors/lumen/lumen-tx-v1.json");
    let mut negatives = 0;
    for case in doc["cases"].as_array().unwrap() {
        if case["kind"] != "negative" || case["name"] == "access_entry_mode_invalid" {
            continue; // the access-entry case is not a whole-tx encoding
        }
        negatives += 1;
        let result = noos_cli::tx_sign(
            case["bytes"].as_str().unwrap(),
            SEED,
            0,
            0,
            &h(0x11),
            &h(0x22),
            0,
            &[],
        );
        match result {
            Err(CliError::Codec(class)) => assert_eq!(
                class,
                case["error_class"].as_str().unwrap(),
                "{}",
                case["name"]
            ),
            other => panic!("{}: expected codec rejection, got {other:?}", case["name"]),
        }
    }
    assert!(negatives >= 9, "vector file lost its negative cases?");
}

#[test]
fn tx_sign_produces_the_frozen_deterministic_signature() {
    let built = noos_cli::tx_build(&minimal_spec().to_string()).unwrap();
    let tx_hex = built["tx"].as_str().unwrap();
    let out = noos_cli::tx_sign(tx_hex, SEED, 0, 0, &h(0x11), &h(0x22), 0, &[]).unwrap();

    // Independent reconstruction: the signature must ed25519-verify over
    // the consensus D-SIG-TX prefix || txid under the verifying key derived
    // from the FROZEN vector secret
    // (sign-a0-i0 uses this exact seed/account/index).
    let doc = vectors("protocol/vectors/wallet/derivation-v1.json");
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "sign-a0-i0")
        .unwrap();
    let secret: [u8; 32] = hex::decode(case["derived_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
    assert_eq!(
        out["verifying_key"].as_str().unwrap(),
        to_hex(&signing.verifying_key().to_bytes())
    );
    let mut message = Vec::new();
    message.extend_from_slice(noos_wallet::LUMEN_TX_SIGNING_DOMAIN);
    message.extend_from_slice(&from_hex(out["txid"].as_str().unwrap()).unwrap());
    let signature = ed25519_dalek::Signature::from_bytes(
        &from_hex(out["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    use ed25519_dalek::Verifier;
    signing
        .verifying_key()
        .verify(&message, &signature)
        .expect("cli signature must verify over the wallet signing law");

    // Falsifier: signing a DIFFERENT canonical tx yields a different
    // signature, and the old signature fails for the new txid.
    let mut other_spec = minimal_spec();
    other_spec["expiry_height"] = json!(11);
    let other_built = noos_cli::tx_build(&other_spec.to_string()).unwrap();
    let other = noos_cli::tx_sign(
        other_built["tx"].as_str().unwrap(),
        SEED,
        0,
        0,
        &h(0x11),
        &h(0x22),
        0,
        &[],
    )
    .unwrap();
    assert_ne!(out["signature"], other["signature"]);

    // Falsifier: mismatched lock reveals fail closed before signing.
    let forged = noos_cli::tx_sign(tx_hex, SEED, 0, 0, &h(0x11), &h(0x22), 0, &["ff".into()]);
    assert!(matches!(forged, Err(CliError::Malformed(_))));

    // The witness container decodes canonically and commits the txid.
    use noos_codec::NoosDecode;
    let witnesses = noos_lumen::objects::TransactionWitnessesV1::decode_canonical(
        &from_hex(out["witnesses"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        to_hex(&witnesses.intents.as_slice()[0].tx_commitment),
        out["txid"].as_str().unwrap()
    );
}

// ---------------------------------------------------------------------------
// submit/status — node line protocol against an in-test server
// ---------------------------------------------------------------------------

struct NodeServer {
    addr: String,
    handle: Option<std::thread::JoinHandle<Vec<String>>>,
}

impl NodeServer {
    /// Serves the node line protocol: bearer-checked /status and
    /// /submit_tx; records every request line it saw.
    fn spawn(token: &'static str, chain_id: String, genesis_hash: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 65536];
                let mut req = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            req.extend_from_slice(&buf[..n]);
                            let text = String::from_utf8_lossy(&req);
                            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                                let want: usize = head
                                    .lines()
                                    .find_map(|l| {
                                        l.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|v| v.trim().parse().unwrap_or(0))
                                    })
                                    .unwrap_or(0);
                                if body.len() >= want {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let text = String::from_utf8_lossy(&req).to_string();
                let request_line = text.lines().next().unwrap_or_default().to_string();
                if request_line.starts_with("GET /stop") {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                    return seen;
                }
                seen.push(text.clone());
                let authorized = text.lines().any(|l| {
                    l.to_ascii_lowercase().starts_with("authorization:")
                        && l.trim_end().ends_with(&format!("Bearer {token}"))
                });
                let (status, body) = if !authorized {
                    (
                        "401 Unauthorized",
                        r#"{"error":{"code":"unauthorized","detail":"missing or bad bearer token"}}"#.to_string(),
                    )
                } else if request_line.starts_with("GET /status") {
                    (
                        "200 OK",
                        format!(
                            concat!(
                                r#"{{"chain_id":"{}","genesis_hash":"{}","#,
                                r#""unsafe_head":{{"height":3,"hash":"{}"}},"#,
                                r#""justified":{{"epoch":0,"hash":"{}"}},"#,
                                r#""finalized":{{"epoch":0,"hash":"{}"}},"#,
                                r#""mempool":{{"txs":0,"bytes":0}},"observer":false}}"#
                            ),
                            chain_id, genesis_hash, genesis_hash, genesis_hash, genesis_hash
                        ),
                    )
                } else if request_line.starts_with("POST /submit_tx") {
                    (
                        "200 OK",
                        format!(r#"{{"accepted":true,"txid":"{}"}}"#, "9".repeat(64)),
                    )
                } else {
                    (
                        "404 Not Found",
                        r#"{"error":{"code":"unknown_route","detail":"no such operator route"}}"#
                            .to_string(),
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }

    fn stop(mut self) -> Vec<String> {
        if let Ok(mut s) = std::net::TcpStream::connect(&self.addr) {
            let _ = s.write_all(b"GET /stop HTTP/1.1\r\n\r\n");
        }
        self.handle.take().unwrap().join().unwrap()
    }
}

#[test]
fn tx_submit_round_trips_the_line_protocol() {
    let server = NodeServer::spawn("sekrit", h(0x11), h(0x22));
    let built = noos_cli::tx_build(&minimal_spec().to_string()).unwrap();
    let signed = noos_cli::tx_sign(
        built["tx"].as_str().unwrap(),
        SEED,
        0,
        0,
        &h(0x11),
        &h(0x22),
        0,
        &[],
    )
    .unwrap();
    let out = noos_cli::tx_submit(
        &server.addr,
        "sekrit",
        &h(0x11),
        &h(0x22),
        built["tx"].as_str().unwrap(),
        signed["witnesses"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(out["accepted"], true);
    assert_eq!(out["txid"].as_str().unwrap(), "9".repeat(64));
    let seen = server.stop();
    // Exactly one /status handshake then one /submit_tx with the payload.
    assert_eq!(seen.len(), 2);
    assert!(seen[0].starts_with("GET /status"));
    assert!(seen[1].starts_with("POST /submit_tx"));
    assert!(seen[1].contains(built["tx"].as_str().unwrap()));
    assert!(seen[1].contains(signed["witnesses"].as_str().unwrap()));
}

#[test]
fn tx_submit_fails_closed_on_wrong_chain_before_sending_bytes() {
    let server = NodeServer::spawn("sekrit", h(0xdd), h(0x22)); // different chain
    let built = noos_cli::tx_build(&minimal_spec().to_string()).unwrap();
    let error = noos_cli::tx_submit(
        &server.addr,
        "sekrit",
        &h(0x11),
        &h(0x22),
        built["tx"].as_str().unwrap(),
        "0100010000000000020000000000",
    )
    .unwrap_err();
    assert_eq!(error, CliError::WrongProtocolIdentity);
    let seen = server.stop();
    // The transaction bytes never left the machine: only /status was hit.
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("GET /status"));
}

#[test]
fn node_status_surfaces_auth_rejection() {
    let server = NodeServer::spawn("sekrit", h(0x11), h(0x22));
    let error = noos_cli::node_status(&server.addr, "WRONG").unwrap_err();
    assert!(matches!(error, CliError::Refused { status: 401, .. }));
    server.stop();
}

// ---------------------------------------------------------------------------
// query — against the REAL noos-indexer router
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn query_reads_blocks_and_transactions_from_a_live_indexer() {
    use noos_indexer::ingest::{NodeBlock, NodeReceipt, NodeSource, NodeStatus};
    use noos_indexer::{Identity, Indexer};

    let identity = Identity {
        chain_id: "a".repeat(64),
        genesis_hash: "b".repeat(64),
        api_version: "v1".into(),
    };
    let dir = tempfile::tempdir().unwrap();
    let indexer = Indexer::open(dir.path(), identity.clone(), identity.clone()).unwrap();

    // Feed one block through the real ingestion driver.
    struct One(Identity);
    impl NodeSource for One {
        fn status(&mut self) -> noos_indexer::Result<NodeStatus> {
            Ok(NodeStatus {
                chain_id: self.0.chain_id.clone(),
                genesis_hash: self.0.genesis_hash.clone(),
                head_height: 1,
                head_hash: "c".repeat(64),
                justified_epoch: 0,
                justified_hash: self.0.genesis_hash.clone(),
                finalized_epoch: 0,
                finalized_hash: self.0.genesis_hash.clone(),
            })
        }
        fn block_by_height(&mut self, h: u64) -> noos_indexer::Result<Option<NodeBlock>> {
            Ok((h == 1).then(|| NodeBlock {
                hash: "c".repeat(64),
                height: 1,
                slot: 1,
                timestamp_ms: 1000,
                parent_hash: self.0.genesis_hash.clone(),
                txids: vec!["d".repeat(64)],
            }))
        }
        fn receipt(&mut self, _t: &str) -> noos_indexer::Result<Option<NodeReceipt>> {
            Ok(Some(NodeReceipt {
                fee_charged: Some("5".into()),
                status_code: Some(0),
            }))
        }
    }
    indexer
        .sync_from_node(&identity, &mut One(identity.clone()), u64::MAX)
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let router = noos_indexer::router(indexer);
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let query_addr = addr.clone();
    let (block, tx, status) = tokio::task::spawn_blocking(move || {
        (
            noos_cli::query_block(&query_addr, "1"),
            noos_cli::query_tx(&query_addr, &"d".repeat(64)),
            noos_cli::indexer_status(&query_addr),
        )
    })
    .await
    .unwrap();

    let block = block.unwrap();
    assert_eq!(block["hash"].as_str().unwrap(), "c".repeat(64));
    assert_eq!(block["transaction_count"], "1");
    let tx = tx.unwrap();
    assert_eq!(tx["state"], "INCLUDED");
    assert_eq!(tx["fee"], "5");
    assert_eq!(tx["inclusion"]["height"], "1");
    let status = status.unwrap();
    assert_eq!(status["unsafe_head"]["height"], "1");
    assert_eq!(
        status["finalized"]["height"], "0",
        "finality never inferred"
    );

    // Falsifier: a missing entity surfaces the API error envelope.
    let addr2 = addr.clone();
    let missing = tokio::task::spawn_blocking(move || noos_cli::query_block(&addr2, "42"))
        .await
        .unwrap();
    assert!(matches!(
        missing,
        Err(CliError::Refused { status: 404, .. })
    ));
}
