//! NOOSPHERE command-line workflows over the real protocol crates.
//!
//! Every command wraps a frozen law rather than re-implementing it:
//! - `keygen` — noos-wallet HKDF derivation (ODR-WALLET-001 vectors);
//!   secrets are derived, used, and zeroized — NEVER printed.
//! - `tx build` — canonical `TransactionV1` encoding via noos-lumen /
//!   noos-codec; byte-identical to `protocol/vectors/lumen/lumen-tx-v1.json`.
//! - `tx sign` — wallet identity-gated signing of the txid; emits the
//!   segregated `TransactionWitnessesV1` container.
//! - `tx submit` / `status` — the noos-node operator line protocol
//!   (`crates/noos-node/src/rpc.rs`), identity checked against `/status`
//!   BEFORE any transaction bytes leave the machine.
//! - `query` — the frozen indexer public API v1.

#![forbid(unsafe_code)]
mod invitation;
mod manifest;

pub use invitation::invitation_verify;
pub use manifest::manifest_verify;

use noos_codec::{NoosDecode, NoosEncode};
use noos_lumen::objects::{
    asset_id as lumen_asset_id, compute_job_id as lumen_compute_job_id,
    lending_market_id as lumen_lending_market_id, object_id as lumen_object_id,
    oracle_feed_id as lumen_oracle_feed_id, pool_id as lumen_pool_id,
    stable_asset_id as lumen_stable_asset_id, txid as lumen_txid, witness_root, AccessEntry,
    ActionV1, BoundedBytes, BoundedList, FeeAuthorizationV1, NoteV1, OptionalHash32,
    OptionalObject, ResourceVector, SignedIntentV1, TransactionV1, TransactionWitnessesV1,
};
use noos_wallet::{derive_authority, IdentityGate, NodeIdentity, Purpose};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Signature suite id carried by every `lumen-tx-v1` intent fixture
/// (64-byte ed25519 signatures).
pub const SIGNATURE_SUITE_ED25519: u16 = 1;
/// Wallet/gate API version (`noos-wallet::API_VERSION`).
pub const API_VERSION: u16 = noos_wallet::API_VERSION;

pub type Result<T, E = CliError> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Bad invocation: unknown command or missing/invalid argument.
    Usage(String),
    /// Input payload violates a protocol law (hex, bounds, spec shape).
    Malformed(String),
    /// Canonical decode rejected the bytes; carries the stable class name.
    Codec(&'static str),
    /// noos-wallet refused (derivation bounds, identity gate, ...).
    Wallet(String),
    /// Transport failure talking to a node or indexer.
    Transport(String),
    /// The remote answered with a non-success status.
    Refused { status: u16, body: String },
    /// The node's declared identity differs from the one supplied.
    WrongProtocolIdentity,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(v) => write!(f, "usage: {v}"),
            Self::Malformed(v) => write!(f, "malformed: {v}"),
            Self::Codec(v) => write!(f, "codec: {v}"),
            Self::Wallet(v) => write!(f, "wallet: {v}"),
            Self::Transport(v) => write!(f, "transport: {v}"),
            Self::Refused { status, body } => write!(f, "refused ({status}): {body}"),
            Self::WrongProtocolIdentity => f.write_str("wrong_protocol_identity"),
        }
    }
}
impl std::error::Error for CliError {}

impl From<noos_wallet::WalletError> for CliError {
    fn from(e: noos_wallet::WalletError) -> Self {
        Self::Wallet(e.to_string())
    }
}
impl From<noos_codec::CodecError> for CliError {
    fn from(e: noos_codec::CodecError) -> Self {
        Self::Codec(e.class_name())
    }
}

// ---------------------------------------------------------------------------
// Hex helpers (lowercase canonical, strict)
// ---------------------------------------------------------------------------

#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(CliError::Malformed(format!("odd-length hex: {s:.16}")));
    }
    let digit = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c.saturating_sub(b'0')),
            b'a'..=b'f' => Ok(c.saturating_sub(b'a').saturating_add(10)),
            _ => Err(CliError::Malformed("non-canonical hex digit".into())),
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().saturating_div(2));
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = digit(bytes[i])?;
        let lo = digit(bytes[i.saturating_add(1)])?;
        out.push(hi.saturating_mul(16).saturating_add(lo));
        i = i.saturating_add(2);
    }
    Ok(out)
}

pub fn from_hex32(s: &str) -> Result<[u8; 32]> {
    let v = from_hex(s)?;
    <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| CliError::Malformed("expected 32-byte hex".into()))
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

pub fn parse_purpose(s: &str) -> Result<Purpose> {
    match s {
        "sign" => Ok(Purpose::Sign),
        "view" => Ok(Purpose::View),
        "agent" => Ok(Purpose::Agent),
        "recovery" => Ok(Purpose::Recovery),
        other => match other.strip_prefix("umbra:") {
            Some(suite) => Ok(Purpose::Umbra {
                suite: suite
                    .parse()
                    .map_err(|_| CliError::Malformed("umbra suite must be u32".into()))?,
            }),
            None => Err(CliError::Usage(format!(
                "unknown purpose {s}; expected sign|view|agent|recovery|umbra:<suite>"
            ))),
        },
    }
}

/// Derives the purpose-separated authority for `(seed, purpose, account,
/// index)` and reports only public material: the derivation path, the
/// blake3 public id, and — for the spending purpose — the ed25519
/// verifying key. The raw secret is zeroized on drop and never emitted.
pub fn keygen(seed_hex: &str, purpose_str: &str, account: u32, index: u32) -> Result<Value> {
    let seed = from_hex(seed_hex)?;
    let purpose = parse_purpose(purpose_str)?;
    let path: Vec<String> = noos_wallet::derivation_path(purpose, account, index)?
        .into_iter()
        .map(|c| format!("{c:#010x}"))
        .collect();
    let authority = derive_authority(&seed, purpose, account, index)?;
    let public_id = to_hex(&authority.public_id());
    let mut out = json!({
        "purpose": purpose_str,
        "account": account.to_string(),
        "index": index.to_string(),
        "path": path,
        "public_id": public_id,
    });
    if matches!(purpose, Purpose::Sign) {
        let spending = authority.into_spending_key()?;
        out["verifying_key"] = json!(to_hex(&spending.verifying_key()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// tx build
// ---------------------------------------------------------------------------

fn spec_str<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| CliError::Malformed(format!("spec field {key} must be a string")))
}

/// u64 spec fields accept a JSON number or a decimal string.
fn spec_u64(v: &Value, key: &str) -> Result<u64> {
    match &v[key] {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| CliError::Malformed(format!("spec field {key} must be u64"))),
        Value::String(s) => s
            .parse()
            .map_err(|_| CliError::Malformed(format!("spec field {key} must be u64"))),
        Value::Null => Err(CliError::Malformed(format!("spec field {key} is required"))),
        _ => Err(CliError::Malformed(format!("spec field {key} must be u64"))),
    }
}

/// u128 spec fields are decimal strings (JSON numbers cannot carry u128).
fn spec_u128(v: &Value, key: &str) -> Result<u128> {
    spec_str(v, key)?
        .parse()
        .map_err(|_| CliError::Malformed(format!("spec field {key} must be a u128 string")))
}

fn spec_u32(v: &Value, key: &str) -> Result<u32> {
    u32::try_from(spec_u64(v, key)?)
        .map_err(|_| CliError::Malformed(format!("spec field {key} must be u32")))
}

fn spec_u16(v: &Value, key: &str) -> Result<u16> {
    u16::try_from(spec_u64(v, key)?)
        .map_err(|_| CliError::Malformed(format!("spec field {key} must be u16")))
}

fn spec_u8(v: &Value, key: &str) -> Result<u8> {
    u8::try_from(spec_u64(v, key)?)
        .map_err(|_| CliError::Malformed(format!("spec field {key} must be u8")))
}

fn spec_text<const MAX: u32>(v: &Value, key: &str) -> Result<BoundedBytes<MAX>> {
    BoundedBytes::new(spec_str(v, key)?.as_bytes().to_vec())
        .ok_or_else(|| CliError::Malformed(format!("spec field {key} exceeds {MAX} bytes")))
}

fn spec_hash(v: &Value, key: &str) -> Result<[u8; 32]> {
    from_hex32(spec_str(v, key)?)
}

fn spec_hash_list<const MAX: u32>(v: &Value, key: &str) -> Result<BoundedList<[u8; 32], MAX>> {
    let items = match &v[key] {
        Value::Null => Vec::new(),
        Value::Array(a) => a
            .iter()
            .map(|e| {
                e.as_str()
                    .ok_or_else(|| CliError::Malformed(format!("{key} entries must be hex")))
                    .and_then(from_hex32)
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(CliError::Malformed(format!("{key} must be an array"))),
    };
    BoundedList::new(items).ok_or_else(|| CliError::Malformed(format!("{key} exceeds bound")))
}

fn structured_action(spec: &Value) -> Result<BoundedBytes<65536>> {
    let action = match spec_str(spec, "type")? {
        "call_object" => {
            let input =
                BoundedBytes::new(from_hex(spec_str(spec, "input")?)?).ok_or_else(|| {
                    CliError::Malformed("call_object input exceeds 65536 bytes".into())
                })?;
            ActionV1::CallObject {
                object_id: spec_hash(spec, "object_id")?,
                input,
            }
        }
        "create_object" => ActionV1::CreateObject {
            class_id: spec_u32(spec, "class_id")?,
            owner_or_policy_root: spec_hash(spec, "owner_or_policy_root")?,
            code_hash: spec_hash(spec, "code_hash")?,
            state_root: spec_hash(spec, "state_root")?,
            storage_words: spec_u64(spec, "storage_words")?,
            rent_deposit: spec_u128(spec, "rent_deposit")?,
            flags: spec_u32(spec, "flags")?,
        },
        "create_asset" => ActionV1::CreateAsset {
            issuer: spec_hash(spec, "issuer")?,
            symbol: spec_text(spec, "symbol")?,
            name: spec_text(spec, "name")?,
            decimals: spec_u8(spec, "decimals")?,
            total_supply: spec_u128(spec, "total_supply")?,
        },
        "create_pool" => ActionV1::CreatePool {
            provider: spec_hash(spec, "provider")?,
            asset_a: spec_hash(spec, "asset_a")?,
            asset_b: spec_hash(spec, "asset_b")?,
            amount_a: spec_u128(spec, "amount_a")?,
            amount_b: spec_u128(spec, "amount_b")?,
            fee_bps: spec_u16(spec, "fee_bps")?,
        },
        "swap_exact_in" => ActionV1::SwapExactIn {
            trader: spec_hash(spec, "trader")?,
            pool_id: spec_hash(spec, "pool_id")?,
            asset_in: spec_hash(spec, "asset_in")?,
            amount_in: spec_u128(spec, "amount_in")?,
            min_amount_out: spec_u128(spec, "min_amount_out")?,
        },
        "add_liquidity" => ActionV1::AddLiquidity {
            provider: spec_hash(spec, "provider")?,
            pool_id: spec_hash(spec, "pool_id")?,
            max_amount_0: spec_u128(spec, "max_amount_0")?,
            max_amount_1: spec_u128(spec, "max_amount_1")?,
            min_shares: spec_u128(spec, "min_shares")?,
        },
        "remove_liquidity" => ActionV1::RemoveLiquidity {
            provider: spec_hash(spec, "provider")?,
            pool_id: spec_hash(spec, "pool_id")?,
            shares: spec_u128(spec, "shares")?,
            min_amount_0: spec_u128(spec, "min_amount_0")?,
            min_amount_1: spec_u128(spec, "min_amount_1")?,
        },
        "create_oracle_feed" => ActionV1::CreateOracleFeed {
            base_asset: spec_hash(spec, "base_asset")?,
            quote_asset: spec_hash(spec, "quote_asset")?,
            reporter_0: spec_hash(spec, "reporter_0")?,
            reporter_1: spec_hash(spec, "reporter_1")?,
            reporter_2: spec_hash(spec, "reporter_2")?,
            max_age_blocks: spec_u64(spec, "max_age_blocks")?,
        },
        "submit_oracle_report" => ActionV1::SubmitOracleReport {
            reporter: spec_hash(spec, "reporter")?,
            feed_id: spec_hash(spec, "feed_id")?,
            price_q9: spec_u128(spec, "price_q9")?,
            confidence_bps: spec_u16(spec, "confidence_bps")?,
            sequence: spec_u64(spec, "sequence")?,
            observed_height: spec_u64(spec, "observed_height")?,
        },
        "create_lending_market" => ActionV1::CreateLendingMarket {
            collateral_asset: spec_hash(spec, "collateral_asset")?,
            oracle_feed_id: spec_hash(spec, "oracle_feed_id")?,
            symbol: spec_text(spec, "symbol")?,
            name: spec_text(spec, "name")?,
            decimals: spec_u8(spec, "decimals")?,
            collateral_factor_bps: spec_u16(spec, "collateral_factor_bps")?,
            liquidation_threshold_bps: spec_u16(spec, "liquidation_threshold_bps")?,
            liquidation_bonus_bps: spec_u16(spec, "liquidation_bonus_bps")?,
            debt_ceiling: spec_u128(spec, "debt_ceiling")?,
            min_debt: spec_u128(spec, "min_debt")?,
        },
        "deposit_collateral" => ActionV1::DepositCollateral {
            owner: spec_hash(spec, "owner")?,
            market_id: spec_hash(spec, "market_id")?,
            amount: spec_u128(spec, "amount")?,
        },
        "withdraw_collateral" => ActionV1::WithdrawCollateral {
            owner: spec_hash(spec, "owner")?,
            market_id: spec_hash(spec, "market_id")?,
            amount: spec_u128(spec, "amount")?,
        },
        "borrow_stable" => ActionV1::BorrowStable {
            owner: spec_hash(spec, "owner")?,
            market_id: spec_hash(spec, "market_id")?,
            amount: spec_u128(spec, "amount")?,
        },
        "repay_stable" => ActionV1::RepayStable {
            owner: spec_hash(spec, "owner")?,
            market_id: spec_hash(spec, "market_id")?,
            amount: spec_u128(spec, "amount")?,
        },
        "liquidate_position" => ActionV1::LiquidatePosition {
            liquidator: spec_hash(spec, "liquidator")?,
            market_id: spec_hash(spec, "market_id")?,
            owner: spec_hash(spec, "owner")?,
            repay_amount: spec_u128(spec, "repay_amount")?,
            min_collateral_out: spec_u128(spec, "min_collateral_out")?,
        },
        "register_compute_worker" => ActionV1::RegisterComputeWorker {
            worker: spec_hash(spec, "worker")?,
            capabilities: spec_u8(spec, "capabilities")?,
            cpu_threads: spec_u16(spec, "cpu_threads")?,
            memory_mb: spec_u32(spec, "memory_mb")?,
            gpu_memory_mb: spec_u32(spec, "gpu_memory_mb")?,
            price_per_unit: spec_u128(spec, "price_per_unit")?,
            endpoint_commitment: spec_hash(spec, "endpoint_commitment")?,
        },
        "open_compute_job" => ActionV1::OpenComputeJob {
            requester: spec_hash(spec, "requester")?,
            workload_kind: spec_u8(spec, "workload_kind")?,
            input_root: spec_hash(spec, "input_root")?,
            units: spec_u64(spec, "units")?,
            unit_size: spec_u32(spec, "unit_size")?,
            max_price_per_unit: spec_u128(spec, "max_price_per_unit")?,
            deadline_height: spec_u64(spec, "deadline_height")?,
        },
        "claim_compute_job" => ActionV1::ClaimComputeJob {
            worker: spec_hash(spec, "worker")?,
            job_id: spec_hash(spec, "job_id")?,
        },
        "submit_compute_result" => ActionV1::SubmitComputeResult {
            worker: spec_hash(spec, "worker")?,
            job_id: spec_hash(spec, "job_id")?,
            result_root: spec_hash(spec, "result_root")?,
            completed_units: spec_u64(spec, "completed_units")?,
        },
        "accept_compute_result" => ActionV1::AcceptComputeResult {
            requester: spec_hash(spec, "requester")?,
            job_id: spec_hash(spec, "job_id")?,
        },
        "cancel_compute_job" => ActionV1::CancelComputeJob {
            requester: spec_hash(spec, "requester")?,
            job_id: spec_hash(spec, "job_id")?,
        },
        other => {
            return Err(CliError::Malformed(format!(
                "unsupported structured action type {other}"
            )))
        }
    };
    BoundedBytes::new(action.encode_canonical())
        .ok_or_else(|| CliError::Malformed("action exceeds 65536 bytes".into()))
}

fn spec_resources(v: &Value) -> Result<ResourceVector> {
    if v.is_null() {
        return Ok(ResourceVector::default());
    }
    Ok(ResourceVector {
        bytes: spec_u64(v, "bytes")?,
        grain_steps: spec_u64(v, "grain_steps")?,
        proof_units: spec_u64(v, "proof_units")?,
        state_reads: spec_u64(v, "state_reads")?,
        state_writes: spec_u64(v, "state_writes")?,
        blob_bytes: spec_u64(v, "blob_bytes")?,
    })
}

fn spec_lock_reveals(v: &Value) -> Result<BoundedList<BoundedBytes<4096>, 256>> {
    let items = match v {
        Value::Null => Vec::new(),
        Value::Array(a) => a
            .iter()
            .map(|e| {
                let bytes = e
                    .as_str()
                    .ok_or_else(|| CliError::Malformed("lock_reveals entries must be hex".into()))
                    .and_then(from_hex)?;
                BoundedBytes::new(bytes)
                    .ok_or_else(|| CliError::Malformed("lock reveal exceeds 4096 bytes".into()))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(CliError::Malformed("lock_reveals must be an array".into())),
    };
    BoundedList::new(items).ok_or_else(|| CliError::Malformed("lock_reveals exceeds bound".into()))
}

fn tx_from_spec(spec: &Value) -> Result<(TransactionV1, BoundedList<BoundedBytes<4096>, 256>)> {
    let fee_authorization = match &spec["fee_authorization"] {
        Value::Null => OptionalObject(None),
        auth => OptionalObject(Some(FeeAuthorizationV1 {
            amount: spec_u128(auth, "amount")?,
            resource_ceiling: spec_resources(&auth["resource_ceiling"])?,
            expiry_height: spec_u64(auth, "expiry_height")?,
            tx_commitment: spec_hash(auth, "tx_commitment")?,
            sponsor: spec_hash(auth, "sponsor")?,
            signature_suite: u16::try_from(spec_u64(auth, "signature_suite")?)
                .map_err(|_| CliError::Malformed("signature_suite must be u16".into()))?,
            signature: BoundedBytes::new(from_hex(spec_str(auth, "signature")?)?)
                .ok_or_else(|| CliError::Malformed("sponsor signature exceeds bound".into()))?,
        })),
    };
    let object_access_list = match &spec["object_access_list"] {
        Value::Null => Vec::new(),
        Value::Array(a) => a
            .iter()
            .map(|e| {
                let mode = match spec_str(e, "mode")? {
                    "read" => AccessEntry::MODE_READ,
                    "read_write" => AccessEntry::MODE_READ_WRITE,
                    other => {
                        return Err(CliError::Malformed(format!(
                            "access mode {other} (expected read|read_write)"
                        )))
                    }
                };
                Ok(AccessEntry {
                    object_id: spec_hash(e, "object_id")?,
                    mode,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        _ => {
            return Err(CliError::Malformed(
                "object_access_list must be an array".into(),
            ))
        }
    };
    let actions = match &spec["actions"] {
        Value::Null => Vec::new(),
        Value::Array(a) => a
            .iter()
            .map(|entry| match entry {
                Value::String(hex) => BoundedBytes::new(from_hex(hex)?)
                    .ok_or_else(|| CliError::Malformed("action exceeds 65536 bytes".into())),
                Value::Object(_) => structured_action(entry),
                _ => Err(CliError::Malformed(
                    "actions entries must be hex strings or structured objects".into(),
                )),
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(CliError::Malformed("actions must be an array".into())),
    };
    let outputs = match &spec["outputs"] {
        Value::Null => Vec::new(),
        Value::Array(a) => a
            .iter()
            .map(|e| {
                Ok(NoteV1 {
                    asset_id: spec_hash(e, "asset_id")?,
                    amount: spec_u128(e, "amount")?,
                    lock_root: spec_hash(e, "lock_root")?,
                    datum_root: spec_hash(e, "datum_root")?,
                    birth_height: spec_u64(e, "birth_height")?,
                    relative_timelock: u32::try_from(spec_u64(e, "relative_timelock")?)
                        .map_err(|_| CliError::Malformed("relative_timelock must be u32".into()))?,
                    memo_commitment: spec_hash(e, "memo_commitment")?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(CliError::Malformed("outputs must be an array".into())),
    };
    let lock_reveals = spec_lock_reveals(&spec["lock_reveals"])?;
    let tx = TransactionV1 {
        chain_id: spec_hash(spec, "chain_id")?,
        format_version: match &spec["format_version"] {
            Value::Null => 1,
            Value::Number(n) => n
                .as_u64()
                .and_then(|x| u16::try_from(x).ok())
                .ok_or_else(|| CliError::Malformed("format_version must be u16".into()))?,
            Value::String(s) => s
                .parse()
                .map_err(|_| CliError::Malformed("format_version must be u16".into()))?,
            _ => return Err(CliError::Malformed("format_version must be u16".into())),
        },
        expiry_height: spec_u64(spec, "expiry_height")?,
        fee_payer: spec_hash(spec, "fee_payer")?,
        fee_authorization,
        resource_limits: spec_resources(&spec["resource_limits"])?,
        note_inputs: spec_hash_list(spec, "note_inputs")?,
        account_inputs: spec_hash_list(spec, "account_inputs")?,
        object_access_list: BoundedList::new(object_access_list)
            .ok_or_else(|| CliError::Malformed("object_access_list exceeds bound".into()))?,
        actions: BoundedList::new(actions)
            .ok_or_else(|| CliError::Malformed("actions exceeds bound".into()))?,
        outputs: BoundedList::new(outputs)
            .ok_or_else(|| CliError::Malformed("outputs exceeds bound".into()))?,
        evidence_refs: spec_hash_list(spec, "evidence_refs")?,
        // The witness root commits the witness PROGRAMS (lock reveals),
        // never signatures — computed, not user-supplied.
        witness_root: witness_root(&lock_reveals),
    };
    Ok((tx, lock_reveals))
}

/// Builds the canonical transaction bytes from a JSON spec.
pub fn tx_build(spec_json: &str) -> Result<Value> {
    let spec: Value = serde_json::from_str(spec_json)
        .map_err(|e| CliError::Malformed(format!("spec is not JSON: {e}")))?;
    let (tx, _) = tx_from_spec(&spec)?;
    let bytes = tx.encode_canonical();
    // Round-trip self-check: what we emit MUST decode canonically.
    TransactionV1::decode_canonical(&bytes)?;
    let txid = lumen_txid(&tx);
    let created_objects: Vec<Value> = tx
        .actions
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(index, bytes)| {
            let ActionV1::CreateObject { class_id, .. } =
                ActionV1::decode_canonical(bytes.as_slice()).ok()?
            else {
                return None;
            };
            let action_index = u32::try_from(index).ok()?;
            Some(json!({
                "action_index": action_index,
                "class_id": class_id,
                "object_id": to_hex(&lumen_object_id(&txid, action_index, class_id)),
            }))
        })
        .collect();
    let created_assets: Vec<Value> = tx
        .actions
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(index, bytes)| {
            let ActionV1::CreateAsset {
                symbol,
                name,
                decimals,
                total_supply,
                ..
            } = ActionV1::decode_canonical(bytes.as_slice()).ok()?
            else {
                return None;
            };
            let action_index = u32::try_from(index).ok()?;
            Some(json!({
                "action_index": action_index,
                "asset_id": to_hex(&lumen_asset_id(&txid, action_index)),
                "symbol": String::from_utf8(symbol.as_slice().to_vec()).ok()?,
                "name": String::from_utf8(name.as_slice().to_vec()).ok()?,
                "decimals": decimals,
                "total_supply": total_supply.to_string(),
            }))
        })
        .collect();
    let created_pools: Vec<Value> = tx
        .actions
        .as_slice()
        .iter()
        .filter_map(|bytes| {
            let ActionV1::CreatePool {
                asset_a,
                asset_b,
                fee_bps,
                ..
            } = ActionV1::decode_canonical(bytes.as_slice()).ok()?
            else {
                return None;
            };
            Some(json!({
                "pool_id": to_hex(&lumen_pool_id(&asset_a, &asset_b)),
                "asset_0": to_hex(if asset_a < asset_b { &asset_a } else { &asset_b }),
                "asset_1": to_hex(if asset_a < asset_b { &asset_b } else { &asset_a }),
                "fee_bps": fee_bps,
            }))
        })
        .collect();
    let created_oracle_feeds: Vec<Value> = tx
        .actions
        .as_slice()
        .iter()
        .filter_map(|bytes| {
            let ActionV1::CreateOracleFeed {
                base_asset,
                quote_asset,
                ..
            } = ActionV1::decode_canonical(bytes.as_slice()).ok()?
            else {
                return None;
            };
            Some(json!({
                "feed_id": to_hex(&lumen_oracle_feed_id(&base_asset, &quote_asset)),
                "base_asset": to_hex(&base_asset),
                "quote_asset": to_hex(&quote_asset),
            }))
        })
        .collect();
    let created_lending_markets: Vec<Value> = tx
        .actions
        .as_slice()
        .iter()
        .filter_map(|bytes| {
            let ActionV1::CreateLendingMarket {
                collateral_asset,
                oracle_feed_id,
                symbol,
                name,
                decimals,
                ..
            } = ActionV1::decode_canonical(bytes.as_slice()).ok()?
            else {
                return None;
            };
            let market_id = lumen_lending_market_id(&collateral_asset, &oracle_feed_id);
            Some(json!({
                "market_id": to_hex(&market_id),
                "stable_asset": to_hex(&lumen_stable_asset_id(&market_id)),
                "collateral_asset": to_hex(&collateral_asset),
                "oracle_feed_id": to_hex(&oracle_feed_id),
                "symbol": String::from_utf8(symbol.as_slice().to_vec()).ok()?,
                "name": String::from_utf8(name.as_slice().to_vec()).ok()?,
                "decimals": decimals,
            }))
        })
        .collect();
    let created_compute_jobs: Vec<Value> = tx
        .actions
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(index, bytes)| {
            let ActionV1::OpenComputeJob {
                workload_kind,
                units,
                unit_size,
                max_price_per_unit,
                deadline_height,
                ..
            } = ActionV1::decode_canonical(bytes.as_slice()).ok()?
            else {
                return None;
            };
            let action_index = u32::try_from(index).ok()?;
            Some(json!({
                "action_index": action_index,
                "job_id": to_hex(&lumen_compute_job_id(&txid, action_index)),
                "workload_kind": workload_kind,
                "units": units.to_string(),
                "unit_size": unit_size,
                "max_price_per_unit": max_price_per_unit.to_string(),
                "deadline_height": deadline_height.to_string(),
            }))
        })
        .collect();
    Ok(json!({
        "tx": to_hex(&bytes),
        "txid": to_hex(&txid),
        "witness_root": to_hex(&tx.witness_root),
        "created_objects": created_objects,
        "created_assets": created_assets,
        "created_pools": created_pools,
        "created_compute_jobs": created_compute_jobs,
        "created_oracle_feeds": created_oracle_feeds,
        "created_lending_markets": created_lending_markets,
    }))
}

// ---------------------------------------------------------------------------
// tx sign
// ---------------------------------------------------------------------------

/// Signs canonical transaction bytes under the wallet identity gate and
/// emits the segregated witness container. Fails closed when the supplied
/// lock reveals do not reproduce the transaction's `witness_root`.
#[allow(clippy::too_many_arguments)]
pub fn tx_sign(
    tx_hex: &str,
    seed_hex: &str,
    account: u32,
    index: u32,
    chain_id_hex: &str,
    genesis_hash_hex: &str,
    signer_scope: u8,
    lock_reveal_hex: &[String],
) -> Result<Value> {
    let bytes = from_hex(tx_hex)?;
    let tx = TransactionV1::decode_canonical(&bytes)?;
    let reveals = spec_lock_reveals(&Value::Array(
        lock_reveal_hex.iter().cloned().map(Value::String).collect(),
    ))?;
    if witness_root(&reveals) != tx.witness_root {
        return Err(CliError::Malformed(
            "lock reveals do not reproduce the transaction witness_root".into(),
        ));
    }
    let identity = NodeIdentity {
        chain_id: from_hex32(chain_id_hex)?,
        genesis_hash: from_hex32(genesis_hash_hex)?,
        api_version: API_VERSION,
    };
    let mut gate = IdentityGate::new(identity);
    gate.verify(identity)?;
    let seed = from_hex(seed_hex)?;
    let spending = derive_authority(&seed, Purpose::Sign, account, index)?.into_spending_key()?;
    let txid = lumen_txid(&tx);
    let signature = spending.sign_lumen_transaction(&gate, &txid)?;
    let witnesses = TransactionWitnessesV1 {
        intents: BoundedList::new(vec![SignedIntentV1 {
            tx_commitment: txid,
            signer_scope,
            capability_ref: OptionalHash32(None),
            signature_suite: SIGNATURE_SUITE_ED25519,
            signature: BoundedBytes::new(signature.to_vec())
                .ok_or_else(|| CliError::Malformed("signature exceeds bound".into()))?,
        }])
        .ok_or_else(|| CliError::Malformed("intents exceed bound".into()))?,
        lock_reveals: reveals,
    };
    Ok(json!({
        "txid": to_hex(&txid),
        "signature": to_hex(&signature),
        "verifying_key": to_hex(&spending.verifying_key()),
        "witnesses": to_hex(&witnesses.encode_canonical()),
    }))
}

// ---------------------------------------------------------------------------
// Line-protocol / indexer HTTP client
// ---------------------------------------------------------------------------

fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<(u16, String)> {
    let err = |e: std::io::Error| CliError::Transport(e.to_string());
    let mut stream = TcpStream::connect(addr).map_err(err)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(err)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(err)?;
    let mut request = format!("{method} {path} HTTP/1.1\r\nhost: {addr}\r\n");
    if let Some(token) = token {
        request.push_str(&format!("authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!(
            "content-type: application/json\r\ncontent-length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("connection: close\r\n\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }
    stream.write_all(request.as_bytes()).map_err(err)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(err)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, payload) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| CliError::Transport("truncated HTTP response".into()))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| CliError::Transport("malformed status line".into()))?;
    Ok((status, payload.to_string()))
}

fn expect_json(status: u16, body: String) -> Result<Value> {
    if status != 200 && status != 202 {
        return Err(CliError::Refused { status, body });
    }
    serde_json::from_str(&body).map_err(|_| CliError::Transport("non-JSON response".into()))
}

/// `GET /status` on the node operator line protocol.
pub fn node_status(node: &str, token: &str) -> Result<Value> {
    let (status, body) = http_request(node, "GET", "/status", Some(token), None)?;
    expect_json(status, body)
}

/// Verifies the node's declared identity, then submits `{"tx","witnesses"}`
/// over the line protocol. Wrong identity fails closed: the transaction
/// bytes never leave the machine.
pub fn tx_submit(
    node: &str,
    token: &str,
    chain_id_hex: &str,
    genesis_hash_hex: &str,
    tx_hex: &str,
    witnesses_hex: &str,
) -> Result<Value> {
    from_hex(tx_hex)?;
    from_hex(witnesses_hex)?;
    let status = node_status(node, token)?;
    if status["chain_id"].as_str() != Some(chain_id_hex)
        || status["genesis_hash"].as_str() != Some(genesis_hash_hex)
    {
        return Err(CliError::WrongProtocolIdentity);
    }
    let body = json!({ "tx": tx_hex, "witnesses": witnesses_hex }).to_string();
    let (code, payload) = http_request(node, "POST", "/submit_tx", Some(token), Some(&body))?;
    expect_json(code, payload)
}

/// `GET /api/v1/blocks/{id}` on the indexer public API.
pub fn query_block(indexer: &str, id: &str) -> Result<Value> {
    let (status, body) = http_request(indexer, "GET", &format!("/api/v1/blocks/{id}"), None, None)?;
    expect_json(status, body)
}

/// `GET /api/v1/transactions/{txid}` on the indexer public API.
pub fn query_tx(indexer: &str, txid: &str) -> Result<Value> {
    let (status, body) = http_request(
        indexer,
        "GET",
        &format!("/api/v1/transactions/{txid}"),
        None,
        None,
    )?;
    expect_json(status, body)
}

/// `GET /api/status` on the indexer public API (three separate heads).
pub fn indexer_status(indexer: &str) -> Result<Value> {
    let (status, body) = http_request(indexer, "GET", "/api/status", None, None)?;
    expect_json(status, body)
}

// ---------------------------------------------------------------------------
// Argument parsing + dispatcher
// ---------------------------------------------------------------------------

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i.saturating_add(1)))
        .cloned()
}

fn required(args: &[String], name: &str) -> Result<String> {
    flag(args, name).ok_or_else(|| CliError::Usage(format!("{name} is required")))
}

fn required_u32(args: &[String], name: &str) -> Result<u32> {
    required(args, name)?
        .parse()
        .map_err(|_| CliError::Usage(format!("{name} must be a u32")))
}

fn multi(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i.saturating_add(1)) {
                out.push(v.clone());
            }
        }
        i = i.saturating_add(1);
    }
    out
}

pub const USAGE: &str = "noos-cli <command>\n\
  keygen    --seed <hex> --purpose sign|view|agent|recovery|umbra:<suite> --account <n> --index <n>\n\
  tx build  --spec <json> | --spec-file <path>\n\
  tx sign   --tx <hex> --seed <hex> --account <n> --index <n> --chain-id <hex32> --genesis-hash <hex32> [--scope <n>] [--lock-reveal <hex>]...\n\
  tx submit --node <addr> --token <t> --chain-id <hex32> --genesis-hash <hex32> --tx <hex> --witnesses <hex>\n\
  query     block <height|hash> --indexer <addr> | tx <txid> --indexer <addr>\n\
  manifest  verify --file <path> --public-key <hex32> [--now-unix-ms <u64>]\n\
  invitation verify --file <path> --public-key <hex32> [--now-unix-ms <u64>]\n\
  status    --node <addr> --token <t> | --indexer <addr>";

/// Runs one CLI invocation; returns the exact stdout payload.
pub fn run(args: &[String]) -> Result<String> {
    let pretty = |v: Value| -> Result<String> {
        serde_json::to_string_pretty(&v).map_err(|e| CliError::Malformed(e.to_string()))
    };
    match args {
        [cmd, rest @ ..] if cmd == "keygen" => pretty(keygen(
            &required(rest, "--seed")?,
            &required(rest, "--purpose")?,
            required_u32(rest, "--account")?,
            required_u32(rest, "--index")?,
        )?),
        [tx, sub, rest @ ..] if tx == "tx" && sub == "build" => {
            let spec = match flag(rest, "--spec") {
                Some(inline) => inline,
                None => {
                    let path = required(rest, "--spec-file")?;
                    std::fs::read_to_string(&path)
                        .map_err(|e| CliError::Usage(format!("--spec-file {path}: {e}")))?
                }
            };
            pretty(tx_build(&spec)?)
        }
        [tx, sub, rest @ ..] if tx == "tx" && sub == "sign" => {
            let scope = match flag(rest, "--scope") {
                Some(v) => v
                    .parse()
                    .map_err(|_| CliError::Usage("--scope must be a u8".into()))?,
                None => 0,
            };
            pretty(tx_sign(
                &required(rest, "--tx")?,
                &required(rest, "--seed")?,
                required_u32(rest, "--account")?,
                required_u32(rest, "--index")?,
                &required(rest, "--chain-id")?,
                &required(rest, "--genesis-hash")?,
                scope,
                &multi(rest, "--lock-reveal"),
            )?)
        }
        [tx, sub, rest @ ..] if tx == "tx" && sub == "submit" => pretty(tx_submit(
            &required(rest, "--node")?,
            &required(rest, "--token")?,
            &required(rest, "--chain-id")?,
            &required(rest, "--genesis-hash")?,
            &required(rest, "--tx")?,
            &required(rest, "--witnesses")?,
        )?),
        [q, kind, id, rest @ ..] if q == "query" && kind == "block" => {
            pretty(query_block(&required(rest, "--indexer")?, id)?)
        }
        [q, kind, id, rest @ ..] if q == "query" && kind == "tx" => {
            pretty(query_tx(&required(rest, "--indexer")?, id)?)
        }
        [manifest, verify, rest @ ..] if manifest == "manifest" && verify == "verify" => {
            let path = required(rest, "--file")?;
            let encoded = std::fs::read_to_string(&path)
                .map_err(|error| CliError::Usage(format!("--file {path}: {error}")))?;
            let now_unix_ms = match flag(rest, "--now-unix-ms") {
                Some(value) => value
                    .parse()
                    .map_err(|_| CliError::Usage("--now-unix-ms must be a u64".into()))?,
                None => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| CliError::Malformed("system clock precedes Unix epoch".into()))?
                    .as_millis()
                    .try_into()
                    .map_err(|_| {
                        CliError::Malformed("system clock does not fit u64 milliseconds".into())
                    })?,
            };
            pretty(manifest_verify(
                &encoded,
                &required(rest, "--public-key")?,
                now_unix_ms,
            )?)
        }
        [invitation, verify, rest @ ..] if invitation == "invitation" && verify == "verify" => {
            let path = required(rest, "--file")?;
            let encoded = std::fs::read_to_string(&path)
                .map_err(|error| CliError::Usage(format!("--file {path}: {error}")))?;
            let now_unix_ms = match flag(rest, "--now-unix-ms") {
                Some(value) => value
                    .parse()
                    .map_err(|_| CliError::Usage("--now-unix-ms must be a u64".into()))?,
                None => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| CliError::Malformed("system clock precedes Unix epoch".into()))?
                    .as_millis()
                    .try_into()
                    .map_err(|_| {
                        CliError::Malformed("system clock does not fit u64 milliseconds".into())
                    })?,
            };
            pretty(invitation_verify(
                &encoded,
                &required(rest, "--public-key")?,
                now_unix_ms,
            )?)
        }
        [cmd, rest @ ..] if cmd == "status" => match flag(rest, "--indexer") {
            Some(indexer) => pretty(indexer_status(&indexer)?),
            None => pretty(node_status(
                &required(rest, "--node")?,
                &required(rest, "--token")?,
            )?),
        },
        _ => Err(CliError::Usage(USAGE.into())),
    }
}
