//! Shared mobile wallet boundary for Kotlin and Swift.
//!
//! Platform shells own transport and hardware-backed seed custody. This crate
//! remains the source of truth for identity gating, canonical transfer review,
//! note conservation, purpose-separated derivation, and Ed25519 signing.
#![forbid(unsafe_code)]

use noos_codec::NoosDecode;
use noos_lumen::objects::{txid as lumen_txid, TransactionV1, TransactionWitnessesV1};
use noos_wallet::{derivation_path, derive_authority as derive_wallet_authority, Purpose};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

const PROTOCOL_VERSION: &str = "v1";
const API_VERSION: &str = "v1";
const MAX_JSON_BYTES: usize = 1_048_576;
const REQUIRED_SPEC_FIELDS: [&str; 11] = [
    "expiry_height",
    "fee_payer",
    "fee_authorization",
    "resource_limits",
    "note_inputs",
    "account_inputs",
    "object_access_list",
    "actions",
    "outputs",
    "evidence_refs",
    "lock_reveals",
];
const REVIEW_DOMAIN: &[u8] = b"NOOS/WALLET/MOBILE/TRANSFER-REVIEW/V1\0";
const LIGHT_NODE_SCHEMA: &str = "noos/mobile-light-node-state/v1";
const LIGHT_NODE_CHECKSUM_DOMAIN: &[u8] = b"NOOS/MOBILE/LIGHT-NODE-STATE/V1\0";
const LIGHT_NODE_TRUST_MODEL: &str = "MULTI_CONTROL_CLUSTER_FINALIZED_QUORUM";
const MAX_LIGHT_NODE_OBSERVATIONS: usize = 16;
const MAX_LIGHT_NODE_HISTORY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error, uniffi::Error)]
pub enum WalletSdkError {
    #[error("invalid_profile")]
    InvalidProfile,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("malformed_status")]
    MalformedStatus,
    #[error("stale_status")]
    StaleStatus,
    #[error("indexer_unavailable")]
    IndexerUnavailable,
    #[error("wrong_protocol_identity")]
    WrongProtocolIdentity,
    #[error("invalid_transaction")]
    InvalidTransaction,
    #[error("insufficient_funds")]
    InsufficientFunds,
    #[error("nonce_boundary")]
    NonceBoundary,
    #[error("fee_boundary")]
    FeeBoundary,
    #[error("review_mismatch")]
    ReviewMismatch,
    #[error("submission_rejected")]
    SubmissionRejected,
    #[error("malformed_submit_response")]
    MalformedSubmitResponse,
    #[error("txid_mismatch")]
    TxidMismatch,
    #[error("invalid_observation")]
    InvalidObservation,
    #[error("insufficient_quorum")]
    InsufficientQuorum,
    #[error("checkpoint_regression")]
    CheckpointRegression,
    #[error("checkpoint_conflict")]
    CheckpointConflict,
    #[error("invalid_persisted_state")]
    InvalidPersistedState,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifiedStatus {
    pub chain_id: String,
    pub genesis_hash: String,
    pub release_version: String,
    pub unsafe_height: u64,
    pub unsafe_hash: String,
    pub justified_height: u64,
    pub justified_hash: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub freshness_ms: u64,
    pub next_output_birth_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DerivedAuthority {
    pub path: Vec<String>,
    pub path_bytes_hex: String,
    pub public_id: String,
    pub verifying_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ResourceLimits {
    pub bytes: u64,
    pub grain_steps: u64,
    pub proof_units: u64,
    pub state_reads: u64,
    pub state_writes: u64,
    pub blob_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AssetAmount {
    pub asset_id: String,
    pub amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutputReview {
    pub asset_id: String,
    pub amount: String,
    pub lock_root: String,
    pub datum_root: String,
    pub birth_height: u64,
    pub relative_timelock: u32,
    pub memo_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransferReview {
    pub review_id: String,
    pub txid: String,
    pub fee_payer: String,
    pub expiry_height: u64,
    pub observed_unsafe_height: u64,
    pub observed_unsafe_hash: String,
    pub observed_finalized_height: u64,
    pub observed_finalized_hash: String,
    pub resource_limits: ResourceLimits,
    pub note_inputs: Vec<String>,
    pub outputs: Vec<OutputReview>,
    pub input_totals: Vec<AssetAmount>,
    pub output_totals: Vec<AssetAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignedTransfer {
    pub review_id: String,
    pub txid: String,
    pub transaction_hex: String,
    pub witnesses_hex: String,
    pub submission_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SubmissionResult {
    pub txid: String,
    pub state: String,
}

#[derive(Debug, uniffi::Object)]
pub struct MobileWalletCore {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    chain_id_hex: String,
    genesis_hash_hex: String,
    maximum_freshness_ms: u64,
}

#[uniffi::export]
impl MobileWalletCore {
    #[uniffi::constructor]
    pub fn new(
        chain_id: String,
        genesis_hash: String,
        api_version: String,
        maximum_freshness_ms: u64,
    ) -> Result<Arc<Self>, WalletSdkError> {
        if api_version != API_VERSION || maximum_freshness_ms == 0 {
            return Err(WalletSdkError::InvalidProfile);
        }
        let chain_id_bytes = parse_hash32(&chain_id).map_err(|_| WalletSdkError::InvalidProfile)?;
        let genesis_hash_bytes =
            parse_hash32(&genesis_hash).map_err(|_| WalletSdkError::InvalidProfile)?;
        Ok(Arc::new(Self {
            chain_id: chain_id_bytes,
            genesis_hash: genesis_hash_bytes,
            chain_id_hex: chain_id,
            genesis_hash_hex: genesis_hash,
            maximum_freshness_ms,
        }))
    }

    pub fn verify_status(&self, status_json: String) -> Result<VerifiedStatus, WalletSdkError> {
        verify_status_document(self, &status_json)
    }

    pub fn derive_authority(
        &self,
        seed: Vec<u8>,
        purpose: String,
        suite: Option<u32>,
        account: u32,
        index: u32,
    ) -> Result<DerivedAuthority, WalletSdkError> {
        if !(16..=128).contains(&seed.len()) {
            return Err(WalletSdkError::InvalidRequest);
        }
        let seed = Zeroizing::new(seed);
        let purpose = parse_purpose(&purpose, suite)?;
        let path =
            derivation_path(purpose, account, index).map_err(|_| WalletSdkError::InvalidRequest)?;
        let mut path_bytes_hex = String::with_capacity(path.len().saturating_mul(8));
        let mut path_display = Vec::with_capacity(path.len());
        for component in path {
            let encoded = hex::encode(component.to_be_bytes());
            path_bytes_hex.push_str(&encoded);
            path_display.push(format!("0x{encoded}"));
        }
        let authority = derive_wallet_authority(&seed, purpose, account, index)
            .map_err(|_| WalletSdkError::InvalidRequest)?;
        let public_id = hex::encode(authority.public_id());
        let verifying_key = if purpose.can_spend() {
            Some(hex::encode(
                authority
                    .into_spending_key()
                    .map_err(|_| WalletSdkError::InvalidRequest)?
                    .verifying_key(),
            ))
        } else {
            None
        };
        Ok(DerivedAuthority {
            path: path_display,
            path_bytes_hex,
            public_id,
            verifying_key,
        })
    }

    pub fn review_transfer(
        &self,
        transaction_spec_json: String,
        status_json: String,
        notes_json: String,
    ) -> Result<TransferReview, WalletSdkError> {
        let unsigned = build_unsigned(self, &transaction_spec_json, &status_json, &notes_json)?;
        Ok(transfer_review(self, &unsigned))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_reviewed_transfer(
        &self,
        seed: Vec<u8>,
        account: u32,
        index: u32,
        signer_scope: u8,
        transaction_spec_json: String,
        status_json: String,
        notes_json: String,
        expected_review_id: String,
    ) -> Result<SignedTransfer, WalletSdkError> {
        if !(16..=128).contains(&seed.len()) || signer_scope != 0 {
            return Err(WalletSdkError::InvalidRequest);
        }
        let unsigned = build_unsigned(self, &transaction_spec_json, &status_json, &notes_json)?;
        let review = transfer_review(self, &unsigned);
        if !constant_time_ascii_eq(&review.review_id, &expected_review_id) {
            return Err(WalletSdkError::ReviewMismatch);
        }

        let seed = Zeroizing::new(seed);
        let seed_hex = Zeroizing::new(hex::encode(seed.as_slice()));
        let signed = noos_cli::tx_sign(
            &unsigned.transaction_hex,
            &seed_hex,
            account,
            index,
            &self.chain_id_hex,
            &self.genesis_hash_hex,
            signer_scope,
            &unsigned.lock_reveals,
        )
        .map_err(|_| WalletSdkError::InvalidTransaction)?;
        let verifying_key = signed["verifying_key"]
            .as_str()
            .ok_or(WalletSdkError::InvalidTransaction)?;
        if parse_hash32(verifying_key).map_err(|_| WalletSdkError::InvalidTransaction)?
            != unsigned.transaction.fee_payer
        {
            return Err(WalletSdkError::NonceBoundary);
        }
        let witnesses_hex = signed["witnesses"]
            .as_str()
            .ok_or(WalletSdkError::InvalidTransaction)?
            .to_owned();
        let witness_bytes =
            hex::decode(&witnesses_hex).map_err(|_| WalletSdkError::InvalidTransaction)?;
        let witnesses = TransactionWitnessesV1::decode_canonical(&witness_bytes)
            .map_err(|_| WalletSdkError::InvalidTransaction)?;
        let txid = lumen_txid(&unsigned.transaction);
        if witnesses.intents.len() != 1
            || witnesses.intents.as_slice()[0].tx_commitment != txid
            || signed["txid"].as_str() != Some(review.txid.as_str())
        {
            return Err(WalletSdkError::InvalidTransaction);
        }
        let submission_json = serde_json::to_string(&json!({
            "tx": unsigned.transaction_hex,
            "witnesses": witnesses_hex,
        }))
        .map_err(|_| WalletSdkError::InvalidTransaction)?;
        Ok(SignedTransfer {
            review_id: review.review_id,
            txid: review.txid,
            transaction_hex: unsigned.transaction_hex,
            witnesses_hex,
            submission_json,
        })
    }

    pub fn validate_submission_response(
        &self,
        expected_txid: String,
        response_json: String,
    ) -> Result<SubmissionResult, WalletSdkError> {
        if parse_hash32(&expected_txid).is_err() || response_json.len() > MAX_JSON_BYTES {
            return Err(WalletSdkError::MalformedSubmitResponse);
        }
        let response: SubmitResponseWire = serde_json::from_str(&response_json)
            .map_err(|_| WalletSdkError::MalformedSubmitResponse)?;
        if parse_hash32(&response.txid).is_err() {
            return Err(WalletSdkError::MalformedSubmitResponse);
        }
        if !constant_time_ascii_eq(&response.txid, &expected_txid) {
            return Err(WalletSdkError::TxidMismatch);
        }
        if !matches!(
            response.state.as_str(),
            "MEMPOOL" | "INCLUDED" | "JUSTIFIED" | "FINALIZED"
        ) {
            return Err(WalletSdkError::SubmissionRejected);
        }
        Ok(SubmissionResult {
            txid: response.txid,
            state: response.state,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainPoint {
    height: String,
    hash: String,
    state_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveStatus {
    #[serde(default)]
    readiness: Option<String>,
    #[serde(default)]
    ready: Option<bool>,
    #[serde(default)]
    indexed_generation: Option<String>,
    chain_id: String,
    genesis_hash: String,
    protocol_version: String,
    api_version: String,
    release_version: String,
    unsafe_head: ChainPoint,
    justified: ChainPoint,
    finalized: ChainPoint,
    freshness_ms: String,
    evidence_registry_root: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveNote {
    note_id: String,
    asset_id: String,
    amount: String,
    created_height: String,
    spent: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitResponseWire {
    txid: String,
    state: String,
}

struct UnsignedTransfer {
    transaction: TransactionV1,
    transaction_hex: String,
    transaction_bytes: Vec<u8>,
    lock_reveals: Vec<String>,
    status: VerifiedStatus,
    notes: Vec<LiveNote>,
}

fn parse_hash32(value: &str) -> Result<[u8; 32], WalletSdkError> {
    if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(WalletSdkError::InvalidRequest);
    }
    hex::decode(value)
        .map_err(|_| WalletSdkError::InvalidRequest)?
        .try_into()
        .map_err(|_| WalletSdkError::InvalidRequest)
}

fn parse_decimal_u64(value: &str) -> Result<u64, WalletSdkError> {
    if value.is_empty()
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(WalletSdkError::InvalidRequest);
    }
    value.parse().map_err(|_| WalletSdkError::InvalidRequest)
}

fn parse_decimal_u128(value: &str) -> Result<u128, WalletSdkError> {
    if value.is_empty()
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(WalletSdkError::InvalidRequest);
    }
    value.parse().map_err(|_| WalletSdkError::InvalidRequest)
}

fn parse_purpose(value: &str, suite: Option<u32>) -> Result<Purpose, WalletSdkError> {
    match (value, suite) {
        ("sign", None) => Ok(Purpose::Sign),
        ("view", None) => Ok(Purpose::View),
        ("umbra", Some(suite)) => Ok(Purpose::Umbra { suite }),
        ("agent", None) => Ok(Purpose::Agent),
        ("recovery", None) => Ok(Purpose::Recovery),
        _ => Err(WalletSdkError::InvalidRequest),
    }
}

fn verify_status_document(
    core: &MobileWalletCore,
    raw: &str,
) -> Result<VerifiedStatus, WalletSdkError> {
    if raw.is_empty() || raw.len() > MAX_JSON_BYTES {
        return Err(WalletSdkError::MalformedStatus);
    }
    let status: LiveStatus =
        serde_json::from_str(raw).map_err(|_| WalletSdkError::MalformedStatus)?;
    if status.ready == Some(false) {
        return Err(WalletSdkError::IndexerUnavailable);
    }
    if status
        .readiness
        .as_deref()
        .is_some_and(|value| value != "ready")
    {
        return Err(WalletSdkError::IndexerUnavailable);
    }
    if status
        .indexed_generation
        .as_deref()
        .is_some_and(|value| parse_decimal_u64(value).is_err())
    {
        return Err(WalletSdkError::MalformedStatus);
    }
    for value in [
        &status.chain_id,
        &status.genesis_hash,
        &status.unsafe_head.hash,
        &status.unsafe_head.state_root,
        &status.justified.hash,
        &status.justified.state_root,
        &status.finalized.hash,
        &status.finalized.state_root,
        &status.evidence_registry_root,
    ] {
        parse_hash32(value).map_err(|_| WalletSdkError::MalformedStatus)?;
    }
    if status.chain_id != core.chain_id_hex
        || status.genesis_hash != core.genesis_hash_hex
        || status.protocol_version != PROTOCOL_VERSION
        || status.api_version != API_VERSION
    {
        return Err(WalletSdkError::WrongProtocolIdentity);
    }
    if status.release_version.is_empty() || status.release_version.len() > 128 {
        return Err(WalletSdkError::MalformedStatus);
    }
    let unsafe_height = parse_decimal_u64(&status.unsafe_head.height)
        .map_err(|_| WalletSdkError::MalformedStatus)?;
    let justified_height =
        parse_decimal_u64(&status.justified.height).map_err(|_| WalletSdkError::MalformedStatus)?;
    let finalized_height =
        parse_decimal_u64(&status.finalized.height).map_err(|_| WalletSdkError::MalformedStatus)?;
    if finalized_height > justified_height || justified_height > unsafe_height {
        return Err(WalletSdkError::MalformedStatus);
    }
    let freshness_ms =
        parse_decimal_u64(&status.freshness_ms).map_err(|_| WalletSdkError::MalformedStatus)?;
    if freshness_ms > core.maximum_freshness_ms {
        return Err(WalletSdkError::StaleStatus);
    }
    let next_output_birth_height = unsafe_height
        .checked_add(1)
        .ok_or(WalletSdkError::MalformedStatus)?;
    Ok(VerifiedStatus {
        chain_id: status.chain_id,
        genesis_hash: status.genesis_hash,
        release_version: status.release_version,
        unsafe_height,
        unsafe_hash: status.unsafe_head.hash,
        justified_height,
        justified_hash: status.justified.hash,
        finalized_height,
        finalized_hash: status.finalized.hash,
        freshness_ms,
        next_output_birth_height,
    })
}

fn complete_spec(raw: &str, chain_id: &str) -> Result<(Value, Vec<String>), WalletSdkError> {
    if raw.is_empty() || raw.len() > MAX_JSON_BYTES {
        return Err(WalletSdkError::InvalidRequest);
    }
    let mut spec: Map<String, Value> = serde_json::from_str::<Value>(raw)
        .map_err(|_| WalletSdkError::InvalidRequest)?
        .as_object()
        .cloned()
        .ok_or(WalletSdkError::InvalidRequest)?;
    let allowed: BTreeSet<&str> = REQUIRED_SPEC_FIELDS.into_iter().collect();
    if spec.len() != allowed.len()
        || spec.keys().any(|key| !allowed.contains(key.as_str()))
        || allowed.iter().any(|key| !spec.contains_key(*key))
    {
        return Err(WalletSdkError::InvalidRequest);
    }
    let lock_reveals = spec
        .get("lock_reveals")
        .and_then(Value::as_array)
        .ok_or(WalletSdkError::InvalidRequest)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|text| text.len() <= 8192)
                .map(str::to_owned)
                .ok_or(WalletSdkError::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    spec.insert("chain_id".to_owned(), Value::String(chain_id.to_owned()));
    spec.insert("format_version".to_owned(), Value::Number(1_u64.into()));
    Ok((Value::Object(spec), lock_reveals))
}

fn strict_transfer_shape(
    transaction: &TransactionV1,
    reveal_count: usize,
) -> Result<(), WalletSdkError> {
    let unique_accounts: BTreeSet<_> = transaction.account_inputs.iter().collect();
    if transaction.account_inputs.len() != 1
        || unique_accounts.len() != 1
        || transaction.account_inputs.as_slice()[0] != transaction.fee_payer
    {
        return Err(WalletSdkError::NonceBoundary);
    }
    if transaction.format_version != 1
        || transaction.fee_authorization.0.is_some()
        || transaction.note_inputs.is_empty()
        || transaction.outputs.is_empty()
        || !transaction.actions.is_empty()
        || !transaction.object_access_list.is_empty()
        || !transaction.evidence_refs.is_empty()
        || transaction.note_inputs.len() != reveal_count
    {
        return Err(WalletSdkError::InvalidTransaction);
    }
    let unique_notes: BTreeSet<_> = transaction.note_inputs.iter().collect();
    if unique_notes.len() != transaction.note_inputs.len() {
        return Err(WalletSdkError::InvalidTransaction);
    }
    Ok(())
}

fn parse_notes(raw: &str) -> Result<Vec<LiveNote>, WalletSdkError> {
    if raw.is_empty() || raw.len() > MAX_JSON_BYTES {
        return Err(WalletSdkError::InsufficientFunds);
    }
    let notes: Vec<LiveNote> =
        serde_json::from_str(raw).map_err(|_| WalletSdkError::InsufficientFunds)?;
    if notes.is_empty() || notes.len() > 256 {
        return Err(WalletSdkError::InsufficientFunds);
    }
    Ok(notes)
}

fn validate_note_funds(
    transaction: &TransactionV1,
    status: &VerifiedStatus,
    notes: &[LiveNote],
) -> Result<(), WalletSdkError> {
    if notes.len() != transaction.note_inputs.len() {
        return Err(WalletSdkError::InsufficientFunds);
    }
    let expected_ids: BTreeSet<[u8; 32]> = transaction.note_inputs.iter().copied().collect();
    let mut seen_ids = BTreeSet::new();
    let mut inputs = BTreeMap::<[u8; 32], u128>::new();
    for note in notes {
        let note_id = parse_hash32(&note.note_id).map_err(|_| WalletSdkError::InsufficientFunds)?;
        let asset_id =
            parse_hash32(&note.asset_id).map_err(|_| WalletSdkError::InsufficientFunds)?;
        let amount =
            parse_decimal_u128(&note.amount).map_err(|_| WalletSdkError::InsufficientFunds)?;
        let created_height = parse_decimal_u64(&note.created_height)
            .map_err(|_| WalletSdkError::InsufficientFunds)?;
        if note.spent
            || amount == 0
            || created_height > status.unsafe_height
            || !expected_ids.contains(&note_id)
            || !seen_ids.insert(note_id)
        {
            return Err(WalletSdkError::InsufficientFunds);
        }
        let total = inputs.entry(asset_id).or_default();
        *total = total
            .checked_add(amount)
            .ok_or(WalletSdkError::InsufficientFunds)?;
    }
    if seen_ids != expected_ids {
        return Err(WalletSdkError::InsufficientFunds);
    }
    let outputs = output_totals(transaction)?;
    if inputs != outputs {
        return Err(WalletSdkError::InsufficientFunds);
    }
    Ok(())
}

fn output_totals(transaction: &TransactionV1) -> Result<BTreeMap<[u8; 32], u128>, WalletSdkError> {
    let mut outputs = BTreeMap::<[u8; 32], u128>::new();
    for note in transaction.outputs.iter() {
        if note.amount == 0 {
            return Err(WalletSdkError::InvalidTransaction);
        }
        let total = outputs.entry(note.asset_id).or_default();
        *total = total
            .checked_add(note.amount)
            .ok_or(WalletSdkError::InsufficientFunds)?;
    }
    Ok(outputs)
}

fn build_unsigned(
    core: &MobileWalletCore,
    transaction_spec_json: &str,
    status_json: &str,
    notes_json: &str,
) -> Result<UnsignedTransfer, WalletSdkError> {
    let status = verify_status_document(core, status_json)?;
    let notes = parse_notes(notes_json)?;
    let (spec, lock_reveals) = complete_spec(transaction_spec_json, &core.chain_id_hex)?;
    let built =
        noos_cli::tx_build(&spec.to_string()).map_err(|_| WalletSdkError::InvalidTransaction)?;
    let transaction_hex = built["tx"]
        .as_str()
        .ok_or(WalletSdkError::InvalidTransaction)?
        .to_owned();
    let transaction_bytes =
        hex::decode(&transaction_hex).map_err(|_| WalletSdkError::InvalidTransaction)?;
    let transaction = TransactionV1::decode_canonical(&transaction_bytes)
        .map_err(|_| WalletSdkError::InvalidTransaction)?;
    if transaction.chain_id != core.chain_id {
        return Err(WalletSdkError::WrongProtocolIdentity);
    }
    strict_transfer_shape(&transaction, lock_reveals.len())?;
    if transaction.expiry_height <= status.unsafe_height
        || transaction
            .outputs
            .iter()
            .any(|output| output.birth_height != status.next_output_birth_height)
    {
        return Err(WalletSdkError::InvalidTransaction);
    }
    let encoded_length =
        u64::try_from(transaction_bytes.len()).map_err(|_| WalletSdkError::FeeBoundary)?;
    if transaction.resource_limits.bytes < encoded_length {
        return Err(WalletSdkError::FeeBoundary);
    }
    validate_note_funds(&transaction, &status, &notes)?;
    Ok(UnsignedTransfer {
        transaction,
        transaction_hex,
        transaction_bytes,
        lock_reveals,
        status,
        notes,
    })
}

fn transfer_review(core: &MobileWalletCore, unsigned: &UnsignedTransfer) -> TransferReview {
    let transaction = &unsigned.transaction;
    let mut input_totals = BTreeMap::<[u8; 32], u128>::new();
    let mut ordered_notes = unsigned.notes.clone();
    ordered_notes.sort_by(|left, right| left.note_id.cmp(&right.note_id));
    for note in &ordered_notes {
        if let (Ok(asset_id), Ok(amount)) = (
            parse_hash32(&note.asset_id),
            parse_decimal_u128(&note.amount),
        ) {
            let current = input_totals.entry(asset_id).or_default();
            *current = current.saturating_add(amount);
        }
    }
    let output_totals = output_totals(transaction).unwrap_or_default();
    let mut review_hasher = blake3::Hasher::new();
    review_hasher.update(REVIEW_DOMAIN);
    review_hasher.update(&core.chain_id);
    review_hasher.update(&core.genesis_hash);
    if let Ok(hash) = parse_hash32(&unsigned.status.unsafe_hash) {
        review_hasher.update(&hash);
    }
    if let Ok(hash) = parse_hash32(&unsigned.status.finalized_hash) {
        review_hasher.update(&hash);
    }
    review_hasher.update(&unsigned.transaction_bytes);
    for note in &ordered_notes {
        if let (Ok(note_id), Ok(asset_id), Ok(amount), Ok(created_height)) = (
            parse_hash32(&note.note_id),
            parse_hash32(&note.asset_id),
            parse_decimal_u128(&note.amount),
            parse_decimal_u64(&note.created_height),
        ) {
            review_hasher.update(&note_id);
            review_hasher.update(&asset_id);
            review_hasher.update(&amount.to_le_bytes());
            review_hasher.update(&created_height.to_le_bytes());
            review_hasher.update(&[u8::from(note.spent)]);
        }
    }
    TransferReview {
        review_id: review_hasher.finalize().to_hex().to_string(),
        txid: hex::encode(lumen_txid(transaction)),
        fee_payer: hex::encode(transaction.fee_payer),
        expiry_height: transaction.expiry_height,
        observed_unsafe_height: unsigned.status.unsafe_height,
        observed_unsafe_hash: unsigned.status.unsafe_hash.clone(),
        observed_finalized_height: unsigned.status.finalized_height,
        observed_finalized_hash: unsigned.status.finalized_hash.clone(),
        resource_limits: ResourceLimits {
            bytes: transaction.resource_limits.bytes,
            grain_steps: transaction.resource_limits.grain_steps,
            proof_units: transaction.resource_limits.proof_units,
            state_reads: transaction.resource_limits.state_reads,
            state_writes: transaction.resource_limits.state_writes,
            blob_bytes: transaction.resource_limits.blob_bytes,
        },
        note_inputs: transaction.note_inputs.iter().map(hex::encode).collect(),
        outputs: transaction
            .outputs
            .iter()
            .map(|output| OutputReview {
                asset_id: hex::encode(output.asset_id),
                amount: output.amount.to_string(),
                lock_root: hex::encode(output.lock_root),
                datum_root: hex::encode(output.datum_root),
                birth_height: output.birth_height,
                relative_timelock: output.relative_timelock,
                memo_commitment: hex::encode(output.memo_commitment),
            })
            .collect(),
        input_totals: asset_amounts(input_totals),
        output_totals: asset_amounts(output_totals),
    }
}

fn asset_amounts(values: BTreeMap<[u8; 32], u128>) -> Vec<AssetAmount> {
    values
        .into_iter()
        .map(|(asset_id, amount)| AssetAmount {
            asset_id: hex::encode(asset_id),
            amount: amount.to_string(),
        })
        .collect()
}

fn constant_time_ascii_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EndpointStatusObservation {
    pub endpoint_id: String,
    pub control_cluster: String,
    pub status_json: String,
    /// Hash returned by this endpoint for the node's currently trusted height.
    /// It is mandatory when advancing from a non-genesis checkpoint.
    pub ancestor_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileNodeSnapshot {
    pub chain_id: String,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub sequence: u64,
    pub minimum_control_cluster_quorum: u8,
    pub trust_model: String,
    pub retained_checkpoints: u32,
    pub state_checksum: String,
    pub required_ancestor_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileNodeSyncOutcome {
    pub advanced: bool,
    pub total_observations: u32,
    pub quorum_endpoints: u32,
    pub quorum_control_clusters: u32,
    pub snapshot: MobileNodeSnapshot,
    pub persisted_state_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LightCheckpoint {
    height: u64,
    hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LightNodeState {
    finalized_height: u64,
    finalized_hash: String,
    sequence: u64,
    history: Vec<LightCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLightNodeState {
    schema: String,
    chain_id: String,
    genesis_hash: String,
    minimum_control_cluster_quorum: u8,
    finalized_height: u64,
    finalized_hash: String,
    sequence: u64,
    history: Vec<LightCheckpoint>,
    checksum: String,
}

#[derive(Debug, uniffi::Object)]
pub struct MobileLightNode {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    chain_id_hex: String,
    genesis_hash_hex: String,
    maximum_freshness_ms: u64,
    minimum_quorum: u8,
    state: Mutex<LightNodeState>,
}

#[uniffi::export]
impl MobileLightNode {
    #[uniffi::constructor]
    pub fn new(
        chain_id: String,
        genesis_hash: String,
        api_version: String,
        maximum_freshness_ms: u64,
        minimum_control_cluster_quorum: u8,
        persisted_state_json: Option<String>,
    ) -> Result<Arc<Self>, WalletSdkError> {
        if api_version != API_VERSION
            || maximum_freshness_ms == 0
            || !(2..=u8::try_from(MAX_LIGHT_NODE_OBSERVATIONS)
                .map_err(|_| WalletSdkError::InvalidProfile)?)
                .contains(&minimum_control_cluster_quorum)
        {
            return Err(WalletSdkError::InvalidProfile);
        }
        let chain_id_bytes = parse_hash32(&chain_id).map_err(|_| WalletSdkError::InvalidProfile)?;
        let genesis_hash_bytes =
            parse_hash32(&genesis_hash).map_err(|_| WalletSdkError::InvalidProfile)?;
        let state = match persisted_state_json {
            Some(raw) => parse_light_node_state(
                &raw,
                &chain_id,
                &genesis_hash,
                minimum_control_cluster_quorum,
            )?,
            None => LightNodeState {
                finalized_height: 0,
                finalized_hash: genesis_hash.clone(),
                sequence: 0,
                history: vec![LightCheckpoint {
                    height: 0,
                    hash: genesis_hash.clone(),
                }],
            },
        };
        Ok(Arc::new(Self {
            chain_id: chain_id_bytes,
            genesis_hash: genesis_hash_bytes,
            chain_id_hex: chain_id,
            genesis_hash_hex: genesis_hash,
            maximum_freshness_ms,
            minimum_quorum: minimum_control_cluster_quorum,
            state: Mutex::new(state),
        }))
    }

    pub fn snapshot(&self) -> Result<MobileNodeSnapshot, WalletSdkError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WalletSdkError::InvalidPersistedState)?;
        Ok(light_node_snapshot(self, &state))
    }

    pub fn export_state(&self) -> Result<String, WalletSdkError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WalletSdkError::InvalidPersistedState)?;
        serialize_light_node_state(self, &state)
    }

    pub fn observe_finalized(
        &self,
        observations: Vec<EndpointStatusObservation>,
    ) -> Result<MobileNodeSyncOutcome, WalletSdkError> {
        if observations.len() < usize::from(self.minimum_quorum)
            || observations.len() > MAX_LIGHT_NODE_OBSERVATIONS
        {
            return Err(WalletSdkError::InvalidObservation);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletSdkError::InvalidPersistedState)?;
        let status_core = MobileWalletCore {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            chain_id_hex: self.chain_id_hex.clone(),
            genesis_hash_hex: self.genesis_hash_hex.clone(),
            maximum_freshness_ms: self.maximum_freshness_ms,
        };
        let mut endpoint_ids = BTreeSet::new();
        let mut groups = BTreeMap::<(u64, String), (BTreeSet<String>, BTreeSet<String>)>::new();
        for observation in &observations {
            let endpoint_id = parse_hash32(&observation.endpoint_id)
                .map_err(|_| WalletSdkError::InvalidObservation)?;
            let control_cluster = parse_hash32(&observation.control_cluster)
                .map_err(|_| WalletSdkError::InvalidObservation)?;
            if endpoint_id == [0; 32]
                || control_cluster == [0; 32]
                || !endpoint_ids.insert(observation.endpoint_id.clone())
            {
                return Err(WalletSdkError::InvalidObservation);
            }
            let status = verify_status_document(&status_core, &observation.status_json)?;
            if status.finalized_height > state.finalized_height && state.finalized_height > 0 {
                let ancestor = observation
                    .ancestor_hash
                    .as_deref()
                    .ok_or(WalletSdkError::InvalidObservation)?;
                parse_hash32(ancestor).map_err(|_| WalletSdkError::InvalidObservation)?;
                if !constant_time_ascii_eq(ancestor, &state.finalized_hash) {
                    return Err(WalletSdkError::CheckpointConflict);
                }
            } else if let Some(ancestor) = observation.ancestor_hash.as_deref() {
                parse_hash32(ancestor).map_err(|_| WalletSdkError::InvalidObservation)?;
            }
            let group = groups
                .entry((status.finalized_height, status.finalized_hash))
                .or_default();
            group.0.insert(observation.control_cluster.clone());
            group.1.insert(observation.endpoint_id.clone());
        }

        let quorum = usize::from(self.minimum_quorum);
        let mut eligible: Vec<_> = groups
            .iter()
            .filter(|(_, (clusters, _))| clusters.len() >= quorum)
            .collect();
        if eligible.is_empty() {
            return Err(WalletSdkError::InsufficientQuorum);
        }
        eligible.sort_by(|left, right| left.0.cmp(right.0));
        let highest_height = eligible
            .last()
            .map(|((height, _), _)| *height)
            .ok_or(WalletSdkError::InsufficientQuorum)?;
        let highest: Vec<_> = eligible
            .into_iter()
            .filter(|((height, _), _)| *height == highest_height)
            .collect();
        if highest.len() != 1 {
            return Err(WalletSdkError::CheckpointConflict);
        }
        let ((candidate_height, candidate_hash), (clusters, endpoints)) = highest[0];
        if *candidate_height < state.finalized_height {
            return Err(WalletSdkError::CheckpointRegression);
        }
        if *candidate_height == state.finalized_height
            && !constant_time_ascii_eq(candidate_hash, &state.finalized_hash)
        {
            return Err(WalletSdkError::CheckpointConflict);
        }
        let advanced = *candidate_height > state.finalized_height;
        if advanced {
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or(WalletSdkError::InvalidPersistedState)?;
            state.finalized_height = *candidate_height;
            state.finalized_hash = candidate_hash.clone();
            state.history.push(LightCheckpoint {
                height: *candidate_height,
                hash: candidate_hash.clone(),
            });
            if state.history.len() > MAX_LIGHT_NODE_HISTORY {
                let excess = state.history.len().saturating_sub(MAX_LIGHT_NODE_HISTORY);
                state.history.drain(..excess);
            }
        }
        let persisted_state_json = serialize_light_node_state(self, &state)?;
        Ok(MobileNodeSyncOutcome {
            advanced,
            total_observations: u32::try_from(observations.len())
                .map_err(|_| WalletSdkError::InvalidObservation)?,
            quorum_endpoints: u32::try_from(endpoints.len())
                .map_err(|_| WalletSdkError::InvalidObservation)?,
            quorum_control_clusters: u32::try_from(clusters.len())
                .map_err(|_| WalletSdkError::InvalidObservation)?,
            snapshot: light_node_snapshot(self, &state),
            persisted_state_json,
        })
    }
}

fn light_node_checksum(
    chain_id: &str,
    genesis_hash: &str,
    minimum_quorum: u8,
    state: &LightNodeState,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LIGHT_NODE_CHECKSUM_DOMAIN);
    hasher.update(chain_id.as_bytes());
    hasher.update(genesis_hash.as_bytes());
    hasher.update(&[minimum_quorum]);
    hasher.update(&state.finalized_height.to_le_bytes());
    hasher.update(state.finalized_hash.as_bytes());
    hasher.update(&state.sequence.to_le_bytes());
    hasher.update(
        &u32::try_from(state.history.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for checkpoint in &state.history {
        hasher.update(&checkpoint.height.to_le_bytes());
        hasher.update(checkpoint.hash.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn serialize_light_node_state(
    node: &MobileLightNode,
    state: &LightNodeState,
) -> Result<String, WalletSdkError> {
    let document = PersistedLightNodeState {
        schema: LIGHT_NODE_SCHEMA.to_owned(),
        chain_id: node.chain_id_hex.clone(),
        genesis_hash: node.genesis_hash_hex.clone(),
        minimum_control_cluster_quorum: node.minimum_quorum,
        finalized_height: state.finalized_height,
        finalized_hash: state.finalized_hash.clone(),
        sequence: state.sequence,
        history: state.history.clone(),
        checksum: light_node_checksum(
            &node.chain_id_hex,
            &node.genesis_hash_hex,
            node.minimum_quorum,
            state,
        ),
    };
    serde_json::to_string(&document).map_err(|_| WalletSdkError::InvalidPersistedState)
}

fn parse_light_node_state(
    raw: &str,
    expected_chain_id: &str,
    expected_genesis_hash: &str,
    expected_quorum: u8,
) -> Result<LightNodeState, WalletSdkError> {
    if raw.is_empty() || raw.len() > MAX_JSON_BYTES {
        return Err(WalletSdkError::InvalidPersistedState);
    }
    let document: PersistedLightNodeState =
        serde_json::from_str(raw).map_err(|_| WalletSdkError::InvalidPersistedState)?;
    if document.schema != LIGHT_NODE_SCHEMA
        || document.chain_id != expected_chain_id
        || document.genesis_hash != expected_genesis_hash
        || document.minimum_control_cluster_quorum != expected_quorum
        || document.history.is_empty()
        || document.history.len() > MAX_LIGHT_NODE_HISTORY
        || parse_hash32(&document.finalized_hash).is_err()
    {
        return Err(WalletSdkError::InvalidPersistedState);
    }
    let mut previous_height = None;
    for checkpoint in &document.history {
        if parse_hash32(&checkpoint.hash).is_err()
            || previous_height.is_some_and(|height| checkpoint.height <= height)
        {
            return Err(WalletSdkError::InvalidPersistedState);
        }
        previous_height = Some(checkpoint.height);
    }
    let Some(last) = document.history.last() else {
        return Err(WalletSdkError::InvalidPersistedState);
    };
    if last.height != document.finalized_height
        || last.hash != document.finalized_hash
        || document.sequence
            < u64::try_from(document.history.len().saturating_sub(1))
                .map_err(|_| WalletSdkError::InvalidPersistedState)?
    {
        return Err(WalletSdkError::InvalidPersistedState);
    }
    if document.history[0].height == 0 && document.history[0].hash != expected_genesis_hash {
        return Err(WalletSdkError::InvalidPersistedState);
    }
    let state = LightNodeState {
        finalized_height: document.finalized_height,
        finalized_hash: document.finalized_hash,
        sequence: document.sequence,
        history: document.history,
    };
    let expected_checksum = light_node_checksum(
        expected_chain_id,
        expected_genesis_hash,
        expected_quorum,
        &state,
    );
    if !constant_time_ascii_eq(&document.checksum, &expected_checksum) {
        return Err(WalletSdkError::InvalidPersistedState);
    }
    Ok(state)
}

fn light_node_snapshot(node: &MobileLightNode, state: &LightNodeState) -> MobileNodeSnapshot {
    MobileNodeSnapshot {
        chain_id: node.chain_id_hex.clone(),
        genesis_hash: node.genesis_hash_hex.clone(),
        finalized_height: state.finalized_height,
        finalized_hash: state.finalized_hash.clone(),
        sequence: state.sequence,
        minimum_control_cluster_quorum: node.minimum_quorum,
        trust_model: LIGHT_NODE_TRUST_MODEL.to_owned(),
        retained_checkpoints: u32::try_from(state.history.len()).unwrap_or(u32::MAX),
        state_checksum: light_node_checksum(
            &node.chain_id_hex,
            &node.genesis_hash_hex,
            node.minimum_quorum,
            state,
        ),
        required_ancestor_height: (state.finalized_height > 0).then_some(state.finalized_height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn core() -> Arc<MobileWalletCore> {
        MobileWalletCore::new("11".repeat(32), "22".repeat(32), "v1".to_owned(), 5_000).unwrap()
    }

    fn point(height: u64, byte: &str) -> Value {
        json!({
            "height": height.to_string(),
            "hash": byte.repeat(32),
            "state_root": "44".repeat(32),
        })
    }

    fn status(height: u64) -> String {
        json!({
            "readiness": "ready",
            "ready": true,
            "indexed_generation": "7",
            "chain_id": "11".repeat(32),
            "genesis_hash": "22".repeat(32),
            "protocol_version": "v1",
            "api_version": "v1",
            "release_version": "test",
            "unsafe_head": point(height, "33"),
            "justified": point(height, "55"),
            "finalized": point(height, "66"),
            "freshness_ms": "1",
            "evidence_registry_root": "77".repeat(32),
        })
        .to_string()
    }

    fn transfer_fixture() -> (Vec<u8>, String, String) {
        let seed = vec![0x42; 64];
        let payer = hex::encode(
            derive_wallet_authority(&seed, Purpose::Sign, 0, 0)
                .unwrap()
                .into_spending_key()
                .unwrap()
                .verifying_key(),
        );
        let spec = json!({
            "expiry_height": "20",
            "fee_payer": payer,
            "fee_authorization": null,
            "resource_limits": {
                "bytes": "10000",
                "grain_steps": "0",
                "proof_units": "0",
                "state_reads": "10",
                "state_writes": "10",
                "blob_bytes": "0"
            },
            "note_inputs": ["88".repeat(32)],
            "account_inputs": [payer],
            "object_access_list": [],
            "actions": [],
            "outputs": [{
                "asset_id": "99".repeat(32),
                "amount": "50",
                "lock_root": "aa".repeat(32),
                "datum_root": "bb".repeat(32),
                "birth_height": "11",
                "relative_timelock": "0",
                "memo_commitment": "cc".repeat(32)
            }],
            "evidence_refs": [],
            "lock_reveals": ["00"]
        });
        let notes = json!([{
            "note_id": "88".repeat(32),
            "asset_id": "99".repeat(32),
            "amount": "50",
            "created_height": "1",
            "spent": false
        }]);
        (seed, spec.to_string(), notes.to_string())
    }

    #[test]
    fn profile_and_status_gate_fail_closed() {
        assert_eq!(
            MobileWalletCore::new("AA".repeat(32), "22".repeat(32), "v1".into(), 1).unwrap_err(),
            WalletSdkError::InvalidProfile
        );
        let core = core();
        let verified = core.verify_status(status(10)).unwrap();
        assert_eq!(verified.next_output_birth_height, 11);
        let mut wrong: Value = serde_json::from_str(&status(10)).unwrap();
        wrong["chain_id"] = json!("ff".repeat(32));
        assert_eq!(
            core.verify_status(wrong.to_string()).unwrap_err(),
            WalletSdkError::WrongProtocolIdentity
        );
        let mut stale: Value = serde_json::from_str(&status(10)).unwrap();
        stale["freshness_ms"] = json!("5001");
        assert_eq!(
            core.verify_status(stale.to_string()).unwrap_err(),
            WalletSdkError::StaleStatus
        );
        let mut rebuilding: Value = serde_json::from_str(&status(10)).unwrap();
        rebuilding["ready"] = json!(false);
        rebuilding["readiness"] = json!("rebuilding");
        assert_eq!(
            core.verify_status(rebuilding.to_string()).unwrap_err(),
            WalletSdkError::IndexerUnavailable
        );
    }

    #[test]
    fn derivation_returns_only_public_material() {
        let derived = core()
            .derive_authority(vec![0x42; 64], "sign".into(), None, 0, 0)
            .unwrap();
        assert_eq!(derived.path.len(), 5);
        assert_eq!(derived.path_bytes_hex.len(), 40);
        assert_eq!(derived.public_id.len(), 64);
        assert_eq!(derived.verifying_key.unwrap().len(), 64);
        let view = core()
            .derive_authority(vec![0x42; 64], "view".into(), None, 0, 0)
            .unwrap();
        assert_eq!(view.verifying_key, None);
    }

    #[test]
    fn review_and_sign_recompute_the_exact_consent_boundary() {
        let core = core();
        let (seed, spec, notes) = transfer_fixture();
        let review = core
            .review_transfer(spec.clone(), status(10), notes.clone())
            .unwrap();
        assert_eq!(review.note_inputs, vec!["88".repeat(32)]);
        assert_eq!(review.input_totals, review.output_totals);
        assert_eq!(review.outputs[0].birth_height, 11);
        let signed = core
            .sign_reviewed_transfer(
                seed.clone(),
                0,
                0,
                0,
                spec.clone(),
                status(10),
                notes.clone(),
                review.review_id.clone(),
            )
            .unwrap();
        assert_eq!(signed.txid, review.txid);
        let envelope: Value = serde_json::from_str(&signed.submission_json).unwrap();
        let transaction = TransactionV1::decode_canonical(
            &hex::decode(envelope["tx"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let witnesses = TransactionWitnessesV1::decode_canonical(
            &hex::decode(envelope["witnesses"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(witnesses.intents.len(), 1);
        assert_eq!(
            witnesses.intents.as_slice()[0].tx_commitment,
            lumen_txid(&transaction)
        );
        assert_eq!(
            core.sign_reviewed_transfer(seed, 0, 0, 0, spec, status(10), notes, "00".repeat(32),)
                .unwrap_err(),
            WalletSdkError::ReviewMismatch
        );
    }

    #[test]
    fn note_conservation_and_birth_height_are_mandatory() {
        let core = core();
        let (_, spec, notes) = transfer_fixture();
        let mut inflated: Value = serde_json::from_str(&spec).unwrap();
        inflated["outputs"][0]["amount"] = json!("51");
        assert_eq!(
            core.review_transfer(inflated.to_string(), status(10), notes.clone())
                .unwrap_err(),
            WalletSdkError::InsufficientFunds
        );
        let mut wrong_birth: Value = serde_json::from_str(&spec).unwrap();
        wrong_birth["outputs"][0]["birth_height"] = json!("12");
        assert_eq!(
            core.review_transfer(wrong_birth.to_string(), status(10), notes)
                .unwrap_err(),
            WalletSdkError::InvalidTransaction
        );
    }

    #[test]
    fn submission_response_must_match_local_txid_and_state() {
        let core = core();
        let txid = "ab".repeat(32);
        let accepted = core
            .validate_submission_response(
                txid.clone(),
                json!({"txid": txid, "state": "MEMPOOL"}).to_string(),
            )
            .unwrap();
        assert_eq!(accepted.state, "MEMPOOL");
        assert_eq!(
            core.validate_submission_response(
                "ab".repeat(32),
                json!({"txid": "cd".repeat(32), "state": "MEMPOOL"}).to_string(),
            )
            .unwrap_err(),
            WalletSdkError::TxidMismatch
        );
        assert_eq!(
            core.validate_submission_response(
                "ab".repeat(32),
                json!({"txid": "ab".repeat(32), "state": "REJECTED"}).to_string(),
            )
            .unwrap_err(),
            WalletSdkError::SubmissionRejected
        );
    }

    fn light_node(persisted: Option<String>, quorum: u8) -> Arc<MobileLightNode> {
        MobileLightNode::new(
            "11".repeat(32),
            "22".repeat(32),
            "v1".to_owned(),
            5_000,
            quorum,
            persisted,
        )
        .unwrap()
    }

    fn observation(
        endpoint_byte: &str,
        cluster_byte: &str,
        height: u64,
        finalized_byte: &str,
        ancestor_hash: Option<String>,
    ) -> EndpointStatusObservation {
        let mut document: Value = serde_json::from_str(&status(height)).unwrap();
        document["finalized"]["hash"] = json!(finalized_byte.repeat(32));
        EndpointStatusObservation {
            endpoint_id: endpoint_byte.repeat(32),
            control_cluster: cluster_byte.repeat(32),
            status_json: document.to_string(),
            ancestor_hash,
        }
    }

    #[test]
    fn mobile_light_node_advances_only_on_distinct_control_cluster_quorum() {
        let node = light_node(None, 2);
        let outcome = node
            .observe_finalized(vec![
                observation("01", "a1", 10, "90", None),
                observation("02", "b2", 10, "90", None),
                observation("03", "c3", 10, "90", None),
            ])
            .unwrap();
        assert!(outcome.advanced);
        assert_eq!(outcome.snapshot.finalized_height, 10);
        assert_eq!(outcome.snapshot.finalized_hash, "90".repeat(32));
        assert_eq!(outcome.quorum_control_clusters, 3);
        assert_eq!(
            outcome.snapshot.trust_model,
            "MULTI_CONTROL_CLUSTER_FINALIZED_QUORUM"
        );

        let resumed = light_node(Some(outcome.persisted_state_json), 2);
        assert_eq!(resumed.snapshot().unwrap().finalized_height, 10);
        let ancestor = Some("90".repeat(32));
        let advanced = resumed
            .observe_finalized(vec![
                observation("04", "a1", 12, "91", ancestor.clone()),
                observation("05", "b2", 12, "91", ancestor),
            ])
            .unwrap();
        assert!(advanced.advanced);
        assert_eq!(advanced.snapshot.sequence, 2);
        assert_eq!(advanced.snapshot.required_ancestor_height, Some(12));
    }

    #[test]
    fn mobile_light_node_rejects_cluster_aliases_conflicts_and_regressions() {
        let node = light_node(None, 2);
        assert_eq!(
            node.observe_finalized(vec![
                observation("01", "a1", 10, "90", None),
                observation("02", "a1", 10, "90", None),
            ])
            .unwrap_err(),
            WalletSdkError::InsufficientQuorum
        );
        assert_eq!(
            node.observe_finalized(vec![
                observation("03", "a1", 10, "90", None),
                observation("04", "b2", 10, "90", None),
                observation("05", "c3", 10, "91", None),
                observation("06", "d4", 10, "91", None),
            ])
            .unwrap_err(),
            WalletSdkError::CheckpointConflict
        );
        node.observe_finalized(vec![
            observation("07", "a1", 10, "90", None),
            observation("08", "b2", 10, "90", None),
        ])
        .unwrap();
        assert_eq!(
            node.observe_finalized(vec![
                observation("09", "a1", 9, "80", None),
                observation("0a", "b2", 9, "80", None),
            ])
            .unwrap_err(),
            WalletSdkError::CheckpointRegression
        );
        assert_eq!(
            node.observe_finalized(vec![
                observation("0b", "a1", 11, "92", Some("ff".repeat(32))),
                observation("0c", "b2", 11, "92", Some("90".repeat(32))),
            ])
            .unwrap_err(),
            WalletSdkError::CheckpointConflict
        );
    }

    #[test]
    fn mobile_light_node_persisted_state_detects_corruption_and_wrong_identity() {
        let node = light_node(None, 2);
        let outcome = node
            .observe_finalized(vec![
                observation("01", "a1", 10, "90", None),
                observation("02", "b2", 10, "90", None),
            ])
            .unwrap();
        let mut corrupted: Value = serde_json::from_str(&outcome.persisted_state_json).unwrap();
        corrupted["finalized_height"] = json!(11);
        assert_eq!(
            MobileLightNode::new(
                "11".repeat(32),
                "22".repeat(32),
                "v1".to_owned(),
                5_000,
                2,
                Some(corrupted.to_string()),
            )
            .unwrap_err(),
            WalletSdkError::InvalidPersistedState
        );
        assert_eq!(
            MobileLightNode::new(
                "33".repeat(32),
                "22".repeat(32),
                "v1".to_owned(),
                5_000,
                2,
                Some(outcome.persisted_state_json),
            )
            .unwrap_err(),
            WalletSdkError::InvalidPersistedState
        );
    }
}
