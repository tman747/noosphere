//! Wallet shell operations. Canonical transaction serialization is delegated
//! to `noos-cli`/`noos-lumen`; this layer owns profile selection, live public
//! API identity/funds checks, and fail-closed submission semantics.

use noos_codec::NoosDecode;
use noos_lumen::objects::{txid as lumen_txid, TransactionV1, TransactionWitnessesV1};
use noos_wallet::{derivation_path, derive_authority, Purpose, WalletError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

const API_VERSION: &str = "v1";
const PROTOCOL_VERSION: &str = "v1";
const STATUS_PATH: &str = "/api/status";
const SUBMIT_PATH: &str = "/api/v1/transactions";
const MAX_RESPONSE_BYTES: usize = 1_048_576;
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

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpsError {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("unknown_chain_profile")]
    UnknownChainProfile,
    #[error("network_failure")]
    NetworkFailure,
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
    #[error("submission_rejected")]
    SubmissionRejected,
    #[error("malformed_submit_response")]
    MalformedSubmitResponse,
    #[error("txid_mismatch")]
    TxidMismatch,
    #[error("{0}")]
    Wallet(WalletError),
}

impl From<WalletError> for OpsError {
    fn from(value: WalletError) -> Self {
        Self::Wallet(value)
    }
}

fn parse_hash32(value: &str) -> Result<[u8; 32], OpsError> {
    if value.len() != 64 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(OpsError::InvalidRequest);
    }
    hex::decode(value)
        .map_err(|_| OpsError::InvalidRequest)?
        .try_into()
        .map_err(|_| OpsError::InvalidRequest)
}

fn parse_seed(seed_hex: &str) -> Result<Vec<u8>, OpsError> {
    if seed_hex.is_empty()
        || seed_hex.len() % 2 != 0
        || seed_hex.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(OpsError::InvalidRequest);
    }
    hex::decode(seed_hex).map_err(|_| OpsError::InvalidRequest)
}

fn parse_decimal_u64(value: &str) -> Result<u64, OpsError> {
    if value.is_empty()
        || value.bytes().any(|b| !b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(OpsError::InvalidRequest);
    }
    value.parse().map_err(|_| OpsError::InvalidRequest)
}

fn parse_decimal_u128(value: &str) -> Result<u128, OpsError> {
    if value.is_empty()
        || value.bytes().any(|b| !b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(OpsError::InvalidRequest);
    }
    value.parse().map_err(|_| OpsError::InvalidRequest)
}

fn parse_purpose(purpose: &str, suite: Option<u32>) -> Result<Purpose, OpsError> {
    match (purpose, suite) {
        ("sign", None) => Ok(Purpose::Sign),
        ("view", None) => Ok(Purpose::View),
        ("umbra", Some(suite)) => Ok(Purpose::Umbra { suite }),
        ("agent", None) => Ok(Purpose::Agent),
        ("recovery", None) => Ok(Purpose::Recovery),
        _ => Err(OpsError::InvalidRequest),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainProfile {
    pub id: String,
    pub label: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub api_version: String,
    pub api_base_url: String,
    pub max_freshness_ms: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainProfilesFile {
    schema: String,
    profiles: Vec<ChainProfile>,
}

pub fn chain_profiles() -> Result<Vec<ChainProfile>, OpsError> {
    let configured: ChainProfilesFile =
        serde_json::from_str(include_str!("../../../chain-profiles.json"))
            .map_err(|_| OpsError::InvalidRequest)?;
    if configured.schema != "noos-wallet-chain-profiles-v1" || configured.profiles.is_empty() {
        return Err(OpsError::InvalidRequest);
    }
    let mut ids = BTreeSet::new();
    for profile in &configured.profiles {
        if profile.id.is_empty()
            || profile.label.is_empty()
            || !ids.insert(profile.id.as_str())
            || parse_hash32(&profile.chain_id).is_err()
            || parse_hash32(&profile.genesis_hash).is_err()
            || profile.api_version != API_VERSION
            || (!profile.api_base_url.starts_with("https://")
                && !profile.api_base_url.starts_with("http://127.0.0.1:"))
            || profile.api_base_url.ends_with('/')
            || parse_decimal_u64(&profile.max_freshness_ms).is_err()
        {
            return Err(OpsError::InvalidRequest);
        }
    }
    Ok(configured.profiles)
}

fn chain_profile(id: &str) -> Result<ChainProfile, OpsError> {
    chain_profiles()?
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or(OpsError::UnknownChainProfile)
}

#[derive(Clone, Debug)]
pub struct DeriveRequest {
    pub seed_hex: Zeroizing<String>,
    pub purpose: String,
    pub suite: Option<u32>,
    pub account: u32,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveResponse {
    pub path: Vec<String>,
    pub bytes: String,
    pub public_id: String,
    pub verifying_key: Option<String>,
}

/// Derive an authority and return only public identifiers.
pub fn derive(req: &DeriveRequest) -> Result<DeriveResponse, OpsError> {
    let purpose = parse_purpose(&req.purpose, req.suite)?;
    let seed = Zeroizing::new(parse_seed(&req.seed_hex)?);
    let path = derivation_path(purpose, req.account, req.index)?;
    let mut bytes = String::with_capacity(path.len().saturating_mul(8));
    let mut path_hex = Vec::with_capacity(path.len());
    for component in &path {
        let encoded = hex::encode(component.to_be_bytes());
        bytes.push_str(&encoded);
        path_hex.push(format!("0x{encoded}"));
    }
    let authority = derive_authority(&seed, purpose, req.account, req.index)?;
    let public_id = hex::encode(authority.public_id());
    let verifying_key = if purpose.can_spend() {
        Some(hex::encode(authority.into_spending_key()?.verifying_key()))
    } else {
        None
    };
    Ok(DeriveResponse {
        path: path_hex,
        bytes,
        public_id,
        verifying_key,
    })
}

#[derive(Debug)]
pub struct SubmitRequest {
    pub profile_id: String,
    pub seed_hex: Zeroizing<String>,
    pub account: u32,
    pub index: u32,
    pub signer_scope: u8,
    /// Complete Lumen v1 JSON spec except `chain_id`, `format_version`, and
    /// `witness_root`, which are profile-bound/protocol-computed fields.
    pub transaction_spec: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitResponse {
    /// Always copied from the successful upstream response after matching the
    /// locally computed canonical txid.
    pub txid: String,
    /// Always copied from the successful upstream response.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStatusResponse {
    pub unsafe_height: String,
    pub next_output_birth_height: String,
    pub freshness_ms: String,
}

#[derive(Debug, Clone)]
struct HttpReply {
    status: u16,
    body: String,
}

trait PublicApiClient {
    fn get(&mut self, url: &str) -> Result<HttpReply, OpsError>;
    fn post_json(&mut self, url: &str, body: &Value) -> Result<HttpReply, OpsError>;
}

struct LivePublicApiClient;

impl LivePublicApiClient {
    fn finish(response: attohttpc::Response) -> Result<HttpReply, OpsError> {
        let status = response.status().as_u16();
        let bytes = response.bytes().map_err(|_| OpsError::NetworkFailure)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(OpsError::NetworkFailure);
        }
        let body = String::from_utf8(bytes).map_err(|_| OpsError::NetworkFailure)?;
        Ok(HttpReply { status, body })
    }
}

impl PublicApiClient for LivePublicApiClient {
    fn get(&mut self, url: &str) -> Result<HttpReply, OpsError> {
        let response = attohttpc::get(url)
            .header("Accept", "application/vnd.noos.v1+json, application/json")
            .follow_redirects(false)
            .timeout(Duration::from_secs(10))
            .send()
            .map_err(|_| OpsError::NetworkFailure)?;
        Self::finish(response)
    }

    fn post_json(&mut self, url: &str, body: &Value) -> Result<HttpReply, OpsError> {
        let request = attohttpc::post(url)
            .header("Accept", "application/vnd.noos.v1+json, application/json")
            .follow_redirects(false)
            .timeout(Duration::from_secs(10))
            .json(body)
            .map_err(|_| OpsError::InvalidRequest)?;
        Self::finish(request.send().map_err(|_| OpsError::NetworkFailure)?)
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

impl LiveStatus {
    fn unsafe_height(&self) -> Result<u64, OpsError> {
        parse_decimal_u64(&self.unsafe_head.height).map_err(|_| OpsError::MalformedStatus)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveNote {
    note_id: String,
    asset_id: String,
    amount: String,
    created_height: String,
    spent: bool,
}

#[derive(Debug)]
struct SignedEnvelope {
    tx: String,
    witnesses: String,
    txid: String,
    transaction: TransactionV1,
}

fn endpoint(profile: &ChainProfile, path: &str) -> String {
    format!("{}{path}", profile.api_base_url)
}

fn fetch_status(
    profile: &ChainProfile,
    client: &mut impl PublicApiClient,
) -> Result<LiveStatus, OpsError> {
    let reply = client.get(&endpoint(profile, STATUS_PATH))?;
    if reply.status != 200 {
        return Err(OpsError::NetworkFailure);
    }
    let status: LiveStatus =
        serde_json::from_str(&reply.body).map_err(|_| OpsError::MalformedStatus)?;
    if status.ready == Some(false)
        || status
            .readiness
            .as_deref()
            .is_some_and(|readiness| readiness != "ready")
    {
        return Err(OpsError::IndexerUnavailable);
    }
    if status
        .indexed_generation
        .as_deref()
        .is_some_and(|generation| parse_decimal_u64(generation).is_err())
    {
        return Err(OpsError::MalformedStatus);
    }
    for hash in [
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
        parse_hash32(hash).map_err(|_| OpsError::MalformedStatus)?;
    }
    parse_decimal_u64(&status.justified.height).map_err(|_| OpsError::MalformedStatus)?;
    parse_decimal_u64(&status.finalized.height).map_err(|_| OpsError::MalformedStatus)?;
    if status.release_version.is_empty() {
        return Err(OpsError::MalformedStatus);
    }
    if status.chain_id != profile.chain_id
        || status.genesis_hash != profile.genesis_hash
        || status.protocol_version != PROTOCOL_VERSION
        || status.api_version != profile.api_version
    {
        return Err(OpsError::WrongProtocolIdentity);
    }
    let freshness =
        parse_decimal_u64(&status.freshness_ms).map_err(|_| OpsError::MalformedStatus)?;
    let maximum =
        parse_decimal_u64(&profile.max_freshness_ms).map_err(|_| OpsError::InvalidRequest)?;
    if freshness > maximum {
        return Err(OpsError::StaleStatus);
    }
    Ok(status)
}

fn complete_spec(raw: &str, profile: &ChainProfile) -> Result<(Value, Vec<String>), OpsError> {
    let mut spec: Map<String, Value> = serde_json::from_str::<Value>(raw)
        .map_err(|_| OpsError::InvalidRequest)?
        .as_object()
        .cloned()
        .ok_or(OpsError::InvalidRequest)?;
    let allowed: BTreeSet<&str> = REQUIRED_SPEC_FIELDS.into_iter().collect();
    if spec.len() != allowed.len()
        || spec.keys().any(|key| !allowed.contains(key.as_str()))
        || allowed.iter().any(|key| !spec.contains_key(*key))
    {
        return Err(OpsError::InvalidRequest);
    }
    let reveals = spec
        .get("lock_reveals")
        .and_then(Value::as_array)
        .ok_or(OpsError::InvalidRequest)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(OpsError::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    spec.insert("chain_id".into(), Value::String(profile.chain_id.clone()));
    spec.insert("format_version".into(), Value::Number(1u64.into()));
    Ok((Value::Object(spec), reveals))
}

fn strict_note_shape(transaction: &TransactionV1, reveal_count: usize) -> Result<(), OpsError> {
    let unique_accounts: BTreeSet<_> = transaction.account_inputs.iter().collect();
    if transaction.account_inputs.len() != 1
        || unique_accounts.len() != transaction.account_inputs.len()
        || transaction.account_inputs.as_slice()[0] != transaction.fee_payer
    {
        // Lumen carries no explicit nonce: each declared account input consumes
        // exactly nonce+1, so this one-intent wallet must declare one payer once.
        return Err(OpsError::NonceBoundary);
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
        return Err(OpsError::InvalidTransaction);
    }
    let unique_notes: BTreeSet<_> = transaction.note_inputs.iter().collect();
    if unique_notes.len() != transaction.note_inputs.len() {
        return Err(OpsError::InvalidTransaction);
    }
    Ok(())
}

fn validate_height_and_fee(
    transaction: &TransactionV1,
    encoded_len: usize,
    status: &LiveStatus,
) -> Result<(), OpsError> {
    let unsafe_height = status.unsafe_height()?;
    let birth_height = unsafe_height
        .checked_add(1)
        .ok_or(OpsError::InvalidTransaction)?;
    if transaction.expiry_height <= unsafe_height
        || transaction
            .outputs
            .iter()
            .any(|output| output.birth_height != birth_height)
    {
        return Err(OpsError::InvalidTransaction);
    }
    let encoded_len = u64::try_from(encoded_len).map_err(|_| OpsError::FeeBoundary)?;
    if transaction.resource_limits.bytes < encoded_len {
        return Err(OpsError::FeeBoundary);
    }
    Ok(())
}

fn fetch_note(
    profile: &ChainProfile,
    note_id: &[u8; 32],
    client: &mut impl PublicApiClient,
) -> Result<LiveNote, OpsError> {
    let id = hex::encode(note_id);
    let reply = client.get(&endpoint(profile, &format!("/api/v1/notes/{id}")))?;
    if reply.status != 200 {
        return Err(OpsError::InsufficientFunds);
    }
    let note: LiveNote =
        serde_json::from_str(&reply.body).map_err(|_| OpsError::InsufficientFunds)?;
    if note.note_id != id
        || parse_hash32(&note.asset_id).is_err()
        || parse_decimal_u64(&note.created_height).is_err()
        || note.spent
    {
        return Err(OpsError::InsufficientFunds);
    }
    parse_decimal_u128(&note.amount).map_err(|_| OpsError::InsufficientFunds)?;
    Ok(note)
}

fn validate_note_funds(
    profile: &ChainProfile,
    transaction: &TransactionV1,
    client: &mut impl PublicApiClient,
) -> Result<(), OpsError> {
    let mut inputs = BTreeMap::<[u8; 32], u128>::new();
    for note_id in transaction.note_inputs.iter() {
        let note = fetch_note(profile, note_id, client)?;
        let asset = parse_hash32(&note.asset_id).map_err(|_| OpsError::InsufficientFunds)?;
        let amount = parse_decimal_u128(&note.amount).map_err(|_| OpsError::InsufficientFunds)?;
        let total = inputs.entry(asset).or_default();
        *total = total
            .checked_add(amount)
            .ok_or(OpsError::InsufficientFunds)?;
    }
    let mut outputs = BTreeMap::<[u8; 32], u128>::new();
    for note in transaction.outputs.iter() {
        let total = outputs.entry(note.asset_id).or_default();
        *total = total
            .checked_add(note.amount)
            .ok_or(OpsError::InsufficientFunds)?;
    }
    if inputs != outputs {
        return Err(OpsError::InsufficientFunds);
    }
    Ok(())
}

fn build_signed(
    req: &SubmitRequest,
    profile: &ChainProfile,
    status: &LiveStatus,
    client: &mut impl PublicApiClient,
) -> Result<SignedEnvelope, OpsError> {
    let (spec, reveals) = complete_spec(&req.transaction_spec, profile)?;
    let built = noos_cli::tx_build(&spec.to_string()).map_err(|_| OpsError::InvalidTransaction)?;
    let tx_hex = built["tx"]
        .as_str()
        .ok_or(OpsError::InvalidTransaction)?
        .to_owned();
    let tx_bytes = hex::decode(&tx_hex).map_err(|_| OpsError::InvalidTransaction)?;
    let transaction =
        TransactionV1::decode_canonical(&tx_bytes).map_err(|_| OpsError::InvalidTransaction)?;
    if transaction.chain_id != parse_hash32(&profile.chain_id)? {
        return Err(OpsError::WrongProtocolIdentity);
    }
    strict_note_shape(&transaction, reveals.len())?;
    validate_height_and_fee(&transaction, tx_bytes.len(), status)?;
    validate_note_funds(profile, &transaction, client)?;

    let signed = noos_cli::tx_sign(
        &tx_hex,
        &req.seed_hex,
        req.account,
        req.index,
        &profile.chain_id,
        &profile.genesis_hash,
        req.signer_scope,
        &reveals,
    )
    .map_err(|_| OpsError::InvalidTransaction)?;
    let verifying_key = signed["verifying_key"]
        .as_str()
        .ok_or(OpsError::InvalidTransaction)?;
    if parse_hash32(verifying_key)? != transaction.fee_payer {
        return Err(OpsError::NonceBoundary);
    }
    let witnesses = signed["witnesses"]
        .as_str()
        .ok_or(OpsError::InvalidTransaction)?
        .to_owned();
    let witness_bytes = hex::decode(&witnesses).map_err(|_| OpsError::InvalidTransaction)?;
    let decoded_witnesses = TransactionWitnessesV1::decode_canonical(&witness_bytes)
        .map_err(|_| OpsError::InvalidTransaction)?;
    let local_txid = hex::encode(lumen_txid(&transaction));
    if decoded_witnesses.intents.len() != 1
        || decoded_witnesses.intents.as_slice()[0].tx_commitment != lumen_txid(&transaction)
        || signed["txid"].as_str() != Some(local_txid.as_str())
    {
        return Err(OpsError::InvalidTransaction);
    }
    Ok(SignedEnvelope {
        tx: tx_hex,
        witnesses,
        txid: local_txid,
        transaction,
    })
}

fn parse_submit_response(
    reply: HttpReply,
    expected_txid: &str,
) -> Result<SubmitResponse, OpsError> {
    if reply.status != 200 && reply.status != 202 {
        return Err(OpsError::SubmissionRejected);
    }
    let value: Value =
        serde_json::from_str(&reply.body).map_err(|_| OpsError::MalformedSubmitResponse)?;
    let object = value.as_object().ok_or(OpsError::MalformedSubmitResponse)?;
    let txid = object
        .get("txid")
        .and_then(Value::as_str)
        .ok_or(OpsError::MalformedSubmitResponse)?;
    let state = object
        .get("state")
        .and_then(Value::as_str)
        .ok_or(OpsError::MalformedSubmitResponse)?;
    if parse_hash32(txid).is_err() {
        return Err(OpsError::MalformedSubmitResponse);
    }
    if txid != expected_txid {
        return Err(OpsError::TxidMismatch);
    }
    if !matches!(state, "MEMPOOL" | "INCLUDED" | "JUSTIFIED" | "FINALIZED") {
        return Err(OpsError::SubmissionRejected);
    }
    Ok(SubmitResponse {
        txid: txid.to_owned(),
        state: state.to_owned(),
    })
}

fn submit_with_client(
    req: &SubmitRequest,
    profile: &ChainProfile,
    client: &mut impl PublicApiClient,
) -> Result<SubmitResponse, OpsError> {
    // First live handshake gates note reads and signing.
    let before_sign = fetch_status(profile, client)?;
    let signed = build_signed(req, profile, &before_sign, client)?;

    // A second live handshake and funds read gate the actual POST. If the head
    // advanced, output birth heights are stale and no bytes leave the wallet.
    let before_submit = fetch_status(profile, client)?;
    validate_height_and_fee(
        &signed.transaction,
        hex::decode(&signed.tx)
            .map_err(|_| OpsError::InvalidTransaction)?
            .len(),
        &before_submit,
    )?;
    validate_note_funds(profile, &signed.transaction, client)?;

    let envelope = json!({"tx": signed.tx, "witnesses": signed.witnesses});
    let reply = client.post_json(&endpoint(profile, SUBMIT_PATH), &envelope)?;
    parse_submit_response(reply, &signed.txid)
}

/// Fetch live identity, build and sign canonical Lumen bytes, re-check live
/// identity/funds, then submit the exact public API envelope.
pub fn submit(req: &SubmitRequest) -> Result<SubmitResponse, OpsError> {
    // Parse once before any network access; seed material never enters an
    // error string, log message, response, or persistent structure.
    let _seed = Zeroizing::new(parse_seed(&req.seed_hex)?);
    let profile = chain_profile(&req.profile_id)?;
    submit_with_client(req, &profile, &mut LivePublicApiClient)
}

/// Fetch and verify the selected profile's live public status without reading
/// wallet state or touching key material.
pub fn check_status(profile_id: &str) -> Result<ChainStatusResponse, OpsError> {
    let profile = chain_profile(profile_id)?;
    let status = fetch_status(&profile, &mut LivePublicApiClient)?;
    let unsafe_height = status.unsafe_height()?;
    Ok(ChainStatusResponse {
        unsafe_height: unsafe_height.to_string(),
        next_output_birth_height: unsafe_height
            .checked_add(1)
            .ok_or(OpsError::MalformedStatus)?
            .to_string(),
        freshness_ms: status.freshness_ms,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct ScriptedClient {
        replies: VecDeque<Result<HttpReply, OpsError>>,
        requests: Vec<(String, String, Option<Value>)>,
    }

    impl ScriptedClient {
        fn reply(&mut self, status: u16, body: Value) {
            self.replies.push_back(Ok(HttpReply {
                status,
                body: body.to_string(),
            }));
        }
    }

    impl PublicApiClient for ScriptedClient {
        fn get(&mut self, url: &str) -> Result<HttpReply, OpsError> {
            self.requests.push(("GET".into(), url.into(), None));
            self.replies
                .pop_front()
                .unwrap_or(Err(OpsError::NetworkFailure))
        }

        fn post_json(&mut self, url: &str, body: &Value) -> Result<HttpReply, OpsError> {
            self.requests
                .push(("POST".into(), url.into(), Some(body.clone())));
            self.replies
                .pop_front()
                .unwrap_or(Err(OpsError::NetworkFailure))
        }
    }

    fn test_profile() -> ChainProfile {
        ChainProfile {
            id: "test".into(),
            label: "Test".into(),
            chain_id: "11".repeat(32),
            genesis_hash: "22".repeat(32),
            api_version: "v1".into(),
            api_base_url: "http://127.0.0.1:18080".into(),
            max_freshness_ms: "5000".into(),
        }
    }

    fn status(profile: &ChainProfile, height: u64) -> Value {
        let point = |height: u64, byte: &str| {
            json!({
                "height": height.to_string(),
                "hash": byte.repeat(32),
                "state_root": "44".repeat(32)
            })
        };
        json!({
            "readiness": "ready",
            "ready": true,
            "indexed_generation": "7",
            "chain_id": profile.chain_id,
            "genesis_hash": profile.genesis_hash,
            "protocol_version": "v1",
            "api_version": "v1",
            "release_version": "test",
            "unsafe_head": point(height, "33"),
            "justified": point(height, "55"),
            "finalized": point(height, "66"),
            "freshness_ms": "1",
            "evidence_registry_root": "77".repeat(32)
        })
    }

    fn test_request(profile: &ChainProfile) -> SubmitRequest {
        let seed_hex = "42".repeat(64);
        let key = derive_authority(&hex::decode(&seed_hex).unwrap(), Purpose::Sign, 0, 0)
            .unwrap()
            .into_spending_key()
            .unwrap();
        let payer = hex::encode(key.verifying_key());
        let note_id = "88".repeat(32);
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
            "note_inputs": [note_id],
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
        SubmitRequest {
            profile_id: profile.id.clone(),
            seed_hex: Zeroizing::new(seed_hex),
            account: 0,
            index: 0,
            signer_scope: 0,
            transaction_spec: spec.to_string(),
        }
    }

    fn note() -> Value {
        json!({
            "note_id": "88".repeat(32),
            "asset_id": "99".repeat(32),
            "amount": "50",
            "created_height": "1",
            "spent": false
        })
    }

    fn build_client(profile: &ChainProfile) -> ScriptedClient {
        let mut client = ScriptedClient::default();
        client.reply(200, status(profile, 10));
        client.reply(200, note());
        client
    }

    #[test]
    fn configured_profiles_expose_all_public_valueless_testnet_indexers() {
        let profiles = chain_profiles().unwrap();
        assert_eq!(profiles.len(), 4);
        assert_eq!(profiles[0].id, "local-live-devnet");
        let public: Vec<_> = profiles
            .iter()
            .filter(|profile| profile.id.starts_with("public-valueless-testnet-"))
            .collect();
        assert_eq!(public.len(), 3);
        assert!(public.iter().all(|profile| {
            profile.chain_id
                == "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b"
                && profile.genesis_hash
                    == "8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e"
                && profile.api_base_url.starts_with("https://")
                && profile.max_freshness_ms == "15000"
        }));
    }

    #[test]
    fn emitted_bytes_decode_as_canonical_lumen_transaction_and_witnesses() {
        let profile = test_profile();
        let req = test_request(&profile);
        let mut client = build_client(&profile);
        let live = fetch_status(&profile, &mut client).unwrap();
        let signed = build_signed(&req, &profile, &live, &mut client).unwrap();
        let tx = TransactionV1::decode_canonical(&hex::decode(&signed.tx).unwrap()).unwrap();
        let witnesses =
            TransactionWitnessesV1::decode_canonical(&hex::decode(&signed.witnesses).unwrap())
                .unwrap();
        assert_eq!(tx.chain_id, [0x11; 32]);
        assert_eq!(witnesses.intents.len(), 1);
        assert_eq!(witnesses.lock_reveals.len(), 1);
        assert_eq!(
            witnesses.intents.as_slice()[0].tx_commitment,
            lumen_txid(&tx)
        );
        assert!(!signed.tx.as_bytes().starts_with(b"NOOS/WALLET/TXBODY/V1"));
    }

    #[test]
    fn identity_mismatch_fails_before_notes_signing_or_submission() {
        let profile = test_profile();
        let req = test_request(&profile);
        let mut wrong = status(&profile, 10);
        wrong["chain_id"] = json!("ff".repeat(32));
        let mut client = ScriptedClient::default();
        client.reply(200, wrong);
        assert_eq!(
            submit_with_client(&req, &profile, &mut client),
            Err(OpsError::WrongProtocolIdentity)
        );
        assert_eq!(client.requests.len(), 1);

        let mut wrong_api = status(&profile, 10);
        wrong_api["api_version"] = json!("v2");
        let mut client = ScriptedClient::default();
        client.reply(200, wrong_api);
        assert_eq!(
            submit_with_client(&req, &profile, &mut client),
            Err(OpsError::WrongProtocolIdentity)
        );
        assert_eq!(client.requests.len(), 1);

        let mut rebuilding = status(&profile, 10);
        rebuilding["readiness"] = json!("rebuilding");
        rebuilding["ready"] = json!(false);
        let mut client = ScriptedClient::default();
        client.reply(200, rebuilding);
        assert_eq!(
            submit_with_client(&req, &profile, &mut client),
            Err(OpsError::IndexerUnavailable)
        );
        assert_eq!(client.requests.len(), 1);
    }

    #[test]
    fn funds_nonce_and_fee_boundaries_fail_closed() {
        let profile = test_profile();

        let mut insufficient = test_request(&profile);
        let mut spec: Value = serde_json::from_str(&insufficient.transaction_spec).unwrap();
        spec["outputs"][0]["amount"] = json!("51");
        insufficient.transaction_spec = spec.to_string();
        let mut client = build_client(&profile);
        let live = fetch_status(&profile, &mut client).unwrap();
        assert_eq!(
            build_signed(&insufficient, &profile, &live, &mut client).unwrap_err(),
            OpsError::InsufficientFunds
        );

        let mut nonce = test_request(&profile);
        let mut spec: Value = serde_json::from_str(&nonce.transaction_spec).unwrap();
        spec["account_inputs"] = json!([spec["fee_payer"].clone(), spec["fee_payer"].clone()]);
        nonce.transaction_spec = spec.to_string();
        let mut client = build_client(&profile);
        let live = fetch_status(&profile, &mut client).unwrap();
        assert_eq!(
            build_signed(&nonce, &profile, &live, &mut client).unwrap_err(),
            OpsError::NonceBoundary
        );

        let mut underpriced = test_request(&profile);
        let mut spec: Value = serde_json::from_str(&underpriced.transaction_spec).unwrap();
        spec["resource_limits"]["bytes"] = json!("1");
        underpriced.transaction_spec = spec.to_string();
        let mut client = build_client(&profile);
        let live = fetch_status(&profile, &mut client).unwrap();
        assert_eq!(
            build_signed(&underpriced, &profile, &live, &mut client).unwrap_err(),
            OpsError::FeeBoundary
        );
    }

    #[test]
    fn exact_envelope_is_posted_and_only_matching_upstream_result_is_returned() {
        let profile = test_profile();
        let req = test_request(&profile);
        let mut client = build_client(&profile);
        let live = fetch_status(&profile, &mut client).unwrap();
        let signed = build_signed(&req, &profile, &live, &mut client).unwrap();

        let mut client = ScriptedClient::default();
        client.reply(200, status(&profile, 10));
        client.reply(200, note());
        client.reply(200, status(&profile, 10));
        client.reply(200, note());
        client.reply(202, json!({"txid": signed.txid, "state": "MEMPOOL"}));
        let result = submit_with_client(&req, &profile, &mut client).unwrap();
        assert_eq!(result.state, "MEMPOOL");
        let post = client.requests.last().unwrap();
        assert_eq!(
            (&post.0, &post.1),
            (&"POST".into(), &endpoint(&profile, SUBMIT_PATH))
        );
        let envelope = post.2.as_ref().unwrap().as_object().unwrap();
        assert_eq!(envelope.len(), 2);
        assert!(envelope["tx"].as_str().is_some());
        assert!(envelope["witnesses"].as_str().is_some());
    }

    #[test]
    fn second_identity_mismatch_and_post_transport_failure_never_accept() {
        let profile = test_profile();
        let req = test_request(&profile);

        let mut wrong = status(&profile, 10);
        wrong["genesis_hash"] = json!("ff".repeat(32));
        let mut client = ScriptedClient::default();
        client.reply(200, status(&profile, 10));
        client.reply(200, note());
        client.reply(200, wrong);
        assert_eq!(
            submit_with_client(&req, &profile, &mut client),
            Err(OpsError::WrongProtocolIdentity)
        );
        assert_eq!(client.requests.len(), 3);
        assert!(client.requests.iter().all(|request| request.0 == "GET"));

        let mut client = ScriptedClient::default();
        client.reply(200, status(&profile, 10));
        client.reply(200, note());
        client.reply(200, status(&profile, 10));
        client.reply(200, note());
        client.replies.push_back(Err(OpsError::NetworkFailure));
        assert_eq!(
            submit_with_client(&req, &profile, &mut client),
            Err(OpsError::NetworkFailure)
        );
        assert_eq!(client.requests.last().unwrap().0, "POST");
    }

    #[test]
    fn rejection_network_failure_malformed_response_and_txid_mismatch_never_accept() {
        let expected = "11".repeat(32);
        assert_eq!(
            parse_submit_response(
                HttpReply {
                    status: 422,
                    body: json!({"code":"validation_failed"}).to_string()
                },
                &expected
            ),
            Err(OpsError::SubmissionRejected)
        );
        assert_eq!(
            parse_submit_response(
                HttpReply {
                    status: 202,
                    body: "not-json".into()
                },
                &expected
            ),
            Err(OpsError::MalformedSubmitResponse)
        );
        assert_eq!(
            parse_submit_response(
                HttpReply {
                    status: 202,
                    body: json!({"txid":"22".repeat(32),"state":"MEMPOOL"}).to_string()
                },
                &expected
            ),
            Err(OpsError::TxidMismatch)
        );
        assert_eq!(
            parse_submit_response(
                HttpReply {
                    status: 202,
                    body: json!({"txid":expected,"state":"REJECTED"}).to_string()
                },
                &"11".repeat(32)
            ),
            Err(OpsError::SubmissionRejected)
        );
        let mut client = ScriptedClient::default();
        client.replies.push_back(Err(OpsError::NetworkFailure));
        assert_eq!(
            fetch_status(&test_profile(), &mut client).unwrap_err(),
            OpsError::NetworkFailure
        );
    }
}
