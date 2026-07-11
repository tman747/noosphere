//! Wire-facing operations over the `noos-wallet` core: authority derivation,
//! transaction build + sign, and submission preparation. All amounts travel
//! as base-10 strings (frozen API integer encoding); no secret material ever
//! crosses the wire — responses expose only public identifiers.

use noos_wallet::{
    construct_transaction, derivation_path, derive_authority, plan_fee, prepare_submission,
    select_notes, IdentityGate, NodeIdentity, Note, Purpose, Resources, UnsignedTransaction,
    WalletError, API_VERSION,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for the canonical transaction body bytes signed by the
/// spending key (the core adds its own `NOOS/WALLET/SIGN/V1` + identity
/// prefix on top).
pub const TX_BODY_DOMAIN: &[u8] = b"NOOS/WALLET/TXBODY/V1";
/// Domain separator for the local transaction identifier.
pub const TXID_DOMAIN: &[u8] = b"NOOS/WALLET/TXID/V1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpsError {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("{0}")]
    Wallet(WalletError),
}

impl From<WalletError> for OpsError {
    fn from(e: WalletError) -> Self {
        Self::Wallet(e)
    }
}

fn parse_hash32(s: &str) -> Result<[u8; 32], OpsError> {
    if s.len() != 64 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(OpsError::InvalidRequest);
    }
    let bytes = hex::decode(s).map_err(|_| OpsError::InvalidRequest)?;
    bytes.try_into().map_err(|_| OpsError::InvalidRequest)
}

fn parse_u128(s: &str) -> Result<u128, OpsError> {
    if s.is_empty() || s.bytes().any(|b| !b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(OpsError::InvalidRequest);
    }
    s.parse().map_err(|_| OpsError::InvalidRequest)
}

fn parse_u64(s: &str) -> Result<u64, OpsError> {
    if s.is_empty() || s.bytes().any(|b| !b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(OpsError::InvalidRequest);
    }
    s.parse().map_err(|_| OpsError::InvalidRequest)
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
pub struct IdentityHex {
    pub chain_id: String,
    pub genesis_hash: String,
    pub api_version: u16,
}

impl IdentityHex {
    fn to_node_identity(&self) -> Result<NodeIdentity, OpsError> {
        Ok(NodeIdentity {
            chain_id: parse_hash32(&self.chain_id)?,
            genesis_hash: parse_hash32(&self.genesis_hash)?,
            api_version: self.api_version,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveRequest {
    pub seed_hex: String,
    pub purpose: String,
    #[serde(default)]
    pub suite: Option<u32>,
    pub account: u32,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeriveResponse {
    /// Hardened path components as `0x`-prefixed 8-hex strings (vector format).
    pub path: Vec<String>,
    /// Big-endian concatenation of the path components, lowercase hex.
    pub bytes: String,
    /// BLAKE3 of the derived secret: the public authority identifier.
    pub public_id: String,
    /// Ed25519 verifying key, present only for the spend-capable purpose.
    pub verifying_key: Option<String>,
}

/// Derive an authority and return only public identifiers.
pub fn derive(req: &DeriveRequest) -> Result<DeriveResponse, OpsError> {
    let purpose = parse_purpose(&req.purpose, req.suite)?;
    let seed = parse_seed(&req.seed_hex)?;
    let path = derivation_path(purpose, req.account, req.index)?;
    let mut bytes = String::with_capacity(path.len().saturating_mul(8));
    let mut path_hex = Vec::with_capacity(path.len());
    for component in &path {
        let h = hex::encode(component.to_be_bytes());
        bytes.push_str(&h);
        path_hex.push(format!("0x{h}"));
    }
    let authority = derive_authority(&seed, purpose, req.account, req.index)?;
    let public_id = hex::encode(authority.public_id());
    let verifying_key = if purpose.can_spend() {
        let signing = authority.into_spending_key()?;
        Some(hex::encode(signing.verifying_key()))
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteReq {
    pub id: String,
    pub amount: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcesReq {
    pub bytes: String,
    pub grain_steps: String,
    pub proof_units: String,
    pub state_reads: String,
    pub state_writes: String,
    pub blob_bytes: String,
}

impl ResourcesReq {
    fn to_resources(&self) -> Result<Resources, OpsError> {
        Ok(Resources {
            bytes: parse_u64(&self.bytes)?,
            grain_steps: parse_u64(&self.grain_steps)?,
            proof_units: parse_u64(&self.proof_units)?,
            state_reads: parse_u64(&self.state_reads)?,
            state_writes: parse_u64(&self.state_writes)?,
            blob_bytes: parse_u64(&self.blob_bytes)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    pub seed_hex: String,
    pub account: u32,
    pub index: u32,
    pub expected: IdentityHex,
    pub actual: IdentityHex,
    pub notes: Vec<NoteReq>,
    pub amount: String,
    pub resources: ResourcesReq,
    pub prices: ResourcesReq,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResponse {
    pub amount: String,
    pub fee: String,
    pub change: String,
    pub inputs: Vec<String>,
    pub body: String,
    pub signature: String,
    pub verifying_key: String,
    pub txid: String,
}

/// Canonical transaction body bytes. Fixed-width big-endian fields; the input
/// set is length-prefixed so no field boundary is ambiguous. An input count
/// that does not fit the u32 prefix is a hard error, never a truncation.
pub fn encode_body(tx: &UnsignedTransaction) -> Result<Vec<u8>, OpsError> {
    let count = u32::try_from(tx.inputs.len()).map_err(|_| OpsError::InvalidRequest)?;
    let mut out = Vec::new();
    out.extend_from_slice(TX_BODY_DOMAIN);
    out.extend_from_slice(&tx.amount.to_be_bytes());
    out.extend_from_slice(&tx.fee.to_be_bytes());
    out.extend_from_slice(&tx.change.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    for input in &tx.inputs {
        out.extend_from_slice(input);
    }
    Ok(out)
}

/// Verify chain identity, select notes, plan the fee, construct, sign, and
/// prepare the submission. Fails closed on any identity mismatch.
pub fn build_and_sign(req: &SignRequest) -> Result<SignResponse, OpsError> {
    let mut gate = IdentityGate::new(req.expected.to_node_identity()?);
    if req.expected.api_version != API_VERSION {
        return Err(OpsError::InvalidRequest);
    }
    gate.verify(req.actual.to_node_identity()?)?;
    let mut notes = Vec::with_capacity(req.notes.len());
    for note in &req.notes {
        notes.push(Note {
            id: parse_hash32(&note.id)?,
            amount: parse_u128(&note.amount)?,
        });
    }
    let amount = parse_u128(&req.amount)?;
    let plan = plan_fee(
        &gate,
        amount,
        req.resources.to_resources()?,
        req.prices.to_resources()?,
    )?;
    let selection = select_notes(&gate, &notes, plan.total_required)?;
    let tx = construct_transaction(&gate, &selection, amount, plan.fee)?;
    let seed = parse_seed(&req.seed_hex)?;
    let authority = derive_authority(&seed, Purpose::Sign, req.account, req.index)?;
    let signing = authority.into_spending_key()?;
    let verifying_key = hex::encode(signing.verifying_key());
    let body = encode_body(&tx)?;
    let signature = signing.sign(&gate, &body)?;
    let submission = prepare_submission(&gate, tx, signature)?;
    let mut txid_input = Vec::with_capacity(
        TXID_DOMAIN
            .len()
            .saturating_add(body.len())
            .saturating_add(signature.len()),
    );
    txid_input.extend_from_slice(TXID_DOMAIN);
    txid_input.extend_from_slice(&body);
    txid_input.extend_from_slice(&signature);
    Ok(SignResponse {
        amount: submission.transaction.amount.to_string(),
        fee: submission.transaction.fee.to_string(),
        change: submission.transaction.change.to_string(),
        inputs: submission
            .transaction
            .inputs
            .iter()
            .map(hex::encode)
            .collect(),
        body: hex::encode(&body),
        signature: hex::encode(signature),
        verifying_key,
        txid: hex::encode(blake3::hash(&txid_input).as_bytes()),
    })
}
