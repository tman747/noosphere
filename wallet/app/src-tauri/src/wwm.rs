//! Native paid-WWM authorization boundary.
//!
//! The webview supplies public identifiers and a prompt commitment only. Seed
//! bytes stay in the operating-system vault, enter this module in zeroizing
//! native memory, and are reduced to an Ed25519 signature. The returned token
//! contains no seed, derived secret, prompt, or output bytes.

use noos_wallet::{derive_authority, IdentityGate, NodeIdentity, Purpose, WalletError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ops::ChainProfile;

const AUTHORIZATION_SCHEMA: &str = "noos/wallet-wwm-paid-authorization/v1";
const AUTHORIZATION_DOMAIN: &[u8] = b"NOOS/WALLET/WWM/PAID-AUTHORIZATION/V1";
const API_VERSION_V1: u16 = 1;
const MAX_LABEL_BYTES: usize = 96;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WwmWalletError {
    #[error("invalid_wwm_authorization_request")]
    InvalidRequest,
    #[error("wrong_protocol_identity")]
    WrongProtocolIdentity,
    #[error("wallet_signing_failed")]
    Signing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaidAuthorizationRequest {
    pub request_id: String,
    pub pin_id: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub prompt_commitment: String,
    pub maximum_fee_micro_noos: u64,
    pub expires_at_height: u64,
    pub payer_nonce: u64,
    pub account: u32,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidAuthorization {
    pub schema: String,
    pub mode: String,
    pub authorization: String,
    pub payer_public_key: String,
    pub intent_root: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub maximum_fee_micro_noos: u64,
    pub expires_at_height: u64,
    pub payer_nonce: u64,
    pub secret_exported_to_ui: bool,
}

pub fn profile_identity(profile: &ChainProfile) -> Result<NodeIdentity, WwmWalletError> {
    if profile.api_version != "v1" {
        return Err(WwmWalletError::WrongProtocolIdentity);
    }
    Ok(NodeIdentity {
        chain_id: hash32(&profile.chain_id)?,
        genesis_hash: hash32(&profile.genesis_hash)?,
        api_version: API_VERSION_V1,
    })
}

pub fn authorize_paid(
    request: &PaidAuthorizationRequest,
    profile: &ChainProfile,
    live_identity: NodeIdentity,
    seed: &[u8],
) -> Result<PaidAuthorization, WwmWalletError> {
    validate_request(request)?;
    let expected = profile_identity(profile)?;
    let mut gate = IdentityGate::new(expected);
    gate.verify(live_identity).map_err(map_wallet_error)?;

    let authority = derive_authority(seed, Purpose::Sign, request.account, request.index)
        .map_err(map_wallet_error)?;
    let spending_key = authority.into_spending_key().map_err(map_wallet_error)?;
    let payer_public_key = spending_key.verifying_key();
    let body = canonical_body(request, &expected)?;
    let intent_root = *blake3::hash(&body).as_bytes();
    let signature = spending_key.sign(&gate, &body).map_err(map_wallet_error)?;

    let mut envelope = Vec::with_capacity(2 + 32 + 32 + 64);
    envelope.extend_from_slice(&1_u16.to_le_bytes());
    envelope.extend_from_slice(&payer_public_key);
    envelope.extend_from_slice(&intent_root);
    envelope.extend_from_slice(&signature);

    Ok(PaidAuthorization {
        schema: AUTHORIZATION_SCHEMA.to_owned(),
        mode: "PAID".to_owned(),
        authorization: hex::encode(envelope),
        payer_public_key: hex::encode(payer_public_key),
        intent_root: hex::encode(intent_root),
        chain_id: profile.chain_id.clone(),
        genesis_hash: profile.genesis_hash.clone(),
        capsule_id: request.capsule_id.clone(),
        execution_profile_id: request.execution_profile_id.clone(),
        query_profile_id: request.query_profile_id.clone(),
        maximum_fee_micro_noos: request.maximum_fee_micro_noos,
        expires_at_height: request.expires_at_height,
        payer_nonce: request.payer_nonce,
        secret_exported_to_ui: false,
    })
}

fn validate_request(request: &PaidAuthorizationRequest) -> Result<(), WwmWalletError> {
    for label in [&request.request_id, &request.pin_id] {
        if label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || !label.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(WwmWalletError::InvalidRequest);
        }
    }
    for value in [
        &request.capsule_id,
        &request.execution_profile_id,
        &request.query_profile_id,
        &request.prompt_commitment,
    ] {
        hash32(value)?;
    }
    if request.maximum_fee_micro_noos == 0 || request.expires_at_height == 0 {
        return Err(WwmWalletError::InvalidRequest);
    }
    Ok(())
}

fn canonical_body(
    request: &PaidAuthorizationRequest,
    identity: &NodeIdentity,
) -> Result<Vec<u8>, WwmWalletError> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(AUTHORIZATION_DOMAIN);
    body.extend_from_slice(&identity.chain_id);
    body.extend_from_slice(&identity.genesis_hash);
    body.extend_from_slice(&identity.api_version.to_le_bytes());
    put_label(&mut body, &request.request_id)?;
    put_label(&mut body, &request.pin_id)?;
    body.extend_from_slice(&hash32(&request.capsule_id)?);
    body.extend_from_slice(&hash32(&request.execution_profile_id)?);
    body.extend_from_slice(&hash32(&request.query_profile_id)?);
    body.extend_from_slice(&hash32(&request.prompt_commitment)?);
    body.extend_from_slice(&request.maximum_fee_micro_noos.to_le_bytes());
    body.extend_from_slice(&request.expires_at_height.to_le_bytes());
    body.extend_from_slice(&request.payer_nonce.to_le_bytes());
    body.extend_from_slice(&request.account.to_le_bytes());
    body.extend_from_slice(&request.index.to_le_bytes());
    Ok(body)
}

fn put_label(out: &mut Vec<u8>, value: &str) -> Result<(), WwmWalletError> {
    let len = u16::try_from(value.len()).map_err(|_| WwmWalletError::InvalidRequest)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn hash32(value: &str) -> Result<[u8; 32], WwmWalletError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(WwmWalletError::InvalidRequest);
    }
    let decoded = hex::decode(value).map_err(|_| WwmWalletError::InvalidRequest)?;
    decoded
        .try_into()
        .map_err(|_| WwmWalletError::InvalidRequest)
}

fn map_wallet_error(error: WalletError) -> WwmWalletError {
    match error {
        WalletError::WrongProtocolIdentity | WalletError::ApiVersionMismatch => {
            WwmWalletError::WrongProtocolIdentity
        }
        _ => WwmWalletError::Signing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ChainProfile {
        ChainProfile {
            id: "devnet".to_owned(),
            label: "Devnet".to_owned(),
            chain_id: "11".repeat(32),
            genesis_hash: "22".repeat(32),
            api_version: "v1".to_owned(),
            api_base_url: "http://127.0.0.1:18080".to_owned(),
            max_freshness_ms: "5000".to_owned(),
        }
    }

    fn request() -> PaidAuthorizationRequest {
        PaidAuthorizationRequest {
            request_id: "request-17".to_owned(),
            pin_id: "pin-19".to_owned(),
            capsule_id: "33".repeat(32),
            execution_profile_id: "44".repeat(32),
            query_profile_id: "55".repeat(32),
            prompt_commitment: "66".repeat(32),
            maximum_fee_micro_noos: 91_337,
            expires_at_height: 4_096,
            payer_nonce: 8,
            account: 2,
            index: 5,
        }
    }

    #[test]
    fn paid_authorization_exports_only_public_material() {
        let profile = profile();
        let identity = profile_identity(&profile).unwrap();
        let seed = [0xabu8; 64];
        let authorization = authorize_paid(&request(), &profile, identity, &seed).unwrap();
        assert_eq!(authorization.mode, "PAID");
        assert_eq!(authorization.authorization.len(), (2 + 32 + 32 + 64) * 2);
        assert!(!authorization.secret_exported_to_ui);
        let json = serde_json::to_string(&authorization).unwrap();
        assert!(!json.contains(&hex::encode(seed)));
        assert!(!json.contains("prompt"));
    }

    #[test]
    fn identity_and_every_execution_pin_fail_closed() {
        let profile = profile();
        let identity = profile_identity(&profile).unwrap();
        let baseline = authorize_paid(&request(), &profile, identity, &[7; 64]).unwrap();

        let mut changed = request();
        changed.prompt_commitment = "77".repeat(32);
        let changed = authorize_paid(&changed, &profile, identity, &[7; 64]).unwrap();
        assert_ne!(baseline.intent_root, changed.intent_root);
        assert_ne!(baseline.authorization, changed.authorization);

        let mut wrong_identity = identity;
        wrong_identity.chain_id = [9; 32];
        assert_eq!(
            authorize_paid(&request(), &profile, wrong_identity, &[7; 64]),
            Err(WwmWalletError::WrongProtocolIdentity)
        );

        let mut malformed = request();
        malformed.capsule_id = "AA".repeat(32);
        assert_eq!(
            authorize_paid(&malformed, &profile, identity, &[7; 64]),
            Err(WwmWalletError::InvalidRequest)
        );
    }
}
