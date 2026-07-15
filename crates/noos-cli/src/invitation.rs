use crate::{from_hex, from_hex32, CliError, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

const SCHEMA: &str = "noos/invitation-lease/v2";
const DOMAIN: &[u8] = b"NOOS/INVITATION/LEASE/V2\0";

fn malformed(message: impl Into<String>) -> CliError {
    CliError::Malformed(message.into())
}

fn required_str<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("invitation {name} must be a string")))
}

fn required_u64(value: &Value, name: &str) -> Result<u64> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(format!("invitation {name} must be a u64")))
}

fn canonical_payload(invite: &Value) -> Result<Vec<u8>> {
    let mut payload = invite
        .as_object()
        .cloned()
        .ok_or_else(|| malformed("invitation root must be an object"))?;
    payload.remove("signature");
    serde_json::to_vec(&Value::Object(payload)).map_err(|error| malformed(error.to_string()))
}

pub fn invitation_verify(
    invitation_json: &str,
    trusted_public_key_hex: &str,
    now_unix_ms: u64,
) -> Result<Value> {
    let invite: Value = serde_json::from_str(invitation_json)
        .map_err(|error| malformed(format!("invitation JSON: {error}")))?;
    if required_str(&invite, "schema")? != SCHEMA {
        return Err(malformed("unsupported invitation lease schema"));
    }
    let trusted = from_hex32(trusted_public_key_hex)?;
    let signing_key = from_hex32(required_str(&invite, "signing_key")?)?;
    if signing_key != trusted {
        return Err(malformed("invitation signing key is not trusted"));
    }
    let issued = required_u64(&invite, "issued_unix_ms")?;
    let expires = required_u64(&invite, "expires_unix_ms")?;
    if issued >= expires || now_unix_ms < issued || now_unix_ms >= expires {
        return Err(malformed("invitation lease is not currently valid"));
    }
    let lease_id = required_str(&invite, "lease_id")?;
    if lease_id.len() != 32 || from_hex(lease_id)?.len() != 16 {
        return Err(malformed("invitation lease id is malformed"));
    }
    let role = required_str(&invite, "role")?;
    let witness_index = required_u64(&invite, "witness_index")?;
    if role != format!("witness-{witness_index}") || !(1..=3).contains(&witness_index) {
        return Err(malformed(
            "invitation witness role does not match its index",
        ));
    }
    if required_str(&invite, "platform")? == "" {
        return Err(malformed("invitation platform is empty"));
    }
    let chain_id = from_hex32(required_str(&invite, "chain_id")?)?;
    let genesis_hash = from_hex32(required_str(&invite, "genesis_hash")?)?;
    let params = required_str(&invite, "params_sha256")?;
    if from_hex(params)?.len() != 32 {
        return Err(malformed("invitation parameters digest is malformed"));
    }
    let signature_bytes = from_hex(required_str(&invite, "signature")?)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| malformed("invitation signature is malformed"))?;
    let key = VerifyingKey::from_bytes(&trusted)
        .map_err(|_| malformed("trusted invitation key is malformed"))?;
    let mut message = Vec::with_capacity(DOMAIN.len() + invitation_json.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&canonical_payload(&invite)?);
    key.verify(&message, &signature)
        .map_err(|_| malformed("invitation signature verification failed"))?;
    Ok(json!({
        "valid": true,
        "lease_id": lease_id,
        "role": role,
        "expires_unix_ms": expires,
        "chain_id": crate::to_hex(&chain_id),
        "genesis_hash": crate::to_hex(&genesis_hash)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_invite() -> (Value, String) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = crate::to_hex(&key.verifying_key().to_bytes());
        let mut invite = json!({
            "schema": SCHEMA,
            "chain_id": "01".repeat(32),
            "genesis_hash": "02".repeat(32),
            "genesis_time_ms": 1,
            "params_sha256": "03".repeat(32),
            "validator_host": "192.0.2.1",
            "validator_p2p_port": 21701,
            "local_p2p_port": 21702,
            "witness_index": 1,
            "wallet_accounts": [],
            "public_api_url": "http://192.0.2.1:21080",
            "compute_market_url": "http://192.0.2.1:18110",
            "test_network": true,
            "lease_id": "04".repeat(16),
            "role": "witness-1",
            "platform": "windows",
            "issued_unix_ms": 1000,
            "expires_unix_ms": 2000,
            "signing_key": public,
        });
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&canonical_payload(&invite).unwrap());
        invite["signature"] = Value::String(crate::to_hex(&key.sign(&message).to_bytes()));
        (invite, public)
    }

    #[test]
    fn signed_invitation_is_time_and_key_bound() {
        let (invite, public) = signed_invite();
        let encoded = serde_json::to_string(&invite).unwrap();
        assert_eq!(
            invitation_verify(&encoded, &public, 1500).unwrap()["valid"],
            true
        );
        assert!(invitation_verify(&encoded, &"09".repeat(32), 1500).is_err());
        assert!(invitation_verify(&encoded, &public, 2000).is_err());
    }

    #[test]
    fn tampering_or_role_mismatch_is_rejected() {
        let (mut invite, public) = signed_invite();
        invite["validator_host"] = Value::String("198.51.100.8".into());
        assert!(invitation_verify(&invite.to_string(), &public, 1500).is_err());
        let (mut invite, public) = signed_invite();
        invite["role"] = Value::String("witness-2".into());
        assert!(invitation_verify(&invite.to_string(), &public, 1500).is_err());
    }
}
