use crate::{from_hex, from_hex32, to_hex, CliError, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};

const SCHEMA: &str = "noos/public-network-manifest/v1";
const DOMAIN: &[u8] = b"NOOS/PUBLIC/NETWORK/MANIFEST/V1\0";
const ALLOWED_FIELDS: &[&str] = &[
    "schema",
    "network",
    "bootstrap_peers",
    "api_base_url",
    "compute_market_url",
    "release",
    "valid_from_unix_ms",
    "expires_unix_ms",
    "signing_key",
    "signature",
];

fn malformed(message: impl Into<String>) -> CliError {
    CliError::Malformed(message.into())
}

fn required_object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| malformed(format!("manifest {name} must be an object")))
}

fn required_str<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("manifest {name} must be a string")))
}

fn required_u64(value: &Value, name: &str) -> Result<u64> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(format!("manifest {name} must be a u64")))
}

fn canonical_payload(manifest: &Value) -> Result<Vec<u8>> {
    let mut payload = manifest
        .as_object()
        .cloned()
        .ok_or_else(|| malformed("manifest root must be an object"))?;
    payload.remove("signature");
    serde_json::to_vec(&Value::Object(payload)).map_err(|error| malformed(error.to_string()))
}

fn validate_shape(manifest: &Value, trusted_key: &[u8; 32], now_unix_ms: u64) -> Result<()> {
    let root = manifest
        .as_object()
        .ok_or_else(|| malformed("manifest root must be an object"))?;
    if root
        .keys()
        .any(|field| !ALLOWED_FIELDS.contains(&field.as_str()))
    {
        return Err(malformed("manifest contains an unknown top-level field"));
    }
    if required_str(manifest, "schema")? != SCHEMA {
        return Err(malformed("unsupported public network manifest schema"));
    }
    let signing_key = from_hex32(required_str(manifest, "signing_key")?)?;
    if &signing_key != trusted_key {
        return Err(malformed(
            "manifest signing key is not the pinned trusted key",
        ));
    }
    let valid_from = required_u64(manifest, "valid_from_unix_ms")?;
    let expires = required_u64(manifest, "expires_unix_ms")?;
    if valid_from >= expires {
        return Err(malformed("manifest validity interval is empty"));
    }
    if now_unix_ms < valid_from {
        return Err(malformed("manifest is not valid yet"));
    }
    if now_unix_ms > expires {
        return Err(malformed("manifest has expired"));
    }

    let network = required_object(manifest, "network")?;
    if network.len() != 3
        || network.get("name").and_then(Value::as_str).is_none()
        || network
            .get("chain_id")
            .and_then(Value::as_str)
            .map(from_hex32)
            .transpose()?
            .is_none()
        || network
            .get("genesis_hash")
            .and_then(Value::as_str)
            .map(from_hex32)
            .transpose()?
            .is_none()
    {
        return Err(malformed("manifest network identity is malformed"));
    }

    let peers = manifest
        .get("bootstrap_peers")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("manifest bootstrap_peers must be an array"))?;
    if peers.len() < 2 || peers.len() > 16 {
        return Err(malformed(
            "manifest must contain between 2 and 16 bootstrap peers",
        ));
    }
    for peer in peers {
        let peer = peer
            .as_str()
            .ok_or_else(|| malformed("manifest bootstrap peer must be a string"))?;
        let address_family = peer.starts_with("/ip4/") || peer.starts_with("/ip6/");
        if !address_family || !peer.contains("/udp/") || !peer.ends_with("/quic-v1") {
            return Err(malformed(
                "manifest bootstrap peer is not an IP QUIC multiaddr",
            ));
        }
    }

    for field in ["api_base_url", "compute_market_url"] {
        let url = required_str(manifest, field)?;
        if !url.starts_with("https://") || url.contains('@') {
            return Err(malformed(format!(
                "manifest {field} must be an HTTPS origin"
            )));
        }
    }

    let release = required_object(manifest, "release")?;
    let version = release
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let artifacts = release
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("manifest release.artifacts must be an array"))?;
    if version.is_empty() || artifacts.is_empty() || artifacts.len() > 32 {
        return Err(malformed("manifest release is incomplete"));
    }
    for artifact in artifacts {
        let object = artifact
            .as_object()
            .ok_or_else(|| malformed("manifest artifact must be an object"))?;
        for field in ["name", "platform", "architecture"] {
            if object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .is_empty()
            {
                return Err(malformed(format!("manifest artifact {field} is missing")));
            }
        }
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !url.starts_with("https://") || url.contains('@') {
            return Err(malformed("manifest artifact URL must use HTTPS"));
        }
        let digest = object
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if from_hex(digest)?.len() != 32 {
            return Err(malformed("manifest artifact sha256 must be 32 bytes"));
        }
    }
    Ok(())
}

pub fn manifest_verify(
    manifest_json: &str,
    trusted_public_key_hex: &str,
    now_unix_ms: u64,
) -> Result<Value> {
    let manifest: Value = serde_json::from_str(manifest_json)
        .map_err(|error| malformed(format!("manifest JSON: {error}")))?;
    let trusted_key = from_hex32(trusted_public_key_hex)?;
    validate_shape(&manifest, &trusted_key, now_unix_ms)?;
    let signature_bytes = from_hex(required_str(&manifest, "signature")?)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| malformed("manifest signature must be 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&trusted_key)
        .map_err(|_| malformed("trusted manifest public key is invalid"))?;
    let payload = canonical_payload(&manifest)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + payload.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&payload);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| malformed("manifest signature verification failed"))?;
    let digest = blake3::hash(&signed);
    Ok(json!({
        "valid": true,
        "schema": SCHEMA,
        "manifest_digest": to_hex(digest.as_bytes()),
        "signing_key": to_hex(&trusted_key),
        "valid_from_unix_ms": required_u64(&manifest, "valid_from_unix_ms")?,
        "expires_unix_ms": required_u64(&manifest, "expires_unix_ms")?,
        "network": manifest["network"].clone(),
        "bootstrap_peers": manifest["bootstrap_peers"].clone(),
        "api_base_url": manifest["api_base_url"].clone(),
        "compute_market_url": manifest["compute_market_url"].clone(),
        "release": manifest["release"].clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_manifest() -> (Value, SigningKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut manifest = json!({
            "schema": SCHEMA,
            "network": {"name":"MindChain Public Testnet","chain_id":"01".repeat(32),"genesis_hash":"02".repeat(32)},
            "bootstrap_peers": ["/ip4/203.0.113.10/udp/19701/quic-v1","/ip4/198.51.100.20/udp/19701/quic-v1"],
            "api_base_url": "https://api.testnet.mindchain.network",
            "compute_market_url": "https://compute.testnet.mindchain.network",
            "release": {"version":"0.1.0-testnet","artifacts":[{"name":"noosd","platform":"macos","architecture":"arm64","url":"https://install.testnet.mindchain.network/noosd","sha256":"03".repeat(32)}]},
            "valid_from_unix_ms": 1_000u64,
            "expires_unix_ms": 2_000u64,
            "signing_key": to_hex(key.verifying_key().as_bytes()),
            "signature": ""
        });
        let payload = canonical_payload(&manifest).unwrap();
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&payload);
        manifest["signature"] = Value::String(to_hex(&key.sign(&signed).to_bytes()));
        (manifest, key)
    }

    #[test]
    fn verifies_exact_signed_manifest() {
        let (manifest, key) = signed_manifest();
        let result = manifest_verify(
            &serde_json::to_string(&manifest).unwrap(),
            &to_hex(key.verifying_key().as_bytes()),
            1_500,
        )
        .unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["bootstrap_peers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_mutation_and_expiry() {
        let (mut manifest, key) = signed_manifest();
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(manifest_verify(&encoded, &to_hex(key.verifying_key().as_bytes()), 2_001).is_err());
        manifest["api_base_url"] = Value::String("https://evil.example".into());
        assert!(manifest_verify(
            &serde_json::to_string(&manifest).unwrap(),
            &to_hex(key.verifying_key().as_bytes()),
            1_500,
        )
        .is_err());
    }
}
