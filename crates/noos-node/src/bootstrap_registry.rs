//! Signed, chain-bound bootstrap discovery snapshots with monotonic rotation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use noos_p2p::{Multiaddr, PeerId};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "noos/bootstrap-registry/v1";
pub const REGISTRY_ID_DOMAIN: &[u8] = b"NOOS/BOOTSTRAP/REGISTRY-ID/V1\0";
pub const SIGNATURE_DOMAIN: &[u8] = b"NOOS/SIG/BOOTSTRAP-REGISTRY/V1\0";
pub const ACCEPTED_DIRECTORY: &str = "accepted-bootstrap-registries";
const MAX_REGISTRY_BYTES: usize = 1024 * 1024;
const MAX_ACCEPTED_FILES: usize = 1024;
const ROOT_FIELDS: &[&str] = &["schema", "body", "signature"];
const BODY_FIELDS: &[&str] = &[
    "registry_id",
    "chain_id",
    "genesis_hash",
    "sequence",
    "previous_registry_id",
    "valid_from_unix_ms",
    "expires_unix_ms",
    "nodes",
];
const NODE_FIELDS: &[&str] = &[
    "node_id",
    "addresses",
    "valid_from_unix_ms",
    "expires_unix_ms",
    "status",
    "revoked_at_unix_ms",
];
const SIGNATURE_FIELDS: &[&str] = &["algorithm", "key_id", "public_key", "signature"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRegistryError(String);

impl BootstrapRegistryError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for BootstrapRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BootstrapRegistryError {}

pub type Result<T, E = BootstrapRegistryError> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapNode {
    pub node_id: String,
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub valid_from_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub status: BootstrapStatus,
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerifiedBootstrapRegistry {
    envelope: Value,
    pub registry_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub sequence: u64,
    pub previous_registry_id: Option<[u8; 32]>,
    pub valid_from_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub nodes: BTreeMap<String, BootstrapNode>,
}

impl VerifiedBootstrapRegistry {
    #[must_use]
    pub fn registry_id_hex(&self) -> String {
        encode_hex(&self.registry_id)
    }

    #[must_use]
    pub fn active_addresses(&self, now_unix_ms: u64) -> Vec<Multiaddr> {
        self.nodes
            .values()
            .filter(|node| {
                node.status == BootstrapStatus::Active
                    && node.valid_from_unix_ms <= now_unix_ms
                    && now_unix_ms < node.expires_unix_ms
            })
            .flat_map(|node| node.addresses.iter().cloned())
            .collect()
    }

    fn canonical_envelope(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.envelope)
            .map_err(|error| BootstrapRegistryError::new(format!("serialize registry: {error}")))
    }
}

fn exact_fields(map: &Map<String, Value>, expected: &[&str], context: &str) -> Result<()> {
    if map.len() != expected.len() || map.keys().any(|field| !expected.contains(&field.as_str())) {
        return Err(BootstrapRegistryError::new(format!(
            "{context} fields are malformed"
        )));
    }
    Ok(())
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| BootstrapRegistryError::new(format!("{field} must be an object")))
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| BootstrapRegistryError::new(format!("{field} must be a string")))
}

fn unsigned(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| BootstrapRegistryError::new(format!("{field} must be a u64")))
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    if value.len() != N.saturating_mul(2) {
        return Err(BootstrapRegistryError::new(format!(
            "{field} must be lowercase hex with {} bytes",
            N
        )));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or_else(|| {
            BootstrapRegistryError::new(format!("{field} must be canonical lowercase hex"))
        })?;
        let low = decode_nibble(pair[1]).ok_or_else(|| {
            BootstrapRegistryError::new(format!("{field} must be canonical lowercase hex"))
        })?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

pub fn decode_public_key_hex(value: &str) -> Result<[u8; 32]> {
    decode_hex(value, "trusted bootstrap public key")
}

fn encode_hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn canonical_body(body: &Map<String, Value>, omit_registry_id: bool) -> Result<Vec<u8>> {
    let mut payload = body.clone();
    if omit_registry_id {
        payload.remove("registry_id");
    }
    serde_json::to_vec(&Value::Object(payload))
        .map_err(|error| BootstrapRegistryError::new(format!("serialize registry body: {error}")))
}

fn parse_node(
    value: &Value,
    registry_valid_from: u64,
    registry_expires: u64,
) -> Result<BootstrapNode> {
    let map = value
        .as_object()
        .ok_or_else(|| BootstrapRegistryError::new("bootstrap node must be an object"))?;
    exact_fields(map, NODE_FIELDS, "bootstrap node")?;
    let node_id = string(value, "node_id")?.to_owned();
    let peer_id: PeerId = node_id
        .parse()
        .map_err(|_| BootstrapRegistryError::new("bootstrap node_id is not a canonical PeerId"))?;
    if peer_id.to_string() != node_id {
        return Err(BootstrapRegistryError::new(
            "bootstrap node_id is not canonical text",
        ));
    }
    let address_values = value
        .get("addresses")
        .and_then(Value::as_array)
        .ok_or_else(|| BootstrapRegistryError::new("bootstrap addresses must be an array"))?;
    if !(1..=4).contains(&address_values.len()) {
        return Err(BootstrapRegistryError::new(
            "bootstrap node must contain one to four addresses",
        ));
    }
    let mut address_text = Vec::with_capacity(address_values.len());
    let mut addresses = Vec::with_capacity(address_values.len());
    for address in address_values {
        let text = address
            .as_str()
            .ok_or_else(|| BootstrapRegistryError::new("bootstrap address must be a string"))?;
        let allowed_family = text.starts_with("/ip4/")
            || text.starts_with("/ip6/")
            || text.starts_with("/dns4/")
            || text.starts_with("/dns6/");
        let peer_suffix = format!("/quic-v1/p2p/{node_id}");
        if !allowed_family || !text.contains("/udp/") || !text.ends_with(&peer_suffix) {
            return Err(BootstrapRegistryError::new(
                "bootstrap address must be an IP/DNS QUIC multiaddr bound to node_id",
            ));
        }
        let parsed: Multiaddr = text
            .parse()
            .map_err(|_| BootstrapRegistryError::new("bootstrap address is not a multiaddr"))?;
        if parsed.to_string() != text {
            return Err(BootstrapRegistryError::new(
                "bootstrap address is not canonical multiaddr text",
            ));
        }
        address_text.push(text.to_owned());
        addresses.push(parsed);
    }
    if address_text.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(BootstrapRegistryError::new(
            "bootstrap addresses must be sorted and unique",
        ));
    }
    let valid_from = unsigned(value, "valid_from_unix_ms")?;
    let expires = unsigned(value, "expires_unix_ms")?;
    if valid_from < registry_valid_from || expires > registry_expires || valid_from >= expires {
        return Err(BootstrapRegistryError::new(
            "bootstrap node validity lies outside the registry interval",
        ));
    }
    let status = match string(value, "status")? {
        "active" => BootstrapStatus::Active,
        "revoked" => BootstrapStatus::Revoked,
        _ => {
            return Err(BootstrapRegistryError::new(
                "bootstrap node status must be active or revoked",
            ))
        }
    };
    let revoked_at = match value.get("revoked_at_unix_ms") {
        Some(Value::Null) => None,
        Some(timestamp) => timestamp.as_u64(),
        None => None,
    };
    match (status, revoked_at) {
        (BootstrapStatus::Active, None) => {}
        (BootstrapStatus::Revoked, Some(timestamp))
            if valid_from <= timestamp && timestamp < expires => {}
        (BootstrapStatus::Active, Some(_)) => {
            return Err(BootstrapRegistryError::new(
                "active bootstrap cannot have a revocation time",
            ))
        }
        (BootstrapStatus::Revoked, None) => {
            return Err(BootstrapRegistryError::new(
                "revoked bootstrap must have a revocation time",
            ))
        }
        (BootstrapStatus::Revoked, Some(_)) => {
            return Err(BootstrapRegistryError::new(
                "bootstrap revocation time is outside its valid interval",
            ))
        }
    }
    Ok(BootstrapNode {
        node_id,
        peer_id,
        addresses,
        valid_from_unix_ms: valid_from,
        expires_unix_ms: expires,
        status,
        revoked_at_unix_ms: revoked_at,
    })
}

pub fn verify_registry_json(
    encoded: &str,
    trusted_public_key: &[u8; 32],
    expected_chain_id: &[u8; 32],
    expected_genesis_hash: &[u8; 32],
    now_unix_ms: Option<u64>,
) -> Result<VerifiedBootstrapRegistry> {
    if encoded.is_empty() || encoded.len() > MAX_REGISTRY_BYTES {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry file size is outside bounds",
        ));
    }
    let envelope: Value = serde_json::from_str(encoded).map_err(|error| {
        BootstrapRegistryError::new(format!("bootstrap registry JSON: {error}"))
    })?;
    let root = envelope
        .as_object()
        .ok_or_else(|| BootstrapRegistryError::new("bootstrap registry root must be an object"))?;
    exact_fields(root, ROOT_FIELDS, "bootstrap registry envelope")?;
    if string(&envelope, "schema")? != SCHEMA {
        return Err(BootstrapRegistryError::new(
            "unsupported bootstrap registry schema",
        ));
    }
    let body = object(&envelope, "body")?;
    exact_fields(body, BODY_FIELDS, "bootstrap registry body")?;
    let body_value = Value::Object(body.clone());
    let registry_id = decode_hex::<32>(string(&body_value, "registry_id")?, "registry_id")?;
    let expected_registry_id = sha256(&[REGISTRY_ID_DOMAIN, &canonical_body(body, true)?]);
    if registry_id != expected_registry_id {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry_id does not match its canonical body",
        ));
    }
    let chain_id = decode_hex::<32>(string(&body_value, "chain_id")?, "chain_id")?;
    let genesis_hash = decode_hex::<32>(string(&body_value, "genesis_hash")?, "genesis_hash")?;
    if &chain_id != expected_chain_id {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry is bound to the wrong chain",
        ));
    }
    if &genesis_hash != expected_genesis_hash {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry is bound to the wrong genesis",
        ));
    }
    let sequence = unsigned(&body_value, "sequence")?;
    if sequence == 0 {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry sequence must be positive",
        ));
    }
    let previous_registry_id = match body.get("previous_registry_id") {
        Some(Value::Null) if sequence == 1 => None,
        Some(Value::String(value)) if sequence > 1 => {
            Some(decode_hex::<32>(value, "previous_registry_id")?)
        }
        _ => {
            return Err(BootstrapRegistryError::new(
                "bootstrap previous_registry_id does not match its sequence",
            ))
        }
    };
    let valid_from = unsigned(&body_value, "valid_from_unix_ms")?;
    let expires = unsigned(&body_value, "expires_unix_ms")?;
    if valid_from >= expires {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry validity interval is empty",
        ));
    }
    let node_values = body
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| BootstrapRegistryError::new("bootstrap nodes must be an array"))?;
    if !(2..=32).contains(&node_values.len()) {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry must contain two to thirty-two nodes",
        ));
    }
    let mut nodes = BTreeMap::new();
    for node_value in node_values {
        let node = parse_node(node_value, valid_from, expires)?;
        if nodes
            .last_key_value()
            .is_some_and(|(prior, _)| prior >= &node.node_id)
        {
            return Err(BootstrapRegistryError::new(
                "bootstrap nodes must be sorted and unique by node_id",
            ));
        }
        nodes.insert(node.node_id.clone(), node);
    }
    if nodes
        .values()
        .filter(|node| node.status == BootstrapStatus::Active)
        .count()
        < 2
    {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry must retain at least two active nodes",
        ));
    }

    let signature_value = Value::Object(object(&envelope, "signature")?.clone());
    let signature_map = signature_value
        .as_object()
        .ok_or_else(|| BootstrapRegistryError::new("bootstrap signature must be an object"))?;
    exact_fields(signature_map, SIGNATURE_FIELDS, "bootstrap signature")?;
    if string(&signature_value, "algorithm")? != "ed25519" {
        return Err(BootstrapRegistryError::new(
            "bootstrap signature algorithm must be ed25519",
        ));
    }
    let public_key = decode_hex::<32>(string(&signature_value, "public_key")?, "public_key")?;
    if &public_key != trusted_public_key {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry signer is not the pinned trusted key",
        ));
    }
    let key_id = decode_hex::<32>(string(&signature_value, "key_id")?, "key_id")?;
    if key_id != sha256(&[trusted_public_key]) {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry signer key_id is invalid",
        ));
    }
    let signature_bytes = decode_hex::<64>(string(&signature_value, "signature")?, "signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|_| BootstrapRegistryError::new("trusted bootstrap key is invalid"))?;
    let body_bytes = canonical_body(body, false)?;
    let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len().saturating_add(body_bytes.len()));
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.extend_from_slice(&body_bytes);
    verifying_key.verify(&signed, &signature).map_err(|_| {
        BootstrapRegistryError::new("bootstrap registry signature verification failed")
    })?;

    let verified = VerifiedBootstrapRegistry {
        envelope,
        registry_id,
        chain_id,
        genesis_hash,
        sequence,
        previous_registry_id,
        valid_from_unix_ms: valid_from,
        expires_unix_ms: expires,
        nodes,
    };
    if let Some(now) = now_unix_ms {
        if now < valid_from {
            return Err(BootstrapRegistryError::new(
                "bootstrap registry is not valid yet",
            ));
        }
        if now >= expires {
            return Err(BootstrapRegistryError::new(
                "bootstrap registry has expired",
            ));
        }
        let active_nodes = verified
            .nodes
            .values()
            .filter(|node| {
                node.status == BootstrapStatus::Active
                    && node.valid_from_unix_ms <= now
                    && now < node.expires_unix_ms
            })
            .count();
        if active_nodes < 2 {
            return Err(BootstrapRegistryError::new(
                "fewer than two bootstrap nodes are active at the current time",
            ));
        }
    }
    Ok(verified)
}

pub fn verify_transition(
    previous: &VerifiedBootstrapRegistry,
    next: &VerifiedBootstrapRegistry,
) -> Result<()> {
    if previous.chain_id != next.chain_id || previous.genesis_hash != next.genesis_hash {
        return Err(BootstrapRegistryError::new(
            "bootstrap rotation changes protocol identity",
        ));
    }
    if next.sequence == previous.sequence {
        if next.registry_id == previous.registry_id {
            return Ok(());
        }
        return Err(BootstrapRegistryError::new(
            "conflicting bootstrap registries share one sequence",
        ));
    }
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or_else(|| BootstrapRegistryError::new("bootstrap sequence overflow"))?;
    if next.sequence != expected_sequence || next.previous_registry_id != Some(previous.registry_id)
    {
        return Err(BootstrapRegistryError::new(
            "bootstrap rotation is not the direct signed successor",
        ));
    }
    for (node_id, old_node) in &previous.nodes {
        let new_node = next.nodes.get(node_id).ok_or_else(|| {
            BootstrapRegistryError::new(format!(
                "bootstrap rotation silently removes node {node_id}; explicit revocation is required"
            ))
        })?;
        if old_node.status == BootstrapStatus::Revoked && new_node != old_node {
            return Err(BootstrapRegistryError::new(format!(
                "bootstrap rotation rewrites or reactivates revoked node {node_id}"
            )));
        }
    }
    Ok(())
}

pub fn read_registry_file(
    path: &Path,
    trusted_public_key: &[u8; 32],
    expected_chain_id: &[u8; 32],
    expected_genesis_hash: &[u8; 32],
    now_unix_ms: Option<u64>,
) -> Result<VerifiedBootstrapRegistry> {
    let metadata = fs::metadata(path).map_err(|error| {
        BootstrapRegistryError::new(format!(
            "read bootstrap registry {}: {error}",
            path.display()
        ))
    })?;
    let length = usize::try_from(metadata.len())
        .map_err(|_| BootstrapRegistryError::new("bootstrap registry file is too large"))?;
    if length == 0 || length > MAX_REGISTRY_BYTES {
        return Err(BootstrapRegistryError::new(
            "bootstrap registry file size is outside bounds",
        ));
    }
    let encoded = fs::read_to_string(path).map_err(|error| {
        BootstrapRegistryError::new(format!(
            "read bootstrap registry {}: {error}",
            path.display()
        ))
    })?;
    verify_registry_json(
        &encoded,
        trusted_public_key,
        expected_chain_id,
        expected_genesis_hash,
        now_unix_ms,
    )
}

pub fn load_latest_accepted(
    directory: &Path,
    trusted_public_key: &[u8; 32],
    expected_chain_id: &[u8; 32],
    expected_genesis_hash: &[u8; 32],
) -> Result<Option<VerifiedBootstrapRegistry>> {
    if !directory.exists() {
        return Ok(None);
    }
    let entries = fs::read_dir(directory).map_err(|error| {
        BootstrapRegistryError::new(format!("read accepted bootstrap directory: {error}"))
    })?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| {
                BootstrapRegistryError::new(format!(
                    "read accepted bootstrap directory entry: {error}"
                ))
            })?
            .path();
        if !path.is_file()
            || !path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            return Err(BootstrapRegistryError::new(
                "accepted bootstrap history contains an unexpected entry",
            ));
        }
        files.push(path);
    }
    files.sort();
    if files.len() > MAX_ACCEPTED_FILES {
        return Err(BootstrapRegistryError::new(
            "accepted bootstrap history exceeds its file bound",
        ));
    }
    let mut latest: Option<VerifiedBootstrapRegistry> = None;
    let mut sequences = BTreeSet::new();
    for path in files {
        let registry = read_registry_file(
            &path,
            trusted_public_key,
            expected_chain_id,
            expected_genesis_hash,
            None,
        )?;
        if !sequences.insert(registry.sequence) {
            return Err(BootstrapRegistryError::new(
                "accepted bootstrap history contains a duplicate sequence",
            ));
        }
        if latest
            .as_ref()
            .is_none_or(|current| registry.sequence > current.sequence)
        {
            latest = Some(registry);
        }
    }
    Ok(latest)
}

pub fn persist_accepted(directory: &Path, registry: &VerifiedBootstrapRegistry) -> Result<PathBuf> {
    fs::create_dir_all(directory).map_err(|error| {
        BootstrapRegistryError::new(format!("create accepted bootstrap directory: {error}"))
    })?;
    let path = directory.join(format!(
        "{:020}-{}.json",
        registry.sequence,
        registry.registry_id_hex()
    ));
    let bytes = registry.canonical_envelope()?;
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(&bytes).map_err(|error| {
                BootstrapRegistryError::new(format!("write accepted bootstrap registry: {error}"))
            })?;
            file.sync_all().map_err(|error| {
                BootstrapRegistryError::new(format!("sync accepted bootstrap registry: {error}"))
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(&path).map_err(|read_error| {
                BootstrapRegistryError::new(format!(
                    "read accepted bootstrap registry: {read_error}"
                ))
            })?;
            if existing != bytes {
                return Err(BootstrapRegistryError::new(
                    "accepted bootstrap registry file conflicts with the signed snapshot",
                ));
            }
        }
        Err(error) => {
            return Err(BootstrapRegistryError::new(format!(
                "create accepted bootstrap registry: {error}"
            )))
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use noos_crypto::Keypair;
    use noos_p2p::peer_id_from_ed25519_public;
    use serde_json::json;

    fn peer(seed: u8) -> String {
        let public = Keypair::from_seed([seed; 32]).public_key().into_bytes();
        peer_id_from_ed25519_public(&public)
            .unwrap_or_else(|| unreachable!("fixed Ed25519 public key"))
            .to_string()
    }

    fn node(seed: u8, host: &str, status: &str, revoked_at: Option<u64>) -> Value {
        let node_id = peer(seed);
        json!({
            "node_id": node_id,
            "addresses": [format!("/dns4/{host}/udp/19701/quic-v1/p2p/{node_id}")],
            "valid_from_unix_ms": 1_000u64,
            "expires_unix_ms": 9_000u64,
            "status": status,
            "revoked_at_unix_ms": revoked_at,
        })
    }

    fn signed_registry(
        key: &SigningKey,
        sequence: u64,
        previous: Option<String>,
        mut nodes: Vec<Value>,
    ) -> Value {
        nodes.sort_by(|left, right| {
            left.get("node_id")
                .and_then(Value::as_str)
                .cmp(&right.get("node_id").and_then(Value::as_str))
        });
        let mut body = json!({
            "registry_id": "",
            "chain_id": "11".repeat(32),
            "genesis_hash": "22".repeat(32),
            "sequence": sequence,
            "previous_registry_id": previous,
            "valid_from_unix_ms": 1_000u64,
            "expires_unix_ms": 10_000u64,
            "nodes": nodes,
        });
        let body_map = body.as_object().unwrap_or_else(|| unreachable!());
        let id = sha256(&[
            REGISTRY_ID_DOMAIN,
            &canonical_body(body_map, true).unwrap_or_else(|_| unreachable!()),
        ]);
        body["registry_id"] = Value::String(encode_hex(&id));
        let encoded = canonical_body(body.as_object().unwrap_or_else(|| unreachable!()), false)
            .unwrap_or_else(|_| unreachable!());
        let mut message = SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&encoded);
        let public = key.verifying_key().to_bytes();
        json!({
            "schema": SCHEMA,
            "body": body,
            "signature": {
                "algorithm": "ed25519",
                "key_id": encode_hex(&sha256(&[&public])),
                "public_key": encode_hex(&public),
                "signature": encode_hex(&key.sign(&message).to_bytes()),
            }
        })
    }

    fn verify(
        value: &Value,
        key: &SigningKey,
        now: Option<u64>,
    ) -> Result<VerifiedBootstrapRegistry> {
        verify_registry_json(
            &serde_json::to_string(value).unwrap_or_else(|_| unreachable!()),
            &key.verifying_key().to_bytes(),
            &[0x11; 32],
            &[0x22; 32],
            now,
        )
    }

    #[test]
    fn verifies_multiple_active_bootstraps_and_refuses_wrong_identity_or_expiry() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let value = signed_registry(
            &key,
            1,
            None,
            vec![
                node(1, "seed-a.example", "active", None),
                node(2, "seed-b.example", "active", None),
            ],
        );
        let verified = verify(&value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(verified.active_addresses(5_000).len(), 2);
        assert!(verify_registry_json(
            &serde_json::to_string(&value).unwrap_or_else(|_| unreachable!()),
            &key.verifying_key().to_bytes(),
            &[0x33; 32],
            &[0x22; 32],
            Some(5_000),
        )
        .is_err());
        assert!(verify(&value, &key, Some(10_000)).is_err());
    }

    #[test]
    fn direct_successor_rotates_addresses_and_requires_explicit_irreversible_revocation() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let first_value = signed_registry(
            &key,
            1,
            None,
            vec![
                node(1, "seed-a.example", "active", None),
                node(2, "seed-b.example", "active", None),
                node(3, "seed-c.example", "active", None),
            ],
        );
        let first =
            verify(&first_value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        let second_value = signed_registry(
            &key,
            2,
            Some(first.registry_id_hex()),
            vec![
                node(1, "seed-a-rotated.example", "active", None),
                node(2, "seed-b.example", "active", None),
                node(3, "seed-c.example", "revoked", Some(4_500)),
            ],
        );
        let second =
            verify(&second_value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        verify_transition(&first, &second).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.active_addresses(5_000).len(), 2);

        let missing_value = signed_registry(
            &key,
            2,
            Some(first.registry_id_hex()),
            vec![
                node(1, "seed-a-rotated.example", "active", None),
                node(2, "seed-b.example", "active", None),
            ],
        );
        let missing =
            verify(&missing_value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        assert!(verify_transition(&first, &missing).is_err());

        let reactivated_value = signed_registry(
            &key,
            3,
            Some(second.registry_id_hex()),
            vec![
                node(1, "seed-a-rotated.example", "active", None),
                node(2, "seed-b.example", "active", None),
                node(3, "seed-c.example", "active", None),
            ],
        );
        let reactivated =
            verify(&reactivated_value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        assert!(verify_transition(&second, &reactivated).is_err());
    }

    #[test]
    fn accepted_history_persists_monotonic_successors_without_a_mutable_pointer() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let first_value = signed_registry(
            &key,
            1,
            None,
            vec![
                node(1, "seed-a.example", "active", None),
                node(2, "seed-b.example", "active", None),
            ],
        );
        let first =
            verify(&first_value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        let second_value = signed_registry(
            &key,
            2,
            Some(first.registry_id_hex()),
            vec![
                node(1, "seed-a-rotated.example", "active", None),
                node(2, "seed-b.example", "active", None),
            ],
        );
        let second =
            verify(&second_value, &key, Some(5_000)).unwrap_or_else(|error| panic!("{error}"));
        let temporary = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let directory = temporary.path().join(ACCEPTED_DIRECTORY);

        assert!(load_latest_accepted(
            &directory,
            &key.verifying_key().to_bytes(),
            &[0x11; 32],
            &[0x22; 32],
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .is_none());
        persist_accepted(&directory, &first).unwrap_or_else(|error| panic!("{error}"));
        let accepted_first = load_latest_accepted(
            &directory,
            &key.verifying_key().to_bytes(),
            &[0x11; 32],
            &[0x22; 32],
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| unreachable!("first registry persisted"));
        verify_transition(&accepted_first, &second).unwrap_or_else(|error| panic!("{error}"));
        persist_accepted(&directory, &second).unwrap_or_else(|error| panic!("{error}"));
        persist_accepted(&directory, &second).unwrap_or_else(|error| panic!("{error}"));
        let accepted_second = load_latest_accepted(
            &directory,
            &key.verifying_key().to_bytes(),
            &[0x11; 32],
            &[0x22; 32],
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| unreachable!("second registry persisted"));
        assert_eq!(accepted_second.sequence, 2);
        assert_eq!(accepted_second.registry_id, second.registry_id);
    }
}
