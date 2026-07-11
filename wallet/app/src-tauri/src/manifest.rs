//! Update-manifest verification per `wallet/update-manifest.template.json`
//! and the `wallet/product-identity.json` signature policy.
//!
//! A manifest is accepted only when every target dimension binds (app id,
//! chain identity, platform, arch, channel), the artifact hash is canonical,
//! and the detached Ed25519 signature from the wallet updater key verifies
//! over the canonical signing bytes. The updater public key arrives via the
//! `NOOS_WALLET_UPDATER_PUBLIC_KEY` environment (product-identity policy) or
//! an explicit caller-supplied key.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Product identity, mirrored from `wallet/product-identity.json`.
pub const APP_ID: &str = "network.mindchain.noosphere.wallet";
pub const CHANNELS: [&str; 2] = ["stable", "beta"];
/// Target vocabulary frozen by `wallet/update-manifest.template.json`.
pub const PLATFORMS: [&str; 3] = ["windows", "linux", "macos"];
pub const ARCHES: [&str; 2] = ["x86_64", "aarch64"];
/// Environment variable naming the updater public key (product-identity).
pub const UPDATER_PUBLIC_KEY_ENV: &str = "NOOS_WALLET_UPDATER_PUBLIC_KEY";
/// Domain separator for the detached update signature.
pub const UPDATE_SIGNING_DOMAIN: &str = "NOOS/WALLET/UPDATE/V1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ManifestError {
    #[error("invalid_update_manifest")]
    InvalidUpdateManifest,
    #[error("wrong_protocol_identity")]
    WrongProtocolIdentity,
    #[error("wrong_update_target")]
    WrongUpdateTarget,
    #[error("bad_signature")]
    BadSignature,
    #[error("invalid_updater_key")]
    InvalidUpdaterKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub app_id: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub platform: String,
    pub arch: String,
    pub version: String,
    pub channel: String,
    pub artifact_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedIdentity {
    pub chain_id: String,
    pub genesis_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTarget {
    pub platform: String,
    pub arch: String,
    /// Channel this installation is subscribed to; a manifest for any other
    /// channel is a wrong target even when correctly signed.
    pub channel: String,
}

fn is_hash64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Canonical signing bytes: domain line followed by the eight non-signature
/// fields as `key=value` lines in template order. Every byte is bound; there
/// is no canonicalization ambiguity to exploit.
#[must_use]
pub fn signing_bytes(m: &UpdateManifest) -> Vec<u8> {
    let fields = [
        ("app_id", m.app_id.as_str()),
        ("chain_id", m.chain_id.as_str()),
        ("genesis_hash", m.genesis_hash.as_str()),
        ("platform", m.platform.as_str()),
        ("arch", m.arch.as_str()),
        ("version", m.version.as_str()),
        ("channel", m.channel.as_str()),
        ("artifact_sha256", m.artifact_sha256.as_str()),
    ];
    let mut out = Vec::new();
    out.extend_from_slice(UPDATE_SIGNING_DOMAIN.as_bytes());
    for (key, value) in fields {
        out.push(b'\n');
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Parse a 32-byte lowercase-hex Ed25519 updater public key.
pub fn updater_key_from_hex(key_hex: &str) -> Result<VerifyingKey, ManifestError> {
    if key_hex.len() != 64 || key_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ManifestError::InvalidUpdaterKey);
    }
    let bytes = hex::decode(key_hex).map_err(|_| ManifestError::InvalidUpdaterKey)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ManifestError::InvalidUpdaterKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ManifestError::InvalidUpdaterKey)
}

/// Full verification: structure, identity binding, target binding, artifact
/// hash canonicality, and the detached updater signature.
pub fn verify(
    m: &UpdateManifest,
    expected: &ExpectedIdentity,
    runtime: &RuntimeTarget,
    updater_key: &VerifyingKey,
) -> Result<(), ManifestError> {
    let required = [
        &m.app_id,
        &m.chain_id,
        &m.genesis_hash,
        &m.platform,
        &m.arch,
        &m.version,
        &m.channel,
        &m.artifact_sha256,
        &m.signature,
    ];
    if required.iter().any(|f| f.is_empty()) {
        return Err(ManifestError::InvalidUpdateManifest);
    }
    if !is_hash64(&m.chain_id) || !is_hash64(&m.genesis_hash) || !is_hash64(&m.artifact_sha256) {
        return Err(ManifestError::InvalidUpdateManifest);
    }
    if !is_hash64(&expected.chain_id) || !is_hash64(&expected.genesis_hash) {
        return Err(ManifestError::InvalidUpdateManifest);
    }
    if m.app_id != APP_ID
        || m.chain_id != expected.chain_id
        || m.genesis_hash != expected.genesis_hash
    {
        return Err(ManifestError::WrongProtocolIdentity);
    }
    if !PLATFORMS.contains(&m.platform.as_str())
        || !ARCHES.contains(&m.arch.as_str())
        || m.platform != runtime.platform
        || m.arch != runtime.arch
        || !CHANNELS.contains(&m.channel.as_str())
        || m.channel != runtime.channel
    {
        return Err(ManifestError::WrongUpdateTarget);
    }
    if m.signature.len() != 128 || m.signature.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ManifestError::InvalidUpdateManifest);
    }
    let sig_bytes = hex::decode(&m.signature).map_err(|_| ManifestError::InvalidUpdateManifest)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ManifestError::InvalidUpdateManifest)?;
    let signature = Signature::from_bytes(&sig_arr);
    updater_key
        .verify_strict(&signing_bytes(m), &signature)
        .map_err(|_| ManifestError::BadSignature)
}
