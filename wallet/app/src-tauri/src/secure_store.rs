//! Operating-system-bound seed custody for the native wallet shell.
//!
//! The UI receives only an opaque wallet id. Seed bytes are written to and
//! read from the platform credential vault by the Rust process and are
//! zeroized immediately after the requested operation.

use keyring::Entry;
use noos_wallet::EncryptedKeystore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const SERVICE: &str = "org.noosphere.mindchain-wallet.seed.v1";
const MIN_SEED_BYTES: usize = 16;
const MAX_SEED_BYTES: usize = 128;
const BROWSER_VAULT_SERVICE: &str = "org.noosphere.mindchain-browser-vault.v1";
const BROWSER_VAULT_KEY_BYTES: usize = 32;
const RECOVERY_SCHEMA: &str = "noos-wallet-recovery-v1";
const RECOVERY_DOMAIN: &[u8] = b"NOOS/WALLET/RECOVERY-PAYLOAD/V1\0";
const MIN_RECOVERY_PASSWORD_BYTES: usize = 12;
const MAX_RECOVERY_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Error)]
pub enum SecureStoreError {
    #[error("invalid_wallet_id")]
    InvalidWalletId,
    #[error("invalid_seed")]
    InvalidSeed,
    #[error("invalid_browser_vault_key")]
    InvalidBrowserVaultKey,
    #[error("secure_store_unavailable")]
    Unavailable,
    #[error("wallet_not_found")]
    NotFound,
    #[error("browser_vault_not_found")]
    BrowserVaultNotFound,
    #[error("invalid_recovery_package")]
    InvalidRecoveryPackage,
    #[error("recovery_authentication_failed")]
    RecoveryAuthentication,
    #[error("wrong_protocol_identity")]
    WrongProtocolIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletHandle {
    pub wallet_id: String,
    pub protection: String,
    pub secret_exported_to_ui: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserVaultHandle {
    pub profile_id: String,
    pub protection: String,
    pub secret_exported_to_ui: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPackage {
    pub schema: String,
    pub wallet_id: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub keystore: EncryptedKeystore,
}

fn validate_wallet_id(wallet_id: &str) -> Result<(), SecureStoreError> {
    if !(3..=64).contains(&wallet_id.len())
        || wallet_id
            .bytes()
            .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')))
    {
        return Err(SecureStoreError::InvalidWalletId);
    }
    Ok(())
}

fn entry(wallet_id: &str) -> Result<Entry, SecureStoreError> {
    validate_wallet_id(wallet_id)?;
    Entry::new(SERVICE, wallet_id).map_err(|_| SecureStoreError::Unavailable)
}

fn browser_vault_entry(profile_id: &str) -> Result<Entry, SecureStoreError> {
    validate_wallet_id(profile_id)?;
    Entry::new(BROWSER_VAULT_SERVICE, profile_id).map_err(|_| SecureStoreError::Unavailable)
}

/// Import seed material into the logged-in user's native credential vault.
/// Existing ids are intentionally replaced so recovery/import is atomic.
pub fn import_seed(wallet_id: &str, seed_hex: &str) -> Result<WalletHandle, SecureStoreError> {
    if seed_hex.len() % 2 != 0
        || seed_hex.bytes().any(|b| b.is_ascii_uppercase())
        || !seed_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(SecureStoreError::InvalidSeed);
    }
    let seed = Zeroizing::new(hex::decode(seed_hex).map_err(|_| SecureStoreError::InvalidSeed)?);
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&seed.len()) {
        return Err(SecureStoreError::InvalidSeed);
    }
    entry(wallet_id)?
        .set_secret(seed.as_slice())
        .map_err(|_| SecureStoreError::Unavailable)?;
    Ok(WalletHandle {
        wallet_id: wallet_id.to_owned(),
        protection: platform_protection().to_owned(),
        secret_exported_to_ui: false,
    })
}

/// Load seed bytes only into zeroizing Rust memory. Callers must not return,
/// log, serialize, or persist this value.
pub fn load_seed(wallet_id: &str) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    let secret = entry(wallet_id)?
        .get_secret()
        .map_err(|error| match error {
            keyring::Error::NoEntry => SecureStoreError::NotFound,
            _ => SecureStoreError::Unavailable,
        })?;
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&secret.len()) {
        return Err(SecureStoreError::InvalidSeed);
    }
    Ok(Zeroizing::new(secret))
}

pub fn delete_seed(wallet_id: &str) -> Result<(), SecureStoreError> {
    entry(wallet_id)?
        .delete_credential()
        .map_err(|error| match error {
            keyring::Error::NoEntry => SecureStoreError::NotFound,
            _ => SecureStoreError::Unavailable,
        })
}

/// Store a 32-byte browser-vault root generated inside the trusted native
/// process. UI commands must never accept or return this key.
pub fn store_browser_vault_key(
    profile_id: &str,
    key: Zeroizing<Vec<u8>>,
) -> Result<BrowserVaultHandle, SecureStoreError> {
    if key.len() != BROWSER_VAULT_KEY_BYTES {
        return Err(SecureStoreError::InvalidBrowserVaultKey);
    }
    browser_vault_entry(profile_id)?
        .set_secret(key.as_slice())
        .map_err(|_| SecureStoreError::Unavailable)?;
    Ok(BrowserVaultHandle {
        profile_id: profile_id.to_owned(),
        protection: platform_protection().to_owned(),
        secret_exported_to_ui: false,
    })
}

/// Load the root only into zeroizing Rust memory for per-origin key
/// derivation. Callers must not serialize, log, or return it to web content.
pub fn load_browser_vault_key(
    profile_id: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    let secret = browser_vault_entry(profile_id)?
        .get_secret()
        .map_err(|error| match error {
            keyring::Error::NoEntry => SecureStoreError::BrowserVaultNotFound,
            _ => SecureStoreError::Unavailable,
        })?;
    if secret.len() != BROWSER_VAULT_KEY_BYTES {
        return Err(SecureStoreError::InvalidBrowserVaultKey);
    }
    Ok(Zeroizing::new(secret))
}

pub fn delete_browser_vault_key(profile_id: &str) -> Result<(), SecureStoreError> {
    browser_vault_entry(profile_id)?
        .delete_credential()
        .map_err(|error| match error {
            keyring::Error::NoEntry => SecureStoreError::BrowserVaultNotFound,
            _ => SecureStoreError::Unavailable,
        })
}

fn parse_hash32(value: &str) -> Result<[u8; 32], SecureStoreError> {
    if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(SecureStoreError::WrongProtocolIdentity);
    }
    hex::decode(value)
        .map_err(|_| SecureStoreError::WrongProtocolIdentity)?
        .try_into()
        .map_err(|_| SecureStoreError::WrongProtocolIdentity)
}

fn validate_recovery_password(password: &[u8]) -> Result<(), SecureStoreError> {
    if !(MIN_RECOVERY_PASSWORD_BYTES..=MAX_RECOVERY_PASSWORD_BYTES).contains(&password.len()) {
        return Err(SecureStoreError::RecoveryAuthentication);
    }
    Ok(())
}

fn recovery_payload(
    wallet_id: &str,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    validate_wallet_id(wallet_id)?;
    if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&seed.len()) {
        return Err(SecureStoreError::InvalidSeed);
    }
    let wallet_id_length =
        u8::try_from(wallet_id.len()).map_err(|_| SecureStoreError::InvalidRecoveryPackage)?;
    let seed_length =
        u16::try_from(seed.len()).map_err(|_| SecureStoreError::InvalidRecoveryPackage)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(
        RECOVERY_DOMAIN
            .len()
            .saturating_add(wallet_id.len())
            .saturating_add(seed.len())
            .saturating_add(67),
    ));
    payload.extend_from_slice(RECOVERY_DOMAIN);
    payload.push(wallet_id_length);
    payload.extend_from_slice(wallet_id.as_bytes());
    payload.extend_from_slice(&chain_id);
    payload.extend_from_slice(&genesis_hash);
    payload.extend_from_slice(&seed_length.to_le_bytes());
    payload.extend_from_slice(seed);
    Ok(payload)
}

fn decode_recovery_payload(
    payload: &[u8],
    expected_wallet_id: &str,
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    let mut remaining = payload
        .strip_prefix(RECOVERY_DOMAIN)
        .ok_or(SecureStoreError::InvalidRecoveryPackage)?;
    let (&wallet_length, rest) = remaining
        .split_first()
        .ok_or(SecureStoreError::InvalidRecoveryPackage)?;
    remaining = rest;
    let wallet_length = usize::from(wallet_length);
    if remaining.len() < wallet_length {
        return Err(SecureStoreError::InvalidRecoveryPackage);
    }
    let (wallet_bytes, rest) = remaining.split_at(wallet_length);
    remaining = rest;
    if wallet_bytes != expected_wallet_id.as_bytes() || remaining.len() < 66 {
        return Err(SecureStoreError::WrongProtocolIdentity);
    }
    let (chain_id, rest) = remaining.split_at(32);
    let (genesis_hash, rest) = rest.split_at(32);
    let (seed_length, seed) = rest.split_at(2);
    if chain_id != expected_chain_id
        || genesis_hash != expected_genesis_hash
        || usize::from(u16::from_le_bytes([seed_length[0], seed_length[1]])) != seed.len()
        || !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&seed.len())
    {
        return Err(SecureStoreError::WrongProtocolIdentity);
    }
    Ok(Zeroizing::new(seed.to_vec()))
}

fn seal_recovery_package(
    wallet_id: &str,
    chain_id: &str,
    genesis_hash: &str,
    seed: &[u8],
    password: &[u8],
) -> Result<RecoveryPackage, SecureStoreError> {
    validate_recovery_password(password)?;
    let chain_id_bytes = parse_hash32(chain_id)?;
    let genesis_hash_bytes = parse_hash32(genesis_hash)?;
    let payload = recovery_payload(wallet_id, chain_id_bytes, genesis_hash_bytes, seed)?;
    let keystore = EncryptedKeystore::seal(&payload, password)
        .map_err(|_| SecureStoreError::InvalidRecoveryPackage)?;
    Ok(RecoveryPackage {
        schema: RECOVERY_SCHEMA.to_owned(),
        wallet_id: wallet_id.to_owned(),
        chain_id: chain_id.to_owned(),
        genesis_hash: genesis_hash.to_owned(),
        keystore,
    })
}

fn open_recovery_package(
    package: &RecoveryPackage,
    expected_wallet_id: &str,
    expected_chain_id: &str,
    expected_genesis_hash: &str,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    validate_wallet_id(expected_wallet_id)?;
    validate_recovery_password(password)?;
    let chain_id = parse_hash32(expected_chain_id)?;
    let genesis_hash = parse_hash32(expected_genesis_hash)?;
    if package.schema != RECOVERY_SCHEMA
        || package.wallet_id != expected_wallet_id
        || package.chain_id != expected_chain_id
        || package.genesis_hash != expected_genesis_hash
    {
        return Err(SecureStoreError::WrongProtocolIdentity);
    }
    let payload = Zeroizing::new(
        package
            .keystore
            .open(password)
            .map_err(|_| SecureStoreError::RecoveryAuthentication)?,
    );
    decode_recovery_payload(
        &payload,
        expected_wallet_id,
        chain_id,
        genesis_hash,
    )
}

pub fn export_recovery_package(
    wallet_id: &str,
    chain_id: &str,
    genesis_hash: &str,
    password: &[u8],
) -> Result<String, SecureStoreError> {
    let seed = load_seed(wallet_id)?;
    let package = seal_recovery_package(wallet_id, chain_id, genesis_hash, &seed, password)?;
    serde_json::to_string(&package).map_err(|_| SecureStoreError::InvalidRecoveryPackage)
}

pub fn import_recovery_package(
    wallet_id: &str,
    chain_id: &str,
    genesis_hash: &str,
    package_json: &str,
    password: &[u8],
) -> Result<WalletHandle, SecureStoreError> {
    if package_json.is_empty() || package_json.len() > 1_048_576 {
        return Err(SecureStoreError::InvalidRecoveryPackage);
    }
    let package: RecoveryPackage = serde_json::from_str(package_json)
        .map_err(|_| SecureStoreError::InvalidRecoveryPackage)?;
    let seed = open_recovery_package(
        &package,
        wallet_id,
        chain_id,
        genesis_hash,
        password,
    )?;
    entry(wallet_id)?
        .set_secret(&seed)
        .map_err(|_| SecureStoreError::Unavailable)?;
    Ok(WalletHandle {
        wallet_id: wallet_id.to_owned(),
        protection: platform_protection().to_owned(),
        secret_exported_to_ui: false,
    })
}

fn platform_protection() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "WINDOWS_CREDENTIAL_MANAGER_DPAPI"
    }
    #[cfg(target_os = "macos")]
    {
        "MACOS_KEYCHAIN"
    }
    #[cfg(target_os = "linux")]
    {
        "LINUX_SECRET_SERVICE"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "UNSUPPORTED"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_ids_are_strict_opaque_handles() {
        assert!(validate_wallet_id("primary-01").is_ok());
        for invalid in ["ab", "Primary", "../seed", "has space", ""] {
            assert_eq!(
                validate_wallet_id(invalid).unwrap_err().to_string(),
                "invalid_wallet_id"
            );
        }
    }

    #[test]
    fn browser_vault_root_is_exactly_32_bytes() {
        let error = store_browser_vault_key(
            "browser-primary",
            Zeroizing::new(vec![7; BROWSER_VAULT_KEY_BYTES - 1]),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid_browser_vault_key");
    }

    #[test]
    fn recovery_package_round_trip_binds_wallet_and_chain() {
        let seed = vec![0x42; 64];
        let password = b"correct horse battery staple";
        let chain_id = "11".repeat(32);
        let genesis_hash = "22".repeat(32);
        let package =
            seal_recovery_package("primary", &chain_id, &genesis_hash, &seed, password).unwrap();
        let encoded = serde_json::to_string(&package).unwrap();
        assert!(!encoded.contains(&hex::encode(&seed)));
        let decoded: RecoveryPackage = serde_json::from_str(&encoded).unwrap();
        let recovered =
            open_recovery_package(&decoded, "primary", &chain_id, &genesis_hash, password).unwrap();
        assert_eq!(recovered.as_slice(), seed.as_slice());

        let mut wrong_chain = decoded.clone();
        wrong_chain.chain_id = "33".repeat(32);
        assert_eq!(
            open_recovery_package(
                &wrong_chain,
                "primary",
                &chain_id,
                &genesis_hash,
                password
            )
            .unwrap_err()
            .to_string(),
            "wrong_protocol_identity"
        );
    }

    #[test]
    fn recovery_package_rejects_wrong_password_and_weak_password() {
        let seed = vec![0x24; 64];
        let chain_id = "11".repeat(32);
        let genesis_hash = "22".repeat(32);
        let package = seal_recovery_package(
            "primary",
            &chain_id,
            &genesis_hash,
            &seed,
            b"correct horse battery staple",
        )
        .unwrap();
        assert_eq!(
            open_recovery_package(
                &package,
                "primary",
                &chain_id,
                &genesis_hash,
                b"incorrect password"
            )
            .unwrap_err()
            .to_string(),
            "recovery_authentication_failed"
        );
        assert_eq!(
            seal_recovery_package("primary", &chain_id, &genesis_hash, &seed, b"short")
                .unwrap_err()
                .to_string(),
            "recovery_authentication_failed"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_recovery_round_trip_uses_the_native_credential_vault() {
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete_seed(&self.0);
            }
        }

        let wallet_id = format!("noos-recovery-test-{}", std::process::id());
        let _cleanup = Cleanup(wallet_id.clone());
        let _ = delete_seed(&wallet_id);
        let seed_hex = "5a".repeat(64);
        let chain_id = "11".repeat(32);
        let genesis_hash = "22".repeat(32);
        let password = b"native vault recovery password";
        let handle = import_seed(&wallet_id, &seed_hex).unwrap();
        assert_eq!(handle.protection, "WINDOWS_CREDENTIAL_MANAGER_DPAPI");
        let package =
            export_recovery_package(&wallet_id, &chain_id, &genesis_hash, password).unwrap();
        assert!(!package.contains(&seed_hex));
        delete_seed(&wallet_id).unwrap();
        import_recovery_package(
            &wallet_id,
            &chain_id,
            &genesis_hash,
            &package,
            password,
        )
        .unwrap();
        assert_eq!(load_seed(&wallet_id).unwrap().as_slice(), vec![0x5a; 64]);
    }

    #[test]
    fn protection_is_an_explicit_native_backend() {
        assert_ne!(platform_protection(), "UNSUPPORTED");
    }
}
