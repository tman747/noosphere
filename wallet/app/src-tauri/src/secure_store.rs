//! Operating-system-bound seed custody for the native wallet shell.
//!
//! The UI receives only an opaque wallet id. Seed bytes are written to and
//! read from the platform credential vault by the Rust process and are
//! zeroized immediately after the requested operation.

use keyring::Entry;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const SERVICE: &str = "org.noosphere.mindchain-wallet.seed.v1";
const MIN_SEED_BYTES: usize = 16;
const MAX_SEED_BYTES: usize = 128;
const BROWSER_VAULT_SERVICE: &str = "org.noosphere.mindchain-browser-vault.v1";
const BROWSER_VAULT_KEY_BYTES: usize = 32;

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
    fn protection_is_an_explicit_native_backend() {
        assert_ne!(platform_protection(), "UNSUPPORTED");
    }
}
