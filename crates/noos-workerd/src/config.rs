//! Minimal TOML-subset config loader for the worker daemon.
//!
//! Accepted grammar (one construct per line, full-line `#` comments only):
//!
//! ```toml
//! [section]
//! key = "quoted string"
//! key = bare_token
//! ```
//!
//! Keys are addressed as `section.key`. Unknown keys are tolerated so a
//! deployment file may carry operator-only annotations; missing required
//! keys are typed errors, never defaults.

use crate::hex::decode_hex32;
use std::collections::BTreeMap;
use std::fmt;

/// Worker daemon configuration.
pub struct Config {
    /// Ed25519 receipt-signing seed. Dev/test files carry fixed seeds;
    /// production operators feed OS-CSPRNG output. The daemon itself never
    /// draws entropy.
    pub seed: [u8; 32],
    /// Chain the emitted receipts bind to (first 32 bytes of every body).
    pub chain_id: [u8; 32],
}

impl fmt::Debug for Config {
    /// The signing seed is never printed, mirroring `noos_crypto::Keypair`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

/// Typed configuration failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A line is neither blank, comment, section header, nor `key = value`.
    Syntax { line: usize },
    /// A required key is absent.
    MissingKey(&'static str),
    /// A key is present but not 64 lowercase hex chars.
    BadHex(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { line } => write!(f, "config syntax error on line {line}"),
            Self::MissingKey(key) => write!(f, "config missing required key {key}"),
            Self::BadHex(key) => write!(f, "config key {key} must be 64 lowercase hex chars"),
        }
    }
}

fn parse_toml(text: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut map = BTreeMap::new();
    let mut section = String::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let line_no = index.saturating_add(1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[') {
            let Some(name) = inner.strip_suffix(']') else {
                return Err(ConfigError::Syntax { line: line_no });
            };
            let name = name.trim();
            if name.is_empty() {
                return Err(ConfigError::Syntax { line: line_no });
            }
            section = name.to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError::Syntax { line: line_no });
        };
        let key = key.trim();
        let mut value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(ConfigError::Syntax { line: line_no });
        }
        if let Some(inner) = value.strip_prefix('"') {
            let Some(inner) = inner.strip_suffix('"') else {
                return Err(ConfigError::Syntax { line: line_no });
            };
            value = inner;
        }
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        map.insert(full_key, value.to_owned());
    }
    Ok(map)
}

fn hex_key(map: &BTreeMap<String, String>, key: &'static str) -> Result<[u8; 32], ConfigError> {
    let value = map.get(key).ok_or(ConfigError::MissingKey(key))?;
    decode_hex32(value).ok_or(ConfigError::BadHex(key))
}

/// Parses configuration text into a validated [`Config`].
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let map = parse_toml(text)?;
    Ok(Config {
        seed: hex_key(&map, "worker.seed_hex")?,
        chain_id: hex_key(&map, "worker.chain_id_hex")?,
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

    fn sample(seed: &str, chain: &str) -> String {
        format!("# dev file\n[worker]\nseed_hex = \"{seed}\"\nchain_id_hex = \"{chain}\"\n")
    }

    #[test]
    fn parses_a_valid_file() {
        let seed = "11".repeat(32);
        let chain = "22".repeat(32);
        let cfg = parse(&sample(&seed, &chain)).unwrap();
        assert_eq!(cfg.seed, [0x11; 32]);
        assert_eq!(cfg.chain_id, [0x22; 32]);
    }

    #[test]
    fn missing_and_malformed_keys_are_typed_errors() {
        assert_eq!(
            parse("[worker]\nchain_id_hex = \"aa\"\n").unwrap_err(),
            ConfigError::MissingKey("worker.seed_hex")
        );
        let short = sample("beef", &"22".repeat(32));
        assert_eq!(
            parse(&short).unwrap_err(),
            ConfigError::BadHex("worker.seed_hex")
        );
    }

    #[test]
    fn syntax_errors_carry_the_line_number() {
        assert_eq!(
            parse("[worker\nseed_hex = \"aa\"\n").unwrap_err(),
            ConfigError::Syntax { line: 1 }
        );
        assert_eq!(
            parse("[worker]\nnot a key value pair\n").unwrap_err(),
            ConfigError::Syntax { line: 2 }
        );
    }

    #[test]
    fn a_forged_seed_in_another_section_is_not_accepted() {
        // The registry key is section-qualified: `[other] seed_hex` must not
        // satisfy the `worker.seed_hex` requirement.
        let text = format!(
            "[other]\nseed_hex = \"{}\"\nchain_id_hex = \"{}\"\n",
            "11".repeat(32),
            "22".repeat(32)
        );
        assert_eq!(
            parse(&text).unwrap_err(),
            ConfigError::MissingKey("worker.seed_hex")
        );
    }
}
