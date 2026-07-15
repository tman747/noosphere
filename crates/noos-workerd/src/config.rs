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
use noos_nel::runtime::{
    PrismBuildIdentityV2, BONSAI_EXECUTION_PROFILE, BONSAI_Q1_BYTE_LENGTH, BONSAI_Q1_SHA256,
    PRISM_LLAMA_CPP_COMMIT,
};
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

/// Canonical Bonsai artifact identity. A differently named, resized, or
/// re-hashed file is substitution, even if a runtime could load it.
pub const BONSAI_MODEL_NAME: &str = "Bonsai-27B-Q1_0.gguf";
pub const BONSAI_MODEL_BYTES: u64 = BONSAI_Q1_BYTE_LENGTH;
pub const BONSAI_MODEL_SHA256: &str =
    "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0";
pub const BONSAI_MANIFEST_ROOT: &str =
    "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7";
pub const BONSAI_MODEL_ALIAS: &str = "bonsai-q1";
pub const PRISM_LLAMA_COMMIT: &str = PRISM_LLAMA_CPP_COMMIT;

/// Strict protocol-v2 worker configuration. Every nested table rejects
/// unknown fields so misspelled security and capacity controls cannot
/// silently turn into defaults.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorConfig {
    pub worker: ExecutorWorkerConfig,
    pub model: ModelConfig,
    pub runtime: RuntimeConfig,
    pub scheduler: SchedulerConfig,
    pub identity: IdentityConfig,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorWorkerConfig {
    pub seed_hex: String,
    pub chain_id_hex: String,
    pub genesis_hash_hex: String,
    pub sidecar_token_hex: String,
    pub listen: String,
    pub scratch_dir: std::path::PathBuf,
    pub drain_file: std::path::PathBuf,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub name: String,
    pub path: std::path::PathBuf,
    pub manifest_path: std::path::PathBuf,
    pub custodian_map_path: std::path::PathBuf,
    pub bytes: u64,
    pub sha256_hex: String,
    pub manifest_root_hex: String,
    pub artifact_id_hex: String,
    pub capsule_id_hex: String,
    pub tokenizer_id_hex: String,
    pub template_id_hex: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub executable: std::path::PathBuf,
    pub source_commit: String,
    pub target_triple: String,
    pub toolchain: String,
    pub build_flags: Vec<String>,
    pub binary_sha256_hex: String,
    pub runtime_root_hex: String,
    pub build_root_hex: String,
    pub sbom_root_hex: String,
    pub build_id_hex: String,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerConfig {
    pub max_concurrent: usize,
    pub max_queue: usize,
    pub max_context_tokens: u32,
    pub max_output_tokens: u32,
    pub job_timeout_ms: u64,
    pub cancel_grace_ms: u64,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub finalized_resolution_path: std::path::PathBuf,
    pub model_alias: String,
    pub trusted_checkpoint_epoch: u64,
    pub trusted_checkpoint_height: u64,
    pub trusted_checkpoint_hash_hex: String,
    pub current_finalized_height: u64,
    pub worker_id_hex: String,
    pub certificate_id_hex: String,
    pub executor_set_epoch: u64,
    pub custodian_set_epoch: u64,
    pub service_directory_epoch: u64,
}

impl fmt::Debug for ExecutorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutorConfig")
            .field("chain_id_hex", &self.worker.chain_id_hex)
            .field("listen", &self.worker.listen)
            .field("model", &self.model)
            .field("runtime", &self.runtime)
            .field("scheduler", &self.scheduler)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorConfigError {
    Toml(String),
    Invalid(&'static str),
}

impl fmt::Display for ExecutorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(message) => write!(f, "strict config: {message}"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for ExecutorConfigError {}

impl ExecutorConfig {
    pub fn parse(text: &str) -> Result<Self, ExecutorConfigError> {
        let config: Self =
            toml::from_str(text).map_err(|error| ExecutorConfigError::Toml(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ExecutorConfigError> {
        if decode_hex32(&self.worker.seed_hex).is_none()
            || decode_hex32(&self.worker.chain_id_hex).is_none()
            || decode_hex32(&self.worker.genesis_hash_hex).is_none()
            || decode_hex32(&self.worker.sidecar_token_hex).is_none()
        {
            return Err(ExecutorConfigError::Invalid(
                "worker identities and secrets must be 64 lowercase hex characters",
            ));
        }
        let seed = decode_hex32(&self.worker.seed_hex)
            .ok_or(ExecutorConfigError::Invalid("invalid signer seed"))?;
        let token = decode_hex32(&self.worker.sidecar_token_hex)
            .ok_or(ExecutorConfigError::Invalid("invalid sidecar token"))?;
        if seed == [0; 32] || token == [0; 32] || seed == token {
            return Err(ExecutorConfigError::Invalid(
                "signer seed and per-boot sidecar token must be nonzero and distinct",
            ));
        }
        for value in [
            &self.model.sha256_hex,
            &self.model.manifest_root_hex,
            &self.model.artifact_id_hex,
            &self.model.capsule_id_hex,
            &self.model.tokenizer_id_hex,
            &self.model.template_id_hex,
            &self.runtime.binary_sha256_hex,
            &self.runtime.runtime_root_hex,
            &self.runtime.build_root_hex,
            &self.runtime.sbom_root_hex,
            &self.runtime.build_id_hex,
            &self.identity.worker_id_hex,
            &self.identity.certificate_id_hex,
            &self.identity.trusted_checkpoint_hash_hex,
        ] {
            if decode_hex32(value).is_none() {
                return Err(ExecutorConfigError::Invalid(
                    "model, runtime, and identity digests must be 64 lowercase hex characters",
                ));
            }
        }
        if self.model.name != BONSAI_MODEL_NAME
            || self.model.bytes != BONSAI_Q1_BYTE_LENGTH
            || decode_hex32(&self.model.sha256_hex) != Some(BONSAI_Q1_SHA256)
            || self.model.manifest_root_hex != BONSAI_MANIFEST_ROOT
        {
            return Err(ExecutorConfigError::Invalid(
                "exact Bonsai-27B-Q1_0 artifact identity required",
            ));
        }
        if self.model.path.as_os_str().is_empty()
            || self.model.manifest_path.as_os_str().is_empty()
            || self.model.custodian_map_path.as_os_str().is_empty()
            || self.model.path == self.model.manifest_path
            || self.model.path == self.model.custodian_map_path
            || self.model.manifest_path == self.model.custodian_map_path
        {
            return Err(ExecutorConfigError::Invalid(
                "model cache, manifest, and custodian map paths must be nonempty and distinct",
            ));
        }
        if self.runtime.source_commit != PRISM_LLAMA_CPP_COMMIT {
            return Err(ExecutorConfigError::Invalid(
                "exact pinned Prism llama.cpp commit required",
            ));
        }
        let build = self.runtime_build_identity()?;
        if build.build_id().ok() != decode_hex32(&self.runtime.build_id_hex) {
            return Err(ExecutorConfigError::Invalid(
                "runtime build ID does not match canonical PrismBuildIdentityV2",
            ));
        }
        crate::executor::security::SidecarEndpoint::parse(&self.worker.listen)
            .map_err(|_| ExecutorConfigError::Invalid("sidecar listener must be private"))?;
        crate::executor::security::validate_runtime_args(&self.runtime.extra_args)
            .map_err(|_| ExecutorConfigError::Invalid("runtime network arguments are forbidden"))?;
        if self.scheduler.max_concurrent == 0
            || self.scheduler.max_queue == 0
            || self.scheduler.max_context_tokens != BONSAI_EXECUTION_PROFILE.max_context_tokens
            || self.scheduler.max_output_tokens != BONSAI_EXECUTION_PROFILE.max_output_tokens
            || self.scheduler.job_timeout_ms == 0
            || self.scheduler.cancel_grace_ms == 0
        {
            return Err(ExecutorConfigError::Invalid(
                "scheduler must use the exact Bonsai execution profile and positive bounds",
            ));
        }
        if self.worker.scratch_dir == self.model.path
            || self
                .worker
                .scratch_dir
                .starts_with(self.model.path.parent().unwrap_or(&self.model.path))
        {
            return Err(ExecutorConfigError::Invalid(
                "runtime scratch must be separate from model weights",
            ));
        }
        if self.identity.model_alias != BONSAI_MODEL_ALIAS
            || self.identity.current_finalized_height < self.identity.trusted_checkpoint_height
        {
            return Err(ExecutorConfigError::Invalid(
                "identity must pin the Bonsai alias and a non-future trusted checkpoint",
            ));
        }
        Ok(())
    }

    pub fn runtime_build_identity(&self) -> Result<PrismBuildIdentityV2, ExecutorConfigError> {
        let build = PrismBuildIdentityV2 {
            source_commit: self.runtime.source_commit.clone(),
            target_triple: self.runtime.target_triple.clone(),
            toolchain: self.runtime.toolchain.clone(),
            build_flags: self.runtime.build_flags.clone(),
            binary_sha256: decode_hex32(&self.runtime.binary_sha256_hex).ok_or(
                ExecutorConfigError::Invalid("invalid runtime binary digest"),
            )?,
            sbom_root: decode_hex32(&self.runtime.sbom_root_hex)
                .ok_or(ExecutorConfigError::Invalid("invalid runtime SBOM root"))?,
        };
        build
            .validate()
            .map_err(|_| ExecutorConfigError::Invalid("invalid canonical PrismBuildIdentityV2"))?;
        Ok(build)
    }

    pub fn seed(&self) -> [u8; 32] {
        decode_hex32(&self.worker.seed_hex).expect("validated executor seed")
    }

    pub fn sidecar_token(&self) -> [u8; 32] {
        decode_hex32(&self.worker.sidecar_token_hex).expect("validated sidecar token")
    }
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

#[cfg(test)]
mod executor_tests {
    use super::*;

    fn valid() -> String {
        format!(
            r#"
[worker]
seed_hex = "{seed}"
chain_id_hex = "{chain}"
genesis_hash_hex = "{genesis}"
sidecar_token_hex = "{token}"
listen = "tcp://127.0.0.1:9807"
scratch_dir = "state/runtime"
drain_file = "state/drain"

[model]
name = "{name}"
path = "artifacts/{name}"
manifest_path = "artifacts/manifest.bin"
custodian_map_path = "state/custodians.json"
bytes = {bytes}
sha256_hex = "{sha}"
manifest_root_hex = "{manifest}"
artifact_id_hex = "{artifact}"
capsule_id_hex = "{capsule}"
tokenizer_id_hex = "{tokenizer}"
template_id_hex = "{template}"

[runtime]
executable = "runtime/llama-cli"
source_commit = "{commit}"
target_triple = "x86_64-pc-windows-msvc"
toolchain = "msvc-19.44"
build_flags = ["GGML_HIP=ON", "LLAMA_CURL=OFF"]
binary_sha256_hex = "{binary}"
runtime_root_hex = "{runtime_root}"
build_root_hex = "{build_root}"
sbom_root_hex = "{sbom}"
build_id_hex = "{build_id}"
extra_args = []

[scheduler]
max_concurrent = 1
max_queue = 2
max_context_tokens = 4096
max_output_tokens = 512
job_timeout_ms = 10000
cancel_grace_ms = 100

[identity]
finalized_resolution_path = "state/resolution.json"
model_alias = "{model_alias}"
trusted_checkpoint_epoch = 0
trusted_checkpoint_height = 0
trusted_checkpoint_hash_hex = "{checkpoint}"
current_finalized_height = 0
worker_id_hex = "{worker}"
certificate_id_hex = "{certificate}"
executor_set_epoch = 1
custodian_set_epoch = 1
service_directory_epoch = 1
"#,
            seed = "11".repeat(32),
            chain = "22".repeat(32),
            genesis = "33".repeat(32),
            token = "44".repeat(32),
            name = BONSAI_MODEL_NAME,
            bytes = BONSAI_MODEL_BYTES,
            sha = BONSAI_MODEL_SHA256,
            manifest = BONSAI_MANIFEST_ROOT,
            artifact = "55".repeat(32),
            capsule = "66".repeat(32),
            tokenizer = "77".repeat(32),
            template = "88".repeat(32),
            commit = PRISM_LLAMA_COMMIT,
            binary = "01".repeat(32),
            runtime_root = "03".repeat(32),
            build_root = "04".repeat(32),
            sbom = "02".repeat(32),
            build_id = "cc3b974794423ff144cb70a6456d954f1f7759e8142d7b86b3d69d238e2142e8",
            model_alias = BONSAI_MODEL_ALIAS,
            checkpoint = "05".repeat(32),
            worker = "aa".repeat(32),
            certificate = "bb".repeat(32),
        )
    }

    #[test]
    fn v2_is_strict_and_redacts_secrets() {
        let config = ExecutorConfig::parse(&valid()).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(&"11".repeat(32)));
        assert!(!debug.contains(&"44".repeat(32)));
        let unknown = valid().replace("[scheduler]", "[scheduler]\nconcurency = 9");
        assert!(matches!(
            ExecutorConfig::parse(&unknown),
            Err(ExecutorConfigError::Toml(_))
        ));
    }

    #[test]
    fn exact_model_and_runtime_substitution_are_rejected() {
        let wrong_model = valid().replace(BONSAI_MODEL_SHA256, &"00".repeat(32));
        assert_eq!(
            ExecutorConfig::parse(&wrong_model).unwrap_err(),
            ExecutorConfigError::Invalid("exact Bonsai-27B-Q1_0 artifact identity required")
        );
        let wrong_runtime = valid().replace(
            PRISM_LLAMA_COMMIT,
            "0000000000000000000000000000000000000000",
        );
        assert_eq!(
            ExecutorConfig::parse(&wrong_runtime).unwrap_err(),
            ExecutorConfigError::Invalid("exact pinned Prism llama.cpp commit required")
        );
        let public = valid().replace("tcp://127.0.0.1:9807", "tcp://0.0.0.0:9807");
        assert_eq!(
            ExecutorConfig::parse(&public).unwrap_err(),
            ExecutorConfigError::Invalid("sidecar listener must be private")
        );
    }
}
