use super::{security::canonical_https_origin, Result, WebCapacityError};
use crate::service::web_capacity::model::{ChainBinding, ExperimentState};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const CONFIG_SCHEMA: &str = "noos/wwm-web-capacityd-config/v1";
const MAX_SOURCE_ORIGINS: usize = 256;
const MAX_MUTATION_ORIGINS: usize = 256;
pub const HARD_MAX_HOSTS: u32 = 1_024;
pub const HARD_MAX_ACTIVE_SESSIONS: u32 = 4_096;
pub const HARD_MAX_ACTIVE_ASSIGNMENTS: u32 = 4_096;
pub const HARD_MAX_PENDING_RESTORE_TASKS: u32 = 256;
pub const HARD_MAX_QUARANTINE_BYTES: u64 = 475_588_608;
pub const CONSERVATIVE_MAX_QUARANTINE_BYTES: u64 = 268_173_312;
pub const HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRegistration {
    pub origin: String,
    pub provider: String,
    pub region: String,
    pub control_cluster: String,
}

#[derive(Debug, Clone)]
pub struct LoopbackTestTransport {
    pub ca_certificate_pem: Vec<u8>,
    pub full_position_repair: bool,
}

#[derive(Debug, Clone)]
pub struct WebCapacityConfig {
    pub listen: SocketAddr,
    pub data_path: PathBuf,
    pub quarantine_dir: PathBuf,
    pub artifact_manifest_path: PathBuf,
    pub coordinator_seed: [u8; 32],
    pub chain_binding: ChainBinding,
    pub experiment_state: ExperimentState,
    pub source_allowlist: Vec<SourceRegistration>,
    pub registered_origins: BTreeSet<String>,
    pub consent_version: String,
    pub session_lifetime_seconds: u64,
    pub assignment_lifetime_seconds: u64,
    pub restore_lifetime_seconds: u64,
    pub host_probe_count: usize,
    pub request_timeout_ms: u64,
    pub rate_limit_per_minute: u32,
    pub max_hosts: u32,
    pub max_active_sessions: u32,
    pub max_active_assignments: u32,
    pub max_pending_restore_tasks: u32,
    pub max_quarantine_bytes: u64,
    pub max_concurrent_restore_verifications: u32,
    pub loopback_test_transport: Option<LoopbackTestTransport>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema: String,
    activation_scope: ActivationScope,
    production: bool,
    rewards: bool,
    listen: String,
    data_path: PathBuf,
    quarantine_dir: PathBuf,
    artifact_manifest_path: PathBuf,
    coordinator_seed_env: String,
    chain_binding: ChainBinding,
    experiment_state: ExperimentState,
    source_allowlist: Vec<SourceRegistration>,
    registered_origins: Vec<String>,
    consent_version: String,
    session_lifetime_seconds: u64,
    assignment_lifetime_seconds: u64,
    restore_lifetime_seconds: u64,
    host_probe_count: usize,
    request_timeout_ms: u64,
    rate_limit_per_minute: u32,
    max_hosts: u32,
    max_active_sessions: u32,
    max_active_assignments: u32,
    max_pending_restore_tasks: u32,
    max_quarantine_bytes: u64,
    max_concurrent_restore_verifications: u32,
    isolation: IsolationDeclaration,
    loopback_test_transport: Option<LoopbackTestTransportDocument>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ActivationScope {
    ExperimentalTestOnly,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolationDeclaration {
    validator_key_path: Option<PathBuf>,
    consensus_store_path: Option<PathBuf>,
    model_execution_path: Option<PathBuf>,
    authority_to_issue_custody_certificates: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoopbackTestTransportDocument {
    enabled: bool,
    ca_certificate_path: PathBuf,
    full_position_repair: bool,
}

impl WebCapacityConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|error| {
            WebCapacityError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let document: ConfigDocument = serde_json::from_slice(&bytes).map_err(|error| {
            WebCapacityError::Config(format!("invalid {}: {error}", path.display()))
        })?;
        if document.schema != CONFIG_SCHEMA
            || document.activation_scope != ActivationScope::ExperimentalTestOnly
            || document.production
            || document.rewards
        {
            return Err(WebCapacityError::Config(
                "only the explicit non-production, unrewarded EXPERIMENTAL_TEST_ONLY profile is supported"
                    .to_owned(),
            ));
        }
        if document.isolation.validator_key_path.is_some()
            || document.isolation.consensus_store_path.is_some()
            || document.isolation.model_execution_path.is_some()
            || document.isolation.authority_to_issue_custody_certificates
        {
            return Err(WebCapacityError::Config(
                "web capacityd cannot receive validator, consensus, model-execution, or custody-certificate authority"
                    .to_owned(),
            ));
        }
        if !document.experiment_state.is_test_only() {
            return Err(WebCapacityError::Config(
                "unsupported experiment state".to_owned(),
            ));
        }
        validate_resource_caps(
            document.max_hosts,
            document.max_active_sessions,
            document.max_active_assignments,
            document.max_pending_restore_tasks,
            document.max_quarantine_bytes,
            document.max_concurrent_restore_verifications,
        )?;
        validate_hashes(&document.chain_binding)?;
        let listen = document.listen.parse::<SocketAddr>().map_err(|_| {
            WebCapacityError::Config("listen must be an explicit socket address".to_owned())
        })?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let data_path = resolve_path(base, document.data_path);
        let quarantine_dir = resolve_path(base, document.quarantine_dir);
        let artifact_manifest_path = resolve_path(base, document.artifact_manifest_path);
        if data_path == quarantine_dir
            || data_path.starts_with(&quarantine_dir)
            || quarantine_dir.starts_with(&data_path)
        {
            return Err(WebCapacityError::Config(
                "SQLite state and artifact quarantine must use separate paths".to_owned(),
            ));
        }
        if !artifact_manifest_path.is_file() {
            return Err(WebCapacityError::Config(format!(
                "canonical artifact manifest is missing: {}",
                artifact_manifest_path.display()
            )));
        }
        if quarantine_dir.starts_with(&artifact_manifest_path)
            || artifact_manifest_path.starts_with(&quarantine_dir)
        {
            return Err(WebCapacityError::Config(
                "artifact quarantine cannot contain the canonical manifest".to_owned(),
            ));
        }
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                WebCapacityError::Config(format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        fs::create_dir_all(&quarantine_dir).map_err(|error| {
            WebCapacityError::Config(format!(
                "cannot create quarantine {}: {error}",
                quarantine_dir.display()
            ))
        })?;

        let coordinator_seed = seed_from_env(&document.coordinator_seed_env)?;
        let source_allowlist = validate_sources(document.source_allowlist)?;
        let registered_origins = validate_origins(document.registered_origins)?;
        let loopback_test_transport = validate_loopback_test_transport(
            document.loopback_test_transport,
            listen,
            &source_allowlist,
            &registered_origins,
            base,
        )?;
        validate_quarantine_profile(
            document.max_quarantine_bytes,
            loopback_test_transport.as_ref(),
        )?;
        if document.consent_version.is_empty() || document.consent_version.len() > 64 {
            return Err(WebCapacityError::Config(
                "consent_version must contain 1..=64 bytes".to_owned(),
            ));
        }
        if !(1..=604_800).contains(&document.session_lifetime_seconds)
            || !(1..=3_600).contains(&document.assignment_lifetime_seconds)
            || !(1..=900).contains(&document.restore_lifetime_seconds)
            || !(1..=32).contains(&document.host_probe_count)
            || !(100..=60_000).contains(&document.request_timeout_ms)
            || !(1..=10_000).contains(&document.rate_limit_per_minute)
        {
            return Err(WebCapacityError::Config(
                "session, assignment, restore, probe, timeout, or rate bounds are invalid"
                    .to_owned(),
            ));
        }
        Ok(Self {
            listen,
            data_path,
            quarantine_dir,
            artifact_manifest_path,
            coordinator_seed,
            chain_binding: document.chain_binding,
            experiment_state: document.experiment_state,
            source_allowlist,
            registered_origins,
            consent_version: document.consent_version,
            session_lifetime_seconds: document.session_lifetime_seconds,
            assignment_lifetime_seconds: document.assignment_lifetime_seconds,
            restore_lifetime_seconds: document.restore_lifetime_seconds,
            host_probe_count: document.host_probe_count,
            request_timeout_ms: document.request_timeout_ms,
            rate_limit_per_minute: document.rate_limit_per_minute,
            max_hosts: document.max_hosts,
            max_active_sessions: document.max_active_sessions,
            max_active_assignments: document.max_active_assignments,
            max_pending_restore_tasks: document.max_pending_restore_tasks,
            max_quarantine_bytes: document.max_quarantine_bytes,
            max_concurrent_restore_verifications: document.max_concurrent_restore_verifications,
            loopback_test_transport,
        })
    }
}

fn validate_resource_caps(
    max_hosts: u32,
    max_active_sessions: u32,
    max_active_assignments: u32,
    max_pending_restore_tasks: u32,
    max_quarantine_bytes: u64,
    max_concurrent_restore_verifications: u32,
) -> Result<()> {
    if !(1..=HARD_MAX_HOSTS).contains(&max_hosts)
        || !(1..=HARD_MAX_ACTIVE_SESSIONS).contains(&max_active_sessions)
        || !(1..=HARD_MAX_ACTIVE_ASSIGNMENTS).contains(&max_active_assignments)
        || !(1..=HARD_MAX_PENDING_RESTORE_TASKS).contains(&max_pending_restore_tasks)
        || !(1..=HARD_MAX_QUARANTINE_BYTES).contains(&max_quarantine_bytes)
        || !(1..=HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS)
            .contains(&max_concurrent_restore_verifications)
    {
        return Err(WebCapacityError::Config(
            "resource caps must be nonzero and cannot exceed the compiled hard maxima".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sources(values: Vec<SourceRegistration>) -> Result<Vec<SourceRegistration>> {
    if values.len() > MAX_SOURCE_ORIGINS {
        return Err(WebCapacityError::Config(
            "source allowlist exceeds 256 origins".to_owned(),
        ));
    }
    let mut origins = BTreeSet::new();
    let mut result = Vec::with_capacity(values.len());
    for mut value in values {
        value.origin = canonical_https_origin(&value.origin)?;
        if !origins.insert(value.origin.clone()) {
            return Err(WebCapacityError::Config(
                "duplicate source allowlist origin".to_owned(),
            ));
        }
        for (label, item) in [
            ("provider", &value.provider),
            ("region", &value.region),
            ("control_cluster", &value.control_cluster),
        ] {
            if item.is_empty() || item.len() > 128 {
                return Err(WebCapacityError::Config(format!(
                    "source {label} must contain 1..=128 bytes"
                )));
            }
        }
        result.push(value);
    }
    Ok(result)
}

fn validate_origins(values: Vec<String>) -> Result<BTreeSet<String>> {
    if values.len() > MAX_MUTATION_ORIGINS {
        return Err(WebCapacityError::Config(
            "registered mutation origin allowlist exceeds 256 origins".to_owned(),
        ));
    }
    let mut origins = BTreeSet::new();
    for value in values {
        let origin = canonical_https_origin(&value)?;
        if !origins.insert(origin) {
            return Err(WebCapacityError::Config(
                "duplicate registered mutation origin".to_owned(),
            ));
        }
    }
    Ok(origins)
}

fn validate_loopback_test_transport(
    document: Option<LoopbackTestTransportDocument>,
    listen: SocketAddr,
    sources: &[SourceRegistration],
    registered_origins: &BTreeSet<String>,
    base: &Path,
) -> Result<Option<LoopbackTestTransport>> {
    let Some(document) = document else {
        return Ok(None);
    };
    if !document.enabled {
        return Err(WebCapacityError::Config(
            "loopback test transport must be absent unless explicitly enabled".to_owned(),
        ));
    }
    if !listen.ip().is_loopback() || sources.is_empty() || registered_origins.is_empty() {
        return Err(WebCapacityError::Config(
            "loopback test transport requires a loopback listener and nonempty explicit source and mutation allowlists"
                .to_owned(),
        ));
    }
    if sources
        .iter()
        .map(|source| source.origin.as_str())
        .chain(registered_origins.iter().map(String::as_str))
        .any(|origin| !is_exact_literal_loopback_origin(origin))
    {
        return Err(WebCapacityError::Config(
            "loopback test transport permits only literal https://127.0.0.1:<port> or https://[::1]:<port> origins"
                .to_owned(),
        ));
    }
    let certificate_path = resolve_path(base, document.ca_certificate_path);
    let certificate = fs::read(&certificate_path).map_err(|error| {
        WebCapacityError::Config(format!(
            "cannot read loopback test CA {}: {error}",
            certificate_path.display()
        ))
    })?;
    if certificate.is_empty() || certificate.len() > 64 * 1024 {
        return Err(WebCapacityError::Config(
            "loopback test CA must contain 1..=65536 bytes".to_owned(),
        ));
    }
    reqwest::Certificate::from_pem(&certificate).map_err(|error| {
        WebCapacityError::Config(format!("loopback test CA is not valid PEM: {error}"))
    })?;
    Ok(Some(LoopbackTestTransport {
        ca_certificate_pem: certificate,
        full_position_repair: document.full_position_repair,
    }))
}

fn validate_quarantine_profile(
    max_quarantine_bytes: u64,
    loopback: Option<&LoopbackTestTransport>,
) -> Result<()> {
    let full_position_repair = loopback.is_some_and(|value| value.full_position_repair);
    if full_position_repair {
        if max_quarantine_bytes != HARD_MAX_QUARANTINE_BYTES {
            return Err(WebCapacityError::Config(
                "full-position repair requires the exact one-position quarantine cap".to_owned(),
            ));
        }
    } else if max_quarantine_bytes > CONSERVATIVE_MAX_QUARANTINE_BYTES {
        return Err(WebCapacityError::Config(
            "quarantine above the conservative cap requires explicit test-only full-position repair"
                .to_owned(),
        ));
    }
    Ok(())
}

fn is_exact_literal_loopback_origin(value: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(value) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.port().is_some()
        && parsed.host_str().is_some_and(|host| {
            let literal = host
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(host);
            literal
                .parse::<std::net::IpAddr>()
                .ok()
                .is_some_and(|address| {
                    address == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                        || address == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                })
        })
}

fn validate_hashes(binding: &ChainBinding) -> Result<()> {
    for (label, value) in [
        ("chain_id", &binding.chain_id),
        ("genesis_hash", &binding.genesis_hash),
        ("artifact_id", &binding.artifact_id),
        ("manifest_root", &binding.manifest_root),
    ] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WebCapacityError::Config(format!(
                "{label} must be canonical lowercase hex32"
            )));
        }
    }
    Ok(())
}

fn seed_from_env(name: &str) -> Result<[u8; 32]> {
    if name.is_empty() || name.len() > 128 {
        return Err(WebCapacityError::Config(
            "coordinator_seed_env must contain 1..=128 bytes".to_owned(),
        ));
    }
    let value = Zeroizing::new(env::var(name).map_err(|_| {
        WebCapacityError::Config(format!(
            "required secret environment variable {name} is absent"
        ))
    })?);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WebCapacityError::Config(format!(
            "{name} must contain canonical lowercase hex32"
        )));
    }
    let decoded = hex::decode(value.as_bytes())
        .map_err(|_| WebCapacityError::Config(format!("{name} must contain canonical hex32")))?;
    decoded
        .try_into()
        .map_err(|_| WebCapacityError::Config(format!("{name} must contain canonical hex32")))
}

fn resolve_path(base: &Path, value: PathBuf) -> PathBuf {
    if value.is_absolute() {
        value
    } else {
        base.join(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_caps_accept_only_nonzero_values_within_hard_maxima() {
        assert!(validate_resource_caps(
            HARD_MAX_HOSTS,
            HARD_MAX_ACTIVE_SESSIONS,
            HARD_MAX_ACTIVE_ASSIGNMENTS,
            HARD_MAX_PENDING_RESTORE_TASKS,
            HARD_MAX_QUARANTINE_BYTES,
            HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS,
        )
        .is_ok());

        for invalid in [
            (0, 1, 1, 1, 1, 1),
            (1, 0, 1, 1, 1, 1),
            (1, 1, 0, 1, 1, 1),
            (1, 1, 1, 0, 1, 1),
            (1, 1, 1, 1, 0, 1),
            (1, 1, 1, 1, 1, 0),
            (HARD_MAX_HOSTS + 1, 1, 1, 1, 1, 1),
            (1, HARD_MAX_ACTIVE_SESSIONS + 1, 1, 1, 1, 1),
            (1, 1, HARD_MAX_ACTIVE_ASSIGNMENTS + 1, 1, 1, 1),
            (1, 1, 1, HARD_MAX_PENDING_RESTORE_TASKS + 1, 1, 1),
            (1, 1, 1, 1, HARD_MAX_QUARANTINE_BYTES + 1, 1),
            (1, 1, 1, 1, 1, HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS + 1),
        ] {
            assert!(
                validate_resource_caps(
                    invalid.0, invalid.1, invalid.2, invalid.3, invalid.4, invalid.5,
                )
                .is_err(),
                "accepted invalid caps {invalid:?}"
            );
        }
    }
    #[test]
    fn config_documents_require_caps_and_reject_values_above_hard_maxima() {
        let directory = tempfile::tempdir().unwrap();
        let base = serde_json::json!({
            "schema": CONFIG_SCHEMA,
            "activation_scope": "EXPERIMENTAL_TEST_ONLY",
            "production": false,
            "rewards": false,
            "listen": "127.0.0.1:9770",
            "data_path": "capacity.sqlite",
            "quarantine_dir": "quarantine",
            "artifact_manifest_path": "missing-manifest.bin",
            "coordinator_seed_env": "UNUSED_TEST_SEED",
            "chain_binding": {
                "chain_id": "01".repeat(32),
                "genesis_hash": "02".repeat(32),
                "artifact_id": "03".repeat(32),
                "manifest_root": "04".repeat(32)
            },
            "experiment_state": "LOCAL_FIXTURE",
            "source_allowlist": [],
            "registered_origins": [],
            "consent_version": "consent-v1",
            "session_lifetime_seconds": 3600,
            "assignment_lifetime_seconds": 300,
            "restore_lifetime_seconds": 300,
            "host_probe_count": 1,
            "request_timeout_ms": 1000,
            "rate_limit_per_minute": 60,
            "max_hosts": HARD_MAX_HOSTS,
            "max_active_sessions": HARD_MAX_ACTIVE_SESSIONS,
            "max_active_assignments": HARD_MAX_ACTIVE_ASSIGNMENTS,
            "max_pending_restore_tasks": HARD_MAX_PENDING_RESTORE_TASKS,
            "max_quarantine_bytes": HARD_MAX_QUARANTINE_BYTES,
            "max_concurrent_restore_verifications":
                HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS,
            "isolation": {
                "validator_key_path": null,
                "consensus_store_path": null,
                "model_execution_path": null,
                "authority_to_issue_custody_certificates": false
            }
        });

        for (index, (field, value)) in [
            ("max_hosts", serde_json::json!(HARD_MAX_HOSTS + 1)),
            (
                "max_active_sessions",
                serde_json::json!(HARD_MAX_ACTIVE_SESSIONS + 1),
            ),
            (
                "max_active_assignments",
                serde_json::json!(HARD_MAX_ACTIVE_ASSIGNMENTS + 1),
            ),
            (
                "max_pending_restore_tasks",
                serde_json::json!(HARD_MAX_PENDING_RESTORE_TASKS + 1),
            ),
            (
                "max_quarantine_bytes",
                serde_json::json!(HARD_MAX_QUARANTINE_BYTES + 1),
            ),
            (
                "max_concurrent_restore_verifications",
                serde_json::json!(HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS + 1),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut document = base.clone();
            document[field] = value;
            let path = directory.path().join(format!("over-limit-{index}.json"));
            fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            let error = WebCapacityConfig::load(&path).unwrap_err().to_string();
            assert!(error.contains("resource caps"), "{field}: {error}");
        }

        let mut missing = base;
        missing
            .as_object_mut()
            .unwrap()
            .remove("max_pending_restore_tasks");
        let path = directory.path().join("missing-cap.json");
        fs::write(&path, serde_json::to_vec(&missing).unwrap()).unwrap();
        assert!(WebCapacityConfig::load(&path)
            .unwrap_err()
            .to_string()
            .contains("missing field"));
    }

    #[test]
    fn loopback_test_transport_is_literal_opt_in_and_default_ssrf_mode_is_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("loopback-ca.pem");
        fs::write(
            &certificate_path,
            b"-----BEGIN CERTIFICATE-----\nMIICwTCCAamgAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1sb29w\nYmFjayB0ZXN0MB4XDTI2MDcxNDE1MzIyN1oXDTM2MDcxMjE1MzIyN1owGDEWMBQG\nA1UEAwwNbG9vcGJhY2sgdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBANsvDCKVzhitua2s8MZH5a6ci9T9ZOvVl4uhkD0viwQq/+Zg9BNT7wa8nZ6y\nm+EPt+dtJS+nbCgvxHBsJrrOxfxLxzay42+75nsoN5zPgD7FFUX1zaJilBoSAlGt\nuAbG1UykgvWALAxeru68TS/aD/ufa16djjMW1id6CsXOW0SptGpKYJzSsOypD3Uk\nH6BvYZ0A7YGvb1mSSvIPH4HntqdOP89YAdoYZhRdsyjcvFhoBcdxKtQIZCRxxEku\nboHMvVXFnfKUNft5KV+qxan9Dm4g/rxuqbM+kFeshMG+a3y5X1Xu8oNcAuDH1jfw\nYD1bWjt4GmesDoI9p4RF6YrtMVkCAwEAAaMWMBQwEgYDVR0TAQH/BAgwBgEB/wIB\nADANBgkqhkiG9w0BAQsFAAOCAQEAEYPL0AcRj1m6QXPwM7rg3PFhrKjUNoa9Z5Q/\n/B4AMeGuAGH/ZG235aTkp9YxbfvvgL0LfN+NjKHwS39PL+DQ2xisism5MMFaa0mv\nQd0tUDZZXCsm7EYWxUIOLCRVh5LTB+Bkj9imu6TAGVpRqyBOr9L/lkv8X5Nt/SXK\nz/0y7n6UaBdaop43uXhGFsTiypUGOAewC7qAvSxjUD/lKNutRuV6xltGXjoIbCvm\ntoXyIqNWqAQzMoQ/F8rx6XA5CWGoIIeW2jKPnf0AYEjaHDxdW+ruh0xxr4mSOjzm\nk/3UegzFEktCSZ8Cbasu6JuC/t256G0j3kKk0ttUA8EkwtdLDQ==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let source = |origin: &str| SourceRegistration {
            origin: origin.to_owned(),
            provider: "fixture-provider".to_owned(),
            region: "fixture-region".to_owned(),
            control_cluster: "fixture-domain".to_owned(),
        };
        let document = || LoopbackTestTransportDocument {
            enabled: true,
            ca_certificate_path: certificate_path.clone(),
            full_position_repair: false,
        };
        let registered = BTreeSet::from(["https://[::1]:9443".to_owned()]);
        let enabled = validate_loopback_test_transport(
            Some(document()),
            "127.0.0.1:9770".parse().unwrap(),
            &[source("https://127.0.0.1:8443")],
            &registered,
            directory.path(),
        )
        .unwrap();
        assert!(enabled.is_some());
        assert!(validate_loopback_test_transport(
            None,
            "0.0.0.0:9770".parse().unwrap(),
            &[source("https://example.com")],
            &BTreeSet::new(),
            directory.path(),
        )
        .unwrap()
        .is_none());

        for (listen, source_origin, mutation_origin) in [
            (
                "0.0.0.0:9770",
                "https://127.0.0.1:8443",
                "https://127.0.0.1:9443",
            ),
            (
                "127.0.0.1:9770",
                "https://127.0.0.2:8443",
                "https://127.0.0.1:9443",
            ),
            (
                "127.0.0.1:9770",
                "https://10.0.0.1:8443",
                "https://127.0.0.1:9443",
            ),
            (
                "127.0.0.1:9770",
                "https://localhost:8443",
                "https://127.0.0.1:9443",
            ),
            (
                "127.0.0.1:9770",
                "https://127.0.0.1:8443",
                "https://example.com:9443",
            ),
        ] {
            let error = validate_loopback_test_transport(
                Some(document()),
                listen.parse().unwrap(),
                &[source(source_origin)],
                &BTreeSet::from([mutation_origin.to_owned()]),
                directory.path(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("loopback") || error.contains("literal"),
                "unsafe combination was not rejected clearly: {error}"
            );
        }
        assert!(
            validate_quarantine_profile(CONSERVATIVE_MAX_QUARANTINE_BYTES, enabled.as_ref(),)
                .is_ok()
        );
        assert!(validate_quarantine_profile(HARD_MAX_QUARANTINE_BYTES, enabled.as_ref(),).is_err());
        let full_position = LoopbackTestTransport {
            ca_certificate_pem: Vec::new(),
            full_position_repair: true,
        };
        assert!(
            validate_quarantine_profile(HARD_MAX_QUARANTINE_BYTES, Some(&full_position),).is_ok()
        );
        assert!(validate_quarantine_profile(
            CONSERVATIVE_MAX_QUARANTINE_BYTES,
            Some(&full_position),
        )
        .is_err());
        let disabled = LoopbackTestTransportDocument {
            enabled: false,
            ca_certificate_path: certificate_path,
            full_position_repair: false,
        };
        assert!(validate_loopback_test_transport(
            Some(disabled),
            "127.0.0.1:9770".parse().unwrap(),
            &[source("https://127.0.0.1:8443")],
            &BTreeSet::from(["https://127.0.0.1:9443".to_owned()]),
            directory.path(),
        )
        .is_err());
    }
}
