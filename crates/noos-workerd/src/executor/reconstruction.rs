//! Proof-bound bridge to the canonical end-user custodian reconstruction path.
//!
//! This module adds no decoder. It validates the operator's position-to-URL
//! map against the finalized custodian profiles and then calls
//! `noos_cli::wwm_client::fetch_from_custodians`, whose only decoder is
//! `noos_da::ArtifactDecoderV1`.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;

use noos_cli::wwm_client::{fetch_from_custodians, validate_custodian_base_url, CustodianEndpoint};
use serde::Serialize;

use crate::config::ExecutorConfig;
use crate::executor::bootstrap::{CustodianEndpointIdentityV1, VerifiedExecutorBootstrapV1};
use crate::executor::residency::{Residency, ResidencyError, ResidencyState};

const MAX_CUSTODIAN_MAP_BYTES: u64 = 64 * 1024;
const RECONSTRUCTION_THRESHOLD: usize = 8;
const POSITION_COUNT: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReconstructionOutcomeV1 {
    pub schema: &'static str,
    pub artifact_path: String,
    pub configured_positions: usize,
    pub installed_from_custodians: bool,
    pub source: &'static str,
    pub publisher_or_gateway_fallback: bool,
    pub production_claimed: bool,
}

#[derive(Debug)]
pub enum ReconstructionError {
    Io(io::Error),
    Map(&'static str),
    Client(String),
    Residency(ResidencyError),
}

impl fmt::Display for ReconstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "reconstruction I/O: {error}"),
            Self::Map(message) => write!(formatter, "custodian map: {message}"),
            Self::Client(message) => write!(formatter, "canonical custodian fetch: {message}"),
            Self::Residency(error) => write!(formatter, "residency: {error}"),
        }
    }
}

impl std::error::Error for ReconstructionError {}

impl From<io::Error> for ReconstructionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ResidencyError> for ReconstructionError {
    fn from(value: ResidencyError) -> Self {
        Self::Residency(value)
    }
}

fn load_verified_custodian_map(
    config: &ExecutorConfig,
    identities: &[CustodianEndpointIdentityV1],
) -> Result<Vec<CustodianEndpoint>, ReconstructionError> {
    let metadata = fs::metadata(&config.model.custodian_map_path)?;
    if metadata.len() > MAX_CUSTODIAN_MAP_BYTES {
        return Err(ReconstructionError::Map("file exceeds 64 KiB"));
    }
    let bytes = fs::read(&config.model.custodian_map_path)?;
    if bytes.len() as u64 > MAX_CUSTODIAN_MAP_BYTES {
        return Err(ReconstructionError::Map("file grew beyond 64 KiB"));
    }
    let endpoints: Vec<CustodianEndpoint> = serde_json::from_slice(&bytes)
        .map_err(|_| ReconstructionError::Map("strict JSON decoding failed"))?;
    if endpoints.len() < RECONSTRUCTION_THRESHOLD || endpoints.len() > POSITION_COUNT {
        return Err(ReconstructionError::Map(
            "must contain between 8 and 12 positions",
        ));
    }
    if identities.len() != POSITION_COUNT {
        return Err(ReconstructionError::Map(
            "finalized proof does not contain twelve custodian identities",
        ));
    }

    let mut positions = BTreeSet::new();
    let mut profiles = BTreeSet::new();
    for endpoint in &endpoints {
        if usize::from(endpoint.position) >= POSITION_COUNT {
            return Err(ReconstructionError::Map(
                "position is outside canonical geometry",
            ));
        }
        let profile_id = endpoint
            .profile_id
            .as_deref()
            .ok_or(ReconstructionError::Map("profile_id is required"))?;
        let endpoint_root = endpoint
            .endpoint_root
            .as_deref()
            .ok_or(ReconstructionError::Map("endpoint_root is required"))?;
        let expected = identities
            .iter()
            .find(|identity| identity.profile_id == profile_id)
            .ok_or(ReconstructionError::Map(
                "custodian profile is absent from finalized proof",
            ))?;
        if endpoint_root != expected.endpoint_root {
            return Err(ReconstructionError::Map(
                "custodian endpoint root does not match finalized proof",
            ));
        }
        if !positions.insert(endpoint.position) || !profiles.insert(profile_id) {
            return Err(ReconstructionError::Map(
                "positions and custodian profiles must be unique",
            ));
        }
        validate_custodian_base_url(&endpoint.base_url)
            .map_err(|_| ReconstructionError::Map("base URL is not HTTPS or loopback HTTP"))?;
    }
    Ok(endpoints)
}

/// Reconstructs the exact Bonsai artifact when the configured cache is absent.
///
/// A present cache is never replaced or treated as a fallback; the subsequent
/// cold-load verifier must still prove its exact length, digest, read-only
/// state, runtime identity, and finalized bootstrap token.
pub fn reconstruct_if_absent(
    config: &ExecutorConfig,
    bootstrap: &VerifiedExecutorBootstrapV1,
    residency: &mut Residency,
) -> Result<ReconstructionOutcomeV1, ReconstructionError> {
    let endpoints =
        load_verified_custodian_map(config, &bootstrap.summary().custodian_endpoint_identities)?;
    let artifact_path = config.model.path.display().to_string();
    if config.model.path.exists() {
        return Ok(ReconstructionOutcomeV1 {
            schema: "noos.wwm.executor-reconstruction.v1",
            artifact_path,
            configured_positions: endpoints.len(),
            installed_from_custodians: false,
            source: "LOCAL_CACHE_PENDING_COLD_VERIFY",
            publisher_or_gateway_fallback: false,
            production_claimed: false,
        });
    }

    let parent = config
        .model
        .path
        .parent()
        .ok_or(ReconstructionError::Map("artifact path has no parent"))?;
    fs::create_dir_all(parent)?;
    residency.transition(ResidencyState::Fetching)?;
    let fetched = fetch_from_custodians(
        &config.model.manifest_path,
        &config.model.custodian_map_path,
        &config.model.manifest_root_hex,
        &config.model.path,
    );
    if let Err(error) = fetched {
        let message = error.to_string();
        residency.fault(message.clone());
        return Err(ReconstructionError::Client(message));
    }
    if !fs::metadata(&config.model.path)?.permissions().readonly() {
        residency.fault("canonical fetch installed writable weights");
        return Err(ReconstructionError::Map(
            "canonical fetch installed writable weights",
        ));
    }

    Ok(ReconstructionOutcomeV1 {
        schema: "noos.wwm.executor-reconstruction.v1",
        artifact_path,
        configured_positions: endpoints.len(),
        installed_from_custodians: true,
        source: "FINALIZED_CUSTODIANS",
        publisher_or_gateway_fallback: false,
        production_claimed: false,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::path::PathBuf;

    fn identities() -> Vec<CustodianEndpointIdentityV1> {
        (0_u8..12)
            .map(|position| CustodianEndpointIdentityV1 {
                profile_id: format!("{:064x}", u64::from(position) + 1),
                endpoint_root: format!("{:064x}", u64::from(position) + 101),
                region_id: "11".repeat(32),
                asn: 65_000 + u32::from(position),
                provider_root: "22".repeat(32),
                operator_id: "33".repeat(32),
            })
            .collect()
    }

    fn map_json(identities: &[CustodianEndpointIdentityV1], count: usize) -> Vec<u8> {
        let rows = identities
            .iter()
            .take(count)
            .enumerate()
            .map(|(position, identity)| {
                serde_json::json!({
                    "position": position,
                    "base_url": "http://127.0.0.1:9761",
                    "profile_id": identity.profile_id,
                    "endpoint_root": identity.endpoint_root,
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&rows).unwrap()
    }

    fn config_with_map(path: PathBuf) -> ExecutorConfig {
        let directory = path.parent().unwrap();
        let map_path = path.to_string_lossy().replace('\\', "/");
        let model_path = directory
            .join("model.gguf")
            .to_string_lossy()
            .replace('\\', "/");
        let manifest_path = directory
            .join("manifest.bin")
            .to_string_lossy()
            .replace('\\', "/");
        let text = include_str!("../../workerd-v2.example.toml")
            .replace("state/workerd/custodians.json", &map_path)
            .replace("artifacts/bonsai/Bonsai-27B-Q1_0.gguf", &model_path)
            .replace("artifacts/bonsai/manifest.bin", &manifest_path);
        ExecutorConfig::parse(&text).unwrap()
    }

    #[test]
    fn map_requires_threshold_and_exact_finalized_endpoint_roots() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("custodians.json");
        let identities = identities();
        fs::write(&path, map_json(&identities, 8)).unwrap();
        let config = config_with_map(path.clone());
        assert_eq!(
            load_verified_custodian_map(&config, &identities)
                .unwrap()
                .len(),
            8
        );
        let mut reassigned: serde_json::Value =
            serde_json::from_slice(&map_json(&identities, 8)).unwrap();
        let profile_0 = reassigned[0]["profile_id"].clone();
        let endpoint_0 = reassigned[0]["endpoint_root"].clone();
        let profile_3 = reassigned[3]["profile_id"].clone();
        let endpoint_3 = reassigned[3]["endpoint_root"].clone();
        reassigned[0]["profile_id"] = profile_3;
        reassigned[0]["endpoint_root"] = endpoint_3;
        reassigned[3]["profile_id"] = profile_0;
        reassigned[3]["endpoint_root"] = endpoint_0;
        fs::write(&path, serde_json::to_vec(&reassigned).unwrap()).unwrap();
        assert_eq!(
            load_verified_custodian_map(&config, &identities)
                .unwrap()
                .len(),
            8
        );

        fs::write(&path, map_json(&identities, 7)).unwrap();
        assert!(matches!(
            load_verified_custodian_map(&config, &identities),
            Err(ReconstructionError::Map(
                "must contain between 8 and 12 positions"
            ))
        ));

        let mut wrong: serde_json::Value =
            serde_json::from_slice(&map_json(&identities, 8)).unwrap();
        wrong[0]["endpoint_root"] = serde_json::Value::String("ff".repeat(32));
        fs::write(&path, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(matches!(
            load_verified_custodian_map(&config, &identities),
            Err(ReconstructionError::Map(
                "custodian endpoint root does not match finalized proof"
            ))
        ));
    }

    #[test]
    fn map_is_strict_and_rejects_public_plaintext_transport() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("custodians.json");
        let identities = identities();
        let mut rows: serde_json::Value =
            serde_json::from_slice(&map_json(&identities, 8)).unwrap();
        rows[0]["unexpected"] = serde_json::Value::Bool(true);
        fs::write(&path, serde_json::to_vec(&rows).unwrap()).unwrap();
        let config = config_with_map(path.clone());
        assert!(matches!(
            load_verified_custodian_map(&config, &identities),
            Err(ReconstructionError::Map("strict JSON decoding failed"))
        ));

        let mut rows: serde_json::Value =
            serde_json::from_slice(&map_json(&identities, 8)).unwrap();
        rows[0]["base_url"] = serde_json::Value::String("http://custodian.example".to_owned());
        fs::write(&path, serde_json::to_vec(&rows).unwrap()).unwrap();
        assert!(matches!(
            load_verified_custodian_map(&config, &identities),
            Err(ReconstructionError::Map(
                "base URL is not HTTPS or loopback HTTP"
            ))
        ));
    }
}
