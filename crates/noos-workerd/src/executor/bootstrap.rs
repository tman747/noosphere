//! Fail-closed executor bootstrap from a canonical finalized resolution proof.
//!
//! The resolver file contributes bytes, never trust booleans. Authority comes
//! from the worker's independently approved chain identity and finalized
//! checkpoint. The canonical node verifier then binds the terminal header,
//! object root, every SMT proof, and the complete active WWM v2 graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::Path;

use axum::http::Uri;
use noos_codec::{NoosDecode, NoosEncode};
use noos_da::artifact::ARTIFACT_SHARE_BYTES;
use noos_lumen::objects::BoundedBytes;
use noos_lumen::wwm::{
    CapabilityStatus, CustodianCapabilitySetV1, ResolutionSelectorKind, ResolutionSelectorV1,
    WwmControlMode, MAX_FINALIZED_RESOLUTION_BYTES,
};
use noos_node::resolver::{
    verify_finalized_model_resolution, FinalizedResolutionTerminalV1, ResolutionError,
    TrustedFinalizedCheckpointV1, VerifiedModelResolutionV1,
};
use serde::{Deserialize, Serialize};

use crate::config::{
    ExecutorConfig, BONSAI_MANIFEST_ROOT, BONSAI_MODEL_ALIAS, BONSAI_MODEL_BYTES,
    BONSAI_MODEL_SHA256,
};
use crate::hex::decode_hex32;

const PROOF_SCHEMA: &str = "noos/wwm-executor-bootstrap-proof/v1";
const MAX_PROOF_ENVELOPE_BYTES: usize = MAX_FINALIZED_RESOLUTION_BYTES * 2 + 1_024;
const BONSAI_STRIPES: u32 = 454;
const BONSAI_POSITIONS: u8 = 12;
const BONSAI_RECONSTRUCTION_THRESHOLD: u8 = 8;
const BONSAI_SCHEDULABLE_MINIMUM: u8 = 9;
const BONSAI_CODEC_PROFILE: u16 = 1;
const SCHEDULABLE_AVAILABILITY_STATE: u8 = 0;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapProofEnvelopeV1 {
    schema: String,
    canonical_resolution_body_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CustodianEndpointIdentityV1 {
    pub profile_id: String,
    pub endpoint_root: String,
    pub region_id: String,
    pub asn: u32,
    pub provider_root: String,
    pub operator_id: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedExecutorBootstrapV1 {
    resolution: VerifiedModelResolutionV1,
    summary: ExecutorBootstrapSummaryV1,
}

impl VerifiedExecutorBootstrapV1 {
    #[must_use]
    pub const fn summary(&self) -> &ExecutorBootstrapSummaryV1 {
        &self.summary
    }

    #[must_use]
    pub const fn resolution(&self) -> &VerifiedModelResolutionV1 {
        &self.resolution
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutorBootstrapSummaryV1 {
    pub schema: &'static str,
    pub chain_id: String,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub objects_root: String,
    pub proof_body_blake3: String,
    pub capsule_id: String,
    pub artifact_id: String,
    pub manifest_root: String,
    pub certificate_id: String,
    pub certificate_valid_until: u64,
    pub position_count: u8,
    pub reconstruction_threshold: u8,
    pub schedulable_minimum: u8,
    pub custodian_endpoint_identities: Vec<CustodianEndpointIdentityV1>,
    pub service_endpoints: Vec<String>,
    pub publisher_or_gateway_fallback: bool,
    pub production_claimed: bool,
}

#[derive(Debug)]
pub enum BootstrapError {
    Io(io::Error),
    Envelope(&'static str),
    Canonical(String),
    Trust(&'static str),
    Proof(ResolutionError),
    Graph(&'static str),
    Identity(&'static str),
    NotReady(&'static str),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "bootstrap I/O: {error}"),
            Self::Envelope(message) => write!(f, "bootstrap envelope: {message}"),
            Self::Canonical(message) => write!(f, "canonical resolution: {message}"),
            Self::Trust(message) => write!(f, "approved checkpoint: {message}"),
            Self::Proof(error) => write!(f, "finalized resolution proof: {error:?}"),
            Self::Graph(message) => write!(f, "active WWM graph: {message}"),
            Self::Identity(message) => write!(f, "executor identity: {message}"),
            Self::NotReady(message) => write!(f, "model not schedulable: {message}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<io::Error> for BootstrapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn load_and_verify_executor_bootstrap(
    config: &ExecutorConfig,
) -> Result<VerifiedExecutorBootstrapV1, BootstrapError> {
    let body = read_proof_body(&config.identity.finalized_resolution_path)?;
    let response = noos_lumen::wwm::FinalizedModelResolutionV1::decode_canonical(&body)
        .map_err(|error| BootstrapError::Canonical(format!("resolution: {error}")))?;
    let terminal =
        FinalizedResolutionTerminalV1::decode_canonical(response.terminal_material.as_slice())
            .map_err(|error| BootstrapError::Canonical(format!("terminal: {error}")))?;

    let trusted_hash = required_hex32(&config.identity.trusted_checkpoint_hash_hex)?;
    if terminal.checkpoint.epoch != config.identity.trusted_checkpoint_epoch
        || terminal.checkpoint.checkpoint_hash != trusted_hash
        || response.resolution_height != config.identity.trusted_checkpoint_height
    {
        return Err(BootstrapError::Trust(
            "terminal does not match the pinned checkpoint",
        ));
    }
    if config.identity.current_finalized_height < response.resolution_height {
        return Err(BootstrapError::Trust("resolution height is in the future"));
    }

    let selector_value = BoundedBytes::new(config.identity.model_alias.as_bytes().to_vec()).ok_or(
        BootstrapError::Identity("model alias exceeds canonical bounds"),
    )?;
    let selector = ResolutionSelectorV1 {
        kind: ResolutionSelectorKind::Alias,
        value: selector_value,
    };
    let expected_chain = required_hex32(&config.worker.chain_id_hex)?;
    let expected_genesis = required_hex32(&config.worker.genesis_hash_hex)?;
    let trusted = TrustedFinalizedCheckpointV1 {
        checkpoint: terminal.checkpoint,
        height: config.identity.trusted_checkpoint_height,
    };
    let verified = verify_finalized_model_resolution(
        &response,
        expected_chain,
        expected_genesis,
        &selector,
        trusted,
        config.identity.current_finalized_height,
    )
    .map_err(BootstrapError::Proof)?;

    verify_active_executor_graph(config, &verified)?;
    let service_endpoints = verified_service_endpoints(
        verified
            .service_directory
            .as_ref()
            .ok_or(BootstrapError::Graph("service directory absent"))?,
        config.identity.current_finalized_height,
    )?;
    let custodian_endpoint_identities = verified_custodian_identities(
        verified
            .availability_policy
            .as_ref()
            .ok_or(BootstrapError::Graph("availability policy absent"))?,
        verified
            .custodian_set
            .as_ref()
            .ok_or(BootstrapError::Graph("custodian set absent"))?,
        config.identity.custodian_set_epoch,
        verified
            .artifact
            .as_ref()
            .ok_or(BootstrapError::Graph("artifact absent"))?
            .stripe_count,
    )?;

    let artifact = verified
        .artifact
        .as_ref()
        .ok_or(BootstrapError::Graph("artifact absent"))?;
    let capsule = verified
        .capsule
        .as_ref()
        .ok_or(BootstrapError::Graph("capsule absent"))?;
    let certificate = verified
        .availability_certificate
        .as_ref()
        .ok_or(BootstrapError::Graph("availability certificate absent"))?;
    let policy = verified
        .availability_policy
        .as_ref()
        .ok_or(BootstrapError::Graph("availability policy absent"))?;
    let summary = ExecutorBootstrapSummaryV1 {
        schema: "noos.wwm.executor-bootstrap-verified.v1",
        chain_id: hex(&expected_chain),
        genesis_hash: hex(&expected_genesis),
        finalized_height: response.resolution_height,
        finalized_hash: hex(&terminal.checkpoint.checkpoint_hash),
        objects_root: hex(&terminal.header.objects_root),
        proof_body_blake3: hex(blake3::hash(&body).as_bytes()),
        capsule_id: hex(&capsule.capsule_id),
        artifact_id: hex(&artifact.artifact_id),
        manifest_root: hex(&artifact.manifest_root),
        certificate_id: hex(&certificate.certificate_id),
        certificate_valid_until: certificate.valid_until,
        position_count: policy.position_count,
        reconstruction_threshold: policy.reconstruction_threshold,
        schedulable_minimum: policy.schedulable_minimum,
        custodian_endpoint_identities: custodian_endpoint_identities.clone(),
        service_endpoints: service_endpoints.clone(),
        publisher_or_gateway_fallback: false,
        production_claimed: false,
    };

    Ok(VerifiedExecutorBootstrapV1 {
        resolution: verified,
        summary,
    })
}

fn read_proof_body(path: &Path) -> Result<Vec<u8>, BootstrapError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_PROOF_ENVELOPE_BYTES as u64 {
        return Err(BootstrapError::Envelope(
            "file exceeds the bounded envelope size",
        ));
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() > MAX_PROOF_ENVELOPE_BYTES {
        return Err(BootstrapError::Envelope(
            "file grew beyond the bounded envelope size",
        ));
    }
    let envelope: BootstrapProofEnvelopeV1 = serde_json::from_slice(&bytes)
        .map_err(|_| BootstrapError::Envelope("strict JSON decoding failed"))?;
    if envelope.schema != PROOF_SCHEMA {
        return Err(BootstrapError::Envelope("schema mismatch"));
    }
    let body = decode_lower_hex(
        &envelope.canonical_resolution_body_hex,
        MAX_FINALIZED_RESOLUTION_BYTES,
    )?;
    if body.is_empty() {
        return Err(BootstrapError::Envelope("canonical body is empty"));
    }
    Ok(body)
}

fn verify_active_executor_graph(
    config: &ExecutorConfig,
    verified: &VerifiedModelResolutionV1,
) -> Result<(), BootstrapError> {
    let active_config = verified
        .config
        .as_ref()
        .ok_or(BootstrapError::Graph("authorized config absent"))?;
    let capsule = verified
        .capsule
        .as_ref()
        .ok_or(BootstrapError::Graph("capsule absent"))?;
    let artifact = verified
        .artifact
        .as_ref()
        .ok_or(BootstrapError::Graph("artifact absent"))?;
    let policy = verified
        .availability_policy
        .as_ref()
        .ok_or(BootstrapError::Graph("availability policy absent"))?;
    let certificate = verified
        .availability_certificate
        .as_ref()
        .ok_or(BootstrapError::Graph("availability certificate absent"))?;
    let registry = verified
        .registry
        .as_ref()
        .ok_or(BootstrapError::Graph("registry vector absent"))?;
    let executor_set = verified
        .executor_set
        .as_ref()
        .ok_or(BootstrapError::Graph("executor set absent"))?;
    let custodian_set = verified
        .custodian_set
        .as_ref()
        .ok_or(BootstrapError::Graph("custodian set absent"))?;
    let execution = verified
        .execution_profile
        .as_ref()
        .ok_or(BootstrapError::Graph("execution profile absent"))?;
    let service = verified
        .service_directory
        .as_ref()
        .ok_or(BootstrapError::Graph("service directory absent"))?;

    if verified.control.mode != WwmControlMode::Testnet
        || active_config.tier != WwmControlMode::Testnet
        || config.identity.model_alias != BONSAI_MODEL_ALIAS
        || capsule.lifecycle != 0
    {
        return Err(BootstrapError::NotReady(
            "active graph is not the Bonsai testnet state",
        ));
    }
    let artifact_id = required_hex32(&config.model.artifact_id_hex)?;
    let capsule_id = required_hex32(&config.model.capsule_id_hex)?;
    let tokenizer_root = required_hex32(&config.model.tokenizer_id_hex)?;
    let template_root = required_hex32(&config.model.template_id_hex)?;
    let manifest_root = required_hex32(&config.model.manifest_root_hex)?;
    let runtime_root = required_hex32(&config.runtime.runtime_root_hex)?;
    let build_root = required_hex32(&config.runtime.build_root_hex)?;
    let sbom_root = required_hex32(&config.runtime.sbom_root_hex)?;
    let published_sha256 = required_hex32(&config.model.sha256_hex)?;
    if config.model.name != crate::config::BONSAI_MODEL_NAME
        || config.model.bytes != BONSAI_MODEL_BYTES
        || config.model.sha256_hex != BONSAI_MODEL_SHA256
        || config.model.manifest_root_hex != BONSAI_MANIFEST_ROOT
        || artifact.artifact_id != artifact_id
        || artifact.source_bytes != BONSAI_MODEL_BYTES
        || artifact.published_sha256 != published_sha256
        || artifact.manifest_root != manifest_root
        || artifact.codec_profile_id != BONSAI_CODEC_PROFILE
        || artifact.stripe_count != BONSAI_STRIPES
        || capsule.capsule_id != capsule_id
        || capsule.artifact_id != artifact_id
        || capsule.manifest_root != manifest_root
        || capsule.tokenizer_root != tokenizer_root
        || capsule.template_root != template_root
        || capsule.runtime_root != runtime_root
        || capsule.build_root != build_root
        || capsule.sbom_root != sbom_root
    {
        return Err(BootstrapError::Identity(
            "chain model/runtime roots do not match config",
        ));
    }
    if execution.tokenizer_root != tokenizer_root
        || execution.template_root != template_root
        || execution.runtime_root != runtime_root
        || execution.max_context_tokens != config.scheduler.max_context_tokens
        || execution.max_output_tokens != config.scheduler.max_output_tokens
        || execution.attachments_allowed != 0
    {
        return Err(BootstrapError::Identity("execution profile substitution"));
    }
    if policy.position_count != BONSAI_POSITIONS
        || policy.reconstruction_threshold != BONSAI_RECONSTRUCTION_THRESHOLD
        || policy.schedulable_minimum != BONSAI_SCHEDULABLE_MINIMUM
        || policy.manifest_root != manifest_root
        || config.identity.current_finalized_height < policy.policy_start_height
        || config.identity.current_finalized_height > policy.policy_end_height
    {
        return Err(BootstrapError::NotReady(
            "availability policy is inactive or wrong geometry",
        ));
    }
    let certificate_id = required_hex32(&config.identity.certificate_id_hex)?;
    if certificate.certificate_id != certificate_id
        || certificate.availability_state != SCHEDULABLE_AVAILABILITY_STATE
        || config.identity.current_finalized_height < certificate.issued_height
        || config.identity.current_finalized_height >= certificate.valid_until
    {
        return Err(BootstrapError::NotReady(
            "availability certificate is not live and schedulable",
        ));
    }
    if registry.executor_epoch != config.identity.executor_set_epoch
        || registry.custodian_epoch != config.identity.custodian_set_epoch
        || registry.service_epoch != config.identity.service_directory_epoch
        || executor_set.epoch != config.identity.executor_set_epoch
        || custodian_set.epoch != config.identity.custodian_set_epoch
        || service.epoch != config.identity.service_directory_epoch
    {
        return Err(BootstrapError::Identity("registry epoch substitution"));
    }
    let executor_bytes = executor_set.encode_canonical();
    let custodian_bytes = custodian_set.encode_canonical();
    let executor_root =
        noos_lumen::domain_hash("NOOS/WWM/CAPABILITY-SET-ROOT/V1", &[&executor_bytes]);
    let custodian_root = noos_lumen::domain_hash(
        "NOOS/WWM/CUSTODIAN-CAPABILITY-SET-ROOT/V1",
        &[&custodian_bytes],
    );
    if certificate.executor_set_root != executor_root
        || certificate.custodian_set_root != custodian_root
    {
        return Err(BootstrapError::Proof(ResolutionError::ReferenceMismatch));
    }
    let executor_ids = executor_set
        .entries
        .iter()
        .map(|profile| profile.profile_id)
        .collect::<Vec<_>>();
    let custodian_ids = custodian_set
        .entries
        .iter()
        .map(|profile| profile.profile_id)
        .collect::<Vec<_>>();
    if active_config.executor_allowlist.as_slice() != executor_ids.as_slice()
        || active_config.custodian_allowlist.as_slice() != custodian_ids.as_slice()
    {
        return Err(BootstrapError::Identity(
            "active allowlist does not match proved sets",
        ));
    }
    let worker_id = required_hex32(&config.identity.worker_id_hex)?;
    let worker = executor_set
        .entries
        .iter()
        .find(|profile| profile.profile_id == worker_id)
        .ok_or(BootstrapError::NotReady(
            "configured worker is not in the active executor set",
        ))?;
    let required_capacity = config
        .model
        .bytes
        .checked_add(worker.headroom_bytes)
        .ok_or(BootstrapError::NotReady("worker capacity overflow"))?;
    if worker.status != CapabilityStatus::Active
        || worker.attestation_epoch > config.identity.executor_set_epoch
        || worker.attestation_expiry < config.identity.executor_set_epoch
        || worker.staging_bytes < config.model.bytes
        || worker.capacity_bytes < required_capacity
    {
        return Err(BootstrapError::NotReady(
            "configured worker profile is inactive or undersized",
        ));
    }
    if active_config.activation_height > config.identity.current_finalized_height
        || verified.control.last_transition_height > config.identity.current_finalized_height
    {
        return Err(BootstrapError::NotReady(
            "active control graph is from the future",
        ));
    }
    Ok(())
}

fn verified_custodian_identities(
    policy: &noos_lumen::wwm::AvailabilityPolicyV2,
    set: &CustodianCapabilitySetV1,
    expected_epoch: u64,
    stripe_count: u32,
) -> Result<Vec<CustodianEndpointIdentityV1>, BootstrapError> {
    if set.entries.len() != policy.position_count as usize || set.epoch != expected_epoch {
        return Err(BootstrapError::NotReady(
            "custodian set does not cover every position",
        ));
    }
    let position_bytes = u64::from(stripe_count)
        .checked_mul(ARTIFACT_SHARE_BYTES as u64)
        .ok_or(BootstrapError::NotReady("position byte count overflow"))?;
    let mut controls = BTreeSet::new();
    let mut regions = BTreeMap::<[u8; 32], usize>::new();
    let mut asns = BTreeMap::<u32, usize>::new();
    let mut providers = BTreeMap::<[u8; 32], usize>::new();
    let mut identities = Vec::with_capacity(set.entries.len());
    for profile in set.entries.as_slice() {
        if profile.status != CapabilityStatus::Active
            || profile.attestation_epoch > expected_epoch
            || profile.attestation_expiry < expected_epoch
            || profile.endpoint_root == [0; 32]
            || profile.staging_bytes < ARTIFACT_SHARE_BYTES as u64
            || profile.capacity_bytes < position_bytes
            || profile.headroom_bytes < ARTIFACT_SHARE_BYTES as u64
            || !controls.insert(profile.beneficial_control_root)
        {
            return Err(BootstrapError::NotReady(
                "custodian profile is inactive, duplicate, or undersized",
            ));
        }
        increment(&mut regions, profile.region_id);
        increment(&mut asns, profile.asn);
        increment(&mut providers, profile.provider_root);
        identities.push(CustodianEndpointIdentityV1 {
            profile_id: hex(&profile.profile_id),
            endpoint_root: hex(&profile.endpoint_root),
            region_id: hex(&profile.region_id),
            asn: profile.asn,
            provider_root: hex(&profile.provider_root),
            operator_id: hex(&profile.operator_id),
        });
    }
    if regions.len() < policy.required_regions as usize
        || regions
            .values()
            .any(|count| *count > policy.max_positions_per_region as usize)
        || asns
            .values()
            .any(|count| *count > policy.max_positions_per_asn as usize)
        || providers
            .values()
            .any(|count| *count > policy.max_positions_per_provider as usize)
    {
        return Err(BootstrapError::NotReady(
            "custodian failure-domain diversity failed",
        ));
    }
    Ok(identities)
}

fn increment<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) {
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

fn verified_service_endpoints(
    service: &noos_lumen::wwm::ServiceDirectoryV1,
    current_finalized_height: u64,
) -> Result<Vec<String>, BootstrapError> {
    if current_finalized_height < service.not_before_height
        || current_finalized_height >= service.not_after_height
        || service.endpoint_records.is_empty()
    {
        return Err(BootstrapError::NotReady("service directory is not live"));
    }
    service
        .endpoint_records
        .iter()
        .map(|record| {
            let endpoint = std::str::from_utf8(record.as_slice())
                .map_err(|_| BootstrapError::Graph("service endpoint is not UTF-8"))?;
            let uri = endpoint
                .parse::<Uri>()
                .map_err(|_| BootstrapError::Graph("service endpoint URI is malformed"))?;
            if !matches!(uri.scheme_str(), Some("http" | "https"))
                || uri.authority().is_none()
                || uri
                    .authority()
                    .is_some_and(|authority| authority.as_str().contains('@'))
                || uri
                    .path_and_query()
                    .is_some_and(|path| path.query().is_some())
            {
                return Err(BootstrapError::Graph(
                    "service endpoint URI is not canonical",
                ));
            }
            Ok(endpoint.to_owned())
        })
        .collect()
}

fn required_hex32(value: &str) -> Result<[u8; 32], BootstrapError> {
    decode_hex32(value).ok_or(BootstrapError::Identity("expected lowercase hex32"))
}

fn decode_lower_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, BootstrapError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum_bytes.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BootstrapError::Envelope(
            "canonical body must be bounded lowercase hex",
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or(BootstrapError::Envelope("invalid hex digit"))?;
        let low = hex_nibble(pair[1]).ok_or(BootstrapError::Envelope("invalid hex digit"))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => value.checked_sub(b'0'),
        b'a'..=b'f' => value
            .checked_sub(b'a')
            .and_then(|nibble| nibble.checked_add(10)),
        _ => None,
    }
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    use crate::config::{
        ExecutorWorkerConfig, IdentityConfig, ModelConfig, RuntimeConfig, SchedulerConfig,
        BONSAI_MODEL_NAME, PRISM_LLAMA_COMMIT,
    };
    use noos_lumen::objects::BoundedList;
    use noos_lumen::wwm::FinalizedModelResolutionV1;
    use noos_node::genesis::{DevnetParams, GenesisSpec};
    use std::path::Path;

    const DEVNET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/genesis/devnet-parameters.toml"
    ));

    fn write_proof(path: &Path, response: &FinalizedModelResolutionV1) {
        let envelope = serde_json::json!({
            "schema": PROOF_SCHEMA,
            "canonical_resolution_body_hex": hex(&response.encode_canonical()),
        });
        std::fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    }

    fn fixture(directory: &Path) -> (ExecutorConfig, FinalizedModelResolutionV1) {
        let params = DevnetParams::parse(DEVNET).unwrap();
        let mut spec = GenesisSpec::devnet(params, 1_760_000_000_000);
        spec.wwm_bonsai_fixture = true;
        let built = spec.build().unwrap();
        let checkpoint = noos_braid::CheckpointRef {
            epoch: 0,
            checkpoint_hash: *built.header.block_hash().unwrap().as_bytes(),
        };
        let terminal = FinalizedResolutionTerminalV1 {
            header: built.header.clone(),
            checkpoint,
            finality: noos_braid::FinalityCertificateV1 {
                source: checkpoint,
                target: checkpoint,
                participation_bitmap: BoundedBytes::default(),
                aggregate_signature: noos_braid::Bytes96([0; 96]),
                raw_weight_sum: 0,
                effective_weight_sum: 0,
                membership_root: [0; 32],
            },
        };
        let selector = ResolutionSelectorV1 {
            kind: ResolutionSelectorKind::Alias,
            value: BoundedBytes::new(BONSAI_MODEL_ALIAS.as_bytes().to_vec()).unwrap(),
        };
        let response = noos_node::resolver::build_finalized_model_resolution(
            &built.ledger,
            built.chain_id,
            built.genesis_hash,
            selector.clone(),
            0,
            terminal,
        )
        .unwrap();
        let encoded = response.encode_canonical();
        assert_eq!(
            decode_lower_hex(&hex(&encoded), MAX_FINALIZED_RESOLUTION_BYTES).unwrap(),
            encoded
        );
        FinalizedResolutionTerminalV1::decode_canonical(response.terminal_material.as_slice())
            .unwrap();
        for (index, proof) in response.proofs.iter().enumerate() {
            noos_lumen::wwm::ResolutionValueV1::decode_canonical(&proof.value.encode_canonical())
                .unwrap_or_else(|error| panic!("value {index} failed canonical decode: {error:?}"));
            noos_lumen::smt::SmtProof::decode_canonical(&proof.proof.encode_canonical())
                .unwrap_or_else(|error| {
                    panic!("SMT proof {index} failed canonical decode: {error:?}")
                });
            noos_lumen::wwm::ResolutionProofV1::decode_canonical(&proof.encode_canonical())
                .unwrap_or_else(|error| panic!("proof {index} failed canonical decode: {error:?}"));
        }
        FinalizedModelResolutionV1::decode_canonical(&encoded).unwrap();
        let verified = verify_finalized_model_resolution(
            &response,
            built.chain_id,
            built.genesis_hash,
            &selector,
            TrustedFinalizedCheckpointV1 {
                checkpoint,
                height: 0,
            },
            0,
        )
        .unwrap();
        let artifact = verified.artifact.as_ref().unwrap();
        let capsule = verified.capsule.as_ref().unwrap();
        let certificate = verified.availability_certificate.as_ref().unwrap();
        let registry = verified.registry.as_ref().unwrap();
        let worker = verified
            .executor_set
            .as_ref()
            .unwrap()
            .entries
            .as_slice()
            .first()
            .unwrap();
        let proof_path = directory.join("finalized-resolution.json");
        write_proof(&proof_path, &response);
        let mut config = ExecutorConfig {
            worker: ExecutorWorkerConfig {
                seed_hex: "11".repeat(32),
                chain_id_hex: hex(&built.chain_id),
                genesis_hash_hex: hex(&built.genesis_hash),
                sidecar_token_hex: "22".repeat(32),
                listen: "tcp://127.0.0.1:9807".to_owned(),
                scratch_dir: directory.join("scratch"),
                drain_file: directory.join("drain"),
            },
            model: ModelConfig {
                name: BONSAI_MODEL_NAME.to_owned(),
                path: directory.join("artifacts").join(BONSAI_MODEL_NAME),
                manifest_path: directory.join("manifest.bin"),
                custodian_map_path: directory.join("custodians.json"),
                bytes: BONSAI_MODEL_BYTES,
                sha256_hex: BONSAI_MODEL_SHA256.to_owned(),
                manifest_root_hex: BONSAI_MANIFEST_ROOT.to_owned(),
                artifact_id_hex: hex(&artifact.artifact_id),
                capsule_id_hex: hex(&capsule.capsule_id),
                tokenizer_id_hex: hex(&capsule.tokenizer_root),
                template_id_hex: hex(&capsule.template_root),
            },
            runtime: RuntimeConfig {
                executable: directory.join("runtime").join("llama-cli"),
                source_commit: PRISM_LLAMA_COMMIT.to_owned(),
                target_triple: "x86_64-pc-windows-msvc".to_owned(),
                toolchain: "msvc-19.44".to_owned(),
                build_flags: vec!["GGML_HIP=ON".to_owned(), "LLAMA_CURL=OFF".to_owned()],
                binary_sha256_hex:
                    "d09e9f62e2bfc20af43f47dac8adddae47de25ae7678702f109faaa03dfe8a56".to_owned(),
                runtime_root_hex: hex(&capsule.runtime_root),
                build_root_hex: hex(&capsule.build_root),
                sbom_root_hex: hex(&capsule.sbom_root),
                build_id_hex: "00".repeat(32),
                extra_args: Vec::new(),
            },
            scheduler: SchedulerConfig {
                max_concurrent: 1,
                max_queue: 4,
                max_context_tokens: 4_096,
                max_output_tokens: 512,
                job_timeout_ms: 120_000,
                cancel_grace_ms: 1_000,
            },
            identity: IdentityConfig {
                finalized_resolution_path: proof_path,
                model_alias: BONSAI_MODEL_ALIAS.to_owned(),
                trusted_checkpoint_epoch: checkpoint.epoch,
                trusted_checkpoint_height: 0,
                trusted_checkpoint_hash_hex: hex(&checkpoint.checkpoint_hash),
                current_finalized_height: 0,
                worker_id_hex: hex(&worker.profile_id),
                certificate_id_hex: hex(&certificate.certificate_id),
                executor_set_epoch: registry.executor_epoch,
                custodian_set_epoch: registry.custodian_epoch,
                service_directory_epoch: registry.service_epoch,
            },
        };
        let build_id = config.runtime_build_identity().unwrap().build_id().unwrap();
        config.runtime.build_id_hex = hex(&build_id);
        config.validate().unwrap();
        (config, response)
    }

    #[test]
    fn finalized_proof_bootstrap_accepts_only_the_pinned_complete_graph() {
        let directory = tempfile::tempdir().unwrap();
        let (config, response) = fixture(directory.path());
        let bootstrap = load_and_verify_executor_bootstrap(&config).unwrap();
        assert_eq!(bootstrap.summary().chain_id, config.worker.chain_id_hex);
        assert_eq!(
            bootstrap.summary().manifest_root,
            config.model.manifest_root_hex
        );
        assert_eq!(bootstrap.summary().position_count, BONSAI_POSITIONS);
        assert_eq!(
            bootstrap.summary().custodian_endpoint_identities.len(),
            BONSAI_POSITIONS as usize
        );
        assert_eq!(
            bootstrap.summary().service_endpoints,
            vec!["http://127.0.0.1:18768/v1"]
        );
        assert!(!bootstrap.summary().publisher_or_gateway_fallback);
        assert!(!bootstrap.summary().production_claimed);
        assert!(bootstrap.resolution().registry.is_some());

        let mut wrong_checkpoint = config.clone();
        wrong_checkpoint.identity.trusted_checkpoint_hash_hex = "00".repeat(32);
        assert!(matches!(
            load_and_verify_executor_bootstrap(&wrong_checkpoint),
            Err(BootstrapError::Trust(_))
        ));

        let mut invalid_response = response;
        let mut invalid_proofs = invalid_response.proofs.as_slice().to_vec();
        invalid_proofs[0].objects_root[0] ^= 1;
        invalid_response.proofs = BoundedList::new(invalid_proofs).unwrap();
        write_proof(
            &config.identity.finalized_resolution_path,
            &invalid_response,
        );
        assert!(matches!(
            load_and_verify_executor_bootstrap(&config),
            Err(BootstrapError::Proof(_))
        ));
    }

    #[test]
    fn proof_envelope_rejects_unknown_claim_booleans_and_noncanonical_hex() {
        let unknown = serde_json::json!({
            "schema": PROOF_SCHEMA,
            "canonical_resolution_body_hex": "00",
            "finality_verified": true,
        });
        assert!(serde_json::from_value::<BootstrapProofEnvelopeV1>(unknown).is_err());
        assert!(decode_lower_hex("AA", 8).is_err());
        assert!(decode_lower_hex("0", 8).is_err());
        assert!(decode_lower_hex("00", 0).is_err());
    }
}
