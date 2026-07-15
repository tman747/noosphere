//! User-facing WWM v2 client workflows.
//!
//! Protocol action construction lives in `crate::wwm`. This module owns only
//! proof-gated remote access, the sole noos-da artifact decoder adapter, and
//! exact local artifact/runtime attestation. It never falls back to another
//! model, runtime, endpoint, or payment mode.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use noos_codec::NoosDecode;
use noos_da::{
    ArtifactDecoderV1, ArtifactError, ArtifactManifestV1, ArtifactShareSource,
    ARTIFACT_SHARE_BYTES, BONSAI_SOURCE_BYTES,
};
use noos_lumen::wwm::{FinalizedModelResolutionV1, ResolutionValueV1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const BONSAI_FILE_NAME: &str = "Bonsai-27B-Q1_0.gguf";
pub const BONSAI_SHA256_HEX: &str =
    "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0";
pub const PRISM_RUNTIME_COMMIT: &str = "62061f91088281e65071cc38c5f69ee95c39f14e";
pub const MAX_HTTP_RESPONSE_BYTES: usize = 524_288;
pub const MAX_OUTPUT_TOKENS: u32 = 512;
pub const MAX_PROMPT_BYTES: usize = 48_000;

pub type Result<T, E = WwmClientError> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum WwmClientError {
    InvalidArgument(&'static str),
    Io(std::io::Error),
    Json(serde_json::Error),
    Transport(String),
    Http { status: u16, body: String },
    WrongIdentity,
    InvalidResolution,
    CandidateNotActive,
    InvalidSignature,
    WrongArtifact,
    WrongRuntime,
    Artifact(ArtifactError),
    RuntimeFailed(i32),
    OutputTooLarge,
}

impl std::fmt::Display for WwmClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message) => f.write_str(message),
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Json(error) => write!(f, "json: {error}"),
            Self::Transport(message) => write!(f, "transport: {message}"),
            Self::Http { status, body } => write!(f, "http {status}: {body}"),
            Self::WrongIdentity => f.write_str("wrong_protocol_identity"),
            Self::InvalidResolution => f.write_str("invalid_resolution_proof"),
            Self::CandidateNotActive => f.write_str("candidate_not_active"),
            Self::InvalidSignature => f.write_str("invalid_signature"),
            Self::WrongArtifact => f.write_str("wrong_bonsai_artifact"),
            Self::WrongRuntime => f.write_str("wrong_prism_runtime"),
            Self::Artifact(error) => write!(f, "artifact: {error}"),
            Self::RuntimeFailed(code) => write!(f, "runtime_failed: {code}"),
            Self::OutputTooLarge => f.write_str("runtime_output_too_large"),
        }
    }
}

impl std::error::Error for WwmClientError {}
impl From<std::io::Error> for WwmClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for WwmClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<ArtifactError> for WwmClientError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCheckpoint {
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub finalized_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapsuleResolution {
    pub capsule_id: String,
    pub model_name: String,
    pub artifact_sha256: String,
    pub artifact_length: u64,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub activation_state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateObjectProofJson {
    pub object_kind: String,
    pub object_id: String,
    pub canonical_value_hex: String,
    pub smt_siblings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalizedResolutionJson {
    pub schema: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub objects_root: String,
    pub pin_id: String,
    pub proofs_verified: bool,
    pub canonical_resolution_body_hex: String,
    pub finality_evidence_hex: String,
    pub state_object_proofs: Vec<StateObjectProofJson>,
    pub active: CapsuleResolution,
    #[serde(default)]
    pub candidates: Vec<CapsuleResolution>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayState {
    pub schema: String,
    pub enabled: bool,
    pub resolution: FinalizedResolutionJson,
    pub signing_key_id: String,
    pub execution: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuoteResponse {
    pub schema: String,
    pub quote_id: String,
    pub request_id: String,
    pub pin_id: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub query_profile_id: String,
    pub prompt_commitment: String,
    pub input_tokens: u32,
    pub maximum_output_tokens: u32,
    pub payment_mode: String,
    pub payment_reference: String,
    pub expires_at_height: u64,
    pub maximum_fee_micro_noos: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptResponse {
    pub schema: String,
    pub receipt_id: String,
    pub job_id: String,
    pub tenant_id: String,
    pub capsule_id: String,
    pub execution_profile_id: String,
    pub prompt_commitment: String,
    pub output_commitment: String,
    pub output_tokens: u32,
    pub terminal_status: String,
    pub evidence_state: String,
    pub chain_anchor: Option<String>,
    pub settlement_state: String,
    pub payment_mode: String,
    pub payment_reference: String,
    pub executor_id: Option<String>,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianEndpoint {
    pub position: u8,
    pub base_url: String,
    pub profile_id: Option<String>,
    pub endpoint_root: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RuntimeAttestation {
    pub claim: &'static str,
    pub model_name: &'static str,
    pub artifact_bytes: u64,
    pub artifact_sha256: &'static str,
    pub runtime_commit: &'static str,
    pub runtime_sha256: String,
    pub maximum_output_tokens: u32,
    pub remote_route_used: bool,
    pub chain_settlement_claimed: bool,
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    let bytes =
        crate::from_hex(value).map_err(|_| WwmClientError::InvalidArgument("invalid_hash32"))?;
    bytes
        .try_into()
        .map_err(|_| WwmClientError::InvalidArgument("invalid_hash32"))
}

fn exact_hex(bytes: &[u8]) -> String {
    crate::to_hex(bytes)
}

fn verify_file_identity(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &[u8; 32],
) -> Result<()> {
    let file = File::open(path)?;
    if file.metadata()?.len() != expected_bytes {
        return Err(WwmClientError::WrongArtifact);
    }
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if &actual != expected_sha256 {
        return Err(WwmClientError::WrongArtifact);
    }
    Ok(())
}

pub fn verify_exact_bonsai(path: &Path) -> Result<()> {
    verify_file_identity(path, BONSAI_SOURCE_BYTES, &hex32(BONSAI_SHA256_HEX)?)
}

fn verify_runtime(path: &Path, expected_sha256_hex: &str) -> Result<String> {
    let expected = hex32(expected_sha256_hex).map_err(|_| WwmClientError::WrongRuntime)?;
    let file = File::open(path).map_err(|_| WwmClientError::WrongRuntime)?;
    let length = file
        .metadata()
        .map_err(|_| WwmClientError::WrongRuntime)?
        .len();
    if length == 0 {
        return Err(WwmClientError::WrongRuntime);
    }
    verify_file_identity(path, length, &expected).map_err(|_| WwmClientError::WrongRuntime)?;
    Ok(expected_sha256_hex.to_owned())
}

pub fn attest_offline_inputs(
    artifact_path: &Path,
    runtime_path: &Path,
    runtime_commit: &str,
    runtime_sha256_hex: &str,
    maximum_output_tokens: u32,
) -> Result<RuntimeAttestation> {
    if runtime_commit != PRISM_RUNTIME_COMMIT {
        return Err(WwmClientError::WrongRuntime);
    }
    if maximum_output_tokens == 0 || maximum_output_tokens > MAX_OUTPUT_TOKENS {
        return Err(WwmClientError::InvalidArgument("invalid_output_limit"));
    }
    verify_exact_bonsai(artifact_path)?;
    let runtime_sha256 = verify_runtime(runtime_path, runtime_sha256_hex)?;
    Ok(RuntimeAttestation {
        claim: "LOCAL_VERIFIED",
        model_name: BONSAI_FILE_NAME,
        artifact_bytes: BONSAI_SOURCE_BYTES,
        artifact_sha256: BONSAI_SHA256_HEX,
        runtime_commit: PRISM_RUNTIME_COMMIT,
        runtime_sha256,
        maximum_output_tokens,
        remote_route_used: false,
        chain_settlement_claimed: false,
    })
}

pub fn run_offline(
    artifact_path: &Path,
    runtime_path: &Path,
    runtime_commit: &str,
    runtime_sha256_hex: &str,
    prompt: &str,
    maximum_output_tokens: u32,
    seed: u64,
) -> Result<Value> {
    if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES {
        return Err(WwmClientError::InvalidArgument("invalid_prompt"));
    }
    let attestation = attest_offline_inputs(
        artifact_path,
        runtime_path,
        runtime_commit,
        runtime_sha256_hex,
        maximum_output_tokens,
    )?;
    let output = Command::new(runtime_path)
        .arg("--model")
        .arg(artifact_path)
        .arg("--prompt")
        .arg(prompt)
        .arg("--n-predict")
        .arg(maximum_output_tokens.to_string())
        .arg("--temp")
        .arg("0")
        .arg("--top-p")
        .arg("1")
        .arg("--top-k")
        .arg("0")
        .arg("--seed")
        .arg(seed.to_string())
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
        .output()?;
    if !output.status.success() {
        return Err(WwmClientError::RuntimeFailed(
            output.status.code().unwrap_or(-1),
        ));
    }
    if output.stdout.len() > 4 * 1024 * 1024 || output.stderr.len() > 1024 * 1024 {
        return Err(WwmClientError::OutputTooLarge);
    }
    Ok(json!({
        "attestation": attestation,
        "output": String::from_utf8_lossy(&output.stdout),
        "runtime_stderr": String::from_utf8_lossy(&output.stderr),
        "disclosure": "Local artifact/runtime verification only. No chain execution or settlement claim.",
    }))
}

pub fn verify_gateway_state(
    json_bytes: &[u8],
    trusted: &TrustedCheckpoint,
) -> Result<GatewayState> {
    if json_bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(WwmClientError::InvalidResolution);
    }
    let state: GatewayState = serde_json::from_slice(json_bytes)?;
    if state.schema != "noos/wwm-gateway/v2"
        || !state.enabled
        || state.execution != "REGISTERED_EXECUTOR_EDGE_ONLY"
        || state.resolution.schema != "noos/finalized-model-resolution/v1"
        || state.resolution.finalized_height == 0
    {
        return Err(WwmClientError::InvalidResolution);
    }
    let body = crate::from_hex(&state.resolution.canonical_resolution_body_hex)
        .map_err(|_| WwmClientError::InvalidResolution)?;
    let resolution = FinalizedModelResolutionV1::decode_canonical(&body)
        .map_err(|_| WwmClientError::InvalidResolution)?;
    if !resolution.validate()
        || resolution.chain_id != trusted.chain_id
        || resolution.genesis_hash != trusted.genesis_hash
        || hex32(&state.resolution.chain_id)? != trusted.chain_id
        || hex32(&state.resolution.genesis_hash)? != trusted.genesis_hash
        || hex32(&state.resolution.finalized_hash)? != trusted.finalized_hash
        || resolution.resolution_height != state.resolution.finalized_height
    {
        return Err(WwmClientError::WrongIdentity);
    }
    let active = &state.resolution.active;
    if active.activation_state != "ACTIVE"
        || active.model_name != BONSAI_FILE_NAME
        || active.artifact_length != BONSAI_SOURCE_BYTES
        || active.artifact_sha256 != BONSAI_SHA256_HEX
        || hex32(&active.capsule_id).is_err()
    {
        return Err(WwmClientError::InvalidResolution);
    }
    if state.resolution.candidates.iter().any(|candidate| {
        candidate.activation_state != "AUTHORIZED_NOT_ACTIVE"
            || candidate.capsule_id == active.capsule_id
    }) {
        return Err(WwmClientError::CandidateNotActive);
    }
    let capsule_proof = state
        .resolution
        .state_object_proofs
        .iter()
        .find(|proof| proof.object_kind == "MODEL_CAPSULE" && proof.object_id == active.capsule_id)
        .ok_or(WwmClientError::InvalidResolution)?;
    let presented_value = crate::from_hex(&capsule_proof.canonical_value_hex)
        .map_err(|_| WwmClientError::InvalidResolution)?;
    let value_is_proved = resolution.proofs.iter().any(|proof| match &proof.value {
        ResolutionValueV1::Present(value) => value.as_slice() == presented_value.as_slice(),
        ResolutionValueV1::Absent => false,
    });
    if !value_is_proved || state.resolution.finality_evidence_hex.is_empty() {
        return Err(WwmClientError::InvalidResolution);
    }
    Ok(state)
}

fn verifying_key(public_key_hex: &str) -> Result<VerifyingKey> {
    let bytes = hex32(public_key_hex).map_err(|_| WwmClientError::InvalidSignature)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| WwmClientError::InvalidSignature)
}

fn signature(value: &str) -> Result<Signature> {
    let bytes = crate::from_hex(value).map_err(|_| WwmClientError::InvalidSignature)?;
    let array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| WwmClientError::InvalidSignature)?;
    Ok(Signature::from_bytes(&array))
}

pub fn verify_quote_signature(json_bytes: &[u8], public_key_hex: &str) -> Result<QuoteResponse> {
    let mut quote: QuoteResponse = serde_json::from_slice(json_bytes)?;
    if quote.schema != "noos/wwm-quote/v2"
        || quote.maximum_output_tokens == 0
        || quote.maximum_output_tokens > MAX_OUTPUT_TOKENS
    {
        return Err(WwmClientError::InvalidSignature);
    }
    let signed = signature(&quote.signature)?;
    quote.signature.clear();
    let canonical = serde_json::to_vec(&quote)?;
    verifying_key(public_key_hex)?
        .verify(&canonical, &signed)
        .map_err(|_| WwmClientError::InvalidSignature)?;
    quote.signature = exact_hex(&signed.to_bytes());
    Ok(quote)
}

pub fn verify_receipt_signature(
    json_bytes: &[u8],
    public_key_hex: &str,
) -> Result<ReceiptResponse> {
    let mut receipt: ReceiptResponse = serde_json::from_slice(json_bytes)?;
    if receipt.schema != "noos/wwm-receipt/v2" || receipt.output_tokens > MAX_OUTPUT_TOKENS {
        return Err(WwmClientError::InvalidSignature);
    }
    let signed = signature(&receipt.signature)?;
    receipt.signature.clear();
    let canonical = serde_json::to_vec(&receipt)?;
    verifying_key(public_key_hex)?
        .verify(&canonical, &signed)
        .map_err(|_| WwmClientError::InvalidSignature)?;
    receipt.signature = exact_hex(&signed.to_bytes());
    Ok(receipt)
}

fn checked_url(base: &str, suffix: &str) -> Result<String> {
    if !(base.starts_with("https://")
        || base.starts_with("http://127.0.0.1:")
        || base.starts_with("http://localhost:"))
        || base.contains(['\r', '\n', '#', '?'])
    {
        return Err(WwmClientError::InvalidArgument("invalid_endpoint"));
    }
    Ok(format!("{}{}", base.trim_end_matches('/'), suffix))
}
pub fn validate_custodian_base_url(base: &str) -> Result<()> {
    checked_url(base, "").map(drop)
}

fn http_bytes(
    method: &str,
    url: &str,
    body: Option<&Value>,
    bearer: Option<&str>,
    idempotency: Option<&str>,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut request = match method {
        "GET" => attohttpc::get(url),
        "POST" => attohttpc::post(url),
        _ => return Err(WwmClientError::InvalidArgument("invalid_http_method")),
    }
    .header(
        "Accept",
        "application/vnd.noos.wwm.v2+json, application/json",
    )
    .follow_redirects(false)
    .timeout(Duration::from_secs(30));
    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(key) = idempotency {
        request = request.header("Idempotency-Key", key);
    }
    let response = if let Some(value) = body {
        request
            .header("Content-Type", "application/json")
            .bytes(serde_json::to_vec(value)?)
            .send()
    } else {
        request.send()
    }
    .map_err(|error| WwmClientError::Transport(error.to_string()))?;
    let status = response.status().as_u16();
    let bytes = response
        .bytes()
        .map_err(|error| WwmClientError::Transport(error.to_string()))?;
    if bytes.len() > maximum {
        return Err(WwmClientError::OutputTooLarge);
    }
    if !(200..300).contains(&status) {
        return Err(WwmClientError::Http {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    Ok(bytes)
}

pub fn get_capsule(base_url: &str, capsule_id: &str, bearer: Option<&str>) -> Result<Value> {
    hex32(capsule_id)?;
    let url = checked_url(base_url, &format!("/api/wwm/v2/capsules/{capsule_id}"))?;
    Ok(serde_json::from_slice(&http_bytes(
        "GET",
        &url,
        None,
        bearer,
        None,
        MAX_HTTP_RESPONSE_BYTES,
    )?)?)
}

pub fn remote_quote(
    base_url: &str,
    request: &Value,
    bearer: Option<&str>,
    signing_key_hex: &str,
) -> Result<Value> {
    let url = checked_url(base_url, "/api/wwm/v2/quotes")?;
    let bytes = http_bytes(
        "POST",
        &url,
        Some(request),
        bearer,
        None,
        MAX_HTTP_RESPONSE_BYTES,
    )?;
    let verified = verify_quote_signature(&bytes, signing_key_hex)?;
    Ok(serde_json::to_value(verified)?)
}

pub fn remote_submit(
    base_url: &str,
    request: &Value,
    bearer: Option<&str>,
    idempotency_key: &str,
) -> Result<Value> {
    if idempotency_key.is_empty() || idempotency_key.len() > 256 {
        return Err(WwmClientError::InvalidArgument("invalid_idempotency_key"));
    }
    let url = checked_url(base_url, "/api/wwm/v2/jobs")?;
    Ok(serde_json::from_slice(&http_bytes(
        "POST",
        &url,
        Some(request),
        bearer,
        Some(idempotency_key),
        MAX_HTTP_RESPONSE_BYTES,
    )?)?)
}

pub fn remote_cancel(base_url: &str, job_id: &str, bearer: Option<&str>) -> Result<Value> {
    hex32(job_id)?;
    let url = checked_url(base_url, &format!("/api/wwm/v2/jobs/{job_id}/cancel"))?;
    Ok(serde_json::from_slice(&http_bytes(
        "POST",
        &url,
        None,
        bearer,
        None,
        MAX_HTTP_RESPONSE_BYTES,
    )?)?)
}

pub fn remote_receipt(
    base_url: &str,
    job_id: &str,
    bearer: Option<&str>,
    signing_key_hex: &str,
) -> Result<Value> {
    hex32(job_id)?;
    let url = checked_url(base_url, &format!("/api/wwm/v2/jobs/{job_id}/receipt"))?;
    let bytes = http_bytes("GET", &url, None, bearer, None, MAX_HTTP_RESPONSE_BYTES)?;
    Ok(serde_json::to_value(verify_receipt_signature(
        &bytes,
        signing_key_hex,
    )?)?)
}

struct CustodianShareSource {
    endpoints: BTreeMap<u8, String>,
    manifest_root: String,
}

impl ArtifactShareSource for CustodianShareSource {
    fn read_share(
        &mut self,
        stripe: u32,
        position: u8,
        out: &mut [u8],
    ) -> std::result::Result<bool, ArtifactError> {
        if out.len() != ARTIFACT_SHARE_BYTES {
            return Err(ArtifactError::InvalidShare { stripe, position });
        }
        let Some(base) = self.endpoints.get(&position) else {
            return Ok(false);
        };
        let suffix = format!(
            "/artifacts/{}/shares/{stripe}/{position}",
            self.manifest_root
        );
        let url = checked_url(base, &suffix)
            .map_err(|error| ArtifactError::Io(std::io::Error::other(error.to_string())))?;
        let response = attohttpc::get(&url)
            .header("Accept", "application/octet-stream")
            .follow_redirects(false)
            .timeout(Duration::from_secs(60))
            .send()
            .map_err(|error| ArtifactError::Io(std::io::Error::other(error.to_string())))?;
        let status = response.status().as_u16();
        if matches!(status, 404 | 410 | 503) {
            return Ok(false);
        }
        if status != 200 {
            return Err(ArtifactError::Io(std::io::Error::other(format!(
                "custodian HTTP {status}"
            ))));
        }
        let bytes = response
            .bytes()
            .map_err(|error| ArtifactError::Io(std::io::Error::other(error.to_string())))?;
        if bytes.len() != ARTIFACT_SHARE_BYTES {
            return Err(ArtifactError::InvalidShare { stripe, position });
        }
        out.copy_from_slice(&bytes);
        Ok(true)
    }
}

#[allow(clippy::permissions_set_readonly_false)]
fn remove_partial(path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            #[cfg(windows)]
            permissions.set_readonly(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                permissions.set_mode(permissions.mode() | 0o200);
            }
            let _ = fs::set_permissions(path, permissions);
        }
    }
    let _ = fs::remove_file(path);
}

pub fn fetch_from_custodians(
    manifest_path: &Path,
    custodian_map_path: &Path,
    expected_manifest_root: &str,
    output_path: &Path,
) -> Result<Value> {
    let manifest_bytes = fs::read(manifest_path)?;
    if manifest_bytes.len() > 1024 * 1024 {
        return Err(WwmClientError::InvalidResolution);
    }
    let manifest = ArtifactManifestV1::from_canonical_bytes(&manifest_bytes)?;
    manifest.validate_bonsai_geometry()?;
    if exact_hex(manifest.manifest_root().as_bytes()) != expected_manifest_root
        || exact_hex(&manifest.published_sha256) != BONSAI_SHA256_HEX
    {
        return Err(WwmClientError::WrongArtifact);
    }
    let endpoint_bytes = fs::read(custodian_map_path)?;
    if endpoint_bytes.len() > 64 * 1024 {
        return Err(WwmClientError::InvalidArgument("custodian_map_too_large"));
    }
    let endpoints: Vec<CustodianEndpoint> = serde_json::from_slice(&endpoint_bytes)?;
    let mut map = BTreeMap::new();
    for endpoint in endpoints {
        if endpoint.position >= 12 || map.insert(endpoint.position, endpoint.base_url).is_some() {
            return Err(WwmClientError::InvalidArgument("invalid_custodian_map"));
        }
    }
    if map.len() < 8 {
        return Err(WwmClientError::InvalidArgument(
            "fewer_than_eight_custodians",
        ));
    }
    let mut source = CustodianShareSource {
        endpoints: map,
        manifest_root: expected_manifest_root.to_owned(),
    };
    if output_path.exists() {
        return Err(WwmClientError::InvalidArgument("artifact_output_exists"));
    }
    let partial = PathBuf::from(format!("{}.partial", output_path.display()));
    let result = (|| -> Result<()> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&partial)?;
        ArtifactDecoderV1::new()?.decode(&manifest, &mut source, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        drop(output);
        verify_exact_bonsai(&partial)?;
        let mut permissions = fs::metadata(&partial)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&partial, permissions)?;
        fs::rename(&partial, output_path)?;
        Ok(())
    })();
    if result.is_err() {
        remove_partial(&partial);
    }
    result?;
    Ok(json!({
        "artifact_path": output_path,
        "artifact_bytes": BONSAI_SOURCE_BYTES,
        "artifact_sha256": BONSAI_SHA256_HEX,
        "manifest_root": expected_manifest_root,
        "source": "BONDED_CUSTODIANS",
        "publisher_or_gateway_fallback": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;

    #[test]
    fn file_identity_rejects_length_and_digest_substitution() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fixture.bin");
        fs::write(&path, b"bonsai").unwrap();
        let digest: [u8; 32] = Sha256::digest(b"bonsai").into();
        verify_file_identity(&path, 6, &digest).unwrap();
        assert!(matches!(
            verify_file_identity(&path, 7, &digest),
            Err(WwmClientError::WrongArtifact)
        ));
        assert!(matches!(
            verify_file_identity(&path, 6, &[0; 32]),
            Err(WwmClientError::WrongArtifact)
        ));
    }

    fn signed_quote(key: &SigningKey) -> (Vec<u8>, String) {
        let mut quote = QuoteResponse {
            schema: "noos/wwm-quote/v2".into(),
            quote_id: "11".repeat(32),
            request_id: "request-1".into(),
            pin_id: "22".repeat(32),
            capsule_id: "33".repeat(32),
            execution_profile_id: "44".repeat(32),
            query_profile_id: "55".repeat(32),
            prompt_commitment: "66".repeat(32),
            input_tokens: 7,
            maximum_output_tokens: 8,
            payment_mode: "PAID".into(),
            payment_reference: "escrow-1".into(),
            expires_at_height: 99,
            maximum_fee_micro_noos: 17,
            signature: String::new(),
        };
        let message = serde_json::to_vec(&quote).unwrap();
        quote.signature = exact_hex(&key.sign(&message).to_bytes());
        (
            serde_json::to_vec(&quote).unwrap(),
            exact_hex(key.verifying_key().as_bytes()),
        )
    }

    #[test]
    fn quote_signature_rejects_wrong_key_and_mutation() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (bytes, public) = signed_quote(&key);
        verify_quote_signature(&bytes, &public).unwrap();
        assert!(matches!(
            verify_quote_signature(&bytes, &"09".repeat(32)),
            Err(WwmClientError::InvalidSignature)
        ));
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["capsule_id"] = Value::String("aa".repeat(32));
        assert!(matches!(
            verify_quote_signature(&serde_json::to_vec(&value).unwrap(), &public),
            Err(WwmClientError::InvalidSignature)
        ));
    }

    #[test]
    fn runtime_attestation_has_no_remote_or_settlement_claim() {
        let attestation = RuntimeAttestation {
            claim: "LOCAL_VERIFIED",
            model_name: BONSAI_FILE_NAME,
            artifact_bytes: BONSAI_SOURCE_BYTES,
            artifact_sha256: BONSAI_SHA256_HEX,
            runtime_commit: PRISM_RUNTIME_COMMIT,
            runtime_sha256: "ab".repeat(32),
            maximum_output_tokens: 64,
            remote_route_used: false,
            chain_settlement_claimed: false,
        };
        let value = serde_json::to_value(attestation).unwrap();
        assert_eq!(value["claim"], "LOCAL_VERIFIED");
        assert_eq!(value["remote_route_used"], false);
        assert_eq!(value["chain_settlement_claimed"], false);
    }

    #[test]
    fn only_https_or_explicit_loopback_http_is_allowed() {
        assert!(checked_url("https://custodian.example", "/x").is_ok());
        assert!(checked_url("http://127.0.0.1:8080", "/x").is_ok());
        assert!(checked_url("http://remote.example", "/x").is_err());
        assert!(checked_url("https://good.example\r\nX-Evil: 1", "/x").is_err());
    }
}
