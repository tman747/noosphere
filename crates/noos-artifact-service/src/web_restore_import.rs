//! One-shot promotion of a complete coordinator-quarantined position into a
//! separate artifact store. Coordinator receipts are routing evidence only;
//! every byte is reverified against the canonical `noos-da` manifest.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use noos_crypto::{hash_domain, verify_domain, DomainId, Hash32, PublicKey, Signature};
use noos_da::{
    share_commitment, ArtifactManifestV1, ARTIFACT_MAX_STRIPES, ARTIFACT_POSITIONS,
    ARTIFACT_SHARE_BYTES,
};
use noos_store::{ArtifactIngestSpec, ArtifactKey, ArtifactStore, ArtifactStoreConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

pub const IMPORT_INDEX_SCHEMA: &str = "noos/wwm-web-capacity/v1";
pub const IMPORT_INDEX_RECORD_KIND: &str = "WEB_RESTORED_POSITION_IMPORT_INDEX";
pub const IMPORT_INDEX_SIGNATURE_DOMAIN: &str = "NOOS/SIG/WWM-WEB-RESTORE-IMPORT-INDEX/V1";
pub const RESTORE_TASK_SIGNATURE_DOMAIN: &str = "NOOS/SIG/WWM-WEB-RESTORE-TASK/V1";
const MAX_IMPORT_INDEX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct WebRestoredPositionImportConfig {
    pub source_store: ArtifactStoreConfig,
    pub quarantine_root: PathBuf,
    pub import_index_path: PathBuf,
    pub target_position: u8,
    /// Operator-pinned coordinator key; never learned from the index itself.
    pub expected_coordinator_public_key: String,
    /// Operator-pinned finalized chain/artifact identity.
    pub expected_chain_binding: ImportChainBinding,
    pub replacement_store: ArtifactStoreConfig,
    pub report_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportChainBinding {
    pub chain_id: String,
    pub genesis_hash: String,
    pub artifact_id: String,
    pub manifest_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportSignature {
    pub suite: String,
    pub domain: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportCoordinate {
    pub stripe: u32,
    pub position: u8,
    pub bytes: u64,
    pub transport_sha256: String,
    pub protocol_share_digest: String,
    pub probe_root: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRestoreTask {
    pub schema: String,
    pub record_kind: String,
    pub task_id: String,
    pub participant_id: String,
    pub canonical_origin: String,
    pub chain_binding: ImportChainBinding,
    pub coordinate: ImportCoordinate,
    pub expected_bytes: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: ImportSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceiptRecord {
    pub schema: String,
    pub record_kind: String,
    pub task_id: String,
    pub coordinate_digest: String,
    pub bytes: u64,
    pub quarantine_id: String,
    pub canonical_verified: bool,
    pub accepted_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportTaskReceiptPair {
    pub source_origin: String,
    pub task: SignedRestoreTask,
    pub receipt: RestoreReceiptRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPositionImportIndex {
    pub schema: String,
    pub record_kind: String,
    pub coordinator_public_key: String,
    pub chain_binding: ImportChainBinding,
    pub target_position: u8,
    pub generated_at: u64,
    pub expires_at: u64,
    pub rows: Vec<ImportTaskReceiptPair>,
    pub signature: ImportSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WebRestoredPositionImportEvidence {
    pub schema: &'static str,
    pub coordinator_public_key: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub artifact_id: String,
    pub manifest_root: String,
    pub protocol_payload_root: String,
    pub published_sha256: String,
    pub position_root: String,
    pub import_index_sha256: String,
    pub target_position: u8,
    pub stripe_count: u32,
    pub imported_share_count: u32,
    pub imported_bytes: u64,
    pub production_custody: bool,
    pub availability_certificate_effect: bool,
    pub rewards: bool,
    pub insert_once: bool,
}

/// Imports exactly one complete manifest position from coordinator quarantine.
///
/// The source store is only used to read its already-published canonical
/// manifest. The replacement store is a distinct isolated store and remains
/// unpublished unless all index rows and all quarantine bytes verify.
pub fn import_web_restored_position(
    config: WebRestoredPositionImportConfig,
) -> Result<WebRestoredPositionImportEvidence, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before Unix epoch: {error}"))?
        .as_secs();
    import_web_restored_position_at(config, now)
}

fn import_web_restored_position_at(
    config: WebRestoredPositionImportConfig,
    now: u64,
) -> Result<WebRestoredPositionImportEvidence, String> {
    if config.target_position as usize >= ARTIFACT_POSITIONS {
        return Err("target position is outside 0..12".to_owned());
    }
    validate_store_separation(&config)?;

    let raw_index = read_bounded_file(&config.import_index_path, MAX_IMPORT_INDEX_BYTES)?;
    let index: SignedPositionImportIndex = serde_json::from_slice(&raw_index)
        .map_err(|error| format!("decode signed import index: {error}"))?;
    verify_index_envelope(
        &index,
        config.target_position,
        &config.expected_coordinator_public_key,
        &config.expected_chain_binding,
        now,
    )?;

    let artifact = decode_hex32(&index.chain_binding.artifact_id, "artifact_id")?;
    let source_store = ArtifactStore::open(config.source_store.clone())
        .map_err(|error| format!("open canonical source artifact store: {error}"))?;
    let manifest_bytes = source_store
        .read_manifest(&artifact)
        .map_err(|error| format!("read canonical source manifest: {error}"))?;
    let manifest = ArtifactManifestV1::from_canonical_bytes(&manifest_bytes)
        .map_err(|error| format!("decode canonical source manifest: {error}"))?;
    manifest
        .validate()
        .map_err(|error| format!("validate canonical source manifest: {error}"))?;
    let manifest_root = hex::encode(manifest.manifest_root().as_bytes());
    if manifest_root != index.chain_binding.manifest_root {
        return Err(
            "import index manifest_root does not match canonical source manifest".to_owned(),
        );
    }
    if index.rows.len() != manifest.stripes.len() {
        return Err(format!(
            "import index must contain exactly {} rows for the canonical manifest",
            manifest.stripes.len()
        ));
    }

    let canonical_quarantine_root = validate_quarantine_root(&config.quarantine_root)?;
    validate_rows_and_quarantine(
        &index,
        &manifest,
        &artifact,
        &canonical_quarantine_root,
        config.target_position,
        now,
    )?;

    let mut report_file = EvidenceReservation::create(&config.report_path)?;
    let result = (|| {
        let mut replacement = ArtifactStore::open(config.replacement_store.clone())
            .map_err(|error| format!("open replacement artifact store: {error}"))?;
        let existing = replacement
            .resume_state(&artifact)
            .map_err(|error| format!("read replacement resume state: {error}"))?;
        if existing.published {
            return Err("replacement artifact is already published".to_owned());
        }
        replacement
            .begin_ingest(ArtifactIngestSpec {
                artifact,
                stripe_count: manifest.stripes.len() as u32,
                positions: vec![config.target_position],
            })
            .map_err(|error| format!("begin replacement position ingest: {error}"))?;

        let mut share = vec![0_u8; ARTIFACT_SHARE_BYTES];
        for row in &index.rows {
            read_and_verify_quarantine_share(
                row,
                &manifest,
                &artifact,
                &canonical_quarantine_root,
                config.target_position,
                &mut share,
            )?;
            replacement
                .stage_share(
                    &artifact,
                    row.task.coordinate.stripe,
                    config.target_position,
                    &share,
                )
                .map_err(|error| format!("stage replacement share: {error}"))?;
            replacement
                .checkpoint_stripe(&artifact, row.task.coordinate.stripe)
                .map_err(|error| format!("checkpoint replacement stripe: {error}"))?;
        }
        replacement
            .publish(&artifact, &manifest_bytes)
            .map_err(|error| format!("publish replacement position: {error}"))?;
        drop(replacement);

        let reopened = ArtifactStore::open(config.replacement_store.clone())
            .map_err(|error| format!("reopen replacement artifact store: {error}"))?;
        if reopened
            .read_manifest(&artifact)
            .map_err(|error| format!("reopen replacement manifest: {error}"))?
            != manifest_bytes
        {
            return Err("reopened replacement manifest bytes changed".to_owned());
        }
        let mut reopened_share = vec![0_u8; ARTIFACT_SHARE_BYTES];
        for stripe in &manifest.stripes {
            reopened
                .read_share(
                    &artifact,
                    stripe.stripe_index,
                    config.target_position,
                    &mut reopened_share,
                )
                .map_err(|error| format!("reopen replacement share: {error}"))?;
            let commitment =
                share_commitment(stripe.stripe_index, config.target_position, &reopened_share)
                    .map_err(|error| format!("reverify replacement share: {error}"))?;
            if commitment != stripe.shares[config.target_position as usize] {
                return Err(format!(
                    "reopened share commitment mismatch at stripe {} position {}",
                    stripe.stripe_index, config.target_position
                ));
            }
        }
        let resume = reopened
            .resume_state(&artifact)
            .map_err(|error| format!("reopen replacement publication state: {error}"))?;
        if !resume.published {
            return Err("reopened replacement publication state is incomplete".to_owned());
        }

        let canonical_index = canonical_json(
            &serde_json::to_value(&index)
                .map_err(|error| format!("encode import index for evidence: {error}"))?,
        )?;
        let evidence = WebRestoredPositionImportEvidence {
            schema: "noos.wwm.web-restored-position-import-evidence.v1",
            coordinator_public_key: index.coordinator_public_key.clone(),
            chain_id: index.chain_binding.chain_id.clone(),
            genesis_hash: index.chain_binding.genesis_hash.clone(),
            artifact_id: index.chain_binding.artifact_id.clone(),
            manifest_root,
            protocol_payload_root: hex::encode(manifest.protocol_payload_root.as_bytes()),
            published_sha256: hex::encode(manifest.published_sha256),
            position_root: hex::encode(
                manifest.position_roots[config.target_position as usize].as_bytes(),
            ),
            import_index_sha256: sha256_hex(&canonical_index),
            target_position: config.target_position,
            stripe_count: manifest.stripes.len() as u32,
            imported_share_count: manifest.stripes.len() as u32,
            imported_bytes: (manifest.stripes.len() as u64)
                .checked_mul(ARTIFACT_SHARE_BYTES as u64)
                .ok_or_else(|| "imported byte count overflow".to_owned())?,
            production_custody: false,
            availability_certificate_effect: false,
            rewards: false,
            insert_once: true,
        };
        report_file.commit(&evidence)?;
        Ok(evidence)
    })();
    result
}

fn validate_store_separation(config: &WebRestoredPositionImportConfig) -> Result<(), String> {
    let source = absolute_normalized(&config.source_store.root)?;
    let replacement = absolute_normalized(&config.replacement_store.root)?;
    let quarantine = absolute_normalized(&config.quarantine_root)?;
    if overlaps(&source, &replacement)
        || overlaps(&source, &quarantine)
        || overlaps(&replacement, &quarantine)
    {
        return Err(
            "source, quarantine, and replacement artifact roots must be pairwise separate"
                .to_owned(),
        );
    }
    Ok(())
}

fn verify_index_envelope(
    index: &SignedPositionImportIndex,
    target_position: u8,
    expected_coordinator_public_key: &str,
    expected_chain_binding: &ImportChainBinding,
    now: u64,
) -> Result<(), String> {
    if index.schema != IMPORT_INDEX_SCHEMA || index.record_kind != IMPORT_INDEX_RECORD_KIND {
        return Err("signed import index schema or record_kind is invalid".to_owned());
    }
    if index.target_position != target_position {
        return Err("signed import index target position mismatch".to_owned());
    }
    if index.rows.is_empty() || index.rows.len() > ARTIFACT_MAX_STRIPES {
        return Err("signed import index row count is outside canonical bounds".to_owned());
    }
    if index.generated_at > now || index.expires_at <= now || index.expires_at <= index.generated_at
    {
        return Err("signed import index is not currently valid".to_owned());
    }
    validate_hex32(&index.coordinator_public_key, "coordinator_public_key")?;
    validate_chain_binding(&index.chain_binding)?;
    validate_hex32(
        expected_coordinator_public_key,
        "expected coordinator_public_key",
    )?;
    validate_chain_binding(expected_chain_binding)?;
    if index.coordinator_public_key != expected_coordinator_public_key {
        return Err(
            "signed import index coordinator key differs from operator-pinned key".to_owned(),
        );
    }
    if &index.chain_binding != expected_chain_binding {
        return Err(
            "signed import index chain binding differs from operator-pinned identity".to_owned(),
        );
    }
    verify_signature_value(
        &index.signature,
        &index.coordinator_public_key,
        IMPORT_INDEX_SIGNATURE_DOMAIN,
        DomainId::SigWwmWebRestoreImportIndexV1,
        unsigned_value(index)?,
    )
}

fn validate_rows_and_quarantine(
    index: &SignedPositionImportIndex,
    manifest: &ArtifactManifestV1,
    artifact: &ArtifactKey,
    quarantine_root: &Path,
    target_position: u8,
    now: u64,
) -> Result<(), String> {
    let mut task_ids = BTreeSet::new();
    let mut quarantine_ids = BTreeSet::new();
    let mut share = vec![0_u8; ARTIFACT_SHARE_BYTES];
    for (expected_stripe, row) in index.rows.iter().enumerate() {
        validate_pair(
            row,
            index,
            manifest,
            artifact,
            expected_stripe as u32,
            target_position,
            now,
            &mut task_ids,
            &mut quarantine_ids,
        )?;
        read_and_verify_quarantine_share(
            row,
            manifest,
            artifact,
            quarantine_root,
            target_position,
            &mut share,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_pair(
    row: &ImportTaskReceiptPair,
    index: &SignedPositionImportIndex,
    manifest: &ArtifactManifestV1,
    artifact: &ArtifactKey,
    expected_stripe: u32,
    target_position: u8,
    now: u64,
    task_ids: &mut BTreeSet<String>,
    quarantine_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    let task = &row.task;
    let receipt = &row.receipt;
    if task.schema != IMPORT_INDEX_SCHEMA || task.record_kind != "RESTORE_TASK" {
        return Err("restore task schema or record_kind is invalid".to_owned());
    }
    if receipt.schema != IMPORT_INDEX_SCHEMA || receipt.record_kind != "RESTORE_RECEIPT" {
        return Err("restore receipt schema or record_kind is invalid".to_owned());
    }
    validate_hex32(&task.task_id, "task_id")?;
    if !task_ids.insert(task.task_id.clone()) {
        return Err("duplicate restore task_id".to_owned());
    }
    validate_canonical_https_origin(&task.canonical_origin)?;
    let source_origin = validate_canonical_https_origin(&row.source_origin)?;
    let coordinate_origin = origin_of_url(&task.coordinate.url)?;
    if coordinate_origin != source_origin {
        return Err("restore coordinate URL leaves its signed source origin".to_owned());
    }
    if task.chain_binding != index.chain_binding {
        return Err("restore task chain binding differs from import index".to_owned());
    }
    if task.coordinate.stripe != expected_stripe
        || task.coordinate.position != target_position
        || task.coordinate.bytes != ARTIFACT_SHARE_BYTES as u64
        || task.expected_bytes != ARTIFACT_SHARE_BYTES as u64
    {
        return Err(format!(
            "restore row has wrong coordinate or length at expected stripe {expected_stripe}"
        ));
    }
    if task.issued_at > now
        || task.expires_at <= now
        || task.expires_at <= task.issued_at
        || receipt.accepted_at < task.issued_at
        || receipt.accepted_at > task.expires_at
    {
        return Err("restore task or receipt time binding is invalid or expired".to_owned());
    }
    verify_signature_value(
        &task.signature,
        &index.coordinator_public_key,
        RESTORE_TASK_SIGNATURE_DOMAIN,
        DomainId::SigWwmWebRestoreTaskV1,
        unsigned_value(task)?,
    )?;
    if receipt.task_id != task.task_id || receipt.bytes != task.expected_bytes {
        return Err("restore receipt does not match its signed task identity".to_owned());
    }
    let coordinate_digest =
        coordinate_digest(&index.chain_binding, expected_stripe, target_position)?;
    if receipt.coordinate_digest != coordinate_digest {
        return Err("restore receipt coordinate digest mismatch".to_owned());
    }
    validate_hex32(&receipt.quarantine_id, "quarantine_id")?;
    let expected_quarantine_id = quarantine_id(
        &task.task_id,
        &coordinate_digest,
        &task.coordinate.transport_sha256,
    )?;
    if receipt.quarantine_id != expected_quarantine_id {
        return Err("restore receipt quarantine_id mismatch".to_owned());
    }
    if !quarantine_ids.insert(receipt.quarantine_id.clone()) {
        return Err("duplicate restore quarantine_id".to_owned());
    }
    let claimed = &task.coordinate;
    validate_hex32(&claimed.transport_sha256, "transport_sha256")?;
    let share_digest = decode_hex32(&claimed.protocol_share_digest, "protocol_share_digest")?;
    let probe_root = decode_hex32(&claimed.probe_root, "probe_root")?;
    let canonical = manifest.stripes[expected_stripe as usize].shares[target_position as usize];
    if canonical.share_digest != Hash32::from_bytes(share_digest)
        || canonical.probe_root != Hash32::from_bytes(probe_root)
    {
        return Err(
            "restore coordinate noos-da commitment differs from canonical manifest".to_owned(),
        );
    }
    let _ = artifact;
    Ok(())
}

fn read_and_verify_quarantine_share(
    row: &ImportTaskReceiptPair,
    manifest: &ArtifactManifestV1,
    artifact: &ArtifactKey,
    quarantine_root: &Path,
    target_position: u8,
    out: &mut [u8],
) -> Result<(), String> {
    let path = quarantine_share_path(
        quarantine_root,
        &hex::encode(artifact),
        &row.receipt.quarantine_id,
    )?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect quarantine share {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "quarantine share is not a regular non-symlink file: {}",
            path.display()
        ));
    }
    if metadata.len() != ARTIFACT_SHARE_BYTES as u64 || out.len() != ARTIFACT_SHARE_BYTES {
        return Err(format!(
            "quarantine share has wrong length: {}",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("canonicalize quarantine share {}: {error}", path.display()))?;
    let canonical_root = quarantine_root;
    if !canonical.starts_with(&canonical_root) {
        return Err("quarantine share escapes quarantine root".to_owned());
    }
    let mut file = File::open(&canonical)
        .map_err(|error| format!("open quarantine share {}: {error}", canonical.display()))?;
    file.read_exact(out)
        .map_err(|error| format!("read quarantine share {}: {error}", canonical.display()))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| format!("finish quarantine share read: {error}"))?
        != 0
    {
        return Err("quarantine share grew while it was read".to_owned());
    }
    if sha256_hex(out) != row.task.coordinate.transport_sha256 {
        return Err(format!(
            "quarantine transport_sha256 mismatch at stripe {} position {}",
            row.task.coordinate.stripe, target_position
        ));
    }
    let commitment = share_commitment(row.task.coordinate.stripe, target_position, out)
        .map_err(|error| format!("compute quarantine noos-da commitment: {error}"))?;
    let canonical_commitment =
        manifest.stripes[row.task.coordinate.stripe as usize].shares[target_position as usize];
    if commitment != canonical_commitment
        || hex::encode(commitment.share_digest.as_bytes())
            != row.task.coordinate.protocol_share_digest
        || hex::encode(commitment.probe_root.as_bytes()) != row.task.coordinate.probe_root
    {
        return Err(format!(
            "quarantine noos-da commitment/probe root mismatch at stripe {} position {}",
            row.task.coordinate.stripe, target_position
        ));
    }
    Ok(())
}

fn validate_quarantine_root(root: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect quarantine root {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("quarantine root must be a non-symlink directory".to_owned());
    }
    fs::canonicalize(root)
        .map_err(|error| format!("canonicalize quarantine root {}: {error}", root.display()))
}

fn quarantine_share_path(
    root: &Path,
    artifact_id: &str,
    quarantine_id: &str,
) -> Result<PathBuf, String> {
    validate_hex32(artifact_id, "artifact_id")?;
    validate_hex32(quarantine_id, "quarantine_id")?;
    let artifact_dir = root.join(artifact_id);
    let metadata = fs::symlink_metadata(&artifact_dir).map_err(|error| {
        format!(
            "inspect quarantine artifact directory {}: {error}",
            artifact_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("quarantine artifact directory must be a non-symlink directory".to_owned());
    }
    Ok(artifact_dir.join(format!("{quarantine_id}.share")))
}

fn validate_chain_binding(binding: &ImportChainBinding) -> Result<(), String> {
    validate_hex32(&binding.chain_id, "chain_id")?;
    validate_hex32(&binding.genesis_hash, "genesis_hash")?;
    validate_hex32(&binding.artifact_id, "artifact_id")?;
    validate_hex32(&binding.manifest_root, "manifest_root")?;
    Ok(())
}

fn verify_signature_value(
    signature: &ImportSignature,
    expected_public_key: &str,
    expected_domain: &str,
    domain: DomainId,
    unsigned: Value,
) -> Result<(), String> {
    if signature.suite != "Ed25519"
        || signature.domain != expected_domain
        || signature.public_key != expected_public_key
    {
        return Err("signature suite/domain/public-key binding is invalid".to_owned());
    }
    let public_key = PublicKey::from_bytes(decode_hex32(&signature.public_key, "public_key")?);
    let signature_bytes = decode_hex64(&signature.signature, "signature")?;
    let signature = Signature::from_bytes(signature_bytes);
    let bytes = canonical_json(&unsigned)?;
    verify_domain(domain, &public_key, &[&bytes], &signature)
        .map_err(|_| "Ed25519 signature verification failed".to_owned())
}

fn unsigned_value<T: Serialize>(record: &T) -> Result<Value, String> {
    let mut value =
        serde_json::to_value(record).map_err(|error| format!("encode signed record: {error}"))?;
    value
        .as_object_mut()
        .ok_or_else(|| "signed record is not a JSON object".to_owned())?
        .remove("signature")
        .ok_or_else(|| "signed record lacks signature".to_owned())?;
    Ok(value)
}

fn coordinate_digest(
    binding: &ImportChainBinding,
    stripe: u32,
    position: u8,
) -> Result<String, String> {
    hash_domain(
        DomainId::WwmWebCoordinateIdV1,
        &[
            binding.artifact_id.as_bytes(),
            binding.manifest_root.as_bytes(),
            &stripe.to_le_bytes(),
            &[position],
        ],
    )
    .map(|hash| hex::encode(hash.as_bytes()))
    .map_err(|error| format!("compute coordinate digest: {error}"))
}

fn quarantine_id(
    task_id: &str,
    coordinate_digest: &str,
    transport_sha256: &str,
) -> Result<String, String> {
    hash_domain(
        DomainId::WwmWebQuarantineIdV1,
        &[
            task_id.as_bytes(),
            coordinate_digest.as_bytes(),
            transport_sha256.as_bytes(),
        ],
    )
    .map(|hash| hex::encode(hash.as_bytes()))
    .map_err(|error| format!("compute quarantine_id: {error}"))
}

fn validate_canonical_https_origin(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|error| format!("invalid HTTPS origin: {error}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("origin must be canonical HTTPS scheme/authority only".to_owned());
    }
    let canonical = parsed.origin().ascii_serialization();
    if canonical != value {
        return Err("origin is not in canonical HTTPS form".to_owned());
    }
    Ok(canonical)
}

fn origin_of_url(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|error| format!("invalid coordinate URL: {error}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "coordinate URL must be absolute HTTPS without credentials or fragment".to_owned(),
        );
    }
    Ok(parsed.origin().ascii_serialization())
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(format!(
            "signed import index must be a regular non-symlink file of at most {maximum} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn absolute_normalized(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(format!("path escapes its root: {}", path.display()));
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn validate_hex32(value: &str, field: &str) -> Result<(), String> {
    decode_hex32(value, field).map(|_| ())
}

fn decode_hex32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{field} must be lowercase hex32"))?;
    if hex::encode(&bytes) != value {
        return Err(format!("{field} must be lowercase hex32"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be exactly 32 bytes"))
}

fn decode_hex64(value: &str, field: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{field} must be lowercase hex64"))?;
    if hex::encode(&bytes) != value {
        return Err(format!("{field} must be lowercase hex64"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be exactly 64 bytes"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err("floating-point values are forbidden in signed records".to_owned());
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(text) => output.extend_from_slice(
            serde_json::to_string(text)
                .map_err(|error| format!("encode JSON string: {error}"))?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| utf16_order(left, right));
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|error| format!("encode JSON key: {error}"))?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn utf16_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

struct EvidenceReservation {
    path: PathBuf,
    file: Option<File>,
}

impl EvidenceReservation {
    fn create(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("create-new evidence report {}: {error}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
        })
    }

    fn commit<T: Serialize>(&mut self, report: &T) -> Result<(), String> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| "evidence reservation already committed".to_owned())?;
        serde_json::to_writer_pretty(&mut *file, report)
            .map_err(|error| format!("encode evidence report: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("finish evidence report: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync evidence report: {error}"))?;
        self.file.take();
        Ok(())
    }
}

impl Drop for EvidenceReservation {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.file.take();
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::env;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use noos_crypto::Keypair;
    use noos_da::{ArtifactEncoderV1, ArtifactError, ArtifactShareSink, ARTIFACT_STRIPE_BYTES};

    static NONCE: AtomicU64 = AtomicU64::new(0);
    const NOW: u64 = 1_800_000_000;
    const POSITION: u8 = 3;

    struct CapturingSink {
        shares: BTreeMap<(u32, u8), Vec<u8>>,
    }

    impl ArtifactShareSink for CapturingSink {
        fn begin_artifact(
            &mut self,
            _source_length: u64,
            _protocol_payload_root: &Hash32,
            _published_sha256: &[u8; 32],
            _stripe_count: u32,
        ) -> Result<(), ArtifactError> {
            Ok(())
        }

        fn stage_share(
            &mut self,
            stripe: u32,
            position: u8,
            bytes: &[u8],
        ) -> Result<(), ArtifactError> {
            self.shares.insert((stripe, position), bytes.to_vec());
            Ok(())
        }

        fn checkpoint_stripe(&mut self, _stripe: u32) -> Result<(), ArtifactError> {
            Ok(())
        }

        fn publish_manifest(
            &mut self,
            _manifest: &ArtifactManifestV1,
        ) -> Result<(), ArtifactError> {
            Ok(())
        }
    }

    struct Fixture {
        root: PathBuf,
        source_config: ArtifactStoreConfig,
        quarantine_root: PathBuf,
        index_path: PathBuf,
        report_path: PathBuf,
        replacement_config: ArtifactStoreConfig,
        artifact: ArtifactKey,
        manifest: ArtifactManifestV1,
        index: SignedPositionImportIndex,
        shares: Vec<Vec<u8>>,
        signer: Keypair,
    }

    impl Fixture {
        fn new(stripes: usize) -> Self {
            let nonce = NONCE.fetch_add(1, AtomicOrdering::Relaxed);
            let root = env::temp_dir().join(format!(
                "noos-web-restore-import-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root).unwrap();
            let source_config = ArtifactStoreConfig::under(
                root.join("source"),
                root.join("source-consensus"),
                128 * 1024 * 1024,
            );
            let replacement_config = ArtifactStoreConfig::under(
                root.join("replacement"),
                root.join("replacement-consensus"),
                128 * 1024 * 1024,
            );
            let quarantine_root = root.join("quarantine");
            fs::create_dir_all(&quarantine_root).unwrap();
            let index_path = root.join("import-index.json");
            let report_path = root.join("evidence.json");
            let source_len = if stripes == 1 {
                37
            } else {
                (stripes - 1) * ARTIFACT_STRIPE_BYTES + 37
            };
            let source = (0..source_len)
                .map(|index| ((index * 29 + 7) % 251) as u8)
                .collect::<Vec<_>>();
            let mut sink = CapturingSink {
                shares: BTreeMap::new(),
            };
            let manifest = ArtifactEncoderV1::new()
                .unwrap()
                .encode(&mut Cursor::new(source), &mut sink, 1)
                .unwrap();
            assert_eq!(manifest.stripes.len(), stripes);
            let artifact = [0x44_u8; 32];

            let mut source_store = ArtifactStore::open(source_config.clone()).unwrap();
            source_store
                .begin_ingest(ArtifactIngestSpec {
                    artifact,
                    stripe_count: stripes as u32,
                    positions: (0..ARTIFACT_POSITIONS as u8).collect(),
                })
                .unwrap();
            for stripe in 0..stripes as u32 {
                for position in 0..ARTIFACT_POSITIONS as u8 {
                    source_store
                        .stage_share(
                            &artifact,
                            stripe,
                            position,
                            &sink.shares[&(stripe, position)],
                        )
                        .unwrap();
                }
                source_store.checkpoint_stripe(&artifact, stripe).unwrap();
            }
            source_store
                .publish(&artifact, &manifest.canonical_bytes())
                .unwrap();
            drop(source_store);

            let artifact_hex = hex::encode(artifact);
            let artifact_quarantine = quarantine_root.join(&artifact_hex);
            fs::create_dir_all(&artifact_quarantine).unwrap();
            let signer = Keypair::from_seed([0x31; 32]);
            let coordinator_public_key = hex::encode(signer.public_key().as_bytes());
            let binding = ImportChainBinding {
                chain_id: hex::encode([0x11; 32]),
                genesis_hash: hex::encode([0x22; 32]),
                artifact_id: artifact_hex,
                manifest_root: hex::encode(manifest.manifest_root().as_bytes()),
            };
            let mut rows = Vec::new();
            let mut shares = Vec::new();
            for stripe in 0..stripes as u32 {
                let share = sink.shares.remove(&(stripe, POSITION)).unwrap();
                let commitment = share_commitment(stripe, POSITION, &share).unwrap();
                let transport_sha256 = sha256_hex(&share);
                let task_id = hex::encode([stripe as u8 + 1; 32]);
                let mut task = SignedRestoreTask {
                    schema: IMPORT_INDEX_SCHEMA.to_owned(),
                    record_kind: "RESTORE_TASK".to_owned(),
                    task_id: task_id.clone(),
                    participant_id: hex::encode([0x55; 32]),
                    canonical_origin: "https://participant.example".to_owned(),
                    chain_binding: binding.clone(),
                    coordinate: ImportCoordinate {
                        stripe,
                        position: POSITION,
                        bytes: ARTIFACT_SHARE_BYTES as u64,
                        transport_sha256: transport_sha256.clone(),
                        protocol_share_digest: hex::encode(commitment.share_digest.as_bytes()),
                        probe_root: hex::encode(commitment.probe_root.as_bytes()),
                        url: format!("https://seed.example/shares/{stripe}/{POSITION}"),
                    },
                    expected_bytes: ARTIFACT_SHARE_BYTES as u64,
                    issued_at: NOW - 10,
                    expires_at: NOW + 100,
                    signature: empty_signature(
                        &coordinator_public_key,
                        RESTORE_TASK_SIGNATURE_DOMAIN,
                    ),
                };
                sign_task(&mut task, &signer);
                let digest = coordinate_digest(&binding, stripe, POSITION).unwrap();
                let quarantine_id = quarantine_id(&task_id, &digest, &transport_sha256).unwrap();
                fs::write(
                    artifact_quarantine.join(format!("{quarantine_id}.share")),
                    &share,
                )
                .unwrap();
                rows.push(ImportTaskReceiptPair {
                    source_origin: "https://seed.example".to_owned(),
                    task,
                    receipt: RestoreReceiptRecord {
                        schema: IMPORT_INDEX_SCHEMA.to_owned(),
                        record_kind: "RESTORE_RECEIPT".to_owned(),
                        task_id,
                        coordinate_digest: digest,
                        bytes: ARTIFACT_SHARE_BYTES as u64,
                        quarantine_id,
                        canonical_verified: true,
                        accepted_at: NOW - 1,
                    },
                });
                shares.push(share);
            }
            let mut index = SignedPositionImportIndex {
                schema: IMPORT_INDEX_SCHEMA.to_owned(),
                record_kind: IMPORT_INDEX_RECORD_KIND.to_owned(),
                coordinator_public_key: coordinator_public_key.clone(),
                chain_binding: binding,
                target_position: POSITION,
                generated_at: NOW - 2,
                expires_at: NOW + 100,
                rows,
                signature: empty_signature(&coordinator_public_key, IMPORT_INDEX_SIGNATURE_DOMAIN),
            };
            sign_index(&mut index, &signer);
            write_index(&index_path, &index);
            Self {
                root,
                source_config,
                quarantine_root,
                index_path,
                report_path,
                replacement_config,
                artifact,
                manifest,
                index,
                shares,
                signer,
            }
        }

        fn config_with(
            &self,
            replacement: ArtifactStoreConfig,
            report: PathBuf,
        ) -> WebRestoredPositionImportConfig {
            WebRestoredPositionImportConfig {
                source_store: self.source_config.clone(),
                quarantine_root: self.quarantine_root.clone(),
                import_index_path: self.index_path.clone(),
                target_position: POSITION,
                expected_coordinator_public_key: self.index.coordinator_public_key.clone(),
                expected_chain_binding: self.index.chain_binding.clone(),
                replacement_store: replacement,
                report_path: report,
            }
        }

        fn config(&self) -> WebRestoredPositionImportConfig {
            self.config_with(self.replacement_config.clone(), self.report_path.clone())
        }

        fn quarantine_path(&self, row: usize) -> PathBuf {
            self.quarantine_root
                .join(&self.index.chain_binding.artifact_id)
                .join(format!(
                    "{}.share",
                    self.index.rows[row].receipt.quarantine_id
                ))
        }

        fn fresh_target(&self, name: &str, quota: u64) -> (ArtifactStoreConfig, PathBuf) {
            (
                ArtifactStoreConfig::under(
                    self.root.join(name),
                    self.root.join(format!("{name}-consensus")),
                    quota,
                ),
                self.root.join(format!("{name}-evidence.json")),
            )
        }

        fn assert_unpublished(&self, config: ArtifactStoreConfig) {
            let store = ArtifactStore::open(config).unwrap();
            assert!(!store.resume_state(&self.artifact).unwrap().published);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn empty_signature(public_key: &str, domain: &str) -> ImportSignature {
        ImportSignature {
            suite: "Ed25519".to_owned(),
            domain: domain.to_owned(),
            public_key: public_key.to_owned(),
            signature: "00".repeat(64),
        }
    }

    fn sign_task(task: &mut SignedRestoreTask, signer: &Keypair) {
        let bytes = canonical_json(&unsigned_value(task).unwrap()).unwrap();
        task.signature.signature = hex::encode(
            signer
                .sign_domain(DomainId::SigWwmWebRestoreTaskV1, &[&bytes])
                .unwrap()
                .as_bytes(),
        );
    }

    fn sign_index(index: &mut SignedPositionImportIndex, signer: &Keypair) {
        let bytes = canonical_json(&unsigned_value(index).unwrap()).unwrap();
        index.signature.signature = hex::encode(
            signer
                .sign_domain(DomainId::SigWwmWebRestoreImportIndexV1, &[&bytes])
                .unwrap()
                .as_bytes(),
        );
    }

    fn write_index(path: &Path, index: &SignedPositionImportIndex) {
        fs::write(path, serde_json::to_vec_pretty(index).unwrap()).unwrap();
    }

    fn run_failure(
        fixture: &Fixture,
        index: &SignedPositionImportIndex,
        target_name: &str,
    ) -> String {
        write_index(&fixture.index_path, index);
        let (target, report) = fixture.fresh_target(target_name, 128 * 1024 * 1024);
        let error = import_web_restored_position_at(
            fixture.config_with(target.clone(), report.clone()),
            NOW,
        )
        .unwrap_err();
        assert!(!report.exists(), "failed import left an evidence report");
        fixture.assert_unpublished(target);
        error
    }

    #[test]
    fn atomic_import_publishes_and_reopens_one_small_manifest_position() {
        let fixture = Fixture::new(1);
        let evidence = import_web_restored_position_at(fixture.config(), NOW).unwrap();
        assert_eq!(evidence.stripe_count, 1);
        assert_eq!(evidence.imported_share_count, 1);
        assert_eq!(evidence.imported_bytes, ARTIFACT_SHARE_BYTES as u64);
        assert!(!evidence.production_custody);
        assert!(!evidence.availability_certificate_effect);
        assert!(!evidence.rewards);
        assert!(evidence.insert_once);
        assert!(fixture.report_path.exists());

        let store = ArtifactStore::open(fixture.replacement_config.clone()).unwrap();
        assert!(store.resume_state(&fixture.artifact).unwrap().published);
        assert_eq!(
            store.read_manifest(&fixture.artifact).unwrap(),
            fixture.manifest.canonical_bytes()
        );
        let mut share = vec![0_u8; ARTIFACT_SHARE_BYTES];
        store
            .read_share(&fixture.artifact, 0, POSITION, &mut share)
            .unwrap();
        assert_eq!(share, fixture.shares[0]);
    }

    #[test]
    fn signed_index_rejects_signature_traversal_duplicate_missing_and_wrong_coordinate() {
        let fixture = Fixture::new(2);

        let mut tampered_signature = fixture.index.clone();
        tampered_signature
            .signature
            .signature
            .replace_range(0..2, "ff");
        assert!(run_failure(&fixture, &tampered_signature, "bad-signature")
            .contains("signature verification"));

        write_index(&fixture.index_path, &fixture.index);
        let (unpinned_target, unpinned_report) =
            fixture.fresh_target("wrong-pinned-key", 128 * 1024 * 1024);
        let mut unpinned = fixture.config_with(unpinned_target.clone(), unpinned_report.clone());
        unpinned.expected_coordinator_public_key = hex::encode([0x99; 32]);
        assert!(import_web_restored_position_at(unpinned, NOW)
            .unwrap_err()
            .contains("operator-pinned key"));
        assert!(!unpinned_report.exists());
        fixture.assert_unpublished(unpinned_target);

        let mut traversal = fixture.index.clone();
        traversal.rows[0].receipt.quarantine_id = "../escape".to_owned();
        sign_index(&mut traversal, &fixture.signer);
        assert!(run_failure(&fixture, &traversal, "traversal").contains("quarantine_id"));

        let mut duplicate = fixture.index.clone();
        duplicate.rows[1] = duplicate.rows[0].clone();
        sign_index(&mut duplicate, &fixture.signer);
        assert!(run_failure(&fixture, &duplicate, "duplicate").contains("duplicate"));

        let mut missing = fixture.index.clone();
        missing.rows.pop();
        sign_index(&mut missing, &fixture.signer);
        assert!(run_failure(&fixture, &missing, "missing").contains("exactly 2 rows"));

        let mut wrong = fixture.index.clone();
        wrong.rows[1].task.coordinate.position = POSITION + 1;
        sign_task(&mut wrong.rows[1].task, &fixture.signer);
        sign_index(&mut wrong, &fixture.signer);
        assert!(run_failure(&fixture, &wrong, "wrong-coordinate").contains("wrong coordinate"));
    }

    #[test]
    fn quarantine_bytes_reject_transport_and_noos_commitment_tampering() {
        let fixture = Fixture::new(1);
        let path = fixture.quarantine_path(0);
        let original = fixture.shares[0].clone();
        let mut corrupt = original.clone();
        corrupt[123] ^= 0x80;
        fs::write(&path, &corrupt).unwrap();
        assert!(run_failure(&fixture, &fixture.index, "bad-transport")
            .contains("transport_sha256 mismatch"));
        fs::write(&path, &original).unwrap();

        let mut noos_tampered = fixture.index.clone();
        let transport = sha256_hex(&corrupt);
        noos_tampered.rows[0].task.coordinate.transport_sha256 = transport.clone();
        sign_task(&mut noos_tampered.rows[0].task, &fixture.signer);
        let digest = noos_tampered.rows[0].receipt.coordinate_digest.clone();
        let quarantine =
            quarantine_id(&noos_tampered.rows[0].task.task_id, &digest, &transport).unwrap();
        noos_tampered.rows[0].receipt.quarantine_id = quarantine.clone();
        sign_index(&mut noos_tampered, &fixture.signer);
        fs::write(
            fixture
                .quarantine_root
                .join(&fixture.index.chain_binding.artifact_id)
                .join(format!("{quarantine}.share")),
            &corrupt,
        )
        .unwrap();
        assert!(run_failure(&fixture, &noos_tampered, "bad-noos")
            .contains("noos-da commitment/probe root mismatch"));
    }

    #[test]
    fn symlinked_quarantine_share_is_never_followed() {
        let fixture = Fixture::new(1);
        let path = fixture.quarantine_path(0);
        let outside = fixture.root.join("outside.share");
        fs::write(&outside, &fixture.shares[0]).unwrap();
        fs::remove_file(&path).unwrap();
        if create_file_symlink(&outside, &path).is_err() {
            // Windows can deny symlink creation unless Developer Mode or the
            // privilege is enabled; the production rejection is platform
            // independent and is exercised where the OS permits the fixture.
            fs::write(&path, &fixture.shares[0]).unwrap();
            return;
        }
        assert!(run_failure(&fixture, &fixture.index, "symlink").contains("non-symlink"));
    }

    #[test]
    fn interrupted_staging_and_existing_output_never_publish() {
        let fixture = Fixture::new(2);
        let (small_target, small_report) =
            fixture.fresh_target("interrupted", ARTIFACT_SHARE_BYTES as u64 + 128);
        let error = import_web_restored_position_at(
            fixture.config_with(small_target.clone(), small_report.clone()),
            NOW,
        )
        .unwrap_err();
        assert!(error.contains("quota"));
        assert!(!small_report.exists());
        fixture.assert_unpublished(small_target);

        let (overwrite_target, overwrite_report) =
            fixture.fresh_target("overwrite", 128 * 1024 * 1024);
        fs::write(&overwrite_report, b"existing evidence").unwrap();
        let error = import_web_restored_position_at(
            fixture.config_with(overwrite_target.clone(), overwrite_report.clone()),
            NOW,
        )
        .unwrap_err();
        assert!(error.contains("create-new evidence report"));
        assert_eq!(fs::read(&overwrite_report).unwrap(), b"existing evidence");
        fixture.assert_unpublished(overwrite_target);
    }

    #[cfg(unix)]
    fn create_file_symlink(source: &Path, target: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(source, target)
    }

    #[cfg(windows)]
    fn create_file_symlink(source: &Path, target: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(source, target)
    }
}
