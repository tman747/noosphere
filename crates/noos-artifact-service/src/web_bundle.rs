use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use noos_da::{share_commitment, ArtifactManifestV1, ARTIFACT_POSITIONS, ARTIFACT_SHARE_BYTES};
use noos_store::ArtifactStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::{
    decode_hex32, BONSAI_ARTIFACT_ID_HEX, BONSAI_MANIFEST_ROOT_HEX, BONSAI_PAYLOAD_ROOT_HEX,
    BONSAI_SHA256_HEX,
};

const WEB_CAPACITY_SCHEMA: &str = "noos/wwm-web-capacity/v1";
const HOST_MANIFEST_PATH: &str = "/.well-known/noos/wwm-web-capacity-v1.json";
const INVENTORY_PATH: &str = "/inventory-v1.json";
const LICENSE_PATH: &str = "/LICENSE.txt";
const NOTICE_PATH: &str = "/NOTICE.txt";
const HOST_SIGNATURE_DOMAIN: &str = "NOOS/SIG/WWM-WEB-HOST-MANIFEST/V1";
const MAX_VALIDITY_SECONDS: u64 = 31 * 86_400;
const MAX_INVENTORY_ROWS: usize = 5_448;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_INVENTORY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LICENSE_BYTES: u64 = 2 * 1024 * 1024;
const BONSAI_LICENSE_BYTES: usize = 10_174;
const BONSAI_LICENSE_SHA256: &str =
    "69849221bfb90053de2134ef5e6d540287b4b98062326492f1f96f5da685524b";
const BONSAI_NOTICE_BYTES: usize = 411;
const BONSAI_NOTICE_SHA256: &str =
    "cef33f95425f9802de78b7b22db0faca84d2216661432a9afcf9620949c21f7e";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareCoordinate {
    pub stripe: u32,
    pub position: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinateSelectionFile {
    coordinates: Vec<ShareCoordinate>,
}

pub struct WebBundleExportConfig {
    pub output_root: PathBuf,
    pub canonical_origin: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub license_path: PathBuf,
    pub notice_path: PathBuf,
    pub coordinates: Vec<ShareCoordinate>,
    pub signing_seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainBinding {
    chain_id: String,
    genesis_hash: String,
    artifact_id: String,
    manifest_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRow {
    stripe: u32,
    position: u8,
    bytes: u64,
    transport_sha256: String,
    protocol_share_digest: String,
    probe_root: String,
    url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticInventory {
    schema: String,
    record_kind: String,
    canonical_origin: String,
    chain_binding: ChainBinding,
    generated_at: u64,
    expires_at: u64,
    rows: Vec<InventoryRow>,
    inventory_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryBinding {
    url: String,
    bytes: u64,
    sha256: String,
    inventory_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LicenseBinding {
    spdx: String,
    license_url: String,
    license_sha256: String,
    notice_url: String,
    notice_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportPolicy {
    cors_allow_origin: String,
    credentials: String,
    redirects: String,
    range_requests: bool,
    immutable_cache: bool,
    content_encoding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ed25519Signature {
    suite: String,
    domain: String,
    public_key: String,
    signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticHostManifest {
    schema: String,
    record_kind: String,
    participant_class: String,
    admission_class: String,
    canonical_origin: String,
    chain_binding: ChainBinding,
    host_signing_key: String,
    valid_from: u64,
    expires_at: u64,
    revocation_url: String,
    inventory: InventoryBinding,
    license: LicenseBinding,
    transport_policy: TransportPolicy,
    production_custody: bool,
    rewards: bool,
    signature: Ed25519Signature,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebBundleExportReport {
    pub schema: &'static str,
    pub output_root: String,
    pub canonical_origin: String,
    pub artifact_id: String,
    pub manifest_root: String,
    pub inventory_root: String,
    pub host_signing_key: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub selected_share_count: usize,
    pub selected_share_bytes: u64,
    pub bundle_bytes: u64,
    pub noos_da_verified_share_count: usize,
    pub canonical_json: bool,
    pub immutable_files: bool,
    pub production_custody: bool,
    pub rewards: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebBundleVerificationReport {
    pub schema: &'static str,
    pub bundle_root: String,
    pub canonical_origin: String,
    pub artifact_id: String,
    pub manifest_root: String,
    pub inventory_root: String,
    pub host_signing_key: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub verified_share_count: usize,
    pub verified_share_bytes: u64,
    pub bundle_bytes: u64,
    pub canonical_json: bool,
    pub immutable_files: bool,
    pub signature_verified: bool,
    pub noos_da_verified: bool,
    pub production_custody: bool,
    pub rewards: bool,
}

pub fn read_coordinate_selection(path: &Path) -> Result<Vec<ShareCoordinate>, String> {
    let bytes = read_regular_file(path, MAX_INVENTORY_BYTES, "coordinate selection")?;
    let selection: CoordinateSelectionFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode coordinate selection: {error}"))?;
    Ok(selection.coordinates)
}

pub fn signing_seed_from_env(name: &str) -> Result<[u8; 32], String> {
    if name.is_empty() || name.len() > 128 {
        return Err("host signing seed environment name must contain 1..=128 bytes".to_owned());
    }
    let value = env::var(name)
        .map_err(|_| format!("host signing seed environment variable {name} is unavailable"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "host signing seed environment variable {name} must be canonical lowercase hex32"
        ));
    }
    let mut seed = [0_u8; 32];
    hex::decode_to_slice(value.as_bytes(), &mut seed)
        .map_err(|error| format!("decode host signing seed from {name}: {error}"))?;
    Ok(seed)
}

pub fn export_bonsai_web_bundle(
    store: &ArtifactStore,
    config: WebBundleExportConfig,
) -> Result<WebBundleExportReport, String> {
    let manifest = load_bonsai_manifest(store)?;
    let artifact = decode_hex32(BONSAI_ARTIFACT_ID_HEX)?;
    let binding = exact_chain_binding(&config.chain_id, &config.genesis_hash)?;
    export_bundle_core(&manifest, binding, config, |stripe, position, output| {
        store
            .read_share(&artifact, stripe, position, output)
            .map_err(|error| error.to_string())
    })
}

pub fn verify_bonsai_web_bundle(
    store: &ArtifactStore,
    bundle_root: &Path,
    canonical_origin: &str,
    chain_id: &str,
    genesis_hash: &str,
) -> Result<WebBundleVerificationReport, String> {
    let manifest = load_bonsai_manifest(store)?;
    let binding = exact_chain_binding(chain_id, genesis_hash)?;
    verify_bundle_core(
        &manifest,
        bundle_root,
        canonical_origin,
        &binding,
        now_seconds()?,
    )
}

fn export_bundle_core<F>(
    manifest: &ArtifactManifestV1,
    binding: ChainBinding,
    config: WebBundleExportConfig,
    read_share: F,
) -> Result<WebBundleExportReport, String>
where
    F: FnMut(u32, u8, &mut [u8]) -> Result<(), String>,
{
    export_bundle_core_with_clock(manifest, binding, config, read_share, now_seconds)
}

fn export_bundle_core_with_clock<F, C>(
    manifest: &ArtifactManifestV1,
    binding: ChainBinding,
    mut config: WebBundleExportConfig,
    mut read_share: F,
    mut clock: C,
) -> Result<WebBundleExportReport, String>
where
    F: FnMut(u32, u8, &mut [u8]) -> Result<(), String>,
    C: FnMut() -> Result<u64, String>,
{
    let now = clock()?;
    canonical_https_origin(&config.canonical_origin)?;
    validate_hash32("chain_id", &binding.chain_id)?;
    validate_hash32("genesis_hash", &binding.genesis_hash)?;
    validate_hash32("artifact_id", &binding.artifact_id)?;
    validate_hash32("manifest_root", &binding.manifest_root)?;
    validate_interval(config.valid_from, config.expires_at, now)?;
    let coordinates = normalize_coordinates(config.coordinates, manifest.stripes.len())?;
    if config.output_root.exists() {
        return Err(format!(
            "bundle output root already exists: {}",
            config.output_root.display()
        ));
    }

    let license = read_regular_file(&config.license_path, MAX_LICENSE_BYTES, "license")?;
    let notice = read_regular_file(&config.notice_path, MAX_LICENSE_BYTES, "NOTICE")?;
    validate_bonsai_release_notices(&license, &notice)?;

    let staging = staging_path(&config.output_root)?;
    fs::create_dir_all(&staging)
        .map_err(|error| format!("create bundle staging root {}: {error}", staging.display()))?;
    let mut guard = StagingGuard::new(staging.clone());

    write_new_file(&staging.join("LICENSE.txt"), &license)?;
    write_new_file(&staging.join("NOTICE.txt"), &notice)?;

    let mut rows = Vec::with_capacity(coordinates.len());
    let mut share = vec![0_u8; ARTIFACT_SHARE_BYTES];
    for coordinate in &coordinates {
        read_share(coordinate.stripe, coordinate.position, &mut share)?;
        let expected =
            manifest.stripes[coordinate.stripe as usize].shares[coordinate.position as usize];
        let actual = share_commitment(coordinate.stripe, coordinate.position, &share)
            .map_err(|error| error.to_string())?;
        if actual != expected {
            return Err(format!(
                "canonical noos-da share verification failed at stripe {} position {}",
                coordinate.stripe, coordinate.position
            ));
        }
        let relative = share_relative_path(*coordinate);
        write_new_file(&staging.join(&relative), &share)?;
        rows.push(InventoryRow {
            stripe: coordinate.stripe,
            position: coordinate.position,
            bytes: ARTIFACT_SHARE_BYTES as u64,
            transport_sha256: sha256_hex(&share),
            protocol_share_digest: hex::encode(actual.share_digest.as_bytes()),
            probe_root: hex::encode(actual.probe_root.as_bytes()),
            url: format!("{}{}", config.canonical_origin, share_url_path(*coordinate)),
        });
    }
    share.fill(0);

    let rows_value = serde_json::to_value(&rows)
        .map_err(|error| format!("encode static inventory rows: {error}"))?;
    let canonical_rows = canonical_json(&rows_value)?;
    let inventory_root = hex::encode(
        hash_domain(DomainId::WwmWebInventoryV1, &[&canonical_rows])
            .map_err(|error| format!("hash static inventory: {error}"))?
            .into_bytes(),
    );
    let inventory = StaticInventory {
        schema: WEB_CAPACITY_SCHEMA.to_owned(),
        record_kind: "STATIC_INVENTORY".to_owned(),
        canonical_origin: config.canonical_origin.clone(),
        chain_binding: binding.clone(),
        generated_at: config.valid_from,
        expires_at: config.expires_at,
        rows,
        inventory_root: inventory_root.clone(),
    };
    let inventory_bytes = canonical_serialize(&inventory)?;
    if inventory_bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err("canonical static inventory exceeds 8 MiB".to_owned());
    }
    write_new_file(&staging.join("inventory-v1.json"), &inventory_bytes)?;

    let signer = Keypair::from_seed(config.signing_seed);
    config.signing_seed.fill(0);
    let public_key = hex::encode(signer.public_key().as_bytes());
    let mut host_manifest = StaticHostManifest {
        schema: WEB_CAPACITY_SCHEMA.to_owned(),
        record_kind: "STATIC_HOST_MANIFEST".to_owned(),
        participant_class: "STATIC_HOST_SEEDER".to_owned(),
        admission_class: "StatelessReissueable".to_owned(),
        canonical_origin: config.canonical_origin.clone(),
        chain_binding: binding.clone(),
        host_signing_key: public_key.clone(),
        valid_from: config.valid_from,
        expires_at: config.expires_at,
        revocation_url: format!("{}{}", config.canonical_origin, HOST_MANIFEST_PATH),
        inventory: InventoryBinding {
            url: format!("{}{}", config.canonical_origin, INVENTORY_PATH),
            bytes: inventory_bytes.len() as u64,
            sha256: sha256_hex(&inventory_bytes),
            inventory_root: inventory_root.clone(),
        },
        license: LicenseBinding {
            spdx: "Apache-2.0".to_owned(),
            license_url: format!("{}{}", config.canonical_origin, LICENSE_PATH),
            license_sha256: BONSAI_LICENSE_SHA256.to_owned(),
            notice_url: format!("{}{}", config.canonical_origin, NOTICE_PATH),
            notice_sha256: BONSAI_NOTICE_SHA256.to_owned(),
        },
        transport_policy: TransportPolicy {
            cors_allow_origin: "*".to_owned(),
            credentials: "omit".to_owned(),
            redirects: "reject".to_owned(),
            range_requests: true,
            immutable_cache: true,
            content_encoding: "identity".to_owned(),
        },
        production_custody: false,
        rewards: false,
        signature: Ed25519Signature {
            suite: "Ed25519".to_owned(),
            domain: HOST_SIGNATURE_DOMAIN.to_owned(),
            public_key: public_key.clone(),
            signature: String::new(),
        },
    };
    let mut unsigned = serde_json::to_value(&host_manifest)
        .map_err(|error| format!("encode unsigned static host manifest: {error}"))?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| "static host manifest must encode as an object".to_owned())?
        .remove("signature")
        .ok_or_else(|| "static host manifest signature field is absent".to_owned())?;
    let unsigned_bytes = canonical_json(&unsigned)?;
    host_manifest.signature.signature = hex::encode(
        signer
            .sign_domain(DomainId::SigWwmWebHostManifestV1, &[&unsigned_bytes])
            .map_err(|error| format!("sign static host manifest: {error}"))?
            .into_bytes(),
    );
    let host_manifest_bytes = canonical_serialize(&host_manifest)?;
    if host_manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("canonical static host manifest exceeds 64 KiB".to_owned());
    }
    let manifest_path = staging.join(".well-known/noos/wwm-web-capacity-v1.json");
    write_new_file(&manifest_path, &host_manifest_bytes)?;

    let verification =
        verify_bundle_core(manifest, &staging, &config.canonical_origin, &binding, now)?;
    make_files_read_only(&staging)?;
    if !all_known_files_read_only(&staging, &inventory.rows)? {
        return Err("exported bundle files are not read-only".to_owned());
    }
    if config.expires_at <= clock()? {
        return Err("bundle expired before publication".to_owned());
    }
    fs::rename(&staging, &config.output_root).map_err(|error| {
        format!(
            "publish bundle staging root {} as {}: {error}",
            staging.display(),
            config.output_root.display()
        )
    })?;
    guard.commit();

    Ok(WebBundleExportReport {
        schema: "noos.wwm.web-static-bundle-export.v1",
        output_root: config.output_root.display().to_string(),
        canonical_origin: config.canonical_origin,
        artifact_id: binding.artifact_id,
        manifest_root: binding.manifest_root,
        inventory_root,
        host_signing_key: public_key,
        valid_from: config.valid_from,
        expires_at: config.expires_at,
        selected_share_count: coordinates.len(),
        selected_share_bytes: verification.verified_share_bytes,
        bundle_bytes: verification.bundle_bytes,
        noos_da_verified_share_count: verification.verified_share_count,
        canonical_json: true,
        immutable_files: true,
        production_custody: false,
        rewards: false,
    })
}

fn verify_bundle_core(
    manifest: &ArtifactManifestV1,
    bundle_root: &Path,
    expected_origin: &str,
    expected_binding: &ChainBinding,
    now: u64,
) -> Result<WebBundleVerificationReport, String> {
    canonical_https_origin(expected_origin)?;
    let host_path = bundle_root.join(".well-known/noos/wwm-web-capacity-v1.json");
    let host_bytes = read_regular_file(&host_path, MAX_MANIFEST_BYTES, "host manifest")?;
    let mut host_value: Value = serde_json::from_slice(&host_bytes)
        .map_err(|error| format!("decode static host manifest: {error}"))?;
    if canonical_json(&host_value)? != host_bytes {
        return Err("static host manifest is not canonical JSON".to_owned());
    }
    let host: StaticHostManifest = serde_json::from_value(host_value.clone())
        .map_err(|error| format!("validate static host manifest: {error}"))?;
    validate_host_manifest(&host, expected_origin, expected_binding, now)?;
    host_value
        .as_object_mut()
        .ok_or_else(|| "static host manifest must be an object".to_owned())?
        .remove("signature")
        .ok_or_else(|| "static host manifest lacks signature".to_owned())?;
    let unsigned = canonical_json(&host_value)?;
    let public_key = PublicKey::from_bytes(parse_hex32(
        "host manifest public key",
        &host.signature.public_key,
    )?);
    let signature = Signature::from_bytes(parse_hex64(
        "host manifest signature",
        &host.signature.signature,
    )?);
    verify_domain(
        DomainId::SigWwmWebHostManifestV1,
        &public_key,
        &[&unsigned],
        &signature,
    )
    .map_err(|_| "static host manifest signature verification failed".to_owned())?;

    let inventory_path = bundle_root.join("inventory-v1.json");
    let inventory_bytes = read_regular_file(&inventory_path, MAX_INVENTORY_BYTES, "inventory")?;
    if inventory_bytes.len() as u64 != host.inventory.bytes
        || sha256_hex(&inventory_bytes) != host.inventory.sha256
    {
        return Err("inventory length or SHA-256 differs from signed manifest".to_owned());
    }
    let inventory_value: Value = serde_json::from_slice(&inventory_bytes)
        .map_err(|error| format!("decode static inventory: {error}"))?;
    if canonical_json(&inventory_value)? != inventory_bytes {
        return Err("static inventory is not canonical JSON".to_owned());
    }
    let inventory: StaticInventory = serde_json::from_value(inventory_value.clone())
        .map_err(|error| format!("validate static inventory: {error}"))?;
    validate_inventory_header(&inventory, &host, expected_binding, now)?;
    let rows_value = inventory_value
        .get("rows")
        .ok_or_else(|| "static inventory lacks rows".to_owned())?;
    let canonical_rows = canonical_json(rows_value)?;
    let computed_inventory_root = hex::encode(
        hash_domain(DomainId::WwmWebInventoryV1, &[&canonical_rows])
            .map_err(|error| format!("hash static inventory: {error}"))?
            .into_bytes(),
    );
    if computed_inventory_root != inventory.inventory_root
        || computed_inventory_root != host.inventory.inventory_root
    {
        return Err("static inventory root does not bind its canonical rows".to_owned());
    }

    let mut prior = None;
    let mut coordinates = BTreeSet::new();
    let mut verified_share_bytes = 0_u64;
    for row in &inventory.rows {
        let coordinate = ShareCoordinate {
            stripe: row.stripe,
            position: row.position,
        };
        if prior.is_some_and(|value| value >= coordinate) || !coordinates.insert(coordinate) {
            return Err("inventory coordinates must be unique and strictly ordered".to_owned());
        }
        prior = Some(coordinate);
        if coordinate.stripe as usize >= manifest.stripes.len()
            || coordinate.position as usize >= ARTIFACT_POSITIONS
            || row.bytes != ARTIFACT_SHARE_BYTES as u64
            || row.url != format!("{}{}", expected_origin, share_url_path(coordinate))
        {
            return Err(format!(
                "invalid inventory coordinate, byte length, or URL at stripe {} position {}",
                row.stripe, row.position
            ));
        }
        validate_hash32("transport_sha256", &row.transport_sha256)?;
        validate_hash32("protocol_share_digest", &row.protocol_share_digest)?;
        validate_hash32("probe_root", &row.probe_root)?;
        let share_path = bundle_root.join(share_relative_path(coordinate));
        let share = read_regular_file(&share_path, ARTIFACT_SHARE_BYTES as u64, "immutable share")?;
        if share.len() != ARTIFACT_SHARE_BYTES || sha256_hex(&share) != row.transport_sha256 {
            return Err(format!(
                "share length or transport SHA-256 mismatch at stripe {} position {}",
                row.stripe, row.position
            ));
        }
        let actual = share_commitment(row.stripe, row.position, &share)
            .map_err(|error| error.to_string())?;
        let expected = manifest.stripes[row.stripe as usize].shares[row.position as usize];
        if actual != expected
            || row.protocol_share_digest != hex::encode(actual.share_digest.as_bytes())
            || row.probe_root != hex::encode(actual.probe_root.as_bytes())
        {
            return Err(format!(
                "canonical noos-da commitment mismatch at stripe {} position {}",
                row.stripe, row.position
            ));
        }
        verified_share_bytes = verified_share_bytes
            .checked_add(share.len() as u64)
            .ok_or_else(|| "verified share byte count overflow".to_owned())?;
    }

    let license = read_regular_file(
        &bundle_root.join("LICENSE.txt"),
        MAX_LICENSE_BYTES,
        "license",
    )?;
    let notice = read_regular_file(&bundle_root.join("NOTICE.txt"), MAX_LICENSE_BYTES, "NOTICE")?;
    if sha256_hex(&license) != host.license.license_sha256
        || sha256_hex(&notice) != host.license.notice_sha256
    {
        return Err("license or NOTICE differs from the signed hash".to_owned());
    }
    validate_bonsai_release_notices(&license, &notice)?;
    let bundle_bytes = verified_share_bytes
        .checked_add(host_bytes.len() as u64)
        .and_then(|value| value.checked_add(inventory_bytes.len() as u64))
        .and_then(|value| value.checked_add(license.len() as u64))
        .and_then(|value| value.checked_add(notice.len() as u64))
        .ok_or_else(|| "bundle byte count overflow".to_owned())?;

    Ok(WebBundleVerificationReport {
        schema: "noos.wwm.web-static-bundle-verification.v1",
        bundle_root: bundle_root.display().to_string(),
        canonical_origin: expected_origin.to_owned(),
        artifact_id: expected_binding.artifact_id.clone(),
        manifest_root: expected_binding.manifest_root.clone(),
        inventory_root: computed_inventory_root,
        host_signing_key: host.host_signing_key,
        valid_from: host.valid_from,
        expires_at: host.expires_at,
        verified_share_count: inventory.rows.len(),
        verified_share_bytes,
        bundle_bytes,
        canonical_json: true,
        immutable_files: all_known_files_read_only(bundle_root, &inventory.rows)?,
        signature_verified: true,
        noos_da_verified: true,
        production_custody: false,
        rewards: false,
    })
}

fn validate_host_manifest(
    host: &StaticHostManifest,
    expected_origin: &str,
    expected_binding: &ChainBinding,
    now: u64,
) -> Result<(), String> {
    if host.schema != WEB_CAPACITY_SCHEMA
        || host.record_kind != "STATIC_HOST_MANIFEST"
        || host.participant_class != "STATIC_HOST_SEEDER"
        || host.admission_class != "StatelessReissueable"
        || host.canonical_origin != expected_origin
        || host.chain_binding != *expected_binding
        || host.production_custody
        || host.rewards
    {
        return Err(
            "static host manifest identity, class, binding, or authority flags are invalid"
                .to_owned(),
        );
    }
    canonical_https_origin(&host.canonical_origin)?;
    validate_interval(host.valid_from, host.expires_at, now)?;
    if host.host_signing_key != host.signature.public_key
        || host.signature.suite != "Ed25519"
        || host.signature.domain != HOST_SIGNATURE_DOMAIN
        || host.revocation_url != format!("{}{}", expected_origin, HOST_MANIFEST_PATH)
        || host.inventory.url != format!("{}{}", expected_origin, INVENTORY_PATH)
        || host.license.spdx != "Apache-2.0"
        || host.license.license_url != format!("{}{}", expected_origin, LICENSE_PATH)
        || host.license.notice_url != format!("{}{}", expected_origin, NOTICE_PATH)
        || host.transport_policy.cors_allow_origin != "*"
        || host.transport_policy.credentials != "omit"
        || host.transport_policy.redirects != "reject"
        || !host.transport_policy.range_requests
        || !host.transport_policy.immutable_cache
        || host.transport_policy.content_encoding != "identity"
    {
        return Err(
            "static host signature, URLs, license, or transport policy is invalid".to_owned(),
        );
    }
    validate_hash32("host_signing_key", &host.host_signing_key)?;
    validate_hash32("inventory SHA-256", &host.inventory.sha256)?;
    validate_hash32("inventory root", &host.inventory.inventory_root)?;
    validate_hash32("license SHA-256", &host.license.license_sha256)?;
    validate_hash32("NOTICE SHA-256", &host.license.notice_sha256)?;
    Ok(())
}

fn validate_inventory_header(
    inventory: &StaticInventory,
    host: &StaticHostManifest,
    expected_binding: &ChainBinding,
    now: u64,
) -> Result<(), String> {
    if inventory.schema != WEB_CAPACITY_SCHEMA
        || inventory.record_kind != "STATIC_INVENTORY"
        || inventory.canonical_origin != host.canonical_origin
        || inventory.chain_binding != *expected_binding
        || inventory.generated_at != host.valid_from
        || inventory.generated_at > now
        || inventory.generated_at >= inventory.expires_at
        || inventory.expires_at != host.expires_at
        || inventory.rows.is_empty()
        || inventory.rows.len() > MAX_INVENTORY_ROWS
        || inventory.inventory_root != host.inventory.inventory_root
    {
        return Err(
            "static inventory identity, interval, binding, or row bound is invalid".to_owned(),
        );
    }
    Ok(())
}

fn load_bonsai_manifest(store: &ArtifactStore) -> Result<ArtifactManifestV1, String> {
    let artifact = decode_hex32(BONSAI_ARTIFACT_ID_HEX)?;
    let bytes = store
        .read_manifest(&artifact)
        .map_err(|error| error.to_string())?;
    let manifest =
        ArtifactManifestV1::from_canonical_bytes(&bytes).map_err(|error| error.to_string())?;
    manifest
        .validate_bonsai_geometry()
        .map_err(|error| error.to_string())?;
    if manifest.published_sha256 != decode_hex32(BONSAI_SHA256_HEX)?
        || manifest.protocol_payload_root.as_bytes() != &decode_hex32(BONSAI_PAYLOAD_ROOT_HEX)?
        || hex::encode(manifest.manifest_root().as_bytes()) != BONSAI_MANIFEST_ROOT_HEX
    {
        return Err("published Bonsai manifest identity mismatch".to_owned());
    }
    Ok(manifest)
}

fn exact_chain_binding(chain_id: &str, genesis_hash: &str) -> Result<ChainBinding, String> {
    validate_hash32("chain_id", chain_id)?;
    validate_hash32("genesis_hash", genesis_hash)?;
    Ok(ChainBinding {
        chain_id: chain_id.to_owned(),
        genesis_hash: genesis_hash.to_owned(),
        artifact_id: BONSAI_ARTIFACT_ID_HEX.to_owned(),
        manifest_root: BONSAI_MANIFEST_ROOT_HEX.to_owned(),
    })
}

fn normalize_coordinates(
    mut coordinates: Vec<ShareCoordinate>,
    stripe_count: usize,
) -> Result<Vec<ShareCoordinate>, String> {
    if coordinates.is_empty() || coordinates.len() > MAX_INVENTORY_ROWS {
        return Err("coordinate selection must contain 1..=5,448 rows".to_owned());
    }
    coordinates.sort_unstable();
    if coordinates.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("coordinate selection contains duplicates".to_owned());
    }
    for coordinate in &coordinates {
        if coordinate.stripe as usize >= stripe_count
            || coordinate.position as usize >= ARTIFACT_POSITIONS
        {
            return Err(format!(
                "coordinate is outside the canonical manifest: stripe {} position {}",
                coordinate.stripe, coordinate.position
            ));
        }
    }
    Ok(coordinates)
}

fn canonical_https_origin(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value).map_err(|_| "origin is not a URL".to_owned())?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(
            "origin must be credential-free HTTPS with no path, query, or fragment".to_owned(),
        );
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "origin lacks a host".to_owned())?;
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let canonical = match parsed.port() {
        Some(port) => format!("https://{authority}:{port}"),
        None => format!("https://{authority}"),
    };
    if value != canonical || value.len() > 253 {
        return Err("origin is not in canonical lowercase form or names a default port".to_owned());
    }
    Ok(())
}

fn validate_interval(valid_from: u64, expires_at: u64, now: u64) -> Result<(), String> {
    if valid_from > now
        || expires_at <= now
        || valid_from >= expires_at
        || expires_at.saturating_sub(valid_from) > MAX_VALIDITY_SECONDS
    {
        return Err(
            "manifest validity interval is absent, expired, future, or over 31 days".to_owned(),
        );
    }
    Ok(())
}

fn validate_bonsai_release_notices(license: &[u8], notice: &[u8]) -> Result<(), String> {
    if license.len() != BONSAI_LICENSE_BYTES || sha256_hex(license) != BONSAI_LICENSE_SHA256 {
        return Err(
            "license differs from the canonical Bonsai release byte length or SHA-256".to_owned(),
        );
    }
    if notice.len() != BONSAI_NOTICE_BYTES || sha256_hex(notice) != BONSAI_NOTICE_SHA256 {
        return Err(
            "NOTICE differs from the canonical Bonsai release byte length or SHA-256".to_owned(),
        );
    }
    Ok(())
}

fn validate_hash32(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be canonical lowercase hex32"));
    }
    Ok(())
}

fn parse_hex32(label: &str, value: &str) -> Result<[u8; 32], String> {
    validate_hash32(label, value)?;
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value.as_bytes(), &mut bytes)
        .map_err(|error| format!("decode {label}: {error}"))?;
    Ok(bytes)
}

fn parse_hex64(label: &str, value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be canonical lowercase hex64"));
    }
    let mut bytes = [0_u8; 64];
    hex::decode_to_slice(value.as_bytes(), &mut bytes)
        .map_err(|error| format!("decode {label}: {error}"))?;
    Ok(bytes)
}

fn canonical_serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("encode canonical JSON value: {error}"))?;
    canonical_json(&value)
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

fn share_relative_path(coordinate: ShareCoordinate) -> PathBuf {
    PathBuf::from("shares")
        .join(format!("{:06}", coordinate.stripe))
        .join(format!("{:02}.share", coordinate.position))
}

fn share_url_path(coordinate: ShareCoordinate) -> String {
    format!(
        "/shares/{:06}/{:02}.share",
        coordinate.stripe, coordinate.position
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))
}

fn read_regular_file(path: &Path, maximum_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    if metadata.len() > maximum_bytes {
        return Err(format!("{label} exceeds its {} byte limit", maximum_bytes));
    }
    fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create bundle directory {}: {error}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create immutable bundle file {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write immutable bundle file {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync immutable bundle file {}: {error}", path.display()))?;
    Ok(())
}

fn staging_path(output_root: &Path) -> Result<PathBuf, String> {
    let parent = output_root
        .parent()
        .ok_or_else(|| "bundle output root must have a parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create bundle output parent {}: {error}", parent.display()))?;
    let name = output_root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "bundle output root must end in a UTF-8 directory name".to_owned())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    let path = parent.join(format!(".{name}.tmp-{}-{nonce}", std::process::id()));
    if path.exists() {
        return Err(format!(
            "bundle staging root already exists: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn make_files_read_only(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root)
        .map_err(|error| format!("list bundle directory {}: {error}", root.display()))?
    {
        let path = entry
            .map_err(|error| format!("read bundle directory entry: {error}"))?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect bundle path {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("bundle contains a symlink: {}", path.display()));
        }
        if metadata.is_dir() {
            make_files_read_only(&path)?;
        } else if metadata.is_file() {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).map_err(|error| {
                format!("mark bundle file read-only {}: {error}", path.display())
            })?;
        } else {
            return Err(format!(
                "bundle contains a non-regular path: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn all_known_files_read_only(root: &Path, rows: &[InventoryRow]) -> Result<bool, String> {
    let mut paths = vec![
        root.join(".well-known/noos/wwm-web-capacity-v1.json"),
        root.join("inventory-v1.json"),
        root.join("LICENSE.txt"),
        root.join("NOTICE.txt"),
    ];
    paths.extend(rows.iter().map(|row| {
        root.join(share_relative_path(ShareCoordinate {
            stripe: row.stripe,
            position: row.position,
        }))
    }));
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect bundle file {}: {error}", path.display()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || !metadata.permissions().readonly()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn make_tree_writable(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            make_tree_writable(&path);
        } else if metadata.is_file() {
            let _ = make_file_writable(&path, &metadata);
        }
    }
}
#[cfg(unix)]
fn make_file_writable(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o200);
    fs::set_permissions(path, permissions)
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn make_file_writable(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    let mut permissions = metadata.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
}

#[cfg(not(any(unix, windows)))]
#[allow(clippy::permissions_set_readonly_false)]
fn make_file_writable(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    let mut permissions = metadata.permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
}

struct StagingGuard {
    path: PathBuf,
    committed: bool,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.committed && self.path.exists() {
            make_tree_writable(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use noos_da::{ArtifactEncoderV1, ArtifactError, ArtifactShareSink};
    use std::collections::{BTreeMap, VecDeque};
    use std::io::Cursor;

    const CANONICAL_LICENSE: &[u8] =
        include_bytes!("../../../deploy/wwm/licenses/Bonsai-27B/LICENSE.txt");
    const CANONICAL_NOTICE: &[u8] =
        include_bytes!("../../../deploy/wwm/licenses/Bonsai-27B/NOTICE.txt");

    #[derive(Default)]
    struct CaptureSink {
        shares: BTreeMap<(u32, u8), Vec<u8>>,
        manifest: Option<ArtifactManifestV1>,
    }

    impl ArtifactShareSink for CaptureSink {
        fn begin_artifact(
            &mut self,
            _source_length: u64,
            _protocol_payload_root: &noos_crypto::Hash32,
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
            if stripe == 0 && position == 0 {
                self.shares.insert((stripe, position), bytes.to_vec());
            }
            Ok(())
        }

        fn checkpoint_stripe(&mut self, _stripe: u32) -> Result<(), ArtifactError> {
            Ok(())
        }

        fn publish_manifest(&mut self, manifest: &ArtifactManifestV1) -> Result<(), ArtifactError> {
            self.manifest = Some(manifest.clone());
            Ok(())
        }
    }

    #[test]
    fn canonical_json_orders_utf16_keys_and_rejects_floats() {
        let value = serde_json::json!({"z": [true, null], "a": 7, "aa": "value"});
        assert_eq!(
            canonical_json(&value).unwrap(),
            br#"{"a":7,"aa":"value","z":[true,null]}"#
        );
        assert!(canonical_json(&serde_json::json!({"float": 1.5})).is_err());
    }

    #[test]
    fn coordinate_selection_sorts_and_rejects_duplicates_or_bounds() {
        let sorted = normalize_coordinates(
            vec![
                ShareCoordinate {
                    stripe: 1,
                    position: 2,
                },
                ShareCoordinate {
                    stripe: 0,
                    position: 9,
                },
            ],
            2,
        )
        .unwrap();
        assert_eq!(sorted[0].stripe, 0);
        assert!(normalize_coordinates(vec![sorted[0], sorted[0]], 2).is_err());
        assert!(normalize_coordinates(
            vec![ShareCoordinate {
                stripe: 2,
                position: 0,
            }],
            2,
        )
        .is_err());
        assert!(normalize_coordinates(
            vec![ShareCoordinate {
                stripe: 0,
                position: 12,
            }],
            2,
        )
        .is_err());
    }

    #[test]
    fn bundle_round_trip_verifies_signature_hashes_and_noos_da_commitment() {
        let mut sink = CaptureSink::default();
        let mut source = Cursor::new(b"canonical static bundle fixture".to_vec());
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut source, &mut sink, 1)
            .unwrap();
        let manifest = sink.manifest.take().unwrap();
        let share = sink.shares.remove(&(0, 0)).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_root = env::temp_dir().join(format!("noos-web-bundle-test-{nonce}"));
        fs::create_dir_all(&test_root).unwrap();
        let license_path = test_root.join("source-license.txt");
        let notice_path = test_root.join("source-notice.txt");
        fs::write(&license_path, CANONICAL_LICENSE).unwrap();
        fs::write(&notice_path, CANONICAL_NOTICE).unwrap();
        let output_root = test_root.join("bundle");
        let now = now_seconds().unwrap();
        let binding = ChainBinding {
            chain_id: "11".repeat(32),
            genesis_hash: "22".repeat(32),
            artifact_id: "33".repeat(32),
            manifest_root: hex::encode(manifest.manifest_root().as_bytes()),
        };
        let config = WebBundleExportConfig {
            output_root: output_root.clone(),
            canonical_origin: "https://static.example".to_owned(),
            chain_id: binding.chain_id.clone(),
            genesis_hash: binding.genesis_hash.clone(),
            valid_from: now.saturating_sub(1),
            expires_at: now + 3_600,
            license_path,
            notice_path,
            coordinates: vec![ShareCoordinate {
                stripe: 0,
                position: 0,
            }],
            signing_seed: [7; 32],
        };
        let report = export_bundle_core(
            &manifest,
            binding.clone(),
            config,
            |stripe, position, output| {
                assert_eq!((stripe, position), (0, 0));
                output.copy_from_slice(&share);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(report.noos_da_verified_share_count, 1);
        assert!(report.immutable_files);

        let verified = verify_bundle_core(
            &manifest,
            &output_root,
            "https://static.example",
            &binding,
            now,
        )
        .unwrap();
        assert_eq!(verified.verified_share_count, 1);
        assert!(verified.signature_verified);
        assert!(verified.noos_da_verified);
        assert!(verified.immutable_files);

        let share_path = output_root.join("shares/000000/00.share");
        let metadata = fs::metadata(&share_path).unwrap();
        make_file_writable(&share_path, &metadata).unwrap();
        let mut tampered = fs::read(&share_path).unwrap();
        tampered[0] ^= 1;
        fs::write(&share_path, tampered).unwrap();
        assert!(verify_bundle_core(
            &manifest,
            &output_root,
            "https://static.example",
            &binding,
            now,
        )
        .unwrap_err()
        .contains("transport SHA-256"));

        make_tree_writable(&test_root);
        fs::remove_dir_all(test_root).unwrap();
    }

    #[test]
    fn substituted_license_or_notice_cannot_publish_a_signed_bundle() {
        let mut sink = CaptureSink::default();
        let mut source = Cursor::new(b"canonical static bundle fixture".to_vec());
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut source, &mut sink, 1)
            .unwrap();
        let manifest = sink.manifest.take().unwrap();
        let share = sink.shares.remove(&(0, 0)).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_root = env::temp_dir().join(format!("noos-web-bundle-notices-test-{nonce}"));
        fs::create_dir_all(&test_root).unwrap();
        let license_path = test_root.join("LICENSE.txt");
        let notice_path = test_root.join("NOTICE.txt");
        fs::write(&license_path, CANONICAL_LICENSE).unwrap();
        fs::write(&notice_path, CANONICAL_NOTICE).unwrap();
        let binding = ChainBinding {
            chain_id: "11".repeat(32),
            genesis_hash: "22".repeat(32),
            artifact_id: "33".repeat(32),
            manifest_root: hex::encode(manifest.manifest_root().as_bytes()),
        };
        let now = now_seconds().unwrap();

        for substituted_file in [&license_path, &notice_path] {
            let mut substituted = fs::read(substituted_file).unwrap();
            substituted[0] ^= 1;
            fs::write(substituted_file, &substituted).unwrap();
            let label = if substituted_file == &license_path {
                "license"
            } else {
                "notice"
            };
            let output_root = test_root.join(format!("bundle-{label}"));
            let config = WebBundleExportConfig {
                output_root: output_root.clone(),
                canonical_origin: "https://static.example".to_owned(),
                chain_id: binding.chain_id.clone(),
                genesis_hash: binding.genesis_hash.clone(),
                valid_from: now.saturating_sub(1),
                expires_at: now + 3_600,
                license_path: license_path.clone(),
                notice_path: notice_path.clone(),
                coordinates: vec![ShareCoordinate {
                    stripe: 0,
                    position: 0,
                }],
                signing_seed: [7; 32],
            };
            let error = export_bundle_core(&manifest, binding.clone(), config, |_, _, output| {
                output.copy_from_slice(&share);
                Ok(())
            })
            .unwrap_err();
            assert!(error.contains("canonical Bonsai release"));
            assert!(!output_root.exists());
            fs::write(
                substituted_file,
                if label == "license" {
                    CANONICAL_LICENSE
                } else {
                    CANONICAL_NOTICE
                },
            )
            .unwrap();
        }

        fs::remove_dir_all(test_root).unwrap();
    }

    #[test]
    fn export_expiring_during_verification_cannot_publish() {
        let mut sink = CaptureSink::default();
        let mut source = Cursor::new(b"canonical static bundle fixture".to_vec());
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut source, &mut sink, 1)
            .unwrap();
        let manifest = sink.manifest.take().unwrap();
        let share = sink.shares.remove(&(0, 0)).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_root = env::temp_dir().join(format!("noos-web-bundle-expiry-test-{nonce}"));
        fs::create_dir_all(&test_root).unwrap();
        let license_path = test_root.join("LICENSE.txt");
        let notice_path = test_root.join("NOTICE.txt");
        fs::write(&license_path, CANONICAL_LICENSE).unwrap();
        fs::write(&notice_path, CANONICAL_NOTICE).unwrap();
        let output_root = test_root.join("bundle");
        let binding = ChainBinding {
            chain_id: "11".repeat(32),
            genesis_hash: "22".repeat(32),
            artifact_id: "33".repeat(32),
            manifest_root: hex::encode(manifest.manifest_root().as_bytes()),
        };
        let config = WebBundleExportConfig {
            output_root: output_root.clone(),
            canonical_origin: "https://static.example".to_owned(),
            chain_id: binding.chain_id.clone(),
            genesis_hash: binding.genesis_hash.clone(),
            valid_from: 999,
            expires_at: 1_001,
            license_path,
            notice_path,
            coordinates: vec![ShareCoordinate {
                stripe: 0,
                position: 0,
            }],
            signing_seed: [7; 32],
        };
        let mut times = VecDeque::from([1_000_u64, 1_001_u64]);
        let error = export_bundle_core_with_clock(
            &manifest,
            binding,
            config,
            |_, _, output| {
                output.copy_from_slice(&share);
                Ok(())
            },
            || Ok(times.pop_front().unwrap()),
        )
        .unwrap_err();
        assert_eq!(error, "bundle expired before publication");
        assert!(times.is_empty());
        assert!(!output_root.exists());

        fs::remove_dir_all(test_root).unwrap();
    }
}
