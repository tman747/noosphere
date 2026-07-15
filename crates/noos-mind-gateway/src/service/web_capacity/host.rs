use super::{
    config::SourceRegistration,
    model::{
        StaticHostManifest, StaticInventory, HOST_MANIFEST_SIGNATURE_DOMAIN, MAX_INVENTORY_ROWS,
        SCHEMA, SHARE_BYTES,
    },
    security::{
        canonical_json, decode_hex32, domain_hash_hex, now_seconds, require_same_origin,
        sha256_hex, verify_json_signature, HostFetcher,
    },
    Result, WebCapacityError,
};
use noos_crypto::DomainId;
use noos_da::artifact::{
    share_commitment, ArtifactManifestV1, ARTIFACT_POSITIONS, ARTIFACT_SHARE_BYTES,
};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};

const WELL_KNOWN_PATH: &str = "/.well-known/noos/wwm-web-capacity-v1.json";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_INVENTORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_LICENSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VerifiedHost {
    pub host_id: String,
    pub manifest: StaticHostManifest,
    pub inventory: StaticInventory,
    pub source: SourceRegistration,
}

#[derive(Clone)]
pub struct HostVerifier {
    fetcher: Arc<dyn HostFetcher>,
    canonical_manifest: Arc<ArtifactManifestV1>,
    chain_binding: super::model::ChainBinding,
    probe_count: usize,
}

impl HostVerifier {
    #[must_use]
    pub fn new(
        fetcher: Arc<dyn HostFetcher>,
        canonical_manifest: Arc<ArtifactManifestV1>,
        chain_binding: super::model::ChainBinding,
        probe_count: usize,
    ) -> Self {
        Self {
            fetcher,
            canonical_manifest,
            chain_binding,
            probe_count,
        }
    }

    pub async fn verify(&self, source: SourceRegistration) -> Result<VerifiedHost> {
        let manifest_url = format!("{}{WELL_KNOWN_PATH}", source.origin);
        let manifest_response = self
            .fetcher
            .fetch(&manifest_url, MAX_MANIFEST_BYTES)
            .await?;
        require_success(&manifest_response, &manifest_url)?;
        require_json_content_type(&manifest_response)?;
        let mut manifest_value =
            parse_canonical_json(&manifest_response.body, "static host manifest")?;
        let manifest: StaticHostManifest =
            serde_json::from_value(manifest_value.clone()).map_err(|error| {
                WebCapacityError::InvalidRecord(format!("invalid static host manifest: {error}"))
            })?;
        if manifest.canonical_origin != source.origin {
            return Err(WebCapacityError::InvalidOrigin(
                "well-known manifest origin differs from the owner-authorized source origin"
                    .to_owned(),
            ));
        }
        self.validate_manifest(&manifest, &mut manifest_value)?;

        let inventory_response = self
            .fetcher
            .fetch(&manifest.inventory.url, MAX_INVENTORY_BYTES)
            .await?;
        require_success(&inventory_response, &manifest.inventory.url)?;
        require_json_content_type(&inventory_response)?;
        if inventory_response.body.len() as u64 != manifest.inventory.bytes
            || sha256_hex(&inventory_response.body) != manifest.inventory.sha256
        {
            return Err(WebCapacityError::InvalidRecord(
                "inventory byte length or SHA-256 differs from the signed manifest".to_owned(),
            ));
        }
        let inventory_value =
            parse_canonical_json(&inventory_response.body, "static inventory")?;
        let inventory: StaticInventory =
            serde_json::from_value(inventory_value.clone()).map_err(|error| {
                WebCapacityError::InvalidRecord(format!("invalid static inventory: {error}"))
            })?;
        self.validate_inventory(&manifest, &inventory, &inventory_value)?;

        self.verify_license(&manifest).await?;
        self.probe_inventory(&inventory).await?;
        let host_id = domain_hash_hex(DomainId::WwmWebHostIdV1, &[source.origin.as_bytes()])?;
        Ok(VerifiedHost {
            host_id,
            manifest,
            inventory,
            source,
        })
    }

    fn validate_manifest(
        &self,
        manifest: &StaticHostManifest,
        manifest_value: &mut Value,
    ) -> Result<()> {
        if manifest.schema != SCHEMA
            || manifest.record_kind != "STATIC_HOST_MANIFEST"
            || manifest.participant_class != "STATIC_HOST_SEEDER"
            || manifest.admission_class != "StatelessReissueable"
            || manifest.production_custody
            || manifest.rewards
            || manifest.canonical_origin.is_empty()
            || manifest.canonical_origin != self.source_origin(manifest)?
            || manifest.chain_binding != self.chain_binding
        {
            return Err(WebCapacityError::InvalidRecord(
                "static host manifest identity, class, origin, chain binding, or authority flags are invalid"
                    .to_owned(),
            ));
        }
        let now = now_seconds()?;
        if manifest.valid_from > now
            || manifest.expires_at <= now
            || manifest.valid_from >= manifest.expires_at
            || manifest.expires_at.saturating_sub(manifest.valid_from) > 31 * 86_400
        {
            return Err(WebCapacityError::InvalidRecord(
                "static host manifest validity interval is absent, expired, future, or over 31 days"
                    .to_owned(),
            ));
        }
        if manifest.signature.suite != "Ed25519"
            || manifest.signature.domain != HOST_MANIFEST_SIGNATURE_DOMAIN
            || manifest.signature.public_key != manifest.host_signing_key
        {
            return Err(WebCapacityError::InvalidSignature);
        }
        for url in [
            &manifest.revocation_url,
            &manifest.inventory.url,
            &manifest.license.license_url,
            &manifest.license.notice_url,
        ] {
            require_same_origin(url, &manifest.canonical_origin)?;
        }
        if manifest.license.spdx != "Apache-2.0"
            || manifest.transport_policy.cors_allow_origin != "*"
            || manifest.transport_policy.credentials != "omit"
            || manifest.transport_policy.redirects != "reject"
            || !manifest.transport_policy.range_requests
            || !manifest.transport_policy.immutable_cache
            || manifest.transport_policy.content_encoding != "identity"
        {
            return Err(WebCapacityError::InvalidRecord(
                "license or immutable transport policy is invalid".to_owned(),
            ));
        }
        let object = manifest_value.as_object_mut().ok_or_else(|| {
            WebCapacityError::InvalidRecord("static host manifest must be an object".to_owned())
        })?;
        object.remove("signature").ok_or_else(|| {
            WebCapacityError::InvalidRecord("static host manifest lacks a signature".to_owned())
        })?;
        verify_json_signature(
            DomainId::SigWwmWebHostManifestV1,
            &manifest.signature.public_key,
            &manifest.signature.signature,
            manifest_value,
        )
    }

    fn source_origin(&self, manifest: &StaticHostManifest) -> Result<String> {
        super::security::canonical_https_origin(&manifest.canonical_origin)
    }

    fn validate_inventory(
        &self,
        manifest: &StaticHostManifest,
        inventory: &StaticInventory,
        inventory_value: &Value,
    ) -> Result<()> {
        let now = now_seconds()?;
        if inventory.schema != SCHEMA
            || inventory.record_kind != "STATIC_INVENTORY"
            || inventory.canonical_origin != manifest.canonical_origin
            || inventory.chain_binding != self.chain_binding
            || inventory.generated_at > now
            || inventory.generated_at >= inventory.expires_at
            || inventory.expires_at != manifest.expires_at
            || inventory.rows.is_empty()
            || inventory.rows.len() > MAX_INVENTORY_ROWS
            || inventory.inventory_root != manifest.inventory.inventory_root
        {
            return Err(WebCapacityError::InvalidRecord(
                "static inventory identity, interval, binding, or row bound is invalid".to_owned(),
            ));
        }
        let rows_value = inventory_value.get("rows").ok_or_else(|| {
            WebCapacityError::InvalidRecord("static inventory lacks rows".to_owned())
        })?;
        let canonical_rows = canonical_json(rows_value)?;
        let computed_root = domain_hash_hex(DomainId::WwmWebInventoryV1, &[&canonical_rows])?;
        if computed_root != inventory.inventory_root {
            return Err(WebCapacityError::InvalidRecord(
                "static inventory root does not bind its canonical rows".to_owned(),
            ));
        }
        let mut prior = None;
        let mut coordinates = BTreeSet::new();
        for row in &inventory.rows {
            let coordinate = (row.stripe, row.position);
            if prior.is_some_and(|value| value >= coordinate) || !coordinates.insert(coordinate) {
                return Err(WebCapacityError::InvalidRecord(
                    "inventory coordinates must be unique and strictly ordered".to_owned(),
                ));
            }
            prior = Some(coordinate);
            if row.stripe as usize >= self.canonical_manifest.stripes.len()
                || row.position as usize >= ARTIFACT_POSITIONS
                || row.bytes != SHARE_BYTES
            {
                return Err(WebCapacityError::InvalidRecord(
                    "inventory coordinate or share length is out of bounds".to_owned(),
                ));
            }
            require_same_origin(&row.url, &manifest.canonical_origin)?;
            let expected =
                self.canonical_manifest.stripes[row.stripe as usize].shares[row.position as usize];
            if decode_hex32(&row.transport_sha256).is_err()
                || decode_hex32(&row.protocol_share_digest)? != expected.share_digest.into_bytes()
                || decode_hex32(&row.probe_root)? != expected.probe_root.into_bytes()
            {
                return Err(WebCapacityError::InvalidRecord(
                    "inventory digest or probe root differs from the canonical noos-da manifest"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    async fn verify_license(&self, manifest: &StaticHostManifest) -> Result<()> {
        for (url, expected) in [
            (
                &manifest.license.license_url,
                &manifest.license.license_sha256,
            ),
            (
                &manifest.license.notice_url,
                &manifest.license.notice_sha256,
            ),
        ] {
            decode_hex32(expected)?;
            let response = self.fetcher.fetch(url, MAX_LICENSE_BYTES).await?;
            require_success(&response, url)?;
            if sha256_hex(&response.body) != *expected {
                return Err(WebCapacityError::InvalidRecord(
                    "license or NOTICE hash differs from the signed manifest".to_owned(),
                ));
            }
        }
        Ok(())
    }

    async fn probe_inventory(&self, inventory: &StaticInventory) -> Result<()> {
        let indices = sample_indices(inventory.rows.len(), self.probe_count);
        for index in indices {
            let row = &inventory.rows[index];
            let response = self.fetcher.fetch(&row.url, ARTIFACT_SHARE_BYTES).await?;
            require_full_share_response(&response, &row.url)?;
            if sha256_hex(&response.body) != row.transport_sha256 {
                return Err(WebCapacityError::InvalidRecord(
                    "sample share failed its transport SHA-256".to_owned(),
                ));
            }
            let commitment =
                share_commitment(row.stripe, row.position, &response.body).map_err(|error| {
                    WebCapacityError::InvalidRecord(format!(
                        "canonical noos-da sample verification failed: {error}"
                    ))
                })?;
            if commitment.share_digest.into_bytes() != decode_hex32(&row.protocol_share_digest)?
                || commitment.probe_root.into_bytes() != decode_hex32(&row.probe_root)?
            {
                return Err(WebCapacityError::InvalidRecord(
                    "sample share differs from its canonical noos-da commitment".to_owned(),
                ));
            }

            let head = self
                .fetcher
                .head(&row.url, ARTIFACT_SHARE_BYTES)
                .await?;
            require_head_response(&head, &row.url)?;

            let range_start = (ARTIFACT_SHARE_BYTES / 2) as u64;
            let range_end = range_start + 1_023;
            let range = self
                .fetcher
                .fetch_range(&row.url, range_start, range_end, 1_024)
                .await?;
            require_range_response(&range, &row.url, range_start, range_end)?;
            let start = range_start as usize;
            let end = range_end as usize + 1;
            if range.body != response.body[start..end] {
                return Err(WebCapacityError::InvalidRecord(
                    "Range probe bytes differ from the immutable share".to_owned(),
                ));
            }

            let unsatisfiable = self
                .fetcher
                .fetch_range(
                    &row.url,
                    ARTIFACT_SHARE_BYTES as u64,
                    ARTIFACT_SHARE_BYTES as u64,
                    4 * 1_024,
                )
                .await?;
            require_unsatisfiable_range_response(&unsatisfiable, &row.url)?;
        }
        Ok(())
    }
}

fn require_success(response: &super::security::FetchedResponse, requested: &str) -> Result<()> {
    if response.status != 200 || response.final_url != requested {
        return Err(WebCapacityError::HostFetch(
            "host response was non-200, redirected, or changed URL".to_owned(),
        ));
    }
    Ok(())
}

fn require_json_content_type(response: &super::security::FetchedResponse) -> Result<()> {
    if response
        .headers
        .get("content-type")
        .is_none_or(|value| value.split(';').next() != Some("application/json"))
    {
        return Err(WebCapacityError::HostFetch(
            "host manifest and inventory require application/json".to_owned(),
        ));
    }
    Ok(())
}

fn parse_canonical_json(bytes: &[u8], label: &str) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        WebCapacityError::InvalidRecord(format!("decode {label}: {error}"))
    })?;
    if canonical_json(&value)? != bytes {
        return Err(WebCapacityError::InvalidRecord(format!(
            "{label} wire bytes are not RFC-8785 canonical JSON"
        )));
    }
    Ok(value)
}

fn require_full_share_response(
    response: &super::security::FetchedResponse,
    requested: &str,
) -> Result<()> {
    require_status_and_url(response, requested, 200, "full share GET")?;
    require_immutable_transport_headers(response)?;
    require_content_length(response, ARTIFACT_SHARE_BYTES)?;
    if response.body.len() != ARTIFACT_SHARE_BYTES {
        return Err(WebCapacityError::InvalidRecord(
            "full share GET body length is not exactly one share".to_owned(),
        ));
    }
    Ok(())
}

fn require_head_response(
    response: &super::security::FetchedResponse,
    requested: &str,
) -> Result<()> {
    require_status_and_url(response, requested, 200, "share HEAD")?;
    require_immutable_transport_headers(response)?;
    require_content_length(response, ARTIFACT_SHARE_BYTES)?;
    if !response.body.is_empty() {
        return Err(WebCapacityError::InvalidRecord(
            "share HEAD response unexpectedly carried a body".to_owned(),
        ));
    }
    Ok(())
}

fn require_range_response(
    response: &super::security::FetchedResponse,
    requested: &str,
    start: u64,
    end: u64,
) -> Result<()> {
    require_status_and_url(response, requested, 206, "satisfiable Range GET")?;
    require_immutable_transport_headers(response)?;
    let expected_length = usize::try_from(end.saturating_sub(start).saturating_add(1))
        .map_err(|_| WebCapacityError::InvalidRecord("Range probe length overflow".to_owned()))?;
    require_content_length(response, expected_length)?;
    let expected_range = format!("bytes {start}-{end}/{ARTIFACT_SHARE_BYTES}");
    if response.headers.get("content-range") != Some(&expected_range)
        || response.body.len() != expected_length
    {
        return Err(WebCapacityError::InvalidRecord(
            "satisfiable Range response has an invalid Content-Range or body length".to_owned(),
        ));
    }
    Ok(())
}

fn require_unsatisfiable_range_response(
    response: &super::security::FetchedResponse,
    requested: &str,
) -> Result<()> {
    require_status_and_url(response, requested, 416, "unsatisfiable Range GET")?;
    let expected_range = format!("bytes */{ARTIFACT_SHARE_BYTES}");
    if response.headers.get("content-range") != Some(&expected_range) {
        return Err(WebCapacityError::InvalidRecord(
            "unsatisfiable Range response lacks the exact share total".to_owned(),
        ));
    }
    require_cors_and_content_encoding(response)
}

fn require_status_and_url(
    response: &super::security::FetchedResponse,
    requested: &str,
    status: u16,
    operation: &str,
) -> Result<()> {
    if response.status != status || response.final_url != requested {
        return Err(WebCapacityError::InvalidRecord(format!(
            "{operation} returned the wrong status, redirected, or changed URL"
        )));
    }
    Ok(())
}

fn require_content_length(
    response: &super::security::FetchedResponse,
    expected: usize,
) -> Result<()> {
    if response
        .headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        != Some(expected)
    {
        return Err(WebCapacityError::InvalidRecord(
            "share response Content-Length is absent or incorrect".to_owned(),
        ));
    }
    Ok(())
}

fn require_immutable_transport_headers(
    response: &super::security::FetchedResponse,
) -> Result<()> {
    require_cors_and_content_encoding(response)?;
    if response
        .headers
        .get("accept-ranges")
        .is_none_or(|value| !value.trim().eq_ignore_ascii_case("bytes"))
    {
        return Err(WebCapacityError::InvalidRecord(
            "share response does not declare byte ranges".to_owned(),
        ));
    }
    let cache_control = response.headers.get("cache-control").ok_or_else(|| {
        WebCapacityError::InvalidRecord(
            "share response lacks public immutable cache controls".to_owned(),
        )
    })?;
    let mut public = false;
    let mut immutable = false;
    let mut max_age = None;
    for directive in cache_control.split(',') {
        let directive = directive.trim();
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| (name.trim(), Some(value.trim())));
        if name.eq_ignore_ascii_case("public") {
            public = true;
        } else if name.eq_ignore_ascii_case("immutable") {
            immutable = true;
        } else if name.eq_ignore_ascii_case("no-store")
            || name.eq_ignore_ascii_case("no-cache")
            || name.eq_ignore_ascii_case("private")
        {
            return Err(WebCapacityError::InvalidRecord(
                "share response has contradictory cache controls".to_owned(),
            ));
        } else if name.eq_ignore_ascii_case("max-age") {
            if max_age.is_some() {
                return Err(WebCapacityError::InvalidRecord(
                    "share response has ambiguous max-age cache controls".to_owned(),
                ));
            }
            max_age = Some(parse_cache_seconds(value, "max-age")?);
        } else if name.eq_ignore_ascii_case("s-maxage")
            && parse_cache_seconds(value, "s-maxage")? == 0
        {
            return Err(WebCapacityError::InvalidRecord(
                "share response disables shared-cache freshness".to_owned(),
            ));
        }
    }
    if !public || !immutable || max_age.is_none_or(|seconds| seconds == 0) {
        return Err(WebCapacityError::InvalidRecord(
            "share response is not explicitly public, immutable, and fresh".to_owned(),
        ));
    }
    Ok(())
}

fn parse_cache_seconds(value: Option<&str>, directive: &str) -> Result<u64> {
    value
        .map(|value| value.trim_matches('"'))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            WebCapacityError::InvalidRecord(format!(
                "share response has an invalid {directive} cache directive"
            ))
        })
}

fn require_cors_and_content_encoding(
    response: &super::security::FetchedResponse,
) -> Result<()> {
    if response
        .headers
        .get("access-control-allow-origin")
        .map(String::as_str)
        != Some("*")
    {
        return Err(WebCapacityError::InvalidRecord(
            "share response lacks wildcard CORS".to_owned(),
        ));
    }
    if response.headers.get("content-encoding").is_some_and(|value| {
        !value.trim().eq_ignore_ascii_case("identity")
    }) {
        return Err(WebCapacityError::InvalidRecord(
            "share response Content-Encoding is not identity".to_owned(),
        ));
    }
    Ok(())
}

fn sample_indices(length: usize, requested: usize) -> Vec<usize> {
    let count = requested.min(length);
    if count == 0 {
        return Vec::new();
    }
    if count == 1 {
        return vec![0];
    }
    let span = length.saturating_sub(1);
    let divisor = count.saturating_sub(1);
    (0..count)
        .map(|index| {
            index
                .checked_mul(span)
                .and_then(|value| value.checked_div(divisor))
                .unwrap_or(span)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::web_capacity::{
        model::{
            ChainBinding, Ed25519Signature, InventoryBinding, InventoryRow, LicenseBinding,
            TransportPolicy,
        },
        security::{sign_json, FetchedResponse},
    };
    use noos_crypto::Keypair;
    use noos_da::artifact::{
        ArtifactEncoderV1, ArtifactError, ArtifactShareSink, ArtifactStripeV1,
    };
    use std::{
        collections::BTreeMap,
        io::Cursor,
        sync::{Arc, LazyLock},
    };

    const ORIGIN: &str = "https://seed.example";
    const SHARE_URL: &str = "https://seed.example/shares/000000/00.share";
    const INVENTORY_URL: &str = "https://seed.example/inventory-v1.json";
    const LICENSE_URL: &str = "https://seed.example/LICENSE.txt";
    const NOTICE_URL: &str = "https://seed.example/NOTICE.txt";
    const SIGNING_SEED: [u8; 32] = [41; 32];

    #[derive(Default)]
    struct FirstShareSink {
        first_share: Vec<u8>,
    }

    impl ArtifactShareSink for FirstShareSink {
        fn stage_share(
            &mut self,
            stripe: u32,
            position: u8,
            bytes: &[u8],
        ) -> std::result::Result<(), ArtifactError> {
            if stripe == 0 && position == 0 {
                self.first_share = bytes.to_vec();
            }
            Ok(())
        }

        fn checkpoint_stripe(
            &mut self,
            _stripe: u32,
        ) -> std::result::Result<(), ArtifactError> {
            Ok(())
        }

        fn checkpoint_artifact_stripe(
            &mut self,
            _stripe: &ArtifactStripeV1,
        ) -> std::result::Result<(), ArtifactError> {
            Ok(())
        }

        fn publish_manifest(
            &mut self,
            _manifest: &ArtifactManifestV1,
        ) -> std::result::Result<(), ArtifactError> {
            Ok(())
        }
    }

    struct StaticFixture {
        canonical_manifest: ArtifactManifestV1,
        chain_binding: ChainBinding,
        source: SourceRegistration,
        manifest: StaticHostManifest,
        manifest_body: Vec<u8>,
        inventory_body: Vec<u8>,
        share: Vec<u8>,
        license: Vec<u8>,
        notice: Vec<u8>,
    }

    static FIXTURE: LazyLock<StaticFixture> = LazyLock::new(build_fixture);

    fn build_fixture() -> StaticFixture {
        let mut sink = FirstShareSink::default();
        let canonical_manifest = ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut Cursor::new(vec![0x5a]), &mut sink, 9)
            .unwrap();
        assert_eq!(sink.first_share.len(), ARTIFACT_SHARE_BYTES);

        let chain_binding = ChainBinding {
            chain_id: "01".repeat(32),
            genesis_hash: "02".repeat(32),
            artifact_id: "03".repeat(32),
            manifest_root: "04".repeat(32),
        };
        let commitment = canonical_manifest.stripes[0].shares[0];
        let rows = vec![InventoryRow {
            stripe: 0,
            position: 0,
            bytes: SHARE_BYTES,
            transport_sha256: sha256_hex(&sink.first_share),
            protocol_share_digest: hex::encode(commitment.share_digest.into_bytes()),
            probe_root: hex::encode(commitment.probe_root.into_bytes()),
            url: SHARE_URL.to_owned(),
        }];
        let rows_value = serde_json::to_value(&rows).unwrap();
        let inventory_root =
            domain_hash_hex(DomainId::WwmWebInventoryV1, &[&canonical_json(&rows_value).unwrap()])
                .unwrap();
        let now = now_seconds().unwrap();
        let inventory = StaticInventory {
            schema: SCHEMA.to_owned(),
            record_kind: "STATIC_INVENTORY".to_owned(),
            canonical_origin: ORIGIN.to_owned(),
            chain_binding: chain_binding.clone(),
            generated_at: now.saturating_sub(1),
            expires_at: now + 3_600,
            rows,
            inventory_root: inventory_root.clone(),
        };
        let inventory_body =
            canonical_json(&serde_json::to_value(&inventory).unwrap()).unwrap();
        let license = b"Apache License 2.0 test fixture".to_vec();
        let notice = b"NOOS test fixture notice".to_vec();
        let signer = Keypair::from_seed(SIGNING_SEED);
        let public_key = hex::encode(signer.public_key().into_bytes());
        let mut manifest = StaticHostManifest {
            schema: SCHEMA.to_owned(),
            record_kind: "STATIC_HOST_MANIFEST".to_owned(),
            participant_class: "STATIC_HOST_SEEDER".to_owned(),
            admission_class: "StatelessReissueable".to_owned(),
            canonical_origin: ORIGIN.to_owned(),
            chain_binding: chain_binding.clone(),
            host_signing_key: public_key.clone(),
            valid_from: now.saturating_sub(1),
            expires_at: now + 3_600,
            revocation_url: format!("{ORIGIN}{WELL_KNOWN_PATH}"),
            inventory: InventoryBinding {
                url: INVENTORY_URL.to_owned(),
                bytes: inventory_body.len() as u64,
                sha256: sha256_hex(&inventory_body),
                inventory_root,
            },
            license: LicenseBinding {
                spdx: "Apache-2.0".to_owned(),
                license_url: LICENSE_URL.to_owned(),
                license_sha256: sha256_hex(&license),
                notice_url: NOTICE_URL.to_owned(),
                notice_sha256: sha256_hex(&notice),
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
                domain: HOST_MANIFEST_SIGNATURE_DOMAIN.to_owned(),
                public_key,
                signature: String::new(),
            },
        };
        let manifest_body = sign_manifest(&mut manifest);
        StaticFixture {
            canonical_manifest,
            chain_binding,
            source: SourceRegistration {
                origin: ORIGIN.to_owned(),
                provider: "fixture-provider".to_owned(),
                region: "fixture-region".to_owned(),
                control_cluster: "fixture-control".to_owned(),
            },
            manifest,
            manifest_body,
            inventory_body,
            share: sink.first_share,
            license,
            notice,
        }
    }

    fn sign_manifest(manifest: &mut StaticHostManifest) -> Vec<u8> {
        let signer = Keypair::from_seed(SIGNING_SEED);
        let mut unsigned = serde_json::to_value(&*manifest).unwrap();
        unsigned
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap();
        manifest.signature.signature =
            sign_json(&signer, DomainId::SigWwmWebHostManifestV1, &unsigned).unwrap();
        canonical_json(&serde_json::to_value(manifest).unwrap()).unwrap()
    }

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        NoncanonicalManifest,
        DuplicateManifestKey,
        NoncanonicalInventory,
        DuplicateInventoryKey,
        FakeAcceptRanges,
        BadPartialContent,
        BadPartialLength,
        BadUnsatisfiableRange,
        ContradictoryCache,
        BadHead,
    }

    struct MockFetcher {
        fault: Fault,
        manifest_body: Vec<u8>,
        inventory_body: Vec<u8>,
    }

    impl MockFetcher {
        fn new(fault: Fault) -> Self {
            let fixture = &*FIXTURE;
            let mut inventory_body = fixture.inventory_body.clone();
            if matches!(fault, Fault::NoncanonicalInventory) {
                inventory_body.push(b'\n');
            } else if matches!(fault, Fault::DuplicateInventoryKey) {
                inventory_body = duplicate_schema_key(&inventory_body);
            }
            let mut manifest = fixture.manifest.clone();
            if matches!(
                fault,
                Fault::NoncanonicalInventory | Fault::DuplicateInventoryKey
            ) {
                manifest.inventory.bytes = inventory_body.len() as u64;
                manifest.inventory.sha256 = sha256_hex(&inventory_body);
            }
            let mut manifest_body = sign_manifest(&mut manifest);
            if matches!(fault, Fault::NoncanonicalManifest) {
                manifest_body.push(b'\n');
            } else if matches!(fault, Fault::DuplicateManifestKey) {
                manifest_body = duplicate_schema_key(&manifest_body);
            }
            Self {
                fault,
                manifest_body,
                inventory_body,
            }
        }
    }

    fn duplicate_schema_key(canonical: &[u8]) -> Vec<u8> {
        let mut duplicate = format!("{{\"schema\":{},", serde_json::to_string(SCHEMA).unwrap())
            .into_bytes();
        duplicate.extend_from_slice(&canonical[1..]);
        duplicate
    }

    #[async_trait::async_trait]
    impl HostFetcher for MockFetcher {
        async fn fetch(&self, url: &str, _maximum_bytes: usize) -> Result<FetchedResponse> {
            if url == format!("{ORIGIN}{WELL_KNOWN_PATH}") {
                return Ok(json_response(url, self.manifest_body.clone()));
            }
            if url == INVENTORY_URL {
                return Ok(json_response(url, self.inventory_body.clone()));
            }
            if url == LICENSE_URL {
                return Ok(basic_response(url, 200, FIXTURE.license.clone()));
            }
            if url == NOTICE_URL {
                return Ok(basic_response(url, 200, FIXTURE.notice.clone()));
            }
            if url == SHARE_URL {
                let body = FIXTURE.share.clone();
                let mut headers = share_headers(self.fault);
                headers.insert("content-length".to_owned(), body.len().to_string());
                return Ok(FetchedResponse {
                    status: 200,
                    final_url: url.to_owned(),
                    headers,
                    body,
                });
            }
            Err(WebCapacityError::HostFetch(
                "unexpected fixture URL".to_owned(),
            ))
        }

        async fn head(&self, url: &str, _maximum_bytes: usize) -> Result<FetchedResponse> {
            let mut headers = share_headers(self.fault);
            let length = if matches!(self.fault, Fault::BadHead) {
                ARTIFACT_SHARE_BYTES - 1
            } else {
                ARTIFACT_SHARE_BYTES
            };
            headers.insert("content-length".to_owned(), length.to_string());
            Ok(FetchedResponse {
                status: 200,
                final_url: url.to_owned(),
                headers,
                body: Vec::new(),
            })
        }

        async fn fetch_range(
            &self,
            url: &str,
            start: u64,
            end: u64,
            _maximum_bytes: usize,
        ) -> Result<FetchedResponse> {
            if start >= ARTIFACT_SHARE_BYTES as u64 {
                let total = if matches!(self.fault, Fault::BadUnsatisfiableRange) {
                    ARTIFACT_SHARE_BYTES - 1
                } else {
                    ARTIFACT_SHARE_BYTES
                };
                let mut headers = BTreeMap::new();
                headers.insert(
                    "content-range".to_owned(),
                    format!("bytes */{total}"),
                );
                headers.insert("access-control-allow-origin".to_owned(), "*".to_owned());
                headers.insert("content-encoding".to_owned(), "identity".to_owned());
                return Ok(FetchedResponse {
                    status: 416,
                    final_url: url.to_owned(),
                    headers,
                    body: Vec::new(),
                });
            }
            let mut body = FIXTURE.share[start as usize..=end as usize].to_vec();
            if matches!(self.fault, Fault::BadPartialLength) {
                body.pop();
            }
            let mut headers = share_headers(self.fault);
            headers.insert(
                "content-length".to_owned(),
                (end - start + 1).to_string(),
            );
            let content_range = if matches!(self.fault, Fault::BadPartialContent) {
                format!("bytes {start}-{end}/{}", ARTIFACT_SHARE_BYTES - 1)
            } else {
                format!("bytes {start}-{end}/{ARTIFACT_SHARE_BYTES}")
            };
            headers.insert("content-range".to_owned(), content_range);
            Ok(FetchedResponse {
                status: if matches!(self.fault, Fault::FakeAcceptRanges) {
                    200
                } else {
                    206
                },
                final_url: url.to_owned(),
                headers,
                body,
            })
        }
    }

    fn json_response(url: &str, body: Vec<u8>) -> FetchedResponse {
        let mut response = basic_response(url, 200, body);
        response
            .headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        response
    }

    fn basic_response(url: &str, status: u16, body: Vec<u8>) -> FetchedResponse {
        FetchedResponse {
            status,
            final_url: url.to_owned(),
            headers: BTreeMap::new(),
            body,
        }
    }

    fn share_headers(fault: Fault) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert("accept-ranges".to_owned(), "bytes".to_owned());
        headers.insert("access-control-allow-origin".to_owned(), "*".to_owned());
        headers.insert("content-encoding".to_owned(), "identity".to_owned());
        headers.insert(
            "cache-control".to_owned(),
            if matches!(fault, Fault::ContradictoryCache) {
                "public, max-age=31536000, immutable, no-store"
            } else {
                "public, max-age=31536000, immutable"
            }
            .to_owned(),
        );
        headers
    }

    async fn verify(fault: Fault) -> Result<VerifiedHost> {
        HostVerifier::new(
            Arc::new(MockFetcher::new(fault)),
            Arc::new(FIXTURE.canonical_manifest.clone()),
            FIXTURE.chain_binding.clone(),
            1,
        )
        .verify(FIXTURE.source.clone())
        .await
    }

    async fn assert_rejected(fault: Fault, expected: &str) {
        match verify(fault).await.unwrap_err() {
            WebCapacityError::InvalidRecord(message) => assert!(
                message.contains(expected),
                "unexpected rejection: {message}"
            ),
            error => panic!("unexpected rejection class: {error}"),
        }
    }

    #[tokio::test]
    async fn compliant_static_host_passes_real_transport_probes() {
        let verified = verify(Fault::None).await.unwrap();
        assert_eq!(verified.source.origin, ORIGIN);
        assert_eq!(verified.inventory.rows.len(), 1);
    }

    #[tokio::test]
    async fn noncanonical_manifest_wire_bytes_fail_registration() {
        assert_rejected(Fault::NoncanonicalManifest, "RFC-8785").await;
    }

    #[tokio::test]
    async fn duplicate_manifest_key_fails_registration() {
        assert_rejected(Fault::DuplicateManifestKey, "RFC-8785").await;
    }

    #[tokio::test]
    async fn noncanonical_inventory_wire_bytes_fail_registration() {
        assert_rejected(Fault::NoncanonicalInventory, "RFC-8785").await;
    }

    #[tokio::test]
    async fn duplicate_inventory_key_fails_registration() {
        assert_rejected(Fault::DuplicateInventoryKey, "RFC-8785").await;
    }

    #[tokio::test]
    async fn fake_accept_ranges_fails_registration() {
        assert_rejected(Fault::FakeAcceptRanges, "satisfiable Range GET").await;
    }

    #[tokio::test]
    async fn bad_partial_content_fails_registration() {
        assert_rejected(Fault::BadPartialContent, "invalid Content-Range").await;
    }

    #[tokio::test]
    async fn bad_partial_body_length_fails_registration() {
        assert_rejected(Fault::BadPartialLength, "body length").await;
    }

    #[tokio::test]
    async fn bad_unsatisfiable_range_fails_registration() {
        assert_rejected(Fault::BadUnsatisfiableRange, "exact share total").await;
    }

    #[tokio::test]
    async fn contradictory_cache_headers_fail_registration() {
        assert_rejected(Fault::ContradictoryCache, "contradictory cache").await;
    }

    #[tokio::test]
    async fn invalid_declared_head_transport_fails_registration() {
        assert_rejected(Fault::BadHead, "Content-Length").await;
    }
}
