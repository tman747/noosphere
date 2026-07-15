mod config;
pub mod benchmark;
mod host;
mod model;
mod security;
mod store;

pub use config::{SourceRegistration, WebCapacityConfig};
pub use model::{
    ChainBinding, CoordinatorConfigResponse, ExperimentState, InventoryRow,
    QueueRestoreAdminReport, QueueRestoreAdminRequest, RestoredPositionReleaseReport,
    SignedRestoredPositionImportIndex, StorageClass, UploadPolicy,
    WebRestoredPositionImportEvidence,
};

use self::{
    host::HostVerifier,
    model::{
        Acknowledgement, BrowserSession, Ed25519Signature, ErrorBody, ErrorResponse,
        HeartbeatRequest, HeartbeatResponse, HostRegistrationRequest, HostRegistrationResponse,
        OfferRequest, ParticipantReport, RestoreReceipt, RestoreTask,
        RestoredPositionImportPair, RevocationRequest, RevocationResponse, ShareAssignment,
        StaticCacheLifecycleDisclosure, ACCESS_LOG_RETENTION_SECONDS,
        ASSIGNMENT_SIGNATURE_DOMAIN, HOST_VERIFICATION_MAX_AGE_SECONDS, JSON_BODY_LIMIT,
        MAX_ASSIGNMENT_ROWS, RESTORE_IMPORT_INDEX_RECORD_KIND,
        RESTORE_IMPORT_INDEX_SIGNATURE_DOMAIN, RESTORE_TASK_SIGNATURE_DOMAIN, SCHEMA, SHARE_BYTES,
    },
    security::{
        canonical_https_origin, canonical_json, decode_hex32, domain_hash, domain_hash_hex,
        now_seconds, origin_of_url, sha256_hex, sign_json, verify_json_signature, HostFetcher,
        ReqwestHostFetcher,
    },
    store::{SessionRecord, WebCapacityStore, WebCapacityStoreLimits},
};
use axum::{
    body::{Body, Bytes},
    extract::{rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::{stream, StreamExt};
use noos_crypto::{DomainId, Keypair};
use noos_da::artifact::{share_commitment, ArtifactManifestV1, ARTIFACT_SHARE_BYTES};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};

pub type Result<T, E = WebCapacityError> = std::result::Result<T, E>;

const MEDIA_TYPE: &str = "application/vnd.noos.wwm-web-capacity.v1+json";
const ACTIVE_PAGE_WINDOW_SECONDS: u64 = 120;
const MAX_REPORT_ERRORS: usize = 32;
const MAX_REPORT_DIGESTS: usize = 256;
const MAX_ERROR_COUNT: u32 = 4_096;
const HOST_REFRESH_INTERVAL_SECONDS: u64 = HOST_VERIFICATION_MAX_AGE_SECONDS;
const RETENTION_PURGE_INTERVAL_SECONDS: u64 = 60;
const HOST_REFRESH_CONCURRENCY: usize = 8;

#[derive(Debug)]
pub enum WebCapacityError {
    Config(String),
    Store(String),
    InvalidOrigin(String),
    Ssrf(String),
    HostFetch(String),
    InvalidRecord(String),
    InvalidSignature,
    Unauthorized(String),
    Forbidden(String),
    RateLimited,
    Quota(String),
    Conflict(String),
    Crypto(String),
    Internal(String),
}

impl fmt::Display for WebCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(formatter, "configuration: {message}"),
            Self::Store(message) => write!(formatter, "isolated SQLite store: {message}"),
            Self::InvalidOrigin(message) => write!(formatter, "origin: {message}"),
            Self::Ssrf(message) => write!(formatter, "SSRF destination rejected: {message}"),
            Self::HostFetch(message) => write!(formatter, "static host fetch: {message}"),
            Self::InvalidRecord(message) => write!(formatter, "record: {message}"),
            Self::InvalidSignature => formatter.write_str("signature verification failed"),
            Self::Unauthorized(message) => write!(formatter, "unauthorized: {message}"),
            Self::Forbidden(message) => write!(formatter, "forbidden: {message}"),
            Self::RateLimited => formatter.write_str("rate limit exceeded"),
            Self::Quota(message) => write!(formatter, "quota: {message}"),
            Self::Conflict(message) => write!(formatter, "conflict: {message}"),
            Self::Crypto(message) => write!(formatter, "cryptography: {message}"),
            Self::Internal(message) => write!(formatter, "internal: {message}"),
        }
    }
}

impl Error for WebCapacityError {}
#[derive(Debug, Serialize)]
pub struct HostRefreshReport {
    pub schema: &'static str,
    pub scanned_hosts: usize,
    pub renewed_hosts: usize,
    pub expired_hosts: usize,
    pub authorization_removed_hosts: usize,
    pub verification_failed_hosts: usize,
    pub deactivated_hosts: usize,
    pub next_refresh_within_seconds: u64,
    pub future_assignments_only: bool,
    pub third_party_cache_erasure: bool,
}

enum HostRefreshOutcome {
    Renewed { updated: bool },
    AuthorizationRemoved {
        deactivated: bool,
    },
    VerificationFailed {
        origin: String,
        error: String,
        deactivated: bool,
    },
}

#[derive(Clone)]
pub struct WebCapacityService {
    inner: Arc<WebCapacityState>,
}

struct WebCapacityState {
    config: WebCapacityConfig,
    store: WebCapacityStore,
    signer: Keypair,
    canonical_manifest: Arc<ArtifactManifestV1>,
    host_verifier: HostVerifier,
}

impl WebCapacityService {
    pub fn new(config: WebCapacityConfig) -> Result<Self> {
        let timeout = Duration::from_millis(config.request_timeout_ms);
        let fetcher: Arc<dyn HostFetcher> = match &config.loopback_test_transport {
            Some(transport) => Arc::new(ReqwestHostFetcher::new_loopback_test(
                timeout,
                &transport.ca_certificate_pem,
            )?),
            None => Arc::new(ReqwestHostFetcher::new(timeout)),
        };
        Self::with_fetcher(config, fetcher)
    }

    pub fn with_fetcher(config: WebCapacityConfig, fetcher: Arc<dyn HostFetcher>) -> Result<Self> {
        let manifest_bytes = fs::read(&config.artifact_manifest_path).map_err(|error| {
            WebCapacityError::Config(format!(
                "cannot read canonical manifest {}: {error}",
                config.artifact_manifest_path.display()
            ))
        })?;
        let manifest =
            ArtifactManifestV1::from_canonical_bytes(&manifest_bytes).map_err(|error| {
                WebCapacityError::Config(format!("invalid canonical artifact manifest: {error}"))
            })?;
        manifest.validate_bonsai_geometry().map_err(|error| {
            WebCapacityError::Config(format!(
                "canonical manifest is not exact Bonsai geometry: {error}"
            ))
        })?;
        if hex::encode(manifest.manifest_root().into_bytes()) != config.chain_binding.manifest_root
        {
            return Err(WebCapacityError::Config(
                "canonical manifest root differs from the configured chain binding".to_owned(),
            ));
        }
        let canonical_manifest = Arc::new(manifest);
        let store = WebCapacityStore::open_with_limits(
            &config.data_path,
            WebCapacityStoreLimits {
                max_hosts: config.max_hosts,
                max_active_sessions: config.max_active_sessions,
                max_active_assignments: config.max_active_assignments,
                max_pending_restore_tasks: config.max_pending_restore_tasks,
                max_quarantine_bytes: config.max_quarantine_bytes,
                max_concurrent_restore_verifications:
                    config.max_concurrent_restore_verifications,
            },
        )?;
        let signer = Keypair::from_seed(config.coordinator_seed);
        let host_verifier = HostVerifier::new(
            fetcher,
            Arc::clone(&canonical_manifest),
            config.chain_binding.clone(),
            config.host_probe_count,
        );
        Ok(Self {
            inner: Arc::new(WebCapacityState {
                config,
                store,
                signer,
                canonical_manifest,
                host_verifier,
            }),
        })
    }

    pub fn router(&self) -> Router {
        let json_routes = Router::new()
            .route(
                "/api/wwm-web-capacity/v1/hosts",
                post(register_host_handler),
            )
            .route("/api/wwm-web-capacity/v1/offers", post(offer_handler))
            .route(
                "/api/wwm-web-capacity/v1/heartbeat",
                post(heartbeat_handler),
            )
            .route("/api/wwm-web-capacity/v1/reports", post(report_handler))
            .route("/api/wwm-web-capacity/v1/revoke", post(revoke_handler))
            .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT));
        let restore_route = Router::new()
            .route(
                "/api/wwm-web-capacity/v1/restores/{task_id}",
                put(restore_handler),
            )
            .layer(DefaultBodyLimit::max(ARTIFACT_SHARE_BYTES));
        Router::new()
            .route("/api/wwm-web-capacity/v1/config", get(config_handler))
            .merge(json_routes)
            .merge(restore_route)
            .layer(middleware::from_fn_with_state(
                self.clone(),
                cors_privacy_middleware,
            ))
            .with_state(self.clone())
    }

    pub async fn run(self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(self.inner.config.listen)
            .await
            .map_err(|error| WebCapacityError::Internal(format!("bind listener: {error}")))?;
        let refresh_service = self.clone();
        let refresh_task = tokio::spawn(async move {
            refresh_service.host_refresh_loop().await;
        });
        let retention_service = self.clone();
        let retention_task = tokio::spawn(async move {
            retention_service.retention_purge_loop().await;
        });
        let result = axum::serve(
            listener,
            self.router()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|error| WebCapacityError::Internal(format!("serve coordinator: {error}")));
        refresh_task.abort();
        retention_task.abort();
        result
    }

    #[must_use]
    pub fn coordinator_public_key(&self) -> String {
        hex::encode(self.inner.signer.public_key().into_bytes())
    }
    pub async fn refresh_static_hosts(&self) -> Result<HostRefreshReport> {
        let now = now_seconds()?;
        let expired_hosts = self.inner.store.deactivate_expired_hosts(now)?;
        let targets = self.inner.store.active_host_refresh_targets()?;
        let scanned_hosts = targets.len();
        let mut sources = self
            .inner
            .config
            .source_allowlist
            .iter()
            .cloned()
            .map(|source| (source.origin.clone(), source))
            .collect::<BTreeMap<_, _>>();
        let jobs = targets
            .into_iter()
            .map(|target| {
                let source = sources.remove(&target.origin);
                (target, source)
            })
            .collect::<Vec<_>>();
        let outcomes = stream::iter(jobs)
            .map(|(target, source)| {
                let verifier = self.inner.host_verifier.clone();
                let store = self.inner.store.clone();
                async move {
                    let Some(source) = source else {
                        let deactivated = store
                            .deactivate_host_if_generation(&target.origin, target.generation)?;
                        return Ok(HostRefreshOutcome::AuthorizationRemoved { deactivated });
                    };
                    match verifier.verify(source).await {
                        Ok(verified) => {
                            let updated = store.replace_host_if_generation(
                                target.generation,
                                &verified.host_id,
                                &verified.source.provider,
                                &verified.source.region,
                                &verified.source.control_cluster,
                                &verified.manifest,
                                &verified.inventory,
                            )?;
                            Ok(HostRefreshOutcome::Renewed { updated })
                        }
                        Err(error) => {
                            let deactivated = store
                                .deactivate_host_if_generation(&target.origin, target.generation)?;
                            Ok(HostRefreshOutcome::VerificationFailed {
                                origin: target.origin,
                                error: error.to_string(),
                                deactivated,
                            })
                        }
                    }
                }
            })
            .buffer_unordered(HOST_REFRESH_CONCURRENCY)
            .collect::<Vec<Result<HostRefreshOutcome>>>()
            .await;
        let mut renewed_hosts = 0_usize;
        let mut authorization_removed_hosts = 0_usize;
        let mut verification_failed_hosts = 0_usize;
        let mut deactivated_hosts = expired_hosts;
        for outcome in outcomes {
            match outcome? {
                HostRefreshOutcome::Renewed { updated } => {
                    renewed_hosts = renewed_hosts.saturating_add(usize::from(updated));
                }
                HostRefreshOutcome::AuthorizationRemoved { deactivated } => {
                    authorization_removed_hosts = authorization_removed_hosts.saturating_add(1);
                    deactivated_hosts = deactivated_hosts.saturating_add(usize::from(deactivated));
                }
                HostRefreshOutcome::VerificationFailed {
                    origin,
                    error,
                    deactivated,
                } => {
                    verification_failed_hosts = verification_failed_hosts.saturating_add(1);
                    deactivated_hosts = deactivated_hosts.saturating_add(usize::from(deactivated));
                    eprintln!(
                        "web-capacity static host refresh failed origin={origin} error={error}"
                    );
                }
            }
        }
        Ok(HostRefreshReport {
            schema: "noos.wwm.web-static-host-refresh.v1",
            scanned_hosts,
            renewed_hosts,
            expired_hosts,
            authorization_removed_hosts,
            verification_failed_hosts,
            deactivated_hosts,
            next_refresh_within_seconds: HOST_REFRESH_INTERVAL_SECONDS,
            future_assignments_only: true,
            third_party_cache_erasure: false,
        })
    }

    async fn host_refresh_loop(&self) {
        let mut interval =
            tokio::time::interval(Duration::from_secs(HOST_REFRESH_INTERVAL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match self.refresh_static_hosts().await {
                Ok(report) => {
                    if let Ok(line) = serde_json::to_string(&report) {
                        eprintln!("{line}");
                    }
                }
                Err(error) => eprintln!("web-capacity static host refresh error: {error}"),
            }
        }
    }
    async fn retention_purge_loop(&self) {
        let mut interval =
            tokio::time::interval(Duration::from_secs(RETENTION_PURGE_INTERVAL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let purge = now_seconds().and_then(|now| {
                self.inner
                    .store
                    .purge_expired(now, ACCESS_LOG_RETENTION_SECONDS)
            });
            if let Err(error) = purge {
                eprintln!("web-capacity retention purge error: {error}");
            }
        }
    }


    pub fn queue_restore(
        &self,
        session_token: &str,
        origin: &str,
        coordinate: InventoryRow,
    ) -> Result<String> {
        let origin = canonical_https_origin(origin)?;
        let now = now_seconds()?;
        let token_hash = session_token_hash(session_token, &origin)?;
        let session = self
            .inner
            .store
            .active_session(token_hash, &origin, now, false)?
            .ok_or_else(|| WebCapacityError::Unauthorized("session is inactive".to_owned()))?;
        validate_inventory_coordinate(&self.inner.canonical_manifest, &coordinate)?;
        let coordinate_json = serde_json::to_value(&coordinate).map_err(|error| {
            WebCapacityError::InvalidRecord(format!("encode restore coordinate: {error}"))
        })?;
        let coordinate_bytes = canonical_json(&coordinate_json)?;
        let task_id = domain_hash_hex(
            DomainId::WwmWebRestoreTaskIdV1,
            &[&token_hash, &now.to_le_bytes(), &coordinate_bytes],
        )?;
        let expires_at = now.saturating_add(self.inner.config.restore_lifetime_seconds);
        self.inner.store.queue_restore(
            &task_id,
            token_hash,
            &session.participant_id,
            &origin,
            &coordinate,
            now,
            expires_at,
        )?;
        Ok(task_id)
    }
    pub fn queue_restore_admin(
        &self,
        request: QueueRestoreAdminRequest,
    ) -> Result<QueueRestoreAdminReport> {
        if request.schema != SCHEMA || request.record_kind != "QUEUE_RESTORE_REQUEST" {
            return Err(WebCapacityError::InvalidRecord(
                "admin restore request schema or record kind is invalid".to_owned(),
            ));
        }
        let origin = canonical_https_origin(&request.canonical_origin)?;
        if origin != request.canonical_origin {
            return Err(WebCapacityError::InvalidOrigin(
                "admin restore session origin is not canonical".to_owned(),
            ));
        }
        let source_origin = canonical_https_origin(&request.source_origin)?;
        if source_origin != request.source_origin
            || origin_of_url(&request.coordinate.url)? != source_origin
            || !self
                .inner
                .config
                .source_allowlist
                .iter()
                .any(|source| source.origin == source_origin)
        {
            return Err(WebCapacityError::Forbidden(
                "restore source is not an exact registered allowlisted origin".to_owned(),
            ));
        }
        let now = now_seconds()?;
        if request.expires_at <= now
            || request.expires_at
                > now.saturating_add(self.inner.config.restore_lifetime_seconds)
        {
            return Err(WebCapacityError::InvalidRecord(
                "admin restore expiry is outside the configured bounded lifetime".to_owned(),
            ));
        }
        let token_hash = session_token_hash(&request.session_token, &origin)?;
        let session = self
            .inner
            .store
            .active_session(token_hash, &origin, now, false)?
            .ok_or_else(|| WebCapacityError::Unauthorized("session is inactive".to_owned()))?;
        validate_inventory_coordinate(&self.inner.canonical_manifest, &request.coordinate)?;
        if !self
            .inner
            .store
            .is_verified_inventory_row(&source_origin, &request.coordinate, now)?
        {
            return Err(WebCapacityError::Forbidden(
                "restore coordinate is not on a fresh verified registered host".to_owned(),
            ));
        }
        let coordinate_value = serde_json::to_value(&request.coordinate).map_err(|error| {
            WebCapacityError::InvalidRecord(format!("encode restore coordinate: {error}"))
        })?;
        let coordinate_bytes = canonical_json(&coordinate_value)?;
        let task_id = domain_hash_hex(
            DomainId::WwmWebRestoreTaskIdV1,
            &[
                &token_hash,
                source_origin.as_bytes(),
                &request.expires_at.to_le_bytes(),
                &coordinate_bytes,
            ],
        )?;
        self.inner.store.queue_restore(
            &task_id,
            token_hash,
            &session.participant_id,
            &origin,
            &request.coordinate,
            now,
            request.expires_at,
        )?;
        let task = self.signed_restore_task(store::StoredRestoreTask {
            task_id,
            participant_id: session.participant_id,
            origin,
            coordinate: request.coordinate,
            issued_at: now,
            expires_at: request.expires_at,
        })?;
        Ok(QueueRestoreAdminReport {
            schema: SCHEMA,
            record_kind: "QUEUE_RESTORE_REPORT",
            task,
            source_origin,
            production_custody: false,
            rewards: false,
            insert_once: true,
        })
    }

    /// Creates a signed, local-only export index for one complete restored
    /// position. This method is deliberately not reachable from the router.
    pub fn export_restored_position_index(
        &self,
        target_position: u8,
        generated_at: u64,
        expires_at: u64,
    ) -> Result<SignedRestoredPositionImportIndex> {
        if target_position as usize >= noos_da::ARTIFACT_POSITIONS
            || generated_at >= expires_at
        {
            return Err(WebCapacityError::InvalidRecord(
                "restore import index position or validity interval is invalid".to_owned(),
            ));
        }
        let manifest = &self.inner.canonical_manifest;
        let completed = self
            .inner
            .store
            .completed_restores_for_position(target_position)?;
        if completed.len() != manifest.stripes.len() {
            return Err(WebCapacityError::Conflict(format!(
                "complete position requires exactly {} restored stripes; found {}",
                manifest.stripes.len(),
                completed.len()
            )));
        }
        let quarantine_metadata = fs::symlink_metadata(&self.inner.config.quarantine_dir)
            .map_err(|error| {
                WebCapacityError::Store(format!("inspect quarantine root: {error}"))
            })?;
        if quarantine_metadata.file_type().is_symlink() || !quarantine_metadata.is_dir() {
            return Err(WebCapacityError::Store(
                "quarantine root must be a non-symlink directory".to_owned(),
            ));
        }
        let quarantine_root = fs::canonicalize(&self.inner.config.quarantine_dir)
            .map_err(|error| {
                WebCapacityError::Store(format!("canonicalize quarantine root: {error}"))
            })?;
        let artifact_id = &self.inner.config.chain_binding.artifact_id;
        let mut by_stripe = BTreeMap::new();
        for record in completed {
            let stripe = record.task.coordinate.stripe;
            if by_stripe.insert(stripe, record).is_some() {
                return Err(WebCapacityError::Conflict(format!(
                    "duplicate completed restore stripe {stripe}"
                )));
            }
        }
        let mut rows = Vec::with_capacity(manifest.stripes.len());
        for stripe in &manifest.stripes {
            let record = by_stripe.remove(&stripe.stripe_index).ok_or_else(|| {
                WebCapacityError::Conflict(format!(
                    "missing completed restore stripe {}",
                    stripe.stripe_index
                ))
            })?;
            if record.task.coordinate.position != target_position
                || record.task.coordinate.bytes != SHARE_BYTES
                || record.bytes != SHARE_BYTES
                || record.task.issued_at > generated_at
                || record.task.expires_at <= generated_at
                || expires_at > record.task.expires_at
                || record.accepted_at < record.task.issued_at
                || record.accepted_at > record.task.expires_at
            {
                return Err(WebCapacityError::InvalidRecord(format!(
                    "completed restore lifecycle/coordinate mismatch at stripe {}",
                    stripe.stripe_index
                )));
            }
            validate_inventory_coordinate(manifest, &record.task.coordinate)?;
            let source_origin = origin_of_url(&record.task.coordinate.url)?;
            if !self
                .inner
                .config
                .source_allowlist
                .iter()
                .any(|source| source.origin == source_origin)
            {
                return Err(WebCapacityError::Forbidden(
                    "completed restore source is no longer allowlisted".to_owned(),
                ));
            }
            let coordinate_digest = domain_hash_hex(
                DomainId::WwmWebCoordinateIdV1,
                &[
                    artifact_id.as_bytes(),
                    self.inner.config.chain_binding.manifest_root.as_bytes(),
                    &stripe.stripe_index.to_le_bytes(),
                    &[target_position],
                ],
            )?;
            if coordinate_digest != record.coordinate_digest {
                return Err(WebCapacityError::InvalidRecord(format!(
                    "completed restore coordinate digest mismatch at stripe {}",
                    stripe.stripe_index
                )));
            }
            let expected_quarantine_id = domain_hash_hex(
                DomainId::WwmWebQuarantineIdV1,
                &[
                    record.task.task_id.as_bytes(),
                    coordinate_digest.as_bytes(),
                    record.task.coordinate.transport_sha256.as_bytes(),
                ],
            )?;
            if expected_quarantine_id != record.quarantine_id {
                return Err(WebCapacityError::InvalidRecord(format!(
                    "completed restore quarantine id mismatch at stripe {}",
                    stripe.stripe_index
                )));
            }
            let expected_path = self
                .inner
                .config
                .quarantine_dir
                .join(artifact_id)
                .join(format!("{}.share", record.quarantine_id));
            if record.path != expected_path {
                return Err(WebCapacityError::Store(format!(
                    "completed restore path is not coordinator-derived at stripe {}",
                    stripe.stripe_index
                )));
            }
            let metadata = fs::symlink_metadata(&expected_path).map_err(|error| {
                WebCapacityError::Store(format!(
                    "inspect completed restore stripe {}: {error}",
                    stripe.stripe_index
                ))
            })?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != SHARE_BYTES
            {
                return Err(WebCapacityError::Store(format!(
                    "completed restore file type/length mismatch at stripe {}",
                    stripe.stripe_index
                )));
            }
            let canonical_path = fs::canonicalize(&expected_path).map_err(|error| {
                WebCapacityError::Store(format!(
                    "canonicalize completed restore stripe {}: {error}",
                    stripe.stripe_index
                ))
            })?;
            if !canonical_path.starts_with(&quarantine_root) {
                return Err(WebCapacityError::Store(
                    "completed restore path escapes quarantine root".to_owned(),
                ));
            }
            let bytes = fs::read(&canonical_path).map_err(|error| {
                WebCapacityError::Store(format!(
                    "read completed restore stripe {}: {error}",
                    stripe.stripe_index
                ))
            })?;
            if bytes.len() != ARTIFACT_SHARE_BYTES
                || sha256_hex(&bytes) != record.task.coordinate.transport_sha256
            {
                return Err(WebCapacityError::InvalidRecord(format!(
                    "completed restore transport bytes mismatch at stripe {}",
                    stripe.stripe_index
                )));
            }
            let commitment = share_commitment(stripe.stripe_index, target_position, &bytes)
                .map_err(|error| {
                    WebCapacityError::InvalidRecord(format!(
                        "compute completed restore commitment: {error}"
                    ))
                })?;
            if commitment != stripe.shares[target_position as usize]
                || hex::encode(commitment.share_digest.as_bytes())
                    != record.task.coordinate.protocol_share_digest
                || hex::encode(commitment.probe_root.as_bytes())
                    != record.task.coordinate.probe_root
            {
                return Err(WebCapacityError::InvalidRecord(format!(
                    "completed restore noos-da commitment mismatch at stripe {}",
                    stripe.stripe_index
                )));
            }
            let receipt_task_id = record.task.task_id.clone();
            let receipt_bytes = record.bytes;
            let receipt_quarantine_id = record.quarantine_id;
            let receipt_accepted_at = record.accepted_at;
            let task = self.signed_restore_task(record.task)?;
            rows.push(RestoredPositionImportPair {
                source_origin,
                task,
                receipt: RestoreReceipt {
                    schema: SCHEMA.to_owned(),
                    record_kind: "RESTORE_RECEIPT".to_owned(),
                    task_id: receipt_task_id,
                    coordinate_digest,
                    bytes: receipt_bytes,
                    quarantine_id: receipt_quarantine_id,
                    canonical_verified: true,
                    accepted_at: receipt_accepted_at,
                },
            });
        }
        if !by_stripe.is_empty() {
            return Err(WebCapacityError::Conflict(
                "completed restores contain out-of-manifest stripes".to_owned(),
            ));
        }
        let coordinator_public_key = self.coordinator_public_key();
        let unsigned = json!({
            "schema": SCHEMA,
            "record_kind": RESTORE_IMPORT_INDEX_RECORD_KIND,
            "coordinator_public_key": coordinator_public_key,
            "chain_binding": self.inner.config.chain_binding,
            "target_position": target_position,
            "generated_at": generated_at,
            "expires_at": expires_at,
            "rows": rows,
        });
        let signature = sign_json(
            &self.inner.signer,
            DomainId::SigWwmWebRestoreImportIndexV1,
            &unsigned,
        )?;
        Ok(SignedRestoredPositionImportIndex {
            schema: SCHEMA.to_owned(),
            record_kind: RESTORE_IMPORT_INDEX_RECORD_KIND.to_owned(),
            coordinator_public_key: self.coordinator_public_key(),
            chain_binding: self.inner.config.chain_binding.clone(),
            target_position,
            generated_at,
            expires_at,
            rows,
            signature: signature_value(
                RESTORE_IMPORT_INDEX_SIGNATURE_DOMAIN,
                self.coordinator_public_key(),
                signature,
            ),
        })
    }

    /// Releases quarantine only after a signed export index is bound to the
    /// artifact service's create-new successful import evidence.
    pub fn release_restored_position(
        &self,
        index: &SignedRestoredPositionImportIndex,
        evidence: &WebRestoredPositionImportEvidence,
        released_at: u64,
    ) -> Result<RestoredPositionReleaseReport> {
        if index.schema != SCHEMA
            || index.record_kind != RESTORE_IMPORT_INDEX_RECORD_KIND
            || index.coordinator_public_key != self.coordinator_public_key()
            || index.chain_binding != self.inner.config.chain_binding
            || index.generated_at >= index.expires_at
            || index.target_position as usize >= noos_da::ARTIFACT_POSITIONS
        {
            return Err(WebCapacityError::InvalidRecord(
                "restore release index identity is invalid".to_owned(),
            ));
        }
        if index.signature.suite != "Ed25519"
            || index.signature.domain != RESTORE_IMPORT_INDEX_SIGNATURE_DOMAIN
            || index.signature.public_key != self.coordinator_public_key()
        {
            return Err(WebCapacityError::InvalidSignature);
        }
        let mut unsigned_index = serde_json::to_value(index).map_err(|error| {
            WebCapacityError::InvalidRecord(format!("encode restore release index: {error}"))
        })?;
        unsigned_index
            .as_object_mut()
            .ok_or_else(|| {
                WebCapacityError::InvalidRecord(
                    "restore release index is not an object".to_owned(),
                )
            })?
            .remove("signature");
        verify_json_signature(
            DomainId::SigWwmWebRestoreImportIndexV1,
            &index.coordinator_public_key,
            &index.signature.signature,
            &unsigned_index,
        )?;
        let canonical_index = canonical_json(
            &serde_json::to_value(index).map_err(|error| {
                WebCapacityError::InvalidRecord(format!(
                    "encode signed restore release index: {error}"
                ))
            })?,
        )?;
        let import_index_sha256 = sha256_hex(&canonical_index);
        let manifest = &self.inner.canonical_manifest;
        let expected_bytes = (manifest.stripes.len() as u64)
            .checked_mul(SHARE_BYTES)
            .ok_or_else(|| {
                WebCapacityError::InvalidRecord("restore release byte overflow".to_owned())
            })?;
        if evidence.schema != "noos.wwm.web-restored-position-import-evidence.v1"
            || evidence.coordinator_public_key != index.coordinator_public_key
            || evidence.chain_id != index.chain_binding.chain_id
            || evidence.genesis_hash != index.chain_binding.genesis_hash
            || evidence.artifact_id != index.chain_binding.artifact_id
            || evidence.manifest_root != index.chain_binding.manifest_root
            || evidence.protocol_payload_root
                != hex::encode(manifest.protocol_payload_root.as_bytes())
            || evidence.published_sha256 != hex::encode(manifest.published_sha256)
            || evidence.position_root
                != hex::encode(manifest.position_roots[index.target_position as usize].as_bytes())
            || evidence.import_index_sha256 != import_index_sha256
            || evidence.target_position != index.target_position
            || evidence.stripe_count as usize != manifest.stripes.len()
            || evidence.imported_share_count as usize != manifest.stripes.len()
            || evidence.imported_bytes != expected_bytes
            || evidence.production_custody
            || evidence.availability_certificate_effect
            || evidence.rewards
            || !evidence.insert_once
        {
            return Err(WebCapacityError::InvalidRecord(
                "artifact import evidence does not bind this complete non-promoting position"
                    .to_owned(),
            ));
        }
        if index.rows.len() != manifest.stripes.len() {
            return Err(WebCapacityError::Conflict(
                "restore release index is not a complete position".to_owned(),
            ));
        }
        let completed = self
            .inner
            .store
            .completed_restores_for_position(index.target_position)?;
        let mut stored_by_stripe = BTreeMap::new();
        for record in completed {
            let stripe = record.task.coordinate.stripe;
            if stored_by_stripe.insert(stripe, record).is_some() {
                return Err(WebCapacityError::Conflict(
                    "duplicate completed restore during release".to_owned(),
                ));
            }
        }
        let artifact_dir = self
            .inner
            .config
            .quarantine_dir
            .join(&index.chain_binding.artifact_id);
        let artifact_metadata = fs::symlink_metadata(&artifact_dir).map_err(|error| {
            WebCapacityError::Store(format!("inspect release quarantine directory: {error}"))
        })?;
        if artifact_metadata.file_type().is_symlink() || !artifact_metadata.is_dir() {
            return Err(WebCapacityError::Store(
                "release quarantine directory must be a non-symlink directory".to_owned(),
            ));
        }
        let mut paths = Vec::with_capacity(index.rows.len());
        let mut release_pairs = Vec::with_capacity(index.rows.len());
        for (expected_stripe, row) in index.rows.iter().enumerate() {
            if row.task.schema != SCHEMA
                || row.task.record_kind != "RESTORE_TASK"
                || row.receipt.schema != SCHEMA
                || row.receipt.record_kind != "RESTORE_RECEIPT"
                || row.task.chain_binding != index.chain_binding
                || row.task.coordinate.stripe != expected_stripe as u32
                || row.task.coordinate.position != index.target_position
                || row.receipt.task_id != row.task.task_id
                || row.receipt.bytes != SHARE_BYTES
            {
                return Err(WebCapacityError::InvalidRecord(
                    "restore release task/receipt identity is invalid".to_owned(),
                ));
            }
            if row.task.signature.suite != "Ed25519"
                || row.task.signature.domain != RESTORE_TASK_SIGNATURE_DOMAIN
                || row.task.signature.public_key != index.coordinator_public_key
            {
                return Err(WebCapacityError::InvalidSignature);
            }
            let mut unsigned_task = serde_json::to_value(&row.task).map_err(|error| {
                WebCapacityError::InvalidRecord(format!(
                    "encode restore release task: {error}"
                ))
            })?;
            unsigned_task
                .as_object_mut()
                .ok_or_else(|| {
                    WebCapacityError::InvalidRecord(
                        "restore release task is not an object".to_owned(),
                    )
                })?
                .remove("signature");
            verify_json_signature(
                DomainId::SigWwmWebRestoreTaskV1,
                &index.coordinator_public_key,
                &row.task.signature.signature,
                &unsigned_task,
            )?;
            if origin_of_url(&row.task.coordinate.url)? != row.source_origin {
                return Err(WebCapacityError::InvalidOrigin(
                    "restore release source origin mismatch".to_owned(),
                ));
            }
            let stored = stored_by_stripe
                .remove(&(expected_stripe as u32))
                .ok_or_else(|| {
                    WebCapacityError::Conflict(format!(
                        "missing completed restore release stripe {expected_stripe}"
                    ))
                })?;
            if stored.task.task_id != row.task.task_id
                || stored.task.participant_id != row.task.participant_id
                || stored.task.origin != row.task.canonical_origin
                || stored.task.coordinate != row.task.coordinate
                || stored.task.issued_at != row.task.issued_at
                || stored.task.expires_at != row.task.expires_at
                || stored.quarantine_id != row.receipt.quarantine_id
                || stored.coordinate_digest != row.receipt.coordinate_digest
                || stored.bytes != row.receipt.bytes
                || stored.accepted_at != row.receipt.accepted_at
            {
                return Err(WebCapacityError::Conflict(
                    "restore release index differs from completed coordinator state".to_owned(),
                ));
            }
            let expected_path = artifact_dir.join(format!("{}.share", row.receipt.quarantine_id));
            if stored.path != expected_path {
                return Err(WebCapacityError::Store(
                    "restore release path is not coordinator-derived".to_owned(),
                ));
            }
            if let Ok(metadata) = fs::symlink_metadata(&expected_path) {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(WebCapacityError::Store(
                        "restore release refuses a non-regular quarantine path".to_owned(),
                    ));
                }
            }
            paths.push(expected_path);
            release_pairs.push((
                row.task.task_id.clone(),
                row.receipt.quarantine_id.clone(),
            ));
        }
        if !stored_by_stripe.is_empty() {
            return Err(WebCapacityError::Conflict(
                "unexpected completed restore rows during release".to_owned(),
            ));
        }
        for path in &paths {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(WebCapacityError::Store(format!(
                        "delete released quarantine share {}: {error}",
                        path.display()
                    )));
                }
            }
        }
        self.inner.store.release_completed_restores(
            &import_index_sha256,
            &index.chain_binding.artifact_id,
            &index.chain_binding.manifest_root,
            index.target_position,
            &release_pairs,
            expected_bytes,
            released_at,
        )?;
        Ok(RestoredPositionReleaseReport {
            schema: "noos.wwm.web-restored-position-release.v1",
            artifact_id: index.chain_binding.artifact_id.clone(),
            manifest_root: index.chain_binding.manifest_root.clone(),
            import_index_sha256,
            target_position: index.target_position,
            released_share_count: index.rows.len() as u32,
            released_bytes: expected_bytes,
            released_at,
            production_custody: false,
            availability_certificate_effect: false,
            rewards: false,
            insert_once: true,
        })
    }


    fn config_response(&self) -> CoordinatorConfigResponse {
        CoordinatorConfigResponse {
            schema: SCHEMA,
            record_kind: "COORDINATOR_CONFIG",
            chain_binding: self.inner.config.chain_binding.clone(),
            geometry: model::Geometry::bonsai(),
            experiment_state: self.inner.config.experiment_state,
            coordinator_key: self.coordinator_public_key(),
            source_allowlist: self
                .inner
                .config
                .source_allowlist
                .iter()
                .map(|source| source.origin.clone())
                .collect(),
            quota_choices_shares: [16, 64, 256],
            privacy: model::PrivacyDisclosure::strict(),
            static_cache_lifecycle: StaticCacheLifecycleDisclosure {
                host_refresh_max_seconds: HOST_REFRESH_INTERVAL_SECONDS,
                expiry_effect: "REMOVES_FUTURE_ASSIGNMENTS_ONLY",
                public_share_license: "Apache-2.0",
                cached_bytes_may_remain_public: true,
                third_party_cache_erasure_available: false,
            },
            participant_classes: ["STATIC_HOST_SEEDER", "BROWSER_ADVISORY_CACHE"],
            production_custody: false,
            rewards: false,
            browser_execution: "STORAGE_AND_OPT_IN_REPAIR_ONLY",
        }
    }

    fn authorize_mutation(&self, headers: &HeaderMap, route: &str) -> Result<String> {
        let value = headers
            .get(header::ORIGIN)
            .ok_or_else(|| WebCapacityError::Forbidden("Origin header is required".to_owned()))?
            .to_str()
            .map_err(|_| WebCapacityError::Forbidden("Origin header is not UTF-8".to_owned()))?;
        let origin = canonical_https_origin(value)?;
        if !self.inner.config.registered_origins.contains(&origin) {
            return Err(WebCapacityError::Forbidden(
                "Origin is not in the explicit mutation allowlist".to_owned(),
            ));
        }
        let now = now_seconds()?;
        if !self.inner.store.check_rate_limit(
            &origin,
            route,
            now,
            self.inner.config.rate_limit_per_minute,
        )? {
            return Err(WebCapacityError::RateLimited);
        }
        Ok(origin)
    }

    fn authenticate_session(
        &self,
        token: &str,
        origin: &str,
        now: u64,
        mark_active: bool,
    ) -> Result<SessionRecord> {
        let token_hash = session_token_hash(token, origin)?;
        self.inner
            .store
            .active_session(token_hash, origin, now, mark_active)?
            .ok_or_else(|| {
                WebCapacityError::Unauthorized(
                    "session is missing, expired, revoked, or bound to another origin".to_owned(),
                )
            })
    }

    fn create_assignment(
        &self,
        session: &SessionRecord,
        now: u64,
        available_bytes: u64,
        stored_coordinate_digests: &[String],
    ) -> Result<Option<ShareAssignment>> {
        let maximum = usize::from(session.quota_shares)
            .min(usize::try_from(available_bytes / SHARE_BYTES).unwrap_or(0))
            .min(MAX_ASSIGNMENT_ROWS);
        if maximum == 0 {
            return Ok(None);
        }
        let excluded = stored_coordinate_digests
            .iter()
            .map(|digest| decode_hex32(digest))
            .collect::<Result<Vec<_>>>()?;
        self.inner.store.reserve_assignment(
            session.token_hash,
            now,
            maximum,
            &excluded,
            |stored_rows| {
                let public_rows = stored_rows
                    .iter()
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>();
                let rows_value = serde_json::to_value(&public_rows).map_err(|error| {
                    WebCapacityError::InvalidRecord(format!("encode assignment rows: {error}"))
                })?;
                let rows_bytes = canonical_json(&rows_value)?;
                let assignment_id = domain_hash_hex(
                    DomainId::WwmWebAssignmentIdV1,
                    &[&session.token_hash, &now.to_le_bytes(), &rows_bytes],
                )?;
                let expires_at =
                    now.saturating_add(self.inner.config.assignment_lifetime_seconds);
                let unsigned = json!({
                    "schema": SCHEMA,
                    "record_kind": "SHARE_ASSIGNMENT",
                    "assignment_id": assignment_id,
                    "participant_id": session.participant_id,
                    "canonical_origin": session.origin,
                    "chain_binding": self.inner.config.chain_binding,
                    "issued_at": now,
                    "expires_at": expires_at,
                    "rows": public_rows,
                });
                let signature = sign_json(
                    &self.inner.signer,
                    DomainId::SigWwmWebAssignmentV1,
                    &unsigned,
                )?;
                let mut signed = unsigned;
                signed
                    .as_object_mut()
                    .ok_or_else(|| {
                        WebCapacityError::Internal(
                            "assignment serialization was not an object".to_owned(),
                        )
                    })?
                    .insert(
                        "signature".to_owned(),
                        serde_json::to_value(signature_value(
                            ASSIGNMENT_SIGNATURE_DOMAIN,
                            self.coordinator_public_key(),
                            signature,
                        ))
                        .map_err(|error| {
                            WebCapacityError::Internal(format!(
                                "encode assignment signature: {error}"
                            ))
                        })?,
                    );
                let assignment: ShareAssignment =
                    serde_json::from_value(signed.clone()).map_err(|error| {
                        WebCapacityError::Internal(format!(
                            "decode signed assignment: {error}"
                        ))
                    })?;
                let body_json = serde_json::to_string(&signed).map_err(|error| {
                    WebCapacityError::Internal(format!("encode signed assignment: {error}"))
                })?;
                Ok((
                    assignment.assignment_id.clone(),
                    body_json,
                    expires_at,
                    assignment,
                ))
            },
        )
    }

    fn signed_restore_task(&self, stored: store::StoredRestoreTask) -> Result<RestoreTask> {
        let unsigned = json!({
            "schema": SCHEMA,
            "record_kind": "RESTORE_TASK",
            "task_id": stored.task_id,
            "participant_id": stored.participant_id,
            "canonical_origin": stored.origin,
            "chain_binding": self.inner.config.chain_binding,
            "coordinate": stored.coordinate,
            "expected_bytes": SHARE_BYTES,
            "issued_at": stored.issued_at,
            "expires_at": stored.expires_at,
        });
        let signature = sign_json(
            &self.inner.signer,
            DomainId::SigWwmWebRestoreTaskV1,
            &unsigned,
        )?;
        let mut signed = unsigned;
        signed
            .as_object_mut()
            .ok_or_else(|| {
                WebCapacityError::Internal(
                    "restore task serialization was not an object".to_owned(),
                )
            })?
            .insert(
                "signature".to_owned(),
                serde_json::to_value(signature_value(
                    RESTORE_TASK_SIGNATURE_DOMAIN,
                    self.coordinator_public_key(),
                    signature,
                ))
                .map_err(|error| {
                    WebCapacityError::Internal(format!("encode restore signature: {error}"))
                })?,
            );
        serde_json::from_value(signed).map_err(|error| {
            WebCapacityError::Internal(format!("decode signed restore task: {error}"))
        })
    }
}

async fn cors_privacy_middleware(
    State(service): State<WebCapacityService>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let mutation = mutation_route(&path);
    let request_method = request.method().clone();
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let now = match now_seconds() {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if let Err(error) = service
        .inner
        .store
        .purge_expired(now, ACCESS_LOG_RETENTION_SECONDS)
    {
        return error_response(error);
    }
    let Some(route) = mutation else {
        let mut response = next.run(request).await;
        if path == "/api/wwm-web-capacity/v1/config" {
            if let Some(allowed) = origin
                .as_deref()
                .and_then(|value| allowed_origin(&service, value).ok())
            {
                apply_actual_cors(&mut response, &allowed);
            }
        }
        return response;
    };
    let allowed = match origin
        .as_deref()
        .ok_or_else(|| WebCapacityError::Forbidden("Origin header is required".to_owned()))
        .and_then(|value| allowed_origin(&service, value))
    {
        Ok(value) => value,
        Err(error) => {
            record_access_observation(&service, &request, route.label, now, false);
            return error_response(error);
        }
    };
    record_access_observation(&service, &request, route.label, now, true);
    if request_method == Method::OPTIONS {
        return match validate_preflight(&request, route) {
            Ok(()) => preflight_response(&allowed, route),
            Err(error) => {
                let mut response = error_response(error);
                apply_actual_cors(&mut response, &allowed);
                response
            }
        };
    }
    let mut response = next.run(request).await;
    apply_actual_cors(&mut response, &allowed);
    response
}

#[derive(Clone, Copy)]
struct MutationRoute {
    label: &'static str,
    method: &'static str,
    allow_headers: &'static str,
}

fn mutation_route(path: &str) -> Option<MutationRoute> {
    match path {
        "/api/wwm-web-capacity/v1/hosts" => Some(MutationRoute {
            label: "hosts",
            method: "POST",
            allow_headers: "content-type",
        }),
        "/api/wwm-web-capacity/v1/offers" => Some(MutationRoute {
            label: "offers",
            method: "POST",
            allow_headers: "content-type",
        }),
        "/api/wwm-web-capacity/v1/heartbeat" => Some(MutationRoute {
            label: "heartbeat",
            method: "POST",
            allow_headers: "content-type",
        }),
        "/api/wwm-web-capacity/v1/reports" => Some(MutationRoute {
            label: "reports",
            method: "POST",
            allow_headers: "content-type",
        }),
        "/api/wwm-web-capacity/v1/revoke" => Some(MutationRoute {
            label: "revoke",
            method: "POST",
            allow_headers: "content-type",
        }),
        value if value.starts_with("/api/wwm-web-capacity/v1/restores/") => Some(MutationRoute {
            label: "restores",
            method: "PUT",
            allow_headers: "authorization, content-type",
        }),
        _ => None,
    }
}

fn allowed_origin(service: &WebCapacityService, value: &str) -> Result<String> {
    let origin = canonical_https_origin(value)?;
    if !service.inner.config.registered_origins.contains(&origin) {
        return Err(WebCapacityError::Forbidden(
            "Origin is not in the explicit mutation allowlist".to_owned(),
        ));
    }
    Ok(origin)
}

fn validate_preflight(request: &Request<Body>, route: MutationRoute) -> Result<()> {
    let requested_method = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            WebCapacityError::Forbidden("preflight lacks Access-Control-Request-Method".to_owned())
        })?;
    if requested_method != route.method {
        return Err(WebCapacityError::Forbidden(
            "preflight method is not authorized for this route".to_owned(),
        ));
    }
    let allowed = route
        .allow_headers
        .split(',')
        .map(str::trim)
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(requested) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
    {
        for name in requested
            .split(',')
            .map(|value| value.trim().to_ascii_lowercase())
        {
            if name.is_empty() || !allowed.contains(name.as_str()) {
                return Err(WebCapacityError::Forbidden(
                    "preflight requested an unauthorized header".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn preflight_response(origin: &str, route: MutationRoute) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(route.method),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(route.allow_headers),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    headers.insert(
        header::VARY,
        HeaderValue::from_static(
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn apply_actual_cors(response: &mut Response, origin: &str) {
    if let Ok(value) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Origin"));
    response
        .headers_mut()
        .remove(HeaderName::from_static("access-control-allow-credentials"));
}

fn record_access_observation(
    service: &WebCapacityService,
    request: &Request<Body>,
    route: &str,
    now: u64,
    allowed: bool,
) {
    let ip_prefix = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| truncate_ip(address.ip()))
        .unwrap_or_else(|| "unknown".to_owned());
    let coarse_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(coarse_user_agent)
        .unwrap_or("Unknown");
    let _ = service
        .inner
        .store
        .record_access(now, &ip_prefix, coarse_agent, route, allowed);
}

fn truncate_ip(address: IpAddr) -> String {
    match address {
        IpAddr::V4(value) => {
            let octets = value.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
        }
    }
}

fn coarse_user_agent(value: &str) -> &'static str {
    let lowered = value.to_ascii_lowercase();
    if lowered.contains("firefox") {
        "Firefox"
    } else if lowered.contains("edg/")
        || lowered.contains("chrome/")
        || lowered.contains("chromium")
    {
        "Chromium"
    } else if lowered.contains("applewebkit") || lowered.contains("safari/") {
        "WebKit"
    } else {
        "Other"
    }
}

async fn config_handler(State(service): State<WebCapacityService>) -> Response {
    let now = match now_seconds() {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if let Err(error) = service
        .inner
        .store
        .purge_expired(now, ACCESS_LOG_RETENTION_SECONDS)
    {
        return error_response(error);
    }
    let mut response = json_response(StatusCode::OK, &service.config_response());
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60, must-revalidate"),
    );
    response
}

async fn register_host_handler(
    State(service): State<WebCapacityService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<HostRegistrationRequest>, JsonRejection>,
) -> Response {
    let result = async {
        service.authorize_mutation(&headers, "hosts")?;
        let request = json_payload(payload)?;
        if request.schema != SCHEMA || request.record_kind != "HOST_REGISTRATION_REQUEST" {
            return Err(WebCapacityError::InvalidRecord(
                "host registration schema or record kind is invalid".to_owned(),
            ));
        }
        let origin = canonical_https_origin(&request.canonical_origin)?;
        let source = service
            .inner
            .config
            .source_allowlist
            .iter()
            .find(|source| source.origin == origin)
            .cloned()
            .ok_or_else(|| {
                WebCapacityError::Forbidden("static origin is not owner-authorized".to_owned())
            })?;
        let verified = service.inner.host_verifier.verify(source).await?;
        service.inner.store.replace_host(
            &verified.host_id,
            &verified.source.provider,
            &verified.source.region,
            &verified.source.control_cluster,
            &verified.manifest,
            &verified.inventory,
        )?;
        Ok(HostRegistrationResponse {
            schema: SCHEMA,
            record_kind: "HOST_REGISTRATION_RESPONSE",
            host_id: verified.host_id,
            canonical_origin: verified.manifest.canonical_origin,
            participant_class: "STATIC_HOST_SEEDER",
            admission_class: "StatelessReissueable",
            inventory_root: verified.inventory.inventory_root,
            verified_rows: verified.inventory.rows.len(),
            expires_at: verified.manifest.expires_at,
            production_custody: false,
            rewards: false,
        })
    }
    .await;
    match result {
        Ok(value) => json_response(StatusCode::CREATED, &value),
        Err(error) => error_response(error),
    }
}

async fn offer_handler(
    State(service): State<WebCapacityService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<OfferRequest>, JsonRejection>,
) -> Response {
    let result = (|| {
        let origin = service.authorize_mutation(&headers, "offers")?;
        let request = json_payload(payload)?;
        if matches!(
            service.inner.config.experiment_state,
            ExperimentState::Disabled | ExperimentState::Closed
        ) {
            return Err(WebCapacityError::Forbidden(
                "web capacity experiment is not accepting offers".to_owned(),
            ));
        }
        validate_offer(&service.inner.config, &request, &origin)?;
        let now = now_seconds()?;
        let expires_at = now.saturating_add(service.inner.config.session_lifetime_seconds);
        let mut raw_token = [0_u8; 32];
        getrandom::getrandom(&mut raw_token).map_err(|error| {
            WebCapacityError::Internal(format!("obtain session entropy: {error}"))
        })?;
        let session_token = URL_SAFE_NO_PAD.encode(raw_token);
        let token_hash = domain_hash(
            DomainId::WwmWebSessionTokenV1,
            &[origin.as_bytes(), &raw_token],
        )?;
        let participant_id = domain_hash_hex(
            DomainId::WwmWebParticipantIdV1,
            &[origin.as_bytes(), &token_hash],
        )?;
        service.inner.store.create_session(
            token_hash,
            &participant_id,
            &origin,
            &request.consent_version,
            request.quota_shares,
            request.effective_bytes,
            request.storage_class,
            &request.upload_policy,
            now,
            expires_at,
        )?;
        Ok(BrowserSession {
            schema: SCHEMA,
            record_kind: "BROWSER_SESSION",
            participant_class: "BROWSER_ADVISORY_CACHE",
            admission_class: "ChorusAdvisory",
            session_token,
            participant_id,
            canonical_origin: origin,
            quota_shares: request.quota_shares,
            effective_bytes: request.effective_bytes,
            storage_class: request.storage_class,
            upload_policy: request.upload_policy,
            issued_at: now,
            expires_at,
            production_custody: false,
            rewards: false,
        })
    })();
    match result {
        Ok(value) => json_response(StatusCode::CREATED, &value),
        Err(error) => error_response(error),
    }
}

async fn heartbeat_handler(
    State(service): State<WebCapacityService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<HeartbeatRequest>, JsonRejection>,
) -> Response {
    let result = (|| {
        let origin = service.authorize_mutation(&headers, "heartbeat")?;
        let request = json_payload(payload)?;
        validate_heartbeat(&request, &origin)?;
        let now = now_seconds()?;
        let session = service.authenticate_session(&request.session_token, &origin, now, true)?;
        if request.available_bytes > session.effective_bytes {
            return Err(WebCapacityError::Quota(
                "reported available bytes exceed the consented effective bound".to_owned(),
            ));
        }
        let restore_task = service
            .inner
            .store
            .pending_restore(session.token_hash, now)?
            .map(|task| service.signed_restore_task(task))
            .transpose()?;
        let assignment = if restore_task.is_none() {
            service.create_assignment(
                &session,
                now,
                request.available_bytes,
                &request.stored_coordinate_digests,
            )?
        } else {
            None
        };
        Ok(HeartbeatResponse {
            schema: SCHEMA,
            record_kind: "HEARTBEAT_RESPONSE",
            server_time: now,
            assignment,
            restore_task,
        })
    })();
    match result {
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(error) => error_response(error),
    }
}

async fn report_handler(
    State(service): State<WebCapacityService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<ParticipantReport>, JsonRejection>,
) -> Response {
    let result = (|| {
        let origin = service.authorize_mutation(&headers, "reports")?;
        let report = json_payload(payload)?;
        validate_report(&report, &origin)?;
        let now = now_seconds()?;
        let session = service.authenticate_session(&report.session_token, &origin, now, true)?;
        if u64::from(report.stored_count).saturating_mul(SHARE_BYTES) > session.effective_bytes
            || report.uploaded_bytes > session.upload_policy.daily_egress_bytes
        {
            return Err(WebCapacityError::Quota(
                "reported storage or upload exceeds the consented bound".to_owned(),
            ));
        }
        service
            .inner
            .store
            .record_report(session.token_hash, &report, now)?;
        Ok(Acknowledgement {
            schema: SCHEMA,
            record_kind: "ACKNOWLEDGEMENT",
            accepted: true,
            server_time: now,
        })
    })();
    match result {
        Ok(value) => json_response(StatusCode::ACCEPTED, &value),
        Err(error) => error_response(error),
    }
}

async fn revoke_handler(
    State(service): State<WebCapacityService>,
    headers: HeaderMap,
    payload: std::result::Result<Json<RevocationRequest>, JsonRejection>,
) -> Response {
    let result = (|| {
        let origin = service.authorize_mutation(&headers, "revoke")?;
        let request = json_payload(payload)?;
        validate_revocation(&request, &origin)?;
        let now = now_seconds()?;
        let token_hash = session_token_hash(&request.session_token, &origin)?;
        if !service
            .inner
            .store
            .revoke_session(token_hash, &origin, now)?
        {
            return Err(WebCapacityError::Unauthorized(
                "session is absent or already revoked".to_owned(),
            ));
        }
        Ok(RevocationResponse {
            schema: SCHEMA,
            record_kind: "REVOCATION_RESPONSE",
            revoked: true,
            assignments_expired: true,
            local_deletion_authority: "CLIENT_ALWAYS_AVAILABLE_OFFLINE",
        })
    })();
    match result {
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(error) => error_response(error),
    }
}

async fn restore_handler(
    State(service): State<WebCapacityService>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = (|| {
        let origin = service.authorize_mutation(&headers, "restores")?;
        decode_hex32(&task_id)?;
        let token = bearer_token(&headers)?;
        let now = now_seconds()?;
        let session = service.authenticate_session(token, &origin, now, false)?;
        if now.saturating_sub(session.last_active_at) > ACTIVE_PAGE_WINDOW_SECONDS {
            return Err(WebCapacityError::Forbidden(
                "restore upload requires a recent active-page heartbeat".to_owned(),
            ));
        }
        let content_length = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if content_length != Some(ARTIFACT_SHARE_BYTES) || body.len() != ARTIFACT_SHARE_BYTES {
            return Err(WebCapacityError::InvalidRecord(
                "restore body must be exactly one 1,047,552-byte share".to_owned(),
            ));
        }
        let task = service
            .inner
            .store
            .begin_restore(&task_id, session.token_hash, &origin, now)?;
        let verify_result =
            verify_restore_body(&service.inner.canonical_manifest, &task.coordinate, &body);
        if let Err(error) = verify_result {
            let _ = service
                .inner
                .store
                .fail_restore(&task_id, "CANONICAL_VERIFICATION_FAILED");
            return Err(error);
        }
        let coordinate_digest = domain_hash_hex(
            DomainId::WwmWebCoordinateIdV1,
            &[
                service.inner.config.chain_binding.artifact_id.as_bytes(),
                service.inner.config.chain_binding.manifest_root.as_bytes(),
                &task.coordinate.stripe.to_le_bytes(),
                &[task.coordinate.position],
            ],
        )?;
        let quarantine_id = domain_hash_hex(
            DomainId::WwmWebQuarantineIdV1,
            &[
                task_id.as_bytes(),
                coordinate_digest.as_bytes(),
                sha256_hex(&body).as_bytes(),
            ],
        )?;
        let final_path = write_quarantine(
            &service.inner.config.quarantine_dir,
            &service.inner.config.chain_binding.artifact_id,
            &quarantine_id,
            &body,
        )?;
        if let Err(error) = service.inner.store.complete_restore(
            &task_id,
            session.token_hash,
            &quarantine_id,
            &coordinate_digest,
            &final_path,
            now,
            SHARE_BYTES,
        ) {
            let _ = fs::remove_file(&final_path);
            let _ = service.inner.store.fail_restore(&task_id, "COMMIT_FAILED");
            return Err(error);
        }
        Ok(RestoreReceipt {
            schema: SCHEMA.to_owned(),
            record_kind: "RESTORE_RECEIPT".to_owned(),
            task_id,
            coordinate_digest,
            bytes: SHARE_BYTES,
            quarantine_id,
            canonical_verified: true,
            accepted_at: now,
        })
    })();
    match result {
        Ok(value) => json_response(StatusCode::CREATED, &value),
        Err(error) => error_response(error),
    }
}

fn validate_offer(
    config: &WebCapacityConfig,
    request: &OfferRequest,
    origin: &str,
) -> Result<()> {
    if request.schema != SCHEMA
        || request.record_kind != "OFFER_REQUEST"
        || request.canonical_origin != origin
        || request.consent_version != config.consent_version
        || !request.page_active
        || !matches!(request.quota_shares, 16 | 64 | 256)
        || request.effective_bytes < SHARE_BYTES
        || !request.effective_bytes.is_multiple_of(SHARE_BYTES)
        || request.effective_bytes > u64::from(request.quota_shares).saturating_mul(SHARE_BYTES)
    {
        return Err(WebCapacityError::InvalidRecord(
            "offer identity, consent, quota, effective bytes, or active-page assertion is invalid"
                .to_owned(),
        ));
    }
    if (!request.upload_policy.enabled && request.upload_policy.daily_egress_bytes != 0)
        || (request.upload_policy.enabled
            && (request.upload_policy.daily_egress_bytes < SHARE_BYTES
                || request.upload_policy.daily_egress_bytes > 256 * SHARE_BYTES))
    {
        return Err(WebCapacityError::InvalidRecord(
            "upload policy is not explicit or exceeds the bounded daily cap".to_owned(),
        ));
    }
    Ok(())
}

fn validate_heartbeat(request: &HeartbeatRequest, origin: &str) -> Result<()> {
    if request.schema != SCHEMA
        || request.record_kind != "HEARTBEAT_REQUEST"
        || request.canonical_origin != origin
        || !request.page_active
        || request.stored_coordinate_digests.len() > MAX_REPORT_DIGESTS
    {
        return Err(WebCapacityError::InvalidRecord(
            "heartbeat identity, origin, active-page assertion, or digest bound is invalid"
                .to_owned(),
        ));
    }
    for digest in &request.stored_coordinate_digests {
        decode_hex32(digest)?;
    }
    Ok(())
}
fn validate_revocation(request: &RevocationRequest, origin: &str) -> Result<()> {
    if request.schema != SCHEMA
        || request.record_kind != "REVOCATION_REQUEST"
        || request.canonical_origin != origin
        || !request.local_deletion_requested
    {
        return Err(WebCapacityError::InvalidRecord(
            "revocation request is invalid or origin-mismatched".to_owned(),
        ));
    }
    Ok(())
}


fn validate_report(report: &ParticipantReport, origin: &str) -> Result<()> {
    if report.schema != SCHEMA
        || report.record_kind != "PARTICIPANT_REPORT"
        || report.canonical_origin != origin
        || !report.page_active
        || report.window_started_at > report.window_ended_at
        || report.coordinate_digests.len() > MAX_REPORT_DIGESTS
        || report.error_codes.len() > MAX_REPORT_ERRORS
        || report.stored_count > 256
        || report.evicted_count > 256
        || report.error_count > MAX_ERROR_COUNT
    {
        return Err(WebCapacityError::InvalidRecord(
            "participant report is unbounded, origin-mismatched, or not active-page telemetry"
                .to_owned(),
        ));
    }
    let mut digests = std::collections::BTreeSet::new();
    for digest in &report.coordinate_digests {
        decode_hex32(digest)?;
        if !digests.insert(digest) {
            return Err(WebCapacityError::InvalidRecord(
                "participant report contains duplicate coordinate digests".to_owned(),
            ));
        }
    }
    let allowed_errors = [
        "QUOTA_CHANGED",
        "STORAGE_PRESSURE",
        "SHARE_EVICTED",
        "DOWNLOAD_ABORTED",
        "UPLOAD_ABORTED",
        "WRONG_LENGTH",
        "WRONG_DIGEST",
        "WRONG_ORIGIN",
        "REDIRECT_REJECTED",
        "ASSIGNMENT_EXPIRED",
        "SESSION_REVOKED",
        "STORAGE_UNAVAILABLE",
        "NETWORK_UNAVAILABLE",
    ];
    let mut errors = std::collections::BTreeSet::new();
    for code in &report.error_codes {
        if !allowed_errors.contains(&code.as_str()) || !errors.insert(code) {
            return Err(WebCapacityError::InvalidRecord(
                "participant report contains an unknown or duplicate error code".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_inventory_coordinate(
    manifest: &ArtifactManifestV1,
    coordinate: &InventoryRow,
) -> Result<()> {
    if coordinate.stripe as usize >= manifest.stripes.len()
        || coordinate.position as usize >= noos_da::artifact::ARTIFACT_POSITIONS
        || coordinate.bytes != SHARE_BYTES
    {
        return Err(WebCapacityError::InvalidRecord(
            "restore coordinate is out of canonical bounds".to_owned(),
        ));
    }
    let expected =
        manifest.stripes[coordinate.stripe as usize].shares[coordinate.position as usize];
    if decode_hex32(&coordinate.protocol_share_digest)? != expected.share_digest.into_bytes()
        || decode_hex32(&coordinate.probe_root)? != expected.probe_root.into_bytes()
        || decode_hex32(&coordinate.transport_sha256).is_err()
    {
        return Err(WebCapacityError::InvalidRecord(
            "restore coordinate differs from the canonical noos-da manifest".to_owned(),
        ));
    }
    Ok(())
}

fn verify_restore_body(
    manifest: &ArtifactManifestV1,
    coordinate: &InventoryRow,
    body: &[u8],
) -> Result<()> {
    validate_inventory_coordinate(manifest, coordinate)?;
    if body.len() != ARTIFACT_SHARE_BYTES || sha256_hex(body) != coordinate.transport_sha256 {
        return Err(WebCapacityError::InvalidRecord(
            "restore share has the wrong byte length or transport SHA-256".to_owned(),
        ));
    }
    let commitment =
        share_commitment(coordinate.stripe, coordinate.position, body).map_err(|error| {
            WebCapacityError::InvalidRecord(format!(
                "canonical noos-da restore verification failed: {error}"
            ))
        })?;
    if commitment.share_digest.into_bytes() != decode_hex32(&coordinate.protocol_share_digest)?
        || commitment.probe_root.into_bytes() != decode_hex32(&coordinate.probe_root)?
    {
        return Err(WebCapacityError::InvalidRecord(
            "restore share differs from the canonical noos-da commitment".to_owned(),
        ));
    }
    Ok(())
}

fn write_quarantine(
    root: &FsPath,
    artifact_id: &str,
    quarantine_id: &str,
    body: &[u8],
) -> Result<PathBuf> {
    let directory = root.join(artifact_id);
    fs::create_dir_all(&directory).map_err(|error| {
        WebCapacityError::Internal(format!("create artifact quarantine: {error}"))
    })?;
    let final_path = directory.join(format!("{quarantine_id}.share"));
    let partial_path = directory.join(format!("{quarantine_id}.partial"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&partial_path)
        .map_err(|error| {
            WebCapacityError::Internal(format!("create quarantine partial: {error}"))
        })?;
    if let Err(error) = file.write_all(body).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&partial_path);
        return Err(WebCapacityError::Internal(format!(
            "durably write quarantine partial: {error}"
        )));
    }
    drop(file);
    if let Err(error) = fs::rename(&partial_path, &final_path) {
        let _ = fs::remove_file(&partial_path);
        return Err(WebCapacityError::Internal(format!(
            "publish quarantine share: {error}"
        )));
    }
    Ok(final_path)
}

fn session_token_hash(token: &str, origin: &str) -> Result<[u8; 32]> {
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| WebCapacityError::Unauthorized("session token is malformed".to_owned()))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| WebCapacityError::Unauthorized("session token is not 256 bits".to_owned()))?;
    domain_hash(DomainId::WwmWebSessionTokenV1, &[origin.as_bytes(), &raw])
}

fn bearer_token(headers: &HeaderMap) -> Result<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| WebCapacityError::Unauthorized("Authorization is required".to_owned()))?
        .to_str()
        .map_err(|_| WebCapacityError::Unauthorized("Authorization is not UTF-8".to_owned()))?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| token.len() == 43)
        .ok_or_else(|| WebCapacityError::Unauthorized("Bearer token is malformed".to_owned()))
}

fn signature_value(domain: &str, public_key: String, signature: String) -> Ed25519Signature {
    Ed25519Signature {
        suite: "Ed25519".to_owned(),
        domain: domain.to_owned(),
        public_key,
        signature,
    }
}

fn json_payload<T>(payload: std::result::Result<Json<T>, JsonRejection>) -> Result<T> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            WebCapacityError::Quota("JSON body exceeds 64 KiB".to_owned())
        } else {
            WebCapacityError::InvalidRecord(format!("invalid JSON body: {rejection}"))
        }
    })
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = Response::new(axum::body::Body::from(body));
            *response.status_mut() = status;
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            response
        }
        Err(error) => {
            let mut response = Response::new(axum::body::Body::from(format!(
                "{{\"schema\":\"{SCHEMA}\",\"record_kind\":\"ERROR\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"response encoding failed: {error}\"}}}}"
            )));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
            response
        }
    }
}

fn error_response(error: WebCapacityError) -> Response {
    let (status, code) = match &error {
        WebCapacityError::Config(_)
        | WebCapacityError::Internal(_)
        | WebCapacityError::Crypto(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
        WebCapacityError::Store(_) => (StatusCode::SERVICE_UNAVAILABLE, "STORE_UNAVAILABLE"),
        WebCapacityError::InvalidOrigin(_) => (StatusCode::BAD_REQUEST, "ORIGIN_MISMATCH"),
        WebCapacityError::Ssrf(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "SSRF_DESTINATION_REJECTED",
        ),
        WebCapacityError::HostFetch(_) => (StatusCode::UNPROCESSABLE_ENTITY, "HOST_FETCH_REJECTED"),
        WebCapacityError::InvalidRecord(_) => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_REQUEST"),
        WebCapacityError::InvalidSignature => {
            (StatusCode::UNPROCESSABLE_ENTITY, "HOST_MANIFEST_INVALID")
        }
        WebCapacityError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "SESSION_INVALID"),
        WebCapacityError::Forbidden(_) => (StatusCode::FORBIDDEN, "ORIGIN_NOT_ALLOWED"),
        WebCapacityError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
        WebCapacityError::Quota(_) => (StatusCode::PAYLOAD_TOO_LARGE, "QUOTA_EXCEEDED"),
        WebCapacityError::Conflict(_) => (StatusCode::CONFLICT, "RESTORE_REPLAYED"),
    };
    json_response(
        status,
        &ErrorResponse {
            schema: SCHEMA,
            record_kind: "ERROR",
            error: ErrorBody {
                code: code.to_owned(),
                message: error.to_string().chars().take(512).collect(),
            },
        },
    )
}

#[cfg(test)]
mod tests;
