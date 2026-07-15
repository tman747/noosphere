use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use noos_da::{ArtifactManifestV1, ARTIFACT_POSITIONS, ARTIFACT_SHARE_BYTES};
use noos_store::ArtifactStore;
use serde::Serialize;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Instant};

use crate::{
    verify_bonsai_store, StoreVerificationReport, BONSAI_ARTIFACT_ID_HEX, BONSAI_MANIFEST_ROOT_HEX,
};

const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const SHARE_CONTENT_TYPE: &str = "application/octet-stream";
const MANIFEST_CONTENT_TYPE: &str = "application/vnd.noos.artifact-manifest-v1";
const EXPOSE_HEADERS: &str =
    "Accept-Ranges, Content-Length, Content-Range, ETag, X-Noos-Probe-Root";
const MAX_CONCURRENCY_LIMIT: usize = 64;
const MAX_QUEUE_CAPACITY: usize = 1_024;
const MAX_TRACKED_CLIENTS_LIMIT: usize = 100_000;
const MAX_REQUEST_METADATA_LIMIT: usize = 64 * 1024;
const MAX_RATE_LIMIT: u32 = 10_000;
const MAX_EGRESS_RATE: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactHttpConfig {
    pub max_concurrent_requests: usize,
    pub queue_capacity: usize,
    pub per_client_requests_per_second: u32,
    pub max_tracked_clients: usize,
    pub max_request_metadata_bytes: usize,
    pub max_range_bytes: usize,
    pub queue_wait_millis: u64,
    pub egress_bytes_per_second: u64,
    pub egress_wait_millis: u64,
}

impl Default for ArtifactHttpConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 4,
            queue_capacity: 16,
            per_client_requests_per_second: 128,
            max_tracked_clients: 4_096,
            max_request_metadata_bytes: 16 * 1024,
            max_range_bytes: ARTIFACT_SHARE_BYTES,
            queue_wait_millis: 2_000,
            egress_bytes_per_second: 64 * 1024 * 1024,
            egress_wait_millis: 5_000,
        }
    }
}

impl ArtifactHttpConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_concurrent_requests == 0 || self.max_concurrent_requests > MAX_CONCURRENCY_LIMIT
        {
            return Err("max concurrent requests outside 1..=64".into());
        }
        if self.queue_capacity > MAX_QUEUE_CAPACITY {
            return Err("queue capacity exceeds 1024".into());
        }
        if self
            .max_concurrent_requests
            .checked_add(self.queue_capacity)
            .is_none()
        {
            return Err("request admission capacity overflow".into());
        }
        if self.per_client_requests_per_second == 0
            || self.per_client_requests_per_second > MAX_RATE_LIMIT
        {
            return Err("per-client rate outside 1..=10000".into());
        }
        if self.max_tracked_clients == 0 || self.max_tracked_clients > MAX_TRACKED_CLIENTS_LIMIT {
            return Err("tracked-client bound outside 1..=100000".into());
        }
        if self.max_request_metadata_bytes == 0
            || self.max_request_metadata_bytes > MAX_REQUEST_METADATA_LIMIT
        {
            return Err("request metadata bound outside 1..=65536".into());
        }
        if self.max_range_bytes == 0 || self.max_range_bytes > ARTIFACT_SHARE_BYTES {
            return Err("range bound exceeds one canonical share".into());
        }
        if self.max_range_bytes != ARTIFACT_SHARE_BYTES {
            return Err("full canonical share GET must remain available".into());
        }
        if self.queue_wait_millis == 0 || self.queue_wait_millis > 30_000 {
            return Err("queue wait outside 1..=30000 milliseconds".into());
        }
        if self.egress_bytes_per_second == 0 || self.egress_bytes_per_second > MAX_EGRESS_RATE {
            return Err("egress rate outside 1..=1GiB/s".into());
        }
        if self.egress_wait_millis == 0 || self.egress_wait_millis > 30_000 {
            return Err("egress wait outside 1..=30000 milliseconds".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ArtifactHttpState {
    inner: Arc<ArtifactHttpInner>,
}

struct ArtifactHttpInner {
    store: Arc<ArtifactStore>,
    artifact: [u8; 32],
    manifest: Arc<ArtifactManifestV1>,
    manifest_bytes: Bytes,
    config: ArtifactHttpConfig,
    total_admission: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    clients: ClientLimiter,
    egress: EgressPacer,
    metrics: ServiceMetrics,
    started: Instant,
}

impl ArtifactHttpState {
    pub fn initialize(
        store: ArtifactStore,
        config: ArtifactHttpConfig,
    ) -> Result<(Self, StoreVerificationReport), String> {
        config.validate()?;
        let verification = verify_bonsai_store(&store)?;
        if !verification.published {
            return Err("artifact store is not published".into());
        }
        let artifact = decode_hex32(BONSAI_ARTIFACT_ID_HEX)?;
        let manifest_bytes = store
            .read_manifest(&artifact)
            .map_err(|error| error.to_string())?;
        let manifest = ArtifactManifestV1::from_canonical_bytes(&manifest_bytes)
            .map_err(|error| error.to_string())?;
        if hex::encode(manifest.manifest_root().as_bytes()) != BONSAI_MANIFEST_ROOT_HEX {
            return Err("artifact service manifest root mismatch".into());
        }
        let admission_capacity = config
            .max_concurrent_requests
            .checked_add(config.queue_capacity)
            .ok_or("request admission capacity overflow")?;
        let state = Self {
            inner: Arc::new(ArtifactHttpInner {
                store: Arc::new(store),
                artifact,
                manifest: Arc::new(manifest),
                manifest_bytes: Bytes::from(manifest_bytes),
                total_admission: Arc::new(Semaphore::new(admission_capacity)),
                workers: Arc::new(Semaphore::new(config.max_concurrent_requests)),
                clients: ClientLimiter::new(
                    config.per_client_requests_per_second,
                    config.max_tracked_clients,
                ),
                egress: EgressPacer::new(
                    config.egress_bytes_per_second,
                    Duration::from_millis(config.egress_wait_millis),
                ),
                config,
                metrics: ServiceMetrics::default(),
                started: Instant::now(),
            }),
        };
        Ok((state, verification))
    }

    #[must_use]
    pub fn config(&self) -> &ArtifactHttpConfig {
        &self.inner.config
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> ServiceMetricsSnapshot {
        self.inner.metrics.snapshot(
            self.inner.started.elapsed(),
            self.inner.store.used_bytes(),
            self.inner.store.config().quota_bytes,
        )
    }
}

pub fn router(state: ArtifactHttpState) -> Router {
    Router::new()
        .route("/artifacts/{manifest_root}/manifest", get(get_manifest))
        .route(
            "/artifacts/{manifest_root}/shares/{stripe}/{position}",
            get(get_share).head(get_share),
        )
        .layer(middleware::from_fn_with_state(state.clone(), request_guard))
        .with_state(state)
}

async fn request_guard(
    State(state): State<ArtifactHttpState>,
    request: Request,
    next: Next,
) -> Response {
    state
        .inner
        .metrics
        .requests_total
        .fetch_add(1, Ordering::Relaxed);
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return rejection(StatusCode::METHOD_NOT_ALLOWED, "GET or HEAD required", None);
    }
    if request.uri().query().is_some() {
        return rejection(
            StatusCode::BAD_REQUEST,
            "query parameters are not accepted",
            None,
        );
    }
    if request.headers().contains_key(header::TRANSFER_ENCODING) {
        return rejection(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request bodies are not accepted",
            None,
        );
    }
    if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
        let Ok(length) = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(())
        else {
            return rejection(StatusCode::BAD_REQUEST, "invalid Content-Length", None);
        };
        if length != 0 {
            return rejection(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request bodies are not accepted",
                None,
            );
        }
    }
    let Some(metadata_bytes) = request_metadata_bytes(&request) else {
        return rejection(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request metadata overflow",
            None,
        );
    };
    if metadata_bytes > state.inner.config.max_request_metadata_bytes {
        return rejection(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request metadata exceeds configured bound",
            None,
        );
    }
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0)
    else {
        return rejection(
            StatusCode::INTERNAL_SERVER_ERROR,
            "peer address unavailable",
            None,
        );
    };
    if !state.inner.clients.allow(peer.ip()).await {
        state
            .inner
            .metrics
            .rate_rejections
            .fetch_add(1, Ordering::Relaxed);
        return rejection(
            StatusCode::TOO_MANY_REQUESTS,
            "per-client rate exceeded",
            Some(1),
        );
    }

    let admission = match state.inner.total_admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            state
                .inner
                .metrics
                .queue_rejections
                .fetch_add(1, Ordering::Relaxed);
            return rejection(
                StatusCode::SERVICE_UNAVAILABLE,
                "artifact queue full",
                Some(1),
            );
        }
    };
    let worker = match state.inner.workers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            state.inner.metrics.queued.fetch_add(1, Ordering::Relaxed);
            let outcome = timeout(
                Duration::from_millis(state.inner.config.queue_wait_millis),
                state.inner.workers.clone().acquire_owned(),
            )
            .await;
            state.inner.metrics.queued.fetch_sub(1, Ordering::Relaxed);
            match outcome {
                Ok(Ok(permit)) => permit,
                _ => {
                    state
                        .inner
                        .metrics
                        .queue_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    drop(admission);
                    return rejection(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "artifact queue wait expired",
                        Some(1),
                    );
                }
            }
        }
    };

    state.inner.metrics.active.fetch_add(1, Ordering::Relaxed);
    let response = next.run(request).await;
    state.inner.metrics.active.fetch_sub(1, Ordering::Relaxed);
    drop(worker);
    drop(admission);
    response
}

async fn get_manifest(
    State(state): State<ArtifactHttpState>,
    Path(manifest_root): Path<String>,
    headers: HeaderMap,
) -> Response {
    if manifest_root != BONSAI_MANIFEST_ROOT_HEX {
        return rejection(StatusCode::NOT_FOUND, "unknown manifest", None);
    }
    let etag = quoted_etag(BONSAI_MANIFEST_ROOT_HEX);
    if matches_etag(&headers, &etag) {
        return not_modified(&etag, false, None);
    }
    let bytes = state.inner.manifest_bytes.clone();
    if !state.inner.egress.reserve(bytes.len() as u64).await {
        state
            .inner
            .metrics
            .egress_rejections
            .fetch_add(1, Ordering::Relaxed);
        return rejection(
            StatusCode::SERVICE_UNAVAILABLE,
            "egress budget wait exceeded",
            Some(1),
        );
    }
    state
        .inner
        .metrics
        .manifest_responses
        .fetch_add(1, Ordering::Relaxed);
    state
        .inner
        .metrics
        .egress_bytes
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    immutable_response(
        StatusCode::OK,
        bytes,
        MANIFEST_CONTENT_TYPE,
        &etag,
        None,
        None,
        false,
    )
}

async fn get_share(
    State(state): State<ArtifactHttpState>,
    Path((manifest_root, stripe, position)): Path<(String, u32, u8)>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if manifest_root != BONSAI_MANIFEST_ROOT_HEX
        || position as usize >= ARTIFACT_POSITIONS
        || stripe as usize >= state.inner.manifest.stripes.len()
    {
        return rejection(StatusCode::NOT_FOUND, "unknown share", None);
    }
    let selection = match select_range(
        &headers,
        ARTIFACT_SHARE_BYTES,
        state.inner.config.max_range_bytes,
    ) {
        Ok(selection) => selection,
        Err(()) => return range_not_satisfiable(ARTIFACT_SHARE_BYTES),
    };
    let commitment = state.inner.manifest.stripes[stripe as usize].shares[position as usize];
    let share_digest = hex::encode(commitment.share_digest.as_bytes());
    let probe_root = hex::encode(commitment.probe_root.as_bytes());
    let etag = quoted_etag(&share_digest);
    if matches_etag(&headers, &etag) {
        return not_modified(&etag, true, Some(&probe_root));
    }
    if method == Method::HEAD {
        state
            .inner
            .metrics
            .share_head_responses
            .fetch_add(1, Ordering::Relaxed);
        return immutable_response(
            selection.status,
            Bytes::new(),
            SHARE_CONTENT_TYPE,
            &etag,
            selection.content_range(ARTIFACT_SHARE_BYTES).as_deref(),
            Some(&probe_root),
            true,
        );
    }

    let store = state.inner.store.clone();
    let artifact = state.inner.artifact;
    let read = tokio::task::spawn_blocking(move || {
        store.read_share_bytes(&artifact, stripe, position, ARTIFACT_SHARE_BYTES)
    })
    .await;
    let bytes = match read {
        Ok(Ok(bytes)) => Bytes::from(bytes),
        _ => {
            state
                .inner
                .metrics
                .read_failures
                .fetch_add(1, Ordering::Relaxed);
            return rejection(
                StatusCode::SERVICE_UNAVAILABLE,
                "share unavailable",
                Some(1),
            );
        }
    };
    let body = bytes.slice(selection.start..selection.end_exclusive);
    if !state.inner.egress.reserve(body.len() as u64).await {
        state
            .inner
            .metrics
            .egress_rejections
            .fetch_add(1, Ordering::Relaxed);
        return rejection(
            StatusCode::SERVICE_UNAVAILABLE,
            "egress budget wait exceeded",
            Some(1),
        );
    }
    state
        .inner
        .metrics
        .share_get_responses
        .fetch_add(1, Ordering::Relaxed);
    state
        .inner
        .metrics
        .egress_bytes
        .fetch_add(body.len() as u64, Ordering::Relaxed);
    immutable_response(
        selection.status,
        body,
        SHARE_CONTENT_TYPE,
        &etag,
        selection.content_range(ARTIFACT_SHARE_BYTES).as_deref(),
        Some(&probe_root),
        false,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RangeSelection {
    start: usize,
    end_exclusive: usize,
    status: StatusCode,
}

impl RangeSelection {
    fn content_range(self, total: usize) -> Option<String> {
        if self.status != StatusCode::PARTIAL_CONTENT {
            return None;
        }
        Some(format!(
            "bytes {}-{}/{}",
            self.start,
            self.end_exclusive.saturating_sub(1),
            total
        ))
    }
}

fn select_range(headers: &HeaderMap, total: usize, maximum: usize) -> Result<RangeSelection, ()> {
    let values = headers.get_all(header::RANGE).iter().collect::<Vec<_>>();
    if values.is_empty() {
        if total > maximum {
            return Err(());
        }
        return Ok(RangeSelection {
            start: 0,
            end_exclusive: total,
            status: StatusCode::OK,
        });
    }
    if values.len() != 1 {
        return Err(());
    }
    let value = values[0].to_str().map_err(|_| ())?;
    let spec = value.strip_prefix("bytes=").ok_or(())?;
    if spec.contains(',') {
        return Err(());
    }
    let (start_text, end_text) = spec.split_once('-').ok_or(())?;
    let (start, end_inclusive) = if start_text.is_empty() {
        let suffix = end_text.parse::<usize>().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        let length = suffix.min(total);
        (total.saturating_sub(length), total.saturating_sub(1))
    } else {
        let start = start_text.parse::<usize>().map_err(|_| ())?;
        if start >= total {
            return Err(());
        }
        let requested_end = if end_text.is_empty() {
            total.saturating_sub(1)
        } else {
            end_text.parse::<usize>().map_err(|_| ())?
        };
        if requested_end < start {
            return Err(());
        }
        (start, requested_end.min(total.saturating_sub(1)))
    };
    let end_exclusive = end_inclusive.checked_add(1).ok_or(())?;
    let length = end_exclusive.checked_sub(start).ok_or(())?;
    if length == 0 || length > maximum {
        return Err(());
    }
    Ok(RangeSelection {
        start,
        end_exclusive,
        status: StatusCode::PARTIAL_CONTENT,
    })
}

fn immutable_response(
    status: StatusCode,
    bytes: Bytes,
    content_type: &'static str,
    etag: &str,
    content_range: Option<&str>,
    probe_root: Option<&str>,
    head_only: bool,
) -> Response {
    let content_length = if head_only {
        content_range
            .and_then(parse_content_range_length)
            .unwrap_or(ARTIFACT_SHARE_BYTES)
    } else {
        bytes.len()
    };
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, content_length.to_string())
        .header(header::CACHE_CONTROL, IMMUTABLE_CACHE_CONTROL)
        .header(header::ETAG, etag)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS);
    if content_type == SHARE_CONTENT_TYPE {
        builder = builder.header(header::ACCEPT_RANGES, "bytes");
    }
    if let Some(value) = content_range {
        builder = builder.header(header::CONTENT_RANGE, value);
    }
    if let Some(value) = probe_root {
        builder = builder.header("x-noos-probe-root", value);
    }
    let body = if head_only {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    builder.body(body).unwrap_or_else(|_| {
        rejection(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response construction failed",
            None,
        )
    })
}

fn parse_content_range_length(value: &str) -> Option<usize> {
    let value = value.strip_prefix("bytes ")?;
    let (range, _) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<usize>().ok()?;
    let end = end.parse::<usize>().ok()?;
    end.checked_sub(start)?.checked_add(1)
}

fn not_modified(etag: &str, share: bool, probe_root: Option<&str>) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(header::CACHE_CONTROL, IMMUTABLE_CACHE_CONTROL)
        .header(header::ETAG, etag)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS);
    if share {
        builder = builder.header(header::ACCEPT_RANGES, "bytes");
    }
    if let Some(value) = probe_root {
        builder = builder.header("x-noos-probe-root", value);
    }
    builder.body(Body::empty()).unwrap_or_else(|_| {
        rejection(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response construction failed",
            None,
        )
    })
}

fn range_not_satisfiable(total: usize) -> Response {
    let mut response = rejection(
        StatusCode::RANGE_NOT_SATISFIABLE,
        "range is not satisfiable",
        None,
    );
    response.headers_mut().insert(
        header::CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes */{total}"))
            .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
    );
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

fn rejection(status: StatusCode, message: &'static str, retry_after: Option<u64>) -> Response {
    let mut response = (status, message).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(seconds) = retry_after {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

fn quoted_etag(digest_hex: &str) -> String {
    format!("\"{digest_hex}\"")
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == etag)
}

fn request_metadata_bytes(request: &Request) -> Option<usize> {
    let mut total = request
        .method()
        .as_str()
        .len()
        .checked_add(request.uri().path().len())?;
    for (name, value) in request.headers() {
        total = total.checked_add(name.as_str().len())?;
        total = total.checked_add(value.as_bytes().len())?;
    }
    Some(total)
}

#[derive(Clone)]
struct ClientLimiter {
    rate: u32,
    maximum_clients: usize,
    clients: Arc<Mutex<BTreeMap<IpAddr, ClientWindow>>>,
}

#[derive(Clone, Copy)]
struct ClientWindow {
    started: Instant,
    last_seen: Instant,
    requests: u32,
}

impl ClientLimiter {
    fn new(rate: u32, maximum_clients: usize) -> Self {
        Self {
            rate,
            maximum_clients,
            clients: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    async fn allow(&self, client: IpAddr) -> bool {
        let now = Instant::now();
        let mut clients = self.clients.lock().await;
        if !clients.contains_key(&client) && clients.len() >= self.maximum_clients {
            clients
                .retain(|_, window| now.duration_since(window.last_seen) < Duration::from_secs(60));
            if clients.len() >= self.maximum_clients {
                return false;
            }
        }
        let window = clients.entry(client).or_insert(ClientWindow {
            started: now,
            last_seen: now,
            requests: 0,
        });
        if now.duration_since(window.started) >= Duration::from_secs(1) {
            window.started = now;
            window.requests = 0;
        }
        window.last_seen = now;
        if window.requests >= self.rate {
            return false;
        }
        window.requests = window.requests.saturating_add(1);
        true
    }
}

#[derive(Clone)]
struct EgressPacer {
    bytes_per_second: u64,
    maximum_wait: Duration,
    next: Arc<Mutex<Instant>>,
}

impl EgressPacer {
    fn new(bytes_per_second: u64, maximum_wait: Duration) -> Self {
        Self {
            bytes_per_second,
            maximum_wait,
            next: Arc::new(Mutex::new(Instant::now())),
        }
    }

    async fn reserve(&self, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        let nanos =
            (u128::from(bytes) * 1_000_000_000_u128).div_ceil(u128::from(self.bytes_per_second));
        let Ok(nanos) = u64::try_from(nanos) else {
            return false;
        };
        let spacing = Duration::from_nanos(nanos);
        let now = Instant::now();
        let mut next = self.next.lock().await;
        let scheduled = if *next > now { *next } else { now };
        if scheduled.duration_since(now) > self.maximum_wait {
            return false;
        }
        let Some(updated) = scheduled.checked_add(spacing) else {
            return false;
        };
        *next = updated;
        drop(next);
        tokio::time::sleep_until(scheduled).await;
        true
    }
}

#[derive(Default)]
struct ServiceMetrics {
    requests_total: AtomicU64,
    active: AtomicUsize,
    queued: AtomicUsize,
    queue_rejections: AtomicU64,
    rate_rejections: AtomicU64,
    egress_rejections: AtomicU64,
    read_failures: AtomicU64,
    manifest_responses: AtomicU64,
    share_get_responses: AtomicU64,
    share_head_responses: AtomicU64,
    egress_bytes: AtomicU64,
}

impl ServiceMetrics {
    fn snapshot(
        &self,
        uptime: Duration,
        store_used_bytes: u64,
        store_quota_bytes: u64,
    ) -> ServiceMetricsSnapshot {
        ServiceMetricsSnapshot {
            schema: "noos.wwm.artifact-service-metrics.v1",
            uptime_millis: uptime.as_millis().try_into().unwrap_or(u64::MAX),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            active_requests: self.active.load(Ordering::Relaxed),
            queued_requests: self.queued.load(Ordering::Relaxed),
            queue_rejections: self.queue_rejections.load(Ordering::Relaxed),
            rate_rejections: self.rate_rejections.load(Ordering::Relaxed),
            egress_rejections: self.egress_rejections.load(Ordering::Relaxed),
            read_failures: self.read_failures.load(Ordering::Relaxed),
            manifest_responses: self.manifest_responses.load(Ordering::Relaxed),
            share_get_responses: self.share_get_responses.load(Ordering::Relaxed),
            share_head_responses: self.share_head_responses.load(Ordering::Relaxed),
            egress_bytes: self.egress_bytes.load(Ordering::Relaxed),
            store_used_bytes,
            store_quota_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceMetricsSnapshot {
    pub schema: &'static str,
    pub uptime_millis: u64,
    pub requests_total: u64,
    pub active_requests: usize,
    pub queued_requests: usize,
    pub queue_rejections: u64,
    pub rate_rejections: u64,
    pub egress_rejections: u64,
    pub read_failures: u64,
    pub manifest_responses: u64,
    pub share_get_responses: u64,
    pub share_head_responses: u64,
    pub egress_bytes: u64,
    pub store_used_bytes: u64,
    pub store_quota_bytes: u64,
}

fn decode_hex32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(range: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static(range));
        headers
    }

    #[test]
    fn range_parser_supports_closed_open_and_suffix_ranges() {
        let total = ARTIFACT_SHARE_BYTES;
        assert_eq!(
            select_range(&HeaderMap::new(), total, total),
            Ok(RangeSelection {
                start: 0,
                end_exclusive: total,
                status: StatusCode::OK,
            })
        );
        assert_eq!(
            select_range(&headers("bytes=2-9"), total, total),
            Ok(RangeSelection {
                start: 2,
                end_exclusive: 10,
                status: StatusCode::PARTIAL_CONTENT,
            })
        );
        assert_eq!(
            select_range(&headers("bytes=10-"), total, total),
            Ok(RangeSelection {
                start: 10,
                end_exclusive: total,
                status: StatusCode::PARTIAL_CONTENT,
            })
        );
        assert_eq!(
            select_range(&headers("bytes=-16"), total, total),
            Ok(RangeSelection {
                start: total.saturating_sub(16),
                end_exclusive: total,
                status: StatusCode::PARTIAL_CONTENT,
            })
        );
    }

    #[test]
    fn range_parser_rejects_multi_invalid_and_oversized_ranges() {
        let total = ARTIFACT_SHARE_BYTES;
        for value in [
            "items=0-1",
            "bytes=0-1,4-5",
            "bytes=9-2",
            "bytes=-0",
            "bytes=1047552-1047553",
        ] {
            assert!(
                select_range(&headers(value), total, total).is_err(),
                "{value}"
            );
        }
        assert!(select_range(&headers("bytes=0-99"), total, 64).is_err());
    }

    #[test]
    fn service_bounds_reject_unbounded_configuration() {
        let config = ArtifactHttpConfig {
            queue_capacity: MAX_QUEUE_CAPACITY.saturating_add(1),
            ..ArtifactHttpConfig::default()
        };
        assert!(config.validate().is_err());
        let config = ArtifactHttpConfig {
            max_range_bytes: ARTIFACT_SHARE_BYTES.saturating_sub(1),
            ..ArtifactHttpConfig::default()
        };
        assert!(config.validate().is_err());
        let config = ArtifactHttpConfig {
            egress_bytes_per_second: 0,
            ..ArtifactHttpConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn client_limiter_bounds_rate_and_client_state() {
        let limiter = ClientLimiter::new(2, 1);
        let first = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let second = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
        assert!(limiter.allow(first).await);
        assert!(limiter.allow(first).await);
        assert!(!limiter.allow(first).await);
        assert!(!limiter.allow(second).await);
    }
}
