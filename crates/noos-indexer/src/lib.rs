//! Identity-bound MindChain indexer and frozen NOOS public API v1.
#![forbid(unsafe_code)]

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

pub mod ingest;

pub const API_VERSION: &str = "v1";
pub const MEDIA_TYPE: &str = "application/vnd.noos.v1+json";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub type Result<T, E = IndexerError> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexerError {
    WrongProtocolIdentity,
    InvalidIdentity,
    Io(String),
    SchemaMismatch,
    NonMonotonicHead,
    /// Live node source failed (transport, auth, or malformed frame).
    Source(String),
    /// A fork's ancestor is older than the retained checkpoint tail;
    /// resuming would silently skip rollback, so ingestion fails closed.
    ReorgBeyondCheckpoint,
}
impl std::fmt::Display for IndexerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongProtocolIdentity => f.write_str("wrong_protocol_identity"),
            Self::InvalidIdentity => f.write_str("invalid protocol identity"),
            Self::Io(v) => write!(f, "I/O: {v}"),
            Self::SchemaMismatch => f.write_str("index schema identity mismatch"),
            Self::NonMonotonicHead => f.write_str("non-monotonic head update"),
            Self::Source(v) => write!(f, "node source: {v}"),
            Self::ReorgBeyondCheckpoint => f.write_str("reorg beyond checkpoint tail"),
        }
    }
}
impl std::error::Error for IndexerError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub chain_id: String,
    pub genesis_hash: String,
    pub api_version: String,
}
impl Identity {
    pub fn validate(&self) -> Result<()> {
        if !is_hash(&self.chain_id)
            || !is_hash(&self.genesis_hash)
            || self.api_version != API_VERSION
        {
            return Err(IndexerError::InvalidIdentity);
        }
        Ok(())
    }
    pub fn require(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        actual.validate()?;
        if self != actual {
            return Err(IndexerError::WrongProtocolIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPoint {
    pub height: String,
    pub hash: String,
    pub state_root: String,
}
impl ChainPoint {
    fn genesis(hash: &str) -> Self {
        Self {
            height: "0".into(),
            hash: hash.into(),
            state_root: ZERO_HASH.into(),
        }
    }
    fn numeric_height(&self) -> Result<u64> {
        self.height
            .parse()
            .map_err(|_| IndexerError::NonMonotonicHead)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadKind {
    Unsafe,
    Justified,
    Finalized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedBlock {
    pub hash: String,
    pub height: String,
    pub parent_hash: String,
    pub slot: String,
    pub epoch: String,
    pub timestamp_ms: String,
    pub execution_receipt_root: String,
    pub lumen_receipts_state_root: String,
    pub transaction_count: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Descriptor {
    schema: String,
    identity: Identity,
}

#[derive(Clone)]
pub struct Indexer {
    identity: Identity,
    root: PathBuf,
    inner: Arc<RwLock<IndexState>>,
}
#[derive(Default)]
struct IndexState {
    unsafe_head: Option<ChainPoint>,
    justified: Option<ChainPoint>,
    finalized: Option<ChainPoint>,
    blocks: BTreeMap<u64, IndexedBlock>,
    /// txids carried by each ingested height — the exact row set a
    /// reorg rollback must delete (ingest::sync_from_node).
    block_txids: BTreeMap<u64, Vec<String>>,
    transactions: HashMap<String, Value>,
    evidence: HashMap<String, Value>,
    telemetry: TelemetryParser,
}

impl Indexer {
    /// Identity comparison deliberately precedes every filesystem operation.
    pub fn open(root: impl AsRef<FsPath>, expected: Identity, actual: Identity) -> Result<Self> {
        expected.require(&actual)?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|e| IndexerError::Io(e.to_string()))?;
        let descriptor_path = root.join("NOOS-INDEX-V1.json");
        let descriptor = Descriptor {
            schema: "noos-index-v1".into(),
            identity: expected.clone(),
        };
        if descriptor_path.exists() {
            let bytes = fs::read(&descriptor_path).map_err(|e| IndexerError::Io(e.to_string()))?;
            let found: Descriptor =
                serde_json::from_slice(&bytes).map_err(|_| IndexerError::SchemaMismatch)?;
            if found.schema != descriptor.schema || found.identity != expected {
                return Err(IndexerError::SchemaMismatch);
            }
        } else {
            let bytes = serde_json::to_vec_pretty(&descriptor)
                .map_err(|e| IndexerError::Io(e.to_string()))?;
            atomic_write(&descriptor_path, &bytes)?;
        }
        let genesis = ChainPoint::genesis(&expected.genesis_hash);
        Ok(Self {
            identity: expected,
            root,
            inner: Arc::new(RwLock::new(IndexState {
                unsafe_head: Some(genesis.clone()),
                justified: Some(genesis.clone()),
                finalized: Some(genesis),
                ..IndexState::default()
            })),
        })
    }
    pub fn root(&self) -> &FsPath {
        &self.root
    }
    pub async fn ingest_head(
        &self,
        identity: &Identity,
        kind: HeadKind,
        point: ChainPoint,
    ) -> Result<()> {
        self.identity.require(identity)?;
        if !is_hash(&point.hash) || !is_hash(&point.state_root) {
            return Err(IndexerError::InvalidIdentity);
        }
        let incoming = point.numeric_height()?;
        let mut state = self.inner.write().await;
        let target = match kind {
            HeadKind::Unsafe => &mut state.unsafe_head,
            HeadKind::Justified => &mut state.justified,
            HeadKind::Finalized => &mut state.finalized,
        };
        if target
            .as_ref()
            .map(ChainPoint::numeric_height)
            .transpose()?
            .is_some_and(|old| incoming < old)
        {
            return Err(IndexerError::NonMonotonicHead);
        }
        *target = Some(point);
        Ok(())
    }
    pub async fn ingest_block(&self, identity: &Identity, block: IndexedBlock) -> Result<()> {
        self.identity.require(identity)?;
        if !is_hash(&block.hash) || !is_hash(&block.parent_hash) {
            return Err(IndexerError::InvalidIdentity);
        }
        let height = block
            .height
            .parse()
            .map_err(|_| IndexerError::InvalidIdentity)?;
        self.inner.write().await.blocks.insert(height, block);
        Ok(())
    }
    pub async fn set_evidence(&self, mechanism: &str, value: Value) {
        self.inner
            .write()
            .await
            .evidence
            .insert(mechanism.into(), value);
    }
    pub async fn telemetry_sample(&self, now: u64, sample: MetricSample) -> TelemetryValue {
        self.inner.write().await.telemetry.observe(now, sample)
    }
}

fn atomic_write(path: &FsPath, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("json.stage");
    fs::write(&temp, bytes).map_err(|e| IndexerError::Io(e.to_string()))?;
    fs::rename(&temp, path).map_err(|e| IndexerError::Io(e.to_string()))
}

#[derive(Clone, Debug)]
pub struct MetricSample {
    pub name: String,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
    pub observed_at: u64,
    pub freshness_deadline: u64,
    pub cardinality_ceiling: usize,
}
#[derive(Clone, Debug, PartialEq)]
pub enum TelemetryValue {
    Numeric(f64),
    Unknown(UnknownReason),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    Absent,
    Stale,
    Malformed,
    CardinalityOverflow,
    CounterReset,
}
type LabelSet = BTreeMap<String, String>;
type MetricFamily = BTreeMap<LabelSet, (f64, u64)>;

#[derive(Default)]
pub struct TelemetryParser {
    families: HashMap<String, MetricFamily>,
}
impl TelemetryParser {
    pub fn observe(&mut self, now: u64, sample: MetricSample) -> TelemetryValue {
        if !sample.name.starts_with("noos_") || !sample.value.is_finite() {
            return TelemetryValue::Unknown(UnknownReason::Malformed);
        }
        if now.saturating_sub(sample.observed_at) > sample.freshness_deadline {
            return TelemetryValue::Unknown(UnknownReason::Stale);
        }
        let family = self.families.entry(sample.name).or_default();
        if !family.contains_key(&sample.labels) && family.len() >= sample.cardinality_ceiling {
            return TelemetryValue::Unknown(UnknownReason::CardinalityOverflow);
        }
        family.insert(sample.labels, (sample.value, sample.observed_at));
        TelemetryValue::Numeric(sample.value)
    }
}

#[derive(Clone)]
struct AppState {
    indexer: Indexer,
}
pub fn router(indexer: Indexer) -> Router {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/v1/blocks", get(blocks))
        .route("/api/v1/blocks/{hash_or_height}", get(block))
        .route("/api/v1/transactions", post(submit_transaction))
        .route("/api/v1/transactions/{txid}", get(entity_transaction))
        .route("/api/v1/notes/{noteid}", get(hash_not_found))
        .route("/api/v1/addresses/{address}/notes", get(address_page))
        .route("/api/v1/addresses/{address}/balance", get(address_resource))
        .route("/api/v1/addresses/{address}/history", get(address_page))
        .route("/api/v1/nodes", get(empty_page))
        .route("/api/v1/workers", get(disabled_work))
        .route("/api/v1/objects/{objectid}", get(hash_not_found))
        .route("/api/v1/models", get(disabled_neural))
        .route("/api/v1/jobs", get(disabled_work))
        .route("/api/v1/jobs/{jobid}/chunks", get(disabled_neural))
        .route("/api/v1/receipts/{receiptid}", get(hash_not_found))
        .route("/api/v1/disputes/{disputeid}", get(disabled_neural))
        .route("/api/v1/evidence/{mechanism_id}", get(evidence))
        .with_state(AppState { indexer })
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    mechanism: Option<&'static str>,
}
impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            mechanism: None,
        }
    }
    fn disabled(mechanism: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "feature_disabled",
            message: "mechanism disabled".into(),
            mechanism: Some(mechanism),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({"code":self.code,"message":self.message,"request_id":"noos-indexer","details":{}});
        if let Some(m) = self.mechanism {
            body["mechanism_id"] = json!(m);
            body["evidence_ref"] = json!(format!("/api/v1/evidence/{m}"));
        }
        let mut response = (self.status, Json(body)).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        response
    }
}
type ApiResult<T, E = ApiError> = std::result::Result<T, E>;

fn accepted(headers: &HeaderMap) -> ApiResult<()> {
    if let Some(value) = headers.get(header::ACCEPT) {
        let value = value.to_str().unwrap_or("");
        if !value.contains("*/*")
            && !value.contains("application/json")
            && !value.contains(MEDIA_TYPE)
        {
            return Err(ApiError::new(
                StatusCode::NOT_ACCEPTABLE,
                "not_acceptable",
                "no acceptable v1 representation",
            ));
        }
    }
    Ok(())
}
fn api_json(value: Value) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    response
}

async fn status(State(s): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    accepted(&headers)?;
    let st = s.indexer.inner.read().await;
    Ok(api_json(json!({
        "chain_id":s.indexer.identity.chain_id,"genesis_hash":s.indexer.identity.genesis_hash,
        "protocol_version":"v1","api_version":"v1","release_version":env!("CARGO_PKG_VERSION"),
        "unsafe_head":st.unsafe_head,"justified":st.justified,"finalized":st.finalized,
        "freshness_ms":"0","evidence_registry_root":ZERO_HASH
    })))
}
#[derive(Deserialize)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}
async fn blocks(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> ApiResult<Response> {
    accepted(&headers)?;
    let limit = q.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "limit must be 1..200",
        ));
    }
    let start = decode_cursor(q.cursor.as_deref(), "blocks", "height:desc,hash:asc")?;
    let st = s.indexer.inner.read().await;
    let items: Vec<_> = st
        .blocks
        .iter()
        .rev()
        .skip(start)
        .take(limit)
        .map(|(_, b)| b)
        .collect();
    let next_key = start.saturating_add(items.len());
    let next =
        (items.len() == limit).then(|| encode_cursor("blocks", "height:desc,hash:asc", next_key));
    Ok(api_json(json!({"items":items,"next_cursor":next})))
}
async fn block(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    let st = s.indexer.inner.read().await;
    let item = if is_hash(&id) {
        st.blocks.values().find(|b| b.hash == id)
    } else if canonical_u64(&id) {
        st.blocks.get(&id.parse::<u64>().unwrap_or_default())
    } else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid block identifier",
        ));
    };
    item.map(|v| api_json(json!(v)))
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "block not found"))
}
async fn entity_transaction(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    if !is_hash(&id) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid txid",
        ));
    }
    s.indexer
        .inner
        .read()
        .await
        .transactions
        .get(&id)
        .cloned()
        .map(api_json)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "transaction not found"))
}
#[derive(Deserialize)]
struct Submit {
    chain_id: String,
    genesis_hash: String,
    api_version: String,
    transaction: String,
}
async fn submit_transaction(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| !v.starts_with("application/json"))
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Content-Type must be application/json",
        ));
    }
    if body.len() > 1_048_576 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "request exceeds 1048576 bytes",
        ));
    }
    let req: Submit = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_request", "invalid JSON"))?;
    let actual = Identity {
        chain_id: req.chain_id,
        genesis_hash: req.genesis_hash,
        api_version: req.api_version,
    };
    s.indexer.identity.require(&actual).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "wrong_protocol_identity",
            "chain, genesis, or API version mismatch",
        )
    })?;
    let tx = STANDARD.decode(req.transaction).map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "transaction is not canonical base64",
        )
    })?;
    if tx.len() > 524_288 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "transaction exceeds 524288 bytes",
        ));
    }
    let txid = format!("{:x}", Sha256::digest(&tx));
    let mut state = s.indexer.inner.write().await;
    let duplicate = state.transactions.contains_key(&txid);
    state.transactions.entry(txid.clone()).or_insert_with(
        || json!({"txid":txid,"wtxid":txid,"state":"MEMPOOL","fee":"0","resource_counters":{}}),
    );
    let status = if duplicate {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    let mut response = (
        status,
        Json(json!({"txid":txid,"state":"MEMPOOL","duplicate":duplicate})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    Ok(response)
}
async fn empty_page(headers: HeaderMap, Query(q): Query<PageQuery>) -> ApiResult<Response> {
    accepted(&headers)?;
    if q.limit.is_some_and(|v| !(1..=200).contains(&v)) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "limit must be 1..200",
        ));
    }
    if q.cursor.is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "cursor is not valid for this snapshot",
        ));
    }
    Ok(api_json(json!({"items":[],"next_cursor":null})))
}
async fn hash_not_found(Path(id): Path<String>) -> ApiResult<Response> {
    if !is_hash(&id) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "identifier must be lowercase 64-hex",
        ));
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "resource not found",
    ))
}
fn reject_unfrozen_address(address: &str) -> ApiError {
    if address.starts_with("mind1") || address.starts_with("MIND1") {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "wrong_protocol_identity",
            "historical address identity",
        )
    } else {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "address layout is OWNER_BLOCKED by identity-v1",
        )
    }
}
async fn address_page(Path(address): Path<String>) -> ApiResult<Response> {
    Err(reject_unfrozen_address(&address))
}
async fn address_resource(Path(address): Path<String>) -> ApiResult<Response> {
    Err(reject_unfrozen_address(&address))
}
async fn disabled_work() -> ApiResult<Response> {
    Err(ApiError::disabled("M-WORK-LOOM"))
}
async fn disabled_neural() -> ApiResult<Response> {
    Err(ApiError::disabled("M-NEL"))
}
async fn evidence(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Response> {
    s.indexer
        .inner
        .read()
        .await
        .evidence
        .get(&id)
        .cloned()
        .map(api_json)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "mechanism evidence not found",
            )
        })
}

#[derive(Serialize, Deserialize)]
struct CursorPayload {
    v: u8,
    route: String,
    sort: String,
    last_key: usize,
    query_sha256: String,
}
fn encode_cursor(route: &str, sort: &str, last_key: usize) -> String {
    let query_sha256 = format!(
        "{:x}",
        Sha256::digest(format!("{route}?sort={sort}").as_bytes())
    );
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&CursorPayload {
            v: 1,
            route: route.into(),
            sort: sort.into(),
            last_key,
            query_sha256,
        })
        .unwrap_or_default(),
    )
}
fn decode_cursor(cursor: Option<&str>, route: &str, sort: &str) -> ApiResult<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    if cursor.contains('=') {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "cursor padding is forbidden",
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "malformed cursor",
        )
    })?;
    let payload: CursorPayload = serde_json::from_slice(&bytes).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "malformed cursor",
        )
    })?;
    let expected = format!(
        "{:x}",
        Sha256::digest(format!("{route}?sort={sort}").as_bytes())
    );
    if payload.v != 1
        || payload.route != route
        || payload.sort != sort
        || payload.query_sha256 != expected
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "cursor query mismatch",
        ));
    }
    Ok(payload.last_key)
}
fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical_u64(s: &str) -> bool {
    (s == "0" || (!s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit())))
        && s.parse::<u64>().is_ok()
}
