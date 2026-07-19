use super::store::{StoreBenchmarkSnapshot, WebCapacityStore, WebCapacityStoreLimits};
use super::{
    config::HARD_MAX_ACTIVE_ASSIGNMENTS,
    model::{
        HeartbeatRequest, OfferRequest, ParticipantReport, RevocationRequest, StorageClass,
        UploadPolicy, ACCESS_LOG_RETENTION_SECONDS, SCHEMA, SHARE_BYTES,
    },
    security::{domain_hash_hex, verify_json_signature},
    session_token_hash, validate_heartbeat, validate_offer, validate_report, validate_revocation,
    WebCapacityConfig, WebCapacityError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use noos_crypto::DomainId;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    time::Instant,
};

const DISTRIBUTION_SCHEMA: &str = "noos/wwm-web-capacity-benchmark-distribution/v1";
const REPORT_SCHEMA: &str = "noos/wwm-web-capacity-benchmark-report/v1";
const REAL_PILOT_SECONDS: u64 = 30 * 24 * 60 * 60;
const SNAPSHOT_INTERVAL: u64 = 4_096;
const INITIAL_LOGICAL_TIME: u64 = 1_700_000_000;
const TRUSTED_REAL_DISTRIBUTION_KEYS: &[&str] = &[];

#[derive(Debug)]
pub struct BenchmarkError(String);

impl BenchmarkError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for BenchmarkError {}

impl From<WebCapacityError> for BenchmarkError {
    fn from(error: WebCapacityError) -> Self {
        Self(error.to_string())
    }
}

impl From<std::io::Error> for BenchmarkError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<serde_json::Error> for BenchmarkError {
    fn from(error: serde_json::Error) -> Self {
        Self(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DistributionScope {
    SyntheticFixture,
    SignedReal30Day,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventWeights {
    pub offers: u64,
    pub active_page_heartbeats: u64,
    pub bounded_reports: u64,
    pub revokes: u64,
    pub expiries: u64,
    pub replacements: u64,
}

impl EventWeights {
    fn total(self) -> Option<u64> {
        self.offers
            .checked_add(self.active_page_heartbeats)?
            .checked_add(self.bounded_reports)?
            .checked_add(self.revokes)?
            .checked_add(self.expiries)?
            .checked_add(self.replacements)
    }

    fn all_positive(self) -> bool {
        self.offers > 0
            && self.active_page_heartbeats > 0
            && self.bounded_reports > 0
            && self.revokes > 0
            && self.expiries > 0
            && self.replacements > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkAssertions {
    pub max_total_rows: u64,
    pub max_sqlite_bytes: u64,
    pub max_peak_queue: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnDistribution {
    pub schema: String,
    pub scope: DistributionScope,
    pub observed_from: Option<u64>,
    pub observed_until: Option<u64>,
    pub signer_public_key: Option<String>,
    pub signature: Option<String>,
    pub weights: EventWeights,
    pub assertions: BenchmarkAssertions,
}

impl ChurnDistribution {
    pub fn from_path(path: &Path) -> Result<Self, BenchmarkError> {
        let bytes = fs::read(path).map_err(|error| {
            BenchmarkError::new(format!(
                "cannot read distribution {}: {error}",
                path.display()
            ))
        })?;
        let distribution: Self = serde_json::from_slice(&bytes).map_err(|error| {
            BenchmarkError::new(format!(
                "invalid closed distribution {}: {error}",
                path.display()
            ))
        })?;
        distribution.validate()?;
        Ok(distribution)
    }

    pub fn validate(&self) -> Result<(), BenchmarkError> {
        if self.schema != DISTRIBUTION_SCHEMA {
            return Err(BenchmarkError::new("unsupported churn-distribution schema"));
        }
        if !self.weights.all_positive() || self.weights.total().is_none() {
            return Err(BenchmarkError::new(
                "all six event weights must be positive and their sum must fit u64",
            ));
        }
        if self.assertions.max_total_rows == 0
            || self.assertions.max_sqlite_bytes == 0
            || self.assertions.max_peak_queue > 256
        {
            return Err(BenchmarkError::new(
                "distribution assertions are outside benchmark bounds",
            ));
        }
        match self.scope {
            DistributionScope::SyntheticFixture => {
                if self.observed_from.is_some()
                    || self.observed_until.is_some()
                    || self.signer_public_key.is_some()
                    || self.signature.is_some()
                {
                    return Err(BenchmarkError::new(
                        "SYNTHETIC_FIXTURE cannot carry measured-pilot identity fields",
                    ));
                }
                Ok(())
            }
            DistributionScope::SignedReal30Day => self.validate_real_scope(),
        }
    }

    fn validate_real_scope(&self) -> Result<(), BenchmarkError> {
        let observed_from = self.observed_from.ok_or_else(|| {
            BenchmarkError::new("SIGNED_REAL_30_DAY requires a signed observation interval")
        })?;
        let observed_until = self.observed_until.ok_or_else(|| {
            BenchmarkError::new("SIGNED_REAL_30_DAY requires a signed observation interval")
        })?;
        if observed_until.saturating_sub(observed_from) < REAL_PILOT_SECONDS {
            return Err(BenchmarkError::new(
                "SIGNED_REAL_30_DAY observation interval is shorter than 30 days",
            ));
        }
        let signer = self.signer_public_key.as_deref().ok_or_else(|| {
            BenchmarkError::new("SIGNED_REAL_30_DAY requires a trusted signer public key")
        })?;
        let signature = self.signature.as_deref().ok_or_else(|| {
            BenchmarkError::new("SIGNED_REAL_30_DAY requires a detached Ed25519 signature")
        })?;
        if signer.len() != 64 || signature.len() != 128 {
            return Err(BenchmarkError::new(
                "SIGNED_REAL_30_DAY signer or signature has the wrong encoded length",
            ));
        }
        if !TRUSTED_REAL_DISTRIBUTION_KEYS.contains(&signer) {
            return Err(BenchmarkError::new(
                "SIGNED_REAL_30_DAY is unavailable: no trusted pilot signer is configured",
            ));
        }
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let value = serde_json::to_value(unsigned)?;
        verify_json_signature(DomainId::SigWwmWebEvidenceV1, signer, signature, &value)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EventTally {
    pub attempted: u64,
    pub accepted: u64,
    pub rejected: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EventTallies {
    pub offers: EventTally,
    pub active_page_heartbeats: EventTally,
    pub bounded_reports: EventTally,
    pub revokes: EventTally,
    pub expiries: EventTally,
    pub replacements: EventTally,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct StateMetrics {
    pub hosts: u64,
    pub active_hosts: u64,
    pub sessions: u64,
    pub active_sessions: u64,
    pub assignments: u64,
    pub active_assignments: u64,
    pub assignment_rows: u64,
    pub reports: u64,
    pub pending_restore_tasks: u64,
    pub verifying_restore_tasks: u64,
    pub restores: u64,
    pub quarantine_bytes: u64,
    pub access_log_rows: u64,
    pub rate_limit_rows: u64,
    pub total_rows: u64,
}

impl From<StoreBenchmarkSnapshot> for StateMetrics {
    fn from(snapshot: StoreBenchmarkSnapshot) -> Self {
        Self {
            hosts: snapshot.hosts,
            active_hosts: snapshot.active_hosts,
            sessions: snapshot.sessions,
            active_sessions: snapshot.active_sessions,
            assignments: snapshot.assignments,
            active_assignments: snapshot.active_assignments,
            assignment_rows: snapshot.assignment_rows,
            reports: snapshot.reports,
            pending_restore_tasks: snapshot.pending_restore_tasks,
            verifying_restore_tasks: snapshot.verifying_restore_tasks,
            restores: snapshot.restores,
            quarantine_bytes: snapshot.quarantine_bytes,
            access_log_rows: snapshot.access_log_rows,
            rate_limit_rows: snapshot.rate_limit_rows,
            total_rows: snapshot.total_rows(),
        }
    }
}

impl StateMetrics {
    fn observe(&mut self, value: Self) {
        self.hosts = self.hosts.max(value.hosts);
        self.active_hosts = self.active_hosts.max(value.active_hosts);
        self.sessions = self.sessions.max(value.sessions);
        self.active_sessions = self.active_sessions.max(value.active_sessions);
        self.assignments = self.assignments.max(value.assignments);
        self.active_assignments = self.active_assignments.max(value.active_assignments);
        self.assignment_rows = self.assignment_rows.max(value.assignment_rows);
        self.reports = self.reports.max(value.reports);
        self.pending_restore_tasks = self.pending_restore_tasks.max(value.pending_restore_tasks);
        self.verifying_restore_tasks = self
            .verifying_restore_tasks
            .max(value.verifying_restore_tasks);
        self.restores = self.restores.max(value.restores);
        self.quarantine_bytes = self.quarantine_bytes.max(value.quarantine_bytes);
        self.access_log_rows = self.access_log_rows.max(value.access_log_rows);
        self.rate_limit_rows = self.rate_limit_rows.max(value.rate_limit_rows);
        self.total_rows = self.total_rows.max(value.total_rows);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CompiledCaps {
    pub max_hosts: u32,
    pub max_active_sessions: u32,
    pub max_active_assignments: u32,
    pub max_pending_restore_tasks: u32,
    pub max_quarantine_bytes: u64,
    pub max_concurrent_restore_verifications: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BenchmarkClaims {
    pub coordinator_benchmark_only: bool,
    pub real_volunteers_observed: bool,
    pub real_availability_measured: bool,
    pub reconstruction_proved: bool,
    pub production_claim: bool,
    pub promotion_authorized: bool,
    pub e_wwm_23_real_pilot_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub schema: &'static str,
    pub experiment_id: &'static str,
    pub distribution_scope: DistributionScope,
    pub event_count: u64,
    pub seed: u64,
    pub events: EventTallies,
    pub restart_checkpoints: Vec<u64>,
    pub snapshot_interval_events: u64,
    pub final_state: StateMetrics,
    pub observed_peak_state: StateMetrics,
    pub sqlite_bytes: u64,
    pub observed_peak_sqlite_bytes: u64,
    pub observed_peak_queue: u64,
    pub deterministic_checksum_blake3: String,
    pub wall_clock_duration_ms: u128,
    pub raw_session_tokens_persisted: bool,
    pub raw_ip_or_user_agent_in_report: bool,
    pub caps: CompiledCaps,
    pub assertions: BenchmarkAssertions,
    pub claims: BenchmarkClaims,
}

#[derive(Debug, Clone)]
struct LiveSession {
    raw_token: String,
    token_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
enum EventKind {
    Offer,
    Heartbeat,
    Report,
    Revoke,
    Expiry,
    Replacement,
}

impl EventKind {
    fn code(self) -> u8 {
        match self {
            Self::Offer => 1,
            Self::Heartbeat => 2,
            Self::Report => 3,
            Self::Revoke => 4,
            Self::Expiry => 5,
            Self::Replacement => 6,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Outcome {
    Accepted,
    Rejected,
}

impl Outcome {
    fn code(self) -> u8 {
        match self {
            Self::Accepted => 1,
            Self::Rejected => 2,
        }
    }
}

pub fn run_benchmark(
    mut config: WebCapacityConfig,
    state_root: &Path,
    distribution: &ChurnDistribution,
    event_count: u64,
    seed: u64,
) -> Result<BenchmarkReport, BenchmarkError> {
    distribution.validate()?;
    if event_count == 0 {
        return Err(BenchmarkError::new("event count must be positive"));
    }
    if !matches!(distribution.scope, DistributionScope::SyntheticFixture) {
        return Err(BenchmarkError::new(
            "only SYNTHETIC_FIXTURE can run without separately trusted pilot evidence",
        ));
    }
    if !matches!(
        config.experiment_state,
        super::model::ExperimentState::LocalFixture
    ) {
        return Err(BenchmarkError::new(
            "benchmark requires the LOCAL_FIXTURE coordinator profile",
        ));
    }
    prepare_state_root(state_root)?;
    config.data_path = state_root.join("coordinator.sqlite");
    config.quarantine_dir = state_root.join("quarantine");
    fs::create_dir(&config.quarantine_dir)?;
    let limits = WebCapacityStoreLimits {
        max_hosts: config.max_hosts,
        max_active_sessions: config.max_active_sessions,
        max_active_assignments: config.max_active_assignments,
        max_pending_restore_tasks: config.max_pending_restore_tasks,
        max_quarantine_bytes: config.max_quarantine_bytes,
        max_concurrent_restore_verifications: config.max_concurrent_restore_verifications,
    };
    let origin = config
        .registered_origins
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| BenchmarkError::new("benchmark config has no registered origin"))?;
    let checkpoints = restart_checkpoints(event_count);
    let started = Instant::now();
    let mut store = WebCapacityStore::open_with_limits(&config.data_path, limits)?;
    let mut rng = SplitMix64::new(seed);
    let mut logical_time = INITIAL_LOGICAL_TIME;
    let mut sessions = Vec::<LiveSession>::with_capacity(config.max_active_sessions as usize);
    let mut raw_tokens = HashSet::<String>::new();
    let mut tallies = EventTallies::default();
    let mut peak = StateMetrics::default();
    let mut peak_sqlite_bytes = sqlite_disk_bytes(&config.data_path)?;
    let mut checksum = blake3::Hasher::new();
    let mut token_serial = 0_u64;

    for event_index in 1..=event_count {
        logical_time = logical_time.saturating_add(1);
        let kind = choose_event(distribution.weights, event_index, seed)?;
        let outcome = match kind {
            EventKind::Offer => execute_offer(
                &store,
                &config,
                &origin,
                logical_time,
                &mut rng,
                &mut token_serial,
                &mut sessions,
                &mut raw_tokens,
            )?,
            EventKind::Heartbeat => {
                execute_heartbeat(&store, &origin, logical_time, &mut rng, &mut sessions)?
            }
            EventKind::Report => {
                execute_report(&store, &origin, logical_time, &mut rng, &mut sessions)?
            }
            EventKind::Revoke => {
                execute_revoke(&store, &origin, logical_time, &mut rng, &mut sessions)?
            }
            EventKind::Expiry => {
                logical_time = logical_time
                    .saturating_add(REAL_PILOT_SECONDS)
                    .saturating_add(config.session_lifetime_seconds)
                    .saturating_add(1);
                store.purge_expired(logical_time, ACCESS_LOG_RETENTION_SECONDS)?;
                sessions.clear();
                Outcome::Accepted
            }
            EventKind::Replacement => {
                if !sessions.is_empty() {
                    let _ = execute_revoke(&store, &origin, logical_time, &mut rng, &mut sessions)?;
                }
                execute_offer(
                    &store,
                    &config,
                    &origin,
                    logical_time,
                    &mut rng,
                    &mut token_serial,
                    &mut sessions,
                    &mut raw_tokens,
                )?
            }
        };
        tally(&mut tallies, kind, outcome);
        checksum.update(&event_index.to_le_bytes());
        checksum.update(&logical_time.to_le_bytes());
        checksum.update(&[kind.code(), outcome.code()]);

        if event_index.is_multiple_of(SNAPSHOT_INTERVAL)
            || event_index == event_count
            || checkpoints.contains(&event_index)
        {
            let snapshot = store.benchmark_snapshot(logical_time)?;
            if snapshot.invalid_token_hash_rows != 0 {
                return Err(BenchmarkError::new(
                    "SQLite contains a session token value that is not a 32-byte hash",
                ));
            }
            peak.observe(snapshot.into());
            peak_sqlite_bytes = peak_sqlite_bytes.max(sqlite_disk_bytes(&config.data_path)?);
        }
        if checkpoints.contains(&event_index) {
            drop(store);
            store = WebCapacityStore::open_with_limits(&config.data_path, limits)?;
            let continuity = store.benchmark_snapshot(logical_time)?;
            checksum.update(&continuity.active_sessions.to_le_bytes());
            checksum.update(&continuity.reports.to_le_bytes());
        }
    }

    let final_snapshot = store.benchmark_snapshot(logical_time)?;
    if final_snapshot.invalid_token_hash_rows != 0 {
        return Err(BenchmarkError::new(
            "session token hashing invariant failed",
        ));
    }
    let final_state = StateMetrics::from(final_snapshot);
    peak.observe(final_state);
    drop(store);
    let sqlite_bytes = sqlite_disk_bytes(&config.data_path)?;
    peak_sqlite_bytes = peak_sqlite_bytes.max(sqlite_bytes);
    assert_caps(&config, distribution, peak, peak_sqlite_bytes)?;
    let raw_session_tokens_persisted = sqlite_contains_any(&config.data_path, &raw_tokens)?;
    if raw_session_tokens_persisted {
        return Err(BenchmarkError::new(
            "raw session token was persisted in SQLite",
        ));
    }
    checksum.update(&final_state.active_sessions.to_le_bytes());
    checksum.update(&final_state.reports.to_le_bytes());
    checksum.update(&final_state.total_rows.to_le_bytes());
    let checksum = checksum.finalize().to_hex().to_string();
    let duration = started.elapsed().as_millis();
    let caps = CompiledCaps {
        max_hosts: config.max_hosts,
        max_active_sessions: config.max_active_sessions,
        max_active_assignments: config.max_active_assignments,
        max_pending_restore_tasks: config.max_pending_restore_tasks,
        max_quarantine_bytes: config.max_quarantine_bytes,
        max_concurrent_restore_verifications: config.max_concurrent_restore_verifications,
    };
    if caps.max_active_assignments > HARD_MAX_ACTIVE_ASSIGNMENTS {
        return Err(BenchmarkError::new(
            "assignment cap exceeds compiled maximum",
        ));
    }
    Ok(BenchmarkReport {
        schema: REPORT_SCHEMA,
        experiment_id: "E-WWM-23",
        distribution_scope: distribution.scope,
        event_count,
        seed,
        events: tallies,
        restart_checkpoints: checkpoints,
        snapshot_interval_events: SNAPSHOT_INTERVAL,
        final_state,
        observed_peak_state: peak,
        sqlite_bytes,
        observed_peak_sqlite_bytes: peak_sqlite_bytes,
        observed_peak_queue: peak.pending_restore_tasks,
        deterministic_checksum_blake3: checksum,
        wall_clock_duration_ms: duration,
        raw_session_tokens_persisted: false,
        raw_ip_or_user_agent_in_report: false,
        caps,
        assertions: distribution.assertions,
        claims: BenchmarkClaims {
            coordinator_benchmark_only: true,
            real_volunteers_observed: false,
            real_availability_measured: false,
            reconstruction_proved: false,
            production_claim: false,
            promotion_authorized: false,
            e_wwm_23_real_pilot_pass: false,
        },
    })
}

fn prepare_state_root(path: &Path) -> Result<(), BenchmarkError> {
    if path.exists() {
        if path.read_dir()?.next().is_some() {
            return Err(BenchmarkError::new(format!(
                "temporary state root is not empty: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn restart_checkpoints(event_count: u64) -> Vec<u64> {
    let mut values = [
        event_count / 4,
        event_count / 2,
        event_count.saturating_mul(3) / 4,
    ]
    .into_iter()
    .filter(|value| *value > 0 && *value < event_count)
    .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn choose_event(
    weights: EventWeights,
    event_index: u64,
    seed: u64,
) -> Result<EventKind, BenchmarkError> {
    let total = weights
        .total()
        .ok_or_else(|| BenchmarkError::new("event-weight sum overflow"))?;
    let mut multiplier = (seed | 1) % total;
    if multiplier == 0 {
        multiplier = 1;
    }
    while greatest_common_divisor(multiplier, total) != 1 {
        multiplier = (multiplier + 2) % total;
        if multiplier == 0 {
            multiplier = 1;
        }
    }
    let position = (event_index - 1) % total;
    let value = ((u128::from(position) * u128::from(multiplier) + u128::from(seed % total))
        % u128::from(total)) as u64;
    let offer_end = weights.offers;
    let heartbeat_end = offer_end + weights.active_page_heartbeats;
    let report_end = heartbeat_end + weights.bounded_reports;
    let revoke_end = report_end + weights.revokes;
    let expiry_end = revoke_end + weights.expiries;
    Ok(if value < offer_end {
        EventKind::Offer
    } else if value < heartbeat_end {
        EventKind::Heartbeat
    } else if value < report_end {
        EventKind::Report
    } else if value < revoke_end {
        EventKind::Revoke
    } else if value < expiry_end {
        EventKind::Expiry
    } else {
        EventKind::Replacement
    })
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[allow(clippy::too_many_arguments)]
fn execute_offer(
    store: &WebCapacityStore,
    config: &WebCapacityConfig,
    origin: &str,
    now: u64,
    rng: &mut SplitMix64,
    token_serial: &mut u64,
    sessions: &mut Vec<LiveSession>,
    raw_tokens: &mut HashSet<String>,
) -> Result<Outcome, BenchmarkError> {
    let request = OfferRequest {
        schema: SCHEMA.to_owned(),
        record_kind: "OFFER_REQUEST".to_owned(),
        canonical_origin: origin.to_owned(),
        consent_version: config.consent_version.clone(),
        quota_shares: 16,
        effective_bytes: 16 * SHARE_BYTES,
        storage_class: StorageClass::Opfs,
        upload_policy: UploadPolicy {
            enabled: false,
            daily_egress_bytes: 0,
        },
        page_active: true,
    };
    validate_offer(config, &request, origin)?;
    *token_serial = token_serial.saturating_add(1);
    let mut raw = [0_u8; 32];
    for chunk in raw.chunks_exact_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    raw[..8].copy_from_slice(&token_serial.to_le_bytes());
    let raw_token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = session_token_hash(&raw_token, origin)?;
    let participant_id = domain_hash_hex(
        DomainId::WwmWebParticipantIdV1,
        &[origin.as_bytes(), &token_hash],
    )?;
    match store.create_session(
        token_hash,
        &participant_id,
        origin,
        &request.consent_version,
        request.quota_shares,
        request.effective_bytes,
        request.storage_class,
        &request.upload_policy,
        now,
        now.saturating_add(config.session_lifetime_seconds),
    ) {
        Ok(()) => {
            raw_tokens.insert(raw_token.clone());
            sessions.push(LiveSession {
                raw_token,
                token_hash,
            });
            Ok(Outcome::Accepted)
        }
        Err(WebCapacityError::Quota(_)) => Ok(Outcome::Rejected),
        Err(error) => Err(error.into()),
    }
}

fn execute_heartbeat(
    store: &WebCapacityStore,
    origin: &str,
    now: u64,
    rng: &mut SplitMix64,
    sessions: &mut Vec<LiveSession>,
) -> Result<Outcome, BenchmarkError> {
    let Some(index) = choose_session(sessions, rng) else {
        return Ok(Outcome::Rejected);
    };
    let request = HeartbeatRequest {
        schema: SCHEMA.to_owned(),
        record_kind: "HEARTBEAT_REQUEST".to_owned(),
        session_token: sessions[index].raw_token.clone(),
        canonical_origin: origin.to_owned(),
        page_active: true,
        stored_coordinate_digests: Vec::new(),
        available_bytes: 16 * SHARE_BYTES,
    };
    validate_heartbeat(&request, origin)?;
    let session = store.active_session(sessions[index].token_hash, origin, now, true)?;
    if session.is_none() {
        sessions.swap_remove(index);
        return Ok(Outcome::Rejected);
    }
    Ok(Outcome::Accepted)
}

fn execute_report(
    store: &WebCapacityStore,
    origin: &str,
    now: u64,
    rng: &mut SplitMix64,
    sessions: &mut Vec<LiveSession>,
) -> Result<Outcome, BenchmarkError> {
    let Some(index) = choose_session(sessions, rng) else {
        return Ok(Outcome::Rejected);
    };
    let report = ParticipantReport {
        schema: SCHEMA.to_owned(),
        record_kind: "PARTICIPANT_REPORT".to_owned(),
        session_token: sessions[index].raw_token.clone(),
        canonical_origin: origin.to_owned(),
        page_active: true,
        window_started_at: now.saturating_sub(60),
        window_ended_at: now,
        stored_count: 0,
        evicted_count: 0,
        error_count: 0,
        uploaded_bytes: 0,
        coordinate_digests: Vec::new(),
        error_codes: Vec::new(),
    };
    validate_report(&report, origin)?;
    let session = store.active_session(sessions[index].token_hash, origin, now, true)?;
    let Some(session) = session else {
        sessions.swap_remove(index);
        return Ok(Outcome::Rejected);
    };
    if u64::from(report.stored_count).saturating_mul(SHARE_BYTES) > session.effective_bytes
        || report.uploaded_bytes > session.upload_policy.daily_egress_bytes
    {
        return Ok(Outcome::Rejected);
    }
    store.record_report(session.token_hash, &report, now)?;
    Ok(Outcome::Accepted)
}

fn execute_revoke(
    store: &WebCapacityStore,
    origin: &str,
    now: u64,
    rng: &mut SplitMix64,
    sessions: &mut Vec<LiveSession>,
) -> Result<Outcome, BenchmarkError> {
    let Some(index) = choose_session(sessions, rng) else {
        return Ok(Outcome::Rejected);
    };
    let session = sessions.swap_remove(index);
    let request = RevocationRequest {
        schema: SCHEMA.to_owned(),
        record_kind: "REVOCATION_REQUEST".to_owned(),
        session_token: session.raw_token,
        canonical_origin: origin.to_owned(),
        local_deletion_requested: true,
    };
    validate_revocation(&request, origin)?;
    Ok(if store.revoke_session(session.token_hash, origin, now)? {
        Outcome::Accepted
    } else {
        Outcome::Rejected
    })
}

fn choose_session(sessions: &[LiveSession], rng: &mut SplitMix64) -> Option<usize> {
    if sessions.is_empty() {
        None
    } else {
        Some((rng.next_u64() as usize) % sessions.len())
    }
}

fn tally(tallies: &mut EventTallies, kind: EventKind, outcome: Outcome) {
    let tally = match kind {
        EventKind::Offer => &mut tallies.offers,
        EventKind::Heartbeat => &mut tallies.active_page_heartbeats,
        EventKind::Report => &mut tallies.bounded_reports,
        EventKind::Revoke => &mut tallies.revokes,
        EventKind::Expiry => &mut tallies.expiries,
        EventKind::Replacement => &mut tallies.replacements,
    };
    tally.attempted = tally.attempted.saturating_add(1);
    match outcome {
        Outcome::Accepted => tally.accepted = tally.accepted.saturating_add(1),
        Outcome::Rejected => tally.rejected = tally.rejected.saturating_add(1),
    }
}

fn assert_caps(
    config: &WebCapacityConfig,
    distribution: &ChurnDistribution,
    peak: StateMetrics,
    peak_sqlite_bytes: u64,
) -> Result<(), BenchmarkError> {
    if peak.active_hosts > u64::from(config.max_hosts)
        || peak.active_sessions > u64::from(config.max_active_sessions)
        || peak.active_assignments > u64::from(config.max_active_assignments)
        || peak.pending_restore_tasks > u64::from(config.max_pending_restore_tasks)
        || peak.quarantine_bytes > config.max_quarantine_bytes
        || peak.verifying_restore_tasks > u64::from(config.max_concurrent_restore_verifications)
    {
        return Err(BenchmarkError::new("compiled coordinator cap was exceeded"));
    }
    if peak.total_rows > distribution.assertions.max_total_rows {
        return Err(BenchmarkError::new(format!(
            "observed {} live rows, above distribution bound {}",
            peak.total_rows, distribution.assertions.max_total_rows
        )));
    }
    if peak_sqlite_bytes > distribution.assertions.max_sqlite_bytes {
        return Err(BenchmarkError::new(format!(
            "observed {peak_sqlite_bytes} SQLite bytes, above distribution bound {}",
            distribution.assertions.max_sqlite_bytes
        )));
    }
    if peak.pending_restore_tasks > distribution.assertions.max_peak_queue {
        return Err(BenchmarkError::new(
            "observed restore queue exceeds distribution bound",
        ));
    }
    Ok(())
}

fn sqlite_disk_bytes(path: &Path) -> Result<u64, BenchmarkError> {
    let mut total = file_len(path)?;
    let base = path.as_os_str().to_string_lossy();
    total = total.saturating_add(file_len(&PathBuf::from(format!("{base}-wal")))?);
    total = total.saturating_add(file_len(&PathBuf::from(format!("{base}-shm")))?);
    Ok(total)
}

fn file_len(path: &Path) -> Result<u64, BenchmarkError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn sqlite_contains_any(path: &Path, forbidden: &HashSet<String>) -> Result<bool, BenchmarkError> {
    if forbidden.is_empty() {
        return Ok(false);
    }
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.as_os_str().to_string_lossy())),
    ] {
        let bytes = match fs::read(&candidate) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if bytes
            .windows(43)
            .any(|window| forbidden.contains(std::str::from_utf8(window).unwrap_or_default()))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::web_capacity::{
        model::{ChainBinding, ExperimentState},
        SourceRegistration,
    };
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    fn distribution() -> ChurnDistribution {
        ChurnDistribution {
            schema: DISTRIBUTION_SCHEMA.to_owned(),
            scope: DistributionScope::SyntheticFixture,
            observed_from: None,
            observed_until: None,
            signer_public_key: None,
            signature: None,
            weights: EventWeights {
                offers: 30,
                active_page_heartbeats: 30,
                bounded_reports: 5,
                revokes: 10,
                expiries: 5,
                replacements: 20,
            },
            assertions: BenchmarkAssertions {
                max_total_rows: 1_000,
                max_sqlite_bytes: 16 * 1024 * 1024,
                max_peak_queue: 0,
            },
        }
    }

    fn config(root: &Path, max_sessions: u32) -> WebCapacityConfig {
        WebCapacityConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_path: root.join("unused.sqlite"),
            quarantine_dir: root.join("unused-quarantine"),
            artifact_manifest_path: root.join("unused-manifest"),
            coordinator_seed: [0x31; 32],
            chain_binding: ChainBinding {
                chain_id: "01".repeat(32),
                genesis_hash: "02".repeat(32),
                artifact_id: "03".repeat(32),
                manifest_root: "04".repeat(32),
            },
            experiment_state: ExperimentState::LocalFixture,
            source_allowlist: Vec::<SourceRegistration>::new(),
            registered_origins: BTreeSet::from(["https://capacity.example".to_owned()]),
            consent_version: "consent-v1".to_owned(),
            session_lifetime_seconds: 3_600,
            assignment_lifetime_seconds: 300,
            restore_lifetime_seconds: 300,
            host_probe_count: 1,
            request_timeout_ms: 1_000,
            rate_limit_per_minute: 10_000,
            max_hosts: 1_024,
            max_active_sessions: max_sessions,
            max_active_assignments: 4_096,
            max_pending_restore_tasks: 256,
            max_quarantine_bytes: 268_173_312,
            max_concurrent_restore_verifications: 8,
            loopback_test_transport: None,
        }
    }

    #[test]
    fn deterministic_checksum_and_restart_continuity() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let first_report = run_benchmark(
            config(first.path(), 32),
            &first.path().join("state"),
            &distribution(),
            2_000,
            77,
        )
        .unwrap();
        let second_report = run_benchmark(
            config(second.path(), 32),
            &second.path().join("state"),
            &distribution(),
            2_000,
            77,
        )
        .unwrap();
        assert_eq!(
            first_report.deterministic_checksum_blake3,
            second_report.deterministic_checksum_blake3
        );
        assert_eq!(first_report.events, second_report.events);
        assert_eq!(first_report.final_state, second_report.final_state);
        assert_eq!(first_report.restart_checkpoints, vec![500, 1_000, 1_500]);
        assert_eq!(first_report.events.offers.attempted, 600);
        assert_eq!(first_report.events.active_page_heartbeats.attempted, 600);
        assert_eq!(first_report.events.bounded_reports.attempted, 100);
        assert_eq!(first_report.events.revokes.attempted, 200);
        assert_eq!(first_report.events.expiries.attempted, 100);
        assert_eq!(first_report.events.replacements.attempted, 400);
    }

    #[test]
    fn cap_pressure_rejection_expiry_and_replacement_remain_bounded() {
        let directory = tempdir().unwrap();
        let report = run_benchmark(
            config(directory.path(), 2),
            &directory.path().join("state"),
            &distribution(),
            4_000,
            19,
        )
        .unwrap();
        assert!(report.events.offers.rejected > 0);
        assert!(report.events.expiries.accepted > 0);
        assert!(report.events.replacements.accepted > 0);
        assert!(report.observed_peak_state.active_sessions <= 2);
        assert_eq!(report.observed_peak_queue, 0);
    }

    #[test]
    fn report_contains_no_raw_token_ip_or_user_agent_and_no_claim_upgrade() {
        let directory = tempdir().unwrap();
        let report = run_benchmark(
            config(directory.path(), 8),
            &directory.path().join("state"),
            &distribution(),
            500,
            23,
        )
        .unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("raw-token"));
        assert!(!json.contains("192.0.2."));
        assert!(!json.contains("Mozilla/"));
        assert!(!report.raw_session_tokens_persisted);
        assert!(!report.raw_ip_or_user_agent_in_report);
        assert!(report.claims.coordinator_benchmark_only);
        assert!(!report.claims.real_volunteers_observed);
        assert!(!report.claims.e_wwm_23_real_pilot_pass);
    }

    #[test]
    fn unsigned_and_under_thirty_day_distributions_cannot_be_measured() {
        let mut unsigned = distribution();
        unsigned.scope = DistributionScope::SignedReal30Day;
        unsigned.observed_from = Some(100);
        unsigned.observed_until = Some(100 + REAL_PILOT_SECONDS);
        assert!(unsigned
            .validate()
            .unwrap_err()
            .to_string()
            .contains("trusted signer"));

        let mut short = unsigned;
        short.signer_public_key = Some("11".repeat(32));
        short.signature = Some("22".repeat(64));
        short.observed_until = Some(100 + REAL_PILOT_SECONDS - 1);
        assert!(short
            .validate()
            .unwrap_err()
            .to_string()
            .contains("shorter than 30 days"));
    }
}
