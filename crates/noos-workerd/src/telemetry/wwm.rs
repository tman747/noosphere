//! Privacy-safe aggregate telemetry for World Wide Mind application services.
//!
//! Metric keys are closed enums. There is no field for a job, request, user,
//! destination, model, snapshot, prompt, output, canary, receipt, or browser
//! origin identifier. Signed windows are operational evidence only and carry
//! zero consensus, finality, issuance, or activation authority.

use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

pub const MAX_SERIES_PER_WINDOW: usize = 256;
pub const MAX_POINTS_PER_SERIES: u64 = 100_000_000;
pub const MAX_RETENTION_BLOCKS: u64 = 201_600;
pub const REQUIRED_HEALTHY_REGIONS: u8 = 3;
pub const REQUIRED_INDEPENDENT_STATE_READS: u8 = 2;
pub const RECOVERY_WINDOWS: u8 = 3;
pub const WWM_TELEMETRY_CONSENSUS_WEIGHT: u64 = 0;
pub const WWM_TELEMETRY_FINALITY_WEIGHT: u64 = 0;
pub const WWM_TELEMETRY_ACTIVATION_AUTHORITY: bool = false;

const HISTOGRAM_UPPER_BOUNDS_MICROS: [u64; 8] = [
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    u64::MAX,
];

const PROHIBITED_LABEL_KEYS: [&str; 24] = [
    "address",
    "block_hash",
    "browser_origin",
    "canary",
    "destination",
    "dispute_id",
    "job",
    "job_id",
    "knowledge_snapshot_id",
    "mindlink_id",
    "model_root",
    "output",
    "peer_id",
    "prompt",
    "receipt_id",
    "request_id",
    "route_descriptor_id",
    "session_id",
    "transaction",
    "txid",
    "user_id",
    "vault_id",
    "wallet",
    "website",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    InvalidMetric,
    ProhibitedLabel,
    UnknownLabel,
    CardinalityExceeded,
    InvalidWindow,
    InvalidSignature,
    DuplicateWindow,
    UnknownWindow,
    RetentionExpired,
    InvalidAuditAccess,
    InvalidDeletionReceipt,
    InvalidIncidentSignal,
    InvalidTransition,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MetricFamily {
    QueryLatency = 0,
    TokenThroughput = 1,
    Availability = 2,
    RetrievalLatency = 3,
    RouteLatency = 4,
    QueueDepth = 5,
    PrivateCacheBytes = 6,
    RefundLatency = 7,
    ContractViolation = 8,
    RegionHealth = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PrivacyClass {
    Open = 0,
    Attested = 1,
    SealedWitness = 2,
    DeepSealed = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OutcomeClass {
    Ok = 0,
    Rejected = 1,
    Timeout = 2,
    Refunded = 3,
    Error = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RouteClass {
    Direct = 0,
    FastOhttp = 1,
    FastOnion = 2,
    DeepMix = 3,
    RemoteConfidentialBrowser = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AssuranceClass {
    Soft = 0,
    Anchored = 1,
    AssuredTee = 2,
    Proven = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RegionClass {
    Primary = 0,
    Secondary = 1,
    Tertiary = 2,
    Other = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MetricKey {
    pub family: MetricFamily,
    pub privacy: PrivacyClass,
    pub outcome: OutcomeClass,
    pub route: RouteClass,
    pub assurance: AssuranceClass,
    pub region: RegionClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregatePoint {
    pub key: MetricKey,
    pub count: u64,
    pub sum: u128,
    pub minimum: u64,
    pub maximum: u64,
    pub histogram_counts: [u64; 8],
}

impl AggregatePoint {
    fn observe(&mut self, value: u64) -> Result<(), TelemetryError> {
        if self.count >= MAX_POINTS_PER_SERIES {
            return Err(TelemetryError::CardinalityExceeded);
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or(TelemetryError::ArithmeticOverflow)?;
        self.sum = self
            .sum
            .checked_add(u128::from(value))
            .ok_or(TelemetryError::ArithmeticOverflow)?;
        self.minimum = self.minimum.min(value);
        self.maximum = self.maximum.max(value);
        let bucket = HISTOGRAM_UPPER_BOUNDS_MICROS
            .iter()
            .position(|upper| value <= *upper)
            .ok_or(TelemetryError::InvalidMetric)?;
        self.histogram_counts[bucket] = self.histogram_counts[bucket]
            .checked_add(1)
            .ok_or(TelemetryError::ArithmeticOverflow)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), TelemetryError> {
        let buckets = self
            .histogram_counts
            .into_iter()
            .try_fold(0_u64, |total, count| {
                total
                    .checked_add(count)
                    .ok_or(TelemetryError::ArithmeticOverflow)
            })?;
        if self.count == 0
            || self.count > MAX_POINTS_PER_SERIES
            || self.minimum > self.maximum
            || buckets != self.count
        {
            return Err(TelemetryError::InvalidMetric);
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        encode_key(out, self.key);
        out.extend(self.count.to_le_bytes());
        out.extend(self.sum.to_le_bytes());
        out.extend(self.minimum.to_le_bytes());
        out.extend(self.maximum.to_le_bytes());
        for count in self.histogram_counts {
            out.extend(count.to_le_bytes());
        }
    }
}

#[derive(Debug, Default)]
pub struct WindowAccumulator {
    points: BTreeMap<MetricKey, AggregatePoint>,
}

impl WindowAccumulator {
    pub fn observe(&mut self, key: MetricKey, value: u64) -> Result<(), TelemetryError> {
        if !self.points.contains_key(&key) && self.points.len() >= MAX_SERIES_PER_WINDOW {
            return Err(TelemetryError::CardinalityExceeded);
        }
        let point = self.points.entry(key).or_insert(AggregatePoint {
            key,
            count: 0,
            sum: 0,
            minimum: u64::MAX,
            maximum: 0,
            histogram_counts: [0; 8],
        });
        point.observe(value)
    }

    pub fn seal(
        self,
        window_start_height: u64,
        window_end_height: u64,
        retention_until_height: u64,
        policy_root: Hash32,
        producer_control_cluster: Hash32,
        producer: &Keypair,
    ) -> Result<TelemetryWindow, TelemetryError> {
        TelemetryWindow::seal(
            self.points.into_values().collect(),
            window_start_height,
            window_end_height,
            retention_until_height,
            policy_root,
            producer_control_cluster,
            producer,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryWindow {
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub retention_until_height: u64,
    pub policy_root: Hash32,
    pub producer_key: Hash32,
    pub producer_control_cluster: Hash32,
    pub points: Vec<AggregatePoint>,
    pub metrics_root: Hash32,
    pub window_id: Hash32,
    pub signature: [u8; 64],
}

impl TelemetryWindow {
    fn seal(
        points: Vec<AggregatePoint>,
        window_start_height: u64,
        window_end_height: u64,
        retention_until_height: u64,
        policy_root: Hash32,
        producer_control_cluster: Hash32,
        producer: &Keypair,
    ) -> Result<Self, TelemetryError> {
        let metrics_root = points_root(&points)?;
        let mut value = Self {
            window_start_height,
            window_end_height,
            retention_until_height,
            policy_root,
            producer_key: producer.public_key().into_bytes(),
            producer_control_cluster,
            points,
            metrics_root,
            window_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body()?;
        value.window_id = digest(DomainId::WwmTelemetryRoot, &[&body])?;
        value.signature = sign(producer, DomainId::WwmTelemetryRoot, value.window_id, &body)?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TelemetryError> {
        self.validate_shape()?;
        let body = self.body()?;
        if digest(DomainId::WwmTelemetryRoot, &[&body])? != self.window_id {
            return Err(TelemetryError::InvalidWindow);
        }
        verify(
            self.producer_key,
            DomainId::WwmTelemetryRoot,
            self.window_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), TelemetryError> {
        let retention = self
            .retention_until_height
            .checked_sub(self.window_end_height)
            .ok_or(TelemetryError::InvalidWindow)?;
        if self.window_start_height >= self.window_end_height
            || retention == 0
            || retention > MAX_RETENTION_BLOCKS
            || [
                self.policy_root,
                self.producer_key,
                self.producer_control_cluster,
                self.metrics_root,
            ]
            .contains(&[0; 32])
            || self.points.is_empty()
            || self.points.len() > MAX_SERIES_PER_WINDOW
            || !strictly_sorted_by(&self.points, |point| point.key)
            || points_root(&self.points)? != self.metrics_root
        {
            return Err(TelemetryError::InvalidWindow);
        }
        for point in &self.points {
            point.validate()?;
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, TelemetryError> {
        let mut out = Vec::new();
        out.extend(self.window_start_height.to_le_bytes());
        out.extend(self.window_end_height.to_le_bytes());
        out.extend(self.retention_until_height.to_le_bytes());
        out.extend(self.policy_root);
        out.extend(self.producer_key);
        out.extend(self.producer_control_cluster);
        out.extend(self.metrics_root);
        out.extend(
            u16::try_from(self.points.len())
                .map_err(|_| TelemetryError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for point in &self.points {
            point.encode(&mut out);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditRole {
    Operator = 0,
    IndependentAuditor = 1,
    IncidentResponder = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAccessReceipt {
    pub role: AuditRole,
    pub requester_key: Hash32,
    pub purpose_root: Hash32,
    pub policy_root: Hash32,
    pub window_ids: Vec<Hash32>,
    pub issued_height: u64,
    pub expires_at_height: u64,
    pub authority_key: Hash32,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl AuditAccessReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        role: AuditRole,
        requester_key: Hash32,
        purpose_root: Hash32,
        policy_root: Hash32,
        window_ids: Vec<Hash32>,
        issued_height: u64,
        expires_at_height: u64,
        authority: &Keypair,
    ) -> Result<Self, TelemetryError> {
        let mut value = Self {
            role,
            requester_key,
            purpose_root,
            policy_root,
            window_ids,
            issued_height,
            expires_at_height,
            authority_key: authority.public_key().into_bytes(),
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body()?;
        value.receipt_id = digest(DomainId::WwmTelemetryRoot, &[b"AUDIT-ACCESS", &body])?;
        value.signature = sign(
            authority,
            DomainId::WwmTelemetryRoot,
            value.receipt_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self, height: u64) -> Result<(), TelemetryError> {
        self.validate_shape()?;
        if height < self.issued_height || height >= self.expires_at_height {
            return Err(TelemetryError::InvalidAuditAccess);
        }
        let body = self.body()?;
        if digest(DomainId::WwmTelemetryRoot, &[b"AUDIT-ACCESS", &body])? != self.receipt_id {
            return Err(TelemetryError::InvalidAuditAccess);
        }
        verify(
            self.authority_key,
            DomainId::WwmTelemetryRoot,
            self.receipt_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), TelemetryError> {
        if [
            self.requester_key,
            self.purpose_root,
            self.policy_root,
            self.authority_key,
        ]
        .contains(&[0; 32])
            || self.window_ids.is_empty()
            || !strictly_sorted(&self.window_ids)
            || self.issued_height >= self.expires_at_height
        {
            return Err(TelemetryError::InvalidAuditAccess);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, TelemetryError> {
        let mut out = Vec::new();
        out.push(self.role as u8);
        out.extend(self.requester_key);
        out.extend(self.purpose_root);
        out.extend(self.policy_root);
        push_hashes(&mut out, &self.window_ids)?;
        out.extend(self.issued_height.to_le_bytes());
        out.extend(self.expires_at_height.to_le_bytes());
        out.extend(self.authority_key);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionReceipt {
    pub deleted_window_ids: Vec<Hash32>,
    pub policy_root: Hash32,
    pub deletion_height: u64,
    pub operator_key: Hash32,
    pub receipt_id: Hash32,
    pub signature: [u8; 64],
}

impl DeletionReceipt {
    fn issue(
        deleted_window_ids: Vec<Hash32>,
        policy_root: Hash32,
        deletion_height: u64,
        operator: &Keypair,
    ) -> Result<Self, TelemetryError> {
        let mut value = Self {
            deleted_window_ids,
            policy_root,
            deletion_height,
            operator_key: operator.public_key().into_bytes(),
            receipt_id: [0; 32],
            signature: [0; 64],
        };
        value.validate_shape()?;
        let body = value.body()?;
        value.receipt_id = digest(DomainId::WwmTelemetryRoot, &[b"DELETE", &body])?;
        value.signature = sign(
            operator,
            DomainId::WwmTelemetryRoot,
            value.receipt_id,
            &body,
        )?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TelemetryError> {
        self.validate_shape()?;
        let body = self.body()?;
        if digest(DomainId::WwmTelemetryRoot, &[b"DELETE", &body])? != self.receipt_id {
            return Err(TelemetryError::InvalidDeletionReceipt);
        }
        verify(
            self.operator_key,
            DomainId::WwmTelemetryRoot,
            self.receipt_id,
            &body,
            self.signature,
        )
    }

    fn validate_shape(&self) -> Result<(), TelemetryError> {
        if self.deleted_window_ids.is_empty()
            || !strictly_sorted(&self.deleted_window_ids)
            || self.policy_root == [0; 32]
            || self.operator_key == [0; 32]
        {
            return Err(TelemetryError::InvalidDeletionReceipt);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, TelemetryError> {
        let mut out = Vec::new();
        push_hashes(&mut out, &self.deleted_window_ids)?;
        out.extend(self.policy_root);
        out.extend(self.deletion_height.to_le_bytes());
        out.extend(self.operator_key);
        Ok(out)
    }
}

#[derive(Debug, Default)]
pub struct TelemetryArchive {
    windows: BTreeMap<Hash32, TelemetryWindow>,
}

impl TelemetryArchive {
    pub fn register(&mut self, window: TelemetryWindow) -> Result<(), TelemetryError> {
        window.validate()?;
        if self.windows.contains_key(&window.window_id) {
            return Err(TelemetryError::DuplicateWindow);
        }
        self.windows.insert(window.window_id, window);
        Ok(())
    }

    pub fn audit(
        &self,
        access: &AuditAccessReceipt,
        height: u64,
    ) -> Result<Vec<&TelemetryWindow>, TelemetryError> {
        access.validate(height)?;
        let mut windows = Vec::with_capacity(access.window_ids.len());
        for id in &access.window_ids {
            let window = self.windows.get(id).ok_or(TelemetryError::UnknownWindow)?;
            if window.policy_root != access.policy_root {
                return Err(TelemetryError::InvalidAuditAccess);
            }
            if height >= window.retention_until_height {
                return Err(TelemetryError::RetentionExpired);
            }
            windows.push(window);
        }
        Ok(windows)
    }

    pub fn delete_expired(
        &mut self,
        height: u64,
        policy_root: Hash32,
        operator: &Keypair,
    ) -> Result<DeletionReceipt, TelemetryError> {
        let expired = self
            .windows
            .iter()
            .filter_map(|(id, window)| {
                (height >= window.retention_until_height && window.policy_root == policy_root)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return Err(TelemetryError::RetentionExpired);
        }
        for id in &expired {
            self.windows.remove(id);
        }
        DeletionReceipt::issue(expired, policy_root, height, operator)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveEventKind {
    Prompt,
    Output,
    PrivateCanary,
    Destination,
    BrowserHistory,
    UserIdentifier,
    JobIdentifier,
    AggregateCounter,
}

pub fn admit_log_event(kind: SensitiveEventKind) -> Result<(), TelemetryError> {
    if kind == SensitiveEventKind::AggregateCounter {
        Ok(())
    } else {
        Err(TelemetryError::ProhibitedLabel)
    }
}

pub fn validate_external_labels(labels: &[(&str, &str)]) -> Result<(), TelemetryError> {
    let mut seen = BTreeSet::new();
    for (key, value) in labels {
        if !seen.insert(*key) {
            return Err(TelemetryError::UnknownLabel);
        }
        if PROHIBITED_LABEL_KEYS.contains(key) {
            return Err(TelemetryError::ProhibitedLabel);
        }
        let valid = match *key {
            "privacy_profile" => matches!(
                *value,
                "open" | "attested" | "sealed_witness" | "deep_sealed"
            ),
            "outcome" => matches!(*value, "ok" | "rejected" | "timeout" | "refunded" | "error"),
            "route_class" => matches!(
                *value,
                "direct" | "fast_ohttp" | "fast_onion" | "deep_mix" | "remote_confidential_browser"
            ),
            "assurance" => matches!(*value, "soft" | "anchored" | "assured_tee" | "proven"),
            "region_class" => matches!(*value, "primary" | "secondary" | "tertiary" | "other"),
            _ => return Err(TelemetryError::UnknownLabel),
        };
        if !valid {
            return Err(TelemetryError::UnknownLabel);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalMode {
    Normal,
    RegionDegraded,
    Blackout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunbookAction {
    FreezeModelActivation,
    FreezeNewPrivateJobs,
    PreserveRefundPath,
    FailOverHealthyRegions,
    RequireIndependentStateQuorum,
    PurgePrivateCaches,
    ContinueAggregateTelemetry,
    AwaitConsecutiveHealthyWindows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentSignals {
    pub healthy_regions: u8,
    pub independent_state_reads: u8,
    pub private_backend_healthy: bool,
    pub refund_path_healthy: bool,
    pub private_cache_purge_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunbookDecision {
    pub mode: OperationalMode,
    pub actions: Vec<RunbookAction>,
    pub admit_public_jobs: bool,
    pub admit_private_jobs: bool,
    pub model_activation_allowed: bool,
    pub refunds_available: bool,
    pub healthy_recovery_windows: u8,
}

#[derive(Debug)]
pub struct OperationsStateMachine {
    mode: OperationalMode,
    healthy_recovery_windows: u8,
}

impl Default for OperationsStateMachine {
    fn default() -> Self {
        Self {
            mode: OperationalMode::Normal,
            healthy_recovery_windows: RECOVERY_WINDOWS,
        }
    }
}

impl OperationsStateMachine {
    pub fn evaluate(
        &mut self,
        signals: IncidentSignals,
    ) -> Result<RunbookDecision, TelemetryError> {
        if signals.healthy_regions > 32 || signals.independent_state_reads > 32 {
            return Err(TelemetryError::InvalidIncidentSignal);
        }
        let blackout = signals.healthy_regions == 0
            || signals.independent_state_reads < REQUIRED_INDEPENDENT_STATE_READS;
        let degraded = signals.healthy_regions < REQUIRED_HEALTHY_REGIONS
            || !signals.private_backend_healthy
            || !signals.private_cache_purge_complete;
        if blackout {
            self.mode = OperationalMode::Blackout;
            self.healthy_recovery_windows = 0;
        } else if degraded {
            self.mode = OperationalMode::RegionDegraded;
            self.healthy_recovery_windows = 0;
        } else if self.mode != OperationalMode::Normal {
            self.healthy_recovery_windows = self
                .healthy_recovery_windows
                .checked_add(1)
                .ok_or(TelemetryError::ArithmeticOverflow)?;
            if self.healthy_recovery_windows >= RECOVERY_WINDOWS {
                self.mode = OperationalMode::Normal;
            }
        }
        Ok(self.decision(signals.refund_path_healthy))
    }

    fn decision(&self, refund_path_healthy: bool) -> RunbookDecision {
        let actions = match self.mode {
            OperationalMode::Normal => vec![
                RunbookAction::FreezeModelActivation,
                RunbookAction::ContinueAggregateTelemetry,
            ],
            OperationalMode::RegionDegraded => vec![
                RunbookAction::FreezeModelActivation,
                RunbookAction::FreezeNewPrivateJobs,
                RunbookAction::PreserveRefundPath,
                RunbookAction::FailOverHealthyRegions,
                RunbookAction::PurgePrivateCaches,
                RunbookAction::ContinueAggregateTelemetry,
                RunbookAction::AwaitConsecutiveHealthyWindows,
            ],
            OperationalMode::Blackout => vec![
                RunbookAction::FreezeModelActivation,
                RunbookAction::FreezeNewPrivateJobs,
                RunbookAction::PreserveRefundPath,
                RunbookAction::RequireIndependentStateQuorum,
                RunbookAction::PurgePrivateCaches,
                RunbookAction::ContinueAggregateTelemetry,
                RunbookAction::AwaitConsecutiveHealthyWindows,
            ],
        };
        RunbookDecision {
            mode: self.mode,
            actions,
            admit_public_jobs: self.mode != OperationalMode::Blackout,
            admit_private_jobs: self.mode == OperationalMode::Normal,
            model_activation_allowed: false,
            refunds_available: refund_path_healthy,
            healthy_recovery_windows: self.healthy_recovery_windows,
        }
    }
}

#[derive(Debug, Default)]
pub struct PrivateCacheAggregate {
    bytes_by_bucket: BTreeMap<u32, u64>,
}

impl PrivateCacheAggregate {
    pub fn observe_bucket(&mut self, size_bucket_bytes: u32) -> Result<(), TelemetryError> {
        if !matches!(size_bucket_bytes, 65_536 | 262_144 | 1_048_576) {
            return Err(TelemetryError::InvalidMetric);
        }
        let count = self
            .bytes_by_bucket
            .get(&size_bucket_bytes)
            .copied()
            .unwrap_or(0);
        self.bytes_by_bucket.insert(
            size_bucket_bytes,
            count
                .checked_add(1)
                .ok_or(TelemetryError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn purge(&mut self) {
        self.bytes_by_bucket.clear();
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes_by_bucket.is_empty()
    }
}

fn points_root(points: &[AggregatePoint]) -> Result<Hash32, TelemetryError> {
    if points.is_empty() || !strictly_sorted_by(points, |point| point.key) {
        return Err(TelemetryError::InvalidWindow);
    }
    let mut out = Vec::new();
    out.extend(
        u16::try_from(points.len())
            .map_err(|_| TelemetryError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for point in points {
        point.encode(&mut out);
    }
    digest(DomainId::WwmTelemetryRoot, &[b"METRICS", &out])
}

fn encode_key(out: &mut Vec<u8>, key: MetricKey) {
    out.push(key.family as u8);
    out.push(key.privacy as u8);
    out.push(key.outcome as u8);
    out.push(key.route as u8);
    out.push(key.assurance as u8);
    out.push(key.region as u8);
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T, K: Ord + Copy>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn push_hashes(out: &mut Vec<u8>, values: &[Hash32]) -> Result<(), TelemetryError> {
    out.extend(
        u16::try_from(values.len())
            .map_err(|_| TelemetryError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for value in values {
        out.extend(value);
    }
    Ok(())
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, TelemetryError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| TelemetryError::InvalidSignature)
}

fn sign(
    signer: &Keypair,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
) -> Result<[u8; 64], TelemetryError> {
    signer
        .sign_domain(
            DomainId::SigWwm,
            &[object_domain.registry_id().as_bytes(), &object_id, body],
        )
        .map(Signature::into_bytes)
        .map_err(|_| TelemetryError::InvalidSignature)
}

fn verify(
    public_key: Hash32,
    object_domain: DomainId,
    object_id: Hash32,
    body: &[u8],
    signature: [u8; 64],
) -> Result<(), TelemetryError> {
    verify_domain(
        DomainId::SigWwm,
        &PublicKey::from_bytes(public_key),
        &[object_domain.registry_id().as_bytes(), &object_id, body],
        &Signature::from_bytes(signature),
    )
    .map_err(|_| TelemetryError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]

    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn key(family: MetricFamily, privacy: PrivacyClass) -> MetricKey {
        MetricKey {
            family,
            privacy,
            outcome: OutcomeClass::Ok,
            route: RouteClass::FastOhttp,
            assurance: AssuranceClass::AssuredTee,
            region: RegionClass::Primary,
        }
    }

    fn window() -> TelemetryWindow {
        let mut accumulator = WindowAccumulator::default();
        accumulator
            .observe(
                key(MetricFamily::QueryLatency, PrivacyClass::Attested),
                200_000,
            )
            .unwrap();
        accumulator
            .observe(
                key(MetricFamily::QueryLatency, PrivacyClass::Attested),
                300_000,
            )
            .unwrap();
        accumulator
            .observe(key(MetricFamily::TokenThroughput, PrivacyClass::Open), 50)
            .unwrap();
        accumulator
            .seal(100, 110, 150, h(1), h(2), &Keypair::from_seed([3; 32]))
            .unwrap()
    }

    #[test]
    fn signed_windows_reproduce_aggregate_slos_without_identifiers() {
        let window = window();
        window.validate().unwrap();
        assert_eq!(window.points.len(), 2);
        let latency = window
            .points
            .iter()
            .find(|point| point.key.family == MetricFamily::QueryLatency)
            .unwrap();
        assert_eq!(latency.count, 2);
        assert_eq!(latency.sum, 500_000);
        assert_eq!(latency.minimum, 200_000);
        assert_eq!(latency.maximum, 300_000);
        assert_eq!(WWM_TELEMETRY_CONSENSUS_WEIGHT, 0);
        assert_eq!(WWM_TELEMETRY_FINALITY_WEIGHT, 0);
        assert!(!WWM_TELEMETRY_ACTIVATION_AUTHORITY);
    }

    #[test]
    fn private_identifiers_canaries_and_unbounded_labels_are_rejected() {
        for key in [
            "job_id",
            "user_id",
            "destination",
            "prompt",
            "output",
            "canary",
        ] {
            assert_eq!(
                validate_external_labels(&[(key, "anything")]),
                Err(TelemetryError::ProhibitedLabel)
            );
        }
        assert_eq!(
            validate_external_labels(&[("region", "us-east-1")]),
            Err(TelemetryError::UnknownLabel)
        );
        assert_eq!(
            admit_log_event(SensitiveEventKind::PrivateCanary),
            Err(TelemetryError::ProhibitedLabel)
        );
        assert_eq!(
            admit_log_event(SensitiveEventKind::AggregateCounter),
            Ok(())
        );
    }

    #[test]
    fn retention_deletes_expired_windows_and_emits_signed_receipt() {
        let window = window();
        let id = window.window_id;
        let mut archive = TelemetryArchive::default();
        archive.register(window).unwrap();
        let authority = Keypair::from_seed([4; 32]);
        let access = AuditAccessReceipt::issue(
            AuditRole::IndependentAuditor,
            h(5),
            h(6),
            h(1),
            vec![id],
            120,
            140,
            &authority,
        )
        .unwrap();
        assert_eq!(archive.audit(&access, 130).unwrap().len(), 1);
        let receipt = archive
            .delete_expired(150, h(1), &Keypair::from_seed([7; 32]))
            .unwrap();
        receipt.validate().unwrap();
        assert_eq!(receipt.deleted_window_ids, vec![id]);
        assert_eq!(
            archive.audit(&access, 130),
            Err(TelemetryError::UnknownWindow)
        );
    }

    #[test]
    fn blackout_freezes_jobs_and_activation_but_preserves_refunds() {
        let mut machine = OperationsStateMachine::default();
        let decision = machine
            .evaluate(IncidentSignals {
                healthy_regions: 0,
                independent_state_reads: 0,
                private_backend_healthy: false,
                refund_path_healthy: true,
                private_cache_purge_complete: false,
            })
            .unwrap();
        assert_eq!(decision.mode, OperationalMode::Blackout);
        assert!(!decision.admit_public_jobs);
        assert!(!decision.admit_private_jobs);
        assert!(!decision.model_activation_allowed);
        assert!(decision.refunds_available);
        assert!(decision
            .actions
            .contains(&RunbookAction::PurgePrivateCaches));
        assert!(decision
            .actions
            .contains(&RunbookAction::RequireIndependentStateQuorum));
    }

    #[test]
    fn recovery_requires_three_consecutive_healthy_windows() {
        let mut machine = OperationsStateMachine::default();
        machine
            .evaluate(IncidentSignals {
                healthy_regions: 1,
                independent_state_reads: 2,
                private_backend_healthy: false,
                refund_path_healthy: true,
                private_cache_purge_complete: false,
            })
            .unwrap();
        for expected in [1, 2] {
            let decision = machine
                .evaluate(IncidentSignals {
                    healthy_regions: 3,
                    independent_state_reads: 2,
                    private_backend_healthy: true,
                    refund_path_healthy: true,
                    private_cache_purge_complete: true,
                })
                .unwrap();
            assert_eq!(decision.mode, OperationalMode::RegionDegraded);
            assert_eq!(decision.healthy_recovery_windows, expected);
        }
        let recovered = machine
            .evaluate(IncidentSignals {
                healthy_regions: 3,
                independent_state_reads: 2,
                private_backend_healthy: true,
                refund_path_healthy: true,
                private_cache_purge_complete: true,
            })
            .unwrap();
        assert_eq!(recovered.mode, OperationalMode::Normal);
        assert!(recovered.admit_public_jobs);
        assert!(recovered.admit_private_jobs);
        assert!(!recovered.model_activation_allowed);
    }

    #[test]
    fn private_cache_uses_only_fixed_size_aggregate_buckets_and_purges() {
        let mut cache = PrivateCacheAggregate::default();
        cache.observe_bucket(65_536).unwrap();
        cache.observe_bucket(262_144).unwrap();
        assert_eq!(
            cache.observe_bucket(70_000),
            Err(TelemetryError::InvalidMetric)
        );
        cache.purge();
        assert!(cache.is_empty());
    }
}
