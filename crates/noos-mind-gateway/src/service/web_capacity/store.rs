use super::{
    model::{
        AssignmentRow, InventoryRow, ParticipantReport, StaticHostManifest, StaticInventory,
        StorageClass, UploadPolicy, ACCESS_LOG_RETENTION_SECONDS,
        HOST_VERIFICATION_MAX_AGE_SECONDS, SHARE_BYTES,
    },
    security::{decode_hex32, now_seconds},
    Result, WebCapacityError,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub token_hash: [u8; 32],
    pub participant_id: String,
    pub origin: String,
    pub quota_shares: u16,
    pub effective_bytes: u64,
    pub upload_policy: UploadPolicy,
    pub last_active_at: u64,
}

#[derive(Debug, Clone)]
pub struct StoredRestoreTask {
    pub task_id: String,
    pub participant_id: String,
    pub origin: String,
    pub coordinate: InventoryRow,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct CompletedRestoreRecord {
    pub task: StoredRestoreTask,
    pub quarantine_id: String,
    pub coordinate_digest: String,
    pub bytes: u64,
    pub path: PathBuf,
    pub accepted_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRefreshTarget {
    pub origin: String,
    pub generation: u64,
}

#[derive(Debug)]
struct AssignmentCandidate {
    host_id: [u8; 32],
    row: AssignmentRow,
    provider: String,
    region: String,
    control_cluster: String,
    coordinate_provider_copies: u64,
    coordinate_region_copies: u64,
    coordinate_cluster_copies: u64,
    global_provider_load: u64,
    global_region_load: u64,
    global_cluster_load: u64,
    global_host_load: u64,
}

#[derive(Default)]
struct BatchDomainLoad {
    providers: BTreeMap<String, u64>,
    regions: BTreeMap<String, u64>,
    control_clusters: BTreeMap<String, u64>,
    hosts: BTreeMap<[u8; 32], u64>,
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct AssignmentCandidateScore<'a> {
    coordinate_provider_copies: u64,
    coordinate_cluster_copies: u64,
    coordinate_region_copies: u64,
    provider_load: u64,
    cluster_load: u64,
    region_load: u64,
    host_load: u64,
    provider: &'a str,
    control_cluster: &'a str,
    region: &'a str,
    host_id: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct WebCapacityStoreLimits {
    pub max_hosts: u32,
    pub max_active_sessions: u32,
    pub max_active_assignments: u32,
    pub max_pending_restore_tasks: u32,
    pub max_quarantine_bytes: u64,
    pub max_concurrent_restore_verifications: u32,
}

impl Default for WebCapacityStoreLimits {
    fn default() -> Self {
        Self {
            max_hosts: 1_024,
            max_active_sessions: 4_096,
            max_active_assignments: 4_096,
            max_pending_restore_tasks: 256,
            max_quarantine_bytes: 268_173_312,
            max_concurrent_restore_verifications: 8,
        }
    }
}

impl WebCapacityStoreLimits {
    fn validate(self) -> Result<Self> {
        let hard = Self::default();
        if self.max_hosts == 0
            || self.max_hosts > hard.max_hosts
            || self.max_active_sessions == 0
            || self.max_active_sessions > hard.max_active_sessions
            || self.max_active_assignments == 0
            || self.max_active_assignments > hard.max_active_assignments
            || self.max_pending_restore_tasks == 0
            || self.max_pending_restore_tasks > hard.max_pending_restore_tasks
            || self.max_quarantine_bytes == 0
            || self.max_quarantine_bytes > super::config::HARD_MAX_QUARANTINE_BYTES
            || self.max_concurrent_restore_verifications == 0
            || self.max_concurrent_restore_verifications
                > hard.max_concurrent_restore_verifications
        {
            return Err(WebCapacityError::Config(
                "web-capacity store limits must be nonzero and within hard maxima".to_owned(),
            ));
        }
        Ok(self)
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct StoreBenchmarkSnapshot {
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
    pub invalid_token_hash_rows: u64,
}

impl StoreBenchmarkSnapshot {
    pub fn total_rows(self) -> u64 {
        self.hosts
            .saturating_add(self.sessions)
            .saturating_add(self.assignments)
            .saturating_add(self.assignment_rows)
            .saturating_add(self.reports)
            .saturating_add(self.pending_restore_tasks)
            .saturating_add(self.verifying_restore_tasks)
            .saturating_add(self.restores)
            .saturating_add(self.access_log_rows)
            .saturating_add(self.rate_limit_rows)
    }
}


#[derive(Clone)]
pub struct WebCapacityStore {
    connection: Arc<Mutex<Connection>>,
    assignment_lock: Arc<Mutex<()>>,
    limits: WebCapacityStoreLimits,
}

impl WebCapacityStore {
    #[cfg(test)]
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_limits(path, WebCapacityStoreLimits::default())
    }

    pub fn open_with_limits(path: &Path, limits: WebCapacityStoreLimits) -> Result<Self> {
        let limits = limits.validate()?;
        let connection = Connection::open(path)
            .map_err(|error| WebCapacityError::Store(format!("open SQLite database: {error}")))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;
                 PRAGMA busy_timeout=5000;
                 CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                 ) STRICT;
                 INSERT INTO metadata(key,value) VALUES('schema','noos/wwm-web-capacity-store/v1')
                    ON CONFLICT(key) DO NOTHING;
                 CREATE TABLE IF NOT EXISTS hosts (
                    host_id BLOB PRIMARY KEY NOT NULL CHECK(length(host_id)=32),
                    origin TEXT NOT NULL UNIQUE,
                    provider TEXT NOT NULL,
                    region TEXT NOT NULL,
                    control_cluster TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    inventory_root BLOB NOT NULL CHECK(length(inventory_root)=32),
                    expires_at INTEGER NOT NULL CHECK(expires_at>=0),
                    verified_at INTEGER NOT NULL CHECK(verified_at>=0),
                    active INTEGER NOT NULL CHECK(active IN (0,1)),
                    generation INTEGER NOT NULL DEFAULT 1 CHECK(generation>=1)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS inventory (
                    host_id BLOB NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
                    stripe INTEGER NOT NULL CHECK(stripe BETWEEN 0 AND 453),
                    position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 11),
                    bytes INTEGER NOT NULL CHECK(bytes=1047552),
                    transport_sha256 BLOB NOT NULL CHECK(length(transport_sha256)=32),
                    protocol_share_digest BLOB NOT NULL CHECK(length(protocol_share_digest)=32),
                    probe_root BLOB NOT NULL CHECK(length(probe_root)=32),
                    url TEXT NOT NULL,
                    PRIMARY KEY(host_id,stripe,position)
                 ) STRICT, WITHOUT ROWID;
                 CREATE INDEX IF NOT EXISTS inventory_coordinate_idx
                    ON inventory(stripe,position,host_id);
                 CREATE TABLE IF NOT EXISTS sessions (
                    token_hash BLOB PRIMARY KEY NOT NULL CHECK(length(token_hash)=32),
                    participant_id BLOB NOT NULL UNIQUE CHECK(length(participant_id)=32),
                    origin TEXT NOT NULL,
                    consent_version TEXT NOT NULL,
                    quota_shares INTEGER NOT NULL CHECK(quota_shares IN (16,64,256)),
                    effective_bytes INTEGER NOT NULL CHECK(effective_bytes BETWEEN 1047552 AND 268173312),
                    storage_class TEXT NOT NULL CHECK(storage_class IN ('OPFS','INDEXEDDB')),
                    upload_enabled INTEGER NOT NULL CHECK(upload_enabled IN (0,1)),
                    daily_egress_cap INTEGER NOT NULL CHECK(daily_egress_cap BETWEEN 0 AND 268173312),
                    egress_day INTEGER NOT NULL CHECK(egress_day>=0),
                    daily_egress_used INTEGER NOT NULL CHECK(daily_egress_used BETWEEN 0 AND 268173312),
                    issued_at INTEGER NOT NULL CHECK(issued_at>=0),
                    expires_at INTEGER NOT NULL CHECK(expires_at>=issued_at),
                    last_active_at INTEGER NOT NULL CHECK(last_active_at>=issued_at),
                    revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at>=issued_at)
                 ) STRICT;
                 CREATE INDEX IF NOT EXISTS sessions_origin_idx ON sessions(origin,expires_at);
                 CREATE TABLE IF NOT EXISTS assignments (
                    assignment_id BLOB PRIMARY KEY NOT NULL CHECK(length(assignment_id)=32),
                    token_hash BLOB NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
                    body_json TEXT NOT NULL,
                    issued_at INTEGER NOT NULL CHECK(issued_at>=0),
                    expires_at INTEGER NOT NULL CHECK(expires_at>=issued_at)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS assignment_rows (
                    assignment_id BLOB NOT NULL REFERENCES assignments(assignment_id) ON DELETE CASCADE,
                    host_id BLOB NOT NULL REFERENCES hosts(host_id),
                    stripe INTEGER NOT NULL CHECK(stripe BETWEEN 0 AND 453),
                    position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 11),
                    PRIMARY KEY(assignment_id,stripe,position)
                 ) STRICT, WITHOUT ROWID;
                 CREATE INDEX IF NOT EXISTS assignment_coordinate_idx
                    ON assignment_rows(stripe,position,host_id);
                 CREATE TABLE IF NOT EXISTS reports (
                    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash BLOB NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
                    window_started_at INTEGER NOT NULL,
                    window_ended_at INTEGER NOT NULL,
                    stored_count INTEGER NOT NULL CHECK(stored_count BETWEEN 0 AND 256),
                    evicted_count INTEGER NOT NULL CHECK(evicted_count BETWEEN 0 AND 256),
                    error_count INTEGER NOT NULL CHECK(error_count BETWEEN 0 AND 4096),
                    uploaded_bytes INTEGER NOT NULL CHECK(uploaded_bytes BETWEEN 0 AND 268173312),
                    coordinate_digests_json TEXT NOT NULL,
                    error_codes_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS restore_tasks (
                    task_id BLOB PRIMARY KEY NOT NULL CHECK(length(task_id)=32),
                    token_hash BLOB NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
                    participant_id BLOB NOT NULL CHECK(length(participant_id)=32),
                    origin TEXT NOT NULL,
                    coordinate_json TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','VERIFYING','COMPLETED','FAILED')),
                    failure_code TEXT
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS restores (
                    quarantine_id BLOB PRIMARY KEY NOT NULL CHECK(length(quarantine_id)=32),
                    task_id BLOB NOT NULL UNIQUE REFERENCES restore_tasks(task_id),
                    coordinate_digest BLOB NOT NULL CHECK(length(coordinate_digest)=32),
                    bytes INTEGER NOT NULL CHECK(bytes=1047552),
                    path TEXT NOT NULL,
                    accepted_at INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS restore_releases (
                    import_index_sha256 BLOB PRIMARY KEY NOT NULL CHECK(length(import_index_sha256)=32),
                    artifact_id BLOB NOT NULL CHECK(length(artifact_id)=32),
                    manifest_root BLOB NOT NULL CHECK(length(manifest_root)=32),
                    position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 11),
                    share_count INTEGER NOT NULL CHECK(share_count BETWEEN 1 AND 454),
                    bytes INTEGER NOT NULL CHECK(bytes BETWEEN 1047552 AND 475588608),
                    released_at INTEGER NOT NULL
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS access_log (
                    access_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    ip_prefix TEXT NOT NULL,
                    coarse_user_agent TEXT NOT NULL,
                    route TEXT NOT NULL,
                    allowed INTEGER NOT NULL CHECK(allowed IN (0,1))
                 ) STRICT;
                 CREATE INDEX IF NOT EXISTS access_log_expiry_idx ON access_log(created_at);
                 CREATE TABLE IF NOT EXISTS rate_limits (
                    origin TEXT NOT NULL,
                    route TEXT NOT NULL,
                    window_minute INTEGER NOT NULL,
                    request_count INTEGER NOT NULL CHECK(request_count>=1),
                    PRIMARY KEY(origin,route,window_minute)
                 ) STRICT, WITHOUT ROWID;",
            )
            .map_err(|error| {
                WebCapacityError::Store(format!("initialize SQLite database: {error}"))
            })?;
        let generation_column_count: u8 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('hosts') WHERE name='generation'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                WebCapacityError::Store(format!("inspect host generation migration: {error}"))
            })?;
        if generation_column_count == 0 {
            connection
                .execute(
                    "ALTER TABLE hosts ADD COLUMN generation INTEGER NOT NULL DEFAULT 1 CHECK(generation>=1)",
                    [],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("migrate host generation: {error}"))
                })?;
        }
        let schema: String = connection
            .query_row("SELECT value FROM metadata WHERE key='schema'", [], |row| {
                row.get(0)
            })
            .map_err(|error| WebCapacityError::Store(format!("read store schema: {error}")))?;
        if schema != "noos/wwm-web-capacity-store/v1" {
            return Err(WebCapacityError::Store(
                "unsupported web capacity SQLite schema".to_owned(),
            ));
        }
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|error| WebCapacityError::Store(format!("database quick_check: {error}")))?;
        if quick_check != "ok" {
            return Err(WebCapacityError::Store(format!(
                "database quick_check failed: {quick_check}"
            )));
        }
        let access_cutoff = now_seconds()?.saturating_sub(ACCESS_LOG_RETENTION_SECONDS);
        connection
            .execute(
                "DELETE FROM access_log WHERE created_at<=?1",
                params![i64_from_u64(access_cutoff)?],
            )
            .map_err(|error| {
                WebCapacityError::Store(format!("purge access observations at startup: {error}"))
            })?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            assignment_lock: Arc::new(Mutex::new(())),
            limits,
        })
    }

    pub fn replace_host(
        &self,
        host_id: &str,
        provider: &str,
        region: &str,
        control_cluster: &str,
        manifest: &StaticHostManifest,
        inventory: &StaticInventory,
    ) -> Result<()> {
        let host_id = decode_hex32(host_id)?;
        let inventory_root = decode_hex32(&inventory.inventory_root)?;
        let manifest_json = serde_json::to_string(manifest).map_err(|error| {
            WebCapacityError::Store(format!("encode static host manifest: {error}"))
        })?;
        let verified_at = now_seconds()?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin host transaction: {error}"))
            })?;
            let existing: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM hosts WHERE origin=?1)",
                    params![manifest.canonical_origin],
                    |row| row.get(0),
                )
                .map_err(|error| WebCapacityError::Store(format!("count static hosts: {error}")))?;
            if !existing {
                let count: u32 = transaction
                    .query_row("SELECT COUNT(*) FROM hosts", [], |row| row.get(0))
                    .map_err(|error| {
                        WebCapacityError::Store(format!("count static hosts: {error}"))
                    })?;
                if count >= self.limits.max_hosts {
                    return Err(WebCapacityError::Quota(
                        "global static-host limit reached".to_owned(),
                    ));
                }
            }
            transaction
                .execute(
                    "INSERT INTO hosts(host_id,origin,provider,region,control_cluster,manifest_json,inventory_root,expires_at,verified_at,active)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)
                     ON CONFLICT(origin) DO UPDATE SET
                        provider=excluded.provider,
                        region=excluded.region,
                        control_cluster=excluded.control_cluster,
                        manifest_json=excluded.manifest_json,
                        inventory_root=excluded.inventory_root,
                        expires_at=excluded.expires_at,
                        verified_at=excluded.verified_at,
                        active=1,
                        generation=hosts.generation+1",
                    params![
                        host_id.as_slice(),
                        manifest.canonical_origin,
                        provider,
                        region,
                        control_cluster,
                        manifest_json,
                        inventory_root.as_slice(),
                        i64_from_u64(manifest.expires_at)?,
                        i64_from_u64(verified_at)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("upsert host: {error}")))?;
            transaction
                .execute(
                    "DELETE FROM inventory WHERE host_id=?1",
                    params![host_id.as_slice()],
                )
                .map_err(|error| WebCapacityError::Store(format!("replace inventory: {error}")))?;
            {
                let mut statement = transaction
                    .prepare_cached(
                        "INSERT INTO inventory(host_id,stripe,position,bytes,transport_sha256,protocol_share_digest,probe_root,url)
                         VALUES(?1,?2,?3,1047552,?4,?5,?6,?7)",
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("prepare inventory insert: {error}"))
                    })?;
                for row in &inventory.rows {
                    statement
                        .execute(params![
                            host_id.as_slice(),
                            row.stripe,
                            row.position,
                            decode_hex32(&row.transport_sha256)?.as_slice(),
                            decode_hex32(&row.protocol_share_digest)?.as_slice(),
                            decode_hex32(&row.probe_root)?.as_slice(),
                            row.url
                        ])
                        .map_err(|error| {
                            WebCapacityError::Store(format!("insert inventory row: {error}"))
                        })?;
                }
            }
            transaction
                .commit()
                .map_err(|error| WebCapacityError::Store(format!("commit host: {error}")))?;
            Ok(())
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn replace_host_if_generation(
        &self,
        expected_generation: u64,
        host_id: &str,
        provider: &str,
        region: &str,
        control_cluster: &str,
        manifest: &StaticHostManifest,
        inventory: &StaticInventory,
    ) -> Result<bool> {
        let host_id = decode_hex32(host_id)?;
        let inventory_root = decode_hex32(&inventory.inventory_root)?;
        let manifest_json = serde_json::to_string(manifest).map_err(|error| {
            WebCapacityError::Store(format!("encode refreshed static host manifest: {error}"))
        })?;
        let verified_at = now_seconds()?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin host refresh transaction: {error}"))
            })?;
            let changed = transaction
                .execute(
                    "UPDATE hosts SET
                        provider=?1,
                        region=?2,
                        control_cluster=?3,
                        manifest_json=?4,
                        inventory_root=?5,
                        expires_at=?6,
                        verified_at=?7,
                        active=1,
                        generation=generation+1
                     WHERE origin=?8 AND host_id=?9 AND generation=?10",
                    params![
                        provider,
                        region,
                        control_cluster,
                        manifest_json,
                        inventory_root.as_slice(),
                        i64_from_u64(manifest.expires_at)?,
                        i64_from_u64(verified_at)?,
                        manifest.canonical_origin,
                        host_id.as_slice(),
                        i64_from_u64(expected_generation)?
                    ],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("compare-and-swap refreshed host: {error}"))
                })?;
            if changed == 0 {
                transaction.rollback().map_err(|error| {
                    WebCapacityError::Store(format!("rollback stale host refresh: {error}"))
                })?;
                return Ok(false);
            }
            transaction
                .execute(
                    "DELETE FROM inventory WHERE host_id=?1",
                    params![host_id.as_slice()],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("replace refreshed inventory: {error}"))
                })?;
            {
                let mut statement = transaction
                    .prepare_cached(
                        "INSERT INTO inventory(host_id,stripe,position,bytes,transport_sha256,protocol_share_digest,probe_root,url)
                         VALUES(?1,?2,?3,1047552,?4,?5,?6,?7)",
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!(
                            "prepare refreshed inventory insert: {error}"
                        ))
                    })?;
                for row in &inventory.rows {
                    statement
                        .execute(params![
                            host_id.as_slice(),
                            row.stripe,
                            row.position,
                            decode_hex32(&row.transport_sha256)?.as_slice(),
                            decode_hex32(&row.protocol_share_digest)?.as_slice(),
                            decode_hex32(&row.probe_root)?.as_slice(),
                            row.url
                        ])
                        .map_err(|error| {
                            WebCapacityError::Store(format!(
                                "insert refreshed inventory row: {error}"
                            ))
                        })?;
                }
            }
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit host refresh: {error}"))
            })?;
            Ok(true)
        })
    }


    pub fn deactivate_expired_hosts(&self, now: u64) -> Result<usize> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE hosts SET active=0 WHERE active=1 AND expires_at<=?1",
                    params![i64_from_u64(now)?],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("deactivate expired hosts: {error}"))
                })
        })
    }

    pub fn active_host_refresh_targets(&self) -> Result<Vec<HostRefreshTarget>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT origin,generation FROM hosts WHERE active=1 ORDER BY origin")
                .map_err(|error| {
                    WebCapacityError::Store(format!("prepare active host scan: {error}"))
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok(HostRefreshTarget {
                        origin: row.get(0)?,
                        generation: row.get(1)?,
                    })
                })
                .map_err(|error| {
                    WebCapacityError::Store(format!("query active host scan: {error}"))
                })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| {
                    WebCapacityError::Store(format!("decode active host scan: {error}"))
                })
        })
    }

    pub fn is_verified_inventory_row(
        &self,
        origin: &str,
        coordinate: &InventoryRow,
        now: u64,
    ) -> Result<bool> {
        let transport = decode_hex32(&coordinate.transport_sha256)?;
        let protocol = decode_hex32(&coordinate.protocol_share_digest)?;
        let probe = decode_hex32(&coordinate.probe_root)?;
        let verification_cutoff = now.saturating_sub(HOST_VERIFICATION_MAX_AGE_SECONDS);
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM inventory i JOIN hosts h ON h.host_id=i.host_id
                       WHERE h.origin=?1 AND h.active=1 AND h.expires_at>?2
                         AND h.verified_at>=?3
                         AND i.stripe=?4 AND i.position=?5 AND i.bytes=?6
                         AND i.transport_sha256=?7 AND i.protocol_share_digest=?8
                         AND i.probe_root=?9 AND i.url=?10
                     )",
                    params![
                        origin,
                        i64_from_u64(now)?,
                        i64_from_u64(verification_cutoff)?,
                        coordinate.stripe,
                        coordinate.position,
                        i64_from_u64(coordinate.bytes)?,
                        transport.as_slice(),
                        protocol.as_slice(),
                        probe.as_slice(),
                        coordinate.url
                    ],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("verify registered inventory row: {error}"))
                })
        })
    }

    pub fn deactivate_host_if_generation(&self, origin: &str, generation: u64) -> Result<bool> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE hosts SET active=0
                     WHERE origin=?1 AND generation=?2 AND active=1",
                    params![origin, i64_from_u64(generation)?],
                )
                .map(|changed| changed != 0)
                .map_err(|error| {
                    WebCapacityError::Store(format!("deactivate static host: {error}"))
                })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_session(
        &self,
        token_hash: [u8; 32],
        participant_id: &str,
        origin: &str,
        consent_version: &str,
        quota_shares: u16,
        effective_bytes: u64,
        storage_class: StorageClass,
        upload_policy: &UploadPolicy,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<()> {
        let participant_id = decode_hex32(participant_id)?;
        let storage_class = storage_class_text(storage_class);
        let day = issued_at / 86_400;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin session transaction: {error}"))
            })?;
            let active_count: u32 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>?1",
                    params![i64_from_u64(issued_at)?],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("count active sessions: {error}"))
                })?;
            if active_count >= self.limits.max_active_sessions {
                return Err(WebCapacityError::Quota(
                    "global active-session limit reached".to_owned(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO sessions(token_hash,participant_id,origin,consent_version,quota_shares,effective_bytes,storage_class,upload_enabled,daily_egress_cap,egress_day,daily_egress_used,issued_at,expires_at,last_active_at,revoked_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11,?12,?11,NULL)",
                    params![
                        token_hash.as_slice(),
                        participant_id.as_slice(),
                        origin,
                        consent_version,
                        quota_shares,
                        i64_from_u64(effective_bytes)?,
                        storage_class,
                        i64::from(upload_policy.enabled),
                        i64_from_u64(upload_policy.daily_egress_bytes)?,
                        i64_from_u64(day)?,
                        i64_from_u64(issued_at)?,
                        i64_from_u64(expires_at)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("create session: {error}")))?;
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit session transaction: {error}"))
            })?;
            Ok(())
        })
    }

    pub fn active_session(
        &self,
        token_hash: [u8; 32],
        origin: &str,
        now: u64,
        mark_active: bool,
    ) -> Result<Option<SessionRecord>> {
        self.with_connection(|connection| {
            let record = connection
                .query_row(
                    "SELECT participant_id,origin,quota_shares,effective_bytes,upload_enabled,daily_egress_cap,last_active_at
                     FROM sessions
                     WHERE token_hash=?1 AND origin=?2 AND revoked_at IS NULL AND expires_at>?3",
                    params![token_hash.as_slice(), origin, i64_from_u64(now)?],
                    |row| {
                        let participant: Vec<u8> = row.get(0)?;
                        Ok((
                            participant,
                            row.get::<_, String>(1)?,
                            row.get::<_, u16>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, bool>(4)?,
                            row.get::<_, u64>(5)?,
                            row.get::<_, u64>(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| WebCapacityError::Store(format!("read session: {error}")))?;
            let Some((participant, stored_origin, quota, effective, upload, cap, last_active)) = record else {
                return Ok(None);
            };
            if mark_active {
                connection
                    .execute(
                        "UPDATE sessions SET last_active_at=?2 WHERE token_hash=?1",
                        params![token_hash.as_slice(), i64_from_u64(now)?],
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("update session activity: {error}"))
                    })?;
            }
            let participant_id = hex::encode(participant);
            Ok(Some(SessionRecord {
                token_hash,
                participant_id,
                origin: stored_origin,
                quota_shares: quota,
                effective_bytes: effective,
                upload_policy: UploadPolicy {
                    enabled: upload,
                    daily_egress_bytes: cap,
                },
                last_active_at: if mark_active { now } else { last_active },
            }))
        })
    }

    pub fn select_assignment_rows(
        &self,
        token_hash: [u8; 32],
        now: u64,
        maximum: usize,
        excluded_protocol_share_digests: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], AssignmentRow)>> {
        let maximum = maximum.min(256);
        let excluded = excluded_protocol_share_digests
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let selection_limit = maximum
            .saturating_add(excluded.len())
            .min(5_448);
        let verification_cutoff = now.saturating_sub(HOST_VERIFICATION_MAX_AGE_SECONDS);
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "WITH active_rows AS (
                       SELECT ar.stripe,ar.position,ar.host_id,h.provider,h.region,h.control_cluster
                       FROM assignment_rows ar
                       JOIN assignments a ON a.assignment_id=ar.assignment_id
                       JOIN hosts h ON h.host_id=ar.host_id
                       WHERE a.expires_at>?2
                     ),
                     eligible_coordinates AS (
                       SELECT DISTINCT i.stripe,i.position
                       FROM inventory i JOIN hosts h ON h.host_id=i.host_id
                       WHERE h.active=1 AND h.expires_at>?2 AND h.verified_at>=?4
                         AND NOT EXISTS (
                           SELECT 1 FROM assignment_rows mine
                           JOIN assignments own ON own.assignment_id=mine.assignment_id
                           WHERE own.token_hash=?1 AND own.expires_at>?2
                             AND mine.stripe=i.stripe AND mine.position=i.position
                         )
                     ),
                     coordinate_load AS (
                       SELECT stripe,position,COUNT(*) AS copies
                       FROM active_rows GROUP BY stripe,position
                     ),
                     selected_coordinates AS (
                       SELECT e.stripe,e.position,COALESCE(c.copies,0) AS copies
                       FROM eligible_coordinates e
                       LEFT JOIN coordinate_load c
                         ON c.stripe=e.stripe AND c.position=e.position
                       ORDER BY copies ASC,e.stripe ASC,e.position ASC
                       LIMIT ?3
                     ),
                     coordinate_provider AS (
                       SELECT stripe,position,provider,COUNT(*) AS copies
                       FROM active_rows GROUP BY stripe,position,provider
                     ),
                     coordinate_region AS (
                       SELECT stripe,position,region,COUNT(*) AS copies
                       FROM active_rows GROUP BY stripe,position,region
                     ),
                     coordinate_cluster AS (
                       SELECT stripe,position,control_cluster,COUNT(*) AS copies
                       FROM active_rows GROUP BY stripe,position,control_cluster
                     ),
                     provider_load AS (
                       SELECT provider,COUNT(*) AS copies FROM active_rows GROUP BY provider
                     ),
                     region_load AS (
                       SELECT region,COUNT(*) AS copies FROM active_rows GROUP BY region
                     ),
                     cluster_load AS (
                       SELECT control_cluster,COUNT(*) AS copies
                       FROM active_rows GROUP BY control_cluster
                     ),
                     host_load AS (
                       SELECT host_id,COUNT(*) AS copies FROM active_rows GROUP BY host_id
                     )
                     SELECT i.host_id,i.stripe,i.position,i.bytes,i.transport_sha256,
                            i.protocol_share_digest,i.probe_root,i.url,h.origin,
                            h.provider,h.region,h.control_cluster,
                            COALESCE(cp.copies,0),COALESCE(cr.copies,0),
                            COALESCE(cc.copies,0),COALESCE(pl.copies,0),
                            COALESCE(rl.copies,0),COALESCE(cl.copies,0),
                            COALESCE(hl.copies,0)
                     FROM selected_coordinates sc
                     JOIN inventory i ON i.stripe=sc.stripe AND i.position=sc.position
                     JOIN hosts h ON h.host_id=i.host_id
                     LEFT JOIN coordinate_provider cp
                       ON cp.stripe=i.stripe AND cp.position=i.position AND cp.provider=h.provider
                     LEFT JOIN coordinate_region cr
                       ON cr.stripe=i.stripe AND cr.position=i.position AND cr.region=h.region
                     LEFT JOIN coordinate_cluster cc
                       ON cc.stripe=i.stripe AND cc.position=i.position
                          AND cc.control_cluster=h.control_cluster
                     LEFT JOIN provider_load pl ON pl.provider=h.provider
                     LEFT JOIN region_load rl ON rl.region=h.region
                     LEFT JOIN cluster_load cl ON cl.control_cluster=h.control_cluster
                     LEFT JOIN host_load hl ON hl.host_id=h.host_id
                     WHERE h.active=1 AND h.expires_at>?2 AND h.verified_at>=?4
                     ORDER BY sc.copies ASC,sc.stripe ASC,sc.position ASC,h.host_id ASC",
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("prepare assignment selection: {error}"))
                })?;
            let rows = statement
                .query_map(
                    params![
                        token_hash.as_slice(),
                        i64_from_u64(now)?,
                        selection_limit,
                        i64_from_u64(verification_cutoff)?
                    ],
                    |row| {
                        let host_id: Vec<u8> = row.get(0)?;
                        let host_id: [u8; 32] = host_id.try_into().map_err(|_value: Vec<u8>| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Blob,
                                "stored host ID has wrong length".into(),
                            )
                        })?;
                        let transport: Vec<u8> = row.get(4)?;
                        let protocol: Vec<u8> = row.get(5)?;
                        let probe: Vec<u8> = row.get(6)?;
                        Ok(AssignmentCandidate {
                            host_id,
                            row: AssignmentRow {
                                stripe: row.get(1)?,
                                position: row.get(2)?,
                                bytes: row.get(3)?,
                                transport_sha256: hex::encode(transport),
                                protocol_share_digest: hex::encode(protocol),
                                probe_root: hex::encode(probe),
                                url: row.get(7)?,
                                source_origin: row.get(8)?,
                            },
                            provider: row.get(9)?,
                            region: row.get(10)?,
                            control_cluster: row.get(11)?,
                            coordinate_provider_copies: row.get(12)?,
                            coordinate_region_copies: row.get(13)?,
                            coordinate_cluster_copies: row.get(14)?,
                            global_provider_load: row.get(15)?,
                            global_region_load: row.get(16)?,
                            global_cluster_load: row.get(17)?,
                            global_host_load: row.get(18)?,
                        })
                    },
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("query assignment selection: {error}"))
                })?;
            let mut result = Vec::with_capacity(maximum);
            let mut batch_load = BatchDomainLoad::default();
            let mut coordinate = None;
            let mut candidates = Vec::new();
            for row in rows {
                let candidate = row.map_err(|error| {
                    WebCapacityError::Store(format!("decode assignment candidate: {error}"))
                })?;
                if excluded.contains(&decode_hex32(&candidate.row.protocol_share_digest)?) {
                    continue;
                }
                let candidate_coordinate = (candidate.row.stripe, candidate.row.position);
                if coordinate.is_some_and(|value| value != candidate_coordinate) {
                    select_balanced_candidate(&mut candidates, &mut batch_load, &mut result);
                }
                coordinate = Some(candidate_coordinate);
                candidates.push(candidate);
            }
            select_balanced_candidate(&mut candidates, &mut batch_load, &mut result);
            result.truncate(maximum);
            Ok(result)
        })
    }

    pub fn reserve_assignment<T>(
        &self,
        token_hash: [u8; 32],
        now: u64,
        maximum: usize,
        excluded_protocol_share_digests: &[[u8; 32]],
        build: impl FnOnce(&[([u8; 32], AssignmentRow)]) -> Result<(String, String, u64, T)>,
    ) -> Result<Option<T>> {
        let _reservation = self.assignment_lock.lock().map_err(|_| {
            WebCapacityError::Store("assignment reservation lock is poisoned".to_owned())
        })?;
        let rows = self.select_assignment_rows(
            token_hash,
            now,
            maximum,
            excluded_protocol_share_digests,
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        let (assignment_id, body_json, expires_at, result) = build(&rows)?;
        self.insert_assignment(
            &assignment_id,
            token_hash,
            &body_json,
            now,
            expires_at,
            &rows,
        )?;
        Ok(Some(result))
    }

    pub fn insert_assignment(
        &self,
        assignment_id: &str,
        token_hash: [u8; 32],
        body_json: &str,
        issued_at: u64,
        expires_at: u64,
        rows: &[([u8; 32], AssignmentRow)],
    ) -> Result<()> {
        let assignment_id = decode_hex32(assignment_id)?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin assignment transaction: {error}"))
            })?;
            let active_count: u32 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM assignments WHERE expires_at>?1",
                    params![i64_from_u64(issued_at)?],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("count active assignments: {error}"))
                })?;
            if active_count >= self.limits.max_active_assignments {
                return Err(WebCapacityError::Quota(
                    "global active-assignment limit reached".to_owned(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO assignments(assignment_id,token_hash,body_json,issued_at,expires_at)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![
                        assignment_id.as_slice(),
                        token_hash.as_slice(),
                        body_json,
                        i64_from_u64(issued_at)?,
                        i64_from_u64(expires_at)?
                    ],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("insert assignment: {error}"))
                })?;
            {
                let mut statement = transaction
                    .prepare_cached(
                        "INSERT INTO assignment_rows(assignment_id,host_id,stripe,position)
                         VALUES(?1,?2,?3,?4)",
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("prepare assignment rows: {error}"))
                    })?;
                for (host_id, row) in rows {
                    statement
                        .execute(params![
                            assignment_id.as_slice(),
                            host_id.as_slice(),
                            row.stripe,
                            row.position
                        ])
                        .map_err(|error| {
                            WebCapacityError::Store(format!("insert assignment row: {error}"))
                        })?;
                }
            }
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit assignment: {error}"))
            })?;
            Ok(())
        })
    }

    pub fn record_report(
        &self,
        token_hash: [u8; 32],
        report: &ParticipantReport,
        created_at: u64,
    ) -> Result<()> {
        let coordinate_digests =
            serde_json::to_string(&report.coordinate_digests).map_err(|error| {
                WebCapacityError::Store(format!("encode coordinate digests: {error}"))
            })?;
        let error_codes = serde_json::to_string(&report.error_codes)
            .map_err(|error| WebCapacityError::Store(format!("encode report errors: {error}")))?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO reports(token_hash,window_started_at,window_ended_at,stored_count,evicted_count,error_count,uploaded_bytes,coordinate_digests_json,error_codes_json,created_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        token_hash.as_slice(),
                        i64_from_u64(report.window_started_at)?,
                        i64_from_u64(report.window_ended_at)?,
                        report.stored_count,
                        report.evicted_count,
                        report.error_count,
                        i64_from_u64(report.uploaded_bytes)?,
                        coordinate_digests,
                        error_codes,
                        i64_from_u64(created_at)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("insert report: {error}")))?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn queue_restore(
        &self,
        task_id: &str,
        token_hash: [u8; 32],
        participant_id: &str,
        origin: &str,
        coordinate: &InventoryRow,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<()> {
        let task_id = decode_hex32(task_id)?;
        let participant_id = decode_hex32(participant_id)?;
        let coordinate_json = serde_json::to_string(coordinate).map_err(|error| {
            WebCapacityError::Store(format!("encode restore coordinate: {error}"))
        })?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin restore queue transaction: {error}"))
            })?;
            let active_count: u32 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM restore_tasks
                     WHERE status IN ('PENDING','VERIFYING') AND expires_at>?1",
                    params![i64_from_u64(issued_at)?],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("count pending restore tasks: {error}"))
                })?;
            if active_count >= self.limits.max_pending_restore_tasks {
                return Err(WebCapacityError::Quota(
                    "global pending-restore limit reached".to_owned(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO restore_tasks(task_id,token_hash,participant_id,origin,coordinate_json,issued_at,expires_at,status,failure_code)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,'PENDING',NULL)",
                    params![
                        task_id.as_slice(),
                        token_hash.as_slice(),
                        participant_id.as_slice(),
                        origin,
                        coordinate_json,
                        i64_from_u64(issued_at)?,
                        i64_from_u64(expires_at)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("queue restore: {error}")))?;
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit restore queue: {error}"))
            })?;
            Ok(())
        })
    }

    pub fn pending_restore(
        &self,
        token_hash: [u8; 32],
        now: u64,
    ) -> Result<Option<StoredRestoreTask>> {
        self.with_connection(|connection| {
            let record = connection
                .query_row(
                    "SELECT task_id,participant_id,origin,coordinate_json,issued_at,expires_at
                     FROM restore_tasks
                     WHERE token_hash=?1 AND status='PENDING' AND expires_at>?2
                     ORDER BY issued_at,task_id LIMIT 1",
                    params![token_hash.as_slice(), i64_from_u64(now)?],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, u64>(4)?,
                            row.get::<_, u64>(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| WebCapacityError::Store(format!("read restore task: {error}")))?;
            record
                .map(|(task, participant, origin, coordinate, issued, expires)| {
                    let coordinate = serde_json::from_str(&coordinate).map_err(|error| {
                        WebCapacityError::Store(format!("decode restore coordinate: {error}"))
                    })?;
                    Ok(StoredRestoreTask {
                        task_id: hex::encode(task),
                        participant_id: hex::encode(participant),
                        origin,
                        coordinate,
                        issued_at: issued,
                        expires_at: expires,
                    })
                })
                .transpose()
        })
    }

    pub fn completed_restores_for_position(
        &self,
        position: u8,
    ) -> Result<Vec<CompletedRestoreRecord>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT t.task_id,t.participant_id,t.origin,t.coordinate_json,t.issued_at,t.expires_at,
                            r.quarantine_id,r.coordinate_digest,r.bytes,r.path,r.accepted_at
                     FROM restore_tasks t
                     JOIN restores r ON r.task_id=t.task_id
                     WHERE t.status='COMPLETED'
                     ORDER BY t.task_id",
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("prepare completed restore export: {error}"))
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, u64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, u64>(10)?,
                    ))
                })
                .map_err(|error| {
                    WebCapacityError::Store(format!("query completed restore export: {error}"))
                })?;
            let mut completed = Vec::new();
            for row in rows {
                let (
                    task_id,
                    participant_id,
                    origin,
                    coordinate_json,
                    issued_at,
                    expires_at,
                    quarantine_id,
                    coordinate_digest,
                    bytes,
                    path,
                    accepted_at,
                ) = row.map_err(|error| {
                    WebCapacityError::Store(format!("read completed restore export: {error}"))
                })?;
                let coordinate: InventoryRow =
                    serde_json::from_str(&coordinate_json).map_err(|error| {
                        WebCapacityError::Store(format!(
                            "decode completed restore coordinate: {error}"
                        ))
                    })?;
                if coordinate.position != position {
                    continue;
                }
                completed.push(CompletedRestoreRecord {
                    task: StoredRestoreTask {
                        task_id: hex::encode(task_id),
                        participant_id: hex::encode(participant_id),
                        origin,
                        coordinate,
                        issued_at,
                        expires_at,
                    },
                    quarantine_id: hex::encode(quarantine_id),
                    coordinate_digest: hex::encode(coordinate_digest),
                    bytes,
                    path: PathBuf::from(path),
                    accepted_at,
                });
            }
            Ok(completed)
        })
    }

    pub fn begin_restore(
        &self,
        task_id: &str,
        token_hash: [u8; 32],
        origin: &str,
        now: u64,
    ) -> Result<StoredRestoreTask> {
        let task_id_bytes = decode_hex32(task_id)?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin restore claim: {error}"))
            })?;
            let verifying_count: u32 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM restore_tasks
                     WHERE status='VERIFYING' AND expires_at>?1",
                    params![i64_from_u64(now)?],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("count restore verifications: {error}"))
                })?;
            if verifying_count >= self.limits.max_concurrent_restore_verifications {
                return Err(WebCapacityError::Quota(
                    "global concurrent restore-verification limit reached".to_owned(),
                ));
            }
            let quarantined_bytes: u64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(bytes),0) FROM restores",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("sum quarantine bytes: {error}"))
                })?;
            let reserved_bytes = u64::from(verifying_count)
                .saturating_add(1)
                .saturating_mul(SHARE_BYTES);
            if quarantined_bytes.saturating_add(reserved_bytes)
                > self.limits.max_quarantine_bytes
            {
                return Err(WebCapacityError::Quota(
                    "global quarantine byte limit reached".to_owned(),
                ));
            }
            let changed = transaction
                .execute(
                    "UPDATE restore_tasks SET status='VERIFYING'
                     WHERE task_id=?1 AND token_hash=?2 AND origin=?3 AND status='PENDING' AND expires_at>?4",
                    params![
                        task_id_bytes.as_slice(),
                        token_hash.as_slice(),
                        origin,
                        i64_from_u64(now)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("claim restore task: {error}")))?;
            if changed != 1 {
                return Err(WebCapacityError::Conflict(
                    "restore task is absent, expired, replayed, or bound to another session"
                        .to_owned(),
                ));
            }
            let (participant, stored_origin, coordinate_json, issued_at, expires_at) = transaction
                .query_row(
                    "SELECT participant_id,origin,coordinate_json,issued_at,expires_at
                     FROM restore_tasks WHERE task_id=?1",
                    params![task_id_bytes.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, u64>(4)?,
                        ))
                    },
                )
                .map_err(|error| WebCapacityError::Store(format!("read claimed restore: {error}")))?;
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit restore claim: {error}"))
            })?;
            let coordinate = serde_json::from_str(&coordinate_json).map_err(|error| {
                WebCapacityError::Store(format!("decode restore coordinate: {error}"))
            })?;
            Ok(StoredRestoreTask {
                task_id: task_id.to_owned(),
                participant_id: hex::encode(participant),
                origin: stored_origin,
                coordinate,
                issued_at,
                expires_at,
            })
        })
    }

    pub fn fail_restore(&self, task_id: &str, failure_code: &str) -> Result<()> {
        if failure_code.is_empty() || failure_code.len() > 64 {
            return Err(WebCapacityError::Store(
                "restore failure code must contain 1..=64 bytes".to_owned(),
            ));
        }
        let task_id = decode_hex32(task_id)?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE restore_tasks SET status='FAILED',failure_code=?2
                     WHERE task_id=?1 AND status='VERIFYING'",
                    params![task_id.as_slice(), failure_code],
                )
                .map_err(|error| WebCapacityError::Store(format!("fail restore: {error}")))?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_restore(
        &self,
        task_id: &str,
        token_hash: [u8; 32],
        quarantine_id: &str,
        coordinate_digest: &str,
        path: &Path,
        accepted_at: u64,
        bytes: u64,
    ) -> Result<()> {
        let task_id = decode_hex32(task_id)?;
        let quarantine_id = decode_hex32(quarantine_id)?;
        let coordinate_digest = decode_hex32(coordinate_digest)?;
        let day = accepted_at / 86_400;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin restore commit: {error}"))
            })?;
            let quarantined_bytes: u64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(bytes),0) FROM restores",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("sum quarantine bytes: {error}"))
                })?;
            if quarantined_bytes.saturating_add(bytes) > self.limits.max_quarantine_bytes {
                return Err(WebCapacityError::Quota(
                    "global quarantine byte limit reached".to_owned(),
                ));
            }
            let session = transaction
                .query_row(
                    "SELECT upload_enabled,daily_egress_cap,egress_day,daily_egress_used
                     FROM sessions WHERE token_hash=?1 AND revoked_at IS NULL AND expires_at>?2",
                    params![token_hash.as_slice(), i64_from_u64(accepted_at)?],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, u64>(2)?,
                            row.get::<_, u64>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| WebCapacityError::Store(format!("read egress cap: {error}")))?
                .ok_or_else(|| WebCapacityError::Unauthorized("session is inactive".to_owned()))?;
            if !session.0 {
                return Err(WebCapacityError::Forbidden(
                    "restore upload is not enabled".to_owned(),
                ));
            }
            let used = if session.2 == day { session.3 } else { 0 };
            let next = used
                .checked_add(bytes)
                .ok_or_else(|| WebCapacityError::Quota("egress byte overflow".to_owned()))?;
            if next > session.1 {
                return Err(WebCapacityError::Quota(
                    "daily restore egress cap would be exceeded".to_owned(),
                ));
            }
            let changed = transaction
                .execute(
                    "UPDATE restore_tasks SET status='COMPLETED',failure_code=NULL
                     WHERE task_id=?1 AND token_hash=?2 AND status='VERIFYING'",
                    params![task_id.as_slice(), token_hash.as_slice()],
                )
                .map_err(|error| WebCapacityError::Store(format!("complete restore task: {error}")))?;
            if changed != 1 {
                return Err(WebCapacityError::Conflict(
                    "restore task is not claimable for completion".to_owned(),
                ));
            }
            transaction
                .execute(
                    "UPDATE sessions SET egress_day=?2,daily_egress_used=?3
                     WHERE token_hash=?1",
                    params![
                        token_hash.as_slice(),
                        i64_from_u64(day)?,
                        i64_from_u64(next)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("charge restore egress: {error}")))?;
            transaction
                .execute(
                    "INSERT INTO restores(quarantine_id,task_id,coordinate_digest,bytes,path,accepted_at)
                     VALUES(?1,?2,?3,1047552,?4,?5)",
                    params![
                        quarantine_id.as_slice(),
                        task_id.as_slice(),
                        coordinate_digest.as_slice(),
                        path.to_string_lossy(),
                        i64_from_u64(accepted_at)?
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("insert restore receipt: {error}")))?;
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit restore receipt: {error}"))
            })?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn release_completed_restores(
        &self,
        import_index_sha256: &str,
        artifact_id: &str,
        manifest_root: &str,
        position: u8,
        pairs: &[(String, String)],
        bytes: u64,
        released_at: u64,
    ) -> Result<()> {
        if pairs.is_empty() || pairs.len() > 454 || position >= 12 {
            return Err(WebCapacityError::InvalidRecord(
                "restore release geometry is invalid".to_owned(),
            ));
        }
        let release_id = decode_hex32(import_index_sha256)?;
        let artifact = decode_hex32(artifact_id)?;
        let manifest = decode_hex32(manifest_root)?;
        let decoded = pairs
            .iter()
            .map(|(task, quarantine)| Ok((decode_hex32(task)?, decode_hex32(quarantine)?)))
            .collect::<Result<Vec<_>>>()?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin restore release transaction: {error}"))
            })?;
            for (task_id, quarantine_id) in &decoded {
                let count: u32 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM restores r
                         JOIN restore_tasks t ON t.task_id=r.task_id
                         WHERE r.task_id=?1 AND r.quarantine_id=?2 AND t.status='COMPLETED'",
                        params![task_id.as_slice(), quarantine_id.as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("verify restore release row: {error}"))
                    })?;
                if count != 1 {
                    return Err(WebCapacityError::Conflict(
                        "restore release row is missing or no longer completed".to_owned(),
                    ));
                }
            }
            transaction
                .execute(
                    "INSERT INTO restore_releases(import_index_sha256,artifact_id,manifest_root,position,share_count,bytes,released_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        release_id.as_slice(),
                        artifact.as_slice(),
                        manifest.as_slice(),
                        position,
                        pairs.len() as u32,
                        i64_from_u64(bytes)?,
                        i64_from_u64(released_at)?
                    ],
                )
                .map_err(|error| {
                    WebCapacityError::Conflict(format!(
                        "restore position was already released or release evidence conflicts: {error}"
                    ))
                })?;
            for (task_id, quarantine_id) in &decoded {
                transaction
                    .execute(
                        "DELETE FROM restores WHERE task_id=?1 AND quarantine_id=?2",
                        params![task_id.as_slice(), quarantine_id.as_slice()],
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("delete released restore receipt: {error}"))
                    })?;
                transaction
                    .execute(
                        "DELETE FROM restore_tasks WHERE task_id=?1 AND status='COMPLETED'",
                        params![task_id.as_slice()],
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("delete released restore task: {error}"))
                    })?;
            }
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit restore release: {error}"))
            })?;
            Ok(())
        })
    }

    pub fn revoke_session(&self, token_hash: [u8; 32], origin: &str, now: u64) -> Result<bool> {
        self.with_connection_mut(|connection| {
            let transaction = connection
                .transaction()
                .map_err(|error| WebCapacityError::Store(format!("begin revocation: {error}")))?;
            let changed = transaction
                .execute(
                    "UPDATE sessions SET revoked_at=?3,expires_at=MIN(expires_at,?3)
                     WHERE token_hash=?1 AND origin=?2 AND revoked_at IS NULL",
                    params![token_hash.as_slice(), origin, i64_from_u64(now)?],
                )
                .map_err(|error| WebCapacityError::Store(format!("revoke session: {error}")))?;
            if changed == 1 {
                transaction
                    .execute(
                        "UPDATE assignments SET expires_at=MIN(expires_at,?2)
                         WHERE token_hash=?1",
                        params![token_hash.as_slice(), i64_from_u64(now)?],
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("expire assignments: {error}"))
                    })?;
                transaction
                    .execute(
                        "UPDATE restore_tasks SET status='FAILED',failure_code='SESSION_REVOKED'
                         WHERE token_hash=?1 AND status IN ('PENDING','VERIFYING')",
                        params![token_hash.as_slice()],
                    )
                    .map_err(|error| {
                        WebCapacityError::Store(format!("expire restore tasks: {error}"))
                    })?;
            }
            transaction
                .commit()
                .map_err(|error| WebCapacityError::Store(format!("commit revocation: {error}")))?;
            Ok(changed == 1)
        })
    }

    pub fn check_rate_limit(
        &self,
        origin: &str,
        route: &str,
        now: u64,
        maximum: u32,
    ) -> Result<bool> {
        let window = now / 60;
        self.with_connection_mut(|connection| {
            let transaction = connection
                .transaction()
                .map_err(|error| WebCapacityError::Store(format!("begin rate limit: {error}")))?;
            transaction
                .execute(
                    "DELETE FROM rate_limits WHERE window_minute<?1",
                    params![i64_from_u64(window.saturating_sub(2))?],
                )
                .map_err(|error| WebCapacityError::Store(format!("prune rate limits: {error}")))?;
            transaction
                .execute(
                    "INSERT INTO rate_limits(origin,route,window_minute,request_count)
                     VALUES(?1,?2,?3,1)
                     ON CONFLICT(origin,route,window_minute)
                     DO UPDATE SET request_count=request_count+1",
                    params![origin, route, i64_from_u64(window)?],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("increment rate limit: {error}"))
                })?;
            let count: u32 = transaction
                .query_row(
                    "SELECT request_count FROM rate_limits
                     WHERE origin=?1 AND route=?2 AND window_minute=?3",
                    params![origin, route, i64_from_u64(window)?],
                    |row| row.get(0),
                )
                .map_err(|error| WebCapacityError::Store(format!("read rate limit: {error}")))?;
            transaction
                .commit()
                .map_err(|error| WebCapacityError::Store(format!("commit rate limit: {error}")))?;
            Ok(count <= maximum)
        })
    }

    pub fn record_access(
        &self,
        created_at: u64,
        ip_prefix: &str,
        coarse_user_agent: &str,
        route: &str,
        allowed: bool,
    ) -> Result<()> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO access_log(created_at,ip_prefix,coarse_user_agent,route,allowed)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![
                        i64_from_u64(created_at)?,
                        ip_prefix,
                        coarse_user_agent,
                        route,
                        i64::from(allowed)
                    ],
                )
                .map_err(|error| WebCapacityError::Store(format!("insert access log: {error}")))?;
            Ok(())
        })
    }

    pub fn purge_expired(&self, now: u64, access_retention_seconds: u64) -> Result<()> {
        let access_cutoff = now.saturating_sub(access_retention_seconds);
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                WebCapacityError::Store(format!("begin retention purge: {error}"))
            })?;
            transaction
                .execute(
                    "DELETE FROM access_log WHERE created_at<=?1",
                    params![i64_from_u64(access_cutoff)?],
                )
                .map_err(|error| WebCapacityError::Store(format!("purge access log: {error}")))?;
            transaction
                .execute(
                    "DELETE FROM reports WHERE created_at<?1",
                    params![i64_from_u64(now.saturating_sub(30 * 86_400))?],
                )
                .map_err(|error| WebCapacityError::Store(format!("purge reports: {error}")))?;
            transaction
                .execute(
                    "DELETE FROM restores WHERE accepted_at<?1",
                    params![i64_from_u64(now.saturating_sub(30 * 86_400))?],
                )
                .map_err(|error| WebCapacityError::Store(format!("purge restores: {error}")))?;
            transaction
                .execute(
                    "DELETE FROM restore_tasks
                     WHERE expires_at<?1 AND status IN ('COMPLETED','FAILED')",
                    params![i64_from_u64(now.saturating_sub(30 * 86_400))?],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("purge restore tasks: {error}"))
                })?;
            transaction
                .execute(
                    "DELETE FROM restore_releases WHERE released_at<?1",
                    params![i64_from_u64(now.saturating_sub(30 * 86_400))?],
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("purge restore releases: {error}"))
                })?;
            transaction
                .execute(
                    "DELETE FROM assignments WHERE expires_at<?1",
                    params![i64_from_u64(now.saturating_sub(86_400))?],
                )
                .map_err(|error| WebCapacityError::Store(format!("purge assignments: {error}")))?;
            transaction
                .execute(
                    "DELETE FROM sessions WHERE expires_at<?1",
                    params![i64_from_u64(now.saturating_sub(30 * 86_400))?],
                )
                .map_err(|error| WebCapacityError::Store(format!("purge sessions: {error}")))?;
            transaction
                .execute(
                    "UPDATE hosts SET active=0 WHERE expires_at<=?1",
                    params![i64_from_u64(now)?],
                )
                .map_err(|error| WebCapacityError::Store(format!("expire hosts: {error}")))?;
            transaction.commit().map_err(|error| {
                WebCapacityError::Store(format!("commit retention purge: {error}"))
            })?;
            Ok(())
        })
    }

    pub(super) fn benchmark_snapshot(&self, now: u64) -> Result<StoreBenchmarkSnapshot> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM hosts),
                       (SELECT COUNT(*) FROM hosts WHERE active=1 AND expires_at>?1),
                       (SELECT COUNT(*) FROM sessions),
                       (SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at>?1),
                       (SELECT COUNT(*) FROM assignments),
                       (SELECT COUNT(*) FROM assignments WHERE expires_at>?1),
                       (SELECT COUNT(*) FROM assignment_rows),
                       (SELECT COUNT(*) FROM reports),
                       (SELECT COUNT(*) FROM restore_tasks WHERE status='PENDING'),
                       (SELECT COUNT(*) FROM restore_tasks WHERE status='VERIFYING'),
                       (SELECT COUNT(*) FROM restores),
                       (SELECT COALESCE(SUM(bytes),0) FROM restores),
                       (SELECT COUNT(*) FROM access_log),
                       (SELECT COUNT(*) FROM rate_limits),
                       (SELECT COUNT(*) FROM sessions WHERE length(token_hash)<>32)",
                    params![i64_from_u64(now)?],
                    |row| {
                        Ok(StoreBenchmarkSnapshot {
                            hosts: row.get(0)?,
                            active_hosts: row.get(1)?,
                            sessions: row.get(2)?,
                            active_sessions: row.get(3)?,
                            assignments: row.get(4)?,
                            active_assignments: row.get(5)?,
                            assignment_rows: row.get(6)?,
                            reports: row.get(7)?,
                            pending_restore_tasks: row.get(8)?,
                            verifying_restore_tasks: row.get(9)?,
                            restores: row.get(10)?,
                            quarantine_bytes: row.get(11)?,
                            access_log_rows: row.get(12)?,
                            rate_limit_rows: row.get(13)?,
                            invalid_token_hash_rows: row.get(14)?,
                        })
                    },
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("read benchmark aggregate snapshot: {error}"))
                })
        })
    }

    #[cfg(test)]
    pub fn table_names(&self) -> Result<Vec<String>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT name FROM sqlite_schema
                     WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )
                .map_err(|error| WebCapacityError::Store(format!("list tables: {error}")))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| WebCapacityError::Store(format!("query tables: {error}")))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| WebCapacityError::Store(format!("decode tables: {error}")))
        })
    }

    #[cfg(test)]
    pub fn access_log_rows(&self) -> Result<Vec<(u64, String, String, String, bool)>> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT created_at,ip_prefix,coarse_user_agent,route,allowed
                     FROM access_log ORDER BY access_id",
                )
                .map_err(|error| {
                    WebCapacityError::Store(format!("prepare access log audit: {error}"))
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                })
                .map_err(|error| {
                    WebCapacityError::Store(format!("query access log audit: {error}"))
                })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| {
                    WebCapacityError::Store(format!("decode access log audit: {error}"))
                })
        })
    }

    #[cfg(test)]
    pub fn persisted_raw_token(&self, token: &str) -> Result<bool> {
        self.with_connection(|connection| {
            for table in ["sessions", "assignments", "reports", "restore_tasks"] {
                let sql = format!(
                    "SELECT COUNT(*) FROM {table} WHERE CAST({table} AS TEXT) LIKE ?1"
                );
                let query = match table {
                    "assignments" => "SELECT COUNT(*) FROM assignments WHERE body_json LIKE ?1",
                    "reports" => "SELECT COUNT(*) FROM reports WHERE coordinate_digests_json LIKE ?1 OR error_codes_json LIKE ?1",
                    "restore_tasks" => "SELECT COUNT(*) FROM restore_tasks WHERE coordinate_json LIKE ?1",
                    _ => {
                        let _ = sql;
                        continue;
                    }
                };
                let count: u64 = connection
                    .query_row(query, params![format!("%{token}%")], |row| row.get(0))
                    .map_err(|error| {
                        WebCapacityError::Store(format!("audit token persistence: {error}"))
                    })?;
                if count != 0 {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    fn with_connection<T>(&self, operation: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| WebCapacityError::Store("SQLite mutex poisoned".to_owned()))?;
        operation(&guard)
    }

    fn with_connection_mut<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .connection
            .lock()
            .map_err(|_| WebCapacityError::Store("SQLite mutex poisoned".to_owned()))?;
        operation(&mut guard)
    }
}

fn select_balanced_candidate(
    candidates: &mut Vec<AssignmentCandidate>,
    batch_load: &mut BatchDomainLoad,
    result: &mut Vec<([u8; 32], AssignmentRow)>,
) {
    if candidates.is_empty() {
        return;
    }
    let mut best_index = 0;
    for index in 1..candidates.len() {
        if assignment_candidate_score(&candidates[index], batch_load)
            < assignment_candidate_score(&candidates[best_index], batch_load)
        {
            best_index = index;
        }
    }
    let selected = candidates.swap_remove(best_index);
    candidates.clear();
    increment_load(&mut batch_load.providers, selected.provider);
    increment_load(&mut batch_load.regions, selected.region);
    increment_load(&mut batch_load.control_clusters, selected.control_cluster);
    increment_load(&mut batch_load.hosts, selected.host_id);
    result.push((selected.host_id, selected.row));
}

fn assignment_candidate_score<'a>(
    candidate: &'a AssignmentCandidate,
    batch: &BatchDomainLoad,
) -> AssignmentCandidateScore<'a> {
    AssignmentCandidateScore {
        coordinate_provider_copies: candidate.coordinate_provider_copies,
        coordinate_cluster_copies: candidate.coordinate_cluster_copies,
        coordinate_region_copies: candidate.coordinate_region_copies,
        provider_load: candidate.global_provider_load.saturating_add(
            batch
                .providers
                .get(&candidate.provider)
                .copied()
                .unwrap_or(0),
        ),
        cluster_load: candidate.global_cluster_load.saturating_add(
            batch
                .control_clusters
                .get(&candidate.control_cluster)
                .copied()
                .unwrap_or(0),
        ),
        region_load: candidate
            .global_region_load
            .saturating_add(batch.regions.get(&candidate.region).copied().unwrap_or(0)),
        host_load: candidate
            .global_host_load
            .saturating_add(batch.hosts.get(&candidate.host_id).copied().unwrap_or(0)),
        provider: &candidate.provider,
        control_cluster: &candidate.control_cluster,
        region: &candidate.region,
        host_id: candidate.host_id,
    }
}

fn increment_load<K: Ord>(loads: &mut BTreeMap<K, u64>, key: K) {
    let value = loads.entry(key).or_default();
    *value = value.saturating_add(1);
}

fn storage_class_text(value: StorageClass) -> &'static str {
    match value {
        StorageClass::Opfs => "OPFS",
        StorageClass::Indexeddb => "INDEXEDDB",
    }
}

fn i64_from_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| WebCapacityError::Store("SQLite integer overflow".to_owned()))
}
