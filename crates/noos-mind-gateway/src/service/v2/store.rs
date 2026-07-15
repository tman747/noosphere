use super::model::{
    JobStatus, QuoteResponse, Receipt, SettlementState, StreamEvent, EVENT_TTL_SECONDS,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityClass {
    TestOnlyLocal,
    SynchronousReplicated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Database(String),
    Crypto,
    Conflict,
    NotFound,
    TenantMismatch,
    InvalidState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredJob {
    pub job_id: String,
    pub tenant_id: String,
    pub quote: QuoteResponse,
    pub prompt: String,
    pub prompt_salt: String,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxKind {
    Dispatch,
    Cancel,
    SettlePaid,
    SettleRefund,
}

impl OutboxKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dispatch => "DISPATCH",
            Self::Cancel => "CANCEL",
            Self::SettlePaid => "SETTLE_PAID",
            Self::SettleRefund => "SETTLE_REFUND",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "DISPATCH" => Ok(Self::Dispatch),
            "CANCEL" => Ok(Self::Cancel),
            "SETTLE_PAID" => Ok(Self::SettlePaid),
            "SETTLE_REFUND" => Ok(Self::SettleRefund),
            _ => Err(StoreError::InvalidState),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub id: i64,
    pub job_id: String,
    pub tenant_id: String,
    pub kind: OutboxKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobInsert {
    pub job_id: String,
    pub replayed: bool,
    pub status: JobStatus,
}

pub trait GatewayV2Store: Send + Sync {
    fn durability(&self) -> DurabilityClass;
    fn put_quote(
        &self,
        tenant: &str,
        request_hash: &str,
        quote: &QuoteResponse,
    ) -> Result<QuoteResponse, StoreError>;
    fn create_job(
        &self,
        tenant: &str,
        idempotency_key: &str,
        request_hash: &str,
        job_id: &str,
        quote_id: &str,
        prompt: &str,
        prompt_salt: &str,
    ) -> Result<JobInsert, StoreError>;
    fn job(&self, tenant: &str, job_id: &str) -> Result<StoredJob, StoreError>;
    fn status(&self, tenant: &str, job_id: &str) -> Result<JobStatus, StoreError>;
    fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>, StoreError>;
    fn begin_running(&self, job_id: &str) -> Result<bool, StoreError>;
    fn complete_execution(
        &self,
        job_id: &str,
        output: &str,
        receipt: &Receipt,
    ) -> Result<(), StoreError>;
    fn request_cancel(&self, tenant: &str, job_id: &str) -> Result<JobStatus, StoreError>;
    fn complete_cancel(&self, job_id: &str, receipt: &Receipt) -> Result<(), StoreError>;
    fn mark_settled(
        &self,
        job_id: &str,
        state: SettlementState,
        chain_anchor: &str,
    ) -> Result<Receipt, StoreError>;
    fn receipt(&self, tenant: &str, job_id: &str) -> Result<Option<Receipt>, StoreError>;
    fn events_after(
        &self,
        tenant: &str,
        job_id: &str,
        after: u64,
    ) -> Result<Vec<StreamEvent>, StoreError>;
    fn finish_outbox(&self, id: i64) -> Result<(), StoreError>;
}

#[derive(Clone)]
pub struct SqliteTestStore {
    connection: Arc<Mutex<Connection>>,
    cipher: Arc<XChaCha20Poly1305>,
    path: PathBuf,
}

impl SqliteTestStore {
    pub fn open(path: &Path, encryption_key: [u8; 32]) -> Result<Self, StoreError> {
        if encryption_key == [0; 32] {
            return Err(StoreError::Crypto);
        }
        let connection = Connection::open(path).map_err(db)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS v2_quotes(
                    quote_id TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    body BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ISSUED','CONSUMED')),
                    UNIQUE(tenant,request_id)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS v2_jobs(
                    job_id TEXT PRIMARY KEY,
                    tenant TEXT NOT NULL,
                    quote_id TEXT NOT NULL REFERENCES v2_quotes(quote_id),
                    idem_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    prompt BLOB NOT NULL,
                    prompt_salt BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','CANCEL_REQUESTED','COMPLETED','CANCELLED','FAILED','NO_QUORUM')),
                    output BLOB,
                    receipt BLOB,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL,
                    UNIQUE(tenant,idem_key)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS v2_events(
                    job_id TEXT NOT NULL REFERENCES v2_jobs(job_id),
                    event_id INTEGER NOT NULL,
                    body BLOB NOT NULL,
                    expires_ms INTEGER NOT NULL,
                    PRIMARY KEY(job_id,event_id)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS v2_outbox(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL REFERENCES v2_jobs(job_id),
                    kind TEXT NOT NULL CHECK(kind IN ('DISPATCH','CANCEL','SETTLE_PAID','SETTLE_REFUND')),
                    state TEXT NOT NULL CHECK(state IN ('PENDING','DONE')),
                    UNIQUE(job_id,kind)
                 ) STRICT;",
            )
            .map_err(db)?;
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(db)?;
        if quick_check != "ok" {
            return Err(StoreError::Database(format!("quick_check: {quick_check}")));
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            cipher: Arc::new(XChaCha20Poly1305::new((&encryption_key).into())),
            path: path.to_path_buf(),
        })
    }

    pub fn raw_storage_contains(&self, needle: &str) -> bool {
        std::fs::read(&self.path)
            .map(|bytes| {
                bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
            .unwrap_or(false)
    }

    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0_u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Crypto)?;
        let mut sealed = nonce.to_vec();
        let body = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), bytes)
            .map_err(|_| StoreError::Crypto)?;
        sealed.extend_from_slice(&body);
        Ok(sealed)
    }

    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
        if bytes.len() < 24 {
            return Err(StoreError::Crypto);
        }
        self.cipher
            .decrypt(XNonce::from_slice(&bytes[..24]), &bytes[24..])
            .map_err(|_| StoreError::Crypto)
    }

    fn seal_json<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, StoreError> {
        self.encrypt(
            &serde_json::to_vec(value).map_err(|error| StoreError::Database(error.to_string()))?,
        )
    }

    fn open_json<T: DeserializeOwned>(&self, value: &[u8]) -> Result<T, StoreError> {
        serde_json::from_slice(&self.decrypt(value)?)
            .map_err(|error| StoreError::Database(error.to_string()))
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| StoreError::Database("database mutex poisoned".to_owned()))?;
        operation(&guard)
    }

    fn with_connection_mut<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut guard = self
            .connection
            .lock()
            .map_err(|_| StoreError::Database("database mutex poisoned".to_owned()))?;
        operation(&mut guard)
    }

    fn append_event_tx(
        &self,
        tx: &Transaction<'_>,
        job_id: &str,
        event_type: &str,
        data: serde_json::Value,
    ) -> Result<(), StoreError> {
        let next: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(event_id),0)+1 FROM v2_events WHERE job_id=?1",
                params![job_id],
                |row| row.get(0),
            )
            .map_err(db)?;
        let event = StreamEvent {
            id: u64::try_from(next).map_err(|_| StoreError::InvalidState)?,
            event_type: event_type.to_owned(),
            data,
        };
        let ttl_ms = i64::try_from(EVENT_TTL_SECONDS.saturating_mul(1_000))
            .map_err(|_| StoreError::InvalidState)?;
        tx.execute(
            "INSERT INTO v2_events(job_id,event_id,body,expires_ms) VALUES(?1,?2,?3,?4)",
            params![
                job_id,
                next,
                self.seal_json(&event)?,
                now_ms()?.saturating_add(ttl_ms)
            ],
        )
        .map_err(db)?;
        Ok(())
    }
}

impl GatewayV2Store for SqliteTestStore {
    fn durability(&self) -> DurabilityClass {
        DurabilityClass::TestOnlyLocal
    }

    fn put_quote(
        &self,
        tenant: &str,
        request_hash: &str,
        quote: &QuoteResponse,
    ) -> Result<QuoteResponse, StoreError> {
        self.with_connection(|connection| {
            let existing: Option<(String, Vec<u8>)> = connection
                .query_row(
                    "SELECT request_hash,body FROM v2_quotes WHERE tenant=?1 AND request_id=?2",
                    params![tenant, quote.request_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db)?;
            if let Some((hash, body)) = existing {
                return if hash == request_hash { self.open_json(&body) } else { Err(StoreError::Conflict) };
            }
            connection.execute(
                "INSERT INTO v2_quotes(quote_id,tenant,request_id,request_hash,body,status) VALUES(?1,?2,?3,?4,?5,'ISSUED')",
                params![quote.quote_id, tenant, quote.request_id, request_hash, self.seal_json(quote)?],
            ).map_err(db)?;
            Ok(quote.clone())
        })
    }

    fn create_job(
        &self,
        tenant: &str,
        idempotency_key: &str,
        request_hash: &str,
        job_id: &str,
        quote_id: &str,
        prompt: &str,
        prompt_salt: &str,
    ) -> Result<JobInsert, StoreError> {
        self.with_connection_mut(|connection| {
            let tx = connection.transaction().map_err(db)?;
            let existing: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT job_id,request_hash,status FROM v2_jobs WHERE tenant=?1 AND idem_key=?2",
                    params![tenant, idempotency_key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(db)?;
            if let Some((existing_job, hash, status)) = existing {
                return if hash == request_hash {
                    Ok(JobInsert { job_id: existing_job, replayed: true, status: parse_status(&status)? })
                } else {
                    Err(StoreError::Conflict)
                };
            }
            let changed = tx.execute(
                "UPDATE v2_quotes SET status='CONSUMED' WHERE quote_id=?1 AND tenant=?2 AND status='ISSUED'",
                params![quote_id, tenant],
            ).map_err(db)?;
            if changed != 1 {
                return Err(StoreError::NotFound);
            }
            let now = now_ms()?;
            tx.execute(
                "INSERT INTO v2_jobs(job_id,tenant,quote_id,idem_key,request_hash,prompt,prompt_salt,status,created_ms,updated_ms)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,'QUEUED',?8,?8)",
                params![job_id, tenant, quote_id, idempotency_key, request_hash, self.encrypt(prompt.as_bytes())?, self.encrypt(prompt_salt.as_bytes())?, now],
            ).map_err(db)?;
            tx.execute(
                "INSERT INTO v2_outbox(job_id,kind,state) VALUES(?1,'DISPATCH','PENDING')",
                params![job_id],
            ).map_err(db)?;
            tx.commit().map_err(db)?;
            Ok(JobInsert { job_id: job_id.to_owned(), replayed: false, status: JobStatus::Queued })
        })
    }

    fn job(&self, tenant: &str, job_id: &str) -> Result<StoredJob, StoreError> {
        self.with_connection(|connection| {
            let row: Option<(String, Vec<u8>, Vec<u8>, String, Vec<u8>)> = connection
                .query_row(
                    "SELECT j.tenant,j.prompt,j.prompt_salt,j.status,q.body FROM v2_jobs j JOIN v2_quotes q ON q.quote_id=j.quote_id WHERE j.job_id=?1",
                    params![job_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()
                .map_err(db)?;
            let (owner, prompt, salt, status, quote) = row.ok_or(StoreError::NotFound)?;
            if owner != tenant {
                return Err(StoreError::TenantMismatch);
            }
            Ok(StoredJob {
                job_id: job_id.to_owned(),
                tenant_id: owner,
                quote: self.open_json(&quote)?,
                prompt: String::from_utf8(self.decrypt(&prompt)?).map_err(|_| StoreError::Crypto)?,
                prompt_salt: String::from_utf8(self.decrypt(&salt)?).map_err(|_| StoreError::Crypto)?,
                status: parse_status(&status)?,
            })
        })
    }

    fn status(&self, tenant: &str, job_id: &str) -> Result<JobStatus, StoreError> {
        self.with_connection(|connection| {
            let row: Option<(String, String)> = connection
                .query_row(
                    "SELECT tenant,status FROM v2_jobs WHERE job_id=?1",
                    params![job_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db)?;
            let (owner, status) = row.ok_or(StoreError::NotFound)?;
            if owner != tenant {
                return Err(StoreError::TenantMismatch);
            }
            parse_status(&status)
        })
    }

    fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT o.id,o.job_id,o.kind,j.tenant FROM v2_outbox o JOIN v2_jobs j ON j.job_id=o.job_id WHERE o.state='PENDING' ORDER BY o.id LIMIT ?1"
            ).map_err(db)?;
            let rows = statement.query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))
            }).map_err(db)?;
            rows.map(|row| {
                let (id, job_id, kind, tenant_id) = row.map_err(db)?;
                Ok(OutboxItem { id, job_id, tenant_id, kind: OutboxKind::parse(&kind)? })
            }).collect()
        })
    }

    fn begin_running(&self, job_id: &str) -> Result<bool, StoreError> {
        self.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE v2_jobs SET status='RUNNING',updated_ms=?2 WHERE job_id=?1 AND status='QUEUED'",
                params![job_id, now_ms()?],
            ).map_err(db)?;
            if changed == 1 { return Ok(true); }
            let status: String = connection.query_row("SELECT status FROM v2_jobs WHERE job_id=?1", params![job_id], |row| row.get(0)).map_err(db)?;
            Ok(status == "RUNNING")
        })
    }

    fn complete_execution(
        &self,
        job_id: &str,
        output: &str,
        receipt: &Receipt,
    ) -> Result<(), StoreError> {
        self.with_connection_mut(|connection| {
            let tx = connection.transaction().map_err(db)?;
            let status: String = tx
                .query_row(
                    "SELECT status FROM v2_jobs WHERE job_id=?1",
                    params![job_id],
                    |row| row.get(0),
                )
                .map_err(db)?;
            if matches!(
                status.as_str(),
                "COMPLETED" | "CANCELLED" | "FAILED" | "NO_QUORUM"
            ) {
                return Ok(());
            }
            if status == "CANCEL_REQUESTED" {
                return Err(StoreError::InvalidState);
            }
            tx.execute(
                "UPDATE v2_jobs SET status=?2,output=?3,receipt=?4,updated_ms=?5 WHERE job_id=?1",
                params![
                    job_id,
                    status_string(&receipt.terminal_status),
                    self.encrypt(output.as_bytes())?,
                    self.seal_json(receipt)?,
                    now_ms()?
                ],
            )
            .map_err(db)?;
            for text in chunk_text(output, 96) {
                self.append_event_tx(
                    &tx,
                    job_id,
                    "output.delta",
                    serde_json::json!({
                        "delta": text,
                        "job_id": receipt.job_id,
                        "capsule_id": receipt.capsule_id,
                        "executor_id": receipt.executor_id,
                        "evidence_state": receipt.evidence_state,
                        "output_commitment": receipt.output_commitment,
                        "receipt_signature": receipt.signature
                    }),
                )?;
            }
            self.append_event_tx(
                &tx,
                job_id,
                "receipt.completed",
                serde_json::to_value(receipt)
                    .map_err(|error| StoreError::Database(error.to_string()))?,
            )?;
            let kind = if receipt.terminal_status == JobStatus::Completed {
                OutboxKind::SettlePaid
            } else {
                OutboxKind::SettleRefund
            };
            tx.execute(
                "INSERT OR IGNORE INTO v2_outbox(job_id,kind,state) VALUES(?1,?2,'PENDING')",
                params![job_id, kind.as_str()],
            )
            .map_err(db)?;
            tx.commit().map_err(db)
        })
    }

    fn request_cancel(&self, tenant: &str, job_id: &str) -> Result<JobStatus, StoreError> {
        self.with_connection_mut(|connection| {
            let tx = connection.transaction().map_err(db)?;
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT tenant,status FROM v2_jobs WHERE job_id=?1",
                    params![job_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db)?;
            let (owner, status) = row.ok_or(StoreError::NotFound)?;
            if owner != tenant {
                return Err(StoreError::TenantMismatch);
            }
            let parsed = parse_status(&status)?;
            if parsed.is_terminal() {
                return Ok(parsed);
            }
            tx.execute(
                "UPDATE v2_jobs SET status='CANCEL_REQUESTED',updated_ms=?2 WHERE job_id=?1",
                params![job_id, now_ms()?],
            )
            .map_err(db)?;
            tx.execute(
                "INSERT OR IGNORE INTO v2_outbox(job_id,kind,state) VALUES(?1,'CANCEL','PENDING')",
                params![job_id],
            )
            .map_err(db)?;
            tx.commit().map_err(db)?;
            Ok(JobStatus::CancelRequested)
        })
    }

    fn complete_cancel(&self, job_id: &str, receipt: &Receipt) -> Result<(), StoreError> {
        self.with_connection_mut(|connection| {
            let tx = connection.transaction().map_err(db)?;
            let changed = tx.execute(
                "UPDATE v2_jobs SET status='CANCELLED',receipt=?2,updated_ms=?3 WHERE job_id=?1 AND status='CANCEL_REQUESTED'",
                params![job_id, self.seal_json(receipt)?, now_ms()?],
            ).map_err(db)?;
            if changed == 0 {
                let status: String = tx.query_row("SELECT status FROM v2_jobs WHERE job_id=?1", params![job_id], |row| row.get(0)).map_err(db)?;
                if status != "CANCELLED" { return Err(StoreError::InvalidState); }
            } else {
                self.append_event_tx(&tx, job_id, "receipt.completed", serde_json::to_value(receipt).map_err(|error| StoreError::Database(error.to_string()))?)?;
                tx.execute("INSERT OR IGNORE INTO v2_outbox(job_id,kind,state) VALUES(?1,'SETTLE_REFUND','PENDING')", params![job_id]).map_err(db)?;
            }
            tx.commit().map_err(db)
        })
    }

    fn mark_settled(
        &self,
        job_id: &str,
        state: SettlementState,
        chain_anchor: &str,
    ) -> Result<Receipt, StoreError> {
        self.with_connection_mut(|connection| {
            let tx = connection.transaction().map_err(db)?;
            let body: Vec<u8> = tx
                .query_row(
                    "SELECT receipt FROM v2_jobs WHERE job_id=?1",
                    params![job_id],
                    |row| row.get(0),
                )
                .map_err(db)?;
            let mut receipt: Receipt = self.open_json(&body)?;
            if receipt.settlement_state != SettlementState::PendingChain {
                return Ok(receipt);
            }
            receipt.settlement_state = state;
            receipt.chain_anchor = Some(chain_anchor.to_owned());
            tx.execute(
                "UPDATE v2_jobs SET receipt=?2,updated_ms=?3 WHERE job_id=?1",
                params![job_id, self.seal_json(&receipt)?, now_ms()?],
            )
            .map_err(db)?;
            self.append_event_tx(
                &tx,
                job_id,
                "settlement.finalized",
                serde_json::to_value(&receipt)
                    .map_err(|error| StoreError::Database(error.to_string()))?,
            )?;
            tx.commit().map_err(db)?;
            Ok(receipt)
        })
    }

    fn receipt(&self, tenant: &str, job_id: &str) -> Result<Option<Receipt>, StoreError> {
        self.with_connection(|connection| {
            let row: Option<(String, Option<Vec<u8>>)> = connection
                .query_row(
                    "SELECT tenant,receipt FROM v2_jobs WHERE job_id=?1",
                    params![job_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db)?;
            let Some((owner, body)) = row else {
                return Ok(None);
            };
            if owner != tenant {
                return Err(StoreError::TenantMismatch);
            }
            body.map(|value| self.open_json(&value)).transpose()
        })
    }

    fn events_after(
        &self,
        tenant: &str,
        job_id: &str,
        after: u64,
    ) -> Result<Vec<StreamEvent>, StoreError> {
        self.status(tenant, job_id)?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "DELETE FROM v2_events WHERE expires_ms<?1",
                    params![now_ms()?],
                )
                .map_err(db)?;
            let mut statement = connection
                .prepare(
                    "SELECT body FROM v2_events WHERE job_id=?1 AND event_id>?2 ORDER BY event_id",
                )
                .map_err(db)?;
            let rows = statement
                .query_map(
                    params![job_id, i64::try_from(after).unwrap_or(i64::MAX)],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(db)?;
            rows.map(|row| self.open_json(&row.map_err(db)?)).collect()
        })
    }

    fn finish_outbox(&self, id: i64) -> Result<(), StoreError> {
        self.with_connection(|connection| {
            connection
                .execute("UPDATE v2_outbox SET state='DONE' WHERE id=?1", params![id])
                .map_err(db)?;
            Ok(())
        })
    }
}

fn db(error: rusqlite::Error) -> StoreError {
    StoreError::Database(error.to_string())
}

fn now_ms() -> Result<i64, StoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::InvalidState)?
        .as_millis();
    i64::try_from(millis).map_err(|_| StoreError::InvalidState)
}

fn parse_status(value: &str) -> Result<JobStatus, StoreError> {
    match value {
        "QUEUED" => Ok(JobStatus::Queued),
        "RUNNING" => Ok(JobStatus::Running),
        "CANCEL_REQUESTED" => Ok(JobStatus::CancelRequested),
        "COMPLETED" => Ok(JobStatus::Completed),
        "CANCELLED" => Ok(JobStatus::Cancelled),
        "FAILED" => Ok(JobStatus::Failed),
        "NO_QUORUM" => Ok(JobStatus::NoQuorum),
        _ => Err(StoreError::InvalidState),
    }
}

fn status_string(value: &JobStatus) -> &'static str {
    match value {
        JobStatus::Queued => "QUEUED",
        JobStatus::Running => "RUNNING",
        JobStatus::CancelRequested => "CANCEL_REQUESTED",
        JobStatus::Completed => "COMPLETED",
        JobStatus::Cancelled => "CANCELLED",
        JobStatus::Failed => "FAILED",
        JobStatus::NoQuorum => "NO_QUORUM",
    }
}

fn chunk_text(value: &str, maximum_bytes: usize) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    for (index, _) in value.char_indices() {
        if index.saturating_sub(start) >= maximum_bytes {
            chunks.push(value[start..index].to_owned());
            start = index;
        }
    }
    if start < value.len() {
        chunks.push(value[start..].to_owned());
    }
    chunks
}
