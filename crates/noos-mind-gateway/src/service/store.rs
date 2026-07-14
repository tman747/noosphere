use super::{Result, ServiceError};
use noos_nel::Hash32;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct GatewayStore {
    connection: Arc<Mutex<Connection>>,
}

impl GatewayStore {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)
            .map_err(|error| ServiceError::Store(format!("open database: {error}")))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS quotes (
                    quote_id BLOB PRIMARY KEY NOT NULL CHECK(length(quote_id)=32),
                    body_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ISSUED','OPENED','EXPIRED'))
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS jobs (
                    job_id BLOB PRIMARY KEY NOT NULL CHECK(length(job_id)=32),
                    quote_id BLOB NOT NULL REFERENCES quotes(quote_id),
                    prompt_commitment BLOB NOT NULL CHECK(length(prompt_commitment)=32),
                    requester_credential BLOB NOT NULL CHECK(length(requester_credential)=32),
                    status TEXT NOT NULL CHECK(status IN ('PENDING','RUNNING','COMPLETED','FAILED')),
                    error_code TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id BLOB PRIMARY KEY NOT NULL CHECK(length(receipt_id)=32),
                    job_id BLOB NOT NULL UNIQUE REFERENCES jobs(job_id),
                    body_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL
                 ) STRICT;",
            )
            .map_err(|error| ServiceError::Store(format!("initialize database: {error}")))?;
        let quick_check: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|error| ServiceError::Store(format!("database quick_check: {error}")))?;
        if quick_check != "ok" {
            return Err(ServiceError::Store(format!(
                "database quick_check failed: {quick_check}"
            )));
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn insert_quote(&self, quote_id: Hash32, body: &Value) -> Result<()> {
        let body = serde_json::to_string(body)
            .map_err(|error| ServiceError::Store(format!("serialize quote: {error}")))?;
        let now = now_ms()?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO quotes(quote_id,body_json,created_ms,status)
                     VALUES(?1,?2,?3,'ISSUED')",
                    params![quote_id.as_slice(), body, now],
                )
                .map_err(|error| ServiceError::Store(format!("insert quote: {error}")))?;
            Ok(())
        })
    }

    pub fn insert_job(
        &self,
        job_id: Hash32,
        quote_id: Hash32,
        prompt_commitment: Hash32,
        requester_credential: Hash32,
    ) -> Result<()> {
        let now = now_ms()?;
        self.with_connection_mut(|connection| {
            let transaction = connection
                .transaction()
                .map_err(|error| ServiceError::Store(format!("begin job transaction: {error}")))?;
            let changed = transaction
                .execute(
                    "UPDATE quotes SET status='OPENED'
                     WHERE quote_id=?1 AND status='ISSUED'",
                    params![quote_id.as_slice()],
                )
                .map_err(|error| ServiceError::Store(format!("open quote: {error}")))?;
            if changed != 1 {
                return Err(ServiceError::Store(
                    "quote was not available for opening".to_owned(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO jobs(job_id,quote_id,prompt_commitment,requester_credential,status,error_code,created_ms,updated_ms)
                     VALUES(?1,?2,?3,?4,'PENDING',NULL,?5,?5)",
                    params![
                        job_id.as_slice(),
                        quote_id.as_slice(),
                        prompt_commitment.as_slice(),
                        requester_credential.as_slice(),
                        now
                    ],
                )
                .map_err(|error| ServiceError::Store(format!("insert job: {error}")))?;
            transaction
                .commit()
                .map_err(|error| ServiceError::Store(format!("commit job: {error}")))?;
            Ok(())
        })
    }

    pub fn claim_job(&self, job_id: Hash32) -> Result<bool> {
        let now = now_ms()?;
        self.with_connection(|connection| {
            let changed = connection
                .execute(
                    "UPDATE jobs SET status='RUNNING',updated_ms=?2
                     WHERE job_id=?1 AND status='PENDING'",
                    params![job_id.as_slice(), now],
                )
                .map_err(|error| ServiceError::Store(format!("claim job: {error}")))?;
            Ok(changed == 1)
        })
    }

    pub fn complete_job(&self, job_id: Hash32, receipt_id: Hash32, body: &Value) -> Result<()> {
        let body = serde_json::to_string(body)
            .map_err(|error| ServiceError::Store(format!("serialize receipt: {error}")))?;
        let now = now_ms()?;
        self.with_connection_mut(|connection| {
            let transaction = connection.transaction().map_err(|error| {
                ServiceError::Store(format!("begin receipt transaction: {error}"))
            })?;
            let changed = transaction
                .execute(
                    "UPDATE jobs SET status='COMPLETED',error_code=NULL,updated_ms=?2
                     WHERE job_id=?1 AND status='RUNNING'",
                    params![job_id.as_slice(), now],
                )
                .map_err(|error| ServiceError::Store(format!("complete job: {error}")))?;
            if changed != 1 {
                return Err(ServiceError::Store(
                    "job was not running at receipt commit".to_owned(),
                ));
            }
            transaction
                .execute(
                    "INSERT INTO receipts(receipt_id,job_id,body_json,created_ms)
                     VALUES(?1,?2,?3,?4)",
                    params![receipt_id.as_slice(), job_id.as_slice(), body, now],
                )
                .map_err(|error| ServiceError::Store(format!("insert receipt: {error}")))?;
            transaction
                .commit()
                .map_err(|error| ServiceError::Store(format!("commit receipt: {error}")))?;
            Ok(())
        })
    }

    pub fn fail_job(&self, job_id: Hash32, error_code: &str) -> Result<()> {
        if error_code.is_empty() || error_code.len() > 64 {
            return Err(ServiceError::Store("invalid error code".to_owned()));
        }
        let now = now_ms()?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "UPDATE jobs SET status='FAILED',error_code=?2,updated_ms=?3
                     WHERE job_id=?1 AND status IN ('PENDING','RUNNING')",
                    params![job_id.as_slice(), error_code, now],
                )
                .map_err(|error| ServiceError::Store(format!("fail job: {error}")))?;
            Ok(())
        })
    }

    pub fn receipt_for_job(
        &self,
        job_id: Hash32,
        requester_credential: Hash32,
    ) -> Result<Option<Value>> {
        self.with_connection(|connection| {
            let body: Option<String> = connection
                .query_row(
                    "SELECT receipts.body_json
                     FROM receipts JOIN jobs USING(job_id)
                     WHERE receipts.job_id=?1 AND jobs.requester_credential=?2",
                    params![job_id.as_slice(), requester_credential.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| ServiceError::Store(format!("read receipt: {error}")))?;
            body.map(|value| {
                serde_json::from_str(&value)
                    .map_err(|error| ServiceError::Store(format!("decode stored receipt: {error}")))
            })
            .transpose()
        })
    }

    #[cfg(test)]
    pub fn persisted_prompt(&self, prompt: &str) -> Result<bool> {
        self.with_connection(|connection| {
            for table in ["quotes", "jobs", "receipts"] {
                let query =
                    format!("SELECT COUNT(*) FROM {table} WHERE CAST(body_json AS TEXT) LIKE ?1");
                if table == "jobs" {
                    continue;
                }
                let count: u64 = connection
                    .query_row(&query, params![format!("%{prompt}%")], |row| row.get(0))
                    .map_err(|error| ServiceError::Store(format!("prompt audit: {error}")))?;
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
            .map_err(|_| ServiceError::Store("database mutex poisoned".to_owned()))?;
        operation(&guard)
    }

    fn with_connection_mut<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .connection
            .lock()
            .map_err(|_| ServiceError::Store("database mutex poisoned".to_owned()))?;
        operation(&mut guard)
    }
}

fn now_ms() -> Result<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError::Store("system clock precedes Unix epoch".to_owned()))?
        .as_millis();
    i64::try_from(millis).map_err(|_| ServiceError::Store("timestamp overflow".to_owned()))
}
