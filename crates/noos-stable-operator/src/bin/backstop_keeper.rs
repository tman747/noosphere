#![forbid(unsafe_code)]

use noos_stable_operator::{
    backstop_candidates, ApiClient, DebtPosition, Items, LendingMarket, OperatorError, OracleFeed,
    OracleReport, StableSafety, Status, TransactionSigner,
};
use rusqlite::{params, Connection, ErrorCode};
use serde_json::json;
use std::env;
use std::thread;
use std::time::Duration;

struct Config {
    api: ApiClient,
    signer: TransactionSigner,
    keeper: String,
    database: Connection,
    interval: Duration,
    once: bool,
}

fn required(name: &str) -> Result<String, OperatorError> {
    env::var(name).map_err(|_| OperatorError::Configuration)
}

fn number<T: std::str::FromStr>(name: &str, default: &str) -> Result<T, OperatorError> {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .map_err(|_| OperatorError::Configuration)
}

fn config() -> Result<Config, OperatorError> {
    let chain_id = required("NOOS_KEEPER_CHAIN_ID")?;
    let genesis_hash = required("NOOS_KEEPER_GENESIS_HASH")?;
    let keeper = required("NOOS_KEEPER_ACCOUNT")?;
    let database = Connection::open(required("NOOS_KEEPER_DATABASE")?)
        .map_err(|_| OperatorError::Configuration)?;
    database
        .execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS backstop_attempts (
                position_id TEXT NOT NULL,
                debt TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('RESERVED','UNKNOWN','SUBMITTED')),
                txid TEXT,
                updated_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY(position_id, debt)
            );
            ",
        )
        .map_err(|_| OperatorError::Configuration)?;
    Ok(Config {
        api: ApiClient::new(required("NOOS_KEEPER_INDEXER")?)?,
        signer: TransactionSigner::new(
            required("NOOS_KEEPER_NODE")?,
            &required("NOOS_KEEPER_OPERATOR_SECRET")?,
            chain_id,
            genesis_hash,
            keeper.clone(),
            &required("NOOS_KEEPER_SEED_FILE")?,
            number("NOOS_KEEPER_DERIVATION_ACCOUNT", "0")?,
            number("NOOS_KEEPER_DERIVATION_INDEX", "0")?,
        )?,
        keeper,
        database,
        interval: Duration::from_secs(number("NOOS_KEEPER_INTERVAL_SECONDS", "15")?),
        once: env::var("NOOS_KEEPER_ONCE").is_ok_and(|value| value == "1"),
    })
}

fn reserve(database: &Connection, position_id: &str, debt: u128) -> Result<bool, OperatorError> {
    match database.execute(
        "INSERT INTO backstop_attempts(position_id, debt, status) VALUES (?1, ?2, 'RESERVED')",
        params![position_id, debt.to_string()],
    ) {
        Ok(_) => Ok(true),
        Err(error) if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) => {
            Ok(false)
        }
        Err(_) => Err(OperatorError::Upstream),
    }
}

fn update_attempt(
    database: &Connection,
    position_id: &str,
    debt: u128,
    status: &str,
    txid: Option<&str>,
) -> Result<(), OperatorError> {
    database
        .execute(
            "UPDATE backstop_attempts SET status = ?1, txid = ?2, updated_unix = unixepoch()
             WHERE position_id = ?3 AND debt = ?4",
            params![status, txid, position_id, debt.to_string()],
        )
        .map_err(|_| OperatorError::Upstream)?;
    Ok(())
}

fn run_once(config: &Config) -> Result<serde_json::Value, OperatorError> {
    let status: Status = config.api.get("/api/status")?;
    let markets: Items<LendingMarket> = config.api.get("/api/v1/lending-markets")?;
    let positions: Items<DebtPosition> = config.api.get("/api/v1/debt-positions")?;
    let safety: Items<StableSafety> = config.api.get("/api/v1/stable-safety")?;
    let feeds: Items<OracleFeed> = config.api.get("/api/v1/oracle-feeds")?;
    let reports: Items<OracleReport> = config.api.get("/api/v1/oracle-reports")?;
    let candidates = backstop_candidates(
        status.unsafe_head.height,
        &markets.items,
        &positions.items,
        &safety.items,
        &feeds.items,
        &reports.items,
    )?;
    let mut submitted = Vec::new();
    for candidate in candidates {
        if !reserve(&config.database, &candidate.position_id, candidate.debt)? {
            continue;
        }
        let action = json!({
            "type": "backstop_liquidate",
            "keeper": config.keeper,
            "market_id": candidate.market_id,
            "owner": candidate.owner,
        });
        match config
            .signer
            .submit_action(action, status.unsafe_head.height)
        {
            Ok(txid) => {
                update_attempt(
                    &config.database,
                    &candidate.position_id,
                    candidate.debt,
                    "SUBMITTED",
                    Some(&txid),
                )?;
                submitted.push(json!({
                    "position_id": candidate.position_id,
                    "debt": candidate.debt.to_string(),
                    "txid": txid,
                }));
            }
            Err(error) => {
                update_attempt(
                    &config.database,
                    &candidate.position_id,
                    candidate.debt,
                    "UNKNOWN",
                    None,
                )?;
                return Err(error);
            }
        }
    }
    Ok(json!({
        "schema": "noos/backstop-keeper-cycle/v1",
        "ok": true,
        "height": status.unsafe_head.height.to_string(),
        "candidate_count": submitted.len(),
        "submitted": submitted,
    }))
}

fn main() -> Result<(), OperatorError> {
    let config = config()?;
    loop {
        match run_once(&config) {
            Ok(value) => println!("{}", value),
            Err(error) => println!(
                "{}",
                json!({
                    "schema": "noos/backstop-keeper-cycle/v1",
                    "ok": false,
                    "error": error.to_string(),
                })
            ),
        }
        if config.once {
            return Ok(());
        }
        thread::sleep(config.interval);
    }
}
