#![forbid(unsafe_code)]

use noos_stable_operator::{
    median_source_price, ApiClient, Items, OperatorError, OracleReport, Status, TransactionSigner,
};
use reqwest::blocking::Client;
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::env;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct SourceQuote {
    #[serde(deserialize_with = "price")]
    price_q9: u128,
    observed_unix: u64,
}

struct Config {
    api: ApiClient,
    source_client: Client,
    source_urls: Vec<String>,
    signer: TransactionSigner,
    reporter: String,
    feed_id: String,
    database: Connection,
    interval: Duration,
    maximum_source_age: u64,
    maximum_spread_bps: u16,
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
    let source_urls = required("NOOS_ORACLE_SOURCE_URLS")?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unique = source_urls.iter().collect::<BTreeSet<_>>();
    if source_urls.len() < 5
        || unique.len() != source_urls.len()
        || source_urls
            .iter()
            .any(|url| !(url.starts_with("http://") || url.starts_with("https://")))
    {
        return Err(OperatorError::Configuration);
    }
    let chain_id = required("NOOS_ORACLE_CHAIN_ID")?;
    let genesis_hash = required("NOOS_ORACLE_GENESIS_HASH")?;
    let reporter = required("NOOS_ORACLE_REPORTER_ACCOUNT")?;
    let feed_id = required("NOOS_ORACLE_FEED_ID")?;
    if reporter.len() != 64 || feed_id.len() != 64 {
        return Err(OperatorError::Configuration);
    }
    let database = Connection::open(required("NOOS_ORACLE_DATABASE")?)
        .map_err(|_| OperatorError::Configuration)?;
    database
        .execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS oracle_submissions (
                feed_id TEXT NOT NULL,
                reporter TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                observed_height INTEGER NOT NULL,
                price_q9 TEXT NOT NULL,
                txid TEXT,
                status TEXT NOT NULL CHECK(status IN ('RESERVED','UNKNOWN','SUBMITTED')),
                updated_unix INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY(feed_id, reporter, sequence),
                UNIQUE(feed_id, reporter, observed_height)
            );
            ",
        )
        .map_err(|_| OperatorError::Configuration)?;
    Ok(Config {
        api: ApiClient::new(required("NOOS_ORACLE_INDEXER")?)?,
        source_client: Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| OperatorError::Configuration)?,
        source_urls,
        signer: TransactionSigner::new(
            required("NOOS_ORACLE_NODE")?,
            &required("NOOS_ORACLE_OPERATOR_SECRET")?,
            chain_id,
            genesis_hash,
            reporter.clone(),
            &required("NOOS_ORACLE_SEED_FILE")?,
            number("NOOS_ORACLE_DERIVATION_ACCOUNT", "0")?,
            number("NOOS_ORACLE_DERIVATION_INDEX", "0")?,
        )?,
        reporter,
        feed_id,
        database,
        interval: Duration::from_secs(number("NOOS_ORACLE_INTERVAL_SECONDS", "15")?),
        maximum_source_age: number("NOOS_ORACLE_MAX_SOURCE_AGE_SECONDS", "30")?,
        maximum_spread_bps: number("NOOS_ORACLE_MAX_SPREAD_BPS", "500")?,
        once: env::var("NOOS_ORACLE_ONCE").is_ok_and(|value| value == "1"),
    })
}

fn next_sequence(config: &Config, reports: &[OracleReport]) -> Result<u64, OperatorError> {
    let chain_sequence = reports
        .iter()
        .filter(|report| report.feed_id == config.feed_id && report.reporter == config.reporter)
        .map(|report| report.sequence)
        .max()
        .unwrap_or(0);
    let database_sequence: u64 = config
        .database
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM oracle_submissions
             WHERE feed_id = ?1 AND reporter = ?2",
            params![config.feed_id, config.reporter],
            |row| row.get(0),
        )
        .map_err(|_| OperatorError::Upstream)?;
    chain_sequence
        .max(database_sequence)
        .checked_add(1)
        .ok_or(OperatorError::Overflow)
}

fn run_once(config: &Config) -> Result<Value, OperatorError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperatorError::Configuration)?
        .as_secs();
    let mut quotes = Vec::with_capacity(config.source_urls.len());
    for url in &config.source_urls {
        let response = config
            .source_client
            .get(url)
            .header("accept", "application/json")
            .send()
            .map_err(|_| OperatorError::Upstream)?;
        if !response.status().is_success() {
            return Err(OperatorError::Upstream);
        }
        let quote: SourceQuote = response.json().map_err(|_| OperatorError::Malformed)?;
        if quote.price_q9 == 0
            || quote.observed_unix > now
            || now.saturating_sub(quote.observed_unix) > config.maximum_source_age
        {
            return Err(OperatorError::Malformed);
        }
        quotes.push(quote.price_q9);
    }
    let price_q9 = median_source_price(quotes.clone(), config.maximum_spread_bps)?;
    let maximum_difference = quotes
        .iter()
        .map(|price| price.abs_diff(price_q9))
        .max()
        .unwrap_or(0);
    let confidence = maximum_difference
        .checked_mul(10_000)
        .and_then(|value| value.checked_div(price_q9))
        .ok_or(OperatorError::Overflow)?
        .min(1_000);
    let confidence_bps = u16::try_from(confidence).map_err(|_| OperatorError::Overflow)?;
    let status: Status = config.api.get("/api/status")?;
    let reports: Items<OracleReport> = config.api.get("/api/v1/oracle-reports")?;
    let sequence = next_sequence(config, &reports.items)?;
    let observed_height = status.unsafe_head.height;
    config
        .database
        .execute(
            "INSERT INTO oracle_submissions
             (feed_id, reporter, sequence, observed_height, price_q9, status)
             VALUES (?1, ?2, ?3, ?4, ?5, 'RESERVED')",
            params![
                config.feed_id,
                config.reporter,
                sequence,
                observed_height,
                price_q9.to_string(),
            ],
        )
        .map_err(|_| OperatorError::Submission)?;
    let action = json!({
        "type": "submit_oracle_report",
        "reporter": config.reporter,
        "feed_id": config.feed_id,
        "price_q9": price_q9.to_string(),
        "confidence_bps": confidence_bps,
        "sequence": sequence.to_string(),
        "observed_height": observed_height.to_string(),
    });
    match config.signer.submit_action(action, observed_height) {
        Ok(txid) => {
            config
                .database
                .execute(
                    "UPDATE oracle_submissions SET status = 'SUBMITTED', txid = ?1,
                     updated_unix = unixepoch()
                     WHERE feed_id = ?2 AND reporter = ?3 AND sequence = ?4",
                    params![txid, config.feed_id, config.reporter, sequence],
                )
                .map_err(|_| OperatorError::Upstream)?;
            Ok(json!({
                "schema": "noos/oracle-reporter-cycle/v1",
                "ok": true,
                "feed_id": config.feed_id,
                "reporter": config.reporter,
                "price_q9": price_q9.to_string(),
                "confidence_bps": confidence_bps,
                "sequence": sequence.to_string(),
                "observed_height": observed_height.to_string(),
                "source_count": quotes.len(),
                "txid": txid,
            }))
        }
        Err(error) => {
            config
                .database
                .execute(
                    "UPDATE oracle_submissions SET status = 'UNKNOWN', updated_unix = unixepoch()
                     WHERE feed_id = ?1 AND reporter = ?2 AND sequence = ?3",
                    params![config.feed_id, config.reporter, sequence],
                )
                .map_err(|_| OperatorError::Upstream)?;
            Err(error)
        }
    }
}

fn price<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::String(text) => text.parse().map_err(serde::de::Error::custom),
        Value::Number(number) => number
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| serde::de::Error::custom("invalid price_q9")),
        _ => Err(serde::de::Error::custom("invalid price_q9")),
    }
}

fn main() -> Result<(), OperatorError> {
    let config = config()?;
    loop {
        match run_once(&config) {
            Ok(value) => println!("{}", value),
            Err(error) => println!(
                "{}",
                json!({
                    "schema": "noos/oracle-reporter-cycle/v1",
                    "ok": false,
                    "feed_id": config.feed_id,
                    "reporter": config.reporter,
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
