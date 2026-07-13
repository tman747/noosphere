#![forbid(unsafe_code)]

use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

pub const PRICE_SCALE: u128 = 1_000_000_000;

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("configuration_error")]
    Configuration,
    #[error("upstream_unavailable")]
    Upstream,
    #[error("malformed_upstream")]
    Malformed,
    #[error("wallet_error")]
    Wallet,
    #[error("arithmetic_overflow")]
    Overflow,
    #[error("submission_refused")]
    Submission,
}

#[derive(Clone)]
pub struct ApiClient {
    origin: String,
    client: Client,
}

impl ApiClient {
    pub fn new(origin: String) -> Result<Self, OperatorError> {
        if !(origin.starts_with("http://") || origin.starts_with("https://")) {
            return Err(OperatorError::Configuration);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| OperatorError::Configuration)?;
        Ok(Self {
            origin: origin.trim_end_matches('/').to_owned(),
            client,
        })
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, OperatorError> {
        let response = self
            .client
            .get(format!("{}{}", self.origin, path))
            .header("accept", "application/json")
            .send()
            .map_err(|_| OperatorError::Upstream)?;
        if !response.status().is_success() {
            return Err(OperatorError::Upstream);
        }
        response.json().map_err(|_| OperatorError::Malformed)
    }
}

pub struct TransactionSigner {
    node: String,
    token: Zeroizing<String>,
    chain_id: String,
    genesis_hash: String,
    account_id: String,
    seed: Zeroizing<String>,
    derivation_account: u32,
    derivation_index: u32,
}

impl TransactionSigner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: String,
        token_file: &str,
        chain_id: String,
        genesis_hash: String,
        account_id: String,
        seed_file: &str,
        derivation_account: u32,
        derivation_index: u32,
    ) -> Result<Self, OperatorError> {
        if chain_id.len() != 64 || genesis_hash.len() != 64 || account_id.len() != 64 {
            return Err(OperatorError::Configuration);
        }
        let token_value = fs::read_to_string(token_file).map_err(|_| OperatorError::Configuration)?;
        let token_json: Value =
            serde_json::from_str(&token_value).map_err(|_| OperatorError::Configuration)?;
        let token = token_json
            .get("rpc_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(OperatorError::Configuration)?
            .to_owned();
        let seed = fs::read_to_string(seed_file)
            .map_err(|_| OperatorError::Configuration)?
            .trim()
            .to_owned();
        if seed.is_empty()
            || seed.len() % 2 != 0
            || !seed.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(OperatorError::Configuration);
        }
        let key = noos_cli::keygen(
            &seed,
            "sign",
            derivation_account,
            derivation_index,
        )
        .map_err(|_| OperatorError::Wallet)?;
        if key.get("verifying_key").and_then(Value::as_str) != Some(account_id.as_str()) {
            return Err(OperatorError::Configuration);
        }
        Ok(Self {
            node,
            token: Zeroizing::new(token),
            chain_id,
            genesis_hash,
            account_id,
            seed: Zeroizing::new(seed),
            derivation_account,
            derivation_index,
        })
    }

    pub fn submit_action(&self, action: Value, head_height: u64) -> Result<String, OperatorError> {
        let expiry_height = head_height.checked_add(40).ok_or(OperatorError::Overflow)?;
        let spec = json!({
            "chain_id": self.chain_id,
            "expiry_height": expiry_height,
            "fee_payer": self.account_id,
            "resource_limits": {
                "bytes": 65536,
                "grain_steps": 100000,
                "proof_units": 8,
                "state_reads": 128,
                "state_writes": 64,
                "blob_bytes": 0
            },
            "account_inputs": [self.account_id],
            "actions": [action]
        });
        let built = noos_cli::tx_build(&spec.to_string()).map_err(|_| OperatorError::Wallet)?;
        let tx = built
            .get("tx")
            .and_then(Value::as_str)
            .ok_or(OperatorError::Wallet)?;
        let signed = noos_cli::tx_sign(
            tx,
            &self.seed,
            self.derivation_account,
            self.derivation_index,
            &self.chain_id,
            &self.genesis_hash,
            0,
            &[],
        )
        .map_err(|_| OperatorError::Wallet)?;
        let witnesses = signed
            .get("witnesses")
            .and_then(Value::as_str)
            .ok_or(OperatorError::Wallet)?;
        let response = noos_cli::tx_submit(
            &self.node,
            &self.token,
            &self.chain_id,
            &self.genesis_hash,
            tx,
            witnesses,
        )
        .map_err(|_| OperatorError::Submission)?;
        response
            .get("txid")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(OperatorError::Malformed)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Items<T> {
    pub items: Vec<T>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Status {
    pub chain_id: String,
    pub genesis_hash: String,
    pub unsafe_head: Head,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Head {
    #[serde(deserialize_with = "decimal_u64")]
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LendingMarket {
    pub market_id: String,
    pub oracle_feed_id: String,
    #[serde(deserialize_with = "decimal_u128")]
    pub liquidation_threshold_bps: u128,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DebtPosition {
    pub position_id: String,
    pub market_id: String,
    pub owner: String,
    #[serde(deserialize_with = "decimal_u128")]
    pub collateral: u128,
    #[serde(deserialize_with = "decimal_u128")]
    pub debt: u128,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StableSafety {
    pub market_id: String,
    #[serde(deserialize_with = "decimal_u128")]
    pub stable_reserve: u128,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OracleFeed {
    pub feed_id: String,
    #[serde(deserialize_with = "decimal_u64")]
    pub max_age_blocks: u64,
    #[serde(deserialize_with = "decimal_u128")]
    pub last_good_price_q9: u128,
    #[serde(deserialize_with = "decimal_u64")]
    pub last_good_height: u64,
    pub mode: u8,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OracleReport {
    pub feed_id: String,
    pub reporter: String,
    #[serde(deserialize_with = "decimal_u128")]
    pub price_q9: u128,
    pub confidence_bps: u16,
    #[serde(deserialize_with = "decimal_u64")]
    pub sequence: u64,
    #[serde(deserialize_with = "decimal_u64")]
    pub observed_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackstopCandidate {
    pub position_id: String,
    pub market_id: String,
    pub owner: String,
    pub debt: u128,
    pub collateral_value: u128,
    pub price_q9: u128,
}

pub fn backstop_candidates(
    height: u64,
    markets: &[LendingMarket],
    positions: &[DebtPosition],
    safety: &[StableSafety],
    feeds: &[OracleFeed],
    reports: &[OracleReport],
) -> Result<Vec<BackstopCandidate>, OperatorError> {
    let mut candidates = Vec::new();
    for position in positions.iter().filter(|position| position.debt > 0) {
        let Some(market) = markets.iter().find(|market| market.market_id == position.market_id)
        else {
            continue;
        };
        let Some(reserve) = safety.iter().find(|item| item.market_id == position.market_id) else {
            continue;
        };
        if reserve.stable_reserve < position.debt {
            continue;
        }
        let Some(feed) = feeds.iter().find(|feed| feed.feed_id == market.oracle_feed_id) else {
            continue;
        };
        let Some(price) = effective_price(height, feed, reports)? else {
            continue;
        };
        let collateral_value = position
            .collateral
            .checked_mul(price)
            .and_then(|value| value.checked_div(PRICE_SCALE))
            .ok_or(OperatorError::Overflow)?;
        let liquidation_value = collateral_value
            .checked_mul(market.liquidation_threshold_bps)
            .and_then(|value| value.checked_div(10_000))
            .ok_or(OperatorError::Overflow)?;
        if position.debt > liquidation_value {
            candidates.push(BackstopCandidate {
                position_id: position.position_id.clone(),
                market_id: position.market_id.clone(),
                owner: position.owner.clone(),
                debt: position.debt,
                collateral_value,
                price_q9: price,
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .debt
            .cmp(&left.debt)
            .then_with(|| left.position_id.cmp(&right.position_id))
    });
    Ok(candidates)
}

pub fn effective_price(
    height: u64,
    feed: &OracleFeed,
    reports: &[OracleReport],
) -> Result<Option<u128>, OperatorError> {
    if feed.mode == 2 {
        return Ok(None);
    }
    if feed.mode == 1 {
        let maximum_age = feed
            .max_age_blocks
            .checked_mul(10)
            .ok_or(OperatorError::Overflow)?;
        return Ok((feed.last_good_price_q9 > 0
            && height.saturating_sub(feed.last_good_height) <= maximum_age)
            .then_some(feed.last_good_price_q9));
    }
    let mut prices = reports
        .iter()
        .filter(|report| {
            report.feed_id == feed.feed_id
                && report.price_q9 > 0
                && report.observed_height <= height
                && height.saturating_sub(report.observed_height) <= feed.max_age_blocks
                && report.confidence_bps <= 1_000
        })
        .map(|report| {
            report
                .price_q9
                .checked_mul(u128::from(10_000u16.saturating_sub(report.confidence_bps)))
                .and_then(|value| value.checked_div(10_000))
                .ok_or(OperatorError::Overflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if prices.len() < 3 {
        return Ok(None);
    }
    prices.sort_unstable();
    Ok(Some(prices[prices.len() / 2]))
}

pub fn median_source_price(mut prices: Vec<u128>, maximum_spread_bps: u16) -> Result<u128, OperatorError> {
    if prices.len() < 5 || prices.contains(&0) {
        return Err(OperatorError::Malformed);
    }
    prices.sort_unstable();
    let median = prices[prices.len() / 2];
    let spread = prices
        .last()
        .copied()
        .and_then(|maximum| maximum.checked_sub(prices[0]))
        .and_then(|difference| difference.checked_mul(10_000))
        .and_then(|scaled| scaled.checked_div(median))
        .ok_or(OperatorError::Overflow)?;
    if spread > u128::from(maximum_spread_bps) {
        return Err(OperatorError::Malformed);
    }
    Ok(median)
}

fn decimal_u64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::String(text) => text.parse().map_err(serde::de::Error::custom),
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("invalid u64")),
        _ => Err(serde::de::Error::custom("invalid u64")),
    }
}

fn decimal_u128<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::String(text) => text.parse().map_err(serde::de::Error::custom),
        Value::Number(number) => number
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| serde::de::Error::custom("invalid u128")),
        _ => Err(serde::de::Error::custom("invalid u128")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn keeper_requires_funded_unhealthy_position_and_fresh_quorum() {
        let markets = vec![LendingMarket {
            market_id: "11".repeat(32),
            oracle_feed_id: "22".repeat(32),
            liquidation_threshold_bps: 7_500,
        }];
        let positions = vec![DebtPosition {
            position_id: "33".repeat(32),
            market_id: "11".repeat(32),
            owner: "44".repeat(32),
            collateral: 100,
            debt: 80,
        }];
        let safety = vec![StableSafety {
            market_id: "11".repeat(32),
            stable_reserve: 80,
        }];
        let feed = OracleFeed {
            feed_id: "22".repeat(32),
            max_age_blocks: 10,
            last_good_price_q9: PRICE_SCALE,
            last_good_height: 100,
            mode: 0,
        };
        let reports = [PRICE_SCALE, PRICE_SCALE, PRICE_SCALE]
            .into_iter()
            .enumerate()
            .map(|(index, price)| OracleReport {
                feed_id: "22".repeat(32),
                reporter: format!("{index:064x}"),
                price_q9: price,
                confidence_bps: 0,
                sequence: 1,
                observed_height: 100,
            })
            .collect::<Vec<_>>();
        let result = backstop_candidates(100, &markets, &positions, &safety, &[feed], &reports)
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].owner, "44".repeat(32));
    }

    #[test]
    fn oracle_aggregation_requires_five_sources_and_bounded_spread() {
        assert_eq!(
            median_source_price(vec![98, 99, 100, 101, 102], 500).unwrap(),
            100
        );
        assert!(median_source_price(vec![1, 2, 100, 101, 102], 500).is_err());
        assert!(median_source_price(vec![99, 100, 101, 102], 500).is_err());
    }
}
