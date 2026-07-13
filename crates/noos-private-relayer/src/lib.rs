//! Non-custodial Tier 1 relay authorization and fresh-address sweep planning.
//! The relayer submits only a fully signed claim transaction whose parsed
//! payment, destination, and fee exactly match the wallet-signed relay intent.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub const RELAY_DOMAIN: &[u8] = b"NOOS/PRIVATE/RELAY/V1";
pub const SWEEP_DERIVATION_CONTEXT: &str = "NOOS/PRIVATE/SWEEP/DESTINATION/V1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RelayError {
    #[error("wrong_chain")]
    WrongChain,
    #[error("invalid_signature")]
    InvalidSignature,
    #[error("invalid_intent")]
    InvalidIntent,
    #[error("intent_not_active")]
    NotActive,
    #[error("intent_expired")]
    Expired,
    #[error("relay_fee_exceeded")]
    FeeExceeded,
    #[error("relay_rate_limited")]
    RateLimited,
    #[error("relay_replay")]
    Replay,
    #[error("simulation_mismatch")]
    SimulationMismatch,
    #[error("upstream_rejected")]
    UpstreamRejected,
    #[error("randomness_unavailable")]
    RandomnessUnavailable,
    #[error("arithmetic_overflow")]
    Overflow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayIntent {
    pub version: u16,
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub signer: Hash32,
    pub payment_id: Hash32,
    pub destination: Hash32,
    pub max_relay_fee: u64,
    pub nonce: u64,
    pub earliest_unix: u64,
    pub expires_unix: u64,
    pub claim_transaction: Vec<u8>,
}

impl RelayIntent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, RelayError> {
        let transaction_len =
            u32::try_from(self.claim_transaction.len()).map_err(|_| RelayError::InvalidIntent)?;
        let mut out = Vec::with_capacity(
            RELAY_DOMAIN
                .len()
                .saturating_add(2 + 32 * 5 + 8 * 4 + 4)
                .saturating_add(self.claim_transaction.len()),
        );
        out.extend_from_slice(RELAY_DOMAIN);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.payment_id);
        out.extend_from_slice(&self.destination);
        out.extend_from_slice(&self.max_relay_fee.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.earliest_unix.to_le_bytes());
        out.extend_from_slice(&self.expires_unix.to_le_bytes());
        out.extend_from_slice(&transaction_len.to_le_bytes());
        out.extend_from_slice(&self.claim_transaction);
        Ok(out)
    }

    pub fn verify_signature(&self, signature: &[u8; 64]) -> Result<(), RelayError> {
        let key =
            VerifyingKey::from_bytes(&self.signer).map_err(|_| RelayError::InvalidSignature)?;
        key.verify(&self.signing_bytes()?, &Signature::from_bytes(signature))
            .map_err(|_| RelayError::InvalidSignature)
    }

    pub fn validate_policy(
        &self,
        policy: &RelayPolicy,
        now_unix: u64,
    ) -> Result<(), RelayError> {
        validate_intent(policy, now_unix, self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPolicy {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub maximum_relay_fee: u64,
    pub maximum_transaction_bytes: usize,
    pub maximum_lifetime_seconds: u64,
    pub requests_per_window: u32,
    pub rate_window_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Simulation {
    pub payment_id: Hash32,
    pub destination: Hash32,
    pub relay_fee: u64,
    pub transaction_id: Hash32,
}

pub trait RelayUpstream {
    fn simulate(&mut self, transaction: &[u8]) -> Result<Simulation, RelayError>;
    fn submit(&mut self, transaction: &[u8]) -> Result<Hash32, RelayError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayReceipt {
    pub version: u16,
    pub payment_id: Hash32,
    pub destination: Hash32,
    pub transaction_id: Hash32,
    pub relay_fee: u64,
    pub accepted_unix: u64,
    pub receipt_hash: Hash32,
}

#[derive(Default)]
pub struct Relayer {
    used_nonces: BTreeSet<(Hash32, u64)>,
    used_payments: BTreeSet<Hash32>,
    rate: BTreeMap<Hash32, (u64, u32)>,
}

impl Relayer {
    pub fn relay(
        &mut self,
        policy: &RelayPolicy,
        now_unix: u64,
        intent: &RelayIntent,
        signature: &[u8; 64],
        upstream: &mut impl RelayUpstream,
    ) -> Result<RelayReceipt, RelayError> {
        validate_intent(policy, now_unix, intent)?;
        intent.verify_signature(signature)?;
        if self.used_nonces.contains(&(intent.signer, intent.nonce))
            || self.used_payments.contains(&intent.payment_id)
        {
            return Err(RelayError::Replay);
        }
        self.check_rate(policy, now_unix, intent.signer)?;
        self.check_rate(policy, now_unix, intent.payment_id)?;
        self.check_rate(policy, now_unix, intent.destination)?;

        let simulation = upstream.simulate(&intent.claim_transaction)?;
        if simulation.payment_id != intent.payment_id
            || simulation.destination != intent.destination
            || simulation.relay_fee > intent.max_relay_fee
            || simulation.relay_fee > policy.maximum_relay_fee
        {
            return Err(RelayError::SimulationMismatch);
        }
        let submitted_id = upstream.submit(&intent.claim_transaction)?;
        if submitted_id != simulation.transaction_id {
            return Err(RelayError::UpstreamRejected);
        }
        self.used_nonces.insert((intent.signer, intent.nonce));
        self.used_payments.insert(intent.payment_id);
        self.increment_rate(policy, now_unix, intent.signer);
        self.increment_rate(policy, now_unix, intent.payment_id);
        self.increment_rate(policy, now_unix, intent.destination);

        let mut receipt = RelayReceipt {
            version: 1,
            payment_id: intent.payment_id,
            destination: intent.destination,
            transaction_id: submitted_id,
            relay_fee: simulation.relay_fee,
            accepted_unix: now_unix,
            receipt_hash: [0; 32],
        };
        receipt.receipt_hash = receipt_hash(&receipt);
        Ok(receipt)
    }

    fn check_rate(
        &self,
        policy: &RelayPolicy,
        now_unix: u64,
        key: Hash32,
    ) -> Result<(), RelayError> {
        if policy.requests_per_window == 0 || policy.rate_window_seconds == 0 {
            return Err(RelayError::InvalidIntent);
        }
        if let Some((window_start, count)) = self.rate.get(&key) {
            let window_end = window_start
                .checked_add(policy.rate_window_seconds)
                .ok_or(RelayError::Overflow)?;
            if now_unix < window_end && *count >= policy.requests_per_window {
                return Err(RelayError::RateLimited);
            }
        }
        Ok(())
    }

    fn increment_rate(&mut self, policy: &RelayPolicy, now_unix: u64, key: Hash32) {
        let entry = self.rate.entry(key).or_insert((now_unix, 0));
        if now_unix.saturating_sub(entry.0) >= policy.rate_window_seconds {
            *entry = (now_unix, 1);
        } else {
            entry.1 = entry.1.saturating_add(1);
        }
    }
}

fn validate_intent(
    policy: &RelayPolicy,
    now_unix: u64,
    intent: &RelayIntent,
) -> Result<(), RelayError> {
    if intent.version != 1
        || intent.claim_transaction.is_empty()
        || intent.claim_transaction.len() > policy.maximum_transaction_bytes
        || intent.signer == [0; 32]
        || intent.payment_id == [0; 32]
        || intent.destination == [0; 32]
        || intent.destination == intent.signer
        || intent.earliest_unix >= intent.expires_unix
    {
        return Err(RelayError::InvalidIntent);
    }
    if intent.chain_id != policy.chain_id || intent.genesis_hash != policy.genesis_hash {
        return Err(RelayError::WrongChain);
    }
    if intent.max_relay_fee > policy.maximum_relay_fee {
        return Err(RelayError::FeeExceeded);
    }
    if now_unix < intent.earliest_unix {
        return Err(RelayError::NotActive);
    }
    if now_unix >= intent.expires_unix {
        return Err(RelayError::Expired);
    }
    if intent.expires_unix.saturating_sub(intent.earliest_unix) > policy.maximum_lifetime_seconds {
        return Err(RelayError::InvalidIntent);
    }
    Ok(())
}

fn receipt_hash(receipt: &RelayReceipt) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/PRIVATE/RELAY/RECEIPT/V1");
    hasher.update(&receipt.version.to_le_bytes());
    hasher.update(&receipt.payment_id);
    hasher.update(&receipt.destination);
    hasher.update(&receipt.transaction_id);
    hasher.update(&receipt.relay_fee.to_le_bytes());
    hasher.update(&receipt.accepted_unix.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepPlan {
    pub version: u16,
    pub payment_id: Hash32,
    pub source: Hash32,
    pub fresh_destination: Hash32,
    pub destination_index: u64,
    pub amount: u64,
    pub maximum_fee: u64,
    pub earliest_unix: u64,
    pub expires_unix: u64,
    pub relayer: Hash32,
    pub urgent: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SweepTimingPolicy {
    pub minimum_delay_seconds: u64,
    pub maximum_delay_seconds: u64,
    pub submission_window_seconds: u64,
}

pub fn derive_fresh_destination(
    wallet_entropy: &[u8; 32],
    payment_id: &Hash32,
    index: u64,
) -> Hash32 {
    let mut material = Vec::with_capacity(72);
    material.extend_from_slice(wallet_entropy);
    material.extend_from_slice(payment_id);
    material.extend_from_slice(&index.to_le_bytes());
    let secret = blake3::derive_key(SWEEP_DERIVATION_CONTEXT, &material);
    ed25519_dalek::SigningKey::from_bytes(&secret)
        .verifying_key()
        .to_bytes()
}

pub fn plan_sweep(
    wallet_entropy: &[u8; 32],
    payment_id: Hash32,
    source: Hash32,
    destination_index: u64,
    amount: u64,
    maximum_fee: u64,
    relayer: Hash32,
    now_unix: u64,
    timing: SweepTimingPolicy,
    urgent: bool,
) -> Result<SweepPlan, RelayError> {
    if payment_id == [0; 32] || source == [0; 32] || relayer == [0; 32] || amount == 0 {
        return Err(RelayError::InvalidIntent);
    }
    let fresh_destination =
        derive_fresh_destination(wallet_entropy, &payment_id, destination_index);
    if fresh_destination == source || fresh_destination == relayer {
        return Err(RelayError::InvalidIntent);
    }
    let (earliest_unix, expires_unix) = schedule_sweep(now_unix, timing, urgent)?;
    Ok(SweepPlan {
        version: 1,
        payment_id,
        source,
        fresh_destination,
        destination_index,
        amount,
        maximum_fee,
        earliest_unix,
        expires_unix,
        relayer,
        urgent,
    })
}

pub fn schedule_sweep(
    now_unix: u64,
    policy: SweepTimingPolicy,
    urgent: bool,
) -> Result<(u64, u64), RelayError> {
    if policy.minimum_delay_seconds > policy.maximum_delay_seconds
        || policy.submission_window_seconds == 0
    {
        return Err(RelayError::InvalidIntent);
    }
    let delay = if urgent {
        0
    } else {
        uniform_inclusive(policy.minimum_delay_seconds, policy.maximum_delay_seconds)?
    };
    let earliest = now_unix.checked_add(delay).ok_or(RelayError::Overflow)?;
    let expires = earliest
        .checked_add(policy.submission_window_seconds)
        .ok_or(RelayError::Overflow)?;
    Ok((earliest, expires))
}

fn uniform_inclusive(minimum: u64, maximum: u64) -> Result<u64, RelayError> {
    let width = maximum
        .checked_sub(minimum)
        .and_then(|delta| delta.checked_add(1))
        .ok_or(RelayError::Overflow)?;
    if width == 0 {
        return Err(RelayError::Overflow);
    }
    let zone = u64::MAX - (u64::MAX % width);
    loop {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|_| RelayError::RandomnessUnavailable)?;
        let sample = u64::from_le_bytes(bytes);
        if sample < zone {
            return minimum
                .checked_add(sample % width)
                .ok_or(RelayError::Overflow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct Upstream {
        simulation: Simulation,
        submissions: usize,
    }
    impl RelayUpstream for Upstream {
        fn simulate(&mut self, _transaction: &[u8]) -> Result<Simulation, RelayError> {
            Ok(self.simulation)
        }
        fn submit(&mut self, _transaction: &[u8]) -> Result<Hash32, RelayError> {
            self.submissions += 1;
            Ok(self.simulation.transaction_id)
        }
    }

    fn setup() -> (RelayPolicy, RelayIntent, SigningKey, Upstream) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let intent = RelayIntent {
            version: 1,
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            signer: key.verifying_key().to_bytes(),
            payment_id: [3; 32],
            destination: [4; 32],
            max_relay_fee: 10,
            nonce: 9,
            earliest_unix: 100,
            expires_unix: 200,
            claim_transaction: vec![5, 6, 7],
        };
        let policy = RelayPolicy {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            maximum_relay_fee: 20,
            maximum_transaction_bytes: 1024,
            maximum_lifetime_seconds: 300,
            requests_per_window: 4,
            rate_window_seconds: 60,
        };
        let upstream = Upstream {
            simulation: Simulation {
                payment_id: intent.payment_id,
                destination: intent.destination,
                relay_fee: 8,
                transaction_id: [8; 32],
            },
            submissions: 0,
        };
        (policy, intent, key, upstream)
    }

    #[test]
    fn valid_exact_intent_is_simulated_submitted_and_receipted() {
        let (policy, intent, key, mut upstream) = setup();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        let receipt = Relayer::default()
            .relay(&policy, 150, &intent, &signature, &mut upstream)
            .unwrap();
        assert_eq!(upstream.submissions, 1);
        assert_eq!(receipt.transaction_id, [8; 32]);
        assert_ne!(receipt.receipt_hash, [0; 32]);
    }

    #[test]
    fn destination_substitution_and_replay_are_rejected() {
        let (policy, intent, key, mut upstream) = setup();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        let mut changed = intent.clone();
        changed.destination = [9; 32];
        assert_eq!(
            Relayer::default().relay(&policy, 150, &changed, &signature, &mut upstream),
            Err(RelayError::InvalidSignature)
        );
        let mut relayer = Relayer::default();
        relayer
            .relay(&policy, 150, &intent, &signature, &mut upstream)
            .unwrap();
        assert_eq!(
            relayer.relay(&policy, 150, &intent, &signature, &mut upstream),
            Err(RelayError::Replay)
        );
    }

    #[test]
    fn simulation_must_match_payment_destination_and_fee() {
        let (policy, intent, key, mut upstream) = setup();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        upstream.simulation.destination = [10; 32];
        assert_eq!(
            Relayer::default().relay(&policy, 150, &intent, &signature, &mut upstream),
            Err(RelayError::SimulationMismatch)
        );
        assert_eq!(upstream.submissions, 0);
    }

    #[test]
    fn sweep_destinations_are_payment_specific_and_never_main_account() {
        let entropy = [11; 32];
        let first = derive_fresh_destination(&entropy, &[12; 32], 0);
        let second = derive_fresh_destination(&entropy, &[13; 32], 0);
        assert_ne!(first, second);
        assert_ne!(
            first,
            SigningKey::from_bytes(&entropy).verifying_key().to_bytes()
        );
        let timing = SweepTimingPolicy {
            minimum_delay_seconds: 30,
            maximum_delay_seconds: 90,
            submission_window_seconds: 20,
        };
        let plan = plan_sweep(
            &entropy, [12; 32], [14; 32], 7, 1_000, 5, [15; 32], 10_000, timing, false,
        )
        .unwrap();
        assert_eq!(plan.destination_index, 7);
        assert_eq!(
            plan.fresh_destination,
            derive_fresh_destination(&entropy, &[12; 32], 7)
        );
        assert_ne!(plan.fresh_destination, plan.source);
    }

    #[test]
    fn randomized_and_urgent_sweep_windows_are_bounded() {
        let policy = SweepTimingPolicy {
            minimum_delay_seconds: 30,
            maximum_delay_seconds: 90,
            submission_window_seconds: 20,
        };
        for _ in 0..64 {
            let (earliest, expires) = schedule_sweep(1_000, policy, false).unwrap();
            assert!((1_030..=1_090).contains(&earliest));
            assert_eq!(expires - earliest, 20);
        }
        assert_eq!(schedule_sweep(1_000, policy, true).unwrap(), (1_000, 1_020));
    }
}
