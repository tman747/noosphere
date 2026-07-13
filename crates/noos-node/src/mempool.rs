//! Mempool: admission, caps, eviction, and deterministic template
//! assembly (plan §7.7; node-v1.md §6).
//!
//! Admission pipeline (exact order; the first failing stage names the
//! rejection):
//!
//! 1. size caps (`max_tx_bytes`, and the declared `resource_limits.bytes`
//!    envelope must cover the encoding — Lumen's own step-2 law);
//! 2. canonical decode of transaction, witnesses, and every action
//!    (noncanonical/trailing/unknown-field bytes reject here);
//! 3. chain id / format version / expiry;
//! 4. fee floor: declared maximum fee under the CURRENT base prices
//!    (`fees::fee(prices, usage(resource_limits))`) must reach the
//!    configured floor; overflow rejects;
//! 5. settled-duplicate and pending-duplicate caches;
//! 6. stateful checks against the live ledger: fee payer exists, payer
//!    balance covers the declared maximum fee, payer appears in
//!    `account_inputs`, witness alignment (`witness_root`, one intent per
//!    account input, `tx_commitment == txid`), and every intent signature
//!    verifies under the node suite law ([`crate::auth::NodeAuthVerifier`]);
//! 7. bounded-resource caps: per-source pending limit, per-payer pending
//!    limit (FIFO nonce ordering — Lumen transactions carry no explicit
//!    nonce; the account input consumes `nonce+1` implicitly, so per-payer
//!    order IS the nonce order), then pool byte/count caps with
//!    fee-density eviction (lowest density leaves first; an incoming
//!    transaction that cannot beat the lowest density is rejected).
//!
//! Template assembly is deterministic: candidates ranked by
//! `(fee density desc, arrival seq asc, txid asc)` under per-payer FIFO,
//! filled under the body caps (count, byte budget, five-axis resource
//! capacity).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use noos_codec::NoosDecode;
use noos_lumen::engine::AuthVerifier;
use noos_lumen::fees::{self, Usage};
use noos_lumen::objects::{txid as compute_txid, ActionV1, TransactionV1, TransactionWitnessesV1};
use noos_lumen::state::{LumenLedger, NOOS_ASSET};

use crate::auth::NodeAuthVerifier;
use crate::Hash32;

/// Mempool bounds and policy.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_count: usize,
    pub max_bytes: usize,
    pub max_tx_bytes: usize,
    pub per_source_pending: usize,
    pub per_account_pending: usize,
    /// Fee floor in micro-NOOS on the declared maximum fee.
    pub min_fee_micro: u128,
    /// Capacity of the recently-settled/seen duplicate cache.
    pub seen_cache: usize,
    /// Template byte budget (tx + witness bytes) under the DA body cap.
    pub template_byte_budget: usize,
    /// Template transaction-count cap (≤ `MAX_TRANSACTIONS`).
    pub template_max_txs: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            max_count: 4096,
            max_bytes: 8 * 1024 * 1024,
            max_tx_bytes: 128 * 1024,
            per_source_pending: 256,
            per_account_pending: 64,
            min_fee_micro: 1,
            seen_cache: 65_536,
            template_byte_budget: 768 * 1024,
            template_max_txs: 2048,
        }
    }
}

/// Admission source (per-IP / per-peer limiter key).
pub type SourceId = u64;

/// Typed admission failures; stable snake_case codes for the RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    Oversized,
    Malformed,
    WrongChain,
    WrongVersion,
    Expired,
    FeeOverflow,
    FeeBelowFloor { fee: u128, floor: u128 },
    DuplicatePending,
    DuplicateSettled,
    UnknownPayer,
    PayerNotSigner,
    InsufficientBalance,
    WitnessMismatch,
    SignatureInvalid,
    SourceLimit,
    AccountLimit,
    PoolFull,
}

impl AdmitError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AdmitError::Oversized => "oversized",
            AdmitError::Malformed => "malformed",
            AdmitError::WrongChain => "wrong_chain",
            AdmitError::WrongVersion => "wrong_version",
            AdmitError::Expired => "expired",
            AdmitError::FeeOverflow => "fee_overflow",
            AdmitError::FeeBelowFloor { .. } => "fee_below_floor",
            AdmitError::DuplicatePending => "duplicate_pending",
            AdmitError::DuplicateSettled => "duplicate_settled",
            AdmitError::UnknownPayer => "unknown_payer",
            AdmitError::PayerNotSigner => "payer_not_signer",
            AdmitError::InsufficientBalance => "insufficient_balance",
            AdmitError::WitnessMismatch => "witness_mismatch",
            AdmitError::SignatureInvalid => "signature_invalid",
            AdmitError::SourceLimit => "source_limit",
            AdmitError::AccountLimit => "account_limit",
            AdmitError::PoolFull => "pool_full",
        }
    }
}

/// One admitted entry.
#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub txid: Hash32,
    pub tx: TransactionV1,
    pub witnesses: TransactionWitnessesV1,
    pub tx_bytes: Vec<u8>,
    pub wit_bytes: Vec<u8>,
    /// Account authorization descriptors against which every signature was
    /// verified at admission. Execution may reuse that result only while all
    /// descriptors remain byte-identical.
    pub signature_authorizations: Vec<(Hash32, Vec<u8>)>,
    /// Declared maximum fee under admission-time prices.
    pub fee: u128,
    /// Fee density: `fee * 1000 / encoded_len` (micro-NOOS per KB-ish;
    /// only the ORDER matters, and it is deterministic).
    pub density: u128,
    pub payer: Hash32,
    pub source: SourceId,
    pub seq: u64,
    pub usage: Usage,
}

impl PoolEntry {
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.tx_bytes.len().saturating_add(self.wit_bytes.len())
    }
    fn density_key(&self) -> (u128, u64, Hash32) {
        (self.density, self.seq, self.txid)
    }
}

/// Bounded FIFO duplicate cache over txids.
#[derive(Debug, Clone, Default)]
struct SeenCache {
    cap: usize,
    order: VecDeque<Hash32>,
    set: BTreeSet<Hash32>,
}

impl SeenCache {
    fn insert(&mut self, id: Hash32) {
        if self.cap == 0 || !self.set.insert(id) {
            return;
        }
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }
    fn contains(&self, id: &Hash32) -> bool {
        self.set.contains(id)
    }
}

/// The mempool. Owned by the consensus task (single writer).
#[derive(Clone)]
pub struct Mempool {
    cfg: MempoolConfig,
    entries: BTreeMap<Hash32, PoolEntry>,
    /// Eviction order: ascending `(density, seq, txid)` — lowest first.
    by_density: BTreeSet<(u128, u64, Hash32)>,
    /// Per-payer FIFO queues (nonce order).
    per_account: BTreeMap<Hash32, VecDeque<Hash32>>,
    per_source: BTreeMap<SourceId, usize>,
    seen: SeenCache,
    total_bytes: usize,
    next_seq: u64,
}

impl Mempool {
    #[must_use]
    pub fn new(cfg: MempoolConfig) -> Self {
        let seen_cap = cfg.seen_cache;
        Mempool {
            cfg,
            entries: BTreeMap::new(),
            by_density: BTreeSet::new(),
            per_account: BTreeMap::new(),
            per_source: BTreeMap::new(),
            seen: SeenCache {
                cap: seen_cap,
                ..SeenCache::default()
            },
            total_bytes: 0,
            next_seq: 0,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    #[must_use]
    pub fn contains(&self, txid: &Hash32) -> bool {
        self.entries.contains_key(txid)
    }

    /// Full admission pipeline; returns the txid on acceptance.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        tx_bytes: &[u8],
        wit_bytes: &[u8],
        source: SourceId,
        next_height: u64,
        chain_id: &Hash32,
        prices: &fees::Prices,
        ledger: &LumenLedger,
    ) -> Result<Hash32, AdmitError> {
        // 1. size caps.
        let encoded_len = tx_bytes.len().saturating_add(wit_bytes.len());
        if encoded_len > self.cfg.max_tx_bytes {
            return Err(AdmitError::Oversized);
        }

        // 2. canonical decode (transaction, witnesses, every action).
        let tx = TransactionV1::decode_canonical(tx_bytes).map_err(|_| AdmitError::Malformed)?;
        let wits = TransactionWitnessesV1::decode_canonical(wit_bytes)
            .map_err(|_| AdmitError::Malformed)?;
        for raw in tx.actions.iter() {
            ActionV1::decode_canonical(raw.as_slice()).map_err(|_| AdmitError::Malformed)?;
        }
        let id = compute_txid(&tx);

        // 3. chain / version / expiry.
        if &tx.chain_id != chain_id {
            return Err(AdmitError::WrongChain);
        }
        if tx.format_version != 1 {
            return Err(AdmitError::WrongVersion);
        }
        if tx.expiry_height < next_height {
            return Err(AdmitError::Expired);
        }
        if u64::try_from(encoded_len).map_or(true, |l| l > tx.resource_limits.bytes) {
            // Lumen would reject at execution; refuse admission up front.
            return Err(AdmitError::Oversized);
        }

        // 4. fee floor under current prices.
        let usage = fees::usage_from_resources(&tx.resource_limits);
        let fee = fees::fee(prices, &usage).ok_or(AdmitError::FeeOverflow)?;
        if fee < self.cfg.min_fee_micro {
            return Err(AdmitError::FeeBelowFloor {
                fee,
                floor: self.cfg.min_fee_micro,
            });
        }

        // 5. duplicates.
        if self.entries.contains_key(&id) {
            return Err(AdmitError::DuplicatePending);
        }
        if self.seen.contains(&id) || ledger.get_receipt(&id).is_some() {
            return Err(AdmitError::DuplicateSettled);
        }

        // 6. stateful checks + signatures.
        let payer = tx.fee_payer;
        let payer_account = ledger.get_account(&payer).ok_or(AdmitError::UnknownPayer)?;
        if !tx.account_inputs.iter().any(|a| a == &payer) {
            return Err(AdmitError::PayerNotSigner);
        }
        if ledger.balance(&payer, &NOOS_ASSET) < fee {
            return Err(AdmitError::InsufficientBalance);
        }
        if noos_lumen::objects::witness_root(&wits.lock_reveals) != tx.witness_root
            || wits.intents.len() != tx.account_inputs.len()
            || wits.lock_reveals.len() != tx.note_inputs.len()
        {
            return Err(AdmitError::WitnessMismatch);
        }
        let verifier = NodeAuthVerifier;
        let mut signature_authorizations = Vec::with_capacity(tx.account_inputs.len());
        for (account_id, intent) in tx.account_inputs.iter().zip(wits.intents.iter()) {
            if intent.tx_commitment != id {
                return Err(AdmitError::WitnessMismatch);
            }
            let account = if account_id == &payer {
                payer_account.clone()
            } else {
                ledger
                    .get_account(account_id)
                    .ok_or(AdmitError::UnknownPayer)?
            };
            if !verifier.verify_signature(
                intent.signature_suite,
                account.auth_descriptor.as_slice(),
                &id,
                intent.signature.as_slice(),
            ) {
                return Err(AdmitError::SignatureInvalid);
            }
            signature_authorizations
                .push((*account_id, account.auth_descriptor.as_slice().to_vec()));
        }

        // 7. bounded-resource caps.
        if self.per_source.get(&source).copied().unwrap_or(0) >= self.cfg.per_source_pending {
            return Err(AdmitError::SourceLimit);
        }
        if self.per_account.get(&payer).map_or(0, VecDeque::len) >= self.cfg.per_account_pending {
            return Err(AdmitError::AccountLimit);
        }

        let density = fee
            .saturating_mul(1000)
            .checked_div(encoded_len.max(1) as u128)
            .unwrap_or(0);

        // Byte/count caps with fee-density eviction.
        while self.entries.len() >= self.cfg.max_count
            || self.total_bytes.saturating_add(encoded_len) > self.cfg.max_bytes
        {
            let lowest = match self.by_density.iter().next() {
                Some(k) => *k,
                None => return Err(AdmitError::PoolFull), // single tx over byte cap
            };
            if (density, u64::MAX, id) <= lowest {
                // Incoming cannot beat the lowest resident density.
                return Err(AdmitError::PoolFull);
            }
            self.remove(&lowest.2);
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let entry = PoolEntry {
            txid: id,
            tx,
            witnesses: wits,
            tx_bytes: tx_bytes.to_vec(),
            wit_bytes: wit_bytes.to_vec(),
            signature_authorizations,
            fee,
            density,
            payer,
            source,
            seq,
            usage,
        };
        self.total_bytes = self.total_bytes.saturating_add(entry.encoded_len());
        self.by_density.insert(entry.density_key());
        self.per_account.entry(payer).or_default().push_back(id);
        let source_count = self.per_source.entry(source).or_default();
        *source_count = source_count.saturating_add(1);
        self.entries.insert(id, entry);
        Ok(id)
    }

    /// Removes an entry from every index; returns it when present.
    pub fn remove(&mut self, txid: &Hash32) -> Option<PoolEntry> {
        let entry = self.entries.remove(txid)?;
        self.by_density.remove(&entry.density_key());
        self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_len());
        if let Some(queue) = self.per_account.get_mut(&entry.payer) {
            queue.retain(|t| t != txid);
            if queue.is_empty() {
                self.per_account.remove(&entry.payer);
            }
        }
        if let Some(count) = self.per_source.get_mut(&entry.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&entry.source);
            }
        }
        Some(entry)
    }

    /// Block-connected housekeeping: settled txids enter the seen cache;
    /// expired entries drop. Returns the txids dropped by expiry.
    pub fn on_block_connected(&mut self, settled: &[Hash32], next_height: u64) -> Vec<Hash32> {
        for id in settled {
            self.remove(id);
            self.seen.insert(*id);
        }
        let expired: Vec<Hash32> = self
            .entries
            .values()
            .filter(|e| e.tx.expiry_height < next_height)
            .map(|e| e.txid)
            .collect();
        for id in &expired {
            self.remove(id);
            self.seen.insert(*id);
        }
        expired
    }

    /// Deterministic block template under the body caps: rank by
    /// `(density desc, seq asc, txid asc)` with per-payer FIFO, fill under
    /// the count cap, byte budget, and the five-axis capacity vector.
    #[must_use]
    pub fn template(&self, capacity: &Usage) -> Vec<&PoolEntry> {
        let mut ranked: Vec<&PoolEntry> = self.entries.values().collect();
        ranked.sort_by(|a, b| {
            b.density
                .cmp(&a.density)
                .then_with(|| a.seq.cmp(&b.seq))
                .then_with(|| a.txid.cmp(&b.txid))
        });

        let mut selected: Vec<&PoolEntry> = Vec::new();
        let mut selected_set: BTreeSet<Hash32> = BTreeSet::new();
        let mut bytes: usize = 0;
        let mut used: Usage = [0; fees::DIMENSIONS];

        // Per-payer FIFO: a candidate is eligible only when every earlier
        // entry in its payer queue is already selected.
        let mut progressed = true;
        while progressed && selected.len() < self.cfg.template_max_txs {
            progressed = false;
            'cand: for entry in &ranked {
                if selected_set.contains(&entry.txid) || selected.len() >= self.cfg.template_max_txs
                {
                    continue;
                }
                if let Some(queue) = self.per_account.get(&entry.payer) {
                    for earlier in queue {
                        if earlier == &entry.txid {
                            break;
                        }
                        if !selected_set.contains(earlier) {
                            continue 'cand; // FIFO head not selected yet
                        }
                    }
                }
                let len = entry.encoded_len();
                if bytes.saturating_add(len) > self.cfg.template_byte_budget {
                    continue;
                }
                let mut next_used = used;
                let mut fits = true;
                for i in 0..fees::DIMENSIONS {
                    match next_used[i].checked_add(entry.usage[i]) {
                        Some(v) if v <= capacity[i] => next_used[i] = v,
                        _ => {
                            fits = false;
                            break;
                        }
                    }
                }
                if !fits {
                    continue;
                }
                used = next_used;
                bytes = bytes.saturating_add(len);
                selected_set.insert(entry.txid);
                selected.push(entry);
                progressed = true;
            }
        }
        selected
    }
}
