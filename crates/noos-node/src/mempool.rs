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

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

use noos_codec::NoosDecode;
use noos_lumen::engine::AuthVerifier;
use noos_lumen::fees::{self, Usage};
use noos_lumen::objects::{txid as compute_txid, ActionV1, TransactionV1, TransactionWitnessesV1};
use noos_lumen::state::{LumenLedger, NOOS_ASSET};
use noos_lumen::wwm::{carrier_len_valid, MAX_TX_WITNESS_BYTES};

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
            max_tx_bytes: MAX_TX_WITNESS_BYTES,
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

/// Borrowed transaction carriers plus their per-peer/per-IP source key.
pub type AdmissionEnvelope<'a> = (&'a [u8], &'a [u8], SourceId);

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
    encoded_len: usize,
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
        self.encoded_len
    }
    fn density_key(&self) -> (u128, u64, Hash32) {
        (self.density, self.seq, self.txid)
    }
}

struct PreparedAdmission {
    id: Hash32,
    tx: TransactionV1,
    witnesses: TransactionWitnessesV1,
    encoded_len: usize,
    source: SourceId,
    fee: u128,
    usage: Usage,
    payer: Hash32,
    stateful_checks: Result<Vec<(Hash32, Vec<u8>)>, AdmitError>,
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
    fn insert_many(&mut self, ids: &[Hash32]) {
        if self.cap == 0 || ids.is_empty() {
            return;
        }
        if ids.len() >= self.cap {
            self.order.clear();
            self.set.clear();
            let retained = &ids[ids.len().saturating_sub(self.cap)..];
            for id in retained {
                self.set.insert(*id);
                self.order.push_back(*id);
            }
            return;
        }
        for id in ids {
            self.insert(*id);
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
    /// Common density while the expensive eviction index can stay elided.
    /// `None` with resident entries means `by_density` is materialized.
    uniform_density: Option<u128>,
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
            uniform_density: None,
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

    fn materialize_density_index(&mut self) {
        if self.uniform_density.take().is_some() {
            self.by_density
                .extend(self.entries.values().map(PoolEntry::density_key));
        }
    }

    fn index_density(&mut self, entry: &PoolEntry) {
        match self.uniform_density {
            Some(density) if density == entry.density => {}
            Some(_) => {
                self.materialize_density_index();
                self.by_density.insert(entry.density_key());
            }
            None if self.entries.is_empty() && self.by_density.is_empty() => {
                self.uniform_density = Some(entry.density);
            }
            None => {
                self.by_density.insert(entry.density_key());
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_admission(
        &self,
        tx_bytes: &[u8],
        wit_bytes: &[u8],
        source: SourceId,
        next_height: u64,
        chain_id: &Hash32,
        prices: &fees::Prices,
        ledger: &LumenLedger,
    ) -> Result<PreparedAdmission, AdmitError> {
        // Stages 1-4 are independent of pool mutation and safe to prepare in
        // parallel. Their errors still return before duplicate checks.
        let encoded_len = tx_bytes
            .len()
            .checked_add(wit_bytes.len())
            .ok_or(AdmitError::Oversized)?;
        if !carrier_len_valid(tx_bytes.len(), wit_bytes.len())
            || encoded_len > self.cfg.max_tx_bytes
        {
            return Err(AdmitError::Oversized);
        }
        let tx = TransactionV1::decode_canonical(tx_bytes).map_err(|_| AdmitError::Malformed)?;
        let wits = TransactionWitnessesV1::decode_canonical(wit_bytes)
            .map_err(|_| AdmitError::Malformed)?;
        for raw in tx.actions.iter() {
            ActionV1::decode_canonical(raw.as_slice()).map_err(|_| AdmitError::Malformed)?;
        }
        let id = compute_txid(&tx);
        if &tx.chain_id != chain_id {
            return Err(AdmitError::WrongChain);
        }
        if tx.format_version != 1 {
            return Err(AdmitError::WrongVersion);
        }
        if tx.expiry_height < next_height {
            return Err(AdmitError::Expired);
        }
        if u64::try_from(encoded_len).map_or(true, |length| length > tx.resource_limits.bytes) {
            return Err(AdmitError::Oversized);
        }
        let usage = fees::usage_from_resources(&tx.resource_limits);
        let fee = fees::fee(prices, &usage).ok_or(AdmitError::FeeOverflow)?;
        if fee < self.cfg.min_fee_micro {
            return Err(AdmitError::FeeBelowFloor {
                fee,
                floor: self.cfg.min_fee_micro,
            });
        }

        // Stage 6 is also immutable-ledger work. Its result is deliberately
        // deferred so stage-5 duplicates retain precedence in input order.
        let payer = tx.fee_payer;
        let stateful_checks = (|| {
            let payer_account = ledger.get_account(&payer).ok_or(AdmitError::UnknownPayer)?;
            if !tx.account_inputs.iter().any(|account| account == &payer) {
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
            let mut authorizations = Vec::with_capacity(tx.account_inputs.len());
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
                authorizations.push((*account_id, account.auth_descriptor.as_slice().to_vec()));
            }
            Ok(authorizations)
        })();
        Ok(PreparedAdmission {
            id,
            tx,
            witnesses: wits,
            source,
            encoded_len,
            fee,
            usage,
            payer,
            stateful_checks,
        })
    }

    fn admit_prepared(
        &mut self,
        prepared: PreparedAdmission,
        ledger: &LumenLedger,
    ) -> Result<Hash32, AdmitError> {
        let PreparedAdmission {
            id,
            tx,
            witnesses,
            source,
            encoded_len,
            fee,
            usage,
            payer,
            stateful_checks,
        } = prepared;

        // Stage 5 remains sequential: earlier inputs in this batch become
        // visible pending duplicates to every later input.
        if self.entries.contains_key(&id) {
            return Err(AdmitError::DuplicatePending);
        }
        if self.seen.contains(&id) || ledger.get_receipt(&id).is_some() {
            return Err(AdmitError::DuplicateSettled);
        }
        let signature_authorizations = stateful_checks?;

        // Stage 7 is canonical input-order mutation of all bounded indices.
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
        if self.entries.len() >= self.cfg.max_count
            || self.total_bytes.saturating_add(encoded_len) > self.cfg.max_bytes
        {
            self.materialize_density_index();
        }
        while self.entries.len() >= self.cfg.max_count
            || self.total_bytes.saturating_add(encoded_len) > self.cfg.max_bytes
        {
            let lowest = match self.by_density.iter().next() {
                Some(key) => *key,
                None => return Err(AdmitError::PoolFull),
            };
            if (density, u64::MAX, id) <= lowest {
                return Err(AdmitError::PoolFull);
            }
            self.remove(&lowest.2);
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let entry = PoolEntry {
            txid: id,
            tx,
            witnesses,
            encoded_len,
            signature_authorizations,
            fee,
            density,
            payer,
            source,
            seq,
            usage,
        };
        self.total_bytes = self.total_bytes.saturating_add(entry.encoded_len());
        self.index_density(&entry);
        self.per_account.entry(payer).or_default().push_back(id);
        let source_count = self.per_source.entry(source).or_default();
        *source_count = source_count.saturating_add(1);
        self.entries.insert(id, entry);
        Ok(id)
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
        let prepared = self.prepare_admission(
            tx_bytes,
            wit_bytes,
            source,
            next_height,
            chain_id,
            prices,
            ledger,
        )?;
        self.admit_prepared(prepared, ledger)
    }

    /// Prepares immutable decoding, fee, state, and signature work in
    /// parallel, then applies duplicate and capacity mutations in exact input
    /// order. Results align one-for-one with `submissions`.
    #[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects)]
    pub fn admit_batch(
        &mut self,
        submissions: &[AdmissionEnvelope<'_>],
        next_height: u64,
        chain_id: &Hash32,
        prices: &fees::Prices,
        ledger: &LumenLedger,
    ) -> Vec<Result<Hash32, AdmitError>> {
        if submissions.is_empty() {
            return Vec::new();
        }
        let mut prepared = std::iter::repeat_with(|| None)
            .take(submissions.len())
            .collect::<Vec<Option<Result<PreparedAdmission, AdmitError>>>>();
        let workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(submissions.len());
        let chunk_size = submissions.len().div_ceil(workers);
        {
            let pool = &*self;
            std::thread::scope(|scope| {
                for (chunk_index, output) in prepared.chunks_mut(chunk_size).enumerate() {
                    let start = chunk_index * chunk_size;
                    scope.spawn(move || {
                        for (offset, slot) in output.iter_mut().enumerate() {
                            let (tx_bytes, wit_bytes, source) = submissions[start + offset];
                            *slot = Some(pool.prepare_admission(
                                tx_bytes,
                                wit_bytes,
                                source,
                                next_height,
                                chain_id,
                                prices,
                                ledger,
                            ));
                        }
                    });
                }
            });
        }

        let mut results = Vec::with_capacity(prepared.len());
        for candidate in prepared {
            let result = match candidate {
                Some(Ok(candidate)) => self.admit_prepared(candidate, ledger),
                Some(Err(error)) => Err(error),
                None => Err(AdmitError::Malformed),
            };
            results.push(result);
        }
        results
    }

    /// Removes an entry from every index; returns it when present.
    pub fn remove(&mut self, txid: &Hash32) -> Option<PoolEntry> {
        let entry = self.entries.remove(txid)?;
        if self.uniform_density.is_none() {
            self.by_density.remove(&entry.density_key());
        }
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
        if self.entries.is_empty() {
            self.uniform_density = None;
        }
        Some(entry)
    }

    fn remove_many(&mut self, txids: &[Hash32]) -> Vec<PoolEntry> {
        let mut removed = Vec::with_capacity(txids.len());
        let mut affected_payers = BTreeSet::new();
        for txid in txids {
            let Some(entry) = self.entries.remove(txid) else {
                continue;
            };
            if self.uniform_density.is_none() {
                self.by_density.remove(&entry.density_key());
            }
            self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_len());
            affected_payers.insert(entry.payer);
            if let Some(count) = self.per_source.get_mut(&entry.source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.per_source.remove(&entry.source);
                }
            }
            removed.push(entry);
        }
        for payer in affected_payers {
            let empty = if let Some(queue) = self.per_account.get_mut(&payer) {
                queue.retain(|txid| self.entries.contains_key(txid));
                queue.is_empty()
            } else {
                false
            };
            if empty {
                self.per_account.remove(&payer);
            }
        }
        if self.entries.is_empty() {
            self.uniform_density = None;
        }
        removed
    }

    /// Block-connected housekeeping: settled txids enter the seen cache;
    /// expired entries drop. Returns the txids dropped by expiry.
    pub fn on_block_connected(&mut self, settled: &[Hash32], next_height: u64) -> Vec<Hash32> {
        if !self.entries.is_empty() {
            self.remove_many(settled);
        }
        self.seen.insert_many(settled);
        let expired: Vec<Hash32> = self
            .entries
            .values()
            .filter(|entry| entry.tx.expiry_height < next_height)
            .map(|entry| entry.txid)
            .collect();
        self.remove_many(&expired);
        self.seen.insert_many(&expired);
        expired
    }

    fn full_linear_template_fits(&self, capacity: &Usage) -> bool {
        let one_density = self.uniform_density.is_some()
            || self
                .by_density
                .first()
                .zip(self.by_density.last())
                .is_some_and(|(first, last)| first.0 == last.0);
        if !one_density
            || self.entries.len() > self.cfg.template_max_txs
            || self.total_bytes > self.cfg.template_byte_budget
        {
            return false;
        }
        let mut used: Usage = [0; fees::DIMENSIONS];
        self.entries.values().all(|entry| {
            for dimension in 0..fees::DIMENSIONS {
                let Some(next) = used[dimension].checked_add(entry.usage[dimension]) else {
                    return false;
                };
                if next > capacity[dimension] {
                    return false;
                }
                used[dimension] = next;
            }
            true
        })
    }

    /// Deterministic block template under the body caps: rank by
    /// `(density desc, seq asc, txid asc)` with per-payer FIFO, fill under
    /// the count cap, byte budget, and the five-axis capacity vector.
    #[must_use]
    pub fn template(&self, capacity: &Usage) -> Vec<&PoolEntry> {
        // When every resident has one density and the entire pool fits, the
        // heap order collapses to arrival order. Every payer FIFO is itself
        // arrival-ordered, so the globally earliest remaining sequence is
        // always eligible. Iterating the density index is therefore
        // byte-identical to the general heap merge, but linear.
        if self.full_linear_template_fits(capacity) {
            if self.uniform_density.is_some() {
                let mut selected = self.entries.values().collect::<Vec<_>>();
                selected.sort_unstable_by_key(|entry| (entry.seq, entry.txid));
                return selected;
            }
            return self
                .by_density
                .iter()
                .filter_map(|(_, _, txid)| self.entries.get(txid))
                .collect();
        }
        // Only each payer's FIFO head is eligible. Keeping those heads in a
        // heap avoids repeatedly scanning and sorting the entire pool as
        // successive transactions from one payer become eligible.
        let mut eligible: BinaryHeap<(u128, Reverse<u64>, Reverse<Hash32>, Hash32, usize)> =
            BinaryHeap::with_capacity(self.per_account.len());
        for (payer, queue) in &self.per_account {
            if let Some(txid) = queue.front() {
                if let Some(entry) = self.entries.get(txid) {
                    eligible.push((
                        entry.density,
                        Reverse(entry.seq),
                        Reverse(entry.txid),
                        *payer,
                        0,
                    ));
                }
            }
        }

        let max_txs = self.cfg.template_max_txs.min(self.entries.len());
        let mut selected: Vec<&PoolEntry> = Vec::with_capacity(max_txs);
        let mut bytes: usize = 0;
        let mut used: Usage = [0; fees::DIMENSIONS];

        while selected.len() < max_txs {
            let Some((_, _, Reverse(txid), payer, queue_index)) = eligible.pop() else {
                break;
            };
            let Some(entry) = self.entries.get(&txid) else {
                debug_assert!(false, "payer queue references a missing mempool entry");
                continue;
            };

            let len = entry.encoded_len();
            if bytes.saturating_add(len) > self.cfg.template_byte_budget {
                // Later entries from this payer are not eligible without its
                // head, so this payer is exhausted for the template.
                continue;
            }

            let mut next_used = used;
            let mut fits = true;
            for i in 0..fees::DIMENSIONS {
                match next_used[i].checked_add(entry.usage[i]) {
                    Some(value) if value <= capacity[i] => next_used[i] = value,
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
            bytes += len;
            selected.push(entry);

            let next_index = queue_index + 1;
            if let Some(next_txid) = self
                .per_account
                .get(&payer)
                .and_then(|queue| queue.get(next_index))
            {
                if let Some(next) = self.entries.get(next_txid) {
                    eligible.push((
                        next.density,
                        Reverse(next.seq),
                        Reverse(next.txid),
                        payer,
                        next_index,
                    ));
                } else {
                    debug_assert!(false, "payer queue references a missing mempool entry");
                }
            }
        }

        selected
    }

    /// Selects the deterministic template and moves its entries out of the
    /// pool in canonical execution order. This avoids duplicating every large
    /// transaction and witness object during block assembly.
    pub fn take_template(&mut self, capacity: &Usage) -> Vec<PoolEntry> {
        if self.full_linear_template_fits(capacity) {
            let entries = std::mem::take(&mut self.entries);
            let mut selected = entries.into_values().collect::<Vec<_>>();
            let minimum_sequence = selected.iter().map(|entry| entry.seq).min();
            let maximum_sequence = selected.iter().map(|entry| entry.seq).max();
            let dense_range = minimum_sequence
                .zip(maximum_sequence)
                .and_then(|(minimum, maximum)| maximum.checked_sub(minimum))
                .and_then(|distance| distance.checked_add(1))
                .and_then(|range| usize::try_from(range).ok())
                .filter(|range| *range <= selected.len().saturating_mul(2));
            if let (Some(minimum), Some(range)) = (minimum_sequence, dense_range) {
                let mut ordered = std::iter::repeat_with(|| None)
                    .take(range)
                    .collect::<Vec<Option<PoolEntry>>>();
                for entry in selected {
                    let index = usize::try_from(entry.seq.saturating_sub(minimum))
                        .expect("dense sequence range");
                    ordered[index] = Some(entry);
                }
                selected = ordered.into_iter().flatten().collect();
            } else {
                selected.sort_unstable_by_key(|entry| (entry.seq, entry.txid));
            }
            self.uniform_density = None;
            self.by_density.clear();
            self.per_account.clear();
            self.per_source.clear();
            self.total_bytes = 0;
            return selected;
        }
        let txids: Vec<Hash32> = self
            .template(capacity)
            .into_iter()
            .map(|entry| entry.txid)
            .collect();
        self.remove_many(&txids)
    }
}
