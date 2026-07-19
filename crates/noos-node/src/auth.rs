//! Authorization and execution boundaries the node plugs into Lumen
//! (node-v1.md §4.2).
//!
//! * [`NodeAuthVerifier`] — the deterministic v1 signature law:
//!   `signature_suite = 1` is Ed25519 under the registered `D-SIG-TX`
//!   domain over the 32-byte txid; the account's `auth_descriptor` is the
//!   raw 32-byte Ed25519 public key. Unknown suites, wrong descriptor
//!   widths, and bad signatures all verify FALSE (Lumen turns that into a
//!   typed rejection). Note lock reveals fail closed: the wallet lock-tree
//!   domain row is a wallet-phase freeze (crypto-domains-v1.csv), so v1
//!   consensus cannot verify one and MUST NOT accept one.
//! * [`GrainContractEngine`] — production contract execution through the
//!   deterministic Grain v1 interpreter and ordinary-contract host. Code is
//!   resolved from an immutable registry, inputs and prior state are decoded
//!   into the explicit contract subject, and stable Grain/host traps are
//!   returned without ambient state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use noos_codec::{NoosEncode, Writer};
use noos_contracts::{
    domain_hash, Access, ContractContext, ContractError, ContractHost, ContractManifest,
    ContractRecord, ReentrancyPolicy, UpgradePolicy, STATE_ROOT_DOMAIN,
};
use noos_crypto::{
    prepare_public_key, verify_domain, verify_domain_batch_prepared, DomainId, PreparedPublicKey,
    PublicKey, Signature,
};
use noos_grain::{decode_formula, decode_subject, encode_noun, Noun, ARENA_MAX_WORDS_PER_TX};
use noos_lumen::engine::{AuthVerifier, ContractEngine, EngineOutcome, EngineTrap};
use noos_lumen::objects::{TransactionV1, TransactionWitnessesV1};
use noos_lumen::state::{DeferredBalanceRoots, LumenLedger};
use noos_lumen::{domain_hash as lumen_domain_hash, domains as lumen_domains, Hash32};

/// Signature suite id 1: Ed25519 over `D-SIG-TX` (node-v1.md §4.2).
pub const SUITE_ED25519: u16 = 1;

/// Stable host trap codes outside the frozen Grain `1..=12` range.
pub const TRAP_UNKNOWN_CONTRACT_CODE: u32 = 0x4E0D_E001;
pub const TRAP_CONTRACT_HOST: u32 = 0x4E0D_E002;

/// Deterministic v1 verifier over noos-crypto Ed25519.
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeAuthVerifier;

impl AuthVerifier for NodeAuthVerifier {
    fn verify_signature(
        &self,
        suite: u16,
        auth_descriptor: &[u8],
        message: &Hash32,
        signature: &[u8],
    ) -> bool {
        if suite != SUITE_ED25519 {
            return false;
        }
        let Ok(key_bytes) = <[u8; 32]>::try_from(auth_descriptor) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let key = PublicKey::from_bytes(key_bytes);
        let sig = Signature::from_bytes(sig_bytes);
        verify_domain(DomainId::SigTx, &key, &[message], &sig).is_ok()
    }

    fn verify_lock_reveal(&self, _lock_root: &Hash32, _reveal: &[u8]) -> bool {
        // Wallet lock-tree domain is a wallet-phase freeze: fail closed.
        false
    }

    fn verify_evidence_ref(&self, _evidence_ref: &Hash32) -> bool {
        // Evidence lane unfrozen: fail closed.
        false
    }
}

/// Execution verifier used only after admission or validator preprocessing
/// has verified every signature against the same unchanged account
/// authorization descriptors. Non-signature authorization remains
/// fail-closed exactly as in [`NodeAuthVerifier`].
#[derive(Debug, Default, Clone, Copy)]
pub struct PreverifiedSignatureAuth {
    transaction_id: Option<Hash32>,
}

impl PreverifiedSignatureAuth {
    #[must_use]
    pub const fn new(transaction_id: Hash32) -> Self {
        Self {
            transaction_id: Some(transaction_id),
        }
    }
}

impl AuthVerifier for PreverifiedSignatureAuth {
    fn verify_signature(
        &self,
        _suite: u16,
        _auth_descriptor: &[u8],
        _message: &Hash32,
        _signature: &[u8],
    ) -> bool {
        true
    }

    fn precomputed_transaction_id(
        &self,
        _transaction: &noos_lumen::objects::TransactionV1,
    ) -> Option<Hash32> {
        self.transaction_id
    }

    fn verify_lock_reveal(&self, lock_root: &Hash32, reveal: &[u8]) -> bool {
        NodeAuthVerifier.verify_lock_reveal(lock_root, reveal)
    }

    fn verify_evidence_ref(&self, evidence_ref: &Hash32) -> bool {
        NodeAuthVerifier.verify_evidence_ref(evidence_ref)
    }

    fn verify_witness_extras(
        &self,
        witnesses: &noos_lumen::objects::TransactionWitnessesV1,
    ) -> bool {
        NodeAuthVerifier.verify_witness_extras(witnesses)
    }
}

const PARALLEL_SIGNATURE_MIN_TRANSACTIONS: usize = 32;
const PRECHECK_PIPELINE_CHUNK_TRANSACTIONS: usize = 32_768;

/// Immutable account-authorization view captured before ordered block
/// execution. Transactions that create or rotate an account authorization
/// after capture automatically fall back to canonical sequential verification.
#[derive(Debug, Clone)]
struct CapturedAuthorization {
    descriptor: Option<Vec<u8>>,
    prepared_key: Option<PreparedPublicKey>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationSnapshot {
    descriptors: BTreeMap<Hash32, CapturedAuthorization>,
}

impl AuthorizationSnapshot {
    fn descriptor(&self, account_id: &Hash32) -> Option<&[u8]> {
        self.descriptors
            .get(account_id)
            .and_then(|authorization| authorization.descriptor.as_deref())
    }

    fn prepared_key(&self, account_id: &Hash32) -> Option<&PreparedPublicKey> {
        self.descriptors
            .get(account_id)
            .and_then(|authorization| authorization.prepared_key.as_ref())
    }

    fn matches_transaction(
        &self,
        ledger: &LumenLedger,
        deferred: &DeferredBalanceRoots,
        transaction: &TransactionV1,
    ) -> bool {
        transaction.account_inputs.iter().all(|account_id| {
            let Some(expected) = self.descriptor(account_id) else {
                return false;
            };
            ledger.deferred_auth_descriptor_matches(deferred, account_id, expected)
        })
    }
}

/// Capture each declared account authorization descriptor once. Missing
/// accounts remain explicitly absent so transactions depending on an account
/// created earlier in the same block cannot reuse a stale precheck.
#[must_use]
pub fn capture_authorization_snapshot(
    ledger: &LumenLedger,
    transactions: &[TransactionV1],
) -> AuthorizationSnapshot {
    let mut descriptors = BTreeMap::new();
    for transaction in transactions {
        for account_id in transaction.account_inputs.iter() {
            descriptors.entry(*account_id).or_insert_with(|| {
                let descriptor = ledger
                    .get_account(account_id)
                    .map(|account| account.auth_descriptor.as_slice().to_vec());
                let prepared_key = descriptor
                    .as_deref()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .and_then(|bytes| prepare_public_key(&PublicKey::from_bytes(bytes)).ok());
                CapturedAuthorization {
                    descriptor,
                    prepared_key,
                }
            });
        }
    }
    AuthorizationSnapshot { descriptors }
}

/// Immutable result of bounded parallel transaction preprocessing.
///
/// The transaction id and exact canonical carrier lengths are computed in the
/// same worker that performs production signature verification. Execution may
/// reuse the signature result only through [`Self::signatures_reusable`].
#[derive(Debug, Clone)]
pub struct TransactionPrecheck {
    transaction_id: Hash32,
    transaction_len: usize,
    witness_len: usize,
    signatures_valid: bool,
}

impl TransactionPrecheck {
    #[must_use]
    pub const fn transaction_id(&self) -> Hash32 {
        self.transaction_id
    }

    #[must_use]
    pub const fn encoded_lengths(&self) -> (usize, usize) {
        (self.transaction_len, self.witness_len)
    }

    /// A prechecked signature is reusable only when it was valid at capture
    /// and every referenced account still has the exact captured descriptor.
    #[must_use]
    pub fn signatures_reusable(
        &self,
        snapshot: &AuthorizationSnapshot,
        ledger: &LumenLedger,
        deferred: &DeferredBalanceRoots,
        transaction: &TransactionV1,
    ) -> bool {
        self.signatures_valid && snapshot.matches_transaction(ledger, deferred, transaction)
    }
}

fn precheck_metadata(
    transaction: &TransactionV1,
    witnesses: &TransactionWitnessesV1,
    transaction_writer: &mut Writer,
    witness_writer: &mut Writer,
) -> (Hash32, usize, usize) {
    transaction_writer.clear();
    transaction.encode(transaction_writer);
    let transaction_id = lumen_domain_hash(lumen_domains::TX_ID, &[transaction_writer.as_bytes()]);
    let transaction_len = transaction_writer.len();
    witness_writer.clear();
    witnesses.encode(witness_writer);
    (transaction_id, transaction_len, witness_writer.len())
}

fn precheck_transaction(
    snapshot: &AuthorizationSnapshot,
    transaction: &TransactionV1,
    witnesses: &TransactionWitnessesV1,
    transaction_writer: &mut Writer,
    witness_writer: &mut Writer,
) -> TransactionPrecheck {
    let (transaction_id, transaction_len, witness_len) =
        precheck_metadata(transaction, witnesses, transaction_writer, witness_writer);
    let signatures_valid = transaction.account_inputs.len() == witnesses.intents.len()
        && transaction
            .account_inputs
            .iter()
            .zip(witnesses.intents.iter())
            .all(|(account_id, intent)| {
                let Some(descriptor) = snapshot.descriptor(account_id) else {
                    return false;
                };
                intent.tx_commitment == transaction_id
                    && NodeAuthVerifier.verify_signature(
                        intent.signature_suite,
                        descriptor,
                        &transaction_id,
                        intent.signature.as_slice(),
                    )
            });
    TransactionPrecheck {
        transaction_id,
        transaction_len,
        witness_len,
        signatures_valid,
    }
}

fn mark_valid_signature_batch(
    public_keys: &[PreparedPublicKey],
    transaction_ids: &[Hash32],
    signatures: &[Signature],
    valid: &mut [bool],
) {
    if public_keys.is_empty() {
        return;
    }
    let parts = transaction_ids
        .iter()
        .map(<[u8; 32]>::as_slice)
        .collect::<Vec<_>>();
    if verify_domain_batch_prepared(DomainId::SigTx, public_keys, &parts, signatures).is_ok() {
        valid.fill(true);
        return;
    }
    if public_keys.len() == 1 {
        return;
    }
    let midpoint = public_keys.len() / 2;
    let (left_valid, right_valid) = valid.split_at_mut(midpoint);
    mark_valid_signature_batch(
        &public_keys[..midpoint],
        &transaction_ids[..midpoint],
        &signatures[..midpoint],
        left_valid,
    );
    mark_valid_signature_batch(
        &public_keys[midpoint..],
        &transaction_ids[midpoint..],
        &signatures[midpoint..],
        right_valid,
    );
}

/// Batch the overwhelmingly common one-account Ed25519 shape. Invalid or
/// mixed shapes retain the exact individual verifier result; a failed batch
/// is bisected deterministically until each bad signature is isolated.
fn precheck_transaction_batch(
    snapshot: &AuthorizationSnapshot,
    transactions: &[TransactionV1],
    witnesses: &[TransactionWitnessesV1],
) -> Vec<TransactionPrecheck> {
    debug_assert_eq!(transactions.len(), witnesses.len());
    let mut checks = Vec::with_capacity(transactions.len());
    let mut candidate_positions = Vec::new();
    let mut public_keys = Vec::new();
    let mut transaction_ids = Vec::new();
    let mut signatures = Vec::new();
    let mut transaction_writer = Writer::with_capacity(512);
    let mut witness_writer = Writer::with_capacity(128);

    for (transaction, transaction_witnesses) in transactions.iter().zip(witnesses) {
        if transaction.account_inputs.len() != 1 || transaction_witnesses.intents.len() != 1 {
            checks.push(precheck_transaction(
                snapshot,
                transaction,
                transaction_witnesses,
                &mut transaction_writer,
                &mut witness_writer,
            ));
            continue;
        }
        let (transaction_id, transaction_len, witness_len) = precheck_metadata(
            transaction,
            transaction_witnesses,
            &mut transaction_writer,
            &mut witness_writer,
        );
        let mut check = TransactionPrecheck {
            transaction_id,
            transaction_len,
            witness_len,
            signatures_valid: false,
        };
        let account_id = transaction.account_inputs.as_slice()[0];
        let intent = &transaction_witnesses.intents.as_slice()[0];
        let Some(public_key) = snapshot.prepared_key(&account_id) else {
            checks.push(check);
            continue;
        };
        let Ok(signature_bytes) = <[u8; 64]>::try_from(intent.signature.as_slice()) else {
            checks.push(check);
            continue;
        };
        if intent.signature_suite != SUITE_ED25519 || intent.tx_commitment != transaction_id {
            checks.push(check);
            continue;
        }
        candidate_positions.push(checks.len());
        public_keys.push(public_key.clone());
        transaction_ids.push(transaction_id);
        signatures.push(Signature::from_bytes(signature_bytes));
        check.signatures_valid = false;
        checks.push(check);
    }

    let mut valid = vec![false; candidate_positions.len()];
    mark_valid_signature_batch(&public_keys, &transaction_ids, &signatures, &mut valid);
    for (position, signatures_valid) in candidate_positions.into_iter().zip(valid) {
        checks[position].signatures_valid = signatures_valid;
    }
    checks
}

/// Verify independent transaction signatures and calculate immutable envelope
/// metadata across a bounded number of scoped workers. Result order always
/// matches transaction order; small batches return `None` entries so the
/// canonical sequential verifier remains the single small-batch path.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn parallel_transaction_prechecks(
    snapshot: &AuthorizationSnapshot,
    transactions: &[TransactionV1],
    witnesses: &[TransactionWitnessesV1],
) -> Vec<Option<TransactionPrecheck>> {
    let transaction_count = transactions.len();
    let mut checks = vec![None; transaction_count];
    if transaction_count < PARALLEL_SIGNATURE_MIN_TRANSACTIONS
        || witnesses.len() != transaction_count
    {
        return checks;
    }
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(transaction_count);
    let chunk_size = transaction_count.div_ceil(workers);
    std::thread::scope(|scope| {
        for (chunk_index, check_chunk) in checks.chunks_mut(chunk_size).enumerate() {
            let start = chunk_index * chunk_size;
            scope.spawn(move || {
                let local = precheck_transaction_batch(
                    snapshot,
                    &transactions[start..start + check_chunk.len()],
                    &witnesses[start..start + check_chunk.len()],
                );
                for (check, value) in check_chunk.iter_mut().zip(local) {
                    *check = Some(value);
                }
            });
        }
    });
    checks
}

/// Precheck one bounded chunk ahead of ordered execution. A fixed scoped
/// worker set lives for the whole batch, and a bounded channel prevents it
/// from running more than two chunks ahead. Parts may complete out of order;
/// only fully assembled chunks reach `consume`, strictly in canonical order.
#[allow(clippy::arithmetic_side_effects)]
pub fn pipelined_transaction_prechecks<E>(
    snapshot: &AuthorizationSnapshot,
    transactions: &[TransactionV1],
    witnesses: &[TransactionWitnessesV1],
    mut consume: impl FnMut(usize, &[Option<TransactionPrecheck>]) -> Result<(), E>,
) -> Result<(), E> {
    if transactions.is_empty() {
        return Ok(());
    }
    if transactions.len() != witnesses.len()
        || transactions.len() < PARALLEL_SIGNATURE_MIN_TRANSACTIONS
    {
        let checks = vec![None; transactions.len()];
        return consume(0, &checks);
    }
    let available = std::thread::available_parallelism().map_or(1, usize::from);
    // Leave capacity for canonical execution plus the concurrently verified
    // body commitments. Oversubscribing curve workers makes both paths slower
    // on production SMT hosts.
    let workers = available.saturating_sub(6).max(1).min(transactions.len());
    let chunk_count = transactions
        .len()
        .div_ceil(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS);
    std::thread::scope(|scope| {
        let channel_capacity = workers.saturating_mul(2).max(1);
        let (sender, receiver) = std::sync::mpsc::sync_channel(channel_capacity);
        for worker_id in 0..workers {
            let sender = sender.clone();
            scope.spawn(move || {
                for chunk_index in 0..chunk_count {
                    let chunk_start =
                        chunk_index.saturating_mul(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS);
                    let chunk_end = chunk_start
                        .saturating_add(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS)
                        .min(transactions.len());
                    let chunk_len = chunk_end.saturating_sub(chunk_start);
                    let active_workers = workers.min(chunk_len);
                    if worker_id >= active_workers {
                        continue;
                    }
                    let local_start = chunk_len
                        .saturating_mul(worker_id)
                        .checked_div(active_workers)
                        .unwrap_or(0);
                    let local_end = chunk_len
                        .saturating_mul(worker_id.saturating_add(1))
                        .checked_div(active_workers)
                        .unwrap_or(chunk_len);
                    let checks = precheck_transaction_batch(
                        snapshot,
                        &transactions[chunk_start + local_start..chunk_start + local_end],
                        &witnesses[chunk_start + local_start..chunk_start + local_end],
                    );
                    if sender.send((chunk_index, local_start, checks)).is_err() {
                        return;
                    }
                }
            });
        }
        drop(sender);

        let mut pending = BTreeMap::<usize, (Vec<Option<TransactionPrecheck>>, usize)>::new();
        let mut next_chunk = 0_usize;
        while next_chunk < chunk_count {
            let Ok((chunk_index, local_start, checks)) = receiver.recv() else {
                break;
            };
            let chunk_start = chunk_index.saturating_mul(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS);
            let chunk_end = chunk_start
                .saturating_add(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS)
                .min(transactions.len());
            let chunk_len = chunk_end.saturating_sub(chunk_start);
            let entry = pending
                .entry(chunk_index)
                .or_insert_with(|| (vec![None; chunk_len], 0));
            for (offset, check) in checks.into_iter().enumerate() {
                let index = local_start.saturating_add(offset);
                entry.0[index] = Some(check);
            }
            entry.1 = entry.1.saturating_add(1);

            loop {
                let next_start = next_chunk.saturating_mul(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS);
                let next_end = next_start
                    .saturating_add(PRECHECK_PIPELINE_CHUNK_TRANSACTIONS)
                    .min(transactions.len());
                let next_len = next_end.saturating_sub(next_start);
                let expected_parts = workers.min(next_len);
                let ready = pending
                    .get(&next_chunk)
                    .is_some_and(|(_, parts)| *parts == expected_parts);
                if !ready {
                    break;
                }
                let Some((checks, _)) = pending.remove(&next_chunk) else {
                    break;
                };
                consume(next_start, &checks)?;
                next_chunk = next_chunk.saturating_add(1);
            }
        }
        Ok(())
    })
}

/// Immutable production adapter from Lumen's pure execution seam to Grain.
///
/// The registry is deliberately part of the engine value rather than a
/// mutable global. Consequently execution remains a pure function of the
/// engine configuration and Lumen's execution tuple, including during
/// mempool simulation and deterministic replay.
#[derive(Debug, Default, Clone)]
pub struct GrainContractEngine {
    chain_id: Hash32,
    genesis_hash: Hash32,
    code: Arc<BTreeMap<Hash32, Vec<u8>>>,
}

impl GrainContractEngine {
    #[must_use]
    pub fn new(chain_id: Hash32, genesis_hash: Hash32, code: BTreeMap<Hash32, Vec<u8>>) -> Self {
        Self {
            chain_id,
            genesis_hash,
            code: Arc::new(code),
        }
    }

    #[must_use]
    pub fn code_hashes(&self) -> BTreeSet<Hash32> {
        self.code.keys().copied().collect()
    }
}

fn host_trap(error: ContractError) -> EngineTrap {
    let code = match error {
        ContractError::Grain(trap) => u32::from(trap.code()),
        ContractError::UnknownContract => TRAP_UNKNOWN_CONTRACT_CODE,
        _ => TRAP_CONTRACT_HOST,
    };
    EngineTrap { code }
}

impl ContractEngine for GrainContractEngine {
    fn execute(
        &self,
        code_hash: &Hash32,
        object_id: &Hash32,
        prior_state_root: &Hash32,
        input: &[u8],
        step_limit: u64,
    ) -> Result<EngineOutcome, EngineTrap> {
        let formula_bytes = self.code.get(code_hash).ok_or(EngineTrap {
            code: TRAP_UNKNOWN_CONTRACT_CODE,
        })?;
        let formula = decode_formula(formula_bytes).map_err(|trap| EngineTrap {
            code: u32::from(trap.code()),
        })?;
        let args = decode_subject(input).map_err(|trap| EngineTrap {
            code: u32::from(trap.code()),
        })?;

        let manifest = ContractManifest {
            code_hash: *code_hash,
            abi_root: [0; 32],
            storage_schema_root: *prior_state_root,
            max_resource_vector: [step_limit, 0, 0, 0, 0, 0],
            upgrade_policy: UpgradePolicy::Immutable,
            reentrancy_policy: ReentrancyPolicy::Disabled,
            allowed_call_classes: 0,
            compiler_id: [0; 32],
        };
        let mut host = ContractHost::new([(*object_id, Access::ReadWrite)]);
        host.install(
            *object_id,
            ContractRecord {
                manifest,
                state: Noun::atom_from_le_bytes(prior_state_root),
                storage: BTreeMap::new(),
                class: 0,
            },
        );
        let context = ContractContext {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            txid: domain_hash(b"NOOS/CONTRACT/INPUT/V1", &[input]),
            caller: [0; 32],
            callee: *object_id,
            block_height: 0,
            finalized_prestate_root: *prior_state_root,
            call_depth: 0,
        };
        let (value, grain_steps) = host
            .execute_grain(
                *object_id,
                &context,
                &formula,
                args,
                step_limit,
                step_limit.min(ARENA_MAX_WORDS_PER_TX),
            )
            .map_err(host_trap)?;
        let encoded = encode_noun(&value);
        let storage_words = u64::try_from(encoded.len()).unwrap_or(u64::MAX).div_ceil(8);
        Ok(EngineOutcome {
            new_state_root: domain_hash(STATE_ROOT_DOMAIN, &[&encoded]),
            grain_steps,
            storage_words,
        })
    }
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct DeferredEngine;

#[cfg(test)]
impl ContractEngine for DeferredEngine {
    fn execute(
        &self,
        _code_hash: &Hash32,
        _object_id: &Hash32,
        _prior_state_root: &Hash32,
        _input: &[u8],
        _step_limit: u64,
    ) -> Result<EngineOutcome, EngineTrap> {
        Err(EngineTrap {
            code: TRAP_UNKNOWN_CONTRACT_CODE,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use noos_grain::GrainTrap;

    #[test]
    fn grain_engine_executes_registered_code_deterministically() {
        let formula = Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1))
            .unwrap_or_else(|_| unreachable!("small noun"));
        let code_hash = [7; 32];
        let engine = GrainContractEngine::new(
            [1; 32],
            [2; 32],
            [(code_hash, encode_noun(&formula))].into_iter().collect(),
        );
        let input = encode_noun(&Noun::atom_u64(9));
        let first = engine
            .execute(&code_hash, &[3; 32], &[4; 32], &input, 10_000)
            .unwrap_or_else(|trap| panic!("unexpected trap {}", trap.code));
        let second = engine
            .execute(&code_hash, &[3; 32], &[4; 32], &input, 10_000)
            .unwrap_or_else(|trap| panic!("unexpected trap {}", trap.code));
        assert_eq!(first, second);
        assert!(first.grain_steps > 0);
        assert!(first.storage_words > 0);
    }

    #[test]
    fn grain_engine_unknown_code_has_stable_trap() {
        let trap = GrainContractEngine::default()
            .execute(&[9; 32], &[3; 32], &[4; 32], &[0], 100)
            .expect_err("unknown code must trap");
        assert_eq!(trap.code, TRAP_UNKNOWN_CONTRACT_CODE);
    }

    #[test]
    fn grain_engine_meter_exhaustion_has_exact_stable_trap() {
        // `[0 1]` charges COST_SLOT_BASE (2) up front; a 1-step budget
        // exhausts on the FIRST charge and surfaces the frozen trap code.
        let formula = Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1))
            .unwrap_or_else(|_| unreachable!("small noun"));
        let code_hash = [7; 32];
        let engine = GrainContractEngine::new(
            [1; 32],
            [2; 32],
            [(code_hash, encode_noun(&formula))].into_iter().collect(),
        );
        let input = encode_noun(&Noun::atom_u64(9));
        let trap = engine
            .execute(&code_hash, &[3; 32], &[4; 32], &input, 1)
            .expect_err("meter must exhaust");
        assert_eq!(trap.code, u32::from(GrainTrap::MeterExhausted.code()));
    }
}
