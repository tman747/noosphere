//! The Lumen state transition (arch §6.6, plan §4.1/§4.4).
//!
//! Every transaction executes against a bounded copy-on-write [`Overlay`]
//! keyed by touched entries. Steps 1–5 of the normative order are pure
//! validation over `base ∪ overlay`; a failure there is a **rejection**: no
//! write occurs and all six roots stay byte-identical. After the fee
//! reservation, an execution trap or failed postcondition **drops the
//! overlay** and commits only the frozen deterministic failure charge
//! (fee-payer balance and nonce plus the failure receipt); the notes,
//! nullifiers, objects, and params roots stay byte-identical.
//!
//! Commits emit a canonical ordered [`StateDelta`] for the storage adapter.
//! Whole-state clones are prohibited on these paths (plan §4.1); the only
//! full-map walk is root recomputation, which allocates no state copy.

use std::collections::BTreeMap;

use noos_codec::{NoosDecode, NoosEncode};

use crate::engine::{AuthVerifier, ContractEngine};
use crate::fees::{self, FeeParamsV1, FeeStateV1, Usage};
use crate::issuance::{EmissionSharesV1, IssuanceParamsV1};
use crate::objects::{
    witness_root as derive_witness_root, AccessEntry, AccountV1, ActionV1, CapabilityGrantV1,
    FeatureControlV1, NoteV1, ObjectV1, ParamRecordV1, PendingParamV1, ReceiptV1, ResourceVector,
    TransactionV1, TransactionWitnessesV1,
};
use crate::smt::Smt;
use crate::Hash32;

/// NOOS asset id: the zero hash (frozen, lumen-v1.md §3.2).
pub const NOOS_ASSET: Hash32 = [0u8; 32];

/// Well-known params-tree keys: ASCII name, zero-padded to 32 bytes
/// (frozen, lumen-v1.md §7.1). Names are ≤ 32 bytes by construction.
#[must_use]
pub fn param_key(name: &str) -> Hash32 {
    let mut key = [0u8; 32];
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 32, "param names are frozen <= 32 bytes");
    let n = bytes.len().min(32);
    key[..n].copy_from_slice(&bytes[..n]);
    key
}

pub const PARAM_FEES: &str = "noos.params.fees.v1";
pub const PARAM_FEE_STATE: &str = "noos.params.feestate.v1";
pub const PARAM_ISSUANCE: &str = "noos.params.issuance.v1";
pub const PARAM_SHARES: &str = "noos.params.shares.v1";
/// Governance authority record: raw 32-byte account id whose signed intent
/// authorizes `GovernanceParamUpdate`/`GovernanceRegistryUpdate` (v1 stand-in
/// for the full bonded-vote pipeline; fails closed when absent).
pub const PARAM_GOV_AUTHORITY: &str = "noos.params.gov-auth.v1";
/// Emergency council record: raw 32-byte account id whose signed intent
/// authorizes disable/quarantine ONLY (arch §12.3).
pub const PARAM_EMERGENCY_AUTHORITY: &str = "noos.params.emrg-auth.v1";
/// Feature-control key prefix: `noos.control.<name>`. Not writable by
/// governance param updates; emergency can only write DISABLED.
pub const CONTROL_PREFIX: &str = "noos.control.";
/// Registry key prefix for `GovernanceRegistryUpdate`.
pub const REGISTRY_PREFIX: &str = "noos.registry.";

/// Block-level execution context supplied by consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    pub chain_id: Hash32,
    pub height: u64,
}

/// Genesis installation payload (plan §2.5: engineering networks use the
/// valueless NOOS_TEST fixtures; mainnet values are OWNER_BLOCKED and never
/// appear as code defaults).
#[derive(Debug)]
pub struct GenesisConfig<'a> {
    pub fee_params: FeeParamsV1,
    pub fee_state: FeeStateV1,
    pub issuance: IssuanceParamsV1,
    pub shares: EmissionSharesV1,
    /// Feature controls (`noos.control.<name>`); every radical control ships
    /// disabled at genesis (plan §6.8).
    pub controls: &'a [(&'a str, bool)],
    /// Initial accounts and their liquid balances.
    pub accounts: &'a [(AccountV1, Vec<(Hash32, u128)>)],
    /// Raw account id authorized for delayed governance updates.
    pub gov_authority: Hash32,
    /// Raw account id authorized for emergency disable/quarantine.
    pub emergency_authority: Hash32,
}

/// The six roots (arch §6.1). `receipts_root` is the post-state compact
/// settled-receipt index — never the block's ordered execution receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LumenRoots {
    pub notes_root: Hash32,
    pub nullifiers_root: Hash32,
    pub accounts_root: Hash32,
    pub objects_root: Hash32,
    pub receipts_root: Hash32,
    pub params_root: Hash32,
}

// ---------------------------------------------------------------------------
// StateDelta
// ---------------------------------------------------------------------------

/// Tree identifiers for delta entries (stable numeric order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TreeId {
    Notes = 0,
    Nullifiers = 1,
    Accounts = 2,
    Objects = 3,
    Receipts = 4,
    Params = 5,
    /// Per-account liquid balance sub-tree: `key` = account id,
    /// `sub_key` = asset id, value = u128 LE amount (16 bytes).
    AccountBalances = 6,
}

/// One touched entry: `value = None` deletes, `Some` inserts/updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaEntry {
    pub tree: TreeId,
    pub key: Hash32,
    pub sub_key: Option<Hash32>,
    pub value: Option<Vec<u8>>,
}

/// Working map behind [`StateDelta`]: `(tree, key, sub_key) -> write`.
type DeltaMap = BTreeMap<(TreeId, Hash32, Option<Hash32>), Option<Vec<u8>>>;

/// Canonical ordered state delta: entries sorted by
/// `(tree, key, sub_key)`, at most one entry per slot. This is the exact
/// write set the storage adapter must apply; ordering is deterministic and
/// insertion-order independent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateDelta {
    pub entries: Vec<DeltaEntry>,
}

impl StateDelta {
    fn from_map(map: DeltaMap) -> Self {
        let entries = map
            .into_iter()
            .map(|((tree, key, sub_key), value)| DeltaEntry {
                tree,
                key,
                sub_key,
                value,
            })
            .collect();
        Self { entries }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Errors and outcomes
// ---------------------------------------------------------------------------

/// Pre-reservation rejection (arch §6.6 steps 1–5): the transaction is
/// invalid; NOTHING is written and all six roots stay byte-identical.
/// Stable numeric codes (lumen-v1.md §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Noncanonical = 1,
    WrongChain = 2,
    WrongFormatVersion = 3,
    Expired = 4,
    ResourceLimitExceedsCapacity = 5,
    OversizedEncoding = 6,
    UnknownNoteInput = 7,
    NullifierAlreadySpent = 8,
    TimelockNotElapsed = 9,
    UnknownAccountInput = 10,
    UnknownObject = 11,
    ObjectQuarantined = 12,
    MissingWitness = 13,
    WitnessRootMismatch = 14,
    SignatureInvalid = 15,
    LockRevealInvalid = 16,
    ProofProfileInvalid = 17,
    FeePayerNotDeclared = 18,
    InsufficientFeeBalance = 19,
    FeeOverflow = 20,
    TxAlreadySettled = 21,
    ActionMalformed = 22,
    CapabilityDenied = 23,
    GovernanceDenied = 24,
    DuplicateOutputNote = 25,
    OutputBirthHeightMismatch = 26,
    DuplicateDeclaredInput = 27,
}

/// Post-reservation execution failure: the overlay is dropped and only the
/// frozen deterministic failure charge commits. Stable numeric codes offset
/// by 1000 from engine traps (lumen-v1.md §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailCode {
    /// Grain trap with its stable code.
    EngineTrap(u32),
    /// Measured resources exceeded the declared limits.
    ResourceOverrun,
    /// Per-asset conservation violated by the executed action set.
    ConservationViolation,
    /// An object invariant/postcondition failed (version/access mismatch).
    PostconditionFailed,
    /// Balance arithmetic overflow during execution.
    Overflow,
    /// Insufficient balance for an executed balance movement.
    InsufficientBalance,
    /// Undeclared object access (reads/writes outside the access list trap).
    UndeclaredAccess,
}

impl FailCode {
    /// Stable receipt status code: 0 is success; engine traps map to
    /// `2000 + code`; Lumen execution failures map to `1000 + variant`.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            FailCode::EngineTrap(code) => {
                let c = u16::try_from(*code).unwrap_or(999);
                2000u16.saturating_add(c.min(999))
            }
            FailCode::ResourceOverrun => 1000,
            FailCode::ConservationViolation => 1001,
            FailCode::PostconditionFailed => 1002,
            FailCode::Overflow => 1003,
            FailCode::InsufficientBalance => 1004,
            FailCode::UndeclaredAccess => 1005,
        }
    }
}

/// Result of applying one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Executed and committed in full.
    Applied {
        receipt: ReceiptV1,
        delta: StateDelta,
    },
    /// Execution trapped after reservation: overlay dropped, deterministic
    /// failure charge committed, failure receipt appended.
    Failed {
        receipt: ReceiptV1,
        delta: StateDelta,
        code: FailCode,
    },
}

impl ApplyOutcome {
    #[must_use]
    pub fn receipt(&self) -> &ReceiptV1 {
        match self {
            ApplyOutcome::Applied { receipt, .. } | ApplyOutcome::Failed { receipt, .. } => receipt,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionError {
    /// Emission for this height was already minted or the height is not
    /// strictly ahead of the last minted height.
    HeightNotAdvancing,
    /// Recipient account does not exist (genesis must create recipients).
    UnknownRecipient,
    /// Schedule/parameters invalid or missing from the params tree.
    InvalidSchedule,
    /// Cap or arithmetic overflow.
    Overflow,
}

// ---------------------------------------------------------------------------
// Overlay
// ---------------------------------------------------------------------------

/// Bounded copy-on-write overlay keyed by touched entries. Reads fall
/// through to the base ledger; writes stay here until commit.
#[derive(Debug, Default)]
struct Overlay {
    notes: BTreeMap<Hash32, Option<Vec<u8>>>,
    nullifiers: BTreeMap<Hash32, Option<Vec<u8>>>,
    accounts: BTreeMap<Hash32, Option<Vec<u8>>>,
    objects: BTreeMap<Hash32, Option<Vec<u8>>>,
    receipts: BTreeMap<Hash32, Option<Vec<u8>>>,
    params: BTreeMap<Hash32, Option<Vec<u8>>>,
    /// (account, asset) -> new amount; 0 removes the balance leaf.
    balances: BTreeMap<(Hash32, Hash32), u128>,
    state_reads: u64,
    state_writes: u64,
}

impl Overlay {
    fn read_count(&mut self) -> Result<(), FailCode> {
        self.state_reads = self.state_reads.checked_add(1).ok_or(FailCode::Overflow)?;
        Ok(())
    }

    fn write_count(&mut self) -> Result<(), FailCode> {
        self.state_writes = self.state_writes.checked_add(1).ok_or(FailCode::Overflow)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// The in-memory authenticated Lumen state: six sparse Merkle maps plus the
/// per-account liquid-balance sub-trees and the emission bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LumenLedger {
    notes: Smt,
    nullifiers: Smt,
    accounts: Smt,
    objects: Smt,
    receipts: Smt,
    params: Smt,
    /// account_id -> (asset_id -> amount) sub-tree backing
    /// `AccountV1.liquid_balances_root`.
    balances: BTreeMap<Hash32, Smt>,
    /// Cumulative minted supply (checked against the issuance cap).
    total_minted: u128,
    /// Last height whose emission was minted; skipped heights are NEVER
    /// recreated (arch §13.2).
    last_emission_height: u64,
}

impl LumenLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current six roots.
    #[must_use]
    pub fn roots(&self) -> LumenRoots {
        LumenRoots {
            notes_root: self.notes.root(),
            nullifiers_root: self.nullifiers.root(),
            accounts_root: self.accounts.root(),
            objects_root: self.objects.root(),
            receipts_root: self.receipts.root(),
            params_root: self.params.root(),
        }
    }

    #[must_use]
    pub fn total_minted(&self) -> u128 {
        self.total_minted
    }

    #[must_use]
    pub fn last_emission_height(&self) -> u64 {
        self.last_emission_height
    }

    /// Liquid balance for (account, asset).
    #[must_use]
    pub fn balance(&self, account: &Hash32, asset: &Hash32) -> u128 {
        self.balances
            .get(account)
            .and_then(|t| t.get(asset))
            .map(decode_amount)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn get_account(&self, id: &Hash32) -> Option<AccountV1> {
        self.accounts
            .get(id)
            .and_then(|b| AccountV1::decode_canonical(b).ok())
    }

    #[must_use]
    pub fn get_object(&self, id: &Hash32) -> Option<ObjectV1> {
        self.objects
            .get(id)
            .and_then(|b| ObjectV1::decode_canonical(b).ok())
    }

    #[must_use]
    pub fn get_note(&self, id: &Hash32) -> Option<NoteV1> {
        self.notes
            .get(id)
            .and_then(|b| NoteV1::decode_canonical(b).ok())
    }

    #[must_use]
    pub fn get_receipt(&self, txid: &Hash32) -> Option<ReceiptV1> {
        self.receipts
            .get(txid)
            .and_then(|b| ReceiptV1::decode_canonical(b).ok())
    }

    #[must_use]
    pub fn nullifier_spent(&self, nullifier: &Hash32) -> bool {
        self.nullifiers.contains(nullifier)
    }

    fn param_record(&self, key: &Hash32) -> Option<ParamRecordV1> {
        self.params
            .get(key)
            .and_then(|b| ParamRecordV1::decode_canonical(b).ok())
    }

    /// Read a typed record out of a params-tree ParamRecord wrapper.
    fn param_current<T: NoosDecode>(&self, name: &str) -> Option<T> {
        let rec = self.param_record(&param_key(name))?;
        T::decode_canonical(rec.current.as_slice()).ok()
    }

    #[must_use]
    pub fn fee_params(&self) -> Option<FeeParamsV1> {
        self.param_current(PARAM_FEES)
    }

    #[must_use]
    pub fn fee_state(&self) -> Option<FeeStateV1> {
        self.param_current(PARAM_FEE_STATE)
    }

    #[must_use]
    pub fn issuance_params(&self) -> Option<IssuanceParamsV1> {
        self.param_current(PARAM_ISSUANCE)
    }

    #[must_use]
    pub fn emission_shares(&self) -> Option<EmissionSharesV1> {
        self.param_current(PARAM_SHARES)
    }

    // -- genesis ------------------------------------------------------------

    /// Install a genesis params set and initial accounts. Direct writes: this
    /// is the only path that seeds state outside a transaction.
    pub fn install_genesis(&mut self, config: &GenesisConfig<'_>) {
        self.write_param_direct(PARAM_GOV_AUTHORITY, &config.gov_authority);
        self.write_param_direct(PARAM_EMERGENCY_AUTHORITY, &config.emergency_authority);
        let fee_params = &config.fee_params;
        let fee_state = &config.fee_state;
        let issuance = &config.issuance;
        let shares = &config.shares;
        let controls = config.controls;
        let accounts = config.accounts;
        self.write_param_direct(PARAM_FEES, &fee_params.encode_canonical());
        self.write_param_direct(PARAM_FEE_STATE, &fee_state.encode_canonical());
        self.write_param_direct(PARAM_ISSUANCE, &issuance.encode_canonical());
        self.write_param_direct(PARAM_SHARES, &shares.encode_canonical());
        for (name, enabled) in controls {
            let ctl = FeatureControlV1 {
                enabled: u8::from(*enabled),
            };
            let full = format!("{CONTROL_PREFIX}{name}");
            self.write_param_direct(&full, &ctl.encode_canonical());
        }
        for (account, balances) in accounts {
            let mut acct = account.clone();
            let tree = self.balances.entry(acct.account_id).or_default();
            for (asset, amount) in balances {
                if *amount > 0 {
                    tree.insert(*asset, encode_amount(*amount));
                }
            }
            acct.liquid_balances_root = tree.root();
            self.accounts
                .insert(acct.account_id, acct.encode_canonical());
        }
    }

    fn write_param_direct(&mut self, name: &str, value: &[u8]) {
        let rec = ParamRecordV1 {
            current: crate::objects::BoundedBytes::new(value.to_vec()).unwrap_or_default(),
            pending: crate::objects::OptionalObject(None),
        };
        self.params.insert(param_key(name), rec.encode_canonical());
    }

    // -- emission -------------------------------------------------------------

    /// Mint the scheduled emission for `height` to the recipient accounts.
    /// The ONLY mint entry point; driven purely by the frozen schedule.
    /// Skipped heights are never recreated: minting at `h` requires
    /// `h > last_emission_height`, and any heights in between are forfeit.
    pub fn apply_emission(
        &mut self,
        height: u64,
        proposer: &Hash32,
        witness_pool: &Hash32,
        treasury: &Hash32,
    ) -> Result<StateDelta, EmissionError> {
        if height <= self.last_emission_height {
            return Err(EmissionError::HeightNotAdvancing);
        }
        let issuance = self
            .issuance_params()
            .ok_or(EmissionError::InvalidSchedule)?;
        issuance
            .validate()
            .map_err(|_| EmissionError::InvalidSchedule)?;
        let shares = self
            .emission_shares()
            .ok_or(EmissionError::InvalidSchedule)?;
        let emission = issuance
            .emission_at(height)
            .map_err(|_| EmissionError::Overflow)?;
        let split = shares
            .split(emission)
            .map_err(|_| EmissionError::InvalidSchedule)?;
        // Recipients must pre-exist.
        for id in [proposer, witness_pool, treasury] {
            if !self.accounts.contains(id) {
                return Err(EmissionError::UnknownRecipient);
            }
        }
        let new_total = self
            .total_minted
            .checked_add(emission)
            .ok_or(EmissionError::Overflow)?;
        if new_total > issuance.max_supply {
            return Err(EmissionError::Overflow);
        }
        let mut delta = BTreeMap::new();
        for (id, amount) in [
            (proposer, split.proposer),
            (witness_pool, split.witness),
            (treasury, split.treasury),
        ] {
            if amount == 0 {
                continue;
            }
            let current = self.balance(id, &NOOS_ASSET);
            let next = current.checked_add(amount).ok_or(EmissionError::Overflow)?;
            self.set_balance_direct(id, &NOOS_ASSET, next, &mut delta);
        }
        self.total_minted = new_total;
        self.last_emission_height = height;
        Ok(StateDelta::from_map(delta))
    }

    /// Direct balance write + account-root refresh (emission/commit paths).
    fn set_balance_direct(
        &mut self,
        account: &Hash32,
        asset: &Hash32,
        amount: u128,
        delta: &mut DeltaMap,
    ) {
        let tree = self.balances.entry(*account).or_default();
        if amount == 0 {
            tree.remove(asset);
            delta.insert((TreeId::AccountBalances, *account, Some(*asset)), None);
        } else {
            tree.insert(*asset, encode_amount(amount));
            delta.insert(
                (TreeId::AccountBalances, *account, Some(*asset)),
                Some(encode_amount(amount)),
            );
        }
        let new_root = tree.root();
        if let Some(mut acct) = self.get_account(account) {
            if acct.liquid_balances_root != new_root {
                acct.liquid_balances_root = new_root;
                let bytes = acct.encode_canonical();
                self.accounts.insert(*account, bytes.clone());
                delta.insert((TreeId::Accounts, *account, None), Some(bytes));
            }
        }
    }

    // -- fee controller -------------------------------------------------------

    /// End-of-block controller step: advance the five base prices from the
    /// block's usage totals (bounded, checked; lumen-v1.md §6.3).
    pub fn end_block_fee_update(&mut self, usage: &Usage) -> Result<StateDelta, RejectReason> {
        let params = self.fee_params().ok_or(RejectReason::GovernanceDenied)?;
        let state = self.fee_state().ok_or(RejectReason::GovernanceDenied)?;
        let next =
            fees::next_prices(&state.prices(), usage, &params).ok_or(RejectReason::FeeOverflow)?;
        let new_state = FeeStateV1::from_prices(next);
        let mut delta = BTreeMap::new();
        let rec = ParamRecordV1 {
            current: crate::objects::BoundedBytes::new(new_state.encode_canonical())
                .unwrap_or_default(),
            pending: crate::objects::OptionalObject(None),
        };
        let bytes = rec.encode_canonical();
        self.params
            .insert(param_key(PARAM_FEE_STATE), bytes.clone());
        delta.insert(
            (TreeId::Params, param_key(PARAM_FEE_STATE), None),
            Some(bytes),
        );
        Ok(StateDelta::from_map(delta))
    }

    /// Activate every pending parameter whose activation height has arrived.
    /// Deterministic key-order walk; called by consensus at block start.
    pub fn activate_pending_params(&mut self, height: u64) -> StateDelta {
        let mut updates: Vec<(Hash32, ParamRecordV1)> = Vec::new();
        for (key, value) in self.params.iter() {
            let Ok(rec) = ParamRecordV1::decode_canonical(value) else {
                continue;
            };
            let Some(pending) = &rec.pending.0 else {
                continue;
            };
            if pending.activation_height <= height {
                let promoted = ParamRecordV1 {
                    current: pending.value.clone(),
                    pending: crate::objects::OptionalObject(None),
                };
                updates.push((*key, promoted));
            }
        }
        let mut delta = BTreeMap::new();
        for (key, rec) in updates {
            let bytes = rec.encode_canonical();
            self.params.insert(key, bytes.clone());
            delta.insert((TreeId::Params, key, None), Some(bytes));
        }
        StateDelta::from_map(delta)
    }

    // -- transaction application ---------------------------------------------

    /// Apply one transaction in the normative order (arch §6.6).
    ///
    /// `Err(RejectReason)` = invalid transaction, nothing written, all six
    /// roots byte-identical. `Ok(ApplyOutcome::Failed{..})` = post-reservation
    /// trap: only the deterministic failure charge and failure receipt
    /// committed. `Ok(ApplyOutcome::Applied{..})` = full commit.
    pub fn apply_transaction(
        &mut self,
        ctx: &BlockContext,
        tx_bytes: &[u8],
        witness_bytes: &[u8],
        engine: &dyn ContractEngine,
        auth: &dyn AuthVerifier,
    ) -> Result<ApplyOutcome, RejectReason> {
        // ---- step 1: decode; reject noncanonical / unknown mandatory ----
        let tx =
            TransactionV1::decode_canonical(tx_bytes).map_err(|_| RejectReason::Noncanonical)?;
        let witnesses = TransactionWitnessesV1::decode_canonical(witness_bytes)
            .map_err(|_| RejectReason::Noncanonical)?;
        let mut actions: Vec<ActionV1> = Vec::with_capacity(tx.actions.len());
        for raw in tx.actions.iter() {
            let action = ActionV1::decode_canonical(raw.as_slice())
                .map_err(|_| RejectReason::ActionMalformed)?;
            actions.push(action);
        }
        let txid = crate::objects::txid(&tx);

        // ---- step 2: chain / version / expiry / resource envelope ----
        if tx.chain_id != ctx.chain_id {
            return Err(RejectReason::WrongChain);
        }
        if tx.format_version != TransactionV1::VERSION {
            return Err(RejectReason::WrongFormatVersion);
        }
        if ctx.height > tx.expiry_height {
            return Err(RejectReason::Expired);
        }
        let fee_params = self.fee_params().ok_or(RejectReason::GovernanceDenied)?;
        let fee_state = self.fee_state().ok_or(RejectReason::GovernanceDenied)?;
        let capacity = fee_params.capacity();
        let declared = fees::usage_from_resources(&tx.resource_limits);
        for i in 0..fees::DIMENSIONS {
            if declared[i] > capacity[i] {
                return Err(RejectReason::ResourceLimitExceedsCapacity);
            }
        }
        let encoded_len = u64::try_from(tx_bytes.len())
            .ok()
            .zip(u64::try_from(witness_bytes.len()).ok())
            .and_then(|(t, w)| t.checked_add(w))
            .ok_or(RejectReason::OversizedEncoding)?;
        if encoded_len > tx.resource_limits.bytes {
            return Err(RejectReason::OversizedEncoding);
        }
        // Replay guard: the settled-receipt index rejects a settled txid.
        if self.receipts.contains(&txid) {
            return Err(RejectReason::TxAlreadySettled);
        }

        // ---- step 3: resolve declared inputs ----
        // Duplicate declarations reject: a note declared twice would count
        // its value twice in the conservation ledger, and a duplicated
        // account would collapse two nonce consumptions into one write.
        if has_duplicates(tx.note_inputs.as_slice()) || has_duplicates(tx.account_inputs.as_slice())
        {
            return Err(RejectReason::DuplicateDeclaredInput);
        }
        let mut input_notes: Vec<(Hash32, NoteV1)> = Vec::with_capacity(tx.note_inputs.len());
        for note_id in tx.note_inputs.iter() {
            if self.nullifiers.contains(note_id) {
                return Err(RejectReason::NullifierAlreadySpent);
            }
            let note = self
                .get_note(note_id)
                .ok_or(RejectReason::UnknownNoteInput)?;
            let unlock = note
                .birth_height
                .checked_add(u64::from(note.relative_timelock))
                .ok_or(RejectReason::TimelockNotElapsed)?;
            if ctx.height < unlock {
                return Err(RejectReason::TimelockNotElapsed);
            }
            input_notes.push((*note_id, note));
        }
        let mut input_accounts: Vec<(Hash32, AccountV1)> =
            Vec::with_capacity(tx.account_inputs.len());
        for account_id in tx.account_inputs.iter() {
            let acct = self
                .get_account(account_id)
                .ok_or(RejectReason::UnknownAccountInput)?;
            input_accounts.push((*account_id, acct));
        }
        for entry in tx.object_access_list.iter() {
            let obj = self
                .get_object(&entry.object_id)
                .ok_or(RejectReason::UnknownObject)?;
            if obj.flags & ObjectV1::FLAG_QUARANTINED != 0 {
                return Err(RejectReason::ObjectQuarantined);
            }
        }
        if !tx.account_inputs.iter().any(|a| *a == tx.fee_payer) {
            return Err(RejectReason::FeePayerNotDeclared);
        }

        // ---- step 4: signatures, lock reveals, capabilities, proofs ----
        if tx.witness_root != derive_witness_root(&witnesses.lock_reveals) {
            return Err(RejectReason::WitnessRootMismatch);
        }
        if witnesses.lock_reveals.len() != input_notes.len()
            || witnesses.intents.len() != input_accounts.len()
        {
            return Err(RejectReason::MissingWitness);
        }
        for ((_, note), reveal) in input_notes.iter().zip(witnesses.lock_reveals.iter()) {
            if !auth.verify_lock_reveal(&note.lock_root, reveal.as_slice()) {
                return Err(RejectReason::LockRevealInvalid);
            }
        }
        for ((_, acct), intent) in input_accounts.iter().zip(witnesses.intents.iter()) {
            if intent.tx_commitment != txid {
                return Err(RejectReason::SignatureInvalid);
            }
            if !auth.verify_signature(
                intent.signature_suite,
                acct.auth_descriptor.as_slice(),
                &txid,
                intent.signature.as_slice(),
            ) {
                return Err(RejectReason::SignatureInvalid);
            }
        }
        if !auth.verify_witness_extras(&witnesses) {
            return Err(RejectReason::SignatureInvalid);
        }
        for evidence in tx.evidence_refs.iter() {
            if !auth.verify_evidence_ref(evidence) {
                return Err(RejectReason::ProofProfileInvalid);
            }
        }
        // Governance/emergency and capability preconditions that require an
        // authorized signer are validated against the signed account set.
        self.validate_action_authority(ctx, &actions, &tx, &fee_params)?;

        // Output notes: birth height must be the current height; duplicate
        // note ids inside one transaction reject.
        let mut planned_outputs: Vec<(Hash32, NoteV1)> = Vec::with_capacity(tx.outputs.len());
        for (index, note) in tx.outputs.iter().enumerate() {
            if note.birth_height != ctx.height {
                return Err(RejectReason::OutputBirthHeightMismatch);
            }
            let idx = u32::try_from(index).map_err(|_| RejectReason::Noncanonical)?;
            let id = crate::objects::note_id(&txid, idx, note);
            if self.notes.contains(&id) || planned_outputs.iter().any(|(x, _)| *x == id) {
                return Err(RejectReason::DuplicateOutputNote);
            }
            planned_outputs.push((id, note.clone()));
        }

        // ---- step 5: reserve the maximum fee ----
        let prices = fee_state.prices();
        let max_fee = fees::fee(&prices, &declared).ok_or(RejectReason::FeeOverflow)?;
        let payer_balance = self.balance(&tx.fee_payer, &NOOS_ASSET);
        if payer_balance < max_fee {
            return Err(RejectReason::InsufficientFeeBalance);
        }
        // Reservation is committed from here on: failures below charge the
        // frozen deterministic failure fee instead of rejecting.

        // ---- steps 6-7: execute actions + conservation in the overlay ----
        let exec = self.execute_in_overlay(
            ctx,
            &tx,
            &txid,
            &actions,
            &input_notes,
            &input_accounts,
            &planned_outputs,
            max_fee,
            engine,
        );

        match exec {
            Ok((mut overlay, grain_steps, storage_words)) => {
                // ---- step 8: charge measured resources, refund the rest ----
                let measured = ResourceVector {
                    bytes: encoded_len,
                    grain_steps,
                    proof_units: u64::try_from(tx.evidence_refs.len()).unwrap_or(u64::MAX),
                    state_reads: overlay.state_reads,
                    state_writes: overlay.state_writes.max(storage_words),
                    blob_bytes: 0,
                };
                if !measured.fits_within(&tx.resource_limits) {
                    return Ok(self.commit_failure(
                        &tx,
                        &txid,
                        FailCode::ResourceOverrun,
                        max_fee,
                        &fee_params,
                        encoded_len,
                    ));
                }
                let used = fees::usage_from_resources(&measured);
                let Some(actual_fee) = fees::fee(&prices, &used) else {
                    return Ok(self.commit_failure(
                        &tx,
                        &txid,
                        FailCode::Overflow,
                        max_fee,
                        &fee_params,
                        encoded_len,
                    ));
                };
                debug_assert!(actual_fee <= max_fee, "fee is monotone in usage");
                let charged = actual_fee.min(max_fee);
                // Deduct the actual fee (reservation minus refund) inside the
                // overlay so the commit is atomic.
                let payer_now = overlay_balance(&overlay, self, &tx.fee_payer, &NOOS_ASSET);
                let Some(after_fee) = payer_now.checked_sub(charged) else {
                    return Ok(self.commit_failure(
                        &tx,
                        &txid,
                        FailCode::InsufficientBalance,
                        max_fee,
                        &fee_params,
                        encoded_len,
                    ));
                };
                overlay
                    .balances
                    .insert((tx.fee_payer, NOOS_ASSET), after_fee);

                // ---- step 9-10: atomic commit + receipt ----
                let receipt = ReceiptV1 {
                    txid,
                    status: 0,
                    fee_charged: charged,
                    resources_used: measured,
                };
                overlay
                    .receipts
                    .insert(txid, Some(receipt.encode_canonical()));
                let delta = self.commit_overlay(overlay);
                Ok(ApplyOutcome::Applied { receipt, delta })
            }
            Err(code) => {
                Ok(self.commit_failure(&tx, &txid, code, max_fee, &fee_params, encoded_len))
            }
        }
    }

    /// Pre-reservation authority checks for actions (part of step 4).
    fn validate_action_authority(
        &self,
        ctx: &BlockContext,
        actions: &[ActionV1],
        tx: &TransactionV1,
        fee_params: &FeeParamsV1,
    ) -> Result<(), RejectReason> {
        let signed = |id: &Hash32| tx.account_inputs.iter().any(|a| a == id);
        // Authority records (raw 32-byte account ids installed at genesis and
        // rotated through the delayed governance path). A governance or
        // emergency action without its signed authority account rejects; a
        // missing record fails closed.
        let gov_ok = || -> bool {
            self.authority_account(PARAM_GOV_AUTHORITY)
                .is_some_and(|id| signed(&id))
        };
        let emergency_ok = || -> bool {
            self.authority_account(PARAM_EMERGENCY_AUTHORITY)
                .is_some_and(|id| signed(&id))
        };
        for action in actions {
            match action {
                ActionV1::GovernanceParamUpdate {
                    param_key: key,
                    activation_height,
                    ..
                } => {
                    if !gov_ok() {
                        return Err(RejectReason::GovernanceDenied);
                    }
                    // Feature controls are NOT governable here: activating a
                    // disabled suite requires a hard fork. Authority records
                    // rotate only through this same delayed path.
                    if key_has_prefix(key, CONTROL_PREFIX) {
                        return Err(RejectReason::GovernanceDenied);
                    }
                    let min = ctx
                        .height
                        .checked_add(fee_params.min_activation_delay)
                        .ok_or(RejectReason::GovernanceDenied)?;
                    if *activation_height < min {
                        return Err(RejectReason::GovernanceDenied);
                    }
                }
                ActionV1::GovernanceRegistryUpdate {
                    registry_key,
                    activation_height,
                    ..
                } => {
                    if !gov_ok() {
                        return Err(RejectReason::GovernanceDenied);
                    }
                    if !key_has_prefix(registry_key, REGISTRY_PREFIX) {
                        return Err(RejectReason::GovernanceDenied);
                    }
                    let min = ctx
                        .height
                        .checked_add(fee_params.min_activation_delay)
                        .ok_or(RejectReason::GovernanceDenied)?;
                    if *activation_height < min {
                        return Err(RejectReason::GovernanceDenied);
                    }
                }
                ActionV1::EmergencyDisable { control_key } => {
                    if !emergency_ok() {
                        return Err(RejectReason::GovernanceDenied);
                    }
                    if !key_has_prefix(control_key, CONTROL_PREFIX) {
                        return Err(RejectReason::GovernanceDenied);
                    }
                }
                ActionV1::EmergencyQuarantine { .. } => {
                    if !emergency_ok() {
                        return Err(RejectReason::GovernanceDenied);
                    }
                }
                ActionV1::GrantCapability { grant } => {
                    if !signed(&grant.issuer) {
                        return Err(RejectReason::CapabilityDenied);
                    }
                }
                ActionV1::RevokeCapability { grant_id } => {
                    let bytes = self
                        .objects
                        .get(grant_id)
                        .ok_or(RejectReason::CapabilityDenied)?;
                    let grant = CapabilityGrantV1::decode_canonical(bytes)
                        .map_err(|_| RejectReason::CapabilityDenied)?;
                    if !signed(&grant.issuer) {
                        return Err(RejectReason::CapabilityDenied);
                    }
                }
                ActionV1::WithdrawFromAccount { account_id, .. } if !signed(account_id) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Raw 32-byte account id stored under an authority param record.
    fn authority_account(&self, name: &str) -> Option<Hash32> {
        let rec = self.param_record(&param_key(name))?;
        let bytes = rec.current.as_slice();
        if bytes.len() != 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        Some(id)
    }

    /// Steps 6–7: execute all actions and enforce per-asset conservation in
    /// a fresh overlay. Any failure drops the overlay (returned by value, so
    /// dropping = discarding).
    #[allow(clippy::too_many_arguments)]
    fn execute_in_overlay(
        &self,
        ctx: &BlockContext,
        tx: &TransactionV1,
        txid: &Hash32,
        actions: &[ActionV1],
        input_notes: &[(Hash32, NoteV1)],
        input_accounts: &[(Hash32, AccountV1)],
        planned_outputs: &[(Hash32, NoteV1)],
        _max_fee: u128,
        engine: &dyn ContractEngine,
    ) -> Result<(Overlay, u64, u64), FailCode> {
        let mut ov = Overlay::default();
        let mut grain_steps: u64 = 0;
        let mut storage_words: u64 = 0;

        // Per-asset conservation ledger:
        //   inputs + withdrawals == outputs + deposits   (strict, per asset)
        let mut inflow: BTreeMap<Hash32, u128> = BTreeMap::new();
        let mut outflow: BTreeMap<Hash32, u128> = BTreeMap::new();
        for (_, note) in input_notes {
            ov.read_count()?;
            add_flow(&mut inflow, &note.asset_id, note.amount)?;
        }
        for (_, note) in planned_outputs {
            add_flow(&mut outflow, &note.asset_id, note.amount)?;
        }

        // Consume inputs: delete note, insert nullifier (= note_id).
        for (note_id, _) in input_notes {
            ov.notes.insert(*note_id, None);
            ov.nullifiers.insert(*note_id, Some(vec![1u8]));
            ov.write_count()?;
            ov.write_count()?;
        }
        // Increment account nonces (consumes exactly nonce+1).
        for (account_id, acct) in input_accounts {
            let mut updated = acct.clone();
            updated.nonce = updated.nonce.checked_add(1).ok_or(FailCode::Overflow)?;
            ov.accounts
                .insert(*account_id, Some(updated.encode_canonical()));
            ov.write_count()?;
        }

        // Execute actions in listed order.
        for (index, action) in actions.iter().enumerate() {
            match action {
                ActionV1::CallObject { object_id, input } => {
                    // Undeclared access traps (fail-closed, arch §6.4).
                    let declared = tx
                        .object_access_list
                        .iter()
                        .find(|e| e.object_id == *object_id)
                        .ok_or(FailCode::UndeclaredAccess)?;
                    if declared.mode != AccessEntry::MODE_READ_WRITE {
                        return Err(FailCode::UndeclaredAccess);
                    }
                    ov.read_count()?;
                    let obj_bytes = overlay_object(&ov, self, object_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut obj = ObjectV1::decode_canonical(&obj_bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if obj.flags & ObjectV1::FLAG_QUARANTINED != 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let remaining = tx
                        .resource_limits
                        .grain_steps
                        .checked_sub(grain_steps)
                        .ok_or(FailCode::ResourceOverrun)?;
                    let outcome = engine
                        .execute(
                            &obj.code_hash,
                            object_id,
                            &obj.state_root,
                            input.as_slice(),
                            remaining,
                        )
                        .map_err(|t| FailCode::EngineTrap(t.code))?;
                    grain_steps = grain_steps
                        .checked_add(outcome.grain_steps)
                        .ok_or(FailCode::Overflow)?;
                    storage_words = storage_words
                        .checked_add(outcome.storage_words)
                        .ok_or(FailCode::Overflow)?;
                    // Atomic version/root write (exact prior version checked
                    // implicitly: we read through the overlay chain).
                    obj.state_root = outcome.new_state_root;
                    obj.object_version = obj
                        .object_version
                        .checked_add(1)
                        .ok_or(FailCode::Overflow)?;
                    obj.storage_words = outcome.storage_words;
                    ov.objects.insert(*object_id, Some(obj.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::CreateObject {
                    class_id,
                    owner_or_policy_root,
                    code_hash,
                    state_root,
                    storage_words: words,
                    rent_deposit,
                    flags,
                } => {
                    let idx = u32::try_from(index).map_err(|_| FailCode::Overflow)?;
                    let id = crate::objects::object_id(txid, idx, *class_id);
                    if overlay_object(&ov, self, &id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    // Rent deposit is value: it flows out of note inputs.
                    add_flow(&mut outflow, &NOOS_ASSET, *rent_deposit)?;
                    let obj = ObjectV1 {
                        object_id: id,
                        class_id: *class_id,
                        owner_or_policy_root: *owner_or_policy_root,
                        code_hash: *code_hash,
                        state_root: *state_root,
                        object_version: 0,
                        storage_words: *words,
                        rent_deposit: *rent_deposit,
                        flags: *flags & !ObjectV1::FLAG_QUARANTINED,
                    };
                    storage_words = storage_words
                        .checked_add(*words)
                        .ok_or(FailCode::Overflow)?;
                    ov.objects.insert(id, Some(obj.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::DepositToAccount {
                    account_id,
                    asset_id,
                    amount,
                } => {
                    if overlay_account(&ov, self, account_id).is_none() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    add_flow(&mut outflow, asset_id, *amount)?;
                    let current = overlay_balance(&ov, self, account_id, asset_id);
                    let next = current.checked_add(*amount).ok_or(FailCode::Overflow)?;
                    ov.balances.insert((*account_id, *asset_id), next);
                    ov.write_count()?;
                }
                ActionV1::WithdrawFromAccount {
                    account_id,
                    asset_id,
                    amount,
                } => {
                    add_flow(&mut inflow, asset_id, *amount)?;
                    let current = overlay_balance(&ov, self, account_id, asset_id);
                    let next = current
                        .checked_sub(*amount)
                        .ok_or(FailCode::InsufficientBalance)?;
                    ov.balances.insert((*account_id, *asset_id), next);
                    ov.write_count()?;
                }
                ActionV1::GovernanceParamUpdate {
                    param_key: key,
                    new_value,
                    activation_height,
                }
                | ActionV1::GovernanceRegistryUpdate {
                    registry_key: key,
                    new_value,
                    activation_height,
                } => {
                    let existing = overlay_param(&ov, self, key);
                    let current = match existing {
                        Some(bytes) => {
                            ParamRecordV1::decode_canonical(&bytes)
                                .map_err(|_| FailCode::PostconditionFailed)?
                                .current
                        }
                        None => crate::objects::BoundedBytes::default(),
                    };
                    let rec = ParamRecordV1 {
                        current,
                        pending: crate::objects::OptionalObject(Some(PendingParamV1 {
                            value: new_value.clone(),
                            activation_height: *activation_height,
                        })),
                    };
                    ov.params.insert(*key, Some(rec.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::EmergencyDisable { control_key } => {
                    // Risk-reducing only: writes DISABLED, never enabled.
                    let ctl = FeatureControlV1 { enabled: 0 };
                    let rec = ParamRecordV1 {
                        current: crate::objects::BoundedBytes::new(ctl.encode_canonical())
                            .ok_or(FailCode::Overflow)?,
                        pending: crate::objects::OptionalObject(None),
                    };
                    ov.params.insert(*control_key, Some(rec.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::EmergencyQuarantine { object_id } => {
                    let bytes = overlay_object(&ov, self, object_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut obj = ObjectV1::decode_canonical(&bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    obj.flags |= ObjectV1::FLAG_QUARANTINED;
                    ov.objects.insert(*object_id, Some(obj.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::RegisterAgent { agent } => {
                    if overlay_object(&ov, self, &agent.agent_id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(agent.agent_id, Some(agent.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::GrantCapability { grant } => {
                    if overlay_object(&ov, self, &grant.grant_id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(grant.grant_id, Some(grant.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::RevokeCapability { grant_id } => {
                    if overlay_object(&ov, self, grant_id).is_none() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects.insert(*grant_id, None);
                    ov.write_count()?;
                }
                ActionV1::SubmitIntent { intent } => {
                    // Deterministic policy gate (arch §11.1): schema is the
                    // typed object itself; check prestate binding, capability
                    // scope, budget, expiry; consume budget.
                    ov.read_count()?;
                    let grant_bytes = overlay_object(&ov, self, &intent.capability_ref)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut grant = CapabilityGrantV1::decode_canonical(&grant_bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if grant.subject_agent != intent.agent_id
                        || ctx.height > grant.expiry_height
                        || ctx.height > intent.deadline
                        || intent.budget > grant.per_action_limit
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    if overlay_object(&ov, self, &intent.agent_id).is_none() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    grant.cumulative_budget = grant
                        .cumulative_budget
                        .checked_sub(intent.budget)
                        .ok_or(FailCode::InsufficientBalance)?;
                    ov.objects
                        .insert(grant.grant_id, Some(grant.encode_canonical()));
                    ov.write_count()?;
                }
            }
        }

        // Write planned outputs.
        for (id, note) in planned_outputs {
            ov.notes.insert(*id, Some(note.encode_canonical()));
            ov.write_count()?;
        }

        // ---- step 7: per-asset conservation (strict equality) ----
        let assets: Vec<Hash32> = inflow
            .keys()
            .chain(outflow.keys())
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for asset in assets {
            let inn = inflow.get(&asset).copied().unwrap_or(0);
            let out = outflow.get(&asset).copied().unwrap_or(0);
            if inn != out {
                return Err(FailCode::ConservationViolation);
            }
        }

        Ok((ov, grain_steps, storage_words))
    }

    /// Failure path: drop the overlay entirely; commit ONLY the frozen
    /// deterministic failure charge (min(failure_fee, reservation)) against
    /// the fee payer, its nonce increment, and the failure receipt.
    /// notes/nullifiers/objects/params roots stay byte-identical.
    fn commit_failure(
        &mut self,
        tx: &TransactionV1,
        txid: &Hash32,
        code: FailCode,
        max_fee: u128,
        fee_params: &FeeParamsV1,
        encoded_len: u64,
    ) -> ApplyOutcome {
        let charge = fee_params.failure_fee.min(max_fee);
        let mut delta = BTreeMap::new();
        let balance = self.balance(&tx.fee_payer, &NOOS_ASSET);
        // The reservation guaranteed balance >= max_fee >= charge.
        let after = balance.saturating_sub(charge);
        self.set_balance_direct(&tx.fee_payer, &NOOS_ASSET, after, &mut delta);
        if let Some(mut acct) = self.get_account(&tx.fee_payer) {
            acct.nonce = acct.nonce.saturating_add(1);
            let bytes = acct.encode_canonical();
            self.accounts.insert(tx.fee_payer, bytes.clone());
            delta.insert((TreeId::Accounts, tx.fee_payer, None), Some(bytes));
        }
        let receipt = ReceiptV1 {
            txid: *txid,
            status: code.status(),
            fee_charged: charge,
            resources_used: ResourceVector {
                bytes: encoded_len,
                ..ResourceVector::default()
            },
        };
        let receipt_bytes = receipt.encode_canonical();
        self.receipts.insert(*txid, receipt_bytes.clone());
        delta.insert((TreeId::Receipts, *txid, None), Some(receipt_bytes));
        ApplyOutcome::Failed {
            receipt,
            delta: StateDelta::from_map(delta),
            code,
        }
    }

    /// Atomic overlay commit: apply every staged write in canonical order
    /// and emit the ordered delta.
    fn commit_overlay(&mut self, ov: Overlay) -> StateDelta {
        let mut delta = BTreeMap::new();
        for (key, value) in ov.notes {
            apply_write(&mut self.notes, TreeId::Notes, key, value, &mut delta);
        }
        for (key, value) in ov.nullifiers {
            apply_write(
                &mut self.nullifiers,
                TreeId::Nullifiers,
                key,
                value,
                &mut delta,
            );
        }
        for (key, value) in ov.accounts {
            apply_write(&mut self.accounts, TreeId::Accounts, key, value, &mut delta);
        }
        for (key, value) in ov.objects {
            apply_write(&mut self.objects, TreeId::Objects, key, value, &mut delta);
        }
        for (key, value) in ov.receipts {
            apply_write(&mut self.receipts, TreeId::Receipts, key, value, &mut delta);
        }
        for (key, value) in ov.params {
            apply_write(&mut self.params, TreeId::Params, key, value, &mut delta);
        }
        // Balances last: they refresh account records deterministically.
        for ((account, asset), amount) in ov.balances {
            self.set_balance_direct(&account, &asset, amount, &mut delta);
        }
        StateDelta::from_map(delta)
    }
}

// ---------------------------------------------------------------------------
// Overlay read-through helpers (free functions to keep borrows narrow)
// ---------------------------------------------------------------------------

fn overlay_object(ov: &Overlay, base: &LumenLedger, id: &Hash32) -> Option<Vec<u8>> {
    match ov.objects.get(id) {
        Some(Some(bytes)) => Some(bytes.clone()),
        Some(None) => None,
        None => base.objects.get(id).map(<[u8]>::to_vec),
    }
}

fn overlay_account(ov: &Overlay, base: &LumenLedger, id: &Hash32) -> Option<Vec<u8>> {
    match ov.accounts.get(id) {
        Some(Some(bytes)) => Some(bytes.clone()),
        Some(None) => None,
        None => base.accounts.get(id).map(<[u8]>::to_vec),
    }
}

fn overlay_param(ov: &Overlay, base: &LumenLedger, key: &Hash32) -> Option<Vec<u8>> {
    match ov.params.get(key) {
        Some(Some(bytes)) => Some(bytes.clone()),
        Some(None) => None,
        None => base.params.get(key).map(<[u8]>::to_vec),
    }
}

fn overlay_balance(ov: &Overlay, base: &LumenLedger, account: &Hash32, asset: &Hash32) -> u128 {
    match ov.balances.get(&(*account, *asset)) {
        Some(amount) => *amount,
        None => base.balance(account, asset),
    }
}

fn apply_write(
    tree: &mut Smt,
    id: TreeId,
    key: Hash32,
    value: Option<Vec<u8>>,
    delta: &mut DeltaMap,
) {
    match &value {
        Some(bytes) => {
            tree.insert(key, bytes.clone());
        }
        None => {
            tree.remove(&key);
        }
    }
    delta.insert((id, key, None), value);
}

fn add_flow(
    flows: &mut BTreeMap<Hash32, u128>,
    asset: &Hash32,
    amount: u128,
) -> Result<(), FailCode> {
    let entry = flows.entry(*asset).or_insert(0);
    *entry = entry.checked_add(amount).ok_or(FailCode::Overflow)?;
    Ok(())
}

/// True when `key`'s zero-padded ASCII name starts with `prefix`.
fn key_has_prefix(key: &Hash32, prefix: &str) -> bool {
    let p = prefix.as_bytes();
    p.len() <= 32 && &key[..p.len()] == p
}

/// True when the slice declares any key twice (O(n log n), deterministic).
fn has_duplicates(keys: &[Hash32]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    keys.iter().any(|k| !seen.insert(*k))
}

/// Balance leaf value: u128 little-endian, exactly 16 bytes (frozen).
fn encode_amount(amount: u128) -> Vec<u8> {
    amount.to_le_bytes().to_vec()
}

fn decode_amount(bytes: &[u8]) -> u128 {
    let mut buf = [0u8; 16];
    let n = bytes.len().min(16);
    buf[..n].copy_from_slice(&bytes[..n]);
    u128::from_le_bytes(buf)
}
