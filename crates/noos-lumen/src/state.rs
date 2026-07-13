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
    agent_private_payment_schema_root, agent_private_payment_scope, asset_id as derive_asset_id,
    compute_job_id as derive_compute_job_id, debt_position_id as derive_debt_position_id,
    lending_market_id as derive_lending_market_id,
    liquidity_position_id as derive_liquidity_position_id, oracle_feed_id as derive_oracle_feed_id,
    oracle_report_id as derive_oracle_report_id, pool_id as derive_pool_id,
    private_payment_id as derive_private_payment_id, private_recipient_commitment,
    stable_asset_id as derive_stable_asset_id, witness_root as derive_witness_root, AccessEntry,
    AccountV1, ActionV1, AssetV1, BoundedBytes, CapabilityGrantV1, ComputeJobV1, ComputeWorkerV1,
    DebtPositionV1, FeatureControlV1, LendingMarketV1, LiquidityPositionV1, NoteV1, ObjectV1,
    OptionalHash32, OracleFeedV1, OracleReportV1, ParamRecordV1, PendingParamV1, PoolV1,
    PrivatePaymentV1, ReceiptV1, ResourceVector, StableAssetV1, TransactionV1,
    TransactionWitnessesV1,
};
use crate::smt::Smt;
use crate::Hash32;

/// NOOS asset id: the zero hash (frozen, lumen-v1.md §3.2).
pub const NOOS_ASSET: Hash32 = [0u8; 32];
/// Native AMM bounds keep every multiplication inside `u128`.
pub const MAX_POOL_QUANTITY: u128 = u64::MAX as u128;
/// Permanently unowned shares prevent complete reserve withdrawal.
pub const MINIMUM_LIQUIDITY: u128 = 1_000;
/// Oracle price scale: quote base units per collateral base unit.
pub const ORACLE_SCALE: u128 = 1_000_000_000;
pub const MAX_ORACLE_CONFIDENCE_BPS: u16 = 1_000;
pub const MAX_CREDIT_QUANTITY: u128 = u64::MAX as u128;
pub const MAX_PRIVATE_PAYMENT_LIFETIME: u64 = 100_000;

fn integer_sqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut x = value;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = x
            .saturating_add(value.checked_div(x).unwrap_or(u128::MAX))
            .checked_div(2)
            .unwrap_or(u128::MAX);
    }
    x
}

fn ceil_mul_div(a: u128, b: u128, denominator: u128) -> Result<u128, FailCode> {
    if denominator == 0 {
        return Err(FailCode::PostconditionFailed);
    }
    a.checked_mul(b)
        .map(|value| value.div_ceil(denominator))
        .ok_or(FailCode::Overflow)
}

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

/// Fail-closed genesis installation errors. Genesis is validated in full
/// before any state is written so a rejected configuration leaves an empty
/// ledger unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisError {
    DuplicateAccount,
    DuplicateBalance,
    InvalidIssuance,
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
    /// NOOS present in the unique genesis account allocation set.
    genesis_issued: u128,
    /// Cumulative schedule emission after genesis. This is deliberately
    /// separate from `genesis_issued`; the cap applies to their checked sum.
    emission_minted: u128,
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
    pub fn genesis_issued(&self) -> u128 {
        self.genesis_issued
    }

    /// Emission-only amount minted after genesis.
    #[must_use]
    pub fn emission_minted(&self) -> u128 {
        self.emission_minted
    }

    /// Total NOOS ever issued: genesis allocation plus scheduled emission.
    #[must_use]
    pub fn total_issued(&self) -> u128 {
        self.genesis_issued.saturating_add(self.emission_minted)
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
    pub fn get_asset(&self, id: &Hash32) -> Option<AssetV1> {
        self.objects
            .get(id)
            .and_then(|bytes| AssetV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn get_pool(&self, id: &Hash32) -> Option<PoolV1> {
        self.objects
            .get(id)
            .and_then(|bytes| PoolV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn get_liquidity_position(
        &self,
        pool: &Hash32,
        provider: &Hash32,
    ) -> Option<LiquidityPositionV1> {
        self.objects
            .get(&derive_liquidity_position_id(pool, provider))
            .and_then(|bytes| LiquidityPositionV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn get_oracle_feed(&self, id: &Hash32) -> Option<OracleFeedV1> {
        self.objects
            .get(id)
            .and_then(|bytes| OracleFeedV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn oracle_feeds(&self) -> Vec<OracleFeedV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| OracleFeedV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn oracle_reports(&self) -> Vec<OracleReportV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| OracleReportV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn get_lending_market(&self, id: &Hash32) -> Option<LendingMarketV1> {
        self.objects
            .get(id)
            .and_then(|bytes| LendingMarketV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn lending_markets(&self) -> Vec<LendingMarketV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| LendingMarketV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn stable_assets(&self) -> Vec<StableAssetV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| StableAssetV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn get_debt_position(&self, market: &Hash32, owner: &Hash32) -> Option<DebtPositionV1> {
        self.objects
            .get(&derive_debt_position_id(market, owner))
            .and_then(|bytes| DebtPositionV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn debt_positions(&self) -> Vec<DebtPositionV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| DebtPositionV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn private_payments(&self) -> Vec<PrivatePaymentV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| PrivatePaymentV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn get_private_payment(&self, id: &Hash32) -> Option<PrivatePaymentV1> {
        self.objects
            .get(id)
            .and_then(|bytes| PrivatePaymentV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn assets(&self) -> Vec<AssetV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| AssetV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn pools(&self) -> Vec<PoolV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| PoolV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn liquidity_positions(&self) -> Vec<LiquidityPositionV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| LiquidityPositionV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn get_compute_worker(&self, id: &Hash32) -> Option<ComputeWorkerV1> {
        self.objects
            .get(id)
            .and_then(|bytes| ComputeWorkerV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn get_compute_job(&self, id: &Hash32) -> Option<ComputeJobV1> {
        self.objects
            .get(id)
            .and_then(|bytes| ComputeJobV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn compute_workers(&self) -> Vec<ComputeWorkerV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| ComputeWorkerV1::decode_canonical(bytes).ok())
            .collect()
    }

    #[must_use]
    pub fn compute_jobs(&self) -> Vec<ComputeJobV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| ComputeJobV1::decode_canonical(bytes).ok())
            .collect()
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

    fn issuance_fits_issued_supply(&self, issuance: &IssuanceParamsV1) -> bool {
        let Ok(scheduled) = issuance.total_scheduled() else {
            return false;
        };
        let Ok(remaining) = issuance.total_scheduled_after(self.last_emission_height) else {
            return false;
        };
        issuance.validate().is_ok()
            && issuance.max_supply >= self.total_issued()
            && self
                .genesis_issued
                .checked_add(scheduled)
                .is_some_and(|maximum| maximum <= issuance.max_supply)
            && self
                .total_issued()
                .checked_add(remaining)
                .is_some_and(|maximum| maximum <= issuance.max_supply)
    }

    // -- genesis ------------------------------------------------------------

    /// Install a genesis params set and initial accounts. Direct writes: this
    /// is the only path that seeds state outside a transaction.
    pub fn install_genesis(&mut self, config: &GenesisConfig<'_>) -> Result<(), GenesisError> {
        config
            .issuance
            .validate()
            .map_err(|_| GenesisError::InvalidIssuance)?;
        config
            .shares
            .validate()
            .map_err(|_| GenesisError::InvalidIssuance)?;

        let mut seen_accounts = std::collections::BTreeSet::new();
        let mut genesis_issued = 0u128;
        for (account, balances) in config.accounts {
            if !seen_accounts.insert(account.account_id) {
                return Err(GenesisError::DuplicateAccount);
            }
            let mut seen_assets = std::collections::BTreeSet::new();
            for (asset, amount) in balances {
                if !seen_assets.insert(*asset) {
                    return Err(GenesisError::DuplicateBalance);
                }
                if *asset == NOOS_ASSET {
                    genesis_issued = genesis_issued
                        .checked_add(*amount)
                        .ok_or(GenesisError::Overflow)?;
                }
            }
        }
        let scheduled = config
            .issuance
            .total_scheduled()
            .map_err(|_| GenesisError::Overflow)?;
        let maximum_issuance = genesis_issued
            .checked_add(scheduled)
            .ok_or(GenesisError::Overflow)?;
        if maximum_issuance > config.issuance.max_supply {
            return Err(GenesisError::InvalidIssuance);
        }

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
        self.genesis_issued = genesis_issued;
        self.emission_minted = 0;
        self.last_emission_height = 0;
        Ok(())
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
        let new_emission_minted = self
            .emission_minted
            .checked_add(emission)
            .ok_or(EmissionError::Overflow)?;
        let new_total_issued = self
            .genesis_issued
            .checked_add(new_emission_minted)
            .ok_or(EmissionError::Overflow)?;
        if new_total_issued > issuance.max_supply {
            return Err(EmissionError::Overflow);
        }
        // Aggregate aliases before touching state (the same account may fill
        // multiple recipient roles), then preflight every resulting balance.
        // This makes overflow rejection atomic instead of leaving an earlier
        // recipient credited when a later recipient overflows.
        let mut credits = BTreeMap::<Hash32, u128>::new();
        for (id, amount) in [
            (proposer, split.proposer),
            (witness_pool, split.witness),
            (treasury, split.treasury),
        ] {
            if amount == 0 {
                continue;
            }
            let prior = credits.get(id).copied().unwrap_or(0);
            credits.insert(
                *id,
                prior.checked_add(amount).ok_or(EmissionError::Overflow)?,
            );
        }
        let next_balances = credits
            .iter()
            .map(|(id, amount)| {
                self.balance(id, &NOOS_ASSET)
                    .checked_add(*amount)
                    .map(|next| (*id, next))
                    .ok_or(EmissionError::Overflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut delta = BTreeMap::new();
        for (id, next) in next_balances {
            self.set_balance_direct(&id, &NOOS_ASSET, next, &mut delta);
        }
        self.emission_minted = new_emission_minted;
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
                if *key == param_key(PARAM_ISSUANCE) {
                    let Ok(candidate) =
                        IssuanceParamsV1::decode_canonical(pending.value.as_slice())
                    else {
                        continue;
                    };
                    if !self.issuance_fits_issued_supply(&candidate) {
                        continue;
                    }
                }
                if *key == param_key(PARAM_SHARES) {
                    let Ok(candidate) =
                        EmissionSharesV1::decode_canonical(pending.value.as_slice())
                    else {
                        continue;
                    };
                    if candidate.validate().is_err() {
                        continue;
                    }
                }
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
                    new_value,
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
                    if *key == param_key(PARAM_ISSUANCE) {
                        let candidate = IssuanceParamsV1::decode_canonical(new_value.as_slice())
                            .map_err(|_| RejectReason::GovernanceDenied)?;
                        if !self.issuance_fits_issued_supply(&candidate) {
                            return Err(RejectReason::GovernanceDenied);
                        }
                    }
                    if *key == param_key(PARAM_SHARES) {
                        let candidate = EmissionSharesV1::decode_canonical(new_value.as_slice())
                            .map_err(|_| RejectReason::GovernanceDenied)?;
                        candidate
                            .validate()
                            .map_err(|_| RejectReason::GovernanceDenied)?;
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
                ActionV1::CreateAsset { issuer, .. } if !signed(issuer) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::CreatePool { provider, .. }
                | ActionV1::AddLiquidity { provider, .. }
                | ActionV1::RemoveLiquidity { provider, .. }
                    if !signed(provider) =>
                {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::SwapExactIn { trader, .. } if !signed(trader) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::CreateOracleFeed { .. } | ActionV1::CreateLendingMarket { .. }
                    if !gov_ok() =>
                {
                    return Err(RejectReason::GovernanceDenied);
                }
                ActionV1::SubmitOracleReport { reporter, .. } if !signed(reporter) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::DepositCollateral { owner, .. }
                | ActionV1::WithdrawCollateral { owner, .. }
                | ActionV1::BorrowStable { owner, .. }
                | ActionV1::RepayStable { owner, .. }
                    if !signed(owner) =>
                {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::LiquidatePosition { liquidator, .. } if !signed(liquidator) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::OpenPrivatePayment { payer, .. }
                | ActionV1::RefundPrivatePayment { payer, .. }
                    if !signed(payer) =>
                {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::ClaimPrivatePayment { recipient, .. } if !signed(recipient) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::OpenAgentPrivatePayment { agent, .. } if !signed(agent) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::RegisterComputeWorker { worker, .. }
                | ActionV1::ClaimComputeJob { worker, .. }
                | ActionV1::SubmitComputeResult { worker, .. }
                    if !signed(worker) =>
                {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::OpenComputeJob { requester, .. }
                | ActionV1::AcceptComputeResult { requester, .. }
                | ActionV1::CancelComputeJob { requester, .. }
                    if !signed(requester) =>
                {
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
                        // Ed25519 accounts are self-authenticating: the account
                        // id is the 32-byte verification key. Creating an empty
                        // recipient account during its first deposit makes a
                        // freshly derived wallet payable without a genesis or
                        // governance registration transaction. No authority is
                        // granted to the sender because later spends still
                        // require a signature under these exact public bytes.
                        let account = AccountV1 {
                            account_id: *account_id,
                            auth_descriptor: BoundedBytes::new(account_id.to_vec())
                                .ok_or(FailCode::PostconditionFailed)?,
                            nonce: 0,
                            liquid_balances_root: crate::smt::empty_root(crate::smt::DEPTH),
                            bond_refs_root: [0; 32],
                            metadata_commitment: [0; 32],
                            recovery_policy_root: [0; 32],
                        };
                        ov.accounts
                            .insert(*account_id, Some(account.encode_canonical()));
                        ov.write_count()?;
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
                ActionV1::CreateAsset {
                    issuer,
                    symbol,
                    name,
                    decimals,
                    total_supply,
                } => {
                    let symbol_valid = !symbol.as_slice().is_empty()
                        && symbol
                            .as_slice()
                            .iter()
                            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
                    if !symbol_valid
                        || name.as_slice().is_empty()
                        || std::str::from_utf8(name.as_slice()).is_err()
                        || *decimals > 18
                        || *total_supply == 0
                        || overlay_account(&ov, self, issuer).is_none()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let idx = u32::try_from(index).map_err(|_| FailCode::Overflow)?;
                    let id = derive_asset_id(txid, idx);
                    if id == NOOS_ASSET || overlay_object(&ov, self, &id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let asset = AssetV1 {
                        asset_id: id,
                        issuer: *issuer,
                        symbol: symbol.clone(),
                        name: name.clone(),
                        decimals: *decimals,
                        total_supply: *total_supply,
                    };
                    ov.objects.insert(id, Some(asset.encode_canonical()));
                    let current = overlay_balance(&ov, self, issuer, &id);
                    let next = current
                        .checked_add(*total_supply)
                        .ok_or(FailCode::Overflow)?;
                    ov.balances.insert((*issuer, id), next);
                    add_flow(&mut inflow, &id, *total_supply)?;
                    add_flow(&mut outflow, &id, *total_supply)?;
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::CreatePool {
                    provider,
                    asset_a,
                    asset_b,
                    amount_a,
                    amount_b,
                    fee_bps,
                } => {
                    if asset_a == asset_b
                        || *amount_a == 0
                        || *amount_b == 0
                        || *amount_a > MAX_POOL_QUANTITY
                        || *amount_b > MAX_POOL_QUANTITY
                        || *fee_bps > 100
                        || overlay_account(&ov, self, provider).is_none()
                        || (*asset_a != NOOS_ASSET
                            && AssetV1::decode_canonical(
                                &overlay_object(&ov, self, asset_a)
                                    .ok_or(FailCode::PostconditionFailed)?,
                            )
                            .is_err())
                        || (*asset_b != NOOS_ASSET
                            && AssetV1::decode_canonical(
                                &overlay_object(&ov, self, asset_b)
                                    .ok_or(FailCode::PostconditionFailed)?,
                            )
                            .is_err())
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let id = derive_pool_id(asset_a, asset_b);
                    if overlay_object(&ov, self, &id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let product = amount_a.checked_mul(*amount_b).ok_or(FailCode::Overflow)?;
                    let total_shares = integer_sqrt(product);
                    if total_shares <= MINIMUM_LIQUIDITY {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance_a = overlay_balance(&ov, self, provider, asset_a);
                    let balance_b = overlay_balance(&ov, self, provider, asset_b);
                    ov.balances.insert(
                        (*provider, *asset_a),
                        balance_a
                            .checked_sub(*amount_a)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.balances.insert(
                        (*provider, *asset_b),
                        balance_b
                            .checked_sub(*amount_b)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    let (asset_0, asset_1, reserve_0, reserve_1) = if asset_a < asset_b {
                        (*asset_a, *asset_b, *amount_a, *amount_b)
                    } else {
                        (*asset_b, *asset_a, *amount_b, *amount_a)
                    };
                    let pool = PoolV1 {
                        pool_id: id,
                        asset_0,
                        asset_1,
                        reserve_0,
                        reserve_1,
                        fee_bps: *fee_bps,
                        creator: *provider,
                        total_shares,
                    };
                    let position_id = derive_liquidity_position_id(&id, provider);
                    let position = LiquidityPositionV1 {
                        position_id,
                        pool_id: id,
                        provider: *provider,
                        shares: total_shares
                            .checked_sub(MINIMUM_LIQUIDITY)
                            .ok_or(FailCode::PostconditionFailed)?,
                    };
                    ov.objects.insert(id, Some(pool.encode_canonical()));
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::SwapExactIn {
                    trader,
                    pool_id,
                    asset_in,
                    amount_in,
                    min_amount_out,
                } => {
                    if *amount_in == 0
                        || *amount_in > MAX_POOL_QUANTITY
                        || overlay_account(&ov, self, trader).is_none()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let raw =
                        overlay_object(&ov, self, pool_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut pool = PoolV1::decode_canonical(&raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if pool.reserve_0 == 0
                        || pool.reserve_1 == 0
                        || pool.reserve_0 > MAX_POOL_QUANTITY
                        || pool.reserve_1 > MAX_POOL_QUANTITY
                        || pool.total_shares <= MINIMUM_LIQUIDITY
                        || pool.fee_bps > 100
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let old_product = pool
                        .reserve_0
                        .checked_mul(pool.reserve_1)
                        .ok_or(FailCode::Overflow)?;
                    let (reserve_in, reserve_out, asset_out, input_is_zero) =
                        if *asset_in == pool.asset_0 {
                            (pool.reserve_0, pool.reserve_1, pool.asset_1, true)
                        } else if *asset_in == pool.asset_1 {
                            (pool.reserve_1, pool.reserve_0, pool.asset_0, false)
                        } else {
                            return Err(FailCode::PostconditionFailed);
                        };
                    let effective = amount_in
                        .checked_mul(u128::from(10_000u16.saturating_sub(pool.fee_bps)))
                        .and_then(|value| value.checked_div(10_000))
                        .ok_or(FailCode::Overflow)?;
                    if effective == 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let amount_out = reserve_out
                        .checked_mul(effective)
                        .and_then(|value| value.checked_div(reserve_in.checked_add(effective)?))
                        .ok_or(FailCode::Overflow)?;
                    if amount_out == 0 || amount_out < *min_amount_out || amount_out >= reserve_out
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let input_balance = overlay_balance(&ov, self, trader, asset_in);
                    let output_balance = overlay_balance(&ov, self, trader, &asset_out);
                    ov.balances.insert(
                        (*trader, *asset_in),
                        input_balance
                            .checked_sub(*amount_in)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.balances.insert(
                        (*trader, asset_out),
                        output_balance
                            .checked_add(amount_out)
                            .ok_or(FailCode::Overflow)?,
                    );
                    if input_is_zero {
                        pool.reserve_0 = pool
                            .reserve_0
                            .checked_add(*amount_in)
                            .filter(|value| *value <= MAX_POOL_QUANTITY)
                            .ok_or(FailCode::Overflow)?;
                        pool.reserve_1 = pool
                            .reserve_1
                            .checked_sub(amount_out)
                            .ok_or(FailCode::Overflow)?;
                    } else {
                        pool.reserve_1 = pool
                            .reserve_1
                            .checked_add(*amount_in)
                            .filter(|value| *value <= MAX_POOL_QUANTITY)
                            .ok_or(FailCode::Overflow)?;
                        pool.reserve_0 = pool
                            .reserve_0
                            .checked_sub(amount_out)
                            .ok_or(FailCode::Overflow)?;
                    }
                    let new_product = pool
                        .reserve_0
                        .checked_mul(pool.reserve_1)
                        .ok_or(FailCode::Overflow)?;
                    if new_product < old_product {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects.insert(*pool_id, Some(pool.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::AddLiquidity {
                    provider,
                    pool_id,
                    max_amount_0,
                    max_amount_1,
                    min_shares,
                } => {
                    if *max_amount_0 == 0
                        || *max_amount_1 == 0
                        || *max_amount_0 > MAX_POOL_QUANTITY
                        || *max_amount_1 > MAX_POOL_QUANTITY
                        || overlay_account(&ov, self, provider).is_none()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let raw =
                        overlay_object(&ov, self, pool_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut pool = PoolV1::decode_canonical(&raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if pool.reserve_0 == 0
                        || pool.reserve_1 == 0
                        || pool.total_shares <= MINIMUM_LIQUIDITY
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let shares_0 = max_amount_0
                        .checked_mul(pool.total_shares)
                        .and_then(|value| value.checked_div(pool.reserve_0))
                        .ok_or(FailCode::Overflow)?;
                    let shares_1 = max_amount_1
                        .checked_mul(pool.total_shares)
                        .and_then(|value| value.checked_div(pool.reserve_1))
                        .ok_or(FailCode::Overflow)?;
                    let shares = shares_0.min(shares_1);
                    if shares == 0 || shares < *min_shares {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let amount_0 = ceil_mul_div(shares, pool.reserve_0, pool.total_shares)?;
                    let amount_1 = ceil_mul_div(shares, pool.reserve_1, pool.total_shares)?;
                    if amount_0 == 0
                        || amount_1 == 0
                        || amount_0 > *max_amount_0
                        || amount_1 > *max_amount_1
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance_0 = overlay_balance(&ov, self, provider, &pool.asset_0);
                    let balance_1 = overlay_balance(&ov, self, provider, &pool.asset_1);
                    ov.balances.insert(
                        (*provider, pool.asset_0),
                        balance_0
                            .checked_sub(amount_0)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.balances.insert(
                        (*provider, pool.asset_1),
                        balance_1
                            .checked_sub(amount_1)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    pool.reserve_0 = pool
                        .reserve_0
                        .checked_add(amount_0)
                        .filter(|value| *value <= MAX_POOL_QUANTITY)
                        .ok_or(FailCode::Overflow)?;
                    pool.reserve_1 = pool
                        .reserve_1
                        .checked_add(amount_1)
                        .filter(|value| *value <= MAX_POOL_QUANTITY)
                        .ok_or(FailCode::Overflow)?;
                    pool.total_shares = pool
                        .total_shares
                        .checked_add(shares)
                        .filter(|value| *value <= MAX_POOL_QUANTITY)
                        .ok_or(FailCode::Overflow)?;
                    let position_id = derive_liquidity_position_id(pool_id, provider);
                    let mut position = overlay_object(&ov, self, &position_id)
                        .map(|bytes| LiquidityPositionV1::decode_canonical(&bytes))
                        .transpose()
                        .map_err(|_| FailCode::PostconditionFailed)?
                        .unwrap_or(LiquidityPositionV1 {
                            position_id,
                            pool_id: *pool_id,
                            provider: *provider,
                            shares: 0,
                        });
                    if position.pool_id != *pool_id || position.provider != *provider {
                        return Err(FailCode::PostconditionFailed);
                    }
                    position.shares = position
                        .shares
                        .checked_add(shares)
                        .ok_or(FailCode::Overflow)?;
                    ov.objects.insert(*pool_id, Some(pool.encode_canonical()));
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    for _ in 0..5 {
                        ov.write_count()?;
                    }
                }
                ActionV1::RemoveLiquidity {
                    provider,
                    pool_id,
                    shares,
                    min_amount_0,
                    min_amount_1,
                } => {
                    if *shares == 0 || overlay_account(&ov, self, provider).is_none() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let raw =
                        overlay_object(&ov, self, pool_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut pool = PoolV1::decode_canonical(&raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let position_id = derive_liquidity_position_id(pool_id, provider);
                    let position_raw = overlay_object(&ov, self, &position_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut position = LiquidityPositionV1::decode_canonical(&position_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if position.pool_id != *pool_id
                        || position.provider != *provider
                        || position.shares < *shares
                        || pool.total_shares <= *shares
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let amount_0 = pool
                        .reserve_0
                        .checked_mul(*shares)
                        .and_then(|value| value.checked_div(pool.total_shares))
                        .ok_or(FailCode::Overflow)?;
                    let amount_1 = pool
                        .reserve_1
                        .checked_mul(*shares)
                        .and_then(|value| value.checked_div(pool.total_shares))
                        .ok_or(FailCode::Overflow)?;
                    if amount_0 == 0
                        || amount_1 == 0
                        || amount_0 < *min_amount_0
                        || amount_1 < *min_amount_1
                        || amount_0 >= pool.reserve_0
                        || amount_1 >= pool.reserve_1
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance_0 = overlay_balance(&ov, self, provider, &pool.asset_0);
                    let balance_1 = overlay_balance(&ov, self, provider, &pool.asset_1);
                    ov.balances.insert(
                        (*provider, pool.asset_0),
                        balance_0.checked_add(amount_0).ok_or(FailCode::Overflow)?,
                    );
                    ov.balances.insert(
                        (*provider, pool.asset_1),
                        balance_1.checked_add(amount_1).ok_or(FailCode::Overflow)?,
                    );
                    pool.reserve_0 = pool
                        .reserve_0
                        .checked_sub(amount_0)
                        .ok_or(FailCode::Overflow)?;
                    pool.reserve_1 = pool
                        .reserve_1
                        .checked_sub(amount_1)
                        .ok_or(FailCode::Overflow)?;
                    pool.total_shares = pool
                        .total_shares
                        .checked_sub(*shares)
                        .ok_or(FailCode::Overflow)?;
                    position.shares = position
                        .shares
                        .checked_sub(*shares)
                        .ok_or(FailCode::Overflow)?;
                    ov.objects.insert(*pool_id, Some(pool.encode_canonical()));
                    ov.objects.insert(
                        position_id,
                        (position.shares != 0).then(|| position.encode_canonical()),
                    );
                    for _ in 0..5 {
                        ov.write_count()?;
                    }
                }
                ActionV1::CreateOracleFeed {
                    base_asset,
                    quote_asset,
                    reporter_0,
                    reporter_1,
                    reporter_2,
                    max_age_blocks,
                } => {
                    let reporters = [*reporter_0, *reporter_1, *reporter_2];
                    if base_asset == quote_asset
                        || reporters[0] == reporters[1]
                        || reporters[0] == reporters[2]
                        || reporters[1] == reporters[2]
                        || !(1..=10_000).contains(max_age_blocks)
                        || reporters
                            .iter()
                            .any(|reporter| overlay_account(&ov, self, reporter).is_none())
                        || (*base_asset != NOOS_ASSET
                            && AssetV1::decode_canonical(
                                &overlay_object(&ov, self, base_asset)
                                    .ok_or(FailCode::PostconditionFailed)?,
                            )
                            .is_err())
                        || (*quote_asset != NOOS_ASSET
                            && AssetV1::decode_canonical(
                                &overlay_object(&ov, self, quote_asset)
                                    .ok_or(FailCode::PostconditionFailed)?,
                            )
                            .is_err())
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let id = derive_oracle_feed_id(base_asset, quote_asset);
                    if overlay_object(&ov, self, &id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let feed = OracleFeedV1 {
                        feed_id: id,
                        base_asset: *base_asset,
                        quote_asset: *quote_asset,
                        reporter_0: *reporter_0,
                        reporter_1: *reporter_1,
                        reporter_2: *reporter_2,
                        max_age_blocks: *max_age_blocks,
                    };
                    ov.objects.insert(id, Some(feed.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::SubmitOracleReport {
                    reporter,
                    feed_id,
                    price_q9,
                    confidence_bps,
                    sequence,
                    observed_height,
                } => {
                    let raw =
                        overlay_object(&ov, self, feed_id).ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&raw, feed_id)?;
                    if ![feed.reporter_0, feed.reporter_1, feed.reporter_2].contains(reporter)
                        || *price_q9 == 0
                        || *price_q9 > MAX_CREDIT_QUANTITY
                        || *confidence_bps > MAX_ORACLE_CONFIDENCE_BPS
                        || *sequence == 0
                        || *observed_height > ctx.height
                        || ctx.height.saturating_sub(*observed_height) > feed.max_age_blocks
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let report_id = derive_oracle_report_id(feed_id, reporter);
                    if let Some(previous) = overlay_object(&ov, self, &report_id) {
                        let previous = OracleReportV1::decode_canonical(&previous)
                            .map_err(|_| FailCode::PostconditionFailed)?;
                        if *sequence <= previous.sequence
                            || *observed_height < previous.observed_height
                        {
                            return Err(FailCode::PostconditionFailed);
                        }
                    }
                    let report = OracleReportV1 {
                        report_id,
                        feed_id: *feed_id,
                        reporter: *reporter,
                        price_q9: *price_q9,
                        confidence_bps: *confidence_bps,
                        sequence: *sequence,
                        observed_height: *observed_height,
                    };
                    ov.objects
                        .insert(report_id, Some(report.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::CreateLendingMarket {
                    collateral_asset,
                    oracle_feed_id,
                    symbol,
                    name,
                    decimals,
                    collateral_factor_bps,
                    liquidation_threshold_bps,
                    liquidation_bonus_bps,
                    debt_ceiling,
                    min_debt,
                } => {
                    let symbol_valid = !symbol.as_slice().is_empty()
                        && symbol
                            .as_slice()
                            .iter()
                            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
                    let feed_raw = overlay_object(&ov, self, oracle_feed_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&feed_raw, oracle_feed_id)?;
                    if !symbol_valid
                        || name.as_slice().is_empty()
                        || std::str::from_utf8(name.as_slice()).is_err()
                        || *decimals > 18
                        || feed.base_asset != *collateral_asset
                        || !(1_000..=8_000).contains(collateral_factor_bps)
                        || *liquidation_threshold_bps <= *collateral_factor_bps
                        || *liquidation_threshold_bps > 9_000
                        || *liquidation_bonus_bps > 1_000
                        || *debt_ceiling == 0
                        || *debt_ceiling > MAX_CREDIT_QUANTITY
                        || *min_debt == 0
                        || *min_debt > *debt_ceiling
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_id = derive_lending_market_id(collateral_asset, oracle_feed_id);
                    let stable_id = derive_stable_asset_id(&market_id);
                    if overlay_object(&ov, self, &market_id).is_some()
                        || overlay_object(&ov, self, &stable_id).is_some()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market = LendingMarketV1 {
                        market_id,
                        collateral_asset: *collateral_asset,
                        stable_asset: stable_id,
                        oracle_feed_id: *oracle_feed_id,
                        collateral_factor_bps: *collateral_factor_bps,
                        liquidation_threshold_bps: *liquidation_threshold_bps,
                        liquidation_bonus_bps: *liquidation_bonus_bps,
                        debt_ceiling: *debt_ceiling,
                        min_debt: *min_debt,
                        total_debt: 0,
                    };
                    let stable = StableAssetV1 {
                        asset_id: stable_id,
                        market_id,
                        symbol: symbol.clone(),
                        name: name.clone(),
                        decimals: *decimals,
                        minted_supply: 0,
                        kind: 1,
                    };
                    ov.objects
                        .insert(market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable_id, Some(stable.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::DepositCollateral {
                    owner,
                    market_id,
                    amount,
                } => {
                    if *amount == 0 || *amount > MAX_CREDIT_QUANTITY {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let market = decode_lending_market(&market_raw, market_id)?;
                    let balance = overlay_balance(&ov, self, owner, &market.collateral_asset);
                    ov.balances.insert(
                        (*owner, market.collateral_asset),
                        balance
                            .checked_sub(*amount)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    let position_id = derive_debt_position_id(market_id, owner);
                    let mut position = overlay_object(&ov, self, &position_id)
                        .map(|bytes| DebtPositionV1::decode_canonical(&bytes))
                        .transpose()
                        .map_err(|_| FailCode::PostconditionFailed)?
                        .unwrap_or(DebtPositionV1 {
                            position_id,
                            market_id: *market_id,
                            owner: *owner,
                            collateral: 0,
                            debt: 0,
                        });
                    if position.position_id != position_id
                        || position.market_id != *market_id
                        || position.owner != *owner
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    position.collateral = position
                        .collateral
                        .checked_add(*amount)
                        .filter(|value| *value <= MAX_CREDIT_QUANTITY)
                        .ok_or(FailCode::Overflow)?;
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::WithdrawCollateral {
                    owner,
                    market_id,
                    amount,
                } => {
                    if *amount == 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let market = decode_lending_market(&market_raw, market_id)?;
                    let position_id = derive_debt_position_id(market_id, owner);
                    let position_raw = overlay_object(&ov, self, &position_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut position = decode_debt_position(&position_raw, market_id, owner)?;
                    position.collateral = position
                        .collateral
                        .checked_sub(*amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    if position.debt > 0 {
                        let feed_raw = overlay_object(&ov, self, &market.oracle_feed_id)
                            .ok_or(FailCode::PostconditionFailed)?;
                        let feed = decode_oracle_feed(&feed_raw, &market.oracle_feed_id)?;
                        let price = conservative_oracle_price(&mut ov, self, &feed, ctx.height)?;
                        let value = collateral_value(position.collateral, price)?;
                        if position.debt > mul_bps(value, market.collateral_factor_bps)? {
                            return Err(FailCode::PostconditionFailed);
                        }
                    }
                    let balance = overlay_balance(&ov, self, owner, &market.collateral_asset);
                    ov.balances.insert(
                        (*owner, market.collateral_asset),
                        balance.checked_add(*amount).ok_or(FailCode::Overflow)?,
                    );
                    ov.objects.insert(
                        position_id,
                        (position.collateral != 0 || position.debt != 0)
                            .then(|| position.encode_canonical()),
                    );
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::BorrowStable {
                    owner,
                    market_id,
                    amount,
                } => {
                    if *amount == 0 || *amount > MAX_CREDIT_QUANTITY {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut market = decode_lending_market(&market_raw, market_id)?;
                    let stable_raw = overlay_object(&ov, self, &market.stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut stable = decode_stable_asset(&stable_raw, &market)?;
                    let position_id = derive_debt_position_id(market_id, owner);
                    let position_raw = overlay_object(&ov, self, &position_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut position = decode_debt_position(&position_raw, market_id, owner)?;
                    let feed_raw = overlay_object(&ov, self, &market.oracle_feed_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&feed_raw, &market.oracle_feed_id)?;
                    let price = conservative_oracle_price(&mut ov, self, &feed, ctx.height)?;
                    let new_debt = position
                        .debt
                        .checked_add(*amount)
                        .ok_or(FailCode::Overflow)?;
                    let new_total = market
                        .total_debt
                        .checked_add(*amount)
                        .filter(|value| *value <= market.debt_ceiling)
                        .ok_or(FailCode::Overflow)?;
                    if new_debt < market.min_debt
                        || new_debt
                            > mul_bps(
                                collateral_value(position.collateral, price)?,
                                market.collateral_factor_bps,
                            )?
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance = overlay_balance(&ov, self, owner, &market.stable_asset);
                    ov.balances.insert(
                        (*owner, market.stable_asset),
                        balance.checked_add(*amount).ok_or(FailCode::Overflow)?,
                    );
                    position.debt = new_debt;
                    market.total_debt = new_total;
                    stable.minted_supply = stable
                        .minted_supply
                        .checked_add(*amount)
                        .ok_or(FailCode::Overflow)?;
                    if stable.minted_supply != market.total_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    ov.objects
                        .insert(*market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable.asset_id, Some(stable.encode_canonical()));
                    for _ in 0..4 {
                        ov.write_count()?;
                    }
                }
                ActionV1::RepayStable {
                    owner,
                    market_id,
                    amount,
                } => {
                    if *amount == 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut market = decode_lending_market(&market_raw, market_id)?;
                    let stable_raw = overlay_object(&ov, self, &market.stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut stable = decode_stable_asset(&stable_raw, &market)?;
                    let position_id = derive_debt_position_id(market_id, owner);
                    let position_raw = overlay_object(&ov, self, &position_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut position = decode_debt_position(&position_raw, market_id, owner)?;
                    let remaining = position
                        .debt
                        .checked_sub(*amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    if remaining != 0 && remaining < market.min_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance = overlay_balance(&ov, self, owner, &market.stable_asset);
                    ov.balances.insert(
                        (*owner, market.stable_asset),
                        balance
                            .checked_sub(*amount)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    position.debt = remaining;
                    market.total_debt = market
                        .total_debt
                        .checked_sub(*amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    stable.minted_supply = stable
                        .minted_supply
                        .checked_sub(*amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    if stable.minted_supply != market.total_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    ov.objects
                        .insert(*market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable.asset_id, Some(stable.encode_canonical()));
                    for _ in 0..4 {
                        ov.write_count()?;
                    }
                }
                ActionV1::LiquidatePosition {
                    liquidator,
                    market_id,
                    owner,
                    repay_amount,
                    min_collateral_out,
                } => {
                    if *repay_amount == 0 || liquidator == owner {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut market = decode_lending_market(&market_raw, market_id)?;
                    let stable_raw = overlay_object(&ov, self, &market.stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut stable = decode_stable_asset(&stable_raw, &market)?;
                    let position_id = derive_debt_position_id(market_id, owner);
                    let position_raw = overlay_object(&ov, self, &position_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut position = decode_debt_position(&position_raw, market_id, owner)?;
                    let feed_raw = overlay_object(&ov, self, &market.oracle_feed_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&feed_raw, &market.oracle_feed_id)?;
                    let price = conservative_oracle_price(&mut ov, self, &feed, ctx.height)?;
                    let value = collateral_value(position.collateral, price)?;
                    if position.debt <= mul_bps(value, market.liquidation_threshold_bps)? {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let max_repay = if position.debt <= market.min_debt.saturating_mul(2) {
                        position.debt
                    } else {
                        position.debt / 2
                    };
                    if *repay_amount > max_repay {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let remaining = position
                        .debt
                        .checked_sub(*repay_amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    if remaining != 0 && remaining < market.min_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let bonus = 10_000u128
                        .checked_add(u128::from(market.liquidation_bonus_bps))
                        .ok_or(FailCode::Overflow)?;
                    let numerator = repay_amount
                        .checked_mul(ORACLE_SCALE)
                        .and_then(|value| value.checked_mul(bonus))
                        .ok_or(FailCode::Overflow)?;
                    let denominator = price.checked_mul(10_000).ok_or(FailCode::Overflow)?;
                    let collateral_out = numerator.div_ceil(denominator);
                    if collateral_out == 0
                        || collateral_out < *min_collateral_out
                        || collateral_out > position.collateral
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let stable_balance =
                        overlay_balance(&ov, self, liquidator, &market.stable_asset);
                    let collateral_balance =
                        overlay_balance(&ov, self, liquidator, &market.collateral_asset);
                    ov.balances.insert(
                        (*liquidator, market.stable_asset),
                        stable_balance
                            .checked_sub(*repay_amount)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.balances.insert(
                        (*liquidator, market.collateral_asset),
                        collateral_balance
                            .checked_add(collateral_out)
                            .ok_or(FailCode::Overflow)?,
                    );
                    position.debt = remaining;
                    position.collateral = position
                        .collateral
                        .checked_sub(collateral_out)
                        .ok_or(FailCode::PostconditionFailed)?;
                    market.total_debt = market
                        .total_debt
                        .checked_sub(*repay_amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    stable.minted_supply = stable
                        .minted_supply
                        .checked_sub(*repay_amount)
                        .ok_or(FailCode::PostconditionFailed)?;
                    if stable.minted_supply != market.total_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    ov.objects
                        .insert(*market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable.asset_id, Some(stable.encode_canonical()));
                    for _ in 0..5 {
                        ov.write_count()?;
                    }
                }
                ActionV1::OpenPrivatePayment {
                    payer,
                    stable_asset,
                    recipient_commitment,
                    memo_commitment,
                    reference_commitment,
                    amount,
                    expiry_height,
                    payment_kind,
                } => {
                    let max_expiry = ctx
                        .height
                        .checked_add(MAX_PRIVATE_PAYMENT_LIFETIME)
                        .ok_or(FailCode::Overflow)?;
                    if *amount == 0
                        || *amount > MAX_CREDIT_QUANTITY
                        || *expiry_height <= ctx.height
                        || *expiry_height > max_expiry
                        || *payment_kind > PrivatePaymentV1::KIND_COMMERCE
                        || *recipient_commitment == [0; 32]
                        || *memo_commitment == [0; 32]
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let stable_raw = overlay_object(&ov, self, stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let stable = StableAssetV1::decode_canonical(&stable_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if stable.kind != 1 || stable.asset_id != *stable_asset {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let payer_balance = overlay_balance(&ov, self, payer, stable_asset);
                    ov.balances.insert(
                        (*payer, *stable_asset),
                        payer_balance
                            .checked_sub(*amount)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    let idx = u32::try_from(index).map_err(|_| FailCode::Overflow)?;
                    let payment_id = derive_private_payment_id(txid, idx);
                    if overlay_object(&ov, self, &payment_id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let payment = PrivatePaymentV1 {
                        payment_id,
                        payer: *payer,
                        stable_asset: *stable_asset,
                        recipient_commitment: *recipient_commitment,
                        memo_commitment: *memo_commitment,
                        reference_commitment: *reference_commitment,
                        amount: *amount,
                        expiry_height: *expiry_height,
                        payment_kind: *payment_kind,
                        status: PrivatePaymentV1::STATUS_OPEN,
                        settled_account: OptionalHash32(None),
                        settled_height: 0,
                    };
                    ov.objects
                        .insert(payment_id, Some(payment.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::OpenAgentPrivatePayment {
                    agent,
                    payer,
                    stable_asset,
                    recipient_commitment,
                    memo_commitment,
                    reference_commitment,
                    amount,
                    expiry_height,
                    capability_ref,
                } => {
                    let max_expiry = ctx
                        .height
                        .checked_add(MAX_PRIVATE_PAYMENT_LIFETIME)
                        .ok_or(FailCode::Overflow)?;
                    let grant_raw = overlay_object(&ov, self, capability_ref)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut grant = CapabilityGrantV1::decode_canonical(&grant_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if grant.grant_id != *capability_ref
                        || grant.issuer != *payer
                        || grant.subject_agent != *agent
                        || grant.allowed_action_schema_root != agent_private_payment_schema_root()
                        || grant.object_scope_root
                            != agent_private_payment_scope(stable_asset, recipient_commitment)
                        || ctx.height > grant.expiry_height
                        || *expiry_height <= ctx.height
                        || *expiry_height > max_expiry
                        || *expiry_height > grant.expiry_height
                        || *amount == 0
                        || *amount > grant.per_action_limit
                        || *amount > MAX_CREDIT_QUANTITY
                        || *recipient_commitment == [0; 32]
                        || *memo_commitment == [0; 32]
                        || *reference_commitment == [0; 32]
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    grant.cumulative_budget = grant
                        .cumulative_budget
                        .checked_sub(*amount)
                        .ok_or(FailCode::InsufficientBalance)?;
                    let stable_raw = overlay_object(&ov, self, stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let stable = StableAssetV1::decode_canonical(&stable_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if stable.kind != 1 || stable.asset_id != *stable_asset {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let payer_balance = overlay_balance(&ov, self, payer, stable_asset);
                    ov.balances.insert(
                        (*payer, *stable_asset),
                        payer_balance
                            .checked_sub(*amount)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    let idx = u32::try_from(index).map_err(|_| FailCode::Overflow)?;
                    let payment_id = derive_private_payment_id(txid, idx);
                    if overlay_object(&ov, self, &payment_id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let payment = PrivatePaymentV1 {
                        payment_id,
                        payer: *payer,
                        stable_asset: *stable_asset,
                        recipient_commitment: *recipient_commitment,
                        memo_commitment: *memo_commitment,
                        reference_commitment: *reference_commitment,
                        amount: *amount,
                        expiry_height: *expiry_height,
                        payment_kind: PrivatePaymentV1::KIND_AGENT,
                        status: PrivatePaymentV1::STATUS_OPEN,
                        settled_account: OptionalHash32(None),
                        settled_height: 0,
                    };
                    ov.objects
                        .insert(payment_id, Some(payment.encode_canonical()));
                    ov.objects
                        .insert(*capability_ref, Some(grant.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::ClaimPrivatePayment {
                    recipient,
                    payment_id,
                    claim_secret,
                } => {
                    let payment_raw = overlay_object(&ov, self, payment_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut payment = PrivatePaymentV1::decode_canonical(&payment_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if payment.payment_id != *payment_id
                        || payment.status != PrivatePaymentV1::STATUS_OPEN
                        || ctx.height > payment.expiry_height
                        || payment.recipient_commitment
                            != private_recipient_commitment(recipient, claim_secret)
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance = overlay_balance(&ov, self, recipient, &payment.stable_asset);
                    ov.balances.insert(
                        (*recipient, payment.stable_asset),
                        balance
                            .checked_add(payment.amount)
                            .ok_or(FailCode::Overflow)?,
                    );
                    payment.status = PrivatePaymentV1::STATUS_CLAIMED;
                    payment.settled_account = OptionalHash32(Some(*recipient));
                    payment.settled_height = ctx.height;
                    ov.objects
                        .insert(*payment_id, Some(payment.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::RefundPrivatePayment { payer, payment_id } => {
                    let payment_raw = overlay_object(&ov, self, payment_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut payment = PrivatePaymentV1::decode_canonical(&payment_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if payment.payment_id != *payment_id
                        || payment.payer != *payer
                        || payment.status != PrivatePaymentV1::STATUS_OPEN
                        || ctx.height <= payment.expiry_height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance = overlay_balance(&ov, self, payer, &payment.stable_asset);
                    ov.balances.insert(
                        (*payer, payment.stable_asset),
                        balance
                            .checked_add(payment.amount)
                            .ok_or(FailCode::Overflow)?,
                    );
                    payment.status = PrivatePaymentV1::STATUS_REFUNDED;
                    payment.settled_account = OptionalHash32(Some(*payer));
                    payment.settled_height = ctx.height;
                    ov.objects
                        .insert(*payment_id, Some(payment.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::RegisterComputeWorker {
                    worker,
                    capabilities,
                    cpu_threads,
                    memory_mb,
                    gpu_memory_mb,
                    price_per_unit,
                    endpoint_commitment,
                } => {
                    let known_capabilities =
                        ComputeWorkerV1::CAPABILITY_CPU | ComputeWorkerV1::CAPABILITY_GPU;
                    if *capabilities == 0
                        || *capabilities & !known_capabilities != 0
                        || (*capabilities & ComputeWorkerV1::CAPABILITY_CPU != 0
                            && *cpu_threads == 0)
                        || (*capabilities & ComputeWorkerV1::CAPABILITY_GPU != 0
                            && *gpu_memory_mb == 0)
                        || *memory_mb == 0
                        || *price_per_unit == 0
                        || overlay_account(&ov, self, worker).is_none()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let prior = overlay_object(&ov, self, worker)
                        .and_then(|bytes| ComputeWorkerV1::decode_canonical(&bytes).ok());
                    let record = ComputeWorkerV1 {
                        worker: *worker,
                        capabilities: *capabilities,
                        cpu_threads: *cpu_threads,
                        memory_mb: *memory_mb,
                        gpu_memory_mb: *gpu_memory_mb,
                        price_per_unit: *price_per_unit,
                        endpoint_commitment: *endpoint_commitment,
                        active: 1,
                        jobs_completed: prior.as_ref().map_or(0, |value| value.jobs_completed),
                        units_completed: prior.as_ref().map_or(0, |value| value.units_completed),
                    };
                    ov.objects.insert(*worker, Some(record.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::OpenComputeJob {
                    requester,
                    workload_kind,
                    input_root,
                    units,
                    unit_size,
                    max_price_per_unit,
                    deadline_height,
                } => {
                    if *workload_kind > 1
                        || *units == 0
                        || *units > 1_000_000_000
                        || *unit_size == 0
                        || *unit_size > 1_048_576
                        || *max_price_per_unit == 0
                        || *deadline_height <= ctx.height
                        || overlay_account(&ov, self, requester).is_none()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let escrow = u128::from(*units)
                        .checked_mul(*max_price_per_unit)
                        .ok_or(FailCode::Overflow)?;
                    let balance = overlay_balance(&ov, self, requester, &NOOS_ASSET);
                    ov.balances.insert(
                        (*requester, NOOS_ASSET),
                        balance
                            .checked_sub(escrow)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    let idx = u32::try_from(index).map_err(|_| FailCode::Overflow)?;
                    let id = derive_compute_job_id(txid, idx);
                    if overlay_object(&ov, self, &id).is_some() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let job = ComputeJobV1 {
                        job_id: id,
                        requester: *requester,
                        worker: crate::objects::OptionalHash32(None),
                        workload_kind: *workload_kind,
                        input_root: *input_root,
                        units: *units,
                        unit_size: *unit_size,
                        max_price_per_unit: *max_price_per_unit,
                        agreed_price_per_unit: 0,
                        escrow,
                        deadline_height: *deadline_height,
                        state: ComputeJobV1::STATE_OPEN,
                        result_root: [0; 32],
                        completed_units: 0,
                    };
                    ov.objects.insert(id, Some(job.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::ClaimComputeJob { worker, job_id } => {
                    let worker_raw =
                        overlay_object(&ov, self, worker).ok_or(FailCode::PostconditionFailed)?;
                    let worker_record = ComputeWorkerV1::decode_canonical(&worker_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let job_raw =
                        overlay_object(&ov, self, job_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut job = ComputeJobV1::decode_canonical(&job_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if worker_record.active != 1
                        || job.state != ComputeJobV1::STATE_OPEN
                        || job.worker.0.is_some()
                        || ctx.height > job.deadline_height
                        || worker_record.price_per_unit > job.max_price_per_unit
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    job.worker = crate::objects::OptionalHash32(Some(*worker));
                    job.agreed_price_per_unit = worker_record.price_per_unit;
                    job.state = ComputeJobV1::STATE_CLAIMED;
                    ov.objects.insert(*job_id, Some(job.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::SubmitComputeResult {
                    worker,
                    job_id,
                    result_root,
                    completed_units,
                } => {
                    let raw =
                        overlay_object(&ov, self, job_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut job = ComputeJobV1::decode_canonical(&raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if job.state != ComputeJobV1::STATE_CLAIMED
                        || job.worker.0 != Some(*worker)
                        || *completed_units != job.units
                        || *result_root == [0; 32]
                        || ctx.height > job.deadline_height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    job.result_root = *result_root;
                    job.completed_units = *completed_units;
                    job.state = ComputeJobV1::STATE_SUBMITTED;
                    ov.objects.insert(*job_id, Some(job.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::AcceptComputeResult { requester, job_id } => {
                    let raw =
                        overlay_object(&ov, self, job_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut job = ComputeJobV1::decode_canonical(&raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if job.requester != *requester
                        || job.state != ComputeJobV1::STATE_SUBMITTED
                        || job.completed_units != job.units
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let worker_id = job.worker.0.ok_or(FailCode::PostconditionFailed)?;
                    let worker_raw = overlay_object(&ov, self, &worker_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut worker_record = ComputeWorkerV1::decode_canonical(&worker_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let payment = u128::from(job.units)
                        .checked_mul(job.agreed_price_per_unit)
                        .ok_or(FailCode::Overflow)?;
                    let refund = job
                        .escrow
                        .checked_sub(payment)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let worker_balance = overlay_balance(&ov, self, &worker_id, &NOOS_ASSET);
                    let requester_balance = overlay_balance(&ov, self, requester, &NOOS_ASSET);
                    ov.balances.insert(
                        (worker_id, NOOS_ASSET),
                        worker_balance
                            .checked_add(payment)
                            .ok_or(FailCode::Overflow)?,
                    );
                    ov.balances.insert(
                        (*requester, NOOS_ASSET),
                        requester_balance
                            .checked_add(refund)
                            .ok_or(FailCode::Overflow)?,
                    );
                    worker_record.jobs_completed = worker_record
                        .jobs_completed
                        .checked_add(1)
                        .ok_or(FailCode::Overflow)?;
                    worker_record.units_completed = worker_record
                        .units_completed
                        .checked_add(job.units)
                        .ok_or(FailCode::Overflow)?;
                    job.escrow = 0;
                    job.state = ComputeJobV1::STATE_SETTLED;
                    ov.objects
                        .insert(worker_id, Some(worker_record.encode_canonical()));
                    ov.objects.insert(*job_id, Some(job.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::CancelComputeJob { requester, job_id } => {
                    let raw =
                        overlay_object(&ov, self, job_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut job = ComputeJobV1::decode_canonical(&raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let cancellable = job.state == ComputeJobV1::STATE_OPEN
                        || (ctx.height > job.deadline_height
                            && job.state != ComputeJobV1::STATE_SETTLED
                            && job.state != ComputeJobV1::STATE_CANCELLED);
                    if job.requester != *requester || !cancellable {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let balance = overlay_balance(&ov, self, requester, &NOOS_ASSET);
                    ov.balances.insert(
                        (*requester, NOOS_ASSET),
                        balance.checked_add(job.escrow).ok_or(FailCode::Overflow)?,
                    );
                    job.escrow = 0;
                    job.state = ComputeJobV1::STATE_CANCELLED;
                    ov.objects.insert(*job_id, Some(job.encode_canonical()));
                    ov.write_count()?;
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

fn mul_bps(value: u128, bps: u16) -> Result<u128, FailCode> {
    let whole = value
        .checked_div(10_000)
        .and_then(|part| part.checked_mul(u128::from(bps)))
        .ok_or(FailCode::Overflow)?;
    let remainder = value
        .checked_rem(10_000)
        .and_then(|part| part.checked_mul(u128::from(bps)))
        .and_then(|part| part.checked_div(10_000))
        .ok_or(FailCode::Overflow)?;
    whole.checked_add(remainder).ok_or(FailCode::Overflow)
}

fn conservative_oracle_price(
    ov: &mut Overlay,
    base: &LumenLedger,
    feed: &OracleFeedV1,
    height: u64,
) -> Result<u128, FailCode> {
    let mut prices = Vec::with_capacity(3);
    for reporter in [feed.reporter_0, feed.reporter_1, feed.reporter_2] {
        ov.read_count()?;
        let id = derive_oracle_report_id(&feed.feed_id, &reporter);
        let Some(raw) = overlay_object(ov, base, &id) else {
            continue;
        };
        let report =
            OracleReportV1::decode_canonical(&raw).map_err(|_| FailCode::PostconditionFailed)?;
        if report.report_id != id
            || report.feed_id != feed.feed_id
            || report.reporter != reporter
            || report.price_q9 == 0
            || report.price_q9 > MAX_CREDIT_QUANTITY
            || report.confidence_bps > MAX_ORACLE_CONFIDENCE_BPS
            || report.observed_height > height
            || height.saturating_sub(report.observed_height) > feed.max_age_blocks
        {
            continue;
        }
        prices.push(mul_bps(
            report.price_q9,
            10_000u16.saturating_sub(report.confidence_bps),
        )?);
    }
    if prices.len() < 2 {
        return Err(FailCode::PostconditionFailed);
    }
    prices.sort_unstable();
    Ok(if prices.len() == 2 {
        prices[0]
    } else {
        prices[1]
    })
}

fn collateral_value(collateral: u128, price_q9: u128) -> Result<u128, FailCode> {
    collateral
        .checked_mul(price_q9)
        .and_then(|value| value.checked_div(ORACLE_SCALE))
        .ok_or(FailCode::Overflow)
}

fn decode_oracle_feed(raw: &[u8], feed_id: &Hash32) -> Result<OracleFeedV1, FailCode> {
    let feed = OracleFeedV1::decode_canonical(raw).map_err(|_| FailCode::PostconditionFailed)?;
    if feed.feed_id != *feed_id
        || feed.feed_id != derive_oracle_feed_id(&feed.base_asset, &feed.quote_asset)
        || feed.base_asset == feed.quote_asset
        || feed.reporter_0 == feed.reporter_1
        || feed.reporter_0 == feed.reporter_2
        || feed.reporter_1 == feed.reporter_2
        || !(1..=10_000).contains(&feed.max_age_blocks)
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(feed)
}

fn decode_lending_market(raw: &[u8], market_id: &Hash32) -> Result<LendingMarketV1, FailCode> {
    let market =
        LendingMarketV1::decode_canonical(raw).map_err(|_| FailCode::PostconditionFailed)?;
    if market.market_id != *market_id
        || market.stable_asset != derive_stable_asset_id(market_id)
        || market.collateral_factor_bps < 1_000
        || market.collateral_factor_bps > 8_000
        || market.liquidation_threshold_bps <= market.collateral_factor_bps
        || market.liquidation_threshold_bps > 9_000
        || market.liquidation_bonus_bps > 1_000
        || market.debt_ceiling == 0
        || market.debt_ceiling > MAX_CREDIT_QUANTITY
        || market.min_debt == 0
        || market.min_debt > market.debt_ceiling
        || market.total_debt > market.debt_ceiling
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(market)
}

fn decode_stable_asset(raw: &[u8], market: &LendingMarketV1) -> Result<StableAssetV1, FailCode> {
    let stable = StableAssetV1::decode_canonical(raw).map_err(|_| FailCode::PostconditionFailed)?;
    if stable.kind != 1
        || stable.asset_id != market.stable_asset
        || stable.market_id != market.market_id
        || stable.minted_supply != market.total_debt
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(stable)
}

fn decode_debt_position(
    raw: &[u8],
    market_id: &Hash32,
    owner: &Hash32,
) -> Result<DebtPositionV1, FailCode> {
    let position =
        DebtPositionV1::decode_canonical(raw).map_err(|_| FailCode::PostconditionFailed)?;
    if position.position_id != derive_debt_position_id(market_id, owner)
        || position.market_id != *market_id
        || position.owner != *owner
        || position.collateral > MAX_CREDIT_QUANTITY
        || position.debt > MAX_CREDIT_QUANTITY
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(position)
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
