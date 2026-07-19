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

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use noos_codec::{NoosDecode, NoosEncode};
use noos_stable_safety::{DebtPosition as SafetyDebtPosition, SafetyPolicy, SafetyState};
use smallvec::SmallVec;

use crate::engine::{AuthVerifier, ContractEngine};
use crate::fees::{self, FeeParamsV1, FeeStateV1, Usage};
use crate::issuance::{EmissionSharesV1, IssuanceParamsV1};
use crate::neural_oracle::{
    evaluate_neural_program, neural_commit_key, neural_input_root, neural_output_root,
    neural_program_key, neural_query_key, neural_reply_commitment, neural_result_id,
    neural_result_key, neural_reveal_key, neural_transcript_root, validate_neural_program,
    NeuralOracleCommitRecordV1, NeuralOracleMode, NeuralOracleQueryV1, NeuralOracleResultV1,
    NeuralOracleRevealRecordV1, NeuralOracleStatus, NeuralProgramV1, MAX_NEURAL_ORACLE_REPORTERS,
    MAX_NEURAL_ORACLE_RESPONSE_BYTES, NEURAL_ORACLE_QUORUM_THRESHOLD,
};
use crate::objects::{
    agent_private_payment_schema_root, agent_private_payment_scope, asset_id as derive_asset_id,
    compute_job_id as derive_compute_job_id, debt_position_id as derive_debt_position_id,
    lending_market_id as derive_lending_market_id,
    liquidity_position_id as derive_liquidity_position_id, oracle_feed_id as derive_oracle_feed_id,
    oracle_report_id as derive_oracle_report_id, pool_id as derive_pool_id,
    private_payment_id as derive_private_payment_id, private_recipient_commitment,
    stable_asset_id as derive_stable_asset_id, stable_safety_id as derive_stable_safety_id,
    witness_root as derive_witness_root, AccessEntry, AccountV1, ActionV1, AssetV1, BoundedBytes,
    CapabilityGrantV1, ComputeJobV1, ComputeWorkerV1, DebtPositionV1, FeatureControlV1,
    LendingMarketV1, LiquidityPositionV1, NoteV1, ObjectV1, OptionalHash32, OracleFeedV1,
    OracleReportV1, ParamRecordV1, PendingParamV1, PoolV1, PrivatePaymentV1, ReceiptV1,
    ResourceVector, StableAssetV1, StableSafetyV1, TransactionV1, TransactionWitnessesV1,
};
use crate::smt::{ReceiptSmt, Smt};
use crate::wwm::{
    genesis_fund_ledger, wwm_fixed_key, wwm_profile_key, CapabilityMutationV1, CapabilitySetV1,
    CapabilityStatus, CustodianCapabilityMutationV2, CustodianCapabilitySetV1, FundBucketTag,
    FundLedgerStatus, FundMutationLockRefV1, FundMutationLockStatus, FundMutationLockV1,
    FundProfileV1, ModelCapsuleV2, RegisterFundProfilePayloadV1, RegistryEpochVectorV1,
    ResolutionProofV1, TestnetModelRegistrationV1, TransitionWwmControlPayloadV1, WwmControlMode,
    WwmControlStateV1, WwmEvidenceTier, WwmFundLedgerV1, WwmJobV1, WwmLeafKind, WwmReceiptV1,
    WwmTerminalCode,
};
use crate::Hash32;

/// NOOS asset id: the zero hash (frozen, lumen-v1.md §3.2).
pub const NOOS_ASSET: Hash32 = [0u8; 32];
/// Native AMM bounds keep every multiplication inside `u128`.
pub const MAX_POOL_QUANTITY: u128 = u64::MAX as u128;
/// Permanently unowned shares prevent complete reserve withdrawal.
pub const MINIMUM_LIQUIDITY: u128 = 1_000;
/// Oracle price scale: quote base units per collateral base unit.
pub const ORACLE_SCALE: u128 = 1_000_000_000;
pub const DEFAULT_PSM_FEE_BPS: u16 = 20;
pub const MAX_ORACLE_CONFIDENCE_BPS: u16 = 1_000;
pub const ORACLE_MODE_LIVE: u8 = 0;
pub const ORACLE_MODE_LAST_GOOD: u8 = 1;
pub const ORACLE_MODE_FROZEN: u8 = 2;
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
    pub entries: SmallVec<[DeltaEntry; 3]>,
}

impl StateDelta {
    fn from_map(map: DeltaMap) -> Self {
        let entries: SmallVec<[DeltaEntry; 3]> = map
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
/// Block-scoped capability for postponing liquid-balance subtree roots.
///
/// The token has no public constructor: callers obtain it only inside
/// [`LumenLedger::with_deferred_balance_roots`], which always materializes
/// every dirty account root before returning.
#[derive(Debug)]
pub struct DeferredBalanceRoots {
    dirty_accounts: BTreeSet<Hash32>,
    dirty_account_records: BTreeSet<Hash32>,
    cached_accounts: BTreeMap<Hash32, AccountV1>,
    fee_params: Option<FeeParamsV1>,
    prices: Option<fees::Prices>,
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

/// Result of executing the full admission and state-transition pipeline
/// against a discardable overlay. No tree, nonce, balance, receipt, or
/// mempool state is mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationOutcome {
    Applied { receipt: ReceiptV1 },
    Failed { receipt: ReceiptV1, code: FailCode },
}

impl SimulationOutcome {
    #[must_use]
    pub fn receipt(&self) -> &ReceiptV1 {
        match self {
            Self::Applied { receipt } | Self::Failed { receipt, .. } => receipt,
        }
    }
}

struct PreparedTransaction<'a> {
    tx: Cow<'a, TransactionV1>,
    actions: Vec<ActionV1>,
    txid: Hash32,
    input_notes: Vec<(Hash32, NoteV1)>,
    input_accounts: Vec<(Hash32, AccountV1)>,
    planned_outputs: Vec<(Hash32, NoteV1)>,
    fee_params: FeeParamsV1,
    prices: fees::Prices,
    max_fee: u128,
    encoded_len: u64,
}

enum EvaluatedTransaction {
    Applied {
        overlay: Overlay,
        receipt: ReceiptV1,
    },
    Failed {
        receipt: ReceiptV1,
        code: FailCode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    ConflictingSafetyObject,
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
    InvalidWwmAnchor,
    WwmAnchorAlreadyInstalled,
    Overflow,
}

// ---------------------------------------------------------------------------
// Overlay
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TinyMap<K, V> {
    entries: SmallVec<[(K, V); 4]>,
}

impl<K, V> Default for TinyMap<K, V> {
    fn default() -> Self {
        Self {
            entries: SmallVec::new(),
        }
    }
}

impl<K: Ord, V> TinyMap<K, V> {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
            .map(|index| &self.entries[index].1)
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self
            .entries
            .binary_search_by(|(candidate, _)| candidate.cmp(&key))
        {
            Ok(index) => Some(std::mem::replace(&mut self.entries[index].1, value)),
            Err(index) => {
                self.entries.insert(index, (key, value));
                None
            }
        }
    }
}

impl<K, V> IntoIterator for TinyMap<K, V> {
    type Item = (K, V);
    type IntoIter = smallvec::IntoIter<[(K, V); 4]>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

/// Bounded copy-on-write overlay keyed by touched entries. Reads fall
/// through to the base ledger; writes stay here until commit.
#[derive(Debug, Default)]
struct Overlay {
    notes: TinyMap<Hash32, Option<Vec<u8>>>,
    nullifiers: TinyMap<Hash32, Option<Vec<u8>>>,
    accounts: TinyMap<Hash32, Option<Vec<u8>>>,
    objects: TinyMap<Hash32, Option<Vec<u8>>>,
    receipts: TinyMap<Hash32, Option<ReceiptV1>>,
    params: TinyMap<Hash32, Option<Vec<u8>>>,
    /// (account, asset) -> new amount; 0 removes the balance leaf.
    balances: TinyMap<(Hash32, Hash32), u128>,
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
    receipts: ReceiptSmt,
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
    /// Return the exact objects-SMT value and its finalized-root proof envelope.
    #[must_use]
    pub fn finalized_object_proof(&self, state_key: Hash32) -> ResolutionProofV1 {
        let value = match self.objects.get(&state_key) {
            None => crate::wwm::ResolutionValueV1::Absent,
            Some(bytes) => crate::objects::BoundedBytes::new(bytes.to_vec()).map_or(
                crate::wwm::ResolutionValueV1::Absent,
                crate::wwm::ResolutionValueV1::Present,
            ),
        };
        ResolutionProofV1 {
            state_key,
            value,
            proof: self.objects.prove(&state_key),
            objects_root: self.objects.root(),
        }
    }

    /// Genesis-only WWM bootstrap hook. It installs one immutable signed fund
    /// profile, a Current zero-money ledger retaining all five policy rows,
    /// the registry anchor at epoch zero, and a Disabled control singleton.
    /// Validation completes before any write.
    pub fn install_wwm_genesis_anchor(
        &mut self,
        profile: &FundProfileV1,
        control: &WwmControlStateV1,
    ) -> Result<(), GenesisError> {
        if !profile.validate()
            || control.mode != WwmControlMode::Disabled
            || control.active_config_id.0.is_some()
            || control.latest_authorized_config_id.0.is_some()
            || control.resolution_config_id.0.is_some()
            || !control.separation_valid()
        {
            return Err(GenesisError::InvalidWwmAnchor);
        }
        let ledger = genesis_fund_ledger(profile).ok_or(GenesisError::InvalidWwmAnchor)?;
        let profile_key = wwm_profile_key(WwmLeafKind::FundProfile, &profile.profile_id);
        let ledger_key = wwm_profile_key(WwmLeafKind::FundLedger, &profile.profile_id);
        let registry_key = wwm_fixed_key(WwmLeafKind::RegistryEpochVector);
        let control_key = wwm_fixed_key(WwmLeafKind::Control);
        if [profile_key, ledger_key, registry_key, control_key]
            .iter()
            .any(|key| self.objects.contains(key))
        {
            return Err(GenesisError::WwmAnchorAlreadyInstalled);
        }
        let mut registry = RegistryEpochVectorV1 {
            vector_id: [0; 32],
            executor_set_id: [0; 32],
            executor_epoch: 0,
            custodian_set_id: [0; 32],
            custodian_epoch: 0,
            fee_policy_id: [0; 32],
            fee_epoch: 0,
            fund_profile_id: profile.profile_id,
            fund_epoch: 0,
            service_directory_id: [0; 32],
            service_epoch: 0,
        };
        registry.vector_id = crate::domain_hash(
            "NOOS/WWM/REGISTRY-EPOCH-VECTOR/V1",
            &[&registry.encode_canonical()],
        );
        self.objects.insert(profile_key, profile.encode_canonical());
        self.objects.insert(ledger_key, ledger.encode_canonical());
        self.objects
            .insert(registry_key, registry.encode_canonical());
        self.objects.insert(control_key, control.encode_canonical());
        Ok(())
    }

    /// Replaces the disabled WWM genesis anchor with one complete Testnet
    /// registration. The caller must explicitly attest that the enclosing
    /// genesis is a test network; all graph validation and collision checks
    /// complete before the first write.
    pub fn install_wwm_testnet_registration(
        &mut self,
        registration: &TestnetModelRegistrationV1,
        is_test_network: bool,
    ) -> Result<(), GenesisError> {
        if !is_test_network {
            return Err(GenesisError::InvalidWwmAnchor);
        }
        let control_key = wwm_fixed_key(WwmLeafKind::Control);
        let registry_key = wwm_fixed_key(WwmLeafKind::RegistryEpochVector);
        let current_control = self
            .objects
            .get(&control_key)
            .and_then(|bytes| WwmControlStateV1::decode_canonical(bytes).ok())
            .ok_or(GenesisError::InvalidWwmAnchor)?;
        let current_registry = self
            .objects
            .get(&registry_key)
            .and_then(|bytes| RegistryEpochVectorV1::decode_canonical(bytes).ok())
            .ok_or(GenesisError::InvalidWwmAnchor)?;
        if current_control.mode != WwmControlMode::Disabled
            || current_control.active_config_id.0.is_some()
            || current_control.latest_authorized_config_id.0.is_some()
            || current_control.resolution_config_id.0.is_some()
            || current_registry.executor_set_id != [0; 32]
            || current_registry.custodian_set_id != [0; 32]
            || current_registry.fee_policy_id != [0; 32]
            || current_registry.service_directory_id != [0; 32]
        {
            return Err(GenesisError::InvalidWwmAnchor);
        }
        let fund_profile = self
            .objects
            .get(&wwm_profile_key(
                WwmLeafKind::FundProfile,
                &current_registry.fund_profile_id,
            ))
            .and_then(|bytes| FundProfileV1::decode_canonical(bytes).ok())
            .ok_or(GenesisError::InvalidWwmAnchor)?;
        let fund_ledger = self
            .objects
            .get(&wwm_profile_key(
                WwmLeafKind::FundLedger,
                &current_registry.fund_profile_id,
            ))
            .and_then(|bytes| WwmFundLedgerV1::decode_canonical(bytes).ok())
            .ok_or(GenesisError::InvalidWwmAnchor)?;
        if !registration.validate(&fund_profile, &fund_ledger) {
            return Err(GenesisError::InvalidWwmAnchor);
        }

        let mut writes = BTreeMap::<Hash32, Vec<u8>>::new();
        let mut add = |key: Hash32, value: Vec<u8>| -> Result<(), GenesisError> {
            if writes.insert(key, value).is_some() {
                return Err(GenesisError::InvalidWwmAnchor);
            }
            Ok(())
        };
        add(
            wwm_fixed_key(WwmLeafKind::ServingAlias),
            registration.alias.encode_canonical(),
        )?;
        add(control_key, registration.control.encode_canonical())?;
        add(
            wwm_profile_key(
                WwmLeafKind::AuthorizedConfig,
                &registration.config.config_id,
            ),
            registration.config.encode_canonical(),
        )?;
        add(
            wwm_profile_key(WwmLeafKind::Capsule, &registration.capsule.capsule_id),
            registration.capsule.encode_canonical(),
        )?;
        add(
            wwm_profile_key(WwmLeafKind::Artifact, &registration.artifact.artifact_id),
            registration.artifact.encode_canonical(),
        )?;
        add(
            wwm_profile_key(
                WwmLeafKind::AvailabilityPolicy,
                &registration.availability_policy.policy_id,
            ),
            registration.availability_policy.encode_canonical(),
        )?;
        add(
            wwm_fixed_key(WwmLeafKind::CurrentCertificatePointer),
            registration
                .availability_certificate
                .certificate_id
                .to_vec(),
        )?;
        add(
            wwm_profile_key(
                WwmLeafKind::Certificate,
                &registration.availability_certificate.certificate_id,
            ),
            registration.availability_certificate.encode_canonical(),
        )?;
        add(registry_key, registration.registry.encode_canonical())?;
        add(
            wwm_profile_key(
                WwmLeafKind::ExecutorCapabilitySet,
                &registration.executor_set.set_id,
            ),
            registration.executor_set.encode_canonical(),
        )?;
        add(
            wwm_profile_key(
                WwmLeafKind::CustodianCapabilitySet,
                &registration.custodian_set.set_id,
            ),
            registration.custodian_set.encode_canonical(),
        )?;
        add(
            wwm_profile_key(
                WwmLeafKind::ExecutionProfile,
                &registration.execution_profile.profile_id,
            ),
            registration.execution_profile.encode_canonical(),
        )?;
        add(
            wwm_profile_key(
                WwmLeafKind::QueryPolicy,
                &registration.query_policy.policy_id,
            ),
            registration.query_policy.encode_canonical(),
        )?;
        add(
            wwm_profile_key(WwmLeafKind::FeePolicy, &registration.fee_policy.policy_id),
            registration.fee_policy.encode_canonical(),
        )?;
        add(
            wwm_profile_key(
                WwmLeafKind::ServiceDirectory,
                &registration.service_directory.directory_id,
            ),
            registration.service_directory.encode_canonical(),
        )?;

        if writes.iter().any(|(key, _)| {
            *key != control_key && *key != registry_key && self.objects.contains(key)
        }) {
            return Err(GenesisError::WwmAnchorAlreadyInstalled);
        }
        for (key, value) in writes {
            self.objects.insert(key, value);
        }
        Ok(())
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

    /// Checks the current account authorization while reusing the block-local
    /// decoded account cache populated by deferred simple transfers.
    #[must_use]
    pub fn deferred_auth_descriptor_matches(
        &self,
        deferred: &DeferredBalanceRoots,
        id: &Hash32,
        expected: &[u8],
    ) -> bool {
        deferred.cached_accounts.get(id).map_or_else(
            || {
                self.get_account(id)
                    .is_some_and(|account| account.auth_descriptor.as_slice() == expected)
            },
            |account| account.auth_descriptor.as_slice() == expected,
        )
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
    pub fn get_neural_program(&self, id: &Hash32) -> Option<NeuralProgramV1> {
        self.objects
            .get(&neural_program_key(id))
            .and_then(|bytes| NeuralProgramV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn get_neural_oracle_query(&self, id: &Hash32) -> Option<NeuralOracleQueryV1> {
        self.objects
            .get(&neural_query_key(id))
            .and_then(|bytes| NeuralOracleQueryV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn get_neural_oracle_result(&self, id: &Hash32) -> Option<NeuralOracleResultV1> {
        self.objects
            .get(&neural_result_key(id))
            .and_then(|bytes| NeuralOracleResultV1::decode_canonical(bytes).ok())
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
    pub fn get_stable_safety(&self, market: &Hash32) -> Option<StableSafetyV1> {
        self.objects
            .get(&derive_stable_safety_id(market))
            .and_then(|bytes| StableSafetyV1::decode_canonical(bytes).ok())
    }

    #[must_use]
    pub fn stable_safeties(&self) -> Vec<StableSafetyV1> {
        self.objects
            .iter()
            .filter_map(|(_, bytes)| StableSafetyV1::decode_canonical(bytes).ok())
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

    #[cfg(test)]
    pub(crate) fn remove_stable_safety_for_test(&mut self, market: &Hash32) {
        self.objects.remove(&derive_stable_safety_id(market));
    }

    #[cfg(test)]
    pub(crate) fn install_wwm_flow_fixture_for_test(
        &mut self,
        control: &WwmControlStateV1,
        capsule: &ModelCapsuleV2,
        execution_profile_id: Hash32,
        query_policy_id: Hash32,
        certificate_id: Hash32,
        fund_profile_id: Hash32,
    ) {
        self.objects.insert(
            wwm_fixed_key(WwmLeafKind::Control),
            control.encode_canonical(),
        );
        self.objects.insert(
            wwm_profile_key(WwmLeafKind::Capsule, &capsule.capsule_id),
            capsule.encode_canonical(),
        );
        for (kind, id) in [
            (WwmLeafKind::ExecutionProfile, execution_profile_id),
            (WwmLeafKind::QueryPolicy, query_policy_id),
            (WwmLeafKind::Certificate, certificate_id),
            (WwmLeafKind::FundProfile, fund_profile_id),
        ] {
            self.objects.insert(wwm_profile_key(kind, &id), vec![1]);
        }
    }

    #[cfg(test)]
    pub(crate) fn install_neural_oracle_fixture_for_test(
        &mut self,
        registry: &RegistryEpochVectorV1,
        executor_set: &CapabilitySetV1,
    ) {
        self.objects.insert(
            wwm_fixed_key(WwmLeafKind::RegistryEpochVector),
            registry.encode_canonical(),
        );
        self.objects.insert(
            wwm_profile_key(WwmLeafKind::ExecutorCapabilitySet, &executor_set.set_id),
            executor_set.encode_canonical(),
        );
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
        self.receipts.get(txid).cloned()
    }

    #[must_use]
    pub fn get_receipt_settlement(&self, txid: &Hash32) -> Option<(u64, u16)> {
        self.receipts.settlement(txid)
    }

    /// Transfers the settled-receipt index between node-owned atomic staging
    /// states. Transactions can only append a previously absent txid. Failed
    /// staging removes only receipts settled above the pre-stage canonical
    /// height, preserving any historical receipt named by invalid replay data.
    #[doc(hidden)]
    pub fn take_receipt_state_for_staging(&mut self) -> ReceiptSmt {
        std::mem::take(&mut self.receipts)
    }

    #[doc(hidden)]
    pub fn replace_receipt_state_for_staging(&mut self, receipts: ReceiptSmt) {
        self.receipts = receipts;
    }

    #[doc(hidden)]
    pub fn remove_receipt_after_height_for_staging(&mut self, txid: &Hash32, settled_height: u64) {
        self.receipts.remove_if_settled_after(txid, settled_height);
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

    /// Direct balance write + account-root refresh (emission/ordinary commit paths).
    fn set_balance_direct(
        &mut self,
        account: &Hash32,
        asset: &Hash32,
        amount: u128,
        delta: &mut DeltaMap,
    ) {
        self.set_balance_leaf_direct(account, asset, amount, delta);
        self.refresh_balance_root_direct(account, delta);
    }

    /// Flush cached nonce updates before a general deferred transaction.
    fn flush_deferred_accounts(&mut self, deferred: &mut DeferredBalanceRoots) {
        for (account_id, account) in std::mem::take(&mut deferred.cached_accounts) {
            self.accounts.insert(account_id, account.encode_canonical());
            deferred.dirty_account_records.insert(account_id);
        }
    }
    /// Update one balance leaf without hashing its account subtree.
    fn set_balance_leaf_direct(
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
            let encoded = encode_amount(amount);
            tree.insert(*asset, encoded.clone());
            delta.insert(
                (TreeId::AccountBalances, *account, Some(*asset)),
                Some(encoded),
            );
        }
    }

    /// Bind an account record to the current root of its balance subtree.
    fn refresh_balance_root_direct(&mut self, account: &Hash32, delta: &mut DeltaMap) {
        let Some(tree) = self.balances.get(account) else {
            return;
        };
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

    fn set_balance_deferred(
        &mut self,
        account: &Hash32,
        asset: &Hash32,
        amount: u128,
        delta: &mut DeltaMap,
        deferred: &mut DeferredBalanceRoots,
    ) {
        self.set_balance_leaf_direct(account, asset, amount, delta);
        deferred.dirty_accounts.insert(*account);
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

    /// Idempotent activation migration for the stable-safety protocol
    /// extension. At or after `activation_height`, every pre-existing lending
    /// market receives the same zero-funded safety object created for new
    /// markets. A conflicting object at the derived id fails closed.
    pub fn activate_stable_safety_upgrade(
        &mut self,
        height: u64,
        activation_height: u64,
    ) -> Result<StateDelta, MigrationError> {
        if height < activation_height {
            return Ok(StateDelta::default());
        }
        let markets = self.lending_markets();
        let mut delta = BTreeMap::new();
        for market in markets {
            let safety_id = derive_stable_safety_id(&market.market_id);
            if let Some(raw) = self.objects.get(&safety_id) {
                let safety = StableSafetyV1::decode_canonical(raw)
                    .map_err(|_| MigrationError::ConflictingSafetyObject)?;
                if safety.safety_id != safety_id
                    || safety.market_id != market.market_id
                    || safety.psm_fee_bps > 500
                {
                    return Err(MigrationError::ConflictingSafetyObject);
                }
                continue;
            }
            let safety = StableSafetyV1 {
                safety_id,
                market_id: market.market_id,
                stable_reserve: 0,
                collateral_reserve: 0,
                psm_debt: 0,
                uncovered_bad_debt: 0,
                psm_fee_bps: DEFAULT_PSM_FEE_BPS,
            };
            let bytes = safety.encode_canonical();
            self.objects.insert(safety_id, bytes.clone());
            delta.insert((TreeId::Objects, safety_id, None), Some(bytes));
        }
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
        let prepared = self.prepare_transaction(ctx, tx_bytes, witness_bytes, auth, None)?;
        match self.evaluate_transaction(ctx, &prepared, engine) {
            EvaluatedTransaction::Applied { overlay, receipt } => {
                let delta = self.commit_overlay(overlay, ctx.height);
                Ok(ApplyOutcome::Applied { receipt, delta })
            }
            EvaluatedTransaction::Failed { receipt, code } => {
                Ok(self.commit_failure_receipt(&prepared.tx, receipt, code, ctx.height))
            }
        }
    }
    /// Execute a block-scoped transaction batch while hashing each touched
    /// account's liquid-balance subtree exactly once at the end.
    ///
    /// Transaction order, reads, writes, receipts, and final roots are
    /// unchanged. The returned delta contains the final account records and
    /// MUST be ordered after the per-transaction deltas in the durable write
    /// set.
    pub fn with_deferred_balance_roots<R>(
        &mut self,
        execute: impl FnOnce(&mut Self, &mut DeferredBalanceRoots) -> R,
    ) -> (R, StateDelta) {
        let fee_params = self.fee_params();
        let prices = self.fee_state().map(|state| state.prices());
        let mut deferred = DeferredBalanceRoots {
            dirty_accounts: BTreeSet::new(),
            dirty_account_records: BTreeSet::new(),
            cached_accounts: BTreeMap::new(),
            fee_params,
            prices,
        };
        let result = execute(self, &mut deferred);
        let delta = self.materialize_deferred_balance_roots(deferred);
        (result, delta)
    }

    /// Raw canonical transaction application for a block-scoped deferred-root
    /// batch. Use only inside [`Self::with_deferred_balance_roots`].
    pub fn apply_transaction_deferred(
        &mut self,
        ctx: &BlockContext,
        tx_bytes: &[u8],
        witness_bytes: &[u8],
        engine: &dyn ContractEngine,
        auth: &dyn AuthVerifier,
        deferred: &mut DeferredBalanceRoots,
    ) -> Result<ApplyOutcome, RejectReason> {
        self.flush_deferred_accounts(deferred);
        let fee_context = deferred.fee_params.as_ref().zip(deferred.prices.as_ref());
        let prepared = self.prepare_transaction(ctx, tx_bytes, witness_bytes, auth, fee_context)?;
        match self.evaluate_transaction(ctx, &prepared, engine) {
            EvaluatedTransaction::Applied { overlay, receipt } => {
                let delta = self.commit_overlay_deferred(overlay, deferred, ctx.height);
                Ok(ApplyOutcome::Applied { receipt, delta })
            }
            EvaluatedTransaction::Failed { receipt, code } => Ok(self
                .commit_failure_receipt_deferred(
                    &prepared.tx,
                    receipt,
                    code,
                    deferred,
                    ctx.height,
                )),
        }
    }

    /// Apply an already canonically decoded transaction without repeating the
    /// codec pass. `encoded_len` MUST be the exact combined canonical
    /// transaction-plus-witness byte length retained by the consensus
    /// admission or block decoder.
    pub fn apply_canonical_decoded_transaction(
        &mut self,
        ctx: &BlockContext,
        tx: &TransactionV1,
        witnesses: &TransactionWitnessesV1,
        encoded_len: usize,
        engine: &dyn ContractEngine,
        auth: &dyn AuthVerifier,
    ) -> Result<ApplyOutcome, RejectReason> {
        let encoded_len =
            u64::try_from(encoded_len).map_err(|_| RejectReason::OversizedEncoding)?;
        let prepared = self.prepare_decoded_transaction(
            ctx,
            Cow::Borrowed(tx),
            witnesses,
            encoded_len,
            auth,
            None,
        )?;
        match self.evaluate_transaction(ctx, &prepared, engine) {
            EvaluatedTransaction::Applied { overlay, receipt } => {
                let delta = self.commit_overlay(overlay, ctx.height);
                Ok(ApplyOutcome::Applied { receipt, delta })
            }
            EvaluatedTransaction::Failed { receipt, code } => {
                Ok(self.commit_failure_receipt(&prepared.tx, receipt, code, ctx.height))
            }
        }
    }
    /// Canonically decoded transaction application for a block-scoped
    /// deferred-root batch. Use only inside
    /// [`Self::with_deferred_balance_roots`].
    pub fn apply_canonical_decoded_transaction_deferred(
        &mut self,
        ctx: &BlockContext,
        tx: &TransactionV1,
        witnesses: &TransactionWitnessesV1,
        encoded_len: usize,
        engine: &dyn ContractEngine,
        auth: &dyn AuthVerifier,
        deferred: &mut DeferredBalanceRoots,
    ) -> Result<ApplyOutcome, RejectReason> {
        self.flush_deferred_accounts(deferred);
        let encoded_len =
            u64::try_from(encoded_len).map_err(|_| RejectReason::OversizedEncoding)?;
        let fee_context = deferred.fee_params.as_ref().zip(deferred.prices.as_ref());
        let prepared = self.prepare_decoded_transaction(
            ctx,
            Cow::Borrowed(tx),
            witnesses,
            encoded_len,
            auth,
            fee_context,
        )?;
        match self.evaluate_transaction(ctx, &prepared, engine) {
            EvaluatedTransaction::Applied { overlay, receipt } => {
                let delta = self.commit_overlay_deferred(overlay, deferred, ctx.height);
                Ok(ApplyOutcome::Applied { receipt, delta })
            }
            EvaluatedTransaction::Failed { receipt, code } => Ok(self
                .commit_failure_receipt_deferred(
                    &prepared.tx,
                    receipt,
                    code,
                    deferred,
                    ctx.height,
                )),
        }
    }

    /// Fast path for the native signed-transfer shape used by payment
    /// workloads. The caller must have verified the sole account signature
    /// against the current descriptor. Ineligible shapes return `Ok(None)`
    /// and use the general engine; eligible transactions preserve every
    /// rejection, failure-charge, resource, nonce, receipt, and balance law.
    pub fn try_apply_preverified_simple_transfer_deferred(
        &mut self,
        ctx: &BlockContext,
        tx: &TransactionV1,
        witnesses: &TransactionWitnessesV1,
        encoded_len: usize,
        transaction_id: Hash32,
        deferred: &mut DeferredBalanceRoots,
    ) -> Result<Option<ApplyOutcome>, RejectReason> {
        if !tx.note_inputs.is_empty()
            || tx.account_inputs.len() != 1
            || !tx.object_access_list.is_empty()
            || tx.actions.len() != 2
            || !tx.outputs.is_empty()
            || !tx.evidence_refs.is_empty()
            || tx.account_inputs.as_slice().first() != Some(&tx.fee_payer)
        {
            return Ok(None);
        }
        let actions = tx.actions.as_slice();
        let Ok(ActionV1::WithdrawFromAccount {
            account_id: sender,
            asset_id: withdraw_asset,
            amount: withdraw_amount,
        }) = ActionV1::decode_canonical(actions[0].as_slice())
        else {
            return Ok(None);
        };
        let Ok(ActionV1::DepositToAccount {
            account_id: recipient,
            asset_id: deposit_asset,
            amount: deposit_amount,
        }) = ActionV1::decode_canonical(actions[1].as_slice())
        else {
            return Ok(None);
        };
        if sender != tx.fee_payer
            || withdraw_asset != deposit_asset
            || withdraw_amount != deposit_amount
        {
            return Ok(None);
        }
        if recipient != sender
            && !deferred.cached_accounts.contains_key(&recipient)
            && self.get_account(&recipient).is_none()
        {
            // The general path creates a first-deposit recipient account.
            return Ok(None);
        }

        let encoded_len =
            u64::try_from(encoded_len).map_err(|_| RejectReason::OversizedEncoding)?;
        if tx.chain_id != ctx.chain_id {
            return Err(RejectReason::WrongChain);
        }
        if tx.format_version != TransactionV1::VERSION {
            return Err(RejectReason::WrongFormatVersion);
        }
        if ctx.height > tx.expiry_height {
            return Err(RejectReason::Expired);
        }
        let fee_params = deferred
            .fee_params
            .clone()
            .ok_or(RejectReason::GovernanceDenied)?;
        let prices = deferred.prices.ok_or(RejectReason::GovernanceDenied)?;
        let declared = fees::usage_from_resources(&tx.resource_limits);
        let capacity = fee_params.capacity();
        for dimension in 0..fees::DIMENSIONS {
            if declared[dimension] > capacity[dimension] {
                return Err(RejectReason::ResourceLimitExceedsCapacity);
            }
        }
        if encoded_len > tx.resource_limits.bytes {
            return Err(RejectReason::OversizedEncoding);
        }
        if self.receipts.contains(&transaction_id) {
            return Err(RejectReason::TxAlreadySettled);
        }
        if !deferred.cached_accounts.contains_key(&sender) {
            let account = self
                .get_account(&sender)
                .ok_or(RejectReason::UnknownAccountInput)?;
            deferred.cached_accounts.insert(sender, account);
        }
        if tx.witness_root != derive_witness_root(&witnesses.lock_reveals) {
            return Err(RejectReason::WitnessRootMismatch);
        }
        if witnesses.intents.len() != 1 || !witnesses.lock_reveals.is_empty() {
            return Err(RejectReason::MissingWitness);
        }
        let intent = &witnesses.intents.as_slice()[0];
        if intent.tx_commitment != transaction_id {
            return Err(RejectReason::SignatureInvalid);
        }

        let max_fee = fees::fee(&prices, &declared).ok_or(RejectReason::FeeOverflow)?;
        if self.balance(&tx.fee_payer, &NOOS_ASSET) < max_fee {
            return Err(RejectReason::InsufficientFeeBalance);
        }

        let mut balances = TinyMap::<(Hash32, Hash32), u128>::default();
        let account_nonce = deferred
            .cached_accounts
            .get(&sender)
            .expect("cached sender")
            .nonce;
        let next_nonce = account_nonce.checked_add(1);
        let mut failure = next_nonce.is_none().then_some(FailCode::Overflow);

        if failure.is_none() {
            let sender_before = self.balance(&sender, &withdraw_asset);
            match sender_before.checked_sub(withdraw_amount) {
                None => failure = Some(FailCode::InsufficientBalance),
                Some(sender_after) => {
                    balances.insert((sender, withdraw_asset), sender_after);
                    let recipient_before = balances
                        .get(&(recipient, deposit_asset))
                        .copied()
                        .unwrap_or_else(|| self.balance(&recipient, &deposit_asset));
                    match recipient_before.checked_add(deposit_amount) {
                        None => failure = Some(FailCode::Overflow),
                        Some(recipient_after) => {
                            balances.insert((recipient, deposit_asset), recipient_after);
                        }
                    }
                }
            }
        }

        let measured = ResourceVector {
            bytes: encoded_len,
            grain_steps: 0,
            proof_units: 0,
            state_reads: 0,
            state_writes: 3,
            blob_bytes: 0,
        };
        let mut charged = 0_u128;
        if failure.is_none() {
            if !measured.fits_within(&tx.resource_limits) {
                failure = Some(FailCode::ResourceOverrun);
            } else {
                match fees::fee(&prices, &fees::usage_from_resources(&measured)) {
                    None => failure = Some(FailCode::Overflow),
                    Some(actual_fee) => {
                        charged = actual_fee.min(max_fee);
                        let payer_balance = balances
                            .get(&(tx.fee_payer, NOOS_ASSET))
                            .copied()
                            .unwrap_or_else(|| self.balance(&tx.fee_payer, &NOOS_ASSET));
                        match payer_balance.checked_sub(charged) {
                            None => failure = Some(FailCode::InsufficientBalance),
                            Some(after_fee) => {
                                balances.insert((tx.fee_payer, NOOS_ASSET), after_fee);
                            }
                        }
                    }
                }
            }
        }

        let (receipt, failed_code) = if let Some(code) = failure {
            let receipt = failure_receipt(&transaction_id, code, max_fee, &fee_params, encoded_len);
            balances = TinyMap::default();
            let after = self
                .balance(&tx.fee_payer, &NOOS_ASSET)
                .saturating_sub(receipt.fee_charged);
            balances.insert((tx.fee_payer, NOOS_ASSET), after);
            let account = deferred
                .cached_accounts
                .get_mut(&sender)
                .expect("cached sender");
            account.nonce = account.nonce.saturating_add(1);
            (receipt, Some(code))
        } else {
            let account = deferred
                .cached_accounts
                .get_mut(&sender)
                .expect("cached sender");
            account.nonce = next_nonce.expect("checked nonce");
            (
                ReceiptV1 {
                    txid: transaction_id,
                    status: 0,
                    fee_charged: charged,
                    resources_used: measured,
                },
                None,
            )
        };

        let receipt_bytes = receipt.encode_canonical();
        self.receipts
            .insert(transaction_id, receipt.clone(), ctx.height);
        let mut entries = SmallVec::<[DeltaEntry; 3]>::new();
        entries.push(DeltaEntry {
            tree: TreeId::Receipts,
            key: transaction_id,
            sub_key: None,
            value: Some(receipt_bytes),
        });
        for ((account, asset), amount) in balances {
            let tree = self.balances.entry(account).or_default();
            let value = if amount == 0 {
                tree.remove(&asset);
                None
            } else {
                let encoded = encode_amount(amount);
                tree.insert(asset, encoded.clone());
                Some(encoded)
            };
            entries.push(DeltaEntry {
                tree: TreeId::AccountBalances,
                key: account,
                sub_key: Some(asset),
                value,
            });
            deferred.dirty_accounts.insert(account);
        }
        deferred.dirty_account_records.insert(sender);
        let delta = StateDelta { entries };
        Ok(Some(match failed_code {
            Some(code) => ApplyOutcome::Failed {
                receipt,
                delta,
                code,
            },
            None => ApplyOutcome::Applied { receipt, delta },
        }))
    }

    /// Execute the exact admission, authorization, fee, and action pipeline
    /// used by [`Self::apply_transaction`] without committing any mutation.
    pub fn simulate_transaction(
        &self,
        ctx: &BlockContext,
        tx_bytes: &[u8],
        witness_bytes: &[u8],
        engine: &dyn ContractEngine,
        auth: &dyn AuthVerifier,
    ) -> Result<SimulationOutcome, RejectReason> {
        let prepared = self.prepare_transaction(ctx, tx_bytes, witness_bytes, auth, None)?;
        Ok(match self.evaluate_transaction(ctx, &prepared, engine) {
            EvaluatedTransaction::Applied { receipt, .. } => SimulationOutcome::Applied { receipt },
            EvaluatedTransaction::Failed { receipt, code } => {
                SimulationOutcome::Failed { receipt, code }
            }
        })
    }

    fn prepare_transaction(
        &self,
        ctx: &BlockContext,
        tx_bytes: &[u8],
        witness_bytes: &[u8],
        auth: &dyn AuthVerifier,
        fee_context: Option<(&FeeParamsV1, &fees::Prices)>,
    ) -> Result<PreparedTransaction<'static>, RejectReason> {
        let tx =
            TransactionV1::decode_canonical(tx_bytes).map_err(|_| RejectReason::Noncanonical)?;
        let witnesses = TransactionWitnessesV1::decode_canonical(witness_bytes)
            .map_err(|_| RejectReason::Noncanonical)?;
        let encoded_len = u64::try_from(tx_bytes.len())
            .ok()
            .zip(u64::try_from(witness_bytes.len()).ok())
            .and_then(|(transaction, witness)| transaction.checked_add(witness))
            .ok_or(RejectReason::OversizedEncoding)?;
        self.prepare_decoded_transaction(
            ctx,
            Cow::Owned(tx),
            &witnesses,
            encoded_len,
            auth,
            fee_context,
        )
    }

    fn prepare_decoded_transaction<'a>(
        &self,
        ctx: &BlockContext,
        tx: Cow<'a, TransactionV1>,
        witnesses: &TransactionWitnessesV1,
        encoded_len: u64,
        auth: &dyn AuthVerifier,
        fee_context: Option<(&FeeParamsV1, &fees::Prices)>,
    ) -> Result<PreparedTransaction<'a>, RejectReason> {
        let mut actions: Vec<ActionV1> = Vec::with_capacity(tx.actions.len());
        for raw in tx.actions.iter() {
            let action = ActionV1::decode_canonical(raw.as_slice())
                .map_err(|_| RejectReason::ActionMalformed)?;
            actions.push(action);
        }
        let txid = auth.precomputed_transaction_id(&tx).map_or_else(
            || crate::objects::txid(&tx),
            |precomputed| {
                debug_assert_eq!(precomputed, crate::objects::txid(&tx));
                precomputed
            },
        );
        if tx.chain_id != ctx.chain_id {
            return Err(RejectReason::WrongChain);
        }
        if tx.format_version != TransactionV1::VERSION {
            return Err(RejectReason::WrongFormatVersion);
        }
        if ctx.height > tx.expiry_height {
            return Err(RejectReason::Expired);
        }
        let (fee_params, prices) = if let Some((fee_params, prices)) = fee_context {
            (fee_params.clone(), *prices)
        } else {
            let fee_params = self.fee_params().ok_or(RejectReason::GovernanceDenied)?;
            let prices = self
                .fee_state()
                .ok_or(RejectReason::GovernanceDenied)?
                .prices();
            (fee_params, prices)
        };
        let capacity = fee_params.capacity();
        let declared = fees::usage_from_resources(&tx.resource_limits);
        for i in 0..fees::DIMENSIONS {
            if declared[i] > capacity[i] {
                return Err(RejectReason::ResourceLimitExceedsCapacity);
            }
        }
        if encoded_len > tx.resource_limits.bytes {
            return Err(RejectReason::OversizedEncoding);
        }
        if self.receipts.contains(&txid) {
            return Err(RejectReason::TxAlreadySettled);
        }
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
            let account = self
                .get_account(account_id)
                .ok_or(RejectReason::UnknownAccountInput)?;
            input_accounts.push((*account_id, account));
        }
        for entry in tx.object_access_list.iter() {
            let object = self
                .get_object(&entry.object_id)
                .ok_or(RejectReason::UnknownObject)?;
            if object.flags & ObjectV1::FLAG_QUARANTINED != 0 {
                return Err(RejectReason::ObjectQuarantined);
            }
        }
        if !tx
            .account_inputs
            .iter()
            .any(|account| *account == tx.fee_payer)
        {
            return Err(RejectReason::FeePayerNotDeclared);
        }
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
        for ((_, account), intent) in input_accounts.iter().zip(witnesses.intents.iter()) {
            if intent.tx_commitment != txid {
                return Err(RejectReason::SignatureInvalid);
            }
            if !auth.verify_signature(
                intent.signature_suite,
                account.auth_descriptor.as_slice(),
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
        self.validate_action_authority(ctx, &actions, &tx, &fee_params)?;
        let mut planned_outputs: Vec<(Hash32, NoteV1)> = Vec::with_capacity(tx.outputs.len());
        for (index, note) in tx.outputs.iter().enumerate() {
            if note.birth_height != ctx.height {
                return Err(RejectReason::OutputBirthHeightMismatch);
            }
            let index = u32::try_from(index).map_err(|_| RejectReason::Noncanonical)?;
            let id = crate::objects::note_id(&txid, index, note);
            if self.notes.contains(&id) || planned_outputs.iter().any(|(other, _)| *other == id) {
                return Err(RejectReason::DuplicateOutputNote);
            }
            planned_outputs.push((id, note.clone()));
        }
        let max_fee = fees::fee(&prices, &declared).ok_or(RejectReason::FeeOverflow)?;
        if self.balance(&tx.fee_payer, &NOOS_ASSET) < max_fee {
            return Err(RejectReason::InsufficientFeeBalance);
        }
        Ok(PreparedTransaction {
            tx,
            actions,
            txid,
            input_notes,
            input_accounts,
            planned_outputs,
            fee_params,
            prices,
            max_fee,
            encoded_len,
        })
    }

    fn evaluate_transaction(
        &self,
        ctx: &BlockContext,
        prepared: &PreparedTransaction<'_>,
        engine: &dyn ContractEngine,
    ) -> EvaluatedTransaction {
        let exec = self.execute_in_overlay(
            ctx,
            &prepared.tx,
            &prepared.txid,
            &prepared.actions,
            &prepared.input_notes,
            &prepared.input_accounts,
            &prepared.planned_outputs,
            prepared.max_fee,
            engine,
        );
        match exec {
            Ok((mut overlay, grain_steps, storage_words)) => {
                let measured = ResourceVector {
                    bytes: prepared.encoded_len,
                    grain_steps,
                    proof_units: u64::try_from(prepared.tx.evidence_refs.len()).unwrap_or(u64::MAX),
                    state_reads: overlay.state_reads,
                    state_writes: overlay.state_writes.max(storage_words),
                    blob_bytes: 0,
                };
                if !measured.fits_within(&prepared.tx.resource_limits) {
                    return EvaluatedTransaction::Failed {
                        receipt: failure_receipt(
                            &prepared.txid,
                            FailCode::ResourceOverrun,
                            prepared.max_fee,
                            &prepared.fee_params,
                            prepared.encoded_len,
                        ),
                        code: FailCode::ResourceOverrun,
                    };
                }
                let used = fees::usage_from_resources(&measured);
                let Some(actual_fee) = fees::fee(&prepared.prices, &used) else {
                    return EvaluatedTransaction::Failed {
                        receipt: failure_receipt(
                            &prepared.txid,
                            FailCode::Overflow,
                            prepared.max_fee,
                            &prepared.fee_params,
                            prepared.encoded_len,
                        ),
                        code: FailCode::Overflow,
                    };
                };
                let charged = actual_fee.min(prepared.max_fee);
                let payer_now =
                    overlay_balance(&overlay, self, &prepared.tx.fee_payer, &NOOS_ASSET);
                let Some(after_fee) = payer_now.checked_sub(charged) else {
                    return EvaluatedTransaction::Failed {
                        receipt: failure_receipt(
                            &prepared.txid,
                            FailCode::InsufficientBalance,
                            prepared.max_fee,
                            &prepared.fee_params,
                            prepared.encoded_len,
                        ),
                        code: FailCode::InsufficientBalance,
                    };
                };
                overlay
                    .balances
                    .insert((prepared.tx.fee_payer, NOOS_ASSET), after_fee);
                let receipt = ReceiptV1 {
                    txid: prepared.txid,
                    status: 0,
                    fee_charged: charged,
                    resources_used: measured,
                };
                overlay
                    .receipts
                    .insert(prepared.txid, Some(receipt.clone()));
                EvaluatedTransaction::Applied { overlay, receipt }
            }
            Err(code) => EvaluatedTransaction::Failed {
                receipt: failure_receipt(
                    &prepared.txid,
                    code,
                    prepared.max_fee,
                    &prepared.fee_params,
                    prepared.encoded_len,
                ),
                code,
            },
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
                ActionV1::CreateOracleFeed { .. }
                | ActionV1::CreateLendingMarket { .. }
                | ActionV1::SetOracleMode { .. }
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
                | ActionV1::PsmMint { owner, .. }
                | ActionV1::PsmRedeem { owner, .. }
                    if !signed(owner) =>
                {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::LiquidatePosition { liquidator, .. } if !signed(liquidator) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::BackstopLiquidate { keeper, .. } if !signed(keeper) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::FundStableReserve { contributor, .. } if !signed(contributor) => {
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
                ActionV1::RegisterNeuralProgram(_) if !gov_ok() => {
                    return Err(RejectReason::GovernanceDenied);
                }
                ActionV1::EvaluateNeuralProgram(v) if !signed(&v.requester) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::OpenNeuralOracleQuery(v) if !signed(&v.requester) => {
                    return Err(RejectReason::CapabilityDenied);
                }
                ActionV1::CommitNeuralOracleReply(v) => {
                    let operator = self
                        .neural_reporter_operator(&v.query_id, &v.reporter_profile_id)
                        .ok_or(RejectReason::CapabilityDenied)?;
                    if !signed(&operator) {
                        return Err(RejectReason::CapabilityDenied);
                    }
                }
                ActionV1::RevealNeuralOracleReply(v) => {
                    let operator = self
                        .neural_reporter_operator(&v.query_id, &v.reporter_profile_id)
                        .ok_or(RejectReason::CapabilityDenied)?;
                    if !signed(&operator) {
                        return Err(RejectReason::CapabilityDenied);
                    }
                }
                ActionV1::RecordWwmReceipt(v) => {
                    if let Some(result) = self.get_neural_oracle_result(&v.job_id) {
                        match result.status {
                            NeuralOracleStatus::Success => {
                                if result.signer_profile_ids.is_empty() {
                                    return Err(RejectReason::CapabilityDenied);
                                }
                                for profile_id in result.signer_profile_ids.iter() {
                                    let operator = self
                                        .neural_reporter_operator(&v.job_id, profile_id)
                                        .ok_or(RejectReason::CapabilityDenied)?;
                                    if !signed(&operator) {
                                        return Err(RejectReason::CapabilityDenied);
                                    }
                                }
                            }
                            NeuralOracleStatus::NoQuorum => {
                                let query = self
                                    .get_neural_oracle_query(&v.job_id)
                                    .ok_or(RejectReason::CapabilityDenied)?;
                                if !signed(&query.requester) {
                                    return Err(RejectReason::CapabilityDenied);
                                }
                            }
                        }
                    } else if !gov_ok() {
                        return Err(RejectReason::GovernanceDenied);
                    }
                }
                ActionV1::TransitionWwmControl(
                    TransitionWwmControlPayloadV1::EmergencyDisable(_),
                ) if !emergency_ok() => return Err(RejectReason::GovernanceDenied),
                ActionV1::RegisterArtifactDescriptor(_)
                | ActionV1::RegisterCustodianProfile(_)
                | ActionV1::RegisterAvailabilityPolicy(_)
                | ActionV1::CommitCustodyPositions(_)
                | ActionV1::RecordCustodyChallenge(_)
                | ActionV1::RecordCustodyProbe(_)
                | ActionV1::IssueAvailabilityCertificate(_)
                | ActionV1::RecordArtifactRepair(_)
                | ActionV1::RegisterModelCapsuleV2(_)
                | ActionV1::RegisterExecutionProfile(_)
                | ActionV1::RegisterExecutorProfile(_)
                | ActionV1::RegisterFeePolicy(_)
                | ActionV1::RegisterFundProfile(_)
                | ActionV1::RegisterQueryPolicy(_)
                | ActionV1::RegisterServiceDirectory(_)
                | ActionV1::OpenWwmJob(_)
                | ActionV1::SettleWwmJob(_)
                | ActionV1::TransitionServingAlias(_)
                | ActionV1::TransitionWwmControl(_)
                    if !gov_ok() =>
                {
                    return Err(RejectReason::GovernanceDenied);
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

    fn neural_reporter_operator(
        &self,
        query_id: &Hash32,
        reporter_profile_id: &Hash32,
    ) -> Option<Hash32> {
        let query = self.get_neural_oracle_query(query_id)?;
        let job = self
            .objects
            .get(&wwm_profile_key(WwmLeafKind::Job, &query.job_id))
            .and_then(|bytes| WwmJobV1::decode_canonical(bytes).ok())?;
        if !job
            .selected_executor_ids
            .iter()
            .any(|profile_id| profile_id == reporter_profile_id)
        {
            return None;
        }
        let set = self
            .objects
            .get(&wwm_profile_key(
                WwmLeafKind::ExecutorCapabilitySet,
                &query.executor_set_id,
            ))
            .and_then(|bytes| CapabilitySetV1::decode_canonical(bytes).ok())?;
        if set.epoch != query.executor_set_epoch {
            return None;
        }
        set.entries
            .iter()
            .find(|profile| {
                profile.profile_id == *reporter_profile_id
                    && profile.status == CapabilityStatus::Active
            })
            .map(|profile| profile.operator_id)
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
                    reporter_3,
                    reporter_4,
                    max_deviation_bps,
                    twap_window_blocks,
                    max_age_blocks,
                } => {
                    let reporters = [
                        *reporter_0,
                        *reporter_1,
                        *reporter_2,
                        *reporter_3,
                        *reporter_4,
                    ];
                    let mut unique_reporters = reporters;
                    unique_reporters.sort_unstable();
                    if base_asset == quote_asset
                        || unique_reporters.windows(2).any(|pair| pair[0] == pair[1])
                        || !(1..=5_000).contains(max_deviation_bps)
                        || !(2..=10_000).contains(twap_window_blocks)
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
                        reporter_3: *reporter_3,
                        reporter_4: *reporter_4,
                        max_age_blocks: *max_age_blocks,
                        max_deviation_bps: *max_deviation_bps,
                        twap_window_blocks: *twap_window_blocks,
                        last_good_price_q9: 0,
                        last_good_height: 0,
                        twap_price_q9: 0,
                        twap_height: 0,
                        mode: ORACLE_MODE_LIVE,
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
                    if ![
                        feed.reporter_0,
                        feed.reporter_1,
                        feed.reporter_2,
                        feed.reporter_3,
                        feed.reporter_4,
                    ]
                    .contains(reporter)
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
                    if let Some(median) = fresh_reporter_median(&mut ov, self, &feed, ctx.height)? {
                        if feed.last_good_price_q9 != 0
                            && deviation_bps(median, feed.last_good_price_q9)?
                                > feed.max_deviation_bps
                        {
                            return Err(FailCode::PostconditionFailed);
                        }
                        let mut updated = feed;
                        updated.last_good_price_q9 = median;
                        updated.last_good_height = ctx.height;
                        updated.twap_price_q9 = update_twap(
                            updated.twap_price_q9,
                            median,
                            updated.twap_height,
                            ctx.height,
                            updated.twap_window_blocks,
                        )?;
                        updated.twap_height = ctx.height;
                        updated.mode = ORACLE_MODE_LIVE;
                        ov.objects
                            .insert(updated.feed_id, Some(updated.encode_canonical()));
                        ov.write_count()?;
                    }
                }
                ActionV1::SetOracleMode { feed_id, mode } => {
                    if !matches!(
                        *mode,
                        ORACLE_MODE_LIVE | ORACLE_MODE_LAST_GOOD | ORACLE_MODE_FROZEN
                    ) {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let raw =
                        overlay_object(&ov, self, feed_id).ok_or(FailCode::PostconditionFailed)?;
                    let mut feed = decode_oracle_feed(&raw, feed_id)?;
                    if *mode == ORACLE_MODE_LAST_GOOD && feed.last_good_price_q9 == 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    feed.mode = *mode;
                    ov.objects.insert(*feed_id, Some(feed.encode_canonical()));
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
                    let safety_id = derive_stable_safety_id(&market_id);
                    if overlay_object(&ov, self, &market_id).is_some()
                        || overlay_object(&ov, self, &stable_id).is_some()
                        || overlay_object(&ov, self, &safety_id).is_some()
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
                    let safety = StableSafetyV1 {
                        safety_id,
                        market_id,
                        stable_reserve: 0,
                        collateral_reserve: 0,
                        psm_debt: 0,
                        uncovered_bad_debt: 0,
                        psm_fee_bps: DEFAULT_PSM_FEE_BPS,
                    };
                    ov.objects
                        .insert(market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable_id, Some(stable.encode_canonical()));
                    ov.objects
                        .insert(safety_id, Some(safety.encode_canonical()));
                    ov.write_count()?;
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
                        let price = risk_increasing_oracle_price(&mut ov, self, &feed, ctx.height)?;
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
                    let price = risk_increasing_oracle_price(&mut ov, self, &feed, ctx.height)?;
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
                    let price = liquidation_oracle_price(&mut ov, self, &feed, ctx.height)?;
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
                ActionV1::FundStableReserve {
                    contributor,
                    market_id,
                    amount,
                } => {
                    if *amount == 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let market = decode_lending_market(&market_raw, market_id)?;
                    let safety_id = derive_stable_safety_id(market_id);
                    let safety_raw = overlay_object(&ov, self, &safety_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut safety = decode_stable_safety(&safety_raw, &market)?;
                    let balance = overlay_balance(&ov, self, contributor, &market.stable_asset);
                    let mut state = safety_state(&safety);
                    state
                        .fund_stable_reserve(*amount)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    update_safety(&mut safety, state);
                    ov.balances.insert(
                        (*contributor, market.stable_asset),
                        balance
                            .checked_sub(*amount)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.objects
                        .insert(safety_id, Some(safety.encode_canonical()));
                    ov.write_count()?;
                    ov.write_count()?;
                }
                ActionV1::BackstopLiquidate {
                    keeper: _,
                    market_id,
                    owner,
                } => {
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut market = decode_lending_market(&market_raw, market_id)?;
                    let stable_raw = overlay_object(&ov, self, &market.stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut stable = decode_stable_asset(&stable_raw, &market)?;
                    let safety_id = derive_stable_safety_id(market_id);
                    let safety_raw = overlay_object(&ov, self, &safety_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut safety = decode_stable_safety(&safety_raw, &market)?;
                    let position_id = derive_debt_position_id(market_id, owner);
                    let position_raw = overlay_object(&ov, self, &position_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut position = decode_debt_position(&position_raw, market_id, owner)?;
                    if safety.stable_reserve < position.debt {
                        return Err(FailCode::InsufficientBalance);
                    }
                    let feed_raw = overlay_object(&ov, self, &market.oracle_feed_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&feed_raw, &market.oracle_feed_id)?;
                    let price = liquidation_oracle_price(&mut ov, self, &feed, ctx.height)?;
                    let mut state = safety_state(&safety);
                    let result = state
                        .backstop_liquidate(
                            safety_policy(&market, &safety),
                            SafetyDebtPosition {
                                collateral: position.collateral,
                                debt: position.debt,
                            },
                            price,
                        )
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if result.remaining_position.debt != 0 || result.newly_uncovered_bad_debt != 0 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    position.collateral = result.remaining_position.collateral;
                    position.debt = 0;
                    market.total_debt = market
                        .total_debt
                        .checked_sub(result.stable_burned)
                        .ok_or(FailCode::PostconditionFailed)?;
                    stable.minted_supply = stable
                        .minted_supply
                        .checked_sub(result.stable_burned)
                        .ok_or(FailCode::PostconditionFailed)?;
                    update_safety(&mut safety, state);
                    if stable.minted_supply != market.total_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(position_id, Some(position.encode_canonical()));
                    ov.objects
                        .insert(*market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable.asset_id, Some(stable.encode_canonical()));
                    ov.objects
                        .insert(safety_id, Some(safety.encode_canonical()));
                    for _ in 0..4 {
                        ov.write_count()?;
                    }
                }
                ActionV1::PsmMint {
                    owner,
                    market_id,
                    collateral_in,
                    min_stable_out,
                } => {
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut market = decode_lending_market(&market_raw, market_id)?;
                    let stable_raw = overlay_object(&ov, self, &market.stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut stable = decode_stable_asset(&stable_raw, &market)?;
                    let safety_id = derive_stable_safety_id(market_id);
                    let safety_raw = overlay_object(&ov, self, &safety_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut safety = decode_stable_safety(&safety_raw, &market)?;
                    let feed_raw = overlay_object(&ov, self, &market.oracle_feed_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&feed_raw, &market.oracle_feed_id)?;
                    let price = risk_increasing_oracle_price(&mut ov, self, &feed, ctx.height)?;
                    let mut state = safety_state(&safety);
                    let result = state
                        .psm_mint(safety_policy(&market, &safety), *collateral_in, price)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if result.stable_to_user < *min_stable_out {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let new_total_debt = market
                        .total_debt
                        .checked_add(result.supply_and_debt_increase)
                        .ok_or(FailCode::Overflow)?;
                    if new_total_debt > market.debt_ceiling {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let collateral_balance =
                        overlay_balance(&ov, self, owner, &market.collateral_asset);
                    let stable_balance = overlay_balance(&ov, self, owner, &market.stable_asset);
                    ov.balances.insert(
                        (*owner, market.collateral_asset),
                        collateral_balance
                            .checked_sub(*collateral_in)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.balances.insert(
                        (*owner, market.stable_asset),
                        stable_balance
                            .checked_add(result.stable_to_user)
                            .ok_or(FailCode::Overflow)?,
                    );
                    market.total_debt = new_total_debt;
                    stable.minted_supply = stable
                        .minted_supply
                        .checked_add(result.supply_and_debt_increase)
                        .ok_or(FailCode::Overflow)?;
                    update_safety(&mut safety, state);
                    if stable.minted_supply != market.total_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(*market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable.asset_id, Some(stable.encode_canonical()));
                    ov.objects
                        .insert(safety_id, Some(safety.encode_canonical()));
                    for _ in 0..5 {
                        ov.write_count()?;
                    }
                }
                ActionV1::PsmRedeem {
                    owner,
                    market_id,
                    stable_in,
                    min_collateral_out,
                } => {
                    let market_raw = overlay_object(&ov, self, market_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut market = decode_lending_market(&market_raw, market_id)?;
                    let stable_raw = overlay_object(&ov, self, &market.stable_asset)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut stable = decode_stable_asset(&stable_raw, &market)?;
                    let safety_id = derive_stable_safety_id(market_id);
                    let safety_raw = overlay_object(&ov, self, &safety_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let mut safety = decode_stable_safety(&safety_raw, &market)?;
                    let feed_raw = overlay_object(&ov, self, &market.oracle_feed_id)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let feed = decode_oracle_feed(&feed_raw, &market.oracle_feed_id)?;
                    let price = risk_increasing_oracle_price(&mut ov, self, &feed, ctx.height)?;
                    let mut state = safety_state(&safety);
                    let result = state
                        .psm_redeem(safety_policy(&market, &safety), *stable_in, price)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if result.collateral_to_user < *min_collateral_out {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let stable_balance = overlay_balance(&ov, self, owner, &market.stable_asset);
                    let collateral_balance =
                        overlay_balance(&ov, self, owner, &market.collateral_asset);
                    ov.balances.insert(
                        (*owner, market.stable_asset),
                        stable_balance
                            .checked_sub(*stable_in)
                            .ok_or(FailCode::InsufficientBalance)?,
                    );
                    ov.balances.insert(
                        (*owner, market.collateral_asset),
                        collateral_balance
                            .checked_add(result.collateral_to_user)
                            .ok_or(FailCode::Overflow)?,
                    );
                    market.total_debt = market
                        .total_debt
                        .checked_sub(result.supply_and_debt_decrease)
                        .ok_or(FailCode::PostconditionFailed)?;
                    stable.minted_supply = stable
                        .minted_supply
                        .checked_sub(result.supply_and_debt_decrease)
                        .ok_or(FailCode::PostconditionFailed)?;
                    update_safety(&mut safety, state);
                    if stable.minted_supply != market.total_debt {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects
                        .insert(*market_id, Some(market.encode_canonical()));
                    ov.objects
                        .insert(stable.asset_id, Some(stable.encode_canonical()));
                    ov.objects
                        .insert(safety_id, Some(safety.encode_canonical()));
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
                ActionV1::RegisterArtifactDescriptor(v) => {
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::Artifact, &v.artifact_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RegisterCustodianProfile(v) => {
                    apply_custodian_mutation(&mut ov, self, v)?;
                }
                ActionV1::RegisterAvailabilityPolicy(v) => {
                    require_wwm(&ov, self, WwmLeafKind::Artifact, &v.artifact_id)?;
                    if v.position_count != 12
                        || v.reconstruction_threshold != 8
                        || v.schedulable_minimum != 9
                        || v.samples_per_challenge == 0
                        || v.verifier_sample_size != 8
                        || v.verifier_threshold != 5
                        || v.reconstructor_sample_size != 5
                        || v.reconstructor_threshold != 3
                        || v.policy_start_height >= v.policy_end_height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::AvailabilityPolicy, &v.policy_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::CommitCustodyPositions(v) => {
                    require_wwm(&ov, self, WwmLeafKind::Artifact, &v.artifact_id)?;
                    require_wwm(&ov, self, WwmLeafKind::AvailabilityPolicy, &v.policy_id)?;
                    let registry = current_registry(&ov, self)?;
                    if v.position >= 12
                        || v.custodian_set_id != registry.custodian_set_id
                        || v.custodian_set_epoch != registry.custodian_epoch
                        || v.valid_from >= v.valid_until
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::CustodyCommitment, &v.commitment_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RecordCustodyChallenge(v) => {
                    require_wwm(&ov, self, WwmLeafKind::CustodyCommitment, &v.commitment_id)?;
                    require_wwm(&ov, self, WwmLeafKind::AvailabilityPolicy, &v.policy_id)?;
                    if v.probe_indices.is_empty()
                        || v.issued_height >= v.response_deadline_height
                        || v.finalized_beacon_height > v.issued_height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::CustodyChallenge, &v.challenge_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RecordCustodyProbe(v) => {
                    require_wwm(&ov, self, WwmLeafKind::CustodyChallenge, &v.challenge_id)?;
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::CustodyProbe, &v.probe_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::IssueAvailabilityCertificate(v) => {
                    require_wwm(&ov, self, WwmLeafKind::AvailabilityPolicy, &v.policy_id)?;
                    if v.availability_state > 2 {
                        return Err(FailCode::PostconditionFailed);
                    }
                    if v.selected_verifiers.len() != 8
                        || v.signer_ids.len() != 5
                        || !strict_hashes(v.selected_verifiers.as_slice())
                        || !strict_hashes(v.signer_ids.as_slice())
                        || v.valid_until <= v.issued_height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::Certificate, &v.certificate_id),
                        v.encode_canonical(),
                    )?;
                    ov.objects.insert(
                        wwm_fixed_key(WwmLeafKind::CurrentCertificatePointer),
                        Some(v.certificate_id.to_vec()),
                    );
                    ov.write_count()?;
                }
                ActionV1::RecordArtifactRepair(v) => match v {
                    crate::wwm::ArtifactRepairPayloadV1::Order(order) => {
                        require_wwm(&ov, self, WwmLeafKind::AvailabilityPolicy, &order.policy_id)?;
                        if order.position >= 12
                            || order.issued_height >= order.deadline_height
                            || order.source_commitment_ids.len() != 8
                            || order.source_positions.len() != 8
                            || !strict_hashes(order.source_commitment_ids.as_slice())
                            || !order
                                .source_positions
                                .as_slice()
                                .windows(2)
                                .all(|w| w[0] < w[1])
                            || order.expected_position_root == [0; 32]
                        {
                            return Err(FailCode::PostconditionFailed);
                        }
                        wwm_insert_unique(
                            &mut ov,
                            self,
                            wwm_profile_key(WwmLeafKind::ArtifactRepair, &order.order_id),
                            order.encode_canonical(),
                        )?;
                    }
                    crate::wwm::ArtifactRepairPayloadV1::Receipt(receipt) => {
                        require_wwm(&ov, self, WwmLeafKind::ArtifactRepair, &receipt.order_id)?;
                        require_wwm(
                            &ov,
                            self,
                            WwmLeafKind::CustodyCommitment,
                            &receipt.prior_commitment_id,
                        )?;
                        require_wwm(
                            &ov,
                            self,
                            WwmLeafKind::CustodyCommitment,
                            &receipt.new_commitment_id,
                        )?;
                        if receipt.bytes_read == 0
                            || receipt.bytes_written == 0
                            || receipt.evidence_root == [0; 32]
                            || receipt.signer_id == [0; 32]
                        {
                            return Err(FailCode::PostconditionFailed);
                        }
                        require_wwm(&ov, self, WwmLeafKind::Certificate, &receipt.certificate_id)?;
                        wwm_insert_unique(
                            &mut ov,
                            self,
                            wwm_profile_key(WwmLeafKind::ArtifactRepair, &receipt.repair_id),
                            receipt.encode_canonical(),
                        )?;
                    }
                },
                ActionV1::RegisterModelCapsuleV2(v) => {
                    require_wwm(&ov, self, WwmLeafKind::Artifact, &v.artifact_id)?;
                    require_wwm(
                        &ov,
                        self,
                        WwmLeafKind::AvailabilityPolicy,
                        &v.availability_policy_id,
                    )?;
                    if v.payload_root == [0; 32]
                        || v.manifest_root == [0; 32]
                        || v.runtime_root == [0; 32]
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::Capsule, &v.capsule_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RegisterExecutionProfile(v) => {
                    require_wwm(&ov, self, WwmLeafKind::Capsule, &v.capsule_id)?;
                    if v.attachments_allowed != 0
                        || v.max_output_tokens == 0
                        || v.max_context_tokens == 0
                        || v.max_output_tokens > v.max_context_tokens
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::ExecutionProfile, &v.profile_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RegisterExecutorProfile(v) => {
                    apply_capability_mutation(
                        &mut ov,
                        self,
                        WwmLeafKind::ExecutorCapabilitySet,
                        v,
                    )?;
                }
                ActionV1::RegisterFeePolicy(v) => {
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::FeePolicy, &v.policy_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RegisterFundProfile(v) => {
                    apply_fund_profile_mutation(&mut ov, self, ctx.height, v)?;
                }
                ActionV1::RegisterQueryPolicy(v) => {
                    require_wwm(&ov, self, WwmLeafKind::Capsule, &v.capsule_id)?;
                    if v.attachments_allowed != 0
                        || v.max_total_tokens == 0
                        || v.max_input_tokens
                            .checked_add(v.max_output_tokens)
                            .is_none_or(|n| n > v.max_total_tokens)
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::QueryPolicy, &v.policy_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RegisterServiceDirectory(v) => {
                    if v.not_before_height >= v.not_after_height || v.endpoint_records.is_empty() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::ServiceDirectory, &v.directory_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::OpenWwmJob(v) => {
                    let control = current_control(&ov, self)?;
                    if !matches!(
                        control.mode,
                        WwmControlMode::Testnet
                            | WwmControlMode::Canary
                            | WwmControlMode::Production
                    ) || control.active_config_id != control.resolution_config_id
                        || control.active_capsule_id.0 != Some(v.capsule_id)
                        || control.capsule_id != v.capsule_id
                        || control.execution_profile_id != v.execution_profile_id
                        || control.query_policy_id != v.query_policy_id
                        || v.chain_id != ctx.chain_id
                        || v.offchain_envelope_root == [0; 32]
                        || v.selected_executor_ids.is_empty()
                        || v.max_input_tokens == 0
                        || v.max_output_tokens == 0
                        || v.deadline_height <= ctx.height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    require_wwm(
                        &ov,
                        self,
                        WwmLeafKind::ExecutionProfile,
                        &v.execution_profile_id,
                    )?;
                    require_wwm(&ov, self, WwmLeafKind::QueryPolicy, &v.query_policy_id)?;
                    require_wwm(
                        &ov,
                        self,
                        WwmLeafKind::Certificate,
                        &v.availability_certificate_id,
                    )?;
                    require_wwm(&ov, self, WwmLeafKind::FundProfile, &v.fund_profile_id)?;
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::Job, &v.job_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RecordWwmReceipt(v) => {
                    let job_bytes =
                        overlay_object(&ov, self, &wwm_profile_key(WwmLeafKind::Job, &v.job_id))
                            .ok_or(FailCode::PostconditionFailed)?;
                    let job = WwmJobV1::decode_canonical(&job_bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let capsule_bytes = overlay_object(
                        &ov,
                        self,
                        &wwm_profile_key(WwmLeafKind::Capsule, &job.capsule_id),
                    )
                    .ok_or(FailCode::PostconditionFailed)?;
                    let capsule = ModelCapsuleV2::decode_canonical(&capsule_bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if v.job_id != job.job_id
                        || v.capsule_id != job.capsule_id
                        || v.artifact_id != capsule.artifact_id
                        || v.tokenizer_root != capsule.tokenizer_root
                        || v.template_root != capsule.template_root
                        || v.runtime_root != capsule.runtime_root
                        || v.sbom_root != capsule.sbom_root
                        || v.execution_profile_id != job.execution_profile_id
                        || v.input_tokens > job.max_input_tokens
                        || v.output_tokens > job.max_output_tokens
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    if overlay_object(&ov, self, &neural_query_key(&job.job_id)).is_some() {
                        validate_neural_wwm_receipt(&ov, self, &job, v, ctx.height)?;
                    } else if v.output_root == [0; 32] || v.token_history_root == [0; 32] {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::Receipt, &v.receipt_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::SettleWwmJob(v) => {
                    let job_bytes =
                        overlay_object(&ov, self, &wwm_profile_key(WwmLeafKind::Job, &v.job_id))
                            .ok_or(FailCode::PostconditionFailed)?;
                    let job = WwmJobV1::decode_canonical(&job_bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let receipt_bytes = overlay_object(
                        &ov,
                        self,
                        &wwm_profile_key(WwmLeafKind::Receipt, &v.receipt_id),
                    )
                    .ok_or(FailCode::PostconditionFailed)?;
                    let receipt = WwmReceiptV1::decode_canonical(&receipt_bytes)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let terminal_total = v
                        .paid_amount
                        .checked_add(v.refunded_amount)
                        .and_then(|value| value.checked_add(v.released_amount))
                        .ok_or(FailCode::Overflow)?;
                    if receipt.job_id != job.job_id
                        || v.job_id != job.job_id
                        || v.receipt_id != receipt.receipt_id
                        || v.fund_profile_id != job.fund_profile_id
                        || v.bucket != FundBucketTag::Job
                        || v.paid_amount != receipt.paid_amount
                        || v.refunded_amount != receipt.refunded_amount
                        || terminal_total != job.reserved_amount
                        || v.settled_height < receipt.anchor_height
                        || v.settled_height > ctx.height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        wwm_profile_key(WwmLeafKind::Settlement, &v.settlement_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::RegisterNeuralProgram(v) => {
                    if validate_neural_program(v).is_err() {
                        return Err(FailCode::PostconditionFailed);
                    }
                    wwm_insert_unique(
                        &mut ov,
                        self,
                        neural_program_key(&v.program_id),
                        v.encode_canonical(),
                    )?;
                }
                ActionV1::EvaluateNeuralProgram(v) => {
                    let control = current_control(&ov, self)?;
                    if !matches!(
                        control.mode,
                        WwmControlMode::Testnet
                            | WwmControlMode::Canary
                            | WwmControlMode::Production
                    ) || v.query_id == [0; 32]
                        || overlay_account(&ov, self, &v.requester).is_none()
                        || overlay_object(&ov, self, &neural_query_key(&v.query_id)).is_some()
                        || overlay_object(&ov, self, &neural_result_key(&v.query_id)).is_some()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let program_raw = overlay_object(&ov, self, &neural_program_key(&v.program_id))
                        .ok_or(FailCode::PostconditionFailed)?;
                    let program = NeuralProgramV1::decode_canonical(&program_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let evaluation = evaluate_neural_program(&program, v.input.as_slice())
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    grain_steps = grain_steps
                        .checked_add(evaluation.operations)
                        .ok_or(FailCode::Overflow)?;
                    let response = BoundedBytes::new(evaluation.output.as_slice().to_vec())
                        .ok_or(FailCode::Overflow)?;
                    let output_root = neural_output_root(response.as_slice());
                    let transcript_root = neural_transcript_root(response.as_slice());
                    let result = NeuralOracleResultV1 {
                        result_id: neural_result_id(&v.query_id, &output_root, &transcript_root),
                        query_id: v.query_id,
                        mode: NeuralOracleMode::L1Deterministic,
                        status: NeuralOracleStatus::Success,
                        source_id: v.program_id,
                        execution_profile_id: [0; 32],
                        input_root: neural_input_root(v.input.as_slice()),
                        response,
                        output_root,
                        transcript_root,
                        signer_profile_ids: crate::objects::BoundedList::default(),
                        finalized_height: ctx.height,
                    };
                    ov.objects.insert(
                        neural_result_key(&v.query_id),
                        Some(result.encode_canonical()),
                    );
                    ov.write_count()?;
                }
                ActionV1::OpenNeuralOracleQuery(v) => {
                    let control = current_control(&ov, self)?;
                    if !matches!(
                        control.mode,
                        WwmControlMode::Testnet
                            | WwmControlMode::Canary
                            | WwmControlMode::Production
                    ) || v.query_id == [0; 32]
                        || v.query_id != v.job_id
                        || v.input_root == [0; 32]
                        || v.max_response_bytes == 0
                        || v.max_response_bytes > MAX_NEURAL_ORACLE_RESPONSE_BYTES
                        || v.commit_deadline <= ctx.height
                        || v.reveal_deadline <= v.commit_deadline
                        || overlay_account(&ov, self, &v.requester).is_none()
                        || overlay_object(&ov, self, &neural_query_key(&v.query_id)).is_some()
                        || overlay_object(&ov, self, &neural_result_key(&v.query_id)).is_some()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let job = neural_job_for_query(&ov, self, v)?;
                    let selected = job.selected_executor_ids.as_slice();
                    if selected.len() != MAX_NEURAL_ORACLE_REPORTERS as usize
                        || !selected.windows(2).all(|window| window[0] < window[1])
                        || v.threshold != NEURAL_ORACLE_QUORUM_THRESHOLD
                        || v.reveal_deadline > job.deadline_height
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let registry = current_registry(&ov, self)?;
                    if registry.executor_set_id != v.executor_set_id
                        || registry.executor_epoch != v.executor_set_epoch
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let mut control_roots = BTreeSet::new();
                    let mut operator_accounts = BTreeSet::new();
                    for profile_id in selected {
                        let profile = neural_reporter_profile(&ov, self, v, profile_id)?;
                        if overlay_account(&ov, self, &profile.operator_id).is_none()
                            || !control_roots.insert(profile.beneficial_control_root)
                            || !operator_accounts.insert(profile.operator_id)
                        {
                            return Err(FailCode::PostconditionFailed);
                        }
                    }
                    ov.objects
                        .insert(neural_query_key(&v.query_id), Some(v.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::CommitNeuralOracleReply(v) => {
                    let query_raw = overlay_object(&ov, self, &neural_query_key(&v.query_id))
                        .ok_or(FailCode::PostconditionFailed)?;
                    let query = NeuralOracleQueryV1::decode_canonical(&query_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    neural_reporter_profile(&ov, self, &query, &v.reporter_profile_id)?;
                    let key = neural_commit_key(&v.query_id, &v.reporter_profile_id);
                    if v.commitment == [0; 32]
                        || ctx.height > query.commit_deadline
                        || overlay_object(&ov, self, &key).is_some()
                        || overlay_object(&ov, self, &neural_result_key(&v.query_id)).is_some()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let record = NeuralOracleCommitRecordV1 {
                        query_id: v.query_id,
                        reporter_profile_id: v.reporter_profile_id,
                        commitment: v.commitment,
                        committed_height: ctx.height,
                    };
                    ov.objects.insert(key, Some(record.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::RevealNeuralOracleReply(v) => {
                    let query_raw = overlay_object(&ov, self, &neural_query_key(&v.query_id))
                        .ok_or(FailCode::PostconditionFailed)?;
                    let query = NeuralOracleQueryV1::decode_canonical(&query_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let job = neural_job_for_query(&ov, self, &query)?;
                    neural_reporter_profile(&ov, self, &query, &v.reporter_profile_id)?;
                    let output_root = neural_output_root(v.response.as_slice());
                    let transcript_root = neural_transcript_root(v.response.as_slice());
                    let commit_key = neural_commit_key(&v.query_id, &v.reporter_profile_id);
                    let commit_raw = overlay_object(&ov, self, &commit_key)
                        .ok_or(FailCode::PostconditionFailed)?;
                    let commit = NeuralOracleCommitRecordV1::decode_canonical(&commit_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let reveal_key = neural_reveal_key(&v.query_id, &v.reporter_profile_id);
                    if ctx.height <= query.commit_deadline
                        || ctx.height > query.reveal_deadline
                        || v.response.is_empty()
                        || v.response.len() > query.max_response_bytes as usize
                        || v.nonce == [0; 32]
                        || v.transcript_root != transcript_root
                        || commit.query_id != v.query_id
                        || commit.reporter_profile_id != v.reporter_profile_id
                        || commit.commitment
                            != neural_reply_commitment(
                                &v.query_id,
                                &v.reporter_profile_id,
                                &output_root,
                                &transcript_root,
                                &v.nonce,
                            )
                        || overlay_object(&ov, self, &reveal_key).is_some()
                        || overlay_object(&ov, self, &neural_result_key(&v.query_id)).is_some()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let reveal = NeuralOracleRevealRecordV1 {
                        query_id: v.query_id,
                        reporter_profile_id: v.reporter_profile_id,
                        response: v.response.clone(),
                        output_root,
                        transcript_root,
                        revealed_height: ctx.height,
                    };
                    ov.objects
                        .insert(reveal_key, Some(reveal.encode_canonical()));
                    ov.write_count()?;

                    let mut signers = Vec::new();
                    for profile_id in job.selected_executor_ids.iter() {
                        let Some(raw) =
                            overlay_object(&ov, self, &neural_reveal_key(&v.query_id, profile_id))
                        else {
                            continue;
                        };
                        let candidate = NeuralOracleRevealRecordV1::decode_canonical(&raw)
                            .map_err(|_| FailCode::PostconditionFailed)?;
                        if candidate.output_root == output_root
                            && candidate.transcript_root == transcript_root
                            && candidate.response == v.response
                        {
                            signers.push(*profile_id);
                        }
                    }
                    if signers.len() >= usize::from(query.threshold) {
                        let signer_profile_ids = crate::objects::BoundedList::new(signers)
                            .ok_or(FailCode::PostconditionFailed)?;
                        let result = NeuralOracleResultV1 {
                            result_id: neural_result_id(
                                &v.query_id,
                                &output_root,
                                &transcript_root,
                            ),
                            query_id: v.query_id,
                            mode: NeuralOracleMode::WwmQuorum,
                            status: NeuralOracleStatus::Success,
                            source_id: job.capsule_id,
                            execution_profile_id: job.execution_profile_id,
                            input_root: query.input_root,
                            response: v.response.clone(),
                            output_root,
                            transcript_root,
                            signer_profile_ids,
                            finalized_height: ctx.height,
                        };
                        ov.objects.insert(
                            neural_result_key(&v.query_id),
                            Some(result.encode_canonical()),
                        );
                        ov.write_count()?;
                    }
                }
                ActionV1::FinalizeNeuralOracleQuery(v) => {
                    let query_raw = overlay_object(&ov, self, &neural_query_key(&v.query_id))
                        .ok_or(FailCode::PostconditionFailed)?;
                    let query = NeuralOracleQueryV1::decode_canonical(&query_raw)
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    let job = neural_job_for_query(&ov, self, &query)?;
                    if ctx.height <= query.reveal_deadline
                        || overlay_object(&ov, self, &neural_result_key(&v.query_id)).is_some()
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    let result = NeuralOracleResultV1 {
                        result_id: neural_result_id(&v.query_id, &[0; 32], &[0; 32]),
                        query_id: v.query_id,
                        mode: NeuralOracleMode::WwmQuorum,
                        status: NeuralOracleStatus::NoQuorum,
                        source_id: job.capsule_id,
                        execution_profile_id: job.execution_profile_id,
                        input_root: query.input_root,
                        response: BoundedBytes::default(),
                        output_root: [0; 32],
                        transcript_root: [0; 32],
                        signer_profile_ids: crate::objects::BoundedList::default(),
                        finalized_height: ctx.height,
                    };
                    ov.objects.insert(
                        neural_result_key(&v.query_id),
                        Some(result.encode_canonical()),
                    );
                    ov.write_count()?;
                }
                ActionV1::TransitionServingAlias(v) => {
                    let control = current_control(&ov, self)?;
                    if !matches!(
                        control.mode,
                        WwmControlMode::Disabled | WwmControlMode::Testnet
                    ) || control.mode != v.expected_control_state
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    require_wwm(&ov, self, WwmLeafKind::Capsule, &v.new_capsule_id)?;
                    let key = wwm_fixed_key(WwmLeafKind::ServingAlias);
                    let prior = overlay_object(&ov, self, &key)
                        .map(|raw| crate::wwm::ServingAliasTransitionV1::decode_canonical(&raw))
                        .transpose()
                        .map_err(|_| FailCode::PostconditionFailed)?;
                    if prior.as_ref().map(|p| p.transition_id) != v.prior_transition_id.0
                        || prior.as_ref().map(|p| p.new_capsule_id) != v.prior_capsule_id.0
                    {
                        return Err(FailCode::PostconditionFailed);
                    }
                    ov.objects.insert(key, Some(v.encode_canonical()));
                    ov.write_count()?;
                }
                ActionV1::TransitionWwmControl(v) => {
                    apply_control_transition(&mut ov, self, ctx.height, v)?;
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
    fn commit_failure_receipt(
        &mut self,
        tx: &TransactionV1,
        receipt: ReceiptV1,
        code: FailCode,
        height: u64,
    ) -> ApplyOutcome {
        let mut delta = BTreeMap::new();
        let balance = self.balance(&tx.fee_payer, &NOOS_ASSET);
        let after = balance.saturating_sub(receipt.fee_charged);
        self.set_balance_direct(&tx.fee_payer, &NOOS_ASSET, after, &mut delta);
        if let Some(mut account) = self.get_account(&tx.fee_payer) {
            account.nonce = account.nonce.saturating_add(1);
            let bytes = account.encode_canonical();
            self.accounts.insert(tx.fee_payer, bytes.clone());
            delta.insert((TreeId::Accounts, tx.fee_payer, None), Some(bytes));
        }
        let receipt_bytes = receipt.encode_canonical();
        self.receipts.insert(receipt.txid, receipt.clone(), height);
        delta.insert((TreeId::Receipts, receipt.txid, None), Some(receipt_bytes));
        ApplyOutcome::Failed {
            receipt,
            delta: StateDelta::from_map(delta),
            code,
        }
    }

    fn commit_failure_receipt_deferred(
        &mut self,
        tx: &TransactionV1,
        receipt: ReceiptV1,
        code: FailCode,
        deferred: &mut DeferredBalanceRoots,
        height: u64,
    ) -> ApplyOutcome {
        let mut delta = BTreeMap::new();
        let balance = self.balance(&tx.fee_payer, &NOOS_ASSET);
        let after = balance.saturating_sub(receipt.fee_charged);
        self.set_balance_deferred(&tx.fee_payer, &NOOS_ASSET, after, &mut delta, deferred);
        if let Some(mut account) = self.get_account(&tx.fee_payer) {
            account.nonce = account.nonce.saturating_add(1);
            let bytes = account.encode_canonical();
            self.accounts.insert(tx.fee_payer, bytes.clone());
            delta.insert((TreeId::Accounts, tx.fee_payer, None), Some(bytes));
        }
        let receipt_bytes = receipt.encode_canonical();
        self.receipts.insert(receipt.txid, receipt.clone(), height);
        delta.insert((TreeId::Receipts, receipt.txid, None), Some(receipt_bytes));
        ApplyOutcome::Failed {
            receipt,
            delta: StateDelta::from_map(delta),
            code,
        }
    }

    /// Atomic overlay commit: apply every staged write in canonical order
    /// and emit the ordered delta.
    fn commit_overlay(&mut self, ov: Overlay, height: u64) -> StateDelta {
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
            let encoded = match value {
                Some(receipt) => {
                    let bytes = receipt.encode_canonical();
                    self.receipts.insert(key, receipt, height);
                    Some(bytes)
                }
                None => {
                    self.receipts.remove(&key);
                    None
                }
            };
            delta.insert((TreeId::Receipts, key, None), encoded);
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

    fn commit_overlay_deferred(
        &mut self,
        ov: Overlay,
        deferred: &mut DeferredBalanceRoots,
        height: u64,
    ) -> StateDelta {
        let capacity = ov
            .notes
            .len()
            .saturating_add(ov.nullifiers.len())
            .saturating_add(ov.accounts.len())
            .saturating_add(ov.objects.len())
            .saturating_add(ov.receipts.len())
            .saturating_add(ov.params.len())
            .saturating_add(ov.balances.len());
        let mut entries = Vec::with_capacity(capacity);
        for (key, value) in ov.notes {
            apply_write_entry(&mut self.notes, TreeId::Notes, key, value, &mut entries);
        }
        for (key, value) in ov.nullifiers {
            apply_write_entry(
                &mut self.nullifiers,
                TreeId::Nullifiers,
                key,
                value,
                &mut entries,
            );
        }
        for (key, value) in ov.accounts {
            apply_write_entry(
                &mut self.accounts,
                TreeId::Accounts,
                key,
                value,
                &mut entries,
            );
        }
        for (key, value) in ov.objects {
            apply_write_entry(&mut self.objects, TreeId::Objects, key, value, &mut entries);
        }
        for (key, value) in ov.receipts {
            let encoded = match value {
                Some(receipt) => {
                    let bytes = receipt.encode_canonical();
                    self.receipts.insert(key, receipt, height);
                    Some(bytes)
                }
                None => {
                    self.receipts.remove(&key);
                    None
                }
            };
            entries.push(DeltaEntry {
                tree: TreeId::Receipts,
                key,
                sub_key: None,
                value: encoded,
            });
        }
        for (key, value) in ov.params {
            apply_write_entry(&mut self.params, TreeId::Params, key, value, &mut entries);
        }
        for ((account, asset), amount) in ov.balances {
            let tree = self.balances.entry(account).or_default();
            let value = if amount == 0 {
                tree.remove(&asset);
                None
            } else {
                let encoded = encode_amount(amount);
                tree.insert(asset, encoded.clone());
                Some(encoded)
            };
            entries.push(DeltaEntry {
                tree: TreeId::AccountBalances,
                key: account,
                sub_key: Some(asset),
                value,
            });
            deferred.dirty_accounts.insert(account);
        }
        StateDelta {
            entries: entries.into(),
        }
    }

    fn materialize_deferred_balance_roots(
        &mut self,
        mut deferred: DeferredBalanceRoots,
    ) -> StateDelta {
        self.flush_deferred_accounts(&mut deferred);
        let mut delta = BTreeMap::new();
        for account in deferred.dirty_account_records {
            if let Some(account_record) = self.get_account(&account) {
                delta.insert(
                    (TreeId::Accounts, account, None),
                    Some(account_record.encode_canonical()),
                );
            }
        }
        for account in deferred.dirty_accounts {
            self.refresh_balance_root_direct(&account, &mut delta);
        }
        StateDelta::from_map(delta)
    }
}

fn failure_receipt(
    txid: &Hash32,
    code: FailCode,
    max_fee: u128,
    fee_params: &FeeParamsV1,
    encoded_len: u64,
) -> ReceiptV1 {
    ReceiptV1 {
        txid: *txid,
        status: code.status(),
        fee_charged: fee_params.failure_fee.min(max_fee),
        resources_used: ResourceVector {
            bytes: encoded_len,
            ..ResourceVector::default()
        },
    }
}

// ---------------------------------------------------------------------------
// Overlay read-through helpers (free functions to keep borrows narrow)
// ---------------------------------------------------------------------------

fn strict_hashes(values: &[Hash32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn wwm_insert_unique(
    ov: &mut Overlay,
    base: &LumenLedger,
    key: Hash32,
    value: Vec<u8>,
) -> Result<(), FailCode> {
    if overlay_object(ov, base, &key).is_some() {
        return Err(FailCode::PostconditionFailed);
    }
    ov.objects.insert(key, Some(value));
    ov.write_count()
}

fn require_wwm(
    ov: &Overlay,
    base: &LumenLedger,
    kind: WwmLeafKind,
    id: &Hash32,
) -> Result<Vec<u8>, FailCode> {
    overlay_object(ov, base, &wwm_profile_key(kind, id)).ok_or(FailCode::PostconditionFailed)
}

fn neural_job_for_query(
    ov: &Overlay,
    base: &LumenLedger,
    query: &NeuralOracleQueryV1,
) -> Result<WwmJobV1, FailCode> {
    let raw = overlay_object(ov, base, &wwm_profile_key(WwmLeafKind::Job, &query.job_id))
        .ok_or(FailCode::PostconditionFailed)?;
    let job = WwmJobV1::decode_canonical(&raw).map_err(|_| FailCode::PostconditionFailed)?;
    if job.job_id != query.job_id
        || job.registry_epoch != query.executor_set_epoch
        || job.offchain_envelope_root != query.input_root
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(job)
}

fn neural_reporter_profile(
    ov: &Overlay,
    base: &LumenLedger,
    query: &NeuralOracleQueryV1,
    reporter_profile_id: &Hash32,
) -> Result<crate::wwm::CapabilityProfileV1, FailCode> {
    let job = neural_job_for_query(ov, base, query)?;
    if !job
        .selected_executor_ids
        .iter()
        .any(|profile_id| profile_id == reporter_profile_id)
    {
        return Err(FailCode::PostconditionFailed);
    }
    let raw = require_wwm(
        ov,
        base,
        WwmLeafKind::ExecutorCapabilitySet,
        &query.executor_set_id,
    )?;
    let set = CapabilitySetV1::decode_canonical(&raw).map_err(|_| FailCode::PostconditionFailed)?;
    if set.set_id != query.executor_set_id || set.epoch != query.executor_set_epoch {
        return Err(FailCode::PostconditionFailed);
    }
    let profile = set
        .entries
        .iter()
        .find(|profile| profile.profile_id == *reporter_profile_id)
        .cloned()
        .ok_or(FailCode::PostconditionFailed)?;
    if profile.status != CapabilityStatus::Active
        || profile.attestation_expiry < query.reveal_deadline
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(profile)
}

fn validate_neural_wwm_receipt(
    ov: &Overlay,
    base: &LumenLedger,
    job: &WwmJobV1,
    receipt: &WwmReceiptV1,
    height: u64,
) -> Result<(), FailCode> {
    let result_raw = overlay_object(ov, base, &neural_result_key(&job.job_id))
        .ok_or(FailCode::PostconditionFailed)?;
    let result = NeuralOracleResultV1::decode_canonical(&result_raw)
        .map_err(|_| FailCode::PostconditionFailed)?;
    let query_raw = overlay_object(ov, base, &neural_query_key(&job.job_id))
        .ok_or(FailCode::PostconditionFailed)?;
    let query = NeuralOracleQueryV1::decode_canonical(&query_raw)
        .map_err(|_| FailCode::PostconditionFailed)?;
    if result.query_id != job.job_id
        || result.mode != NeuralOracleMode::WwmQuorum
        || result.source_id != job.capsule_id
        || result.execution_profile_id != job.execution_profile_id
        || result.input_root != query.input_root
        || result.finalized_height > height
        || receipt.anchor_height < result.finalized_height
        || receipt.signer_ids.as_slice() != result.signer_profile_ids.as_slice()
        || receipt.control_cluster_ids.len() != receipt.signer_ids.len()
        || receipt.signatures.len() != receipt.signer_ids.len()
        || !strict_hashes(receipt.signer_ids.as_slice())
        || !strict_hashes(receipt.control_cluster_ids.as_slice())
        || receipt
            .signatures
            .iter()
            .zip(receipt.signer_ids.iter())
            .any(|(signature, signer)| {
                signature.signer_id != *signer || signature.signature.is_empty()
            })
    {
        return Err(FailCode::PostconditionFailed);
    }
    match result.status {
        NeuralOracleStatus::Success => {
            if result.response.is_empty()
                || result.signer_profile_ids.len() < usize::from(NEURAL_ORACLE_QUORUM_THRESHOLD)
                || receipt.evidence_tier != WwmEvidenceTier::MatchedQuorum
                || receipt.terminal_code != WwmTerminalCode::Complete
                || receipt.output_root != result.output_root
                || receipt.token_history_root != result.transcript_root
            {
                return Err(FailCode::PostconditionFailed);
            }
        }
        NeuralOracleStatus::NoQuorum => {
            if receipt.evidence_tier != WwmEvidenceTier::NoQuorum
                || receipt.terminal_code != WwmTerminalCode::NoQuorum
                || receipt.output_tokens != 0
                || receipt.output_root != [0; 32]
                || receipt.token_history_root != [0; 32]
                || !receipt.signer_ids.is_empty()
                || !receipt.control_cluster_ids.is_empty()
                || !receipt.signatures.is_empty()
                || receipt.paid_amount != 0
            {
                return Err(FailCode::PostconditionFailed);
            }
        }
    }
    Ok(())
}

fn current_registry(ov: &Overlay, base: &LumenLedger) -> Result<RegistryEpochVectorV1, FailCode> {
    let key = wwm_fixed_key(WwmLeafKind::RegistryEpochVector);
    match overlay_object(ov, base, &key) {
        Some(raw) => {
            RegistryEpochVectorV1::decode_canonical(&raw).map_err(|_| FailCode::PostconditionFailed)
        }
        None => Ok(RegistryEpochVectorV1 {
            vector_id: [0; 32],
            executor_set_id: [0; 32],
            executor_epoch: 0,
            custodian_set_id: [0; 32],
            custodian_epoch: 0,
            fee_policy_id: [0; 32],
            fee_epoch: 0,
            fund_profile_id: [0; 32],
            fund_epoch: 0,
            service_directory_id: [0; 32],
            service_epoch: 0,
        }),
    }
}

fn write_registry(ov: &mut Overlay, mut value: RegistryEpochVectorV1) -> Result<(), FailCode> {
    value.vector_id = [0; 32];
    value.vector_id = crate::domain_hash(
        "NOOS/WWM/REGISTRY-EPOCH-VECTOR/V1",
        &[&value.encode_canonical()],
    );
    ov.objects.insert(
        wwm_fixed_key(WwmLeafKind::RegistryEpochVector),
        Some(value.encode_canonical()),
    );
    ov.write_count()
}

fn apply_capability_mutation(
    ov: &mut Overlay,
    base: &LumenLedger,
    kind: WwmLeafKind,
    mutation: &CapabilityMutationV1,
) -> Result<(), FailCode> {
    let fixed_key = wwm_fixed_key(kind);
    let current = overlay_object(ov, base, &fixed_key)
        .map(|raw| CapabilitySetV1::decode_canonical(&raw))
        .transpose()
        .map_err(|_| FailCode::PostconditionFailed)?;
    let prior_id = current.as_ref().map_or([0; 32], |set| set.set_id);
    let prior_epoch = current.as_ref().map_or(0, |set| set.epoch);
    let mut entries = current
        .as_ref()
        .map_or_else(Vec::new, |set| set.entries.as_slice().to_vec());
    let declared_prior = match mutation {
        CapabilityMutationV1::InstallProfile(install) => {
            if install.profile.status != CapabilityStatus::Active
                || entries
                    .iter()
                    .any(|p| p.profile_id == install.profile.profile_id)
            {
                return Err(FailCode::PostconditionFailed);
            }
            entries.push(install.profile.clone());
            install.prior_set_id
        }
        CapabilityMutationV1::TransitionCapability(transition) => {
            let profile = entries
                .iter_mut()
                .find(|profile| profile.profile_id == transition.profile_id)
                .ok_or(FailCode::PostconditionFailed)?;
            let legal = matches!(
                (transition.prior_status, transition.new_status),
                (CapabilityStatus::Active, CapabilityStatus::Suspended)
                    | (CapabilityStatus::Active, CapabilityStatus::Retired)
                    | (CapabilityStatus::Suspended, CapabilityStatus::Active)
                    | (CapabilityStatus::Suspended, CapabilityStatus::Retired)
            );
            if !legal || profile.status != transition.prior_status {
                return Err(FailCode::PostconditionFailed);
            }
            profile.status = transition.new_status;
            transition.prior_set_id
        }
    };
    if declared_prior != prior_id {
        return Err(FailCode::PostconditionFailed);
    }
    entries.sort_by_key(|profile| profile.profile_id);
    let entries = crate::objects::BoundedList::new(entries).ok_or(FailCode::PostconditionFailed)?;
    let epoch = prior_epoch.checked_add(1).ok_or(FailCode::Overflow)?;
    let set_id = crate::domain_hash(
        "NOOS/WWM/CAPABILITY-SET/V1",
        &[&prior_id, &epoch.to_le_bytes(), &entries.encode_canonical()],
    );
    let set = CapabilitySetV1 {
        set_id,
        prior_set_id: prior_id,
        epoch,
        entries,
    };
    if !set.validate() {
        return Err(FailCode::PostconditionFailed);
    }
    ov.objects.insert(fixed_key, Some(set.encode_canonical()));
    ov.objects
        .insert(wwm_profile_key(kind, &set_id), Some(set.encode_canonical()));
    ov.write_count()?;
    ov.write_count()?;
    let mut registry = current_registry(ov, base)?;
    match kind {
        WwmLeafKind::ExecutorCapabilitySet => {
            registry.executor_set_id = set_id;
            registry.executor_epoch = epoch;
        }
        _ => return Err(FailCode::PostconditionFailed),
    }
    write_registry(ov, registry)
}
fn apply_custodian_mutation(
    ov: &mut Overlay,
    base: &LumenLedger,
    mutation: &CustodianCapabilityMutationV2,
) -> Result<(), FailCode> {
    let kind = WwmLeafKind::CustodianCapabilitySet;
    let fixed_key = wwm_fixed_key(kind);
    let current = overlay_object(ov, base, &fixed_key)
        .map(|raw| CustodianCapabilitySetV1::decode_canonical(&raw))
        .transpose()
        .map_err(|_| FailCode::PostconditionFailed)?;
    let prior_id = current.as_ref().map_or([0; 32], |set| set.set_id);
    let prior_epoch = current.as_ref().map_or(0, |set| set.epoch);
    let mut entries = current
        .as_ref()
        .map_or_else(Vec::new, |set| set.entries.as_slice().to_vec());
    let declared_prior = match mutation {
        CustodianCapabilityMutationV2::InstallProfile(install) => {
            if install.profile.status != CapabilityStatus::Active
                || entries
                    .iter()
                    .any(|p| p.profile_id == install.profile.profile_id)
                || install.profile.capacity_bytes
                    < install
                        .profile
                        .staging_bytes
                        .saturating_add(install.profile.headroom_bytes)
            {
                return Err(FailCode::PostconditionFailed);
            }
            entries.push(install.profile.clone());
            install.prior_set_id
        }
        CustodianCapabilityMutationV2::TransitionCapability(transition) => {
            let profile = entries
                .iter_mut()
                .find(|p| p.profile_id == transition.profile_id)
                .ok_or(FailCode::PostconditionFailed)?;
            let legal = matches!(
                (transition.prior_status, transition.new_status),
                (CapabilityStatus::Active, CapabilityStatus::Suspended)
                    | (CapabilityStatus::Active, CapabilityStatus::Retired)
                    | (CapabilityStatus::Suspended, CapabilityStatus::Active)
                    | (CapabilityStatus::Suspended, CapabilityStatus::Retired)
            );
            if !legal || profile.status != transition.prior_status {
                return Err(FailCode::PostconditionFailed);
            }
            profile.status = transition.new_status;
            transition.prior_set_id
        }
    };
    if declared_prior != prior_id {
        return Err(FailCode::PostconditionFailed);
    }
    entries.sort_by_key(|profile| profile.profile_id);
    let entries = crate::objects::BoundedList::new(entries).ok_or(FailCode::PostconditionFailed)?;
    let epoch = prior_epoch.checked_add(1).ok_or(FailCode::Overflow)?;
    let set_id = crate::domain_hash(
        "NOOS/WWM/CUSTODIAN-CAPABILITY-SET/V1",
        &[&prior_id, &epoch.to_le_bytes(), &entries.encode_canonical()],
    );
    let set = CustodianCapabilitySetV1 {
        set_id,
        prior_set_id: prior_id,
        epoch,
        entries,
    };
    if !set.validate() {
        return Err(FailCode::PostconditionFailed);
    }
    ov.objects.insert(fixed_key, Some(set.encode_canonical()));
    ov.objects
        .insert(wwm_profile_key(kind, &set_id), Some(set.encode_canonical()));
    ov.write_count()?;
    ov.write_count()?;
    let mut registry = current_registry(ov, base)?;
    registry.custodian_set_id = set_id;
    registry.custodian_epoch = epoch;
    write_registry(ov, registry)
}

fn ledger_root(ledger: &WwmFundLedgerV1) -> Hash32 {
    crate::domain_hash(
        "NOOS/WWM/FUND-LEDGER-ROOT/V1",
        &[&ledger.encode_canonical()],
    )
}

fn read_ledger(
    ov: &Overlay,
    base: &LumenLedger,
    profile_id: &Hash32,
) -> Result<WwmFundLedgerV1, FailCode> {
    let raw = require_wwm(ov, base, WwmLeafKind::FundLedger, profile_id)?;
    WwmFundLedgerV1::decode_canonical(&raw).map_err(|_| FailCode::PostconditionFailed)
}

fn write_ledger(ov: &mut Overlay, ledger: &WwmFundLedgerV1) -> Result<(), FailCode> {
    if !ledger.validate() {
        return Err(FailCode::PostconditionFailed);
    }
    ov.objects.insert(
        wwm_profile_key(WwmLeafKind::FundLedger, &ledger.profile_id),
        Some(ledger.encode_canonical()),
    );
    ov.write_count()
}

fn apply_fund_profile_mutation(
    ov: &mut Overlay,
    base: &LumenLedger,
    height: u64,
    mutation: &RegisterFundProfilePayloadV1,
) -> Result<(), FailCode> {
    match mutation {
        RegisterFundProfilePayloadV1::StageFundProfile(stage) => {
            let registry = current_registry(ov, base)?;
            if !stage.profile.validate() || stage.prior_current_id != registry.fund_profile_id {
                return Err(FailCode::PostconditionFailed);
            }
            let profile_key = wwm_profile_key(WwmLeafKind::FundProfile, &stage.profile.profile_id);
            let ledger_key = wwm_profile_key(WwmLeafKind::FundLedger, &stage.profile.profile_id);
            if overlay_object(ov, base, &profile_key).is_some()
                || overlay_object(ov, base, &ledger_key).is_some()
            {
                return Err(FailCode::PostconditionFailed);
            }
            let mut ledger =
                genesis_fund_ledger(&stage.profile).ok_or(FailCode::PostconditionFailed)?;
            ledger.status = FundLedgerStatus::Staged;
            ov.objects
                .insert(profile_key, Some(stage.profile.encode_canonical()));
            ov.objects
                .insert(ledger_key, Some(ledger.encode_canonical()));
            ov.write_count()?;
            ov.write_count()
        }
        RegisterFundProfilePayloadV1::LockFundMutation(lock) => {
            if lock.source_profile_id == lock.other_profile_id
                || lock.execute_before_height <= height
            {
                return Err(FailCode::PostconditionFailed);
            }
            let registry = current_registry(ov, base)?;
            let mut source = read_ledger(ov, base, &lock.source_profile_id)?;
            let mut other = read_ledger(ov, base, &lock.other_profile_id)?;
            if source.lock_ref.0.is_some()
                || other.lock_ref.0.is_some()
                || source.topup_permit_epoch != lock.prior_source_permit_epoch
                || other.topup_permit_epoch != lock.prior_other_permit_epoch
            {
                return Err(FailCode::PostconditionFailed);
            }
            let legal = match lock.operation {
                crate::wwm::FundMutationOperation::Activate => {
                    source.profile_id == registry.fund_profile_id
                        && source.status == FundLedgerStatus::Current
                        && other.status == FundLedgerStatus::Staged
                }
                crate::wwm::FundMutationOperation::Close => {
                    other.profile_id == registry.fund_profile_id
                        && other.status == FundLedgerStatus::Current
                        && matches!(
                            source.status,
                            FundLedgerStatus::Staged | FundLedgerStatus::Superseded
                        )
                }
            };
            if !legal {
                return Err(FailCode::PostconditionFailed);
            }
            source.topup_permit_epoch = source
                .topup_permit_epoch
                .checked_add(1)
                .ok_or(FailCode::Overflow)?;
            other.topup_permit_epoch = other
                .topup_permit_epoch
                .checked_add(1)
                .ok_or(FailCode::Overflow)?;
            let lock_id = crate::domain_hash(
                "NOOS/WWM/FUND-MUTATION-LOCK/V1",
                &[&mutation.encode_canonical()],
            );
            source.lock_ref = crate::objects::OptionalObject(Some(FundMutationLockRefV1 {
                lock_id,
                operation: lock.operation,
                peer_profile_id: other.profile_id,
                execute_before_height: lock.execute_before_height,
            }));
            other.lock_ref = crate::objects::OptionalObject(Some(FundMutationLockRefV1 {
                lock_id,
                operation: lock.operation,
                peer_profile_id: source.profile_id,
                execute_before_height: lock.execute_before_height,
            }));
            let source_root = ledger_root(&source);
            let other_root = ledger_root(&other);
            let record = FundMutationLockV1 {
                lock_id,
                operation: lock.operation,
                profile_id_0: source.profile_id.min(other.profile_id),
                profile_id_1: source.profile_id.max(other.profile_id),
                post_ref_root_0: if source.profile_id < other.profile_id {
                    source_root
                } else {
                    other_root
                },
                post_ref_root_1: if source.profile_id < other.profile_id {
                    other_root
                } else {
                    source_root
                },
                permit_epoch_0: if source.profile_id < other.profile_id {
                    source.topup_permit_epoch
                } else {
                    other.topup_permit_epoch
                },
                permit_epoch_1: if source.profile_id < other.profile_id {
                    other.topup_permit_epoch
                } else {
                    source.topup_permit_epoch
                },
                authority_epoch: lock.authority.authority_epoch,
                execute_before_height: lock.execute_before_height,
                status: FundMutationLockStatus::Pending,
                signature: lock.authority.signature.clone(),
            };
            write_ledger(ov, &source)?;
            write_ledger(ov, &other)?;
            wwm_insert_unique(
                ov,
                base,
                wwm_profile_key(WwmLeafKind::FundMutationLock, &lock_id),
                record.encode_canonical(),
            )
        }
        RegisterFundProfilePayloadV1::ActivateFundProfile(activate) => {
            let mut registry = current_registry(ov, base)?;
            if activate.prior_current_id != registry.fund_profile_id {
                return Err(FailCode::PostconditionFailed);
            }
            let mut current = read_ledger(ov, base, &activate.prior_current_id)?;
            let mut candidate = read_ledger(ov, base, &activate.profile_id)?;
            let lock_key = wwm_profile_key(WwmLeafKind::FundMutationLock, &activate.lock_id);
            let raw = overlay_object(ov, base, &lock_key).ok_or(FailCode::PostconditionFailed)?;
            let mut lock = FundMutationLockV1::decode_canonical(&raw)
                .map_err(|_| FailCode::PostconditionFailed)?;
            if lock.status != FundMutationLockStatus::Pending
                || lock.operation != crate::wwm::FundMutationOperation::Activate
                || height > lock.execute_before_height
                || ledger_root(&current) != activate.locked_current_ledger_root
                || ledger_root(&candidate) != activate.locked_candidate_ledger_root
                || current.status != FundLedgerStatus::Current
                || candidate.status != FundLedgerStatus::Staged
            {
                return Err(FailCode::PostconditionFailed);
            }
            current.status = FundLedgerStatus::Superseded;
            candidate.status = FundLedgerStatus::Current;
            current.lock_ref = crate::objects::OptionalObject(None);
            candidate.lock_ref = crate::objects::OptionalObject(None);
            lock.status = FundMutationLockStatus::Completed;
            write_ledger(ov, &current)?;
            write_ledger(ov, &candidate)?;
            ov.objects.insert(lock_key, Some(lock.encode_canonical()));
            ov.write_count()?;
            registry.fund_profile_id = candidate.profile_id;
            registry.fund_epoch = registry
                .fund_epoch
                .checked_add(1)
                .ok_or(FailCode::Overflow)?;
            write_registry(ov, registry)
        }
        RegisterFundProfilePayloadV1::CloseFundProfile(close) => {
            let registry = current_registry(ov, base)?;
            if close.current_profile_id != registry.fund_profile_id {
                return Err(FailCode::PostconditionFailed);
            }
            let mut source = read_ledger(ov, base, &close.profile_id)?;
            let mut current = read_ledger(ov, base, &close.current_profile_id)?;
            let lock_key = wwm_profile_key(WwmLeafKind::FundMutationLock, &close.lock_id);
            let raw = overlay_object(ov, base, &lock_key).ok_or(FailCode::PostconditionFailed)?;
            let mut lock = FundMutationLockV1::decode_canonical(&raw)
                .map_err(|_| FailCode::PostconditionFailed)?;
            if lock.status != FundMutationLockStatus::Pending
                || lock.operation != crate::wwm::FundMutationOperation::Close
                || height > lock.execute_before_height
                || ledger_root(&source) != close.locked_source_ledger_root
                || ledger_root(&current) != close.locked_current_ledger_root
                || source
                    .rows
                    .iter()
                    .any(|row| row.reserved != 0 || row.live_liability != 0)
            {
                return Err(FailCode::PostconditionFailed);
            }
            for (source_row, current_row) in
                source.rows.as_slice().iter().zip(current.rows.as_slice())
            {
                if source_row.bucket != current_row.bucket {
                    return Err(FailCode::PostconditionFailed);
                }
            }
            let mut source_rows = source.rows.as_slice().to_vec();
            let mut current_rows = current.rows.as_slice().to_vec();
            for (source_row, current_row) in source_rows.iter_mut().zip(current_rows.iter_mut()) {
                current_row.migrated_in = current_row
                    .migrated_in
                    .checked_add(source_row.free)
                    .ok_or(FailCode::Overflow)?;
                current_row.free = current_row
                    .free
                    .checked_add(source_row.free)
                    .ok_or(FailCode::Overflow)?;
                source_row.migrated_out = source_row
                    .migrated_out
                    .checked_add(source_row.free)
                    .ok_or(FailCode::Overflow)?;
                source_row.free = 0;
            }
            source.rows = crate::objects::BoundedList::new(source_rows)
                .ok_or(FailCode::PostconditionFailed)?;
            current.rows = crate::objects::BoundedList::new(current_rows)
                .ok_or(FailCode::PostconditionFailed)?;
            source.status = FundLedgerStatus::Closed;
            source.lock_ref = crate::objects::OptionalObject(None);
            current.lock_ref = crate::objects::OptionalObject(None);
            lock.status = FundMutationLockStatus::Completed;
            write_ledger(ov, &source)?;
            write_ledger(ov, &current)?;
            ov.objects.insert(lock_key, Some(lock.encode_canonical()));
            ov.write_count()
        }
    }
}

fn current_control(ov: &Overlay, base: &LumenLedger) -> Result<WwmControlStateV1, FailCode> {
    let raw = overlay_object(ov, base, &wwm_fixed_key(WwmLeafKind::Control))
        .ok_or(FailCode::PostconditionFailed)?;
    let control =
        WwmControlStateV1::decode_canonical(&raw).map_err(|_| FailCode::PostconditionFailed)?;
    if control.separation_valid() {
        Ok(control)
    } else {
        Err(FailCode::PostconditionFailed)
    }
}

fn write_control(ov: &mut Overlay, control: &WwmControlStateV1) -> Result<(), FailCode> {
    if !control.separation_valid() {
        return Err(FailCode::PostconditionFailed);
    }
    ov.objects.insert(
        wwm_fixed_key(WwmLeafKind::Control),
        Some(control.encode_canonical()),
    );
    ov.write_count()
}

fn apply_control_transition(
    ov: &mut Overlay,
    base: &LumenLedger,
    height: u64,
    payload: &TransitionWwmControlPayloadV1,
) -> Result<(), FailCode> {
    let mut control = current_control(ov, base)?;
    match payload {
        TransitionWwmControlPayloadV1::Activate { transition, config } => {
            let legal = matches!(
                (control.mode, transition.target),
                (WwmControlMode::Disabled, WwmControlMode::Testnet)
                    | (WwmControlMode::Disabled, WwmControlMode::Canary)
                    | (WwmControlMode::Canary, WwmControlMode::Production)
            );
            if !legal
                || transition.source != control.mode
                || transition.config_id != config.config_id
                || transition.expected_active_config_id != control.active_config_id
                || transition.activation_height != height
                || config.activation_height != height
                || config.tier != transition.target
                || !config.validate()
                || config.capsule_id != control.capsule_id
            {
                return Err(FailCode::PostconditionFailed);
            }
            let alias_raw = overlay_object(ov, base, &wwm_fixed_key(WwmLeafKind::ServingAlias))
                .ok_or(FailCode::PostconditionFailed)?;
            let alias = crate::wwm::ServingAliasTransitionV1::decode_canonical(&alias_raw)
                .map_err(|_| FailCode::PostconditionFailed)?;
            if alias.new_capsule_id != config.capsule_id {
                return Err(FailCode::PostconditionFailed);
            }
            wwm_insert_unique(
                ov,
                base,
                wwm_profile_key(WwmLeafKind::AuthorizedConfig, &config.config_id),
                config.encode_canonical(),
            )?;
            control.direct_prior_live_mode = control.mode;
            control.direct_prior_config_id = control.active_config_id;
            control.mode = transition.target;
            control.active_capsule_id = crate::objects::OptionalHash32(Some(config.capsule_id));
            control.last_transition_id =
                crate::objects::OptionalHash32(Some(transition.transition_id));
            control.last_transition_height = height;
            control.active_config_id = crate::objects::OptionalHash32(Some(config.config_id));
            control.latest_authorized_config_id =
                crate::objects::OptionalHash32(Some(config.config_id));
            control.resolution_config_id = crate::objects::OptionalHash32(Some(config.config_id));
            write_control(ov, &control)
        }
        TransitionWwmControlPayloadV1::EmergencyDisable(disable) => {
            if !matches!(
                control.mode,
                WwmControlMode::Testnet | WwmControlMode::Canary | WwmControlMode::Production
            ) || control.mode != disable.expected_state
                || control.active_config_id != disable.expected_config
                || disable.incident_root == [0; 32]
            {
                return Err(FailCode::PostconditionFailed);
            }
            control.direct_prior_live_mode = control.mode;
            control.direct_prior_config_id = control.active_config_id;
            control.mode = WwmControlMode::EmergencyDisabled;
            control.last_transition_height = height;
            write_control(ov, &control)
        }
        TransitionWwmControlPayloadV1::AuthorizeOperationalConfig(reconfiguration) => {
            if !matches!(
                control.mode,
                WwmControlMode::Canary
                    | WwmControlMode::Production
                    | WwmControlMode::EmergencyDisabled
            ) || reconfiguration.prior_active_config_id
                != control
                    .active_config_id
                    .0
                    .ok_or(FailCode::PostconditionFailed)?
                || reconfiguration.candidate_config.parent_config_id.0 != control.active_config_id.0
                || reconfiguration.candidate_config.capsule_id != control.capsule_id
                || reconfiguration.candidate_config.tier
                    != if control.mode == WwmControlMode::EmergencyDisabled {
                        control.direct_prior_live_mode
                    } else {
                        control.mode
                    }
                || !reconfiguration.candidate_config.validate()
                || reconfiguration.encode_canonical().len()
                    > crate::wwm::MAX_OPERATIONAL_RECONFIG_BYTES
            {
                return Err(FailCode::PostconditionFailed);
            }
            wwm_insert_unique(
                ov,
                base,
                wwm_profile_key(
                    WwmLeafKind::OperationalAuthorization,
                    &reconfiguration.authorization_id,
                ),
                reconfiguration.encode_canonical(),
            )?;
            wwm_insert_unique(
                ov,
                base,
                wwm_profile_key(
                    WwmLeafKind::AuthorizedConfig,
                    &reconfiguration.candidate_config.config_id,
                ),
                reconfiguration.candidate_config.encode_canonical(),
            )?;
            control.latest_authorized_config_id =
                crate::objects::OptionalHash32(Some(reconfiguration.candidate_config.config_id));
            write_control(ov, &control)
        }
        TransitionWwmControlPayloadV1::ApplyOperationalConfig(apply) => {
            if !matches!(
                control.mode,
                WwmControlMode::Canary | WwmControlMode::Production
            ) || control.active_config_id.0 != Some(apply.expected_active_config_id)
            {
                return Err(FailCode::PostconditionFailed);
            }
            let raw = require_wwm(
                ov,
                base,
                WwmLeafKind::OperationalAuthorization,
                &apply.authorization_id,
            )?;
            let reconfiguration = crate::wwm::OperationalReconfigurationV1::decode_canonical(&raw)
                .map_err(|_| FailCode::PostconditionFailed)?;
            if control.latest_authorized_config_id.0
                != Some(reconfiguration.candidate_config.config_id)
                || reconfiguration.not_before_height > height
                || reconfiguration.expiry_height < height
                || reconfiguration.candidate_config.tier != control.mode
            {
                return Err(FailCode::PostconditionFailed);
            }
            control.direct_prior_config_id = control.active_config_id;
            control.active_config_id =
                crate::objects::OptionalHash32(Some(reconfiguration.candidate_config.config_id));
            control.resolution_config_id = control.active_config_id;
            control.last_transition_height = height;
            write_control(ov, &control)
        }
        TransitionWwmControlPayloadV1::Recover(recovery) => {
            if control.mode != WwmControlMode::EmergencyDisabled
                || recovery.target_tier != control.direct_prior_live_mode
                || control.latest_authorized_config_id.0 != Some(recovery.selected_config_id)
                || recovery.not_before_height > height
                || recovery.expiry_height < height
                || recovery.activation_height != height
            {
                return Err(FailCode::PostconditionFailed);
            }
            require_wwm(
                ov,
                base,
                WwmLeafKind::AuthorizedConfig,
                &recovery.selected_config_id,
            )?;
            control.mode = recovery.target_tier;
            control.active_config_id =
                crate::objects::OptionalHash32(Some(recovery.selected_config_id));
            control.resolution_config_id = control.active_config_id;
            control.last_transition_id =
                crate::objects::OptionalHash32(Some(recovery.authorization_id));
            control.last_transition_height = height;
            write_control(ov, &control)
        }
    }
}

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

fn deviation_bps(current: u128, reference: u128) -> Result<u16, FailCode> {
    if reference == 0 {
        return Err(FailCode::PostconditionFailed);
    }
    let difference = current.abs_diff(reference);
    let scaled = difference
        .checked_mul(10_000)
        .and_then(|value| value.checked_div(reference))
        .ok_or(FailCode::Overflow)?;
    u16::try_from(scaled.min(u128::from(u16::MAX))).map_err(|_| FailCode::Overflow)
}

fn update_twap(
    previous: u128,
    current: u128,
    previous_height: u64,
    height: u64,
    window: u64,
) -> Result<u128, FailCode> {
    if previous == 0 || previous_height == 0 {
        return Ok(current);
    }
    let elapsed = height.saturating_sub(previous_height).min(window);
    let old_weight = window.saturating_sub(elapsed);
    previous
        .checked_mul(u128::from(old_weight))
        .and_then(|old| {
            current
                .checked_mul(u128::from(elapsed))
                .and_then(|new| old.checked_add(new))
        })
        .and_then(|total| total.checked_div(u128::from(window)))
        .ok_or(FailCode::Overflow)
}

fn risk_increasing_oracle_price(
    ov: &mut Overlay,
    base: &LumenLedger,
    feed: &OracleFeedV1,
    height: u64,
) -> Result<u128, FailCode> {
    if feed.mode != ORACLE_MODE_LIVE {
        return Err(FailCode::PostconditionFailed);
    }
    let fresh =
        fresh_reporter_median(ov, base, feed, height)?.ok_or(FailCode::PostconditionFailed)?;
    if feed.twap_price_q9 == 0 || deviation_bps(fresh, feed.twap_price_q9)? > feed.max_deviation_bps
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(fresh.min(feed.twap_price_q9))
}

fn liquidation_oracle_price(
    ov: &mut Overlay,
    base: &LumenLedger,
    feed: &OracleFeedV1,
    height: u64,
) -> Result<u128, FailCode> {
    match feed.mode {
        ORACLE_MODE_LIVE => {
            let fresh = fresh_reporter_median(ov, base, feed, height)?
                .ok_or(FailCode::PostconditionFailed)?;
            Ok(if feed.twap_price_q9 == 0 {
                fresh
            } else {
                fresh.min(feed.twap_price_q9)
            })
        }
        ORACLE_MODE_LAST_GOOD => {
            let emergency_age = feed
                .max_age_blocks
                .checked_mul(10)
                .ok_or(FailCode::Overflow)?;
            if feed.last_good_price_q9 == 0
                || height.saturating_sub(feed.last_good_height) > emergency_age
            {
                return Err(FailCode::PostconditionFailed);
            }
            Ok(if feed.twap_price_q9 == 0 {
                feed.last_good_price_q9
            } else {
                feed.last_good_price_q9.min(feed.twap_price_q9)
            })
        }
        _ => Err(FailCode::PostconditionFailed),
    }
}

fn fresh_reporter_median(
    ov: &mut Overlay,
    base: &LumenLedger,
    feed: &OracleFeedV1,
    height: u64,
) -> Result<Option<u128>, FailCode> {
    let mut prices = Vec::with_capacity(5);
    for reporter in [
        feed.reporter_0,
        feed.reporter_1,
        feed.reporter_2,
        feed.reporter_3,
        feed.reporter_4,
    ] {
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
    if prices.len() < 3 {
        return Ok(None);
    }
    prices.sort_unstable();
    Ok(Some(prices[prices.len() / 2]))
}

fn collateral_value(collateral: u128, price_q9: u128) -> Result<u128, FailCode> {
    collateral
        .checked_mul(price_q9)
        .and_then(|value| value.checked_div(ORACLE_SCALE))
        .ok_or(FailCode::Overflow)
}

fn decode_oracle_feed(raw: &[u8], feed_id: &Hash32) -> Result<OracleFeedV1, FailCode> {
    let feed = OracleFeedV1::decode_canonical(raw).map_err(|_| FailCode::PostconditionFailed)?;
    let mut reporters = [
        feed.reporter_0,
        feed.reporter_1,
        feed.reporter_2,
        feed.reporter_3,
        feed.reporter_4,
    ];
    reporters.sort_unstable();
    if feed.feed_id != *feed_id
        || feed.feed_id != derive_oracle_feed_id(&feed.base_asset, &feed.quote_asset)
        || feed.base_asset == feed.quote_asset
        || reporters.windows(2).any(|pair| pair[0] == pair[1])
        || !(1..=10_000).contains(&feed.max_age_blocks)
        || !(1..=5_000).contains(&feed.max_deviation_bps)
        || !(2..=10_000).contains(&feed.twap_window_blocks)
        || feed.mode > ORACLE_MODE_FROZEN
        || (feed.mode == ORACLE_MODE_LAST_GOOD && feed.last_good_price_q9 == 0)
        || (feed.last_good_price_q9 == 0
            && (feed.last_good_height != 0 || feed.twap_price_q9 != 0 || feed.twap_height != 0))
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

fn decode_stable_safety(raw: &[u8], market: &LendingMarketV1) -> Result<StableSafetyV1, FailCode> {
    let safety =
        StableSafetyV1::decode_canonical(raw).map_err(|_| FailCode::PostconditionFailed)?;
    if safety.safety_id != derive_stable_safety_id(&market.market_id)
        || safety.market_id != market.market_id
        || safety.psm_fee_bps > 500
        || safety.psm_debt > market.total_debt
    {
        return Err(FailCode::PostconditionFailed);
    }
    Ok(safety)
}

fn safety_state(value: &StableSafetyV1) -> SafetyState {
    SafetyState {
        stable_reserve: value.stable_reserve,
        collateral_reserve: value.collateral_reserve,
        psm_debt: value.psm_debt,
        uncovered_bad_debt: value.uncovered_bad_debt,
    }
}

fn update_safety(value: &mut StableSafetyV1, state: SafetyState) {
    value.stable_reserve = state.stable_reserve;
    value.collateral_reserve = state.collateral_reserve;
    value.psm_debt = state.psm_debt;
    value.uncovered_bad_debt = state.uncovered_bad_debt;
}

fn safety_policy(market: &LendingMarketV1, safety: &StableSafetyV1) -> SafetyPolicy {
    SafetyPolicy {
        liquidation_threshold_bps: market.liquidation_threshold_bps,
        liquidation_bonus_bps: market.liquidation_bonus_bps,
        psm_fee_bps: safety.psm_fee_bps,
    }
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

fn apply_write_entry(
    tree: &mut Smt,
    id: TreeId,
    key: Hash32,
    value: Option<Vec<u8>>,
    entries: &mut Vec<DeltaEntry>,
) {
    match &value {
        Some(bytes) => {
            tree.insert(key, bytes.clone());
        }
        None => {
            tree.remove(&key);
        }
    }
    entries.push(DeltaEntry {
        tree: id,
        key,
        sub_key: None,
        value,
    });
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
