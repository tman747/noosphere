//! Exact Lumen object shapes (arch §6/§11.1, frozen field table:
//! `protocol/spec/schema-tables/lumen-objects.md`).
//!
//! Every consensus object uses the noos-codec law: fixed-width little-endian
//! fields, explicit `u16` version, numeric mandatory tags in declaration
//! order, canonical `u32`-length-delimited bounded collections, strict
//! whole-input decode.

use crate::{domain_hash, domains, Hash32};
use noos_codec::{define_object, CodecError, NoosDecode, NoosEncode, Reader, Writer};

// ---------------------------------------------------------------------------
// Bounded helper types
// ---------------------------------------------------------------------------

/// Canonical length-delimited byte string bounded by `MAX`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedBytes<const MAX: u32>(Vec<u8>);

impl<const MAX: u32> BoundedBytes<MAX> {
    /// Construct; `None` when over the bound (encoders build only valid objects).
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() <= MAX as usize {
            Some(Self(bytes))
        } else {
            None
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const MAX: u32> NoosEncode for BoundedBytes<MAX> {
    fn encode(&self, w: &mut Writer) {
        w.put_bytes(&self.0, MAX);
    }
}

impl<const MAX: u32> NoosDecode for BoundedBytes<MAX> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(r.get_bytes(MAX)?))
    }
}

/// Canonical length-delimited list bounded by `MAX` elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedList<T, const MAX: u32>(Vec<T>);

impl<T, const MAX: u32> Default for BoundedList<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T, const MAX: u32> BoundedList<T, MAX> {
    #[must_use]
    pub fn new(items: Vec<T>) -> Option<Self> {
        if items.len() <= MAX as usize {
            Some(Self(items))
        } else {
            None
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T: NoosEncode, const MAX: u32> NoosEncode for BoundedList<T, MAX> {
    fn encode(&self, w: &mut Writer) {
        w.put_list(&self.0, MAX);
    }
}

impl<T: NoosDecode, const MAX: u32> NoosDecode for BoundedList<T, MAX> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self(r.get_list(MAX)?))
    }
}

/// Optional 32-byte hash: presence byte `0`/`1` then the payload.
/// Any other presence byte rejects (`UnknownDiscriminant`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OptionalHash32(pub Option<Hash32>);

impl NoosEncode for OptionalHash32 {
    fn encode(&self, w: &mut Writer) {
        match &self.0 {
            None => w.put_u8(0),
            Some(h) => {
                w.put_u8(1);
                w.put_array32(h);
            }
        }
    }
}

impl NoosDecode for OptionalHash32 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_u8()? {
            0 => Ok(Self(None)),
            1 => Ok(Self(Some(r.get_array32()?))),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

/// Optional nested object with a presence byte (same law as [`OptionalHash32`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionalObject<T>(pub Option<T>);

impl<T: NoosEncode> NoosEncode for OptionalObject<T> {
    fn encode(&self, w: &mut Writer) {
        match &self.0 {
            None => w.put_u8(0),
            Some(v) => {
                w.put_u8(1);
                v.encode(w);
            }
        }
    }
}

impl<T: NoosDecode> NoosDecode for OptionalObject<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_u8()? {
            0 => Ok(Self(None)),
            1 => Ok(Self(Some(T::decode(r)?))),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

// ---------------------------------------------------------------------------
// Resource vector (ch01 §6.5) — nested fixed record, no version/tags.
// ---------------------------------------------------------------------------

/// `{bytes, grain_steps, proof_units, state_reads, state_writes, blob_bytes}`,
/// six fixed `u64` little-endian words.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceVector {
    pub bytes: u64,
    pub grain_steps: u64,
    pub proof_units: u64,
    pub state_reads: u64,
    pub state_writes: u64,
    pub blob_bytes: u64,
}

impl ResourceVector {
    /// True when every component of `self` is ≤ the matching component of `cap`.
    #[must_use]
    pub fn fits_within(&self, cap: &ResourceVector) -> bool {
        self.bytes <= cap.bytes
            && self.grain_steps <= cap.grain_steps
            && self.proof_units <= cap.proof_units
            && self.state_reads <= cap.state_reads
            && self.state_writes <= cap.state_writes
            && self.blob_bytes <= cap.blob_bytes
    }
}

impl NoosEncode for ResourceVector {
    fn encode(&self, w: &mut Writer) {
        w.put_u64(self.bytes);
        w.put_u64(self.grain_steps);
        w.put_u64(self.proof_units);
        w.put_u64(self.state_reads);
        w.put_u64(self.state_writes);
        w.put_u64(self.blob_bytes);
    }
}

impl NoosDecode for ResourceVector {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            bytes: r.get_u64()?,
            grain_steps: r.get_u64()?,
            proof_units: r.get_u64()?,
            state_reads: r.get_u64()?,
            state_writes: r.get_u64()?,
            blob_bytes: r.get_u64()?,
        })
    }
}

/// Object access-list entry: object id + read/write mode.
/// `mode`: 0 = read, 1 = read-write; anything else rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessEntry {
    pub object_id: Hash32,
    pub mode: u8,
}

impl AccessEntry {
    pub const MODE_READ: u8 = 0;
    pub const MODE_READ_WRITE: u8 = 1;
}

impl NoosEncode for AccessEntry {
    fn encode(&self, w: &mut Writer) {
        w.put_array32(&self.object_id);
        w.put_u8(self.mode);
    }
}

impl NoosDecode for AccessEntry {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let object_id = r.get_array32()?;
        let mode = r.get_u8()?;
        if mode > AccessEntry::MODE_READ_WRITE {
            return Err(CodecError::UnknownDiscriminant);
        }
        Ok(Self { object_id, mode })
    }
}

// ---------------------------------------------------------------------------
// Frozen object shapes (tags per lumen-objects.md registry)
// ---------------------------------------------------------------------------

define_object! {
    /// LumenState (family tag 1): the six post-state roots. `receipts_root`
    /// is the post-state compact settled-receipt index, NOT the block's
    /// ordered execution receipts (ch01 §6.1; plan §4.2).
    pub struct LumenStateV1 {
        version: 1;
        1 => notes_root: [u8; 32],
        2 => nullifiers_root: [u8; 32],
        3 => accounts_root: [u8; 32],
        4 => objects_root: [u8; 32],
        5 => receipts_root: [u8; 32],
        6 => params_root: [u8; 32],
    }
}

define_object! {
    /// Note (family tag 2, ch01 §6.2): immutable output consumed exactly once.
    pub struct NoteV1 {
        version: 1;
        1 => asset_id: [u8; 32],
        2 => amount: u128,
        3 => lock_root: [u8; 32],
        4 => datum_root: [u8; 32],
        5 => birth_height: u64,
        6 => relative_timelock: u32,
        7 => memo_commitment: [u8; 32],
    }
}

/// `note_id = H("NOOS/NOTE/V1" || creating_txid || output_index_u32_le || canonical_note)`
/// (D-NOTE-ID; output-index width frozen as u32 LE in lumen-v1.md §4.1).
#[must_use]
pub fn note_id(creating_txid: &Hash32, output_index: u32, note: &NoteV1) -> Hash32 {
    let canonical = note.encode_canonical();
    domain_hash(
        domains::NOTE_ID,
        &[creating_txid, &output_index.to_le_bytes(), &canonical],
    )
}

define_object! {
    /// Account (family tag 3, ch01 §6.3). A transaction listing this account
    /// as an input consumes exactly `nonce+1`.
    pub struct AccountV1 {
        version: 1;
        1 => account_id: [u8; 32],
        2 => auth_descriptor: BoundedBytes<1024>,
        3 => nonce: u64,
        4 => liquid_balances_root: [u8; 32],
        5 => bond_refs_root: [u8; 32],
        6 => metadata_commitment: [u8; 32],
        7 => recovery_policy_root: [u8; 32],
    }
}

define_object! {
    /// Object (family tag 4, ch01 §6.4): Grain-controlled persistent state.
    pub struct ObjectV1 {
        version: 1;
        1 => object_id: [u8; 32],
        2 => class_id: u32,
        3 => owner_or_policy_root: [u8; 32],
        4 => code_hash: [u8; 32],
        5 => state_root: [u8; 32],
        6 => object_version: u64,
        7 => storage_words: u64,
        8 => rent_deposit: u128,
        9 => flags: u32,
    }
}

impl ObjectV1 {
    /// Flag bit 0: quarantined by emergency authority; calls reject.
    pub const FLAG_QUARANTINED: u32 = 1;
}

/// `object_id = H("NOOS/OBJECT/ID/V1" || creating_txid || action_index_u32_le || class_id_u32_le)`
/// (D-OBJECT-ID, registered in crypto-domains-v1.csv).
#[must_use]
pub fn object_id(creating_txid: &Hash32, action_index: u32, class_id: u32) -> Hash32 {
    domain_hash(
        domains::OBJECT_ID,
        &[
            creating_txid,
            &action_index.to_le_bytes(),
            &class_id.to_le_bytes(),
        ],
    )
}

define_object! {
    /// FeeAuthorization (family tag 11, ch01 §6.3 prose): sponsor pays fees
    /// for note-only or agent transactions.
    pub struct FeeAuthorizationV1 {
        version: 1;
        1 => amount: u128,
        2 => resource_ceiling: ResourceVector,
        3 => expiry_height: u64,
        4 => tx_commitment: [u8; 32],
        5 => sponsor: [u8; 32],
        6 => signature_suite: u16,
        7 => signature: BoundedBytes<96>,
    }
}

define_object! {
    /// TransactionV1 (family tag 5, ch01 §6.5): canonical non-witness body.
    /// `txid = H(D-TX-ID || canonical body)`; witnesses are segregated.
    pub struct TransactionV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => format_version: u16,
        3 => expiry_height: u64,
        4 => fee_payer: [u8; 32],
        5 => fee_authorization: OptionalObject<FeeAuthorizationV1>,
        6 => resource_limits: ResourceVector,
        7 => note_inputs: BoundedList<[u8; 32], 256>,
        8 => account_inputs: BoundedList<[u8; 32], 64>,
        9 => object_access_list: BoundedList<AccessEntry, 256>,
        10 => actions: BoundedList<BoundedBytes<65536>, 64>,
        11 => outputs: BoundedList<NoteV1, 256>,
        12 => evidence_refs: BoundedList<[u8; 32], 64>,
        13 => witness_root: [u8; 32],
    }
}

define_object! {
    /// SignedIntentV1 (family tag 6, ch01 §6.5). `tx_commitment` MUST equal
    /// the txid: the txid covers the body including `witness_root` (the
    /// witness program roots) and excludes segregated witness bytes.
    pub struct SignedIntentV1 {
        version: 1;
        1 => tx_commitment: [u8; 32],
        2 => signer_scope: u8,
        3 => capability_ref: OptionalHash32,
        4 => signature_suite: u16,
        5 => signature: BoundedBytes<96>,
    }
}

define_object! {
    /// Segregated witness container (lumen-v1.md §4.2): account-intent
    /// signatures + note lock reveals. `intents` align with `account_inputs`
    /// by index; `lock_reveals` align with `note_inputs` by index.
    /// Signatures live here and are excluded from the txid.
    pub struct TransactionWitnessesV1 {
        version: 1;
        1 => intents: BoundedList<SignedIntentV1, 64>,
        2 => lock_reveals: BoundedList<BoundedBytes<4096>, 256>,
    }
}

define_object! {
    /// ContractManifest (family tag 7, ch01 §6.10).
    pub struct ContractManifestV1 {
        version: 1;
        1 => code_hash: [u8; 32],
        2 => abi_root: [u8; 32],
        3 => storage_schema_root: [u8; 32],
        4 => declared_jet_set: BoundedList<[u8; 32], 64>,
        5 => max_resource_vector: ResourceVector,
        6 => upgrade_policy: u8,
        7 => allowed_call_classes: u32,
        8 => invariant_commitments: BoundedList<[u8; 32], 32>,
        9 => compiler_id: [u8; 32],
    }
}

define_object! {
    /// AgentID (family tag 8, ch01 §11.1).
    pub struct AgentIdV1 {
        version: 1;
        1 => agent_id: [u8; 32],
        2 => genesis_manifest_root: [u8; 32],
        3 => controller_policy_root: [u8; 32],
        4 => active_key_root: [u8; 32],
        5 => model_refs_root: [u8; 32],
        6 => host_refs_root: [u8; 32],
        7 => capability_root: [u8; 32],
        8 => recovery_root: [u8; 32],
        9 => agent_version: u64,
    }
}

define_object! {
    /// CapabilityGrant (family tag 9, ch01 §11.1): attenuable, consumable,
    /// expiring, depth-limited, revocable.
    pub struct CapabilityGrantV1 {
        version: 1;
        1 => grant_id: [u8; 32],
        2 => issuer: [u8; 32],
        3 => subject_agent: [u8; 32],
        4 => allowed_action_schema_root: [u8; 32],
        5 => object_scope_root: [u8; 32],
        6 => per_action_limit: u128,
        7 => cumulative_budget: u128,
        8 => expiry_height: u64,
        9 => delegation_depth: u8,
        10 => revocation_nonce: u64,
    }
}

define_object! {
    /// Intent (family tag 10, ch01 §11.1): a model can only PROPOSE this;
    /// the deterministic policy gate checks schema, prestate, capability,
    /// budget, and postcondition. Direction is the typed `action_type`.
    pub struct IntentV1 {
        version: 1;
        1 => agent_id: [u8; 32],
        2 => action_type: u32,
        3 => canonical_arguments: BoundedBytes<65536>,
        4 => finalized_prestate_root: [u8; 32],
        5 => expected_postcondition_root: [u8; 32],
        6 => budget: u128,
        7 => deadline: u64,
        8 => capability_ref: [u8; 32],
        9 => nonce: u64,
    }
}

define_object! {
    /// Settled receipt record: value of the post-state compact
    /// settled-receipt index (keyed by txid). `status` 0 = success; any
    /// non-zero value is the stable failure/trap code (lumen-v1.md §6.4).
    pub struct ReceiptV1 {
        version: 1;
        1 => txid: [u8; 32],
        2 => status: u16,
        3 => fee_charged: u128,
        4 => resources_used: ResourceVector,
    }
}

// ---------------------------------------------------------------------------
// Transaction identity
// ---------------------------------------------------------------------------

/// `txid = H("NOOS/TX/ID/V1" || canonical non-witness body)` (D-TX-ID).
#[must_use]
pub fn txid(tx: &TransactionV1) -> Hash32 {
    domain_hash(domains::TX_ID, &[&tx.encode_canonical()])
}

/// `wtxid = H("NOOS/TX/WID/V1" || canonical body || canonical witnesses)`
/// (D-TX-WID). Distinct from txid by domain AND by covering witness bytes.
#[must_use]
pub fn wtxid(tx: &TransactionV1, witnesses: &TransactionWitnessesV1) -> Hash32 {
    domain_hash(
        domains::TX_WID,
        &[&tx.encode_canonical(), &witnesses.encode_canonical()],
    )
}

/// `witness_root = H("NOOS/TX/WROOT/V1" || canonical lock_reveals list)`
/// (D-TX-WROOT): commits the witness PROGRAMS (revealed lock branches),
/// never the signatures — so the txid→signature binding stays acyclic.
#[must_use]
pub fn witness_root(lock_reveals: &BoundedList<BoundedBytes<4096>, 256>) -> Hash32 {
    domain_hash(domains::TX_WROOT, &[&lock_reveals.encode_canonical()])
}

define_object! {
    /// Fixed-supply user asset registered exactly once by `CreateAsset`.
    pub struct AssetV1 {
        version: 1;
        1 => asset_id: [u8; 32],
        2 => issuer: [u8; 32],
        3 => symbol: BoundedBytes<12>,
        4 => name: BoundedBytes<64>,
        5 => decimals: u8,
        6 => total_supply: u128,
    }
}

define_object! {
    /// Constant-product liquidity pool. Asset ordering is canonical.
    pub struct PoolV1 {
        version: 1;
        1 => pool_id: [u8; 32],
        2 => asset_0: [u8; 32],
        3 => asset_1: [u8; 32],
        4 => reserve_0: u128,
        5 => reserve_1: u128,
        6 => fee_bps: u16,
        7 => creator: [u8; 32],
        8 => total_shares: u128,
    }
}

define_object! {
    /// Provider-owned share balance for one constant-product pool.
    pub struct LiquidityPositionV1 {
        version: 1;
        1 => position_id: [u8; 32],
        2 => pool_id: [u8; 32],
        3 => provider: [u8; 32],
        4 => shares: u128,
    }
}

define_object! {
    /// Governance-created three-reporter price feed.
    pub struct OracleFeedV1 {
        version: 1;
        1 => feed_id: [u8; 32],
        2 => base_asset: [u8; 32],
        3 => quote_asset: [u8; 32],
        4 => reporter_0: [u8; 32],
        5 => reporter_1: [u8; 32],
        6 => reporter_2: [u8; 32],
        7 => max_age_blocks: u64,
    }
}

define_object! {
    /// Monotonic authenticated report for one feed member.
    pub struct OracleReportV1 {
        version: 1;
        1 => report_id: [u8; 32],
        2 => feed_id: [u8; 32],
        3 => reporter: [u8; 32],
        4 => price_q9: u128,
        5 => confidence_bps: u16,
        6 => sequence: u64,
        7 => observed_height: u64,
    }
}

define_object! {
    /// Dynamically issued stable asset whose supply equals market debt.
    pub struct StableAssetV1 {
        version: 1;
        1 => asset_id: [u8; 32],
        2 => market_id: [u8; 32],
        3 => symbol: BoundedBytes<12>,
        4 => name: BoundedBytes<64>,
        5 => decimals: u8,
        6 => minted_supply: u128,
        7 => kind: u8,
    }
}

define_object! {
    /// One isolated overcollateralized stable-debt market.
    pub struct LendingMarketV1 {
        version: 1;
        1 => market_id: [u8; 32],
        2 => collateral_asset: [u8; 32],
        3 => stable_asset: [u8; 32],
        4 => oracle_feed_id: [u8; 32],
        5 => collateral_factor_bps: u16,
        6 => liquidation_threshold_bps: u16,
        7 => liquidation_bonus_bps: u16,
        8 => debt_ceiling: u128,
        9 => min_debt: u128,
        10 => total_debt: u128,
    }
}

define_object! {
    /// Owner-isolated collateral and stable debt.
    pub struct DebtPositionV1 {
        version: 1;
        1 => position_id: [u8; 32],
        2 => market_id: [u8; 32],
        3 => owner: [u8; 32],
        4 => collateral: u128,
        5 => debt: u128,
    }
}
define_object! {
    /// Compute worker advertisement used by the application-only rental
    /// market. Capability bit 0 = CPU and bit 1 = GPU.
    pub struct ComputeWorkerV1 {
        version: 1;
        1 => worker: [u8; 32],
        2 => capabilities: u8,
        3 => cpu_threads: u16,
        4 => memory_mb: u32,
        5 => gpu_memory_mb: u32,
        6 => price_per_unit: u128,
        7 => endpoint_commitment: [u8; 32],
        8 => active: u8,
        9 => jobs_completed: u64,
        10 => units_completed: u64,
    }
}

define_object! {
    /// Escrowed V0 compute job. Result correctness is accepted explicitly by
    /// the requester; `Submitted` alone can never release payment.
    pub struct ComputeJobV1 {
        version: 1;
        1 => job_id: [u8; 32],
        2 => requester: [u8; 32],
        3 => worker: OptionalHash32,
        4 => workload_kind: u8,
        5 => input_root: [u8; 32],
        6 => units: u64,
        7 => unit_size: u32,
        8 => max_price_per_unit: u128,
        9 => agreed_price_per_unit: u128,
        10 => escrow: u128,
        11 => deadline_height: u64,
        12 => state: u8,
        13 => result_root: [u8; 32],
        14 => completed_units: u64,
    }
}

impl ComputeWorkerV1 {
    pub const CAPABILITY_CPU: u8 = 1;
    pub const CAPABILITY_GPU: u8 = 2;
}

impl ComputeJobV1 {
    pub const STATE_OPEN: u8 = 0;
    pub const STATE_CLAIMED: u8 = 1;
    pub const STATE_SUBMITTED: u8 = 2;
    pub const STATE_SETTLED: u8 = 3;
    pub const STATE_CANCELLED: u8 = 4;
}

#[must_use]
pub fn asset_id(creating_txid: &Hash32, action_index: u32) -> Hash32 {
    domain_hash(
        "NOOS/ASSET/ID/V1",
        &[creating_txid, &action_index.to_le_bytes()],
    )
}

#[must_use]
pub fn pool_id(asset_a: &Hash32, asset_b: &Hash32) -> Hash32 {
    let (asset_0, asset_1) = if asset_a < asset_b {
        (asset_a, asset_b)
    } else {
        (asset_b, asset_a)
    };
    domain_hash("NOOS/POOL/ID/V1", &[asset_0, asset_1])
}

#[must_use]
pub fn liquidity_position_id(pool: &Hash32, provider: &Hash32) -> Hash32 {
    domain_hash("NOOS/POOL/POSITION/ID/V1", &[pool, provider])
}

#[must_use]
pub fn oracle_feed_id(base_asset: &Hash32, quote_asset: &Hash32) -> Hash32 {
    domain_hash("NOOS/ORACLE/FEED/ID/V1", &[base_asset, quote_asset])
}

#[must_use]
pub fn oracle_report_id(feed: &Hash32, reporter: &Hash32) -> Hash32 {
    domain_hash("NOOS/ORACLE/REPORT/ID/V1", &[feed, reporter])
}

#[must_use]
pub fn lending_market_id(collateral: &Hash32, feed: &Hash32) -> Hash32 {
    domain_hash("NOOS/LENDING/MARKET/ID/V1", &[collateral, feed])
}

#[must_use]
pub fn stable_asset_id(market: &Hash32) -> Hash32 {
    domain_hash("NOOS/STABLE/ASSET/ID/V1", &[market])
}

#[must_use]
pub fn debt_position_id(market: &Hash32, owner: &Hash32) -> Hash32 {
    domain_hash("NOOS/LENDING/POSITION/ID/V1", &[market, owner])
}
#[must_use]
pub fn compute_job_id(creating_txid: &Hash32, action_index: u32) -> Hash32 {
    domain_hash(
        "NOOS/COMPUTE/JOB/ID/V1",
        &[creating_txid, &action_index.to_le_bytes()],
    )
}

// ---------------------------------------------------------------------------
// Typed actions (declaration-order discriminants, lumen-v1.md §5)
// ---------------------------------------------------------------------------

// User-asset issuance below is fixed-supply, domain-derived, and exactly once;
// it cannot mint NOOS, alter scheduled issuance, seize state, revert finality,
// admit code, exceed hard caps, or activate a disabled suite.

/// Typed transaction action. Encoded as `u16` discriminant in declaration
/// order followed by the variant fields; carried inside the envelope's
/// bounded `actions[]` byte strings.
///
/// Closed by construction (plan §4.7): user-asset creation is fixed-supply
/// and domain-derived; there is no variant that mints NOOS, seizes user
/// state, reverts finalized state, forges finality, admits code outside the
/// registry path, exceeds caps, or activates a disabled suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionV1 {
    /// 0 — call a Grain contract object through the ContractEngine.
    CallObject {
        object_id: Hash32,
        input: BoundedBytes<65536>,
    },
    /// 1 — create an object; `object_id` derives from (txid, action index,
    /// class_id) under D-OBJECT-ID.
    CreateObject {
        class_id: u32,
        owner_or_policy_root: Hash32,
        code_hash: Hash32,
        state_root: Hash32,
        storage_words: u64,
        rent_deposit: u128,
        flags: u32,
    },
    /// 2 — move value from note-input surplus into an account liquid balance.
    DepositToAccount {
        account_id: Hash32,
        asset_id: Hash32,
        amount: u128,
    },
    /// 3 — move value from a signed account input's balance into output surplus.
    WithdrawFromAccount {
        account_id: Hash32,
        asset_id: Hash32,
        amount: u128,
    },
    /// 4 — versioned parameter update with activation delay. Feature-control
    /// keys (`noos.control.*`) are NOT writable here (activation of a
    /// disabled suite requires a hard fork, ch01 §8.6/§12).
    GovernanceParamUpdate {
        param_key: Hash32,
        new_value: BoundedBytes<4096>,
        activation_height: u64,
    },
    /// 5 — versioned registry update (`noos.registry.*` keys only), same
    /// activation-delay law as parameter updates.
    GovernanceRegistryUpdate {
        registry_key: Hash32,
        new_value: BoundedBytes<4096>,
        activation_height: u64,
    },
    /// 6 — emergency: set a feature control to DISABLED (never enable).
    EmergencyDisable { control_key: Hash32 },
    /// 7 — emergency: quarantine an object (set FLAG_QUARANTINED; calls
    /// reject until governance lifts it through the delayed path).
    EmergencyQuarantine { object_id: Hash32 },
    /// 8 — register an agent identity object.
    RegisterAgent { agent: AgentIdV1 },
    /// 9 — issue a capability grant (issuer must be a signed account input).
    GrantCapability { grant: CapabilityGrantV1 },
    /// 10 — revoke a capability grant (issuer must be a signed account input).
    RevokeCapability { grant_id: Hash32 },
    /// 11 — submit a typed agent intent through the deterministic policy gate.
    SubmitIntent { intent: IntentV1 },
    /// 12 — register and issue a fixed-supply user asset to its signed issuer.
    CreateAsset {
        issuer: Hash32,
        symbol: BoundedBytes<12>,
        name: BoundedBytes<64>,
        decimals: u8,
        total_supply: u128,
    },
    /// 13 — seed the unique constant-product pool for an unordered pair.
    CreatePool {
        provider: Hash32,
        asset_a: Hash32,
        asset_b: Hash32,
        amount_a: u128,
        amount_b: u128,
        fee_bps: u16,
    },
    /// 14 — swap an exact signed-account input with a minimum output.
    SwapExactIn {
        trader: Hash32,
        pool_id: Hash32,
        asset_in: Hash32,
        amount_in: u128,
        min_amount_out: u128,
    },
    /// 15 — create or update a signed worker advertisement.
    RegisterComputeWorker {
        worker: Hash32,
        capabilities: u8,
        cpu_threads: u16,
        memory_mb: u32,
        gpu_memory_mb: u32,
        price_per_unit: u128,
        endpoint_commitment: Hash32,
    },
    /// 16 — lock requester NOOS for one independently executable shard.
    OpenComputeJob {
        requester: Hash32,
        workload_kind: u8,
        input_root: Hash32,
        units: u64,
        unit_size: u32,
        max_price_per_unit: u128,
        deadline_height: u64,
    },
    /// 17 — bind an open shard to a signed registered worker.
    ClaimComputeJob { worker: Hash32, job_id: Hash32 },
    /// 18 — commit delivery; payment remains locked pending requester review.
    SubmitComputeResult {
        worker: Hash32,
        job_id: Hash32,
        result_root: Hash32,
        completed_units: u64,
    },
    /// 19 — requester accepts delivery and atomically settles worker payment.
    AcceptComputeResult { requester: Hash32, job_id: Hash32 },
    /// 20 — requester cancels an unclaimed or expired job and receives escrow.
    CancelComputeJob { requester: Hash32, job_id: Hash32 },
    /// 21 — add proportional reserves and receive non-dilutive pool shares.
    AddLiquidity {
        provider: Hash32,
        pool_id: Hash32,
        max_amount_0: u128,
        max_amount_1: u128,
        min_shares: u128,
    },
    /// 22 — burn owned shares for proportional reserves.
    RemoveLiquidity {
        provider: Hash32,
        pool_id: Hash32,
        shares: u128,
        min_amount_0: u128,
        min_amount_1: u128,
    },
    /// 23 — governance creates a fixed three-reporter feed.
    CreateOracleFeed {
        base_asset: Hash32,
        quote_asset: Hash32,
        reporter_0: Hash32,
        reporter_1: Hash32,
        reporter_2: Hash32,
        max_age_blocks: u64,
    },
    /// 24 — one feed member advances its authenticated report.
    SubmitOracleReport {
        reporter: Hash32,
        feed_id: Hash32,
        price_q9: u128,
        confidence_bps: u16,
        sequence: u64,
        observed_height: u64,
    },
    /// 25 — governance creates an isolated overcollateralized stable market.
    CreateLendingMarket {
        collateral_asset: Hash32,
        oracle_feed_id: Hash32,
        symbol: BoundedBytes<12>,
        name: BoundedBytes<64>,
        decimals: u8,
        collateral_factor_bps: u16,
        liquidation_threshold_bps: u16,
        liquidation_bonus_bps: u16,
        debt_ceiling: u128,
        min_debt: u128,
    },
    /// 26 — lock signed collateral in the owner's isolated position.
    DepositCollateral {
        owner: Hash32,
        market_id: Hash32,
        amount: u128,
    },
    /// 27 — withdraw collateral while preserving the borrow ratio.
    WithdrawCollateral {
        owner: Hash32,
        market_id: Hash32,
        amount: u128,
    },
    /// 28 — mint stable debt to a healthy signed position.
    BorrowStable {
        owner: Hash32,
        market_id: Hash32,
        amount: u128,
    },
    /// 29 — burn stable balance and reduce signed debt.
    RepayStable {
        owner: Hash32,
        market_id: Hash32,
        amount: u128,
    },
    /// 30 — repay unhealthy debt and seize bounded collateral.
    LiquidatePosition {
        liquidator: Hash32,
        market_id: Hash32,
        owner: Hash32,
        repay_amount: u128,
        min_collateral_out: u128,
    },
}

impl ActionV1 {
    pub const VARIANT_COUNT: u16 = 31;
}

impl NoosEncode for ActionV1 {
    fn encode(&self, w: &mut Writer) {
        match self {
            ActionV1::CallObject { object_id, input } => {
                w.put_u16(0);
                w.put_array32(object_id);
                input.encode(w);
            }
            ActionV1::CreateObject {
                class_id,
                owner_or_policy_root,
                code_hash,
                state_root,
                storage_words,
                rent_deposit,
                flags,
            } => {
                w.put_u16(1);
                w.put_u32(*class_id);
                w.put_array32(owner_or_policy_root);
                w.put_array32(code_hash);
                w.put_array32(state_root);
                w.put_u64(*storage_words);
                w.put_u128(*rent_deposit);
                w.put_u32(*flags);
            }
            ActionV1::DepositToAccount {
                account_id,
                asset_id,
                amount,
            } => {
                w.put_u16(2);
                w.put_array32(account_id);
                w.put_array32(asset_id);
                w.put_u128(*amount);
            }
            ActionV1::WithdrawFromAccount {
                account_id,
                asset_id,
                amount,
            } => {
                w.put_u16(3);
                w.put_array32(account_id);
                w.put_array32(asset_id);
                w.put_u128(*amount);
            }
            ActionV1::GovernanceParamUpdate {
                param_key,
                new_value,
                activation_height,
            } => {
                w.put_u16(4);
                w.put_array32(param_key);
                new_value.encode(w);
                w.put_u64(*activation_height);
            }
            ActionV1::GovernanceRegistryUpdate {
                registry_key,
                new_value,
                activation_height,
            } => {
                w.put_u16(5);
                w.put_array32(registry_key);
                new_value.encode(w);
                w.put_u64(*activation_height);
            }
            ActionV1::EmergencyDisable { control_key } => {
                w.put_u16(6);
                w.put_array32(control_key);
            }
            ActionV1::EmergencyQuarantine { object_id } => {
                w.put_u16(7);
                w.put_array32(object_id);
            }
            ActionV1::RegisterAgent { agent } => {
                w.put_u16(8);
                agent.encode(w);
            }
            ActionV1::GrantCapability { grant } => {
                w.put_u16(9);
                grant.encode(w);
            }
            ActionV1::RevokeCapability { grant_id } => {
                w.put_u16(10);
                w.put_array32(grant_id);
            }
            ActionV1::SubmitIntent { intent } => {
                w.put_u16(11);
                intent.encode(w);
            }
            ActionV1::CreateAsset {
                issuer,
                symbol,
                name,
                decimals,
                total_supply,
            } => {
                w.put_u16(12);
                w.put_array32(issuer);
                symbol.encode(w);
                name.encode(w);
                w.put_u8(*decimals);
                w.put_u128(*total_supply);
            }
            ActionV1::CreatePool {
                provider,
                asset_a,
                asset_b,
                amount_a,
                amount_b,
                fee_bps,
            } => {
                w.put_u16(13);
                w.put_array32(provider);
                w.put_array32(asset_a);
                w.put_array32(asset_b);
                w.put_u128(*amount_a);
                w.put_u128(*amount_b);
                w.put_u16(*fee_bps);
            }
            ActionV1::SwapExactIn {
                trader,
                pool_id,
                asset_in,
                amount_in,
                min_amount_out,
            } => {
                w.put_u16(14);
                w.put_array32(trader);
                w.put_array32(pool_id);
                w.put_array32(asset_in);
                w.put_u128(*amount_in);
                w.put_u128(*min_amount_out);
            }
            ActionV1::AddLiquidity {
                provider,
                pool_id,
                max_amount_0,
                max_amount_1,
                min_shares,
            } => {
                w.put_u16(21);
                w.put_array32(provider);
                w.put_array32(pool_id);
                w.put_u128(*max_amount_0);
                w.put_u128(*max_amount_1);
                w.put_u128(*min_shares);
            }
            ActionV1::RemoveLiquidity {
                provider,
                pool_id,
                shares,
                min_amount_0,
                min_amount_1,
            } => {
                w.put_u16(22);
                w.put_array32(provider);
                w.put_array32(pool_id);
                w.put_u128(*shares);
                w.put_u128(*min_amount_0);
                w.put_u128(*min_amount_1);
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
                w.put_u16(15);
                w.put_array32(worker);
                w.put_u8(*capabilities);
                w.put_u16(*cpu_threads);
                w.put_u32(*memory_mb);
                w.put_u32(*gpu_memory_mb);
                w.put_u128(*price_per_unit);
                w.put_array32(endpoint_commitment);
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
                w.put_u16(16);
                w.put_array32(requester);
                w.put_u8(*workload_kind);
                w.put_array32(input_root);
                w.put_u64(*units);
                w.put_u32(*unit_size);
                w.put_u128(*max_price_per_unit);
                w.put_u64(*deadline_height);
            }
            ActionV1::ClaimComputeJob { worker, job_id } => {
                w.put_u16(17);
                w.put_array32(worker);
                w.put_array32(job_id);
            }
            ActionV1::SubmitComputeResult {
                worker,
                job_id,
                result_root,
                completed_units,
            } => {
                w.put_u16(18);
                w.put_array32(worker);
                w.put_array32(job_id);
                w.put_array32(result_root);
                w.put_u64(*completed_units);
            }
            ActionV1::AcceptComputeResult { requester, job_id } => {
                w.put_u16(19);
                w.put_array32(requester);
                w.put_array32(job_id);
            }
            ActionV1::CancelComputeJob { requester, job_id } => {
                w.put_u16(20);
                w.put_array32(requester);
                w.put_array32(job_id);
            }
            ActionV1::CreateOracleFeed {
                base_asset,
                quote_asset,
                reporter_0,
                reporter_1,
                reporter_2,
                max_age_blocks,
            } => {
                w.put_u16(23);
                w.put_array32(base_asset);
                w.put_array32(quote_asset);
                w.put_array32(reporter_0);
                w.put_array32(reporter_1);
                w.put_array32(reporter_2);
                w.put_u64(*max_age_blocks);
            }
            ActionV1::SubmitOracleReport {
                reporter,
                feed_id,
                price_q9,
                confidence_bps,
                sequence,
                observed_height,
            } => {
                w.put_u16(24);
                w.put_array32(reporter);
                w.put_array32(feed_id);
                w.put_u128(*price_q9);
                w.put_u16(*confidence_bps);
                w.put_u64(*sequence);
                w.put_u64(*observed_height);
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
                w.put_u16(25);
                w.put_array32(collateral_asset);
                w.put_array32(oracle_feed_id);
                symbol.encode(w);
                name.encode(w);
                w.put_u8(*decimals);
                w.put_u16(*collateral_factor_bps);
                w.put_u16(*liquidation_threshold_bps);
                w.put_u16(*liquidation_bonus_bps);
                w.put_u128(*debt_ceiling);
                w.put_u128(*min_debt);
            }
            ActionV1::DepositCollateral {
                owner,
                market_id,
                amount,
            } => {
                w.put_u16(26);
                w.put_array32(owner);
                w.put_array32(market_id);
                w.put_u128(*amount);
            }
            ActionV1::WithdrawCollateral {
                owner,
                market_id,
                amount,
            } => {
                w.put_u16(27);
                w.put_array32(owner);
                w.put_array32(market_id);
                w.put_u128(*amount);
            }
            ActionV1::BorrowStable {
                owner,
                market_id,
                amount,
            } => {
                w.put_u16(28);
                w.put_array32(owner);
                w.put_array32(market_id);
                w.put_u128(*amount);
            }
            ActionV1::RepayStable {
                owner,
                market_id,
                amount,
            } => {
                w.put_u16(29);
                w.put_array32(owner);
                w.put_array32(market_id);
                w.put_u128(*amount);
            }
            ActionV1::LiquidatePosition {
                liquidator,
                market_id,
                owner,
                repay_amount,
                min_collateral_out,
            } => {
                w.put_u16(30);
                w.put_array32(liquidator);
                w.put_array32(market_id);
                w.put_array32(owner);
                w.put_u128(*repay_amount);
                w.put_u128(*min_collateral_out);
            }
        }
    }
}

impl NoosDecode for ActionV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        match r.get_discriminant(Self::VARIANT_COUNT)? {
            0 => Ok(ActionV1::CallObject {
                object_id: r.get_array32()?,
                input: BoundedBytes::decode(r)?,
            }),
            1 => Ok(ActionV1::CreateObject {
                class_id: r.get_u32()?,
                owner_or_policy_root: r.get_array32()?,
                code_hash: r.get_array32()?,
                state_root: r.get_array32()?,
                storage_words: r.get_u64()?,
                rent_deposit: r.get_u128()?,
                flags: r.get_u32()?,
            }),
            2 => Ok(ActionV1::DepositToAccount {
                account_id: r.get_array32()?,
                asset_id: r.get_array32()?,
                amount: r.get_u128()?,
            }),
            3 => Ok(ActionV1::WithdrawFromAccount {
                account_id: r.get_array32()?,
                asset_id: r.get_array32()?,
                amount: r.get_u128()?,
            }),
            4 => Ok(ActionV1::GovernanceParamUpdate {
                param_key: r.get_array32()?,
                new_value: BoundedBytes::decode(r)?,
                activation_height: r.get_u64()?,
            }),
            5 => Ok(ActionV1::GovernanceRegistryUpdate {
                registry_key: r.get_array32()?,
                new_value: BoundedBytes::decode(r)?,
                activation_height: r.get_u64()?,
            }),
            6 => Ok(ActionV1::EmergencyDisable {
                control_key: r.get_array32()?,
            }),
            7 => Ok(ActionV1::EmergencyQuarantine {
                object_id: r.get_array32()?,
            }),
            8 => Ok(ActionV1::RegisterAgent {
                agent: AgentIdV1::decode(r)?,
            }),
            9 => Ok(ActionV1::GrantCapability {
                grant: CapabilityGrantV1::decode(r)?,
            }),
            10 => Ok(ActionV1::RevokeCapability {
                grant_id: r.get_array32()?,
            }),
            11 => Ok(ActionV1::SubmitIntent {
                intent: IntentV1::decode(r)?,
            }),
            12 => Ok(ActionV1::CreateAsset {
                issuer: r.get_array32()?,
                symbol: BoundedBytes::decode(r)?,
                name: BoundedBytes::decode(r)?,
                decimals: r.get_u8()?,
                total_supply: r.get_u128()?,
            }),
            13 => Ok(ActionV1::CreatePool {
                provider: r.get_array32()?,
                asset_a: r.get_array32()?,
                asset_b: r.get_array32()?,
                amount_a: r.get_u128()?,
                amount_b: r.get_u128()?,
                fee_bps: r.get_u16()?,
            }),
            14 => Ok(ActionV1::SwapExactIn {
                trader: r.get_array32()?,
                pool_id: r.get_array32()?,
                asset_in: r.get_array32()?,
                amount_in: r.get_u128()?,
                min_amount_out: r.get_u128()?,
            }),
            15 => Ok(ActionV1::RegisterComputeWorker {
                worker: r.get_array32()?,
                capabilities: r.get_u8()?,
                cpu_threads: r.get_u16()?,
                memory_mb: r.get_u32()?,
                gpu_memory_mb: r.get_u32()?,
                price_per_unit: r.get_u128()?,
                endpoint_commitment: r.get_array32()?,
            }),
            16 => Ok(ActionV1::OpenComputeJob {
                requester: r.get_array32()?,
                workload_kind: r.get_u8()?,
                input_root: r.get_array32()?,
                units: r.get_u64()?,
                unit_size: r.get_u32()?,
                max_price_per_unit: r.get_u128()?,
                deadline_height: r.get_u64()?,
            }),
            17 => Ok(ActionV1::ClaimComputeJob {
                worker: r.get_array32()?,
                job_id: r.get_array32()?,
            }),
            18 => Ok(ActionV1::SubmitComputeResult {
                worker: r.get_array32()?,
                job_id: r.get_array32()?,
                result_root: r.get_array32()?,
                completed_units: r.get_u64()?,
            }),
            19 => Ok(ActionV1::AcceptComputeResult {
                requester: r.get_array32()?,
                job_id: r.get_array32()?,
            }),
            20 => Ok(ActionV1::CancelComputeJob {
                requester: r.get_array32()?,
                job_id: r.get_array32()?,
            }),
            21 => Ok(ActionV1::AddLiquidity {
                provider: r.get_array32()?,
                pool_id: r.get_array32()?,
                max_amount_0: r.get_u128()?,
                max_amount_1: r.get_u128()?,
                min_shares: r.get_u128()?,
            }),
            22 => Ok(ActionV1::RemoveLiquidity {
                provider: r.get_array32()?,
                pool_id: r.get_array32()?,
                shares: r.get_u128()?,
                min_amount_0: r.get_u128()?,
                min_amount_1: r.get_u128()?,
            }),
            23 => Ok(ActionV1::CreateOracleFeed {
                base_asset: r.get_array32()?,
                quote_asset: r.get_array32()?,
                reporter_0: r.get_array32()?,
                reporter_1: r.get_array32()?,
                reporter_2: r.get_array32()?,
                max_age_blocks: r.get_u64()?,
            }),
            24 => Ok(ActionV1::SubmitOracleReport {
                reporter: r.get_array32()?,
                feed_id: r.get_array32()?,
                price_q9: r.get_u128()?,
                confidence_bps: r.get_u16()?,
                sequence: r.get_u64()?,
                observed_height: r.get_u64()?,
            }),
            25 => Ok(ActionV1::CreateLendingMarket {
                collateral_asset: r.get_array32()?,
                oracle_feed_id: r.get_array32()?,
                symbol: BoundedBytes::decode(r)?,
                name: BoundedBytes::decode(r)?,
                decimals: r.get_u8()?,
                collateral_factor_bps: r.get_u16()?,
                liquidation_threshold_bps: r.get_u16()?,
                liquidation_bonus_bps: r.get_u16()?,
                debt_ceiling: r.get_u128()?,
                min_debt: r.get_u128()?,
            }),
            26 => Ok(ActionV1::DepositCollateral {
                owner: r.get_array32()?,
                market_id: r.get_array32()?,
                amount: r.get_u128()?,
            }),
            27 => Ok(ActionV1::WithdrawCollateral {
                owner: r.get_array32()?,
                market_id: r.get_array32()?,
                amount: r.get_u128()?,
            }),
            28 => Ok(ActionV1::BorrowStable {
                owner: r.get_array32()?,
                market_id: r.get_array32()?,
                amount: r.get_u128()?,
            }),
            29 => Ok(ActionV1::RepayStable {
                owner: r.get_array32()?,
                market_id: r.get_array32()?,
                amount: r.get_u128()?,
            }),
            30 => Ok(ActionV1::LiquidatePosition {
                liquidator: r.get_array32()?,
                market_id: r.get_array32()?,
                owner: r.get_array32()?,
                repay_amount: r.get_u128()?,
                min_collateral_out: r.get_u128()?,
            }),
            _ => Err(CodecError::UnknownDiscriminant),
        }
    }
}

// ---------------------------------------------------------------------------
// Params-tree records (values are always ParamRecordV1 wrapping inner bytes)
// ---------------------------------------------------------------------------

define_object! {
    /// Every params-tree value: current canonical bytes plus at most one
    /// pending update with its activation height (governance delay law,
    /// lumen-v1.md §7).
    pub struct ParamRecordV1 {
        version: 1;
        1 => current: BoundedBytes<4096>,
        2 => pending: OptionalObject<PendingParamV1>,
    }
}

define_object! {
    /// Pending parameter value awaiting activation.
    pub struct PendingParamV1 {
        version: 1;
        1 => value: BoundedBytes<4096>,
        2 => activation_height: u64,
    }
}

define_object! {
    /// Feature control (params tree, `noos.control.*`): `enabled` is 0 or 1.
    /// Emergency can only write 0; governance param updates reject these keys.
    pub struct FeatureControlV1 {
        version: 1;
        1 => enabled: u8,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_note(amount: u128) -> NoteV1 {
        NoteV1 {
            asset_id: [1; 32],
            amount,
            lock_root: [2; 32],
            datum_root: [3; 32],
            birth_height: 7,
            relative_timelock: 0,
            memo_commitment: [4; 32],
        }
    }

    fn sample_tx() -> TransactionV1 {
        TransactionV1 {
            chain_id: [9; 32],
            format_version: 1,
            expiry_height: 100,
            fee_payer: [8; 32],
            fee_authorization: OptionalObject(None),
            resource_limits: ResourceVector {
                bytes: 4096,
                grain_steps: 1000,
                proof_units: 0,
                state_reads: 16,
                state_writes: 16,
                blob_bytes: 0,
            },
            note_inputs: BoundedList::new(vec![[5; 32]]).unwrap(),
            account_inputs: BoundedList::new(vec![[8; 32]]).unwrap(),
            object_access_list: BoundedList::new(vec![]).unwrap(),
            actions: BoundedList::new(vec![]).unwrap(),
            outputs: BoundedList::new(vec![sample_note(50)]).unwrap(),
            evidence_refs: BoundedList::new(vec![]).unwrap(),
            witness_root: [0; 32],
        }
    }

    #[test]
    fn all_objects_roundtrip() {
        let tx = sample_tx();
        let b = tx.encode_canonical();
        assert_eq!(TransactionV1::decode_canonical(&b).unwrap(), tx);

        let note = sample_note(1);
        assert_eq!(
            NoteV1::decode_canonical(&note.encode_canonical()).unwrap(),
            note
        );

        let acct = AccountV1 {
            account_id: [1; 32],
            auth_descriptor: BoundedBytes::new(vec![1, 2, 3]).unwrap(),
            nonce: 5,
            liquid_balances_root: crate::smt::empty_root(crate::smt::DEPTH),
            bond_refs_root: [0; 32],
            metadata_commitment: [0; 32],
            recovery_policy_root: [0; 32],
        };
        assert_eq!(
            AccountV1::decode_canonical(&acct.encode_canonical()).unwrap(),
            acct
        );

        let manifest = ContractManifestV1 {
            code_hash: [1; 32],
            abi_root: [2; 32],
            storage_schema_root: [3; 32],
            declared_jet_set: BoundedList::new(vec![[4; 32]]).unwrap(),
            max_resource_vector: ResourceVector::default(),
            upgrade_policy: 0,
            allowed_call_classes: 0xF,
            invariant_commitments: BoundedList::new(vec![]).unwrap(),
            compiler_id: [5; 32],
        };
        assert_eq!(
            ContractManifestV1::decode_canonical(&manifest.encode_canonical()).unwrap(),
            manifest
        );

        let grant = CapabilityGrantV1 {
            grant_id: [1; 32],
            issuer: [2; 32],
            subject_agent: [3; 32],
            allowed_action_schema_root: [4; 32],
            object_scope_root: [5; 32],
            per_action_limit: 100,
            cumulative_budget: 1000,
            expiry_height: 99,
            delegation_depth: 2,
            revocation_nonce: 0,
        };
        assert_eq!(
            CapabilityGrantV1::decode_canonical(&grant.encode_canonical()).unwrap(),
            grant
        );
    }

    #[test]
    fn txid_and_wtxid_differ_and_witnesses_bind_wtxid_only() {
        let tx = sample_tx();
        let w0 = TransactionWitnessesV1 {
            intents: BoundedList::new(vec![]).unwrap(),
            lock_reveals: BoundedList::new(vec![BoundedBytes::new(vec![1]).unwrap()]).unwrap(),
        };
        let w1 = TransactionWitnessesV1 {
            intents: BoundedList::new(vec![]).unwrap(),
            lock_reveals: BoundedList::new(vec![BoundedBytes::new(vec![2]).unwrap()]).unwrap(),
        };
        let id = txid(&tx);
        assert_ne!(id, wtxid(&tx, &w0), "txid and wtxid must differ");
        // Witness malleation changes wtxid but never txid.
        assert_ne!(wtxid(&tx, &w0), wtxid(&tx, &w1));
        assert_eq!(id, txid(&tx));
        // Even for empty witnesses the domains keep the ids distinct.
        let empty = TransactionWitnessesV1 {
            intents: BoundedList::new(vec![]).unwrap(),
            lock_reveals: BoundedList::new(vec![]).unwrap(),
        };
        assert_ne!(txid(&tx), wtxid(&tx, &empty));
    }

    #[test]
    fn note_id_binds_txid_index_and_content() {
        let n = sample_note(10);
        let base = note_id(&[1; 32], 0, &n);
        assert_ne!(base, note_id(&[2; 32], 0, &n), "txid must bind");
        assert_ne!(base, note_id(&[1; 32], 1, &n), "output index must bind");
        assert_ne!(
            base,
            note_id(&[1; 32], 0, &sample_note(11)),
            "content must bind"
        );
        // The historical chain's note domain (hex-decoded at runtime; old
        // identity literals are forbidden in source) never reproduces a
        // NOOS note id.
        let legacy = crate::test_util::legacy_note_domain();
        let old = domain_hash(
            &legacy,
            &[&[1u8; 32], &0u32.to_le_bytes(), &n.encode_canonical()],
        );
        assert_ne!(base, old);
    }

    #[test]
    fn action_discriminants_are_declaration_ordered_and_closed() {
        let actions = vec![
            ActionV1::CallObject {
                object_id: [1; 32],
                input: BoundedBytes::new(vec![]).unwrap(),
            },
            ActionV1::EmergencyDisable {
                control_key: [2; 32],
            },
            ActionV1::RevokeCapability { grant_id: [3; 32] },
        ];
        for a in &actions {
            let b = a.encode_canonical();
            assert_eq!(&ActionV1::decode_canonical(&b).unwrap(), a);
        }
        // Discriminant 12 (one past the closed set) rejects: there is no
        // mint / seize / revert / forge-finality / admit-code / exceed-caps /
        // activate-suite action, at the type level.
        let mut w = Writer::new();
        w.put_u16(ActionV1::VARIANT_COUNT);
        w.put_array32(&[0; 32]);
        assert_eq!(
            ActionV1::decode_canonical(&w.into_bytes()),
            Err(CodecError::UnknownDiscriminant)
        );
    }

    #[test]
    fn optional_presence_byte_is_strict() {
        let mut w = Writer::new();
        w.put_u8(2);
        w.put_array32(&[0; 32]);
        assert_eq!(
            OptionalHash32::decode_canonical(&w.into_bytes()),
            Err(CodecError::UnknownDiscriminant)
        );
    }

    #[test]
    fn access_entry_mode_is_strict() {
        let mut w = Writer::new();
        w.put_array32(&[0; 32]);
        w.put_u8(2);
        assert_eq!(
            AccessEntry::decode_canonical(&w.into_bytes()),
            Err(CodecError::UnknownDiscriminant)
        );
    }

    #[test]
    fn oversized_collection_rejects_at_bound() {
        // 65 account inputs exceed the frozen max of 64.
        let mut w = Writer::new();
        w.put_u32(65);
        for _ in 0..65 {
            w.put_array32(&[7; 32]);
        }
        let r: Result<BoundedList<[u8; 32], 64>, _> =
            BoundedList::decode_canonical(&w.into_bytes());
        assert_eq!(r, Err(CodecError::LengthExceedsBound));
    }
}
