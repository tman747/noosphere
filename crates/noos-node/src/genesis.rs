//! Genesis boot (plan §2.3-2.5; identity-v1.md §4; node-v1.md §2).
//!
//! * [`DevnetParams`] — strict loader for
//!   `protocol/genesis/devnet-parameters.toml`. The file is CHECKED, never
//!   trusted: consensus timing values must equal the compile-frozen crate
//!   constants, and every `is_test_fixture` item is refused unless
//!   `is_test_network = true` (plan §2.5 — mainnet parameters are
//!   OWNER_BLOCKED and absent by design).
//! * [`GenesisParameterManifestV1`] — the canonical fixed-width manifest
//!   whose hash (under `D-GENESIS-PARAMS`) derives `chain_id` (under
//!   `D-CHAIN-ID`), then `genesis_hash` (under `D-GENESIS-FINAL` with the
//!   devnet zero Bitcoin anchor, fixture DKG root, canonical allocation
//!   commitment, and every constructed Lumen state root). A JSON/TOML map
//!   serialization is never hashed (identity-v1.md §4).
//! * [`GenesisSpec::build`] — the genesis ledger (valueless `NOOS_TEST`
//!   faucet + fixture authority/recipient accounts), genesis block header,
//!   body, and trivially mined Ground ticket.

use noos_braid::{
    BlockBodyV1, BlockHeaderV1, Bytes48, Bytes96, CheckpointRef, GroundTicketWire,
    ResourcePriceVectorV1, ResourceVectorV1, ZERO_ROOT,
};
use noos_codec::{define_object, NoosEncode};
use noos_crypto::{hash_domain, BlsSecretKey, DomainId};
use noos_ground::{
    ground_challenge, ground_digest, ChallengeInputs, GroundTicketV1, GROUND_PROFILE_ID_V1, U256,
};
use noos_lumen::fees::{FeeParamsV1, FeeStateV1};
use noos_lumen::issuance::{EmissionSharesV1, IssuanceParamsV1};
use noos_lumen::objects::{AccountV1, BoundedBytes, BoundedList};
use noos_lumen::state::{GenesisConfig, LumenLedger, NOOS_ASSET};

use crate::roots::{
    body_cert_root, body_receipt_root, body_ticket_root, body_tx_root, body_witness_root,
};
use crate::{Hash32, NodeError};

// ---------------------------------------------------------------------------
// Devnet fixture identities (valueless; node-v1.md §2.2)
// ---------------------------------------------------------------------------

/// Devnet emission recipient: proposer pool account (fixture).
pub const PROPOSER_POOL_ACCOUNT: Hash32 = [0xA1; 32];
/// Devnet emission recipient: witness pool account (fixture).
pub const WITNESS_POOL_ACCOUNT: Hash32 = [0xA2; 32];
/// Devnet emission recipient: treasury account (fixture).
pub const TREASURY_ACCOUNT: Hash32 = [0xA3; 32];
/// Devnet governance authority account (fixture).
pub const GOV_AUTHORITY_ACCOUNT: Hash32 = [0xB0; 32];
/// Devnet emergency authority account (fixture).
pub const EMERGENCY_AUTHORITY_ACCOUNT: Hash32 = [0xE0; 32];
/// Seed of the devnet fixture BLS proposer key (test networks only).
pub const DEVNET_PROPOSER_SEED: [u8; 32] = [0x47; 32];

/// The eight genesis controls, in manifest bit order (plan §6.8).
///
/// These are the params-tree key names under `noos.control.<name>`;
/// `noos-lumen::state::param_key` freezes full names at <= 32 bytes and
/// `CONTROL_PREFIX` is 13 bytes, so every name here MUST be <= 19 bytes
/// (enforced by `control_key_names_fit_frozen_param_law`). The long plan
/// aliases are recorded next to each entry.
pub const CONTROL_NAMES: [&str; 8] = [
    "work_loom_credit",    // work_loom_credit_enabled
    "work_loom_weightcap", // work_loom_weight_cap != 0
    "witness_proofpower",  // witness_proofpower_bonus_enabled
    "neural_lane",         // neural_lane_enabled
    "reflex_lane",         // reflex_lane_enabled
    "umbra_suite",         // umbra_suite_enabled (all suites)
    "dream_lane",          // dream_lane_enabled
    "class_gate_budget",   // class_gate_irreversible_budget != 0
];

// ---------------------------------------------------------------------------
// Parameters file
// ---------------------------------------------------------------------------

/// Parsed devnet parameter set. Field meanings mirror
/// `protocol/genesis/devnet-parameters.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevnetParams {
    pub schema_version: u32,
    pub chain_name: String,
    pub is_test_network: bool,
    pub token_decimals: u8,
    pub slot_seconds: u64,
    pub epoch_length: u64,
    pub max_slot_skip: u64,
    pub median_time_past_blocks: u64,
    pub witness_membership_lookback_epochs: u64,
    pub pulse_target_spacing_seconds: u64,
    pub pulse_half_life_seconds: u64,
    pub max_future_drift_ms: u64,
    pub n_max: u64,
    pub n_tail: u64,
    pub n_hard: u64,
    pub min_bond_micro: u128,
    pub min_bond_is_test_fixture: bool,
    pub faucet_enabled: bool,
    pub faucet_allocation_micro: u128,
    pub faucet_pubkey: Hash32,
    pub faucet_is_test_fixture: bool,
    pub faucet_per_request_micro: u128,
    pub faucet_cooldown_seconds: u64,
    pub dkg_participants: u32,
    pub dkg_threshold: u32,
    pub dkg_is_test_fixture: bool,
}

/// Strict mini-TOML reader for exactly the devnet parameter schema:
/// `[section]` headers plus `key = value` with bool / integer / string
/// values. Anything else is a typed [`NodeError::Config`].
fn parse_toml(text: &str) -> Result<std::collections::BTreeMap<String, String>, NodeError> {
    let mut section = String::new();
    let mut map = std::collections::BTreeMap::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = match raw.find('#') {
            // A '#' inside a quoted string does not occur in this schema;
            // the loader rejects values containing '#' below.
            Some(i) => &raw[..i],
            None => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            let name = name.strip_suffix(']').ok_or_else(|| {
                NodeError::Config(format!("line {}: bad section", lineno.saturating_add(1)))
            })?;
            section = name.trim().to_string();
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            NodeError::Config(format!(
                "line {}: expected key = value",
                lineno.saturating_add(1)
            ))
        })?;
        let key = key.trim();
        let mut value = value.trim().to_string();
        if value.starts_with('"') {
            value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .ok_or_else(|| {
                    NodeError::Config(format!("line {}: bad string", lineno.saturating_add(1)))
                })?
                .to_string();
        }
        if value.is_empty() || value.contains('#') {
            return Err(NodeError::Config(format!(
                "line {}: bad value",
                lineno.saturating_add(1)
            )));
        }
        let full = if section.is_empty() {
            key.to_string()
        } else {
            format!("{section}.{key}")
        };
        if map.insert(full.clone(), value).is_some() {
            return Err(NodeError::Config(format!("duplicate key {full}")));
        }
    }
    Ok(map)
}

fn req<'m>(
    map: &'m std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<&'m str, NodeError> {
    map.get(key)
        .map(String::as_str)
        .ok_or_else(|| NodeError::Config(format!("missing key {key}")))
}

fn req_u<T: TryFrom<u128>>(
    map: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<T, NodeError> {
    let raw = req(map, key)?;
    let parsed: u128 = raw
        .parse()
        .map_err(|_| NodeError::Config(format!("{key}: not an unsigned integer")))?;
    T::try_from(parsed).map_err(|_| NodeError::Config(format!("{key}: out of range")))
}

fn req_bool(
    map: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<bool, NodeError> {
    match req(map, key)? {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(NodeError::Config(format!("{key}: bad bool `{other}`"))),
    }
}

fn hex32(raw: &str, key: &str) -> Result<Hash32, NodeError> {
    let bytes = raw.as_bytes();
    if bytes.len() != 64 {
        return Err(NodeError::Config(format!("{key}: expected 64 hex chars")));
    }
    let mut out = [0_u8; 32];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| NodeError::Config(format!("{key}: bad hex")))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| NodeError::Config(format!("{key}: bad hex")))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

impl DevnetParams {
    /// Parses and validates the parameters file text.
    ///
    /// # Errors
    /// [`NodeError::Config`] on any malformed, missing, or
    /// constant-contradicting entry, and on any test fixture present while
    /// `is_test_network = false` (the fixture-refusal law, plan §2.5).
    pub fn parse(text: &str) -> Result<Self, NodeError> {
        let map = parse_toml(text)?;
        let params = DevnetParams {
            schema_version: req_u(&map, "schema_version")?,
            chain_name: req(&map, "chain_name")?.to_string(),
            is_test_network: req_bool(&map, "is_test_network")?,
            token_decimals: req_u(&map, "token.decimals")?,
            slot_seconds: req_u(&map, "consensus.slot_seconds")?,
            epoch_length: req_u(&map, "consensus.epoch_length")?,
            max_slot_skip: req_u(&map, "consensus.max_slot_skip")?,
            median_time_past_blocks: req_u(&map, "consensus.median_time_past_blocks")?,
            witness_membership_lookback_epochs: req_u(
                &map,
                "consensus.witness_membership_lookback_epochs",
            )?,
            pulse_target_spacing_seconds: req_u(&map, "consensus.pulse_target_spacing_seconds")?,
            pulse_half_life_seconds: req_u(&map, "consensus.pulse_half_life_seconds")?,
            max_future_drift_ms: req_u(&map, "consensus.max_future_drift_ms")?,
            n_max: req_u(&map, "witness_ring.n_max")?,
            n_tail: req_u(&map, "witness_ring.n_tail")?,
            n_hard: req_u(&map, "witness_ring.n_hard")?,
            min_bond_micro: req_u(&map, "witness_ring.min_bond_micro_noos_test")?,
            min_bond_is_test_fixture: req_bool(&map, "witness_ring.min_bond_is_test_fixture")?,
            faucet_enabled: req_bool(&map, "faucet.enabled")?,
            faucet_allocation_micro: req_u(&map, "faucet.allocation_micro_noos_test")?,
            faucet_pubkey: hex32(
                req(&map, "faucet.account_pubkey_ed25519_hex")?,
                "faucet.account_pubkey_ed25519_hex",
            )?,
            faucet_is_test_fixture: req_bool(&map, "faucet.is_test_fixture")?,
            faucet_per_request_micro: req_u(&map, "faucet.per_request_micro_noos_test")?,
            faucet_cooldown_seconds: req_u(&map, "faucet.cooldown_seconds")?,
            dkg_participants: req_u(&map, "dkg.participants")?,
            dkg_threshold: req_u(&map, "dkg.threshold")?,
            dkg_is_test_fixture: req_bool(&map, "dkg.is_test_fixture")?,
        };
        params.validate(&map)?;
        Ok(params)
    }

    fn validate(&self, map: &std::collections::BTreeMap<String, String>) -> Result<(), NodeError> {
        // The six genesis controls: ALL radical controls must be off.
        for (key, expect) in [
            ("controls.work_loom_credit_enabled", "false"),
            ("controls.work_loom_weight_cap", "0"),
            ("controls.witness_proofpower_bonus_enabled", "false"),
            ("controls.neural_lane_enabled", "false"),
            ("controls.reflex_lane_enabled", "false"),
            ("controls.umbra_suite_enabled", "false"),
            ("controls.dream_lane_enabled", "false"),
            ("controls.class_gate_irreversible_budget", "0"),
        ] {
            if req(map, key)? != expect {
                return Err(NodeError::Config(format!(
                    "{key} must be {expect} at genesis (plan §6.8)"
                )));
            }
        }
        // The file is checked against the compile-frozen constants, never
        // trusted to redefine them.
        let frozen: [(&str, u64); 8] = [
            ("consensus.slot_seconds", noos_ground::SLOT_MS / 1000),
            ("consensus.epoch_length", noos_braid::EPOCH_LENGTH),
            ("consensus.max_slot_skip", noos_ground::MAX_SLOT_SKIP),
            (
                "consensus.median_time_past_blocks",
                noos_ground::MEDIAN_TIME_PAST_BLOCKS as u64,
            ),
            ("consensus.witness_membership_lookback_epochs", 2),
            (
                "consensus.pulse_target_spacing_seconds",
                noos_ground::TARGET_SPACING_SECONDS,
            ),
            (
                "consensus.pulse_half_life_seconds",
                noos_ground::HALF_LIFE_SECONDS,
            ),
            (
                "consensus.max_future_drift_ms",
                noos_ground::DEVNET_MAX_FUTURE_DRIFT_MS,
            ),
        ];
        for (key, expect) in frozen {
            let got: u64 = req_u(map, key)?;
            if got != expect {
                return Err(NodeError::Config(format!(
                    "{key} = {got} contradicts the frozen constant {expect}"
                )));
            }
        }
        if (self.n_max, self.n_tail, self.n_hard)
            != (
                noos_witness::N_MAX as u64,
                noos_witness::N_TAIL as u64,
                noos_witness::N_HARD as u64,
            )
        {
            return Err(NodeError::Config(
                "witness_ring caps contradict frozen constants".into(),
            ));
        }
        if self.token_decimals != 6 {
            return Err(NodeError::Config("token.decimals must be 6".into()));
        }
        if self.chain_name.is_empty() || self.chain_name.as_bytes().len() > 64 {
            return Err(NodeError::Config(
                "chain_name must contain 1..=64 UTF-8 bytes".into(),
            ));
        }
        // Fixture-refusal law: nodes MUST refuse is_test_fixture material
        // on a network where is_test_network = false.
        if !self.is_test_network
            && (self.min_bond_is_test_fixture
                || self.faucet_is_test_fixture
                || self.dkg_is_test_fixture)
        {
            return Err(NodeError::Config(
                "is_test_fixture material refused: is_test_network = false".into(),
            ));
        }
        // This runtime implements engineering networks only; mainnet
        // economics are OWNER_BLOCKED (plan §2.5).
        if !self.is_test_network {
            return Err(NodeError::Config(
                "mainnet genesis is OWNER_BLOCKED; only is_test_network = true loads".into(),
            ));
        }
        Ok(())
    }

    /// Loads and parses a parameters file from disk.
    pub fn load(path: &std::path::Path) -> Result<Self, NodeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("read {}: {e}", path.display())))?;
        Self::parse(&text)
    }
}

// ---------------------------------------------------------------------------
// Canonical manifest and identity derivation
// ---------------------------------------------------------------------------

define_object! {
    /// Canonical fixed-width genesis parameter manifest (identity-v1.md §4).
    /// Explicitly EXCLUDES the Bitcoin anchor, the DKG transcript, and every
    /// derived hash. Controls are bit-packed in [`CONTROL_NAMES`] order and
    /// are all zero at genesis (checked by the loader).
    pub struct GenesisParameterManifestV1 {
        version: 1;
        1 => schema_version: u32,
        2 => chain_name: BoundedBytes<64>,
        3 => is_test_network: u8,
        4 => token_decimals: u8,
        5 => slot_seconds: u64,
        6 => epoch_length: u64,
        7 => max_slot_skip: u64,
        8 => median_time_past_blocks: u64,
        9 => witness_membership_lookback_epochs: u64,
        10 => pulse_target_spacing_seconds: u64,
        11 => pulse_half_life_seconds: u64,
        12 => max_future_drift_ms: u64,
        13 => n_max: u64,
        14 => n_tail: u64,
        15 => n_hard: u64,
        16 => min_bond_micro: u128,
        17 => controls_bits: u32,
        18 => faucet_enabled: u8,
        19 => faucet_allocation_micro: u128,
        20 => faucet_pubkey: [u8; 32],
        21 => faucet_per_request_micro: u128,
        22 => faucet_cooldown_seconds: u64,
        23 => dkg_participants: u32,
        24 => dkg_threshold: u32,
    }
}

define_object! {
    /// Canonical devnet final genesis body: binds the manifest hash, the two
    /// post-freeze scalars, the complete account allocation commitment, and
    /// every Lumen state root. The Bitcoin anchor and DKG root enter the
    /// `genesis_hash` preimage beside it, never inside it.
    pub struct FinalGenesisBodyV1 {
        version: 1;
        1 => manifest_hash: [u8; 32],
        2 => genesis_time_ms: u64,
        3 => initial_ground_target: [u8; 32],
        4 => allocation_root: [u8; 32],
        5 => notes_root: [u8; 32],
        6 => nullifiers_root: [u8; 32],
        7 => accounts_root: [u8; 32],
        8 => objects_root: [u8; 32],
        9 => receipts_root: [u8; 32],
        10 => params_root: [u8; 32],
    }
}

/// Everything needed to boot a network deterministically.
#[derive(Debug, Clone)]
pub struct GenesisSpec {
    pub params: DevnetParams,
    /// Genesis wall-clock origin, milliseconds (devnet fixture input).
    pub genesis_time_ms: u64,
    /// Initial Ground target, little-endian (devnet: `T_MAX` = trivial).
    pub initial_ground_target: U256,
    /// Extra fixture accounts installed at genesis: `(account_id, balance)`
    /// where the account id IS the Ed25519 public key bytes and the
    /// auth_descriptor is the same bytes (the node's suite-1 verifier law).
    /// Lumen v1 has no account-creation action (lumen-v1.md §6: deposit
    /// targets must already exist), so engineering networks pre-provision
    /// their operator accounts here. REFUSED unless `is_test_network = true`
    /// (plan §2.5); mainnet allocations are OWNER_BLOCKED by design.
    pub extra_accounts: Vec<(Hash32, u128)>,
}

/// A fully derived genesis: identity, ledger, and the genesis block.
pub struct BuiltGenesis {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub ledger: LumenLedger,
    pub header: BlockHeaderV1,
    pub body: BlockBodyV1,
    pub ticket: GroundTicketV1,
    /// Canonical body bytes (the DA-encoded content).
    pub body_bytes: Vec<u8>,
}

impl GenesisSpec {
    /// Devnet spec over the frozen parameters file with a fixed time origin.
    pub fn devnet(params: DevnetParams, genesis_time_ms: u64) -> Self {
        GenesisSpec {
            params,
            genesis_time_ms,
            initial_ground_target: U256::MAX,
            extra_accounts: Vec::new(),
        }
    }

    pub fn manifest(&self) -> Result<GenesisParameterManifestV1, NodeError> {
        let p = &self.params;
        let chain_name = BoundedBytes::new(p.chain_name.as_bytes().to_vec()).ok_or_else(|| {
            NodeError::Config("chain_name must contain at most 64 UTF-8 bytes".into())
        })?;
        Ok(GenesisParameterManifestV1 {
            schema_version: p.schema_version,
            chain_name,
            is_test_network: u8::from(p.is_test_network),
            token_decimals: p.token_decimals,
            slot_seconds: p.slot_seconds,
            epoch_length: p.epoch_length,
            max_slot_skip: p.max_slot_skip,
            median_time_past_blocks: p.median_time_past_blocks,
            witness_membership_lookback_epochs: p.witness_membership_lookback_epochs,
            pulse_target_spacing_seconds: p.pulse_target_spacing_seconds,
            pulse_half_life_seconds: p.pulse_half_life_seconds,
            max_future_drift_ms: p.max_future_drift_ms,
            n_max: p.n_max,
            n_tail: p.n_tail,
            n_hard: p.n_hard,
            min_bond_micro: p.min_bond_micro,
            controls_bits: 0, // all radical controls off at genesis
            faucet_enabled: u8::from(p.faucet_enabled),
            faucet_allocation_micro: p.faucet_allocation_micro,
            faucet_pubkey: p.faucet_pubkey,
            faucet_per_request_micro: p.faucet_per_request_micro,
            faucet_cooldown_seconds: p.faucet_cooldown_seconds,
            dkg_participants: p.dkg_participants,
            dkg_threshold: p.dkg_threshold,
        })
    }

    /// `chain_id = H(D-CHAIN-ID || H(D-GENESIS-PARAMS || canonical manifest))`.
    pub fn chain_id(&self) -> Result<Hash32, NodeError> {
        let manifest_hash = hash_domain(
            DomainId::GenesisParams,
            &[&self.manifest()?.encode_canonical()],
        )
        .map_err(|_| NodeError::Crypto)?;
        Ok(hash_domain(DomainId::ChainId, &[manifest_hash.as_bytes()])
            .map_err(|_| NodeError::Crypto)?
            .into_bytes())
    }

    /// Devnet fixture DKG root under the registered `D-DKG-TRANSCRIPT`
    /// domain (a deterministic local stand-in for the multi-party
    /// ceremony; excluded from mainnet by the fixture-refusal law).
    pub fn dkg_root(&self) -> Result<Hash32, NodeError> {
        Ok(hash_domain(
            DomainId::DkgTranscript,
            &[
                b"noos-devnet/dkg-fixture/v1",
                &self.params.dkg_participants.to_le_bytes(),
                &self.params.dkg_threshold.to_le_bytes(),
            ],
        )
        .map_err(|_| NodeError::Crypto)?
        .into_bytes())
    }

    /// `genesis_hash = H(D-GENESIS-FINAL || chain_id || bitcoin_anchor ||
    /// dkg_root || canonical(FinalGenesisBodyV1))`; the devnet Bitcoin
    /// anchor is the zero hash (test network, identity-v1.md §4).
    pub fn genesis_hash(&self) -> Result<Hash32, NodeError> {
        let ledger = self.build_ledger()?;
        self.genesis_hash_for_ledger(&ledger)
    }

    fn genesis_hash_for_ledger(&self, ledger: &LumenLedger) -> Result<Hash32, NodeError> {
        let chain_id = self.chain_id()?;
        let manifest_hash = hash_domain(
            DomainId::GenesisParams,
            &[&self.manifest()?.encode_canonical()],
        )
        .map_err(|_| NodeError::Crypto)?;
        let roots = ledger.roots();
        let body = FinalGenesisBodyV1 {
            manifest_hash: *manifest_hash.as_bytes(),
            genesis_time_ms: self.genesis_time_ms,
            initial_ground_target: self.initial_ground_target.to_le_bytes(),
            allocation_root: self.allocation_root()?,
            notes_root: roots.notes_root,
            nullifiers_root: roots.nullifiers_root,
            accounts_root: roots.accounts_root,
            objects_root: roots.objects_root,
            receipts_root: roots.receipts_root,
            params_root: roots.params_root,
        };
        let bitcoin_anchor = [0_u8; 32];
        Ok(hash_domain(
            DomainId::GenesisFinal,
            &[
                &chain_id,
                &bitcoin_anchor,
                &self.dkg_root()?,
                &body.encode_canonical(),
            ],
        )
        .map_err(|_| NodeError::Crypto)?
        .into_bytes())
    }

    fn fixture_account(id: Hash32, auth: &[u8]) -> AccountV1 {
        AccountV1 {
            account_id: id,
            auth_descriptor: noos_lumen::objects::BoundedBytes::new(auth.to_vec())
                .unwrap_or_default(),
            nonce: 0,
            liquid_balances_root: noos_lumen::smt::empty_root(noos_lumen::smt::DEPTH),
            bond_refs_root: [0; 32],
            metadata_commitment: [0; 32],
            recovery_policy_root: [0; 32],
        }
    }

    fn canonical_accounts(&self) -> Result<Vec<(AccountV1, Vec<(Hash32, u128)>)>, NodeError> {
        if !self.extra_accounts.is_empty() && !self.params.is_test_network {
            return Err(NodeError::Config(
                "extra fixture accounts are a test-network-only mechanism \
                 (is_test_network = false)"
                    .into(),
            ));
        }
        let faucet = Self::fixture_account(self.params.faucet_pubkey, &self.params.faucet_pubkey);
        let mut accounts = vec![
            (
                faucet,
                vec![(NOOS_ASSET, self.params.faucet_allocation_micro)],
            ),
            (Self::fixture_account(PROPOSER_POOL_ACCOUNT, &[]), vec![]),
            (Self::fixture_account(WITNESS_POOL_ACCOUNT, &[]), vec![]),
            (Self::fixture_account(TREASURY_ACCOUNT, &[]), vec![]),
            (Self::fixture_account(GOV_AUTHORITY_ACCOUNT, &[]), vec![]),
            (
                Self::fixture_account(EMERGENCY_AUTHORITY_ACCOUNT, &[]),
                vec![],
            ),
        ];
        for (id, balance) in &self.extra_accounts {
            let balances = if *balance > 0 {
                vec![(NOOS_ASSET, *balance)]
            } else {
                vec![]
            };
            accounts.push((Self::fixture_account(*id, id), balances));
        }
        accounts.sort_by_key(|(account, _)| account.account_id);
        if accounts
            .windows(2)
            .any(|pair| pair[0].0.account_id == pair[1].0.account_id)
        {
            return Err(NodeError::Config(
                "genesis accounts must have unique canonical account IDs".into(),
            ));
        }
        Ok(accounts)
    }

    /// Canonical allocation commitment: sorted account id followed by its
    /// checked NOOS balance. Zero-balance fixture accounts are included so
    /// the commitment describes the complete accepted account set.
    fn allocation_root(&self) -> Result<Hash32, NodeError> {
        let accounts = self.canonical_accounts()?;
        let count = u32::try_from(accounts.len())
            .map_err(|_| NodeError::Config("too many genesis accounts".into()))?;
        let capacity = accounts
            .len()
            .checked_mul(48)
            .and_then(|n| n.checked_add(4))
            .ok_or_else(|| NodeError::Config("genesis allocation encoding overflow".into()))?;
        let mut canonical = Vec::with_capacity(capacity);
        canonical.extend_from_slice(&count.to_le_bytes());
        for (account, balances) in accounts {
            canonical.extend_from_slice(&account.account_id);
            let amount = balances
                .iter()
                .find_map(|(asset, amount)| (*asset == NOOS_ASSET).then_some(*amount))
                .unwrap_or(0);
            canonical.extend_from_slice(&amount.to_le_bytes());
        }
        Ok(*blake3::hash(&canonical).as_bytes())
    }

    /// Installs the genesis ledger: NOOS_TEST fee/issuance fixtures, the
    /// faucet account (id = fixture Ed25519 pubkey bytes; auth_descriptor =
    /// the same pubkey, verified by the node's Ed25519 suite), fixture
    /// authority and emission-recipient accounts, and the disabled-control
    /// records.
    pub fn build_ledger(&self) -> Result<LumenLedger, NodeError> {
        let mut ledger = LumenLedger::new();
        let accounts = self.canonical_accounts()?;
        let controls: Vec<(&str, bool)> = CONTROL_NAMES.iter().map(|n| (*n, false)).collect();
        ledger
            .install_genesis(&GenesisConfig {
                fee_params: FeeParamsV1::testnet_fixture(),
                fee_state: FeeStateV1::testnet_fixture(),
                issuance: IssuanceParamsV1::testnet_fixture(),
                shares: EmissionSharesV1::testnet_fixture(),
                controls: &controls,
                accounts: &accounts,
                gov_authority: GOV_AUTHORITY_ACCOUNT,
                emergency_authority: EMERGENCY_AUTHORITY_ACCOUNT,
            })
            .map_err(|error| NodeError::Config(format!("invalid genesis ledger: {error:?}")))?;
        Ok(ledger)
    }

    /// Builds the complete genesis: ledger, header, body, mined ticket.
    ///
    /// # Errors
    /// [`NodeError::Config`] on fixture-law violations; [`NodeError::Crypto`]
    /// only on registry misuse (build defect).
    pub fn build(&self) -> Result<BuiltGenesis, NodeError> {
        let chain_id = self.chain_id()?;
        let ledger = self.build_ledger()?;
        let genesis_hash = self.genesis_hash_for_ledger(&ledger)?;
        let roots = ledger.roots();

        let proposer_secret =
            BlsSecretKey::from_seed(DEVNET_PROPOSER_SEED).map_err(|_| NodeError::Crypto)?;
        let proposer_key = Bytes48(proposer_secret.public_key().into_bytes());
        let fee_prices = FeeStateV1::testnet_fixture().prices();
        let price = |value: u128| {
            u64::try_from(value)
                .map_err(|_| NodeError::Config("genesis fee price exceeds u64".into()))
        };

        // Genesis body: no transactions, no certificates. The ticket starts
        // as the canonical zero placeholder (roots::zero_ticket) so the DA
        // form is ticket-independent (ch01 §4.3 fixes the commitment before
        // search; node-v1.md §3.2).
        let placeholder_ticket = crate::roots::zero_ticket();
        let mut body = BlockBodyV1 {
            transactions: BoundedList::new(vec![]).unwrap_or_default(),
            segregated_witnesses: BoundedList::new(vec![]).unwrap_or_default(),
            system_transitions: BoundedList::new(vec![]).unwrap_or_default(),
            finality_certificates: BoundedList::new(vec![]).unwrap_or_default(),
            ground_ticket: GroundTicketWire(placeholder_ticket),
            loom_credit_claims: BoundedList::new(vec![]).unwrap_or_default(),
            consensus_blob_descriptors: BoundedList::new(vec![]).unwrap_or_default(),
        };

        let mut header = BlockHeaderV1 {
            chain_id,
            height: 0,
            slot: 0,
            timestamp_ms: self.genesis_time_ms,
            parent_hash: ZERO_ROOT,
            proposer_key,
            tx_root: body_tx_root(&body.transactions)?,
            witness_root: body_witness_root(&body.segregated_witnesses)?,
            execution_receipt_root: body_receipt_root(&[])?,
            evidence_root: ZERO_ROOT,
            body_da_root: ZERO_ROOT, // set from the DA form before mining
            notes_root: roots.notes_root,
            nullifiers_root: roots.nullifiers_root,
            accounts_root: roots.accounts_root,
            objects_root: roots.objects_root,
            lumen_receipts_state_root: roots.receipts_root,
            params_root: roots.params_root,
            justified_checkpoint: CheckpointRef::default(),
            finalized_checkpoint: CheckpointRef::default(),
            finality_certificate_root: body_cert_root(&body.finality_certificates)?,
            witness_membership_root: ZERO_ROOT,
            ground_profile_id: GROUND_PROFILE_ID_V1,
            ground_target: self.initial_ground_target.to_le_bytes(),
            ground_ticket_root: ZERO_ROOT, // patched after mining
            loom_credit_root: ZERO_ROOT,
            loom_credit: 0,
            gas_used: ResourceVectorV1::default(),
            base_prices: {
                ResourcePriceVectorV1 {
                    p_bytes: price(fee_prices[0])?,
                    p_grain_steps: price(fee_prices[1])?,
                    p_proof_units: price(fee_prices[2])?,
                    p_state_word_epochs: price(fee_prices[3])?,
                    p_blob_bytes: price(fee_prices[4])?,
                }
            },
            proposer_signature: Bytes96([0; 96]),
        };

        // The DA commitment covers the ticket-independent DA form and is
        // therefore fixed BEFORE the nonce search (ch01 §4.3 step 5-6).
        let da_bytes = crate::roots::da_form_bytes(&body);
        let encoded = noos_da::encode_body(&da_bytes)?;
        header.body_da_root = encoded.shard_root().into_bytes();

        // Mine the genesis ticket against the header's own proposal
        // commitment (parent = zero hash, parent target = the initial
        // target). Trivial at T_MAX.
        let commitment = header
            .proposal_commitment()
            .map_err(|_| NodeError::Crypto)?;
        let ticket = mine_ticket(
            &chain_id,
            &ZERO_ROOT,
            &self.initial_ground_target,
            0,
            &commitment,
            &proposer_key.0,
            &self.initial_ground_target,
        )?;
        header.ground_ticket_root = body_ticket_root(&ticket)?;
        body.ground_ticket = GroundTicketWire(ticket);

        // Served body bytes: the real ticket travels here; DA bytes stay
        // derivable through roots::da_form_bytes.
        let body_bytes = body.encode_canonical();

        // Devnet proposer signature: BLS over the proposal commitment under
        // the registered D-BLS-PROPOSER DST.
        let sig = proposer_secret
            .sign_domain(DomainId::BlsProposer, commitment.as_bytes())
            .map_err(|_| NodeError::Crypto)?;
        header.proposer_signature = Bytes96(sig.into_bytes());

        // The genesis hash commits to the parameter identity, not the block
        // hash; both are bound into the store identity by the caller.
        Ok(BuiltGenesis {
            chain_id,
            genesis_hash,
            ledger,
            header,
            body,
            ticket,
            body_bytes,
        })
    }
}

/// Deterministic ticket search: ascending nonce under an extra nonce
/// derived from the per-block challenge (which binds parent, slot, and
/// proposal commitment), so the `(proposer, nonce, extra_nonce)` tuple is
/// unique per block and never trips the ch01 §4.2 rule-8 duplicate scan
/// even at the trivial devnet target. Devnet targets are trivial, so the
/// search terminates immediately; a real Ground worker replaces this loop.
pub fn mine_ticket(
    chain_id: &Hash32,
    parent_hash: &Hash32,
    parent_ground_target: &U256,
    slot: u64,
    proposal_commitment: &noos_crypto::Hash32,
    proposer_pubkey: &[u8; 48],
    target: &U256,
) -> Result<GroundTicketV1, NodeError> {
    let chain = noos_crypto::Hash32::from_bytes(*chain_id);
    let parent = noos_crypto::Hash32::from_bytes(*parent_hash);
    let challenge = ground_challenge(&ChallengeInputs {
        chain_id: &chain,
        parent_hash: &parent,
        parent_ground_target,
        slot,
        proposal_commitment,
        proposer_pubkey,
    })
    .map_err(|_| NodeError::Crypto)?;
    let extra_nonce = *challenge.as_bytes();
    let mut nonce: u64 = 0;
    loop {
        let digest =
            ground_digest(&challenge, nonce, &extra_nonce).map_err(|_| NodeError::Crypto)?;
        if &U256::from_le_bytes(digest.as_bytes()) < target {
            return Ok(GroundTicketV1 {
                profile_id: GROUND_PROFILE_ID_V1,
                nonce,
                extra_nonce,
                digest,
            });
        }
        nonce = nonce.checked_add(1).ok_or(NodeError::BodyMismatch {
            what: "nonce space exhausted",
        })?;
    }
}

#[cfg(test)]
mod production_proposal_refusal_tests {
    use super::{DevnetParams, GenesisSpec};

    const DEVNET: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/genesis/devnet-parameters.toml"
    ));

    /// The only node parameter loader is deliberately devnet-only. Keep an
    /// executable regression proving that a filled-but-unsigned owner proposal
    /// cannot become production configuration merely because its economics are
    /// numerically complete.
    #[test]
    fn unsigned_owner_proposal_is_refused_by_node_loader() {
        let proposal = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/genesis/mainnet-parameters.proposal.toml"
        ));
        assert!(
            DevnetParams::parse(proposal).is_err(),
            "an unsigned owner proposal must never load as node parameters"
        );
    }

    #[test]
    fn chain_names_are_bounded_and_distinct_names_are_distinct_chains() {
        let overlong = DEVNET.replace("noos-devnet-1", &"x".repeat(65));
        assert!(DevnetParams::parse(&overlong).is_err());

        let first = GenesisSpec::devnet(DevnetParams::parse(DEVNET).unwrap(), 1_760_000_000_000);
        let renamed = DEVNET.replace("noos-devnet-1", "noos-devnet-2");
        let second = GenesisSpec::devnet(DevnetParams::parse(&renamed).unwrap(), 1_760_000_000_000);
        assert_ne!(first.chain_id().unwrap(), second.chain_id().unwrap());
        assert_ne!(
            first.genesis_hash().unwrap(),
            second.genesis_hash().unwrap()
        );
    }

    #[test]
    fn extra_account_set_is_canonical_and_bound_to_genesis_identity() {
        let params = DevnetParams::parse(DEVNET).unwrap();
        let mut first = GenesisSpec::devnet(params.clone(), 1_760_000_000_000);
        first.extra_accounts = vec![([0x71; 32], 7), ([0x72; 32], 8)];
        let mut reordered = GenesisSpec::devnet(params.clone(), 1_760_000_000_000);
        reordered.extra_accounts = vec![([0x72; 32], 8), ([0x71; 32], 7)];
        let mut changed = GenesisSpec::devnet(params, 1_760_000_000_000);
        changed.extra_accounts = vec![([0x71; 32], 7), ([0x72; 32], 9)];

        let first_built = first.build().unwrap();
        let reordered_built = reordered.build().unwrap();
        let changed_built = changed.build().unwrap();
        assert_eq!(first_built.chain_id, changed_built.chain_id);
        assert_eq!(first_built.genesis_hash, reordered_built.genesis_hash);
        assert_eq!(first_built.ledger.roots(), reordered_built.ledger.roots());
        assert_ne!(first_built.genesis_hash, changed_built.genesis_hash);
        assert_ne!(first_built.ledger.roots(), changed_built.ledger.roots());

        let mut duplicate = first;
        duplicate.extra_accounts.push(([0x71; 32], 10));
        assert!(duplicate.build().is_err());
    }

    #[test]
    fn devnet_identity_vector_is_stable_after_state_binding() {
        let spec = GenesisSpec::devnet(DevnetParams::parse(DEVNET).unwrap(), 1_760_000_000_000);
        let built = spec.build().unwrap();
        assert_eq!(
            super::hex32_for_test(built.chain_id),
            "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b"
        );
        assert_eq!(
            super::hex32_for_test(built.genesis_hash),
            "989340dfa04e2285d9e038dc45c87d56bb3d65ad96dac3d3411d1cf34a9c3214"
        );
    }
}

#[cfg(test)]
fn hex32_for_test(value: Hash32) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
