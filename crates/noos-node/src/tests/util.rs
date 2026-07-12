//! Shared test fixtures: devnet spec, funded genesis, in-proc stores,
//! simulated witness sets, and signed transfer transactions.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use noos_braid::{CheckpointRef, FinalityCertificateV1};
use noos_codec::NoosEncode;
use noos_crypto::{BlsSecretKey, DomainId, Keypair};
use noos_lumen::objects::{
    txid, witness_root, AccessEntry, ActionV1, BoundedBytes, BoundedList, NoteV1, OptionalHash32,
    OptionalObject, ResourceVector, SignedIntentV1, TransactionV1, TransactionWitnessesV1,
};
use noos_witness::bond::WitnessBondV1;
use noos_witness::membership::MembershipSnapshotV1;
use noos_witness::vote::FinalityVoteV1;

use crate::consensus::{NodeConfig, NodeCore, DEVNET_BEACON_RANDOMNESS};
use crate::genesis::{DevnetParams, GenesisSpec};
use crate::metrics::Metrics;
use crate::store_port::InProcStore;
use crate::Hash32;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// Fresh per-test data directory under the platform tmp root.
pub fn test_dir(tag: &str) -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("noos-node-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create test dir");
    p
}

/// Devnet genesis time fixture.
pub const GENESIS_TIME_MS: u64 = 1_760_000_000_000;

/// Parsed frozen devnet parameters, with the faucet public key overridden
/// to a SPENDABLE test keypair (the file fixture pins only the public
/// half; tests need the secret to sign transfers).
pub fn devnet_params() -> DevnetParams {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/genesis/devnet-parameters.toml");
    let mut params = DevnetParams::load(&path).expect("devnet parameters parse");
    params.faucet_pubkey = faucet_key().public_key().into_bytes();
    params
}

/// Devnet spec with operator fixture accounts 1..=4 pre-provisioned
/// (lumen v1 deposit targets must exist; genesis is the only creator).
pub fn spec() -> GenesisSpec {
    let mut s = GenesisSpec::devnet(devnet_params(), GENESIS_TIME_MS);
    s.extra_accounts = (1..=4).map(|i| (operator_account(i), 0)).collect();
    s
}

/// Spendable faucet fixture keypair (test networks only).
pub fn faucet_key() -> Keypair {
    Keypair::from_seed([0xFA; 32])
}

/// Deterministic operator keypair `i` (Ed25519, suite 1).
pub fn operator_key(i: u8) -> Keypair {
    Keypair::from_seed([0x30_u8.wrapping_add(i); 32])
}

/// Account id for operator `i`: its raw public key bytes.
pub fn operator_account(i: u8) -> Hash32 {
    operator_key(i).public_key().into_bytes()
}

/// Witness fixture: `n` bonds above the devnet minimum, real BLS keys
/// (the shared `devnet_fixture` module — same set `noosd --validator` runs).
pub fn witness_bonds(n: usize) -> Vec<WitnessBondV1> {
    crate::devnet_fixture::fixture_witness_bonds(n).expect("fixture bonds")
}

pub fn witness_secret(i: usize) -> BlsSecretKey {
    crate::devnet_fixture::fixture_witness_secret(i).expect("bls seed")
}

/// Node config with a 4-member simulated witness set.
pub fn node_config() -> NodeConfig {
    let mut cfg = NodeConfig {
        witness_bonds: witness_bonds(4),
        min_bond: devnet_params().min_bond_micro,
        ..NodeConfig::default()
    };
    // In-process consensus/RPC tests do not need live sockets. The focused
    // network tests explicitly re-enable this fixture field.
    cfg.network.enabled = false;
    cfg
}

/// Boots a fresh full node over a (new or existing) store in `dir`.
pub fn boot_node(dir: &std::path::Path, cfg: NodeConfig) -> NodeCore<InProcStore> {
    let mut spec = spec();
    spec.contract_codes = cfg.contract_codes.clone();
    let built = spec.build().expect("genesis build");
    let port = InProcStore::open(dir.to_path_buf(), &built.chain_id, &built.genesis_hash)
        .expect("store open");
    NodeCore::boot(cfg, &spec, built, port, Arc::new(Metrics::default())).expect("node boot")
}

/// Quorum certificate over the node's witness fixture for
/// `source -> target`, signed by the first three members (raw weight
/// 3/4 >= floor(2W/3)+1).
pub fn quorum_certificate(
    core: &mut NodeCore<InProcStore>,
    source: CheckpointRef,
    target: CheckpointRef,
) -> FinalityCertificateV1 {
    core.ensure_snapshot(target.epoch).expect("snapshot");
    let snapshot = snapshot_for(target.epoch);
    let chain = core.chain_id();
    let votes: Vec<FinalityVoteV1> = (0..3)
        .map(|i| {
            let vid = snapshot.members()[i].validator_id;
            let idx = (vid[0] as usize) - 1; // validator_id = [i+1; 32]
            FinalityVoteV1::sign(
                chain,
                target.epoch,
                source,
                target,
                vid,
                snapshot.root(),
                &witness_secret(idx),
            )
            .expect("vote sign")
        })
        .collect();
    noos_witness::finality::build_certificate(&votes, &chain, &snapshot).expect("certificate")
}

/// The snapshot the node builds for `epoch` (same inputs, same output).
pub fn snapshot_for(epoch: u64) -> MembershipSnapshotV1 {
    match noos_witness::membership::build_snapshot(
        epoch,
        &witness_bonds(4),
        &DEVNET_BEACON_RANDOMNESS,
        devnet_params().min_bond_micro,
        None,
        false,
    )
    .expect("snapshot build")
    {
        noos_witness::membership::SnapshotOutcome::Normal(s) => s,
        other => panic!("expected normal snapshot, got {other:?}"),
    }
}

/// Signed transfer: `from` (account id = signer pubkey) withdraws
/// `amount` and deposits it to `to`. Returns `(tx_bytes, wit_bytes, txid)`.
pub fn signed_transfer(
    chain_id: Hash32,
    expiry_height: u64,
    from_key: &Keypair,
    to: Hash32,
    amount: u128,
) -> (Vec<u8>, Vec<u8>, Hash32) {
    let from = from_key.public_key().into_bytes();
    let actions = vec![
        ActionV1::WithdrawFromAccount {
            account_id: from,
            asset_id: noos_lumen::state::NOOS_ASSET,
            amount,
        },
        ActionV1::DepositToAccount {
            account_id: to,
            asset_id: noos_lumen::state::NOOS_ASSET,
            amount,
        },
    ];
    build_signed_tx(chain_id, expiry_height, from_key, actions, vec![])
}

/// Default declared resource envelope for fixture transactions.
pub fn default_limits() -> ResourceVector {
    ResourceVector {
        bytes: 65_536,
        grain_steps: 10_000,
        proof_units: 8,
        state_reads: 64,
        state_writes: 64,
        blob_bytes: 0,
    }
}

/// Assembles + signs a transaction whose only signer is `key` (also the
/// fee payer). One intent, no note inputs.
pub fn build_signed_tx(
    chain_id: Hash32,
    expiry_height: u64,
    key: &Keypair,
    actions: Vec<ActionV1>,
    outputs: Vec<NoteV1>,
) -> (Vec<u8>, Vec<u8>, Hash32) {
    build_signed_tx_full(
        chain_id,
        expiry_height,
        key,
        actions,
        outputs,
        vec![],
        default_limits(),
    )
}

/// Full-control builder: explicit declared object access list and resource
/// limits (contract-call tests exercise both envelopes).
pub fn build_signed_tx_full(
    chain_id: Hash32,
    expiry_height: u64,
    key: &Keypair,
    actions: Vec<ActionV1>,
    outputs: Vec<NoteV1>,
    object_access: Vec<AccessEntry>,
    resource_limits: ResourceVector,
) -> (Vec<u8>, Vec<u8>, Hash32) {
    let signer = key.public_key().into_bytes();
    let action_bytes: Vec<BoundedBytes<65536>> = actions
        .iter()
        .map(|a| BoundedBytes::new(a.encode_canonical()).unwrap())
        .collect();
    let lock_reveals = BoundedList::new(vec![]).unwrap();
    let tx = TransactionV1 {
        chain_id,
        format_version: 1,
        expiry_height,
        fee_payer: signer,
        fee_authorization: OptionalObject(None),
        resource_limits,
        note_inputs: BoundedList::new(vec![]).unwrap(),
        account_inputs: BoundedList::new(vec![signer]).unwrap(),
        object_access_list: BoundedList::new(object_access).unwrap(),
        actions: BoundedList::new(action_bytes).unwrap(),
        outputs: BoundedList::new(outputs).unwrap(),
        evidence_refs: BoundedList::new(vec![]).unwrap(),
        witness_root: witness_root(&lock_reveals),
    };
    let id = txid(&tx);
    let signature = key.sign_domain(DomainId::SigTx, &[&id]).expect("sign tx");
    let intents = vec![SignedIntentV1 {
        tx_commitment: id,
        signer_scope: 0,
        capability_ref: OptionalHash32(None),
        signature_suite: 1,
        signature: BoundedBytes::new(signature.into_bytes().to_vec()).unwrap(),
    }];
    let witnesses = TransactionWitnessesV1 {
        intents: BoundedList::new(intents).unwrap(),
        lock_reveals,
    };
    (tx.encode_canonical(), witnesses.encode_canonical(), id)
}

/// Advances the node clock one slot and produces the next block.
pub fn produce_next(core: &mut NodeCore<InProcStore>) -> Hash32 {
    produce_full(core).hash
}

/// Like [`produce_next`] but returns the full gossip-ready block
/// (header, ticket, body, DA claim, shards) for import-side tests.
pub fn produce_full(core: &mut NodeCore<InProcStore>) -> crate::consensus::ProducedBlock {
    let (height, _) = core.head();
    let now = GENESIS_TIME_MS + (height + 1) * 6000;
    core.set_now(now);
    core.produce_block().expect("produce block")
}
