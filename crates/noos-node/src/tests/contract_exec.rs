//! Production Grain contract execution through the node path (A-GRAIN /
//! A-AGENT-ABI local binding): a `CallObject` transaction executes through
//! [`crate::auth::GrainContractEngine`] inside block production AND block
//! import, with
//! - deterministic metering (identical steps, roots, and receipts on
//!   independent re-execution),
//! - storage-word accounting feeding the fee dimension,
//! - Grain trap codes surfacing as typed receipt status classes
//!   (`2000 + trap`), and
//! - the declared read/write-set law failing closed (undeclared or
//!   read-only access never writes).
//!
//! Failure atomicity is the node-path migration guarantee: a failed
//! transaction leaves every object byte-identical (only the frozen failure
//! charge, payer nonce, and failure receipt commit).

use std::collections::BTreeMap;

use noos_codec::NoosEncode;
use noos_grain::{encode_noun, GrainTrap, Noun, COST_SLOT_BASE};
use noos_lumen::fees;
use noos_lumen::objects::{object_id, AccessEntry, ActionV1, BoundedBytes, ResourceVector};
use noos_lumen::state::{FailCode, NOOS_ASSET};

use crate::consensus::{ImportOutcome, NodeConfig, NodeCore};
use crate::store_port::InProcStore;
use crate::view::{TxStatus, ViewLookup};
use crate::Hash32;

use super::util::*;

/// Registry key for the fixture formula (the engine registry is keyed by
/// the manifest code hash; the devnet config supplies the mapping).
const CODE_HASH: Hash32 = [0xC0; 32];

/// `[0 1]` — slot axis 1: return the whole explicit subject. Costs exactly
/// `COST_SLOT_BASE` grain-steps, so metering is pinned to the frozen table.
fn identity_formula() -> Noun {
    Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1)).expect("small noun")
}

/// Node config whose engine registry carries the fixture contract code.
fn contract_config() -> NodeConfig {
    let mut cfg = node_config();
    cfg.contract_codes = BTreeMap::from([(CODE_HASH, encode_noun(&identity_formula()))]);
    cfg
}

fn create_action(class_id: u32) -> ActionV1 {
    ActionV1::CreateObject {
        class_id,
        owner_or_policy_root: [0; 32],
        code_hash: CODE_HASH,
        state_root: [0; 32],
        storage_words: 0,
        rent_deposit: 0,
        flags: 0,
    }
}

fn call_action(object_id: Hash32) -> ActionV1 {
    ActionV1::CallObject {
        object_id,
        input: BoundedBytes::new(encode_noun(&Noun::atom_u64(9))).unwrap(),
    }
}

fn rw(object_id: Hash32) -> AccessEntry {
    AccessEntry {
        object_id,
        mode: AccessEntry::MODE_READ_WRITE,
    }
}

/// Block 1 fixture: one transaction creating contract objects for each
/// class id; returns the derived object ids.
fn create_objects(core: &mut NodeCore<InProcStore>, class_ids: &[u32]) -> Vec<Hash32> {
    let chain = core.chain_id();
    let actions = class_ids.iter().map(|c| create_action(*c)).collect();
    let (tx, wit, create_txid) = build_signed_tx(chain, 40, &faucet_key(), actions, vec![]);
    core.submit_tx(&tx, &wit, 7).expect("admit create");
    produce_next(core);
    class_ids
        .iter()
        .enumerate()
        .map(|(i, class_id)| {
            let oid = object_id(&create_txid, i as u32, *class_id);
            let obj = core.ledger().get_object(&oid).expect("object created");
            assert_eq!(obj.object_version, 0);
            assert_eq!(obj.code_hash, CODE_HASH);
            oid
        })
        .collect()
}

#[test]
fn contract_call_reexecutes_identically_on_import() {
    let dir_a = test_dir("grain-exec-a");
    let dir_b = test_dir("grain-exec-b");
    let mut a = boot_node(&dir_a, contract_config());
    let mut b = boot_node(&dir_b, contract_config());
    let chain = a.chain_id();

    // Block 1: create the contract object; keep the produced block for B.
    let (tx, wit, create_txid) =
        build_signed_tx(chain, 40, &faucet_key(), vec![create_action(7)], vec![]);
    a.submit_tx(&tx, &wit, 7).expect("admit create");
    let pb1 = produce_full(&mut a);
    let oid = object_id(&create_txid, 0, 7);
    let created = a.ledger().get_object(&oid).expect("object created");

    // Block 2: call it with a declared read-write entry.
    let (tx2, wit2, call_txid) = build_signed_tx_full(
        chain,
        40,
        &faucet_key(),
        vec![call_action(oid)],
        vec![],
        vec![rw(oid)],
        default_limits(),
    );
    a.submit_tx(&tx2, &wit2, 7).expect("admit call");
    let pb2 = produce_full(&mut a);
    assert_eq!(
        a.view.tx_status(&call_txid),
        ViewLookup::Found(TxStatus::Settled {
            height: 2,
            status: 0
        })
    );

    // The call executed through the Grain engine: the object migrated
    // atomically (state root, version, storage words in one commit) and the
    // metering charge is exactly the frozen cost-table value for `[0 1]`.
    let after = a.ledger().get_object(&oid).expect("object");
    assert_eq!(after.object_version, 1);
    assert_ne!(after.state_root, created.state_root);
    assert!(after.storage_words > 0, "storage words accounted");
    let receipt = a.ledger().get_receipt(&call_txid).expect("receipt");
    assert_eq!(receipt.status, 0);
    assert_eq!(receipt.resources_used.grain_steps, COST_SLOT_BASE);
    assert!(receipt.resources_used.state_writes >= after.storage_words);

    // Independent node B re-executes both blocks from the wire form:
    // byte-identical roots, object, and receipt (deterministic replay).
    b.set_now(pb1.header.timestamp_ms);
    assert_eq!(
        b.import_block(&pb1.header, &pb1.ticket, &pb1.claim, &pb1.shards)
            .expect("import block 1"),
        ImportOutcome::Executed { hash: pb1.hash }
    );
    b.set_now(pb2.header.timestamp_ms);
    assert_eq!(
        b.import_block(&pb2.header, &pb2.ticket, &pb2.claim, &pb2.shards)
            .expect("import block 2"),
        ImportOutcome::Executed { hash: pb2.hash }
    );
    assert_eq!(b.ledger().roots(), a.ledger().roots(), "identical roots");
    assert_eq!(
        b.ledger().get_object(&oid).map(|o| o.encode_canonical()),
        Some(after.encode_canonical()),
        "identical object bytes"
    );
    assert_eq!(
        b.ledger()
            .get_receipt(&call_txid)
            .map(|r| r.encode_canonical()),
        Some(receipt.encode_canonical()),
        "identical receipt bytes"
    );
}

#[test]
fn meter_exhaustion_surfaces_exact_trap_and_frozen_failure_charge() {
    let dir = test_dir("grain-meter");
    let mut core = boot_node(&dir, contract_config());
    let chain = core.chain_id();
    let oid = create_objects(&mut core, &[7])[0];
    let before = core.ledger().get_object(&oid).expect("object");
    let roots_before = core.ledger().roots();
    let payer = faucet_key().public_key().into_bytes();
    let balance_before = core.ledger().balance(&payer, &NOOS_ASSET);
    let prices = core.ledger().fee_state().expect("fee state").prices();

    // Declared budget of 1 grain-step: the interpreter's FIRST charge
    // (`COST_SLOT_BASE` = 2) exceeds it, so the Meter traps and pins
    // spent == limit (noos-grain law); the node surfaces the exact class.
    let limits = ResourceVector {
        grain_steps: 1,
        ..default_limits()
    };
    let (tx, wit, call_txid) = build_signed_tx_full(
        chain,
        40,
        &faucet_key(),
        vec![call_action(oid)],
        vec![],
        vec![rw(oid)],
        limits,
    );
    core.submit_tx(&tx, &wit, 7).expect("admit exhausting call");
    produce_next(&mut core);

    // Typed rejection class: exactly METER_EXHAUSTED, offset into the
    // receipt status space (2000 + trap code 3).
    let expected = FailCode::EngineTrap(u32::from(GrainTrap::MeterExhausted.code())).status();
    assert_eq!(expected, 2003);
    assert_eq!(
        core.view.tx_status(&call_txid),
        ViewLookup::Found(TxStatus::Settled {
            height: 2,
            status: expected
        })
    );

    // Failure atomicity: the object and every non-fee tree are untouched.
    assert_eq!(
        core.ledger().get_object(&oid).map(|o| o.encode_canonical()),
        Some(before.encode_canonical())
    );
    let roots_after = core.ledger().roots();
    assert_eq!(roots_after.objects_root, roots_before.objects_root);
    assert_eq!(roots_after.notes_root, roots_before.notes_root);
    assert_eq!(roots_after.nullifiers_root, roots_before.nullifiers_root);

    // Frozen deterministic failure charge: min(failure_fee, reservation),
    // never the open-ended execution fee.
    let params = core.ledger().fee_params().expect("fee params");
    let max_fee = fees::fee(&prices, &fees::usage_from_resources(&limits)).expect("max fee");
    let receipt = core
        .ledger()
        .get_receipt(&call_txid)
        .expect("failure receipt");
    assert_eq!(receipt.status, expected);
    assert_eq!(receipt.fee_charged, params.failure_fee.min(max_fee));
    assert_eq!(
        balance_before - core.ledger().balance(&payer, &NOOS_ASSET),
        receipt.fee_charged,
        "payer is charged exactly the frozen failure fee"
    );
}

#[test]
fn undeclared_object_write_fails_closed() {
    let dir = test_dir("grain-undeclared");
    let mut core = boot_node(&dir, contract_config());
    let chain = core.chain_id();
    let oid = create_objects(&mut core, &[7])[0];
    let before = core.ledger().get_object(&oid).expect("object");
    let objects_root_before = core.ledger().roots().objects_root;
    let undeclared = FailCode::UndeclaredAccess.status();
    assert_eq!(undeclared, 1005);

    // Forgery 1: a call with NO declared access entry for the object.
    let (tx, wit, forged1) = build_signed_tx_full(
        chain,
        40,
        &faucet_key(),
        vec![call_action(oid)],
        vec![],
        vec![],
        default_limits(),
    );
    core.submit_tx(&tx, &wit, 7)
        .expect("admitted; execution law rejects");
    produce_next(&mut core);
    assert_eq!(
        core.view.tx_status(&forged1),
        ViewLookup::Found(TxStatus::Settled {
            height: 2,
            status: undeclared
        })
    );

    // Forgery 2: a READ-only declaration must not authorize the write.
    let (tx2, wit2, forged2) = build_signed_tx_full(
        chain,
        40,
        &faucet_key(),
        vec![call_action(oid)],
        vec![],
        vec![AccessEntry {
            object_id: oid,
            mode: AccessEntry::MODE_READ,
        }],
        default_limits(),
    );
    core.submit_tx(&tx2, &wit2, 7)
        .expect("admitted; execution law rejects");
    produce_next(&mut core);
    assert_eq!(
        core.view.tx_status(&forged2),
        ViewLookup::Found(TxStatus::Settled {
            height: 3,
            status: undeclared
        })
    );

    // Neither forgery moved the object or the objects tree.
    assert_eq!(
        core.ledger().get_object(&oid).map(|o| o.encode_canonical()),
        Some(before.encode_canonical())
    );
    assert_eq!(core.ledger().roots().objects_root, objects_root_before);
}

#[test]
fn failed_action_drops_all_contract_effects_atomically() {
    let dir = test_dir("grain-atomic");
    let mut core = boot_node(&dir, contract_config());
    let chain = core.chain_id();
    let ids = create_objects(&mut core, &[7, 8]);
    let (oid_a, oid_b) = (ids[0], ids[1]);

    // Call A (declared, would succeed alone) then B (undeclared): the
    // WHOLE transaction fails and A's in-overlay migration is dropped.
    let (tx, wit, forged) = build_signed_tx_full(
        chain,
        40,
        &faucet_key(),
        vec![call_action(oid_a), call_action(oid_b)],
        vec![],
        vec![rw(oid_a)],
        default_limits(),
    );
    core.submit_tx(&tx, &wit, 7)
        .expect("admit multi-action call");
    produce_next(&mut core);
    assert_eq!(
        core.view.tx_status(&forged),
        ViewLookup::Found(TxStatus::Settled {
            height: 2,
            status: FailCode::UndeclaredAccess.status()
        })
    );
    let a_after_fail = core.ledger().get_object(&oid_a).expect("object A");
    assert_eq!(a_after_fail.object_version, 0, "partial effect dropped");
    assert_eq!(a_after_fail.state_root, [0; 32]);

    // The failure left no residue: the same declared call still migrates
    // A forward exactly once.
    let (tx2, wit2, ok) = build_signed_tx_full(
        chain,
        40,
        &faucet_key(),
        vec![call_action(oid_a)],
        vec![],
        vec![rw(oid_a)],
        default_limits(),
    );
    core.submit_tx(&tx2, &wit2, 7).expect("admit call");
    produce_next(&mut core);
    assert_eq!(
        core.view.tx_status(&ok),
        ViewLookup::Found(TxStatus::Settled {
            height: 3,
            status: 0
        })
    );
    let a_final = core.ledger().get_object(&oid_a).expect("object A");
    assert_eq!(a_final.object_version, 1);
    assert_ne!(a_final.state_root, [0; 32]);
}
