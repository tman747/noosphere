//! Mempool admission / eviction / per-payer FIFO ("nonce order") / fee
//! floor battery (node-v1.md §6.1-§6.2), driven directly against the
//! genesis ledger — every typed [`AdmitError`] arm is exercised where the
//! admission pipeline specifies it.

use noos_codec::{NoosDecode, NoosEncode};
use noos_crypto::{DomainId, Keypair};
use noos_lumen::fees;
use noos_lumen::objects::{
    txid, witness_root, BoundedBytes, BoundedList, OptionalHash32, OptionalObject, ResourceVector,
    SignedIntentV1, TransactionV1, TransactionWitnessesV1,
};
use noos_lumen::state::{LumenLedger, NOOS_ASSET};

use crate::mempool::{AdmitError, Mempool, MempoolConfig, SourceId};
use crate::Hash32;

use super::util::*;

/// Genesis fixture: ledger + chain id + block-start prices.
fn ledger_fixture() -> (LumenLedger, Hash32, fees::Prices) {
    let built = spec().build().expect("genesis build");
    let prices = built
        .ledger
        .fee_state()
        .expect("fee state installed")
        .prices();
    (built.ledger, built.chain_id, prices)
}

fn default_resources() -> ResourceVector {
    ResourceVector {
        bytes: 65_536,
        grain_steps: 10_000,
        proof_units: 8,
        state_reads: 64,
        state_writes: 64,
        blob_bytes: 0,
    }
}

/// Unsigned transaction with every admission-relevant knob exposed.
#[allow(clippy::too_many_arguments)]
fn make_tx(
    chain_id: Hash32,
    format_version: u16,
    expiry_height: u64,
    fee_payer: Hash32,
    account_inputs: Vec<Hash32>,
    resource_limits: ResourceVector,
) -> TransactionV1 {
    let lock_reveals: BoundedList<BoundedBytes<4096>, 256> = BoundedList::new(vec![]).unwrap();
    TransactionV1 {
        chain_id,
        format_version,
        expiry_height,
        fee_payer,
        fee_authorization: OptionalObject(None),
        resource_limits,
        note_inputs: BoundedList::new(vec![]).unwrap(),
        account_inputs: BoundedList::new(account_inputs).unwrap(),
        object_access_list: BoundedList::new(vec![]).unwrap(),
        actions: BoundedList::new(vec![]).unwrap(),
        outputs: BoundedList::new(vec![]).unwrap(),
        evidence_refs: BoundedList::new(vec![]).unwrap(),
        witness_root: witness_root(&lock_reveals),
    }
}

/// Signs one intent per account input with `key` over `commitment`
/// (default: the real txid).
fn sign_tx(
    tx: &TransactionV1,
    key: &Keypair,
    commitment: Option<Hash32>,
) -> (Vec<u8>, Vec<u8>, Hash32) {
    let id = txid(tx);
    let commit = commitment.unwrap_or(id);
    let signature = key.sign_domain(DomainId::SigTx, &[&commit]).expect("sign");
    let intents: Vec<SignedIntentV1> = tx
        .account_inputs
        .iter()
        .map(|_| SignedIntentV1 {
            tx_commitment: commit,
            signer_scope: 0,
            capability_ref: OptionalHash32(None),
            signature_suite: 1,
            signature: BoundedBytes::new(signature.into_bytes().to_vec()).unwrap(),
        })
        .collect();
    let witnesses = TransactionWitnessesV1 {
        intents: BoundedList::new(intents).unwrap(),
        lock_reveals: BoundedList::new(vec![]).unwrap(),
    };
    (tx.encode_canonical(), witnesses.encode_canonical(), id)
}

/// Well-formed faucet transaction with a chosen `grain_steps` limit
/// (the fee/density knob) and expiry.
fn faucet_tx(chain_id: Hash32, expiry: u64, grain_steps: u64) -> (Vec<u8>, Vec<u8>, Hash32) {
    let key = faucet_key();
    let payer = key.public_key().into_bytes();
    let mut res = default_resources();
    res.grain_steps = grain_steps;
    let tx = make_tx(chain_id, 1, expiry, payer, vec![payer], res);
    sign_tx(&tx, &key, None)
}

fn admit(
    mp: &mut Mempool,
    ledger: &LumenLedger,
    chain_id: &Hash32,
    prices: &fees::Prices,
    tx: &(Vec<u8>, Vec<u8>, Hash32),
    source: SourceId,
) -> Result<Hash32, AdmitError> {
    mp.admit(&tx.0, &tx.1, source, 1, chain_id, prices, ledger)
}

#[test]
fn admission_pipeline_rejects_each_stage_with_its_typed_error() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig::default());
    let key = faucet_key();
    let payer = key.public_key().into_bytes();

    // Stage 2: malformed bytes.
    assert_eq!(
        mp.admit(&[0xFF; 8], &[0xFF; 4], 1, 1, &chain_id, &prices, &ledger),
        Err(AdmitError::Malformed)
    );

    // Stage 3: wrong chain.
    let t = sign_tx(
        &make_tx([9; 32], 1, 40, payer, vec![payer], default_resources()),
        &key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::WrongChain)
    );

    // Stage 3: wrong format version.
    let t = sign_tx(
        &make_tx(chain_id, 2, 40, payer, vec![payer], default_resources()),
        &key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::WrongVersion)
    );

    // Stage 3: expired (expiry below next height 1).
    let t = sign_tx(
        &make_tx(chain_id, 1, 0, payer, vec![payer], default_resources()),
        &key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::Expired)
    );

    // Stage 1: declared byte envelope below the actual encoding.
    let mut res = default_resources();
    res.bytes = 1;
    let t = sign_tx(
        &make_tx(chain_id, 1, 40, payer, vec![payer], res),
        &key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::Oversized)
    );

    // Stage 6: unknown fee payer.
    let ghost_key = operator_key(9);
    let ghost = ghost_key.public_key().into_bytes();
    let t = sign_tx(
        &make_tx(chain_id, 1, 40, ghost, vec![ghost], default_resources()),
        &ghost_key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::UnknownPayer)
    );

    // Stage 6: fee payer not among the declared account inputs.
    let t = sign_tx(
        &make_tx(
            chain_id,
            1,
            40,
            payer,
            vec![operator_account(1)],
            default_resources(),
        ),
        &key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::PayerNotSigner)
    );

    // Stage 6: payer exists (operator fixture) but cannot cover the fee.
    let poor_key = operator_key(1);
    let poor = poor_key.public_key().into_bytes();
    assert_eq!(ledger.balance(&poor, &NOOS_ASSET), 0);
    let t = sign_tx(
        &make_tx(chain_id, 1, 40, poor, vec![poor], default_resources()),
        &poor_key,
        None,
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::InsufficientBalance)
    );

    // Stage 6: intent commitment does not equal the txid.
    let t = sign_tx(
        &make_tx(chain_id, 1, 40, payer, vec![payer], default_resources()),
        &key,
        Some([0xAB; 32]),
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::WitnessMismatch)
    );

    // Stage 6: valid commitment, wrong signing key.
    let tx = make_tx(chain_id, 1, 41, payer, vec![payer], default_resources());
    let id = txid(&tx);
    let (tx_bytes, _, _) = sign_tx(&tx, &key, None);
    let forged = operator_key(2)
        .sign_domain(DomainId::SigTx, &[&id])
        .unwrap();
    let witnesses = TransactionWitnessesV1 {
        intents: BoundedList::new(vec![SignedIntentV1 {
            tx_commitment: id,
            signer_scope: 0,
            capability_ref: OptionalHash32(None),
            signature_suite: 1,
            signature: BoundedBytes::new(forged.into_bytes().to_vec()).unwrap(),
        }])
        .unwrap(),
        lock_reveals: BoundedList::new(vec![]).unwrap(),
    };
    assert_eq!(
        mp.admit(
            &tx_bytes,
            &witnesses.encode_canonical(),
            1,
            1,
            &chain_id,
            &prices,
            &ledger
        ),
        Err(AdmitError::SignatureInvalid)
    );

    // Nothing above was admitted.
    assert!(mp.is_empty());

    // Every arm carries its stable snake_case RPC code.
    assert_eq!(
        AdmitError::FeeBelowFloor { fee: 1, floor: 2 }.code(),
        "fee_below_floor"
    );
    assert_eq!(AdmitError::DuplicatePending.code(), "duplicate_pending");
    assert_eq!(AdmitError::PoolFull.code(), "pool_full");
}

#[test]
fn oversized_transactions_are_refused_up_front() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig {
        max_tx_bytes: 16,
        ..MempoolConfig::default()
    });
    let t = faucet_tx(chain_id, 40, 10_000);
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::Oversized)
    );
}

#[test]
fn fee_floor_rejects_with_the_exact_fee_and_floor() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let t = faucet_tx(chain_id, 40, 10_000);
    let tx = TransactionV1::decode_canonical(&t.0).expect("decode back");
    let fee =
        fees::fee(&prices, &fees::usage_from_resources(&tx.resource_limits)).expect("fee computes");
    let mut mp = Mempool::new(MempoolConfig {
        min_fee_micro: fee + 1,
        ..MempoolConfig::default()
    });
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::FeeBelowFloor {
            fee,
            floor: fee + 1
        })
    );
    // At the floor exactly, admission passes.
    let mut mp = Mempool::new(MempoolConfig {
        min_fee_micro: fee,
        ..MempoolConfig::default()
    });
    assert_eq!(admit(&mut mp, &ledger, &chain_id, &prices, &t, 1), Ok(t.2));
}

#[test]
fn duplicate_pending_and_settled_are_distinct_rejections() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig::default());
    let t = faucet_tx(chain_id, 40, 10_000);
    assert_eq!(admit(&mut mp, &ledger, &chain_id, &prices, &t, 1), Ok(t.2));
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::DuplicatePending)
    );

    // Settling it (block connected) moves the rejection class.
    let expired = mp.on_block_connected(&[t.2], 2);
    assert!(expired.is_empty());
    assert!(mp.is_empty());
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::DuplicateSettled)
    );
}

#[test]
fn expiry_drops_on_block_connect() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig::default());
    let t = faucet_tx(chain_id, 5, 10_000);
    assert_eq!(admit(&mut mp, &ledger, &chain_id, &prices, &t, 1), Ok(t.2));
    // Still live while next_height <= expiry.
    assert!(mp.on_block_connected(&[], 5).is_empty());
    assert!(mp.contains(&t.2));
    // One block later it expires out (and is remembered as seen).
    let dropped = mp.on_block_connected(&[], 6);
    assert_eq!(dropped, vec![t.2]);
    assert!(mp.is_empty());
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t, 1),
        Err(AdmitError::DuplicateSettled)
    );
}

#[test]
fn per_source_and_per_account_limits_bound_admission() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig {
        per_source_pending: 1,
        ..MempoolConfig::default()
    });
    let t1 = faucet_tx(chain_id, 40, 10_000);
    let t2 = faucet_tx(chain_id, 41, 10_000);
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t1, 7),
        Ok(t1.2)
    );
    // Same source hits the per-source cap first.
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t2, 7),
        Err(AdmitError::SourceLimit)
    );

    // Distinct source, same payer: the per-account cap.
    let mut mp = Mempool::new(MempoolConfig {
        per_account_pending: 1,
        ..MempoolConfig::default()
    });
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t1, 7),
        Ok(t1.2)
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &t2, 8),
        Err(AdmitError::AccountLimit)
    );
}

#[test]
fn fee_density_eviction_removes_the_cheapest_and_refuses_a_loser() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig {
        max_count: 2,
        ..MempoolConfig::default()
    });
    // Same byte size, ascending fee ⇒ ascending density.
    let low = faucet_tx(chain_id, 40, 10_000);
    let mid = faucet_tx(chain_id, 41, 20_000);
    let high = faucet_tx(chain_id, 42, 40_000);
    let tiny = faucet_tx(chain_id, 43, 5_000);

    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &low, 1),
        Ok(low.2)
    );
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &mid, 2),
        Ok(mid.2)
    );
    assert_eq!(mp.len(), 2);

    // The pool is full: the incoming higher-density tx evicts the lowest.
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &high, 3),
        Ok(high.2)
    );
    assert_eq!(mp.len(), 2);
    assert!(!mp.contains(&low.2), "lowest density evicted");
    assert!(mp.contains(&mid.2));
    assert!(mp.contains(&high.2));

    // An incoming tx that cannot beat the lowest resident density loses.
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &tiny, 4),
        Err(AdmitError::PoolFull)
    );

    // A single transaction over the byte cap is unconditionally refused.
    let mut mp = Mempool::new(MempoolConfig {
        max_bytes: 10,
        ..MempoolConfig::default()
    });
    assert_eq!(
        admit(&mut mp, &ledger, &chain_id, &prices, &low, 1),
        Err(AdmitError::PoolFull)
    );
}

#[test]
fn template_respects_per_payer_fifo_nonce_order_and_capacity() {
    let (ledger, chain_id, prices) = ledger_fixture();
    let mut mp = Mempool::new(MempoolConfig::default());
    let capacity = ledger.fee_params().expect("fee params").capacity();

    // Lumen transactions carry no explicit nonce: the account input
    // consumes nonce+1 implicitly, so per-payer arrival order IS the
    // nonce order. Admit LOW density first, HIGH second — the template
    // must still emit them in FIFO order.
    let first_low = faucet_tx(chain_id, 40, 10_000);
    let second_high = faucet_tx(chain_id, 41, 40_000);
    admit(&mut mp, &ledger, &chain_id, &prices, &first_low, 1).unwrap();
    admit(&mut mp, &ledger, &chain_id, &prices, &second_high, 1).unwrap();

    let template = mp.template(&capacity);
    let order: Vec<Hash32> = template.iter().map(|e| e.txid).collect();
    assert_eq!(order, vec![first_low.2, second_high.2], "per-payer FIFO");
    let payer = faucet_key().public_key().into_bytes();
    assert_eq!(
        template[0].signature_authorizations,
        vec![(payer, payer.to_vec())],
        "admission must bind the exact descriptor used for signature verification"
    );

    // Capacity that only fits the head of the queue: exactly one entry.
    let one = template[0].usage;
    let template_one = mp.template(&one);
    assert_eq!(template_one.len(), 1);
    assert_eq!(template_one[0].txid, first_low.2);

    // Zero capacity: an empty template, never a panic.
    assert!(mp.template(&[0; fees::DIMENSIONS]).is_empty());
}
