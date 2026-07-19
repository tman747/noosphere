//! State-transition tests: root-transition invariants, conservation,
//! failure-fee determinism, replay/nullifier law, governance/emergency
//! limits, capability gate, StateDelta ordering, and a seeded property
//! battery. Whole-ledger clones appear ONLY here (bounded test oracles,
//! plan §4.1).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_codec::{NoosDecode, NoosEncode};

use crate::engine::{AuthVerifier, ContractEngine, EngineOutcome, EngineTrap};
use crate::fees::{self, FeeParamsV1, FeeStateV1};
use crate::issuance::{EmissionSharesV1, IssuanceParamsV1};
use crate::neural_oracle::{
    neural_output_root, neural_program_id, neural_reply_commitment, neural_result_key,
    neural_transcript_root, EvaluateNeuralProgramV1, FinalizeNeuralOracleQueryV1,
    NeuralOracleCommitV1, NeuralOracleMode, NeuralOracleQueryV1, NeuralOracleRevealV1,
    NeuralOracleStatus, NeuralProgramV1,
};
use crate::objects::{
    agent_private_payment_schema_root, agent_private_payment_scope, asset_id, compute_job_id,
    debt_position_id, lending_market_id, liquidity_position_id, note_id, oracle_feed_id, pool_id,
    private_recipient_commitment, stable_asset_id, txid, witness_root, AccessEntry, AccountV1,
    ActionV1, BoundedBytes, BoundedList, CapabilityGrantV1, ComputeJobV1, ComputeWorkerV1,
    FeatureControlV1, IntentV1, NoteV1, ObjectV1, OptionalHash32, OptionalObject, PrivatePaymentV1,
    ResourceVector, SignedIntentV1, TransactionV1, TransactionWitnessesV1,
};
use crate::state::{
    param_key, ApplyOutcome, BlockContext, FailCode, GenesisConfig, GenesisError, LumenLedger,
    LumenRoots, RejectReason, SimulationOutcome, StateDelta, TreeId, CONTROL_PREFIX, NOOS_ASSET,
    PARAM_ISSUANCE,
};
use crate::test_util::SplitMix64;
use crate::wwm::{
    wwm_profile_key, CapabilityProfileV1, CapabilitySetV1, CapabilityStatus, FundBucketTag,
    ModelCapsuleV2, RegistryEpochVectorV1, SignatureEntryV1, WwmControlMode, WwmControlStateV1,
    WwmEvidenceTier, WwmJobV1, WwmLeafKind, WwmReceiptV1, WwmSettlementV1, WwmTerminalCode,
};
use crate::Hash32;

const CHAIN: Hash32 = [0x11; 32];
const PAYER: Hash32 = [0x0F; 32];
const GOV: Hash32 = [0xB0; 32];
const EMERGENCY: Hash32 = [0xE0; 32];
const PROPOSER: Hash32 = [0xA1; 32];
const WITNESS_POOL: Hash32 = [0xA2; 32];
const TREASURY: Hash32 = [0xA3; 32];
/// Objects with this code hash trap deterministically in the stub engine.
const TRAP_CODE: Hash32 = [0xEE; 32];
const OK_CODE: Hash32 = [0xCC; 32];

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

/// Accept-all verifier (crypto arrives with noos-crypto).
struct AcceptAll;
impl AuthVerifier for AcceptAll {
    fn verify_signature(&self, _: u16, _: &[u8], _: &Hash32, _: &[u8]) -> bool {
        true
    }
    fn verify_lock_reveal(&self, _: &Hash32, _: &[u8]) -> bool {
        true
    }
    fn verify_evidence_ref(&self, _: &Hash32) -> bool {
        true
    }
}

/// Rejects every signature: exercises the rejection path.
struct RejectSigs;
impl AuthVerifier for RejectSigs {
    fn verify_signature(&self, _: u16, _: &[u8], _: &Hash32, _: &[u8]) -> bool {
        false
    }
    fn verify_lock_reveal(&self, _: &Hash32, _: &[u8]) -> bool {
        true
    }
    fn verify_evidence_ref(&self, _: &Hash32) -> bool {
        true
    }
}

/// Deterministic engine stub: traps on TRAP_CODE, otherwise returns a state
/// root derived from the input and a fixed charge.
struct StubEngine;
impl ContractEngine for StubEngine {
    fn execute(
        &self,
        code_hash: &Hash32,
        _object_id: &Hash32,
        prior_state_root: &Hash32,
        input: &[u8],
        step_limit: u64,
    ) -> Result<EngineOutcome, EngineTrap> {
        if *code_hash == TRAP_CODE {
            return Err(EngineTrap { code: 7 });
        }
        if step_limit < 100 {
            return Err(EngineTrap { code: 3 }); // exhausted meter
        }
        Ok(EngineOutcome {
            new_state_root: crate::domain_hash(
                crate::domains::SMT_LEAF,
                &[prior_state_root, input],
            ),
            grain_steps: 100,
            storage_words: 4,
        })
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn account(id: Hash32) -> AccountV1 {
    AccountV1 {
        account_id: id,
        auth_descriptor: BoundedBytes::new(vec![1]).unwrap(),
        nonce: 0,
        liquid_balances_root: crate::smt::empty_root(crate::smt::DEPTH),
        bond_refs_root: [0; 32],
        metadata_commitment: [0; 32],
        recovery_policy_root: [0; 32],
    }
}

/// Genesis ledger: NOOS_TEST fixtures, funded payer, authority accounts,
/// emission recipients, one callable object and one trapping object.
fn genesis() -> LumenLedger {
    let mut ledger = LumenLedger::new();
    let accounts = [
        (account(PAYER), vec![(NOOS_ASSET, 1_000_000_000u128)]),
        (account(GOV), vec![]),
        (account(EMERGENCY), vec![]),
        (account(PROPOSER), vec![]),
        (account(WITNESS_POOL), vec![]),
        (account(TREASURY), vec![]),
    ];
    ledger
        .install_genesis(&GenesisConfig {
            fee_params: FeeParamsV1::testnet_fixture(),
            fee_state: FeeStateV1::testnet_fixture(),
            issuance: IssuanceParamsV1::testnet_fixture(),
            shares: EmissionSharesV1::testnet_fixture(),
            controls: &[("neural_lane", false), ("dream_lane", false)],
            accounts: &accounts,
            gov_authority: GOV,
            emergency_authority: EMERGENCY,
        })
        .expect("valid test genesis");
    ledger
}

fn ctx(height: u64) -> BlockContext {
    BlockContext {
        chain_id: CHAIN,
        height,
    }
}

fn limits() -> ResourceVector {
    ResourceVector {
        bytes: 65_536,
        grain_steps: 10_000,
        proof_units: 8,
        state_reads: 64,
        state_writes: 64,
        blob_bytes: 0,
    }
}

/// Build a transaction + aligned witnesses. `signers` must contain the fee
/// payer; one intent per account input, one lock reveal per note input.
fn build_tx(
    height: u64,
    note_inputs: Vec<Hash32>,
    signers: Vec<Hash32>,
    actions: Vec<ActionV1>,
    outputs: Vec<NoteV1>,
) -> (Vec<u8>, Vec<u8>, TransactionV1) {
    let reveals: Vec<BoundedBytes<4096>> = note_inputs
        .iter()
        .map(|_| BoundedBytes::new(vec![0x01]).unwrap())
        .collect();
    let lock_reveals = BoundedList::new(reveals).unwrap();
    let action_bytes: Vec<BoundedBytes<65536>> = actions
        .iter()
        .map(|a| BoundedBytes::new(a.encode_canonical()).unwrap())
        .collect();
    let tx = TransactionV1 {
        chain_id: CHAIN,
        format_version: 1,
        expiry_height: height + 10,
        fee_payer: PAYER,
        fee_authorization: OptionalObject(None),
        resource_limits: limits(),
        note_inputs: BoundedList::new(note_inputs).unwrap(),
        account_inputs: BoundedList::new(signers.clone()).unwrap(),
        object_access_list: BoundedList::new(
            actions
                .iter()
                .filter_map(|a| match a {
                    ActionV1::CallObject { object_id, .. } => Some(AccessEntry {
                        object_id: *object_id,
                        mode: AccessEntry::MODE_READ_WRITE,
                    }),
                    _ => None,
                })
                .collect(),
        )
        .unwrap(),
        actions: BoundedList::new(action_bytes).unwrap(),
        outputs: BoundedList::new(outputs).unwrap(),
        evidence_refs: BoundedList::new(vec![]).unwrap(),
        witness_root: witness_root(&lock_reveals),
    };
    let id = txid(&tx);
    let intents: Vec<SignedIntentV1> = signers
        .iter()
        .map(|_| SignedIntentV1 {
            tx_commitment: id,
            signer_scope: 0,
            capability_ref: OptionalHash32(None),
            signature_suite: 1,
            signature: BoundedBytes::new(vec![0xAB; 64]).unwrap(),
        })
        .collect();
    let witnesses = TransactionWitnessesV1 {
        intents: BoundedList::new(intents).unwrap(),
        lock_reveals,
    };
    (tx.encode_canonical(), witnesses.encode_canonical(), tx)
}

fn out_note(amount: u128, height: u64, fill: u8) -> NoteV1 {
    NoteV1 {
        asset_id: NOOS_ASSET,
        amount,
        lock_root: [fill; 32],
        datum_root: [0; 32],
        birth_height: height,
        relative_timelock: 0,
        memo_commitment: [0; 32],
    }
}

/// Create a note on the ledger through the real transition: withdraw from
/// the payer balance into a fresh output note. Returns the note id.
fn mint_note_via_withdraw(ledger: &mut LumenLedger, height: u64, amount: u128, fill: u8) -> Hash32 {
    let note = out_note(amount, height, fill);
    let (tx_bytes, wit_bytes, tx) = build_tx(
        height,
        vec![],
        vec![PAYER],
        vec![ActionV1::WithdrawFromAccount {
            account_id: PAYER,
            asset_id: NOOS_ASSET,
            amount,
        }],
        vec![note.clone()],
    );
    let outcome = ledger
        .apply_transaction(&ctx(height), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "seed tx failed: {outcome:?}"
    );
    note_id(&txid(&tx), 0, &note)
}

fn assert_roots_eq(a: &LumenRoots, b: &LumenRoots) {
    assert_eq!(a.notes_root, b.notes_root, "notes_root diverged");
    assert_eq!(
        a.nullifiers_root, b.nullifiers_root,
        "nullifiers_root diverged"
    );
    assert_eq!(a.accounts_root, b.accounts_root, "accounts_root diverged");
    assert_eq!(a.objects_root, b.objects_root, "objects_root diverged");
    assert_eq!(a.receipts_root, b.receipts_root, "receipts_root diverged");
    assert_eq!(a.params_root, b.params_root, "params_root diverged");
}

fn merged_delta_map(
    deltas: Vec<StateDelta>,
) -> std::collections::BTreeMap<(TreeId, Hash32, Option<Hash32>), Option<Vec<u8>>> {
    let mut merged = std::collections::BTreeMap::new();
    for delta in deltas {
        for entry in delta.entries {
            merged.insert((entry.tree, entry.key, entry.sub_key), entry.value);
        }
    }
    merged
}

/// Create an object and return its derived id.
fn create_object(ledger: &mut LumenLedger, height: u64, code_hash: Hash32) -> Hash32 {
    let (tx_bytes, wit_bytes, tx) = build_tx(
        height,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreateObject {
            class_id: 1,
            owner_or_policy_root: [0; 32],
            code_hash,
            state_root: [0; 32],
            storage_words: 4,
            rent_deposit: 0,
            flags: 0,
        }],
        vec![],
    );
    let outcome = ledger
        .apply_transaction(&ctx(height), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(
        matches!(outcome, ApplyOutcome::Applied { .. }),
        "create failed: {outcome:?}"
    );
    crate::objects::object_id(&txid(&tx), 0, 1)
}

// ---------------------------------------------------------------------------
// Root-transition invariants
// ---------------------------------------------------------------------------

#[test]
fn simulation_matches_application_without_mutating_any_state() {
    let mut ledger = genesis();
    let (tx_bytes, witness_bytes, tx) = build_tx(1, vec![], vec![PAYER], vec![], vec![]);
    let transaction_id = txid(&tx);
    let roots_before = ledger.roots();
    let balance_before = ledger.balance(&PAYER, &NOOS_ASSET);
    let nonce_before = ledger.get_account(&PAYER).unwrap().nonce;

    let simulated = ledger
        .simulate_transaction(&ctx(1), &tx_bytes, &witness_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    let SimulationOutcome::Applied {
        receipt: simulated_receipt,
    } = simulated
    else {
        panic!("valid transaction did not simulate successfully");
    };
    assert_roots_eq(&roots_before, &ledger.roots());
    assert_eq!(ledger.balance(&PAYER, &NOOS_ASSET), balance_before);
    assert_eq!(ledger.get_account(&PAYER).unwrap().nonce, nonce_before);
    assert!(ledger.get_receipt(&transaction_id).is_none());

    let applied = ledger
        .apply_transaction(&ctx(1), &tx_bytes, &witness_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    assert_eq!(applied.receipt(), &simulated_receipt);
    assert!(ledger.get_receipt(&transaction_id).is_some());
}

#[test]
fn canonical_decoded_application_matches_raw_application() {
    let mut raw_ledger = genesis();
    let mut decoded_ledger = raw_ledger.clone();
    let (tx_bytes, witness_bytes, tx) = build_tx(1, vec![], vec![PAYER], vec![], vec![]);
    let witnesses = TransactionWitnessesV1::decode_canonical(&witness_bytes).unwrap();
    let raw = raw_ledger
        .apply_transaction(&ctx(1), &tx_bytes, &witness_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    let decoded = decoded_ledger
        .apply_canonical_decoded_transaction(
            &ctx(1),
            &tx,
            &witnesses,
            tx_bytes.len() + witness_bytes.len(),
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    assert_eq!(raw.receipt(), decoded.receipt());
    assert_roots_eq(&raw_ledger.roots(), &decoded_ledger.roots());
}

#[test]
fn deferred_balance_roots_match_ordinary_ordered_execution() {
    let mut base = genesis();
    let trapping_object = create_object(&mut base, 1, TRAP_CODE);
    let transactions = vec![
        build_tx(
            2,
            vec![],
            vec![PAYER],
            vec![
                ActionV1::WithdrawFromAccount {
                    account_id: PAYER,
                    asset_id: NOOS_ASSET,
                    amount: 100,
                },
                ActionV1::DepositToAccount {
                    account_id: GOV,
                    asset_id: NOOS_ASSET,
                    amount: 100,
                },
            ],
            vec![],
        ),
        build_tx(
            3,
            vec![],
            vec![PAYER, GOV],
            vec![
                ActionV1::WithdrawFromAccount {
                    account_id: GOV,
                    asset_id: NOOS_ASSET,
                    amount: 40,
                },
                ActionV1::DepositToAccount {
                    account_id: PAYER,
                    asset_id: NOOS_ASSET,
                    amount: 40,
                },
            ],
            vec![],
        ),
        build_tx(
            4,
            vec![],
            vec![PAYER],
            vec![ActionV1::CallObject {
                object_id: trapping_object,
                input: BoundedBytes::new(vec![0xAA]).unwrap(),
            }],
            vec![],
        ),
    ];
    let mut ordinary = base.clone();
    let mut deferred = base;
    let mut ordinary_receipts = Vec::new();
    let mut ordinary_deltas = Vec::new();
    for (tx_bytes, witness_bytes, tx) in &transactions {
        let witnesses = TransactionWitnessesV1::decode_canonical(witness_bytes).unwrap();
        let outcome = ordinary
            .apply_canonical_decoded_transaction(
                &ctx(2),
                tx,
                &witnesses,
                tx_bytes.len() + witness_bytes.len(),
                &StubEngine,
                &AcceptAll,
            )
            .unwrap();
        match outcome {
            ApplyOutcome::Applied { receipt, delta } => {
                ordinary_receipts.push((receipt, None));
                ordinary_deltas.push(delta);
            }
            ApplyOutcome::Failed {
                receipt,
                delta,
                code,
            } => {
                ordinary_receipts.push((receipt, Some(code)));
                ordinary_deltas.push(delta);
            }
        }
    }

    let mut deferred_receipts = Vec::new();
    let mut deferred_deltas = Vec::new();
    let (execution_result, final_balance_roots) =
        deferred.with_deferred_balance_roots(|ledger, roots| {
            for (tx_bytes, witness_bytes, tx) in &transactions {
                let witnesses = TransactionWitnessesV1::decode_canonical(witness_bytes).unwrap();
                let outcome = match ledger
                    .try_apply_preverified_simple_transfer_deferred(
                        &ctx(2),
                        tx,
                        &witnesses,
                        tx_bytes.len() + witness_bytes.len(),
                        txid(tx),
                        roots,
                    )
                    .unwrap()
                {
                    Some(outcome) => outcome,
                    None => ledger
                        .apply_canonical_decoded_transaction_deferred(
                            &ctx(2),
                            tx,
                            &witnesses,
                            tx_bytes.len() + witness_bytes.len(),
                            &StubEngine,
                            &AcceptAll,
                            roots,
                        )
                        .unwrap(),
                };
                match outcome {
                    ApplyOutcome::Applied { receipt, delta } => {
                        deferred_receipts.push((receipt, None));
                        deferred_deltas.push(delta);
                    }
                    ApplyOutcome::Failed {
                        receipt,
                        delta,
                        code,
                    } => {
                        deferred_receipts.push((receipt, Some(code)));
                        deferred_deltas.push(delta);
                    }
                }
            }
            Ok::<(), RejectReason>(())
        });
    execution_result.unwrap();
    deferred_deltas.push(final_balance_roots);

    assert_eq!(ordinary_receipts, deferred_receipts);
    assert_eq!(
        merged_delta_map(ordinary_deltas),
        merged_delta_map(deferred_deltas)
    );
    assert_roots_eq(&ordinary.roots(), &deferred.roots());
    assert_eq!(ordinary, deferred);
}

#[test]
fn rejected_transaction_leaves_all_six_roots_byte_identical() {
    let mut ledger = genesis();
    let _seed = mint_note_via_withdraw(&mut ledger, 1, 10_000, 0x21);
    let before = ledger.roots();

    // Wrong chain.
    let (tx_bytes, wit_bytes, _) = build_tx(2, vec![], vec![PAYER], vec![], vec![]);
    let mut wrong_chain = tx_bytes.clone();
    wrong_chain[4] ^= 0xFF; // chain_id first byte (after version+tag)
    let r = ledger.apply_transaction(&ctx(2), &wrong_chain, &wit_bytes, &StubEngine, &AcceptAll);
    assert!(r.is_err());
    assert_roots_eq(&before, &ledger.roots());

    // Expired.
    let r = ledger.apply_transaction(&ctx(9_999), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::Expired);
    assert_roots_eq(&before, &ledger.roots());

    // Unknown note input.
    let (tx2, wit2, _) = build_tx(2, vec![[0xDD; 32]], vec![PAYER], vec![], vec![]);
    let r = ledger.apply_transaction(&ctx(2), &tx2, &wit2, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::UnknownNoteInput);
    assert_roots_eq(&before, &ledger.roots());

    // Bad signature.
    let r = ledger.apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &RejectSigs);
    assert_eq!(r.unwrap_err(), RejectReason::SignatureInvalid);
    assert_roots_eq(&before, &ledger.roots());

    // Noncanonical bytes.
    let mut trailing = tx_bytes.clone();
    trailing.push(0);
    let r = ledger.apply_transaction(&ctx(2), &trailing, &wit_bytes, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::Noncanonical);
    assert_roots_eq(&before, &ledger.roots());

    // Insufficient fee balance: drain-scale declared limits ok, but a payer
    // with zero balance cannot reserve. Use GOV (no balance) as payer.
    let mut tx = TransactionV1::decode_canonical_helper(&tx_bytes);
    tx.fee_payer = GOV;
    tx.account_inputs = BoundedList::new(vec![GOV]).unwrap();
    let id = txid(&tx);
    let wit = TransactionWitnessesV1 {
        intents: BoundedList::new(vec![SignedIntentV1 {
            tx_commitment: id,
            signer_scope: 0,
            capability_ref: OptionalHash32(None),
            signature_suite: 1,
            signature: BoundedBytes::new(vec![0xAB; 64]).unwrap(),
        }])
        .unwrap(),
        lock_reveals: BoundedList::new(vec![]).unwrap(),
    };
    let r = ledger.apply_transaction(
        &ctx(2),
        &tx.encode_canonical(),
        &wit.encode_canonical(),
        &StubEngine,
        &AcceptAll,
    );
    assert_eq!(r.unwrap_err(), RejectReason::InsufficientFeeBalance);
    assert_roots_eq(&before, &ledger.roots());
}

#[test]
fn execution_trap_charges_only_failure_fee_and_preserves_four_roots() {
    let mut ledger = genesis();
    let trap_object = create_object(&mut ledger, 1, TRAP_CODE);
    let before = ledger.roots();
    let payer_before = ledger.balance(&PAYER, &NOOS_ASSET);
    let nonce_before = ledger.get_account(&PAYER).unwrap().nonce;

    let (tx_bytes, wit_bytes, tx) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![ActionV1::CallObject {
            object_id: trap_object,
            input: BoundedBytes::new(vec![1]).unwrap(),
        }],
        vec![],
    );
    let outcome = ledger
        .apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    let ApplyOutcome::Failed {
        receipt,
        delta,
        code,
    } = outcome
    else {
        panic!("expected Failed, got {outcome:?}");
    };
    assert_eq!(code, FailCode::EngineTrap(7));
    assert_eq!(receipt.status, 2007);

    let after = ledger.roots();
    // Four roots byte-identical: the overlay was dropped.
    assert_eq!(before.notes_root, after.notes_root);
    assert_eq!(before.nullifiers_root, after.nullifiers_root);
    assert_eq!(before.objects_root, after.objects_root);
    assert_eq!(before.params_root, after.params_root);
    // Accounts and receipts changed: failure charge + failure receipt.
    assert_ne!(before.accounts_root, after.accounts_root);
    assert_ne!(before.receipts_root, after.receipts_root);

    // The charge is exactly the frozen failure fee (min with reservation).
    let fee_params = FeeParamsV1::testnet_fixture();
    let charged = payer_before - ledger.balance(&PAYER, &NOOS_ASSET);
    assert_eq!(charged, fee_params.failure_fee);
    assert_eq!(receipt.fee_charged, charged);
    // Only the fee payer's nonce advanced.
    assert_eq!(ledger.get_account(&PAYER).unwrap().nonce, nonce_before + 1);
    // The failure receipt is settled: replaying the same tx now rejects.
    let r = ledger.apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::TxAlreadySettled);
    assert_eq!(ledger.get_receipt(&txid(&tx)).unwrap().status, 2007);
    assert!(!delta.is_empty());
}

#[test]
fn failure_fee_is_deterministic_across_identical_ledgers() {
    // Bounded test oracle: two identical ledgers, same trap tx, byte-identical
    // roots and deltas afterwards.
    let mut a = genesis();
    let trap_a = create_object(&mut a, 1, TRAP_CODE);
    let mut b = genesis();
    let trap_b = create_object(&mut b, 1, TRAP_CODE);
    assert_eq!(trap_a, trap_b, "object derivation must be deterministic");
    assert_roots_eq(&a.roots(), &b.roots());

    let (tx_bytes, wit_bytes, _) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![ActionV1::CallObject {
            object_id: trap_a,
            input: BoundedBytes::new(vec![1]).unwrap(),
        }],
        vec![],
    );
    let oa = a
        .apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    let ob = b
        .apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    assert_eq!(oa, ob, "failure outcomes must be byte-identical");
    assert_roots_eq(&a.roots(), &b.roots());
}

// ---------------------------------------------------------------------------
// Conservation and value flow
// ---------------------------------------------------------------------------

#[test]
fn per_asset_conservation_is_strict() {
    let mut ledger = genesis();
    let seed = mint_note_via_withdraw(&mut ledger, 1, 10_000, 0x21);

    // Spend 10_000 into 6_000 + 4_000: conserves, applies.
    let (tx_bytes, wit_bytes, _) = build_tx(
        2,
        vec![seed],
        vec![PAYER],
        vec![],
        vec![out_note(6_000, 2, 0x31), out_note(4_000, 2, 0x32)],
    );
    let outcome = ledger
        .apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
    assert!(ledger.nullifier_spent(&seed));
    assert!(
        ledger.get_note(&seed).is_none(),
        "spent note must leave the unspent set"
    );

    // Imbalanced: 6_000 -> 7_000 must fail conservation (post-reservation).
    let seed2 = mint_note_via_withdraw(&mut ledger, 3, 6_000, 0x41);
    let before = ledger.roots();
    let (tx_bytes, wit_bytes, _) = build_tx(
        4,
        vec![seed2],
        vec![PAYER],
        vec![],
        vec![out_note(7_000, 4, 0x51)],
    );
    let outcome = ledger
        .apply_transaction(&ctx(4), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    let ApplyOutcome::Failed { code, .. } = outcome else {
        panic!("imbalance must fail");
    };
    assert_eq!(code, FailCode::ConservationViolation);
    // Note set untouched: the seed note is still unspent.
    assert_eq!(before.notes_root, ledger.roots().notes_root);
    assert!(ledger.get_note(&seed2).is_some());
}

#[test]
fn fixed_supply_launch_and_constant_product_swaps_are_atomic() {
    let mut ledger = genesis();
    let symbol = BoundedBytes::new(b"MIND".to_vec()).unwrap();
    let name = BoundedBytes::new(b"Mind Launch".to_vec()).unwrap();
    let supply = 1_000_000_000u128;
    let (create_bytes, create_witnesses, create_tx) = build_tx(
        1,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreateAsset {
            issuer: PAYER,
            symbol,
            name,
            decimals: 6,
            total_supply: supply,
        }],
        vec![],
    );
    let launched = asset_id(&txid(&create_tx), 0);
    let outcome = ledger
        .apply_transaction(
            &ctx(1),
            &create_bytes,
            &create_witnesses,
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
    assert_eq!(ledger.get_asset(&launched).unwrap().total_supply, supply);
    assert_eq!(ledger.balance(&PAYER, &launched), supply);

    let seeded_noos = 10_000_000u128;
    let seeded_token = 100_000_000u128;
    let pool = pool_id(&NOOS_ASSET, &launched);
    let (pool_bytes, pool_witnesses, _) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreatePool {
            provider: PAYER,
            asset_a: NOOS_ASSET,
            asset_b: launched,
            amount_a: seeded_noos,
            amount_b: seeded_token,
            fee_bps: 30,
        }],
        vec![],
    );
    let outcome = ledger
        .apply_transaction(
            &ctx(2),
            &pool_bytes,
            &pool_witnesses,
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
    let before = ledger.get_pool(&pool).unwrap();
    assert_eq!(
        (before.reserve_0, before.reserve_1),
        (seeded_noos, seeded_token)
    );

    let amount_in = 1_000_000u128;
    let effective = amount_in * 9_970 / 10_000;
    let expected_out = seeded_token * effective / (seeded_noos + effective);
    let token_before = ledger.balance(&PAYER, &launched);
    let (swap_bytes, swap_witnesses, _) = build_tx(
        3,
        vec![],
        vec![PAYER],
        vec![ActionV1::SwapExactIn {
            trader: PAYER,
            pool_id: pool,
            asset_in: NOOS_ASSET,
            amount_in,
            min_amount_out: expected_out,
        }],
        vec![],
    );
    let outcome = ledger
        .apply_transaction(
            &ctx(3),
            &swap_bytes,
            &swap_witnesses,
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
    let after = ledger.get_pool(&pool).unwrap();
    assert_eq!(after.reserve_0, seeded_noos + amount_in);
    assert_eq!(after.reserve_1, seeded_token - expected_out);
    assert_eq!(
        ledger.balance(&PAYER, &launched),
        token_before + expected_out
    );
    assert!(
        after.reserve_0 * after.reserve_1 >= before.reserve_0 * before.reserve_1,
        "fees keep constant product nondecreasing"
    );

    let pool_before_failure = after.clone();
    let (bad_bytes, bad_witnesses, _) = build_tx(
        4,
        vec![],
        vec![PAYER],
        vec![ActionV1::SwapExactIn {
            trader: PAYER,
            pool_id: pool,
            asset_in: NOOS_ASSET,
            amount_in,
            min_amount_out: u128::MAX,
        }],
        vec![],
    );
    let outcome = ledger
        .apply_transaction(&ctx(4), &bad_bytes, &bad_witnesses, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(
        outcome,
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
    assert_eq!(ledger.get_pool(&pool), Some(pool_before_failure));
}

#[test]
fn liquidity_shares_add_and_remove_without_dilution() {
    let mut ledger = genesis();
    let (asset_bytes, asset_witnesses, asset_tx) = build_tx(
        1,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreateAsset {
            issuer: PAYER,
            symbol: BoundedBytes::new(b"LIQ".to_vec()).unwrap(),
            name: BoundedBytes::new(b"Liquidity Test".to_vec()).unwrap(),
            decimals: 6,
            total_supply: 1_000_000_000,
        }],
        vec![],
    );
    let asset = asset_id(&txid(&asset_tx), 0);
    assert!(matches!(
        ledger
            .apply_transaction(
                &ctx(1),
                &asset_bytes,
                &asset_witnesses,
                &StubEngine,
                &AcceptAll,
            )
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    let pool_id = pool_id(&NOOS_ASSET, &asset);
    let (create_bytes, create_witnesses, _) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreatePool {
            provider: PAYER,
            asset_a: NOOS_ASSET,
            asset_b: asset,
            amount_a: 10_000_000,
            amount_b: 100_000_000,
            fee_bps: 30,
        }],
        vec![],
    );
    ledger
        .apply_transaction(
            &ctx(2),
            &create_bytes,
            &create_witnesses,
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    let initial_pool = ledger.get_pool(&pool_id).unwrap();
    let position_id = liquidity_position_id(&pool_id, &PAYER);
    let initial_position = ledger.get_liquidity_position(&pool_id, &PAYER).unwrap();
    assert_eq!(initial_position.position_id, position_id);
    assert_eq!(
        initial_position.shares + crate::state::MINIMUM_LIQUIDITY,
        initial_pool.total_shares
    );

    let (add_bytes, add_witnesses, _) = build_tx(
        3,
        vec![],
        vec![PAYER],
        vec![ActionV1::AddLiquidity {
            provider: PAYER,
            pool_id,
            max_amount_0: 1_000_000,
            max_amount_1: 10_000_000,
            min_shares: 1,
        }],
        vec![],
    );
    ledger
        .apply_transaction(&ctx(3), &add_bytes, &add_witnesses, &StubEngine, &AcceptAll)
        .unwrap();
    let added_pool = ledger.get_pool(&pool_id).unwrap();
    let added_position = ledger.get_liquidity_position(&pool_id, &PAYER).unwrap();
    let minted = added_position.shares - initial_position.shares;
    assert!(minted > 0);
    assert!(
        added_pool.reserve_0 * initial_pool.total_shares
            >= initial_pool.reserve_0 * added_pool.total_shares,
        "rounded add cannot dilute reserve-0 ownership"
    );
    assert!(
        added_pool.reserve_1 * initial_pool.total_shares
            >= initial_pool.reserve_1 * added_pool.total_shares,
        "rounded add cannot dilute reserve-1 ownership"
    );

    let (remove_bytes, remove_witnesses, _) = build_tx(
        4,
        vec![],
        vec![PAYER],
        vec![ActionV1::RemoveLiquidity {
            provider: PAYER,
            pool_id,
            shares: minted,
            min_amount_0: 1,
            min_amount_1: 1,
        }],
        vec![],
    );
    ledger
        .apply_transaction(
            &ctx(4),
            &remove_bytes,
            &remove_witnesses,
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    let removed_pool = ledger.get_pool(&pool_id).unwrap();
    let removed_position = ledger.get_liquidity_position(&pool_id, &PAYER).unwrap();
    assert_eq!(removed_position.shares, initial_position.shares);
    assert_eq!(removed_pool.total_shares, initial_pool.total_shares);
    assert!(removed_pool.reserve_0 >= initial_pool.reserve_0);
    assert!(removed_pool.reserve_1 >= initial_pool.reserve_1);
}

#[test]
fn seeded_amm_actions_preserve_share_and_reserve_invariants() {
    let mut ledger = genesis();
    let apply = |ledger: &mut LumenLedger, height: u64, action: ActionV1| {
        let (bytes, witnesses, _) = build_tx(height, vec![], vec![PAYER], vec![action], vec![]);
        ledger
            .apply_transaction(&ctx(height), &bytes, &witnesses, &StubEngine, &AcceptAll)
            .unwrap()
    };
    let (asset_bytes, asset_witnesses, asset_tx) = build_tx(
        1,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreateAsset {
            issuer: PAYER,
            symbol: BoundedBytes::new(b"PROP".to_vec()).unwrap(),
            name: BoundedBytes::new(b"Property Asset".to_vec()).unwrap(),
            decimals: 6,
            total_supply: 1_000_000_000,
        }],
        vec![],
    );
    let asset = asset_id(&txid(&asset_tx), 0);
    assert!(matches!(
        ledger
            .apply_transaction(
                &ctx(1),
                &asset_bytes,
                &asset_witnesses,
                &StubEngine,
                &AcceptAll,
            )
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    let pool_id = pool_id(&NOOS_ASSET, &asset);
    assert!(matches!(
        apply(
            &mut ledger,
            2,
            ActionV1::CreatePool {
                provider: PAYER,
                asset_a: NOOS_ASSET,
                asset_b: asset,
                amount_a: 10_000_000,
                amount_b: 100_000_000,
                fee_bps: 30,
            },
        ),
        ApplyOutcome::Applied { .. }
    ));

    let mut rng = SplitMix64(0xA11C_E5EED);
    for step in 0..128u64 {
        let before = ledger.get_pool(&pool_id).unwrap();
        let position_before = ledger.get_liquidity_position(&pool_id, &PAYER).unwrap();
        let action = match rng.next_u64() % 3 {
            0 => ActionV1::SwapExactIn {
                trader: PAYER,
                pool_id,
                asset_in: NOOS_ASSET,
                amount_in: u128::from(rng.next_u64() % 10_000 + 1),
                min_amount_out: 1,
            },
            1 => {
                let max_amount_0 = u128::from(rng.next_u64() % 9_001 + 1_000);
                let max_amount_1 = (max_amount_0 * before.reserve_1).div_ceil(before.reserve_0);
                ActionV1::AddLiquidity {
                    provider: PAYER,
                    pool_id,
                    max_amount_0,
                    max_amount_1,
                    min_shares: 1,
                }
            }
            _ if position_before.shares > 1 => ActionV1::RemoveLiquidity {
                provider: PAYER,
                pool_id,
                shares: (position_before.shares / 100).max(1),
                min_amount_0: 1,
                min_amount_1: 1,
            },
            _ => continue,
        };
        assert!(matches!(
            apply(&mut ledger, step + 3, action),
            ApplyOutcome::Applied { .. }
        ));
        let after = ledger.get_pool(&pool_id).unwrap();
        let position_after = ledger.get_liquidity_position(&pool_id, &PAYER).unwrap();
        assert!(after.reserve_0 > 0 && after.reserve_1 > 0);
        assert!(after.total_shares >= crate::state::MINIMUM_LIQUIDITY);
        assert_eq!(
            after.total_shares,
            position_after.shares + crate::state::MINIMUM_LIQUIDITY,
            "single-provider shares plus locked minimum must equal total"
        );
        if after.total_shares == before.total_shares {
            assert!(
                after.reserve_0 * after.reserve_1 >= before.reserve_0 * before.reserve_1,
                "a swap cannot decrease constant product"
            );
        }
    }
}

#[test]
fn quorum_oracle_and_collateralized_stable_debt_lifecycle() {
    let mut ledger = genesis();
    let apply =
        |ledger: &mut LumenLedger, height: u64, accounts: Vec<Hash32>, actions: Vec<ActionV1>| {
            let (bytes, witnesses, _) = build_tx(height, vec![], accounts, actions, vec![]);
            ledger
                .apply_transaction(&ctx(height), &bytes, &witnesses, &StubEngine, &AcceptAll)
                .unwrap()
        };

    let (asset_bytes, asset_witnesses, asset_tx) = build_tx(
        1,
        vec![],
        vec![PAYER],
        vec![ActionV1::CreateAsset {
            issuer: PAYER,
            symbol: BoundedBytes::new(b"COLL".to_vec()).unwrap(),
            name: BoundedBytes::new(b"Collateral".to_vec()).unwrap(),
            decimals: 9,
            total_supply: 1_000_000,
        }],
        vec![],
    );
    let collateral = asset_id(&txid(&asset_tx), 0);
    ledger
        .apply_transaction(
            &ctx(1),
            &asset_bytes,
            &asset_witnesses,
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    let feed_id = oracle_feed_id(&collateral, &NOOS_ASSET);
    assert!(matches!(
        apply(
            &mut ledger,
            2,
            vec![PAYER, GOV],
            vec![ActionV1::CreateOracleFeed {
                base_asset: collateral,
                quote_asset: NOOS_ASSET,
                reporter_0: GOV,
                reporter_1: EMERGENCY,
                reporter_2: PROPOSER,
                reporter_3: WITNESS_POOL,
                reporter_4: TREASURY,
                max_age_blocks: 100,
                max_deviation_bps: 5_000,
                twap_window_blocks: 2,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    for (height, reporter, price) in [
        (3, GOV, 2_000_000_000u128),
        (4, EMERGENCY, 2_020_000_000),
        (5, PROPOSER, 1_980_000_000),
    ] {
        assert!(matches!(
            apply(
                &mut ledger,
                height,
                vec![PAYER, reporter],
                vec![ActionV1::SubmitOracleReport {
                    reporter,
                    feed_id,
                    price_q9: price,
                    confidence_bps: 100,
                    sequence: 1,
                    observed_height: height,
                }],
            ),
            ApplyOutcome::Applied { .. }
        ));
    }
    let market_id = lending_market_id(&collateral, &feed_id);
    let stable = stable_asset_id(&market_id);
    assert!(matches!(
        apply(
            &mut ledger,
            6,
            vec![PAYER, GOV],
            vec![ActionV1::CreateLendingMarket {
                collateral_asset: collateral,
                oracle_feed_id: feed_id,
                symbol: BoundedBytes::new(b"MUSD".to_vec()).unwrap(),
                name: BoundedBytes::new(b"Mind USD".to_vec()).unwrap(),
                decimals: 9,
                collateral_factor_bps: 5_000,
                liquidation_threshold_bps: 7_500,
                liquidation_bonus_bps: 500,
                debt_ceiling: 1_000_000,
                min_debt: 1_000,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(ledger.get_stable_safety(&market_id).is_some());
    ledger.remove_stable_safety_for_test(&market_id);
    assert!(ledger
        .activate_stable_safety_upgrade(6, 7)
        .unwrap()
        .is_empty());
    assert!(ledger.get_stable_safety(&market_id).is_none());
    assert!(!ledger
        .activate_stable_safety_upgrade(7, 7)
        .unwrap()
        .is_empty());
    assert!(ledger.get_stable_safety(&market_id).is_some());
    assert!(matches!(
        apply(
            &mut ledger,
            7,
            vec![PAYER],
            vec![ActionV1::DepositCollateral {
                owner: PAYER,
                market_id,
                amount: 100_000,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            8,
            vec![PAYER],
            vec![ActionV1::BorrowStable {
                owner: PAYER,
                market_id,
                amount: 80_000,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(ledger.balance(&PAYER, &stable), 80_000);
    assert_eq!(
        ledger.get_lending_market(&market_id).unwrap().total_debt,
        80_000
    );
    assert_eq!(ledger.stable_assets()[0].minted_supply, 80_000);

    assert!(matches!(
        apply(
            &mut ledger,
            9,
            vec![PAYER],
            vec![ActionV1::RepayStable {
                owner: PAYER,
                market_id,
                amount: 20_000,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            10,
            vec![PAYER],
            vec![
                ActionV1::WithdrawFromAccount {
                    account_id: PAYER,
                    asset_id: stable,
                    amount: 20_000,
                },
                ActionV1::DepositToAccount {
                    account_id: GOV,
                    asset_id: stable,
                    amount: 20_000,
                },
            ],
        ),
        ApplyOutcome::Applied { .. }
    ));

    for (height, reporter, price) in [
        (11, GOV, 1_100_000_000u128),
        (12, EMERGENCY, 1_110_000_000),
        (13, PROPOSER, 1_090_000_000),
    ] {
        assert!(matches!(
            apply(
                &mut ledger,
                height,
                vec![PAYER, reporter],
                vec![ActionV1::SubmitOracleReport {
                    reporter,
                    feed_id,
                    price_q9: price,
                    confidence_bps: 100,
                    sequence: 2,
                    observed_height: height,
                }],
            ),
            ApplyOutcome::Applied { .. }
        ));
    }
    for (reporter, price) in [
        (GOV, 700_000_000u128),
        (EMERGENCY, 710_000_000),
        (PROPOSER, 690_000_000),
    ] {
        assert!(matches!(
            apply(
                &mut ledger,
                13,
                vec![PAYER, reporter],
                vec![ActionV1::SubmitOracleReport {
                    reporter,
                    feed_id,
                    price_q9: price,
                    confidence_bps: 100,
                    sequence: 3,
                    observed_height: 13,
                }],
            ),
            ApplyOutcome::Applied { .. }
        ));
    }
    assert!(matches!(
        apply(
            &mut ledger,
            14,
            vec![PAYER, GOV],
            vec![ActionV1::SetOracleMode {
                feed_id,
                mode: crate::state::ORACLE_MODE_LAST_GOOD,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            14,
            vec![PAYER, GOV],
            vec![ActionV1::LiquidatePosition {
                liquidator: GOV,
                market_id,
                owner: PAYER,
                repay_amount: 20_000,
                min_collateral_out: 1,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    let position = ledger.get_debt_position(&market_id, &PAYER).unwrap();
    assert_eq!(position.position_id, debt_position_id(&market_id, &PAYER));
    assert_eq!(position.debt, 40_000);
    assert!(position.collateral < 100_000);
    assert!(ledger.balance(&GOV, &collateral) > 0);
    assert_eq!(ledger.balance(&GOV, &stable), 0);
    assert_eq!(
        ledger.get_lending_market(&market_id).unwrap().total_debt,
        40_000
    );
    assert_eq!(ledger.stable_assets()[0].minted_supply, 40_000);
    assert!(matches!(
        apply(
            &mut ledger,
            14,
            vec![PAYER],
            vec![ActionV1::FundStableReserve {
                contributor: PAYER,
                market_id,
                amount: 40_000,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        ledger.get_stable_safety(&market_id).unwrap().stable_reserve,
        40_000
    );
    assert!(matches!(
        apply(
            &mut ledger,
            14,
            vec![PAYER, GOV],
            vec![ActionV1::BackstopLiquidate {
                keeper: GOV,
                market_id,
                owner: PAYER,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        ledger.get_debt_position(&market_id, &PAYER).unwrap().debt,
        0
    );
    assert_eq!(
        ledger.get_stable_safety(&market_id).unwrap().stable_reserve,
        0
    );
    assert!(
        ledger
            .get_stable_safety(&market_id)
            .unwrap()
            .collateral_reserve
            > 0
    );
    assert!(matches!(
        apply(
            &mut ledger,
            14,
            vec![PAYER, GOV],
            vec![ActionV1::SetOracleMode {
                feed_id,
                mode: crate::state::ORACLE_MODE_LIVE,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            14,
            vec![PAYER],
            vec![ActionV1::PsmMint {
                owner: PAYER,
                market_id,
                collateral_in: 20_000,
                min_stable_out: 13_000,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        ledger.get_stable_safety(&market_id).unwrap().psm_debt,
        13_860
    );

    let claim_secret = [0xC1; 32];
    assert!(matches!(
        apply(
            &mut ledger,
            15,
            vec![PAYER],
            vec![ActionV1::OpenPrivatePayment {
                payer: PAYER,
                stable_asset: stable,
                recipient_commitment: private_recipient_commitment(&EMERGENCY, &claim_secret),
                memo_commitment: [0xB1; 32],
                reference_commitment: [0xA1; 32],
                amount: 5_000,
                expiry_height: 25,
                payment_kind: PrivatePaymentV1::KIND_AGENT,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    let payment_id = ledger
        .private_payments()
        .into_iter()
        .find(|payment| payment.reference_commitment == [0xA1; 32])
        .unwrap()
        .payment_id;
    let wrong_claim = apply(
        &mut ledger,
        16,
        vec![PAYER, GOV],
        vec![ActionV1::ClaimPrivatePayment {
            recipient: GOV,
            payment_id,
            claim_secret,
        }],
    );
    assert!(matches!(
        wrong_claim,
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            17,
            vec![PAYER, EMERGENCY],
            vec![ActionV1::ClaimPrivatePayment {
                recipient: EMERGENCY,
                payment_id,
                claim_secret,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(ledger.balance(&EMERGENCY, &stable), 5_000);
    assert_eq!(
        ledger.get_private_payment(&payment_id).unwrap().status,
        PrivatePaymentV1::STATUS_CLAIMED
    );

    assert!(matches!(
        apply(
            &mut ledger,
            18,
            vec![PAYER],
            vec![ActionV1::OpenPrivatePayment {
                payer: PAYER,
                stable_asset: stable,
                recipient_commitment: private_recipient_commitment(&EMERGENCY, &[0xC2; 32]),
                memo_commitment: [0xB2; 32],
                reference_commitment: [0xA2; 32],
                amount: 3_000,
                expiry_height: 19,
                payment_kind: PrivatePaymentV1::KIND_INVOICE,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    let refundable_id = ledger
        .private_payments()
        .into_iter()
        .find(|payment| payment.reference_commitment == [0xA2; 32])
        .unwrap()
        .payment_id;
    assert!(matches!(
        apply(
            &mut ledger,
            19,
            vec![PAYER],
            vec![ActionV1::RefundPrivatePayment {
                payer: PAYER,
                payment_id: refundable_id,
            }],
        ),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            20,
            vec![PAYER],
            vec![ActionV1::RefundPrivatePayment {
                payer: PAYER,
                payment_id: refundable_id,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(ledger.balance(&PAYER, &stable), 8_833);
    assert_eq!(
        ledger.get_private_payment(&refundable_id).unwrap().status,
        PrivatePaymentV1::STATUS_REFUNDED
    );

    let agent_secret = [0xC3; 32];
    let agent_recipient = private_recipient_commitment(&EMERGENCY, &agent_secret);
    let grant_id = [0xD1; 32];
    assert!(matches!(
        apply(
            &mut ledger,
            21,
            vec![PAYER],
            vec![ActionV1::GrantCapability {
                grant: CapabilityGrantV1 {
                    grant_id,
                    issuer: PAYER,
                    subject_agent: GOV,
                    allowed_action_schema_root: agent_private_payment_schema_root(),
                    object_scope_root: agent_private_payment_scope(&stable, &agent_recipient),
                    per_action_limit: 4_000,
                    cumulative_budget: 6_000,
                    expiry_height: 50,
                    delegation_depth: 0,
                    revocation_nonce: 0,
                },
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            22,
            vec![PAYER, GOV],
            vec![ActionV1::OpenAgentPrivatePayment {
                agent: GOV,
                payer: PAYER,
                stable_asset: stable,
                recipient_commitment: agent_recipient,
                memo_commitment: [0xB3; 32],
                reference_commitment: [0xA3; 32],
                amount: 3_000,
                expiry_height: 40,
                capability_ref: grant_id,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(ledger.balance(&PAYER, &stable), 5_833);
    let overspend = apply(
        &mut ledger,
        23,
        vec![PAYER, GOV],
        vec![ActionV1::OpenAgentPrivatePayment {
            agent: GOV,
            payer: PAYER,
            stable_asset: stable,
            recipient_commitment: agent_recipient,
            memo_commitment: [0xB4; 32],
            reference_commitment: [0xA4; 32],
            amount: 4_000,
            expiry_height: 40,
            capability_ref: grant_id,
        }],
    );
    assert!(matches!(
        overspend,
        ApplyOutcome::Failed {
            code: FailCode::InsufficientBalance,
            ..
        }
    ));
    assert_eq!(ledger.balance(&PAYER, &stable), 5_833);
    assert!(matches!(
        apply(
            &mut ledger,
            24,
            vec![PAYER],
            vec![ActionV1::PsmRedeem {
                owner: PAYER,
                market_id,
                stable_in: 1_000,
                min_collateral_out: 1,
            }],
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(ledger.balance(&PAYER, &stable), 4_833);
    assert_eq!(
        ledger.get_stable_safety(&market_id).unwrap().psm_debt,
        12_862
    );
}

#[test]
fn oracle_replay_and_single_report_borrow_fail_closed() {
    let mut ledger = genesis();
    let apply =
        |ledger: &mut LumenLedger, height: u64, accounts: Vec<Hash32>, actions: Vec<ActionV1>| {
            let (bytes, witnesses, tx) = build_tx(height, vec![], accounts, actions, vec![]);
            let outcome = ledger
                .apply_transaction(&ctx(height), &bytes, &witnesses, &StubEngine, &AcceptAll)
                .unwrap();
            (outcome, tx)
        };
    let (asset_outcome, asset_tx) = apply(
        &mut ledger,
        1,
        vec![PAYER],
        vec![ActionV1::CreateAsset {
            issuer: PAYER,
            symbol: BoundedBytes::new(b"QUOTE".to_vec()).unwrap(),
            name: BoundedBytes::new(b"Quote Unit".to_vec()).unwrap(),
            decimals: 9,
            total_supply: 1_000_000,
        }],
    );
    assert!(matches!(asset_outcome, ApplyOutcome::Applied { .. }));
    let quote = asset_id(&txid(&asset_tx), 0);
    let feed_id = oracle_feed_id(&NOOS_ASSET, &quote);
    assert!(matches!(
        apply(
            &mut ledger,
            2,
            vec![PAYER, GOV],
            vec![ActionV1::CreateOracleFeed {
                base_asset: NOOS_ASSET,
                quote_asset: quote,
                reporter_0: GOV,
                reporter_1: EMERGENCY,
                reporter_2: PROPOSER,
                reporter_3: WITNESS_POOL,
                reporter_4: TREASURY,
                max_age_blocks: 10,
                max_deviation_bps: 1_500,
                twap_window_blocks: 100,
            }],
        )
        .0,
        ApplyOutcome::Applied { .. }
    ));
    let report = ActionV1::SubmitOracleReport {
        reporter: GOV,
        feed_id,
        price_q9: 2_000_000_000,
        confidence_bps: 0,
        sequence: 1,
        observed_height: 3,
    };
    assert!(matches!(
        apply(&mut ledger, 3, vec![PAYER, GOV], vec![report.clone()]).0,
        ApplyOutcome::Applied { .. }
    ));
    let replay = apply(&mut ledger, 4, vec![PAYER, GOV], vec![report]).0;
    assert!(matches!(
        replay,
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    let market_id = lending_market_id(&NOOS_ASSET, &feed_id);
    assert!(matches!(
        apply(
            &mut ledger,
            5,
            vec![PAYER, GOV],
            vec![ActionV1::CreateLendingMarket {
                collateral_asset: NOOS_ASSET,
                oracle_feed_id: feed_id,
                symbol: BoundedBytes::new(b"SOLO".to_vec()).unwrap(),
                name: BoundedBytes::new(b"Single Report Refusal".to_vec()).unwrap(),
                decimals: 9,
                collateral_factor_bps: 5_000,
                liquidation_threshold_bps: 7_500,
                liquidation_bonus_bps: 500,
                debt_ceiling: 1_000_000,
                min_debt: 1_000,
            }],
        )
        .0,
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &mut ledger,
            6,
            vec![PAYER],
            vec![ActionV1::DepositCollateral {
                owner: PAYER,
                market_id,
                amount: 100_000,
            }],
        )
        .0,
        ApplyOutcome::Applied { .. }
    ));
    let before = ledger.roots();
    let borrow = apply(
        &mut ledger,
        7,
        vec![PAYER],
        vec![ActionV1::BorrowStable {
            owner: PAYER,
            market_id,
            amount: 10_000,
        }],
    )
    .0;
    assert!(matches!(
        borrow,
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
    assert_eq!(
        ledger.get_debt_position(&market_id, &PAYER).unwrap().debt,
        0
    );
    assert_eq!(ledger.get_lending_market(&market_id).unwrap().total_debt, 0);
    assert_ne!(ledger.roots().receipts_root, before.receipts_root);
}

#[test]
fn compute_market_escrow_requires_requester_acceptance_before_payment() {
    let mut ledger = genesis();
    let worker = [0xA7; 32];

    // First payment creates the worker's self-authenticating account.
    let (fund, fund_witnesses, _) = build_tx(
        1,
        vec![],
        vec![PAYER],
        vec![
            ActionV1::WithdrawFromAccount {
                account_id: PAYER,
                asset_id: NOOS_ASSET,
                amount: 100_000,
            },
            ActionV1::DepositToAccount {
                account_id: worker,
                asset_id: NOOS_ASSET,
                amount: 100_000,
            },
        ],
        vec![],
    );
    assert!(matches!(
        ledger
            .apply_transaction(&ctx(1), &fund, &fund_witnesses, &StubEngine, &AcceptAll)
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));

    let (register, register_witnesses, _) = build_tx(
        2,
        vec![],
        vec![PAYER, worker],
        vec![ActionV1::RegisterComputeWorker {
            worker,
            capabilities: ComputeWorkerV1::CAPABILITY_CPU | ComputeWorkerV1::CAPABILITY_GPU,
            cpu_threads: 8,
            memory_mb: 16_384,
            gpu_memory_mb: 8_192,
            price_per_unit: 7,
            endpoint_commitment: [0x44; 32],
        }],
        vec![],
    );
    assert!(matches!(
        ledger
            .apply_transaction(
                &ctx(2),
                &register,
                &register_witnesses,
                &StubEngine,
                &AcceptAll,
            )
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));

    let (open, open_witnesses, open_tx) = build_tx(
        3,
        vec![],
        vec![PAYER],
        vec![ActionV1::OpenComputeJob {
            requester: PAYER,
            workload_kind: 0,
            input_root: [0x55; 32],
            units: 100,
            unit_size: 4096,
            max_price_per_unit: 10,
            deadline_height: 20,
        }],
        vec![],
    );
    let job_id = compute_job_id(&txid(&open_tx), 0);
    assert!(matches!(
        ledger
            .apply_transaction(&ctx(3), &open, &open_witnesses, &StubEngine, &AcceptAll)
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(ledger.get_compute_job(&job_id).unwrap().escrow, 1_000);

    let (claim, claim_witnesses, _) = build_tx(
        4,
        vec![],
        vec![PAYER, worker],
        vec![ActionV1::ClaimComputeJob { worker, job_id }],
        vec![],
    );
    assert!(matches!(
        ledger
            .apply_transaction(&ctx(4), &claim, &claim_witnesses, &StubEngine, &AcceptAll)
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    let worker_before_submit = ledger.balance(&worker, &NOOS_ASSET);

    let (submit, submit_witnesses, _) = build_tx(
        5,
        vec![],
        vec![PAYER, worker],
        vec![ActionV1::SubmitComputeResult {
            worker,
            job_id,
            result_root: [0x66; 32],
            completed_units: 100,
        }],
        vec![],
    );
    assert!(matches!(
        ledger
            .apply_transaction(&ctx(5), &submit, &submit_witnesses, &StubEngine, &AcceptAll,)
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        ledger.balance(&worker, &NOOS_ASSET),
        worker_before_submit,
        "worker cannot self-release escrow"
    );
    assert_eq!(
        ledger.get_compute_job(&job_id).unwrap().state,
        ComputeJobV1::STATE_SUBMITTED
    );

    let (accept, accept_witnesses, _) = build_tx(
        6,
        vec![],
        vec![PAYER],
        vec![ActionV1::AcceptComputeResult {
            requester: PAYER,
            job_id,
        }],
        vec![],
    );
    assert!(matches!(
        ledger
            .apply_transaction(&ctx(6), &accept, &accept_witnesses, &StubEngine, &AcceptAll)
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        ledger.balance(&worker, &NOOS_ASSET),
        worker_before_submit + 700
    );
    let settled = ledger.get_compute_job(&job_id).unwrap();
    assert_eq!(settled.state, ComputeJobV1::STATE_SETTLED);
    assert_eq!(settled.escrow, 0);
    assert_eq!(
        ledger.get_compute_worker(&worker).unwrap().jobs_completed,
        1
    );
}

#[test]
fn duplicate_nullifier_rejects_within_and_across_transactions() {
    let mut ledger = genesis();
    let seed = mint_note_via_withdraw(&mut ledger, 1, 5_000, 0x21);

    // Spend once.
    let (tx_bytes, wit_bytes, _) = build_tx(
        2,
        vec![seed],
        vec![PAYER],
        vec![],
        vec![out_note(5_000, 2, 0x31)],
    );
    let outcome = ledger
        .apply_transaction(&ctx(2), &tx_bytes, &wit_bytes, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(outcome, ApplyOutcome::Applied { .. }));

    // Second spend of the same note rejects: the nullifier is set.
    let before = ledger.roots();
    let (tx2, wit2, _) = build_tx(
        3,
        vec![seed],
        vec![PAYER],
        vec![],
        vec![out_note(5_000, 3, 0x32)],
    );
    let r = ledger.apply_transaction(&ctx(3), &tx2, &wit2, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::NullifierAlreadySpent);
    assert_roots_eq(&before, &ledger.roots());

    // Duplicate note input inside ONE transaction also rejects (the second
    // resolution sees the identical id; conservation would also catch it,
    // but resolution must fail first on the duplicate declared input).
    let seed2 = mint_note_via_withdraw(&mut ledger, 4, 5_000, 0x41);
    let (tx3, wit3_bad, _) = build_tx(
        5,
        vec![seed2, seed2],
        vec![PAYER],
        vec![],
        vec![out_note(10_000, 5, 0x51)],
    );
    let r = ledger.apply_transaction(&ctx(5), &tx3, &wit3_bad, &StubEngine, &AcceptAll);
    assert!(r.is_err(), "double-declared input must not apply");
}

#[test]
fn supply_invariant_holds_under_seeded_random_traffic() {
    // Property battery: minted + genesis funding == notes + balances + fees
    // burned, after every step, across 200 seeded random operations.
    let mut ledger = genesis();
    let genesis_funding: u128 = 1_000_000_000;
    let mut fees_burned: u128 = 0;
    let mut live_notes: Vec<(Hash32, u128)> = Vec::new();
    let mut rng = SplitMix64(0xC0FFEE);
    let mut height = 1u64;

    for step in 0..200u32 {
        height += 1;
        let choice = rng.next_u64() % 3;
        let outcome = if choice == 0 || live_notes.is_empty() {
            // Withdraw a random amount into a fresh note.
            let amount = u128::from(rng.next_u64() % 50_000 + 1);
            if ledger.balance(&PAYER, &NOOS_ASSET) < amount + 100_000 {
                continue; // keep fee headroom
            }
            let fill = u8::try_from(step % 251).unwrap();
            let note = out_note(amount, height, fill);
            let (txb, witb, tx) = build_tx(
                height,
                vec![],
                vec![PAYER],
                vec![ActionV1::WithdrawFromAccount {
                    account_id: PAYER,
                    asset_id: NOOS_ASSET,
                    amount,
                }],
                vec![note.clone()],
            );
            let out = ledger
                .apply_transaction(&ctx(height), &txb, &witb, &StubEngine, &AcceptAll)
                .unwrap();
            if matches!(out, ApplyOutcome::Applied { .. }) {
                live_notes.push((note_id(&txid(&tx), 0, &note), amount));
            }
            out
        } else if choice == 1 {
            // Spend a random note into two conserving outputs.
            let idx = (rng.next_u64() as usize) % live_notes.len();
            let (id, amount) = live_notes.swap_remove(idx);
            let a = amount / 2;
            let b = amount - a;
            let fill_a = u8::try_from((step * 2) % 251).unwrap();
            let fill_b = u8::try_from((step * 2 + 1) % 251).unwrap();
            let mut outs = vec![out_note(a, height, fill_a), out_note(b, height, fill_b)];
            outs.retain(|n| n.amount > 0);
            let (txb, witb, tx) = build_tx(height, vec![id], vec![PAYER], vec![], outs.clone());
            let out = ledger
                .apply_transaction(&ctx(height), &txb, &witb, &StubEngine, &AcceptAll)
                .unwrap();
            if matches!(out, ApplyOutcome::Applied { .. }) {
                for (i, n) in outs.iter().enumerate() {
                    live_notes.push((note_id(&txid(&tx), u32::try_from(i).unwrap(), n), n.amount));
                }
            } else {
                live_notes.push((id, amount)); // note survived the failure
            }
            out
        } else {
            // Deposit a random note back into the payer balance.
            let idx = (rng.next_u64() as usize) % live_notes.len();
            let (id, amount) = live_notes.swap_remove(idx);
            let (txb, witb, _) = build_tx(
                height,
                vec![id],
                vec![PAYER],
                vec![ActionV1::DepositToAccount {
                    account_id: PAYER,
                    asset_id: NOOS_ASSET,
                    amount,
                }],
                vec![],
            );
            let out = ledger
                .apply_transaction(&ctx(height), &txb, &witb, &StubEngine, &AcceptAll)
                .unwrap();
            if !matches!(out, ApplyOutcome::Applied { .. }) {
                live_notes.push((id, amount));
            }
            out
        };
        fees_burned += outcome.receipt().fee_charged;

        // Invariant after EVERY step.
        let note_total: u128 = live_notes.iter().map(|(_, a)| *a).sum();
        let balance_total = ledger.balance(&PAYER, &NOOS_ASSET);
        assert_eq!(
            genesis_funding + ledger.emission_minted(),
            note_total + balance_total + fees_burned,
            "supply conservation violated at step {step}"
        );
    }
    assert!(fees_burned > 0, "battery must actually charge fees");
    assert!(!live_notes.is_empty(), "battery must leave live notes");
}

#[test]
fn first_deposit_creates_a_self_authenticating_recipient_account() {
    let mut ledger = genesis();
    let recipient = [0xA7; 32];
    assert!(ledger.get_account(&recipient).is_none());

    let amount = 50_000u128;
    let (fund, fund_witnesses, _) = build_tx(
        1,
        vec![],
        vec![PAYER],
        vec![
            ActionV1::WithdrawFromAccount {
                account_id: PAYER,
                asset_id: NOOS_ASSET,
                amount,
            },
            ActionV1::DepositToAccount {
                account_id: recipient,
                asset_id: NOOS_ASSET,
                amount,
            },
        ],
        vec![],
    );
    assert!(matches!(
        ledger
            .apply_transaction(&ctx(1), &fund, &fund_witnesses, &StubEngine, &AcceptAll)
            .unwrap(),
        ApplyOutcome::Applied { .. }
    ));
    let created = ledger.get_account(&recipient).expect("recipient account");
    assert_eq!(created.account_id, recipient);
    assert_eq!(created.auth_descriptor.as_slice(), recipient.as_slice());
    assert_eq!(ledger.balance(&recipient, &NOOS_ASSET), amount);
}

// ---------------------------------------------------------------------------
// StateDelta ordering
// ---------------------------------------------------------------------------

#[test]
fn state_delta_is_canonically_ordered_and_deterministic() {
    let mut a = genesis();
    let mut b = genesis();
    let seed_a = mint_note_via_withdraw(&mut a, 1, 9_000, 0x21);
    let seed_b = mint_note_via_withdraw(&mut b, 1, 9_000, 0x21);
    assert_eq!(seed_a, seed_b);

    let (txb, witb, _) = build_tx(
        2,
        vec![seed_a],
        vec![PAYER],
        vec![ActionV1::DepositToAccount {
            account_id: PAYER,
            asset_id: NOOS_ASSET,
            amount: 9_000,
        }],
        vec![],
    );
    let extract = |o: ApplyOutcome| -> StateDelta {
        match o {
            ApplyOutcome::Applied { delta, .. } | ApplyOutcome::Failed { delta, .. } => delta,
        }
    };
    let da = extract(
        a.apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
            .unwrap(),
    );
    let db = extract(
        b.apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
            .unwrap(),
    );
    assert_eq!(da, db, "identical ledgers must emit identical deltas");

    // Canonical order: strictly ascending (tree, key, sub_key).
    let keys: Vec<_> = da
        .entries
        .iter()
        .map(|e| (e.tree, e.key, e.sub_key))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted, "delta must be sorted and duplicate-free");
    // Touches at least notes (delete), nullifiers, accounts, balances, receipts.
    let trees: std::collections::BTreeSet<TreeId> = da.entries.iter().map(|e| e.tree).collect();
    assert!(trees.contains(&TreeId::Notes));
    assert!(trees.contains(&TreeId::Nullifiers));
    assert!(trees.contains(&TreeId::Accounts));
    assert!(trees.contains(&TreeId::Receipts));
    assert!(trees.contains(&TreeId::AccountBalances));
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

#[test]
fn emission_follows_schedule_and_never_recreates_missed_heights() {
    let mut ledger = genesis();
    let issuance = IssuanceParamsV1::testnet_fixture();
    let e1 = issuance.emission_at(1).unwrap();
    let e5 = issuance.emission_at(5).unwrap();

    let d = ledger
        .apply_emission(1, &PROPOSER, &WITNESS_POOL, &TREASURY)
        .unwrap();
    assert!(!d.is_empty());
    assert_eq!(ledger.emission_minted(), e1);

    // Same height twice: rejected, nothing minted.
    let before = ledger.roots();
    assert!(ledger
        .apply_emission(1, &PROPOSER, &WITNESS_POOL, &TREASURY)
        .is_err());
    assert_roots_eq(&before, &ledger.roots());
    assert_eq!(ledger.emission_minted(), e1);

    // Skip to height 5: heights 2-4 are FORFEIT, only E_5 mints.
    ledger
        .apply_emission(5, &PROPOSER, &WITNESS_POOL, &TREASURY)
        .unwrap();
    assert_eq!(ledger.emission_minted(), e1 + e5);
    assert_eq!(ledger.last_emission_height(), 5);

    // Going back rejects.
    assert!(ledger
        .apply_emission(3, &PROPOSER, &WITNESS_POOL, &TREASURY)
        .is_err());

    // The split is conserved to the micro.
    let shares = EmissionSharesV1::testnet_fixture();
    let split = shares.split(e1).unwrap();
    assert_eq!(split.total().unwrap(), e1);
    // Balances credited (both heights).
    let total_credited = ledger.balance(&PROPOSER, &NOOS_ASSET)
        + ledger.balance(&WITNESS_POOL, &NOOS_ASSET)
        + ledger.balance(&TREASURY, &NOOS_ASSET);
    assert_eq!(total_credited, e1 + e5);
}

#[test]
fn emission_past_terminal_height_is_zero_and_unknown_recipient_rejects() {
    let mut ledger = genesis();
    let issuance = IssuanceParamsV1::testnet_fixture();
    // Unknown recipient fails closed.
    assert!(ledger
        .apply_emission(1, &[0xFF; 32], &WITNESS_POOL, &TREASURY)
        .is_err());
    // Past terminal: mints zero but advances the height watermark.
    ledger
        .apply_emission(
            issuance.terminal_height + 10,
            &PROPOSER,
            &WITNESS_POOL,
            &TREASURY,
        )
        .unwrap();
    assert_eq!(ledger.emission_minted(), 0);
}

#[test]
fn genesis_supply_is_checked_for_duplicates_overflow_and_full_schedule() {
    let base = account(PAYER);
    let shares = EmissionSharesV1::testnet_fixture();
    let fees = FeeParamsV1::testnet_fixture();
    let fee_state = FeeStateV1::testnet_fixture();
    let issuance = IssuanceParamsV1 {
        max_supply: 10,
        initial_per_height: 10,
        era_length: 1,
        decay_numerator: 1,
        decay_denominator: 2,
        terminal_height: 1,
    };
    let install = |accounts: &[(AccountV1, Vec<(Hash32, u128)>)], issuance| {
        let mut ledger = LumenLedger::new();
        ledger.install_genesis(&GenesisConfig {
            fee_params: fees.clone(),
            fee_state: fee_state.clone(),
            issuance,
            shares: shares.clone(),
            controls: &[],
            accounts,
            gov_authority: GOV,
            emergency_authority: EMERGENCY,
        })
    };

    let over_cap = [(base.clone(), vec![(NOOS_ASSET, 1)])];
    assert_eq!(
        install(&over_cap, issuance.clone()),
        Err(GenesisError::InvalidIssuance),
        "genesis allocation plus the full schedule must fit the cap"
    );

    let duplicate = [
        (base.clone(), vec![(NOOS_ASSET, 1)]),
        (base.clone(), vec![(NOOS_ASSET, 1)]),
    ];
    let mut no_emission = issuance.clone();
    no_emission.initial_per_height = 0;
    assert_eq!(
        install(&duplicate, no_emission.clone()),
        Err(GenesisError::DuplicateAccount)
    );

    let overflow = [
        (base.clone(), vec![(NOOS_ASSET, u128::MAX)]),
        (account(GOV), vec![(NOOS_ASSET, 1)]),
    ];
    no_emission.max_supply = u128::MAX;
    assert_eq!(install(&overflow, no_emission), Err(GenesisError::Overflow));
}

#[test]
fn issued_supply_is_explicit_and_deterministic_under_replay() {
    let mut first = genesis();
    let mut replay = genesis();
    assert_eq!(first.genesis_issued(), 1_000_000_000);
    assert_eq!(first.emission_minted(), 0);
    assert_eq!(first.total_issued(), first.genesis_issued());
    for height in [1, 5, 12] {
        first
            .apply_emission(height, &PROPOSER, &WITNESS_POOL, &TREASURY)
            .unwrap();
        replay
            .apply_emission(height, &PROPOSER, &WITNESS_POOL, &TREASURY)
            .unwrap();
    }
    assert_eq!(first, replay);
    assert_eq!(
        first.total_issued(),
        first
            .genesis_issued()
            .checked_add(first.emission_minted())
            .unwrap()
    );
}

fn wwm_flow_fixture(
    mode: WwmControlMode,
) -> (LumenLedger, WwmJobV1, WwmReceiptV1, WwmSettlementV1) {
    let capsule_id = [0x31; 32];
    let artifact_id = [0x32; 32];
    let execution_profile_id = [0x33; 32];
    let query_policy_id = [0x34; 32];
    let certificate_id = [0x35; 32];
    let fund_profile_id = [0x36; 32];
    let config_id = [0x37; 32];
    let capsule = ModelCapsuleV2 {
        capsule_id,
        artifact_id,
        payload_root: [0x38; 32],
        manifest_root: [0x39; 32],
        weight_manifest_root: [0x3a; 32],
        tokenizer_root: [0x3b; 32],
        template_root: [0x3c; 32],
        runtime_root: [0x3d; 32],
        build_root: [0x3e; 32],
        sbom_root: [0x3f; 32],
        execution_profile_ids: BoundedList::new(vec![execution_profile_id]).unwrap(),
        query_policy_id,
        availability_policy_id: [0x40; 32],
        license_root: [0x41; 32],
        rights_root: [0x42; 32],
        provenance_root: [0x43; 32],
        lifecycle: 1,
        rollback_capsule_id: OptionalHash32(None),
        publisher_threshold: 1,
        publisher_signatures: BoundedList::<SignatureEntryV1, 32>::default(),
    };
    let control = WwmControlStateV1 {
        mode,
        active_capsule_id: OptionalHash32(Some(capsule_id)),
        last_transition_id: OptionalHash32(Some([0x44; 32])),
        last_transition_height: 1,
        direct_prior_live_mode: WwmControlMode::Disabled,
        direct_prior_config_id: OptionalHash32(None),
        active_config_id: OptionalHash32(Some(config_id)),
        latest_authorized_config_id: OptionalHash32(Some(config_id)),
        resolution_config_id: OptionalHash32(Some(config_id)),
        release_root: [0x45; 32],
        promotion_ledger_root: [0x46; 32],
        capsule_id,
        artifact_id,
        availability_policy_id: capsule.availability_policy_id,
        execution_profile_id,
        query_policy_id,
        runway_root: [0x47; 32],
    };
    let mut ledger = genesis();
    ledger.install_wwm_flow_fixture_for_test(
        &control,
        &capsule,
        execution_profile_id,
        query_policy_id,
        certificate_id,
        fund_profile_id,
    );
    let job = WwmJobV1 {
        job_id: [0x48; 32],
        chain_id: CHAIN,
        genesis_hash: [0x49; 32],
        quote_id: [0x4a; 32],
        registry_epoch: 1,
        client_commitment: [0x4b; 32],
        capsule_id,
        execution_profile_id,
        query_policy_id,
        max_input_tokens: 32,
        max_output_tokens: 16,
        deadline_height: 100,
        selected_executor_ids: BoundedList::new(vec![[0x4c; 32]]).unwrap(),
        availability_certificate_id: certificate_id,
        fund_profile_id,
        reserved_amount: 100,
        offchain_envelope_root: [0x4d; 32],
    };
    let receipt = WwmReceiptV1 {
        receipt_id: [0x4e; 32],
        job_id: job.job_id,
        capsule_id,
        artifact_id,
        tokenizer_root: capsule.tokenizer_root,
        template_root: capsule.template_root,
        runtime_root: capsule.runtime_root,
        sbom_root: capsule.sbom_root,
        execution_profile_id,
        input_tokens: 4,
        output_tokens: 2,
        token_history_root: [0x4f; 32],
        output_root: [0x50; 32],
        signer_ids: BoundedList::new(vec![[0x51; 32]]).unwrap(),
        control_cluster_ids: BoundedList::new(vec![[0x52; 32]]).unwrap(),
        evidence_tier: WwmEvidenceTier::LocalVerified,
        availability_until: 200,
        evidence_until: 200,
        anchor_height: 10,
        anchor_block: [0x53; 32],
        metered_amount: 30,
        paid_amount: 30,
        refunded_amount: 10,
        terminal_code: WwmTerminalCode::Complete,
        signatures: BoundedList::<SignatureEntryV1, 3>::default(),
    };
    let settlement = WwmSettlementV1 {
        settlement_id: [0x54; 32],
        job_id: job.job_id,
        receipt_id: receipt.receipt_id,
        fund_profile_id,
        bucket: FundBucketTag::Job,
        prior_settlement_index: 0,
        paid_amount: 30,
        refunded_amount: 10,
        released_amount: 60,
        settled_height: 12,
        authority_epoch: 1,
        signature: BoundedBytes::new(b"TESTNET_FIXTURE_ONLY".to_vec()).unwrap(),
    };
    (ledger, job, receipt, settlement)
}

fn apply_wwm_action(ledger: &mut LumenLedger, height: u64, action: ActionV1) -> ApplyOutcome {
    let (tx, witnesses, _) = build_tx(height, vec![], vec![PAYER, GOV], vec![action], vec![]);
    ledger
        .apply_transaction(&ctx(height), &tx, &witnesses, &StubEngine, &AcceptAll)
        .unwrap()
}

fn neural_reporter_profile(
    profile_id: Hash32,
    operator_id: Hash32,
    control_marker: u8,
) -> CapabilityProfileV1 {
    CapabilityProfileV1 {
        profile_id,
        status: CapabilityStatus::Active,
        beneficial_control_root: [control_marker; 32],
        region_id: [control_marker.wrapping_add(1); 32],
        asn: u32::from(control_marker),
        provider_root: [control_marker.wrapping_add(2); 32],
        software_lineage_root: [control_marker.wrapping_add(3); 32],
        attestation_epoch: 1,
        attestation_expiry: 100,
        capability_bitmap: 1,
        selection_weight: 1,
        endpoint_root: [control_marker.wrapping_add(4); 32],
        staging_bytes: 1,
        capacity_bytes: 1,
        headroom_bytes: 1,
        operator_id,
        signing_key: [control_marker.wrapping_add(5); 32],
        reviewer_id: [control_marker.wrapping_add(6); 32],
        reviewer_signature: BoundedBytes::new(vec![control_marker]).unwrap(),
    }
}

fn install_neural_reporters(ledger: &mut LumenLedger, job: &mut WwmJobV1) -> (Hash32, [Hash32; 3]) {
    let set_id = [0x60; 32];
    let profile_ids = [[0x61; 32], [0x62; 32], [0x63; 32]];
    let executor_set = CapabilitySetV1 {
        set_id,
        prior_set_id: [0x5f; 32],
        epoch: 1,
        entries: BoundedList::new(vec![
            neural_reporter_profile(profile_ids[0], PAYER, 0x71),
            neural_reporter_profile(profile_ids[1], GOV, 0x72),
            neural_reporter_profile(profile_ids[2], EMERGENCY, 0x73),
        ])
        .unwrap(),
    };
    assert!(executor_set.validate());
    let registry = RegistryEpochVectorV1 {
        vector_id: [0x64; 32],
        executor_set_id: set_id,
        executor_epoch: 1,
        custodian_set_id: [0x65; 32],
        custodian_epoch: 1,
        fee_policy_id: [0x66; 32],
        fee_epoch: 1,
        fund_profile_id: job.fund_profile_id,
        fund_epoch: 1,
        service_directory_id: [0x67; 32],
        service_epoch: 1,
    };
    ledger.install_neural_oracle_fixture_for_test(&registry, &executor_set);
    job.selected_executor_ids = BoundedList::new(profile_ids.to_vec()).unwrap();
    (set_id, profile_ids)
}

#[test]
fn neural_l1_program_evaluates_with_exact_trinary_result() {
    let (mut ledger, _, _, _) = wwm_flow_fixture(WwmControlMode::Testnet);
    let issued_before = ledger.total_issued();
    let mut program = NeuralProgramV1 {
        program_id: [0; 32],
        input_width: 2,
        hidden_width: 2,
        output_width: 1,
        hidden_weights: BoundedBytes::new(vec![2, 0, 1, 2]).unwrap(),
        hidden_biases: BoundedBytes::new(vec![0, 0]).unwrap(),
        output_weights: BoundedBytes::new(vec![2, 0]).unwrap(),
        output_biases: BoundedBytes::new(vec![0]).unwrap(),
    };
    program.program_id = neural_program_id(&program);
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            10,
            ActionV1::RegisterNeuralProgram(program.clone())
        ),
        ApplyOutcome::Applied { .. }
    ));

    let query_id = [0x68; 32];
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            11,
            ActionV1::EvaluateNeuralProgram(EvaluateNeuralProgramV1 {
                query_id,
                program_id: program.program_id,
                requester: PAYER,
                input: BoundedBytes::new(vec![2, 0]).unwrap(),
            })
        ),
        ApplyOutcome::Applied { .. }
    ));
    let result = ledger.get_neural_oracle_result(&query_id).unwrap();
    assert_eq!(result.mode, NeuralOracleMode::L1Deterministic);
    assert_eq!(result.status, NeuralOracleStatus::Success);
    assert_eq!(result.source_id, program.program_id);
    assert_eq!(result.response.as_slice(), &[2]);
    assert!(result.signer_profile_ids.is_empty());
    assert_eq!(result.output_root, neural_output_root(&[2]));
    assert_eq!(ledger.total_issued(), issued_before);
    assert_eq!(ledger.emission_minted(), 0);
    assert!(ledger
        .finalized_object_proof(neural_result_key(&query_id))
        .verify());

    let (mut disabled, _, _, _) = wwm_flow_fixture(WwmControlMode::Disabled);
    assert!(matches!(
        apply_wwm_action(
            &mut disabled,
            10,
            ActionV1::RegisterNeuralProgram(program.clone())
        ),
        ApplyOutcome::Applied { .. }
    ));
    let disabled_query_id = [0x69; 32];
    assert!(matches!(
        apply_wwm_action(
            &mut disabled,
            11,
            ActionV1::EvaluateNeuralProgram(EvaluateNeuralProgramV1 {
                query_id: disabled_query_id,
                program_id: program.program_id,
                requester: PAYER,
                input: BoundedBytes::new(vec![2, 0]).unwrap(),
            })
        ),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
    assert!(disabled
        .get_neural_oracle_result(&disabled_query_id)
        .is_none());
}

#[test]
fn neural_wwm_quorum_preserves_raw_response_and_binds_receipt() {
    let (mut ledger, mut job, mut receipt, _) = wwm_flow_fixture(WwmControlMode::Testnet);
    let (executor_set_id, profile_ids) = install_neural_reporters(&mut ledger, &mut job);
    assert!(matches!(
        apply_wwm_action(&mut ledger, 10, ActionV1::OpenWwmJob(job.clone())),
        ApplyOutcome::Applied { .. }
    ));
    let query = NeuralOracleQueryV1 {
        query_id: job.job_id,
        job_id: job.job_id,
        requester: PAYER,
        executor_set_id,
        executor_set_epoch: 1,
        input_root: job.offchain_envelope_root,
        max_response_bytes: 128,
        threshold: 2,
        commit_deadline: 13,
        reveal_deadline: 18,
    };
    let mut single_reporter = query.clone();
    single_reporter.threshold = 1;
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            11,
            ActionV1::OpenNeuralOracleQuery(single_reporter)
        ),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            11,
            ActionV1::OpenNeuralOracleQuery(query.clone())
        ),
        ApplyOutcome::Applied { .. }
    ));

    let mut collision_program = NeuralProgramV1 {
        program_id: [0; 32],
        input_width: 1,
        hidden_width: 1,
        output_width: 1,
        hidden_weights: BoundedBytes::new(vec![2]).unwrap(),
        hidden_biases: BoundedBytes::new(vec![0]).unwrap(),
        output_weights: BoundedBytes::new(vec![2]).unwrap(),
        output_biases: BoundedBytes::new(vec![0]).unwrap(),
    };
    collision_program.program_id = neural_program_id(&collision_program);
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            11,
            ActionV1::RegisterNeuralProgram(collision_program.clone())
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            12,
            ActionV1::EvaluateNeuralProgram(EvaluateNeuralProgramV1 {
                query_id: job.job_id,
                program_id: collision_program.program_id,
                requester: PAYER,
                input: BoundedBytes::new(vec![2]).unwrap(),
            })
        ),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    let response = b"raw model bytes: no median, trim, or reinterpretation";
    let output_root = neural_output_root(response);
    let transcript_root = neural_transcript_root(response);
    let nonces = [[0x81; 32], [0x82; 32]];
    for (index, height) in [12, 13].into_iter().enumerate() {
        let commitment = neural_reply_commitment(
            &job.job_id,
            &profile_ids[index],
            &output_root,
            &transcript_root,
            &nonces[index],
        );
        assert!(matches!(
            apply_wwm_action(
                &mut ledger,
                height,
                ActionV1::CommitNeuralOracleReply(NeuralOracleCommitV1 {
                    query_id: job.job_id,
                    reporter_profile_id: profile_ids[index],
                    commitment,
                })
            ),
            ApplyOutcome::Applied { .. }
        ));
    }
    for (index, height) in [14, 15].into_iter().enumerate() {
        assert!(matches!(
            apply_wwm_action(
                &mut ledger,
                height,
                ActionV1::RevealNeuralOracleReply(NeuralOracleRevealV1 {
                    query_id: job.job_id,
                    reporter_profile_id: profile_ids[index],
                    response: BoundedBytes::new(response.to_vec()).unwrap(),
                    transcript_root,
                    nonce: nonces[index],
                })
            ),
            ApplyOutcome::Applied { .. }
        ));
    }

    let result = ledger.get_neural_oracle_result(&job.job_id).unwrap();
    assert_eq!(result.mode, NeuralOracleMode::WwmQuorum);
    assert_eq!(result.status, NeuralOracleStatus::Success);
    assert_eq!(result.response.as_slice(), response);
    assert_eq!(result.output_root, output_root);
    assert_eq!(result.transcript_root, transcript_root);
    assert_eq!(result.signer_profile_ids.as_slice(), &profile_ids[..2]);

    receipt.output_root = result.output_root;
    receipt.token_history_root = result.transcript_root;
    receipt.signer_ids = result.signer_profile_ids.clone();
    receipt.control_cluster_ids = BoundedList::new(vec![[0x91; 32], [0x92; 32]]).unwrap();
    receipt.evidence_tier = WwmEvidenceTier::MatchedQuorum;
    receipt.anchor_height = 16;
    receipt.signatures = BoundedList::new(
        profile_ids[..2]
            .iter()
            .map(|profile_id| SignatureEntryV1 {
                signer_id: *profile_id,
                signature: BoundedBytes::new(vec![1]).unwrap(),
            })
            .collect(),
    )
    .unwrap();
    assert!(matches!(
        apply_wwm_action(&mut ledger, 16, ActionV1::RecordWwmReceipt(receipt.clone())),
        ApplyOutcome::Applied { .. }
    ));
    let proof =
        ledger.finalized_object_proof(wwm_profile_key(WwmLeafKind::Receipt, &receipt.receipt_id));
    assert!(proof.verify());
    let crate::wwm::ResolutionValueV1::Present(stored) = proof.value else {
        panic!("receipt proof must contain the canonical receipt");
    };
    let stored = WwmReceiptV1::decode_canonical(stored.as_slice()).unwrap();
    assert_eq!(stored.output_root, result.output_root);
    assert_eq!(stored.token_history_root, result.transcript_root);
}

#[test]
fn neural_wwm_timeout_finalizes_explicit_no_quorum_receipt() {
    let (mut ledger, mut job, mut receipt, _) = wwm_flow_fixture(WwmControlMode::Testnet);
    let (executor_set_id, _) = install_neural_reporters(&mut ledger, &mut job);
    job.job_id = [0xa4; 32];
    job.offchain_envelope_root = [0xa5; 32];
    assert!(matches!(
        apply_wwm_action(&mut ledger, 10, ActionV1::OpenWwmJob(job.clone())),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            11,
            ActionV1::OpenNeuralOracleQuery(NeuralOracleQueryV1 {
                query_id: job.job_id,
                job_id: job.job_id,
                requester: PAYER,
                executor_set_id,
                executor_set_epoch: 1,
                input_root: job.offchain_envelope_root,
                max_response_bytes: 64,
                threshold: 2,
                commit_deadline: 12,
                reveal_deadline: 14,
            })
        ),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply_wwm_action(
            &mut ledger,
            15,
            ActionV1::FinalizeNeuralOracleQuery(FinalizeNeuralOracleQueryV1 {
                query_id: job.job_id,
            })
        ),
        ApplyOutcome::Applied { .. }
    ));

    let result = ledger.get_neural_oracle_result(&job.job_id).unwrap();
    assert_eq!(result.mode, NeuralOracleMode::WwmQuorum);
    assert_eq!(result.status, NeuralOracleStatus::NoQuorum);
    assert!(result.response.is_empty());
    assert!(result.signer_profile_ids.is_empty());
    assert_eq!(result.output_root, [0; 32]);
    assert_eq!(result.transcript_root, [0; 32]);

    receipt.receipt_id = [0xa6; 32];
    receipt.job_id = job.job_id;
    receipt.output_tokens = 0;
    receipt.output_root = [0; 32];
    receipt.token_history_root = [0; 32];
    receipt.signer_ids = BoundedList::default();
    receipt.control_cluster_ids = BoundedList::default();
    receipt.evidence_tier = WwmEvidenceTier::NoQuorum;
    receipt.anchor_height = 16;
    receipt.metered_amount = 0;
    receipt.paid_amount = 0;
    receipt.refunded_amount = job.reserved_amount;
    receipt.terminal_code = WwmTerminalCode::NoQuorum;
    receipt.signatures = BoundedList::default();
    assert!(matches!(
        apply_wwm_action(&mut ledger, 16, ActionV1::RecordWwmReceipt(receipt)),
        ApplyOutcome::Applied { .. }
    ));
}

#[test]
fn testnet_wwm_job_receipt_settlement_flow_is_insert_once_and_bound() {
    let (mut ledger, job, receipt, settlement) = wwm_flow_fixture(WwmControlMode::Testnet);
    assert!(matches!(
        apply_wwm_action(&mut ledger, 10, ActionV1::OpenWwmJob(job.clone())),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply_wwm_action(&mut ledger, 11, ActionV1::RecordWwmReceipt(receipt.clone())),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply_wwm_action(&mut ledger, 12, ActionV1::SettleWwmJob(settlement.clone())),
        ApplyOutcome::Applied { .. }
    ));
    for (kind, id) in [
        (WwmLeafKind::Job, job.job_id),
        (WwmLeafKind::Receipt, receipt.receipt_id),
        (WwmLeafKind::Settlement, settlement.settlement_id),
    ] {
        let proof = ledger.finalized_object_proof(wwm_profile_key(kind, &id));
        assert!(proof.verify());
        assert!(matches!(
            proof.value,
            crate::wwm::ResolutionValueV1::Present(_)
        ));
    }
    assert!(matches!(
        apply_wwm_action(&mut ledger, 13, ActionV1::OpenWwmJob(job)),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
}

#[test]
fn testnet_wwm_flow_rejects_disabled_wrong_capsule_job_and_receipt() {
    let (mut disabled, job, _, _) = wwm_flow_fixture(WwmControlMode::Disabled);
    assert!(matches!(
        apply_wwm_action(&mut disabled, 10, ActionV1::OpenWwmJob(job)),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    let (mut wrong_capsule, mut job, _, _) = wwm_flow_fixture(WwmControlMode::Testnet);
    job.capsule_id = [0xa1; 32];
    assert!(matches!(
        apply_wwm_action(&mut wrong_capsule, 10, ActionV1::OpenWwmJob(job)),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    let (mut ledger, job, mut receipt, mut settlement) = wwm_flow_fixture(WwmControlMode::Testnet);
    assert!(matches!(
        apply_wwm_action(&mut ledger, 10, ActionV1::OpenWwmJob(job)),
        ApplyOutcome::Applied { .. }
    ));
    receipt.job_id = [0xa2; 32];
    assert!(matches!(
        apply_wwm_action(&mut ledger, 11, ActionV1::RecordWwmReceipt(receipt)),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    let (mut ledger, job, receipt, _) = wwm_flow_fixture(WwmControlMode::Testnet);
    assert!(matches!(
        apply_wwm_action(&mut ledger, 10, ActionV1::OpenWwmJob(job)),
        ApplyOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply_wwm_action(&mut ledger, 11, ActionV1::RecordWwmReceipt(receipt)),
        ApplyOutcome::Applied { .. }
    ));
    settlement.receipt_id = [0xa3; 32];
    assert!(matches!(
        apply_wwm_action(&mut ledger, 12, ActionV1::SettleWwmJob(settlement)),
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Governance and emergency limits
// ---------------------------------------------------------------------------

#[test]
fn governance_requires_authority_delay_and_cannot_touch_controls() {
    let mut ledger = genesis();
    let target = param_key("noos.registry.jets.v1");
    let update = |activation: u64, key: Hash32| ActionV1::GovernanceRegistryUpdate {
        registry_key: key,
        new_value: BoundedBytes::new(vec![9, 9]).unwrap(),
        activation_height: activation,
    };

    // Without the governance authority signed: reject, roots unchanged.
    let before = ledger.roots();
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER], vec![update(100, target)], vec![]);
    let r = ledger.apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::GovernanceDenied);
    assert_roots_eq(&before, &ledger.roots());

    // With authority but an activation below the delay floor: reject.
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER, GOV], vec![update(3, target)], vec![]);
    let r = ledger.apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::GovernanceDenied);

    // Param update aimed at a feature-control key: reject even with authority
    // and delay (suite activation requires a hard fork).
    let control = param_key(&format!("{CONTROL_PREFIX}neural_lane"));
    let enable = ActionV1::GovernanceParamUpdate {
        param_key: control,
        new_value: BoundedBytes::new(FeatureControlV1 { enabled: 1 }.encode_canonical()).unwrap(),
        activation_height: 100,
    };
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER, GOV], vec![enable], vec![]);
    let r = ledger.apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::GovernanceDenied);

    // Valid: pending recorded, current unchanged until activation.
    let (txb, witb, _) = build_tx(
        2,
        vec![],
        vec![PAYER, GOV],
        vec![update(100, target)],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(out, ApplyOutcome::Applied { .. }));
    // Before activation: promoting at height 99 does nothing for this key.
    let d = ledger.activate_pending_params(99);
    assert!(d.is_empty());
    // At activation: promoted.
    let d = ledger.activate_pending_params(100);
    assert!(!d.is_empty());
}

#[test]
fn governance_cannot_lower_cap_below_issued_or_enable_genesis_schedule_overflow() {
    let mut ledger = genesis();
    ledger
        .apply_emission(1, &PROPOSER, &WITNESS_POOL, &TREASURY)
        .unwrap();
    let mut below_issued = IssuanceParamsV1::testnet_fixture();
    below_issued.initial_per_height = 0;
    below_issued.max_supply = ledger.total_issued() - 1;
    let update = ActionV1::GovernanceParamUpdate {
        param_key: param_key(PARAM_ISSUANCE),
        new_value: BoundedBytes::new(below_issued.encode_canonical()).unwrap(),
        activation_height: 200_000,
    };
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER, GOV], vec![update], vec![]);
    assert_eq!(
        ledger
            .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
            .unwrap_err(),
        RejectReason::GovernanceDenied
    );

    let mut schedule_overflow = IssuanceParamsV1::testnet_fixture();
    schedule_overflow.max_supply = schedule_overflow.total_scheduled().unwrap();
    let update = ActionV1::GovernanceParamUpdate {
        param_key: param_key(PARAM_ISSUANCE),
        new_value: BoundedBytes::new(schedule_overflow.encode_canonical()).unwrap(),
        activation_height: 200_000,
    };
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER, GOV], vec![update], vec![]);
    assert_eq!(
        ledger
            .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
            .unwrap_err(),
        RejectReason::GovernanceDenied
    );
}

#[test]
fn issuance_update_is_rechecked_against_supply_at_activation() {
    let mut ledger = genesis();
    let mut candidate = IssuanceParamsV1::testnet_fixture();
    candidate.initial_per_height = 1;
    candidate.max_supply = ledger
        .genesis_issued()
        .checked_add(candidate.total_scheduled().unwrap())
        .unwrap();
    let update = ActionV1::GovernanceParamUpdate {
        param_key: param_key(PARAM_ISSUANCE),
        new_value: BoundedBytes::new(candidate.encode_canonical()).unwrap(),
        activation_height: 100,
    };
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER, GOV], vec![update], vec![]);
    assert!(ledger
        .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
        .is_ok());

    ledger
        .apply_emission(50, &PROPOSER, &WITNESS_POOL, &TREASURY)
        .unwrap();
    assert!(ledger.activate_pending_params(100).is_empty());
    assert_ne!(ledger.issuance_params().unwrap(), candidate);
}

#[test]
fn emergency_can_only_disable_and_quarantine() {
    let mut ledger = genesis();
    let obj = create_object(&mut ledger, 1, OK_CODE);
    let control = param_key(&format!("{CONTROL_PREFIX}neural_lane"));

    // Emergency without authority: reject.
    let (txb, witb, _) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![ActionV1::EmergencyDisable {
            control_key: control,
        }],
        vec![],
    );
    let r = ledger.apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::GovernanceDenied);

    // With authority: disable applies (idempotent risk reduction).
    let (txb, witb, _) = build_tx(
        2,
        vec![],
        vec![PAYER, EMERGENCY],
        vec![ActionV1::EmergencyDisable {
            control_key: control,
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(out, ApplyOutcome::Applied { .. }));

    // Quarantine the object, then calls against it REJECT pre-reservation.
    let (txb, witb, _) = build_tx(
        3,
        vec![],
        vec![PAYER, EMERGENCY],
        vec![ActionV1::EmergencyQuarantine { object_id: obj }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(3), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(out, ApplyOutcome::Applied { .. }));
    assert!(ledger.get_object(&obj).unwrap().flags & ObjectV1::FLAG_QUARANTINED != 0);

    let before = ledger.roots();
    let (txb, witb, _) = build_tx(
        4,
        vec![],
        vec![PAYER],
        vec![ActionV1::CallObject {
            object_id: obj,
            input: BoundedBytes::new(vec![1]).unwrap(),
        }],
        vec![],
    );
    let r = ledger.apply_transaction(&ctx(4), &txb, &witb, &StubEngine, &AcceptAll);
    assert_eq!(r.unwrap_err(), RejectReason::ObjectQuarantined);
    assert_roots_eq(&before, &ledger.roots());
}

// ---------------------------------------------------------------------------
// Contract calls and capabilities
// ---------------------------------------------------------------------------

#[test]
fn contract_call_updates_object_and_charges_grain_steps() {
    let mut ledger = genesis();
    let obj = create_object(&mut ledger, 1, OK_CODE);
    let before_version = ledger.get_object(&obj).unwrap().object_version;

    let (txb, witb, _) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![ActionV1::CallObject {
            object_id: obj,
            input: BoundedBytes::new(vec![7]).unwrap(),
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    let ApplyOutcome::Applied { receipt, .. } = out else {
        panic!("call must apply");
    };
    assert_eq!(receipt.resources_used.grain_steps, 100);
    assert!(receipt.fee_charged > 0);
    let obj_after = ledger.get_object(&obj).unwrap();
    assert_eq!(obj_after.object_version, before_version + 1);

    // Undeclared access: same call WITHOUT the access-list entry traps.
    // Build manually: build_tx auto-declares, so strip the list.
    let action = ActionV1::CallObject {
        object_id: obj,
        input: BoundedBytes::new(vec![8]).unwrap(),
    };
    let lock_reveals: BoundedList<BoundedBytes<4096>, 256> = BoundedList::new(vec![]).unwrap();
    let tx = TransactionV1 {
        chain_id: CHAIN,
        format_version: 1,
        expiry_height: 20,
        fee_payer: PAYER,
        fee_authorization: OptionalObject(None),
        resource_limits: limits(),
        note_inputs: BoundedList::new(vec![]).unwrap(),
        account_inputs: BoundedList::new(vec![PAYER]).unwrap(),
        object_access_list: BoundedList::new(vec![]).unwrap(),
        actions: BoundedList::new(vec![BoundedBytes::new(action.encode_canonical()).unwrap()])
            .unwrap(),
        outputs: BoundedList::new(vec![]).unwrap(),
        evidence_refs: BoundedList::new(vec![]).unwrap(),
        witness_root: witness_root(&lock_reveals),
    };
    let id = txid(&tx);
    let wit = TransactionWitnessesV1 {
        intents: BoundedList::new(vec![SignedIntentV1 {
            tx_commitment: id,
            signer_scope: 0,
            capability_ref: OptionalHash32(None),
            signature_suite: 1,
            signature: BoundedBytes::new(vec![0xAB; 64]).unwrap(),
        }])
        .unwrap(),
        lock_reveals,
    };
    let out = ledger
        .apply_transaction(
            &ctx(3),
            &tx.encode_canonical(),
            &wit.encode_canonical(),
            &StubEngine,
            &AcceptAll,
        )
        .unwrap();
    let ApplyOutcome::Failed { code, .. } = out else {
        panic!("undeclared access must trap");
    };
    assert_eq!(code, FailCode::UndeclaredAccess);
}

#[test]
fn capability_gate_enforces_issuer_budget_and_expiry() {
    let mut ledger = genesis();
    let agent = crate::objects::AgentIdV1 {
        agent_id: [0x77; 32],
        genesis_manifest_root: [0; 32],
        controller_policy_root: [0; 32],
        active_key_root: [0; 32],
        model_refs_root: [0; 32],
        host_refs_root: [0; 32],
        capability_root: [0; 32],
        recovery_root: [0; 32],
        agent_version: 1,
    };
    let grant = CapabilityGrantV1 {
        grant_id: [0x88; 32],
        issuer: PAYER,
        subject_agent: agent.agent_id,
        allowed_action_schema_root: [0; 32],
        object_scope_root: [0; 32],
        per_action_limit: 500,
        cumulative_budget: 800,
        expiry_height: 50,
        delegation_depth: 1,
        revocation_nonce: 0,
    };
    // Register agent + grant (issuer PAYER is signed).
    let (txb, witb, _) = build_tx(
        2,
        vec![],
        vec![PAYER],
        vec![
            ActionV1::RegisterAgent {
                agent: agent.clone(),
            },
            ActionV1::GrantCapability {
                grant: grant.clone(),
            },
        ],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(out, ApplyOutcome::Applied { .. }));

    let intent = |budget: u128, deadline: u64, nonce: u64| IntentV1 {
        agent_id: agent.agent_id,
        action_type: 1,
        canonical_arguments: BoundedBytes::new(vec![]).unwrap(),
        finalized_prestate_root: [0; 32],
        expected_postcondition_root: [0; 32],
        budget,
        deadline,
        capability_ref: grant.grant_id,
        nonce,
    };

    // Budget over per-action limit: fails (policy gate).
    let (txb, witb, _) = build_tx(
        3,
        vec![],
        vec![PAYER],
        vec![ActionV1::SubmitIntent {
            intent: intent(600, 50, 0),
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(3), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(
        out,
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    // Two valid intents of 500 + 400 > 800: the second breaks the cumulative
    // budget after the first consumed it.
    let (txb, witb, _) = build_tx(
        4,
        vec![],
        vec![PAYER],
        vec![ActionV1::SubmitIntent {
            intent: intent(500, 50, 1),
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(4), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(out, ApplyOutcome::Applied { .. }));
    let (txb, witb, _) = build_tx(
        5,
        vec![],
        vec![PAYER],
        vec![ActionV1::SubmitIntent {
            intent: intent(400, 50, 2),
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(5), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(
        out,
        ApplyOutcome::Failed {
            code: FailCode::InsufficientBalance,
            ..
        }
    ));

    // Past expiry: fails.
    let (txb, witb, _) = build_tx(
        60,
        vec![],
        vec![PAYER],
        vec![ActionV1::SubmitIntent {
            intent: intent(1, 100, 3),
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(60), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(
        out,
        ApplyOutcome::Failed {
            code: FailCode::PostconditionFailed,
            ..
        }
    ));

    // Revocation by a non-issuer rejects; by the issuer applies.
    let (txb, witb, _) = build_tx(
        6,
        vec![],
        vec![GOV],
        vec![ActionV1::RevokeCapability {
            grant_id: grant.grant_id,
        }],
        vec![],
    );
    // GOV is not the issuer AND not the fee payer -> fee payer missing.
    let r = ledger.apply_transaction(&ctx(6), &txb, &witb, &StubEngine, &AcceptAll);
    assert!(r.is_err());
    let (txb, witb, _) = build_tx(
        6,
        vec![],
        vec![PAYER],
        vec![ActionV1::RevokeCapability {
            grant_id: grant.grant_id,
        }],
        vec![],
    );
    let out = ledger
        .apply_transaction(&ctx(6), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    assert!(matches!(out, ApplyOutcome::Applied { .. }));
}

// ---------------------------------------------------------------------------
// Fee edges + controller integration
// ---------------------------------------------------------------------------

#[test]
fn fee_reservation_and_refund_never_overcharge() {
    let mut ledger = genesis();
    let before = ledger.balance(&PAYER, &NOOS_ASSET);
    let (txb, witb, _) = build_tx(2, vec![], vec![PAYER], vec![], vec![]);
    let out = ledger
        .apply_transaction(&ctx(2), &txb, &witb, &StubEngine, &AcceptAll)
        .unwrap();
    let ApplyOutcome::Applied { receipt, .. } = out else {
        panic!()
    };
    // The declared maximum fee is far above the measured fee.
    let params = FeeStateV1::testnet_fixture();
    let max_fee = fees::fee(&params.prices(), &fees::usage_from_resources(&limits())).unwrap();
    assert!(
        receipt.fee_charged < max_fee,
        "actual must be below the reservation"
    );
    assert_eq!(
        before - ledger.balance(&PAYER, &NOOS_ASSET),
        receipt.fee_charged
    );
}

#[test]
fn end_block_controller_updates_prices_in_params_root() {
    let mut ledger = genesis();
    let before = ledger.roots().params_root;
    let prices_before = ledger.fee_state().unwrap().prices();
    let cap = FeeParamsV1::testnet_fixture().capacity();
    // Full block on B, empty elsewhere.
    let usage = [cap[0], 0, 0, 0, 0];
    let delta = ledger.end_block_fee_update(&usage).unwrap();
    assert!(!delta.is_empty());
    assert_ne!(
        ledger.roots().params_root,
        before,
        "prices live under params_root"
    );
    let prices_after = ledger.fee_state().unwrap().prices();
    assert!(prices_after[0] > prices_before[0]);
    assert!(prices_after[1] <= prices_before[1]);
}

// ---------------------------------------------------------------------------
// LumenState projection
// ---------------------------------------------------------------------------

#[test]
fn lumen_state_object_carries_the_six_roots() {
    let ledger = genesis();
    let roots = ledger.roots();
    let state = crate::objects::LumenStateV1 {
        notes_root: roots.notes_root,
        nullifiers_root: roots.nullifiers_root,
        accounts_root: roots.accounts_root,
        objects_root: roots.objects_root,
        receipts_root: roots.receipts_root,
        params_root: roots.params_root,
    };
    let bytes = state.encode_canonical();
    use noos_codec::NoosDecode;
    assert_eq!(
        crate::objects::LumenStateV1::decode_canonical(&bytes).unwrap(),
        state
    );
    // Fresh ledger: notes/nullifiers/objects/receipts are the empty root.
    let empty = crate::smt::empty_root(crate::smt::DEPTH);
    assert_eq!(roots.notes_root, empty);
    assert_eq!(roots.nullifiers_root, empty);
    assert_eq!(roots.objects_root, empty);
    assert_eq!(roots.receipts_root, empty);
    assert_ne!(roots.accounts_root, empty);
    assert_ne!(roots.params_root, empty);
}

// Helper used by the rejection test to mutate a decoded transaction.
trait DecodeHelper {
    fn decode_canonical_helper(bytes: &[u8]) -> TransactionV1;
}
impl DecodeHelper for TransactionV1 {
    fn decode_canonical_helper(bytes: &[u8]) -> TransactionV1 {
        use noos_codec::NoosDecode;
        TransactionV1::decode_canonical(bytes).unwrap()
    }
}
