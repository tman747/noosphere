//! Cross-crate settlement integration: an NEL dispute lost by bisection
//! slashes the worker bond and refunds the requester through the existing
//! noos-work-loom escrow/dispute/quarantine lifecycle, with activation
//! witnesses held in noos-hearth custody gating the challenge clock
//! (availability precedes challenge time).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_hearth::{admit_custody, ContentShard, CustodyRole, CustodySet, HearthError};
use noos_nel::inference::{
    ops, run_bisection, run_lane, token_history_root, LaneRun, MiniModel, Tamper,
};
use noos_nel::{distribute_executor_slash, FreivaldsProfile, Verdict};
use noos_work_loom::{
    artifact_id, domain_hash, domains, work_commit, Assurance, AvailabilityCertificate,
    AvailabilityPolicy, Correctness, Delivery, DeliveryRule, DemandClassification, DisputeVerdict,
    EvaluatorPolicy, JobClass, JobState, LoomError, OpenJob, ProofProfile, Quality, Registries,
    RegistryStatus, ResourceVector, SettlementAccounts, SettlementSplit, WorkClass, WorkReceipt,
    WorkerCommit, WorkerProfile,
};
use std::collections::BTreeSet;

type Hash32 = [u8; 32];

const REQUESTER: Hash32 = [1; 32];
const CHEATER: Hash32 = [2; 32];
const HONEST_WORKER: Hash32 = [9; 32];
const CHALLENGER: Hash32 = [6; 32];
const WATCH_POOL: Hash32 = [5; 32];
const EVALUATOR: Hash32 = [4; 32];
const BURN_SINK: Hash32 = [0xEE; 32];
const CHEATER_PROFILE: u32 = 2;
const HONEST_PROFILE: u32 = 1;

fn h(byte: u8) -> Hash32 {
    [byte; 32]
}

fn registries() -> Registries {
    let mut r = Registries::default();
    r.register_work_class(WorkClass {
        id: 1,
        relation_root: h(10),
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    for id in [HONEST_PROFILE, CHEATER_PROFILE] {
        r.register_worker_profile(WorkerProfile {
            id,
            source_root: h(11),
            compiler_toolchain_root: h(12),
            machine_code_root: h(13u8.wrapping_add(id as u8)),
            hardware_root: h(14),
            status: RegistryStatus::Enabled,
        })
        .unwrap();
    }
    r.register_proof_profile(ProofProfile {
        id: 1,
        verifier_root: h(15),
        max_proof_bytes: 1_024,
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r.register_availability_policy(AvailabilityPolicy {
        id: 1,
        min_retrievers: 2,
        retention_blocks: 100,
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r.register_evaluator_policy(EvaluatorPolicy {
        id: 1,
        policy_root: h(16),
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r.register_job_class(JobClass {
        id: 1,
        work_class_id: 1,
        program_or_relation_root: h(10),
        input_schema_root: h(17),
        output_schema_root: h(18),
        numeric_profile_root: noos_nel::inference::mini_profile_id(),
        allowed_worker_profiles: BTreeSet::from([HONEST_PROFILE, CHEATER_PROFILE]),
        assurance: Assurance::V2,
        confidentiality_flags: 0,
        proof_profile_id: 1,
        evaluator_policy_id: 1,
        availability_policy_id: 1,
        max_resources: ResourceVector {
            bytes: 1_000,
            compute: 1_000,
            verification: 1_000,
            reads: 1_000,
            da_bytes: 1_000,
        },
        challenge_period: 10,
        minimum_worker_bond: 50,
        slashable: true,
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r
}

fn loom() -> noos_work_loom::WorkLoom {
    let mut loom = noos_work_loom::WorkLoom::new(registries());
    for account in [REQUESTER, CHEATER, HONEST_WORKER, CHALLENGER] {
        loom.credit_genesis(account, 1_000).unwrap();
    }
    loom
}

const PROMPT: [u32; 4] = [1, 2, 3, 4];

fn open_job(model: &MiniModel, nonce: u64) -> OpenJob {
    OpenJob {
        requester: REQUESTER,
        refund_account: REQUESTER,
        class_id: 1,
        required_assurance: Assurance::V2,
        input_root: token_history_root(&PROMPT),
        model_or_program_root: model.weight_root(),
        delivery_pubkey: h(22),
        delivery_rule: DeliveryRule::Availability,
        settlement_accounts: SettlementAccounts {
            verifier: WATCH_POOL,
            evaluator: EVALUATOR,
            da_provider: BURN_SINK,
        },
        max_resources: ResourceVector {
            bytes: 100,
            compute: 100,
            verification: 100,
            reads: 100,
            da_bytes: 100,
        },
        fee_escrow: 80,
        evaluator_escrow: 20,
        opened_height: 10,
        commit_deadline: 20,
        submit_deadline: 40,
        expiry_height: 60,
        nonce,
    }
}

fn commit(job_id: Hash32, worker: Hash32, profile: u32, bond: u128) -> WorkerCommit {
    WorkerCommit {
        job_id,
        worker,
        implementation_profile: profile,
        input_root: token_history_root(&PROMPT),
        worker_nonce_commitment: h(30),
        availability_plan_root: h(31),
        bond,
        committed_height: 15,
    }
}

/// Build a valid receipt whose evidence root is the run's chunk trace root
/// and whose artifact is the generated token stream.
fn receipt_for_run(
    run: &LaneRun,
    job_id: Hash32,
    commit_hash: Hash32,
    challenge: Hash32,
    profile: u32,
    nullifier: Hash32,
) -> WorkReceipt {
    let token_bytes: Vec<u8> = run.tokens.iter().flat_map(|t| t.to_le_bytes()).collect();
    let artifact = artifact_id(b"tensor:u32le:tokens", &token_bytes);
    let evidence = run.chunk_trace_root();
    let mut r = WorkReceipt {
        receipt_id: [0; 32],
        job_id,
        worker_commit_hash: commit_hash,
        challenge,
        artifact_id: artifact,
        work_commit: work_commit(&challenge, &artifact, profile, &evidence),
        output_commitment: *run.states.last().unwrap(),
        encrypted_delivery_commitment: h(33),
        execution_evidence_root: evidence,
        proof_profile_id: 1,
        proof_bytes_or_blob_root: h(35),
        availability_root: h(36),
        resource_measurement: ResourceVector {
            bytes: 5,
            compute: 10,
            verification: 2,
            reads: 3,
            da_bytes: 4,
        },
        nullifier,
        worker_signature: [7; 64],
        correctness: Correctness::Verified,
        external_demand: DemandClassification::Unknown,
        delivery: Delivery::Committed,
        quality: Quality::NotEvaluated,
    };
    // receipt_id is the frozen public law over the public domain constants.
    r.receipt_id = domain_hash(
        domains::RECEIPT_ID,
        &[
            &r.job_id,
            &r.worker_commit_hash,
            &r.challenge,
            &r.artifact_id,
            &r.output_commitment,
            &r.encrypted_delivery_commitment,
            &r.execution_evidence_root,
            &r.nullifier,
        ],
    );
    r
}

/// Erasure-shard the run's activation witness bytes into hearth custody:
/// 4 data + 2 parity shards under the evidence root.
fn custody_for_run(run: &LaneRun, corrupt_data_shards: bool) -> (CustodySet, bool) {
    let mut witness = Vec::new();
    for step in &run.steps {
        for layer in &step.layer_outputs {
            witness.extend(layer.iter().map(|&x| x.cast_unsigned()));
        }
    }
    let root = run.chunk_trace_root();
    let mut set = CustodySet::default();
    let piece = witness.len().div_ceil(4).max(1);
    for index in 0u16..6 {
        // Parity shards (indices 4,5) reuse data bytes in this fixture; the
        // custody ledger tracks placement and corruption, not coding math.
        let slice_index = usize::from(index % 4);
        let start = slice_index * piece;
        let end = witness.len().min(start + piece);
        let bytes = &witness[start..end];
        let mut body = vec![u8::try_from(index).unwrap()];
        body.extend(bytes);
        admit_custody(9_500, CustodyRole::StatefulProduction, false).unwrap();
        set.insert(ContentShard {
            artifact_root: root,
            shard_index: index,
            data_shards: 4,
            parity_shards: 2,
            bytes_root: noos_nel::domain_hash("NOOS/NEL/WITNESS/SHARD/V1", &body),
            holder_hearth: h(0x40u8.wrapping_add(index as u8)),
        })
        .unwrap();
    }
    if corrupt_data_shards {
        // Three corrupted shards leave 3 < 4 data shards: unreconstructible.
        for index in 0u16..3 {
            let err = set.mark_corrupt(root, index, h(0xDD)).unwrap_err();
            assert_eq!(err, HearthError::CorruptShardRejected);
        }
    }
    let ok = set.reconstructible(root);
    (set, ok)
}

fn availability(run: &LaneRun) -> AvailabilityCertificate {
    AvailabilityCertificate {
        evidence_root: run.chunk_trace_root(),
        availability_root: h(36),
        retriever_count: 2,
        finalized_height: 35,
    }
}

#[test]
fn lost_bisection_slashes_worker_bond_refunds_requester_and_quarantines_profile() {
    let model = MiniModel::deterministic();
    let mut l = loom();

    // The cheating executor corrupts one QKV accumulator mid-stream and
    // propagates consistently; its claims look internally coherent.
    let tamper = Tamper {
        position: 5,
        layer: 1,
        op: ops::QKV,
        delta: 12_345,
    };
    let job = open_job(&model, 71);
    let id = l.open_job(job).unwrap();
    let chash = l
        .commit_worker(commit(id, CHEATER, CHEATER_PROFILE, 100))
        .unwrap();
    let challenge = l.assign_finalized_challenge(id, h(99), h(98), 16).unwrap();
    let claimed = run_lane(&model, id, &PROMPT, 8, Some(&tamper)).unwrap();
    l.submit_receipt(
        receipt_for_run(&claimed, id, chash, challenge, CHEATER_PROFILE, h(71)),
        30,
    )
    .unwrap();

    // Witness custody is reconstructible, so the challenge clock may start.
    let (_set, reconstructible) = custody_for_run(&claimed, false);
    assert!(reconstructible);
    l.finalize_availability(id, availability(&claimed)).unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Challengeable);

    // The challenger recomputes and sees a different committed trace root:
    // the corruption here is output-preserving (the tampered Q-slice never
    // reaches KV and greedy re-converges), yet the executor still committed
    // a fraudulent C32 surface — claim fraud is slashable even when the
    // token stream happens to match.
    let referee = run_lane(&model, id, &PROMPT, 8, None).unwrap();
    assert_ne!(referee.chunk_trace_root(), claimed.chunk_trace_root());
    assert_ne!(&referee.states[6], &claimed.states[6], "interior S_t lies");
    l.open_dispute(id, CHALLENGER, 40, referee.chunk_trace_root(), 36)
        .unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Disputed);

    // The NEL bisection isolates the exact corrupted GEMM leaf.
    let report =
        run_bisection(&model, &referee, &claimed, FreivaldsProfile::StandardReps2).unwrap();
    assert_eq!(report.verdict, Verdict::ExecutorFault);
    assert_eq!((report.position, report.layer, report.op), (5, 1, ops::QKV));

    // Settlement: the worker bond is slashed per the lane's split law and
    // the requester escrow is refunded in full.
    let split = distribute_executor_slash(100);
    assert_eq!(split.challenger + split.watch_pool + split.burn, 100);
    l.resolve_dispute(
        id,
        DisputeVerdict::WorkerFault,
        SettlementSplit {
            worker: u128::from(split.challenger),
            verifier: u128::from(split.watch_pool),
            evaluator: 0,
            da_provider: u128::from(split.burn),
        },
        SettlementAccounts {
            verifier: WATCH_POOL,
            evaluator: EVALUATOR,
            da_provider: BURN_SINK,
        },
    )
    .unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Rejected);
    assert_eq!(
        l.job(&id).unwrap().receipt.as_ref().unwrap().correctness,
        Correctness::Rejected
    );
    assert_eq!(l.balance(&REQUESTER), 1_000, "escrow refunded in full");
    assert_eq!(l.balance(&CHEATER), 900, "bond slashed");
    assert_eq!(
        l.balance(&CHALLENGER),
        1_000 + u128::from(split.challenger),
        "challenger bond returned plus slash share"
    );
    assert_eq!(l.balance(&WATCH_POOL), u128::from(split.watch_pool));
    assert_eq!(l.balance(&BURN_SINK), 0, "burn share never lands anywhere");
    assert_eq!(l.burned(), u128::from(split.burn));
    l.assert_conserved().unwrap();

    // Quarantine the faulty implementation profile: new commits under it
    // reject; the independent profile keeps working.
    l.quarantine_profile(CHEATER_PROFILE).unwrap();
    let job_b = open_job(&model, 72);
    let id_b = l.open_job(job_b).unwrap();
    assert_eq!(
        l.commit_worker(commit(id_b, CHEATER, CHEATER_PROFILE, 100)),
        Err(LoomError::ProfileQuarantined)
    );
    assert!(l
        .commit_worker(commit(id_b, HONEST_WORKER, HONEST_PROFILE, 60))
        .is_ok());
}

#[test]
fn honest_executor_survives_a_frivolous_dispute_and_settles() {
    let model = MiniModel::deterministic();
    let mut l = loom();
    let id = l.open_job(open_job(&model, 81)).unwrap();
    let chash = l
        .commit_worker(commit(id, HONEST_WORKER, HONEST_PROFILE, 60))
        .unwrap();
    let challenge = l.assign_finalized_challenge(id, h(99), h(98), 16).unwrap();
    let run = run_lane(&model, id, &PROMPT, 8, None).unwrap();
    l.submit_receipt(
        receipt_for_run(&run, id, chash, challenge, HONEST_PROFILE, h(81)),
        30,
    )
    .unwrap();
    let (_set, reconstructible) = custody_for_run(&run, false);
    assert!(reconstructible);
    l.finalize_availability(id, availability(&run)).unwrap();

    // A frivolous challenger recomputes... the same grid.
    let referee = run_lane(&model, id, &PROMPT, 8, None).unwrap();
    l.open_dispute(id, CHALLENGER, 40, referee.chunk_trace_root(), 36)
        .unwrap();
    let report = run_bisection(&model, &referee, &run, FreivaldsProfile::StandardReps2).unwrap();
    assert_eq!(report.verdict, Verdict::ChallengerFault);
    assert_eq!(report.rounds, 0);

    // Upheld: the job returns to its window and settles normally.
    l.resolve_dispute(
        id,
        DisputeVerdict::WorkerUpheld,
        SettlementSplit {
            worker: 0,
            verifier: 0,
            evaluator: 0,
            da_provider: 0,
        },
        SettlementAccounts {
            verifier: WATCH_POOL,
            evaluator: EVALUATOR,
            da_provider: BURN_SINK,
        },
    )
    .unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Challengeable);
    l.settle(
        id,
        46,
        SettlementSplit {
            worker: 70,
            verifier: 10,
            evaluator: 10,
            da_provider: 10,
        },
        SettlementAccounts {
            verifier: WATCH_POOL,
            evaluator: EVALUATOR,
            da_provider: BURN_SINK,
        },
    )
    .unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Settled);
    assert_eq!(l.balance(&HONEST_WORKER), 1_070, "pay plus bond back");
    assert_eq!(l.balance(&CHALLENGER), 1_000, "frivolous bond returned");
    assert_eq!(l.balance(&REQUESTER), 900, "escrow spent on delivery");
    l.assert_conserved().unwrap();
}

#[test]
fn falsifier_unreconstructible_witness_custody_never_starts_the_challenge_clock() {
    let model = MiniModel::deterministic();
    let mut l = loom();
    let id = l.open_job(open_job(&model, 91)).unwrap();
    let chash = l
        .commit_worker(commit(id, HONEST_WORKER, HONEST_PROFILE, 60))
        .unwrap();
    let challenge = l.assign_finalized_challenge(id, h(99), h(98), 16).unwrap();
    let run = run_lane(&model, id, &PROMPT, 8, None).unwrap();
    l.submit_receipt(
        receipt_for_run(&run, id, chash, challenge, HONEST_PROFILE, h(91)),
        30,
    )
    .unwrap();
    // Corrupted custody: the witness set cannot be rebuilt, so no
    // availability certificate exists and the clock must not start.
    let (_set, reconstructible) = custody_for_run(&run, true);
    assert!(!reconstructible, "corrupted custody must not certify");
    assert_eq!(l.job(&id).unwrap().challenge_start, None);
    assert_eq!(
        l.open_dispute(id, CHALLENGER, 40, run.chunk_trace_root(), 36),
        Err(LoomError::InvalidState),
        "no availability, no dispute clock (availability precedes challenge)"
    );
    l.assert_conserved().unwrap();
}
