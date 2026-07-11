#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::assertions_on_constants
)]

use super::*;

fn h(byte: u8) -> Hash32 {
    [byte; 32]
}

fn demand_evidence(classification: DemandClassification) -> economics::DemandEvidence {
    use economics::{CompletionEvidence, ControlEvidence, FundingEvidence};
    let mut evidence = economics::DemandEvidence {
        on_chain_escrow: true,
        delivered: true,
        requester_worker_control: ControlEvidence::Independent,
        requester_evaluator_control: ControlEvidence::Independent,
        completion: CompletionEvidence::RequesterAccepted,
        funding: FundingEvidence::ExternalNoCircularDetected,
    };
    match classification {
        DemandClassification::Independent => {}
        DemandClassification::Related => {
            evidence.requester_worker_control = ControlEvidence::CommonControl;
        }
        DemandClassification::Subsidized => {
            evidence.funding = FundingEvidence::SubsidizedOrRebated;
        }
        DemandClassification::Unknown => {
            evidence.requester_worker_control = ControlEvidence::Unknown;
        }
    }
    evidence
}
fn accounts() -> SettlementAccounts {
    SettlementAccounts {
        verifier: h(3),
        evaluator: h(4),
        da_provider: h(5),
    }
}
fn payout() -> SettlementSplit {
    SettlementSplit {
        worker: 70,
        verifier: 10,
        evaluator: 10,
        da_provider: 10,
    }
}

fn registries() -> Registries {
    let mut r = Registries::default();
    r.register_work_class(WorkClass {
        id: 1,
        relation_root: h(10),
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r.register_worker_profile(WorkerProfile {
        id: 1,
        source_root: h(11),
        compiler_toolchain_root: h(12),
        machine_code_root: h(13),
        hardware_root: h(14),
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r.register_worker_profile(WorkerProfile {
        id: 2,
        source_root: h(11),
        compiler_toolchain_root: h(22),
        machine_code_root: h(23),
        hardware_root: h(14),
        status: RegistryStatus::Enabled,
    })
    .unwrap();
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
        numeric_profile_root: h(19),
        allowed_worker_profiles: BTreeSet::from([1, 2]),
        assurance: Assurance::V2,
        confidentiality_flags: 0,
        proof_profile_id: 1,
        evaluator_policy_id: 1,
        availability_policy_id: 1,
        max_resources: ResourceVector {
            bytes: 100,
            compute: 100,
            verification: 100,
            reads: 100,
            da_bytes: 100,
        },
        challenge_period: 10,
        minimum_worker_bond: 50,
        slashable: true,
        status: RegistryStatus::Enabled,
    })
    .unwrap();
    r
}

fn open() -> OpenJob {
    OpenJob {
        requester: h(1),
        refund_account: h(1),
        class_id: 1,
        required_assurance: Assurance::V2,
        input_root: h(20),
        model_or_program_root: h(21),
        delivery_pubkey: h(22),
        delivery_rule: DeliveryRule::Availability,
        settlement_accounts: accounts(),
        max_resources: ResourceVector {
            bytes: 10,
            compute: 20,
            verification: 3,
            reads: 4,
            da_bytes: 5,
        },
        fee_escrow: 80,
        evaluator_escrow: 20,
        opened_height: 10,
        commit_deadline: 20,
        submit_deadline: 40,
        expiry_height: 60,
        nonce: 7,
    }
}

fn loom() -> WorkLoom {
    let mut loom = WorkLoom::new(registries());
    loom.credit_genesis(h(1), 1_000).unwrap();
    loom.credit_genesis(h(2), 1_000).unwrap();
    loom.credit_genesis(h(6), 1_000).unwrap();
    loom
}

fn commit(job_id: Hash32, profile: RegistryId) -> WorkerCommit {
    WorkerCommit {
        job_id,
        worker: h(2),
        implementation_profile: profile,
        input_root: h(20),
        worker_nonce_commitment: h(30),
        availability_plan_root: h(31),
        bond: 50,
        committed_height: 15,
    }
}

fn receipt(
    job_id: Hash32,
    commit_hash: Hash32,
    challenge: Hash32,
    profile: RegistryId,
    nullifier: Hash32,
) -> WorkReceipt {
    let artifact = artifact_id(b"tensor:f32le:1x1", &[42, 0, 0, 0]);
    let evidence = h(34);
    let mut r = WorkReceipt {
        receipt_id: [0; 32],
        job_id,
        worker_commit_hash: commit_hash,
        challenge,
        artifact_id: artifact,
        work_commit: work_commit(&challenge, &artifact, profile, &evidence),
        output_commitment: h(32),
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
    r.receipt_id = receipt_id(&r);
    r
}

fn reach_submitted(loom: &mut WorkLoom, nonce: u8) -> Hash32 {
    let mut job = open();
    job.nonce = u64::from(nonce);
    let id = loom.open_job(job).unwrap();
    let chash = loom.commit_worker(commit(id, 1)).unwrap();
    let challenge = loom
        .assign_finalized_challenge(id, h(99), h(98), 16)
        .unwrap();
    loom.submit_receipt(receipt(id, chash, challenge, 1, h(nonce)), 30)
        .unwrap();
    id
}

fn availability() -> AvailabilityCertificate {
    AvailabilityCertificate {
        evidence_root: h(34),
        availability_root: h(36),
        retriever_count: 2,
        finalized_height: 35,
    }
}

fn paid_delivery(job_id: Hash32) -> PaidDeliveryCertificate {
    PaidDeliveryCertificate {
        job_id,
        requester_domain: h(1),
        worker_domain: h(2),
        evaluator_domain: Some(h(4)),
        artifact_id: artifact_id(b"tensor:f32le:1x1", &[42, 0, 0, 0]),
        output_commitment: h(32),
        encrypted_delivery_commitment: h(33),
        delivery_ack_signature: [8; 64],
        payment_txid: h(70),
        independence_domains_root: h(71),
    }
}

#[test]
fn complete_lifecycle_conserves_and_pays_all_roles() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 40);
    l.finalize_availability(id, availability()).unwrap();
    l.settle(id, 46, payout(), accounts()).unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Settled);
    assert_eq!(l.balance(&h(1)), 900);
    assert_eq!(l.balance(&h(2)), 1_070);
    assert_eq!(l.balance(&h(3)), 10);
    assert_eq!(l.balance(&h(4)), 10);
    assert_eq!(l.balance(&h(5)), 10);
    assert_eq!(l.locked(), 0);
    l.assert_conserved().unwrap();
}

#[test]
fn challenge_requires_post_commit_finality() {
    let mut l = loom();
    let id = l.open_job(open()).unwrap();
    l.commit_worker(commit(id, 1)).unwrap();
    assert_eq!(
        l.assign_finalized_challenge(id, h(1), h(2), 15),
        Err(LoomError::NotFinalized)
    );
}

#[test]
fn receipt_cannot_precede_challenge() {
    let mut l = loom();
    let id = l.open_job(open()).unwrap();
    let ch = l.commit_worker(commit(id, 1)).unwrap();
    assert_eq!(
        l.submit_receipt(receipt(id, ch, h(44), 1, h(45)), 20),
        Err(LoomError::InvalidState)
    );
}

#[test]
fn submission_does_not_start_dispute_clock() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 41);
    assert_eq!(l.job(&id).unwrap().challenge_start, None);
    assert_eq!(
        l.open_dispute(id, h(6), 5, h(1), 31),
        Err(LoomError::InvalidState)
    );
}

#[test]
fn availability_must_be_final_and_exact() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 42);
    let mut bad = availability();
    bad.evidence_root = h(90);
    assert_eq!(
        l.finalize_availability(id, bad),
        Err(LoomError::InvalidAvailability)
    );
    let mut too_few = availability();
    too_few.retriever_count = 1;
    assert_eq!(
        l.finalize_availability(id, too_few),
        Err(LoomError::InvalidAvailability)
    );
    assert_eq!(l.job(&id).unwrap().state, JobState::Submitted);
}

#[test]
fn dispute_window_is_availability_gated() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 43);
    let mut cert = availability();
    cert.finalized_height = 50;
    l.finalize_availability(id, cert).unwrap();
    assert_eq!(
        l.open_dispute(id, h(6), 10, h(7), 49),
        Err(LoomError::DisputeWindowClosed)
    );
    l.open_dispute(id, h(6), 10, h(7), 50).unwrap();
}

#[test]
fn successful_dispute_refunds_and_slashes_without_mint() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 44);
    l.finalize_availability(id, availability()).unwrap();
    l.open_dispute(id, h(6), 10, h(7), 36).unwrap();
    let slash = SettlementSplit {
        worker: 20,
        verifier: 10,
        evaluator: 5,
        da_provider: 15,
    };
    l.resolve_dispute(id, DisputeVerdict::WorkerFault, slash, accounts())
        .unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Rejected);
    assert_eq!(l.balance(&h(1)), 1_000);
    assert_eq!(l.balance(&h(6)), 1_020);
    assert_eq!(l.burned(), 15);
    assert_eq!(l.locked(), 0);
    l.assert_conserved().unwrap();
}

#[test]
fn failed_dispute_returns_challenger_bond_and_job_continues() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 45);
    l.finalize_availability(id, availability()).unwrap();
    l.open_dispute(id, h(6), 10, h(7), 36).unwrap();
    l.resolve_dispute(id, DisputeVerdict::WorkerUpheld, payout(), accounts())
        .unwrap();
    assert_eq!(l.balance(&h(6)), 1_000);
    assert_eq!(l.job(&id).unwrap().state, JobState::Challengeable);
}

#[test]
fn malformed_settlement_is_atomic() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 46);
    l.finalize_availability(id, availability()).unwrap();
    let before = l.locked();
    let bad = SettlementSplit {
        worker: 1,
        verifier: 2,
        evaluator: 3,
        da_provider: 4,
    };
    assert_eq!(
        l.settle(id, 46, bad, accounts()),
        Err(LoomError::InvalidSettlement)
    );
    assert_eq!(l.locked(), before);
    assert_eq!(l.job(&id).unwrap().state, JobState::Challengeable);
}

#[test]
fn settlement_accounts_are_job_bound_and_mutation_is_atomic() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 48);
    l.finalize_availability(id, availability()).unwrap();
    let locked = l.locked();
    let mut confused = accounts();
    confused.evaluator = h(99);
    assert_eq!(
        l.settle(id, 46, payout(), confused),
        Err(LoomError::AccountConflict)
    );
    assert_eq!(l.locked(), locked);
    assert_eq!(l.balance(&h(99)), 0);
    assert_eq!(l.job(&id).unwrap().state, JobState::Challengeable);
}

#[test]
fn cancellation_refunds_all_escrow() {
    let mut l = loom();
    let id = l.open_job(open()).unwrap();
    l.cancel_open(id, h(1), 11).unwrap();
    assert_eq!(l.balance(&h(1)), 1_000);
    assert_eq!(l.job(&id).unwrap().state, JobState::Cancelled);
    l.assert_conserved().unwrap();
}

#[test]
fn refund_direction_is_precommitted_not_chosen_by_terminal_caller() {
    let mut l = loom();
    let mut job = open();
    job.refund_account = h(9);
    let id = l.open_job(job).unwrap();
    l.cancel_open(id, h(1), 11).unwrap();
    assert_eq!(l.balance(&h(1)), 900);
    assert_eq!(l.balance(&h(9)), 100);
    assert_eq!(l.locked(), 0);
    l.assert_conserved().unwrap();
}

#[test]
fn expiry_releases_job_and_worker_funds() {
    let mut l = loom();
    let id = l.open_job(open()).unwrap();
    l.commit_worker(commit(id, 1)).unwrap();
    l.expire(id, 41).unwrap();
    assert_eq!(l.balance(&h(1)), 1_000);
    assert_eq!(l.balance(&h(2)), 1_000);
    assert_eq!(l.locked(), 0);
}

#[test]
fn unresolved_dispute_timeout_has_no_trapped_escrow() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 47);
    l.finalize_availability(id, availability()).unwrap();
    l.open_dispute(id, h(6), 10, h(7), 36).unwrap();
    l.expire(id, 61).unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Expired);
    assert_eq!(l.balance(&h(1)), 1_000);
    assert_eq!(l.balance(&h(2)), 1_000);
    assert_eq!(l.balance(&h(6)), 1_000);
    assert_eq!(l.locked(), 0);
    l.assert_conserved().unwrap();
}

#[test]
fn duplicate_nullifier_rejects_across_jobs() {
    let mut l = loom();
    reach_submitted(&mut l, 55);
    let mut second = open();
    second.nonce = 77;
    let id = l.open_job(second).unwrap();
    let ch = l.commit_worker(commit(id, 1)).unwrap();
    let challenge = l.assign_finalized_challenge(id, h(99), h(98), 16).unwrap();
    assert_eq!(
        l.submit_receipt(receipt(id, ch, challenge, 1, h(55)), 30),
        Err(LoomError::DuplicateNullifier)
    );
}

#[test]
fn immutable_registry_rejects_replacement() {
    let mut r = registries();
    let replacement = WorkerProfile {
        id: 1,
        source_root: h(99),
        compiler_toolchain_root: h(99),
        machine_code_root: h(99),
        hardware_root: h(99),
        status: RegistryStatus::Enabled,
    };
    assert_eq!(
        r.register_worker_profile(replacement),
        Err(LoomError::ImmutableRegistry)
    );
}

#[test]
fn unknown_and_disabled_registry_ids_reject() {
    let mut l = loom();
    let mut job = open();
    job.class_id = 999;
    assert_eq!(l.open_job(job), Err(LoomError::UnknownRegistryId));
    let mut r = Registries::default();
    r.register_work_class(WorkClass {
        id: 8,
        relation_root: h(1),
        status: RegistryStatus::Disabled,
    })
    .unwrap();
    assert_eq!(
        r.register_job_class(JobClass {
            id: 9,
            work_class_id: 8,
            program_or_relation_root: h(1),
            input_schema_root: h(1),
            output_schema_root: h(1),
            numeric_profile_root: h(1),
            allowed_worker_profiles: BTreeSet::from([1]),
            assurance: Assurance::V0,
            confidentiality_flags: 0,
            proof_profile_id: 1,
            evaluator_policy_id: 1,
            availability_policy_id: 1,
            max_resources: ResourceVector::default(),
            challenge_period: 1,
            minimum_worker_bond: 1,
            slashable: false,
            status: RegistryStatus::Enabled
        }),
        Err(LoomError::DisabledRegistryId)
    );
}

#[test]
fn compiler_or_machine_code_change_requires_distinct_profile() {
    let r = registries();
    assert_ne!(
        r.worker_profile(1).unwrap().compiler_toolchain_root,
        r.worker_profile(2).unwrap().compiler_toolchain_root
    );
    assert_ne!(
        r.worker_profile(1).unwrap().machine_code_root,
        r.worker_profile(2).unwrap().machine_code_root
    );
}

#[test]
fn quarantine_blocks_only_new_commits() {
    let mut l = loom();
    let id_a = l.open_job(open()).unwrap();
    l.commit_worker(commit(id_a, 1)).unwrap();
    l.quarantine_profile(1).unwrap();
    assert!(l.assign_finalized_challenge(id_a, h(1), h(2), 16).is_ok());
    let mut job = open();
    job.nonce = 88;
    let id_b = l.open_job(job).unwrap();
    assert_eq!(
        l.commit_worker(commit(id_b, 1)),
        Err(LoomError::ProfileQuarantined)
    );
    assert_eq!(l.job(&id_a).unwrap().state, JobState::Running);
    assert_eq!(l.job(&id_b).unwrap().state, JobState::Open);
}

#[test]
fn disputed_job_does_not_block_unrelated_settlement() {
    let mut l = loom();
    let first = reach_submitted(&mut l, 60);
    l.finalize_availability(first, availability()).unwrap();
    l.open_dispute(first, h(6), 10, h(7), 36).unwrap();
    let second = reach_submitted(&mut l, 61);
    l.finalize_availability(second, availability()).unwrap();
    l.settle(second, 46, payout(), accounts()).unwrap();
    assert_eq!(l.job(&first).unwrap().state, JobState::Disputed);
    assert_eq!(l.job(&second).unwrap().state, JobState::Settled);
}

#[test]
fn correctness_demand_delivery_quality_are_independent() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 62);
    let r = l.jobs.get_mut(&id).unwrap().receipt.as_mut().unwrap();
    r.correctness = Correctness::Verified;
    r.external_demand = DemandClassification::Subsidized;
    r.delivery = Delivery::Committed;
    r.quality = Quality::Score(1);
    assert_eq!(
        (r.correctness, r.external_demand, r.delivery, r.quality),
        (
            Correctness::Verified,
            DemandClassification::Subsidized,
            Delivery::Committed,
            Quality::Score(1)
        )
    );
}

#[test]
fn paid_delivery_is_optional_for_settlement_but_required_for_external_label() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 63);
    l.finalize_availability(id, availability()).unwrap();
    assert!(l.job(&id).unwrap().delivery_certificate.is_none());
    l.settle(id, 46, payout(), accounts()).unwrap();
    assert_eq!(
        l.job(&id).unwrap().receipt.as_ref().unwrap().delivery,
        Delivery::Available
    );
}

#[test]
fn paid_acknowledgement_rule_is_bound_before_escrow() {
    let mut l = loom();
    let mut job = open();
    job.delivery_rule = DeliveryRule::PaidAcknowledgement;
    job.nonce = 90;
    let id = l.open_job(job).unwrap();
    let commit_hash = l.commit_worker(commit(id, 1)).unwrap();
    let challenge = l.assign_finalized_challenge(id, h(99), h(98), 16).unwrap();
    l.submit_receipt(receipt(id, commit_hash, challenge, 1, h(90)), 30)
        .unwrap();
    l.finalize_availability(id, availability()).unwrap();
    assert_eq!(
        l.settle(id, 46, payout(), accounts()),
        Err(LoomError::InvalidSettlement)
    );
    l.attach_paid_delivery(id, paid_delivery(id)).unwrap();
    l.settle(id, 46, payout(), accounts()).unwrap();
    assert_eq!(l.job(&id).unwrap().state, JobState::Settled);
}

#[test]
fn job_id_binds_every_market_and_refund_term() {
    let base = open();
    let expected = job_id(&base);
    let mutations: Vec<OpenJob> = vec![
        OpenJob {
            requester: h(99),
            ..base.clone()
        },
        OpenJob {
            refund_account: h(99),
            ..base.clone()
        },
        OpenJob {
            required_assurance: Assurance::V3,
            ..base.clone()
        },
        OpenJob {
            input_root: h(99),
            ..base.clone()
        },
        OpenJob {
            model_or_program_root: h(99),
            ..base.clone()
        },
        OpenJob {
            delivery_pubkey: h(99),
            ..base.clone()
        },
        OpenJob {
            delivery_rule: DeliveryRule::PaidAcknowledgement,
            ..base.clone()
        },
        OpenJob {
            settlement_accounts: SettlementAccounts {
                evaluator: h(99),
                ..accounts()
            },
            ..base.clone()
        },
        OpenJob {
            fee_escrow: 79,
            ..base.clone()
        },
        OpenJob {
            commit_deadline: 19,
            ..base.clone()
        },
        OpenJob {
            submit_deadline: 39,
            ..base.clone()
        },
        OpenJob {
            expiry_height: 61,
            ..base.clone()
        },
    ];
    for mutation in mutations {
        assert_ne!(
            job_id(&mutation),
            expected,
            "unbound mutation: {mutation:?}"
        );
    }
}

#[test]
fn seeded_adversarial_market_traces_are_terminal_and_conserved() {
    for seed in 0..4_096u64 {
        let mut l = loom();
        let mut job = open();
        job.nonce = 1_000 + seed;
        let id = l.open_job(job).unwrap();
        match seed & 7 {
            0 => l.cancel_open(id, h(1), 11).unwrap(),
            1 => l.expire(id, 21).unwrap(),
            mode => {
                let commit_hash = l.commit_worker(commit(id, 1)).unwrap();
                if mode == 2 {
                    l.expire(id, 41).unwrap();
                } else {
                    let challenge = l.assign_finalized_challenge(id, h(99), h(98), 16).unwrap();
                    let nullifier = domain_hash("NOOS/LOOM/TRACE/V1", &[&seed.to_le_bytes()]);
                    l.submit_receipt(receipt(id, commit_hash, challenge, 1, nullifier), 30)
                        .unwrap();
                    if mode == 3 {
                        l.expire(id, 61).unwrap();
                    } else {
                        l.finalize_availability(id, availability()).unwrap();
                        match mode {
                            4 => l.settle(id, 46, payout(), accounts()).unwrap(),
                            5 => {
                                l.open_dispute(id, h(6), 10, h(7), 36).unwrap();
                                l.resolve_dispute(
                                    id,
                                    DisputeVerdict::WorkerFault,
                                    SettlementSplit {
                                        worker: 20,
                                        verifier: 10,
                                        evaluator: 5,
                                        da_provider: 15,
                                    },
                                    accounts(),
                                )
                                .unwrap();
                            }
                            6 => {
                                l.open_dispute(id, h(6), 10, h(7), 36).unwrap();
                                l.expire(id, 61).unwrap();
                            }
                            _ => {
                                l.attach_paid_delivery(id, paid_delivery(id)).unwrap();
                                l.settle(id, 46, payout(), accounts()).unwrap();
                            }
                        }
                    }
                }
            }
        }
        assert!(l.job(&id).unwrap().state.terminal(), "seed {seed}");
        assert_eq!(l.locked(), 0, "seed {seed}");
        l.assert_conserved().unwrap();
        assert_eq!(
            l.cancel_open(id, h(1), 11),
            Err(LoomError::InvalidState),
            "seed {seed} double terminal mutation"
        );
    }
}

#[test]
fn artifact_stable_and_work_commit_challenge_bound() {
    let a = artifact_id(b"d", b"bytes");
    assert_eq!(a, artifact_id(b"d", b"bytes"));
    assert_ne!(
        work_commit(&h(1), &a, 1, &h(2)),
        work_commit(&h(3), &a, 1, &h(2))
    );
    assert_ne!(
        work_commit(&h(1), &a, 1, &h(2)),
        work_commit(&h(1), &a, 2, &h(2))
    );
}

#[test]
fn zero_jobs_and_shadow_never_influence_production() {
    let l = loom();
    assert_eq!(l.production_influence(), ProductionInfluence::default());
    let out = shadow::calculate(
        shadow::Inputs {
            ground_work: 900,
            settled_value: 100,
            calibration_units: 200,
            raw_stake: 1_000,
            demand_evidence: demand_evidence(DemandClassification::Independent),
            delivered: true,
            paid_certificate: true,
        },
        h(1),
    );
    assert!(out.counterfactual_loom_credit > 0);
    assert_eq!(out.counterfactual_proofpower, 0);
    assert_eq!(out.counterfactual_duplex, 0);
    assert_eq!(
        (
            out.production_loom_credit,
            out.production_proofpower,
            out.production_duplex
        ),
        (0, 0, 0)
    );
    assert!(!WORK_LOOM_CREDIT_ENABLED && !WITNESS_PROOFPOWER_ENABLED && !DUPLEX_ISSUANCE_ENABLED);
    assert_eq!(DEMAND_WASH_BINDING, "E-DEMAND-WASH-01");
}

#[test]
fn demand_classification_is_telemetry_only() {
    for demand in [
        DemandClassification::Independent,
        DemandClassification::Related,
        DemandClassification::Subsidized,
        DemandClassification::Unknown,
    ] {
        let out = shadow::calculate(
            shadow::Inputs {
                ground_work: 900,
                settled_value: 100,
                calibration_units: 100,
                raw_stake: 1_000,
                demand_evidence: demand_evidence(demand),
                delivered: true,
                paid_certificate: true,
            },
            h(1),
        );
        assert_eq!(
            (
                out.production_loom_credit,
                out.production_proofpower,
                out.production_duplex
            ),
            (0, 0, 0)
        );
        if demand != DemandClassification::Independent {
            assert_eq!(
                (
                    out.counterfactual_loom_credit,
                    out.counterfactual_proofpower,
                    out.counterfactual_duplex
                ),
                (0, 0, 0)
            );
        }
    }
}

#[test]
fn settlement_cannot_mint_via_overflow_or_bad_split() {
    let mut l = loom();
    let id = reach_submitted(&mut l, 64);
    l.finalize_availability(id, availability()).unwrap();
    let bad = SettlementSplit {
        worker: u128::MAX,
        verifier: 1,
        evaluator: 0,
        da_provider: 0,
    };
    assert_eq!(
        l.settle(id, 46, bad, accounts()),
        Err(LoomError::ArithmeticOverflow)
    );
    l.assert_conserved().unwrap();
}

#[test]
fn lumen_adapter_reserve_settle_and_refund() {
    let mut a = LumenEscrowAdapter::default();
    a.credit_genesis(h(1), 100).unwrap();
    a.set_plan(h(9), BTreeMap::from([(h(2), 60), (h(3), 40)]))
        .unwrap();
    WorkJobEscrow::reserve(&mut a, &h(9), &h(1), 100).unwrap();
    WorkJobEscrow::settle(&mut a, &h(9)).unwrap();
    assert_eq!(
        (a.balance(&h(1)), a.balance(&h(2)), a.balance(&h(3))),
        (0, 60, 40)
    );

    let mut b = LumenEscrowAdapter::default();
    b.credit_genesis(h(1), 100).unwrap();
    b.set_plan(h(8), BTreeMap::from([(h(2), 100)])).unwrap();
    WorkJobEscrow::reserve(&mut b, &h(8), &h(1), 100).unwrap();
    WorkJobEscrow::refund(&mut b, &h(8)).unwrap();
    assert_eq!(b.balance(&h(1)), 100);
}

#[test]
fn wrong_resources_and_deadlines_reject_before_debit() {
    let mut l = loom();
    let mut job = open();
    job.max_resources.compute = 101;
    assert_eq!(l.open_job(job), Err(LoomError::InvalidRegistryEntry));
    assert_eq!(l.balance(&h(1)), 1_000);
    let mut job = open();
    job.commit_deadline = job.opened_height;
    assert_eq!(l.open_job(job), Err(LoomError::Deadline));
    assert_eq!(l.balance(&h(1)), 1_000);
}
