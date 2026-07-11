//! Machine-readable deterministic metrics for the assigned NEL claim cluster.

use noos_nel::lab::{
    audit_local_reference, evaluate_accuracy, run_da_replay_local, run_grind_study,
    run_hostile_dispute_local, AccuracyPreregistration, AccuracyTaskResult, LatencyExperiment,
    LatencyPreregistration, LatencySample, ProofBenchmarkRecord, ProofEvidenceClass,
};
use noos_nel::{lab, FinalityClass};
use std::collections::BTreeSet;
use std::fmt::Debug;

fn required<T, E: Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{context}: {error:?}");
            std::process::exit(1);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn profile_metrics(claim: &str) {
    let report = required(audit_local_reference(), "local profile audit");
    println!(
        "{{\"claim\":\"{claim}\",\"profile_id\":\"{}\",\"tokenizer_root\":\"{}\",\"matmul_instances\":{},\"semantic_op_families\":{},\"schedule_mismatches\":{},\"cobatch_mismatches\":{},\"invalid_tokenizer_bytes_rejected\":{}}}",
        hex(&report.profile_id),
        hex(&report.tokenizer_root),
        report.matmul_instances,
        report.semantic_op_families,
        report.schedule_mismatches,
        report.cobatch_mismatches,
        report.invalid_tokenizer_bytes_rejected
    );
}

fn accuracy_metrics() {
    let registration = AccuracyPreregistration {
        source_checkpoint: [1; 32],
        quantization_artifacts: [2; 32],
        calibration_artifacts: [3; 32],
        tasks: BTreeSet::from(["task-a".to_owned(), "task-b".to_owned()]),
        safety_tasks: BTreeSet::from(["safety".to_owned()]),
        minimum_samples_per_task: 100,
        maximum_quality_loss_ppm: 10_000,
        registered_at: 10,
        hidden_suite_opens_at: 11,
    };
    let results = [
        AccuracyTaskResult {
            task: "task-a".to_owned(),
            samples: 100,
            source_score_ppm: 900_000,
            w8a8_score_ppm: 895_000,
        },
        AccuracyTaskResult {
            task: "task-b".to_owned(),
            samples: 100,
            source_score_ppm: 800_000,
            w8a8_score_ppm: 790_000,
        },
        AccuracyTaskResult {
            task: "safety".to_owned(),
            samples: 100,
            source_score_ppm: 990_000,
            w8a8_score_ppm: 990_000,
        },
    ];
    let report = required(
        evaluate_accuracy(&registration, &results),
        "accuracy schema fixture",
    );
    println!(
        "{{\"claim\":\"E-NEL-02\",\"fixture_only\":true,\"registered_tasks\":{},\"reported_tasks\":{},\"schema_passed\":{},\"real_0_5b_hidden_suite\":false}}",
        3,
        report.losses_ppm.len(),
        report.passed
    );
}

fn latency_metrics() {
    let samples: Vec<LatencySample> = (0..100u32)
        .map(|index| LatencySample {
            control_cluster: (index % 3) as u8,
            forward_ms: 500u32.saturating_add(index),
            quorum_ms: 100,
            anchoring_ms: 1_000,
            onchain_inclusion_ms: 2_000,
            proof_ms: 3_000,
            disagreement: index == 1,
            dropped: index == 2,
            refunded: index == 2,
            surface_label: FinalityClass::Soft,
        })
        .collect();
    let registration = LatencyPreregistration {
        arrival_process_root: [1; 32],
        context_generation_mix_root: [2; 32],
        executor_committees_root: [3; 32],
        regions_root: [4; 32],
        target_concurrency: 100,
        faults_root: [5; 32],
        registered_at: 10,
        opens_at: 11,
    };
    let mut experiment = required(
        LatencyExperiment::preregister(registration),
        "latency preregistration",
    );
    required(experiment.start(11), "latency start");
    for sample in samples {
        required(experiment.record(sample), "latency sample");
    }
    let report = required(experiment.seal(), "latency seal");
    let lifecycle_sealed = experiment.state == lab::LatencyExperimentState::Sealed;
    println!(
        "{{\"claim\":\"E-NEL-03\",\"fixture_only\":true,\"lifecycle_sealed\":{lifecycle_sealed},\"p50_ms\":{},\"p95_ms\":{},\"p99_ms\":{},\"control_clusters\":{},\"disagreements\":{},\"drops\":{},\"refunds\":{},\"all_surfaces_soft\":{},\"public_experiment\":false}}",
        report.committed_p50_ms,
        report.committed_p95_ms,
        report.committed_p99_ms,
        report.control_clusters,
        report.disagreements,
        report.drops,
        report.refunds,
        report.all_surfaces_soft
    );
}

fn dispute_metrics() {
    let report = required(run_hostile_dispute_local(), "hostile dispute fixture");
    println!(
        "{{\"claim\":\"E-NEL-04\",\"fixture_only\":true,\"t\":32,\"isolated_position\":{},\"isolated_layer\":{},\"isolated_op\":{},\"local_bisection_rounds\":{},\"declared_public_rounds\":{},\"declared_public_transactions\":{},\"move_deadline\":{},\"wrong_job_lost\":{},\"unrelated_job_live\":{},\"late_move_rejected\":{},\"malformed_move_rejected\":{},\"frivolous_challenger_lost\":{},\"public_testnet\":false}}",
        report.isolated_position,
        report.isolated_layer,
        report.isolated_op,
        report.local_bisection_rounds,
        report.declared_public_rounds,
        report.declared_public_transactions,
        report.move_deadline,
        report.wrong_job_lost,
        report.unrelated_job_live,
        report.late_move_rejected,
        report.malformed_move_rejected,
        report.frivolous_challenger_lost
    );
}

fn da_metrics() {
    let report = required(run_da_replay_local(), "DA/replay fixture");
    println!(
        "{{\"claim\":\"E-NEL-05\",\"fixture_only\":true,\"weight_bytes\":{},\"activation_bytes\":{},\"weight_root\":\"{}\",\"activation_root\":\"{}\",\"single_loss_reconstructs\":{},\"correlated_loss_blocks_assurance\":{},\"replay_probes\":{},\"replay_mismatches\":{},\"poison_detected\":{},\"cross_domain_hits\":{},\"real_0_5b_weights\":false,\"public_30_day_window\":false}}",
        report.weight_bytes,
        report.activation_bytes,
        hex(&report.weight_root),
        hex(&report.activation_root),
        report.single_loss_reconstructs,
        report.correlated_loss_blocks_assurance,
        report.replay_probes,
        report.replay_mismatches,
        report.poison_detected,
        report.cross_domain_hits
    );
}

fn proof_metrics() {
    let fixture = ProofBenchmarkRecord {
        evidence_class: ProofEvidenceClass::Extrapolation,
        parameters: 500_000_000,
        chunk_tokens: 32,
        hardware: "fixture".to_owned(),
        circuit_commit: [1; 32],
        compiler_commit: [2; 32],
        witness_peak_bytes: 1,
        prover_wall_ms: 1,
        prover_energy_mj: 1,
        prover_cost_microunits: 1,
        replicated_inference_cost_microunits: 1,
        proof_bytes: 1,
        aggregation_ms: 1,
        verifier_ms: 1,
        failed_proofs: 0,
        verifier_implementations: ["fixture-a".to_owned(), "fixture-b".to_owned()],
        verifier_results: [[3; 32], [3; 32]],
        challenge_window_ms: 2,
    };
    let extrapolation_rejected = matches!(
        lab::validate_proof_benchmark(&fixture),
        Err(lab::LabError::ExtrapolatedProofEvidence)
    );
    println!(
        "{{\"claim\":\"E-NEL-06\",\"benchmark_interface_complete\":true,\"extrapolation_rejected\":{extrapolation_rejected},\"real_specialized_proof_run\":false,\"independent_verifiers\":false}}"
    );
}

fn grind_metrics() {
    let report = required(run_grind_study(), "grind study");
    println!(
        "{{\"claim\":\"E-NEL-07\",\"schedules\":{},\"post_reveal_commitments_accepted\":{},\"alternate_beacons_accepted\":{},\"replay_draws_accepted\":{},\"withholding_refunds\":{},\"greedy_cursor_is_zero\":{},\"independent_second_client\":false,\"public_30_day_stall_measurement\":false}}",
        report.schedules,
        report.post_reveal_commitments_accepted,
        report.alternate_beacons_accepted,
        report.replay_draws_accepted,
        report.withholding_refunds,
        report.greedy_cursor_is_zero
    );
}

fn main() {
    let Some(claim) = std::env::args().nth(1) else {
        eprintln!("claim id argument required");
        std::process::exit(2);
    };
    match claim.as_str() {
        "N-PROFILE" | "E-NEL-01" | "E-NEL-01a" => profile_metrics(&claim),
        "E-NEL-02" => accuracy_metrics(),
        "E-NEL-03" => latency_metrics(),
        "E-NEL-04" => dispute_metrics(),
        "E-NEL-05" => da_metrics(),
        "E-NEL-06" => proof_metrics(),
        "E-NEL-07" => grind_metrics(),
        _ => panic!("unsupported claim {claim}"),
    }
}
