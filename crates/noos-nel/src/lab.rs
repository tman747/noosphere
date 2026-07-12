//! Deterministic local experiment contracts for the E-NEL claim family.
//!
//! These types deliberately separate a locally executable precursor from an
//! experiment that satisfies the frozen public gate. A fixture can exercise
//! every transition and falsifier here, but cannot manufacture independent
//! vendors, a real 0.5B model, public elapsed time, specialized hardware, or
//! an independently authored verifier.

// Experiment counters and checked, bounded matrix indices deliberately use
// ordinary arithmetic so the independently ordered reference remains easy to
// audit against the frozen formulas.
#![allow(clippy::arithmetic_side_effects)]

use crate::inference::{
    mini_profile_id, ops, run_bisection, run_lane, BOperand, LaneRun, MatMulRecord, MiniModel,
    SamplerParams, Tamper, HIDDEN, LAYERS, MLP, OPS_PER_LAYER, QKV_DIM, VOCAB,
};
use crate::{
    domain_hash, domains as wire_domains, BisectMove, Dispute, DisputeOpen, FinalityClass,
    FreivaldsProfile, Hash32, NelError, Verdict,
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

/// Registered production weight-shard lower bound (4 MiB).
pub const MIN_WEIGHT_SHARD_BYTES: u32 = 4 * 1024 * 1024;
/// Registered production weight-shard upper bound (16 MiB).
pub const MAX_WEIGHT_SHARD_BYTES: u32 = 16 * 1024 * 1024;
/// Frozen E-NEL-04 depth deadline.
pub const DISPUTE_MOVE_DEADLINE: u64 = 25;
/// Frozen declared public dispute path.
pub const DECLARED_DISPUTE_ROUNDS: u32 = 19;
/// Frozen declared public transaction count.
pub const DECLARED_DISPUTE_TRANSACTIONS: u32 = 40;
/// Required randomized KV checkpoint probes.
pub const KV_REPLAY_PROBES: u32 = 10_000;
/// Required adversarial sampler/beacon schedules.
pub const GRIND_SCHEDULES: u64 = 1_000_000;

/// Failure modes shared by the deterministic lab contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabError {
    MissingRegistration,
    SuiteAlreadyOpen,
    TaskSetMismatch,
    Underpowered,
    QualityToleranceExceeded,
    LabelLaundering,
    InvalidArtifact,
    ProfileContractMismatch,
    InvalidShardGeometry,
    Unavailable,
    PoisonedCheckpoint,
    ExtrapolatedProofEvidence,
    IndependentVerifierRequired,
    UnsupportedProofScale,
    PostRevealCommitment,
    BeaconUnavailable,
    ReplayDraw,
}

/// Canonical mini-profile tokenizer: one token is one byte in `[0, VOCAB)`.
/// Invalid bytes fail closed, exercising E-NEL-01's tokenizer adversary. This
/// is explicitly not the external Qwen tokenizer required by E-NEL-01a.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiniTokenizer;

impl MiniTokenizer {
    /// Domain-separated tokenizer specification root.
    #[must_use]
    pub fn root() -> Hash32 {
        domain_hash("NOOS/NEL/TOKENIZER/MINI-BYTE64/V1", &[VOCAB as u8])
    }

    /// Decode canonical bytes to token identifiers.
    pub fn decode(bytes: &[u8]) -> Result<Vec<u32>, LabError> {
        if bytes.is_empty() || bytes.iter().any(|&byte| usize::from(byte) >= VOCAB) {
            return Err(LabError::InvalidArtifact);
        }
        Ok(bytes.iter().map(|&byte| u32::from(byte)).collect())
    }

    /// Encode token identifiers to canonical bytes.
    pub fn encode(tokens: &[u32]) -> Result<Vec<u8>, LabError> {
        if tokens.is_empty() || tokens.iter().any(|&token| token >= VOCAB as u32) {
            return Err(LabError::InvalidArtifact);
        }
        tokens
            .iter()
            .map(|&token| u8::try_from(token).map_err(|_| LabError::InvalidArtifact))
            .collect()
    }
}

/// Immutable identity of the complete local W8A8 profile contract. The numeric profile root
/// commits LUTs, scales and tensor shapes; the additional roots make tokenizer, overflow,
/// rounding, saturation, tie-breaking and decoding semantics explicit admission inputs rather
/// than assumptions inherited from an implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenProfileContract {
    pub numeric_profile_id: Hash32,
    pub tokenizer_root: Hash32,
    pub arithmetic_semantics_root: Hash32,
    pub decoding_semantics_root: Hash32,
    pub shape: [u32; 7],
}

impl FrozenProfileContract {
    #[must_use]
    pub fn canonical_local() -> Self {
        Self {
            numeric_profile_id: mini_profile_id(),
            tokenizer_root: MiniTokenizer::root(),
            arithmetic_semantics_root: domain_hash(
                "NOOS/NEL/PROFILE/ARITHMETIC-SEMANTICS/V1",
                b"i8-weights;i8-activations;i64-checked-accumulator;add-positive-half-then-arithmetic-right-shift;negative-ties-toward-positive-infinity;saturate-i8;integer-rmsnorm;lut-silu;lut-softmax;integer-rope",
            ),
            decoding_semantics_root: domain_hash(
                "NOOS/NEL/PROFILE/DECODING-SEMANTICS/V1",
                b"greedy;lowest-token-id-wins-ties;reject-noncanonical-tokenizer-bytes",
            ),
            shape: [
                HIDDEN as u32,
                LAYERS as u32,
                QKV_DIM as u32,
                MLP as u32,
                VOCAB as u32,
                OPS_PER_LAYER as u32,
                1,
            ],
        }
    }

    #[must_use]
    pub fn commitment(&self) -> Hash32 {
        let mut body = Vec::new();
        body.extend(self.numeric_profile_id);
        body.extend(self.tokenizer_root);
        body.extend(self.arithmetic_semantics_root);
        body.extend(self.decoding_semantics_root);
        for dimension in self.shape {
            body.extend(dimension.to_le_bytes());
        }
        domain_hash("NOOS/NEL/PROFILE/LOCAL-CONTRACT/V1", &body)
    }

    pub fn validate_local(&self) -> Result<(), LabError> {
        if self == &Self::canonical_local() {
            Ok(())
        } else {
            Err(LabError::ProfileContractMismatch)
        }
    }
}

/// Identity of the complete local reference profile.
#[must_use]
pub fn local_reference_profile_id() -> Hash32 {
    FrozenProfileContract::canonical_local().commitment()
}

fn resolve_b(model: &MiniModel, record: &MatMulRecord) -> Result<Vec<i64>, NelError> {
    match &record.b {
        BOperand::Weight(id) => model.weight_i64(*id),
        BOperand::Inline(values) => Ok(values.clone()),
    }
}

/// Independently derived column-stream accumulator. The loop order is
/// `column -> inner -> row`, unlike the frozen reference's
/// `row -> column -> inner` order.
fn column_stream(
    record: &MatMulRecord,
    b: &[i64],
    reverse_inner: bool,
) -> Result<Vec<i64>, NelError> {
    let a_len = record
        .m
        .checked_mul(record.k)
        .ok_or(NelError::ArithmeticOverflow)?;
    let b_len = record
        .k
        .checked_mul(record.n)
        .ok_or(NelError::ArithmeticOverflow)?;
    if record.a.len() != a_len || b.len() != b_len {
        return Err(NelError::InvalidCount);
    }
    let mut out = vec![0i64; record.m * record.n];
    for col in 0..record.n {
        for offset in 0..record.k {
            let inner = if reverse_inner {
                record.k - 1 - offset
            } else {
                offset
            };
            for row in 0..record.m {
                out[row * record.n + col] = out[row * record.n + col]
                    .checked_add(
                        record.a[row * record.k + inner]
                            .checked_mul(b[inner * record.n + col])
                            .ok_or(NelError::ArithmeticOverflow)?,
                    )
                    .ok_or(NelError::ArithmeticOverflow)?;
            }
        }
    }
    Ok(out)
}

/// Local conformance metrics over the frozen W8A8 vector shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub profile_id: Hash32,
    pub tokenizer_root: Hash32,
    pub matmul_instances: u64,
    pub semantic_op_families: u32,
    pub schedule_mismatches: u64,
    pub cobatch_mismatches: u64,
    pub invalid_tokenizer_bytes_rejected: bool,
    pub contract_mutations_rejected: bool,
}

/// Exercise the complete local op family, two reduction schedules, tokenizer
/// bytes, and co-batch independence. This is not a vendor campaign.
pub fn audit_local_reference() -> Result<ConformanceReport, NelError> {
    let model = MiniModel::deterministic();
    let prompt = MiniTokenizer::decode(&[1, 2, 3, 4]).map_err(|_| NelError::InvalidCount)?;
    let run = run_lane(&model, [7; 32], &prompt, 8, None)?;
    let cobatch = run_lane(&model, [8; 32], &prompt, 8, None)?;
    let mut matmul_instances = 0u64;
    let mut schedule_mismatches = 0u64;
    let mut families = BTreeSet::new();
    for step in &run.steps {
        for (layer, payloads) in step.op_payloads.iter().enumerate() {
            for (op, payload) in payloads.iter().enumerate() {
                // SELECT is empty on prefill positions and populated on
                // generation positions; semantic coverage requires at least
                // one committed instance, not a fabricated prefill token.
                if !payload.is_empty() {
                    families.insert((u8::from(layer >= LAYERS), op as u16));
                }
            }
        }
        for record in &step.matmuls {
            let b = resolve_b(&model, record)?;
            let forward = column_stream(record, &b, false)?;
            let reverse = column_stream(record, &b, true)?;
            if forward != record.c || reverse != record.c {
                schedule_mismatches += 1;
            }
            matmul_instances += 1;
        }
    }
    let cobatch_mismatches = run
        .steps
        .iter()
        .zip(&cobatch.steps)
        .filter(|(left, right)| {
            left.logits != right.logits || left.op_payloads != right.op_payloads
        })
        .count() as u64;
    let canonical_contract = FrozenProfileContract::canonical_local();
    canonical_contract
        .validate_local()
        .map_err(|_| NelError::InvalidCount)?;
    let mut mutations = Vec::new();
    for replacement in [[90; 32], [91; 32], [92; 32], [93; 32]] {
        let mut mutation = canonical_contract.clone();
        match mutations.len() {
            0 => mutation.numeric_profile_id = replacement,
            1 => mutation.tokenizer_root = replacement,
            2 => mutation.arithmetic_semantics_root = replacement,
            _ => mutation.decoding_semantics_root = replacement,
        }
        mutations.push(mutation);
    }
    for index in 0..canonical_contract.shape.len() {
        let mut mutation = canonical_contract.clone();
        mutation.shape[index] = mutation.shape[index].saturating_add(1);
        mutations.push(mutation);
    }
    let contract_mutations_rejected = mutations
        .iter()
        .all(|mutation| mutation.validate_local() == Err(LabError::ProfileContractMismatch));
    Ok(ConformanceReport {
        profile_id: canonical_contract.commitment(),
        tokenizer_root: MiniTokenizer::root(),
        matmul_instances,
        semantic_op_families: families.len() as u32,
        schedule_mismatches,
        cobatch_mismatches,
        invalid_tokenizer_bytes_rejected: MiniTokenizer::decode(&[VOCAB as u8]).is_err(),
        contract_mutations_rejected,
    })
}

/// Immutable per-model accuracy preregistration. Scores and tolerances are
/// integer parts-per-million to avoid floating-point ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccuracyPreregistration {
    pub source_checkpoint: Hash32,
    pub quantization_artifacts: Hash32,
    pub calibration_artifacts: Hash32,
    pub tasks: BTreeSet<String>,
    pub safety_tasks: BTreeSet<String>,
    pub minimum_samples_per_task: u32,
    pub maximum_quality_loss_ppm: u32,
    pub registered_at: u64,
    pub hidden_suite_opens_at: u64,
}

/// One task result, always reported individually.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccuracyTaskResult {
    pub task: String,
    pub samples: u32,
    pub source_score_ppm: u32,
    pub w8a8_score_ppm: u32,
}

/// Per-task accuracy report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccuracyReport {
    pub losses_ppm: BTreeMap<String, u32>,
    pub passed: bool,
}

/// Evaluate the exact preregistered task set; missing a weak task cannot be
/// hidden by an aggregate mean.
pub fn evaluate_accuracy(
    registration: &AccuracyPreregistration,
    results: &[AccuracyTaskResult],
) -> Result<AccuracyReport, LabError> {
    if registration.source_checkpoint == [0; 32]
        || registration.quantization_artifacts == [0; 32]
        || registration.calibration_artifacts == [0; 32]
        || registration.tasks.is_empty()
        || registration.safety_tasks.is_empty()
        || registration.minimum_samples_per_task == 0
        || registration.registered_at >= registration.hidden_suite_opens_at
    {
        return Err(LabError::MissingRegistration);
    }
    let expected: BTreeSet<String> = registration
        .tasks
        .union(&registration.safety_tasks)
        .cloned()
        .collect();
    let actual: BTreeSet<String> = results.iter().map(|result| result.task.clone()).collect();
    if actual != expected || actual.len() != results.len() {
        return Err(LabError::TaskSetMismatch);
    }
    if results
        .iter()
        .any(|result| result.samples < registration.minimum_samples_per_task)
    {
        return Err(LabError::Underpowered);
    }
    let losses_ppm: BTreeMap<String, u32> = results
        .iter()
        .map(|result| {
            (
                result.task.clone(),
                result
                    .source_score_ppm
                    .saturating_sub(result.w8a8_score_ppm),
            )
        })
        .collect();
    let passed = losses_ppm
        .values()
        .all(|loss| *loss <= registration.maximum_quality_loss_ppm);
    Ok(AccuracyReport { losses_ppm, passed })
}

/// Every visible experiment surface must preserve SOFT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySample {
    pub control_cluster: u8,
    pub forward_ms: u32,
    pub quorum_ms: u32,
    pub anchoring_ms: u32,
    pub onchain_inclusion_ms: u32,
    pub proof_ms: u32,
    pub disagreement: bool,
    pub dropped: bool,
    pub refunded: bool,
    pub surface_label: FinalityClass,
}

/// Frozen inputs that must be registered before a latency run opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyPreregistration {
    pub arrival_process_root: Hash32,
    pub context_generation_mix_root: Hash32,
    pub executor_committees_root: Hash32,
    pub regions_root: Hash32,
    pub target_concurrency: u32,
    pub faults_root: Hash32,
    pub registered_at: u64,
    pub opens_at: u64,
}

/// Fail-closed experiment lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyExperimentState {
    Preregistered,
    Running,
    Sealed,
    Invalidated,
}

/// SOFT latency experiment state machine. It cannot record before opening,
/// mutate preregistration, or retain a sample that launders the finality
/// label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyExperiment {
    pub registration: LatencyPreregistration,
    pub state: LatencyExperimentState,
    samples: Vec<LatencySample>,
}

impl LatencyExperiment {
    pub fn preregister(registration: LatencyPreregistration) -> Result<Self, LabError> {
        if registration.arrival_process_root == [0; 32]
            || registration.context_generation_mix_root == [0; 32]
            || registration.executor_committees_root == [0; 32]
            || registration.regions_root == [0; 32]
            || registration.target_concurrency == 0
            || registration.faults_root == [0; 32]
            || registration.registered_at >= registration.opens_at
        {
            return Err(LabError::MissingRegistration);
        }
        Ok(Self {
            registration,
            state: LatencyExperimentState::Preregistered,
            samples: Vec::new(),
        })
    }

    pub fn start(&mut self, now: u64) -> Result<(), LabError> {
        if self.state != LatencyExperimentState::Preregistered || now < self.registration.opens_at {
            return Err(LabError::SuiteAlreadyOpen);
        }
        self.state = LatencyExperimentState::Running;
        Ok(())
    }

    pub fn record(&mut self, sample: LatencySample) -> Result<(), LabError> {
        if self.state != LatencyExperimentState::Running {
            return Err(LabError::SuiteAlreadyOpen);
        }
        if sample.surface_label != FinalityClass::Soft {
            self.state = LatencyExperimentState::Invalidated;
            return Err(LabError::LabelLaundering);
        }
        self.samples.push(sample);
        Ok(())
    }

    pub fn seal(&mut self) -> Result<LatencyReport, LabError> {
        if self.state != LatencyExperimentState::Running {
            return Err(LabError::SuiteAlreadyOpen);
        }
        let report = summarize_soft_latency(&self.samples)?;
        self.state = LatencyExperimentState::Sealed;
        Ok(report)
    }
}

/// Deterministic nearest-rank latency summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyReport {
    pub committed_p50_ms: u32,
    pub committed_p95_ms: u32,
    pub committed_p99_ms: u32,
    pub control_clusters: u32,
    pub disagreements: u64,
    pub drops: u64,
    pub refunds: u64,
    pub all_surfaces_soft: bool,
}

fn nearest_rank(values: &mut [u32], percentile: usize) -> Result<u32, LabError> {
    if values.is_empty() {
        return Err(LabError::Underpowered);
    }
    values.sort_unstable();
    let rank = percentile
        .checked_mul(values.len())
        .and_then(|value| value.checked_add(99))
        .ok_or(LabError::Underpowered)?
        / 100;
    Ok(values[rank.saturating_sub(1).min(values.len() - 1)])
}

/// Measure committed-token latency separately from on-chain/proof latency.
pub fn summarize_soft_latency(samples: &[LatencySample]) -> Result<LatencyReport, LabError> {
    if samples.is_empty() {
        return Err(LabError::Underpowered);
    }
    if samples
        .iter()
        .any(|sample| sample.surface_label != FinalityClass::Soft)
    {
        return Err(LabError::LabelLaundering);
    }
    let clusters: BTreeSet<u8> = samples
        .iter()
        .map(|sample| sample.control_cluster)
        .collect();
    let mut committed: Vec<u32> = samples
        .iter()
        .filter(|sample| !sample.dropped)
        .map(|sample| sample.forward_ms.saturating_add(sample.quorum_ms))
        .collect();
    let mut p50 = committed.clone();
    let mut p95 = committed.clone();
    Ok(LatencyReport {
        committed_p50_ms: nearest_rank(&mut p50, 50)?,
        committed_p95_ms: nearest_rank(&mut p95, 95)?,
        committed_p99_ms: nearest_rank(&mut committed, 99)?,
        control_clusters: clusters.len() as u32,
        disagreements: samples.iter().filter(|sample| sample.disagreement).count() as u64,
        drops: samples.iter().filter(|sample| sample.dropped).count() as u64,
        refunds: samples.iter().filter(|sample| sample.refunded).count() as u64,
        all_surfaces_soft: true,
    })
}

/// Local hostile-dispute outcome. Public-testnet and challenger-economics
/// fields remain absent by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostileDisputeReport {
    pub isolated_position: u32,
    pub isolated_layer: u16,
    pub isolated_op: u16,
    pub local_bisection_rounds: u32,
    pub declared_public_rounds: u32,
    pub declared_public_transactions: u32,
    pub move_deadline: u64,
    pub wrong_job_lost: bool,
    pub unrelated_job_live: bool,
    pub late_move_rejected: bool,
    pub malformed_move_rejected: bool,
    pub frivolous_challenger_lost: bool,
}

fn signed_move(
    signer: &SigningKey,
    dispute_id: Hash32,
    round: u16,
    position: u32,
    left: Hash32,
    right: Hash32,
) -> BisectMove {
    let mut body = Vec::new();
    body.extend(dispute_id);
    body.extend(round.to_le_bytes());
    body.extend(position.to_le_bytes());
    body.extend(left);
    body.extend(right);
    let message = domain_hash(wire_domains::BISECT, &body);
    BisectMove {
        dispute_id,
        round,
        position,
        left,
        right,
        mover: signer.verifying_key().to_bytes(),
        signature: signer.sign(&message).to_bytes(),
    }
}

/// Run an actual T=32 local corruption through the existing referee.
pub fn run_hostile_dispute_local() -> Result<HostileDisputeReport, NelError> {
    let model = MiniModel::deterministic();
    let prompt = [1];
    let honest = run_lane(&model, [21; 32], &prompt, 32, None)?;
    let tamper = Tamper {
        position: 31,
        layer: 1,
        op: ops::DOWN,
        delta: 1,
    };
    let dishonest = run_lane(&model, [21; 32], &prompt, 32, Some(&tamper))?;
    let dispute = run_bisection(
        &model,
        &honest,
        &dishonest,
        FreivaldsProfile::ProductionReps4,
    )?;
    let frivolous = run_bisection(&model, &honest, &honest, FreivaldsProfile::ProductionReps4)?;
    let unrelated = run_lane(&model, [22; 32], &[2], 2, None)?;
    let executor = SigningKey::from_bytes(&[51; 32]);
    let challenger = SigningKey::from_bytes(&[52; 32]);
    let dispute_id = [53; 32];
    let open = DisputeOpen {
        dispute_id,
        chunk_claim_ref: honest.chunk_trace_root(),
        challenger: challenger.verifying_key().to_bytes(),
        challenger_bond: 1,
        alleged_s_end: *dishonest.states.last().ok_or(NelError::InvalidCount)?,
    };
    let deadline_fixture = Dispute::new(open.clone(), executor.verifying_key().to_bytes(), 100)?;
    let valid = signed_move(&executor, dispute_id, 0, 0, [54; 32], [55; 32]);
    let mut late_fixture = deadline_fixture.clone();
    let late_move_rejected = late_fixture.apply_move(&valid, 126) == Err(NelError::Deadline);
    let mut malformed = valid;
    malformed.left[0] ^= 1;
    let mut malformed_fixture = deadline_fixture;
    let malformed_move_rejected =
        malformed_fixture.apply_move(&malformed, 100) == Err(NelError::InvalidSignature);
    Ok(HostileDisputeReport {
        isolated_position: dispute.position,
        isolated_layer: dispute.layer,
        isolated_op: dispute.op,
        local_bisection_rounds: dispute.rounds,
        declared_public_rounds: DECLARED_DISPUTE_ROUNDS,
        declared_public_transactions: DECLARED_DISPUTE_TRANSACTIONS,
        move_deadline: DISPUTE_MOVE_DEADLINE,
        wrong_job_lost: dispute.verdict == Verdict::ExecutorFault,
        unrelated_job_live: !unrelated.states.is_empty(),
        late_move_rejected,
        malformed_move_rejected,
        frivolous_challenger_lost: frivolous.verdict == Verdict::ChallengerFault,
    })
}

/// One systematic shard plus a single XOR parity shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureObject {
    pub namespace: &'static str,
    pub object_root: Hash32,
    pub original_len: usize,
    pub data_shards: Vec<Vec<u8>>,
    pub parity_shard: Vec<u8>,
    pub operators: Vec<Hash32>,
}

impl ErasureObject {
    /// Encode all bytes into systematic shards and one XOR parity shard.
    pub fn encode(
        namespace: &'static str,
        bytes: &[u8],
        data_shards: usize,
        operators: Vec<Hash32>,
    ) -> Result<Self, LabError> {
        if bytes.is_empty()
            || data_shards < 2
            || operators.len() != data_shards + 1
            || operators.iter().collect::<BTreeSet<_>>().len() != operators.len()
        {
            return Err(LabError::InvalidShardGeometry);
        }
        let width = bytes.len().div_ceil(data_shards);
        let mut shards = vec![vec![0u8; width]; data_shards];
        for (index, byte) in bytes.iter().enumerate() {
            shards[index / width][index % width] = *byte;
        }
        let mut parity = vec![0u8; width];
        for shard in &shards {
            for (slot, byte) in parity.iter_mut().zip(shard) {
                *slot ^= *byte;
            }
        }
        let mut body = namespace.as_bytes().to_vec();
        body.extend(bytes);
        Ok(Self {
            namespace,
            object_root: domain_hash("NOOS/NEL/DA/OBJECT/V1", &body),
            original_len: bytes.len(),
            data_shards: shards,
            parity_shard: parity,
            operators,
        })
    }

    /// Reconstruct with no loss or one missing systematic shard. More loss
    /// fails closed and therefore cannot start an assurance clock.
    pub fn reconstruct(&self, missing: &BTreeSet<usize>) -> Result<Vec<u8>, LabError> {
        if missing.len() > 1 || missing.iter().any(|index| *index >= self.data_shards.len()) {
            return Err(LabError::Unavailable);
        }
        let mut shards = self.data_shards.clone();
        if let Some(&missing_index) = missing.iter().next() {
            let mut rebuilt = self.parity_shard.clone();
            for (index, shard) in shards.iter().enumerate() {
                if index != missing_index {
                    for (slot, byte) in rebuilt.iter_mut().zip(shard) {
                        *slot ^= *byte;
                    }
                }
            }
            shards[missing_index] = rebuilt;
        }
        let mut bytes: Vec<u8> = shards.into_iter().flatten().collect();
        bytes.truncate(self.original_len);
        let mut body = self.namespace.as_bytes().to_vec();
        body.extend(&bytes);
        if domain_hash("NOOS/NEL/DA/OBJECT/V1", &body) != self.object_root {
            return Err(LabError::InvalidArtifact);
        }
        Ok(bytes)
    }
}

/// Full local weights/activation DA plus 10^4 deterministic replay probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaReplayReport {
    pub weight_bytes: u64,
    pub activation_bytes: u64,
    pub weight_root: Hash32,
    pub activation_root: Hash32,
    pub single_loss_reconstructs: bool,
    pub correlated_loss_blocks_assurance: bool,
    pub replay_probes: u32,
    pub replay_mismatches: u32,
    pub poison_detected: bool,
    pub cross_domain_hits: u32,
}

/// Exercise all mini-profile weight and activation bytes, then sample 10^4
/// positions across two independently executed canonical state chains.
pub fn run_da_replay_local() -> Result<DaReplayReport, NelError> {
    let model = MiniModel::deterministic();
    let weights = model.canonical_weight_bytes();
    let run = run_lane(&model, [31; 32], &[1, 2, 3, 4], 32, None)?;
    let replay = run_lane(&model, [31; 32], &[1, 2, 3, 4], 32, None)?;
    let activations: Vec<u8> = run
        .steps
        .iter()
        .flat_map(|step| step.layer_outputs.iter())
        .flat_map(|layer| layer.iter().map(|value| value.cast_unsigned()))
        .collect();
    let weight_da = ErasureObject::encode(
        "weights",
        &weights,
        4,
        (1u8..=5).map(|id| [id; 32]).collect(),
    )
    .map_err(|_| NelError::InvalidTransition)?;
    let activation_da = ErasureObject::encode(
        "activations",
        &activations,
        4,
        (6u8..=10).map(|id| [id; 32]).collect(),
    )
    .map_err(|_| NelError::InvalidTransition)?;
    let mut one_missing = BTreeSet::new();
    one_missing.insert(2);
    let mut two_missing = one_missing.clone();
    two_missing.insert(3);
    let single_loss_reconstructs = weight_da
        .reconstruct(&one_missing)
        .is_ok_and(|rebuilt| rebuilt == weights)
        && activation_da
            .reconstruct(&one_missing)
            .is_ok_and(|rebuilt| rebuilt == activations);
    let correlated_loss_blocks_assurance = weight_da.reconstruct(&two_missing).is_err()
        && activation_da.reconstruct(&two_missing).is_err();
    let mut seed = 0x4e45_4c05u64;
    let mut replay_mismatches = 0u32;
    for _ in 0..KV_REPLAY_PROBES {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let index = usize::try_from(seed % run.states.len() as u64)
            .map_err(|_| NelError::ArithmeticOverflow)?;
        if run.states[index] != replay.states[index]
            || run.state_bodies[index].kv_commitment != replay.state_bodies[index].kv_commitment
        {
            replay_mismatches += 1;
        }
    }
    let mut poisoned = replay.state_bodies[1].clone();
    poisoned.kv_commitment[0] ^= 1;
    let poison_detected = poisoned.commitment() != run.state_bodies[1].commitment();
    let other_job = run_lane(&model, [32; 32], &[1, 2, 3, 4], 1, None)?;
    let cross_domain_hits =
        u32::from(run.state_bodies[1].kv_commitment == other_job.state_bodies[1].kv_commitment);
    Ok(DaReplayReport {
        weight_bytes: weights.len() as u64,
        activation_bytes: activations.len() as u64,
        weight_root: weight_da.object_root,
        activation_root: activation_da.object_root,
        single_loss_reconstructs,
        correlated_loss_blocks_assurance,
        replay_probes: KV_REPLAY_PROBES,
        replay_mismatches,
        poison_detected,
        cross_domain_hits,
    })
}

/// Provenance class for a specialized-proof benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofEvidenceClass {
    LocalFixture,
    Extrapolation,
    PublicHardwareRun,
}

/// Machine-verifiable E-NEL-06 benchmark record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBenchmarkRecord {
    pub evidence_class: ProofEvidenceClass,
    pub parameters: u64,
    pub chunk_tokens: u32,
    pub hardware: String,
    pub circuit_commit: Hash32,
    pub compiler_commit: Hash32,
    pub witness_peak_bytes: u64,
    pub prover_wall_ms: u64,
    pub prover_energy_mj: u64,
    pub prover_cost_microunits: u64,
    pub replicated_inference_cost_microunits: u64,
    pub proof_bytes: u64,
    pub aggregation_ms: u64,
    pub verifier_ms: u64,
    pub failed_proofs: u64,
    pub verifier_implementations: [String; 2],
    pub verifier_results: [Hash32; 2],
    pub challenge_window_ms: u64,
}

/// Validate a real benchmark record. Local fixtures and extrapolations are
/// rejected before economics are considered.
pub fn validate_proof_benchmark(record: &ProofBenchmarkRecord) -> Result<(), LabError> {
    match record.evidence_class {
        ProofEvidenceClass::PublicHardwareRun => {}
        ProofEvidenceClass::Extrapolation => return Err(LabError::ExtrapolatedProofEvidence),
        ProofEvidenceClass::LocalFixture => return Err(LabError::UnsupportedProofScale),
    }
    if record.parameters < 500_000_000
        || !(16..=32).contains(&record.chunk_tokens)
        || record.hardware.trim().is_empty()
        || record.circuit_commit == [0; 32]
        || record.compiler_commit == [0; 32]
        || record.witness_peak_bytes == 0
        || record.prover_energy_mj == 0
        || record.proof_bytes == 0
    {
        return Err(LabError::UnsupportedProofScale);
    }
    if record.verifier_implementations[0] == record.verifier_implementations[1]
        || record
            .verifier_implementations
            .iter()
            .any(|name| name.trim().is_empty())
        || record.verifier_results[0] != record.verifier_results[1]
    {
        return Err(LabError::IndependentVerifierRequired);
    }
    let max_cost = record
        .replicated_inference_cost_microunits
        .checked_mul(10)
        .ok_or(LabError::UnsupportedProofScale)?;
    if record.prover_cost_microunits > max_cost
        || record.prover_wall_ms > record.challenge_window_ms
        || record.verifier_ms >= 1_000
    {
        return Err(LabError::QualityToleranceExceeded);
    }
    Ok(())
}

/// Commit-before-beacon lifecycle. The output is uniquely committed by the
/// threshold protocol; withholding can stall/refund but cannot substitute
/// executor randomness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconRound {
    pub round: u64,
    pub execution_commitments: BTreeSet<Hash32>,
    pub commitments_closed: bool,
    pub unique_output_commitment: Hash32,
    pub beacon: Option<Hash32>,
    pub consumed_draws: BTreeSet<(Hash32, u32, u64)>,
    pub refunded: bool,
}

impl BeaconRound {
    #[must_use]
    pub fn new(round: u64, unique_output_commitment: Hash32) -> Self {
        Self {
            round,
            execution_commitments: BTreeSet::new(),
            commitments_closed: false,
            unique_output_commitment,
            beacon: None,
            consumed_draws: BTreeSet::new(),
            refunded: false,
        }
    }

    pub fn commit_execution(&mut self, commitment: Hash32) -> Result<(), LabError> {
        if self.commitments_closed {
            return Err(LabError::PostRevealCommitment);
        }
        self.execution_commitments.insert(commitment);
        Ok(())
    }

    pub fn close_commitments(&mut self) -> Result<(), LabError> {
        if self.execution_commitments.is_empty() {
            return Err(LabError::MissingRegistration);
        }
        self.commitments_closed = true;
        Ok(())
    }

    pub fn publish_beacon(&mut self, beacon: Hash32) -> Result<(), LabError> {
        if !self.commitments_closed {
            return Err(LabError::PostRevealCommitment);
        }
        if domain_hash("NOOS/NEL/BEACON/OUTPUT/V1", &beacon) != self.unique_output_commitment {
            return Err(LabError::InvalidArtifact);
        }
        self.beacon = Some(beacon);
        Ok(())
    }

    pub fn consume_draw(
        &mut self,
        job_id: Hash32,
        token_index: u32,
        draw_index: u64,
    ) -> Result<(), LabError> {
        if self.beacon.is_none() {
            return Err(LabError::BeaconUnavailable);
        }
        if !self
            .consumed_draws
            .insert((job_id, token_index, draw_index))
        {
            return Err(LabError::ReplayDraw);
        }
        Ok(())
    }

    pub fn timeout_refund(&mut self) -> Result<(), LabError> {
        if self.beacon.is_some() {
            return Err(LabError::InvalidArtifact);
        }
        self.refunded = true;
        Ok(())
    }
}

/// Deterministic million-schedule local grind study.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrindStudyReport {
    pub schedules: u64,
    pub post_reveal_commitments_accepted: u64,
    pub alternate_beacons_accepted: u64,
    pub replay_draws_accepted: u64,
    pub withholding_refunds: u64,
    pub greedy_cursor_is_zero: bool,
}

/// Enumerate 10^6 adversarial schedule choices. Withholding is deliberately
/// counted as bounded refund, not as a stochastic success or a 30-day stall
/// measurement.
pub fn run_grind_study() -> Result<GrindStudyReport, LabError> {
    let beacon = [41; 32];
    let commitment = domain_hash("NOOS/NEL/BEACON/OUTPUT/V1", &beacon);
    let mut post_reveal_commitments_accepted = 0u64;
    let mut alternate_beacons_accepted = 0u64;
    let mut replay_draws_accepted = 0u64;
    let mut withholding_refunds = 0u64;
    for schedule in 0..GRIND_SCHEDULES {
        let mut round = BeaconRound::new(schedule, commitment);
        round.commit_execution(domain_hash(
            "NOOS/NEL/EXECUTION/V1",
            &schedule.to_le_bytes(),
        ))?;
        round.close_commitments()?;
        if schedule % 17 == 0 {
            round.timeout_refund()?;
            withholding_refunds += 1;
            continue;
        }
        round.publish_beacon(beacon)?;
        if round.commit_execution([99; 32]).is_ok() {
            post_reveal_commitments_accepted += 1;
        }
        if round.publish_beacon([42; 32]).is_ok() {
            alternate_beacons_accepted += 1;
        }
        let job_id = domain_hash("NOOS/NEL/JOB/FIXTURE/V1", &schedule.to_le_bytes());
        round.consume_draw(job_id, 0, 0)?;
        if round.consume_draw(job_id, 0, 0).is_ok() {
            replay_draws_accepted += 1;
        }
    }
    // Phase B uses run_lane, whose state bodies pin rng_cursor to zero.
    let greedy = run_lane(&MiniModel::deterministic(), [43; 32], &[1], 2, None)
        .map_err(|_| LabError::InvalidArtifact)?;
    let greedy_cursor_is_zero = greedy
        .state_bodies
        .iter()
        .all(|state| state.rng_cursor == 0);
    // Also exercise the admitted sampler path once without treating it as
    // independent-client evidence.
    let _ = crate::inference::sample_token(
        &[9, 8, 7],
        SamplerParams {
            top_k: 2,
            top_p_q15: 32_767,
        },
        &beacon,
        &[44; 32],
        0,
        1,
        0,
    )
    .map_err(|_| LabError::InvalidArtifact)?;
    Ok(GrindStudyReport {
        schedules: GRIND_SCHEDULES,
        post_reveal_commitments_accepted,
        alternate_beacons_accepted,
        replay_draws_accepted,
        withholding_refunds,
        greedy_cursor_is_zero,
    })
}

/// Frozen production shard-size schema check, separate from the smaller
/// deterministic mini-profile fixture.
pub fn validate_production_shard_size(bytes: u32) -> Result<(), LabError> {
    if !(MIN_WEIGHT_SHARD_BYTES..=MAX_WEIGHT_SHARD_BYTES).contains(&bytes) {
        return Err(LabError::InvalidShardGeometry);
    }
    Ok(())
}

/// Whether a local latency report meets numeric thresholds. This does not
/// attest public clusters or turn local samples into E-NEL-03 evidence.
#[must_use]
pub fn local_latency_threshold(report: &LatencyReport) -> bool {
    report.committed_p95_ms < 2_000
        && report.committed_p99_ms < 5_000
        && report.control_clusters >= 3
        && report.all_surfaces_soft
}

/// Extract activation witness bytes from a run for external DA adapters.
#[must_use]
pub fn activation_witness_bytes(run: &LaneRun) -> Vec<u8> {
    run.steps
        .iter()
        .flat_map(|step| step.layer_outputs.iter())
        .flat_map(|layer| layer.iter().map(|value| value.cast_unsigned()))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn accuracy_registration() -> AccuracyPreregistration {
        AccuracyPreregistration {
            source_checkpoint: [1; 32],
            quantization_artifacts: [2; 32],
            calibration_artifacts: [3; 32],
            tasks: BTreeSet::from(["task-a".to_owned(), "task-b".to_owned()]),
            safety_tasks: BTreeSet::from(["safety".to_owned()]),
            minimum_samples_per_task: 100,
            maximum_quality_loss_ppm: 10_000,
            registered_at: 10,
            hidden_suite_opens_at: 11,
        }
    }

    #[test]
    fn full_local_profile_covers_every_op_family_and_two_schedules() {
        let report = audit_local_reference().unwrap();
        assert_eq!(report.semantic_op_families, u32::from(OPS_PER_LAYER) + 3);
        assert!(report.matmul_instances > 0);
        assert_eq!(report.schedule_mismatches, 0);
        assert_eq!(report.cobatch_mismatches, 0);
        assert!(report.invalid_tokenizer_bytes_rejected);
        assert!(report.contract_mutations_rejected);
        assert_ne!(report.profile_id, mini_profile_id());
    }

    #[test]
    fn accuracy_requires_every_preregistered_task_at_power() {
        let registration = accuracy_registration();
        let complete = [
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
        assert!(evaluate_accuracy(&registration, &complete).unwrap().passed);
        assert_eq!(
            evaluate_accuracy(&registration, &complete[..2]),
            Err(LabError::TaskSetMismatch)
        );
        let mut underpowered = complete.clone();
        underpowered[0].samples = 99;
        assert_eq!(
            evaluate_accuracy(&registration, &underpowered),
            Err(LabError::Underpowered)
        );
    }

    #[test]
    fn accuracy_exposes_one_task_crossing_the_tolerance() {
        let registration = accuracy_registration();
        let results = [
            AccuracyTaskResult {
                task: "task-a".to_owned(),
                samples: 100,
                source_score_ppm: 900_000,
                w8a8_score_ppm: 899_000,
            },
            AccuracyTaskResult {
                task: "task-b".to_owned(),
                samples: 100,
                source_score_ppm: 800_000,
                w8a8_score_ppm: 700_000,
            },
            AccuracyTaskResult {
                task: "safety".to_owned(),
                samples: 100,
                source_score_ppm: 990_000,
                w8a8_score_ppm: 990_000,
            },
        ];
        let report = evaluate_accuracy(&registration, &results).unwrap();
        assert!(!report.passed);
        assert_eq!(report.losses_ppm["task-b"], 100_000);
    }

    #[test]
    fn soft_latency_rejects_label_laundering_and_separates_refunds() {
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
        let mut experiment = LatencyExperiment::preregister(registration.clone()).unwrap();
        assert_eq!(experiment.state, LatencyExperimentState::Preregistered);
        experiment.start(11).unwrap();
        for index in 0..100u32 {
            experiment
                .record(LatencySample {
                    control_cluster: (index % 3) as u8,
                    forward_ms: 500 + index,
                    quorum_ms: 100,
                    anchoring_ms: 1_000,
                    onchain_inclusion_ms: 2_000,
                    proof_ms: 3_000,
                    disagreement: index == 1,
                    dropped: index == 2,
                    refunded: index == 2,
                    surface_label: FinalityClass::Soft,
                })
                .unwrap();
        }
        let report = experiment.seal().unwrap();
        assert_eq!(experiment.state, LatencyExperimentState::Sealed);
        assert!(local_latency_threshold(&report));
        assert_eq!((report.drops, report.refunds), (1, 1));
        let mut laundering = LatencyExperiment::preregister(registration).unwrap();
        laundering.start(11).unwrap();
        assert_eq!(
            laundering.record(LatencySample {
                control_cluster: 0,
                forward_ms: 1,
                quorum_ms: 1,
                anchoring_ms: 1,
                onchain_inclusion_ms: 1,
                proof_ms: 1,
                disagreement: false,
                dropped: false,
                refunded: false,
                surface_label: FinalityClass::Assured,
            }),
            Err(LabError::LabelLaundering)
        );
        assert_eq!(laundering.state, LatencyExperimentState::Invalidated);
    }

    #[test]
    fn hostile_t32_fixture_isolates_fault_and_keeps_unrelated_job_live() {
        let report = run_hostile_dispute_local().unwrap();
        assert_eq!(
            (
                report.isolated_position,
                report.isolated_layer,
                report.isolated_op
            ),
            (31, 1, ops::DOWN)
        );
        assert!(report.wrong_job_lost);
        assert!(report.unrelated_job_live);
        assert!(report.frivolous_challenger_lost);
        assert_eq!(report.move_deadline, 25);
        assert_eq!(report.declared_public_rounds, 19);
        assert_eq!(report.declared_public_transactions, 40);
    }

    #[test]
    fn full_local_da_reconstructs_and_poison_never_survives() {
        let report = run_da_replay_local().unwrap();
        assert!(report.weight_bytes > 0 && report.activation_bytes > 0);
        assert!(report.single_loss_reconstructs);
        assert!(report.correlated_loss_blocks_assurance);
        assert_eq!(report.replay_probes, 10_000);
        assert_eq!(report.replay_mismatches, 0);
        assert!(report.poison_detected);
        assert_eq!(report.cross_domain_hits, 0);
    }

    #[test]
    fn proof_interface_rejects_fixture_extrapolation_and_shared_verifier() {
        let mut record = ProofBenchmarkRecord {
            evidence_class: ProofEvidenceClass::Extrapolation,
            parameters: 500_000_000,
            chunk_tokens: 32,
            hardware: "named-hardware".to_owned(),
            circuit_commit: [1; 32],
            compiler_commit: [2; 32],
            witness_peak_bytes: 1,
            prover_wall_ms: 1,
            prover_energy_mj: 1,
            prover_cost_microunits: 10,
            replicated_inference_cost_microunits: 1,
            proof_bytes: 1,
            aggregation_ms: 1,
            verifier_ms: 1,
            failed_proofs: 0,
            verifier_implementations: ["a".to_owned(), "b".to_owned()],
            verifier_results: [[3; 32], [3; 32]],
            challenge_window_ms: 2,
        };
        assert_eq!(
            validate_proof_benchmark(&record),
            Err(LabError::ExtrapolatedProofEvidence)
        );
        record.evidence_class = ProofEvidenceClass::LocalFixture;
        assert_eq!(
            validate_proof_benchmark(&record),
            Err(LabError::UnsupportedProofScale)
        );
        record.evidence_class = ProofEvidenceClass::PublicHardwareRun;
        record.verifier_implementations[1] = "a".to_owned();
        assert_eq!(
            validate_proof_benchmark(&record),
            Err(LabError::IndependentVerifierRequired)
        );
    }

    #[test]
    fn million_schedule_grind_study_fails_closed() {
        let report = run_grind_study().unwrap();
        assert_eq!(report.schedules, 1_000_000);
        assert_eq!(report.post_reveal_commitments_accepted, 0);
        assert_eq!(report.alternate_beacons_accepted, 0);
        assert_eq!(report.replay_draws_accepted, 0);
        assert!(report.withholding_refunds > 0);
        assert!(report.greedy_cursor_is_zero);
    }

    #[test]
    fn production_shard_geometry_is_exact() {
        assert!(validate_production_shard_size(4 * 1024 * 1024).is_ok());
        assert!(validate_production_shard_size(16 * 1024 * 1024).is_ok());
        assert_eq!(
            validate_production_shard_size(4 * 1024 * 1024 - 1),
            Err(LabError::InvalidShardGeometry)
        );
    }
}
