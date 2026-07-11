#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use super::*;
use serde_json::Value;

fn model() -> MiniModel {
    MiniModel::deterministic()
}

fn job(byte: u8) -> Hash32 {
    [byte; 32]
}

fn honest_run() -> LaneRun {
    run_lane(&model(), job(7), &[1, 2, 3, 4], 8, None).unwrap()
}

fn hex(h: &Hash32) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn vector_json() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/nel/forward-w8a8-v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

// ------------------------------------------------------------------ N-PROFILE

#[test]
fn isqrt_pinned_matches_floor_sqrt_everywhere_probed() {
    for v in 0u64..100_000 {
        assert_eq!(isqrt_pinned(v), v.isqrt(), "v={v}");
    }
    for v in [
        u64::MAX,
        u64::MAX - 1,
        1 << 62,
        (1 << 32) - 1,
        1 << 32,
        (1 << 32) + 1,
        u64::from(u32::MAX) * u64::from(u32::MAX),
        u64::from(u32::MAX) * u64::from(u32::MAX) - 1,
    ] {
        assert_eq!(isqrt_pinned(v), v.isqrt(), "v={v}");
    }
}

#[test]
fn requant_is_the_exact_floor_quotient_round_half_up_identity() {
    // Reference: q = sat8(floor((acc * mult + 2^(shift-1)) / 2^shift)) in i128.
    for &(acc, mult, shift) in &[
        (3i64, 1i64, 1u32),
        (-3, 1, 1),
        (2047, 1, 11),
        (-2047, 1, 11),
        (1024, 1, 11),
        (-1024, 1, 11),
        (1023, 1, 11),
        (i64::from(i32::MAX), 1, 15),
        (i64::from(i32::MIN), 1, 15),
        (129 << 11, 1, 11),
        (-129 << 11, 1, 11),
    ] {
        let num = i128::from(acc) * i128::from(mult) + (1i128 << (shift - 1));
        let q = num.div_euclid(1i128 << shift);
        let expect = q.clamp(-128, 127) as i8;
        assert_eq!(requant(acc, mult, shift), expect, "acc={acc} shift={shift}");
    }
    // Round-half-up at the boundary: +0.5 rounds up, -0.5 rounds toward +inf.
    assert_eq!(requant(1, 1, 1), 1);
    assert_eq!(requant(-1, 1, 1), 0);
}

#[test]
fn gemm_accumulator_lemma_rejects_unregistrable_shapes() {
    // G8: k * 127 * 127 must stay below 2^31; the first violating k.
    let k_bad = usize::try_from((1i64 << 31) / (127 * 127) + 1).unwrap();
    let a = vec![0i8; k_bad];
    let b = vec![0i8; k_bad];
    assert_eq!(
        gemm_i8(&a, &b, 1, k_bad, 1),
        Err(NelError::ArithmeticOverflow)
    );
    let k_pv = usize::try_from((1i64 << 31) / (32_767 * 127) + 1).unwrap();
    let p = vec![0i16; k_pv];
    let v = vec![0i8; k_pv];
    assert_eq!(
        gemm_pv(&p, &v, 1, k_pv, 1),
        Err(NelError::ArithmeticOverflow)
    );
    // In-lemma shapes accept and never saturate accumulators.
    assert!(gemm_i8(&[127; 64], &[127; 64], 1, 64, 1).is_ok());
}

#[test]
fn integer_gemm_is_reduction_order_invariant() {
    // The structural vendor-invariance argument at mini scale: summation in
    // reverse (a different "schedule") produces identical accumulators.
    let a = tensor_i8("sched.a", 16 * 32);
    let b = tensor_i8("sched.b", 32 * 24);
    let c = gemm_i8(&a, &b, 16, 32, 24).unwrap();
    let mut c_rev = vec![0i32; 16 * 24];
    for row in 0..16 {
        for col in 0..24 {
            let mut acc = 0i32;
            for x in (0..32).rev() {
                acc += i32::from(a[row * 32 + x]) * i32::from(b[x * 24 + col]);
            }
            c_rev[row * 24 + col] = acc;
        }
    }
    assert_eq!(c, c_rev);
}

#[test]
fn softmax_rows_are_q15_capped_masked_and_order_preserving() {
    // A single visible entry takes the full (capped) mass.
    let p = softmax_q15(&[100, 0, 0], 1).unwrap();
    assert_eq!(p[0], 32_767);
    assert_eq!((p[1], p[2]), (0, 0));
    // Masked entries are pinned to zero and total mass is ~1.0 in Q1.15.
    let p = softmax_q15(&[5_000, 4_000, 3_000, 9_999], 3).unwrap();
    assert_eq!(p[3], 0);
    assert!(p[0] >= p[1] && p[1] >= p[2], "monotone in score");
    let total: i64 = p.iter().map(|&x| i64::from(x)).sum();
    assert!((32_000..=33_000).contains(&total), "total={total}");
    assert_eq!(softmax_q15(&[1], 0), Err(NelError::InvalidCount));
}

#[test]
fn forward_is_bit_deterministic_across_runs() {
    let a = honest_run();
    let b = honest_run();
    assert_eq!(a.states, b.states);
    assert_eq!(a.tokens, b.tokens);
    assert_eq!(a.trace_roots, b.trace_roots);
    assert_eq!(a.cache, b.cache);
}

#[test]
fn frozen_forward_vector_matches_bit_for_bit() {
    let v = vector_json();
    assert_eq!(v["schema"].as_str().unwrap(), "NOOS/NEL/FORWARD-W8A8/V1");
    let case = |name: &str| -> (String, bool) {
        let c = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing case {name}"));
        (
            c["bytes"].as_str().unwrap().to_owned(),
            c["kind"].as_str() == Some("positive"),
        )
    };
    let run = honest_run();
    for (name, actual) in [
        ("lut-root", hex(&lut_root())),
        ("profile-id", hex(&mini_profile_id())),
        ("weight-root", hex(&run.model_root)),
        ("s-end", hex(run.states.last().unwrap())),
        ("chunk-trace-root", hex(&run.chunk_trace_root())),
        (
            "tokens-u32le",
            run.tokens
                .iter()
                .flat_map(|t| t.to_le_bytes())
                .map(|b| format!("{b:02x}"))
                .collect(),
        ),
    ] {
        let (frozen, positive) = case(name);
        assert!(positive, "{name} must be a positive case");
        assert_eq!(actual, frozen, "{name} drifted from the frozen profile");
    }
    // The negative case is a corrupted S_end no implementation may emit.
    let (corrupt, positive) = case("s-end-single-bit-corruption");
    assert!(!positive);
    assert_ne!(hex(run.states.last().unwrap()), corrupt);
}

#[test]
fn falsifier_single_weight_flip_diverges_and_changes_identity() {
    let mut m = model();
    m.embed[0] = m.embed[0].wrapping_add(1);
    let honest = honest_run();
    let flipped = run_lane(&m, job(7), &[1, 2, 3, 4], 8, None).unwrap();
    assert_ne!(m.weight_root(), honest.model_root, "new weight identity");
    assert_ne!(
        flipped.states.last(),
        honest.states.last(),
        "one weight bit is consensus-visible"
    );
}

// -------------------------------------------------------------- N-TOKEN-STATE

#[test]
fn state_commitment_binds_every_field() {
    let run = honest_run();
    let base = run.state_bodies.last().unwrap().clone();
    let c0 = base.commitment();
    let mutations: Vec<TokenStateCommitment> = vec![
        TokenStateCommitment {
            job_id: [9; 32],
            ..base.clone()
        },
        TokenStateCommitment {
            model_root: [9; 32],
            ..base.clone()
        },
        TokenStateCommitment {
            numeric_profile: [9; 32],
            ..base.clone()
        },
        TokenStateCommitment {
            t: base.t + 1,
            ..base.clone()
        },
        TokenStateCommitment {
            token_history_root: [9; 32],
            ..base.clone()
        },
        TokenStateCommitment {
            kv_commitment: [9; 32],
            ..base.clone()
        },
        TokenStateCommitment {
            rng_cursor: base.rng_cursor + 1,
            ..base.clone()
        },
        TokenStateCommitment {
            trace_root: [9; 32],
            ..base.clone()
        },
    ];
    for (i, m) in mutations.iter().enumerate() {
        assert_ne!(m.commitment(), c0, "field {i} not bound");
    }
}

#[test]
fn falsifier_cross_job_replay_produces_disjoint_chains() {
    let a = run_lane(&model(), job(7), &[1, 2, 3, 4], 4, None).unwrap();
    let b = run_lane(&model(), job(8), &[1, 2, 3, 4], 4, None).unwrap();
    assert_eq!(a.tokens, b.tokens, "same execution");
    for (sa, sb) in a.states.iter().zip(&b.states) {
        assert_ne!(sa, sb, "a state is replayable across jobs");
    }
}

#[test]
fn token_history_root_is_positional_and_append_only() {
    let r1 = token_history_root(&[1, 2, 3]);
    let r2 = token_history_root(&[3, 2, 1]);
    let r3 = token_history_root(&[1, 2]);
    let r4 = token_history_root(&[1, 2, 3, 4]);
    assert_ne!(r1, r2);
    assert_ne!(r1, r3);
    assert_ne!(r1, r4);
    assert_eq!(r1, token_history_root(&[1, 2, 3]));
}

#[test]
fn first_state_divergence_is_binary_searchable() {
    // The chain property: two parties disagreeing about a stream disagree
    // about a first index, findable by binary search over commitments.
    let honest = honest_run();
    let tamper = Tamper {
        position: 6,
        layer: 1,
        op: ops::GATE,
        delta: 17,
    };
    let claimed = run_lane(&model(), job(7), &[1, 2, 3, 4], 8, Some(&tamper)).unwrap();
    let first = claimed
        .states
        .iter()
        .zip(&honest.states)
        .position(|(a, b)| a != b)
        .unwrap();
    // S_7 is the first commitment covering step 6.
    assert_eq!(first, 7);
    assert_eq!(&claimed.states[..first], &honest.states[..first]);
}

// ---------------------------------------------------------- N-CHUNK-FREIVALDS

fn chunk_records(run: &LaneRun, layer: u16, op: u16, t: usize) -> Vec<&MatMulRecord> {
    run.steps
        .iter()
        .take(t)
        .map(|s| {
            s.matmuls
                .iter()
                .find(|r| r.layer == layer && r.op == op)
                .unwrap()
        })
        .collect()
}

#[test]
fn chunk_freivalds_accepts_honest_chunks_and_the_cost_law_is_exactly_one_over_t() {
    let run = run_lane(&model(), job(3), &[1, 2, 3], 30, None).unwrap();
    assert!(run.steps.len() >= 32);
    let root = run.chunk_trace_root();
    let reps = FreivaldsProfile::StandardReps2.reps() as u64;
    let (k, n) = (HIDDEN as u64, MLP as u64);
    let a_term = reps * k * n; // chunk-fixed W·r cost
    let b_term = reps * (k + n); // per-token marginal
    let mut prev_per_token = u64::MAX;
    let mut prev_speedup_num = 0u64;
    let mut prev_speedup_den = 1u64;
    for t in [1usize, 2, 4, 8, 16, 32] {
        let records = chunk_records(&run, 0, ops::GATE, t);
        let report =
            verify_chunk_op(&model(), &records, &root, FreivaldsProfile::StandardReps2).unwrap();
        assert!(report.accepted, "honest chunk rejected at T={t}");
        // Exact measured law: muls(T) = A + B*T  <=>  per-token = A/T + B.
        let t64 = t as u64;
        assert_eq!(report.multiplications, a_term + b_term * t64, "T={t}");
        assert_eq!(
            report.multiplications,
            freivalds_cost_muls(t64, k, n, reps),
            "declared law drifts from measured count at T={t}"
        );
        let per_token = report.multiplications / t64;
        assert!(per_token < prev_per_token, "per-token cost must fall in T");
        prev_per_token = per_token;
        // Speedup vs direct recompute grows with T.
        let direct = recompute_cost_muls(t64, k, n);
        assert!(
            direct * prev_speedup_den >= prev_speedup_num * report.multiplications,
            "speedup must be monotone in T"
        );
        prev_speedup_num = direct;
        prev_speedup_den = report.multiplications;
    }
    // At T=32 the chunk verifier beats recompute on this shape.
    let records = chunk_records(&run, 0, ops::GATE, 32);
    let report =
        verify_chunk_op(&model(), &records, &root, FreivaldsProfile::StandardReps2).unwrap();
    assert!(recompute_cost_muls(32, k, n) > report.multiplications);
}

#[test]
fn falsifier_chunk_freivalds_rejects_every_single_element_tamper() {
    let run = run_lane(&model(), job(3), &[1, 2, 3], 10, None).unwrap();
    let root = run.chunk_trace_root();
    let m = model();
    let weight_ops: [(u16, u16); 6] = [
        (0, ops::QKV),
        (0, ops::GATE),
        (0, ops::UP),
        (1, ops::OUT),
        (1, ops::DOWN),
        (LAYERS as u16, ops::LM_HEAD),
    ];
    for &(layer, op) in &weight_ops {
        let records = chunk_records(&run, layer, op, 8);
        let honest = verify_chunk_op(&m, &records, &root, FreivaldsProfile::StandardReps2).unwrap();
        assert!(honest.accepted, "layer {layer} op {op}");
        // Tamper exactly one accumulator element in one token of the chunk.
        let mut tampered: Vec<MatMulRecord> = records.iter().map(|r| (*r).clone()).collect();
        tampered[3].c[1] = tampered[3].c[1].wrapping_add(1);
        let refs: Vec<&MatMulRecord> = tampered.iter().collect();
        let report = verify_chunk_op(&m, &refs, &root, FreivaldsProfile::StandardReps2).unwrap();
        assert!(!report.accepted, "tamper accepted at layer {layer} op {op}");
        // REPS=4 production profile rejects it too.
        let report4 = verify_chunk_op(&m, &refs, &root, FreivaldsProfile::ProductionReps4).unwrap();
        assert!(!report4.accepted);
    }
}

#[test]
fn counting_verifier_agrees_with_frozen_freivalds_verifier() {
    // Dual-verifier agreement: the counted twin and the frozen public
    // verifier accept and reject the same transcripts.
    let run = run_lane(&model(), job(3), &[1, 2, 3], 6, None).unwrap();
    let root = run.chunk_trace_root();
    let m = model();
    let records = chunk_records(&run, 0, ops::QKV, 4);
    let b = u64s(&m.weight_i64(WeightId::Qkv(0)).unwrap());
    let mut a = Vec::new();
    let mut c = Vec::new();
    for r in &records {
        a.extend(u64s(&r.a));
        c.extend(u64s(&r.c));
    }
    let vectors = challenge_vectors(&root, QKV_DIM, 2);
    let frozen = freivalds_verify_u64(
        &a,
        &b,
        &c,
        4,
        HIDDEN,
        QKV_DIM,
        &vectors,
        FreivaldsProfile::StandardReps2,
    )
    .unwrap();
    let counted = freivalds_verify_u64_counted(
        &a,
        &b,
        &c,
        4,
        HIDDEN,
        QKV_DIM,
        &vectors,
        FreivaldsProfile::StandardReps2,
    )
    .unwrap();
    assert!(frozen && counted.accepted);
    let mut bad = c.clone();
    bad[5] = bad[5].wrapping_add(1);
    let frozen = freivalds_verify_u64(
        &a,
        &b,
        &bad,
        4,
        HIDDEN,
        QKV_DIM,
        &vectors,
        FreivaldsProfile::StandardReps2,
    )
    .unwrap();
    let counted = freivalds_verify_u64_counted(
        &a,
        &b,
        &bad,
        4,
        HIDDEN,
        QKV_DIM,
        &vectors,
        FreivaldsProfile::StandardReps2,
    )
    .unwrap();
    assert!(!frozen && !counted.accepted);
}

#[test]
fn frozen_verifier_freivalds_vector_still_passes() {
    // The Workerd-consumed public API stays bit-stable: the checked-in
    // verifier vector from protocol/vectors/nel must keep verifying.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/nel/verifier-freivalds-v1.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(v.get("cases").is_some());
}

// -------------------------------------------------------------------- N-BISECT

#[test]
fn bisection_converges_to_a_tampered_gemm_leaf_and_faults_the_executor() {
    let honest = honest_run();
    let tamper = Tamper {
        position: 5,
        layer: 1,
        op: ops::QKV,
        delta: 33,
    };
    let claimed = run_lane(&model(), job(7), &[1, 2, 3, 4], 8, Some(&tamper)).unwrap();
    let report =
        run_bisection(&model(), &honest, &claimed, FreivaldsProfile::StandardReps2).unwrap();
    assert_eq!(report.verdict, Verdict::ExecutorFault);
    assert_eq!(report.position, 5);
    assert_eq!(report.layer, 1);
    assert_eq!(report.op, ops::QKV);
    // Descent is logarithmic in the grid, never linear.
    let max_rounds = (usize::BITS - (honest.states.len() - 1).leading_zeros())
        + (usize::BITS - (LAYERS + 1).leading_zeros())
        + (usize::BITS - usize::from(OPS_PER_LAYER).leading_zeros());
    assert!(report.rounds <= max_rounds, "rounds {}", report.rounds);
}

#[test]
fn bisection_converges_to_a_tampered_nonlinear_leaf() {
    let honest = honest_run();
    for (layer, op) in [
        (0u16, ops::SOFTMAX),
        (0, ops::RMS1),
        (1, ops::SILU_MUL),
        (LAYERS as u16, ops::FINAL_RMS),
    ] {
        let tamper = Tamper {
            position: 3,
            layer,
            op,
            delta: 5,
        };
        let claimed = run_lane(&model(), job(7), &[1, 2, 3, 4], 8, Some(&tamper)).unwrap();
        let report =
            run_bisection(&model(), &honest, &claimed, FreivaldsProfile::StandardReps2).unwrap();
        assert_eq!(report.verdict, Verdict::ExecutorFault, "l{layer} o{op}");
        assert_eq!(report.position, 3);
        assert_eq!(report.layer, layer);
        assert_eq!(report.op, op);
    }
}

#[test]
fn falsifier_frivolous_challenge_against_honest_executor_loses() {
    let honest = honest_run();
    let claimed = honest_run();
    let report =
        run_bisection(&model(), &honest, &claimed, FreivaldsProfile::StandardReps2).unwrap();
    assert_eq!(report.verdict, Verdict::ChallengerFault);
    assert_eq!(report.rounds, 0);
}

#[test]
fn falsifier_cheating_prover_cannot_win_from_any_single_op_corruption() {
    // Sweep every op family at one grid point: whatever the cheater
    // corrupts, the descent isolates it and the exact referee rejects.
    let honest = honest_run();
    for op in 0..OPS_PER_LAYER {
        let tamper = Tamper {
            position: 4,
            layer: 0,
            op,
            delta: 9,
        };
        let claimed = run_lane(&model(), job(7), &[1, 2, 3, 4], 8, Some(&tamper)).unwrap();
        if claimed.states == honest.states {
            // A corruption that never reaches any commitment is not a lie.
            continue;
        }
        let report =
            run_bisection(&model(), &honest, &claimed, FreivaldsProfile::StandardReps2).unwrap();
        assert_eq!(report.verdict, Verdict::ExecutorFault, "op {op} escaped");
    }
}

// -------------------------------------------------------------------- N-ACT-DA

#[test]
fn activation_witness_reveals_verify_and_tampered_reveals_reject() {
    let run = honest_run();
    let step = &run.steps[2];
    // Rebuild the committed leaf set for step 2 exactly as run_lane does.
    let mut leaves: Vec<Hash32> = step
        .layer_outputs
        .iter()
        .enumerate()
        .map(|(l, bytes)| {
            let raw: Vec<u8> = bytes.iter().map(|&x| x.cast_unsigned()).collect();
            activation_leaf(&run.job_id, 2, l as u16, &raw)
        })
        .collect();
    for (l, layer_ops) in step.op_payloads.iter().enumerate() {
        for (o, payload) in layer_ops.iter().enumerate() {
            leaves.push(op_commitment(l as u16, o as u16, payload));
        }
    }
    let root = merkle_root(&leaves);
    assert_eq!(root, run.trace_roots[2], "trace root reconstruction");
    // Reveal-on-dispute: open layer 1's activation block.
    let proof = merkle_open(&leaves, 1).unwrap();
    let raw: Vec<u8> = step.layer_outputs[1]
        .iter()
        .map(|&x| x.cast_unsigned())
        .collect();
    let leaf = activation_leaf(&run.job_id, 2, 1, &raw);
    assert!(merkle_verify(&root, &leaf, &proof));
    // Falsifier: a tampered reveal is Merkle-inconsistent.
    let mut bad = raw.clone();
    bad[0] ^= 1;
    let bad_leaf = activation_leaf(&run.job_id, 2, 1, &bad);
    assert!(!merkle_verify(&root, &bad_leaf, &proof));
    // Falsifier: a transplanted proof (wrong index) rejects.
    let wrong = MerkleProof {
        index: proof.index + 1,
        path: proof.path.clone(),
    };
    assert!(!merkle_verify(&root, &leaf, &wrong));
    // A root proves identity, not availability: the same root is
    // reconstructible only from the leaves themselves.
    assert_ne!(merkle_root(&leaves[..1]), root);
}

#[test]
fn commit_bytes_stay_constant_while_reveal_bytes_scale_with_hidden() {
    // The commit-vs-reveal asymmetry that makes the lean profile a lane:
    // the chain carries one 32-byte root per step; the witness bytes are
    // HIDDEN per layer, revealed only on dispute.
    let run = honest_run();
    assert_eq!(run.trace_roots.len(), run.steps.len());
    for step in &run.steps {
        let reveal: usize = step.layer_outputs.iter().map(Vec::len).sum();
        assert_eq!(reveal, HIDDEN * LAYERS);
    }
}

// ----------------------------------------------------------------- N-KV-REPLAY

#[test]
fn kv_checkpoint_equals_canonical_replay_at_every_position() {
    let run = honest_run();
    // Canonical replay: rebuild KV from the committed token history alone.
    let mut cache = KvCache::default();
    for (pos, &tok) in run.tokens[..run.steps.len()].iter().enumerate() {
        forward_token(&model(), &mut cache, pos as u32, tok, None).unwrap();
        let replayed = cache.commitment(&run.model_root, &run.profile_id, &run.job_id);
        assert_eq!(
            replayed,
            run.state_bodies[pos + 1].kv_commitment,
            "replay diverged at position {pos}"
        );
    }
    assert_eq!(cache, run.cache, "full logical KV state replays exactly");
}

#[test]
fn falsifier_poisoned_kv_checkpoint_is_caught_before_signing() {
    let run = honest_run();
    let mut poisoned = run.cache.clone();
    poisoned.layers[0].k[3][2] = poisoned.layers[0].k[3][2].wrapping_add(1);
    let commitment = poisoned.commitment(&run.model_root, &run.profile_id, &run.job_id);
    assert_ne!(
        commitment,
        run.state_bodies.last().unwrap().kv_commitment,
        "a poisoned checkpoint must not match the committed logical KV"
    );
}

#[test]
fn falsifier_kv_commitment_binds_job_model_and_profile() {
    // Cross-tenant / cross-model cache reuse is a profile violation: the
    // same bytes under a different binding tuple commit differently.
    let run = honest_run();
    let base = run
        .cache
        .commitment(&run.model_root, &run.profile_id, &run.job_id);
    assert_ne!(
        base,
        run.cache
            .commitment(&run.model_root, &run.profile_id, &job(9))
    );
    assert_ne!(
        base,
        run.cache.commitment(&[9; 32], &run.profile_id, &run.job_id)
    );
    assert_ne!(
        base,
        run.cache.commitment(&run.model_root, &[9; 32], &run.job_id)
    );
}

// ------------------------------------------------------------------ N-SAMPLER

fn flat_logits() -> Vec<i32> {
    vec![1_000; 8]
}

#[test]
fn sampler_is_a_pure_function_of_the_derivation_tuple() {
    let logits = [9_000, 8_500, 8_000, 100].to_vec();
    let params = SamplerParams {
        top_k: 4,
        top_p_q15: 32_768,
    };
    let (t1, c1) = sample_token(&logits, params, &job(1), &job(2), 5, 3, 0).unwrap();
    let (t2, c2) = sample_token(&logits, params, &job(1), &job(2), 5, 3, 0).unwrap();
    assert_eq!((t1, c1), (t2, c2), "identical tuple, identical draw");
    assert_eq!(c1, 1, "cursor advances by exactly one");
    // Every tuple component moves the variate.
    let base = draw_hash(&job(1), &job(2), 5, 3, 0);
    assert_ne!(base, draw_hash(&job(9), &job(2), 5, 3, 0), "beacon");
    assert_ne!(base, draw_hash(&job(1), &job(9), 5, 3, 0), "job");
    assert_ne!(base, draw_hash(&job(1), &job(2), 6, 3, 0), "token index");
    assert_ne!(base, draw_hash(&job(1), &job(2), 5, 4, 0), "round");
    assert_ne!(base, draw_hash(&job(1), &job(2), 5, 3, 1), "draw index");
}

#[test]
fn falsifier_no_executor_input_can_grind_the_draw() {
    // The derivation tuple is (beacon, job, position, round, cursor); an
    // executor holds none of them freely. Grinding the cursor is the one
    // residual dial, and the cursor is bound inside S_t: a cursor lie is a
    // state-commitment lie.
    let run = honest_run();
    let body = run.state_bodies.last().unwrap().clone();
    let honest_commitment = body.commitment();
    let ground = TokenStateCommitment {
        rng_cursor: body.rng_cursor + 5,
        ..body
    };
    assert_ne!(ground.commitment(), honest_commitment);
    // And different cursors genuinely change the sampled token on flat mass.
    let params = SamplerParams {
        top_k: 8,
        top_p_q15: 32_768,
    };
    let picks: std::collections::BTreeSet<u32> = (0..16)
        .map(|cursor| {
            sample_token(&flat_logits(), params, &job(1), &job(2), 0, 0, cursor)
                .unwrap()
                .0
        })
        .collect();
    assert!(picks.len() > 1, "cursor is draw-relevant");
}

#[test]
fn sampler_tie_topk_and_topp_rules_are_pinned() {
    // Ties order by lowest token id.
    let (t, _) = sample_token(
        &flat_logits(),
        SamplerParams {
            top_k: 1,
            top_p_q15: 32_768,
        },
        &job(1),
        &job(2),
        0,
        0,
        0,
    )
    .unwrap();
    assert_eq!(t, 0, "tie resolves to lowest token id");
    // top_k=1 degenerates to greedy for any beacon.
    let logits = [50, 9_000, 400, 8_999].to_vec();
    for b in 0..8u8 {
        let (t, _) = sample_token(
            &logits,
            SamplerParams {
                top_k: 1,
                top_p_q15: 1,
            },
            &job(b),
            &job(2),
            0,
            0,
            0,
        )
        .unwrap();
        assert_eq!(Some(t), crate::greedy_token(&logits));
    }
    // top-p boundary is inclusive: a head token holding >= p keeps the
    // prefix at length one, so the draw is forced.
    let peaked = [100_000, 0, 0, 0].to_vec();
    for b in 0..8u8 {
        let (t, _) = sample_token(
            &peaked,
            SamplerParams {
                top_k: 4,
                top_p_q15: 32_000,
            },
            &job(b),
            &job(2),
            0,
            0,
            0,
        )
        .unwrap();
        assert_eq!(t, 0);
    }
    assert_eq!(
        sample_token(
            &flat_logits(),
            SamplerParams {
                top_k: 0,
                top_p_q15: 1
            },
            &job(1),
            &job(2),
            0,
            0,
            0
        ),
        Err(NelError::InvalidCount)
    );
}

#[test]
fn sampler_matches_independent_reference_implementation_on_small_vectors() {
    // Second implementation of the pinned pseudocode, written differently.
    #[allow(clippy::too_many_arguments)]
    fn reference(
        logits: &[i32],
        k: u32,
        p_q15: u32,
        beacon: &Hash32,
        jid: &Hash32,
        t: u32,
        round: u64,
        cursor: u64,
    ) -> u32 {
        let masses = softmax_q15(logits, logits.len()).unwrap();
        let mut idx: Vec<u32> = (0..logits.len() as u32).collect();
        idx.sort_by_key(|&i| (-i64::from(masses[i as usize]), i));
        idx.truncate(k as usize);
        let mut kept = Vec::new();
        let mut cum = 0u64;
        for &i in &idx {
            kept.push(i);
            cum += u64::from(masses[i as usize].max(0).cast_unsigned());
            if cum >= u64::from(p_q15) {
                break;
            }
        }
        let total: u64 = kept
            .iter()
            .map(|&i| u64::from(masses[i as usize].max(0).cast_unsigned()))
            .sum();
        let u = draw_hash(beacon, jid, t, round, cursor);
        let mut target = 0u64;
        for &byte in &u {
            target = (target.wrapping_mul(256).wrapping_add(u64::from(byte))) % total;
        }
        let mut acc = 0u64;
        for &i in &kept {
            acc += u64::from(masses[i as usize].max(0).cast_unsigned());
            if acc > target {
                return i;
            }
        }
        unreachable!()
    }
    let vectors: [(&[i32], u32, u32); 6] = [
        (&[10, 20, 30], 3, 32_768),
        (&[5_000, 4_000, 3_000, 2_000], 2, 32_768),
        (&[5_000, 4_000, 3_000, 2_000], 4, 16_384),
        (&[0, 0, 0, 0, 0], 5, 32_768),
        (&[1_000, 1_000, 500], 2, 8_192),
        (&[9_999, 1, 1, 1, 1, 1, 1, 1], 8, 32_768),
    ];
    for (i, &(logits, k, p)) in vectors.iter().enumerate() {
        for cursor in 0..8 {
            let params = SamplerParams {
                top_k: k,
                top_p_q15: p,
            };
            let (got, _) = sample_token(logits, params, &job(11), &job(12), 1, 2, cursor).unwrap();
            let want = reference(logits, k, p, &job(11), &job(12), 1, 2, cursor);
            assert_eq!(got, want, "vector {i} cursor {cursor}");
        }
    }
}

#[test]
fn greedy_lane_keeps_rng_cursor_frozen() {
    // Phase B is randomness-free: every committed state pins cursor 0.
    let run = honest_run();
    for body in &run.state_bodies {
        assert_eq!(body.rng_cursor, 0);
    }
}
