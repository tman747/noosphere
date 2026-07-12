//! E-WEFT-03 — Derived-verifier parity (ch04 §3.7).
//!
//! Claim under test: a verifier derived from `Tensor<i8,[m,k],@W8A8v1>`
//! reproduces the kt-ladder Freivalds span relation, transcript, and
//! tamper behavior at 32^3. Pass: byte-identical roots; all seven
//! tamper/transplant/splice gates reject, including a payout identity
//! transplant; verifier scaling exponent in
//! [1.9, 2.1]. Kill: any tamper acceptance.
//!
//! Both admission paths run on every gate: the re-derivation path
//! (`admit_span_certificate`) and the O(n^2) Freivalds path
//! (`admit_span_certificate_freivalds`). The RISC Zero derived-guest cycle
//! envelope (<= 1.15 x 61,175 cycles) needs the external zkVM toolchain and
//! stays an explicit external gap; the multiply-accumulate census below is
//! the local deterministic proxy for the same regression.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]

use noos_weft_compile::{
    admit_span_certificate, admit_span_certificate_freivalds, commit_span_transcript, compile,
    derive_span_certificate, freivalds_span_check, gemm_i8, project_span, requant_w8a8,
    CertificateError, SpanCertificate,
};

const CHALLENGE: [u32; 2] = [0x2026_0711, 0x0BAD_5EED];
const MULT: u32 = 3;
const SHIFT: u8 = 2;

/// Deterministic non-degenerate operand fill (kt-ladder style lab pattern).
fn operands(side: usize, salt: i32) -> (Vec<i8>, Vec<i8>) {
    let a = (0..side * side)
        .map(|i| (((i as i32 * 7 + salt) % 255) - 127) as i8)
        .collect();
    let b = (0..side * side)
        .map(|i| (((i as i32 * 11 + salt * 3 + 5) % 255) - 127) as i8)
        .collect();
    (a, b)
}

struct Batch {
    a: Vec<i8>,
    b: Vec<i8>,
    c: Vec<i32>,
    c8: Vec<i8>,
    payout: [u8; 32],
    cert: SpanCertificate,
}

fn batch(side: usize, salt: i32) -> Batch {
    let (a, b) = operands(side, salt);
    let c = gemm_i8(&a, &b, side, side, side).unwrap();
    let c8 = requant_w8a8(&c, MULT, SHIFT).unwrap();
    let s = side as u16;
    let payout = [salt as u8; 32];
    let cert = derive_span_certificate(&a, &b, s, s, s, MULT, SHIFT, payout, CHALLENGE).unwrap();
    Batch {
        a,
        b,
        c,
        c8,
        payout,
        cert,
    }
}

/// Every falsifier must be rejected by BOTH admission paths.
#[allow(clippy::too_many_arguments)]
fn assert_both_reject(
    label: &str,
    cert: &SpanCertificate,
    a: &[i8],
    b: &[i8],
    c: &[i32],
    c8: &[i8],
    expected_payout: [u8; 32],
    want_rederive: CertificateError,
    want_freivalds: CertificateError,
) {
    assert_eq!(
        admit_span_certificate(cert, a, b, c, c8, expected_payout),
        Err(want_rederive),
        "re-derivation path accepted or misclassified: {label}"
    );
    assert_eq!(
        admit_span_certificate_freivalds(cert, a, b, c, c8, expected_payout, CHALLENGE),
        Err(want_freivalds),
        "Freivalds path accepted or misclassified: {label}"
    );
}

// ---------------------------------------------------------------------------
// Honest 32^3 and 64^3: parity between the two admission paths
// ---------------------------------------------------------------------------

#[test]
fn honest_32_cubed_admits_on_both_paths() {
    let x = batch(32, 3);
    assert_eq!(
        admit_span_certificate(&x.cert, &x.a, &x.b, &x.c, &x.c8, x.payout),
        Ok(())
    );
    assert_eq!(
        admit_span_certificate_freivalds(
            &x.cert, &x.a, &x.b, &x.c, &x.c8, x.payout, CHALLENGE,
        ),
        Ok(())
    );
}

#[test]
fn honest_64_cubed_admits_on_both_paths() {
    let x = batch(64, 9);
    assert_eq!(
        admit_span_certificate(&x.cert, &x.a, &x.b, &x.c, &x.c8, x.payout),
        Ok(())
    );
    assert_eq!(
        admit_span_certificate_freivalds(
            &x.cert, &x.a, &x.b, &x.c, &x.c8, x.payout, CHALLENGE,
        ),
        Ok(())
    );
}

#[test]
fn roots_are_byte_identical_across_independent_derivations() {
    let x = batch(32, 3);
    let hand_built = SpanCertificate {
        m: 32,
        k: 32,
        n: 32,
        reps: 2,
        rbits: 32,
        payout: x.payout,
        commitment: hand_built_commitment(&x),
        challenge: CHALLENGE,
        projections: hand_built_projections(&x.c),
        c32_hash: hash_c32(&x.c),
        c8_hash: hash_c8(&x.c8),
        mult: MULT,
        shift: SHIFT,
    };
    assert_eq!(x.cert, hand_built);
    assert_eq!(
        serde_json::to_vec(&x.cert).unwrap(),
        serde_json::to_vec(&hand_built).unwrap(),
        "derived and hand-built transcript roots must be byte-identical"
    );
}

/// Hand-built kt-ladder transcript construction, intentionally restated
/// without calling the derivation helpers under test.
fn hand_built_commitment(x: &Batch) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"NOOS/WEFT/W8A8/COMMIT/V1");
    for value in &x.a {
        h.update(&value.to_le_bytes());
    }
    for value in &x.b {
        h.update(&value.to_le_bytes());
    }
    for value in &x.c {
        h.update(&value.to_le_bytes());
    }
    for value in &x.c8 {
        h.update(&value.to_le_bytes());
    }
    h.update(&32u16.to_le_bytes());
    h.update(&32u16.to_le_bytes());
    h.update(&32u16.to_le_bytes());
    h.update(&MULT.to_le_bytes());
    h.update(&[SHIFT]);
    h.update(&x.payout);
    h.finalize().to_hex().to_string()
}

fn hand_built_projections(c: &[i32]) -> Vec<u64> {
    CHALLENGE
        .iter()
        .map(|challenge| {
            c.iter().enumerate().fold(0u64, |total, (i, value)| {
                total.wrapping_add(
                    (*value as i64 as u64)
                        .wrapping_mul(u64::from(challenge.rotate_left((i % 32) as u32))),
                )
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The seven tamper/transplant/splice gates (all must reject)
// ---------------------------------------------------------------------------

#[test]
fn gate_1_c32_tamper_rejects() {
    let x = batch(32, 3);
    let mut c = x.c.clone();
    c[17] += 1;
    // Claimed C8 stays honest (the tampered accumulator still saturates to
    // the same i8): the re-derivation path notices the C32 output hash;
    // the Freivalds path notices the commitment no longer binds C32.
    assert_both_reject(
        "C32[17] += 1",
        &x.cert,
        &x.a,
        &x.b,
        &c,
        &x.c8,
        x.payout,
        CertificateError::Output,
        CertificateError::Commitment,
    );
}

#[test]
fn gate_2_c8_tamper_rejects() {
    let x = batch(32, 3);
    let mut c8 = x.c8.clone();
    c8[5] = c8[5].wrapping_add(1);
    assert_both_reject(
        "C8[5] += 1",
        &x.cert,
        &x.a,
        &x.b,
        &x.c,
        &c8,
        x.payout,
        CertificateError::Output,
        CertificateError::Output,
    );
}

#[test]
fn gate_3_input_tamper_rejects() {
    let x = batch(32, 3);
    let mut a = x.a.clone();
    a[0] = a[0].wrapping_add(1);
    assert_both_reject(
        "A[0] += 1",
        &x.cert,
        &a,
        &x.b,
        &x.c,
        &x.c8,
        x.payout,
        CertificateError::Commitment,
        CertificateError::Commitment,
    );
}

#[test]
fn gate_4_payout_transplant_rejects() {
    // Tensor bytes and certificate are unchanged, but the ledger attempts
    // to settle them to another payout identity.
    let x = batch(32, 3);
    let y = batch(32, 4);
    assert_both_reject(
        "transplanted payout",
        &x.cert,
        &x.a,
        &x.b,
        &x.c,
        &x.c8,
        y.payout,
        CertificateError::Payout,
        CertificateError::Payout,
    );
}

#[test]
fn gate_5_projection_splice_rejects() {
    let x = batch(32, 3);
    let y = batch(32, 4);
    let mut cert = x.cert.clone();
    cert.projections = y.cert.projections.clone();
    assert_both_reject(
        "spliced projections",
        &cert,
        &x.a,
        &x.b,
        &x.c,
        &x.c8,
        x.payout,
        CertificateError::Projection,
        CertificateError::Projection,
    );
}

#[test]
fn gate_6_challenge_splice_rejects() {
    // Foreign challenge with the original projections: the projections no
    // longer answer the challenge actually presented.
    let x = batch(32, 3);
    let mut cert = x.cert.clone();
    cert.challenge = [0xDEAD_BEEF, 0x1234_5678];
    assert_both_reject(
        "spliced challenge",
        &cert,
        &x.a,
        &x.b,
        &x.c,
        &x.c8,
        x.payout,
        CertificateError::Projection,
        CertificateError::Challenge,
    );
}

#[test]
fn gate_7_soundness_downgrade_rejects() {
    let x = batch(32, 3);
    for (reps, rbits) in [(1u8, 32u8), (2, 16), (0, 0)] {
        let mut cert = x.cert.clone();
        cert.reps = reps;
        cert.rbits = rbits;
        assert_both_reject(
            "soundness downgrade",
            &cert,
            &x.a,
            &x.b,
            &x.c,
            &x.c8,
            x.payout,
            CertificateError::Soundness,
            CertificateError::Soundness,
        );
    }
}

// ---------------------------------------------------------------------------
// The Freivalds relation is load-bearing: a fully self-consistent forgery
// ---------------------------------------------------------------------------

#[test]
fn forged_self_consistent_transcript_dies_on_the_span_relation() {
    // The attacker controls every certificate field and recomputes the
    // whole transcript over a wrong product: commitment, output hashes and
    // projections all match the claimed bytes. The re-derivation path
    // catches the forgery at its commitment gate (it recomputes the true
    // product); the Freivalds path passes every binding check and must die
    // exactly on the span relation.
    let x = batch(32, 3);
    let mut c = x.c.clone();
    c[17] += 1;
    let c8 = requant_w8a8(&c, MULT, SHIFT).unwrap();
    let forged = SpanCertificate {
        commitment: commit_span_transcript(&x.a, &x.b, &c, &c8, 32, 32, 32, MULT, SHIFT, x.payout),
        projections: project_span(&c, CHALLENGE),
        // The attacker hashes the claimed outputs under the frozen output
        // domains (restated below independently of the crate internals).
        c32_hash: hash_c32(&c),
        c8_hash: hash_c8(&c8),
        ..x.cert.clone()
    };
    assert_eq!(
        admit_span_certificate(&forged, &x.a, &x.b, &c, &c8, x.payout),
        Err(CertificateError::Commitment),
        "re-derivation path must reject the forgery when recomputing the true product"
    );
    assert_eq!(
        admit_span_certificate_freivalds(
            &forged, &x.a, &x.b, &c, &c8, x.payout, CHALLENGE,
        ),
        Err(CertificateError::Relation),
        "the Freivalds relation is the only gate left standing — it must hold"
    );
    // Direct relation check as well: wrong product, exact witness.
    assert_eq!(
        freivalds_span_check(&x.a, &x.b, &c, 32, 32, 32, CHALLENGE),
        Err(CertificateError::Relation)
    );
}

#[test]
fn attacker_selected_zero_challenge_rejects_before_relation_check() {
    // A zero challenge makes every Freivalds weight and projection zero.
    // The attacker can therefore make a wrong product self-consistent with
    // every certificate-owned field. Admission must compare against the
    // independently supplied post-commit beacon before evaluating it.
    let x = batch(32, 3);
    let mut c = x.c.clone();
    c[17] += 1;
    let c8 = requant_w8a8(&c, MULT, SHIFT).unwrap();
    let forged = SpanCertificate {
        challenge: [0, 0],
        commitment: commit_span_transcript(&x.a, &x.b, &c, &c8, 32, 32, 32, MULT, SHIFT, x.payout),
        projections: project_span(&c, [0, 0]),
        c32_hash: hash_c32(&c),
        c8_hash: hash_c8(&c8),
        ..x.cert.clone()
    };
    assert_eq!(
        freivalds_span_check(&x.a, &x.b, &c, 32, 32, 32, [0, 0]),
        Ok(2 * 3 * 32 * 32),
        "mutation no longer reproduces the zero-weight relation bypass"
    );
    assert_eq!(
        admit_span_certificate_freivalds(
            &forged, &x.a, &x.b, &c, &c8, x.payout, CHALLENGE,
        ),
        Err(CertificateError::Challenge),
        "certificate-selected challenge bypassed the post-commit beacon binding"
    );
}

/// The frozen output-hash domains, restated independently of the crate
/// internals (blake3 over domain || bytes, hex).
fn hash_c32(c: &[i32]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"NOOS/WEFT/W8A8/C32/V1");
    for x in c {
        h.update(&x.to_le_bytes());
    }
    h.finalize().to_hex().to_string()
}
fn hash_c8(c8: &[i8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"NOOS/WEFT/W8A8/C8/V1");
    for x in c8 {
        h.update(&x.to_le_bytes());
    }
    h.finalize().to_hex().to_string()
}

// ---------------------------------------------------------------------------
// Cycle-envelope proxy: deterministic op census and scaling exponent
// ---------------------------------------------------------------------------

#[test]
fn verifier_scaling_exponent_is_quadratic() {
    let x32 = batch(32, 3);
    let x64 = batch(64, 9);
    let ops32 = freivalds_span_check(&x32.a, &x32.b, &x32.c, 32, 32, 32, CHALLENGE).unwrap();
    let ops64 = freivalds_span_check(&x64.a, &x64.b, &x64.c, 64, 64, 64, CHALLENGE).unwrap();
    // Frozen census: reps * 3 * side^2 multiply-accumulates.
    assert_eq!(ops32, 2 * 3 * 32 * 32, "32^3 op census drifted");
    assert_eq!(ops64, 2 * 3 * 64 * 64, "64^3 op census drifted");
    // Doubling the side: exponent = log2(ops64/ops32). Must sit in the
    // preregistered [1.9, 2.1] window.
    let exponent = ((ops64 as f64) / (ops32 as f64)).log2();
    assert!(
        (1.9..=2.1).contains(&exponent),
        "scaling exponent {exponent:.3} outside [1.9, 2.1]"
    );
}

// ---------------------------------------------------------------------------
// Profile typing: the @W8A8v1 source of the derived verifier
// ---------------------------------------------------------------------------

#[test]
fn tensor_profile_typing_feeds_the_meaning_contract() {
    let ok = compile(
        "fn keep<m: Size, k: Size>(x: Tensor<i8, [m, k], @W8A8v1>) -> Tensor<i8, [m, k], @W8A8v1> ! {} cost 32 dec 0 { x }",
    )
    .unwrap();
    assert_eq!(
        ok.units[0].meaning_contract.numeric_profiles,
        vec!["W8A8v1"]
    );

    let unknown = compile("fn f(x: Tensor<i8, [8, 8], @Nope>) -> Tensor<i8, [8, 8], @Nope> { x }")
        .unwrap_err();
    assert!(unknown.iter().any(|d| d.code == "E-PROFILE-002"));

    let element =
        compile("fn f(x: Tensor<u64, [8, 8], @W8A8v1>) -> Tensor<u64, [8, 8], @W8A8v1> { x }")
            .unwrap_err();
    assert!(element.iter().any(|d| d.code == "E-PROFILE-003"));

    let dims = compile("fn f(x: Tensor<i8, [0, 8], @W8A8v1>) -> Tensor<i8, [0, 8], @W8A8v1> { x }")
        .unwrap_err();
    assert!(dims.iter().any(|d| d.code == "E-PROFILE-004"));
}

#[test]
fn requant_profile_parameters_are_validated() {
    let c = vec![100i32; 4];
    assert_eq!(
        requant_w8a8(&c, 0, 2).unwrap_err(),
        CertificateError::Profile
    );
    assert_eq!(
        requant_w8a8(&c, 3, 0).unwrap_err(),
        CertificateError::Profile
    );
    assert_eq!(
        requant_w8a8(&c, 3, 32).unwrap_err(),
        CertificateError::Profile
    );
    // The frozen kt-ladder rounding law: sat8((acc*mult + 2^(shift-1)) >> shift);
    // the arithmetic shift floors, so -298+2 >> 2 = -75.
    assert_eq!(
        requant_w8a8(&[100, -100, 1000], 3, 2).unwrap(),
        vec![75, -75, 127]
    );
}

#[test]
fn shape_gate_rejects_dimension_forgery() {
    let x = batch(32, 3);
    let mut cert = x.cert.clone();
    cert.m = 16;
    assert!(matches!(
        admit_span_certificate_freivalds(
            &cert, &x.a, &x.b, &x.c, &x.c8, x.payout, CHALLENGE,
        ),
        Err(CertificateError::Shape)
    ));
    assert!(matches!(
        admit_span_certificate(&cert, &x.a, &x.b, &x.c, &x.c8, x.payout),
        Err(CertificateError::Shape | CertificateError::Commitment)
    ));
}
