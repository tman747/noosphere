#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use super::*;
use ed25519_dalek::{Signer, SigningKey};
fn h(x: u8) -> [u8; 32] {
    [x; 32]
}
fn ctx() -> ChannelContext {
    ChannelContext {
        party: 0,
        request_id: h(1),
        model_hash: h(2),
        numeric_profile: h(3),
        tensor_id: h(4),
        rows: 128,
        cols: 2,
        chunk: 7,
        block_order: 8,
        key_epoch: 9,
        direction: Direction::Request,
    }
}
#[test]
fn additive_shares_reconstruct_mod_2_64() {
    let x = Matrix::new(1, 3, vec![0, u64::MAX, 9]).unwrap();
    let (a, b) = split(&x, vec![5, 6, u64::MAX]).unwrap();
    assert_eq!(reconstruct(&a, &b).unwrap(), x);
}
#[test]
fn canonical_matrix_encoding_binds_shape_and_rejects_trailing_bytes() {
    let row = Matrix::new(1, 2, vec![7, 8]).unwrap();
    let col = Matrix::new(2, 1, vec![7, 8]).unwrap();
    assert_ne!(encode_matrix(&row), encode_matrix(&col));
    assert_eq!(decode_matrix(&encode_matrix(&row)).unwrap(), row);
    let mut trailing = encode_matrix(&col);
    trailing.push(0);
    assert_eq!(decode_matrix(&trailing), Err(BesiError::NonCanonical));
}
#[test]
fn public_weight_share_gemms_conserve() {
    let x = Matrix::new(2, 2, vec![1, 2, 3, 4]).unwrap();
    let w = Matrix::new(2, 1, vec![5, 6]).unwrap();
    let (a, b) = split(&x, vec![8, 9, 10, 11]).unwrap();
    let got = reconstruct(
        &raw_public_weight_gemm(&a, &w).unwrap(),
        &raw_public_weight_gemm(&b, &w).unwrap(),
    )
    .unwrap();
    assert_eq!(got, raw_public_weight_gemm(&x, &w).unwrap());
}
#[test]
fn padded_exact_z_checked_before_slice() {
    let x = Matrix::new(2, 2, vec![1, 2, 3, 4]).unwrap();
    let (px, n) = pad_rows(&x).unwrap();
    assert_eq!(px.rows, 128);
    let w = Matrix::new(2, 2, vec![2, 0, 0, 3]).unwrap();
    let y = raw_public_weight_gemm(&px, &w).unwrap();
    assert!(freivalds_exact_z(&px, &w, &y, &[vec![7, 11], vec![13, 17]]).is_ok());
    assert_eq!(slice_after_verification(&y, n, true).unwrap().rows, 2);
}
#[test]
fn tampered_gemm_fails() {
    let x = Matrix::new(1, 2, vec![1, 2]).unwrap();
    let w = Matrix::new(2, 2, vec![3, 4, 5, 6]).unwrap();
    let mut y = raw_public_weight_gemm(&x, &w).unwrap();
    y.data[0] += 1;
    assert_eq!(
        freivalds_exact_z(&x, &w, &y, &[vec![1, 1]]),
        Err(BesiError::FreivaldsMismatch)
    );
    assert_eq!(
        slice_after_verification(&y, 1, false),
        Err(BesiError::FreivaldsMismatch)
    );
}
#[test]
fn channel_roundtrip_and_replay_reject() {
    let a = StaticSecret::from(h(11));
    let b = StaticSecret::from(h(12));
    let env = encrypt(&a, &PublicKey::from(&b), &ctx(), [7; 12], 1, b"share").unwrap();
    let mut g = ReplayGuard::default();
    assert_eq!(g.decrypt(&b, &ctx(), &env).unwrap(), b"share");
    assert_eq!(g.decrypt(&b, &ctx(), &env), Err(BesiError::Replay));
}
#[test]
fn context_mutation_rejects() {
    let a = StaticSecret::from(h(11));
    let b = StaticSecret::from(h(12));
    let env = encrypt(&a, &PublicKey::from(&b), &ctx(), [8; 12], 2, b"share").unwrap();
    let original = ctx();
    let mutations = vec![
        ChannelContext {
            party: 1,
            ..original.clone()
        },
        ChannelContext {
            request_id: h(99),
            ..original.clone()
        },
        ChannelContext {
            model_hash: h(99),
            ..original.clone()
        },
        ChannelContext {
            numeric_profile: h(99),
            ..original.clone()
        },
        ChannelContext {
            tensor_id: h(99),
            ..original.clone()
        },
        ChannelContext {
            rows: 127,
            ..original.clone()
        },
        ChannelContext {
            cols: 3,
            ..original.clone()
        },
        ChannelContext {
            chunk: 6,
            ..original.clone()
        },
        ChannelContext {
            block_order: 7,
            ..original.clone()
        },
    ];
    for wrong in mutations {
        assert_eq!(
            ReplayGuard::default().decrypt(&b, &wrong, &env),
            Err(BesiError::Decrypt)
        );
    }
}
#[test]
fn request_response_keys_are_separate() {
    let a = StaticSecret::from(h(11));
    let b = StaticSecret::from(h(12));
    let env = encrypt(&a, &PublicKey::from(&b), &ctx(), [9; 12], 3, b"share").unwrap();
    let mut wrong = ctx();
    wrong.direction = Direction::Response;
    assert_eq!(
        ReplayGuard::default().decrypt(&b, &wrong, &env),
        Err(BesiError::Decrypt)
    );
}
#[test]
fn key_epoch_rotation_prevents_cross_epoch_decrypt() {
    let a = StaticSecret::from(h(11));
    let b = StaticSecret::from(h(12));
    let env = encrypt(&a, &PublicKey::from(&b), &ctx(), [10; 12], 4, b"share").unwrap();
    let mut wrong = ctx();
    wrong.key_epoch = 10;
    assert_eq!(
        ReplayGuard::default().decrypt(&b, &wrong, &env),
        Err(BesiError::Decrypt)
    );
}
#[test]
fn raw_shares_never_public_da() {
    assert_eq!(
        admit_public_da(&PublicDaArtifact::RawActivationShare(vec![1])),
        Err(BesiError::RawSharePublicDa)
    );
    assert!(admit_public_da(&PublicDaArtifact::CiphertextCommitment(h(1))).is_ok());
}
fn signed_receipt() -> (AdjudicationReceipt, VerifyingKey) {
    let sk = SigningKey::from_bytes(&h(55));
    let mut r = AdjudicationReceipt {
        job_id: h(1),
        ordered_response_ciphertext_commitments: [h(2), h(3)],
        output_commitment: h(4),
        private_witness_proof_root: h(5),
        suite: DISPUTE_SUITE.into(),
        verdict: Verdict::Executor0Fault,
        epoch: 7,
        nonce: 8,
        signature: [0; 64],
    };
    r.signature = sk.sign(&r.message()).to_bytes();
    (r, sk.verifying_key())
}
#[test]
fn signed_private_adjudication_and_replay() {
    let (r, k) = signed_receipt();
    let mut used = BTreeSet::new();
    assert!(r.verify(&k, 7, &mut used).is_ok());
    assert_eq!(r.verify(&k, 7, &mut used), Err(BesiError::Replay));
}
#[test]
fn adjudication_rebinding_rejects() {
    let (original, k) = signed_receipt();
    let mutations = vec![
        AdjudicationReceipt {
            job_id: h(44),
            ..original.clone()
        },
        AdjudicationReceipt {
            ordered_response_ciphertext_commitments: [h(44), h(3)],
            ..original.clone()
        },
        AdjudicationReceipt {
            output_commitment: h(44),
            ..original.clone()
        },
        AdjudicationReceipt {
            private_witness_proof_root: h(44),
            ..original.clone()
        },
        AdjudicationReceipt {
            verdict: Verdict::Accept,
            ..original.clone()
        },
        AdjudicationReceipt {
            nonce: 44,
            ..original.clone()
        },
        AdjudicationReceipt {
            signature: [44; 64],
            ..original.clone()
        },
    ];
    for mutation in mutations {
        assert_eq!(
            mutation.verify(&k, 7, &mut BTreeSet::new()),
            Err(BesiError::Signature)
        );
    }
}
#[test]
fn unknown_adjudication_suite_rejects() {
    let (mut r, k) = signed_receipt();
    r.suite = "generic-proof".into();
    assert_eq!(
        r.verify(&k, 7, &mut BTreeSet::new()),
        Err(BesiError::UnknownSuite)
    );
}
#[test]
fn assurance_substitution_rejects() {
    assert!(exact_assurance(PRIVACY_PROFILE, EXECUTION_MODE, ASSURANCE));
    assert!(!exact_assurance(PRIVACY_PROFILE, EXECUTION_MODE, "PROVEN"));
    assert!(!exact_assurance(
        "P2_SEALED_WITNESS",
        EXECUTION_MODE,
        ASSURANCE
    ));
}
#[test]
fn disabled_experiments_have_blockers() {
    let ExperimentStatus::Disabled(m) = MALICIOUS_3PC_STATUS;
    assert!(m.contains("MAC"));
    let ExperimentStatus::Disabled(h) = HFHE_STATUS;
    assert!(h.contains("reduction"));
}

#[test]
fn sanitized_default_result_has_no_prompt_token_logit_or_hidden_fields() {
    let result = SanitizedBesiResult {
        job_id: h(1),
        output_commitment: h(2),
        integrity: true,
        public_bucket: PADDING_BUCKET,
        remote_gemms: 8,
        assurance: ASSURANCE,
    };
    assert_eq!(result.assurance, "ASSURED_SPLIT");
    let fields = SanitizedBesiResult::field_names().join(",");
    for forbidden in [
        "prompt",
        "token",
        "logit",
        "layer_digest",
        "exact_length",
        "final_hidden",
    ] {
        assert!(!fields.contains(forbidden));
    }
}
