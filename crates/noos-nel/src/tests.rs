#![allow(
    clippy::arithmetic_side_effects,
    clippy::assertions_on_constants,
    clippy::unwrap_used
)]

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

fn h(x: u8) -> Hash32 {
    [x; 32]
}
fn sig(x: u8) -> Signature {
    [x; 64]
}
fn qs() -> QuorumSignatures {
    QuorumSignatures {
        first: sig(1),
        second: sig(2),
    }
}
fn record(p: u32) -> TokenRecord {
    TokenRecord {
        position: p,
        token_id: p + 100,
        logits_root: h((p % 251) as u8),
    }
}
fn full(start: u32) -> ChunkClaimV1 {
    ChunkClaimV1 {
        s_start: h(1),
        s_end: h(2),
        chunk_trace_root: h(3),
        toploc_fingerprint: [4; 258],
        records: std::array::from_fn(|i| record(start + u32::try_from(i).unwrap_or(0))),
        signatures: qs(),
    }
}
fn final_claim(start: u32, n: u8) -> FinalChunkClaimV1 {
    FinalChunkClaimV1 {
        s_start: h(1),
        s_end: h(2),
        chunk_trace_root: h(3),
        token_count: n,
        toploc_fingerprint: [4; 258],
        records: (0..u32::from(n)).map(|i| record(start + i)).collect(),
        signatures: qs(),
    }
}
fn manifest() -> ModelManifest {
    ModelManifest {
        architecture_hash: h(1),
        tokenizer_root: h(2),
        weight_root: h(3),
        shard_size: 4 * 1024 * 1024,
        data_shards: 8,
        parity_shards: 4,
        numeric_profile_id: h(4),
        circuit_id: [0; 32],
        reference_interpreter_hash: h(5),
        max_context: 1024,
        max_generation: 128,
        activation_table_root: h(6),
    }
}
fn sign(key: &SigningKey, domain: &str, body: &[u8]) -> Signature {
    key.sign(&domain_hash(domain, body)).to_bytes()
}

#[test]
fn fixed_wire_sizes_and_roundtrips() {
    let m = manifest();
    assert_eq!(m.encode().len(), 240);
    assert_eq!(ModelManifest::decode(&m.encode()).unwrap(), m);
    let job = PromptJob {
        model_id: m.model_id(),
        prompt_commitment: h(8),
        prompt_blob_ref: h(9),
        privacy_profile: PrivacyProfile::P0Open,
        decoding_profile_id: registered_decoding_hash(),
        max_new_tokens: 64,
        fee_escrow: 20,
        committee_size: 3,
        quorum: 2,
        bond_class: 1,
        challenge_period: 1800,
    };
    assert_eq!(job.encode().len(), 147);
    assert_eq!(PromptJob::decode(&job.encode()).unwrap(), job);
    let c = full(0);
    assert_eq!(c.encode().len(), 1634);
    assert_eq!(ChunkClaimV1::decode(&c.encode(), 0).unwrap(), c);
    let t = TokenClaim {
        s_t: h(1),
        token_id: 7,
        logits_commitment: h(2),
        s_next: h(3),
        chunk_trace_root: h(4),
        toploc_commitment: h(5),
        signatures: qs(),
    };
    assert_eq!(t.encode().len(), 292);
    assert_eq!(TokenClaim::decode(&t.encode()).unwrap(), t)
}

#[test]
fn exact_boundaries_1_31_32_33_63_64() {
    for total in [1u32, 31, 32, 33, 63, 64] {
        let mut chunks = Vec::new();
        let full_count = total / 32;
        for i in 0..full_count {
            chunks.push(ChunkClaim::Full(full(i * 32)))
        }
        if total % 32 != 0 {
            chunks.push(ChunkClaim::Final(final_claim(
                full_count * 32,
                (total % 32) as u8,
            )))
        }
        for (i, c) in chunks.iter().enumerate() {
            c.validate_for_job(i as u32, total).unwrap()
        }
        match total {
            1 => assert_eq!(
                match &chunks[0] {
                    ChunkClaim::Final(c) => c.encode().unwrap().len(),
                    _ => 0,
                },
                519
            ),
            31 => assert_eq!(
                match &chunks[0] {
                    ChunkClaim::Final(c) => c.encode().unwrap().len(),
                    _ => 0,
                },
                1599
            ),
            32 | 64 => assert!(chunks.iter().all(|x| matches!(x, ChunkClaim::Full(_)))),
            33 => assert!(
                matches!((&chunks[0],&chunks[1]),(ChunkClaim::Full(_),ChunkClaim::Final(c)) if c.token_count==1)
            ),
            63 => assert!(
                matches!((&chunks[0],&chunks[1]),(ChunkClaim::Full(_),ChunkClaim::Final(c)) if c.token_count==31)
            ),
            _ => {}
        }
    }
}

#[test]
fn malformed_final_claims_reject() {
    for n in [0u8, 32] {
        let c = final_claim(0, n);
        assert_eq!(c.encode(), Err(NelError::InvalidCount))
    }
    let mut one = final_claim(0, 1).encode().unwrap();
    one[96] = 2;
    assert!(matches!(
        FinalChunkClaimV1::decode(&one, 0),
        Err(NelError::WrongLength)
    ));
    let mut truncated = final_claim(0, 31).encode().unwrap();
    truncated.pop();
    assert_eq!(
        FinalChunkClaimV1::decode(&truncated, 0),
        Err(NelError::WrongLength)
    );
    let mut extra = final_claim(0, 1).encode().unwrap();
    extra.extend([0; 258]);
    assert_eq!(
        FinalChunkClaimV1::decode(&extra, 0),
        Err(NelError::WrongLength)
    );
    let mut duplicate = final_claim(0, 2);
    duplicate.records[1].position = 0;
    assert_eq!(duplicate.encode(), Err(NelError::DuplicatePosition));
    let mut reordered = final_claim(0, 2);
    reordered.records.swap(0, 1);
    assert_eq!(reordered.encode(), Err(NelError::ReorderedRecord));
    assert_eq!(
        ChunkClaim::Final(final_claim(0, 31)).validate_for_job(0, 32),
        Err(NelError::WrongChunkKind)
    );
    assert_eq!(
        ChunkClaim::Full(full(0)).validate_for_job(0, 31),
        Err(NelError::WrongChunkKind)
    )
}

#[test]
fn full_claim_truncation_extension_and_substitution_reject() {
    let c = full(0).encode();
    assert_eq!(
        ChunkClaimV1::decode(&c[..1633], 0),
        Err(NelError::WrongLength)
    );
    let mut e = c.clone();
    e.push(0);
    assert_eq!(ChunkClaimV1::decode(&e, 0), Err(NelError::WrongLength));
    assert!(FinalChunkClaimV1::decode(&c, 0).is_err())
}

#[test]
fn quorum_is_ordered_distinct_and_domain_bound() {
    let keys = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ];
    let committee = keys.each_ref().map(|k| k.verifying_key().to_bytes());
    let body = b"claim";
    let q = QuorumSignatures {
        first: sign(&keys[0], domains::CHUNK_CLAIM, body),
        second: sign(&keys[2], domains::CHUNK_CLAIM, body),
    };
    verify_quorum(body, domains::CHUNK_CLAIM, &q, [0, 2], &committee).unwrap();
    assert_eq!(
        verify_quorum(body, domains::CHUNK_CLAIM, &q, [0, 0], &committee),
        Err(NelError::DuplicateSigner)
    );
    assert_eq!(
        verify_quorum(body, domains::FINAL_CHUNK_CLAIM, &q, [0, 2], &committee),
        Err(NelError::InvalidSignature)
    );
    assert_eq!(
        verify_quorum(body, domains::CHUNK_CLAIM, &q, [2, 0], &committee),
        Err(NelError::DuplicateSigner)
    )
}

#[test]
fn first_activation_rejects_unsupported_modes_and_underbonding() {
    let m = manifest();
    let mut j = PromptJob {
        model_id: m.model_id(),
        prompt_commitment: h(7),
        prompt_blob_ref: h(8),
        privacy_profile: PrivacyProfile::P0Open,
        decoding_profile_id: registered_decoding_hash(),
        max_new_tokens: 1,
        fee_escrow: 1,
        committee_size: 3,
        quorum: 2,
        bond_class: 1,
        challenge_period: 1800,
    };
    j.validate_first_activation(&m, 1800).unwrap();
    j.privacy_profile = PrivacyProfile::P1Attested;
    assert_eq!(
        j.validate_first_activation(&m, 1800),
        Err(NelError::UnsupportedMode)
    );
    let rt = JobRuntime {
        state: JobState::Open,
        total_tokens: 1,
        anchored_chunks: BTreeSet::new(),
        available_chunks: BTreeSet::new(),
        anchor_deadlines: BTreeMap::new(),
        finality: None,
        dependent_tail_from: None,
        committee: [[1; 32], [2; 32], [3; 32]],
        committee_epoch: 1,
        value_ceiling: 100,
        dispute_cost_reserve: 30,
        bond_min: 229,
    };
    assert_eq!(rt.validate_bond(), Err(NelError::InvalidBond))
}

#[test]
fn greedy_ties_choose_lowest_token_id() {
    assert_eq!(greedy_token(&[3, 9, 9, 1]), Some(1));
    assert_eq!(greedy_token(&[]), None)
}

#[test]
fn freivalds_profiles_are_real_mod_2_64_checks() {
    let a = [1u64, 2, 3, 4];
    let b = [5u64, 6, 7, 8];
    let c = [19u64, 22, 43, 50];
    let r2 = vec![vec![1, 2], vec![u32::MAX, 17]];
    assert!(
        freivalds_verify_u64(&a, &b, &c, 2, 2, 2, &r2, FreivaldsProfile::StandardReps2).unwrap()
    );
    let r4 = vec![vec![1, 2], vec![3, 4], vec![5, 6], vec![7, 8]];
    assert!(
        freivalds_verify_u64(&a, &b, &c, 2, 2, 2, &r4, FreivaldsProfile::ProductionReps4).unwrap()
    );
    let mut bad = c;
    bad[3] ^= 1;
    assert!(!freivalds_verify_u64(
        &a,
        &b,
        &bad,
        2,
        2,
        2,
        &r4,
        FreivaldsProfile::ProductionReps4
    )
    .unwrap());
    assert_eq!(
        freivalds_verify_u64(&a, &b, &c, 2, 2, 2, &r2, FreivaldsProfile::ProductionReps4),
        Err(NelError::InvalidCount)
    )
}

#[test]
fn envelope_closed_dispatch_and_real_signature_verification() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let vp = |id| VerifierProfile {
        id,
        image_id: h(id as u8),
        verifier_key: key.verifying_key().to_bytes(),
        max_proof_bytes: 64,
        status: RegistryStatus::Enabled,
    };
    let regs = Registries::first_activation(
        ModelProfile {
            id: 1,
            manifest: manifest(),
            parameter_count: 494_000_000,
            status: RegistryStatus::Enabled,
        },
        NumericProfile {
            id: 1,
            profile_hash: h(2),
            silu_table_hash: h(3),
            version: 1,
            status: RegistryStatus::Enabled,
        },
        [
            vp(VerifierId::EnvelopeV1),
            vp(VerifierId::Risc0FreivaldsLeafV1),
            vp(VerifierId::Risc0NonlinearLeafV1),
        ],
    )
    .unwrap();
    let input = h(9);
    let mut body = Vec::new();
    body.push(VerifierId::Risc0FreivaldsLeafV1 as u8);
    body.extend(h(2));
    body.extend(input);
    let e = EnvelopeV1 {
        verifier_id: VerifierId::Risc0FreivaldsLeafV1,
        image_id: h(2),
        public_input_hash: input,
        proof: sign(&key, domains::ENVELOPE, &body).to_vec(),
    };
    e.verify(&regs, &input).unwrap();
    let mut malformed = e.encode().unwrap();
    malformed[65..69].copy_from_slice(&65u32.to_le_bytes());
    assert_eq!(
        EnvelopeV1::decode(&malformed, 64),
        Err(NelError::ProofTooLarge)
    );
    let mut wrong = e.clone();
    wrong.proof[0] ^= 1;
    assert_eq!(wrong.verify(&regs, &input), Err(NelError::InvalidSignature));
    assert_eq!(
        regs.verifier(VerifierId::SpecializedChunkV1),
        Err(NelError::UnknownRegistryId)
    )
}

#[test]
fn monotone_availability_anchor_tail_and_tombstone() {
    let committee = [[1; 32], [2; 32], [3; 32]];
    let mut j = JobRuntime {
        state: JobState::Executing,
        total_tokens: 33,
        anchored_chunks: BTreeSet::new(),
        available_chunks: BTreeSet::new(),
        anchor_deadlines: BTreeMap::from([(0, 100), (1, 101)]),
        finality: None,
        dependent_tail_from: None,
        committee,
        committee_epoch: 1,
        value_ceiling: 10,
        dispute_cost_reserve: 5,
        bond_min: 25,
    };
    j.validate_bond().unwrap();
    j.soft().unwrap();
    j.anchor(0, 50).unwrap();
    assert_eq!(j.assure(), Err(NelError::AvailabilityRequired));
    j.mark_available(0).unwrap();
    j.assure().unwrap();
    assert_eq!(j.soft(), Err(NelError::InvalidTransition));
    j.invalidate_tail(17, [[4; 32], [5; 32], [6; 32]], 2)
        .unwrap();
    assert_eq!(j.dependent_tail_from, Some(17));
    j.tombstone().unwrap();
    assert_eq!(j.anchor(1, 60), Err(NelError::InvalidTransition))
}

#[test]
fn dispute_deadline_clock_pauses_and_moves_force_stages() {
    let exec = SigningKey::from_bytes(&[11; 32]);
    let chal = SigningKey::from_bytes(&[12; 32]);
    let open = DisputeOpen {
        dispute_id: h(1),
        chunk_claim_ref: h(2),
        challenger: chal.verifying_key().to_bytes(),
        challenger_bond: 10,
        alleged_s_end: h(3),
    };
    let mut d = Dispute::new(open, exec.verifying_key().to_bytes(), 100).unwrap();
    d.pause_unavailable(110);
    assert_eq!(
        d.apply_move(
            &BisectMove {
                dispute_id: h(1),
                round: 0,
                position: 0,
                left: h(4),
                right: h(5),
                mover: exec.verifying_key().to_bytes(),
                signature: [0; 64]
            },
            111
        ),
        Err(NelError::ClockPaused)
    );
    d.resume_available(140).unwrap();
    assert_eq!(d.deadline_height, 155);
    let mut body = Vec::new();
    body.extend(h(1));
    body.extend(0u16.to_le_bytes());
    body.extend(0u32.to_le_bytes());
    body.extend(h(4));
    body.extend(h(5));
    let mv = BisectMove {
        dispute_id: h(1),
        round: 0,
        position: 0,
        left: h(4),
        right: h(5),
        mover: exec.verifying_key().to_bytes(),
        signature: sign(&exec, domains::BISECT, &body),
    };
    d.apply_move(&mv, 150).unwrap();
    assert_eq!(d.stage, DisputeStage::Token);
    assert_eq!(d.next_mover, chal.verifying_key().to_bytes());
    assert_eq!(d.deadline_height, 175)
}

#[test]
fn slash_distribution_conserves_and_unbond_waits() {
    for amount in 0..1000u64 {
        let d = distribute_executor_slash(amount);
        assert_eq!(d.challenger + d.watch_pool + d.burn, amount)
    }
    let reg = ExecutorRegistration {
        executor_key: h(1),
        manifest_set: BTreeSet::from([h(2)]),
        failure_domains_root: h(3),
        conformance_cert_ref: h(4),
        bond: 100,
        exit_notice_height: 0,
    };
    let mut a = ExecutorAccount {
        registration: reg,
        status: ExecutorStatus::Eligible,
        outstanding_claims: BTreeMap::from([(h(9), 50)]),
    };
    a.request_exit(10).unwrap();
    assert_eq!(a.release(50), Err(NelError::OutstandingClaims));
    assert_eq!(a.release(51), Ok(100))
}

#[test]
fn activation_controls_and_blockers_are_explicit() {
    assert!(!NEURAL_LANE_ENABLED);
    assert_eq!(PROOFPOWER, 0);
    assert_eq!(MOVE_DEADLINE_BLOCKS, 25);
    assert_eq!(MIN_CHALLENGE_SECONDS, 21600);
    assert_eq!(activation_blockers().len(), 6)
}

fn decode_hex(text: &str) -> Vec<u8> {
    let bytes = text.trim().as_bytes();
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("non-hex vector byte"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

#[test]
fn checked_in_wire_vectors_match_canonical_encoder() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors/nel");
    let final_one = decode_hex(&std::fs::read_to_string(root.join("final-count-01.hex")).unwrap());
    let final_31 = decode_hex(&std::fs::read_to_string(root.join("final-count-31.hex")).unwrap());
    let full_32 = decode_hex(&std::fs::read_to_string(root.join("full-count-32.hex")).unwrap());
    assert_eq!(final_one, final_claim(0, 1).encode().unwrap());
    assert_eq!(final_31, final_claim(0, 31).encode().unwrap());
    assert_eq!(full_32, full(0).encode());
    FinalChunkClaimV1::decode(&final_one, 0).unwrap();
    FinalChunkClaimV1::decode(&final_31, 0).unwrap();
    ChunkClaimV1::decode(&full_32, 0).unwrap();
}

fn vector_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors/nel")
}

fn vector_json(name: &str) -> Value {
    let path = vector_root().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display()))
}

fn json_u64(value: &Value) -> u64 {
    value.as_u64().unwrap()
}

#[test]
fn checked_in_json_vectors_use_frozen_envelope() {
    let names = [
        "boundary-v1.json",
        "malformed-v1.json",
        "verifier-freivalds-v1.json",
    ];
    for name in names {
        let document = vector_json(name);
        assert!(
            document["schema"]
                .as_str()
                .is_some_and(|schema| !schema.trim().is_empty()),
            "{name}: missing schema"
        );
        let cases = document["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: cases must be an array"));
        assert!(!cases.is_empty(), "{name}: cases must not be empty");
        let mut seen = BTreeSet::new();
        for case in cases {
            let case_name = case["name"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}: case missing name"));
            assert!(!case_name.trim().is_empty(), "{name}: empty case name");
            assert!(
                seen.insert(case_name),
                "{name}: duplicate case name {case_name}"
            );
            assert!(
                matches!(case["kind"].as_str(), Some("positive" | "negative")),
                "{name}/{case_name}: invalid kind"
            );
            let bytes = case["bytes"]
                .as_str()
                .unwrap_or_else(|| panic!("{name}/{case_name}: missing bytes"));
            assert_eq!(bytes.len() % 2, 0, "{name}/{case_name}: odd-length bytes");
            assert!(
                bytes
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{name}/{case_name}: bytes are not lowercase hex"
            );
        }
    }
}

#[test]
fn boundary_vectors_match_claim_files_and_validation_law() {
    let document = vector_json("boundary-v1.json");
    assert_eq!(json_u64(&document["chunk_tokens"]), 32);
    assert_eq!(json_u64(&document["full_claim_bytes"]), 1634);
    let expected_totals = [1u32, 31, 32, 33, 63, 64];
    let cases = document["cases"].as_array().unwrap();
    assert_eq!(cases.len(), expected_totals.len());
    for (case, expected_total) in cases.iter().zip(expected_totals) {
        assert_eq!(case["kind"], "positive");
        assert_eq!(json_u64(&case["job_tokens"]), u64::from(expected_total));
        let payload = decode_hex(case["bytes"].as_str().unwrap());
        let claims = case["claims"].as_array().unwrap();
        let mut offset = 0usize;
        for (chunk_index, claim) in claims.iter().enumerate() {
            let encoded_len = usize::try_from(json_u64(&claim["bytes"])).unwrap();
            let end = offset.checked_add(encoded_len).unwrap();
            let encoded = &payload[offset..end];
            let fixture =
                std::fs::read_to_string(vector_root().join(claim["hex_file"].as_str().unwrap()))
                    .unwrap();
            assert_eq!(encoded, decode_hex(&fixture));
            let start = u32::try_from(chunk_index).unwrap() * 32;
            let decoded = match claim["kind"].as_str().unwrap() {
                "full" => ChunkClaim::Full(ChunkClaimV1::decode(encoded, start).unwrap()),
                "final" => {
                    let final_claim = FinalChunkClaimV1::decode(encoded, start).unwrap();
                    assert_eq!(
                        u64::from(final_claim.token_count),
                        json_u64(&claim["token_count"])
                    );
                    ChunkClaim::Final(final_claim)
                }
                other => panic!("unknown boundary claim kind {other}"),
            };
            decoded
                .validate_for_job(u32::try_from(chunk_index).unwrap(), expected_total)
                .unwrap();
            offset = end;
        }
        assert_eq!(offset, payload.len());
    }
}

#[test]
fn malformed_wire_vectors_reject_with_declared_semantics() {
    let document = vector_json("malformed-v1.json");
    for case in document["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert_eq!(case["id"], name);
        assert_eq!(case["kind"], "negative");
        assert!(case["expect"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        let bytes = decode_hex(case["bytes"].as_str().unwrap());
        let actual = match name {
            "final_count_0"
            | "final_count_32"
            | "count_record_mismatch"
            | "extra_fingerprint"
            | "truncation_final" => Some(FinalChunkClaimV1::decode(&bytes, 0).unwrap_err()),
            "truncation_full" | "trailing_full" | "final_as_full" => {
                Some(ChunkClaimV1::decode(&bytes, 0).unwrap_err())
            }
            "full_as_final" => Some(FinalChunkClaimV1::decode(&bytes, 0).unwrap_err()),
            _ => {
                assert!(
                    case["construction"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "{name}: declarative case needs a construction"
                );
                None
            }
        };
        if let Some(error) = actual {
            match case["expect"].as_str().unwrap() {
                "INVALID_COUNT" => assert_eq!(error, NelError::InvalidCount),
                "WRONG_LENGTH" => assert_eq!(error, NelError::WrongLength),
                "REJECT" => {}
                other => panic!("{name}: unsupported executable expectation {other}"),
            }
        }
    }
}

#[test]
fn freivalds_vectors_execute_declared_profiles() {
    let document = vector_json("verifier-freivalds-v1.json");
    let matrix = &document["freivalds"]["matrix"];
    let a: Vec<u64> = matrix["A"]
        .as_array()
        .unwrap()
        .iter()
        .map(json_u64)
        .collect();
    let b: Vec<u64> = matrix["B"]
        .as_array()
        .unwrap()
        .iter()
        .map(json_u64)
        .collect();
    let canonical_c: Vec<u64> = matrix["C"]
        .as_array()
        .unwrap()
        .iter()
        .map(json_u64)
        .collect();
    for case in document["cases"].as_array().unwrap() {
        let c: Vec<u64> = case.get("C").and_then(Value::as_array).map_or_else(
            || canonical_c.clone(),
            |values| values.iter().map(json_u64).collect(),
        );
        let vectors: Vec<Vec<u32>> = case["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vector| {
                vector
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| u32::try_from(json_u64(value)).unwrap())
                    .collect()
            })
            .collect();
        let profile = match json_u64(&case["reps"]) {
            2 => FreivaldsProfile::StandardReps2,
            4 => FreivaldsProfile::ProductionReps4,
            reps => panic!("unsupported vector repetition count {reps}"),
        };
        let accepted = freivalds_verify_u64(
            &a,
            &b,
            &c,
            usize::try_from(json_u64(&matrix["m"])).unwrap(),
            usize::try_from(json_u64(&matrix["k"])).unwrap(),
            usize::try_from(json_u64(&matrix["n"])).unwrap(),
            &vectors,
            profile,
        )
        .unwrap();
        assert_eq!(accepted, case["expect"].as_bool().unwrap());
        assert_eq!(case["kind"], if accepted { "positive" } else { "negative" });
    }
}
