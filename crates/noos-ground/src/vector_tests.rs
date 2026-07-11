//! Conformance tests over `protocol/vectors/ground/*.json`.
//!
//! Both files are generated independently by
//! `tools/vector-generators/gen_ground_vectors.py` (Python blake3 for the
//! ticket law, pure-Python big integers for Pulse). Every case must
//! reproduce bit-for-bit here and in the Go client.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::{
    pulse_target_v1, validate_ticket, DuplicateSet, GroundError, GroundTicketV1, PulseAnchor,
    TicketContext, U256,
};
use noos_crypto::Hash32;
use serde_json::Value;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("vectors")
        .join("ground")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON in {name}: {e}"))
}

fn cases(doc: &Value) -> &Vec<Value> {
    doc["cases"].as_array().expect("cases array")
}

fn name(case: &Value) -> &str {
    case["name"].as_str().expect("name")
}

fn hexf(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        case[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}: {case}")),
    )
    .unwrap_or_else(|e| panic!("bad hex in {field}: {e}"))
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    <[u8; N]>::try_from(bytes).unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

fn h32(case: &Value, field: &str) -> Hash32 {
    Hash32::from_bytes(arr::<32>(&hexf(case, field)))
}

fn u256_le(case: &Value, field: &str) -> U256 {
    U256::from_le_bytes(&arr::<32>(&hexf(case, field)))
}

fn u64f(case: &Value, field: &str) -> u64 {
    case[field]
        .as_u64()
        .unwrap_or_else(|| panic!("missing u64 {field}: {case}"))
}

fn is_positive(case: &Value) -> bool {
    match case["kind"].as_str().expect("kind") {
        "positive" => true,
        "negative" => false,
        other => panic!("unknown kind {other}"),
    }
}

struct FlagDup(bool);
impl DuplicateSet for FlagDup {
    fn contains(&self, _: &[u8; 48], _: u64, _: &[u8; 32]) -> bool {
        self.0
    }
}

/// Maps a vector `expect_error` label to a structural check on the verdict.
fn error_matches(label: &str, err: &GroundError) -> bool {
    matches!(
        (label, err),
        ("WrongProfileId", GroundError::WrongProfileId { .. })
            | ("DigestMismatch", GroundError::DigestMismatch)
            | ("DigestNotBelowTarget", GroundError::DigestNotBelowTarget)
            | ("TargetMismatch", GroundError::TargetMismatch)
            | ("SlotMismatch", GroundError::SlotMismatch { .. })
            | ("SlotBehindParent", GroundError::SlotBehindParent { .. })
            | ("SlotSkipTooLarge", GroundError::SlotSkipTooLarge { .. })
            | (
                "TimestampNotAfterMedianTimePast",
                GroundError::TimestampNotAfterMedianTimePast { .. }
            )
            | (
                "TimestampTooFarInFuture",
                GroundError::TimestampTooFarInFuture { .. }
            )
            | ("DuplicateTicket", GroundError::DuplicateTicket)
    )
}

#[test]
fn ground_ticket_vectors() {
    let doc = load("ground-ticket-v1.json");
    assert!(cases(&doc).len() >= 20, "ticket+pulse vector floor");
    for case in cases(&doc) {
        let ticket_bytes = hexf(case, "bytes");
        let ticket = GroundTicketV1::decode(&ticket_bytes)
            .unwrap_or_else(|| panic!("{}: undecodable ticket bytes", name(case)));
        // Strict re-encode round trip.
        assert_eq!(
            ticket.encode().as_slice(),
            ticket_bytes.as_slice(),
            "{}",
            name(case)
        );

        let chain_id = h32(case, "chain_id");
        let parent_hash = h32(case, "parent_hash");
        let parent_target = u256_le(case, "parent_ground_target_le");
        let ground_target = u256_le(case, "ground_target_le");
        let expected_target = u256_le(case, "expected_target_le");
        let proposal_commitment = h32(case, "proposal_commitment");
        let proposer_pubkey = arr::<48>(&hexf(case, "proposer_pubkey"));
        let window: Vec<u64> = case["parent_timestamps_ms"]
            .as_array()
            .expect("parent_timestamps_ms")
            .iter()
            .map(|v| v.as_u64().expect("timestamp"))
            .collect();
        let ctx = TicketContext {
            chain_id: &chain_id,
            parent_hash: &parent_hash,
            parent_ground_target: &parent_target,
            slot: u64f(case, "slot"),
            timestamp_ms: u64f(case, "timestamp_ms"),
            genesis_time_ms: u64f(case, "genesis_time_ms"),
            parent_slot: u64f(case, "parent_slot"),
            parent_timestamps_ms: &window,
            adjusted_now_ms: u64f(case, "adjusted_now_ms"),
            max_future_drift_ms: u64f(case, "max_future_drift_ms"),
            ground_target: &ground_target,
            expected_target: &expected_target,
            proposal_commitment: &proposal_commitment,
            proposer_pubkey: &proposer_pubkey,
        };
        let dup = FlagDup(case["duplicate"].as_bool().expect("duplicate"));

        // The recorded challenge must match our domain-bound recomputation
        // for the recorded slot (independent Python blake3 generated it).
        let challenge = crate::ground_challenge(&crate::ChallengeInputs {
            chain_id: &chain_id,
            parent_hash: &parent_hash,
            parent_ground_target: &parent_target,
            slot: ctx.slot,
            proposal_commitment: &proposal_commitment,
            proposer_pubkey: &proposer_pubkey,
        })
        .unwrap();
        assert_eq!(
            challenge,
            h32(case, "challenge"),
            "{}: challenge",
            name(case)
        );

        let verdict = validate_ticket(&ctx, &ticket, &dup);
        if is_positive(case) {
            assert_eq!(verdict, Ok(()), "{}: expected acceptance", name(case));
        } else {
            let label = case["expect_error"].as_str().expect("expect_error");
            let err = verdict.expect_err(name(case));
            assert!(
                error_matches(label, &err),
                "{}: expected {label}, got {err:?}",
                name(case)
            );
        }
    }
}

#[test]
fn pulse_retarget_vectors() {
    let doc = load("pulse-retarget-v1.json");
    for case in cases(&doc) {
        assert!(
            is_positive(case),
            "{}: pulse vectors are exact-output cases",
            name(case)
        );
        let anchor = PulseAnchor {
            height: u64f(case, "h_a"),
            median_time_past_s: u64f(case, "t_a"),
            target: U256::from_be_hex(case["anchor_target_hex"].as_str().expect("anchor"))
                .expect("anchor hex"),
        };
        let got = pulse_target_v1(&anchor, u64f(case, "t"), u64f(case, "h"))
            .unwrap_or_else(|e| panic!("{}: {e}", name(case)));
        let expected = U256::from_be_hex(case["expected_target_hex"].as_str().expect("expected"))
            .expect("expected hex");
        assert_eq!(got, expected, "{}", name(case));
        // `bytes` carries the same value little-endian.
        assert_eq!(
            got.to_le_bytes().as_slice(),
            hexf(case, "bytes").as_slice(),
            "{}: le bytes",
            name(case)
        );
    }
}
