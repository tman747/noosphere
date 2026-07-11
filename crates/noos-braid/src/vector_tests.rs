//! Conformance tests over `protocol/vectors/braid/*.json`.
//!
//! Two layers:
//! 1. every generated case is executed against the implementation
//!    semantics of its schema (so the generator can never emit a wrong
//!    verdict), and
//! 2. the on-disk JSON must be byte-identical to the generator output (so
//!    the frozen vectors can never drift from the implementation).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use noos_codec::{NoosDecode, NoosEncode};
use noos_ground::U256;
use std::path::PathBuf;

use crate::fork::ForkScore;
use crate::header::BlockHeaderV1;
use crate::vector_gen::{files, render_json, Case};
use crate::BlockBodyV1;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("vectors")
        .join("braid")
}

fn extra<'a>(case: &'a Case, key: &str) -> &'a [u8] {
    case.extras
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_slice())
        .unwrap_or_else(|| panic!("{}: missing extra {key}", case.name))
}

fn extra_str<'a>(case: &'a Case, key: &str) -> &'a str {
    case.extras_str
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("{}: missing extra {key}", case.name))
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    <[u8; N]>::try_from(bytes).unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

#[test]
fn on_disk_vectors_match_the_generator_exactly() {
    for (name, file) in files() {
        let path = vectors_dir().join(name);
        let disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e} (run gen_vectors)", path.display()));
        // Normalize line endings: git may check the file out with CRLF.
        let disk = disk.replace("\r\n", "\n");
        assert_eq!(disk, render_json(&file), "{name} drifted; regenerate");
    }
}

#[test]
fn header_vectors_execute() {
    let all = files();
    let (_, file) = &all[0];
    assert!(file.cases.len() >= 8);
    for case in &file.cases {
        match case.kind {
            "positive" => {
                let h = BlockHeaderV1::decode_canonical(&case.bytes)
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(h.encode_canonical(), case.bytes, "{}", case.name);
                assert_eq!(
                    h.block_hash().unwrap().as_bytes().as_slice(),
                    extra(case, "block_hash"),
                    "{}",
                    case.name
                );
                assert_eq!(
                    h.proposal_commitment().unwrap().as_bytes().as_slice(),
                    extra(case, "proposal_commitment"),
                    "{}",
                    case.name
                );
            }
            "negative" => {
                let err = BlockHeaderV1::decode_canonical(&case.bytes)
                    .expect_err(&format!("{} must reject", case.name));
                assert_eq!(Some(err.class_name()), case.error_class, "{}", case.name);
            }
            other => panic!("bad kind {other}"),
        }
    }
}

#[test]
fn header_validation_vectors_execute() {
    let all = files();
    let (_, file) = &all[1];
    assert!(file.cases.len() >= 6);
    for case in &file.cases {
        let h = BlockHeaderV1::decode_canonical(&case.bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let chain: [u8; 32] = arr(extra(case, "chain_id"));
        let verdict = h.validate_structure(&chain, false);
        match case.kind {
            "positive" => verdict.unwrap_or_else(|e| panic!("{}: {e}", case.name)),
            "negative" => {
                let err = verdict.expect_err(&format!("{} must reject", case.name));
                assert_eq!(Some(err.class_name()), case.error_class, "{}", case.name);
            }
            other => panic!("bad kind {other}"),
        }
    }
}

#[test]
fn proposal_commitment_vectors_execute() {
    let all = files();
    let (_, file) = &all[2];
    assert!(file.cases.len() >= 5);
    for case in &file.cases {
        let h = BlockHeaderV1::decode_canonical(&case.bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let recomputed = h.proposal_commitment().unwrap();
        let claimed = extra(case, "proposal_commitment");
        match case.kind {
            "positive" => assert_eq!(
                recomputed.as_bytes().as_slice(),
                claimed,
                "{}: commitment must match",
                case.name
            ),
            "negative" => assert_ne!(
                recomputed.as_bytes().as_slice(),
                claimed,
                "{}: wrong-coverage claim must NOT match",
                case.name
            ),
            other => panic!("bad kind {other}"),
        }
    }
}

fn parse_score(bytes: &[u8]) -> ForkScore {
    assert_eq!(bytes.len(), 80);
    ForkScore {
        finalized_epoch: u64::from_le_bytes(arr(&bytes[0..8])),
        justified_epoch: u64::from_le_bytes(arr(&bytes[8..16])),
        work_since_finalized: U256::from_le_bytes(&arr(&bytes[16..48])),
        block_hash: arr(&bytes[48..80]),
    }
}

#[test]
fn fork_choice_vectors_execute() {
    let all = files();
    let (_, file) = &all[3];
    assert!(file.cases.len() >= 7);
    for case in &file.cases {
        assert_eq!(case.bytes.len(), 160, "{}", case.name);
        let a = parse_score(&case.bytes[..80]);
        let b = parse_score(&case.bytes[80..]);
        let winner = if a > b { "a" } else { "b" };
        assert_eq!(winner, extra_str(case, "expected"), "{}", case.name);
        // Antisymmetry: the comparison is a strict total order.
        assert_eq!(a > b, b < a, "{}", case.name);
        assert_ne!(a, b, "{}: degenerate case", case.name);
    }
}

#[test]
fn body_vectors_execute() {
    let all = files();
    let (_, file) = &all[4];
    assert!(file.cases.len() >= 6);
    for case in &file.cases {
        match case.kind {
            "positive" => {
                let body = BlockBodyV1::decode_canonical(&case.bytes)
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(body.encode_canonical(), case.bytes, "{}", case.name);
            }
            "negative" => {
                let err = BlockBodyV1::decode_canonical(&case.bytes)
                    .expect_err(&format!("{} must reject", case.name));
                assert_eq!(Some(err.class_name()), case.error_class, "{}", case.name);
            }
            other => panic!("bad kind {other}"),
        }
    }
}

#[test]
fn at_least_twenty_vectors_exist() {
    let total: usize = files().iter().map(|(_, f)| f.cases.len()).sum();
    assert!(total >= 20, "only {total} cases");
}
