//! Conformance tests over `protocol/vectors/da/*.json`.
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

use std::path::PathBuf;

use noos_braid::BlobDescriptorV1;
use noos_codec::NoosDecode;
use noos_crypto::Hash32;

use crate::vector_gen::{
    case_body, files, forged_content_encoding, inconsistent_parity_encoding,
    nonzero_padding_encoding, render_json, Case,
};
use crate::{
    encode_body, reconstruct_and_verify, validate_blob_descriptor,
    validate_consensus_blob_descriptor, verify_shard_sample, BodyDaClaimV1, DaError, EncodedBodyV1,
    ShardBranch, BODY_SHARD_DEPTH, MAX_BLOCK_BODY_BYTES,
};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("vectors")
        .join("da")
}

fn extra<'a>(case: &'a Case, key: &str) -> &'a [u8] {
    case.extras
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_slice())
        .unwrap_or_else(|| panic!("{}: missing extra {key}", case.name))
}

fn extra_str<'a>(case: &'a Case, key: &str) -> Option<&'a str> {
    case.extras_str
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

fn hash32(bytes: &[u8]) -> Hash32 {
    Hash32::from_bytes(<[u8; 32]>::try_from(bytes).expect("32-byte extra"))
}

fn expect_err(case: &Case, got: DaError) {
    assert_eq!(
        Some(got.class_name()),
        case.error_class,
        "{}: got {got}",
        case.name
    );
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

// ---------------------------------------------------------------------------
// noos-da/body-coding-v1
// ---------------------------------------------------------------------------

#[test]
fn body_coding_vectors_execute() {
    let (_, file) = files().remove(0);
    assert_eq!(file.schema, "noos-da/body-coding-v1");
    for case in &file.cases {
        let body = case_body(case);
        match case.kind {
            "positive" => {
                let enc = encode_body(&body).unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(
                    enc.claim().content_root,
                    hash32(extra(case, "content_root")),
                    "{}",
                    case.name
                );
                assert_eq!(
                    *enc.shard_root(),
                    hash32(extra(case, "shard_root")),
                    "{}",
                    case.name
                );
                // Deterministic shard bytes: re-encoding is identical.
                assert_eq!(&encode_body(&body).unwrap(), &enc, "{}", case.name);
            }
            "negative" => {
                let err = encode_body(&body).expect_err(&format!("{} must reject", case.name));
                expect_err(case, err);
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// noos-da/shard-sample-v1
// ---------------------------------------------------------------------------

fn parse_sample(bytes: &[u8]) -> (u32, ShardBranch) {
    assert_eq!(bytes.len(), 4 + 32 * BODY_SHARD_DEPTH, "sample layout");
    let index = u32::from_le_bytes(<[u8; 4]>::try_from(&bytes[..4]).unwrap());
    let mut branch = [Hash32::ZERO; BODY_SHARD_DEPTH];
    for (i, slot) in branch.iter_mut().enumerate() {
        let at = 4 + i * 32;
        *slot = hash32(&bytes[at..at + 32]);
    }
    (index, branch)
}

#[test]
fn shard_sample_vectors_execute() {
    let (_, file) = files().remove(1);
    assert_eq!(file.schema, "noos-da/shard-sample-v1");
    for case in &file.cases {
        let body = case_body(case);
        let enc = encode_body(&body).unwrap();
        let (index, branch) = parse_sample(&case.bytes);
        let shard_root = hash32(extra(case, "shard_root"));
        let mut content_root = hash32(extra(case, "content_root"));

        // The sampled shard: honest bytes unless the index is out of range
        // (then any fixed-size stand-in shows the range check fires first).
        let mut shard = enc
            .shards()
            .get(index as usize)
            .cloned()
            .unwrap_or_else(|| vec![0_u8; crate::BODY_SHARD_BYTES]);

        match extra_str(case, "tamper") {
            Some("flip_shard_byte") => shard[0] ^= 0xFF,
            Some("foreign_content_root") => content_root = Hash32::from_bytes([0x66; 32]),
            Some(other) => panic!("{}: unknown tamper {other}", case.name),
            None => {}
        }

        let got = verify_shard_sample(&shard_root, &content_root, index, &shard, &branch);
        match case.kind {
            "positive" => got.unwrap_or_else(|e| panic!("{}: {e}", case.name)),
            "negative" => {
                expect_err(case, got.expect_err(&format!("{} must reject", case.name)));
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// noos-da/reconstruction-v1
// ---------------------------------------------------------------------------

fn adversarial_encoding(tamper: Option<&str>, body: &[u8]) -> EncodedBodyV1 {
    match tamper {
        Some("inconsistent_parity") => inconsistent_parity_encoding(body),
        Some("nonzero_padding") => nonzero_padding_encoding(body),
        Some("forged_content_root") => forged_content_encoding(body),
        _ => encode_body(body).unwrap(),
    }
}

#[test]
fn reconstruction_vectors_execute() {
    let (_, file) = files().remove(2);
    assert_eq!(file.schema, "noos-da/reconstruction-v1");
    for case in &file.cases {
        let body = case_body(case);
        let tamper = extra_str(case, "tamper");
        let enc = adversarial_encoding(tamper, &body);

        // The trusted inputs come from the vector itself and must agree
        // with the (possibly adversarial) encoding the executor rebuilt.
        let shard_root = hash32(extra(case, "shard_root"));
        assert_eq!(
            *enc.shard_root(),
            shard_root,
            "{}: fixture drift",
            case.name
        );
        let mut claim = BodyDaClaimV1 {
            content_root: hash32(extra(case, "content_root")),
            original_bytes: body.len() as u64,
        };
        assert_eq!(
            claim.content_root,
            enc.claim().content_root,
            "{}",
            case.name
        );

        let subset: Vec<u32> = extra_str(case, "subset")
            .unwrap_or_else(|| panic!("{}: missing subset", case.name))
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap())
            .collect();
        let mut candidates: Vec<_> = subset.iter().map(|&i| enc.candidate(i).unwrap()).collect();

        match tamper {
            Some("corrupt_first_candidate") => candidates[0].bytes[0] ^= 0x01,
            Some("oversize_claim") => claim.original_bytes = MAX_BLOCK_BODY_BYTES as u64 + 1,
            _ => {}
        }

        let got = reconstruct_and_verify(&shard_root, &claim, &candidates);
        match case.kind {
            "positive" => {
                let rec = got.unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert_eq!(rec.bytes(), &body[..], "{}: exact body", case.name);
                assert_eq!(rec.shard_root(), &shard_root, "{}", case.name);
            }
            "negative" => {
                expect_err(case, got.expect_err(&format!("{} must reject", case.name)));
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// noos-da/blob-descriptor-v1
// ---------------------------------------------------------------------------

#[test]
fn blob_descriptor_vectors_execute() {
    let (_, file) = files().remove(3);
    assert_eq!(file.schema, "noos-da/blob-descriptor-v1");
    for case in &file.cases {
        // Wire decode is noos-braid law and must succeed for every case:
        // these vectors test SEMANTIC acceptance.
        let d = BlobDescriptorV1::decode_canonical(&case.bytes)
            .unwrap_or_else(|e| panic!("{}: wire decode: {e}", case.name));
        let got = match extra_str(case, "law") {
            Some("consensus") => validate_consensus_blob_descriptor(&d),
            Some("any") => validate_blob_descriptor(&d),
            other => panic!("{}: bad law {other:?}", case.name),
        };
        match case.kind {
            "positive" => {
                got.unwrap_or_else(|e| panic!("{}: {e}", case.name));
            }
            "negative" => {
                expect_err(case, got.expect_err(&format!("{} must reject", case.name)));
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

#[test]
fn at_least_fifteen_vectors_exist() {
    let total: usize = files().iter().map(|(_, f)| f.cases.len()).sum();
    assert!(total >= 15, "only {total} DA vector cases");
}
