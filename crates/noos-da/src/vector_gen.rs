//! Deterministic conformance-vector generator for `protocol/vectors/da/`.
//!
//! Shared by `bin/gen_vectors.rs` (writes the JSON files) and the crate
//! tests (which re-derive and verify every case), so the emitted vectors
//! can never drift from the implementation. JSON is emitted by hand from
//! fully controlled ASCII content; the file shape satisfies
//! `tools/gates/check_vectors.py`.
//!
//! ## Case conventions
//!
//! * Bodies too large to inline are generated from the shared byte pattern
//!   [`pattern_body`] and named by the `body_len` string extra; when
//!   `body_len` is absent the case's `bytes` field IS the body.
//! * `content_root` / `shard_root` extras are exactly the claim and the
//!   trusted commitment root handed to the verifier under test — for
//!   adversarial cases these are the **adversary's** commitments.
//! * `subset` lists the candidate shard indices handed to reconstruction,
//!   comma-separated, in submission order (duplicates intentional where
//!   present).
//! * `tamper` names an adversarial mutation; the executor semantics live
//!   in `vector_tests.rs` and are asserted against the typed error law.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use noos_braid::BlobDescriptorV1;
use noos_codec::{NoosEncode, Writer};
use noos_crypto::Hash32;
use noos_lumen::objects::{BoundedBytes, OptionalHash32, OptionalObject};

use crate::error::DaError;
use crate::{
    body_shard_bytes, commit_shards, content_root, encode_body, encode_padded_region,
    BodyDaClaimV1, EncodedBodyV1, BODY_DATA_SHARDS, MAX_BLOCK_DA_FORM_BYTES,
};

/// One conformance case.
pub struct Case {
    pub name: String,
    pub kind: &'static str,
    pub bytes: Vec<u8>,
    /// Extra `"field": "hex"` pairs (all values hex-encoded byte strings).
    pub extras: Vec<(&'static str, Vec<u8>)>,
    /// Extra `"field": "literal"` string pairs (e.g. subset selections).
    pub extras_str: Vec<(&'static str, String)>,
    pub error_class: Option<&'static str>,
    pub note: String,
}

pub struct VectorFile {
    pub schema: &'static str,
    pub cases: Vec<Case>,
}

fn case(name: &str, kind: &'static str, bytes: Vec<u8>, note: &str) -> Case {
    Case {
        name: name.to_string(),
        kind,
        bytes,
        extras: Vec::new(),
        extras_str: Vec::new(),
        error_class: None,
        note: note.to_string(),
    }
}

fn positive(name: &str, bytes: Vec<u8>, note: &str) -> Case {
    case(name, "positive", bytes, note)
}

fn negative(name: &str, bytes: Vec<u8>, err: DaError, note: &str) -> Case {
    let mut c = case(name, "negative", bytes, note);
    c.error_class = Some(err.class_name());
    c
}

fn str_extra(mut c: Case, key: &'static str, value: String) -> Case {
    c.extras_str.push((key, value));
    c
}

fn roots_extra(mut c: Case, content: &Hash32, shard_root: &Hash32) -> Case {
    c.extras.push(("content_root", content.as_bytes().to_vec()));
    c.extras
        .push(("shard_root", shard_root.as_bytes().to_vec()));
    c
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// The shared deterministic body pattern: byte `i` is
/// `(i * 31 + 7) mod 251`. Cheap, aperiodic over shard boundaries, and
/// trivially reproducible in any language.
#[must_use]
pub fn pattern_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

fn h(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// Resolves a case's body: `body_len` extra wins, else the inline bytes.
#[must_use]
pub fn case_body(c: &Case) -> Vec<u8> {
    c.extras_str
        .iter()
        .find(|(k, _)| *k == "body_len")
        .map_or_else(
            || c.bytes.clone(),
            |(_, v)| pattern_body(v.parse::<usize>().expect("body_len")),
        )
}

/// The honest reconstruction claim for a body.
#[must_use]
pub fn claim_for(body: &[u8]) -> BodyDaClaimV1 {
    BodyDaClaimV1 {
        content_root: content_root(body).unwrap(),
        original_bytes: body.len() as u64,
    }
}

// ---------------------------------------------------------------------------
// Adversarial fixtures (shared with vector_tests)
// ---------------------------------------------------------------------------

/// Proposer misbehavior: the committed tree covers a garbage parity shard
/// 31, so the committed set is not a Reed-Solomon codeword.
#[must_use]
pub fn inconsistent_parity_encoding(body: &[u8]) -> EncodedBodyV1 {
    let honest = encode_body(body).unwrap();
    let mut shards = honest.shards().to_vec();
    shards[31] = vec![0xEE; shards[31].len()];
    commit_shards(*honest.claim(), shards).unwrap()
}

/// Proposer misbehavior: a consistent codeword whose padding region
/// carries a nonzero byte (offset 1,000).
#[must_use]
pub fn nonzero_padding_encoding(body: &[u8]) -> EncodedBodyV1 {
    let shard_bytes = body_shard_bytes(body.len() as u64).unwrap();
    let mut region = vec![0_u8; shard_bytes * BODY_DATA_SHARDS];
    region[..body.len()].copy_from_slice(body);
    region[1_000] = 0xEE;
    encode_padded_region(claim_for(body), &region).unwrap()
}

/// The forged content root used by the forged-content-root fixtures.
#[must_use]
pub fn forged_content_root() -> Hash32 {
    Hash32::from_bytes(h(0x77))
}

/// Proposer misbehavior: every leaf binds a forged content root; the
/// codeword and padding are otherwise honest.
#[must_use]
pub fn forged_content_encoding(body: &[u8]) -> EncodedBodyV1 {
    let shard_bytes = body_shard_bytes(body.len() as u64).unwrap();
    let mut region = vec![0_u8; shard_bytes * BODY_DATA_SHARDS];
    region[..body.len()].copy_from_slice(body);
    let claim = BodyDaClaimV1 {
        content_root: forged_content_root(),
        original_bytes: body.len() as u64,
    };
    encode_padded_region(claim, &region).unwrap()
}

// ---------------------------------------------------------------------------
// File 1: body coding
// ---------------------------------------------------------------------------

fn coding_case(name: &str, body_len: usize, inline: bool, note: &str) -> Case {
    let body = pattern_body(body_len);
    let mut c = positive(name, if inline { body.clone() } else { Vec::new() }, note);
    if !inline {
        c = str_extra(c, "body_len", body_len.to_string());
    }
    let enc = encode_body(&body).unwrap();
    roots_extra(c, &enc.claim().content_root, enc.shard_root())
}

fn coding_file() -> VectorFile {
    let cases = vec![
        coding_case(
            "coding-empty-body",
            0,
            true,
            "zero-length body: 16 all-zero data shards, still committed",
        ),
        coding_case(
            "coding-one-byte",
            1,
            true,
            "one byte then 1,048,575 zero-padding bytes",
        ),
        coding_case(
            "coding-small-inline",
            200,
            true,
            "200 patterned bytes carried inline",
        ),
        coding_case(
            "coding-exact-one-shard",
            65_536,
            false,
            "body exactly fills data shard 0; shards 1..16 all zero",
        ),
        coding_case(
            "coding-64mib-adaptive",
            67_108_864,
            false,
            "body fills 16 adaptive 4 MiB data shards below the 128 MiB cap",
        ),
        str_extra(
            negative(
                "coding-max-plus-one",
                Vec::new(),
                DaError::BodyTooLarge {
                    len: MAX_BLOCK_DA_FORM_BYTES as u64 + 1,
                },
                "one byte exceeds the adaptive 16 x 8 MiB data capacity",
            ),
            "body_len",
            MAX_BLOCK_DA_FORM_BYTES.saturating_add(1).to_string(),
        ),
    ];
    VectorFile {
        schema: "noos-da/body-coding-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// File 2: shard sampling
// ---------------------------------------------------------------------------

/// Body length shared by every sampling case.
pub const SAMPLE_BODY_LEN: usize = 100_000;

/// `bytes` layout for sampling cases: `index:u32-LE || branch (5 x 32)`.
fn sample_bytes(index: u32, branch: &[Hash32]) -> Vec<u8> {
    let mut out = index.to_le_bytes().to_vec();
    for hash in branch {
        out.extend_from_slice(hash.as_bytes());
    }
    out
}

fn sample_file() -> VectorFile {
    let body = pattern_body(SAMPLE_BODY_LEN);
    let enc = encode_body(&body).unwrap();
    let honest = |c: Case| -> Case {
        let c = str_extra(c, "body_len", SAMPLE_BODY_LEN.to_string());
        roots_extra(c, &enc.claim().content_root, enc.shard_root())
    };
    let mut cases = Vec::new();

    cases.push(honest(positive(
        "sample-data-shard-valid",
        sample_bytes(3, &enc.branch(3).unwrap()),
        "honest branch for data shard 3 verifies; OPINION only, never acceptance",
    )));

    cases.push(honest(positive(
        "sample-parity-shard-valid",
        sample_bytes(31, &enc.branch(31).unwrap()),
        "honest branch for the last parity shard verifies",
    )));

    cases.push(str_extra(
        honest(negative(
            "sample-tampered-shard",
            sample_bytes(5, &enc.branch(5).unwrap()),
            DaError::ShardProofMismatch { index: 5 },
            "first shard byte flipped by the executor: leaf changes, branch fails",
        )),
        "tamper",
        "flip_shard_byte".to_string(),
    ));

    let mut bad_branch = enc.branch(5).unwrap();
    let mut first = *bad_branch[0].as_bytes();
    first[0] ^= 0x01;
    bad_branch[0] = Hash32::from_bytes(first);
    cases.push(honest(negative(
        "sample-tampered-branch",
        sample_bytes(5, &bad_branch),
        DaError::ShardProofMismatch { index: 5 },
        "level-0 sibling hash flipped inside the carried branch",
    )));

    cases.push(honest(negative(
        "sample-index-out-of-range",
        sample_bytes(32, &[Hash32::ZERO; 5]),
        DaError::ShardIndexOutOfRange { index: 32 },
        "index 32 outside 0..32 rejects before any hashing",
    )));

    cases.push(str_extra(
        honest(negative(
            "sample-transplanted-content-root",
            sample_bytes(3, &enc.branch(3).unwrap()),
            DaError::ShardProofMismatch { index: 3 },
            "verifying under a foreign content root: the leaf binding breaks",
        )),
        "tamper",
        "foreign_content_root".to_string(),
    ));

    VectorFile {
        schema: "noos-da/shard-sample-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// File 3: reconstruction
// ---------------------------------------------------------------------------

/// Body length shared by the untampered reconstruction cases.
pub const RECONSTRUCT_BODY_LEN: usize = 300_000;

fn subset_str(subset: &[u32]) -> String {
    subset
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn reconstruct_case(
    name: &str,
    err: Option<DaError>,
    body_len: usize,
    subset: &[u32],
    tamper: Option<&str>,
    note: &str,
) -> Case {
    let body = pattern_body(body_len);
    let mut c = case(
        name,
        if err.is_some() {
            "negative"
        } else {
            "positive"
        },
        Vec::new(),
        note,
    );
    c.error_class = err.map(DaError::class_name);
    c = str_extra(c, "body_len", body_len.to_string());
    c = str_extra(c, "subset", subset_str(subset));
    if let Some(t) = tamper {
        c = str_extra(c, "tamper", t.to_string());
    }
    // The extras carry exactly what the verifier under test is given as
    // trusted/claimed inputs — the adversary's commitments where tampered.
    let (claim_root, shard_root) = match tamper {
        Some("inconsistent_parity") => {
            let adv = inconsistent_parity_encoding(&body);
            (adv.claim().content_root, *adv.shard_root())
        }
        Some("nonzero_padding") => {
            let adv = nonzero_padding_encoding(&body);
            (adv.claim().content_root, *adv.shard_root())
        }
        Some("forged_content_root") => {
            let adv = forged_content_encoding(&body);
            (adv.claim().content_root, *adv.shard_root())
        }
        _ => {
            let enc = encode_body(&body).unwrap();
            (enc.claim().content_root, *enc.shard_root())
        }
    };
    roots_extra(c, &claim_root, &shard_root)
}

fn reconstruction_file() -> VectorFile {
    let all_data: Vec<u32> = (0..16).collect();
    let all_parity: Vec<u32> = (16..32).collect();
    let mixed: Vec<u32> = vec![0, 3, 5, 6, 9, 11, 13, 14, 17, 19, 21, 22, 25, 27, 29, 30];

    let cases = vec![
        reconstruct_case(
            "reconstruct-all-data",
            None,
            RECONSTRUCT_BODY_LEN,
            &all_data,
            None,
            "all 16 data shards: pure passthrough reconstruction",
        ),
        reconstruct_case(
            "reconstruct-all-parity",
            None,
            RECONSTRUCT_BODY_LEN,
            &all_parity,
            None,
            "all 16 parity shards: full erasure decode",
        ),
        reconstruct_case(
            "reconstruct-mixed",
            None,
            RECONSTRUCT_BODY_LEN,
            &mixed,
            None,
            "8 data + 8 parity shards",
        ),
        reconstruct_case(
            "reconstruct-duplicate-candidates",
            None,
            RECONSTRUCT_BODY_LEN,
            &[0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15],
            None,
            "duplicate submissions of one index count once and stay harmless",
        ),
        reconstruct_case(
            "reconstruct-fifteen-shards",
            Some(DaError::NotEnoughValidShards {
                valid: 15,
                needed: 16,
            }),
            RECONSTRUCT_BODY_LEN,
            &all_data[..15],
            None,
            "15 valid shards are typed unavailability, never a partial body",
        ),
        reconstruct_case(
            "reconstruct-corrupt-shard-dropped",
            None,
            RECONSTRUCT_BODY_LEN,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some("corrupt_first_candidate"),
            "17 candidates, first corrupted: it is rejected individually and the rest reconstruct",
        ),
        reconstruct_case(
            "reconstruct-corrupt-shard-starves",
            Some(DaError::NotEnoughValidShards {
                valid: 15,
                needed: 16,
            }),
            RECONSTRUCT_BODY_LEN,
            &all_data,
            Some("corrupt_first_candidate"),
            "16 candidates, one corrupt: only 15 survive the branch law",
        ),
        reconstruct_case(
            "reconstruct-inconsistent-parity-commitment",
            Some(DaError::CommitmentMismatch),
            RECONSTRUCT_BODY_LEN,
            &all_data,
            Some("inconsistent_parity"),
            "proposer committed a tree over garbage parity shard 31; 16 valid branches still \
             reject at the recomputed-root check - no partial acceptance",
        ),
        reconstruct_case(
            "reconstruct-nonzero-padding",
            Some(DaError::NonZeroPadding),
            5,
            &all_data,
            Some("nonzero_padding"),
            "consistent codeword with a nonzero byte in the padding region rejects",
        ),
        reconstruct_case(
            "reconstruct-forged-content-root",
            Some(DaError::ContentRootMismatch),
            5,
            &all_data,
            Some("forged_content_root"),
            "leaves bind a forged content root; the reconstructed body unmasks it",
        ),
        reconstruct_case(
            "reconstruct-oversize-claim",
            Some(DaError::BodyTooLarge { len: 1_048_577 }),
            RECONSTRUCT_BODY_LEN,
            &all_data,
            Some("oversize_claim"),
            "claimed original_bytes over the body maximum rejects before any decode",
        ),
    ];

    VectorFile {
        schema: "noos-da/reconstruction-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// File 4: blob descriptors
// ---------------------------------------------------------------------------

fn enc_obj<T: NoosEncode>(v: &T) -> Vec<u8> {
    let mut w = Writer::new();
    v.encode(&mut w);
    w.into_bytes()
}

/// A valid fee-paid consensus-aux blob descriptor.
#[must_use]
pub fn consensus_blob() -> BlobDescriptorV1 {
    BlobDescriptorV1 {
        namespace: 1,
        content_root: h(0x41),
        original_bytes: 262_144,
        shard_bytes: 65_536,
        data_shards: 4,
        parity_shards: 4,
        retention_epochs: 8,
        codec_id: 1,
        encryption_descriptor: OptionalObject(None),
        access_policy_root: OptionalHash32(None),
    }
}

/// A valid NEL-trace artifact descriptor with both optional roots set.
#[must_use]
pub fn artifact_blob() -> BlobDescriptorV1 {
    BlobDescriptorV1 {
        namespace: 2,
        content_root: h(0x51),
        original_bytes: 2_752_512, // 21,504 B/token x 128 tokens
        shard_bytes: 1_048_576,
        data_shards: 3,
        parity_shards: 3,
        retention_epochs: 30,
        codec_id: 1,
        encryption_descriptor: OptionalObject(Some(BoundedBytes::new(vec![0x99; 64]).unwrap())),
        access_policy_root: OptionalHash32(Some(h(0x52))),
    }
}

fn law(c: Case, which: &str) -> Case {
    str_extra(c, "law", which.to_string())
}

fn descriptor_file() -> VectorFile {
    let mut cases = Vec::new();

    cases.push(law(
        positive(
            "blob-consensus-aux-valid",
            enc_obj(&consensus_blob()),
            "maximal consensus-aux blob: 262,144 bytes over 4+4 x 64 KiB shards",
        ),
        "consensus",
    ));

    cases.push(law(
        positive(
            "blob-nel-trace-valid",
            enc_obj(&artifact_blob()),
            "NEL activation-trace artifact with encryption descriptor and access-policy root",
        ),
        "any",
    ));

    let mut weights = consensus_blob();
    weights.namespace = 3;
    weights.original_bytes = 3_260_000_000;
    weights.shard_bytes = 16_777_216;
    weights.data_shards = 195;
    weights.parity_shards = 61;
    weights.retention_epochs = 1024;
    cases.push(law(
        positive(
            "blob-model-weights-valid",
            enc_obj(&weights),
            "model-weight artifact at the 16 MiB shard ceiling, 256 total shards",
        ),
        "any",
    ));

    let mut unknown_ns = consensus_blob();
    unknown_ns.namespace = 9;
    cases.push(law(
        negative(
            "blob-unknown-namespace",
            enc_obj(&unknown_ns),
            DaError::UnknownNamespace { namespace: 9 },
            "namespace 9 is not in the closed registry",
        ),
        "any",
    ));

    let mut unknown_codec = consensus_blob();
    unknown_codec.codec_id = 2;
    cases.push(law(
        negative(
            "blob-unknown-codec",
            enc_obj(&unknown_codec),
            DaError::UnknownCodec { codec_id: 2 },
            "codec 2 is not in the closed registry",
        ),
        "any",
    ));

    let mut zero_retention = consensus_blob();
    zero_retention.retention_epochs = 0;
    cases.push(law(
        negative(
            "blob-zero-retention",
            enc_obj(&zero_retention),
            DaError::ZeroRetention,
            "a blob must declare a nonzero retention horizon",
        ),
        "any",
    ));

    let mut empty = consensus_blob();
    empty.original_bytes = 0;
    empty.data_shards = 1;
    empty.parity_shards = 1;
    cases.push(law(
        negative(
            "blob-empty",
            enc_obj(&empty),
            DaError::EmptyBlob,
            "zero original bytes commit to nothing",
        ),
        "any",
    ));

    let mut too_large = consensus_blob();
    too_large.original_bytes = 262_145;
    too_large.data_shards = 5;
    cases.push(law(
        negative(
            "blob-too-large",
            enc_obj(&too_large),
            DaError::BlobTooLarge {
                original_bytes: 262_145,
                max: 262_144,
            },
            "one byte over the consensus-aux 262,144 blob limit",
        ),
        "any",
    ));

    let mut overflow = consensus_blob();
    overflow.data_shards = 3;
    cases.push(law(
        negative(
            "blob-capacity-overflow",
            enc_obj(&overflow),
            DaError::ShardGeometry,
            "262,144 bytes cannot fit 3 x 64 KiB data shards",
        ),
        "any",
    ));

    let mut oversharded = consensus_blob();
    oversharded.original_bytes = 100_000;
    cases.push(law(
        negative(
            "blob-oversharded",
            enc_obj(&oversharded),
            DaError::ShardGeometry,
            "100,000 bytes need 2 data shards, not 4: geometry must be minimal",
        ),
        "any",
    ));

    let mut no_parity = consensus_blob();
    no_parity.parity_shards = 0;
    cases.push(law(
        negative(
            "blob-zero-parity",
            enc_obj(&no_parity),
            DaError::ShardGeometry,
            "zero parity shards is chunking, not availability coding",
        ),
        "any",
    ));

    cases.push(law(
        negative(
            "blob-artifact-in-consensus",
            enc_obj(&artifact_blob()),
            DaError::NamespaceNotConsensus { namespace: 2 },
            "a valid artifact descriptor still rejects inside consensus_blob_descriptors: \
             artifacts cannot buy consensus retention or consensus IO",
        ),
        "consensus",
    ));

    VectorFile {
        schema: "noos-da/blob-descriptor-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Every DA vector file, in emission order.
#[must_use]
pub fn files() -> Vec<(&'static str, VectorFile)> {
    vec![
        ("da-body-coding-v1.json", coding_file()),
        ("da-shard-sample-v1.json", sample_file()),
        ("da-reconstruction-v1.json", reconstruction_file()),
        ("da-blob-descriptor-v1.json", descriptor_file()),
    ]
}

/// Renders a vector file as `check_vectors.py`-conformant JSON.
#[must_use]
pub fn render_json(file: &VectorFile) -> String {
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"schema\": \"{}\",\n", file.schema));
    out.push_str("  \"cases\": [\n");
    for (i, c) in file.cases.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", c.name));
        out.push_str(&format!("      \"kind\": \"{}\",\n", c.kind));
        out.push_str(&format!("      \"bytes\": \"{}\",\n", hex(&c.bytes)));
        for (k, v) in &c.extras {
            out.push_str(&format!("      \"{k}\": \"{}\",\n", hex(v)));
        }
        for (k, v) in &c.extras_str {
            out.push_str(&format!("      \"{k}\": \"{v}\",\n"));
        }
        if let Some(err) = c.error_class {
            out.push_str(&format!("      \"error_class\": \"{err}\",\n"));
        }
        out.push_str(&format!("      \"note\": \"{}\"\n", c.note));
        out.push_str(if i + 1 == file.cases.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    out.push_str("  ]\n}\n");
    out
}
