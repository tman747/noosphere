//! Behavioral tests for the DA laws: subset-class reconstruction coverage,
//! individual corrupt-shard rejection, commitment/content/padding
//! rejection, padding edges, registry semantics, determinism, and the
//! availability primitive.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use noos_crypto::Hash32;

use crate::vector_gen::{
    artifact_blob, consensus_blob, forged_content_encoding, inconsistent_parity_encoding,
    nonzero_padding_encoding, pattern_body,
};
use crate::{
    encode_body, reconstruct_and_verify, validate_blob_descriptor,
    validate_consensus_blob_descriptor, verify_body_shard, verify_shard_sample, AvailabilityLedger,
    DaError, EncodedBodyV1, ShardCandidateV1, StorageDomain, BODY_DATA_SHARDS, BODY_SHARD_BYTES,
    BODY_TOTAL_SHARDS, MAX_BLOCK_DA_FORM_BYTES,
};

fn candidates(enc: &EncodedBodyV1, indices: &[u32]) -> Vec<ShardCandidateV1> {
    indices.iter().map(|&i| enc.candidate(i).unwrap()).collect()
}

fn reconstruct_subset(body: &[u8], indices: &[u32]) -> Result<Vec<u8>, DaError> {
    let enc = encode_body(body).unwrap();
    reconstruct_and_verify(enc.shard_root(), enc.claim(), &candidates(&enc, indices))
        .map(crate::ReconstructedBodyV1::into_bytes)
}

// ---------------------------------------------------------------------------
// Subset-class coverage: every (k data, 16-k parity) class, k = 0..=16
// ---------------------------------------------------------------------------

/// Deterministic subset with exactly `k` data shards and `16 - k` parity
/// shards, spread (not contiguous) so different erasure patterns are hit.
fn class_subset(k: usize) -> Vec<u32> {
    let data: Vec<u32> = (0..BODY_DATA_SHARDS as u32).step_by(1).collect();
    let parity: Vec<u32> = (BODY_DATA_SHARDS as u32..BODY_TOTAL_SHARDS as u32).collect();
    let mut out = Vec::with_capacity(BODY_DATA_SHARDS);
    // Take every other data shard first to interleave erasures.
    out.extend(data.iter().rev().step_by(1).take(k).copied());
    out.extend(parity.iter().step_by(1).take(BODY_DATA_SHARDS - k).copied());
    out.sort_unstable();
    out
}

#[test]
fn roundtrip_every_sixteen_subset_class() {
    let body = pattern_body(123_457);
    for k in 0..=BODY_DATA_SHARDS {
        let subset = class_subset(k);
        assert_eq!(subset.len(), BODY_DATA_SHARDS, "class {k}");
        let got = reconstruct_subset(&body, &subset)
            .unwrap_or_else(|e| panic!("class {k} ({subset:?}): {e}"));
        assert_eq!(got, body, "class {k} must reproduce the exact body");
    }
}

#[test]
fn roundtrip_padding_edges() {
    for len in [
        0_usize,
        1,
        BODY_SHARD_BYTES - 1,
        BODY_SHARD_BYTES,
        BODY_SHARD_BYTES + 1,
        MAX_BLOCK_DA_FORM_BYTES - 1,
        MAX_BLOCK_DA_FORM_BYTES,
    ] {
        let body = pattern_body(len);
        let all_parity: Vec<u32> = (16..32).collect();
        let got =
            reconstruct_subset(&body, &all_parity).unwrap_or_else(|e| panic!("len {len}: {e}"));
        assert_eq!(got, body, "len {len}");
    }
}

#[test]
fn oversized_body_rejects() {
    let body = pattern_body(MAX_BLOCK_DA_FORM_BYTES + 1);
    assert_eq!(
        encode_body(&body).unwrap_err(),
        DaError::BodyTooLarge {
            len: MAX_BLOCK_DA_FORM_BYTES as u64 + 1
        }
    );
}

// ---------------------------------------------------------------------------
// Corrupt/short-shard law
// ---------------------------------------------------------------------------

#[test]
fn corrupt_shard_rejects_individually() {
    let body = pattern_body(50_000);
    let enc = encode_body(&body).unwrap();

    let mut corrupt = enc.candidate(2).unwrap();
    corrupt.bytes[100] ^= 0xFF;
    assert_eq!(
        verify_body_shard(enc.shard_root(), enc.claim(), &corrupt),
        Err(DaError::ShardProofMismatch { index: 2 })
    );

    // 17 candidates with one corrupt: reconstruction survives.
    let mut cands = candidates(&enc, &(0..17).collect::<Vec<_>>());
    cands[2].bytes[100] ^= 0xFF;
    let got = reconstruct_and_verify(enc.shard_root(), enc.claim(), &cands).unwrap();
    assert_eq!(got.bytes(), &body[..]);

    // Exactly 16 candidates with one corrupt: typed unavailability.
    let mut cands = candidates(&enc, &(0..16).collect::<Vec<_>>());
    cands[0].bytes[0] ^= 0x01;
    assert_eq!(
        reconstruct_and_verify(enc.shard_root(), enc.claim(), &cands).unwrap_err(),
        DaError::NotEnoughValidShards {
            valid: 15,
            needed: 16
        }
    );
}

#[test]
fn short_and_misindexed_shards_reject() {
    let body = pattern_body(10);
    let enc = encode_body(&body).unwrap();
    let root = enc.shard_root();
    let claim = enc.claim();

    let mut short = enc.candidate(0).unwrap();
    short.bytes.truncate(BODY_SHARD_BYTES - 1);
    assert_eq!(
        verify_body_shard(root, claim, &short),
        Err(DaError::WrongShardLength {
            index: 0,
            len: BODY_SHARD_BYTES as u64 - 1
        })
    );

    let mut oob = enc.candidate(0).unwrap();
    oob.index = 32;
    assert_eq!(
        verify_body_shard(root, claim, &oob),
        Err(DaError::ShardIndexOutOfRange { index: 32 })
    );

    // A shard presented at the wrong (in-range) index fails its branch.
    let mut swapped = enc.candidate(4).unwrap();
    swapped.index = 5;
    assert_eq!(
        verify_body_shard(root, claim, &swapped),
        Err(DaError::ShardProofMismatch { index: 5 })
    );
}

#[test]
fn fewer_than_sixteen_valid_shards_fail_typed() {
    let body = pattern_body(77_777);
    let subset: Vec<u32> = (0..15).collect();
    assert_eq!(
        reconstruct_subset(&body, &subset).unwrap_err(),
        DaError::NotEnoughValidShards {
            valid: 15,
            needed: 16
        }
    );
    assert_eq!(
        reconstruct_subset(&body, &[]).unwrap_err(),
        DaError::NotEnoughValidShards {
            valid: 0,
            needed: 16
        }
    );
}

// ---------------------------------------------------------------------------
// Commitment / content / padding rejection (no partial acceptance)
// ---------------------------------------------------------------------------

#[test]
fn inconsistent_committed_codeword_rejects_whole_body() {
    let body = pattern_body(90_001);
    let adv = inconsistent_parity_encoding(&body);
    // All 16 provided branches are VALID against the adversarial root...
    let cands = candidates(&adv, &(0..16).collect::<Vec<_>>());
    for c in &cands {
        verify_body_shard(adv.shard_root(), adv.claim(), c).unwrap();
    }
    // ...and the body still rejects as a whole at the recomputed-root check.
    assert_eq!(
        reconstruct_and_verify(adv.shard_root(), adv.claim(), &cands).unwrap_err(),
        DaError::CommitmentMismatch
    );
}

#[test]
fn wrong_trusted_root_rejects() {
    let body = pattern_body(4_242);
    let enc = encode_body(&body).unwrap();
    let cands = candidates(&enc, &(0..16).collect::<Vec<_>>());
    let wrong_root = Hash32::from_bytes([0xAB; 32]);
    // Every branch fails against a foreign root: typed unavailability,
    // never a body accepted under the wrong commitment.
    assert_eq!(
        reconstruct_and_verify(&wrong_root, enc.claim(), &cands).unwrap_err(),
        DaError::NotEnoughValidShards {
            valid: 0,
            needed: 16
        }
    );
}

#[test]
fn nonzero_padding_rejects() {
    let body = pattern_body(5);
    let adv = nonzero_padding_encoding(&body);
    let cands = candidates(&adv, &(0..16).collect::<Vec<_>>());
    assert_eq!(
        reconstruct_and_verify(adv.shard_root(), adv.claim(), &cands).unwrap_err(),
        DaError::NonZeroPadding
    );
}

#[test]
fn forged_content_root_rejects() {
    let body = pattern_body(5);
    let adv = forged_content_encoding(&body);
    let cands = candidates(&adv, &(0..16).collect::<Vec<_>>());
    assert_eq!(
        reconstruct_and_verify(adv.shard_root(), adv.claim(), &cands).unwrap_err(),
        DaError::ContentRootMismatch
    );
}

#[test]
fn wrong_original_bytes_claim_rejects() {
    let body = pattern_body(100);
    let enc = encode_body(&body).unwrap();
    let cands = candidates(&enc, &(0..16).collect::<Vec<_>>());

    // Shorter claim: the true body byte at offset 99 lands in the claimed
    // padding region.
    let mut short_claim = *enc.claim();
    short_claim.original_bytes = 99;
    assert_eq!(
        reconstruct_and_verify(enc.shard_root(), &short_claim, &cands).unwrap_err(),
        DaError::NonZeroPadding
    );

    // Longer claim: padding is zero, but the content hash unmasks it.
    let mut long_claim = *enc.claim();
    long_claim.original_bytes = 101;
    assert_eq!(
        reconstruct_and_verify(enc.shard_root(), &long_claim, &cands).unwrap_err(),
        DaError::ContentRootMismatch
    );

    // Oversize claim rejects before any decode.
    let mut oversize = *enc.claim();
    oversize.original_bytes = MAX_BLOCK_DA_FORM_BYTES as u64 + 1;
    assert_eq!(
        reconstruct_and_verify(enc.shard_root(), &oversize, &cands).unwrap_err(),
        DaError::BodyTooLarge {
            len: MAX_BLOCK_DA_FORM_BYTES as u64 + 1
        }
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn encoding_is_deterministic() {
    let body = pattern_body(200_200);
    let a = encode_body(&body).unwrap();
    let b = encode_body(&body).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.shards(), b.shards());
    assert_eq!(a.shard_root(), b.shard_root());
}

/// Golden root: pins the exact shard bytes (including the RS-GF8-V1
/// generator matrix of the pinned `reed-solomon-erasure` 6.0.0) and the
/// domain-separated tree. Any library or domain change breaks this.
#[test]
fn golden_shard_root_is_stable() {
    let enc = encode_body(&pattern_body(200)).unwrap();
    let got = format!("{:x}", enc.shard_root());
    assert_eq!(
        got,
        crate::tests::golden::SHARD_ROOT_PATTERN_200,
        "shard commitment changed: RS matrix, domains, or tree law drifted"
    );
}

pub(crate) mod golden {
    /// `shard_root` of `pattern_body(200)`; regenerate ONLY for an
    /// intentional, versioned coding-law change.
    pub const SHARD_ROOT_PATTERN_200: &str =
        "429b94e8da0e654df7c3c1bce4c3096f1998ca3202740b5ccc7435797ac76b1a";
}

// ---------------------------------------------------------------------------
// Sampling primitive
// ---------------------------------------------------------------------------

#[test]
fn shard_sample_verifies_and_rejects() {
    let body = pattern_body(65_537);
    let enc = encode_body(&body).unwrap();
    let root = enc.shard_root();
    let claim = enc.claim();

    for index in [0_u32, 1, 15, 16, 31] {
        let branch = enc.branch(index).unwrap();
        verify_shard_sample(root, claim, index, &enc.shards()[index as usize], &branch)
            .unwrap_or_else(|e| panic!("index {index}: {e}"));
    }

    // Sampling is an opinion: a passing sample never marks availability.
    let ledger = AvailabilityLedger::new();
    assert!(!ledger.body_available(root));

    let mut tampered = enc.shards()[3].clone();
    tampered[0] ^= 0x80;
    let branch = enc.branch(3).unwrap();
    assert_eq!(
        verify_shard_sample(root, claim, 3, &tampered, &branch),
        Err(DaError::ShardProofMismatch { index: 3 })
    );
}

// ---------------------------------------------------------------------------
// Availability ledger primitive
// ---------------------------------------------------------------------------

#[test]
fn availability_ledger_tracks_only_held_bodies() {
    let body_a = pattern_body(11);
    let body_b = pattern_body(22);
    let enc_a = encode_body(&body_a).unwrap();
    let enc_b = encode_body(&body_b).unwrap();

    let mut ledger = AvailabilityLedger::new();
    assert!(ledger.is_empty());
    assert!(!ledger.body_available(enc_a.shard_root()));

    // Proposer path.
    ledger.record_encoded(&enc_a);
    assert!(ledger.body_available(enc_a.shard_root()));
    assert!(!ledger.body_available(enc_b.shard_root()));

    // Full-node path: only a verified reconstruction can enter.
    let cands = candidates(&enc_b, &(16..32).collect::<Vec<_>>());
    let rec = reconstruct_and_verify(enc_b.shard_root(), enc_b.claim(), &cands).unwrap();
    ledger.record_reconstructed(&rec);
    assert!(ledger.body_available(enc_b.shard_root()));
    assert_eq!(ledger.len(), 2);

    // Deterministic byte-ordered iteration.
    let roots: Vec<_> = ledger.available_roots().collect();
    let mut sorted = roots.clone();
    sorted.sort();
    assert_eq!(roots, sorted);
}

// ---------------------------------------------------------------------------
// Blob descriptor semantics
// ---------------------------------------------------------------------------

#[test]
fn descriptor_registries_accept_and_reject() {
    let ns = validate_blob_descriptor(&consensus_blob()).unwrap();
    assert_eq!(ns.domain, StorageDomain::ConsensusBody);

    let ns = validate_blob_descriptor(&artifact_blob()).unwrap();
    assert_eq!(ns.domain, StorageDomain::Artifact);

    let mut d = consensus_blob();
    d.namespace = 9;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::UnknownNamespace { namespace: 9 }
    );

    let mut d = consensus_blob();
    d.codec_id = 0;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::UnknownCodec { codec_id: 0 }
    );

    let mut d = consensus_blob();
    d.retention_epochs = 0;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::ZeroRetention
    );

    let mut d = consensus_blob();
    d.original_bytes = 0;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::EmptyBlob
    );
}

#[test]
fn descriptor_geometry_law() {
    // Capacity overflow.
    let mut d = consensus_blob();
    d.data_shards = 3;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::ShardGeometry
    );

    // Non-minimal data shard count.
    let mut d = consensus_blob();
    d.original_bytes = 100_000;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::ShardGeometry
    );

    // Zero parity / zero data / zero shard bytes.
    for f in [
        |d: &mut noos_braid::BlobDescriptorV1| d.parity_shards = 0,
        |d: &mut noos_braid::BlobDescriptorV1| d.data_shards = 0,
        |d: &mut noos_braid::BlobDescriptorV1| d.shard_bytes = 0,
    ] {
        let mut d = consensus_blob();
        f(&mut d);
        assert_eq!(
            validate_blob_descriptor(&d).unwrap_err(),
            DaError::ShardGeometry
        );
    }

    // Codec total-shard ceiling (GF(2^8): 256 symbols).
    let mut d = consensus_blob();
    d.namespace = 3;
    d.shard_bytes = 16_777_216;
    d.original_bytes = 4_294_967_296;
    d.data_shards = 256;
    d.parity_shards = 1;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::ShardGeometry
    );

    // Namespace shard-size ceiling.
    let mut d = consensus_blob();
    d.shard_bytes = 65_537;
    d.data_shards = 4;
    assert_eq!(
        validate_blob_descriptor(&d).unwrap_err(),
        DaError::ShardGeometry
    );
}

#[test]
fn consensus_law_excludes_artifact_namespaces() {
    assert_eq!(
        validate_consensus_blob_descriptor(&artifact_blob()).unwrap_err(),
        DaError::NamespaceNotConsensus { namespace: 2 }
    );
    validate_consensus_blob_descriptor(&consensus_blob()).unwrap();
}

#[test]
fn storage_domains_are_disjoint() {
    assert_ne!(
        StorageDomain::ConsensusBody.segment_namespace(),
        StorageDomain::Artifact.segment_namespace()
    );
    // Every registered namespace maps to exactly one domain.
    for ns in &crate::NAMESPACES {
        let via_lookup = crate::namespace_by_id(ns.id).unwrap();
        assert_eq!(via_lookup.domain, ns.domain);
    }
}
