use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use noos_crypto::Hash32;
use reed_solomon_erasure::galois_8::ReedSolomon;

use super::artifact::*;

#[derive(Default, Clone)]
struct MemoryArtifact {
    shares: BTreeMap<(u32, u8), Vec<u8>>,
    manifest: Option<ArtifactManifestV1>,
    identity: Option<(u64, Hash32, [u8; 32], u32)>,
    checkpoint_rows: Vec<ArtifactStripeV1>,
    checkpoint_calls: Vec<u32>,
    stage_calls: BTreeMap<(u32, u8), usize>,
    max_staged_bytes: usize,
    max_read_request: usize,
    fail_checkpoint: Option<u32>,
}

impl ArtifactShareSink for MemoryArtifact {
    fn begin_artifact(
        &mut self,
        source_length: u64,
        protocol_payload_root: &Hash32,
        published_sha256: &[u8; 32],
        stripe_count: u32,
    ) -> Result<(), ArtifactError> {
        self.identity = Some((
            source_length,
            *protocol_payload_root,
            *published_sha256,
            stripe_count,
        ));
        Ok(())
    }

    fn stage_share(
        &mut self,
        stripe: u32,
        position: u8,
        bytes: &[u8],
    ) -> Result<(), ArtifactError> {
        self.max_staged_bytes = self.max_staged_bytes.max(bytes.len());
        *self.stage_calls.entry((stripe, position)).or_default() += 1;
        self.shares.insert((stripe, position), bytes.to_vec());
        Ok(())
    }

    fn checkpoint_stripe(&mut self, stripe: u32) -> Result<(), ArtifactError> {
        self.checkpoint_calls.push(stripe);
        if self.fail_checkpoint == Some(stripe) {
            return Err(ArtifactError::Sink("injected checkpoint failure".into()));
        }
        Ok(())
    }

    fn checkpoint_artifact_stripe(
        &mut self,
        stripe: &ArtifactStripeV1,
    ) -> Result<(), ArtifactError> {
        self.checkpoint_rows.push(stripe.clone());
        self.checkpoint_stripe(stripe.stripe_index)
    }

    fn publish_manifest(&mut self, manifest: &ArtifactManifestV1) -> Result<(), ArtifactError> {
        self.manifest = Some(manifest.clone());
        Ok(())
    }
}

impl ArtifactShareSource for MemoryArtifact {
    fn read_share(
        &mut self,
        stripe: u32,
        position: u8,
        out: &mut [u8],
    ) -> Result<bool, ArtifactError> {
        self.max_read_request = self.max_read_request.max(out.len());
        let Some(bytes) = self.shares.get(&(stripe, position)) else {
            return Ok(false);
        };
        if bytes.len() != out.len() {
            return Ok(false);
        }
        out.copy_from_slice(bytes);
        Ok(true)
    }
}

fn bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 131 + i / 251) & 255) as u8)
        .collect()
}

fn combinations(n: u8, k: u8) -> Vec<Vec<u8>> {
    fn walk(n: u8, k: u8, next: u8, selected: &mut Vec<u8>, out: &mut Vec<Vec<u8>>) {
        if selected.len() == k as usize {
            out.push(selected.clone());
            return;
        }
        for i in next..n {
            selected.push(i);
            walk(n, k, i + 1, selected, out);
            selected.pop();
        }
    }
    let mut out = Vec::new();
    walk(n, k, 0, &mut Vec::new(), &mut out);
    out
}

struct SubsetSource<'a> {
    complete: &'a MemoryArtifact,
    keep: &'a [u8],
}

impl ArtifactShareSource for SubsetSource<'_> {
    fn read_share(
        &mut self,
        stripe: u32,
        position: u8,
        out: &mut [u8],
    ) -> Result<bool, ArtifactError> {
        if !self.keep.contains(&position) {
            return Ok(false);
        }
        let Some(bytes) = self.complete.shares.get(&(stripe, position)) else {
            return Ok(false);
        };
        if bytes.len() != out.len() {
            return Ok(false);
        }
        out.copy_from_slice(bytes);
        Ok(true)
    }
}

struct DuplicateSource {
    share: Vec<u8>,
}

impl ArtifactShareSource for DuplicateSource {
    fn read_share(
        &mut self,
        _stripe: u32,
        _position: u8,
        out: &mut [u8],
    ) -> Result<bool, ArtifactError> {
        out.copy_from_slice(&self.share);
        Ok(true)
    }
}

struct TrackingReader {
    cursor: Cursor<Vec<u8>>,
    max_request: usize,
}

impl TrackingReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(bytes),
            max_request: 0,
        }
    }
}

impl Read for TrackingReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.max_request = self.max_request.max(out.len());
        self.cursor.read(out)
    }
}

impl Seek for TrackingReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.cursor.seek(position)
    }
}

struct MutatingSource {
    cursor: Cursor<Vec<u8>>,
    replacement: Vec<u8>,
    switched: bool,
}

impl MutatingSource {
    fn new(first: Vec<u8>, replacement: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(first),
            replacement,
            switched: false,
        }
    }
}

impl Read for MutatingSource {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(out)
    }
}

impl Seek for MutatingSource {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        if position == SeekFrom::Start(0) && self.cursor.position() != 0 && !self.switched {
            self.cursor = Cursor::new(self.replacement.clone());
            self.switched = true;
        }
        self.cursor.seek(position)
    }
}

fn test_domain_hash(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    Hash32::from_bytes(*hasher.finalize().as_bytes())
}

fn decode_error(manifest: &ArtifactManifestV1, mut store: MemoryArtifact) -> ArtifactError {
    ArtifactDecoderV1::new()
        .unwrap()
        .decode(manifest, &mut store, &mut std::io::sink())
        .unwrap_err()
}

#[test]
fn small_boundaries_stream_roundtrip_and_geometry() {
    assert!(ARTIFACT_CODEC_WORKING_SET_BYTES <= 32 * 1024 * 1024);
    for len in [
        1,
        ARTIFACT_SHARE_BYTES - 1,
        ARTIFACT_SHARE_BYTES,
        ARTIFACT_STRIPE_BYTES - 1,
        ARTIFACT_STRIPE_BYTES,
        ARTIFACT_STRIPE_BYTES + 1,
    ] {
        let original = bytes(len);
        let mut store = MemoryArtifact::default();
        let manifest = ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut Cursor::new(&original), &mut store, 9)
            .unwrap();
        manifest.validate().unwrap();
        assert_eq!(manifest.stripes.len(), len.div_ceil(ARTIFACT_STRIPE_BYTES));
        assert!(manifest.canonical_bytes().len() <= ARTIFACT_SHARE_BYTES);
        for stripe in &manifest.stripes {
            assert_eq!(
                stripe.descriptor.original_bytes,
                ARTIFACT_STRIPE_BYTES as u64
            );
            assert_eq!(
                stripe.actual_source_bytes + stripe.padding_bytes,
                ARTIFACT_STRIPE_BYTES as u32
            );
        }
        let mut decoded = Vec::new();
        ArtifactDecoderV1::new()
            .unwrap()
            .decode(&manifest, &mut store, &mut decoded)
            .unwrap();
        assert_eq!(decoded, original);
    }
}

#[test]
fn every_495_subset_and_any_four_losses_reconstruct() {
    let original = bytes(ARTIFACT_STRIPE_BYTES);
    let mut complete = MemoryArtifact::default();
    let manifest = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(&original), &mut complete, 9)
        .unwrap();
    let subsets = combinations(12, 8);
    assert_eq!(subsets.len(), 495);
    for keep in subsets {
        let mut partial = SubsetSource {
            complete: &complete,
            keep: &keep,
        };
        ArtifactDecoderV1::new()
            .unwrap()
            .decode(&manifest, &mut partial, &mut std::io::sink())
            .unwrap();
    }
}

#[test]
fn corruption_replay_transplant_probe_and_padding_reject() {
    let original = bytes(ARTIFACT_STRIPE_BYTES + 73);
    let mut store = MemoryArtifact::default();
    let manifest = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(&original), &mut store, 9)
        .unwrap();

    let share = store.shares.get(&(0, 2)).unwrap();
    let commitment = share_commitment(0, 2, share).unwrap();
    let (leaf, branch) = probe_branch(0, 2, share, 7).unwrap();
    assert!(verify_probe(
        &commitment.probe_root,
        0,
        2,
        7,
        &leaf,
        &branch
    ));
    assert!(!verify_probe(
        &commitment.probe_root,
        1,
        2,
        7,
        &leaf,
        &branch
    ));
    let mut corrupt_leaf = leaf;
    corrupt_leaf[0] ^= 1;
    assert!(!verify_probe(
        &commitment.probe_root,
        0,
        2,
        7,
        &corrupt_leaf,
        &branch
    ));

    // A corrupt share is discarded; eight other positions still recover.
    store.shares.get_mut(&(0, 0)).unwrap()[99] ^= 1;
    ArtifactDecoderV1::new()
        .unwrap()
        .decode(&manifest, &mut store, &mut std::io::sink())
        .unwrap();

    // Replaying a share into another stripe and transplanting it to another
    // position both fail their stripe+position-bound commitment.
    let replay = store.shares.get(&(0, 1)).unwrap().clone();
    store.shares.insert((1, 1), replay.clone());
    for p in 3..12 {
        store.shares.remove(&(1, p));
    }
    assert!(matches!(
        ArtifactDecoderV1::new()
            .unwrap()
            .decode(&manifest, &mut store, &mut std::io::sink()),
        Err(ArtifactError::InsufficientShares { stripe: 1, .. })
    ));
    store.shares.insert((1, 2), replay);
    assert!(
        share_commitment(1, 2, store.shares.get(&(1, 2)).unwrap()).unwrap()
            != manifest.stripes[1].shares[2]
    );

    let mut bad = manifest.clone();
    bad.stripes[1].actual_source_bytes += 1;
    bad.stripes[1].padding_bytes -= 1;
    assert!(matches!(
        bad.validate(),
        Err(ArtifactError::InvalidManifest("final padding law"))
    ));
}

#[test]
fn repair_recreates_exact_position_root() {
    let original = bytes(ARTIFACT_STRIPE_BYTES + 17);
    let mut complete = MemoryArtifact::default();
    let manifest = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(&original), &mut complete, 9)
        .unwrap();
    let mut source = complete.clone();
    source.shares.retain(|(_, p), _| *p != 4);
    let mut repaired = MemoryArtifact::default();
    ArtifactDecoderV1::new()
        .unwrap()
        .repair_position(&manifest, 4, &mut source, &mut repaired)
        .unwrap();
    for stripe in 0..manifest.stripes.len() as u32 {
        assert_eq!(
            repaired.shares.get(&(stripe, 4)),
            complete.shares.get(&(stripe, 4))
        );
    }
    assert_eq!(
        repaired.manifest.as_ref().unwrap().position_roots[4],
        manifest.position_roots[4]
    );
}

#[test]
fn frozen_geometry_empty_and_early_bounds_are_canonical() {
    assert_eq!(ARTIFACT_SHARE_BYTES, 1_047_552);
    assert_eq!(ARTIFACT_STRIPE_BYTES, 8_380_416);
    assert_eq!(ARTIFACT_PROBE_LEAF_BYTES, 32_736);
    assert_eq!(
        ARTIFACT_PROBE_LEAF_BYTES * ARTIFACT_PROBE_LEAVES,
        ARTIFACT_SHARE_BYTES
    );
    assert_eq!(BONSAI_STRIPES, 454);
    assert_eq!(
        (u64::from(BONSAI_STRIPES) - 1) * ARTIFACT_STRIPE_BYTES as u64
            + u64::from(BONSAI_FINAL_ACTUAL_BYTES),
        BONSAI_SOURCE_BYTES,
    );
    assert_eq!(
        BONSAI_FINAL_ACTUAL_BYTES + BONSAI_FINAL_PADDING_BYTES,
        ARTIFACT_STRIPE_BYTES as u32,
    );
    assert_eq!(
        BONSAI_POSITION_BYTES,
        BONSAI_STRIPES as u64 * ARTIFACT_SHARE_BYTES as u64
    );
    assert_eq!(ARTIFACT_MAX_STRIPES, 1_246);
    assert_eq!(ARTIFACT_MAX_SOURCE_BYTES, 10_441_998_336);
    assert!(
        ARTIFACT_MANIFEST_FIXED_BYTES + ARTIFACT_MAX_STRIPES * ARTIFACT_MANIFEST_STRIPE_BYTES
            <= ARTIFACT_SHARE_BYTES,
    );

    let mut store = MemoryArtifact::default();
    assert!(matches!(
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut Cursor::new(Vec::<u8>::new()), &mut store, 9),
        Err(ArtifactError::Empty),
    ));
    assert!(store.shares.is_empty());

    assert!(matches!(
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut Cursor::new(vec![1]), &mut store, 0),
        Err(ArtifactError::InvalidManifest("zero retention")),
    ));
    assert!(store.shares.is_empty());

    let mut encoded_count = vec![0_u8; ARTIFACT_MANIFEST_FIXED_BYTES];
    encoded_count[76..80].copy_from_slice(&((ARTIFACT_MAX_STRIPES + 1) as u32).to_le_bytes());
    assert!(matches!(
        ArtifactManifestV1::from_canonical_bytes(&encoded_count),
        Err(ArtifactError::TooManyStripes),
    ));
}

#[test]
fn canonical_manifest_parser_roundtrips_and_rejects_bad_lengths() {
    let original = bytes(37);
    let mut store = MemoryArtifact::default();
    let manifest = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(original), &mut store, 9)
        .unwrap();
    let canonical = manifest.canonical_bytes();
    assert_eq!(
        canonical.len(),
        ARTIFACT_MANIFEST_FIXED_BYTES + ARTIFACT_MANIFEST_STRIPE_BYTES
    );
    assert_eq!(
        ArtifactManifestV1::from_canonical_bytes(&canonical).unwrap(),
        manifest
    );

    let mut truncated = canonical.clone();
    truncated.pop();
    assert!(ArtifactManifestV1::from_canonical_bytes(&truncated).is_err());

    let mut trailing = canonical;
    trailing.push(0);
    assert!(ArtifactManifestV1::from_canonical_bytes(&trailing).is_err());
    assert!(matches!(
        ArtifactManifestV1::from_canonical_bytes(&vec![0; ARTIFACT_SHARE_BYTES + 1]),
        Err(ArtifactError::InvalidManifest("manifest byte length")),
    ));
}

#[test]
fn short_oversize_corrupt_transplanted_and_duplicate_shares_do_not_count() {
    let original = bytes(4_097);
    let mut complete = MemoryArtifact::default();
    let manifest = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(original), &mut complete, 9)
        .unwrap();

    let first_eight = || {
        let mut partial = complete.clone();
        partial.shares.retain(|(_, position), _| *position < 8);
        partial
    };

    let mut short = first_eight();
    short.shares.get_mut(&(0, 0)).unwrap().pop();
    assert!(matches!(
        decode_error(&manifest, short),
        ArtifactError::InsufficientShares {
            stripe: 0,
            valid: 7
        },
    ));

    let mut oversize = first_eight();
    oversize.shares.get_mut(&(0, 0)).unwrap().push(0);
    assert!(matches!(
        decode_error(&manifest, oversize),
        ArtifactError::InsufficientShares {
            stripe: 0,
            valid: 7
        },
    ));

    let mut corrupt = first_eight();
    corrupt.shares.get_mut(&(0, 0)).unwrap()[17] ^= 1;
    assert!(matches!(
        decode_error(&manifest, corrupt),
        ArtifactError::InsufficientShares {
            stripe: 0,
            valid: 7
        },
    ));

    let mut transplanted = first_eight();
    let position_one = transplanted.shares.get(&(0, 1)).unwrap().clone();
    transplanted.shares.insert((0, 0), position_one);
    assert!(matches!(
        decode_error(&manifest, transplanted),
        ArtifactError::InsufficientShares {
            stripe: 0,
            valid: 7
        },
    ));

    let mut duplicates = DuplicateSource {
        share: complete.shares.get(&(0, 0)).unwrap().clone(),
    };
    assert!(matches!(
        ArtifactDecoderV1::new()
            .unwrap()
            .decode(&manifest, &mut duplicates, &mut std::io::sink()),
        Err(ArtifactError::InsufficientShares {
            stripe: 0,
            valid: 1
        }),
    ));
}

#[test]
fn nonzero_final_padding_is_rejected_after_valid_rs_reconstruction() {
    let original = bytes(73);
    let mut store = MemoryArtifact::default();
    let mut manifest = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(original), &mut store, 9)
        .unwrap();
    let mut shards = (0..ARTIFACT_POSITIONS)
        .map(|position| store.shares.get(&(0, position as u8)).unwrap().clone())
        .collect::<Vec<_>>();
    shards[0][73] = 1;
    ReedSolomon::new(ARTIFACT_DATA_POSITIONS, ARTIFACT_PARITY_POSITIONS)
        .unwrap()
        .encode(&mut shards)
        .unwrap();

    let mut content = blake3::Hasher::new();
    content.update(b"NOOS/WWM/ARTIFACT/STRIPE/V1");
    content.update(&(ARTIFACT_STRIPE_BYTES as u64).to_le_bytes());
    for shard in shards.iter().take(ARTIFACT_DATA_POSITIONS) {
        content.update(shard);
    }
    manifest.stripes[0].descriptor.content_root = *content.finalize().as_bytes();
    for (position, shard) in shards.iter().enumerate() {
        store.shares.insert((0, position as u8), shard.clone());
        manifest.stripes[0].shares[position] = share_commitment(0, position as u8, shard).unwrap();
        let commitment = manifest.stripes[0].shares[position];
        manifest.position_roots[position] = test_domain_hash(
            b"NOOS/WWM/ARTIFACT/POSITION-LEAF/V1",
            &[
                &0_u32.to_le_bytes(),
                &[position as u8],
                commitment.share_digest.as_bytes(),
                commitment.probe_root.as_bytes(),
            ],
        );
    }
    manifest.validate().unwrap();
    assert!(matches!(
        ArtifactDecoderV1::new()
            .unwrap()
            .decode(&manifest, &mut store, &mut std::io::sink()),
        Err(ArtifactError::NonZeroFinalPadding),
    ));
}

#[test]
fn checkpoint_restart_rederives_rows_and_finishes_deterministically() {
    let original = bytes(ARTIFACT_STRIPE_BYTES + 17);
    let mut interrupted = MemoryArtifact {
        fail_checkpoint: Some(0),
        ..MemoryArtifact::default()
    };
    assert!(matches!(
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut Cursor::new(&original), &mut interrupted, 9),
        Err(ArtifactError::Sink(_)),
    ));
    assert_eq!(interrupted.checkpoint_rows.len(), 1);
    let (source_length, protocol_payload_root, published_sha256, stripe_count) =
        interrupted.identity.unwrap();
    assert_eq!(stripe_count, 2);
    let checkpoint = ArtifactEncodeCheckpointV1 {
        source_length,
        protocol_payload_root,
        published_sha256,
        retention_epochs: 9,
        stripes: interrupted.checkpoint_rows.clone(),
    };

    interrupted.fail_checkpoint = None;
    let resumed = ArtifactEncoderV1::new()
        .unwrap()
        .encode_resume(
            &mut Cursor::new(&original),
            &mut interrupted,
            9,
            Some(&checkpoint),
        )
        .unwrap();
    assert_eq!(interrupted.manifest.as_ref(), Some(&resumed));
    assert_eq!(resumed.stripes.len(), 2);

    let mut fresh_store = MemoryArtifact::default();
    let fresh = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(&original), &mut fresh_store, 9)
        .unwrap();
    assert_eq!(resumed, fresh);
    assert_eq!(interrupted.shares, fresh_store.shares);

    let mut corrupt_checkpoint = checkpoint;
    corrupt_checkpoint.stripes[0].shares[0].share_digest = Hash32::ZERO;
    assert!(ArtifactEncoderV1::new()
        .unwrap()
        .encode_resume(
            &mut Cursor::new(&original),
            &mut MemoryArtifact::default(),
            9,
            Some(&corrupt_checkpoint),
        )
        .is_err());
}

#[test]
fn source_mutation_between_passes_is_rejected_without_publication() {
    let first = bytes(8_193);
    let mut second = first.clone();
    second[4_096] ^= 1;
    let mut source = MutatingSource::new(first, second);
    let mut store = MemoryArtifact::default();
    assert!(matches!(
        ArtifactEncoderV1::new()
            .unwrap()
            .encode(&mut source, &mut store, 9),
        Err(ArtifactError::SourceLengthChanged),
    ));
    assert!(store.manifest.is_none());
}

#[test]
fn deterministic_roots_and_stripe_bounded_io_shape() {
    let original = bytes(ARTIFACT_STRIPE_BYTES + 1);
    let mut source = TrackingReader::new(original.clone());
    let mut first_store = MemoryArtifact::default();
    let first = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut source, &mut first_store, 9)
        .unwrap();
    assert!(source.max_request <= ARTIFACT_SHARE_BYTES);
    assert_eq!(first_store.max_staged_bytes, ARTIFACT_SHARE_BYTES);
    assert_eq!(first_store.stage_calls.len(), ARTIFACT_POSITIONS * 2);
    assert!(ARTIFACT_CODEC_WORKING_SET_BYTES < 14 * 1024 * 1024);

    let mut second_store = MemoryArtifact::default();
    let second = ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut Cursor::new(original), &mut second_store, 9)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first_store.shares, second_store.shares);
    assert_eq!(
        hex::encode(first.manifest_root().as_bytes()),
        "23ef4729ce363a93e34ef6de6fa3da0021bc087af122c724ef7aeec3a2368ca7",
    );

    ArtifactDecoderV1::new()
        .unwrap()
        .decode(&first, &mut first_store, &mut std::io::sink())
        .unwrap();
    assert_eq!(first_store.max_read_request, ARTIFACT_SHARE_BYTES);
}
