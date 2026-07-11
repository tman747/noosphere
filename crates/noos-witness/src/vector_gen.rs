//! Deterministic conformance-vector construction for
//! `protocol/vectors/witness/`.
//!
//! Shared by `bin/gen_vectors.rs` (writes the JSON) and the crate tests
//! (which re-derive and execute every case), so the frozen vectors can
//! never drift from the implementation. The braid pattern, verbatim.
//!
//! Case-byte layouts, per schema:
//!
//! - `noos-witness/bond-v1`: bytes are a canonical `BondRegistrationV1`.
//!   Positive: decode + `validate_registration` pass. Negative: decode or
//!   validity fails with `error_class`.
//! - `noos-witness/vote-v1`: bytes are a canonical `FinalityVoteV1`.
//!   Positive: decode, signature and the §1.2 law pass against the fixture
//!   snapshot. Negative: fails with `error_class`.
//! - `noos-witness/threshold-v1`: bytes are `W (u128 LE) || Q (u128 LE)`.
//!   Positive: `quorum_threshold(W) == Q`. The `naive_ceil` extra pins the
//!   rounded-two-thirds value; `naive_differs` marks the `3 | W` cases
//!   where the exact law and the naive ceiling disagree.
//! - `noos-witness/membership-v1`: bytes are a `u32`-prefixed list of
//!   canonical `WitnessBondV1`. The case carries `epoch`, `randomness`,
//!   `min_bond`, and the expected `outcome` (plus `membership_root` when
//!   normal); execution re-runs `build_snapshot`.
//! - `noos-witness/certificate-v1`: bytes are a canonical
//!   `FinalityCertificateV1`, verified against the epoch-1 fixture
//!   snapshot (tamper matrix: bitmap flip, sum inflation, wrong root,
//!   wrong DST, subset signature, ...).
//! - `noos-witness/beacon-v1`: commit digests, reveal hashes, and full mix
//!   transcripts (`prev_digest || reveal_i ...`) with withheld-member
//!   substitution, against the epoch-1 fixture snapshot.
//! - `noos-witness/slashing-v1`: bytes are a canonical
//!   `SlashingEvidenceV1`, executed through `verify_evidence` with the
//!   fixture recheck (`body_ref[0] = 0xAA` unavailable / `0xBB` diverged /
//!   else match) at the case's `current_epoch`.

// Generator/test-support code, never a consensus path.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use noos_braid::{Bytes48, Bytes96, CheckpointRef, FinalityCertificateV1};
use noos_codec::{CodecError, NoosEncode, Writer};
use noos_crypto::{bls_aggregate, bls_pop_prove, BlsSecretKey, DomainId, Keypair};
use noos_lumen::objects::BoundedBytes;

use crate::beacon::{commit_digest, reveal_hash, BeaconCommitV1, BeaconRevealV1, BeaconState};
use crate::bond::{BondRegistrationV1, Bytes64, WitnessBondV1};
use crate::finality::{build_certificate, quorum_threshold};
use crate::membership::{build_snapshot, MembershipSnapshotV1, SnapshotOutcome};
use crate::slashing::{DivergenceWitnessV1, RecheckOutcome, SlashingEvidenceV1, TransitionRecheck};
use crate::vote::{CheckpointView, FinalityVoteV1};
use crate::WitnessError;

// ---------------------------------------------------------------------------
// Case plumbing (braid pattern)
// ---------------------------------------------------------------------------

/// One conformance case.
pub struct Case {
    pub name: String,
    pub kind: &'static str,
    pub bytes: Vec<u8>,
    /// Extra `"field": "hex"` pairs.
    pub extras: Vec<(&'static str, Vec<u8>)>,
    /// Extra `"field": "literal"` string pairs.
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

fn negative_codec(name: &str, bytes: Vec<u8>, err: CodecError, note: &str) -> Case {
    let mut c = case(name, "negative", bytes, note);
    c.error_class = Some(err.class_name());
    c
}

fn negative_witness(name: &str, bytes: Vec<u8>, err: &WitnessError, note: &str) -> Case {
    let mut c = case(name, "negative", bytes, note);
    c.error_class = Some(err.class_name());
    c
}

// ---------------------------------------------------------------------------
// Fixtures (shared with the crate tests)
// ---------------------------------------------------------------------------

/// Fixture weights: W = 100, `Q = floor(200/3)+1 = 67`, no key at or above
/// `ceil(100/3) = 34` (the §2.5 cap), and the minimum quorum is three
/// signers (30 + 28 + 22 = 80).
pub const FIXTURE_WEIGHTS: &[u128] = &[30, 28, 22, 20];

/// The devnet-fixture chain id used by every witness vector.
#[must_use]
pub fn fixture_chain_id() -> [u8; 32] {
    [0xC7; 32]
}

/// Deterministic fixture BLS secret for canonical member index `i`.
#[must_use]
pub fn fixture_secret(i: usize) -> BlsSecretKey {
    BlsSecretKey::from_seed([(i as u8) + 1; 32]).unwrap()
}

/// Deterministic fixture Ed25519 withdrawal keypair for member `i`.
#[must_use]
pub fn fixture_withdrawal(i: usize) -> Keypair {
    Keypair::from_seed([(i as u8) + 0x81; 32])
}

/// Fixture bonds: `validator_id = [i+1; 32]` (so canonical ascending order
/// equals index order), real BLS consensus keys, real Ed25519 withdrawal
/// keys.
#[must_use]
pub fn fixture_bonds(weights: &[u128]) -> Vec<WitnessBondV1> {
    weights
        .iter()
        .enumerate()
        .map(|(i, w)| WitnessBondV1 {
            validator_id: [(i as u8) + 1; 32],
            consensus_bls_key: Bytes48(fixture_secret(i).public_key().into_bytes()),
            withdrawal_key: fixture_withdrawal(i).public_key().into_bytes(),
            network_endpoints_commitment: [0x11; 32],
            failure_domains: BoundedBytes::new(vec![b'c', i as u8]).unwrap(),
            bonded_noos: *w,
            activation_epoch: 0,
            exit_epoch: 0,
            proofpower_account: [0x22; 32],
        })
        .collect()
}

/// The fixture randomness feeding reserve sampling.
#[must_use]
pub fn fixture_randomness() -> [u8; 32] {
    [0x5A; 32]
}

/// A NORMAL fixture snapshot for `epoch` over `weights`.
#[must_use]
pub fn fixture_snapshot(epoch: u64, weights: &[u128]) -> MembershipSnapshotV1 {
    match build_snapshot(
        epoch,
        &fixture_bonds(weights),
        &fixture_randomness(),
        1,
        None,
        false,
    )
    .unwrap()
    {
        SnapshotOutcome::Normal(s) => s,
        other => panic!("fixture weights must yield a normal snapshot, got {other:?}"),
    }
}

/// A signed fixture vote by canonical member `i`.
#[must_use]
pub fn fixture_vote(
    snapshot: &MembershipSnapshotV1,
    i: usize,
    source: CheckpointRef,
    target: CheckpointRef,
) -> FinalityVoteV1 {
    FinalityVoteV1::sign(
        fixture_chain_id(),
        target.epoch,
        source,
        target,
        snapshot.members()[i].validator_id,
        snapshot.root(),
        &fixture_secret(i),
    )
    .unwrap()
}

/// Checkpoint-view fixture: justifies everything (or nothing), with an
/// optional denied descent edge.
#[derive(Clone, Debug)]
pub struct FixtureView {
    pub justify_all: bool,
    pub justified: BTreeSet<CheckpointRef>,
    pub deny_descent: Option<(CheckpointRef, CheckpointRef)>,
}

impl Default for FixtureView {
    fn default() -> Self {
        Self {
            justify_all: true,
            justified: BTreeSet::new(),
            deny_descent: None,
        }
    }
}

impl FixtureView {
    /// A view in which nothing is justified.
    #[must_use]
    pub fn nothing_justified() -> Self {
        Self {
            justify_all: false,
            justified: BTreeSet::new(),
            deny_descent: None,
        }
    }

    /// The default view minus one descent edge.
    #[must_use]
    pub fn deny(source: CheckpointRef, target: CheckpointRef) -> Self {
        Self {
            deny_descent: Some((source, target)),
            ..Self::default()
        }
    }
}

impl CheckpointView for FixtureView {
    fn is_justified(&self, checkpoint: &CheckpointRef) -> bool {
        self.justify_all || self.justified.contains(checkpoint)
    }
    fn descends(&self, source: &CheckpointRef, target: &CheckpointRef) -> bool {
        self.deny_descent != Some((*source, *target))
    }
}

/// Deterministic re-execution fixture: `body_ref[0]` selects the outcome —
/// `0xAA` unavailable, `0xBB` diverged (with [`fixture_divergence`]),
/// anything else matches.
pub struct FixtureRecheck;

impl TransitionRecheck for FixtureRecheck {
    fn recheck(&self, body_ref: &[u8; 32], _vote: &FinalityVoteV1) -> RecheckOutcome {
        match body_ref[0] {
            0xAA => RecheckOutcome::Unavailable,
            0xBB => RecheckOutcome::Diverged(fixture_divergence()),
            _ => RecheckOutcome::Match,
        }
    }
}

/// The divergence the fixture recheck reports for `body_ref[0] = 0xBB`.
#[must_use]
pub fn fixture_divergence() -> DivergenceWitnessV1 {
    DivergenceWitnessV1 {
        claimed_state_root: [0x01; 32],
        recomputed_state_root: [0x02; 32],
        claimed_receipt_root: [0x03; 32],
        recomputed_receipt_root: [0x03; 32],
    }
}

fn checkpoint(epoch: u64, seed: u8) -> CheckpointRef {
    CheckpointRef {
        epoch,
        checkpoint_hash: [seed; 32],
    }
}

/// The fixture source (genesis) and epoch-1 target used by vote and
/// certificate vectors.
#[must_use]
pub fn fixture_source() -> CheckpointRef {
    checkpoint(0, 0xA0)
}

#[must_use]
pub fn fixture_target() -> CheckpointRef {
    checkpoint(1, 0xA1)
}

/// The quorum certificate over the epoch-1 fixture snapshot (signers
/// 0, 1, 2 — raw and effective 80 ≥ 67).
#[must_use]
pub fn fixture_certificate() -> FinalityCertificateV1 {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let votes: Vec<FinalityVoteV1> = (0..3)
        .map(|i| fixture_vote(&snap, i, fixture_source(), fixture_target()))
        .collect();
    build_certificate(&votes, &fixture_chain_id(), &snap).unwrap()
}

// ---------------------------------------------------------------------------
// bond-v1
// ---------------------------------------------------------------------------

/// A fully signed fixture registration for member `i`.
#[must_use]
pub fn fixture_registration(i: usize) -> BondRegistrationV1 {
    let bond = fixture_bonds(FIXTURE_WEIGHTS)[i].clone();
    let pop = bls_pop_prove(&fixture_secret(i)).unwrap();
    let sig = fixture_withdrawal(i)
        .sign_domain(DomainId::SigTx, &[&bond.encode_canonical()])
        .unwrap();
    BondRegistrationV1 {
        bond,
        bls_possession_proof: Bytes96(pop.into_bytes()),
        withdrawal_self_signature: Bytes64(sig.into_bytes()),
    }
}

fn bond_file() -> VectorFile {
    let mut cases = Vec::new();

    let reg = fixture_registration(0);
    cases.push(positive(
        "registration-valid",
        reg.encode_canonical(),
        "nine-field bond, BLS proof of possession under D-BLS-POP, Ed25519 self-signature under NOOS/SIG/TX/V1",
    ));
    cases.push(positive(
        "registration-valid-second-member",
        fixture_registration(1).encode_canonical(),
        "independent keys per member; canonical roundtrip",
    ));

    let mut overlap = fixture_registration(2);
    let wk = overlap.bond.withdrawal_key;
    overlap.bond.consensus_bls_key.0[8..40].copy_from_slice(&wk);
    cases.push(negative_witness(
        "registration-key-material-overlap",
        overlap.encode_canonical(),
        &WitnessError::KeyMaterialOverlap,
        "withdrawal key embedded at offset 8 of the consensus key: distinct-keys law",
    ));

    let mut bad_pop = fixture_registration(0);
    bad_pop.bls_possession_proof.0[5] ^= 0x40;
    cases.push(negative_witness(
        "registration-pop-invalid",
        bad_pop.encode_canonical(),
        &WitnessError::PossessionProofInvalid,
        "flipped bit in the BLS proof of possession",
    ));

    let mut tampered = fixture_registration(0);
    tampered.bond.bonded_noos += 1;
    cases.push(negative_witness(
        "registration-self-signature-broken",
        tampered.encode_canonical(),
        &WitnessError::SelfSignatureInvalid,
        "bond mutated after the withdrawal key signed it",
    ));

    let valid_bytes = reg.encode_canonical();
    cases.push(negative_codec(
        "registration-truncated",
        valid_bytes[..valid_bytes.len() - 3].to_vec(),
        CodecError::Truncated,
        "canonical bytes cut short",
    ));
    let mut trailing = valid_bytes.clone();
    trailing.push(0x00);
    cases.push(negative_codec(
        "registration-trailing-byte",
        trailing,
        CodecError::TrailingBytes,
        "decode must consume the whole input",
    ));

    VectorFile {
        schema: "noos-witness/bond-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// vote-v1
// ---------------------------------------------------------------------------

fn vote_file() -> VectorFile {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let vote = fixture_vote(&snap, 0, fixture_source(), fixture_target());
    let mut cases = Vec::new();

    let mut ok = positive(
        "vote-valid",
        vote.encode_canonical(),
        "signed under the registered vote DST over canonical fields 0-5; passes the full 1.2 law",
    );
    ok.extras
        .push(("signer_key", snap.members()[0].consensus_bls_key.0.to_vec()));
    ok.extras.push(("signing_bytes", vote.signing_bytes()));
    cases.push(ok);

    let mut bad_sig = vote.clone();
    bad_sig.signature.0[7] ^= 0x02;
    cases.push(negative_witness(
        "vote-signature-flipped",
        bad_sig.encode_canonical(),
        &WitnessError::SignatureInvalid,
        "one flipped signature bit",
    ));

    let mut wrong_root = vote.clone();
    wrong_root.membership_root = [0x77; 32];
    // Re-sign so ONLY the root binding fails.
    let resigned = FinalityVoteV1::sign(
        wrong_root.chain_id,
        wrong_root.epoch,
        wrong_root.source,
        wrong_root.target,
        wrong_root.validator_id,
        wrong_root.membership_root,
        &fixture_secret(0),
    )
    .unwrap();
    cases.push(negative_witness(
        "vote-wrong-membership-root",
        resigned.encode_canonical(),
        &WitnessError::MembershipRootMismatch,
        "membership_root must equal the snapshotted Ring for the epoch",
    ));

    let stranger = FinalityVoteV1::sign(
        fixture_chain_id(),
        1,
        fixture_source(),
        fixture_target(),
        [0xFE; 32],
        snap.root(),
        &fixture_secret(9),
    )
    .unwrap();
    cases.push(negative_witness(
        "vote-unknown-validator",
        stranger.encode_canonical(),
        &WitnessError::UnknownValidator,
        "voter not in the epoch snapshot",
    ));

    let bytes = vote.encode_canonical();
    cases.push(negative_codec(
        "vote-truncated",
        bytes[..40].to_vec(),
        CodecError::Truncated,
        "cut inside the source checkpoint",
    ));
    let mut wrong_tag = bytes;
    wrong_tag[2] = 0x09; // first field tag 1 -> 9
    cases.push(negative_codec(
        "vote-wrong-tag-order",
        wrong_tag,
        CodecError::UnknownMandatoryField,
        "mandatory tags must appear in exact declaration order",
    ));

    VectorFile {
        schema: "noos-witness/vote-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// threshold-v1
// ---------------------------------------------------------------------------

fn threshold_case(w: u128, note: &str) -> Case {
    let q = quorum_threshold(w);
    let naive_ceil = (2 * w).div_ceil(3); // overflows above u128::MAX/2; callers keep w below
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&w.to_le_bytes());
    bytes.extend_from_slice(&q.to_le_bytes());
    let mut c = positive(&format!("threshold-w-{w}"), bytes, note);
    c.extras_str.push(("naive_ceil", naive_ceil.to_string()));
    c.extras_str
        .push(("naive_differs", (naive_ceil != q).to_string()));
    c
}

fn threshold_file() -> VectorFile {
    let mut cases = Vec::new();
    // Boundary triplets W = 3k / 3k+1 / 3k+2 around small and large k,
    // pinning exactly where floor(2W/3)+1 and the naive ceil diverge
    // (every W divisible by 3).
    for w in [0_u128, 1, 2, 3, 4, 5, 6, 7, 8, 66, 67, 68, 99, 100, 101] {
        cases.push(threshold_case(
            w,
            if w % 3 == 0 {
                "3 | W: exact Q = floor(2W/3)+1 EXCEEDS the naive ceil(2W/3) by one"
            } else {
                "3 does not divide W: exact Q equals the naive ceiling"
            },
        ));
    }
    cases.push(threshold_case(
        3_000_000_000_000_000_000,
        "large 3k boundary: naive rounding still differs by one",
    ));
    cases.push(threshold_case(
        3_000_000_000_000_000_001,
        "large 3k+1 boundary",
    ));
    cases.push(threshold_case(
        3_000_000_000_000_000_002,
        "large 3k+2 boundary",
    ));

    // u128::MAX = 3k+0? MAX % 3 == 0: (2^128 - 1) % 3 = 0. Exercise the
    // overflow-free path without the naive-ceil extra (2W would overflow).
    let w = u128::MAX;
    let q = quorum_threshold(w);
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&w.to_le_bytes());
    bytes.extend_from_slice(&q.to_le_bytes());
    let mut c = positive(
        "threshold-w-u128-max",
        bytes,
        "3 | u128::MAX; Q computed overflow-free as 2*(W/3) + 1",
    );
    c.extras_str.push(("naive_differs", "true".to_string()));
    cases.push(c);

    VectorFile {
        schema: "noos-witness/threshold-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// membership-v1
// ---------------------------------------------------------------------------

fn encode_bonds(bonds: &[WitnessBondV1]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_list(bonds, u32::MAX);
    w.into_bytes()
}

fn membership_case(
    name: &str,
    bonds: &[WitnessBondV1],
    epoch: u64,
    min_bond: u128,
    note: &str,
) -> Case {
    let outcome =
        build_snapshot(epoch, bonds, &fixture_randomness(), min_bond, None, false).unwrap();
    let mut c = positive(name, encode_bonds(bonds), note);
    c.extras.push(("randomness", fixture_randomness().to_vec()));
    c.extras_str.push(("epoch", epoch.to_string()));
    c.extras_str.push(("min_bond", min_bond.to_string()));
    match outcome {
        SnapshotOutcome::Normal(s) => {
            c.extras_str.push(("outcome", "normal".to_string()));
            c.extras_str.push(("member_count", s.len().to_string()));
            c.extras.push(("membership_root", s.root().to_vec()));
        }
        SnapshotOutcome::EmergencyContinuation(_) => {
            c.extras_str.push(("outcome", "emergency".to_string()));
        }
        SnapshotOutcome::Halt => {
            c.extras_str.push(("outcome", "halt".to_string()));
        }
    }
    c
}

/// A synthetic bond whose consensus key is derived from the id (membership
/// selection never checks BLS validity; registration vectors do).
fn synthetic_bond(vid: [u8; 32], weight: u128) -> WitnessBondV1 {
    let mut key = [0_u8; 48];
    key[..32].copy_from_slice(&vid);
    key[32] = 0x4B;
    WitnessBondV1 {
        validator_id: vid,
        consensus_bls_key: Bytes48(key),
        withdrawal_key: [0xD0; 32],
        network_endpoints_commitment: [0x11; 32],
        failure_domains: BoundedBytes::new(vec![]).unwrap(),
        bonded_noos: weight,
        activation_epoch: 0,
        exit_epoch: 0,
        proofpower_account: [0x22; 32],
    }
}

/// `count` equal-weight synthetic bonds with distinct ids.
#[must_use]
pub fn synthetic_flock(count: u32, weight: u128, tag: u8) -> Vec<WitnessBondV1> {
    (0..count)
        .map(|i| {
            let mut vid = [0_u8; 32];
            vid[0] = tag;
            vid[1] = (i / 256) as u8;
            vid[2] = (i % 256) as u8;
            synthetic_bond(vid, weight)
        })
        .collect()
}

fn membership_file() -> VectorFile {
    let mut cases = Vec::new();

    cases.push(membership_case(
        "membership-fixture-four",
        &fixture_bonds(FIXTURE_WEIGHTS),
        1,
        1,
        "the standard four-member fixture snapshot; root binds key and both weights per member",
    ));

    // Equal weights beyond N_max: the epoch-salted tiebreak decides the cut.
    let flock = synthetic_flock(300, 1_000_000, 0x01);
    cases.push(membership_case(
        "membership-tiebreak-cut-at-256",
        &flock,
        5,
        1,
        "300 equal-weight candidates: exactly the 256 with the smallest NOOS/WITNESS/TIEBREAK/V1 hashes are active",
    ));

    // Min-bond and activity filters.
    let mut filtered = fixture_bonds(FIXTURE_WEIGHTS);
    filtered[3].bonded_noos = 5; // below min bond 10
    let mut inactive = synthetic_bond([0x60; 32], 50);
    inactive.activation_epoch = 9;
    filtered.push(inactive);
    cases.push(membership_case(
        "membership-eligibility-filters",
        &filtered,
        1,
        10,
        "below-minimum bond and not-yet-active candidates are excluded before selection",
    ));

    // Whale that admission repairs: active set violates the cap, sampled
    // admission dilutes it below one third.
    let mut repair = vec![synthetic_bond([0xEE; 32], 3_000_000)];
    repair.extend(synthetic_flock(400, 20_000, 0x02));
    cases.push(membership_case(
        "membership-cap-repair-by-admission",
        &repair,
        1,
        1,
        "one 3e6 whale over 400 x 20k: the top-256 set violates the one-third cap; reserve admission in sample order repairs it",
    ));

    // Unrepairable: single whale, nothing to admit, no previous set: HALT.
    cases.push(membership_case(
        "membership-unrepairable-halts",
        &[synthetic_bond([0xEF; 32], 1_000_000)],
        1,
        1,
        "a single candidate always holds 100% >= one third; with no previous set the ring HALTS (never normalizes an unsafe set)",
    ));

    VectorFile {
        schema: "noos-witness/membership-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// certificate-v1
// ---------------------------------------------------------------------------

fn certificate_file() -> VectorFile {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let cert = fixture_certificate();
    let votes: Vec<FinalityVoteV1> = (0..3)
        .map(|i| fixture_vote(&snap, i, fixture_source(), fixture_target()))
        .collect();
    let mut cases = Vec::new();

    let mut ok = positive(
        "certificate-valid",
        cert.encode_canonical(),
        "signers 0,1,2 (80/100 raw and effective, both >= Q=67); verified by recomputing both sums from the snapshot",
    );
    ok.extras.push((
        "digest",
        crate::finality::certificate_digest(&cert).unwrap().to_vec(),
    ));
    ok.extras.push(("membership_root", snap.root().to_vec()));
    cases.push(ok);

    // Tamper matrix.
    let mut flipped = cert.clone();
    let mut bm = flipped.participation_bitmap.as_slice().to_vec();
    bm[0] ^= 0b1000; // add member 3
    flipped.participation_bitmap = BoundedBytes::new(bm).unwrap();
    cases.push(negative_witness(
        "certificate-bitmap-bit-flip",
        flipped.encode_canonical(),
        &WitnessError::WeightSumMismatch,
        "bitmap adds member 3: recomputed sums (100) disagree with carried sums (80)",
    ));

    let mut forged = cert.clone();
    let mut bm = forged.participation_bitmap.as_slice().to_vec();
    bm[0] ^= 0b1000;
    forged.participation_bitmap = BoundedBytes::new(bm).unwrap();
    forged.raw_weight_sum = 100;
    forged.effective_weight_sum = 100;
    cases.push(negative_witness(
        "certificate-bitmap-flip-with-matching-sums",
        forged.encode_canonical(),
        &WitnessError::AggregateInvalid,
        "bitmap and sums forged together: the aggregate does not cover member 3's vote body",
    ));

    let mut inflated = cert.clone();
    inflated.raw_weight_sum = 100;
    cases.push(negative_witness(
        "certificate-raw-sum-inflated",
        inflated.encode_canonical(),
        &WitnessError::WeightSumMismatch,
        "carried raw sum is never trusted: recomputation wins",
    ));

    let mut inflated_eff = cert.clone();
    inflated_eff.effective_weight_sum = 99;
    cases.push(negative_witness(
        "certificate-effective-sum-inflated",
        inflated_eff.encode_canonical(),
        &WitnessError::WeightSumMismatch,
        "carried effective sum is never trusted",
    ));

    let mut wrong_root = cert.clone();
    wrong_root.membership_root = [0x66; 32];
    cases.push(negative_witness(
        "certificate-wrong-membership-root",
        wrong_root.encode_canonical(),
        &WitnessError::MembershipRootMismatch,
        "certificate bound to a different Ring",
    ));

    let mut wrong_dst = cert.clone();
    let cert_dst_sigs: Vec<_> = (0..3)
        .map(|i| {
            fixture_secret(i)
                .sign_domain(DomainId::BlsCert, &votes[i].signing_bytes())
                .unwrap()
        })
        .collect();
    wrong_dst.aggregate_signature = Bytes96(bls_aggregate(&cert_dst_sigs).unwrap().into_bytes());
    cases.push(negative_witness(
        "certificate-wrong-dst",
        wrong_dst.encode_canonical(),
        &WitnessError::AggregateInvalid,
        "same bodies signed under NOOS-BLS-CERT instead of the registered vote DST",
    ));

    let mut subset = cert.clone();
    let two_sigs: Vec<_> = (0..2)
        .map(|i| noos_crypto::BlsSignature::from_bytes(votes[i].signature.0))
        .collect();
    subset.aggregate_signature = Bytes96(bls_aggregate(&two_sigs).unwrap().into_bytes());
    cases.push(negative_witness(
        "certificate-subset-signature",
        subset.encode_canonical(),
        &WitnessError::AggregateInvalid,
        "bitmap claims signers 0,1,2 but the aggregate carries only 0,1",
    ));

    let mut empty = cert.clone();
    empty.participation_bitmap = BoundedBytes::new(vec![0x00]).unwrap();
    empty.raw_weight_sum = 0;
    empty.effective_weight_sum = 0;
    cases.push(negative_witness(
        "certificate-empty-signer-set",
        empty.encode_canonical(),
        &WitnessError::EmptySignerSet,
        "an all-zero bitmap selects nobody",
    ));

    let mut oob = cert.clone();
    oob.participation_bitmap = BoundedBytes::new(vec![0b0001_0111]).unwrap();
    cases.push(negative_witness(
        "certificate-bitmap-out-of-range",
        oob.encode_canonical(),
        &WitnessError::BitmapOutOfRange,
        "bit 4 set with only 4 members",
    ));

    let bytes = cert.encode_canonical();
    cases.push(negative_codec(
        "certificate-truncated",
        bytes[..bytes.len() - 10].to_vec(),
        CodecError::Truncated,
        "cut inside the membership root",
    ));

    VectorFile {
        schema: "noos-witness/certificate-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// beacon-v1
// ---------------------------------------------------------------------------

/// The four fixture reveals (member `i` reveals `[0x10 + i; 32]`).
#[must_use]
pub fn fixture_reveals() -> Vec<[u8; 32]> {
    (0..4_u8).map(|i| [0x10 + i; 32]).collect()
}

/// Runs the fixture beacon to a mix with the given withheld member set.
#[must_use]
pub fn fixture_mix(withheld: &[usize], prev: &[u8; 32]) -> crate::beacon::SealedRandomness {
    struct NullBarrier;
    impl crate::beacon::DurabilityBarrier for NullBarrier {
        fn persist(
            &mut self,
            _record: &crate::beacon::BeaconSafetyRecordV1,
        ) -> Result<(), crate::beacon::BarrierError> {
            Ok(())
        }
    }
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let reveals = fixture_reveals();
    let mut state = BeaconState::new(fixture_chain_id(), &snap);
    let mut barrier = NullBarrier;
    for (i, member) in snap.members().iter().enumerate() {
        state
            .local_commit(
                &mut barrier,
                member.validator_id,
                reveal_hash(&reveals[i]).unwrap(),
                0,
            )
            .unwrap();
    }
    state.finalize_commits().unwrap();
    for (i, member) in snap.members().iter().enumerate() {
        if !withheld.contains(&i) {
            state
                .local_reveal(&mut barrier, member.validator_id, reveals[i])
                .unwrap();
        }
    }
    state.compute_mix(prev).unwrap()
}

fn beacon_file() -> VectorFile {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let reveals = fixture_reveals();
    let prev = [0x55; 32];
    let mut cases = Vec::new();

    // Reveal hash vector.
    let mut rh = positive(
        "beacon-reveal-hash",
        reveals[0].to_vec(),
        "committed_hash = H(NOOS/BEACON/REVEAL/V1 || reveal)",
    );
    rh.extras
        .push(("reveal_hash", reveal_hash(&reveals[0]).unwrap().to_vec()));
    cases.push(rh);

    // Commit message + digest vector.
    let commit = BeaconCommitV1 {
        chain_id: fixture_chain_id(),
        epoch: 1,
        membership_root: snap.root(),
        validator_id: snap.members()[0].validator_id,
        reveal_hash: reveal_hash(&reveals[0]).unwrap(),
    };
    let digest = commit_digest(
        &commit.chain_id,
        commit.epoch,
        &commit.membership_root,
        &commit.validator_id,
        &commit.reveal_hash,
    )
    .unwrap();
    let mut cm = positive(
        "beacon-commit-digest",
        commit.encode_canonical(),
        "c_i = H(NOOS/BEACON/COMMIT/V1 || chain || epoch_le || membership_root || validator || reveal_hash)",
    );
    cm.extras.push(("commit_digest", digest.to_vec()));
    cases.push(cm);

    // Mix transcripts: bytes = prev_digest || reveal_0..reveal_3.
    let transcript_bytes = |reveals: &[[u8; 32]]| {
        let mut b = prev.to_vec();
        for r in reveals {
            b.extend_from_slice(r);
        }
        b
    };
    let full = fixture_mix(&[], &prev);
    let mut all = positive(
        "beacon-mix-all-revealed",
        transcript_bytes(&reveals),
        "all four members revealed; bitmap 0b1111",
    );
    all.extras
        .push(("randomness", full.raw_for_vectors().to_vec()));
    all.extras
        .push(("bitmap", full.contribution_bitmap.clone()));
    all.extras_str.push(("withheld_index", "none".to_string()));
    cases.push(all);

    let withheld = fixture_mix(&[2], &prev);
    let mut wh = positive(
        "beacon-mix-member-2-withheld",
        transcript_bytes(&reveals),
        "member 2 committed but withheld: m_2 is its already-committed hash, bitmap 0b1011, and the member is penalty-listed",
    );
    wh.extras
        .push(("randomness", withheld.raw_for_vectors().to_vec()));
    wh.extras
        .push(("bitmap", withheld.contribution_bitmap.clone()));
    wh.extras_str.push(("withheld_index", "2".to_string()));
    cases.push(wh);

    // Post-cutoff commit rejects.
    let mut late = negative_witness(
        "beacon-commit-post-cutoff",
        commit.encode_canonical(),
        &WitnessError::PostCutoffCommit,
        "commit at slot offset 192 (the frozen cutoff) rejects",
    );
    late.extras_str.push((
        "slot_in_epoch",
        crate::BEACON_COMMIT_CUTOFF_SLOT_OFFSET.to_string(),
    ));
    cases.push(late);

    // Duplicate commit rejects.
    let mut dup = negative_witness(
        "beacon-commit-duplicate",
        commit.encode_canonical(),
        &WitnessError::DuplicateCommit,
        "the same witness cannot commit twice (exactly-one-commit law)",
    );
    dup.extras_str.push(("ingest_twice", "true".to_string()));
    cases.push(dup);

    // Mismatched reveal rejects.
    let bad_reveal = BeaconRevealV1 {
        chain_id: fixture_chain_id(),
        epoch: 1,
        membership_root: snap.root(),
        validator_id: snap.members()[0].validator_id,
        reveal: [0x99; 32],
    };
    cases.push(negative_witness(
        "beacon-reveal-mismatch",
        bad_reveal.encode_canonical(),
        &WitnessError::RevealMismatch,
        "reveal does not hash to the committed value",
    ));

    VectorFile {
        schema: "noos-witness/beacon-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// slashing-v1
// ---------------------------------------------------------------------------

fn slashing_file() -> VectorFile {
    let snap1 = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let snap2 = fixture_snapshot(2, FIXTURE_WEIGHTS);
    let snap3 = fixture_snapshot(3, FIXTURE_WEIGHTS);
    let mut cases = Vec::new();

    let with_epoch = |mut c: Case, current: u64| {
        c.extras_str.push(("current_epoch", current.to_string()));
        c
    };

    let double = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&snap1, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(&snap1, 0, checkpoint(0, 0xA0), checkpoint(1, 0xB1)),
    };
    cases.push(with_epoch(
        positive(
            "slashing-double-vote",
            double.encode_canonical(),
            "same target epoch, distinct targets, one validator: slashable; removal at the next epoch boundary",
        ),
        3,
    ));

    let surround = SlashingEvidenceV1::SurroundVote {
        outer: fixture_vote(&snap3, 1, checkpoint(0, 0xA0), checkpoint(3, 0xA3)),
        inner: fixture_vote(&snap2, 1, checkpoint(1, 0xA1), checkpoint(2, 0xA2)),
    };
    cases.push(with_epoch(
        positive(
            "slashing-surround-vote",
            surround.encode_canonical(),
            "outer [0,3] strictly surrounds inner [1,2] on both ends",
        ),
        3,
    ));

    let invalid = SlashingEvidenceV1::InvalidTransitionVote {
        vote: fixture_vote(&snap1, 2, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        body_ref: [0xBB; 32],
        divergence_proof: fixture_divergence(),
    };
    cases.push(with_epoch(
        positive(
            "slashing-invalid-transition",
            invalid.encode_canonical(),
            "complete body available AND deterministic re-execution diverges",
        ),
        3,
    ));

    let same_target = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&snap1, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(&snap1, 0, checkpoint(0, 0xB0), checkpoint(1, 0xA1)),
    };
    cases.push(with_epoch(
        negative_witness(
            "slashing-double-vote-same-target",
            same_target.encode_canonical(),
            &WitnessError::TargetsNotDistinct,
            "two votes for the SAME target are not a double vote",
        ),
        3,
    ));

    let not_surround = SlashingEvidenceV1::SurroundVote {
        outer: fixture_vote(&snap2, 1, checkpoint(1, 0xA1), checkpoint(2, 0xA2)),
        inner: fixture_vote(&snap3, 1, checkpoint(0, 0xA0), checkpoint(3, 0xA3)),
    };
    cases.push(with_epoch(
        negative_witness(
            "slashing-surround-mislabeled-direction",
            not_surround.encode_canonical(),
            &WitnessError::NotSurrounding,
            "the labeled outer interval lies INSIDE the labeled inner one: strict surround fails",
        ),
        3,
    ));

    let unavailable = SlashingEvidenceV1::InvalidTransitionVote {
        vote: fixture_vote(&snap1, 2, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        body_ref: [0xAA; 32],
        divergence_proof: fixture_divergence(),
    };
    cases.push(with_epoch(
        negative_witness(
            "slashing-unavailable-body-never-slashable",
            unavailable.encode_canonical(),
            &WitnessError::BodyUnavailable,
            "unavailability alone is NEVER slashable (ch01 4.8 rule 3)",
        ),
        3,
    ));

    let no_divergence = SlashingEvidenceV1::InvalidTransitionVote {
        vote: fixture_vote(&snap1, 2, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        body_ref: [0xCC; 32],
        divergence_proof: fixture_divergence(),
    };
    cases.push(with_epoch(
        negative_witness(
            "slashing-no-divergence",
            no_divergence.encode_canonical(),
            &WitnessError::NoDivergence,
            "re-execution matched the vote",
        ),
        3,
    ));

    cases.push(with_epoch(
        negative_witness(
            "slashing-evidence-expired",
            double.encode_canonical(),
            &WitnessError::EvidenceExpired,
            "offense epoch 1 evaluated at epoch 66 exceeds the 64-epoch testnet horizon",
        ),
        66,
    ));

    cases.push(negative_codec(
        "slashing-unknown-discriminant",
        3_u16.to_le_bytes().to_vec(),
        CodecError::UnknownDiscriminant,
        "offense classes are a closed declaration-order enum",
    ));

    VectorFile {
        schema: "noos-witness/slashing-v1",
        cases,
    }
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Every witness vector file, in emission order.
#[must_use]
pub fn files() -> Vec<(&'static str, VectorFile)> {
    vec![
        ("witness-bond-v1.json", bond_file()),
        ("witness-vote-v1.json", vote_file()),
        ("witness-threshold-v1.json", threshold_file()),
        ("witness-membership-v1.json", membership_file()),
        ("witness-certificate-v1.json", certificate_file()),
        ("witness-beacon-v1.json", beacon_file()),
        ("witness-slashing-v1.json", slashing_file()),
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
