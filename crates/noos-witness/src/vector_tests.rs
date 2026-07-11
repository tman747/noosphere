//! Conformance tests over `protocol/vectors/witness/*.json`.
//!
//! Two layers (the braid pattern):
//! 1. every generated case is executed against the implementation
//!    semantics of its schema, so the generator can never emit a wrong
//!    verdict; and
//! 2. the on-disk JSON must be byte-identical to the generator output, so
//!    the frozen vectors can never drift from the implementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::PathBuf;

use noos_braid::FinalityCertificateV1;
use noos_codec::{NoosDecode, NoosEncode, Reader};

use crate::beacon::{commit_digest, reveal_hash, BeaconCommitV1, BeaconRevealV1, BeaconState};
use crate::bond::{validate_registration, BondRegistrationV1, WitnessBondV1};
use crate::finality::{certificate_digest, quorum_threshold, verify_certificate, SnapshotRegistry};
use crate::membership::{build_snapshot, SnapshotOutcome};
use crate::params::WitnessParamsV1;
use crate::slashing::{verify_evidence, SlashingEvidenceV1};
use crate::vector_gen::{
    self, fixture_chain_id, fixture_mix, fixture_reveals, fixture_snapshot, Case, FixtureRecheck,
    FixtureView, FIXTURE_WEIGHTS,
};
use crate::vote::{validate_vote, FinalityVoteV1};
use crate::WitnessError;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("vectors")
        .join("witness")
}

fn extra<'a>(case: &'a Case, key: &str) -> &'a [u8] {
    case.extras
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_slice())
        .unwrap_or_else(|| panic!("case {} missing extra {key}", case.name))
}

fn extra_str<'a>(case: &'a Case, key: &str) -> &'a str {
    case.extras_str
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("case {} missing extra {key}", case.name))
}

fn has_extra_str(case: &Case, key: &str) -> bool {
    case.extras_str.iter().any(|(k, _)| *k == key)
}

fn arr<const N: usize>(bytes: &[u8]) -> [u8; N] {
    <[u8; N]>::try_from(bytes).unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

/// Runs a fallible pipeline against a case: positives must succeed,
/// negatives must fail with exactly `error_class`.
fn expect_verdict(case: &Case, result: Result<(), String>) {
    match (case.kind, result) {
        ("positive", Ok(())) => {}
        ("positive", Err(e)) => panic!("case {} must pass, failed with {e}", case.name),
        ("negative", Ok(())) => panic!("case {} must fail, passed", case.name),
        ("negative", Err(class)) => {
            assert_eq!(
                Some(class.as_str()),
                case.error_class,
                "case {} error class",
                case.name
            );
        }
        (kind, _) => panic!("unknown kind {kind}"),
    }
}

fn codec_class(e: noos_codec::CodecError) -> String {
    e.class_name().to_string()
}

fn witness_class(e: &WitnessError) -> String {
    e.class_name().to_string()
}

#[test]
fn on_disk_vectors_match_the_generator_exactly() {
    for (name, file) in vector_gen::files() {
        let path = vectors_dir().join(name);
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e} (run gen_vectors)", path.display()));
        let generated = vector_gen::render_json(&file);
        assert_eq!(
            on_disk, generated,
            "{name} drifted from the generator; regenerate with `cargo run -p noos-witness --bin gen_vectors`"
        );
    }
}

#[test]
fn bond_vectors_execute() {
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-bond-v1.json")
        .unwrap()
        .1
        .cases
    {
        let result = BondRegistrationV1::decode_canonical(&case.bytes)
            .map_err(codec_class)
            .and_then(|reg| {
                validate_registration(&reg).map_err(|e| witness_class(&e))?;
                // Positive registrations must also roundtrip byte-identically.
                if reg.encode_canonical() != case.bytes {
                    return Err("re-encode mismatch".to_string());
                }
                Ok(())
            });
        expect_verdict(&case, result);
    }
}

#[test]
fn vote_vectors_execute() {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let view = FixtureView::default();
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-vote-v1.json")
        .unwrap()
        .1
        .cases
    {
        let result = FinalityVoteV1::decode_canonical(&case.bytes)
            .map_err(codec_class)
            .and_then(|vote| {
                validate_vote(&vote, &fixture_chain_id(), &snap, &view)
                    .map_err(|e| witness_class(&e))?;
                Ok(vote)
            })
            .map(|vote| {
                // Extras pin the signer key and the canonical signed body.
                if case.kind == "positive" {
                    assert_eq!(extra(&case, "signing_bytes"), vote.signing_bytes());
                    assert_eq!(
                        extra(&case, "signer_key"),
                        snap.member(&vote.validator_id).unwrap().consensus_bls_key.0
                    );
                }
            });
        expect_verdict(&case, result);
    }
}

#[test]
fn threshold_vectors_execute() {
    let mut pinned_divergence = 0_u32;
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-threshold-v1.json")
        .unwrap()
        .1
        .cases
    {
        assert_eq!(case.bytes.len(), 32);
        let w = u128::from_le_bytes(arr::<16>(&case.bytes[..16]));
        let q = u128::from_le_bytes(arr::<16>(&case.bytes[16..]));
        assert_eq!(quorum_threshold(w), q, "case {}", case.name);
        // The exact law vs the naive rounded two-thirds: pinned per case.
        let naive_differs = extra_str(&case, "naive_differs") == "true";
        assert_eq!(naive_differs, w.is_multiple_of(3), "case {}", case.name);
        if naive_differs {
            pinned_divergence += 1;
        }
        if has_extra_str(&case, "naive_ceil") {
            let naive: u128 = extra_str(&case, "naive_ceil").parse().unwrap();
            assert_eq!(naive, (2 * w).div_ceil(3));
            if naive_differs {
                assert_eq!(q, naive + 1, "exact Q exceeds the naive ceiling by one");
            } else {
                assert_eq!(q, naive);
            }
        }
    }
    // The file MUST pin at least one boundary where naive rounding is wrong.
    assert!(pinned_divergence >= 3);
}

#[test]
fn membership_vectors_execute() {
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-membership-v1.json")
        .unwrap()
        .1
        .cases
    {
        let mut r = Reader::new(&case.bytes);
        let bonds: Vec<WitnessBondV1> = r.get_list(u32::MAX).unwrap();
        r.finish().unwrap();
        let epoch: u64 = extra_str(&case, "epoch").parse().unwrap();
        let min_bond: u128 = extra_str(&case, "min_bond").parse().unwrap();
        let randomness = arr::<32>(extra(&case, "randomness"));
        let outcome = build_snapshot(epoch, &bonds, &randomness, min_bond, None, false).unwrap();
        match (extra_str(&case, "outcome"), outcome) {
            ("normal", SnapshotOutcome::Normal(s)) => {
                assert_eq!(arr::<32>(extra(&case, "membership_root")), s.root());
                let count: usize = extra_str(&case, "member_count").parse().unwrap();
                assert_eq!(s.len(), count);
            }
            ("emergency", SnapshotOutcome::EmergencyContinuation(_)) => {}
            ("halt", SnapshotOutcome::Halt) => {}
            (expected, got) => panic!("case {}: expected {expected}, got {got:?}", case.name),
        }
    }
}

#[test]
fn certificate_vectors_execute() {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let view = FixtureView::default();
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-certificate-v1.json")
        .unwrap()
        .1
        .cases
    {
        let result = FinalityCertificateV1::decode_canonical(&case.bytes)
            .map_err(codec_class)
            .and_then(|cert| {
                verify_certificate(&cert, &fixture_chain_id(), &snap, &view)
                    .map_err(|e| witness_class(&e))?;
                if case.kind == "positive" {
                    assert_eq!(
                        arr::<32>(extra(&case, "digest")),
                        certificate_digest(&cert).unwrap()
                    );
                    assert_eq!(arr::<32>(extra(&case, "membership_root")), snap.root());
                }
                Ok(())
            });
        expect_verdict(&case, result);
    }
}

#[test]
fn beacon_vectors_execute() {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-beacon-v1.json")
        .unwrap()
        .1
        .cases
    {
        match case.name.as_str() {
            "beacon-reveal-hash" => {
                let reveal = arr::<32>(&case.bytes);
                assert_eq!(
                    arr::<32>(extra(&case, "reveal_hash")),
                    reveal_hash(&reveal).unwrap()
                );
            }
            "beacon-commit-digest" => {
                let msg = BeaconCommitV1::decode_canonical(&case.bytes).unwrap();
                let digest = commit_digest(
                    &msg.chain_id,
                    msg.epoch,
                    &msg.membership_root,
                    &msg.validator_id,
                    &msg.reveal_hash,
                )
                .unwrap();
                assert_eq!(arr::<32>(extra(&case, "commit_digest")), digest);
            }
            "beacon-mix-all-revealed" | "beacon-mix-member-2-withheld" => {
                // bytes = prev_digest || reveal_0..reveal_3.
                assert_eq!(case.bytes.len(), 32 * 5);
                let prev = arr::<32>(&case.bytes[..32]);
                let reveals: Vec<[u8; 32]> = case.bytes[32..].chunks(32).map(arr::<32>).collect();
                assert_eq!(reveals, fixture_reveals());
                let withheld: &[usize] = match extra_str(&case, "withheld_index") {
                    "none" => &[],
                    "2" => &[2],
                    other => panic!("unknown withheld_index {other}"),
                };
                let sealed = fixture_mix(withheld, &prev);
                assert_eq!(
                    arr::<32>(extra(&case, "randomness")),
                    sealed.raw_for_vectors()
                );
                assert_eq!(extra(&case, "bitmap"), sealed.contribution_bitmap);
            }
            "beacon-commit-post-cutoff" => {
                let msg = BeaconCommitV1::decode_canonical(&case.bytes).unwrap();
                let mut state = BeaconState::new(fixture_chain_id(), &snap);
                let slot: u64 = extra_str(&case, "slot_in_epoch").parse().unwrap();
                let err = state.ingest_commit(&msg, slot).unwrap_err();
                assert_eq!(Some(err.class_name()), case.error_class);
            }
            "beacon-commit-duplicate" => {
                let msg = BeaconCommitV1::decode_canonical(&case.bytes).unwrap();
                let mut state = BeaconState::new(fixture_chain_id(), &snap);
                state.ingest_commit(&msg, 0).unwrap();
                let err = state.ingest_commit(&msg, 0).unwrap_err();
                assert_eq!(Some(err.class_name()), case.error_class);
            }
            "beacon-reveal-mismatch" => {
                let msg = BeaconRevealV1::decode_canonical(&case.bytes).unwrap();
                let mut state = BeaconState::new(fixture_chain_id(), &snap);
                let commit = BeaconCommitV1 {
                    chain_id: fixture_chain_id(),
                    epoch: 1,
                    membership_root: snap.root(),
                    validator_id: msg.validator_id,
                    reveal_hash: reveal_hash(&fixture_reveals()[0]).unwrap(),
                };
                state.ingest_commit(&commit, 0).unwrap();
                state.finalize_commits().unwrap();
                let err = state.ingest_reveal(&msg).unwrap_err();
                assert_eq!(Some(err.class_name()), case.error_class);
            }
            other => panic!("unknown beacon case {other}"),
        }
    }
}

#[test]
fn slashing_vectors_execute() {
    let mut registry = SnapshotRegistry::new();
    for e in [1, 2, 3] {
        registry
            .insert(fixture_snapshot(e, FIXTURE_WEIGHTS))
            .unwrap();
    }
    let params = WitnessParamsV1::testnet_fixture();
    for case in vector_gen::files()
        .into_iter()
        .find(|(n, _)| *n == "witness-slashing-v1.json")
        .unwrap()
        .1
        .cases
    {
        let result = SlashingEvidenceV1::decode_canonical(&case.bytes)
            .map_err(codec_class)
            .and_then(|evidence| {
                let current: u64 = extra_str(&case, "current_epoch").parse().unwrap();
                let outcome = verify_evidence(
                    &evidence,
                    &fixture_chain_id(),
                    current,
                    &registry,
                    &FixtureRecheck,
                    &params,
                )
                .map_err(|e| witness_class(&e))?;
                // Universal slash laws: conserved split, removal at the
                // NEXT epoch boundary only.
                let bond = registry
                    .get(outcome.offense_epoch)
                    .unwrap()
                    .member(&outcome.validator_id)
                    .unwrap()
                    .raw_weight;
                assert!(outcome.split.conserves(bond), "case {}", case.name);
                assert_eq!(outcome.removal_effective_epoch, current + 1);
                Ok(())
            });
        expect_verdict(&case, result);
    }
}

#[test]
fn at_least_twenty_five_vectors_exist() {
    let total: usize = vector_gen::files().iter().map(|(_, f)| f.cases.len()).sum();
    assert!(total >= 25, "only {total} witness vectors");
    // And the vector files land in the frozen directory set.
    assert_eq!(vector_gen::files().len(), 7);
}
