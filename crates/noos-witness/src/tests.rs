//! Witness Ring law tests (witness-v1.md §§1–7): every law positive and
//! negative, plus seeded property tests.
//!
//! Fixture geometry (see [`crate::vector_gen`]): four members with weights
//! `[30, 28, 22, 20]` — `W = 100`, `Q = floor(200/3)+1 = 67`, no key at or
//! above `ceil(100/3) = 34`, minimum quorum = signers {0, 1, 2} (80).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use noos_braid::{Bytes96, CheckpointRef};
use noos_codec::{NoosDecode, NoosEncode};
use noos_crypto::{bls_aggregate, DomainId};
use noos_lumen::objects::BoundedBytes;

use crate::beacon::{
    commit_digest, reveal_hash, BarrierError, BeaconPhase, BeaconSafetyRecordV1, BeaconState,
    DurabilityBarrier, SAFETY_RECORD_COMMIT,
};
use crate::bond::WitnessBondV1;
use crate::finality::{
    bitmap_indices, build_certificate, certificate_digest, quorum_threshold, verify_certificate,
    FatalHistoryError, FinalityTracker, IngestOutcome, SnapshotRegistry,
};
use crate::liveness::leak_for_future_epoch;
use crate::membership::{
    build_snapshot, cap_violated, cluster_telemetry, membership_root, reduce_proofpower,
    reserve_sample, tiebreak_hash, MembershipSnapshotV1, SnapshotOutcome,
};
use crate::params::WitnessParamsV1;
use crate::slashing::{verify_evidence, SlashSplit, SlashingEvidenceV1};
use crate::vector_gen::{
    fixture_bonds, fixture_chain_id, fixture_divergence, fixture_secret, fixture_snapshot,
    fixture_vote, synthetic_flock, FixtureRecheck, FixtureView, FIXTURE_WEIGHTS,
};
use crate::vote::{validate_vote, FinalityVoteV1};
use crate::{WitnessError, N_MAX, N_TAIL};

// ---------------------------------------------------------------------------
// Seeded PRNG (xorshift64*)
// ---------------------------------------------------------------------------

struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

fn checkpoint(epoch: u64, seed: u8) -> CheckpointRef {
    CheckpointRef {
        epoch,
        checkpoint_hash: [seed; 32],
    }
}

/// A synthetic bond for membership-shape tests (no signature paths).
fn synthetic(seed: u8, weight: u128) -> WitnessBondV1 {
    let mut flock = synthetic_flock(1, weight, seed);
    flock[0].validator_id = [seed; 32];
    flock[0].consensus_bls_key.0[..32].copy_from_slice(&[seed; 32]);
    flock.remove(0)
}

// ---------------------------------------------------------------------------
// §3 thresholds
// ---------------------------------------------------------------------------

#[test]
fn threshold_exact_at_all_three_residues() {
    // W = 3k, 3k+1, 3k+2 boundaries: Q-1 never suffices, Q always does,
    // and Q agrees with the exact rational law 3s > 2W.
    for k in [0_u128, 1, 2, 33, 1_000_000, u128::MAX / 3 - 2] {
        for r in 0_u128..3 {
            let w = 3 * k + r;
            let q = quorum_threshold(w);
            let expected = match r {
                0 | 1 => 2 * k + 1,
                _ => 2 * k + 2,
            };
            assert_eq!(q, expected, "W = 3*{k}+{r}");
            if w < u128::MAX / 4 {
                // Exact-rational cross-check where 3s cannot overflow.
                assert!(3 * q > 2 * w);
                assert!(q == 0 || 3 * (q - 1) <= 2 * w);
            }
        }
    }
}

#[test]
fn threshold_differs_from_naive_ceiling_exactly_when_w_divisible_by_3() {
    // The naive "two thirds rounded up" is ceil(2W/3); witness-v1.md §3
    // demands floor(2W/3)+1. They differ exactly when 3 | W — the vector
    // file pins these.
    let naive_ceil = |w: u128| (2 * w).div_ceil(3);
    let mut differed = false;
    for w in 0_u128..1000 {
        let q = quorum_threshold(w);
        if w % 3 == 0 {
            assert_eq!(q, naive_ceil(w) + 1, "W={w}");
            differed = true;
        } else {
            assert_eq!(q, naive_ceil(w), "W={w}");
        }
    }
    assert!(differed);
}

#[test]
fn threshold_property_random_sums() {
    let mut prng = Prng::new(0xBEEF);
    for _ in 0..10_000 {
        let w = u128::from(prng.next_u64());
        let q = quorum_threshold(w);
        // Definitionally floor(2W/3) + 1 (no overflow at u64-scale W).
        assert_eq!(q, 2 * w / 3 + 1);
    }
}

// ---------------------------------------------------------------------------
// §2 membership
// ---------------------------------------------------------------------------

#[test]
fn selection_takes_top_n_max_with_deterministic_tiebreak() {
    // 300 equal-weight candidates: exactly N_MAX active, chosen by
    // ascending tiebreak hash, and the choice is epoch-salted.
    let bonds = synthetic_flock(300, 5_000_000_000, 0x01);
    let snap =
        |epoch: u64| match build_snapshot(epoch, &bonds, &[0x22; 32], 1, None, false).unwrap() {
            SnapshotOutcome::Normal(s) => s,
            other => panic!("expected normal outcome, got {other:?}"),
        };
    let s5 = snap(5);
    assert_eq!(s5.len(), N_MAX);
    // Deterministic: same epoch → same set.
    assert_eq!(snap(5).root(), s5.root());
    // Epoch-salted: a different epoch reshuffles the equal-weight ties.
    assert_ne!(snap(6).root(), s5.root());
    // The chosen set is exactly the N_MAX smallest tiebreak hashes.
    let mut by_tiebreak: Vec<([u8; 32], [u8; 32])> = bonds
        .iter()
        .map(|b| (tiebreak_hash(5, &b.validator_id).unwrap(), b.validator_id))
        .collect();
    by_tiebreak.sort();
    for (_, vid) in by_tiebreak.iter().take(N_MAX) {
        assert!(s5.member(vid).is_some(), "tiebreak winner excluded");
    }
}

#[test]
fn eligibility_filters_bond_and_epoch_window() {
    let mut low = synthetic(0x31, 100); // below min bond
    low.bonded_noos = 100;
    let mut not_yet = synthetic(0x32, 5_000_000_000);
    not_yet.activation_epoch = 9;
    let mut exited = synthetic(0x33, 5_000_000_000);
    exited.exit_epoch = 5;
    // Four equal survivors (each 25% < the one-third cap).
    let ok: Vec<WitnessBondV1> = (0x41..0x45_u8)
        .map(|s| synthetic(s, 5_000_000_000))
        .collect();
    let mut all = vec![low, not_yet, exited];
    all.extend(ok.clone());
    let out = build_snapshot(5, &all, &[0; 32], 1_000_000_000, None, false).unwrap();
    match out {
        SnapshotOutcome::Normal(s) => {
            assert_eq!(s.len(), 4);
            for b in &ok {
                assert!(s.member(&b.validator_id).is_some());
            }
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn duplicate_ids_and_keys_reject() {
    let a = synthetic(0x51, 5_000_000_000);
    let mut b = synthetic(0x51, 6_000_000_000);
    b.consensus_bls_key.0[0] ^= 1;
    assert_eq!(
        build_snapshot(1, &[a.clone(), b], &[0; 32], 1, None, false),
        Err(WitnessError::DuplicateValidatorId)
    );
    let mut c = synthetic(0x52, 6_000_000_000);
    c.consensus_bls_key = a.consensus_bls_key;
    assert_eq!(
        build_snapshot(1, &[a, c], &[0; 32], 1, None, false),
        Err(WitnessError::DuplicateConsensusKey)
    );
}

#[test]
fn reserve_is_sampled_without_replacement_by_randomness() {
    let remainder: Vec<WitnessBondV1> = (0..80_u8).map(|i| synthetic(i + 1, 1_000)).collect();
    let r1 = reserve_sample(3, &remainder, &[0x01; 32]).unwrap();
    let r2 = reserve_sample(3, &remainder, &[0x02; 32]).unwrap();
    assert_eq!(r1.len(), N_TAIL);
    assert_eq!(r2.len(), N_TAIL);
    // Without replacement: all distinct.
    assert_eq!(r1.iter().collect::<BTreeSet<_>>().len(), N_TAIL);
    // Randomness-dependent order.
    assert_ne!(r1, r2);
    // Deterministic.
    assert_eq!(reserve_sample(3, &remainder, &[0x01; 32]).unwrap(), r1);
}

#[test]
fn cap_repair_admits_reserves_in_sample_order_until_valid() {
    // Whale + 199 small, NO remainder to admit: unrepairable → the
    // previous set continues one emergency epoch.
    let mut bonds = vec![synthetic(0xE1, 1_000_000)];
    bonds.extend(synthetic_flock(199, 1_000, 0x02));
    let prev = fixture_snapshot(0, FIXTURE_WEIGHTS);
    match build_snapshot(1, &bonds, &[0x33; 32], 1, Some(&prev), false).unwrap() {
        SnapshotOutcome::EmergencyContinuation(s) => {
            assert_eq!(s.epoch(), 1);
            assert_eq!(s.root(), prev.root());
        }
        other => panic!("expected emergency, got {other:?}"),
    }

    // Whale 3e6 over 400 x 20k: the active top-256 set (whale + 255*20k =
    // 8.1e6 total, third = 2.7e6) violates; admitting sampled reserves
    // dilutes the whale below one third (full total 11e6, third ≈ 3.67e6).
    let mut bonds = vec![synthetic(0xEE, 3_000_000)];
    bonds.extend(synthetic_flock(400, 20_000, 0x03));
    match build_snapshot(1, &bonds, &[0x33; 32], 1, None, false).unwrap() {
        SnapshotOutcome::Normal(s) => {
            assert!(s.len() > N_MAX, "reserves were admitted");
            let members = s.members().to_vec();
            assert!(!cap_violated(&members));
        }
        other => panic!("expected repaired normal outcome, got {other:?}"),
    }
}

#[test]
fn unrepairable_set_continues_one_emergency_epoch_then_halts() {
    // A single whale with no other candidates can never satisfy the cap.
    let whale = vec![synthetic(0xE9, 5_000_000_000)];
    let prev = fixture_snapshot(6, FIXTURE_WEIGHTS);
    // First failure: previous set continues.
    let out = build_snapshot(7, &whale, &[0; 32], 1, Some(&prev), false).unwrap();
    let continued = match out {
        SnapshotOutcome::EmergencyContinuation(s) => s,
        other => panic!("expected emergency, got {other:?}"),
    };
    assert_eq!(continued.epoch(), 7);
    assert_eq!(continued.members(), prev.members());
    // Second consecutive failure: HALT (never normalizes an unsafe set).
    assert_eq!(
        build_snapshot(8, &whale, &[0; 32], 1, Some(&continued), true).unwrap(),
        SnapshotOutcome::Halt
    );
    // No previous set at all: HALT immediately.
    assert_eq!(
        build_snapshot(7, &whale, &[0; 32], 1, None, false).unwrap(),
        SnapshotOutcome::Halt
    );
}

#[test]
fn proofpower_reduction_arm_engages_before_touching_raw_weight() {
    // Genesis weights cannot express eff > raw; manufacture members where
    // ONLY the effective dimension violates and confirm the reduction arm
    // repairs it (the loop's second step).
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let mut members = snap.members().to_vec();
    members[0].effective_weight = 200; // eff whale, raw fine
    assert!(cap_violated(&members));
    assert!(reduce_proofpower(&mut members));
    assert!(!cap_violated(&members));
    for m in &members {
        assert_eq!(m.effective_weight, m.raw_weight);
    }
    // Second reduction is a no-op.
    assert!(!reduce_proofpower(&mut members));
}

#[test]
fn effective_weight_is_raw_under_genesis_controls() {
    use crate::membership::effective_weight;
    // Flag off.
    assert_eq!(effective_weight(77, 1_000_000, false), 77);
    // Flag on: the compile-time zero cap still clamps the bonus.
    assert_eq!(effective_weight(77, 1_000_000, true), 77);
}

#[test]
fn membership_root_is_order_independent_and_binds_weights() {
    let bonds = fixture_bonds(FIXTURE_WEIGHTS);
    let mut reversed = bonds.clone();
    reversed.reverse();
    let normal = |bonds: &[WitnessBondV1], weights_tag: &str| match build_snapshot(
        1, bonds, &[0; 32], 1, None, false,
    )
    .unwrap()
    {
        SnapshotOutcome::Normal(s) => s,
        other => panic!("{weights_tag}: {other:?}"),
    };
    let a = normal(&bonds, "forward");
    let b = normal(&reversed, "reversed");
    assert_eq!(a.root(), b.root());
    // Weight change → root change.
    let c = normal(&fixture_bonds(&[31, 28, 22, 20]), "variant");
    assert_ne!(a.root(), c.root());
    // Root recomputes from the member list.
    assert_eq!(membership_root(a.members()), a.root());
}

#[test]
fn cluster_telemetry_treats_unknown_as_one_correlated_cluster() {
    let mut bonds = fixture_bonds(FIXTURE_WEIGHTS);
    bonds[0].failure_domains = BoundedBytes::new(vec![]).unwrap(); // unknown
    bonds[1].failure_domains = BoundedBytes::new(vec![]).unwrap(); // unknown
    bonds[2].failure_domains = BoundedBytes::new(b"op:acme".to_vec()).unwrap();
    bonds[3].failure_domains = BoundedBytes::new(b"op:acme".to_vec()).unwrap();
    let snap = match build_snapshot(1, &bonds, &[0; 32], 1, None, false).unwrap() {
        SnapshotOutcome::Normal(s) => s,
        other => panic!("{other:?}"),
    };
    let stats = cluster_telemetry(&snap);
    assert_eq!(stats.len(), 2);
    let unknown = &stats[0]; // empty key sorts first
    assert!(!unknown.declared);
    assert_eq!(unknown.member_count, 2);
    assert_eq!(unknown.raw_weight, 58); // 30 + 28
    let acme = &stats[1];
    assert!(acme.declared);
    assert_eq!(acme.member_count, 2);
    assert_eq!(acme.raw_weight, 42); // 22 + 20
}

#[test]
fn cap_repair_property_terminates_with_valid_or_degraded_outcome() {
    let mut prng = Prng::new(0xC0FFEE);
    let prev = fixture_snapshot(0, FIXTURE_WEIGHTS);
    for iteration in 0..200 {
        let n = 1 + prng.range(40) as usize;
        let mut bonds = Vec::with_capacity(n);
        for i in 0..n {
            let whale = prng.range(10) == 0;
            let weight = if whale {
                1_000_000_000 + u128::from(prng.next_u64() % 1_000_000_000)
            } else {
                1 + u128::from(prng.next_u64() % 1_000_000)
            };
            let mut vid = [0xAB_u8; 32];
            vid[30] = (i / 256) as u8;
            vid[31] = (i % 256) as u8;
            let mut b = synthetic(0x77, weight);
            b.validator_id = vid;
            b.consensus_bls_key.0[..32].copy_from_slice(&vid);
            bonds.push(b);
        }
        // Terminates (or the test itself would hang) with a lawful outcome.
        match build_snapshot(1, &bonds, &[0x44; 32], 1, Some(&prev), false).unwrap() {
            SnapshotOutcome::Normal(s) => {
                let members = s.members().to_vec();
                assert!(!cap_violated(&members), "iteration {iteration}");
                assert_eq!(
                    s.total_raw_weight(),
                    members.iter().map(|m| m.raw_weight).sum::<u128>()
                );
            }
            SnapshotOutcome::EmergencyContinuation(s) => {
                assert_eq!(s.members(), prev.members(), "iteration {iteration}");
            }
            SnapshotOutcome::Halt => panic!("prev exists: halt unreachable here"),
        }
    }
}

// ---------------------------------------------------------------------------
// §1.2 votes
// ---------------------------------------------------------------------------

#[test]
fn vote_validity_law_every_branch() {
    let chain = fixture_chain_id();
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let view = FixtureView::default();
    let good = fixture_vote(&snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1));
    assert_eq!(validate_vote(&good, &chain, &snap, &view), Ok(()));

    let mut wrong_chain = good.clone();
    wrong_chain.chain_id = [0xEE; 32];
    assert_eq!(
        validate_vote(&wrong_chain, &chain, &snap, &view),
        Err(WitnessError::WrongChain)
    );

    let mut wrong_epoch = good.clone();
    wrong_epoch.epoch = 2;
    assert_eq!(
        validate_vote(&wrong_epoch, &chain, &snap, &view),
        Err(WitnessError::EpochMismatch)
    );

    let mut bad_interval = good.clone();
    bad_interval.source = checkpoint(1, 0xA0);
    assert_eq!(
        validate_vote(&bad_interval, &chain, &snap, &view),
        Err(WitnessError::MalformedInterval)
    );

    let mut wrong_root = good.clone();
    wrong_root.membership_root = [0x77; 32];
    assert_eq!(
        validate_vote(&wrong_root, &chain, &snap, &view),
        Err(WitnessError::MembershipRootMismatch)
    );

    let mut stranger = good.clone();
    stranger.validator_id = [0xFE; 32];
    assert_eq!(
        validate_vote(&stranger, &chain, &snap, &view),
        Err(WitnessError::UnknownValidator)
    );

    assert_eq!(
        validate_vote(&good, &chain, &snap, &FixtureView::nothing_justified()),
        Err(WitnessError::SourceNotJustified)
    );

    assert_eq!(
        validate_vote(
            &good,
            &chain,
            &snap,
            &FixtureView::deny(good.source, good.target)
        ),
        Err(WitnessError::TargetNotDescended)
    );

    let mut bad_sig = good;
    bad_sig.signature.0[10] ^= 0x01;
    assert_eq!(
        validate_vote(&bad_sig, &chain, &snap, &view),
        Err(WitnessError::SignatureInvalid)
    );
    assert_eq!(
        validate_vote(&bad_sig, &chain, &snap, &FixtureView::nothing_justified()),
        Err(WitnessError::SignatureInvalid),
        "a future-source vote is authenticated before it can be deferred"
    );
}

// ---------------------------------------------------------------------------
// §§1.3, 3 certificates
// ---------------------------------------------------------------------------

fn quorum_votes(
    snap: &MembershipSnapshotV1,
    source: CheckpointRef,
    target: CheckpointRef,
) -> Vec<FinalityVoteV1> {
    // Members 0, 1, 2 (30 + 28 + 22 = 80 >= Q(100) = 67).
    (0..3)
        .map(|i| fixture_vote(snap, i, source, target))
        .collect()
}

#[test]
fn build_certificate_requires_quorum_inputs() {
    let chain = fixture_chain_id();
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let source = checkpoint(0, 0xA0);
    let target = checkpoint(1, 0xA1);
    // Below quorum: 30 + 28 = 58 < 67 — no API constructs a certificate
    // without the quorum inputs (§5).
    let underweight = vec![
        fixture_vote(&snap, 0, source, target),
        fixture_vote(&snap, 1, source, target),
    ];
    assert_eq!(
        build_certificate(&underweight, &chain, &snap),
        Err(WitnessError::QuorumNotMet)
    );
    // At quorum it exists and verifies end to end.
    let cert = build_certificate(&quorum_votes(&snap, source, target), &chain, &snap).unwrap();
    let verified = verify_certificate(&cert, &chain, &snap, &FixtureView::default()).unwrap();
    assert_eq!(verified.raw_weight, 80);
    assert_eq!(verified.effective_weight, 80);
    assert_eq!(verified.signer_indices, vec![0, 1, 2]);
    // Duplicate votes cannot pad a quorum.
    let padded = vec![
        fixture_vote(&snap, 0, source, target),
        fixture_vote(&snap, 0, source, target),
        fixture_vote(&snap, 1, source, target),
    ];
    assert_eq!(
        build_certificate(&padded, &chain, &snap),
        Err(WitnessError::DuplicateValidatorId)
    );
}

#[test]
fn certificate_tamper_matrix() {
    let chain = fixture_chain_id();
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let view = FixtureView::default();
    let source = checkpoint(0, 0xA0);
    let target = checkpoint(1, 0xA1);
    let votes = quorum_votes(&snap, source, target);
    let cert = build_certificate(&votes, &chain, &snap).unwrap();

    // Bitmap bit flip (adds non-signer 3): recomputed sums disagree with
    // the carried sums.
    let mut flipped = cert.clone();
    let mut bytes = flipped.participation_bitmap.as_slice().to_vec();
    bytes[0] ^= 0b1000;
    flipped.participation_bitmap = BoundedBytes::new(bytes).unwrap();
    assert_eq!(
        verify_certificate(&flipped, &chain, &snap, &view),
        Err(WitnessError::WeightSumMismatch)
    );

    // Bitmap flip WITH matching sum re-inflation: the aggregate no longer
    // matches the claimed signer set.
    let mut forged = cert.clone();
    let mut bytes = forged.participation_bitmap.as_slice().to_vec();
    bytes[0] ^= 0b1000;
    forged.participation_bitmap = BoundedBytes::new(bytes).unwrap();
    forged.raw_weight_sum = 100;
    forged.effective_weight_sum = 100;
    assert_eq!(
        verify_certificate(&forged, &chain, &snap, &view),
        Err(WitnessError::AggregateInvalid)
    );

    // Sum inflation alone: recomputation wins — the carried sum is never
    // trusted.
    let mut inflated = cert.clone();
    inflated.raw_weight_sum = 100;
    assert_eq!(
        verify_certificate(&inflated, &chain, &snap, &view),
        Err(WitnessError::WeightSumMismatch)
    );
    let mut inflated_eff = cert.clone();
    inflated_eff.effective_weight_sum = 100;
    assert_eq!(
        verify_certificate(&inflated_eff, &chain, &snap, &view),
        Err(WitnessError::WeightSumMismatch)
    );

    // Wrong membership root.
    let mut wrong_root = cert.clone();
    wrong_root.membership_root = [0x66; 32];
    assert_eq!(
        verify_certificate(&wrong_root, &chain, &snap, &view),
        Err(WitnessError::MembershipRootMismatch)
    );

    // Wrong DST: the same vote bodies signed under the CERT DST instead of
    // the registered VOTE DST.
    let mut wrong_dst = cert.clone();
    let sigs: Vec<_> = (0..3)
        .map(|i| {
            fixture_secret(i)
                .sign_domain(DomainId::BlsCert, &votes[i].signing_bytes())
                .unwrap()
        })
        .collect();
    wrong_dst.aggregate_signature = Bytes96(bls_aggregate(&sigs).unwrap().into_bytes());
    assert_eq!(
        verify_certificate(&wrong_dst, &chain, &snap, &view),
        Err(WitnessError::AggregateInvalid)
    );

    // Subset signature: bitmap claims {0, 1, 2} but member 2's vote is
    // missing from the aggregate.
    let mut subset = cert.clone();
    let two: Vec<_> = (0..2)
        .map(|i| noos_crypto::BlsSignature::from_bytes(votes[i].signature.0))
        .collect();
    subset.aggregate_signature = Bytes96(bls_aggregate(&two).unwrap().into_bytes());
    assert_eq!(
        verify_certificate(&subset, &chain, &snap, &view),
        Err(WitnessError::AggregateInvalid)
    );

    // Empty signer set.
    let mut empty = cert.clone();
    empty.participation_bitmap = BoundedBytes::new(vec![0]).unwrap();
    empty.raw_weight_sum = 0;
    empty.effective_weight_sum = 0;
    assert_eq!(
        verify_certificate(&empty, &chain, &snap, &view),
        Err(WitnessError::EmptySignerSet)
    );

    // Non-canonical bitmap length.
    let mut long = cert.clone();
    long.participation_bitmap = BoundedBytes::new(vec![0b0111, 0]).unwrap();
    assert_eq!(
        verify_certificate(&long, &chain, &snap, &view),
        Err(WitnessError::BitmapLengthInvalid)
    );

    // Out-of-range bit (bit 4 with 4 members).
    let mut oob = cert.clone();
    oob.participation_bitmap = BoundedBytes::new(vec![0b0001_0111]).unwrap();
    assert_eq!(
        verify_certificate(&oob, &chain, &snap, &view),
        Err(WitnessError::BitmapOutOfRange)
    );

    // The untampered certificate still verifies (the matrix never mutated
    // the original).
    assert!(verify_certificate(&cert, &chain, &snap, &view).is_ok());
}

#[test]
fn bitmap_index_law() {
    assert_eq!(bitmap_indices(&[0b0000_0011], 4).unwrap(), vec![0, 1]);
    assert_eq!(bitmap_indices(&[0xFF, 0x01], 9).unwrap().len(), 9);
    assert_eq!(
        bitmap_indices(&[0xFF], 4),
        Err(WitnessError::BitmapOutOfRange)
    );
    assert_eq!(
        bitmap_indices(&[0x01, 0x00], 4),
        Err(WitnessError::BitmapLengthInvalid)
    );
    assert_eq!(
        bitmap_indices(&[0x00], 4),
        Err(WitnessError::EmptySignerSet)
    );
}

// ---------------------------------------------------------------------------
// §3 pointer state machine
// ---------------------------------------------------------------------------

struct Always;
impl crate::finality::Ancestry for Always {
    fn descends(&self, _s: &CheckpointRef, _t: &CheckpointRef) -> bool {
        true
    }
}

fn registry_for(epochs: &[u64]) -> SnapshotRegistry {
    let mut registry = SnapshotRegistry::new();
    for &e in epochs {
        registry
            .insert(fixture_snapshot(e, FIXTURE_WEIGHTS))
            .unwrap();
    }
    registry
}

#[test]
fn genesis_is_justified_and_finalized() {
    let genesis = checkpoint(0, 0xA0);
    let tracker = FinalityTracker::genesis(fixture_chain_id(), genesis);
    assert!(tracker.is_checkpoint_justified(&genesis));
    assert_eq!(tracker.finalized_head(), genesis);
    assert_eq!(tracker.justified_head(), genesis);
}

#[test]
fn direct_child_rule_finalizes_and_pointers_never_revert() {
    let chain = fixture_chain_id();
    let genesis = checkpoint(0, 0xA0);
    let cp1 = checkpoint(1, 0xA1);
    let cp2 = checkpoint(2, 0xA2);
    let registry = registry_for(&[1, 2, 3]);
    let mut tracker = FinalityTracker::genesis(chain, genesis);

    // 0 → 1: target justified; the finalized head (genesis) does not move.
    let snap1 = registry.get(1).unwrap().clone();
    let cert1 = build_certificate(&quorum_votes(&snap1, genesis, cp1), &chain, &snap1).unwrap();
    assert_eq!(
        tracker
            .ingest_certificate(&cert1, &registry, &Always)
            .unwrap(),
        IngestOutcome::Justified
    );
    assert!(tracker.is_checkpoint_justified(&cp1));
    assert_eq!(tracker.finalized_head(), genesis);
    assert_eq!(tracker.justified_head(), cp1);

    // Duplicate short-circuit on content digest, BEFORE verification.
    assert_eq!(
        tracker
            .ingest_certificate(&cert1, &registry, &Always)
            .unwrap(),
        IngestOutcome::Duplicate
    );

    // 1 → 2 (direct child): finalizes checkpoint 1.
    let snap2 = registry.get(2).unwrap().clone();
    let cert2 = build_certificate(&quorum_votes(&snap2, cp1, cp2), &chain, &snap2).unwrap();
    assert_eq!(
        tracker
            .ingest_certificate(&cert2, &registry, &Always)
            .unwrap(),
        IngestOutcome::Finalized(cp1)
    );
    assert_eq!(tracker.finalized_head(), cp1);
    assert!(tracker.is_finalized_carrier(&certificate_digest(&cert2).unwrap()));

    // Never revert: a conflicting epoch-1 target can no longer justify.
    let cp1_alt = checkpoint(1, 0xEE);
    let alt = build_certificate(&quorum_votes(&snap1, genesis, cp1_alt), &chain, &snap1).unwrap();
    assert_eq!(
        tracker.ingest_certificate(&alt, &registry, &Always),
        Err(WitnessError::ConflictingFinalization)
    );
    assert_eq!(tracker.finalized_head(), cp1);

    // Non-direct child (1 → 3): justified only.
    let cp3 = checkpoint(3, 0xA3);
    let snap3 = registry.get(3).unwrap().clone();
    let cert3 = build_certificate(&quorum_votes(&snap3, cp1, cp3), &chain, &snap3).unwrap();
    assert_eq!(
        tracker
            .ingest_certificate(&cert3, &registry, &Always)
            .unwrap(),
        IngestOutcome::Justified
    );
    assert_eq!(tracker.finalized_head(), cp1);
}

#[test]
fn handover_binding_and_attestation() {
    use crate::finality::{handover_digest, verify_handover_attestation, HandoverBindingV1};
    let old = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let new = fixture_snapshot(2, &[31, 28, 22, 20]);
    let binding = HandoverBindingV1 {
        chain_id: fixture_chain_id(),
        epoch: 2,
        old_membership_root: old.root(),
        new_membership_root: new.root(),
        finalized_checkpoint: checkpoint(1, 0xA1),
    };
    let digest = handover_digest(&binding).unwrap();

    // The digest binds every field of (chain, epoch, old root, new root,
    // finalized checkpoint).
    for mutate in 0..5_usize {
        let mut other = binding.clone();
        match mutate {
            0 => other.chain_id = [0xEE; 32],
            1 => other.epoch = 3,
            2 => other.old_membership_root = [0x01; 32],
            3 => other.new_membership_root = [0x02; 32],
            _ => other.finalized_checkpoint = checkpoint(1, 0xEE),
        }
        assert_ne!(handover_digest(&other).unwrap(), digest, "field {mutate}");
    }

    // OLD-set signers attest the transcript under D-BLS-HANDOVER.
    let signers: Vec<_> = (0..3)
        .map(|i| noos_crypto::BlsPublicKey::from_bytes(old.members()[i].consensus_bls_key.0))
        .collect();
    let sigs: Vec<_> = (0..3)
        .map(|i| {
            fixture_secret(i)
                .sign_domain(DomainId::BlsHandover, &digest)
                .unwrap()
        })
        .collect();
    let aggregate = bls_aggregate(&sigs).unwrap();
    assert_eq!(
        verify_handover_attestation(&binding, &signers, &aggregate),
        Ok(())
    );

    // The same signers under the VOTE DST do not attest a handover.
    let wrong: Vec<_> = (0..3)
        .map(|i| {
            fixture_secret(i)
                .sign_domain(DomainId::BlsVote, &digest)
                .unwrap()
        })
        .collect();
    assert_eq!(
        verify_handover_attestation(&binding, &signers, &bls_aggregate(&wrong).unwrap()),
        Err(WitnessError::AggregateInvalid)
    );

    // A tampered binding invalidates the attestation.
    let mut tampered = binding;
    tampered.new_membership_root = [0x03; 32];
    assert_eq!(
        verify_handover_attestation(&tampered, &signers, &aggregate),
        Err(WitnessError::AggregateInvalid)
    );
}

#[test]
fn certificate_source_must_already_be_justified() {
    let chain = fixture_chain_id();
    let registry = registry_for(&[2]);
    let mut tracker = FinalityTracker::genesis(chain, checkpoint(0, 0xA0));
    // 1 → 2 without epoch 1 ever justified.
    let snap2 = registry.get(2).unwrap().clone();
    let cert = build_certificate(
        &quorum_votes(&snap2, checkpoint(1, 0xA1), checkpoint(2, 0xA2)),
        &chain,
        &snap2,
    )
    .unwrap();
    assert_eq!(
        tracker.ingest_certificate(&cert, &registry, &Always),
        Err(WitnessError::SourceNotJustified)
    );
    // Threshold failure means the epoch continues unfinalized: pointers
    // never moved (§5).
    assert_eq!(tracker.finalized_head(), checkpoint(0, 0xA0));
    assert_eq!(tracker.justified_head(), checkpoint(0, 0xA0));
}

#[test]
fn unknown_snapshot_epoch_rejects() {
    let chain = fixture_chain_id();
    let registry = registry_for(&[1]);
    let mut tracker = FinalityTracker::genesis(chain, checkpoint(0, 0xA0));
    let snap = fixture_snapshot(9, FIXTURE_WEIGHTS);
    let cert = build_certificate(
        &quorum_votes(&snap, checkpoint(0, 0xA0), checkpoint(9, 0xA9)),
        &chain,
        &snap,
    )
    .unwrap();
    assert_eq!(
        tracker.ingest_certificate(&cert, &registry, &Always),
        Err(WitnessError::UnknownSnapshot)
    );
}

#[test]
fn history_loading_is_typed_fatal_on_malformation() {
    let s1 = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let s2 = fixture_snapshot(2, FIXTURE_WEIGHTS);
    // Well-formed history loads.
    assert!(
        SnapshotRegistry::load_history([(s1.clone(), s1.root()), (s2.clone(), s2.root())]).is_ok()
    );
    // Root mismatch: typed fatal, never a reset.
    assert_eq!(
        SnapshotRegistry::load_history([(s1.clone(), [0xDD; 32])]).unwrap_err(),
        FatalHistoryError::RootMismatch(1)
    );
    // Duplicate epoch: typed fatal.
    assert_eq!(
        SnapshotRegistry::load_history([(s1.clone(), s1.root()), (s1.clone(), s1.root())])
            .unwrap_err(),
        FatalHistoryError::DuplicateEpoch(1)
    );
}

// ---------------------------------------------------------------------------
// §1.4 slashing
// ---------------------------------------------------------------------------

fn double_vote_evidence(snap: &MembershipSnapshotV1) -> SlashingEvidenceV1 {
    SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xB1)),
    }
}

#[test]
fn double_vote_predicate_and_split() {
    let chain = fixture_chain_id();
    let registry = registry_for(&[1]);
    let snap = registry.get(1).unwrap().clone();
    let params = WitnessParamsV1::testnet_fixture();
    let outcome = verify_evidence(
        &double_vote_evidence(&snap),
        &chain,
        3,
        &registry,
        &FixtureRecheck,
        &params,
    )
    .unwrap();
    assert_eq!(outcome.validator_id, snap.members()[0].validator_id);
    assert_eq!(outcome.offense_epoch, 1);
    // Removal at the NEXT epoch boundary only.
    assert_eq!(outcome.removal_effective_epoch, 4);
    // Conserved split of the offender's bond (weight 30).
    assert!(outcome.split.conserves(30));
    // Existing snapshot untouched (membership never mutates mid-epoch).
    assert_eq!(registry.get(1).unwrap().root(), snap.root());

    // Byte-identical votes: not a double vote.
    let same = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(&snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
    };
    assert_eq!(
        verify_evidence(&same, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::IdenticalVotes)
    );

    // Distinct votes, same target: still not this offense class.
    let same_target = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(&snap, 0, checkpoint(0, 0xB0), checkpoint(1, 0xA1)),
    };
    assert_eq!(
        verify_evidence(&same_target, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::TargetsNotDistinct)
    );

    // Distinct target EPOCHS: not a double vote.
    let registry2 = registry_for(&[1, 2]);
    let snap2 = registry2.get(2).unwrap().clone();
    let cross = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(&snap2, 0, checkpoint(0, 0xA0), checkpoint(2, 0xB1)),
    };
    assert_eq!(
        verify_evidence(&cross, &chain, 3, &registry2, &FixtureRecheck, &params),
        Err(WitnessError::TargetEpochMismatch)
    );

    // Different validators: never one offense.
    let mixed = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&snap, 0, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
        vote_b: fixture_vote(&snap, 1, checkpoint(0, 0xA0), checkpoint(1, 0xB1)),
    };
    assert_eq!(
        verify_evidence(&mixed, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::ValidatorMismatch)
    );
}

#[test]
fn surround_predicate_is_strict_both_directions() {
    let chain = fixture_chain_id();
    let registry = registry_for(&[1, 2, 3]);
    let params = WitnessParamsV1::testnet_fixture();
    let snap2 = registry.get(2).unwrap().clone();
    let snap3 = registry.get(3).unwrap().clone();
    let outer = fixture_vote(&snap3, 1, checkpoint(0, 0xA0), checkpoint(3, 0xA3));
    let inner = fixture_vote(&snap2, 1, checkpoint(1, 0xA1), checkpoint(2, 0xA2));

    // outer strictly surrounds inner: slashable.
    let good = SlashingEvidenceV1::SurroundVote {
        outer: outer.clone(),
        inner: inner.clone(),
    };
    let outcome = verify_evidence(&good, &chain, 3, &registry, &FixtureRecheck, &params).unwrap();
    assert_eq!(outcome.offense_epoch, 3);
    assert!(outcome.split.conserves(28)); // member 1 weight

    // Mislabeled direction (inner presented as outer): rejected — the
    // predicate is directional and strict in both directions.
    let swapped = SlashingEvidenceV1::SurroundVote {
        outer: inner.clone(),
        inner: outer.clone(),
    };
    assert_eq!(
        verify_evidence(&swapped, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::NotSurrounding)
    );

    // Equal source epochs: NOT strict surround.
    let equal_source = SlashingEvidenceV1::SurroundVote {
        outer: fixture_vote(&snap3, 1, checkpoint(1, 0xA1), checkpoint(3, 0xA3)),
        inner: fixture_vote(&snap2, 1, checkpoint(1, 0xA1), checkpoint(2, 0xA2)),
    };
    assert_eq!(
        verify_evidence(
            &equal_source,
            &chain,
            3,
            &registry,
            &FixtureRecheck,
            &params
        ),
        Err(WitnessError::NotSurrounding)
    );

    // Equal target epochs: NOT strict surround.
    let equal_target = SlashingEvidenceV1::SurroundVote {
        outer: fixture_vote(&snap2, 1, checkpoint(0, 0xA0), checkpoint(2, 0xA2)),
        inner: fixture_vote(&snap2, 1, checkpoint(1, 0xA1), checkpoint(2, 0xB2)),
    };
    assert_eq!(
        verify_evidence(
            &equal_target,
            &chain,
            3,
            &registry,
            &FixtureRecheck,
            &params
        ),
        Err(WitnessError::NotSurrounding)
    );
}

#[test]
fn invalid_transition_needs_body_and_divergence() {
    let chain = fixture_chain_id();
    let registry = registry_for(&[1]);
    let snap = registry.get(1).unwrap().clone();
    let params = WitnessParamsV1::testnet_fixture();
    let vote = fixture_vote(&snap, 2, checkpoint(0, 0xA0), checkpoint(1, 0xA1));

    // Unavailable body: NEVER slashable.
    let unavailable = SlashingEvidenceV1::InvalidTransitionVote {
        vote: vote.clone(),
        body_ref: [0xAA; 32],
        divergence_proof: fixture_divergence(),
    };
    assert_eq!(
        verify_evidence(&unavailable, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::BodyUnavailable)
    );

    // Re-execution matches: no offense.
    let matches = SlashingEvidenceV1::InvalidTransitionVote {
        vote: vote.clone(),
        body_ref: [0xCC; 32],
        divergence_proof: fixture_divergence(),
    };
    assert_eq!(
        verify_evidence(&matches, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::NoDivergence)
    );

    // Divergence witness mismatch: evidence must carry the actual recheck.
    let mut wrong_witness = fixture_divergence();
    wrong_witness.recomputed_state_root = [0x09; 32];
    let mismatched = SlashingEvidenceV1::InvalidTransitionVote {
        vote: vote.clone(),
        body_ref: [0xBB; 32],
        divergence_proof: wrong_witness,
    };
    assert_eq!(
        verify_evidence(&mismatched, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::DivergenceWitnessMismatch)
    );

    // Real divergence: slashable (member 2, weight 22).
    let good = SlashingEvidenceV1::InvalidTransitionVote {
        vote,
        body_ref: [0xBB; 32],
        divergence_proof: fixture_divergence(),
    };
    let outcome = verify_evidence(&good, &chain, 3, &registry, &FixtureRecheck, &params).unwrap();
    assert!(outcome.split.conserves(22));
}

#[test]
fn evidence_horizon_and_bindings() {
    let chain = fixture_chain_id();
    let registry = registry_for(&[1]);
    let snap = registry.get(1).unwrap().clone();
    let params = WitnessParamsV1::testnet_fixture();

    // Beyond the horizon (offense epoch 1, horizon 64): expired.
    assert_eq!(
        verify_evidence(
            &double_vote_evidence(&snap),
            &chain,
            66,
            &registry,
            &FixtureRecheck,
            &params
        ),
        Err(WitnessError::EvidenceExpired)
    );
    // At the horizon boundary: still valid.
    assert!(verify_evidence(
        &double_vote_evidence(&snap),
        &chain,
        65,
        &registry,
        &FixtureRecheck,
        &params
    )
    .is_ok());

    // Wrong chain binding.
    assert_eq!(
        verify_evidence(
            &double_vote_evidence(&snap),
            &[0xEF; 32],
            3,
            &registry,
            &FixtureRecheck,
            &params
        ),
        Err(WitnessError::WrongChain)
    );

    // Tampered signature inside evidence.
    let mut tampered = double_vote_evidence(&snap);
    if let SlashingEvidenceV1::DoubleVote { vote_a, .. } = &mut tampered {
        vote_a.signature.0[0] ^= 1;
    }
    assert_eq!(
        verify_evidence(&tampered, &chain, 3, &registry, &FixtureRecheck, &params),
        Err(WitnessError::SignatureInvalid)
    );

    // Evidence bound to a snapshot the registry does not know.
    let foreign = fixture_snapshot(8, FIXTURE_WEIGHTS);
    let unknown = SlashingEvidenceV1::DoubleVote {
        vote_a: fixture_vote(&foreign, 0, checkpoint(0, 0xA0), checkpoint(8, 0xA1)),
        vote_b: fixture_vote(&foreign, 0, checkpoint(0, 0xA0), checkpoint(8, 0xB1)),
    };
    assert_eq!(
        verify_evidence(&unknown, &chain, 9, &registry, &FixtureRecheck, &params),
        Err(WitnessError::UnknownSnapshot)
    );
}

#[test]
fn evidence_wire_roundtrip_and_unknown_discriminant() {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let cases = vec![
        double_vote_evidence(&snap),
        SlashingEvidenceV1::SurroundVote {
            outer: fixture_vote(&snap, 1, checkpoint(0, 0xA0), checkpoint(1, 0xA3)),
            inner: fixture_vote(&snap, 1, checkpoint(0, 0xB0), checkpoint(1, 0xA2)),
        },
        SlashingEvidenceV1::InvalidTransitionVote {
            vote: fixture_vote(&snap, 2, checkpoint(0, 0xA0), checkpoint(1, 0xA1)),
            body_ref: [0xBB; 32],
            divergence_proof: fixture_divergence(),
        },
    ];
    for ev in cases {
        let bytes = ev.encode_canonical();
        assert_eq!(SlashingEvidenceV1::decode_canonical(&bytes).unwrap(), ev);
    }
    // Unknown discriminant (3) rejects at decode.
    assert!(SlashingEvidenceV1::decode_canonical(&3_u16.to_le_bytes()).is_err());
}

#[test]
fn slash_split_conservation_property() {
    let mut prng = Prng::new(0xDEAD);
    let mut params = WitnessParamsV1::testnet_fixture();
    for _ in 0..5_000 {
        params.slash_burn_ppm = prng.range(1_000_001) as u32;
        params.slash_reporter_ppm = prng.range(1_000_001 - u64::from(params.slash_burn_ppm)) as u32;
        let amount = u128::from(prng.next_u64());
        let split = SlashSplit::compute(amount, &params).unwrap();
        assert!(split.conserves(amount));
        assert!(split.burn <= amount && split.reporter <= amount);
    }
}

// ---------------------------------------------------------------------------
// §4 beacon
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockBarrier {
    records: Vec<BeaconSafetyRecordV1>,
    fail: bool,
}

impl DurabilityBarrier for MockBarrier {
    fn persist(&mut self, record: &BeaconSafetyRecordV1) -> Result<(), BarrierError> {
        if self.fail {
            return Err(BarrierError("injected fsync failure".into()));
        }
        self.records.push(record.clone());
        Ok(())
    }
}

fn beacon_fixture() -> (MembershipSnapshotV1, BeaconState, MockBarrier) {
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let state = BeaconState::new(fixture_chain_id(), &snap);
    (snap, state, MockBarrier::default())
}

fn member_id(snap: &MembershipSnapshotV1, i: usize) -> [u8; 32] {
    snap.members()[i].validator_id
}

#[test]
fn commit_law_cutoff_membership_and_exactly_one() {
    let (snap, mut state, mut barrier) = beacon_fixture();
    let v0 = member_id(&snap, 0);
    let rh = reveal_hash(&[0x11; 32]).unwrap();

    // The cutoff slot itself already rejects.
    assert_eq!(
        state.local_commit(
            &mut barrier,
            v0,
            rh,
            crate::BEACON_COMMIT_CUTOFF_SLOT_OFFSET
        ),
        Err(WitnessError::PostCutoffCommit)
    );
    // Non-member rejects.
    assert_eq!(
        state.local_commit(&mut barrier, [0xFD; 32], rh, 0),
        Err(WitnessError::NotAMember)
    );
    // First commit passes, just before the cutoff.
    let msg = state
        .local_commit(
            &mut barrier,
            v0,
            rh,
            crate::BEACON_COMMIT_CUTOFF_SLOT_OFFSET - 1,
        )
        .unwrap();
    assert_eq!(msg.reveal_hash, rh);
    // Exactly one commit: any second commit (same or different) rejects.
    assert_eq!(
        state.local_commit(&mut barrier, v0, rh, 1),
        Err(WitnessError::DuplicateCommit)
    );
    let other = reveal_hash(&[0x12; 32]).unwrap();
    assert_eq!(
        state.local_commit(&mut barrier, v0, other, 1),
        Err(WitnessError::DuplicateCommit)
    );
}

#[test]
fn nothing_is_emitted_before_the_barrier_acknowledges() {
    let (snap, mut state, mut barrier) = beacon_fixture();
    let v0 = member_id(&snap, 0);
    let rh = reveal_hash(&[0x11; 32]).unwrap();

    // Failing barrier: no message, no state change, nothing persisted.
    barrier.fail = true;
    assert_eq!(
        state.local_commit(&mut barrier, v0, rh, 0),
        Err(WitnessError::BarrierFailed)
    );
    assert!(barrier.records.is_empty());

    // Recovery: the same commit succeeds afterwards (state was untouched),
    // and the persisted record precedes the returned message.
    barrier.fail = false;
    let msg = state.local_commit(&mut barrier, v0, rh, 0).unwrap();
    assert_eq!(barrier.records.len(), 1);
    assert_eq!(barrier.records[0].kind, SAFETY_RECORD_COMMIT);
    assert_eq!(barrier.records[0].payload, msg.reveal_hash);

    // Same law on the reveal path.
    state.finalize_commits().unwrap();
    barrier.fail = true;
    assert_eq!(
        state.local_reveal(&mut barrier, v0, [0x11; 32]),
        Err(WitnessError::BarrierFailed)
    );
    assert_eq!(barrier.records.len(), 1);
    barrier.fail = false;
    let reveal = state.local_reveal(&mut barrier, v0, [0x11; 32]).unwrap();
    assert_eq!(reveal.reveal, [0x11; 32]);
    assert_eq!(barrier.records.len(), 2);
}

#[test]
fn reveal_law_matching_late_alternate_duplicate() {
    let (snap, mut state, mut barrier) = beacon_fixture();
    let v0 = member_id(&snap, 0);
    let v1 = member_id(&snap, 1);
    state
        .local_commit(&mut barrier, v0, reveal_hash(&[0x11; 32]).unwrap(), 0)
        .unwrap();
    state
        .local_commit(&mut barrier, v1, reveal_hash(&[0x22; 32]).unwrap(), 0)
        .unwrap();

    // Reveal before the commit set finalizes: wrong phase.
    assert_eq!(
        state.local_reveal(&mut barrier, v0, [0x11; 32]),
        Err(WitnessError::WrongBeaconPhase)
    );
    state.finalize_commits().unwrap();
    // Post-finalization commits reject.
    assert_eq!(
        state.local_commit(
            &mut barrier,
            member_id(&snap, 2),
            reveal_hash(&[0x33; 32]).unwrap(),
            0
        ),
        Err(WitnessError::WrongBeaconPhase)
    );
    // Mismatched (alternate) reveal rejects.
    assert_eq!(
        state.local_reveal(&mut barrier, v0, [0x99; 32]),
        Err(WitnessError::RevealMismatch)
    );
    // No commitment: unknown.
    assert_eq!(
        state.local_reveal(&mut barrier, member_id(&snap, 3), [0x44; 32]),
        Err(WitnessError::UnknownCommit)
    );
    // Matching reveal passes; a second one is a duplicate.
    state.local_reveal(&mut barrier, v0, [0x11; 32]).unwrap();
    assert_eq!(
        state.local_reveal(&mut barrier, v0, [0x11; 32]),
        Err(WitnessError::DuplicateReveal)
    );
    // After the mix, reveals are LATE.
    state.compute_mix(&[0x55; 32]).unwrap();
    assert_eq!(
        state.local_reveal(&mut barrier, v1, [0x22; 32]),
        Err(WitnessError::WrongBeaconPhase)
    );
    assert_eq!(state.phase(), BeaconPhase::Mixed);
}

#[test]
fn withholding_substitutes_the_committed_hash_and_cannot_reselect() {
    use crate::vector_gen::{fixture_mix, fixture_reveals};
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let reveals = fixture_reveals();
    let prev = [0x55; 32];

    let sealed_full = fixture_mix(&[], &prev);
    let sealed_withheld = fixture_mix(&[2], &prev);

    // The withheld member is reported for the penalty hook and excluded
    // from the contribution bitmap.
    assert_eq!(sealed_withheld.withheld, vec![member_id(&snap, 2)]);
    assert_eq!(sealed_withheld.contribution_bitmap, vec![0b1011]);
    assert_eq!(sealed_full.contribution_bitmap, vec![0b1111]);
    assert!(sealed_full.withheld.is_empty());

    // Withholding changes the output (bitmap + substituted hash) but both
    // transcripts are fully determined at commit time: recompute manually
    // under D-BEACON-MIX.
    let manual = |bitmap: &[u8], contribs: &[[u8; 32]]| -> [u8; 32] {
        let epoch_le = 1_u64.to_le_bytes();
        let chain = fixture_chain_id();
        let root = snap.root();
        let mut parts: Vec<&[u8]> = vec![&chain, &epoch_le, &root, bitmap, &prev];
        for c in contribs {
            parts.push(c);
        }
        noos_crypto::hash_domain(DomainId::BeaconMix, &parts)
            .unwrap()
            .into_bytes()
    };
    let full_contribs: Vec<[u8; 32]> = reveals.clone();
    let mut withheld_contribs = reveals.clone();
    withheld_contribs[2] = reveal_hash(&reveals[2]).unwrap(); // committed hash substitutes
    assert_eq!(
        sealed_full.raw_for_vectors(),
        manual(&[0b1111], &full_contribs)
    );
    assert_eq!(
        sealed_withheld.raw_for_vectors(),
        manual(&[0b1011], &withheld_contribs)
    );
    assert_ne!(
        sealed_full.raw_for_vectors(),
        sealed_withheld.raw_for_vectors()
    );
}

#[test]
fn crash_and_reorg_recovery_at_every_cutoff() {
    let (snap, mut state, mut barrier) = beacon_fixture();
    let v0 = member_id(&snap, 0);
    let v1 = member_id(&snap, 1);
    let prev = [0x55; 32];
    state
        .local_commit(&mut barrier, v0, reveal_hash(&[0x11; 32]).unwrap(), 0)
        .unwrap();

    // Crash after the commit persisted, before finalization: the restored
    // state forbids a DIFFERENT commit (no reselection after a crash).
    let mut restored = BeaconState::new(fixture_chain_id(), &snap);
    restored.restore(&barrier.records).unwrap();
    assert_eq!(
        restored.local_commit(&mut barrier, v0, reveal_hash(&[0x77; 32]).unwrap(), 0),
        Err(WitnessError::DuplicateCommit)
    );

    // Reorg past the commit finalization: rebuild, re-finalize, reveal —
    // then compare against a crash-after-reveal recovery.
    let mut a = BeaconState::new(fixture_chain_id(), &snap);
    a.restore(&barrier.records).unwrap();
    a.local_commit(&mut barrier, v1, reveal_hash(&[0x22; 32]).unwrap(), 0)
        .unwrap();
    a.finalize_commits().unwrap();
    a.local_reveal(&mut barrier, v0, [0x11; 32]).unwrap();
    a.local_reveal(&mut barrier, v1, [0x22; 32]).unwrap();
    let sealed_a = a.compute_mix(&prev).unwrap();

    // Crash after the reveals persisted: restore reproduces the same mix.
    let mut b = BeaconState::new(fixture_chain_id(), &snap);
    b.restore(&barrier.records).unwrap();
    b.finalize_commits().unwrap();
    let sealed_b = b.compute_mix(&prev).unwrap();
    assert_eq!(sealed_a, sealed_b);

    // A reveal record contradicting its commit is typed fatal.
    let mut bad = barrier.records.clone();
    bad[0].payload = [0xEA; 32]; // the commit no longer matches the reveal
    let mut c = BeaconState::new(fixture_chain_id(), &snap);
    assert_eq!(c.restore(&bad), Err(WitnessError::MalformedSafetyRecord));

    // A record bound to another epoch/chain/root is typed fatal.
    let mut foreign = barrier.records.clone();
    foreign[0].epoch = 9;
    let mut d = BeaconState::new(fixture_chain_id(), &snap);
    assert_eq!(
        d.restore(&foreign),
        Err(WitnessError::MalformedSafetyRecord)
    );
}

#[test]
fn randomness_is_sealed_until_the_carrying_certificate_finalizes() {
    let (snap, mut state, mut barrier) = beacon_fixture();
    let v0 = member_id(&snap, 0);
    state
        .local_commit(&mut barrier, v0, reveal_hash(&[0x11; 32]).unwrap(), 0)
        .unwrap();
    state.finalize_commits().unwrap();
    state.local_reveal(&mut barrier, v0, [0x11; 32]).unwrap();
    let sealed = state.compute_mix(&[0x55; 32]).unwrap();

    // Build a real finalization: genesis → cp1 → cp2 finalizes cp1.
    let chain = fixture_chain_id();
    let genesis = checkpoint(0, 0xA0);
    let registry = registry_for(&[1, 2]);
    let mut tracker = FinalityTracker::genesis(chain, genesis);
    let snap1 = registry.get(1).unwrap().clone();
    let cert1 = build_certificate(
        &quorum_votes(&snap1, genesis, checkpoint(1, 0xA1)),
        &chain,
        &snap1,
    )
    .unwrap();
    tracker
        .ingest_certificate(&cert1, &registry, &Always)
        .unwrap();
    let digest1 = certificate_digest(&cert1).unwrap();
    // cert1 justified but did NOT advance finalization: still sealed.
    assert_eq!(sealed.open(&tracker, &digest1), None);

    let snap2 = registry.get(2).unwrap().clone();
    let cert2 = build_certificate(
        &quorum_votes(&snap2, checkpoint(1, 0xA1), checkpoint(2, 0xA2)),
        &chain,
        &snap2,
    )
    .unwrap();
    tracker
        .ingest_certificate(&cert2, &registry, &Always)
        .unwrap();
    let digest2 = certificate_digest(&cert2).unwrap();
    // The finalizing (carrying) certificate opens the seal.
    assert_eq!(
        sealed.open(&tracker, &digest2),
        Some(sealed.raw_for_vectors())
    );
}

#[test]
fn commit_digest_binds_the_full_transcript_context() {
    let chain = fixture_chain_id();
    let root = fixture_snapshot(1, FIXTURE_WEIGHTS).root();
    let rh = reveal_hash(&[0x11; 32]).unwrap();
    let base = commit_digest(&chain, 1, &root, &[1; 32], &rh).unwrap();
    assert_ne!(
        commit_digest(&[0xEE; 32], 1, &root, &[1; 32], &rh).unwrap(),
        base
    );
    assert_ne!(
        commit_digest(&chain, 2, &root, &[1; 32], &rh).unwrap(),
        base
    );
    assert_ne!(
        commit_digest(&chain, 1, &[0xDD; 32], &[1; 32], &rh).unwrap(),
        base
    );
    assert_ne!(
        commit_digest(&chain, 1, &root, &[2; 32], &rh).unwrap(),
        base
    );
}

// ---------------------------------------------------------------------------
// §5 liveness
// ---------------------------------------------------------------------------

#[test]
fn inactivity_leak_applies_to_future_epochs_only() {
    let params = WitnessParamsV1::testnet_fixture(); // delay 4, 1% per epoch
    let bonds = fixture_bonds(&[1_000_000, 2_000_000]);
    let nonvoters: BTreeSet<[u8; 32]> = [bonds[0].validator_id].into();

    // Within the delay: identity.
    let same = leak_for_future_epoch(&bonds, &nonvoters, 4, &params).unwrap();
    assert_eq!(same, bonds);

    // Beyond the delay: only the nonvoter leaks, deterministically.
    let leaked = leak_for_future_epoch(&bonds, &nonvoters, 6, &params).unwrap();
    // Two leak epochs at 1%: 1_000_000 * 0.99 * 0.99 = 980_100.
    assert_eq!(leaked[0].bonded_noos, 980_100);
    assert_eq!(leaked[1].bonded_noos, 2_000_000);

    // FUTURE epochs only: an existing snapshot cannot be touched — the
    // leak is a pure candidate-list function and the snapshot type is
    // immutable. Its root is unchanged by any amount of leaking.
    let snap = fixture_snapshot(1, FIXTURE_WEIGHTS);
    let root_before = snap.root();
    let _ = leak_for_future_epoch(&bonds, &nonvoters, 100, &params).unwrap();
    assert_eq!(snap.root(), root_before);
}
