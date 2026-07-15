#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use noos_crypto::Keypair;

use super::artifact::{
    probe_branch, share_commitment, ARTIFACT_SHARE_BYTES, BONSAI_POSITION_BYTES,
};
use super::custody::*;

fn h(n: u8) -> Hash32 {
    [n; 32]
}

struct Fixture {
    policy: AvailabilityPolicyV2,
    profiles: BTreeMap<Hash32, CustodianProfileV2>,
    commitments: Vec<CustodyPositionCommitmentV2>,
    challenge: CustodyChallengeV2,
    probes: Vec<CustodyProbeResponseV2>,
    executors: Vec<ExecutorProfileV1>,
    executor_keys: BTreeMap<Hash32, Keypair>,
}

fn fixture() -> Fixture {
    let reviewer = Keypair::from_seed([200; 32]);
    let policy = AvailabilityPolicyV2::new(h(1), 10, 200, 50, 80).unwrap();
    let mut profiles = BTreeMap::new();
    let mut commitments = Vec::new();
    let mut custodian_keys = Vec::new();
    for position in 0..12_u8 {
        let key = Keypair::from_seed([20 + position; 32]);
        let control_expiry = if position == 3 { 135 } else { 190 };
        let profile = CustodianProfileV2::new(
            &key,
            &reviewer,
            h(30 + position),
            h(50 + position),
            h(80 + position / 3),
            h(100 + position / 3),
            64_000 + u32::from(position / 2),
            BONSAI_POSITION_BYTES + 1_000_000,
            10_000,
            10,
            control_expiry,
            190,
        )
        .unwrap();
        let commitment = CustodyPositionCommitmentV2::new(
            &key,
            policy.policy_id,
            profile.profile_id,
            position,
            h(120 + position),
            20,
            180,
        )
        .unwrap();
        profile.validate().unwrap();
        commitment.validate(&profile).unwrap();
        custodian_keys.push(key);
        profiles.insert(profile.profile_id, profile);
        commitments.push(commitment);
    }
    let challenge = CustodyChallengeV2::derive(&policy, &commitments, 77, h(2), 90).unwrap();
    let mut probes = Vec::new();
    for (commitment, key) in commitments.iter().zip(&custodian_keys) {
        let ch = challenge
            .positions
            .iter()
            .find(|x| x.position == commitment.position)
            .unwrap();
        let share = vec![commitment.position; ARTIFACT_SHARE_BYTES];
        let expected = share_commitment(ch.stripe, ch.position, &share).unwrap();
        let (leaf, branch) = probe_branch(ch.stripe, ch.position, &share, ch.probe_leaf).unwrap();
        let response = CustodyProbeResponseV2::new(
            key,
            challenge.challenge_id,
            commitment.commitment_id,
            commitment.custodian_profile_id,
            ch.position,
            ch.stripe,
            ch.probe_leaf,
            100,
            leaf,
            branch,
        )
        .unwrap();
        response
            .validate(
                &challenge,
                commitment,
                profiles.get(&commitment.custodian_profile_id).unwrap(),
                &expected,
            )
            .unwrap();
        probes.push(response);
    }
    let mut executors = Vec::new();
    let mut executor_keys = BTreeMap::new();
    for i in 0..10_u8 {
        let key = Keypair::from_seed([140 + i; 32]);
        let profile = ExecutorProfileV1::new(&key, h(150 + i), h(4), 7, true, true, 170).unwrap();
        profile.validate().unwrap();
        executor_keys.insert(profile.executor_id, key);
        executors.push(profile);
    }
    Fixture {
        policy,
        profiles,
        commitments,
        challenge,
        probes,
        executors,
        executor_keys,
    }
}

#[test]
fn certificate_selects_eight_requires_exactly_five_and_intersects_every_expiry() {
    let f = fixture();
    let mut cert = AvailabilityCertificateV2::unsigned(
        &f.policy,
        &f.challenge,
        &f.commitments,
        &f.profiles,
        &f.probes,
        &f.executors,
        h(5),
        7,
        100,
    )
    .unwrap();
    assert_eq!(cert.selected_executor_ids.len(), 8);
    assert_eq!(cert.valid_until, 135); // selected profile control-attestation expiry wins
    for id in cert.selected_executor_ids[..5].to_vec() {
        let profile = f.executors.iter().find(|p| p.executor_id == id).unwrap();
        cert.sign(profile, f.executor_keys.get(&id).unwrap())
            .unwrap();
    }
    assert_eq!(cert.signatures.len(), 5);
    cert.validate(
        &f.policy,
        &f.challenge,
        &f.commitments,
        &f.profiles,
        &f.probes,
        &f.executors,
        120,
    )
    .unwrap();

    let mut four = cert.clone();
    four.signatures.pop();
    assert_eq!(
        four.validate(
            &f.policy,
            &f.challenge,
            &f.commitments,
            &f.profiles,
            &f.probes,
            &f.executors,
            120
        ),
        Err(CustodyError::InvalidCertificate)
    );
    let sixth_id = cert.selected_executor_ids[5];
    cert.sign(
        f.executors
            .iter()
            .find(|p| p.executor_id == sixth_id)
            .unwrap(),
        f.executor_keys.get(&sixth_id).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cert.validate(
            &f.policy,
            &f.challenge,
            &f.commitments,
            &f.profiles,
            &f.probes,
            &f.executors,
            120
        ),
        Err(CustodyError::InvalidCertificate)
    );
}

#[test]
fn twelve_to_nine_to_eight_to_seven_state_law_and_control_dedup() {
    let f = fixture();
    assert_eq!(
        availability_state(&f.commitments, &f.profiles, 100),
        ArtifactAvailability::Schedulable
    );
    assert_eq!(
        availability_state(&f.commitments[..9], &f.profiles, 100),
        ArtifactAvailability::Schedulable
    );
    assert_eq!(
        availability_state(&f.commitments[..8], &f.profiles, 100),
        ArtifactAvailability::EmergencyRepairOnly
    );
    assert_eq!(
        availability_state(&f.commitments[..7], &f.profiles, 100),
        ArtifactAvailability::Unavailable
    );
    let mut duplicate = f.profiles.clone();
    let first_control = duplicate
        .get(&f.commitments[0].custodian_profile_id)
        .unwrap()
        .beneficial_control_root;
    duplicate
        .get_mut(&f.commitments[1].custodian_profile_id)
        .unwrap()
        .beneficial_control_root = first_control;
    assert_eq!(
        availability_state(&f.commitments[..9], &duplicate, 100),
        ArtifactAvailability::EmergencyRepairOnly
    );
}

#[test]
fn repair_handover_cannot_count_before_root_durability_probe_and_certificate() {
    let f = fixture();
    let order = RepairOrderV1::new(
        f.policy.policy_id,
        0,
        f.commitments[0].commitment_id,
        f.commitments[0].custodian_profile_id,
        [1, 2, 3, 4, 5, 6, 7, 8],
        160,
    )
    .unwrap();
    let mut handover = RepairHandoverV1::new(order);
    assert_eq!(handover.activate(), Err(CustodyError::InvalidRepair));
    handover
        .verify_root(f.commitments[0].position_root)
        .unwrap();
    handover.durable().unwrap();
    handover.commit(&f.commitments[0]).unwrap();
    handover.probe(&f.probes[0]).unwrap();

    let mut cert = AvailabilityCertificateV2::unsigned(
        &f.policy,
        &f.challenge,
        &f.commitments,
        &f.profiles,
        &f.probes,
        &f.executors,
        h(5),
        7,
        100,
    )
    .unwrap();
    for id in cert.selected_executor_ids[..5].to_vec() {
        cert.sign(
            f.executors.iter().find(|p| p.executor_id == id).unwrap(),
            f.executor_keys.get(&id).unwrap(),
        )
        .unwrap();
    }
    handover.certify(&cert).unwrap();
    handover.activate().unwrap();
    assert_eq!(handover.stage, HandoverStage::Live);
}
