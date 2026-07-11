#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use super::*;

fn h(v: u8) -> [u8; 32] {
    [v; 32]
}
struct V {
    hash: Hash32,
    family: Hash32,
    verdict: bool,
}
impl CompleteTupleVerifier for V {
    fn verifier_hash(&self) -> Hash32 {
        self.hash
    }
    fn verifier_family(&self) -> Hash32 {
        self.family
    }
    fn verify(
        &self,
        _: &SuiteEntry,
        _tuple: &[u8],
        proof: &[u8],
        root: Hash32,
    ) -> Result<bool, VerificationError> {
        Ok(self.verdict && root == *blake3::hash(proof).as_bytes() && proof == b"valid")
    }
}
fn fixture() -> (UmbraState, EncryptedTransitionV1, V, V) {
    let key = RegistryKey {
        suite_id: SuiteId(h(1)),
        proof_profile_id: ProofProfileId(h(2)),
        verifier_version: 1,
        verifier_hash: h(3),
        first_key_epoch: KeyEpoch(4),
        last_key_epoch: KeyEpoch(8),
    };
    let entry = SuiteEntry {
        key: key.clone(),
        schema_hash: h(4),
        verification_key_hash: h(5),
        parameter_hash: h(6),
        max_proof_bytes: 64,
        max_inputs: 4,
        max_nullifiers: 4,
        max_commitments: 4,
        max_resource: ResourceVector {
            bytes: 100,
            verification: 100,
            reads: 4,
            writes: 4,
        },
        verification_cost: 7,
        activation_height: 5,
        retirement_height: None,
        enabled: true,
        kind: SuiteKind::Base,
        exit_relation: Some(ExitRelation {
            proof_profile_id: ProofProfileId(h(9)),
            circuit_root: h(10),
            activated_at: 5,
        }),
    };
    let fiber = UmbraFiber {
        fiber_id: FiberId(h(11)),
        suite_id: key.suite_id,
        owner_policy_root: h(12),
        ciphertext_root: h(13),
        circuit_root: h(14),
        lineage_root: h(15),
        rights_root: h(16),
        privacy_budget: 10,
        key_epoch: KeyEpoch(4),
        realized_head: None,
        branch_set_root: h(17),
        version: 0,
    };
    let mut s = UmbraState::default();
    s.register_suite(entry).unwrap();
    s.insert_fiber(fiber.clone()).unwrap();
    let mut tx = EncryptedTransitionV1 {
        fiber_id: fiber.fiber_id,
        suite_id: fiber.suite_id,
        previous_version: 0,
        previous_ciphertext_root: fiber.ciphertext_root,
        previous_circuit_root: fiber.circuit_root,
        program_manifest_root: h(18),
        ordered_input_roots: vec![h(19)],
        new_ciphertext_root: h(20),
        new_circuit_root: h(21),
        new_lineage_root: h(22),
        key_epoch: KeyEpoch(4),
        rights_root: fiber.rights_root,
        privacy_budget_debit: 2,
        read_nullifiers: vec![Nullifier32(h(23))],
        write_commitments: vec![Commitment32(h(24))],
        resource_vector: ResourceVector {
            bytes: 5,
            verification: 6,
            reads: 1,
            writes: 1,
        },
        proof_profile_id: key.proof_profile_id,
        verifier_version: 1,
        verifier_hash: h(3),
        proof_root: [0; 32],
        proof: b"valid".to_vec(),
        authorization: vec![1],
    };
    tx.proof_root = *blake3::hash(&tx.proof).as_bytes();
    (
        s,
        tx,
        V {
            hash: h(3),
            family: h(30),
            verdict: true,
        },
        V {
            hash: h(3),
            family: h(31),
            verdict: true,
        },
    )
}
#[test]
fn transition_is_atomic_and_updates_dedicated_sets() {
    let (mut s, tx, a, b) = fixture();
    let before = (s.commitment_root(), s.nullifier_root());
    s.apply(&tx, 5, [&a, &b]).unwrap();
    assert!(s.contains_nullifier(tx.read_nullifiers[0]));
    assert_ne!(before, (s.commitment_root(), s.nullifier_root()));
    assert_eq!(s.fiber(tx.fiber_id).unwrap().version, 1);
}
#[test]
fn nullifier_replay_rejects_without_change() {
    let (mut s, tx, a, b) = fixture();
    s.apply(&tx, 5, [&a, &b]).unwrap();
    let roots = (s.commitment_root(), s.nullifier_root());
    assert_eq!(s.apply(&tx, 5, [&a, &b]), Err(UmbraError::PriorState));
    assert_eq!(roots, (s.commitment_root(), s.nullifier_root()));
}
#[test]
fn malformed_proof_is_atomic() {
    let (mut s, mut tx, a, b) = fixture();
    tx.proof.clear();
    let roots = (s.commitment_root(), s.nullifier_root());
    assert_eq!(s.apply(&tx, 5, [&a, &b]), Err(UmbraError::Bounds));
    assert_eq!(roots, (s.commitment_root(), s.nullifier_root()));
}
#[test]
fn wrong_epoch_is_atomic() {
    let (mut s, mut tx, a, b) = fixture();
    tx.key_epoch = KeyEpoch(99);
    let roots = (s.commitment_root(), s.nullifier_root());
    assert_eq!(s.apply(&tx, 5, [&a, &b]), Err(UmbraError::WrongKeyEpoch));
    assert_eq!(roots, (s.commitment_root(), s.nullifier_root()));
}
#[test]
fn verifier_disagreement_rejects() {
    let (mut s, tx, a, _) = fixture();
    let no = V {
        hash: h(3),
        family: h(31),
        verdict: false,
    };
    assert_eq!(
        s.apply(&tx, 5, [&a, &no]),
        Err(UmbraError::VerifierDisagreement)
    );
}
#[test]
fn disable_preserves_predeclared_exit() {
    let (mut s, tx, a, b) = fixture();
    let id = tx.fiber_id;
    s.disable_suite(tx.suite_id, 6).unwrap();
    assert_eq!(s.apply(&tx, 6, [&a, &b]), Err(UmbraError::SuiteDisabled));
    assert!(s.exit_disabled(id, ProofProfileId(h(9)), h(10), 6).is_ok());
}
#[test]
fn disabled_suite_retains_historical_verification() {
    let (mut s, tx, a, b) = fixture();
    s.disable_suite(tx.suite_id, 6).unwrap();
    assert!(s.verify_historical(&tx, [&a, &b]).is_ok());
}

#[test]
fn invented_exit_rejects() {
    let (mut s, tx, _, _) = fixture();
    s.disable_suite(tx.suite_id, 6).unwrap();
    assert_eq!(
        s.exit_disabled(tx.fiber_id, ProofProfileId(h(8)), h(10), 6),
        Err(UmbraError::ExitMismatch)
    );
}
#[test]
fn assurance_substitution_rejects() {
    assert!(assurance_relation(
        PrivacyProfile::P3DeepSealed,
        ExecutionMode::BesiSplitPrototype,
        Assurance::AssuredSplit
    ));
    assert!(!assurance_relation(
        PrivacyProfile::P3DeepSealed,
        ExecutionMode::BesiSplitPrototype,
        Assurance::Proven
    ));
    assert!(!assurance_relation(
        PrivacyProfile::P1Attested,
        ExecutionMode::Tee,
        Assurance::Proven
    ));
}
#[test]
fn experimental_suites_cannot_enable() {
    let (mut s, _, _, _) = fixture();
    let mut e = s.registry.values().next().unwrap().clone();
    e.key.suite_id = SuiteId(h(77));
    e.kind = SuiteKind::P2CompleteInferenceExperimental;
    e.enabled = true;
    assert_eq!(s.register_suite(e), Err(UmbraError::SuiteDisabled));
}
#[test]
fn mainnet_secret_fixture_rejects() {
    let d = WorkloadDkg {
        suite_id: SuiteId(h(1)),
        epoch: KeyEpoch(1),
        participant_keys: vec![h(2), h(3)],
        threshold: 2,
        transcript_root: h(4),
        contains_secret_fixture: true,
    };
    assert_eq!(
        d.validate(NetworkClass::Mainnet),
        Err(UmbraError::KeyLifecycle)
    );
    assert!(d.validate(NetworkClass::TestNetwork).is_ok());
}
#[test]
fn key_rotation_is_sequential() {
    let r = KeyRotation {
        suite_id: SuiteId(h(1)),
        from: KeyEpoch(4),
        to: KeyEpoch(5),
        transcript_root: h(2),
        migration_relation: ProofProfileId(h(3)),
    };
    assert!(r.validate().is_ok());
    let mut bad = r;
    bad.to = KeyEpoch(6);
    assert_eq!(bad.validate(), Err(UmbraError::KeyLifecycle));
}
#[test]
fn owner_derivation_separates_fiber_and_epoch() {
    let m = h(8);
    assert_ne!(
        derive_owner_key(&m, FiberId(h(1)), KeyEpoch(1)).unwrap(),
        derive_owner_key(&m, FiberId(h(2)), KeyEpoch(1)).unwrap()
    );
    assert_ne!(
        derive_owner_key(&m, FiberId(h(1)), KeyEpoch(1)).unwrap(),
        derive_owner_key(&m, FiberId(h(1)), KeyEpoch(2)).unwrap()
    );
}
#[test]
fn owner_backup_roundtrip_and_context_tamper_reject() {
    let recovery = h(40);
    let owner = h(41);
    let backup = create_owner_backup(
        &recovery,
        FiberId(h(42)),
        KeyEpoch(7),
        &owner,
        h(43),
        [44; 12],
    )
    .unwrap();
    assert_eq!(restore_owner_backup(&recovery, &backup).unwrap(), owner);
    let mut rebound = backup;
    rebound.key_epoch = KeyEpoch(8);
    assert_eq!(
        restore_owner_backup(&recovery, &rebound),
        Err(UmbraError::KeyLifecycle)
    );
}

#[test]
fn migration_binds_commitment_rights_and_relation() {
    let migration = Migration {
        fiber_id: FiberId(h(1)),
        old_suite: SuiteId(h(2)),
        new_suite: SuiteId(h(3)),
        old_epoch: KeyEpoch(4),
        new_epoch: KeyEpoch(5),
        plaintext_commitment: Commitment32(h(6)),
        rights_root: h(7),
        relation: ProofProfileId(h(8)),
    };
    assert!(migration.validate().is_ok());
    let mut invalid = migration;
    invalid.rights_root = [0; 32];
    assert_eq!(invalid.validate(), Err(UmbraError::KeyLifecycle));
}
