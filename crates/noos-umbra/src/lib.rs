//! Umbra encrypted causal fibers. Consensus state stores commitments and roots, never plaintext
//! or a network-wide decrypt/bootstrap key.
#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

macro_rules! id32 {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash)]
        pub struct $name(pub [u8; 32]);
    };
}
id32!(Commitment32);
id32!(Nullifier32);
id32!(SuiteId);
id32!(ProofProfileId);
id32!(FiberId);

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct KeyEpoch(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyProfile {
    P0Open,
    P1Attested,
    P2SealedWitness,
    P3DeepSealed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Open,
    Tee,
    CompletePrivateRelation,
    BesiSplitPrototype,
    Malicious3PcDisabled,
    HfheDisabled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assurance {
    P0Open,
    AssuredTee,
    Proven,
    AssuredSplit,
}

impl Assurance {
    pub const P0_OPEN: &'static str = "P0_OPEN";
    pub const ASSURED_TEE: &'static str = "ASSURED_TEE";
    pub const PROVEN: &'static str = "PROVEN";
    pub const ASSURED_SPLIT: &'static str = "ASSURED_SPLIT";
}

#[must_use]
pub fn assurance_relation(
    profile: PrivacyProfile,
    mode: ExecutionMode,
    assurance: Assurance,
) -> bool {
    matches!(
        (profile, mode, assurance),
        (
            PrivacyProfile::P0Open,
            ExecutionMode::Open,
            Assurance::P0Open
        ) | (
            PrivacyProfile::P1Attested,
            ExecutionMode::Tee,
            Assurance::AssuredTee
        ) | (
            PrivacyProfile::P2SealedWitness,
            ExecutionMode::CompletePrivateRelation,
            Assurance::Proven
        ) | (
            PrivacyProfile::P3DeepSealed,
            ExecutionMode::BesiSplitPrototype,
            Assurance::AssuredSplit
        )
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UmbraFiber {
    pub fiber_id: FiberId,
    pub suite_id: SuiteId,
    pub owner_policy_root: Hash32,
    pub ciphertext_root: Hash32,
    pub circuit_root: Hash32,
    pub lineage_root: Hash32,
    pub rights_root: Hash32,
    pub privacy_budget: u64,
    pub key_epoch: KeyEpoch,
    pub realized_head: Option<Commitment32>,
    pub branch_set_root: Hash32,
    pub version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceVector {
    pub bytes: u64,
    pub verification: u64,
    pub reads: u32,
    pub writes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedTransitionV1 {
    pub fiber_id: FiberId,
    pub suite_id: SuiteId,
    pub previous_version: u64,
    pub previous_ciphertext_root: Hash32,
    pub previous_circuit_root: Hash32,
    pub program_manifest_root: Hash32,
    pub ordered_input_roots: Vec<Hash32>,
    pub new_ciphertext_root: Hash32,
    pub new_circuit_root: Hash32,
    pub new_lineage_root: Hash32,
    pub key_epoch: KeyEpoch,
    pub rights_root: Hash32,
    pub privacy_budget_debit: u64,
    pub read_nullifiers: Vec<Nullifier32>,
    pub write_commitments: Vec<Commitment32>,
    pub resource_vector: ResourceVector,
    pub proof_profile_id: ProofProfileId,
    pub verifier_version: u32,
    pub verifier_hash: Hash32,
    pub proof_root: Hash32,
    pub proof: Vec<u8>,
    pub authorization: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RegistryKey {
    pub suite_id: SuiteId,
    pub proof_profile_id: ProofProfileId,
    pub verifier_version: u32,
    pub verifier_hash: Hash32,
    pub first_key_epoch: KeyEpoch,
    pub last_key_epoch: KeyEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitRelation {
    pub proof_profile_id: ProofProfileId,
    pub circuit_root: Hash32,
    pub activated_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuiteKind {
    Base,
    P1TeeExperimental,
    P2CompleteInferenceExperimental,
    BesiExperimental,
    Malicious3PcDisabled,
    HfheDisabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuiteEntry {
    pub key: RegistryKey,
    pub schema_hash: Hash32,
    pub verification_key_hash: Hash32,
    pub parameter_hash: Hash32,
    pub max_proof_bytes: u32,
    pub max_inputs: u32,
    pub max_nullifiers: u32,
    pub max_commitments: u32,
    pub max_resource: ResourceVector,
    pub verification_cost: u64,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub enabled: bool,
    pub kind: SuiteKind,
    pub exit_relation: Option<ExitRelation>,
}

impl SuiteEntry {
    fn accepts_epoch(&self, epoch: KeyEpoch) -> bool {
        epoch >= self.key.first_key_epoch && epoch <= self.key.last_key_epoch
    }
    fn write_enabled(&self, height: u64) -> bool {
        self.enabled
            && height >= self.activation_height
            && self
                .retirement_height
                .is_none_or(|retirement| height < retirement)
            && matches!(self.kind, SuiteKind::Base)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UmbraError {
    UnknownSuite,
    SuiteDisabled,
    Bounds,
    PriorState,
    Unauthorized,
    DuplicateNullifier,
    DuplicateCommitment,
    Rights,
    Budget,
    Resources,
    WrongKeyEpoch,
    MalformedProof,
    VerifierDisagreement,
    InvalidProof,
    ExitNotPredeclared,
    ExitMismatch,
    KeyLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationError;

pub trait CompleteTupleVerifier {
    fn verifier_hash(&self) -> Hash32;
    /// Stable identifier for an independently implemented verifier family.
    fn verifier_family(&self) -> Hash32;
    fn verify(
        &self,
        entry: &SuiteEntry,
        tuple: &[u8],
        proof: &[u8],
        proof_root: Hash32,
    ) -> Result<bool, VerificationError>;
}

#[derive(Clone, Debug, Default)]
pub struct UmbraState {
    fibers: BTreeMap<FiberId, UmbraFiber>,
    commitments: BTreeSet<Commitment32>,
    nullifiers: BTreeSet<Nullifier32>,
    registry: BTreeMap<RegistryKey, SuiteEntry>,
}

impl UmbraState {
    pub fn register_suite(&mut self, entry: SuiteEntry) -> Result<(), UmbraError> {
        if entry.key.first_key_epoch > entry.key.last_key_epoch
            || entry.max_proof_bytes == 0
            || entry.max_inputs == 0
            || entry.schema_hash == [0; 32]
            || entry.verification_key_hash == [0; 32]
            || entry.parameter_hash == [0; 32]
        {
            return Err(UmbraError::Bounds);
        }
        if !matches!(entry.kind, SuiteKind::Base) && entry.enabled {
            return Err(UmbraError::SuiteDisabled);
        }
        if self.registry.insert(entry.key.clone(), entry).is_some() {
            return Err(UmbraError::Bounds);
        }
        Ok(())
    }
    pub fn insert_fiber(&mut self, fiber: UmbraFiber) -> Result<(), UmbraError> {
        if !self
            .registry
            .values()
            .any(|e| e.key.suite_id == fiber.suite_id && e.accepts_epoch(fiber.key_epoch))
        {
            return Err(UmbraError::UnknownSuite);
        }
        if self.fibers.insert(fiber.fiber_id, fiber).is_some() {
            return Err(UmbraError::PriorState);
        }
        Ok(())
    }
    pub fn fiber(&self, id: FiberId) -> Option<&UmbraFiber> {
        self.fibers.get(&id)
    }
    pub fn contains_nullifier(&self, n: Nullifier32) -> bool {
        self.nullifiers.contains(&n)
    }
    pub fn commitment_root(&self) -> Hash32 {
        set_root(
            b"NOOS/UMBRA/COMMITMENT-ACCUMULATOR/V1",
            self.commitments.iter().map(|x| x.0),
        )
    }
    pub fn nullifier_root(&self) -> Hash32 {
        set_root(
            b"NOOS/UMBRA/GLOBAL-NULLIFIERS/V1",
            self.nullifiers.iter().map(|x| x.0),
        )
    }

    pub fn disable_suite(&mut self, suite: SuiteId, at_height: u64) -> Result<(), UmbraError> {
        let mut found = false;
        for entry in self
            .registry
            .values_mut()
            .filter(|e| e.key.suite_id == suite)
        {
            found = true;
            entry.enabled = false;
            entry.retirement_height = Some(at_height);
        }
        if found {
            Ok(())
        } else {
            Err(UmbraError::UnknownSuite)
        }
    }

    pub fn apply(
        &mut self,
        tx: &EncryptedTransitionV1,
        height: u64,
        verifiers: [&dyn CompleteTupleVerifier; 2],
    ) -> Result<(), UmbraError> {
        // 1 activation and canonical bounds; exact registry key lookup.
        let key_match = self
            .registry
            .iter()
            .find(|(key, _)| {
                key.suite_id == tx.suite_id
                    && key.proof_profile_id == tx.proof_profile_id
                    && key.verifier_version == tx.verifier_version
                    && key.verifier_hash == tx.verifier_hash
                    && tx.key_epoch >= key.first_key_epoch
                    && tx.key_epoch <= key.last_key_epoch
            })
            .map(|(_, value)| value);
        let entry = key_match.ok_or_else(|| {
            if self.registry.keys().any(|k| k.suite_id == tx.suite_id) {
                UmbraError::WrongKeyEpoch
            } else {
                UmbraError::UnknownSuite
            }
        })?;
        if !entry.write_enabled(height) {
            return Err(UmbraError::SuiteDisabled);
        }
        if tx.proof.is_empty()
            || tx.proof.len() > entry.max_proof_bytes as usize
            || tx.ordered_input_roots.len() > entry.max_inputs as usize
            || tx.read_nullifiers.len() > entry.max_nullifiers as usize
            || tx.write_commitments.len() > entry.max_commitments as usize
            || !strictly_unique(&tx.read_nullifiers)
            || !strictly_unique(&tx.write_commitments)
        {
            return Err(UmbraError::Bounds);
        }
        // 2 prior state.
        let fiber = self
            .fibers
            .get(&tx.fiber_id)
            .ok_or(UmbraError::PriorState)?;
        if fiber.suite_id != tx.suite_id
            || fiber.version != tx.previous_version
            || fiber.ciphertext_root != tx.previous_ciphertext_root
            || fiber.circuit_root != tx.previous_circuit_root
            || fiber.key_epoch != tx.key_epoch
        {
            return Err(UmbraError::PriorState);
        }
        // 3 authorization.
        if tx.authorization.is_empty() {
            return Err(UmbraError::Unauthorized);
        }
        // 4 freshness and global uniqueness.
        if tx
            .read_nullifiers
            .iter()
            .any(|n| self.nullifiers.contains(n))
        {
            return Err(UmbraError::DuplicateNullifier);
        }
        if tx
            .write_commitments
            .iter()
            .any(|c| self.commitments.contains(c))
        {
            return Err(UmbraError::DuplicateCommitment);
        }
        // 5 rights and budget.
        if tx.rights_root != fiber.rights_root {
            return Err(UmbraError::Rights);
        }
        let new_budget = fiber
            .privacy_budget
            .checked_sub(tx.privacy_budget_debit)
            .ok_or(UmbraError::Budget)?;
        // 6 resources.
        if tx.resource_vector.bytes > entry.max_resource.bytes
            || tx.resource_vector.verification > entry.max_resource.verification
            || tx.resource_vector.reads > entry.max_resource.reads
            || tx.resource_vector.writes > entry.max_resource.writes
        {
            return Err(UmbraError::Resources);
        }
        // 7 proof of the complete tuple, checked by two independent implementations.
        verify_pair(entry, tx, verifiers)?;
        // 8 atomic candidate update: all fallible work precedes mutation.
        let mut updated = fiber.clone();
        updated.version = updated
            .version
            .checked_add(1)
            .ok_or(UmbraError::PriorState)?;
        updated.ciphertext_root = tx.new_ciphertext_root;
        updated.circuit_root = tx.new_circuit_root;
        updated.lineage_root = tx.new_lineage_root;
        updated.privacy_budget = new_budget;
        for n in &tx.read_nullifiers {
            self.nullifiers.insert(*n);
        }
        for c in &tx.write_commitments {
            self.commitments.insert(*c);
        }
        self.fibers.insert(tx.fiber_id, updated);
        Ok(())
    }

    /// Verifies an already-finalized transition against the retained historical registry entry.
    /// Suite disable/retirement is intentionally ignored; no state is mutated.
    pub fn verify_historical(
        &self,
        tx: &EncryptedTransitionV1,
        verifiers: [&dyn CompleteTupleVerifier; 2],
    ) -> Result<(), UmbraError> {
        let entry = self
            .registry
            .values()
            .find(|entry| {
                entry.key.suite_id == tx.suite_id
                    && entry.key.proof_profile_id == tx.proof_profile_id
                    && entry.key.verifier_version == tx.verifier_version
                    && entry.key.verifier_hash == tx.verifier_hash
                    && entry.accepts_epoch(tx.key_epoch)
            })
            .ok_or(UmbraError::UnknownSuite)?;
        verify_pair(entry, tx, verifiers)
    }

    pub fn exit_disabled(
        &mut self,
        fiber_id: FiberId,
        proof_profile: ProofProfileId,
        circuit_root: Hash32,
        height: u64,
    ) -> Result<UmbraFiber, UmbraError> {
        let fiber = self.fibers.get(&fiber_id).ok_or(UmbraError::PriorState)?;
        let relation = self
            .registry
            .values()
            .find(|e| e.key.suite_id == fiber.suite_id && !e.enabled)
            .and_then(|e| e.exit_relation.as_ref())
            .ok_or(UmbraError::ExitNotPredeclared)?;
        if relation.activated_at > height
            || relation.proof_profile_id != proof_profile
            || relation.circuit_root != circuit_root
        {
            return Err(UmbraError::ExitMismatch);
        }
        self.fibers.remove(&fiber_id).ok_or(UmbraError::PriorState)
    }
}

fn verify_pair(
    entry: &SuiteEntry,
    tx: &EncryptedTransitionV1,
    verifiers: [&dyn CompleteTupleVerifier; 2],
) -> Result<(), UmbraError> {
    if verifiers[0].verifier_hash() != entry.key.verifier_hash
        || verifiers[1].verifier_hash() != entry.key.verifier_hash
    {
        return Err(UmbraError::MalformedProof);
    }
    if verifiers[0].verifier_family() == verifiers[1].verifier_family() {
        return Err(UmbraError::VerifierDisagreement);
    }
    let tuple = complete_tuple(tx);
    let a = verifiers[0]
        .verify(entry, &tuple, &tx.proof, tx.proof_root)
        .map_err(|_| UmbraError::MalformedProof)?;
    let b = verifiers[1]
        .verify(entry, &tuple, &tx.proof, tx.proof_root)
        .map_err(|_| UmbraError::MalformedProof)?;
    if a != b {
        return Err(UmbraError::VerifierDisagreement);
    }
    if !a {
        return Err(UmbraError::InvalidProof);
    }
    Ok(())
}

fn strictly_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|w| w[0] < w[1])
}
fn set_root<I: Iterator<Item = [u8; 32]>>(domain: &[u8], items: I) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for x in items {
        h.update(&x);
    }
    *h.finalize().as_bytes()
}
fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v);
}

/// Canonical complete proof public input; every transition field except proof bytes is bound.
#[must_use]
pub fn complete_tuple(tx: &EncryptedTransitionV1) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(b"NOOS/UMBRA/ENCRYPTED-TRANSITION/V1");
    o.extend_from_slice(&tx.fiber_id.0);
    o.extend_from_slice(&tx.suite_id.0);
    o.extend_from_slice(&tx.previous_version.to_le_bytes());
    for h in [
        tx.previous_ciphertext_root,
        tx.previous_circuit_root,
        tx.program_manifest_root,
    ] {
        o.extend_from_slice(&h);
    }
    o.extend_from_slice(&(tx.ordered_input_roots.len() as u32).to_le_bytes());
    for h in &tx.ordered_input_roots {
        o.extend_from_slice(h);
    }
    for h in [
        tx.new_ciphertext_root,
        tx.new_circuit_root,
        tx.new_lineage_root,
    ] {
        o.extend_from_slice(&h);
    }
    o.extend_from_slice(&tx.key_epoch.0.to_le_bytes());
    o.extend_from_slice(&tx.rights_root);
    o.extend_from_slice(&tx.privacy_budget_debit.to_le_bytes());
    o.extend_from_slice(&(tx.read_nullifiers.len() as u32).to_le_bytes());
    for n in &tx.read_nullifiers {
        o.extend_from_slice(&n.0);
    }
    o.extend_from_slice(&(tx.write_commitments.len() as u32).to_le_bytes());
    for c in &tx.write_commitments {
        o.extend_from_slice(&c.0);
    }
    o.extend_from_slice(&tx.resource_vector.bytes.to_le_bytes());
    o.extend_from_slice(&tx.resource_vector.verification.to_le_bytes());
    o.extend_from_slice(&tx.resource_vector.reads.to_le_bytes());
    o.extend_from_slice(&tx.resource_vector.writes.to_le_bytes());
    o.extend_from_slice(&tx.proof_profile_id.0);
    o.extend_from_slice(&tx.verifier_version.to_le_bytes());
    o.extend_from_slice(&tx.verifier_hash);
    o.extend_from_slice(&tx.proof_root);
    put_vec(&mut o, &tx.authorization);
    o
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkClass {
    Mainnet,
    TestNetwork,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerKeyBackup {
    pub fiber_id: FiberId,
    pub key_epoch: KeyEpoch,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
    pub encrypted_backup: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadDkg {
    pub suite_id: SuiteId,
    pub epoch: KeyEpoch,
    pub participant_keys: Vec<[u8; 32]>,
    pub threshold: u16,
    pub transcript_root: Hash32,
    pub contains_secret_fixture: bool,
}
impl WorkloadDkg {
    pub fn validate(&self, network: NetworkClass) -> Result<(), UmbraError> {
        if self.threshold < 2
            || usize::from(self.threshold) > self.participant_keys.len()
            || self.transcript_root == [0; 32]
            || (network == NetworkClass::Mainnet && self.contains_secret_fixture)
        {
            return Err(UmbraError::KeyLifecycle);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotation {
    pub suite_id: SuiteId,
    pub from: KeyEpoch,
    pub to: KeyEpoch,
    pub transcript_root: Hash32,
    pub migration_relation: ProofProfileId,
}
impl KeyRotation {
    pub fn validate(&self) -> Result<(), UmbraError> {
        if self.to.0 != self.from.0.checked_add(1).ok_or(UmbraError::KeyLifecycle)?
            || self.transcript_root == [0; 32]
        {
            Err(UmbraError::KeyLifecycle)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revocation {
    pub suite_id: SuiteId,
    pub epoch: KeyEpoch,
    pub effective_height: u64,
    pub compromise_evidence_root: Hash32,
}

impl Revocation {
    pub fn validate(&self) -> Result<(), UmbraError> {
        if self.effective_height == 0 || self.compromise_evidence_root == [0; 32] {
            Err(UmbraError::KeyLifecycle)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Migration {
    pub fiber_id: FiberId,
    pub old_suite: SuiteId,
    pub new_suite: SuiteId,
    pub old_epoch: KeyEpoch,
    pub new_epoch: KeyEpoch,
    pub plaintext_commitment: Commitment32,
    pub rights_root: Hash32,
    pub relation: ProofProfileId,
}

impl Migration {
    pub fn validate(&self) -> Result<(), UmbraError> {
        if self.old_suite == self.new_suite && self.old_epoch == self.new_epoch {
            return Err(UmbraError::KeyLifecycle);
        }
        if self.plaintext_commitment == Commitment32([0; 32])
            || self.rights_root == [0; 32]
            || self.relation == ProofProfileId([0; 32])
        {
            return Err(UmbraError::KeyLifecycle);
        }
        Ok(())
    }
}

pub fn create_owner_backup(
    recovery_key: &[u8; 32],
    fiber_id: FiberId,
    key_epoch: KeyEpoch,
    owner_key: &[u8; 32],
    salt: [u8; 32],
    nonce: [u8; 12],
) -> Result<OwnerKeyBackup, UmbraError> {
    let key = backup_key(recovery_key, fiber_id, key_epoch, salt)?;
    let mut aad = b"NOOS/UMBRA/OWNER-BACKUP/V1".to_vec();
    aad.extend_from_slice(&fiber_id.0);
    aad.extend_from_slice(&key_epoch.0.to_le_bytes());
    let encrypted_backup = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: owner_key,
                aad: &aad,
            },
        )
        .map_err(|_| UmbraError::KeyLifecycle)?;
    Ok(OwnerKeyBackup {
        fiber_id,
        key_epoch,
        salt,
        nonce,
        encrypted_backup,
    })
}

pub fn restore_owner_backup(
    recovery_key: &[u8; 32],
    backup: &OwnerKeyBackup,
) -> Result<[u8; 32], UmbraError> {
    let key = backup_key(recovery_key, backup.fiber_id, backup.key_epoch, backup.salt)?;
    let mut aad = b"NOOS/UMBRA/OWNER-BACKUP/V1".to_vec();
    aad.extend_from_slice(&backup.fiber_id.0);
    aad.extend_from_slice(&backup.key_epoch.0.to_le_bytes());
    let plaintext = ChaCha20Poly1305::new((&key).into())
        .decrypt(
            Nonce::from_slice(&backup.nonce),
            Payload {
                msg: &backup.encrypted_backup,
                aad: &aad,
            },
        )
        .map_err(|_| UmbraError::KeyLifecycle)?;
    plaintext.try_into().map_err(|_| UmbraError::KeyLifecycle)
}

fn backup_key(
    recovery_key: &[u8; 32],
    fiber_id: FiberId,
    key_epoch: KeyEpoch,
    salt: [u8; 32],
) -> Result<[u8; 32], UmbraError> {
    let hk = Hkdf::<Sha256>::new(Some(&salt), recovery_key);
    let mut info = b"NOOS/UMBRA/OWNER-BACKUP-KEY/V1".to_vec();
    info.extend_from_slice(&fiber_id.0);
    info.extend_from_slice(&key_epoch.0.to_le_bytes());
    let mut key = [0; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| UmbraError::KeyLifecycle)?;
    Ok(key)
}

pub fn derive_owner_key(
    master: &[u8; 32],
    fiber: FiberId,
    epoch: KeyEpoch,
) -> Result<[u8; 32], UmbraError> {
    let hk = Hkdf::<Sha256>::new(Some(b"NOOS/UMBRA/OWNER-DERIVE/V1"), master);
    let mut out = [0; 32];
    let mut info = [0u8; 40];
    info[..32].copy_from_slice(&fiber.0);
    info[32..].copy_from_slice(&epoch.0.to_le_bytes());
    hk.expand(&info, &mut out)
        .map_err(|_| UmbraError::KeyLifecycle)?;
    Ok(out)
}

#[cfg(test)]
mod tests;
