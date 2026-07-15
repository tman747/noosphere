//! Proof-carrying refresh dispatch precursor for `M-PROOF-CARRYING-REFRESH`.
//!
//! Every dispatched refresh binds source/destination suites, both epochs, both rights policies,
//! ciphertext commitments, job, transcript, and a fresh challenge. The only local prover is a
//! symmetric audit-tag stand-in over a toy Z/(2^64) LWE-shaped negative-control ciphertext. It
//! is neither the Octra-derived F_(2^127-1) suite nor a zero-knowledge proof, so both registry
//! rows remain PARTIAL and disabled.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub type Hash32 = [u8; 32];
pub const REFRESH_SUITE: Hash32 = *b"NOOS/HFHE-REFRESH-SKELETON/V1\0\0\0";
pub const LATTICE_DIM: usize = 8;
pub const DELTA: u64 = 1 << 32;
pub const NOISE_CEILING: u64 = DELTA / 2;
pub const BASE_NOISE: u64 = 1 << 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefreshError {
    WrongEpoch,
    KeyRetired,
    BudgetExhausted,
    NoiseOverflow,
    MissingProof,
    ProofForged,
    PlaintextMismatch,
    CommitMismatch,
    EpochNotMonotone,
    RightsMismatch,
    SuiteMismatch,
    PolicyMismatch,
    ContextMismatch,
    ChallengeMissing,
    ChallengeStale,
    ChallengeReplay,
    Rollback,
    UnsupportedDispatch,
}

#[derive(Eq, PartialEq)]
pub struct SecretKey {
    pub key_epoch: u64,
    s: [u64; LATTICE_DIM],
    retired: bool,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretKey")
            .field("key_epoch", &self.key_epoch)
            .field("retired", &self.retired)
            .field("material", &"REDACTED")
            .finish()
    }
}

impl SecretKey {
    pub fn retire(&mut self) {
        self.s.fill(0);
        self.retired = true;
    }

    #[must_use]
    pub fn is_zeroized(&self) -> bool {
        self.retired && self.s.iter().all(|word| *word == 0)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.s.fill(0);
        self.retired = true;
    }
}

#[must_use]
pub fn derive_key(master: &Hash32, key_epoch: u64) -> SecretKey {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"NOOS/HFHE-NEGATIVE-CONTROL/KEY/V1");
    hasher.update(&key_epoch.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut s = [0u64; LATTICE_DIM];
    let mut buf = [0u8; 8];
    for slot in &mut s {
        reader.fill(&mut buf);
        *slot = u64::from_le_bytes(buf);
    }
    SecretKey {
        key_epoch,
        s,
        retired: false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    pub a: [u64; LATTICE_DIM],
    pub b: u64,
    pub key_epoch: u64,
    pub logical_rows: u32,
    pub logical_cols: u32,
    pub noise_bound: u64,
}

fn inner(a: &[u64; LATTICE_DIM], s: &[u64; LATTICE_DIM]) -> u64 {
    a.iter()
        .zip(s)
        .fold(0u64, |acc, (x, y)| acc.wrapping_add(x.wrapping_mul(*y)))
}

fn mask_vector(master: &Hash32, key_epoch: u64, tweak: u64) -> [u64; LATTICE_DIM] {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"NOOS/HFHE-NEGATIVE-CONTROL/MASK/V1");
    hasher.update(&key_epoch.to_le_bytes());
    hasher.update(&tweak.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut a = [0u64; LATTICE_DIM];
    let mut buf = [0u8; 8];
    for slot in &mut a {
        reader.fill(&mut buf);
        *slot = u64::from_le_bytes(buf);
    }
    a
}

pub fn encrypt(
    sk: &SecretKey,
    master: &Hash32,
    m: u32,
    e: u64,
    tweak: u64,
) -> Result<Ciphertext, RefreshError> {
    if sk.retired {
        return Err(RefreshError::KeyRetired);
    }
    if e >= NOISE_CEILING {
        return Err(RefreshError::NoiseOverflow);
    }
    let a = mask_vector(master, sk.key_epoch, tweak);
    let b = inner(&a, &sk.s)
        .wrapping_add(e)
        .wrapping_add(u64::from(m).wrapping_mul(DELTA));
    Ok(Ciphertext {
        a,
        b,
        key_epoch: sk.key_epoch,
        logical_rows: 1,
        logical_cols: 1,
        noise_bound: e,
    })
}

pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Result<u32, RefreshError> {
    if sk.retired {
        return Err(RefreshError::KeyRetired);
    }
    if sk.key_epoch != ct.key_epoch {
        return Err(RefreshError::WrongEpoch);
    }
    if ct.logical_rows == 0 || ct.logical_cols == 0 {
        return Err(RefreshError::ContextMismatch);
    }
    if ct.noise_bound >= NOISE_CEILING {
        return Err(RefreshError::BudgetExhausted);
    }
    let phase = ct.b.wrapping_sub(inner(&ct.a, &sk.s));
    Ok((phase.wrapping_add(NOISE_CEILING) / DELTA) as u32)
}

#[must_use]
pub fn measured_noise(sk: &SecretKey, ct: &Ciphertext) -> u64 {
    if sk.retired {
        return u64::MAX;
    }
    let phase = ct.b.wrapping_sub(inner(&ct.a, &sk.s));
    let m = phase.wrapping_add(NOISE_CEILING) / DELTA;
    phase.wrapping_sub(m.wrapping_mul(DELTA))
}

pub fn add(x: &Ciphertext, y: &Ciphertext) -> Result<Ciphertext, RefreshError> {
    if x.key_epoch != y.key_epoch {
        return Err(RefreshError::WrongEpoch);
    }
    if x.logical_rows != y.logical_rows || x.logical_cols != y.logical_cols {
        return Err(RefreshError::ContextMismatch);
    }
    let mut a = [0u64; LATTICE_DIM];
    for (slot, (xa, ya)) in a.iter_mut().zip(x.a.iter().zip(&y.a)) {
        *slot = xa.wrapping_add(*ya);
    }
    Ok(Ciphertext {
        a,
        b: x.b.wrapping_add(y.b),
        key_epoch: x.key_epoch,
        logical_rows: x.logical_rows,
        logical_cols: x.logical_cols,
        noise_bound: x
            .noise_bound
            .checked_add(y.noise_bound)
            .ok_or(RefreshError::NoiseOverflow)?,
    })
}

pub fn mul_plain(x: &Ciphertext, k: u64) -> Result<Ciphertext, RefreshError> {
    let mut a = [0u64; LATTICE_DIM];
    for (slot, xa) in a.iter_mut().zip(&x.a) {
        *slot = xa.wrapping_mul(k);
    }
    Ok(Ciphertext {
        a,
        b: x.b.wrapping_mul(k),
        key_epoch: x.key_epoch,
        logical_rows: x.logical_rows,
        logical_cols: x.logical_cols,
        noise_bound: x
            .noise_bound
            .checked_mul(k)
            .ok_or(RefreshError::NoiseOverflow)?,
    })
}

#[must_use]
pub fn encode_ciphertext(ct: &Ciphertext) -> Vec<u8> {
    let mut encoded = b"NOOS/HFHE-NEGATIVE-CONTROL/CIPHERTEXT/V1".to_vec();
    encoded.extend_from_slice(&ct.logical_rows.to_le_bytes());
    encoded.extend_from_slice(&ct.logical_cols.to_le_bytes());
    encoded.extend_from_slice(&(LATTICE_DIM as u32).to_le_bytes());
    for word in &ct.a {
        encoded.extend_from_slice(&word.to_le_bytes());
    }
    encoded.extend_from_slice(&ct.b.to_le_bytes());
    encoded.extend_from_slice(&ct.key_epoch.to_le_bytes());
    encoded.extend_from_slice(&ct.noise_bound.to_le_bytes());
    encoded
}

#[must_use]
pub fn commit_ciphertext(ct: &Ciphertext) -> Hash32 {
    *blake3::hash(&encode_ciphertext(ct)).as_bytes()
}

pub struct AuditKey {
    material: Hash32,
    retired: bool,
}

impl fmt::Debug for AuditKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditKey")
            .field("retired", &self.retired)
            .field("material", &"REDACTED")
            .finish()
    }
}

impl AuditKey {
    #[must_use]
    pub const fn new(material: Hash32) -> Self {
        Self {
            material,
            retired: false,
        }
    }

    pub fn retire(&mut self) {
        self.material.fill(0);
        self.retired = true;
    }

    #[must_use]
    pub fn is_zeroized(&self) -> bool {
        self.retired && self.material.iter().all(|byte| *byte == 0)
    }
}

impl Drop for AuditKey {
    fn drop(&mut self) {
        self.material.fill(0);
        self.retired = true;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshContext {
    pub chain_id: Hash32,
    pub job_id: Hash32,
    pub suite_from: Hash32,
    pub suite_to: Hash32,
    pub rights_root_from: Hash32,
    pub rights_root_to: Hash32,
    pub policy_root_from: Hash32,
    pub policy_root_to: Hash32,
    pub transcript_root: Hash32,
    pub challenge: Hash32,
    pub challenge_issued_at: u64,
    pub expires_at: u64,
}

impl RefreshContext {
    fn validate(&self) -> Result<(), RefreshError> {
        if self.challenge == [0; 32] {
            return Err(RefreshError::ChallengeMissing);
        }
        if self.suite_from != REFRESH_SUITE || self.suite_to != REFRESH_SUITE {
            return Err(RefreshError::UnsupportedDispatch);
        }
        if self.rights_root_from == [0; 32]
            || self.rights_root_to == [0; 32]
            || self.policy_root_from == [0; 32]
            || self.policy_root_to == [0; 32]
            || self.transcript_root == [0; 32]
            || self.job_id == [0; 32]
            || self.chain_id == [0; 32]
        {
            return Err(RefreshError::ContextMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshProof {
    pub proof_suite: Hash32,
    pub suite_from: Hash32,
    pub suite_to: Hash32,
    pub epoch_from: u64,
    pub epoch_to: u64,
    pub rights_root_from: Hash32,
    pub rights_root_to: Hash32,
    pub policy_root_from: Hash32,
    pub policy_root_to: Hash32,
    pub chain_id: Hash32,
    pub job_id: Hash32,
    pub transcript_root: Hash32,
    pub challenge: Hash32,
    pub challenge_issued_at: u64,
    pub expires_at: u64,
    pub ct_from_commit: Hash32,
    pub ct_to_commit: Hash32,
    pub plaintext_digest: Hash32,
    pub continuity_tag: Hash32,
}

fn proof_statement_bytes(proof: &RefreshProof) -> Vec<u8> {
    let mut encoded = b"NOOS/HFHE/PROOF-CARRYING-REFRESH/STATEMENT/V1".to_vec();
    for field in [
        proof.proof_suite,
        proof.suite_from,
        proof.suite_to,
        proof.rights_root_from,
        proof.rights_root_to,
        proof.policy_root_from,
        proof.policy_root_to,
        proof.chain_id,
        proof.job_id,
        proof.transcript_root,
        proof.challenge,
        proof.ct_from_commit,
        proof.ct_to_commit,
        proof.plaintext_digest,
    ] {
        encoded.extend_from_slice(&field);
    }
    for value in [
        proof.epoch_from,
        proof.epoch_to,
        proof.challenge_issued_at,
        proof.expires_at,
    ] {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    encoded
}

fn continuity_tag(key: &AuditKey, proof: &RefreshProof) -> Result<Hash32, RefreshError> {
    if key.retired {
        return Err(RefreshError::KeyRetired);
    }
    let mut hasher = blake3::Hasher::new_keyed(&key.material);
    hasher.update(b"NOOS/HFHE/PROOF-CARRYING-REFRESH/AUDIT-STANDIN/V1");
    hasher.update(&proof_statement_bytes(proof));
    Ok(*hasher.finalize().as_bytes())
}

fn plaintext_digest(message: u32, context: &RefreshContext) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/HFHE/REFRESH-PLAINTEXT-CONTINUITY/V1");
    hasher.update(&message.to_le_bytes());
    hasher.update(&context.chain_id);
    hasher.update(&context.job_id);
    hasher.update(&context.suite_from);
    hasher.update(&context.suite_to);
    hasher.update(&context.policy_root_from);
    hasher.update(&context.policy_root_to);
    *hasher.finalize().as_bytes()
}

pub fn dispatch_refresh(
    master: &Hash32,
    audit_key: &AuditKey,
    ct: &Ciphertext,
    context: &RefreshContext,
    tweak: u64,
) -> Result<(Ciphertext, RefreshProof), RefreshError> {
    context.validate()?;
    let sk_from = derive_key(master, ct.key_epoch);
    let message = decrypt(&sk_from, ct)?;
    let epoch_to = ct
        .key_epoch
        .checked_add(1)
        .ok_or(RefreshError::EpochNotMonotone)?;
    let sk_to = derive_key(master, epoch_to);
    let fresh = encrypt(&sk_to, master, message, BASE_NOISE, tweak)?;
    let mut proof = RefreshProof {
        proof_suite: REFRESH_SUITE,
        suite_from: context.suite_from,
        suite_to: context.suite_to,
        epoch_from: ct.key_epoch,
        epoch_to,
        rights_root_from: context.rights_root_from,
        rights_root_to: context.rights_root_to,
        policy_root_from: context.policy_root_from,
        policy_root_to: context.policy_root_to,
        chain_id: context.chain_id,
        job_id: context.job_id,
        transcript_root: context.transcript_root,
        challenge: context.challenge,
        challenge_issued_at: context.challenge_issued_at,
        expires_at: context.expires_at,
        ct_from_commit: commit_ciphertext(ct),
        ct_to_commit: commit_ciphertext(&fresh),
        plaintext_digest: plaintext_digest(message, context),
        continuity_tag: [0; 32],
    };
    proof.continuity_tag = continuity_tag(audit_key, &proof)?;
    Ok((fresh, proof))
}

#[derive(Clone, Debug, Default)]
pub struct RefreshVerifierState {
    seen_challenges: BTreeSet<(Hash32, Hash32)>,
    high_epoch_by_job: BTreeMap<Hash32, u64>,
}

impl RefreshVerifierState {
    pub fn verify(
        &mut self,
        audit_key: &AuditKey,
        ct_from: &Ciphertext,
        ct_to: &Ciphertext,
        context: &RefreshContext,
        proof: Option<&RefreshProof>,
        now: u64,
    ) -> Result<(), RefreshError> {
        context.validate()?;
        let proof = proof.ok_or(RefreshError::MissingProof)?;
        if proof.proof_suite != REFRESH_SUITE
            || proof.suite_from != context.suite_from
            || proof.suite_to != context.suite_to
        {
            return Err(RefreshError::SuiteMismatch);
        }
        if proof.epoch_to
            != proof
                .epoch_from
                .checked_add(1)
                .ok_or(RefreshError::EpochNotMonotone)?
            || ct_from.key_epoch != proof.epoch_from
            || ct_to.key_epoch != proof.epoch_to
        {
            return Err(RefreshError::EpochNotMonotone);
        }
        if proof.rights_root_from != context.rights_root_from
            || proof.rights_root_to != context.rights_root_to
        {
            return Err(RefreshError::RightsMismatch);
        }
        if proof.policy_root_from != context.policy_root_from
            || proof.policy_root_to != context.policy_root_to
        {
            return Err(RefreshError::PolicyMismatch);
        }
        if proof.chain_id != context.chain_id
            || proof.job_id != context.job_id
            || proof.transcript_root != context.transcript_root
            || proof.challenge != context.challenge
            || proof.challenge_issued_at != context.challenge_issued_at
            || proof.expires_at != context.expires_at
        {
            return Err(RefreshError::ContextMismatch);
        }
        if proof.challenge_issued_at > now || now > proof.expires_at {
            return Err(RefreshError::ChallengeStale);
        }
        let challenge_key = (proof.job_id, proof.challenge);
        if self.seen_challenges.contains(&challenge_key) {
            return Err(RefreshError::ChallengeReplay);
        }
        if self
            .high_epoch_by_job
            .get(&proof.job_id)
            .is_some_and(|epoch| proof.epoch_from < *epoch)
        {
            return Err(RefreshError::Rollback);
        }
        if proof.ct_from_commit != commit_ciphertext(ct_from)
            || proof.ct_to_commit != commit_ciphertext(ct_to)
        {
            return Err(RefreshError::CommitMismatch);
        }
        if proof.continuity_tag != continuity_tag(audit_key, proof)? {
            return Err(RefreshError::ProofForged);
        }
        self.seen_challenges.insert(challenge_key);
        self.high_epoch_by_job.insert(proof.job_id, proof.epoch_to);
        Ok(())
    }
    /// Deterministic local execution checker for the refresh relation.
    ///
    /// In addition to the public audit-tag checks in [`Self::verify`], this
    /// backend re-opens both negative-control ciphertexts with the pinned
    /// master secret and checks exact plaintext continuity and the committed
    /// plaintext digest. It is deliberately non-zero-knowledge and is not an
    /// independent verifier family, but prevents a holder of the symmetric
    /// audit key from manufacturing a locally accepted discontinuous refresh.
    pub fn verify_executed(
        &mut self,
        master: &Hash32,
        audit_key: &AuditKey,
        ct_from: &Ciphertext,
        ct_to: &Ciphertext,
        context: &RefreshContext,
        proof: Option<&RefreshProof>,
        now: u64,
    ) -> Result<(), RefreshError> {
        context.validate()?;
        let proof = proof.ok_or(RefreshError::MissingProof)?;
        let from_message = decrypt(&derive_key(master, ct_from.key_epoch), ct_from)?;
        let to_message = decrypt(&derive_key(master, ct_to.key_epoch), ct_to)?;
        if from_message != to_message
            || proof.plaintext_digest != plaintext_digest(from_message, context)
        {
            return Err(RefreshError::PlaintextMismatch);
        }
        self.verify(audit_key, ct_from, ct_to, context, Some(proof), now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshAssuranceBoundary {
    pub complete_zero_knowledge_prover: bool,
    pub independent_verifier_families: u8,
    pub production_parameters: bool,
    pub suite_registered: bool,
}

#[must_use]
pub const fn assurance_boundary() -> RefreshAssuranceBoundary {
    RefreshAssuranceBoundary {
        complete_zero_knowledge_prover: false,
        independent_verifier_families: 1,
        production_parameters: false,
        suite_registered: false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const MASTER: Hash32 = [77; 32];
    fn audit() -> AuditKey {
        AuditKey::new([88; 32])
    }
    fn context(challenge: u8, job: u8, issued: u64) -> RefreshContext {
        RefreshContext {
            chain_id: [1; 32],
            job_id: [job; 32],
            suite_from: REFRESH_SUITE,
            suite_to: REFRESH_SUITE,
            rights_root_from: [3; 32],
            rights_root_to: [4; 32],
            policy_root_from: [5; 32],
            policy_root_to: [6; 32],
            transcript_root: [7; 32],
            challenge: [challenge; 32],
            challenge_issued_at: issued,
            expires_at: issued + 10,
        }
    }
    fn fresh(message: u32, epoch: u64, tweak: u64) -> Ciphertext {
        let sk = derive_key(&MASTER, epoch);
        encrypt(&sk, &MASTER, message, BASE_NOISE, tweak).unwrap()
    }

    #[test]
    fn refresh_binds_complete_statement_and_preserves_plaintext() {
        let ct = fresh(123_456, 0, 1);
        let ctx = context(9, 8, 100);
        let audit = audit();
        let (ct_to, proof) = dispatch_refresh(&MASTER, &audit, &ct, &ctx, 2).unwrap();
        let mut verifier = RefreshVerifierState::default();
        assert_eq!(
            verifier.verify_executed(&MASTER, &audit, &ct, &ct_to, &ctx, Some(&proof), 105),
            Ok(())
        );
        assert_eq!(decrypt(&derive_key(&MASTER, 1), &ct_to), Ok(123_456));
        let boundary = assurance_boundary();
        assert!(!boundary.complete_zero_knowledge_prover);
        assert_eq!(boundary.independent_verifier_families, 1);
        assert!(!boundary.suite_registered);
    }

    #[test]
    fn execution_checker_rejects_discontinuity_signed_by_audit_key_holder() {
        let audit = audit();
        let ct_from = fresh(7, 0, 1);
        let context = context(13, 14, 100);
        let (honest_to, mut forged) =
            dispatch_refresh(&MASTER, &audit, &ct_from, &context, 2).unwrap();
        let discontinuous_to = fresh(8, 1, 3);
        assert_ne!(honest_to, discontinuous_to);
        forged.ct_to_commit = commit_ciphertext(&discontinuous_to);
        forged.continuity_tag = continuity_tag(&audit, &forged).unwrap();

        // The public symmetric-tag precursor cannot defend against its own
        // audit-key holder. The pinned execution backend must.
        assert_eq!(
            RefreshVerifierState::default().verify(
                &audit,
                &ct_from,
                &discontinuous_to,
                &context,
                Some(&forged),
                105
            ),
            Ok(())
        );
        assert_eq!(
            RefreshVerifierState::default().verify_executed(
                &MASTER,
                &audit,
                &ct_from,
                &discontinuous_to,
                &context,
                Some(&forged),
                105
            ),
            Err(RefreshError::PlaintextMismatch)
        );
    }

    #[test]
    fn missing_replayed_stale_and_rollback_challenges_reject() {
        let audit = audit();
        let ct = fresh(1, 0, 1);
        let ctx = context(9, 8, 100);
        let (ct_to, proof) = dispatch_refresh(&MASTER, &audit, &ct, &ctx, 2).unwrap();
        let mut verifier = RefreshVerifierState::default();
        assert_eq!(
            verifier.verify(&audit, &ct, &ct_to, &ctx, None, 105),
            Err(RefreshError::MissingProof)
        );
        verifier
            .verify(&audit, &ct, &ct_to, &ctx, Some(&proof), 105)
            .unwrap();
        assert_eq!(
            verifier.verify(&audit, &ct, &ct_to, &ctx, Some(&proof), 105),
            Err(RefreshError::ChallengeReplay)
        );
        let stale_ctx = context(10, 9, 100);
        let (stale_to, stale_proof) =
            dispatch_refresh(&MASTER, &audit, &ct, &stale_ctx, 3).unwrap();
        assert_eq!(
            RefreshVerifierState::default().verify(
                &audit,
                &ct,
                &stale_to,
                &stale_ctx,
                Some(&stale_proof),
                111
            ),
            Err(RefreshError::ChallengeStale)
        );

        let ct_epoch_two = fresh(1, 2, 4);
        let high_ctx = context(11, 10, 100);
        let (ct_epoch_three, high_proof) =
            dispatch_refresh(&MASTER, &audit, &ct_epoch_two, &high_ctx, 5).unwrap();
        let mut state = RefreshVerifierState::default();
        state
            .verify(
                &audit,
                &ct_epoch_two,
                &ct_epoch_three,
                &high_ctx,
                Some(&high_proof),
                105,
            )
            .unwrap();
        let old = fresh(1, 0, 6);
        let old_ctx = context(12, 10, 100);
        let (old_to, old_proof) = dispatch_refresh(&MASTER, &audit, &old, &old_ctx, 7).unwrap();
        assert_eq!(
            state.verify(&audit, &old, &old_to, &old_ctx, Some(&old_proof), 105),
            Err(RefreshError::Rollback)
        );
    }

    #[test]
    fn tamper_and_cross_transcript_splice_reject() {
        let audit = audit();
        let ct_a = fresh(7, 0, 1);
        let ct_b = fresh(8, 0, 2);
        let ctx_a = context(20, 20, 100);
        let ctx_b = context(21, 21, 100);
        let (to_a, proof_a) = dispatch_refresh(&MASTER, &audit, &ct_a, &ctx_a, 3).unwrap();
        let (to_b, proof_b) = dispatch_refresh(&MASTER, &audit, &ct_b, &ctx_b, 4).unwrap();
        assert_eq!(
            RefreshVerifierState::default().verify(
                &audit,
                &ct_a,
                &to_b,
                &ctx_a,
                Some(&proof_a),
                105
            ),
            Err(RefreshError::CommitMismatch)
        );
        let mut splice = proof_a.clone();
        splice.plaintext_digest = proof_b.plaintext_digest;
        assert_eq!(
            RefreshVerifierState::default().verify(
                &audit,
                &ct_a,
                &to_a,
                &ctx_a,
                Some(&splice),
                105
            ),
            Err(RefreshError::ProofForged)
        );
        let mut policy_tamper = ctx_a.clone();
        policy_tamper.policy_root_to = [99; 32];
        assert_eq!(
            RefreshVerifierState::default().verify(
                &audit,
                &ct_a,
                &to_a,
                &policy_tamper,
                Some(&proof_a),
                105
            ),
            Err(RefreshError::PolicyMismatch)
        );
    }

    #[test]
    fn every_statement_class_is_bound_and_suite_downgrade_rejects() {
        let audit = audit();
        let ct = fresh(7, 0, 1);
        let ctx = context(20, 20, 100);
        let (to, proof) = dispatch_refresh(&MASTER, &audit, &ct, &ctx, 3).unwrap();
        let mutations = vec![
            RefreshProof {
                proof_suite: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                suite_from: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                epoch_to: 9,
                ..proof.clone()
            },
            RefreshProof {
                rights_root_to: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                policy_root_from: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                job_id: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                transcript_root: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                challenge: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                ct_to_commit: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                plaintext_digest: [1; 32],
                ..proof.clone()
            },
            RefreshProof {
                continuity_tag: [1; 32],
                ..proof.clone()
            },
        ];
        for mutation in mutations {
            assert!(RefreshVerifierState::default()
                .verify(&audit, &ct, &to, &ctx, Some(&mutation), 105)
                .is_err());
        }
        let mut downgrade = ctx.clone();
        downgrade.suite_to = [55; 32];
        assert_eq!(
            dispatch_refresh(&MASTER, &audit, &ct, &downgrade, 4),
            Err(RefreshError::UnsupportedDispatch)
        );
    }

    #[test]
    fn ciphertext_shape_is_committed_and_homomorphic_noise_fails_closed() {
        let x = fresh(10, 0, 1);
        let y = fresh(20, 0, 2);
        let sum = add(&x, &y).unwrap();
        assert_eq!(decrypt(&derive_key(&MASTER, 0), &sum), Ok(30));
        let mut reshaped = sum.clone();
        reshaped.logical_rows = 2;
        assert_ne!(commit_ciphertext(&reshaped), commit_ciphertext(&sum));
        assert_eq!(add(&sum, &reshaped), Err(RefreshError::ContextMismatch));
        let mut hot = mul_plain(&sum, 5).unwrap();
        hot.noise_bound = NOISE_CEILING;
        assert_eq!(
            decrypt(&derive_key(&MASTER, 0), &hot),
            Err(RefreshError::BudgetExhausted)
        );
    }

    #[test]
    fn retired_keys_have_explicit_zeroized_state_and_cannot_dispatch() {
        let mut key = derive_key(&MASTER, 0);
        key.retire();
        assert!(key.is_zeroized());
        assert_eq!(
            decrypt(&key, &fresh(1, 0, 1)),
            Err(RefreshError::KeyRetired)
        );
        let mut audit = audit();
        audit.retire();
        assert!(audit.is_zeroized());
        let ctx = context(9, 8, 100);
        assert_eq!(
            dispatch_refresh(&MASTER, &audit, &fresh(1, 0, 1), &ctx, 2),
            Err(RefreshError::KeyRetired)
        );
    }
}
