//! M-PROOF-CARRYING-REFRESH / M-HFHE-SUITE research skeleton (both registry rows stay PARTIAL).
//!
//! A toy integer-lattice ciphertext over the BESI ring Z/2^64 (LWE-shaped: b = <a,s> + e + m*D,
//! D = 2^32) supports add, plaintext scaling, and a proof-carrying refresh: every refresh emits a
//! `RefreshProof` binding suite, both key epochs, rights root, both ciphertext commitments, and a
//! plaintext-continuity digest under a keyed tag. The verifier rejects a missing proof, any
//! mutated field, any substituted ciphertext, and non-monotone key epochs; refreshed state never
//! decrypts under the retired epoch key.
//!
//! Honest limitations that keep the rows PARTIAL: the continuity tag is a symmetric-key
//! stand-in for the required zero-knowledge prover (a malicious holder of the audit key is out
//! of scope), parameters are toy, there is no IND-style model or concrete attack estimate, no
//! second independent verifier implementation, and no production bootstrapping.

pub const REFRESH_SUITE: [u8; 32] = *b"NOOS/HFHE-REFRESH-SKELETON/V1\0\0\0";
pub const LATTICE_DIM: usize = 8;
pub const DELTA: u64 = 1 << 32;
/// Fail-closed decryption ceiling: noise at or beyond DELTA/2 may flip the plaintext.
pub const NOISE_CEILING: u64 = DELTA / 2;
/// Fresh-encryption noise magnitude (deterministic in this skeleton).
pub const BASE_NOISE: u64 = 1 << 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefreshError {
    WrongEpoch,
    /// The tracked noise bound reached the ceiling: decryption refuses instead of guessing.
    BudgetExhausted,
    NoiseOverflow,
    MissingProof,
    ProofForged,
    CommitMismatch,
    EpochNotMonotone,
    RightsMismatch,
    SuiteMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey {
    pub key_epoch: u64,
    s: [u64; LATTICE_DIM],
}

/// Deterministic per-epoch key schedule from a master secret (test/skeleton key lifecycle).
#[must_use]
pub fn derive_key(master: &[u8; 32], key_epoch: u64) -> SecretKey {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"NOOS/HFHE-REFRESH/KEY");
    hasher.update(&key_epoch.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut s = [0u64; LATTICE_DIM];
    let mut buf = [0u8; 8];
    for slot in &mut s {
        reader.fill(&mut buf);
        *slot = u64::from_le_bytes(buf);
    }
    SecretKey { key_epoch, s }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    pub a: [u64; LATTICE_DIM],
    pub b: u64,
    pub key_epoch: u64,
    /// Tracked worst-case noise magnitude. Consumed by the fail-closed decrypt and priced by
    /// the privacy-depth market.
    pub noise_bound: u64,
}

fn inner(a: &[u64; LATTICE_DIM], s: &[u64; LATTICE_DIM]) -> u64 {
    a.iter()
        .zip(s)
        .fold(0u64, |acc, (x, y)| acc.wrapping_add(x.wrapping_mul(*y)))
}

fn mask_vector(master: &[u8; 32], key_epoch: u64, tweak: u64) -> [u64; LATTICE_DIM] {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"NOOS/HFHE-REFRESH/MASK");
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

/// Encrypts `m` under the epoch key with explicit deterministic noise `e` (must stay below the
/// ceiling; production callers would sample from a distribution).
pub fn encrypt(
    sk: &SecretKey,
    master: &[u8; 32],
    m: u32,
    e: u64,
    tweak: u64,
) -> Result<Ciphertext, RefreshError> {
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
        noise_bound: e,
    })
}

/// Fail-closed decrypt: wrong epoch or an exhausted noise budget refuses before decoding.
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Result<u32, RefreshError> {
    if sk.key_epoch != ct.key_epoch {
        return Err(RefreshError::WrongEpoch);
    }
    if ct.noise_bound >= NOISE_CEILING {
        return Err(RefreshError::BudgetExhausted);
    }
    let phase = ct.b.wrapping_sub(inner(&ct.a, &sk.s));
    Ok((phase.wrapping_add(NOISE_CEILING) / DELTA) as u32)
}

/// Exact residual noise of a ciphertext (test/measurement support for the depth market).
#[must_use]
pub fn measured_noise(sk: &SecretKey, ct: &Ciphertext) -> u64 {
    let phase = ct.b.wrapping_sub(inner(&ct.a, &sk.s));
    let m = phase.wrapping_add(NOISE_CEILING) / DELTA;
    phase.wrapping_sub(m.wrapping_mul(DELTA))
}

pub fn add(x: &Ciphertext, y: &Ciphertext) -> Result<Ciphertext, RefreshError> {
    if x.key_epoch != y.key_epoch {
        return Err(RefreshError::WrongEpoch);
    }
    let mut a = [0u64; LATTICE_DIM];
    for (slot, (xa, ya)) in a.iter_mut().zip(x.a.iter().zip(&y.a)) {
        *slot = xa.wrapping_add(*ya);
    }
    Ok(Ciphertext {
        a,
        b: x.b.wrapping_add(y.b),
        key_epoch: x.key_epoch,
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
        noise_bound: x
            .noise_bound
            .checked_mul(k)
            .ok_or(RefreshError::NoiseOverflow)?,
    })
}

#[must_use]
pub fn commit_ciphertext(ct: &Ciphertext) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/HFHE-REFRESH/CT-COMMIT");
    for word in &ct.a {
        hasher.update(&word.to_le_bytes());
    }
    hasher.update(&ct.b.to_le_bytes());
    hasher.update(&ct.key_epoch.to_le_bytes());
    hasher.update(&ct.noise_bound.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Symmetric audit key: the skeleton's stand-in for the missing zero-knowledge prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditKey(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshProof {
    pub suite: [u8; 32],
    pub epoch_from: u64,
    pub epoch_to: u64,
    pub rights_root: [u8; 32],
    pub ct_from_commit: [u8; 32],
    pub ct_to_commit: [u8; 32],
    pub plaintext_digest: [u8; 32],
    pub continuity_tag: [u8; 32],
}

fn continuity_tag(key: &AuditKey, proof: &RefreshProof) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&key.0);
    hasher.update(b"NOOS/HFHE-REFRESH/CONTINUITY");
    hasher.update(&proof.suite);
    hasher.update(&proof.epoch_from.to_le_bytes());
    hasher.update(&proof.epoch_to.to_le_bytes());
    hasher.update(&proof.rights_root);
    hasher.update(&proof.ct_from_commit);
    hasher.update(&proof.ct_to_commit);
    hasher.update(&proof.plaintext_digest);
    *hasher.finalize().as_bytes()
}

/// Proof-carrying refresh: decrypts under the retiring epoch, re-encrypts fresh under the next
/// epoch (noise reset to `BASE_NOISE`), and emits the continuity proof.
pub fn refresh(
    master: &[u8; 32],
    audit_key: &AuditKey,
    ct: &Ciphertext,
    rights_root: [u8; 32],
    tweak: u64,
) -> Result<(Ciphertext, RefreshProof), RefreshError> {
    let sk_from = derive_key(master, ct.key_epoch);
    let m = decrypt(&sk_from, ct)?;
    let epoch_to = ct.key_epoch.saturating_add(1);
    let sk_to = derive_key(master, epoch_to);
    let fresh = encrypt(&sk_to, master, m, BASE_NOISE, tweak)?;
    let mut proof = RefreshProof {
        suite: REFRESH_SUITE,
        epoch_from: ct.key_epoch,
        epoch_to,
        rights_root,
        ct_from_commit: commit_ciphertext(ct),
        ct_to_commit: commit_ciphertext(&fresh),
        plaintext_digest: *blake3::hash(&m.to_le_bytes()).as_bytes(),
        continuity_tag: [0u8; 32],
    };
    proof.continuity_tag = continuity_tag(audit_key, &proof);
    Ok((fresh, proof))
}

/// Verifier side: a refresh without a valid proof never passes. Checks suite, epoch
/// monotonicity, rights binding, both ciphertext commitments, and the keyed continuity tag.
pub fn verify_refresh(
    audit_key: &AuditKey,
    ct_from: &Ciphertext,
    ct_to: &Ciphertext,
    rights_root: [u8; 32],
    proof: Option<&RefreshProof>,
) -> Result<(), RefreshError> {
    let proof = proof.ok_or(RefreshError::MissingProof)?;
    if proof.suite != REFRESH_SUITE {
        return Err(RefreshError::SuiteMismatch);
    }
    if proof.epoch_to != proof.epoch_from.saturating_add(1)
        || ct_from.key_epoch != proof.epoch_from
        || ct_to.key_epoch != proof.epoch_to
    {
        return Err(RefreshError::EpochNotMonotone);
    }
    if proof.rights_root != rights_root {
        return Err(RefreshError::RightsMismatch);
    }
    if proof.ct_from_commit != commit_ciphertext(ct_from)
        || proof.ct_to_commit != commit_ciphertext(ct_to)
    {
        return Err(RefreshError::CommitMismatch);
    }
    if proof.continuity_tag != continuity_tag(audit_key, proof) {
        return Err(RefreshError::ProofForged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const MASTER: [u8; 32] = [77u8; 32];
    const AUDIT: AuditKey = AuditKey([88u8; 32]);
    const RIGHTS: [u8; 32] = [9u8; 32];

    fn fresh(m: u32) -> Ciphertext {
        let sk = derive_key(&MASTER, 0);
        encrypt(&sk, &MASTER, m, BASE_NOISE, 1).unwrap()
    }

    #[test]
    fn refresh_preserves_plaintext_and_verifies() {
        let ct = fresh(123_456);
        let (ct2, proof) = refresh(&MASTER, &AUDIT, &ct, RIGHTS, 2).unwrap();
        assert_eq!(
            verify_refresh(&AUDIT, &ct, &ct2, RIGHTS, Some(&proof)),
            Ok(())
        );
        let sk1 = derive_key(&MASTER, 1);
        assert_eq!(decrypt(&sk1, &ct2), Ok(123_456));
        // Noise resets to base after refresh.
        assert_eq!(ct2.noise_bound, BASE_NOISE);
    }

    #[test]
    fn falsifier_missing_proof_rejects() {
        let ct = fresh(1);
        let (ct2, _proof) = refresh(&MASTER, &AUDIT, &ct, RIGHTS, 2).unwrap();
        assert_eq!(
            verify_refresh(&AUDIT, &ct, &ct2, RIGHTS, None),
            Err(RefreshError::MissingProof)
        );
    }

    #[test]
    fn falsifier_every_forged_proof_field_rejects() {
        let ct = fresh(7);
        let (ct2, proof) = refresh(&MASTER, &AUDIT, &ct, RIGHTS, 2).unwrap();
        let mutations: Vec<(RefreshProof, RefreshError)> = vec![
            (
                RefreshProof {
                    suite: [0u8; 32],
                    ..proof.clone()
                },
                RefreshError::SuiteMismatch,
            ),
            (
                RefreshProof {
                    epoch_to: 5,
                    ..proof.clone()
                },
                RefreshError::EpochNotMonotone,
            ),
            (
                RefreshProof {
                    rights_root: [1u8; 32],
                    ..proof.clone()
                },
                RefreshError::RightsMismatch,
            ),
            (
                RefreshProof {
                    ct_to_commit: [2u8; 32],
                    ..proof.clone()
                },
                RefreshError::CommitMismatch,
            ),
            (
                RefreshProof {
                    plaintext_digest: [3u8; 32],
                    ..proof.clone()
                },
                RefreshError::ProofForged,
            ),
            (
                RefreshProof {
                    continuity_tag: [4u8; 32],
                    ..proof.clone()
                },
                RefreshError::ProofForged,
            ),
        ];
        for (forged, expected) in mutations {
            assert_eq!(
                verify_refresh(&AUDIT, &ct, &ct2, RIGHTS, Some(&forged)),
                Err(expected)
            );
        }
    }

    #[test]
    fn falsifier_substituted_ciphertext_rejects_without_audit_key() {
        let ct = fresh(7);
        let (_ct2, proof) = refresh(&MASTER, &AUDIT, &ct, RIGHTS, 2).unwrap();
        // Adversary substitutes a different epoch-1 ciphertext (different plaintext).
        let sk1 = derive_key(&MASTER, 1);
        let substituted = encrypt(&sk1, &MASTER, 999, BASE_NOISE, 3).unwrap();
        assert_eq!(
            verify_refresh(&AUDIT, &ct, &substituted, RIGHTS, Some(&proof)),
            Err(RefreshError::CommitMismatch)
        );
        // Retagging without the audit key cannot fix it: any guessed tag mismatches.
        let mut forged = proof.clone();
        forged.ct_to_commit = commit_ciphertext(&substituted);
        forged.continuity_tag = [0xAB; 32];
        assert_eq!(
            verify_refresh(&AUDIT, &ct, &substituted, RIGHTS, Some(&forged)),
            Err(RefreshError::ProofForged)
        );
    }

    #[test]
    fn falsifier_retired_epoch_key_cannot_open_refreshed_state() {
        let ct = fresh(42);
        let (ct2, _proof) = refresh(&MASTER, &AUDIT, &ct, RIGHTS, 2).unwrap();
        let sk0 = derive_key(&MASTER, 0);
        assert_eq!(decrypt(&sk0, &ct2), Err(RefreshError::WrongEpoch));
        // Even relabeling the epoch does not help: the actual key differs, so the commitment
        // binding breaks and the decode is garbage relative to the true plaintext.
        let mut relabeled = ct2.clone();
        relabeled.key_epoch = 0;
        assert_ne!(commit_ciphertext(&relabeled), commit_ciphertext(&ct2));
        assert_ne!(decrypt(&sk0, &relabeled), Ok(42));
    }

    #[test]
    fn homomorphic_ops_track_noise_and_fail_closed() {
        let x = fresh(10);
        let y = fresh(20);
        let sum = add(&x, &y).unwrap();
        let sk0 = derive_key(&MASTER, 0);
        assert_eq!(decrypt(&sk0, &sum), Ok(30));
        assert_eq!(sum.noise_bound, 2 * BASE_NOISE);
        let scaled = mul_plain(&sum, 5).unwrap();
        assert_eq!(decrypt(&sk0, &scaled), Ok(150));
        // Push the tracked bound past the ceiling: decrypt refuses instead of guessing.
        let mut hot = scaled;
        hot.noise_bound = NOISE_CEILING;
        assert_eq!(decrypt(&sk0, &hot), Err(RefreshError::BudgetExhausted));
    }
}
