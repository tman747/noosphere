//! M-BRANCH local contract: a family right derives its nullifier as
//! `N_F = PRF_sk(domain, chainID, C_parent, u_F)`. Registration consumes the unique right `u_F`
//! exactly once and binds exactly one family root `R_F`; afterwards exactly one separately
//! authorized branch may activate. Falsified behaviors — right reuse, a second root for the same
//! nullifier, cross-chain replay, multi-activation, and branch/root substitution — all reject
//! with typed errors. Non-claims: this proves neither privacy, nor quality, nor that activation
//! ever occurs.

use crate::{Commitment32, Hash32, Nullifier32};
use std::collections::{BTreeMap, BTreeSet};

pub const BRANCH_PRF_DOMAIN: &[u8] = b"NOOS/UMBRA/BRANCH-NULLIFIER/V1";
pub const BRANCH_AUTH_DOMAIN: &[u8] = b"NOOS/UMBRA/BRANCH-ACTIVATE/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchError {
    /// The unique right u_F was already consumed.
    RightReused,
    /// The nullifier was already registered with a different family root.
    RootSubstitution,
    /// Registration is idempotent-free: the same family may not register twice.
    DuplicateRegistration,
    /// The nullifier derivation does not bind this chain: replay from another chain.
    CrossChainReplay,
    UnknownFamily,
    /// The activation authorization does not bind this nullifier and branch root.
    Unauthorized,
    /// Exactly one branch may ever activate for a family.
    AlreadyActivated,
}

/// `N_F = PRF_sk(domain, chainID, C_parent, u_F)`, keyed BLAKE3 as the PRF.
#[must_use]
pub fn family_nullifier(
    sk: &[u8; 32],
    domain: Hash32,
    chain_id: Hash32,
    parent: &Commitment32,
    unique_right: Hash32,
) -> Nullifier32 {
    let mut payload = Vec::with_capacity(BRANCH_PRF_DOMAIN.len().saturating_add(128));
    payload.extend_from_slice(BRANCH_PRF_DOMAIN);
    payload.extend_from_slice(&domain);
    payload.extend_from_slice(&chain_id);
    payload.extend_from_slice(&parent.0);
    payload.extend_from_slice(&unique_right);
    Nullifier32(*blake3::keyed_hash(sk, &payload).as_bytes())
}

/// Activation authorization bound to the family nullifier AND the branch root.
#[must_use]
pub fn activation_authorization(
    sk: &[u8; 32],
    nullifier: &Nullifier32,
    branch_root: Hash32,
) -> Hash32 {
    let mut payload = Vec::with_capacity(BRANCH_AUTH_DOMAIN.len().saturating_add(64));
    payload.extend_from_slice(BRANCH_AUTH_DOMAIN);
    payload.extend_from_slice(&nullifier.0);
    payload.extend_from_slice(&branch_root);
    *blake3::keyed_hash(sk, &payload).as_bytes()
}

/// Registration statement: the public derivation witness plus the claimed nullifier and root.
/// (In production the derivation is shown in zero knowledge; locally the registry re-runs the
/// PRF relation with the prover-supplied key, standing in for the admitted circuit.)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyRegistration {
    pub domain: Hash32,
    pub chain_id: Hash32,
    pub parent: Commitment32,
    pub unique_right: Hash32,
    pub family_root: Hash32,
    pub nullifier: Nullifier32,
}

#[derive(Clone, Debug)]
struct FamilyRecord {
    family_root: Hash32,
    activated_branch: Option<Hash32>,
}

/// Per-chain registry: exactly-once family registration, at-most-once branch activation.
#[derive(Clone, Debug)]
pub struct BranchRegistry {
    chain_id: Hash32,
    consumed_rights: BTreeSet<Hash32>,
    families: BTreeMap<Nullifier32, FamilyRecord>,
}

impl BranchRegistry {
    #[must_use]
    pub fn new(chain_id: Hash32) -> Self {
        Self {
            chain_id,
            consumed_rights: BTreeSet::new(),
            families: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        sk: &[u8; 32],
        registration: &FamilyRegistration,
    ) -> Result<(), BranchError> {
        // The derivation relation must bind THIS chain: a nullifier derived for another chain
        // (or a registration claiming another chain id) never verifies here.
        let expected = family_nullifier(
            sk,
            registration.domain,
            self.chain_id,
            &registration.parent,
            registration.unique_right,
        );
        if registration.chain_id != self.chain_id || registration.nullifier != expected {
            return Err(BranchError::CrossChainReplay);
        }
        if let Some(existing) = self.families.get(&registration.nullifier) {
            if existing.family_root != registration.family_root {
                return Err(BranchError::RootSubstitution);
            }
            return Err(BranchError::DuplicateRegistration);
        }
        if !self.consumed_rights.insert(registration.unique_right) {
            return Err(BranchError::RightReused);
        }
        self.families.insert(
            registration.nullifier,
            FamilyRecord {
                family_root: registration.family_root,
                activated_branch: None,
            },
        );
        Ok(())
    }

    pub fn activate(
        &mut self,
        sk: &[u8; 32],
        nullifier: &Nullifier32,
        branch_root: Hash32,
        authorization: Hash32,
    ) -> Result<(), BranchError> {
        let record = self
            .families
            .get_mut(nullifier)
            .ok_or(BranchError::UnknownFamily)?;
        if authorization != activation_authorization(sk, nullifier, branch_root) {
            return Err(BranchError::Unauthorized);
        }
        if record.activated_branch.is_some() {
            return Err(BranchError::AlreadyActivated);
        }
        record.activated_branch = Some(branch_root);
        Ok(())
    }

    #[must_use]
    pub fn family_root(&self, nullifier: &Nullifier32) -> Option<Hash32> {
        self.families.get(nullifier).map(|r| r.family_root)
    }

    #[must_use]
    pub fn activated_branch(&self, nullifier: &Nullifier32) -> Option<Hash32> {
        self.families
            .get(nullifier)
            .and_then(|r| r.activated_branch)
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

    const SK: [u8; 32] = [3u8; 32];
    const CHAIN_A: Hash32 = [10u8; 32];
    const CHAIN_B: Hash32 = [11u8; 32];

    fn registration(chain_id: Hash32, right: u8, root: u8) -> FamilyRegistration {
        let parent = Commitment32([1u8; 32]);
        let nullifier = family_nullifier(&SK, [2u8; 32], chain_id, &parent, [right; 32]);
        FamilyRegistration {
            domain: [2u8; 32],
            chain_id,
            parent,
            unique_right: [right; 32],
            family_root: [root; 32],
            nullifier,
        }
    }

    #[test]
    fn exactly_one_registration_then_at_most_one_activation() {
        let mut registry = BranchRegistry::new(CHAIN_A);
        let reg = registration(CHAIN_A, 7, 20);
        registry.register(&SK, &reg).unwrap();
        assert_eq!(registry.family_root(&reg.nullifier), Some([20u8; 32]));
        let auth = activation_authorization(&SK, &reg.nullifier, [30u8; 32]);
        registry
            .activate(&SK, &reg.nullifier, [30u8; 32], auth)
            .unwrap();
        assert_eq!(registry.activated_branch(&reg.nullifier), Some([30u8; 32]));
    }

    #[test]
    fn falsifier_unique_right_reuse_rejects() {
        let mut registry = BranchRegistry::new(CHAIN_A);
        registry
            .register(&SK, &registration(CHAIN_A, 7, 20))
            .unwrap();
        // Same u_F under a different parent still consumes the same unique right.
        let mut second = registration(CHAIN_A, 7, 21);
        second.parent = Commitment32([9u8; 32]);
        second.nullifier = family_nullifier(
            &SK,
            second.domain,
            CHAIN_A,
            &second.parent,
            second.unique_right,
        );
        assert_eq!(
            registry.register(&SK, &second),
            Err(BranchError::RightReused)
        );
    }

    #[test]
    fn falsifier_second_root_for_same_family_is_substitution() {
        let mut registry = BranchRegistry::new(CHAIN_A);
        let reg = registration(CHAIN_A, 7, 20);
        registry.register(&SK, &reg).unwrap();
        let mut resubmitted = reg.clone();
        resubmitted.family_root = [21u8; 32];
        assert_eq!(
            registry.register(&SK, &resubmitted),
            Err(BranchError::RootSubstitution)
        );
        assert_eq!(
            registry.register(&SK, &reg),
            Err(BranchError::DuplicateRegistration)
        );
        // The bound root never moved.
        assert_eq!(registry.family_root(&reg.nullifier), Some([20u8; 32]));
    }

    #[test]
    fn falsifier_cross_chain_replay_rejects() {
        let mut registry_a = BranchRegistry::new(CHAIN_A);
        let reg_a = registration(CHAIN_A, 7, 20);
        registry_a.register(&SK, &reg_a).unwrap();
        // Replaying the chain-A registration on chain B fails: the PRF binds the chain id.
        let mut registry_b = BranchRegistry::new(CHAIN_B);
        assert_eq!(
            registry_b.register(&SK, &reg_a),
            Err(BranchError::CrossChainReplay)
        );
        // Relabeling the claimed chain id without re-deriving the nullifier also fails.
        let mut relabeled = reg_a.clone();
        relabeled.chain_id = CHAIN_B;
        assert_eq!(
            registry_b.register(&SK, &relabeled),
            Err(BranchError::CrossChainReplay)
        );
    }

    #[test]
    fn falsifier_second_activation_rejects() {
        let mut registry = BranchRegistry::new(CHAIN_A);
        let reg = registration(CHAIN_A, 7, 20);
        registry.register(&SK, &reg).unwrap();
        let first = activation_authorization(&SK, &reg.nullifier, [30u8; 32]);
        registry
            .activate(&SK, &reg.nullifier, [30u8; 32], first)
            .unwrap();
        // Even a freshly authorized second branch cannot activate.
        let second = activation_authorization(&SK, &reg.nullifier, [31u8; 32]);
        assert_eq!(
            registry.activate(&SK, &reg.nullifier, [31u8; 32], second),
            Err(BranchError::AlreadyActivated)
        );
        assert_eq!(registry.activated_branch(&reg.nullifier), Some([30u8; 32]));
    }

    #[test]
    fn falsifier_branch_substitution_is_unauthorized() {
        let mut registry = BranchRegistry::new(CHAIN_A);
        let reg = registration(CHAIN_A, 7, 20);
        registry.register(&SK, &reg).unwrap();
        // Authorization for branch X presented with branch Y: the binding rejects.
        let auth_for_x = activation_authorization(&SK, &reg.nullifier, [30u8; 32]);
        assert_eq!(
            registry.activate(&SK, &reg.nullifier, [31u8; 32], auth_for_x),
            Err(BranchError::Unauthorized)
        );
        // Nothing activated.
        assert_eq!(registry.activated_branch(&reg.nullifier), None);
    }
}
