//! M-FIBER / A-UMBRA-CAUSAL local contract: an encrypted state object binds ciphertext root,
//! causal root, key epoch, rights root, privacy budget, and a certificate that binds exactly one
//! certified successor per transition. The lineage accepts at most one realized successor per
//! parent (no dual heads), rejects forged or unbound certificates, rejects causal omission, and
//! a commutation claim is valid only when both certificates bind the same certified successor —
//! otherwise the writes must serialize.

use crate::{Commitment32, Hash32, KeyEpoch};
use std::collections::BTreeMap;

pub const FIBER_CERT_DOMAIN: &[u8] = b"NOOS/UMBRA/FIBER-TRANSITION-CERT/V1";
pub const FIBER_CAUSAL_DOMAIN: &[u8] = b"NOOS/UMBRA/FIBER-CAUSAL/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FiberDagError {
    /// A second, different successor was presented for an already-realized parent.
    DualHead,
    /// The certificate binding does not cover these fields (forgery or substitution).
    ForgedCert,
    /// The causal root does not commit to the parent and inputs (causal omission).
    CausalOmission,
    /// The transitions do not commute: they bind different successors and must serialize.
    MustSerialize,
    UnknownParent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionKind {
    /// Deterministic transition of a named program.
    Deterministic,
    /// Nondeterministic transition: meaningful only because the certificate binds exactly one
    /// certified successor commitment.
    Nondeterministic,
}

/// Transition certificate. Binds every field, successor included, under the certifier key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionCert {
    pub parent: Commitment32,
    pub successor: Commitment32,
    pub ciphertext_root: Hash32,
    pub causal_root: Hash32,
    pub key_epoch: KeyEpoch,
    pub rights_root: Hash32,
    pub privacy_budget_debit: u64,
    pub kind: TransitionKind,
    pub binding: Hash32,
}

fn binding_payload(cert: &TransitionCert, bind_successor: bool) -> Vec<u8> {
    let mut payload = Vec::with_capacity(200);
    payload.extend_from_slice(FIBER_CERT_DOMAIN);
    payload.extend_from_slice(&cert.parent.0);
    if bind_successor {
        payload.push(1);
        payload.extend_from_slice(&cert.successor.0);
    } else {
        payload.push(0);
    }
    payload.extend_from_slice(&cert.ciphertext_root);
    payload.extend_from_slice(&cert.causal_root);
    payload.extend_from_slice(&cert.key_epoch.0.to_le_bytes());
    payload.extend_from_slice(&cert.rights_root);
    payload.extend_from_slice(&cert.privacy_budget_debit.to_le_bytes());
    payload.push(match cert.kind {
        TransitionKind::Deterministic => 1,
        TransitionKind::Nondeterministic => 2,
    });
    payload
}

/// Expected causal root: a commitment to the parent and the ordered input roots.
#[must_use]
pub fn causal_root(parent: &Commitment32, ordered_inputs: &[Hash32]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIBER_CAUSAL_DOMAIN);
    hasher.update(&parent.0);
    hasher.update(&(ordered_inputs.len() as u64).to_le_bytes());
    for input in ordered_inputs {
        hasher.update(input);
    }
    *hasher.finalize().as_bytes()
}

/// Certifier side: issues a certificate binding exactly one successor.
#[must_use]
pub fn certify(certifier_key: &[u8; 32], mut cert: TransitionCert) -> TransitionCert {
    cert.binding = *blake3::keyed_hash(certifier_key, &binding_payload(&cert, true)).as_bytes();
    cert
}

/// Adversarial helper modeling the "nondeterministic unbound transition" forgery: a binding
/// computed WITHOUT the successor commitment. The lineage must reject it.
#[must_use]
pub fn forge_unbound_cert(certifier_key: &[u8; 32], mut cert: TransitionCert) -> TransitionCert {
    cert.binding = *blake3::keyed_hash(certifier_key, &binding_payload(&cert, false)).as_bytes();
    cert
}

/// Realized lineage: at most one certified successor per parent, full closure tracking.
#[derive(Clone, Debug)]
pub struct Lineage {
    certifier_key: [u8; 32],
    successors: BTreeMap<Commitment32, Commitment32>,
}

impl Lineage {
    #[must_use]
    pub fn new(certifier_key: [u8; 32]) -> Self {
        Self {
            certifier_key,
            successors: BTreeMap::new(),
        }
    }

    /// Applies one certified transition. Verification order: certificate binding (successor
    /// bound), causal closure, then single-successor realization.
    pub fn apply(
        &mut self,
        cert: &TransitionCert,
        ordered_inputs: &[Hash32],
    ) -> Result<(), FiberDagError> {
        let expected =
            *blake3::keyed_hash(&self.certifier_key, &binding_payload(cert, true)).as_bytes();
        if cert.binding != expected {
            return Err(FiberDagError::ForgedCert);
        }
        if cert.causal_root != causal_root(&cert.parent, ordered_inputs) {
            return Err(FiberDagError::CausalOmission);
        }
        match self.successors.get(&cert.parent) {
            Some(existing) if *existing == cert.successor => Ok(()),
            Some(_) => Err(FiberDagError::DualHead),
            None => {
                self.successors.insert(cert.parent, cert.successor);
                Ok(())
            }
        }
    }

    /// Realized closure from `root`: the unique successor chain.
    #[must_use]
    pub fn closure(&self, root: &Commitment32) -> Vec<Commitment32> {
        let mut chain = vec![*root];
        let mut cursor = *root;
        while let Some(next) = self.successors.get(&cursor) {
            chain.push(*next);
            cursor = *next;
        }
        chain
    }

    /// A commutation certificate is meaningful only when both transitions bind the same
    /// certified successor; anything else must serialize.
    pub fn prove_commutation(
        &self,
        a: &TransitionCert,
        b: &TransitionCert,
    ) -> Result<Commitment32, FiberDagError> {
        for cert in [a, b] {
            let expected =
                *blake3::keyed_hash(&self.certifier_key, &binding_payload(cert, true)).as_bytes();
            if cert.binding != expected {
                return Err(FiberDagError::ForgedCert);
            }
        }
        if a.parent != b.parent {
            return Err(FiberDagError::UnknownParent);
        }
        if a.successor != b.successor {
            return Err(FiberDagError::MustSerialize);
        }
        Ok(a.successor)
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

    const KEY: [u8; 32] = [5u8; 32];

    fn commitment(v: u8) -> Commitment32 {
        Commitment32([v; 32])
    }

    fn cert(parent: u8, successor: u8, inputs: &[Hash32]) -> TransitionCert {
        certify(
            &KEY,
            TransitionCert {
                parent: commitment(parent),
                successor: commitment(successor),
                ciphertext_root: [7u8; 32],
                causal_root: causal_root(&commitment(parent), inputs),
                key_epoch: KeyEpoch(1),
                rights_root: [8u8; 32],
                privacy_budget_debit: 3,
                kind: TransitionKind::Nondeterministic,
                binding: [0u8; 32],
            },
        )
    }

    #[test]
    fn lineage_closure_matches_the_reference_graph() {
        let mut lineage = Lineage::new(KEY);
        lineage.apply(&cert(1, 2, &[]), &[]).unwrap();
        lineage
            .apply(&cert(2, 3, &[[9u8; 32]]), &[[9u8; 32]])
            .unwrap();
        lineage.apply(&cert(3, 4, &[]), &[]).unwrap();
        assert_eq!(
            lineage.closure(&commitment(1)),
            vec![commitment(1), commitment(2), commitment(3), commitment(4)]
        );
        // Idempotent re-application of the same certified transition is not a dual head.
        assert_eq!(
            lineage.apply(&cert(2, 3, &[[9u8; 32]]), &[[9u8; 32]]),
            Ok(())
        );
    }

    #[test]
    fn falsifier_second_successor_is_a_dual_head() {
        let mut lineage = Lineage::new(KEY);
        lineage.apply(&cert(1, 2, &[]), &[]).unwrap();
        assert_eq!(
            lineage.apply(&cert(1, 3, &[]), &[]),
            Err(FiberDagError::DualHead)
        );
        // The realized head is unchanged.
        assert_eq!(
            lineage.closure(&commitment(1)),
            vec![commitment(1), commitment(2)]
        );
    }

    #[test]
    fn falsifier_unbound_nondeterministic_transition_rejects() {
        let mut lineage = Lineage::new(KEY);
        let unbound = forge_unbound_cert(
            &KEY,
            TransitionCert {
                parent: commitment(1),
                successor: commitment(2),
                ciphertext_root: [7u8; 32],
                causal_root: causal_root(&commitment(1), &[]),
                key_epoch: KeyEpoch(1),
                rights_root: [8u8; 32],
                privacy_budget_debit: 3,
                kind: TransitionKind::Nondeterministic,
                binding: [0u8; 32],
            },
        );
        assert_eq!(lineage.apply(&unbound, &[]), Err(FiberDagError::ForgedCert));
    }

    #[test]
    fn falsifier_lineage_substitution_rejects() {
        let mut lineage = Lineage::new(KEY);
        let mut substituted = cert(1, 2, &[]);
        substituted.rights_root = [9u8; 32];
        assert_eq!(
            lineage.apply(&substituted, &[]),
            Err(FiberDagError::ForgedCert)
        );
        let mut swapped = cert(1, 2, &[]);
        swapped.successor = commitment(3);
        assert_eq!(lineage.apply(&swapped, &[]), Err(FiberDagError::ForgedCert));
    }

    #[test]
    fn falsifier_causal_omission_rejects() {
        let mut lineage = Lineage::new(KEY);
        let inputs = [[9u8; 32], [10u8; 32]];
        let honest = cert(1, 2, &inputs);
        // Presenting the certificate while omitting an input from the causal statement fails.
        assert_eq!(
            lineage.apply(&honest, &inputs[..1]),
            Err(FiberDagError::CausalOmission)
        );
        assert_eq!(lineage.apply(&honest, &inputs), Ok(()));
    }

    #[test]
    fn falsifier_noncommuting_writes_must_serialize() {
        let lineage = Lineage::new(KEY);
        let a = cert(1, 2, &[]);
        let b = cert(1, 3, &[]);
        assert_eq!(
            lineage.prove_commutation(&a, &b),
            Err(FiberDagError::MustSerialize)
        );
        // Commutation to the same certified successor is the only accepted claim.
        let c = cert(1, 2, &[]);
        assert_eq!(lineage.prove_commutation(&a, &c), Ok(commitment(2)));
    }
}
