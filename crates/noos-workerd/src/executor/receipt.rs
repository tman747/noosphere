//! Canonical signed execution receipts and designated-primary matching.

use noos_crypto::{DomainId, Keypair, PublicKey, Signature};
use std::collections::BTreeMap;
use std::fmt;

pub type Id = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EvidenceState {
    AwaitingPrimary = 0,
    ProvisionalSigned = 1,
    MatchedQuorum = 2,
    MinorityDisagreement = 3,
    NoQuorum = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TerminalCode {
    Completed = 0,
    Cancelled = 1,
    RuntimeCrash = 2,
    RuntimeTimeout = 3,
    NoQuorum = 4,
    Rejected = 5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WwmReceiptV1 {
    pub chain_id: Id,
    pub genesis_hash: Id,
    pub job_id: Id,
    pub quote_id: Id,
    pub capsule_id: Id,
    pub artifact_id: Id,
    pub tokenizer_id: Id,
    pub template_id: Id,
    pub runtime_id: Id,
    pub profile_id: Id,
    pub prompt_tokens: u32,
    pub output_tokens: u32,
    pub token_history_root: Id,
    pub output_root: Id,
    pub signer_ids: Vec<Id>,
    pub control_cluster_ids: Vec<Id>,
    pub evidence: EvidenceState,
    pub reserved_micro_noos: u128,
    pub metered_micro_noos: u128,
    pub paid_micro_noos: u128,
    pub refunded_micro_noos: u128,
    pub terminal: TerminalCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    InvalidSignerSet,
    InvalidSettlement,
    Signing,
}
impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receipt: {self:?}")
    }
}
impl std::error::Error for ReceiptError {}

impl WwmReceiptV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        if self.evidence == EvidenceState::AwaitingPrimary {
            return Err(ReceiptError::InvalidSignerSet);
        }
        let minimum_signers = match self.evidence {
            EvidenceState::MatchedQuorum | EvidenceState::MinorityDisagreement => 2,
            EvidenceState::ProvisionalSigned | EvidenceState::NoQuorum => 1,
            EvidenceState::AwaitingPrimary => unreachable!(),
        };
        if self.signer_ids.len() < minimum_signers
            || self.signer_ids.len() > 3
            || self.signer_ids.len() != self.control_cluster_ids.len()
            || !strictly_sorted_unique(&self.signer_ids)
            || !strictly_sorted_unique(&self.control_cluster_ids)
        {
            return Err(ReceiptError::InvalidSignerSet);
        }
        if self.paid_micro_noos.checked_add(self.refunded_micro_noos)
            != Some(self.reserved_micro_noos)
            || self.metered_micro_noos > self.paid_micro_noos
        {
            return Err(ReceiptError::InvalidSettlement);
        }
        let mut bytes = Vec::with_capacity(640);
        bytes.extend_from_slice(b"NOOS/WWM/RECEIPT/V1\0");
        for id in [
            &self.chain_id,
            &self.genesis_hash,
            &self.job_id,
            &self.quote_id,
            &self.capsule_id,
            &self.artifact_id,
            &self.tokenizer_id,
            &self.template_id,
            &self.runtime_id,
            &self.profile_id,
        ] {
            bytes.extend_from_slice(id);
        }
        bytes.extend_from_slice(&self.prompt_tokens.to_le_bytes());
        bytes.extend_from_slice(&self.output_tokens.to_le_bytes());
        bytes.extend_from_slice(&self.token_history_root);
        bytes.extend_from_slice(&self.output_root);
        bytes
            .push(u8::try_from(self.signer_ids.len()).map_err(|_| ReceiptError::InvalidSignerSet)?);
        for id in &self.signer_ids {
            bytes.extend_from_slice(id);
        }
        bytes.push(
            u8::try_from(self.control_cluster_ids.len())
                .map_err(|_| ReceiptError::InvalidSignerSet)?,
        );
        for id in &self.control_cluster_ids {
            bytes.extend_from_slice(id);
        }
        bytes.push(self.evidence as u8);
        bytes.extend_from_slice(&self.reserved_micro_noos.to_le_bytes());
        bytes.extend_from_slice(&self.metered_micro_noos.to_le_bytes());
        bytes.extend_from_slice(&self.paid_micro_noos.to_le_bytes());
        bytes.extend_from_slice(&self.refunded_micro_noos.to_le_bytes());
        bytes.push(self.terminal as u8);
        Ok(bytes)
    }
}

fn strictly_sorted_unique(values: &[Id]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReceipt {
    pub body: Vec<u8>,
    pub signer: PublicKey,
    pub signature: Signature,
}

pub fn sign_receipt(
    receipt: &WwmReceiptV1,
    keypair: &Keypair,
) -> Result<SignedReceipt, ReceiptError> {
    let body = receipt.canonical_bytes()?;
    let signature = keypair
        .sign_domain(DomainId::SigWorkReceipt, &[&body])
        .map_err(|_| ReceiptError::Signing)?;
    Ok(SignedReceipt {
        body,
        signer: keypair.public_key(),
        signature,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedClaim {
    pub member_id: Id,
    pub control_cluster_id: Id,
    pub output_root: Id,
    pub token_history_root: Id,
    pub signature: [u8; 64],
}
impl ObservedClaim {
    fn matches(&self, other: &Self) -> bool {
        self.output_root == other.output_root && self.token_history_root == other.token_history_root
    }
}

/// Tracks exactly one designated primary and two designated backups. Matching
/// backups never replace the primary and claims are never spliced.
pub struct MatchTracker {
    primary: Id,
    backups: [Id; 2],
    claims: BTreeMap<Id, ObservedClaim>,
    deadline_closed: bool,
}
impl MatchTracker {
    pub fn new(primary: Id, backups: [Id; 2]) -> Result<Self, ReceiptError> {
        if primary == backups[0] || primary == backups[1] || backups[0] == backups[1] {
            return Err(ReceiptError::InvalidSignerSet);
        }
        Ok(Self {
            primary,
            backups,
            claims: BTreeMap::new(),
            deadline_closed: false,
        })
    }
    pub fn observe(&mut self, claim: ObservedClaim) -> Result<EvidenceState, ReceiptError> {
        if self.deadline_closed
            || (claim.member_id != self.primary && !self.backups.contains(&claim.member_id))
        {
            return Err(ReceiptError::InvalidSignerSet);
        }
        self.claims.entry(claim.member_id).or_insert(claim);
        Ok(self.status())
    }

    #[must_use]
    pub fn status(&self) -> EvidenceState {
        let Some(primary) = self.claims.get(&self.primary) else {
            return if self.deadline_closed {
                EvidenceState::NoQuorum
            } else {
                EvidenceState::AwaitingPrimary
            };
        };
        let backup_claims: Vec<&ObservedClaim> = self
            .backups
            .iter()
            .filter_map(|id| self.claims.get(id))
            .collect();
        let matches = backup_claims
            .iter()
            .filter(|claim| claim.matches(primary))
            .count();
        let dissent = backup_claims.iter().any(|claim| !claim.matches(primary));
        if matches > 0 && dissent {
            EvidenceState::MinorityDisagreement
        } else if matches > 0 {
            EvidenceState::MatchedQuorum
        } else if self.deadline_closed {
            EvidenceState::NoQuorum
        } else {
            EvidenceState::ProvisionalSigned
        }
    }

    pub fn close_deadline(&mut self) -> EvidenceState {
        self.deadline_closed = true;
        self.status()
    }

    #[must_use]
    pub fn claims(&self) -> Vec<&ObservedClaim> {
        self.claims.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noos_crypto::verify_domain;

    fn claim(member: u8, output: u8) -> ObservedClaim {
        ObservedClaim {
            member_id: [member; 32],
            control_cluster_id: [member + 10; 32],
            output_root: [output; 32],
            token_history_root: [output + 1; 32],
            signature: [member; 64],
        }
    }

    #[test]
    fn receipt_signature_rejects_every_mutation() {
        let key = Keypair::from_seed([7; 32]);
        let mut receipt = WwmReceiptV1 {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            job_id: [3; 32],
            quote_id: [4; 32],
            capsule_id: [5; 32],
            artifact_id: [6; 32],
            tokenizer_id: [7; 32],
            template_id: [8; 32],
            runtime_id: [9; 32],
            profile_id: [10; 32],
            prompt_tokens: 4,
            output_tokens: 2,
            token_history_root: [11; 32],
            output_root: [12; 32],
            signer_ids: vec![[1; 32], [2; 32]],
            control_cluster_ids: vec![[3; 32], [4; 32]],
            evidence: EvidenceState::MatchedQuorum,
            reserved_micro_noos: 9,
            metered_micro_noos: 7,
            paid_micro_noos: 7,
            refunded_micro_noos: 2,
            terminal: TerminalCode::Completed,
        };
        let signed = sign_receipt(&receipt, &key).unwrap();
        verify_domain(
            DomainId::SigWorkReceipt,
            &signed.signer,
            &[&signed.body],
            &signed.signature,
        )
        .unwrap();
        receipt.output_root[0] ^= 1;
        let mutated = receipt.canonical_bytes().unwrap();
        assert!(verify_domain(
            DomainId::SigWorkReceipt,
            &signed.signer,
            &[&mutated],
            &signed.signature
        )
        .is_err());
        receipt.output_root[0] ^= 1;
        receipt.refunded_micro_noos = 3;
        assert_eq!(
            receipt.canonical_bytes().err(),
            Some(ReceiptError::InvalidSettlement)
        );
    }

    #[test]
    fn primary_backup_dissent_and_no_quorum_matrix() {
        let mut matched = MatchTracker::new([1; 32], [[2; 32], [3; 32]]).unwrap();
        assert_eq!(
            matched.observe(claim(1, 9)).unwrap(),
            EvidenceState::ProvisionalSigned
        );
        assert_eq!(
            matched.observe(claim(2, 9)).unwrap(),
            EvidenceState::MatchedQuorum
        );
        assert_eq!(
            matched.observe(claim(3, 8)).unwrap(),
            EvidenceState::MinorityDisagreement
        );

        let mut backups_agree = MatchTracker::new([1; 32], [[2; 32], [3; 32]]).unwrap();
        backups_agree.observe(claim(1, 9)).unwrap();
        backups_agree.observe(claim(2, 8)).unwrap();
        backups_agree.observe(claim(3, 8)).unwrap();
        assert_eq!(backups_agree.close_deadline(), EvidenceState::NoQuorum);

        let mut no_primary = MatchTracker::new([1; 32], [[2; 32], [3; 32]]).unwrap();
        no_primary.observe(claim(2, 8)).unwrap();
        no_primary.observe(claim(3, 8)).unwrap();
        assert_eq!(no_primary.close_deadline(), EvidenceState::NoQuorum);
    }
}
