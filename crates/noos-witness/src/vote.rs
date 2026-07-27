//! `FinalityVoteV1` and its validity law (witness-v1.md §1.2; ch01 §4.8).
//!
//! Wire: versioned mandatory-tagged object, tags `1..=7` for schema fields
//! 0–6. The BLS signature (field 6) is under the registered vote DST
//! (`D-BLS-VOTE`) over the CANONICAL VOTE BODY — the encoding of fields
//! 0–5, i.e. the full wire encoding truncated before tag 7.
//!
//! Valid iff (§1.2):
//! * the target is an epoch checkpoint descended from the source;
//! * the source is already justified in the voter's view;
//! * `membership_root` equals the snapshotted Ring for `epoch`;
//! * the signature verifies under the vote DST over the canonical body.

use noos_braid::{Bytes96, CheckpointRef};
use noos_codec::{define_object, NoosEncode, Writer};
use noos_crypto::{bls_verify, BlsPublicKey, BlsSecretKey, BlsSignature, DomainId};

use crate::membership::MembershipSnapshotV1;
use crate::WitnessError;

define_object! {
    /// Source/target checkpoint vote (witness-v1.md §1.2).
    pub struct FinalityVoteV1 {
        version: 1;
        1 => chain_id: [u8; 32],
        2 => epoch: u64,
        3 => source: CheckpointRef,
        4 => target: CheckpointRef,
        5 => validator_id: [u8; 32],
        6 => membership_root: [u8; 32],
        7 => signature: Bytes96,
    }
}

/// The unsigned vote body (fields 0–5) as canonical bytes.
#[must_use]
pub fn vote_signing_bytes(
    chain_id: &[u8; 32],
    epoch: u64,
    source: &CheckpointRef,
    target: &CheckpointRef,
    validator_id: &[u8; 32],
    membership_root: &[u8; 32],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(FinalityVoteV1::VERSION);
    w.put_mandatory_tag(1);
    w.put_array32(chain_id);
    w.put_mandatory_tag(2);
    w.put_u64(epoch);
    w.put_mandatory_tag(3);
    source.encode(&mut w);
    w.put_mandatory_tag(4);
    target.encode(&mut w);
    w.put_mandatory_tag(5);
    w.put_array32(validator_id);
    w.put_mandatory_tag(6);
    w.put_array32(membership_root);
    w.into_bytes()
}

impl FinalityVoteV1 {
    /// Canonical vote body (fields 0–5) — the signed message.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        vote_signing_bytes(
            &self.chain_id,
            self.epoch,
            &self.source,
            &self.target,
            &self.validator_id,
            &self.membership_root,
        )
    }

    /// Signs a vote body under the registered vote DST.
    pub fn sign(
        chain_id: [u8; 32],
        epoch: u64,
        source: CheckpointRef,
        target: CheckpointRef,
        validator_id: [u8; 32],
        membership_root: [u8; 32],
        secret: &BlsSecretKey,
    ) -> Result<Self, WitnessError> {
        let body = vote_signing_bytes(
            &chain_id,
            epoch,
            &source,
            &target,
            &validator_id,
            &membership_root,
        );
        let sig = secret
            .sign_domain(DomainId::BlsVote, &body)
            .map_err(|_| WitnessError::CryptoRejected)?;
        Ok(Self {
            chain_id,
            epoch,
            source,
            target,
            validator_id,
            membership_root,
            signature: Bytes96(sig.into_bytes()),
        })
    }

    /// Verifies only the signature under the vote DST.
    pub fn verify_signature(&self, key: &BlsPublicKey) -> Result<(), WitnessError> {
        let sig = BlsSignature::from_bytes(self.signature.0);
        bls_verify(DomainId::BlsVote, key, &self.signing_bytes(), &sig)
            .map_err(|_| WitnessError::SignatureInvalid)
    }
}

/// The voter's local checkpoint view (§1.2): justification status and
/// checkpoint ancestry are Braid-side knowledge, consumed behind a trait.
pub trait CheckpointView {
    /// Whether `checkpoint` is justified in this view.
    fn is_justified(&self, checkpoint: &CheckpointRef) -> bool;
    /// Whether `target` is an epoch checkpoint descended from `source`.
    fn descends(&self, source: &CheckpointRef, target: &CheckpointRef) -> bool;
}

/// The full §1.2 validity law for a single vote against the epoch snapshot.
pub fn validate_vote(
    vote: &FinalityVoteV1,
    chain_id: &[u8; 32],
    snapshot: &MembershipSnapshotV1,
    view: &impl CheckpointView,
) -> Result<(), WitnessError> {
    if vote.chain_id != *chain_id {
        return Err(WitnessError::WrongChain);
    }
    // The vote's epoch IS the target checkpoint epoch; the snapshot must be
    // the Ring snapshotted for that epoch.
    if vote.epoch != vote.target.epoch || snapshot.epoch() != vote.epoch {
        return Err(WitnessError::EpochMismatch);
    }
    if vote.target.epoch <= vote.source.epoch {
        return Err(WitnessError::MalformedInterval);
    }
    if vote.membership_root != snapshot.root() {
        return Err(WitnessError::MembershipRootMismatch);
    }
    let member = snapshot
        .member(&vote.validator_id)
        .ok_or(WitnessError::UnknownValidator)?;
    if !view.descends(&vote.source, &vote.target) {
        return Err(WitnessError::TargetNotDescended);
    }
    vote.verify_signature(&BlsPublicKey::from_bytes(member.consensus_bls_key.0))?;
    if !view.is_justified(&vote.source) {
        return Err(WitnessError::SourceNotJustified);
    }
    Ok(())
}
