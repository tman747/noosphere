//! Consent-bound, non-authoritative Dream/Twin research notebook.
//!
//! The general forecast market is killed and cannot be enabled through this
//! module. The surviving API is private, payout-free, causally insulated, and
//! requires an owner-signed capability distinct from persona output before a
//! branch can be realized.

use crate::Hash32;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DREAM_LANE_ENABLED: bool = false;
pub const DREAM_PAYOUT: u128 = 0;
pub const DREAM_PROPOSAL_WEIGHT: u64 = 0;
pub const DREAM_FINALITY_WEIGHT: u64 = 0;
pub const MAX_FUTURE_CLOCK_SKEW_MS: u64 = 5_000;
pub const E_DREAM_02_EVENTS: u64 = 100_000;
pub const E_DREAM_02_SEED: u64 = 20_260_710;
pub const E_DREAM_02_PREMIUMS_UT: [u32; 5] = [0, 271, 542, 813, 1_084];
pub const E_DREAM_02_QUALITY_THRESHOLD_MILLI_MILLI_BRIER: i64 = 75_000;

fn digest(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    *h.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwinProfile {
    pub profile_id: Hash32,
    pub owner_identity: Hash32,
    pub owner_key: [u8; 32],
    pub persona_key: [u8; 32],
    pub consent_epoch: u64,
    pub permitted_questions: BTreeSet<Hash32>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    revoked: bool,
    quarantined: bool,
}

impl TwinProfile {
    #[must_use]
    pub fn derive_owner_identity(owner_key: [u8; 32]) -> Hash32 {
        digest(b"NOOS/DREAM/OWNER-IDENTITY/V1", &[&owner_key])
    }

    #[must_use]
    pub fn derive_profile_id(
        owner_identity: Hash32,
        owner_key: [u8; 32],
        persona_key: [u8; 32],
        consent_epoch: u64,
        permitted_questions: &BTreeSet<Hash32>,
        valid_from_ms: u64,
        valid_until_ms: u64,
    ) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/DREAM/TWIN-PROFILE/V1");
        h.update(&owner_identity);
        h.update(&owner_key);
        h.update(&persona_key);
        h.update(&consent_epoch.to_le_bytes());
        for question in permitted_questions {
            h.update(question);
        }
        h.update(&valid_from_ms.to_le_bytes());
        h.update(&valid_until_ms.to_le_bytes());
        *h.finalize().as_bytes()
    }

    pub fn validate(&self) -> Result<(), DreamError> {
        if self.owner_identity == [0; 32]
            || self.permitted_questions.is_empty()
            || self.valid_from_ms > self.valid_until_ms
            || self.owner_key == self.persona_key
            || self.owner_identity != Self::derive_owner_identity(self.owner_key)
            || self.profile_id
                != Self::derive_profile_id(
                    self.owner_identity,
                    self.owner_key,
                    self.persona_key,
                    self.consent_epoch,
                    &self.permitted_questions,
                    self.valid_from_ms,
                    self.valid_until_ms,
                )
        {
            return Err(DreamError::ProfileBinding);
        }
        VerifyingKey::from_bytes(&self.owner_key).map_err(|_| DreamError::ProfileBinding)?;
        VerifyingKey::from_bytes(&self.persona_key).map_err(|_| DreamError::ProfileBinding)?;
        Ok(())
    }

    pub fn permits(&self, question_id: Hash32, at_ms: u64) -> Result<(), DreamError> {
        self.validate()?;
        if self.revoked || self.quarantined {
            return Err(DreamError::ProfileRevoked);
        }
        if at_ms < self.valid_from_ms || at_ms > self.valid_until_ms {
            return Err(DreamError::ConsentScope);
        }
        if !self.permitted_questions.contains(&question_id) {
            return Err(DreamError::ConsentScope);
        }
        Ok(())
    }

    #[must_use]
    pub const fn represents_legal_identity(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn grants_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerRevocation {
    pub profile_id: Hash32,
    pub owner_identity: Hash32,
    pub consent_epoch: u64,
    pub revoked_at_ms: u64,
    pub signature: [u8; 64],
}

impl OwnerRevocation {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(112);
        bytes.extend_from_slice(b"NOOS/DREAM/OWNER-REVOCATION/V1");
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.owner_identity);
        bytes.extend_from_slice(&self.consent_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.revoked_at_ms.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResearchPolicy {
    pub private_notebook: bool,
    pub causally_insulated: bool,
    pub action_influence_possible: bool,
    pub payout: u128,
}

impl ResearchPolicy {
    #[must_use]
    pub const fn surviving_notebook() -> Self {
        Self {
            private_notebook: true,
            causally_insulated: true,
            action_influence_possible: false,
            payout: DREAM_PAYOUT,
        }
    }

    fn validate(self) -> Result<(), DreamError> {
        if !self.private_notebook
            || !self.causally_insulated
            || self.action_influence_possible
            || self.payout != 0
        {
            return Err(DreamError::KilledMarketBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchFamily {
    pub family_id: Hash32,
    pub profile_id: Hash32,
    pub question_id: Hash32,
    pub resolver_id: Hash32,
    pub commit_deadline_ms: u64,
    pub outcome_time_ms: u64,
    pub reveal_deadline_ms: u64,
}

impl BranchFamily {
    #[must_use]
    pub fn derive_id(
        profile_id: Hash32,
        question_id: Hash32,
        resolver_id: Hash32,
        commit_deadline_ms: u64,
        outcome_time_ms: u64,
        reveal_deadline_ms: u64,
    ) -> Hash32 {
        digest(
            b"NOOS/DREAM/BRANCH-FAMILY/V1",
            &[
                &profile_id,
                &question_id,
                &resolver_id,
                &commit_deadline_ms.to_le_bytes(),
                &outcome_time_ms.to_le_bytes(),
                &reveal_deadline_ms.to_le_bytes(),
            ],
        )
    }

    fn validate(&self, profile: &TwinProfile) -> Result<(), DreamError> {
        if self.profile_id != profile.profile_id
            || self.resolver_id == [0; 32]
            || self.commit_deadline_ms >= self.outcome_time_ms
            || self.outcome_time_ms >= self.reveal_deadline_ms
            || self.family_id
                != Self::derive_id(
                    self.profile_id,
                    self.question_id,
                    self.resolver_id,
                    self.commit_deadline_ms,
                    self.outcome_time_ms,
                    self.reveal_deadline_ms,
                )
        {
            return Err(DreamError::FamilyBinding);
        }
        profile.permits(self.question_id, self.commit_deadline_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBranch {
    pub family_id: Hash32,
    pub profile_id: Hash32,
    pub branch_id: Hash32,
    pub sequence: u64,
    pub prior_message: Hash32,
    pub submitted_at_ms: u64,
    pub forecast_commitment: Hash32,
    pub persona_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SealedBranch {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"NOOS/DREAM/SEALED-BRANCH/V1");
        bytes.extend_from_slice(&self.family_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.branch_id);
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.prior_message);
        bytes.extend_from_slice(&self.submitted_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.forecast_commitment);
        bytes.extend_from_slice(&self.persona_key);
        bytes
    }

    #[must_use]
    pub fn digest(&self) -> Hash32 {
        *blake3::hash(&self.signing_bytes()).as_bytes()
    }

    #[must_use]
    pub fn commitment(
        family_id: Hash32,
        profile_id: Hash32,
        branch_id: Hash32,
        payload: &[u8],
        salt: Hash32,
    ) -> Hash32 {
        digest(
            b"NOOS/DREAM/FORECAST-COMMITMENT/V1",
            &[&family_id, &profile_id, &branch_id, payload, &salt],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FamilyPhase {
    Draft = 0,
    Sealed = 1,
    Resolved = 2,
    Realized = 3,
    Invalidated = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptKind {
    Sealed = 0,
    Resolved = 1,
    Revealed = 2,
    RealizedByExternalCapability = 3,
    Revoked = 4,
    Invalidated = 5,
    RolledBack = 6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DreamReceipt {
    pub sequence: u64,
    pub previous_receipt_root: Hash32,
    pub event_root: Hash32,
    pub receipt_root: Hash32,
    pub family_id: Hash32,
    pub kind: ReceiptKind,
    pub authoritative_persona_output: bool,
    pub payout: u128,
    pub proposal_weight: u64,
    pub finality_weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FamilyState {
    family: BranchFamily,
    phase: FamilyPhase,
    candidates: BTreeMap<Hash32, SealedBranch>,
    accepted: BTreeMap<Hash32, SealedBranch>,
    outcome_root: Option<Hash32>,
    revealed: BTreeSet<Hash32>,
    realized_branch: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalRealizationCapability {
    pub capability_id: Hash32,
    pub owner_identity: Hash32,
    pub profile_id: Hash32,
    pub family_id: Hash32,
    pub branch_id: Hash32,
    pub expires_at_ms: u64,
    pub nonce: Hash32,
    pub signature: [u8; 64],
}

impl ExternalRealizationCapability {
    #[must_use]
    pub fn derive_id(
        owner_identity: Hash32,
        profile_id: Hash32,
        family_id: Hash32,
        branch_id: Hash32,
        expires_at_ms: u64,
        nonce: Hash32,
    ) -> Hash32 {
        digest(
            b"NOOS/DREAM/REALIZATION-CAPABILITY/V1",
            &[
                &owner_identity,
                &profile_id,
                &family_id,
                &branch_id,
                &expires_at_ms.to_le_bytes(),
                &nonce,
            ],
        )
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(232);
        bytes.extend_from_slice(b"NOOS/DREAM/REALIZATION-CAPABILITY/V1");
        bytes.extend_from_slice(&self.capability_id);
        bytes.extend_from_slice(&self.owner_identity);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.family_id);
        bytes.extend_from_slice(&self.branch_id);
        bytes.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DreamRollbackReceipt {
    pub prior_application_root: Hash32,
    pub restored_application_root: Hash32,
    pub base_consensus_root_before: Hash32,
    pub base_consensus_root_after: Hash32,
    pub quarantined_profile: Hash32,
    pub discarded_families: usize,
    pub dream_lane_enabled: bool,
    pub payout: u128,
    pub proposal_weight: u64,
    pub finality_weight: u64,
}

pub struct DreamNotebook {
    profile: TwinProfile,
    policy: ResearchPolicy,
    families: BTreeMap<Hash32, FamilyState>,
    receipt_sequence: u64,
    receipt_root: Hash32,
    spent_realization_nullifiers: BTreeSet<Hash32>,
    base_consensus_root: Hash32,
    disabled: bool,
}

impl DreamNotebook {
    pub fn new(
        profile: TwinProfile,
        policy: ResearchPolicy,
        base_consensus_root: Hash32,
    ) -> Result<Self, DreamError> {
        profile.validate()?;
        policy.validate()?;
        if base_consensus_root == [0; 32] {
            return Err(DreamError::BaseIsolation);
        }
        Ok(Self {
            profile,
            policy,
            families: BTreeMap::new(),
            receipt_sequence: 0,
            receipt_root: [0; 32],
            spent_realization_nullifiers: BTreeSet::new(),
            base_consensus_root,
            disabled: false,
        })
    }

    fn ensure_live(&self) -> Result<(), DreamError> {
        if self.disabled || self.profile.revoked || self.profile.quarantined {
            return Err(DreamError::ProfileRevoked);
        }
        self.policy.validate()
    }

    fn check_clock(&self, observed_at_ms: u64, now_ms: u64) -> Result<(), DreamError> {
        let latest = now_ms
            .checked_add(MAX_FUTURE_CLOCK_SKEW_MS)
            .ok_or(DreamError::ClockSkew)?;
        if observed_at_ms > latest {
            return Err(DreamError::ClockSkew);
        }
        Ok(())
    }

    pub fn register_family(&mut self, family: BranchFamily) -> Result<(), DreamError> {
        self.ensure_live()?;
        family.validate(&self.profile)?;
        if self.families.contains_key(&family.family_id) {
            return Err(DreamError::Duplicate);
        }
        self.families.insert(
            family.family_id,
            FamilyState {
                family,
                phase: FamilyPhase::Draft,
                candidates: BTreeMap::new(),
                accepted: BTreeMap::new(),
                outcome_root: None,
                revealed: BTreeSet::new(),
                realized_branch: None,
            },
        );
        Ok(())
    }

    pub fn submit_branch(
        &mut self,
        branch: SealedBranch,
        now_ms: u64,
    ) -> Result<Hash32, DreamError> {
        self.ensure_live()?;
        self.check_clock(branch.submitted_at_ms, now_ms)?;
        if branch.profile_id != self.profile.profile_id
            || branch.persona_key != self.profile.persona_key
            || branch.forecast_commitment == [0; 32]
        {
            return Err(DreamError::ProfileBinding);
        }
        self.profile.permits(
            self.families
                .get(&branch.family_id)
                .ok_or(DreamError::UnknownFamily)?
                .family
                .question_id,
            branch.submitted_at_ms,
        )?;
        let state = self
            .families
            .get_mut(&branch.family_id)
            .ok_or(DreamError::UnknownFamily)?;
        if state.phase != FamilyPhase::Draft {
            return Err(DreamError::Stale);
        }
        if branch.submitted_at_ms > state.family.commit_deadline_ms {
            return Err(DreamError::ClockSkew);
        }
        let key = VerifyingKey::from_bytes(&self.profile.persona_key)
            .map_err(|_| DreamError::Signature)?;
        key.verify(
            &branch.signing_bytes(),
            &Signature::from_bytes(&branch.signature),
        )
        .map_err(|_| DreamError::Signature)?;
        let branch_digest = branch.digest();
        if state.candidates.contains_key(&branch_digest) {
            return Err(DreamError::Duplicate);
        }
        state.candidates.insert(branch_digest, branch);
        Ok(branch_digest)
    }

    fn make_receipt(
        &mut self,
        family_id: Hash32,
        kind: ReceiptKind,
        event_root: Hash32,
    ) -> Result<DreamReceipt, DreamError> {
        let sequence = self.receipt_sequence;
        let previous_receipt_root = self.receipt_root;
        let kind_byte = [kind as u8];
        let receipt_root = digest(
            b"NOOS/DREAM/RECEIPT/V1",
            &[
                &sequence.to_le_bytes(),
                &previous_receipt_root,
                &event_root,
                &family_id,
                &kind_byte,
            ],
        );
        self.receipt_sequence = self
            .receipt_sequence
            .checked_add(1)
            .ok_or(DreamError::StateOverflow)?;
        self.receipt_root = receipt_root;
        Ok(DreamReceipt {
            sequence,
            previous_receipt_root,
            event_root,
            receipt_root,
            family_id,
            kind,
            authoritative_persona_output: false,
            payout: DREAM_PAYOUT,
            proposal_weight: DREAM_PROPOSAL_WEIGHT,
            finality_weight: DREAM_FINALITY_WEIGHT,
        })
    }

    pub fn reconcile_family(&mut self, family_id: Hash32) -> Result<DreamReceipt, DreamError> {
        self.ensure_live()?;
        let (event_root, invalid) = {
            let state = self
                .families
                .get_mut(&family_id)
                .ok_or(DreamError::UnknownFamily)?;
            if state.phase != FamilyPhase::Draft || state.candidates.is_empty() {
                return Err(DreamError::Phase);
            }
            let mut by_sequence: BTreeMap<u64, Vec<(Hash32, SealedBranch)>> = BTreeMap::new();
            let mut by_branch: BTreeMap<Hash32, usize> = BTreeMap::new();
            for (candidate_digest, branch) in &state.candidates {
                by_sequence
                    .entry(branch.sequence)
                    .or_default()
                    .push((*candidate_digest, branch.clone()));
                let count = by_branch.entry(branch.branch_id).or_default();
                *count = count.checked_add(1).ok_or(DreamError::StateOverflow)?;
            }
            let conflict = by_sequence.values().any(|branches| branches.len() != 1)
                || by_branch.values().any(|count| *count != 1);
            let mut expected_sequence = 0u64;
            let mut expected_prior = [0; 32];
            let mut accepted = BTreeMap::new();
            if !conflict {
                for (sequence, branches) in by_sequence {
                    let (candidate_digest, branch) =
                        branches.first().cloned().ok_or(DreamError::StateOverflow)?;
                    if sequence != expected_sequence || branch.prior_message != expected_prior {
                        return Err(DreamError::BranchReconciliation);
                    }
                    accepted.insert(branch.branch_id, branch);
                    expected_sequence = expected_sequence
                        .checked_add(1)
                        .ok_or(DreamError::StateOverflow)?;
                    expected_prior = candidate_digest;
                }
            }
            let mut h = blake3::Hasher::new();
            h.update(b"NOOS/DREAM/RECONCILED-FAMILY/V1");
            h.update(&family_id);
            if conflict {
                for candidate_digest in state.candidates.keys() {
                    h.update(candidate_digest);
                }
                state.phase = FamilyPhase::Invalidated;
            } else {
                for branch in accepted.values() {
                    h.update(&branch.digest());
                }
                state.accepted = accepted;
                state.phase = FamilyPhase::Sealed;
            }
            (*h.finalize().as_bytes(), conflict)
        };
        self.make_receipt(
            family_id,
            if invalid {
                ReceiptKind::Invalidated
            } else {
                ReceiptKind::Sealed
            },
            event_root,
        )
    }

    pub fn resolve(
        &mut self,
        family_id: Hash32,
        resolver_id: Hash32,
        outcome_root: Hash32,
        resolved_at_ms: u64,
        participant_influence_detected: bool,
    ) -> Result<DreamReceipt, DreamError> {
        self.ensure_live()?;
        self.profile.permits(
            self.families
                .get(&family_id)
                .ok_or(DreamError::UnknownFamily)?
                .family
                .question_id,
            resolved_at_ms,
        )?;
        let (kind, event_root) = {
            let state = self
                .families
                .get_mut(&family_id)
                .ok_or(DreamError::UnknownFamily)?;
            if state.phase != FamilyPhase::Sealed
                || resolver_id != state.family.resolver_id
                || outcome_root == [0; 32]
                || resolved_at_ms < state.family.outcome_time_ms
                || resolved_at_ms > state.family.reveal_deadline_ms
            {
                return Err(DreamError::Resolution);
            }
            let event_root = digest(
                b"NOOS/DREAM/RESOLUTION/V1",
                &[
                    &family_id,
                    &resolver_id,
                    &outcome_root,
                    &resolved_at_ms.to_le_bytes(),
                    &[u8::from(participant_influence_detected)],
                ],
            );
            if participant_influence_detected {
                state.phase = FamilyPhase::Invalidated;
                (ReceiptKind::Invalidated, event_root)
            } else {
                state.outcome_root = Some(outcome_root);
                state.phase = FamilyPhase::Resolved;
                (ReceiptKind::Resolved, event_root)
            }
        };
        self.make_receipt(family_id, kind, event_root)
    }

    pub fn reveal(
        &mut self,
        family_id: Hash32,
        branch_id: Hash32,
        payload: &[u8],
        salt: Hash32,
        revealed_at_ms: u64,
    ) -> Result<DreamReceipt, DreamError> {
        self.ensure_live()?;
        self.profile.permits(
            self.families
                .get(&family_id)
                .ok_or(DreamError::UnknownFamily)?
                .family
                .question_id,
            revealed_at_ms,
        )?;
        let event_root = {
            let state = self
                .families
                .get_mut(&family_id)
                .ok_or(DreamError::UnknownFamily)?;
            if state.phase != FamilyPhase::Resolved
                || revealed_at_ms > state.family.reveal_deadline_ms
            {
                return Err(DreamError::Phase);
            }
            let branch = state
                .accepted
                .get(&branch_id)
                .ok_or(DreamError::UnknownBranch)?;
            let commitment = SealedBranch::commitment(
                family_id,
                self.profile.profile_id,
                branch_id,
                payload,
                salt,
            );
            if commitment != branch.forecast_commitment || !state.revealed.insert(branch_id) {
                return Err(DreamError::Reveal);
            }
            digest(
                b"NOOS/DREAM/REVEAL/V1",
                &[&family_id, &branch_id, &commitment],
            )
        };
        self.make_receipt(family_id, ReceiptKind::Revealed, event_root)
    }

    pub fn persona_realization_attempt(&self, _family_id: Hash32) -> Result<(), DreamError> {
        Err(DreamError::SeparateCapabilityRequired)
    }

    pub fn realize(
        &mut self,
        capability: &ExternalRealizationCapability,
        now_ms: u64,
    ) -> Result<DreamReceipt, DreamError> {
        self.ensure_live()?;
        self.profile.permits(
            self.families
                .get(&capability.family_id)
                .ok_or(DreamError::UnknownFamily)?
                .family
                .question_id,
            now_ms,
        )?;
        if capability.owner_identity != self.profile.owner_identity
            || capability.profile_id != self.profile.profile_id
            || capability.nonce == [0; 32]
            || capability.expires_at_ms < now_ms
            || capability.capability_id
                != ExternalRealizationCapability::derive_id(
                    capability.owner_identity,
                    capability.profile_id,
                    capability.family_id,
                    capability.branch_id,
                    capability.expires_at_ms,
                    capability.nonce,
                )
        {
            return Err(DreamError::Capability);
        }
        let owner_key =
            VerifyingKey::from_bytes(&self.profile.owner_key).map_err(|_| DreamError::Signature)?;
        owner_key
            .verify(
                &capability.signing_bytes(),
                &Signature::from_bytes(&capability.signature),
            )
            .map_err(|_| DreamError::Signature)?;
        let nullifier = digest(
            b"NOOS/DREAM/REALIZATION-NULLIFIER/V1",
            &[
                &capability.profile_id,
                &capability.family_id,
                &capability.nonce,
            ],
        );
        if !self.spent_realization_nullifiers.insert(nullifier) {
            return Err(DreamError::RealizationReplay);
        }
        {
            let state = self
                .families
                .get_mut(&capability.family_id)
                .ok_or(DreamError::UnknownFamily)?;
            if state.phase != FamilyPhase::Resolved
                || !state.revealed.contains(&capability.branch_id)
                || state.realized_branch.is_some()
            {
                self.spent_realization_nullifiers.remove(&nullifier);
                return Err(DreamError::Capability);
            }
            state.realized_branch = Some(capability.branch_id);
            state.phase = FamilyPhase::Realized;
        }
        self.make_receipt(
            capability.family_id,
            ReceiptKind::RealizedByExternalCapability,
            capability.capability_id,
        )
    }

    pub fn revoke_profile(
        &mut self,
        revocation: &OwnerRevocation,
    ) -> Result<DreamReceipt, DreamError> {
        if self.profile.revoked || self.profile.quarantined {
            return Err(DreamError::ProfileRevoked);
        }
        if revocation.profile_id != self.profile.profile_id
            || revocation.owner_identity != self.profile.owner_identity
            || revocation.consent_epoch != self.profile.consent_epoch
        {
            return Err(DreamError::ProfileBinding);
        }
        let key =
            VerifyingKey::from_bytes(&self.profile.owner_key).map_err(|_| DreamError::Signature)?;
        key.verify(
            &revocation.signing_bytes(),
            &Signature::from_bytes(&revocation.signature),
        )
        .map_err(|_| DreamError::Signature)?;
        self.profile.revoked = true;
        self.profile.quarantined = true;
        for state in self.families.values_mut() {
            if state.phase != FamilyPhase::Realized {
                state.phase = FamilyPhase::Invalidated;
            }
        }
        let event_root = *blake3::hash(&revocation.signing_bytes()).as_bytes();
        self.make_receipt([0; 32], ReceiptKind::Revoked, event_root)
    }

    #[must_use]
    pub fn application_root(&self) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/DREAM/APPLICATION-STATE/V1");
        h.update(&self.profile.profile_id);
        h.update(&self.receipt_root);
        h.update(&[
            u8::from(self.profile.revoked),
            u8::from(self.profile.quarantined),
            u8::from(self.disabled),
        ]);
        for (family_id, state) in &self.families {
            h.update(family_id);
            h.update(&[state.phase as u8]);
        }
        *h.finalize().as_bytes()
    }

    #[must_use]
    pub fn disable_and_rollback(&mut self) -> DreamRollbackReceipt {
        let prior_application_root = self.application_root();
        let discarded_families = self.families.len();
        let base_consensus_root_before = self.base_consensus_root;
        self.families.clear();
        self.spent_realization_nullifiers.clear();
        self.profile.quarantined = true;
        self.disabled = true;
        self.receipt_root = [0; 32];
        self.receipt_sequence = 0;
        DreamRollbackReceipt {
            prior_application_root,
            restored_application_root: self.application_root(),
            base_consensus_root_before,
            base_consensus_root_after: self.base_consensus_root,
            quarantined_profile: self.profile.profile_id,
            discarded_families,
            dream_lane_enabled: DREAM_LANE_ENABLED,
            payout: DREAM_PAYOUT,
            proposal_weight: DREAM_PROPOSAL_WEIGHT,
            finality_weight: DREAM_FINALITY_WEIGHT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PremiumSweepObservation {
    pub premium_ut: u32,
    pub events: u64,
    pub seed: u64,
    pub insulated_only: bool,
    pub manipulator_excluded: bool,
    /// Tenths of a microtoken per event, avoiding floating point.
    pub manipulator_net_tenths_ut: i64,
    pub honest_net_tenths_ut: i64,
    /// Thousandths of a milli-Brier improvement.
    pub main_quality_milli_milli_brier: i64,
    pub manipulation_quality_milli_milli_brier: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DreamExperimentVerdict {
    Passed { premium_ut: u32 },
    Killed,
}

/// Exact integer evaluator for the preregistered E-DREAM-02 sweep. It is an
/// instrument precursor; it does not manufacture the experiment observations.
pub struct DreamInstrumentV1;

impl DreamInstrumentV1 {
    pub fn evaluate(
        observations: &[PremiumSweepObservation],
    ) -> Result<DreamExperimentVerdict, DreamError> {
        if observations.len() != E_DREAM_02_PREMIUMS_UT.len() {
            return Err(DreamError::InstrumentShape);
        }
        let mut by_premium = BTreeMap::new();
        for observation in observations {
            if observation.events != E_DREAM_02_EVENTS
                || observation.seed != E_DREAM_02_SEED
                || !observation.insulated_only
                || by_premium
                    .insert(observation.premium_ut, *observation)
                    .is_some()
            {
                return Err(DreamError::InstrumentShape);
            }
        }
        if by_premium.keys().copied().collect::<Vec<_>>() != E_DREAM_02_PREMIUMS_UT {
            return Err(DreamError::InstrumentShape);
        }
        let exclusion = by_premium.get(&0).ok_or(DreamError::InstrumentShape)?;
        if !exclusion.manipulator_excluded {
            return Err(DreamError::InstrumentShape);
        }
        for premium in [271, 542, 813, 1_084] {
            if by_premium
                .get(&premium)
                .ok_or(DreamError::InstrumentShape)?
                .manipulator_excluded
            {
                return Err(DreamError::InstrumentShape);
            }
        }
        for premium in [542, 813, 1_084] {
            let observation = by_premium
                .get(&premium)
                .ok_or(DreamError::InstrumentShape)?;
            if observation.manipulator_net_tenths_ut <= 0
                && observation.honest_net_tenths_ut > 0
                && observation.main_quality_milli_milli_brier
                    >= E_DREAM_02_QUALITY_THRESHOLD_MILLI_MILLI_BRIER
                && observation.manipulation_quality_milli_milli_brier
                    >= E_DREAM_02_QUALITY_THRESHOLD_MILLI_MILLI_BRIER
            {
                return Ok(DreamExperimentVerdict::Passed {
                    premium_ut: premium,
                });
            }
        }
        Ok(DreamExperimentVerdict::Killed)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DreamError {
    #[error("twin profile identity or consent binding invalid")]
    ProfileBinding,
    #[error("twin profile is revoked or quarantined")]
    ProfileRevoked,
    #[error("query is outside consent scope")]
    ConsentScope,
    #[error("general dream market boundary is killed")]
    KilledMarketBoundary,
    #[error("branch family binding invalid")]
    FamilyBinding,
    #[error("unknown branch family")]
    UnknownFamily,
    #[error("unknown sealed branch")]
    UnknownBranch,
    #[error("duplicate message or family")]
    Duplicate,
    #[error("stale lifecycle message")]
    Stale,
    #[error("message is outside the inclusive clock boundary")]
    ClockSkew,
    #[error("invalid owner or persona signature")]
    Signature,
    #[error("family lifecycle phase rejects this transition")]
    Phase,
    #[error("branch family has an equivocation or noncanonical chain")]
    BranchReconciliation,
    #[error("resolution source, outcome, or time invalid")]
    Resolution,
    #[error("forecast reveal does not open its commitment")]
    Reveal,
    #[error("persona output cannot realize a branch")]
    SeparateCapabilityRequired,
    #[error("external realization capability invalid")]
    Capability,
    #[error("realization nullifier already spent")]
    RealizationReplay,
    #[error("base consensus isolation invalid")]
    BaseIsolation,
    #[error("dream state counter overflow")]
    StateOverflow,
    #[error("E-DREAM-02 instrument inputs do not match the preregistration")]
    InstrumentShape,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        clippy::unwrap_used
    )]

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn profile(owner: &SigningKey, persona: &SigningKey) -> TwinProfile {
        let owner_key = owner.verifying_key().to_bytes();
        let persona_key = persona.verifying_key().to_bytes();
        let owner_identity = TwinProfile::derive_owner_identity(owner_key);
        let permitted_questions = BTreeSet::from([h(10), h(11)]);
        let consent_epoch = 7;
        let valid_from_ms = 0;
        let valid_until_ms = 1_000_000;
        TwinProfile {
            profile_id: TwinProfile::derive_profile_id(
                owner_identity,
                owner_key,
                persona_key,
                consent_epoch,
                &permitted_questions,
                valid_from_ms,
                valid_until_ms,
            ),
            owner_identity,
            owner_key,
            persona_key,
            consent_epoch,
            permitted_questions,
            valid_from_ms,
            valid_until_ms,
            revoked: false,
            quarantined: false,
        }
    }

    fn branch_family(
        profile: &TwinProfile,
        question_id: Hash32,
        discriminator: u8,
    ) -> BranchFamily {
        let resolver_id = h(discriminator);
        let commit_deadline_ms = 100_000;
        let outcome_time_ms = 200_000;
        let reveal_deadline_ms = 300_000;
        BranchFamily {
            family_id: BranchFamily::derive_id(
                profile.profile_id,
                question_id,
                resolver_id,
                commit_deadline_ms,
                outcome_time_ms,
                reveal_deadline_ms,
            ),
            profile_id: profile.profile_id,
            question_id,
            resolver_id,
            commit_deadline_ms,
            outcome_time_ms,
            reveal_deadline_ms,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn branch(
        persona: &SigningKey,
        profile: &TwinProfile,
        family: &BranchFamily,
        branch_id: Hash32,
        sequence: u64,
        prior_message: Hash32,
        submitted_at_ms: u64,
        payload: &[u8],
        salt: Hash32,
    ) -> SealedBranch {
        let mut branch = SealedBranch {
            family_id: family.family_id,
            profile_id: profile.profile_id,
            branch_id,
            sequence,
            prior_message,
            submitted_at_ms,
            forecast_commitment: SealedBranch::commitment(
                family.family_id,
                profile.profile_id,
                branch_id,
                payload,
                salt,
            ),
            persona_key: persona.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        branch.signature = persona.sign(&branch.signing_bytes()).to_bytes();
        branch
    }

    fn capability(
        owner: &SigningKey,
        profile: &TwinProfile,
        family_id: Hash32,
        branch_id: Hash32,
    ) -> ExternalRealizationCapability {
        let expires_at_ms = 400_000;
        let nonce = h(90);
        let mut capability = ExternalRealizationCapability {
            capability_id: ExternalRealizationCapability::derive_id(
                profile.owner_identity,
                profile.profile_id,
                family_id,
                branch_id,
                expires_at_ms,
                nonce,
            ),
            owner_identity: profile.owner_identity,
            profile_id: profile.profile_id,
            family_id,
            branch_id,
            expires_at_ms,
            nonce,
            signature: [0; 64],
        };
        capability.signature = owner.sign(&capability.signing_bytes()).to_bytes();
        capability
    }

    #[test]
    fn profile_is_consent_bound_and_never_identity_or_authority() {
        let owner = SigningKey::from_bytes(&h(1));
        let persona = SigningKey::from_bytes(&h(2));
        let profile = profile(&owner, &persona);
        assert!(profile.validate().is_ok());
        assert!(profile.permits(h(10), 100).is_ok());
        assert_eq!(profile.permits(h(99), 100), Err(DreamError::ConsentScope));
        assert!(!profile.represents_legal_identity());
        assert!(!profile.grants_authority());
        let mut rebound = profile.clone();
        rebound.owner_identity = h(77);
        assert_eq!(rebound.validate(), Err(DreamError::ProfileBinding));
    }

    #[test]
    fn plural_branch_order_reconciles_to_identical_receipts() {
        let owner = SigningKey::from_bytes(&h(3));
        let persona = SigningKey::from_bytes(&h(4));
        let profile = profile(&owner, &persona);
        let family = branch_family(&profile, h(10), 30);
        let first = branch(
            &persona,
            &profile,
            &family,
            h(40),
            0,
            [0; 32],
            99_000,
            b"future-a",
            h(50),
        );
        let second = branch(
            &persona,
            &profile,
            &family,
            h(41),
            1,
            first.digest(),
            99_001,
            b"future-b",
            h(51),
        );
        let mut left = DreamNotebook::new(
            profile.clone(),
            ResearchPolicy::surviving_notebook(),
            h(100),
        )
        .unwrap();
        let mut right = DreamNotebook::new(
            profile.clone(),
            ResearchPolicy::surviving_notebook(),
            h(100),
        )
        .unwrap();
        left.register_family(family.clone()).unwrap();
        right.register_family(family.clone()).unwrap();
        left.submit_branch(first.clone(), 99_000).unwrap();
        left.submit_branch(second.clone(), 99_001).unwrap();
        right.submit_branch(second, 99_001).unwrap();
        right.submit_branch(first, 99_000).unwrap();
        let left_receipt = left.reconcile_family(family.family_id).unwrap();
        let right_receipt = right.reconcile_family(family.family_id).unwrap();
        assert_eq!(left_receipt, right_receipt);
        assert_eq!(left_receipt.kind, ReceiptKind::Sealed);
        assert!(!left_receipt.authoritative_persona_output);
        assert_eq!(
            (
                left_receipt.payout,
                left_receipt.proposal_weight,
                left_receipt.finality_weight
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn duplicate_stale_and_forked_branches_fail_closed() {
        let owner = SigningKey::from_bytes(&h(5));
        let persona = SigningKey::from_bytes(&h(6));
        let profile = profile(&owner, &persona);
        let family = branch_family(&profile, h(10), 31);
        let first = branch(
            &persona,
            &profile,
            &family,
            h(42),
            0,
            [0; 32],
            99_000,
            b"future",
            h(52),
        );
        let mut notebook = DreamNotebook::new(
            profile.clone(),
            ResearchPolicy::surviving_notebook(),
            h(100),
        )
        .unwrap();
        notebook.register_family(family.clone()).unwrap();
        notebook.submit_branch(first.clone(), 99_000).unwrap();
        assert_eq!(
            notebook.submit_branch(first.clone(), 99_000),
            Err(DreamError::Duplicate)
        );
        notebook.reconcile_family(family.family_id).unwrap();
        assert_eq!(
            notebook.submit_branch(first, 99_000),
            Err(DreamError::Stale)
        );

        let fork_family = branch_family(&profile, h(11), 32);
        let fork_a = branch(
            &persona,
            &profile,
            &fork_family,
            h(43),
            0,
            [0; 32],
            99_000,
            b"a",
            h(53),
        );
        let fork_b = branch(
            &persona,
            &profile,
            &fork_family,
            h(44),
            0,
            [0; 32],
            99_000,
            b"b",
            h(54),
        );
        notebook.register_family(fork_family.clone()).unwrap();
        notebook.submit_branch(fork_a, 99_000).unwrap();
        notebook.submit_branch(fork_b, 99_000).unwrap();
        let receipt = notebook.reconcile_family(fork_family.family_id).unwrap();
        assert_eq!(receipt.kind, ReceiptKind::Invalidated);
        assert_eq!(
            notebook.families.get(&fork_family.family_id).unwrap().phase,
            FamilyPhase::Invalidated
        );
    }

    #[test]
    fn clock_skew_boundaries_and_profile_binding_are_exact() {
        let owner = SigningKey::from_bytes(&h(7));
        let persona = SigningKey::from_bytes(&h(8));
        let profile = profile(&owner, &persona);
        let family = branch_family(&profile, h(10), 33);
        let now = 90_000;
        let at_boundary = branch(
            &persona,
            &profile,
            &family,
            h(45),
            0,
            [0; 32],
            now + MAX_FUTURE_CLOCK_SKEW_MS,
            b"ok",
            h(55),
        );
        let mut notebook = DreamNotebook::new(
            profile.clone(),
            ResearchPolicy::surviving_notebook(),
            h(100),
        )
        .unwrap();
        notebook.register_family(family.clone()).unwrap();
        assert!(notebook.submit_branch(at_boundary, now).is_ok());

        let other_family = branch_family(&profile, h(11), 34);
        notebook.register_family(other_family.clone()).unwrap();
        let beyond = branch(
            &persona,
            &profile,
            &other_family,
            h(46),
            0,
            [0; 32],
            now + MAX_FUTURE_CLOCK_SKEW_MS + 1,
            b"late",
            h(56),
        );
        assert_eq!(
            notebook.submit_branch(beyond, now),
            Err(DreamError::ClockSkew)
        );
        let foreign_persona = SigningKey::from_bytes(&h(9));
        let rebound = branch(
            &foreign_persona,
            &profile,
            &other_family,
            h(47),
            0,
            [0; 32],
            now,
            b"rebound",
            h(57),
        );
        assert_eq!(
            notebook.submit_branch(rebound, now),
            Err(DreamError::ProfileBinding)
        );
    }

    #[test]
    fn realization_requires_owner_capability_and_is_globally_one_shot() {
        let owner = SigningKey::from_bytes(&h(10));
        let persona = SigningKey::from_bytes(&h(11));
        let profile = profile(&owner, &persona);
        let family = branch_family(&profile, h(10), 35);
        let branch_id = h(48);
        let payload = b"revealed future";
        let salt = h(58);
        let sealed = branch(
            &persona, &profile, &family, branch_id, 0, [0; 32], 99_000, payload, salt,
        );
        let mut notebook = DreamNotebook::new(
            profile.clone(),
            ResearchPolicy::surviving_notebook(),
            h(100),
        )
        .unwrap();
        notebook.register_family(family.clone()).unwrap();
        notebook.submit_branch(sealed, 99_000).unwrap();
        notebook.reconcile_family(family.family_id).unwrap();
        notebook
            .resolve(
                family.family_id,
                family.resolver_id,
                h(70),
                family.outcome_time_ms,
                false,
            )
            .unwrap();
        notebook
            .reveal(
                family.family_id,
                branch_id,
                payload,
                salt,
                family.reveal_deadline_ms,
            )
            .unwrap();
        assert_eq!(
            notebook.persona_realization_attempt(family.family_id),
            Err(DreamError::SeparateCapabilityRequired)
        );
        let capability = capability(&owner, &profile, family.family_id, branch_id);
        let receipt = notebook.realize(&capability, 350_000).unwrap();
        assert_eq!(receipt.kind, ReceiptKind::RealizedByExternalCapability);
        assert!(!receipt.authoritative_persona_output);
        assert_eq!(
            notebook.realize(&capability, 350_000),
            Err(DreamError::RealizationReplay)
        );
    }

    #[test]
    fn influence_revocation_and_rollback_quarantine_without_base_effects() {
        let owner = SigningKey::from_bytes(&h(12));
        let persona = SigningKey::from_bytes(&h(13));
        let profile = profile(&owner, &persona);
        let base_root = h(100);
        let family = branch_family(&profile, h(10), 36);
        let sealed = branch(
            &persona,
            &profile,
            &family,
            h(49),
            0,
            [0; 32],
            99_000,
            b"future",
            h(59),
        );
        let mut notebook = DreamNotebook::new(
            profile.clone(),
            ResearchPolicy::surviving_notebook(),
            base_root,
        )
        .unwrap();
        notebook.register_family(family.clone()).unwrap();
        notebook.submit_branch(sealed, 99_000).unwrap();
        notebook.reconcile_family(family.family_id).unwrap();
        let invalidated = notebook
            .resolve(
                family.family_id,
                family.resolver_id,
                h(71),
                family.outcome_time_ms,
                true,
            )
            .unwrap();
        assert_eq!(invalidated.kind, ReceiptKind::Invalidated);

        let mut revocation = OwnerRevocation {
            profile_id: profile.profile_id,
            owner_identity: profile.owner_identity,
            consent_epoch: profile.consent_epoch,
            revoked_at_ms: 250_000,
            signature: [0; 64],
        };
        revocation.signature = owner.sign(&revocation.signing_bytes()).to_bytes();
        let receipt = notebook.revoke_profile(&revocation).unwrap();
        assert_eq!(receipt.kind, ReceiptKind::Revoked);
        assert_eq!(
            notebook.register_family(family.clone()),
            Err(DreamError::ProfileRevoked)
        );
        let before_disabled = notebook.application_root();
        let rollback = notebook.disable_and_rollback();
        assert_ne!(rollback.prior_application_root, [0; 32]);
        assert_ne!(before_disabled, rollback.restored_application_root);
        assert_eq!(rollback.base_consensus_root_before, base_root);
        assert_eq!(rollback.base_consensus_root_after, base_root);
        assert_eq!(
            (
                rollback.dream_lane_enabled,
                rollback.payout,
                rollback.proposal_weight,
                rollback.finality_weight
            ),
            (false, 0, 0, 0)
        );
        let root = notebook.application_root();
        assert_eq!(
            notebook.register_family(family),
            Err(DreamError::ProfileRevoked)
        );
        assert_eq!(notebook.application_root(), root);
    }

    #[test]
    fn killed_market_policy_cannot_be_reopened() {
        let owner = SigningKey::from_bytes(&h(14));
        let persona = SigningKey::from_bytes(&h(15));
        let profile = profile(&owner, &persona);
        for policy in [
            ResearchPolicy {
                private_notebook: false,
                ..ResearchPolicy::surviving_notebook()
            },
            ResearchPolicy {
                causally_insulated: false,
                ..ResearchPolicy::surviving_notebook()
            },
            ResearchPolicy {
                action_influence_possible: true,
                ..ResearchPolicy::surviving_notebook()
            },
            ResearchPolicy {
                payout: 1,
                ..ResearchPolicy::surviving_notebook()
            },
        ] {
            assert!(matches!(
                DreamNotebook::new(profile.clone(), policy, h(100)),
                Err(DreamError::KilledMarketBoundary)
            ));
        }
        assert!(!DREAM_LANE_ENABLED);
        assert_eq!(
            (DREAM_PAYOUT, DREAM_PROPOSAL_WEIGHT, DREAM_FINALITY_WEIGHT),
            (0, 0, 0)
        );
    }

    fn measured_sweep() -> [PremiumSweepObservation; 5] {
        [
            PremiumSweepObservation {
                premium_ut: 0,
                events: E_DREAM_02_EVENTS,
                seed: E_DREAM_02_SEED,
                insulated_only: true,
                manipulator_excluded: true,
                manipulator_net_tenths_ut: 0,
                honest_net_tenths_ut: 11_391,
                main_quality_milli_milli_brier: 167_544,
                manipulation_quality_milli_milli_brier: 176_806,
            },
            PremiumSweepObservation {
                premium_ut: 271,
                events: E_DREAM_02_EVENTS,
                seed: E_DREAM_02_SEED,
                insulated_only: true,
                manipulator_excluded: false,
                manipulator_net_tenths_ut: 13_346,
                honest_net_tenths_ut: 11_391,
                main_quality_milli_milli_brier: 167_643,
                manipulation_quality_milli_milli_brier: 215_093,
            },
            PremiumSweepObservation {
                premium_ut: 542,
                events: E_DREAM_02_EVENTS,
                seed: E_DREAM_02_SEED,
                insulated_only: true,
                manipulator_excluded: false,
                manipulator_net_tenths_ut: 10_636,
                honest_net_tenths_ut: 11_391,
                main_quality_milli_milli_brier: 167_643,
                manipulation_quality_milli_milli_brier: 215_093,
            },
            PremiumSweepObservation {
                premium_ut: 813,
                events: E_DREAM_02_EVENTS,
                seed: E_DREAM_02_SEED,
                insulated_only: true,
                manipulator_excluded: false,
                manipulator_net_tenths_ut: 7_926,
                honest_net_tenths_ut: 11_391,
                main_quality_milli_milli_brier: 167_643,
                manipulation_quality_milli_milli_brier: 215_093,
            },
            PremiumSweepObservation {
                premium_ut: 1_084,
                events: E_DREAM_02_EVENTS,
                seed: E_DREAM_02_SEED,
                insulated_only: true,
                manipulator_excluded: false,
                manipulator_net_tenths_ut: 5_216,
                honest_net_tenths_ut: 11_391,
                main_quality_milli_milli_brier: 167_643,
                manipulation_quality_milli_milli_brier: 215_093,
            },
        ]
    }

    #[test]
    fn e_dream_02_instrument_enforces_exact_sweep_and_kill_without_repricing() {
        let measured = measured_sweep();
        assert_eq!(
            DreamInstrumentV1::evaluate(&measured).unwrap(),
            DreamExperimentVerdict::Killed
        );
        let mut passing = measured;
        passing[4].manipulator_net_tenths_ut = 0;
        assert_eq!(
            DreamInstrumentV1::evaluate(&passing).unwrap(),
            DreamExperimentVerdict::Passed { premium_ut: 1_084 }
        );
        let mut malformed = measured;
        malformed[3].premium_ut = 814;
        assert_eq!(
            DreamInstrumentV1::evaluate(&malformed),
            Err(DreamError::InstrumentShape)
        );
    }
}
