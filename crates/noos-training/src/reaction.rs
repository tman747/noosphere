use noos_species::{domain_hash, Hash32, SpeciesRevision, UpdateKind, UpdatePacket};
use std::collections::{BTreeMap, BTreeSet};

use crate::TrainingError;

const REACTION_DOMAIN: &str = "NOOS/SPECIES/REACTION/V1";
const REACTION_OUTPUT_DOMAIN: &str = "NOOS/SPECIES/REACTION-OUTPUT/V1";
const CAPSULE_DOMAIN: &str = "NOOS/SPECIES/REACTION-CAPSULE/V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactionCapsule {
    pub capsule_root: Hash32,
    pub delta: Vec<i64>,
    pub divisor: u64,
}

impl ReactionCapsule {
    #[must_use]
    pub fn derived_root(&self) -> Hash32 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.divisor.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.delta.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for value in &self.delta {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        domain_hash(CAPSULE_DOMAIN, &[&bytes])
    }

    pub fn validate(&self) -> Result<(), TrainingError> {
        if self.delta.is_empty() || self.divisor == 0 || self.capsule_root != self.derived_root() {
            Err(TrainingError::InvalidReactionCapsule)
        } else {
            Ok(())
        }
    }
}

fn state_root(values: &[i64]) -> Hash32 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u32::try_from(values.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    domain_hash(REACTION_OUTPUT_DOMAIN, &[&bytes])
}

#[derive(Clone, Copy, Debug)]
pub struct ReactionReplay<'a> {
    pub capsule: &'a ReactionCapsule,
    pub parent_state: &'a [i64],
    pub candidate_state: &'a [i64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reaction {
    pub reaction_id: Hash32,
    pub parent_revision: Hash32,
    pub update_packet: Hash32,
    pub capsule_root: Hash32,
    pub numeric_profile: Hash32,
    pub candidate_revision: Hash32,
    pub candidate_composition_root: Hash32,
    pub submitted_at: u64,
    pub available_at: u64,
    pub challenge_deadline: u64,
}

impl Reaction {
    pub fn replay_candidate(
        packet: &UpdatePacket,
        capsule: &ReactionCapsule,
        parent_state: &[i64],
    ) -> Result<Vec<i64>, TrainingError> {
        capsule.validate()?;
        if packet.payload != capsule.capsule_root
            || !matches!(
                packet.update_kind,
                UpdateKind::LowRank | UpdateKind::SparseDelta
            )
            || capsule.delta.len() != parent_state.len()
        {
            return Err(TrainingError::InvalidReactionCapsule);
        }
        capsule
            .delta
            .iter()
            .zip(parent_state)
            .map(|(delta, parent)| {
                let numerator = i128::from(*parent)
                    .checked_mul(i128::from(capsule.divisor))
                    .and_then(|value| value.checked_add(i128::from(*delta)))
                    .ok_or(TrainingError::ReactionArithmetic)?;
                let divisor = i128::from(capsule.divisor);
                if numerator.rem_euclid(divisor) != 0 {
                    return Err(TrainingError::InexactReactionProfile);
                }
                i64::try_from(
                    numerator
                        .checked_div(divisor)
                        .ok_or(TrainingError::ReactionArithmetic)?,
                )
                .map_err(|_| TrainingError::ReactionArithmetic)
            })
            .collect()
    }

    #[must_use]
    pub fn derived_id(&self) -> Hash32 {
        domain_hash(
            REACTION_DOMAIN,
            &[
                &self.parent_revision,
                &self.update_packet,
                &self.capsule_root,
                &self.numeric_profile,
                &self.candidate_revision,
                &self.candidate_composition_root,
                &self.submitted_at.to_be_bytes(),
                &self.available_at.to_be_bytes(),
                &self.challenge_deadline.to_be_bytes(),
            ],
        )
    }

    pub fn validate(
        &self,
        parent: &SpeciesRevision,
        packet: &UpdatePacket,
        replay: ReactionReplay<'_>,
    ) -> Result<(), TrainingError> {
        packet
            .validate_canonical()
            .map_err(|_| TrainingError::InvalidUpdatePacket)?;
        let reproduced = Self::replay_candidate(packet, replay.capsule, replay.parent_state)?;
        if self.reaction_id != self.derived_id()
            || self.parent_revision != parent.revision_id
            || self.update_packet != packet.packet_id
            || !packet.base_members.contains(&parent.revision_id)
            || self.numeric_profile != packet.numeric_profile
            || self.capsule_root != replay.capsule.capsule_root
            || self.candidate_revision == parent.revision_id
            || parent.composition_root != state_root(replay.parent_state)
            || replay.candidate_state != reproduced
            || self.candidate_composition_root != state_root(&reproduced)
            || self.submitted_at >= self.available_at
            || self.available_at >= self.challenge_deadline
        {
            return Err(TrainingError::InvalidReaction);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateState {
    Proposed,
    Available,
    Challengeable,
    Admitted,
    Rejected,
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CandidateRecord {
    reaction: Reaction,
    state: CandidateState,
}

/// Owns the reversible application pointer. Trainers can submit immutable
/// reactions, but only this delayed challenge state machine can move it.
#[derive(Clone, Debug)]
pub struct PromotionController {
    active_revision: Hash32,
    retained_revisions: BTreeSet<Hash32>,
    candidates: BTreeMap<Hash32, CandidateRecord>,
}

impl PromotionController {
    #[must_use]
    pub fn new(active_revision: Hash32) -> Self {
        Self {
            active_revision,
            retained_revisions: BTreeSet::from([active_revision]),
            candidates: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn active_revision(&self) -> Hash32 {
        self.active_revision
    }

    pub fn submit(
        &mut self,
        reaction: Reaction,
        parent: &SpeciesRevision,
        packet: &UpdatePacket,
        replay: ReactionReplay<'_>,
    ) -> Result<(), TrainingError> {
        reaction.validate(parent, packet, replay)?;
        if reaction.parent_revision != self.active_revision {
            return Err(TrainingError::StaleParent);
        }
        if self.candidates.contains_key(&reaction.reaction_id) {
            return Err(TrainingError::ReactionReplay);
        }
        self.candidates.insert(
            reaction.reaction_id,
            CandidateRecord {
                reaction,
                state: CandidateState::Proposed,
            },
        );
        Ok(())
    }

    pub fn mark_available(
        &mut self,
        reaction_id: Hash32,
        height: u64,
        reconstructible: bool,
    ) -> Result<(), TrainingError> {
        let candidate = self
            .candidates
            .get_mut(&reaction_id)
            .ok_or(TrainingError::UnknownReaction)?;
        if candidate.state != CandidateState::Proposed
            || height < candidate.reaction.available_at
            || !reconstructible
        {
            return Err(TrainingError::InvalidReactionTransition);
        }
        candidate.state = CandidateState::Available;
        Ok(())
    }

    pub fn open_challenge_period(&mut self, reaction_id: Hash32) -> Result<(), TrainingError> {
        let candidate = self
            .candidates
            .get_mut(&reaction_id)
            .ok_or(TrainingError::UnknownReaction)?;
        if candidate.state != CandidateState::Available {
            return Err(TrainingError::InvalidReactionTransition);
        }
        candidate.state = CandidateState::Challengeable;
        Ok(())
    }

    pub fn challenge(
        &mut self,
        reaction_id: Hash32,
        height: u64,
        falsifier_succeeded: bool,
    ) -> Result<(), TrainingError> {
        let candidate = self
            .candidates
            .get_mut(&reaction_id)
            .ok_or(TrainingError::UnknownReaction)?;
        if candidate.state != CandidateState::Challengeable
            || height >= candidate.reaction.challenge_deadline
        {
            return Err(TrainingError::InvalidReactionTransition);
        }
        if falsifier_succeeded {
            candidate.state = CandidateState::Rejected;
            Ok(())
        } else {
            Err(TrainingError::ChallengeFailed)
        }
    }

    pub fn admit(&mut self, reaction_id: Hash32, height: u64) -> Result<Hash32, TrainingError> {
        let candidate = self
            .candidates
            .get_mut(&reaction_id)
            .ok_or(TrainingError::UnknownReaction)?;
        if candidate.state != CandidateState::Challengeable
            || height < candidate.reaction.challenge_deadline
            || candidate.reaction.parent_revision != self.active_revision
        {
            return Err(TrainingError::InvalidReactionTransition);
        }
        candidate.state = CandidateState::Admitted;
        self.retained_revisions.insert(self.active_revision);
        self.active_revision = candidate.reaction.candidate_revision;
        Ok(self.active_revision)
    }

    pub fn rollback(&mut self, reaction_id: Hash32) -> Result<Hash32, TrainingError> {
        let candidate = self
            .candidates
            .get_mut(&reaction_id)
            .ok_or(TrainingError::UnknownReaction)?;
        if candidate.state != CandidateState::Admitted
            || self.active_revision != candidate.reaction.candidate_revision
            || !self
                .retained_revisions
                .contains(&candidate.reaction.parent_revision)
        {
            return Err(TrainingError::InvalidReactionTransition);
        }
        self.active_revision = candidate.reaction.parent_revision;
        candidate.state = CandidateState::RolledBack;
        Ok(self.active_revision)
    }

    #[must_use]
    pub fn state(&self, reaction_id: &Hash32) -> Option<CandidateState> {
        self.candidates.get(reaction_id).map(|record| record.state)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use noos_species::{RevisionLifecycle, UpdateKind};

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn parent() -> SpeciesRevision {
        let parent_state = [10, 20, 30];
        SpeciesRevision {
            revision_id: h(1),
            species_id: h(2),
            manifest_version: 1,
            composition_root: state_root(&parent_state),
            required_artifacts: vec![h(4)],
            execution_manifest: h(5),
            relation_claims: vec![],
            serving_profiles: vec![h(6)],
            availability_certificate: h(7),
            rights_certificate: h(8),
            lifecycle: RevisionLifecycle::Admitted,
        }
    }

    fn capsule() -> ReactionCapsule {
        let mut capsule = ReactionCapsule {
            capsule_root: [0; 32],
            delta: vec![2, -4, 6],
            divisor: 2,
        };
        capsule.capsule_root = capsule.derived_root();
        capsule
    }

    fn packet(capsule: &ReactionCapsule) -> UpdatePacket {
        let mut packet = UpdatePacket {
            packet_id: [0; 32],
            base_members: vec![h(1)],
            update_kind: UpdateKind::LowRank,
            payload: capsule.capsule_root,
            applicability_predicate: h(11),
            tokenizer: h(12),
            numeric_profile: h(13),
            training_recipe: Some(h(14)),
            source_capsules: vec![h(15)],
            policy_version: Some(4),
            privacy_parameters_root: None,
            rights_expression: h(16),
            provenance_root: h(17),
            availability_commitments: vec![h(18)],
            contributor_set: vec![h(19)],
            evaluation_receipts: vec![h(20)],
            expiry: Some(100),
        };
        packet.packet_id = packet.derived_id();
        packet
    }

    fn reaction(
        parent: &SpeciesRevision,
        packet: &UpdatePacket,
        capsule: &ReactionCapsule,
        candidate_state: &[i64],
    ) -> Reaction {
        let mut reaction = Reaction {
            reaction_id: [0; 32],
            parent_revision: parent.revision_id,
            update_packet: packet.packet_id,
            capsule_root: capsule.capsule_root,
            numeric_profile: packet.numeric_profile,
            candidate_revision: h(22),
            candidate_composition_root: state_root(candidate_state),
            submitted_at: 10,
            available_at: 12,
            challenge_deadline: 20,
        };
        reaction.reaction_id = reaction.derived_id();
        reaction
    }

    #[test]
    fn claim_reaction_replay_delay_challenge_and_rollback_laws() {
        let parent = parent();
        let capsule = capsule();
        let packet = packet(&capsule);
        let parent_state = [10, 20, 30];
        let candidate_state = Reaction::replay_candidate(&packet, &capsule, &parent_state).unwrap();
        assert_eq!(candidate_state, vec![11, 18, 33]);
        let reaction = reaction(&parent, &packet, &capsule, &candidate_state);
        let mut controller = PromotionController::new(parent.revision_id);
        controller
            .submit(
                reaction.clone(),
                &parent,
                &packet,
                ReactionReplay {
                    capsule: &capsule,
                    parent_state: &parent_state,
                    candidate_state: &candidate_state,
                },
            )
            .unwrap();
        assert_eq!(
            controller.submit(
                reaction.clone(),
                &parent,
                &packet,
                ReactionReplay {
                    capsule: &capsule,
                    parent_state: &parent_state,
                    candidate_state: &candidate_state,
                },
            ),
            Err(TrainingError::ReactionReplay)
        );
        assert_eq!(
            controller.mark_available(reaction.reaction_id, 11, true),
            Err(TrainingError::InvalidReactionTransition)
        );
        controller
            .mark_available(reaction.reaction_id, 12, true)
            .unwrap();
        controller
            .open_challenge_period(reaction.reaction_id)
            .unwrap();
        assert_eq!(
            controller.admit(reaction.reaction_id, 19),
            Err(TrainingError::InvalidReactionTransition)
        );
        assert_eq!(controller.admit(reaction.reaction_id, 20).unwrap(), h(22));
        assert_eq!(controller.rollback(reaction.reaction_id).unwrap(), h(1));
        assert_eq!(
            controller.state(&reaction.reaction_id),
            Some(CandidateState::RolledBack)
        );
    }

    #[test]
    fn claim_reaction_tamper_splice_stale_and_falsifier_reject() {
        let parent = parent();
        let capsule = capsule();
        let packet = packet(&capsule);
        let parent_state = [10, 20, 30];
        let candidate_state = Reaction::replay_candidate(&packet, &capsule, &parent_state).unwrap();
        let replay = ReactionReplay {
            capsule: &capsule,
            parent_state: &parent_state,
            candidate_state: &candidate_state,
        };
        let mut tampered = reaction(&parent, &packet, &capsule, &candidate_state);
        tampered.capsule_root = h(99);
        assert_eq!(
            tampered.validate(&parent, &packet, replay),
            Err(TrainingError::InvalidReaction)
        );

        let mut spliced_packet = packet.clone();
        spliced_packet.base_members = vec![h(30)];
        spliced_packet.packet_id = spliced_packet.derived_id();
        let spliced_reaction = reaction(&parent, &spliced_packet, &capsule, &candidate_state);
        assert_eq!(
            spliced_reaction.validate(&parent, &spliced_packet, replay),
            Err(TrainingError::InvalidReaction)
        );

        let wrong_candidate = [11, 18, 34];
        assert_eq!(
            reaction(&parent, &packet, &capsule, &wrong_candidate).validate(
                &parent,
                &packet,
                ReactionReplay {
                    capsule: &capsule,
                    parent_state: &parent_state,
                    candidate_state: &wrong_candidate,
                },
            ),
            Err(TrainingError::InvalidReaction)
        );

        let reaction = reaction(&parent, &packet, &capsule, &candidate_state);
        let mut stale_controller = PromotionController::new(h(90));
        assert_eq!(
            stale_controller.submit(reaction.clone(), &parent, &packet, replay),
            Err(TrainingError::StaleParent)
        );

        let mut controller = PromotionController::new(parent.revision_id);
        controller
            .submit(reaction.clone(), &parent, &packet, replay)
            .unwrap();
        controller
            .mark_available(reaction.reaction_id, 12, true)
            .unwrap();
        controller
            .open_challenge_period(reaction.reaction_id)
            .unwrap();
        controller
            .challenge(reaction.reaction_id, 19, true)
            .unwrap();
        assert_eq!(
            controller.admit(reaction.reaction_id, 20),
            Err(TrainingError::InvalidReactionTransition)
        );
        assert_eq!(controller.active_revision(), parent.revision_id);
    }
}
