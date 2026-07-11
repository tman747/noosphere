use crate::{domain_hash, Hash32, Height, Right, RightsExpression};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwinProfileState {
    Active,
    Revoked,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwinUseKind {
    Query,
    EffectProposal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwinProfile {
    pub profile_id: Hash32,
    pub owner_identity: Hash32,
    pub observations_root: Hash32,
    pub models_root: Hash32,
    pub uncertainty_root: Hash32,
    pub permitted_questions: BTreeSet<Hash32>,
    pub capability_scope: BTreeSet<Hash32>,
    pub rights_expression: Hash32,
    pub consent_receipt: Hash32,
    pub state: TwinProfileState,
    pub revocation_epoch: u64,
}
impl TwinProfile {
    #[must_use]
    pub fn derive_id(&self) -> Hash32 {
        let mut questions = Vec::new();
        for question in &self.permitted_questions {
            questions.extend_from_slice(question);
        }
        let mut capabilities = Vec::new();
        for capability in &self.capability_scope {
            capabilities.extend_from_slice(capability);
        }
        domain_hash(
            "NOOS/LOAM/TWIN-PROFILE/V1",
            &[
                &self.owner_identity,
                &self.observations_root,
                &self.models_root,
                &self.uncertainty_root,
                &questions,
                &capabilities,
                &self.rights_expression,
                &self.consent_receipt,
            ],
        )
    }

    #[must_use]
    pub fn display_identity(&self) -> TwinDisplayIdentity {
        TwinDisplayIdentity {
            profile_id: self.profile_id,
            owner_identity: self.owner_identity,
            kind: TwinIdentityKind::AdvisoryProfile,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwinIdentityKind {
    AdvisoryProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwinDisplayIdentity {
    pub profile_id: Hash32,
    pub owner_identity: Hash32,
    pub kind: TwinIdentityKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwinUseRequest {
    pub profile_id: Hash32,
    pub principal: Hash32,
    pub purpose: Hash32,
    pub question: Hash32,
    pub capability: Hash32,
    pub kind: TwinUseKind,
    pub height: Height,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwinPermit {
    profile_id: Hash32,
    question: Hash32,
    capability: Hash32,
    kind: TwinUseKind,
    revocation_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwinRecommendation {
    pub profile_id: Hash32,
    pub recommendation_digest: Hash32,
    pub kind: TwinUseKind,
}
impl TwinRecommendation {
    pub const AUTHORITY: Option<Hash32> = None;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwinError {
    Duplicate,
    UnknownProfile,
    Malformed,
    ConsentDenied,
    ScopeDenied,
    Revoked,
    StalePermit,
    ProfileSubstitution,
}

#[derive(Debug, Default)]
pub struct TwinProfileRegistry {
    profiles: BTreeMap<Hash32, TwinProfile>,
    rights: BTreeMap<Hash32, RightsExpression>,
}
impl TwinProfileRegistry {
    pub fn install(
        &mut self,
        profile: TwinProfile,
        rights: RightsExpression,
    ) -> Result<(), TwinError> {
        if profile.profile_id != profile.derive_id()
            || profile.profile_id == profile.owner_identity
            || profile.state != TwinProfileState::Active
            || profile.revocation_epoch != 0
            || profile.rights_expression != rights.expression_id
            || profile.consent_receipt == [0; 32]
            || profile.permitted_questions.is_empty()
            || profile.capability_scope.is_empty()
        {
            return Err(TwinError::Malformed);
        }
        if self.profiles.contains_key(&profile.profile_id) {
            return Err(TwinError::Duplicate);
        }
        if self
            .rights
            .get(&rights.expression_id)
            .is_some_and(|existing| existing != &rights)
        {
            return Err(TwinError::Malformed);
        }
        self.rights.insert(rights.expression_id, rights);
        self.profiles.insert(profile.profile_id, profile);
        Ok(())
    }

    pub fn authorize(&self, request: TwinUseRequest) -> Result<TwinPermit, TwinError> {
        let profile = self
            .profiles
            .get(&request.profile_id)
            .ok_or(TwinError::UnknownProfile)?;
        if profile.state != TwinProfileState::Active {
            return Err(TwinError::Revoked);
        }
        let rights = self
            .rights
            .get(&profile.rights_expression)
            .ok_or(TwinError::ConsentDenied)?;
        if !rights.grantees.contains(&request.principal)
            || !rights.purposes.contains(&request.purpose)
            || !rights.rights.contains(&Right::Evaluate)
            || rights
                .expires_at
                .is_some_and(|height| request.height >= height)
        {
            return Err(TwinError::ConsentDenied);
        }
        if !profile.permitted_questions.contains(&request.question)
            || !profile.capability_scope.contains(&request.capability)
        {
            return Err(TwinError::ScopeDenied);
        }
        Ok(TwinPermit {
            profile_id: profile.profile_id,
            question: request.question,
            capability: request.capability,
            kind: request.kind,
            revocation_epoch: profile.revocation_epoch,
        })
    }

    pub fn use_permit(
        &self,
        target_profile: Hash32,
        permit: TwinPermit,
        output: &[u8],
    ) -> Result<TwinRecommendation, TwinError> {
        if permit.profile_id != target_profile {
            return Err(TwinError::ProfileSubstitution);
        }
        let profile = self
            .profiles
            .get(&target_profile)
            .ok_or(TwinError::UnknownProfile)?;
        if profile.state != TwinProfileState::Active {
            return Err(TwinError::Revoked);
        }
        if profile.revocation_epoch != permit.revocation_epoch
            || !profile.permitted_questions.contains(&permit.question)
            || !profile.capability_scope.contains(&permit.capability)
        {
            return Err(TwinError::StalePermit);
        }
        Ok(TwinRecommendation {
            profile_id: target_profile,
            recommendation_digest: domain_hash(
                "NOOS/LOAM/TWIN-RECOMMENDATION/V1",
                &[
                    &target_profile,
                    &permit.question,
                    &permit.capability,
                    output,
                ],
            ),
            kind: permit.kind,
        })
    }

    pub fn revoke(&mut self, profile_id: Hash32) -> Result<(), TwinError> {
        let profile = self
            .profiles
            .get_mut(&profile_id)
            .ok_or(TwinError::UnknownProfile)?;
        profile.state = TwinProfileState::Revoked;
        profile.revocation_epoch = profile
            .revocation_epoch
            .checked_add(1)
            .ok_or(TwinError::Malformed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(n: u8) -> Hash32 {
        [n; 32]
    }

    fn rights() -> RightsExpression {
        RightsExpression {
            expression_id: h(8),
            grantees: BTreeSet::from([h(9)]),
            rights: BTreeSet::from([Right::Evaluate]),
            purposes: BTreeSet::from([h(10)]),
            jurisdictions: BTreeSet::new(),
            expires_at: Some(100),
            revocation_endpoint: Some(h(11)),
            local_only: true,
            descendants_inherit: false,
        }
    }

    fn profile(owner: u8) -> TwinProfile {
        let mut profile = TwinProfile {
            profile_id: [0; 32],
            owner_identity: h(owner),
            observations_root: h(2),
            models_root: h(3),
            uncertainty_root: h(4),
            permitted_questions: BTreeSet::from([h(5)]),
            capability_scope: BTreeSet::from([h(6)]),
            rights_expression: h(8),
            consent_receipt: h(7),
            state: TwinProfileState::Active,
            revocation_epoch: 0,
        };
        profile.profile_id = profile.derive_id();
        profile
    }

    fn request(profile_id: Hash32) -> TwinUseRequest {
        TwinUseRequest {
            profile_id,
            principal: h(9),
            purpose: h(10),
            question: h(5),
            capability: h(6),
            kind: TwinUseKind::EffectProposal,
            height: 1,
        }
    }

    #[test]
    fn consent_scope_identity_and_authority_are_separate() {
        let mut registry = TwinProfileRegistry::default();
        let profile = profile(1);
        let profile_id = profile.profile_id;
        let display = profile.display_identity();
        assert_ne!(display.profile_id, display.owner_identity);
        assert_eq!(display.kind, TwinIdentityKind::AdvisoryProfile);
        registry.install(profile, rights()).unwrap();
        let permit = registry.authorize(request(profile_id)).unwrap();
        let recommendation = registry
            .use_permit(profile_id, permit, b"advisory output")
            .unwrap();
        assert_eq!(recommendation.kind, TwinUseKind::EffectProposal);
        assert_eq!(TwinRecommendation::AUTHORITY, None);

        let mut out_of_scope = request(profile_id);
        out_of_scope.question = h(99);
        assert_eq!(
            registry.authorize(out_of_scope),
            Err(TwinError::ScopeDenied)
        );
    }

    #[test]
    fn revocation_race_and_profile_substitution_fail_closed() {
        let mut registry = TwinProfileRegistry::default();
        let first = profile(1);
        let first_id = first.profile_id;
        let second = profile(12);
        let second_id = second.profile_id;
        registry.install(first, rights()).unwrap();
        registry.install(second, rights()).unwrap();
        let permit = registry.authorize(request(first_id)).unwrap();
        assert_eq!(
            registry.use_permit(second_id, permit, b"x"),
            Err(TwinError::ProfileSubstitution)
        );
        let permit = registry.authorize(request(first_id)).unwrap();
        registry.revoke(first_id).unwrap();
        assert_eq!(
            registry.use_permit(first_id, permit, b"x"),
            Err(TwinError::Revoked)
        );
        assert_eq!(
            registry.authorize(request(first_id)),
            Err(TwinError::Revoked)
        );
    }
}
