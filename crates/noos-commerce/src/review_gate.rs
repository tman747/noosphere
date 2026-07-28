//! Fail-closed independent-review gates for lending and bridge activation.
//!
//! Risk-increasing operations require an exact-revision target and two
//! independent organizations covering every required review scope. Repay,
//! collateral deposit, bridge exit, and refund paths remain available while a
//! gate is closed. Reviews are Ed25519 signed and cannot be reused across
//! targets, revisions, or surfaces.

use crate::{domain_hash, Hash32};
use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::{Signer, SigningKey, Verifier};

pub const MAX_REVIEW_ATTESTATIONS: usize = 16;
pub const MIN_INDEPENDENT_REVIEW_ORGANIZATIONS: u8 = 2;

pub const SCOPE_ORACLE: u64 = 1 << 0;
pub const SCOPE_LIQUIDATION: u64 = 1 << 1;
pub const SCOPE_CROSS_CHAIN: u64 = 1 << 2;
pub const SCOPE_EXPOSURE_LIMITS: u64 = 1 << 3;
pub const SCOPE_FAILURE_MODES: u64 = 1 << 4;
pub const SCOPE_EMERGENCY_CONTROLS: u64 = 1 << 5;
pub const ALL_REVIEW_SCOPES: u64 = SCOPE_ORACLE
    | SCOPE_LIQUIDATION
    | SCOPE_CROSS_CHAIN
    | SCOPE_EXPOSURE_LIMITS
    | SCOPE_FAILURE_MODES
    | SCOPE_EMERGENCY_CONTROLS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewGateError {
    InvalidTarget,
    TargetUnchanged,
    UnknownTarget,
    TargetMismatch,
    InvalidAttestation,
    InvalidSignature,
    DuplicateReviewer,
    TooManyAttestations,
    HeightRegression,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedSurface {
    Lending = 1,
    Bridge = 2,
}

impl ReviewedSurface {
    #[must_use]
    pub const fn required_scopes(self) -> u64 {
        match self {
            Self::Lending => {
                SCOPE_ORACLE
                    | SCOPE_LIQUIDATION
                    | SCOPE_EXPOSURE_LIMITS
                    | SCOPE_FAILURE_MODES
                    | SCOPE_EMERGENCY_CONTROLS
            }
            Self::Bridge => {
                SCOPE_CROSS_CHAIN
                    | SCOPE_EXPOSURE_LIMITS
                    | SCOPE_FAILURE_MODES
                    | SCOPE_EMERGENCY_CONTROLS
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationOperation {
    LendingDepositCollateral,
    LendingBorrow,
    LendingWithdrawCollateral,
    LendingRepay,
    LendingRedeem,
    BridgeLock,
    BridgeMint,
    BridgeExit,
    BridgeRefund,
}

impl ApplicationOperation {
    #[must_use]
    pub const fn surface(self) -> ReviewedSurface {
        match self {
            Self::LendingDepositCollateral
            | Self::LendingBorrow
            | Self::LendingWithdrawCollateral
            | Self::LendingRepay
            | Self::LendingRedeem => ReviewedSurface::Lending,
            Self::BridgeLock | Self::BridgeMint | Self::BridgeExit | Self::BridgeRefund => {
                ReviewedSurface::Bridge
            }
        }
    }

    #[must_use]
    pub const fn is_exit_or_risk_reducing(self) -> bool {
        matches!(
            self,
            Self::LendingDepositCollateral
                | Self::LendingRepay
                | Self::LendingRedeem
                | Self::BridgeExit
                | Self::BridgeRefund
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewTarget {
    pub surface: ReviewedSurface,
    pub revision: Hash32,
    pub implementation_root: Hash32,
    /// Oracle, liquidation, cross-chain, exposure, failure, emergency roots.
    pub design_roots: [Hash32; 6],
    pub activation_not_before: u64,
    pub expires_at: u64,
    pub minimum_independent_organizations: u8,
}

impl ReviewTarget {
    pub fn validate(self) -> Result<(), ReviewGateError> {
        if self.revision == [0; 32]
            || self.implementation_root == [0; 32]
            || self.activation_not_before >= self.expires_at
            || !(MIN_INDEPENDENT_REVIEW_ORGANIZATIONS..=5)
                .contains(&self.minimum_independent_organizations)
        {
            return Err(ReviewGateError::InvalidTarget);
        }
        let required = self.surface.required_scopes();
        for (index, root) in self.design_roots.iter().enumerate() {
            if required & (1_u64 << index) != 0 && *root == [0; 32] {
                return Err(ReviewGateError::InvalidTarget);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn target_root(self) -> Hash32 {
        let mut parts: [&[u8]; 11] = [&[]; 11];
        let surface = [self.surface as u8];
        parts[0] = &surface;
        parts[1] = &self.revision;
        parts[2] = &self.implementation_root;
        for (offset, root) in self.design_roots.iter().enumerate() {
            parts[3 + offset] = root;
        }
        let activation = self.activation_not_before.to_le_bytes();
        let expiry = self.expires_at.to_le_bytes();
        parts[9] = &activation;
        parts[10] = &expiry;
        domain_hash("NOOS/APPLICATION-REVIEW/TARGET/V1", &parts)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewAttestation {
    pub target_root: Hash32,
    pub reviewer_public_key: Hash32,
    pub organization_id: Hash32,
    pub scope_bits: u64,
    pub findings_root: Hash32,
    pub unresolved_critical_findings: u32,
    pub unresolved_high_findings: u32,
    pub approved: bool,
    pub signed_at_height: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl ReviewAttestation {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn sign(
        target_root: Hash32,
        signing_key: &SigningKey,
        organization_id: Hash32,
        scope_bits: u64,
        findings_root: Hash32,
        unresolved_critical_findings: u32,
        unresolved_high_findings: u32,
        approved: bool,
        signed_at_height: u64,
        expires_at: u64,
    ) -> Self {
        let reviewer_public_key = signing_key.verifying_key().to_bytes();
        let digest = attestation_digest(
            &target_root,
            &reviewer_public_key,
            &organization_id,
            scope_bits,
            &findings_root,
            unresolved_critical_findings,
            unresolved_high_findings,
            approved,
            signed_at_height,
            expires_at,
        );
        Self {
            target_root,
            reviewer_public_key,
            organization_id,
            scope_bits,
            findings_root,
            unresolved_critical_findings,
            unresolved_high_findings,
            approved,
            signed_at_height,
            expires_at,
            signature: signing_key.sign(&digest).to_bytes(),
        }
    }

    fn verify(self) -> Result<(), ReviewGateError> {
        if self.target_root == [0; 32]
            || self.reviewer_public_key == [0; 32]
            || self.organization_id == [0; 32]
            || self.findings_root == [0; 32]
            || self.scope_bits == 0
            || self.scope_bits & !ALL_REVIEW_SCOPES != 0
            || self.signed_at_height >= self.expires_at
        {
            return Err(ReviewGateError::InvalidAttestation);
        }
        let verifier = VerifyingKey::from_bytes(&self.reviewer_public_key)
            .map_err(|_| ReviewGateError::InvalidSignature)?;
        let digest = attestation_digest(
            &self.target_root,
            &self.reviewer_public_key,
            &self.organization_id,
            self.scope_bits,
            &self.findings_root,
            self.unresolved_critical_findings,
            self.unresolved_high_findings,
            self.approved,
            self.signed_at_height,
            self.expires_at,
        );
        verifier
            .verify(&digest, &Signature::from_bytes(&self.signature))
            .map_err(|_| ReviewGateError::InvalidSignature)
    }

    fn counts_for(self, scope: u64, height: u64) -> bool {
        self.approved
            && self.unresolved_critical_findings == 0
            && self.unresolved_high_findings == 0
            && self.scope_bits & scope != 0
            && self.signed_at_height <= height
            && height <= self.expires_at
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Ready,
    ExitAllowedWhileClosed,
    MissingTarget,
    RevisionMismatch,
    Timelocked,
    Expired,
    EmergencyDisabled,
    InsufficientIndependentReviews,
}

impl GateDecision {
    #[must_use]
    pub const fn allows(self) -> bool {
        matches!(self, Self::Ready | Self::ExitAllowedWhileClosed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SurfaceReviewState {
    target: Option<ReviewTarget>,
    attestations: [Option<ReviewAttestation>; MAX_REVIEW_ATTESTATIONS],
    emergency_disabled: bool,
}

impl Default for SurfaceReviewState {
    fn default() -> Self {
        Self {
            target: None,
            attestations: [None; MAX_REVIEW_ATTESTATIONS],
            emergency_disabled: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplicationReviewGate {
    lending: SurfaceReviewState,
    bridge: SurfaceReviewState,
}

impl ApplicationReviewGate {
    #[must_use]
    pub const fn target(&self, surface: ReviewedSurface) -> Option<ReviewTarget> {
        self.state(surface).target
    }

    pub fn install_target(
        &mut self,
        target: ReviewTarget,
        current_height: u64,
    ) -> Result<Hash32, ReviewGateError> {
        target.validate()?;
        if target.activation_not_before < current_height || target.expires_at <= current_height {
            return Err(ReviewGateError::HeightRegression);
        }
        let root = target.target_root();
        let state = self.state_mut(target.surface);
        if state
            .target
            .is_some_and(|current| current.target_root() == root)
        {
            return Err(ReviewGateError::TargetUnchanged);
        }
        state.target = Some(target);
        state.attestations = [None; MAX_REVIEW_ATTESTATIONS];
        state.emergency_disabled = false;
        Ok(root)
    }

    pub fn submit_attestation(
        &mut self,
        surface: ReviewedSurface,
        attestation: ReviewAttestation,
        current_height: u64,
    ) -> Result<(), ReviewGateError> {
        attestation.verify()?;
        let state = self.state_mut(surface);
        let target = state.target.ok_or(ReviewGateError::UnknownTarget)?;
        if attestation.target_root != target.target_root()
            || attestation.signed_at_height > current_height
            || attestation.expires_at < current_height
            || attestation.expires_at > target.expires_at
            || attestation.scope_bits & !target.surface.required_scopes() != 0
        {
            return Err(ReviewGateError::TargetMismatch);
        }
        if state.attestations.iter().flatten().any(|existing| {
            existing.reviewer_public_key == attestation.reviewer_public_key
                || existing.organization_id == attestation.organization_id
        }) {
            return Err(ReviewGateError::DuplicateReviewer);
        }
        let slot = state
            .attestations
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ReviewGateError::TooManyAttestations)?;
        *slot = Some(attestation);
        Ok(())
    }

    pub fn emergency_disable(&mut self, surface: ReviewedSurface) {
        self.state_mut(surface).emergency_disabled = true;
    }

    #[must_use]
    pub fn decision(
        &self,
        surface: ReviewedSurface,
        revision: Hash32,
        current_height: u64,
    ) -> GateDecision {
        let state = self.state(surface);
        let Some(target) = state.target else {
            return GateDecision::MissingTarget;
        };
        if target.revision != revision {
            return GateDecision::RevisionMismatch;
        }
        if state.emergency_disabled {
            return GateDecision::EmergencyDisabled;
        }
        if current_height < target.activation_not_before {
            return GateDecision::Timelocked;
        }
        if current_height > target.expires_at {
            return GateDecision::Expired;
        }
        let required = surface.required_scopes();
        for bit in 0..6 {
            let scope = 1_u64 << bit;
            if required & scope == 0 {
                continue;
            }
            let mut organizations = [[0_u8; 32]; MAX_REVIEW_ATTESTATIONS];
            let mut organization_count = 0_usize;
            for attestation in state.attestations.iter().flatten().copied() {
                if !attestation.counts_for(scope, current_height)
                    || organizations[..organization_count].contains(&attestation.organization_id)
                {
                    continue;
                }
                organizations[organization_count] = attestation.organization_id;
                organization_count += 1;
            }
            if organization_count < usize::from(target.minimum_independent_organizations) {
                return GateDecision::InsufficientIndependentReviews;
            }
        }
        GateDecision::Ready
    }

    #[must_use]
    pub fn authorize_operation(
        &self,
        operation: ApplicationOperation,
        revision: Hash32,
        current_height: u64,
    ) -> GateDecision {
        let decision = self.decision(operation.surface(), revision, current_height);
        if decision.allows() || !operation.is_exit_or_risk_reducing() {
            decision
        } else {
            GateDecision::ExitAllowedWhileClosed
        }
    }

    const fn state(&self, surface: ReviewedSurface) -> &SurfaceReviewState {
        match surface {
            ReviewedSurface::Lending => &self.lending,
            ReviewedSurface::Bridge => &self.bridge,
        }
    }

    fn state_mut(&mut self, surface: ReviewedSurface) -> &mut SurfaceReviewState {
        match surface {
            ReviewedSurface::Lending => &mut self.lending,
            ReviewedSurface::Bridge => &mut self.bridge,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn attestation_digest(
    target_root: &Hash32,
    reviewer_public_key: &Hash32,
    organization_id: &Hash32,
    scope_bits: u64,
    findings_root: &Hash32,
    unresolved_critical_findings: u32,
    unresolved_high_findings: u32,
    approved: bool,
    signed_at_height: u64,
    expires_at: u64,
) -> Hash32 {
    domain_hash(
        "NOOS/APPLICATION-REVIEW/ATTESTATION/V1",
        &[
            target_root,
            reviewer_public_key,
            organization_id,
            &scope_bits.to_le_bytes(),
            findings_root,
            &unresolved_critical_findings.to_le_bytes(),
            &unresolved_high_findings.to_le_bytes(),
            &[u8::from(approved)],
            &signed_at_height.to_le_bytes(),
            &expires_at.to_le_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn target(surface: ReviewedSurface) -> ReviewTarget {
        ReviewTarget {
            surface,
            revision: h(1),
            implementation_root: h(2),
            design_roots: [h(3), h(4), h(5), h(6), h(7), h(8)],
            activation_not_before: 20,
            expires_at: 200,
            minimum_independent_organizations: 2,
        }
    }

    fn review(
        target: ReviewTarget,
        signing_seed: u8,
        organization: u8,
        approved: bool,
        critical: u32,
    ) -> ReviewAttestation {
        ReviewAttestation::sign(
            target.target_root(),
            &SigningKey::from_bytes(&[signing_seed; 32]),
            h(organization),
            target.surface.required_scopes(),
            h(signing_seed + 100),
            critical,
            0,
            approved,
            10,
            190,
        )
    }

    #[test]
    fn two_independent_full_scope_reviews_open_exact_revision_only() {
        let target = target(ReviewedSurface::Lending);
        let mut gate = ApplicationReviewGate::default();
        gate.install_target(target, 1).unwrap();
        assert_eq!(
            gate.decision(ReviewedSurface::Lending, h(1), 20),
            GateDecision::InsufficientIndependentReviews
        );
        gate.submit_attestation(
            ReviewedSurface::Lending,
            review(target, 10, 20, true, 0),
            10,
        )
        .unwrap();
        assert_eq!(
            gate.decision(ReviewedSurface::Lending, h(1), 20),
            GateDecision::InsufficientIndependentReviews
        );
        gate.submit_attestation(
            ReviewedSurface::Lending,
            review(target, 11, 21, true, 0),
            10,
        )
        .unwrap();
        assert_eq!(
            gate.decision(ReviewedSurface::Lending, h(1), 20),
            GateDecision::Ready
        );
        assert_eq!(
            gate.decision(ReviewedSurface::Lending, h(9), 20),
            GateDecision::RevisionMismatch
        );
        assert_eq!(
            gate.decision(ReviewedSurface::Bridge, h(1), 20),
            GateDecision::MissingTarget
        );
    }

    #[test]
    fn negative_findings_are_preserved_but_never_activate() {
        let target = target(ReviewedSurface::Lending);
        let mut gate = ApplicationReviewGate::default();
        gate.install_target(target, 1).unwrap();
        gate.submit_attestation(
            ReviewedSurface::Lending,
            review(target, 10, 20, false, 0),
            10,
        )
        .unwrap();
        gate.submit_attestation(
            ReviewedSurface::Lending,
            review(target, 11, 21, true, 1),
            10,
        )
        .unwrap();
        assert_eq!(
            gate.decision(ReviewedSurface::Lending, h(1), 20),
            GateDecision::InsufficientIndependentReviews
        );
    }

    #[test]
    fn signatures_targets_and_organizations_cannot_be_reused() {
        let lending = target(ReviewedSurface::Lending);
        let bridge = target(ReviewedSurface::Bridge);
        let mut gate = ApplicationReviewGate::default();
        gate.install_target(lending, 1).unwrap();
        let valid = review(lending, 10, 20, true, 0);
        let mut tampered = valid;
        tampered.scope_bits = SCOPE_ORACLE;
        assert_eq!(
            gate.submit_attestation(ReviewedSurface::Lending, tampered, 10),
            Err(ReviewGateError::InvalidSignature)
        );
        gate.submit_attestation(ReviewedSurface::Lending, valid, 10)
            .unwrap();
        assert_eq!(
            gate.submit_attestation(
                ReviewedSurface::Lending,
                review(lending, 11, 20, true, 0),
                10,
            ),
            Err(ReviewGateError::DuplicateReviewer)
        );

        gate.install_target(bridge, 1).unwrap();
        assert_eq!(
            gate.submit_attestation(ReviewedSurface::Bridge, valid, 10),
            Err(ReviewGateError::TargetMismatch)
        );
    }

    #[test]
    fn emergency_and_expiry_close_risk_but_preserve_exits() {
        let target = target(ReviewedSurface::Lending);
        let mut gate = ApplicationReviewGate::default();
        gate.install_target(target, 1).unwrap();
        for (seed, organization) in [(10, 20), (11, 21)] {
            gate.submit_attestation(
                ReviewedSurface::Lending,
                review(target, seed, organization, true, 0),
                10,
            )
            .unwrap();
        }
        gate.emergency_disable(ReviewedSurface::Lending);
        assert_eq!(
            gate.authorize_operation(ApplicationOperation::LendingBorrow, h(1), 20),
            GateDecision::EmergencyDisabled
        );
        assert_eq!(
            gate.authorize_operation(ApplicationOperation::LendingRepay, h(1), 20),
            GateDecision::ExitAllowedWhileClosed
        );
        assert_eq!(
            gate.authorize_operation(ApplicationOperation::LendingRedeem, h(1), 201),
            GateDecision::ExitAllowedWhileClosed
        );
    }

    #[test]
    fn incomplete_scope_coverage_never_opens_a_surface() {
        let target = target(ReviewedSurface::Bridge);
        let mut gate = ApplicationReviewGate::default();
        gate.install_target(target, 1).unwrap();
        for (seed, organization) in [(10, 20), (11, 21)] {
            let mut attestation = review(target, seed, organization, true, 0);
            attestation.scope_bits &= !SCOPE_CROSS_CHAIN;
            let signing_key = SigningKey::from_bytes(&[seed; 32]);
            attestation = ReviewAttestation::sign(
                target.target_root(),
                &signing_key,
                h(organization),
                attestation.scope_bits,
                attestation.findings_root,
                0,
                0,
                true,
                10,
                190,
            );
            gate.submit_attestation(ReviewedSurface::Bridge, attestation, 10)
                .unwrap();
        }
        assert_eq!(
            gate.decision(ReviewedSurface::Bridge, h(1), 20),
            GateDecision::InsufficientIndependentReviews
        );
    }
}
