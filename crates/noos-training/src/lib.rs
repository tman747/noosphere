//! Immutable experimental training records, deterministic integer execution,
//! Freivalds fidelity audits, and shadow-only I-PENTAGON evidence.
#![forbid(unsafe_code)]
// Modular arithmetic and validated matrix index arithmetic are the experiment's
// subject; dimensions are bounded before any allocation or indexing.
#![allow(clippy::arithmetic_side_effects)]
use noos_species::{
    Hash32, LearningDecision, LearningRecord, RevisionLifecycle, SpeciesRevision, UpdatePacket,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub mod adjoint;
pub mod reaction;
pub mod rl_lag;
pub mod toploc;

pub use reaction::{
    CandidateState, PromotionController, Reaction, ReactionCapsule, ReactionReplay,
};
pub use rl_lag::{classify_group, classify_rollout, LagClass, LagPolicy, RolloutVersions};
pub use toploc::{
    commit_seed, fingerprint, mismatch_count, verifies_execution, ToplocFingerprint, ToplocProfile,
};

pub const LIFECYCLE: &str = "EXPERIMENTAL";
pub const RESULT: &str = "SHADOW_ONLY";
pub const TRAINING_SLASHABLE: bool = false;
pub const I_PENTAGON_ENABLED: bool = false;
pub const I_PENTAGON_RESULT: &str = "SHADOW_ONLY";
pub const MAX_MATRIX_DIMENSION: u32 = 4_096;
pub const MAX_IDENT01_COST_BPS: u32 = 20_000;
pub const MAX_IDENT02_COST_BPS: u32 = 35_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionRecord {
    pub reaction_id: Hash32,
    pub packet_id: Hash32,
    pub base_revision: Hash32,
    pub decision: ReactionDecision,
    pub fidelity_evidence_root: Hash32,
    pub quality_evidence_root: Hash32,
    pub decided_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactionDecision {
    Accepted,
    Rejected,
    Quarantined,
}
impl ReactionRecord {
    pub fn validate(&self) -> Result<(), TrainingError> {
        if self.fidelity_evidence_root == self.quality_evidence_root {
            Err(TrainingError::QualityFidelityConflation)
        } else {
            Ok(())
        }
    }
}

pub fn promote(
    packet: &UpdatePacket,
    base: &SpeciesRevision,
    reaction: &ReactionRecord,
    new_revision_id: Hash32,
    new_composition_root: Hash32,
) -> Result<(SpeciesRevision, LearningRecord), TrainingError> {
    reaction.validate()?;
    if reaction.packet_id != packet.packet_id
        || reaction.base_revision != base.revision_id
        || reaction.decision != ReactionDecision::Accepted
        || new_revision_id == base.revision_id
    {
        return Err(TrainingError::InvalidPromotion);
    }
    let revision = SpeciesRevision {
        revision_id: new_revision_id,
        species_id: base.species_id,
        manifest_version: base.manifest_version,
        composition_root: new_composition_root,
        required_artifacts: vec![packet.payload],
        execution_manifest: base.execution_manifest,
        relation_claims: base.relation_claims.clone(),
        serving_profiles: base.serving_profiles.clone(),
        availability_certificate: base.availability_certificate,
        rights_certificate: packet.rights_expression,
        lifecycle: RevisionLifecycle::Proposed,
    };
    let record = LearningRecord {
        record_id: reaction.reaction_id,
        packet_id: packet.packet_id,
        base_revision: base.revision_id,
        decision: LearningDecision::Accepted,
        evidence_root: reaction.fidelity_evidence_root,
        decided_at: reaction.decided_at,
        promoted_revision: Some(new_revision_id),
    };
    Ok((revision, record))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegerProfile {
    pub profile_id: Hash32,
    pub modulus: u64,
    pub rows: u32,
    pub inner: u32,
    pub cols: u32,
    pub challenge_domain: Hash32,
    pub independent_implementations: u8,
}
impl IntegerProfile {
    pub fn validate(&self) -> Result<(), TrainingError> {
        if self.modulus < 3
            || self.rows == 0
            || self.inner == 0
            || self.cols == 0
            || self.rows > MAX_MATRIX_DIMENSION
            || self.inner > MAX_MATRIX_DIMENSION
            || self.cols > MAX_MATRIX_DIMENSION
            || self.independent_implementations < 2
        {
            Err(TrainingError::InvalidProfile)
        } else {
            Ok(())
        }
    }
}
fn add_mod(a: u64, b: u64, m: u64) -> u64 {
    u64::try_from((u128::from(a) + u128::from(b)) % u128::from(m)).unwrap_or(0)
}
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    u64::try_from(u128::from(a) * u128::from(b) % u128::from(m)).unwrap_or(0)
}
pub fn matmul_loop(p: &IntegerProfile, a: &[u64], b: &[u64]) -> Result<Vec<u64>, TrainingError> {
    p.validate()?;
    let r = usize::try_from(p.rows).map_err(|_| TrainingError::Shape)?;
    let n = usize::try_from(p.inner).map_err(|_| TrainingError::Shape)?;
    let c = usize::try_from(p.cols).map_err(|_| TrainingError::Shape)?;
    if a.len() != r * n || b.len() != n * c {
        return Err(TrainingError::Shape);
    }
    let mut out = vec![0; r * c];
    for i in 0..r {
        for k in 0..n {
            for j in 0..c {
                out[i * c + j] = add_mod(
                    out[i * c + j],
                    mul_mod(
                        a[i * n + k] % p.modulus,
                        b[k * c + j] % p.modulus,
                        p.modulus,
                    ),
                    p.modulus,
                );
            }
        }
    }
    Ok(out)
}
pub fn matmul_storage(p: &IntegerProfile, a: &[u64], b: &[u64]) -> Result<Vec<u64>, TrainingError> {
    p.validate()?;
    let r = p.rows as usize;
    let n = p.inner as usize;
    let c = p.cols as usize;
    if a.len() != r * n || b.len() != n * c {
        return Err(TrainingError::Shape);
    }
    let columns = (0..c)
        .map(|j| (0..n).map(|k| b[k * c + j]).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(r * c);
    for row in a.chunks_exact(n) {
        for col in &columns {
            out.push(row.iter().zip(col).fold(0, |acc, (x, y)| {
                add_mod(
                    acc,
                    mul_mod(*x % p.modulus, *y % p.modulus, p.modulus),
                    p.modulus,
                )
            }));
        }
    }
    Ok(out)
}
fn challenge(seed: Hash32, len: usize, m: u64) -> Vec<u64> {
    (0..len)
        .map(|i| {
            let mut h = blake3::Hasher::new();
            h.update(b"NOOS/E-GRAD-01/FREIVALDS/V1");
            h.update(&seed);
            h.update(&(i as u64).to_le_bytes());
            u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().unwrap_or([0; 8])) % m
        })
        .collect()
}
pub fn freivalds(
    p: &IntegerProfile,
    a: &[u64],
    b: &[u64],
    claimed: &[u64],
    seed: Hash32,
) -> Result<bool, TrainingError> {
    p.validate()?;
    let r = p.rows as usize;
    let n = p.inner as usize;
    let c = p.cols as usize;
    if a.len() != r * n || b.len() != n * c || claimed.len() != r * c {
        return Err(TrainingError::Shape);
    }
    let v = challenge(seed, c, p.modulus);
    let mut bv = vec![0; n];
    for k in 0..n {
        for j in 0..c {
            bv[k] = add_mod(
                bv[k],
                mul_mod(b[k * c + j] % p.modulus, v[j], p.modulus),
                p.modulus,
            );
        }
    }
    for i in 0..r {
        let mut left = 0;
        let mut right = 0;
        for k in 0..n {
            left = add_mod(
                left,
                mul_mod(a[i * n + k] % p.modulus, bv[k], p.modulus),
                p.modulus,
            );
        }
        for j in 0..c {
            right = add_mod(
                right,
                mul_mod(claimed[i * c + j] % p.modulus, v[j], p.modulus),
                p.modulus,
            );
        }
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GradientAudit {
    pub fidelity_passed: bool,
    pub quality_score: Option<i64>,
    pub forged_gradient_coverage: bool,
    pub slashable: bool,
}
pub fn audit_gradient(
    p: &IntegerProfile,
    a: &[u64],
    b: &[u64],
    claimed: &[u64],
    seed: Hash32,
    quality_score: Option<i64>,
) -> Result<GradientAudit, TrainingError> {
    let loop_out = matmul_loop(p, a, b)?;
    let storage_out = matmul_storage(p, a, b)?;
    if loop_out != storage_out {
        return Err(TrainingError::ImplementationDivergence);
    }
    let nonzero = claimed.iter().any(|x| *x % p.modulus != 0);
    Ok(GradientAudit {
        fidelity_passed: freivalds(p, a, b, claimed, seed)?,
        quality_score,
        forged_gradient_coverage: nonzero,
        slashable: false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PentagonPath {
    ThoughtDelivery,
    ShadowSecurity,
    DisputeEvidence,
    TrainingAdjoint,
    BranchRegistration,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PentagonWitness {
    pub witness_root: Hash32,
    pub model_parameters: u64,
    pub chunk_tokens: u32,
    pub inference_cost: u64,
    pub path_roots: BTreeMap<PentagonPath, Hash32>,
    pub disabled: BTreeSet<PentagonPath>,
}
impl PentagonWitness {
    pub fn derive_path(&self, path: PentagonPath) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/I-PENTAGON/PATH/V1");
        h.update(&self.witness_root);
        h.update(&(path as u8).to_le_bytes());
        *h.finalize().as_bytes()
    }
    pub fn validate_ident01(
        &self,
        marginal_cost: u64,
        double_credits: u64,
        orderings: u64,
    ) -> Result<(), TrainingError> {
        let all = [
            PentagonPath::ThoughtDelivery,
            PentagonPath::ShadowSecurity,
            PentagonPath::DisputeEvidence,
            PentagonPath::TrainingAdjoint,
            PentagonPath::BranchRegistration,
        ];
        if self.model_parameters != 500_000_000
            || self.chunk_tokens != 32
            || orderings < 100_000
            || double_credits != 0
            || self.inference_cost == 0
        {
            return Err(TrainingError::Ident01);
        }
        for p in all {
            if self.path_roots.get(&p).copied() != Some(self.derive_path(p)) {
                return Err(TrainingError::Ident01);
            }
        }
        if u128::from(marginal_cost) * 10_000
            > u128::from(self.inference_cost) * u128::from(MAX_IDENT01_COST_BPS)
        {
            return Err(TrainingError::IdentCost);
        }
        Ok(())
    }
}
#[must_use]
pub fn pentagon_path_output(witness: &PentagonWitness, path: PentagonPath) -> Option<Hash32> {
    if witness.disabled.contains(&path) {
        None
    } else {
        witness.path_roots.get(&path).copied()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GemmLeaf {
    ForwardY,
    InputGradient,
    WeightGradient,
}
#[must_use]
pub fn ident02_transcript_domain(leaf: GemmLeaf, witness_root: Hash32) -> Hash32 {
    let label: &[u8] = match leaf {
        GemmLeaf::ForwardY => b"Y=XW",
        GemmLeaf::InputGradient => b"G_X=G_YW^T",
        GemmLeaf::WeightGradient => b"G_W=X^TG_Y",
    };
    let mut h = blake3::Hasher::new();
    h.update(b"NOOS/E-IDENT-02/THREE-GEMM/V1");
    h.update(label);
    h.update(&witness_root);
    *h.finalize().as_bytes()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident02Result {
    pub mutation_rejections: u8,
    pub transplant_rejections: u64,
    pub transplant_attempts: u64,
    pub complete_binding: bool,
    pub cost: u64,
    pub inference_chunk_cost: u64,
}
impl Ident02Result {
    pub fn verdict(&self) -> Result<&'static str, TrainingError> {
        if !self.complete_binding
            || self.mutation_rejections != 15
            || self.transplant_attempts == 0
            || self.transplant_rejections != self.transplant_attempts
        {
            return Err(TrainingError::IdentTamper);
        }
        if u128::from(self.cost) * 10_000
            > u128::from(self.inference_chunk_cost) * u128::from(MAX_IDENT02_COST_BPS)
        {
            return Ok("REPRICE_NEW_CLAIM_VERSION");
        }
        Ok("PASS_SHADOW_ONLY")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisableTrial {
    pub lane: &'static str,
    pub epochs_disabled: u8,
    pub surviving_cost_bps: u16,
    pub base_behavior_identical: bool,
}
pub fn validate_ident03(trials: &[DisableTrial]) -> Result<&'static str, TrainingError> {
    let required = BTreeSet::from(["DREAM", "TRAINING_CREDIT", "LOOM_CREDIT", "CHORUS"]);
    let got = trials.iter().map(|t| t.lane).collect::<BTreeSet<_>>();
    if got != required
        || trials
            .iter()
            .any(|t| t.epochs_disabled < 2 || !t.base_behavior_identical)
    {
        return Err(TrainingError::Ident03);
    }
    if trials.iter().any(|t| t.surviving_cost_bps > 20_000) {
        return Ok("COLLAPSE_COUPLED_LABELS");
    }
    if trials.iter().any(|t| t.surviving_cost_bps > 12_500) {
        return Ok("FAIL_COST_TARGET");
    }
    Ok("PASS_SHADOW_ONLY")
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrainingError {
    #[error("quality and fidelity evidence must be distinct")]
    QualityFidelityConflation,
    #[error("invalid promotion")]
    InvalidPromotion,
    #[error("invalid integer profile")]
    InvalidProfile,
    #[error("matrix shape mismatch")]
    Shape,
    #[error("independent implementations diverged")]
    ImplementationDivergence,
    #[error("E-IDENT-01 failed")]
    Ident01,
    #[error("identity experiment cost exceeded")]
    IdentCost,
    #[error("E-IDENT-02 tamper accepted")]
    IdentTamper,
    #[error("E-IDENT-03 failed")]
    Ident03,
    #[error("invalid canonical update packet")]
    InvalidUpdatePacket,
    #[error("invalid immutable reaction")]
    InvalidReaction,
    #[error("reaction parent is stale")]
    StaleParent,
    #[error("reaction replay")]
    ReactionReplay,
    #[error("unknown reaction")]
    UnknownReaction,
    #[error("invalid reaction lifecycle transition")]
    InvalidReactionTransition,
    #[error("challenge did not falsify the candidate")]
    ChallengeFailed,
    #[error("invalid rollout lag policy")]
    InvalidLagPolicy,
    #[error("rollout names a future policy version")]
    FuturePolicyVersion,
    #[error("rollout lag arithmetic failed")]
    LagArithmetic,
    #[error("rollout group is empty")]
    EmptyRolloutGroup,
    #[error("invalid TOPLOC profile")]
    InvalidToplocProfile,
    #[error("TOPLOC seed does not match its prior commitment")]
    ToplocSeedSubstitution,
    #[error("TOPLOC model or profile substitution")]
    ToplocProfileSubstitution,
    #[error("TOPLOC hidden width is unsupported")]
    ToplocWidth,
    #[error("TOPLOC projection arithmetic failed")]
    ToplocArithmetic,
    #[error("invalid or tampered reaction capsule")]
    InvalidReactionCapsule,
    #[error("reaction arithmetic overflow")]
    ReactionArithmetic,
    #[error("reaction is not exact under its numeric profile")]
    InexactReactionProfile,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use noos_species::UpdateKind;
    fn h(v: u8) -> Hash32 {
        [v; 32]
    }
    fn profile() -> IntegerProfile {
        IntegerProfile {
            profile_id: h(1),
            modulus: 97,
            rows: 2,
            inner: 3,
            cols: 2,
            challenge_domain: h(2),
            independent_implementations: 2,
        }
    }
    #[test]
    fn implementations_and_freivalds_agree() {
        let p = profile();
        let a = [1, 2, 3, 4, 5, 6];
        let b = [7, 8, 9, 10, 11, 12];
        let c = matmul_loop(&p, &a, &b).unwrap();
        assert_eq!(c, matmul_storage(&p, &a, &b).unwrap());
        assert!(freivalds(&p, &a, &b, &c, h(3)).unwrap());
        let mut bad = c;
        bad[0] += 1;
        assert!(!freivalds(&p, &a, &b, &bad, h(3)).unwrap());
    }
    #[test]
    fn zero_gradient_not_forged_coverage_and_quality_is_separate() {
        let p = profile();
        let a = [0; 6];
        let b = [0; 6];
        let x = audit_gradient(&p, &a, &b, &[0; 4], h(1), Some(88)).unwrap();
        assert!(x.fidelity_passed && !x.forged_gradient_coverage && !x.slashable);
        assert_eq!(x.quality_score, Some(88));
    }
    #[test]
    fn promotion_creates_new_revision() {
        let base = SpeciesRevision {
            revision_id: h(1),
            species_id: h(2),
            manifest_version: 1,
            composition_root: h(3),
            required_artifacts: vec![],
            execution_manifest: h(4),
            relation_claims: vec![],
            serving_profiles: vec![],
            availability_certificate: h(5),
            rights_certificate: h(6),
            lifecycle: RevisionLifecycle::Admitted,
        };
        let packet = UpdatePacket {
            packet_id: h(7),
            base_members: vec![h(1)],
            update_kind: UpdateKind::LowRank,
            payload: h(8),
            applicability_predicate: h(9),
            tokenizer: h(10),
            numeric_profile: h(11),
            training_recipe: None,
            source_capsules: vec![],
            policy_version: None,
            privacy_parameters_root: None,
            rights_expression: h(12),
            provenance_root: h(17),
            availability_commitments: vec![h(18)],
            contributor_set: vec![],
            evaluation_receipts: vec![],
            expiry: None,
        };
        let reaction = ReactionRecord {
            reaction_id: h(13),
            packet_id: h(7),
            base_revision: h(1),
            decision: ReactionDecision::Accepted,
            fidelity_evidence_root: h(14),
            quality_evidence_root: h(15),
            decided_at: 3,
        };
        let (r, l) = promote(&packet, &base, &reaction, h(16), h(17)).unwrap();
        assert_eq!(r.revision_id, h(16));
        assert_eq!(l.promoted_revision, Some(h(16)));
    }
    #[test]
    fn ident02_exact_mutation_and_transplant_gate() {
        let ok = Ident02Result {
            mutation_rejections: 15,
            transplant_rejections: 4,
            transplant_attempts: 4,
            complete_binding: true,
            cost: 3,
            inference_chunk_cost: 1,
        };
        assert_eq!(ok.verdict().unwrap(), "PASS_SHADOW_ONLY");
        let bad = Ident02Result {
            mutation_rejections: 14,
            ..ok
        };
        assert_eq!(bad.verdict(), Err(TrainingError::IdentTamper));
    }
    #[test]
    fn ident03_base_effect_kills() {
        let mut t = vec![
            DisableTrial {
                lane: "DREAM",
                epochs_disabled: 2,
                surviving_cost_bps: 10_000,
                base_behavior_identical: true,
            },
            DisableTrial {
                lane: "TRAINING_CREDIT",
                epochs_disabled: 2,
                surviving_cost_bps: 10_000,
                base_behavior_identical: true,
            },
            DisableTrial {
                lane: "LOOM_CREDIT",
                epochs_disabled: 2,
                surviving_cost_bps: 10_000,
                base_behavior_identical: true,
            },
            DisableTrial {
                lane: "CHORUS",
                epochs_disabled: 2,
                surviving_cost_bps: 10_000,
                base_behavior_identical: true,
            },
        ];
        assert_eq!(validate_ident03(&t).unwrap(), "PASS_SHADOW_ONLY");
        t[0].base_behavior_identical = false;
        assert_eq!(validate_ident03(&t), Err(TrainingError::Ident03));
    }
}

#[cfg(test)]
mod identity_domain_tests {
    use super::*;
    #[test]
    fn three_gemm_transcript_domains_are_distinct() {
        let witness = [7; 32];
        let domains = BTreeSet::from([
            ident02_transcript_domain(GemmLeaf::ForwardY, witness),
            ident02_transcript_domain(GemmLeaf::InputGradient, witness),
            ident02_transcript_domain(GemmLeaf::WeightGradient, witness),
        ]);
        assert_eq!(domains.len(), 3);
    }
    #[test]
    fn each_pentagon_path_is_independently_disableable() {
        let mut witness = PentagonWitness {
            witness_root: [1; 32],
            model_parameters: 500_000_000,
            chunk_tokens: 32,
            inference_cost: 100,
            path_roots: BTreeMap::new(),
            disabled: BTreeSet::new(),
        };
        for path in [
            PentagonPath::ThoughtDelivery,
            PentagonPath::ShadowSecurity,
            PentagonPath::DisputeEvidence,
            PentagonPath::TrainingAdjoint,
            PentagonPath::BranchRegistration,
        ] {
            witness.path_roots.insert(path, witness.derive_path(path));
        }
        assert!(pentagon_path_output(&witness, PentagonPath::DisputeEvidence).is_some());
        witness.disabled.insert(PentagonPath::DisputeEvidence);
        assert_eq!(
            pentagon_path_output(&witness, PentagonPath::DisputeEvidence),
            None
        );
        assert!(pentagon_path_output(&witness, PentagonPath::ThoughtDelivery).is_some());
    }
}
