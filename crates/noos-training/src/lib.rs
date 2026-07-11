//! Immutable experimental training records, deterministic integer execution,
//! Freivalds fidelity audits, and shadow-only I-PENTAGON evidence.
#![forbid(unsafe_code)]
// Modular arithmetic and validated matrix index arithmetic are the experiment's
// subject; dimensions are bounded before any allocation or indexing.
#![allow(clippy::arithmetic_side_effects)]
use noos_nel::{freivalds_verify_u64 as nel_freivalds, FreivaldsProfile};
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

/// The H-TRAIN outer-loop and receipt shape. It remains experimental until
/// the real 32-hearth, 1.5B, live-stake pilot passes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainStepClaim {
    pub reaction_id: Hash32,
    pub member_root: Hash32,
    pub outer_step: u64,
    pub inner_lo: u64,
    pub inner_hi: u64,
    pub policy_lag: u16,
    pub data_shard_root: Hash32,
    pub fwd_root: Hash32,
    pub bwd_root: Hash32,
    pub grad_root: Hash32,
    pub opt_state_root: Hash32,
    pub pseudograd_root: Hash32,
    pub registered_graph_root: Hash32,
    pub local_opening_root: Hash32,
    pub toploc_root: Hash32,
}

impl TrainStepClaim {
    pub fn validate(&self, maximum_policy_lag: u16) -> Result<(), TrainingError> {
        if self.inner_lo >= self.inner_hi
            || self.policy_lag > maximum_policy_lag
            || [
                self.reaction_id,
                self.member_root,
                self.data_shard_root,
                self.fwd_root,
                self.bwd_root,
                self.grad_root,
                self.opt_state_root,
                self.pseudograd_root,
                self.registered_graph_root,
                self.local_opening_root,
                self.toploc_root,
            ]
            .contains(&[0; 32])
        {
            return Err(TrainingError::InvalidTrainStep);
        }
        if self.local_opening_root != expected_training_opening(self) {
            return Err(TrainingError::UnboundJacobianOpening);
        }
        Ok(())
    }
}

#[must_use]
pub fn expected_training_opening(claim: &TrainStepClaim) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/HEARTH/TRAINING-OPENING/V1");
    hasher.update(&claim.registered_graph_root);
    hasher.update(&claim.fwd_root);
    hasher.update(&claim.bwd_root);
    hasher.update(&claim.grad_root);
    hasher.update(&claim.opt_state_root);
    hasher.update(&claim.outer_step.to_le_bytes());
    hasher.update(&claim.inner_lo.to_le_bytes());
    hasher.update(&claim.inner_hi.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeGemmWitness {
    pub x: Vec<u64>,
    pub w: Vec<u64>,
    pub dy: Vec<u64>,
    pub y: Vec<u64>,
    pub dx: Vec<u64>,
    pub dw: Vec<u64>,
}

impl ThreeGemmWitness {
    pub fn honest(
        profile: &IntegerProfile,
        x: Vec<u64>,
        w: Vec<u64>,
        dy: Vec<u64>,
    ) -> Result<Self, TrainingError> {
        let y = matmul_loop(profile, &x, &w)?;
        let w_t = transpose(&w, profile.inner as usize, profile.cols as usize)?;
        let x_t = transpose(&x, profile.rows as usize, profile.inner as usize)?;
        let dx_profile = derived_profile(profile, profile.rows, profile.cols, profile.inner, b"DX");
        let dw_profile = derived_profile(profile, profile.inner, profile.rows, profile.cols, b"DW");
        let dx = matmul_loop(&dx_profile, &dy, &w_t)?;
        let dw = matmul_loop(&dw_profile, &x_t, &dy)?;
        Ok(Self {
            x,
            w,
            dy,
            y,
            dx,
            dw,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrainingAttack {
    SignFlippedGradient,
    StalePolicy,
    CoherentFakeJacobian,
    UnopenedNodeCorruption,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrainingAuditReport {
    pub forward_passed: bool,
    pub input_gradient_passed: bool,
    pub weight_gradient_passed: bool,
    pub opening_bound: bool,
    pub policy_lag_valid: bool,
    pub detected_attacks: BTreeSet<TrainingAttack>,
    pub false_slash: bool,
}

impl TrainingAuditReport {
    #[must_use]
    pub fn exact_fidelity_passed(&self) -> bool {
        self.forward_passed
            && self.input_gradient_passed
            && self.weight_gradient_passed
            && self.opening_bound
            && self.policy_lag_valid
    }
}

pub fn audit_training_step(
    profile: &IntegerProfile,
    claim: &TrainStepClaim,
    witness: &ThreeGemmWitness,
    challenge_seed: Hash32,
    maximum_policy_lag: u16,
) -> Result<TrainingAuditReport, TrainingError> {
    profile.validate()?;
    let forward_passed = freivalds(profile, &witness.x, &witness.w, &witness.y, challenge_seed)?
        && same_chunk_leaf(
            &witness.x,
            &witness.w,
            &witness.y,
            profile.rows,
            profile.inner,
            profile.cols,
            challenge_seed,
        )?;
    let w_t = transpose(&witness.w, profile.inner as usize, profile.cols as usize)?;
    let x_t = transpose(&witness.x, profile.rows as usize, profile.inner as usize)?;
    let dx_profile = derived_profile(profile, profile.rows, profile.cols, profile.inner, b"DX");
    let dw_profile = derived_profile(profile, profile.inner, profile.rows, profile.cols, b"DW");
    let dx_seed = transcript_seed(challenge_seed, b"DX");
    let dw_seed = transcript_seed(challenge_seed, b"DW");
    let input_gradient_passed = freivalds(&dx_profile, &witness.dy, &w_t, &witness.dx, dx_seed)?
        && same_chunk_leaf(
            &witness.dy,
            &w_t,
            &witness.dx,
            dx_profile.rows,
            dx_profile.inner,
            dx_profile.cols,
            dx_seed,
        )?;
    let weight_gradient_passed = freivalds(&dw_profile, &x_t, &witness.dy, &witness.dw, dw_seed)?
        && same_chunk_leaf(
            &x_t,
            &witness.dy,
            &witness.dw,
            dw_profile.rows,
            dw_profile.inner,
            dw_profile.cols,
            dw_seed,
        )?;
    let opening_bound = claim.local_opening_root == expected_training_opening(claim);
    let policy_lag_valid = claim.policy_lag <= maximum_policy_lag;
    let mut detected_attacks = BTreeSet::new();
    if !weight_gradient_passed {
        detected_attacks.insert(TrainingAttack::SignFlippedGradient);
    }
    if !policy_lag_valid {
        detected_attacks.insert(TrainingAttack::StalePolicy);
    }
    if !input_gradient_passed {
        detected_attacks.insert(TrainingAttack::CoherentFakeJacobian);
    }
    if !opening_bound {
        detected_attacks.insert(TrainingAttack::UnopenedNodeCorruption);
    }
    Ok(TrainingAuditReport {
        forward_passed,
        input_gradient_passed,
        weight_gradient_passed,
        opening_bound,
        policy_lag_valid,
        detected_attacks,
        false_slash: false,
    })
}

fn same_chunk_leaf(
    a: &[u64],
    b: &[u64],
    c: &[u64],
    rows: u32,
    inner: u32,
    cols: u32,
    seed: Hash32,
) -> Result<bool, TrainingError> {
    let cols_usize = usize::try_from(cols).map_err(|_| TrainingError::Shape)?;
    let vectors = (0..FreivaldsProfile::StandardReps2.reps())
        .map(|repetition| {
            (0..cols_usize)
                .map(|column| {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"NOOS/HEARTH/TRAINING-NEL-LEAF/V1");
                    hasher.update(&seed);
                    hasher.update(&(repetition as u64).to_le_bytes());
                    hasher.update(&(column as u64).to_le_bytes());
                    u32::from_le_bytes(
                        hasher.finalize().as_bytes()[..4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    nel_freivalds(
        a,
        b,
        c,
        usize::try_from(rows).map_err(|_| TrainingError::Shape)?,
        usize::try_from(inner).map_err(|_| TrainingError::Shape)?,
        cols_usize,
        &vectors,
        FreivaldsProfile::StandardReps2,
    )
    .map_err(|_| TrainingError::InvalidTrainStep)
}

fn derived_profile(
    profile: &IntegerProfile,
    rows: u32,
    inner: u32,
    cols: u32,
    label: &[u8],
) -> IntegerProfile {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/HEARTH/TRAINING-GEMM-PROFILE/V1");
    hasher.update(&profile.profile_id);
    hasher.update(label);
    IntegerProfile {
        profile_id: *hasher.finalize().as_bytes(),
        modulus: profile.modulus,
        rows,
        inner,
        cols,
        challenge_domain: profile.challenge_domain,
        independent_implementations: profile.independent_implementations,
    }
}

fn transcript_seed(seed: Hash32, label: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/HEARTH/TRAINING-GEMM-CHALLENGE/V1");
    hasher.update(&seed);
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

fn transpose(values: &[u64], rows: usize, cols: usize) -> Result<Vec<u64>, TrainingError> {
    if values.len() != rows.saturating_mul(cols) {
        return Err(TrainingError::Shape);
    }
    let mut transposed = vec![0; values.len()];
    for row in 0..rows {
        for col in 0..cols {
            transposed[col * rows + row] = values[row * cols + col];
        }
    }
    Ok(transposed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrainingPilotModel {
    pub hearths: u16,
    pub model_parameters: u64,
    pub outer_loop_h: u16,
    pub local_batch_tokens: u32,
    pub sync_milliseconds: u64,
    pub compute_milliseconds: u64,
    pub witness_bytes: u64,
    pub witness_budget_bytes: u64,
}

impl TrainingPilotModel {
    pub fn validate_reference_shape(self) -> Result<(), TrainingError> {
        if self.hearths < 32
            || self.model_parameters != 1_500_000_000
            || self.outer_loop_h != 500
            || self.local_batch_tokens != 8_192
            || self.compute_milliseconds == 0
        {
            return Err(TrainingError::InvalidPilotShape);
        }
        Ok(())
    }

    pub fn sync_compute_ratio_bps(self) -> Result<u64, TrainingError> {
        self.validate_reference_shape()?;
        Ok(self.sync_milliseconds.saturating_mul(10_000) / self.compute_milliseconds)
    }

    pub fn local_thresholds_met(self) -> Result<bool, TrainingError> {
        // 1.2 * modeled 1.08 = 1.296, represented exactly in basis points.
        Ok(self.sync_compute_ratio_bps()? <= 12_960
            && self.witness_bytes <= self.witness_budget_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrainingFallback {
    SlashableCandidate,
    TrustedFederationNoCredit,
}

#[must_use]
pub fn rollback_training(any_false_slash: bool, witness_affordable: bool) -> TrainingFallback {
    if any_false_slash || !witness_affordable {
        TrainingFallback::TrustedFederationNoCredit
    } else {
        TrainingFallback::SlashableCandidate
    }
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
    #[error("invalid training-step claim")]
    InvalidTrainStep,
    #[error("training Jacobian opening is not bound to the registered graph")]
    UnboundJacobianOpening,
    #[error("invalid H-TRAIN pilot shape")]
    InvalidPilotShape,
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
    fn train_claim() -> TrainStepClaim {
        let mut claim = TrainStepClaim {
            reaction_id: h(20),
            member_root: h(21),
            outer_step: 7,
            inner_lo: 500,
            inner_hi: 1_000,
            policy_lag: 1,
            data_shard_root: h(22),
            fwd_root: h(23),
            bwd_root: h(24),
            grad_root: h(25),
            opt_state_root: h(26),
            pseudograd_root: h(27),
            registered_graph_root: h(28),
            local_opening_root: h(29),
            toploc_root: h(30),
        };
        claim.local_opening_root = expected_training_opening(&claim);
        claim
    }
    #[test]
    fn three_training_gemms_accept_honest_and_detect_each_local_attack_surface() {
        let mut p = profile();
        // This bounded fixture never reaches the modulus, so the field-model
        // verifier and the production wrapping-integer NEL leaf are identical.
        p.modulus = u64::MAX;
        let x = vec![1, 2, 3, 4, 5, 6];
        let w = vec![7, 8, 9, 10, 11, 12];
        let dy = vec![2, 3, 5, 7];
        let honest = ThreeGemmWitness::honest(&p, x, w, dy).unwrap();
        assert_eq!(honest.y, vec![58, 64, 139, 154]);
        assert!(nel_freivalds(
            &honest.x,
            &honest.w,
            &honest.y,
            2,
            3,
            2,
            &[vec![1, 2], vec![3, 5]],
            FreivaldsProfile::StandardReps2
        )
        .unwrap());
        let claim = train_claim();
        assert!(freivalds(&p, &honest.x, &honest.w, &honest.y, h(31)).unwrap());
        assert!(same_chunk_leaf(
            &honest.x,
            &honest.w,
            &honest.y,
            p.rows,
            p.inner,
            p.cols,
            h(31)
        )
        .unwrap());
        let report = audit_training_step(&p, &claim, &honest, h(31), 2).unwrap();
        assert!(report.exact_fidelity_passed(), "{report:?}");
        assert!(report.detected_attacks.is_empty());
        assert!(!report.false_slash);

        let mut sign_flip = honest.clone();
        sign_flip.dw[0] = (p.modulus - sign_flip.dw[0]) % p.modulus;
        let report = audit_training_step(&p, &claim, &sign_flip, h(31), 2).unwrap();
        assert!(report
            .detected_attacks
            .contains(&TrainingAttack::SignFlippedGradient));

        let mut fake_jacobian = honest.clone();
        fake_jacobian.dx[0] = (fake_jacobian.dx[0] + 1) % p.modulus;
        let report = audit_training_step(&p, &claim, &fake_jacobian, h(31), 2).unwrap();
        assert!(report
            .detected_attacks
            .contains(&TrainingAttack::CoherentFakeJacobian));

        let mut stale = claim.clone();
        stale.policy_lag = 3;
        let report = audit_training_step(&p, &stale, &honest, h(31), 2).unwrap();
        assert!(report
            .detected_attacks
            .contains(&TrainingAttack::StalePolicy));

        let mut unopened = claim;
        unopened.local_opening_root[0] ^= 1;
        let report = audit_training_step(&p, &unopened, &honest, h(31), 2).unwrap();
        assert!(report
            .detected_attacks
            .contains(&TrainingAttack::UnopenedNodeCorruption));
    }
    #[test]
    fn training_pilot_model_pins_reference_shape_ratio_and_rollback() {
        let pilot = TrainingPilotModel {
            hearths: 32,
            model_parameters: 1_500_000_000,
            outer_loop_h: 500,
            local_batch_tokens: 8_192,
            sync_milliseconds: 1_080,
            compute_milliseconds: 1_000,
            witness_bytes: 100,
            witness_budget_bytes: 100,
        };
        assert_eq!(pilot.sync_compute_ratio_bps().unwrap(), 10_800);
        assert!(pilot.local_thresholds_met().unwrap());
        assert_eq!(
            rollback_training(false, true),
            TrainingFallback::SlashableCandidate
        );
        assert_eq!(
            rollback_training(true, true),
            TrainingFallback::TrustedFederationNoCredit
        );
        assert_eq!(
            rollback_training(false, false),
            TrainingFallback::TrustedFederationNoCredit
        );
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
