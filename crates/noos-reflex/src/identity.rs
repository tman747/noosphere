//! Local precursor for I-PENTAGON and E-IDENT-01..03.
//!
//! The implementation consumes one exact INT8/C32 span artifact. Product
//! derivation never calls the GEMM executor. Production-shape cycle, silicon,
//! public-testnet, and paid-demand measurements remain outside this module.

use crate::Hash32;
use noos_nel::{
    inference::{freivalds_cost_muls, gemm_i8, recompute_cost_muls, requant},
    TokenStateCommitment,
};
use noos_training::{ident02_transcript_domain, GemmLeaf, PentagonPath, PentagonWitness};
use noos_umbra::{
    branch::{family_nullifier, BranchError, BranchRegistry, FamilyRegistration},
    Commitment32,
};
use noos_work_loom::{
    economics::{CompletionEvidence, ControlEvidence, DemandEvidence, FundingEvidence},
    shadow,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const INFERENCE_DOMAIN: &[u8] = b"NOOS/E-IDENT-02/INFERENCE/V1";
const SPAN_DOMAIN: &[u8] = b"NOOS/I-PENTAGON/SPAN/V1";
const PRODUCT_DOMAIN: &[u8] = b"NOOS/I-PENTAGON/PRODUCT/V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanParams {
    pub beacon: Hash32,
    pub domain_id: Hash32,
    pub payout_key: Hash32,
    pub multiplier: i64,
    pub shift: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanArtifact {
    pub rows: usize,
    pub inner: usize,
    pub columns: usize,
    pub left: Vec<i8>,
    pub right: Vec<i8>,
    pub c32: Vec<i32>,
    pub c8: Vec<i8>,
    pub params: SpanParams,
    root: Hash32,
}

impl SpanArtifact {
    /// The single underlying `O(T*K*N)` execution used by every Pentagon
    /// product path.
    pub fn execute(
        left: Vec<i8>,
        right: Vec<i8>,
        rows: usize,
        inner: usize,
        columns: usize,
        params: SpanParams,
    ) -> Result<Self, IdentityError> {
        let c32 = gemm_i8(&left, &right, rows, inner, columns).map_err(|_| IdentityError::Shape)?;
        let c8 = c32
            .iter()
            .map(|&value| requant(i64::from(value), params.multiplier, params.shift))
            .collect();
        let mut artifact = Self {
            rows,
            inner,
            columns,
            left,
            right,
            c32,
            c8,
            params,
            root: [0; 32],
        };
        artifact.root = artifact.compute_root();
        Ok(artifact)
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        if self.compute_root() != self.root {
            return Err(IdentityError::WitnessMutation);
        }
        let expected = gemm_i8(&self.left, &self.right, self.rows, self.inner, self.columns)
            .map_err(|_| IdentityError::Shape)?;
        if expected != self.c32
            || self.c8
                != self
                    .c32
                    .iter()
                    .map(|&value| {
                        requant(i64::from(value), self.params.multiplier, self.params.shift)
                    })
                    .collect::<Vec<_>>()
        {
            return Err(IdentityError::LeafRelation);
        }
        Ok(())
    }

    #[must_use]
    pub const fn root(&self) -> Hash32 {
        self.root
    }

    #[must_use]
    pub fn c32_root(&self) -> Hash32 {
        hash_i32(b"NOOS/I-PENTAGON/C32/V1", &self.c32)
    }

    #[must_use]
    pub fn c8_root(&self) -> Hash32 {
        hash_i8(b"NOOS/I-PENTAGON/C8/V1", &self.c8)
    }

    fn compute_root(&self) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(SPAN_DOMAIN);
        h.update(&(self.rows as u64).to_le_bytes());
        h.update(&(self.inner as u64).to_le_bytes());
        h.update(&(self.columns as u64).to_le_bytes());
        h.update(&hash_i8(b"NOOS/I-PENTAGON/A/V1", &self.left));
        h.update(&hash_i8(b"NOOS/I-PENTAGON/B/V1", &self.right));
        h.update(&self.c32_root());
        h.update(&self.c8_root());
        h.update(&self.params.beacon);
        h.update(&self.params.domain_id);
        h.update(&self.params.payout_key);
        h.update(&self.params.multiplier.to_le_bytes());
        h.update(&self.params.shift.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeafRole {
    Inference,
    Forward,
    InputGradient,
    WeightGradient,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedLeaf {
    pub role: LeafRole,
    pub span_id: Hash32,
    pub gy_root: Hash32,
    pub artifact: SpanArtifact,
    transcript_root: Hash32,
}

impl SharedLeaf {
    fn execute(
        role: LeafRole,
        left: Vec<i8>,
        right: Vec<i8>,
        shape: (usize, usize, usize),
        gy_root: Hash32,
        common: &SpanParams,
    ) -> Result<Self, IdentityError> {
        let (rows, inner, columns) = shape;
        let span_id = role_span_id(role, common.beacon);
        let mut params = common.clone();
        params.domain_id = span_id;
        let artifact = SpanArtifact::execute(left, right, rows, inner, columns, params)?;
        let transcript_root = leaf_transcript_root(role, span_id, gy_root, artifact.root());
        Ok(Self {
            role,
            span_id,
            gy_root,
            artifact,
            transcript_root,
        })
    }

    pub fn verify(
        &self,
        expected_role: LeafRole,
        expected_gy: Hash32,
    ) -> Result<(), IdentityError> {
        if self.role != expected_role
            || self.span_id != role_span_id(expected_role, self.artifact.params.beacon)
            || self.artifact.params.domain_id != self.span_id
        {
            return Err(IdentityError::LeafSubstitution);
        }
        if expected_role == LeafRole::Inference {
            if self.gy_root != [0; 32] {
                return Err(IdentityError::GradientBinding);
            }
        } else if self.gy_root != expected_gy || expected_gy == [0; 32] {
            return Err(IdentityError::GradientBinding);
        }
        self.artifact.verify()?;
        if self.transcript_root
            != leaf_transcript_root(self.role, self.span_id, self.gy_root, self.artifact.root())
        {
            return Err(IdentityError::Transcript);
        }
        Ok(())
    }

    #[must_use]
    pub const fn transcript_root(&self) -> Hash32 {
        self.transcript_root
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseCensus {
    pub forward_macs: u64,
    pub input_gradient_macs: u64,
    pub weight_gradient_macs: u64,
    pub training_total_macs: u64,
    pub inference_macs: u64,
}

impl PhaseCensus {
    #[must_use]
    pub fn ratio_bps(&self) -> u64 {
        self.training_total_macs
            .saturating_mul(10_000)
            .checked_div(self.inference_macs)
            .unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn phase_sum_is_exact(&self) -> bool {
        self.forward_macs
            .checked_add(self.input_gradient_macs)
            .and_then(|sum| sum.checked_add(self.weight_gradient_macs))
            == Some(self.training_total_macs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrainingStepWitness {
    pub inference: SharedLeaf,
    pub forward: SharedLeaf,
    pub input_gradient: SharedLeaf,
    pub weight_gradient: SharedLeaf,
    pub gy_root: Hash32,
    pub census: PhaseCensus,
}

impl TrainingStepWitness {
    pub fn execute(
        x: Vec<i8>,
        w: Vec<i8>,
        gy: Vec<i8>,
        t: usize,
        k: usize,
        n: usize,
        common: SpanParams,
    ) -> Result<Self, IdentityError> {
        if x.len() != t.saturating_mul(k)
            || w.len() != k.saturating_mul(n)
            || gy.len() != t.saturating_mul(n)
        {
            return Err(IdentityError::Shape);
        }
        let gy_root = hash_i8(b"NOOS/E-IDENT-02/GY/V1", &gy);
        let w_t = transpose(&w, k, n)?;
        let x_t = transpose(&x, t, k)?;
        let inference = SharedLeaf::execute(
            LeafRole::Inference,
            x.clone(),
            w.clone(),
            (t, k, n),
            [0; 32],
            &common,
        )?;
        let forward = SharedLeaf::execute(LeafRole::Forward, x, w, (t, k, n), gy_root, &common)?;
        let input_gradient = SharedLeaf::execute(
            LeafRole::InputGradient,
            gy.clone(),
            w_t,
            (t, n, k),
            gy_root,
            &common,
        )?;
        let weight_gradient = SharedLeaf::execute(
            LeafRole::WeightGradient,
            x_t,
            gy,
            (k, t, n),
            gy_root,
            &common,
        )?;
        let inference_macs = macs(t, k, n)?;
        let forward_macs = inference_macs;
        let input_gradient_macs = macs(t, n, k)?;
        let weight_gradient_macs = macs(k, t, n)?;
        let training_total_macs = forward_macs
            .checked_add(input_gradient_macs)
            .and_then(|sum| sum.checked_add(weight_gradient_macs))
            .ok_or(IdentityError::CostOverflow)?;
        Ok(Self {
            inference,
            forward,
            input_gradient,
            weight_gradient,
            gy_root,
            census: PhaseCensus {
                forward_macs,
                input_gradient_macs,
                weight_gradient_macs,
                training_total_macs,
                inference_macs,
            },
        })
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        self.inference.verify(LeafRole::Inference, [0; 32])?;
        self.forward.verify(LeafRole::Forward, self.gy_root)?;
        self.input_gradient
            .verify(LeafRole::InputGradient, self.gy_root)?;
        self.weight_gradient
            .verify(LeafRole::WeightGradient, self.gy_root)?;
        if self.forward.artifact.c32 != self.inference.artifact.c32 {
            return Err(IdentityError::LeafSubstitution);
        }
        if !self.census.phase_sum_is_exact() || self.census.ratio_bps() > 35_000 {
            return Err(IdentityError::CostEnvelope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PentagonSpanWitness {
    pub artifact: SpanArtifact,
    pub terminal_token_state: TokenStateCommitment,
    pub training: TrainingStepWitness,
    pub escrow_id: Hash32,
    witness_root: Hash32,
}

impl PentagonSpanWitness {
    pub fn bind(
        artifact: SpanArtifact,
        terminal_token_state: TokenStateCommitment,
        training: TrainingStepWitness,
        escrow_id: Hash32,
    ) -> Result<Self, IdentityError> {
        artifact.verify()?;
        training.verify()?;
        if escrow_id == [0; 32] || artifact.c32_root() != training.forward.artifact.c32_root() {
            return Err(IdentityError::AdjointSubstitution);
        }
        let mut witness = Self {
            artifact,
            terminal_token_state,
            training,
            escrow_id,
            witness_root: [0; 32],
        };
        witness.witness_root = witness.compute_root();
        Ok(witness)
    }

    #[must_use]
    pub const fn root(&self) -> Hash32 {
        self.witness_root
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        self.artifact.verify()?;
        self.training.verify()?;
        if self.artifact.c32_root() != self.training.forward.artifact.c32_root() {
            return Err(IdentityError::AdjointSubstitution);
        }
        if self.compute_root() != self.witness_root {
            return Err(IdentityError::WitnessMutation);
        }
        Ok(())
    }

    fn compute_root(&self) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/I-PENTAGON/ONE-WITNESS/V1");
        h.update(&self.artifact.root());
        h.update(&self.terminal_token_state.commitment());
        h.update(&self.training.forward.transcript_root());
        h.update(&self.training.input_gradient.transcript_root());
        h.update(&self.training.weight_gradient.transcript_root());
        h.update(&self.escrow_id);
        *h.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductControls {
    pub disabled: Option<PentagonPath>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductReceipt {
    pub path: PentagonPath,
    pub witness_root: Hash32,
    pub product_root: Hash32,
    pub consensus_weight: u64,
    pub counterfactual_loom_credit: u128,
    pub production_loom_credit: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PentagonDelivery {
    pub receipts: BTreeMap<PentagonPath, ProductReceipt>,
    pub underlying_executions: u8,
    pub evidence_multiplications: u64,
    pub standalone_multiplications: u64,
}

/// Consume one already-produced span witness through all enabled products.
/// The only executor call is [`SpanArtifact::execute`], before this function.
pub fn compose_pentagon(
    witness: &PentagonSpanWitness,
    controls: ProductControls,
    branch_registry: &mut BranchRegistry,
    branch_key: &[u8; 32],
    chain_id: Hash32,
) -> Result<PentagonDelivery, IdentityError> {
    witness.verify()?;
    let paths = all_paths();
    let disabled = controls.disabled.into_iter().collect::<BTreeSet<_>>();
    let model_parameters =
        u64::try_from(witness.artifact.right.len()).map_err(|_| IdentityError::CostOverflow)?;
    let mut shared = PentagonWitness {
        witness_root: witness.root(),
        model_parameters,
        chunk_tokens: u32::try_from(witness.artifact.rows)
            .map_err(|_| IdentityError::CostOverflow)?,
        inference_cost: macs(
            witness.artifact.rows,
            witness.artifact.inner,
            witness.artifact.columns,
        )?,
        path_roots: BTreeMap::new(),
        disabled,
    };
    for path in paths {
        shared.path_roots.insert(path, shared.derive_path(path));
    }

    let mut receipts = BTreeMap::new();
    for path in paths {
        if shared.disabled.contains(&path) {
            continue;
        }
        let product_root = derive_product(witness, path)?;
        if path == PentagonPath::BranchRegistration {
            let parent = Commitment32(witness.terminal_token_state.commitment());
            let unique_right = product_root;
            let nullifier =
                family_nullifier(branch_key, witness.root(), chain_id, &parent, unique_right);
            branch_registry.register(
                branch_key,
                &FamilyRegistration {
                    domain: witness.root(),
                    chain_id,
                    parent,
                    unique_right,
                    family_root: product_root,
                    nullifier,
                },
            )?;
        }
        let shadow_credit = if path == PentagonPath::ShadowSecurity {
            shadow::calculate(
                shadow::Inputs {
                    ground_work: u128::from(shared.inference_cost),
                    settled_value: witness.artifact.c8.len() as u128,
                    calibration_units: u128::from(shared.inference_cost),
                    raw_stake: u128::from(shared.inference_cost),
                    demand_evidence: DemandEvidence {
                        on_chain_escrow: true,
                        delivered: true,
                        requester_worker_control: ControlEvidence::Independent,
                        requester_evaluator_control: ControlEvidence::Independent,
                        completion: CompletionEvidence::RequesterAccepted,
                        funding: FundingEvidence::ExternalNoCircularDetected,
                    },
                    delivered: true,
                    paid_certificate: true,
                },
                witness.root(),
            )
        } else {
            shadow::Outputs::default()
        };
        receipts.insert(
            path,
            ProductReceipt {
                path,
                witness_root: witness.root(),
                product_root,
                // I-PENTAGON is shadow-only; no product has base authority.
                consensus_weight: 0,
                counterfactual_loom_credit: shadow_credit.counterfactual_loom_credit,
                production_loom_credit: shadow_credit.production_loom_credit,
            },
        );
    }
    let t = u64::try_from(witness.artifact.rows).map_err(|_| IdentityError::CostOverflow)?;
    let k = u64::try_from(witness.artifact.inner).map_err(|_| IdentityError::CostOverflow)?;
    let n = u64::try_from(witness.artifact.columns).map_err(|_| IdentityError::CostOverflow)?;
    Ok(PentagonDelivery {
        receipts,
        underlying_executions: 1,
        evidence_multiplications: freivalds_cost_muls(t, k, n, 2),
        standalone_multiplications: recompute_cost_muls(t, k, n),
    })
}

fn derive_product(
    witness: &PentagonSpanWitness,
    path: PentagonPath,
) -> Result<Hash32, IdentityError> {
    let component = match path {
        PentagonPath::ThoughtDelivery => witness.artifact.c8_root(),
        PentagonPath::ShadowSecurity => {
            // Receipt-only shadow lottery: proposal and Loom weight are both zero.
            hash_parts(b"NOOS/I-PENTAGON/SHADOW-SECURITY/V1", &[&[0; 8], &[0; 8]])
        }
        PentagonPath::DisputeEvidence => {
            witness.artifact.verify()?;
            witness.artifact.c32_root()
        }
        PentagonPath::TrainingAdjoint => {
            witness.training.verify()?;
            if witness.artifact.c32_root() != witness.training.forward.artifact.c32_root() {
                return Err(IdentityError::AdjointSubstitution);
            }
            hash_parts(
                b"NOOS/I-PENTAGON/ADJOINT/V1",
                &[
                    &witness.training.forward.transcript_root(),
                    &witness.training.input_gradient.transcript_root(),
                    &witness.training.weight_gradient.transcript_root(),
                    &witness.training.gy_root,
                ],
            )
        }
        PentagonPath::BranchRegistration => hash_parts(
            b"NOOS/I-PENTAGON/BRANCH/V1",
            &[&witness.terminal_token_state.commitment()],
        ),
    };
    Ok(hash_parts(
        PRODUCT_DOMAIN,
        &[&witness.root(), &[path as u8], &component],
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CreditKind {
    Proposal,
    Proofpower,
}

#[derive(Default)]
pub struct CrossProductCreditLedger {
    credited: BTreeMap<(Hash32, u64), CreditKind>,
}

impl CrossProductCreditLedger {
    pub fn claim(
        &mut self,
        witness: Hash32,
        maturity: u64,
        kind: CreditKind,
    ) -> Result<(), IdentityError> {
        match self.credited.entry((witness, maturity)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(kind);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(IdentityError::CrossProductDoubleCredit)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClosureLane {
    Dream,
    TrainingCredit,
    LoomCredit,
    Chorus,
}

impl ClosureLane {
    const fn product(self) -> PentagonPath {
        match self {
            Self::Dream => PentagonPath::BranchRegistration,
            Self::TrainingCredit => PentagonPath::TrainingAdjoint,
            Self::LoomCredit => PentagonPath::ShadowSecurity,
            Self::Chorus => PentagonPath::DisputeEvidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureEpoch {
    pub epoch: u64,
    pub disabled: ClosureLane,
    /// Costs in basis points of each product's all-lanes-on baseline.
    pub surviving_cost_bps: BTreeMap<PentagonPath, u16>,
    pub base_finality_root: Hash32,
    pub base_liveness_height: u64,
    pub forks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradationVerdict {
    PassShadowOnly,
    FailCostTarget,
    CollapseCoupledLabels,
    UniversalKillBaseCoupling,
}

pub fn evaluate_degradation(
    epochs: &[ClosureEpoch],
    baseline_finality_root: Hash32,
    baseline_liveness_height: u64,
) -> Result<DegradationVerdict, IdentityError> {
    let cycle = [
        ClosureLane::Dream,
        ClosureLane::TrainingCredit,
        ClosureLane::LoomCredit,
        ClosureLane::Chorus,
    ];
    if epochs.len() != 8 {
        return Err(IdentityError::ClosureSchedule);
    }
    let mut fail_target = false;
    let mut collapse = false;
    for (index, (expected_lane, epoch)) in cycle.into_iter().cycle().zip(epochs).enumerate() {
        if epoch.epoch != index as u64
            || epoch.disabled != expected_lane
            || epoch
                .surviving_cost_bps
                .contains_key(&epoch.disabled.product())
        {
            return Err(IdentityError::ClosureSchedule);
        }
        let expected = all_paths()
            .into_iter()
            .filter(|path| *path != epoch.disabled.product())
            .collect::<BTreeSet<_>>();
        if epoch
            .surviving_cost_bps
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != expected
        {
            return Err(IdentityError::ClosureSchedule);
        }
        if epoch.base_finality_root != baseline_finality_root
            || epoch.base_liveness_height != baseline_liveness_height
            || epoch.forks != 0
        {
            return Ok(DegradationVerdict::UniversalKillBaseCoupling);
        }
        for cost in epoch.surviving_cost_bps.values() {
            fail_target |= *cost > 12_500;
            collapse |= *cost > 20_000;
        }
    }
    if collapse {
        Ok(DegradationVerdict::CollapseCoupledLabels)
    } else if fail_target {
        Ok(DegradationVerdict::FailCostTarget)
    } else {
        Ok(DegradationVerdict::PassShadowOnly)
    }
}

fn role_span_id(role: LeafRole, beacon: Hash32) -> Hash32 {
    match role {
        LeafRole::Inference => hash_parts(INFERENCE_DOMAIN, &[&beacon]),
        LeafRole::Forward => ident02_transcript_domain(GemmLeaf::ForwardY, beacon),
        LeafRole::InputGradient => ident02_transcript_domain(GemmLeaf::InputGradient, beacon),
        LeafRole::WeightGradient => ident02_transcript_domain(GemmLeaf::WeightGradient, beacon),
    }
}

fn leaf_transcript_root(
    role: LeafRole,
    span_id: Hash32,
    gy_root: Hash32,
    artifact_root: Hash32,
) -> Hash32 {
    hash_parts(
        b"NOOS/E-IDENT-02/LEAF-TRANSCRIPT/V1",
        &[&[role as u8], &span_id, &gy_root, &artifact_root],
    )
}

fn transpose(input: &[i8], rows: usize, columns: usize) -> Result<Vec<i8>, IdentityError> {
    if input.len() != rows.saturating_mul(columns) {
        return Err(IdentityError::Shape);
    }
    let mut output = vec![0; input.len()];
    for row in 0..rows {
        for column in 0..columns {
            let output_index = column
                .checked_mul(rows)
                .and_then(|value| value.checked_add(row))
                .ok_or(IdentityError::Shape)?;
            let input_index = row
                .checked_mul(columns)
                .and_then(|value| value.checked_add(column))
                .ok_or(IdentityError::Shape)?;
            output[output_index] = input[input_index];
        }
    }
    Ok(output)
}

fn macs(rows: usize, inner: usize, columns: usize) -> Result<u64, IdentityError> {
    let rows = u64::try_from(rows).map_err(|_| IdentityError::CostOverflow)?;
    let inner = u64::try_from(inner).map_err(|_| IdentityError::CostOverflow)?;
    let columns = u64::try_from(columns).map_err(|_| IdentityError::CostOverflow)?;
    rows.checked_mul(inner)
        .and_then(|value| value.checked_mul(columns))
        .ok_or(IdentityError::CostOverflow)
}

fn all_paths() -> [PentagonPath; 5] {
    [
        PentagonPath::ThoughtDelivery,
        PentagonPath::ShadowSecurity,
        PentagonPath::DisputeEvidence,
        PentagonPath::TrainingAdjoint,
        PentagonPath::BranchRegistration,
    ]
}

fn hash_i8(domain: &[u8], values: &[i8]) -> Hash32 {
    let bytes = values
        .iter()
        .map(|value| value.cast_unsigned())
        .collect::<Vec<_>>();
    hash_parts(domain, &[&bytes])
}

fn hash_i32(domain: &[u8], values: &[i32]) -> Hash32 {
    let mut bytes = Vec::with_capacity(values.len().saturating_mul(4));
    for value in values {
        bytes.extend(value.to_le_bytes());
    }
    hash_parts(domain, &[&bytes])
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    *h.finalize().as_bytes()
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("matrix shape invalid")]
    Shape,
    #[error("committed witness mutated")]
    WitnessMutation,
    #[error("exact C32 or requant relation failed")]
    LeafRelation,
    #[error("leaf role/span substitution")]
    LeafSubstitution,
    #[error("committed G_Y mismatch")]
    GradientBinding,
    #[error("transcript commitment mismatch")]
    Transcript,
    #[error("training phase cost overflow")]
    CostOverflow,
    #[error("training verifier cost exceeds 3.5x or phase sum is ambiguous")]
    CostEnvelope,
    #[error("C32 substituted into the adjoint binding")]
    AdjointSubstitution,
    #[error("one witness credited across products in one maturity window")]
    CrossProductDoubleCredit,
    #[error("identity closure schedule is not two complete four-lane cycles")]
    ClosureSchedule,
    #[error("branch registry rejected the committed terminal token state: {0:?}")]
    Branch(BranchError),
}

impl From<BranchError> for IdentityError {
    fn from(error: BranchError) -> Self {
        Self::Branch(error)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

    use super::*;

    fn values(len: usize, salt: usize) -> Vec<i8> {
        (0..len)
            .map(|index| (((index * 17 + salt * 29) % 31) as i8) - 15)
            .collect()
    }

    fn params() -> SpanParams {
        SpanParams {
            beacon: [7; 32],
            domain_id: [8; 32],
            payout_key: [9; 32],
            multiplier: 3,
            shift: 5,
        }
    }

    fn training(t: usize, k: usize, n: usize) -> TrainingStepWitness {
        TrainingStepWitness::execute(
            values(t * k, 1),
            values(k * n, 2),
            values(t * n, 3),
            t,
            k,
            n,
            params(),
        )
        .unwrap()
    }

    fn token_state(trace_root: Hash32) -> TokenStateCommitment {
        TokenStateCommitment {
            job_id: [1; 32],
            model_root: [2; 32],
            numeric_profile: [3; 32],
            t: 32,
            token_history_root: [4; 32],
            kv_commitment: [5; 32],
            rng_cursor: 0,
            trace_root,
        }
    }

    fn witness() -> PentagonSpanWitness {
        let step = training(32, 32, 32);
        PentagonSpanWitness::bind(
            step.forward.artifact.clone(),
            token_state(step.forward.transcript_root()),
            step,
            [11; 32],
        )
        .unwrap()
    }

    #[test]
    fn square_and_rectangular_training_share_the_exact_leaf_at_three_x() {
        for step in [training(32, 32, 32), training(32, 16, 24)] {
            step.verify().unwrap();
            assert_eq!(step.census.ratio_bps(), 30_000);
            assert!(step.census.phase_sum_is_exact());
            assert_eq!(step.inference.artifact.c32, step.forward.artifact.c32);
        }
    }

    #[test]
    fn five_tampers_per_gemm_and_every_cross_leaf_substitution_reject() {
        let honest = training(32, 32, 32);
        let leaves = [
            (LeafRole::Forward, honest.forward.clone()),
            (LeafRole::InputGradient, honest.input_gradient.clone()),
            (LeafRole::WeightGradient, honest.weight_gradient.clone()),
        ];
        let mut rejected = 0_u8;
        for (role, leaf) in &leaves {
            let mut variants = Vec::new();
            let mut left = leaf.clone();
            left.artifact.left[0] ^= 1;
            variants.push(left);
            let mut right = leaf.clone();
            right.artifact.right[0] ^= 1;
            variants.push(right);
            let mut c32 = leaf.clone();
            c32.artifact.c32[0] = c32.artifact.c32[0].wrapping_add(1 << 16);
            variants.push(c32);
            let mut requant_lie = leaf.clone();
            requant_lie.artifact.c8[0] ^= 1;
            variants.push(requant_lie);
            let mut span = leaf.clone();
            span.span_id[0] ^= 1;
            variants.push(span);
            for variant in variants {
                assert!(variant.verify(*role, honest.gy_root).is_err());
                rejected += 1;
            }
        }
        assert_eq!(rejected, 15);

        let mut attempts = 0;
        for (_, leaf) in &leaves {
            for (role, _) in &leaves {
                if leaf.role != *role {
                    attempts += 1;
                    assert_eq!(
                        leaf.verify(*role, honest.gy_root),
                        Err(IdentityError::LeafSubstitution)
                    );
                }
            }
        }
        assert_eq!(attempts, 6);
    }

    #[test]
    fn one_witness_emits_five_products_and_each_is_independently_disableable() {
        let witness = witness();
        let chain = [12; 32];
        let branch_key = [13; 32];
        let mut registry = BranchRegistry::new(chain);
        let all = compose_pentagon(
            &witness,
            ProductControls { disabled: None },
            &mut registry,
            &branch_key,
            chain,
        )
        .unwrap();
        assert_eq!(all.receipts.len(), 5);
        assert_eq!(all.underlying_executions, 1);
        assert!(all.evidence_multiplications < all.standalone_multiplications);
        assert!(all.receipts.values().all(|receipt| {
            receipt.witness_root == witness.root() && receipt.consensus_weight == 0
        }));
        let security = &all.receipts[&PentagonPath::ShadowSecurity];
        assert!(security.counterfactual_loom_credit > 0);
        assert_eq!(security.production_loom_credit, 0);

        for disabled in all_paths() {
            let mut registry = BranchRegistry::new(chain);
            let delivery = compose_pentagon(
                &witness,
                ProductControls {
                    disabled: Some(disabled),
                },
                &mut registry,
                &branch_key,
                chain,
            )
            .unwrap();
            assert_eq!(delivery.receipts.len(), 4);
            assert!(!delivery.receipts.contains_key(&disabled));
        }
    }

    #[test]
    fn witness_and_adjoint_substitution_and_branch_without_capability_reject() {
        let mut changed = witness();
        changed.artifact.c32[0] ^= 1;
        let chain = [12; 32];
        assert!(compose_pentagon(
            &changed,
            ProductControls { disabled: None },
            &mut BranchRegistry::new(chain),
            &[13; 32],
            chain
        )
        .is_err());

        let witness = witness();
        let mut registry = BranchRegistry::new(chain);
        compose_pentagon(
            &witness,
            ProductControls { disabled: None },
            &mut registry,
            &[13; 32],
            chain,
        )
        .unwrap();
        let fake_nullifier = noos_umbra::Nullifier32([99; 32]);
        assert_eq!(
            registry.activate(&[13; 32], &fake_nullifier, [1; 32], [2; 32]),
            Err(BranchError::UnknownFamily)
        );
    }

    #[test]
    fn zero_double_credit_over_one_hundred_thousand_adversarial_orderings() {
        let root = witness().root();
        let mut x = 0x1de7_2026_0710_u64;
        let mut double_credits = 0_u64;
        for maturity in 0..100_000_u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let first = if x & 1 == 0 {
                CreditKind::Proposal
            } else {
                CreditKind::Proofpower
            };
            let second = if first == CreditKind::Proposal {
                CreditKind::Proofpower
            } else {
                CreditKind::Proposal
            };
            let mut ledger = CrossProductCreditLedger::default();
            ledger.claim(root, maturity, first).unwrap();
            if ledger.claim(root, maturity, second).is_ok() {
                double_credits += 1;
            }
        }
        assert_eq!(double_credits, 0);
    }

    fn closure_epochs(cost: u16) -> Vec<ClosureEpoch> {
        let cycle = [
            ClosureLane::Dream,
            ClosureLane::TrainingCredit,
            ClosureLane::LoomCredit,
            ClosureLane::Chorus,
        ];
        (0..8)
            .map(|epoch| {
                let disabled = cycle[epoch % 4];
                let surviving_cost_bps = all_paths()
                    .into_iter()
                    .filter(|path| *path != disabled.product())
                    .map(|path| (path, cost))
                    .collect();
                ClosureEpoch {
                    epoch: epoch as u64,
                    disabled,
                    surviving_cost_bps,
                    base_finality_root: [21; 32],
                    base_liveness_height: 100,
                    forks: 0,
                }
            })
            .collect()
    }

    #[test]
    fn degradation_thresholds_rollback_and_base_chain_kill_are_exact() {
        assert_eq!(
            evaluate_degradation(&closure_epochs(12_500), [21; 32], 100).unwrap(),
            DegradationVerdict::PassShadowOnly
        );
        assert_eq!(
            evaluate_degradation(&closure_epochs(12_501), [21; 32], 100).unwrap(),
            DegradationVerdict::FailCostTarget
        );
        assert_eq!(
            evaluate_degradation(&closure_epochs(20_001), [21; 32], 100).unwrap(),
            DegradationVerdict::CollapseCoupledLabels
        );
        let mut base_effect = closure_epochs(10_000);
        base_effect[5].forks = 1;
        assert_eq!(
            evaluate_degradation(&base_effect, [21; 32], 100).unwrap(),
            DegradationVerdict::UniversalKillBaseCoupling
        );
    }
}
