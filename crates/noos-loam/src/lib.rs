//! Loam local-first memory, consent, retention, and honest repair accounting.
#![forbid(unsafe_code)]
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub mod access;
pub mod twin_profile;
pub use access::*;
pub use twin_profile::*;

pub type Hash32 = [u8; 32];
pub type Height = u64;
pub const NON_REPAIRABLE: &str = "NON_REPAIRABLE";
pub const PLAINTEXT_FORGETTING_NON_CLAIM: &str =
    "Plaintext already disclosed cannot be made forgotten";

#[must_use]
pub fn domain_hash(domain: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Public,
    Personal,
    Confidential,
    Restricted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoragePlane {
    LocalPlaintext,
    LocalEncrypted,
    EncryptedAvailability,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleState {
    Ingested,
    Verified,
    Contested,
    Composted,
    Incorporated,
    Dormant,
    Revoked,
    Repaired,
    Exhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub start_ms: u64,
    pub end_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReference {
    pub source_id: Hash32,
    pub locator_commitment: Hash32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionRule {
    UntilHeight(Height),
    ForBlocks(u64),
    IndefiniteUntilRevoked,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoamCapsule {
    pub capsule_id: Hash32,
    pub owner: Hash32,
    pub content_commitment: Hash32,
    pub encrypted_content: Option<Hash32>,
    pub storage_plane: StoragePlane,
    pub provenance: Vec<SourceReference>,
    pub observed_at: TimeRange,
    pub confidence_statement: String,
    pub sensitivity: Sensitivity,
    pub rights_expression: Hash32,
    pub purpose_limits: BTreeSet<Hash32>,
    pub retention_rule: RetentionRule,
    pub consent_receipt: Option<Hash32>,
    pub lineage_parents: Vec<Hash32>,
    pub index_derivatives: Vec<Hash32>,
    pub state: CapsuleState,
    pub ingested_at: Height,
}
impl LoamCapsule {
    pub fn validate(&self) -> Result<(), LoamError> {
        if self.observed_at.start_ms > self.observed_at.end_ms
            || self.confidence_statement.is_empty()
        {
            return Err(LoamError::InvalidCapsule);
        }
        if self.storage_plane == StoragePlane::EncryptedAvailability
            && self.encrypted_content.is_none()
        {
            return Err(LoamError::PlaintextPublicationForbidden);
        }
        Ok(())
    }
    #[must_use]
    pub fn expires_at(&self) -> Option<Height> {
        match self.retention_rule {
            RetentionRule::UntilHeight(h) => Some(h),
            RetentionRule::ForBlocks(n) => self.ingested_at.checked_add(n),
            RetentionRule::IndefiniteUntilRevoked => None,
        }
    }
    #[must_use]
    pub fn expired(&self, height: Height) -> bool {
        self.expires_at().is_some_and(|h| height >= h)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LumenProjection {
    pub capsule_id: Hash32,
    pub rights_root: Hash32,
    pub provenance_root: Hash32,
    pub repair_debt_refs: Vec<Hash32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Right {
    Read,
    Derive,
    Train,
    Evaluate,
    Disclose,
    Sell,
    Delegate,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightsExpression {
    pub expression_id: Hash32,
    pub grantees: BTreeSet<Hash32>,
    pub rights: BTreeSet<Right>,
    pub purposes: BTreeSet<Hash32>,
    pub jurisdictions: BTreeSet<Hash32>,
    pub expires_at: Option<Height>,
    pub revocation_endpoint: Option<Hash32>,
    pub local_only: bool,
    pub descendants_inherit: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureMode {
    NoExport,
    RawDisclosure,
    PrivateOperator,
    AggregateStatistics,
    PreferencePacket,
    TrajectoryPacket,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    ReadLocal,
    Encrypt,
    Aggregate,
    DifferentialPrivacy,
    PrivateExecute,
    EmitRaw,
    EmitAggregate,
    EmitPacket,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    pub capsule_id: Hash32,
    pub principal: Hash32,
    pub purpose: Hash32,
    pub height: Height,
    pub mode: DisclosureMode,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPlan {
    pub capsule_id: Hash32,
    pub mode: DisclosureMode,
    pub operators: Vec<Operator>,
    pub emitted_rights_root: Hash32,
    pub receipt_id: Hash32,
}

pub struct ConsentCompiler;
impl ConsentCompiler {
    pub fn compile(
        capsule: &LoamCapsule,
        rights: &RightsExpression,
        request: &ConsentRequest,
    ) -> Result<ConsentPlan, LoamError> {
        capsule.validate()?;
        if capsule.capsule_id != request.capsule_id
            || capsule.rights_expression != rights.expression_id
            || !rights.grantees.contains(&request.principal)
            || !rights.purposes.contains(&request.purpose)
            || rights.expires_at.is_some_and(|h| request.height >= h)
            || capsule.expired(request.height)
        {
            return Err(LoamError::ConsentDenied);
        }
        let (required, operators) = match request.mode {
            DisclosureMode::NoExport => (None, vec![Operator::ReadLocal]),
            DisclosureMode::RawDisclosure => (
                Some(Right::Disclose),
                vec![Operator::ReadLocal, Operator::EmitRaw],
            ),
            DisclosureMode::PrivateOperator => (
                Some(Right::Evaluate),
                vec![
                    Operator::ReadLocal,
                    Operator::PrivateExecute,
                    Operator::EmitAggregate,
                ],
            ),
            DisclosureMode::AggregateStatistics => (
                Some(Right::Derive),
                vec![
                    Operator::ReadLocal,
                    Operator::Aggregate,
                    Operator::EmitAggregate,
                ],
            ),
            DisclosureMode::PreferencePacket | DisclosureMode::TrajectoryPacket => (
                Some(Right::Train),
                vec![Operator::ReadLocal, Operator::EmitPacket],
            ),
        };
        if required.is_some_and(|r| !rights.rights.contains(&r))
            || (rights.local_only && request.mode != DisclosureMode::NoExport)
        {
            return Err(LoamError::ConsentDenied);
        }
        let receipt_id = domain_hash(
            "NOOS/LOAM/CONSENT/V1",
            &[
                &capsule.capsule_id,
                &request.principal,
                &request.purpose,
                &[request.mode as u8],
            ],
        );
        Ok(ConsentPlan {
            capsule_id: capsule.capsule_id,
            mode: request.mode,
            operators,
            emitted_rights_root: rights.expression_id,
            receipt_id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    Index,
    Summarize,
    Aggregate,
    LowRankUpdate,
    FullTraining,
    Transcode,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repairability {
    Repairable,
    NonRepairable,
}
impl Transform {
    #[must_use]
    pub fn repairability(self) -> Repairability {
        match self {
            Self::Index | Self::Transcode => Repairability::Repairable,
            Self::Summarize | Self::Aggregate | Self::LowRankUpdate | Self::FullTraining => {
                Repairability::NonRepairable
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepairAction {
    DeleteIndex,
    StopServing,
    Retrain,
    CounterfactualUnlearn,
    Notify,
    Compensate,
    DocumentImpossibility,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairState {
    Open,
    Partial,
    Satisfied,
    Impossible,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairDebt {
    pub debt_id: Hash32,
    pub revoked_root: Hash32,
    pub affected_artifacts: Vec<Hash32>,
    pub required_actions: BTreeSet<RepairAction>,
    pub responsible_principals: BTreeSet<Hash32>,
    pub deadline: Height,
    pub residual_risk: String,
    pub state: RepairState,
    pub repairability_literal: &'static str,
}
impl RepairDebt {
    pub fn validate(&self) -> Result<(), LoamError> {
        if self.required_actions.is_empty()
            || self.responsible_principals.is_empty()
            || self.residual_risk.is_empty()
        {
            return Err(LoamError::InvalidRepairDebt);
        }
        if self.state == RepairState::Impossible
            && (self.repairability_literal != NON_REPAIRABLE
                || !self
                    .required_actions
                    .contains(&RepairAction::DocumentImpossibility))
        {
            return Err(LoamError::NonRepairableLabelRequired);
        }
        Ok(())
    }
    pub fn claim_plaintext_forgotten(&self) -> Result<(), LoamError> {
        Err(LoamError::PlaintextForgettingCannotBeClaimed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoamError {
    DuplicateCapsule,
    UnknownCapsule,
    InvalidCapsule,
    PlaintextPublicationForbidden,
    ConsentDenied,
    InvalidTransition,
    InvalidRepairDebt,
    NonRepairableLabelRequired,
    PlaintextForgettingCannotBeClaimed,
}
#[derive(Debug, Default)]
pub struct LoamStore {
    capsules: BTreeMap<Hash32, LoamCapsule>,
    disposable_indexes: BTreeMap<Hash32, Hash32>,
    debts: BTreeMap<Hash32, RepairDebt>,
    lineage: BTreeMap<Hash32, BTreeSet<Hash32>>,
}
impl LoamStore {
    pub fn ingest(&mut self, capsule: LoamCapsule) -> Result<(), LoamError> {
        capsule.validate()?;
        if self.capsules.contains_key(&capsule.capsule_id) {
            return Err(LoamError::DuplicateCapsule);
        }
        for parent in &capsule.lineage_parents {
            self.lineage
                .entry(*parent)
                .or_default()
                .insert(capsule.capsule_id);
        }
        for idx in &capsule.index_derivatives {
            self.disposable_indexes.insert(*idx, capsule.capsule_id);
        }
        self.capsules.insert(capsule.capsule_id, capsule);
        Ok(())
    }
    pub fn project(&self, id: &Hash32) -> Result<LumenProjection, LoamError> {
        let c = self.capsules.get(id).ok_or(LoamError::UnknownCapsule)?;
        let mut bytes = Vec::new();
        for p in &c.provenance {
            bytes.extend_from_slice(&p.source_id);
            bytes.extend_from_slice(&p.locator_commitment);
        }
        let provenance_root = domain_hash("NOOS/LOAM/PROVENANCE/V1", &[&bytes]);
        let repair_debt_refs = self
            .debts
            .values()
            .filter(|d| d.revoked_root == *id)
            .map(|d| d.debt_id)
            .collect();
        Ok(LumenProjection {
            capsule_id: *id,
            rights_root: c.rights_expression,
            provenance_root,
            repair_debt_refs,
        })
    }
    pub fn expire(&mut self, height: Height) -> Vec<Hash32> {
        let ids: Vec<_> = self
            .capsules
            .iter()
            .filter(|(_, c)| c.expired(height))
            .map(|(id, _)| *id)
            .collect();
        for id in &ids {
            if let Some(c) = self.capsules.get_mut(id) {
                c.state = CapsuleState::Exhausted;
            }
            self.purge_indexes_for(id);
        }
        ids
    }
    pub fn purge_indexes_for(&mut self, id: &Hash32) {
        self.disposable_indexes.retain(|_, owner| owner != id);
    }
    #[must_use]
    pub fn has_index(&self, id: &Hash32) -> bool {
        self.disposable_indexes.contains_key(id)
    }
    #[must_use]
    pub fn repair_frontier(&self, root: &Hash32) -> BTreeSet<Hash32> {
        let mut out = BTreeSet::new();
        let mut queue = VecDeque::from([*root]);
        while let Some(id) = queue.pop_front() {
            if let Some(children) = self.lineage.get(&id) {
                for child in children {
                    if out.insert(*child) {
                        queue.push_back(*child);
                    }
                }
            }
        }
        out
    }
    pub fn add_debt(&mut self, debt: RepairDebt) -> Result<(), LoamError> {
        debt.validate()?;
        if !self.capsules.contains_key(&debt.revoked_root) {
            return Err(LoamError::UnknownCapsule);
        }
        self.debts.insert(debt.debt_id, debt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(n: u8) -> Hash32 {
        [n; 32]
    }
    fn capsule() -> LoamCapsule {
        LoamCapsule {
            capsule_id: h(1),
            owner: h(2),
            content_commitment: h(3),
            encrypted_content: None,
            storage_plane: StoragePlane::LocalPlaintext,
            provenance: vec![SourceReference {
                source_id: h(4),
                locator_commitment: h(5),
            }],
            observed_at: TimeRange {
                start_ms: 1,
                end_ms: 2,
            },
            confidence_statement: "observed".into(),
            sensitivity: Sensitivity::Personal,
            rights_expression: h(6),
            purpose_limits: BTreeSet::from([h(7)]),
            retention_rule: RetentionRule::ForBlocks(10),
            consent_receipt: None,
            lineage_parents: vec![],
            index_derivatives: vec![h(8)],
            state: CapsuleState::Ingested,
            ingested_at: 5,
        }
    }
    fn rights() -> RightsExpression {
        RightsExpression {
            expression_id: h(6),
            grantees: BTreeSet::from([h(9)]),
            rights: BTreeSet::from([Right::Disclose, Right::Derive]),
            purposes: BTreeSet::from([h(7)]),
            jurisdictions: BTreeSet::new(),
            expires_at: Some(20),
            revocation_endpoint: None,
            local_only: false,
            descendants_inherit: true,
        }
    }
    #[test]
    fn content_never_projects() {
        let mut s = LoamStore::default();
        assert!(s.ingest(capsule()).is_ok());
        let Ok(p) = s.project(&h(1)) else {
            panic!("projection must exist");
        };
        assert_eq!(p.rights_root, h(6));
        assert_ne!(p.provenance_root, h(3));
    }
    #[test]
    fn indexes_are_disposable() {
        let mut s = LoamStore::default();
        assert!(s.ingest(capsule()).is_ok());
        assert!(s.has_index(&h(8)));
        s.purge_indexes_for(&h(1));
        assert!(!s.has_index(&h(8)));
    }
    #[test]
    fn expiry_exhausts_and_purges() {
        let mut s = LoamStore::default();
        assert!(s.ingest(capsule()).is_ok());
        assert!(s.expire(14).is_empty());
        assert_eq!(s.expire(15), vec![h(1)]);
        assert!(!s.has_index(&h(8)));
    }
    #[test]
    fn raw_consent_requires_disclose() {
        let plan = ConsentCompiler::compile(
            &capsule(),
            &rights(),
            &ConsentRequest {
                capsule_id: h(1),
                principal: h(9),
                purpose: h(7),
                height: 10,
                mode: DisclosureMode::RawDisclosure,
            },
        );
        assert!(plan.is_ok());
    }
    #[test]
    fn local_only_denies_export() {
        let mut r = rights();
        r.local_only = true;
        assert_eq!(
            ConsentCompiler::compile(
                &capsule(),
                &r,
                &ConsentRequest {
                    capsule_id: h(1),
                    principal: h(9),
                    purpose: h(7),
                    height: 10,
                    mode: DisclosureMode::RawDisclosure
                }
            ),
            Err(LoamError::ConsentDenied)
        );
    }
    #[test]
    fn encrypted_da_requires_ciphertext() {
        let mut c = capsule();
        c.storage_plane = StoragePlane::EncryptedAvailability;
        assert_eq!(c.validate(), Err(LoamError::PlaintextPublicationForbidden));
    }
    #[test]
    fn impossible_repair_requires_literal() {
        let d = RepairDebt {
            debt_id: h(1),
            revoked_root: h(2),
            affected_artifacts: vec![],
            required_actions: BTreeSet::from([RepairAction::DocumentImpossibility]),
            responsible_principals: BTreeSet::from([h(3)]),
            deadline: 5,
            residual_risk: "memorization".into(),
            state: RepairState::Impossible,
            repairability_literal: "repairable",
        };
        assert_eq!(d.validate(), Err(LoamError::NonRepairableLabelRequired));
    }
    #[test]
    fn plaintext_forgetting_never_claimed() {
        let d = RepairDebt {
            debt_id: h(1),
            revoked_root: h(2),
            affected_artifacts: vec![],
            required_actions: BTreeSet::from([RepairAction::DocumentImpossibility]),
            responsible_principals: BTreeSet::from([h(3)]),
            deadline: 5,
            residual_risk: "disclosed".into(),
            state: RepairState::Impossible,
            repairability_literal: NON_REPAIRABLE,
        };
        assert_eq!(
            d.claim_plaintext_forgotten(),
            Err(LoamError::PlaintextForgettingCannotBeClaimed)
        );
    }
}
