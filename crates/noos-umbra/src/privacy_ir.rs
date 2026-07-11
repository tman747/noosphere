//! Canonical, trust-explicit privacy IR for `S-PRIVACY-IR`.
//!
//! The IR admits only a lowering whose logical result agrees with a separately implemented
//! reference interpreter and whose trust, leakage, key ownership, recovery path, and
//! non-guarantees are explicit. It is a semantic/admission layer, not an implementation of PSI,
//! PIR, VDAF, MPC, TEE, FHE, or ZK cryptography.

use std::collections::{BTreeMap, BTreeSet};

pub type Hash32 = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Backend {
    Psi,
    Pir,
    Vdaf,
    Mpc,
    Tee,
    Fhe,
    Zk,
}

impl Backend {
    const fn tag(self) -> u8 {
        match self {
            Self::Psi => 0,
            Self::Pir => 1,
            Self::Vdaf => 2,
            Self::Mpc => 3,
            Self::Tee => 4,
            Self::Fhe => 5,
            Self::Zk => 6,
        }
    }

    const fn required_trust(self) -> TrustKind {
        match self {
            Self::Psi => TrustKind::PeerSet,
            Self::Pir => TrustKind::PirServers,
            Self::Vdaf => TrustKind::AggregatorCommittee,
            Self::Mpc => TrustKind::MpcCommittee,
            Self::Tee => TrustKind::TeeVendor,
            Self::Fhe => TrustKind::ParameterSet,
            Self::Zk => TrustKind::ProofSystem,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustKind {
    PeerSet,
    PirServers,
    AggregatorCommittee,
    MpcCommittee,
    TeeVendor,
    ParameterSet,
    ProofSystem,
}

impl TrustKind {
    const fn tag(self) -> u8 {
        match self {
            Self::PeerSet => 0,
            Self::PirServers => 1,
            Self::AggregatorCommittee => 2,
            Self::MpcCommittee => 3,
            Self::TeeVendor => 4,
            Self::ParameterSet => 5,
            Self::ProofSystem => 6,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustRoot {
    pub kind: TrustKind,
    pub name: String,
    pub commitment: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivacyOperation {
    SetIntersection { left: Vec<u64>, right: Vec<u64> },
    PrivateLookup { key: u64, table: BTreeMap<u64, u64> },
    AggregateSum { measurements: Vec<u64> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticValue {
    Set(Vec<u64>),
    OptionalScalar(Option<u64>),
    Scalar(u64),
}

impl PrivacyOperation {
    fn tag(&self) -> u8 {
        match self {
            Self::SetIntersection { .. } => 0,
            Self::PrivateLookup { .. } => 1,
            Self::AggregateSum { .. } => 2,
        }
    }

    fn supports(&self, backend: Backend) -> bool {
        match self {
            Self::SetIntersection { .. } => {
                matches!(
                    backend,
                    Backend::Psi | Backend::Mpc | Backend::Tee | Backend::Zk
                )
            }
            Self::PrivateLookup { .. } => {
                matches!(
                    backend,
                    Backend::Pir | Backend::Mpc | Backend::Tee | Backend::Fhe
                )
            }
            Self::AggregateSum { .. } => matches!(
                backend,
                Backend::Vdaf | Backend::Mpc | Backend::Tee | Backend::Fhe | Backend::Zk
            ),
        }
    }

    fn minimum_leakage_bits(&self) -> Result<u64, PrivacyIrError> {
        match self {
            Self::SetIntersection { left, right } => {
                let unique_left: BTreeSet<u64> = left.iter().copied().collect();
                let unique_right: BTreeSet<u64> = right.iter().copied().collect();
                let count = unique_left.intersection(&unique_right).count();
                u64::try_from(count)
                    .ok()
                    .and_then(|value| value.checked_mul(64))
                    .ok_or(PrivacyIrError::Overflow)
            }
            Self::PrivateLookup { .. } => Ok(65),
            Self::AggregateSum { .. } => Ok(64),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeakageManifest {
    pub composition_scope: Hash32,
    pub disclosed_fields: Vec<String>,
    pub estimated_bits: u64,
    pub budget_bits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyManifest {
    pub holders: Vec<String>,
    pub epoch: u64,
    pub permanent_global_key: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMode {
    FailClosed,
    OwnerAuthorizedDecryptReencrypt,
    TransparentOffchain,
}

impl RecoveryMode {
    const fn tag(self) -> u8 {
        match self {
            Self::FailClosed => 0,
            Self::OwnerAuthorizedDecryptReencrypt => 1,
            Self::TransparentOffchain => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweringManifest {
    pub backend: Backend,
    pub trust_roots: Vec<TrustRoot>,
    pub leakage: LeakageManifest,
    pub keys: KeyManifest,
    pub recovery: RecoveryMode,
    pub non_guarantees: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredOperation {
    pub operation: PrivacyOperation,
    pub manifest: LoweringManifest,
    pub operation_commitment: Hash32,
    pub lowering_commitment: Hash32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivacyIrError {
    UnsupportedLowering,
    HiddenTrust,
    LeakageUnderdeclared,
    LeakageBudgetExceeded,
    MissingKeyOwner,
    PermanentGlobalKey,
    MissingNonGuarantee,
    SemanticMismatch,
    NonCanonical,
    Overflow,
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), PrivacyIrError> {
    let len = u32::try_from(value.len()).map_err(|_| PrivacyIrError::Overflow)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn operation_bytes(operation: &PrivacyOperation) -> Result<Vec<u8>, PrivacyIrError> {
    let mut out = b"NOOS/PRIVACY-IR/OPERATION/V1".to_vec();
    out.push(operation.tag());
    match operation {
        PrivacyOperation::SetIntersection { left, right } => {
            for values in [left, right] {
                let len = u32::try_from(values.len()).map_err(|_| PrivacyIrError::Overflow)?;
                out.extend_from_slice(&len.to_le_bytes());
                for value in values {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        PrivacyOperation::PrivateLookup { key, table } => {
            out.extend_from_slice(&key.to_le_bytes());
            let len = u32::try_from(table.len()).map_err(|_| PrivacyIrError::Overflow)?;
            out.extend_from_slice(&len.to_le_bytes());
            for (table_key, value) in table {
                out.extend_from_slice(&table_key.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        PrivacyOperation::AggregateSum { measurements } => {
            let len = u32::try_from(measurements.len()).map_err(|_| PrivacyIrError::Overflow)?;
            out.extend_from_slice(&len.to_le_bytes());
            for value in measurements {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    Ok(out)
}

fn manifest_bytes(manifest: &LoweringManifest) -> Result<Vec<u8>, PrivacyIrError> {
    let mut out = b"NOOS/PRIVACY-IR/LOWERING-MANIFEST/V1".to_vec();
    out.push(manifest.backend.tag());
    let roots_len =
        u32::try_from(manifest.trust_roots.len()).map_err(|_| PrivacyIrError::Overflow)?;
    out.extend_from_slice(&roots_len.to_le_bytes());
    for root in &manifest.trust_roots {
        out.push(root.kind.tag());
        put_bytes(&mut out, root.name.as_bytes())?;
        out.extend_from_slice(&root.commitment);
    }
    out.extend_from_slice(&manifest.leakage.composition_scope);
    out.extend_from_slice(&manifest.leakage.estimated_bits.to_le_bytes());
    out.extend_from_slice(&manifest.leakage.budget_bits.to_le_bytes());
    for fields in [
        &manifest.leakage.disclosed_fields,
        &manifest.keys.holders,
        &manifest.non_guarantees,
    ] {
        let len = u32::try_from(fields.len()).map_err(|_| PrivacyIrError::Overflow)?;
        out.extend_from_slice(&len.to_le_bytes());
        for field in fields {
            put_bytes(&mut out, field.as_bytes())?;
        }
    }
    out.extend_from_slice(&manifest.keys.epoch.to_le_bytes());
    out.push(u8::from(manifest.keys.permanent_global_key));
    out.push(manifest.recovery.tag());
    Ok(out)
}

/// Reference semantics, independent of any backend lowering.
pub fn interpret(operation: &PrivacyOperation) -> Result<SemanticValue, PrivacyIrError> {
    match operation {
        PrivacyOperation::SetIntersection { left, right } => {
            let right_set: BTreeSet<u64> = right.iter().copied().collect();
            let mut result: Vec<u64> = left
                .iter()
                .copied()
                .filter(|value| right_set.contains(value))
                .collect();
            result.sort_unstable();
            result.dedup();
            Ok(SemanticValue::Set(result))
        }
        PrivacyOperation::PrivateLookup { key, table } => {
            Ok(SemanticValue::OptionalScalar(table.get(key).copied()))
        }
        PrivacyOperation::AggregateSum { measurements } => measurements
            .iter()
            .try_fold(0u64, |sum, value| sum.checked_add(*value))
            .map(SemanticValue::Scalar)
            .ok_or(PrivacyIrError::Overflow),
    }
}

/// A deliberately separate lowered interpreter used to catch incorrect lowering semantics.
pub fn execute_lowered(lowered: &LoweredOperation) -> Result<SemanticValue, PrivacyIrError> {
    verify_integrity(lowered)?;
    match &lowered.operation {
        PrivacyOperation::SetIntersection { left, right } => {
            let left_set: BTreeSet<u64> = left.iter().copied().collect();
            let right_set: BTreeSet<u64> = right.iter().copied().collect();
            Ok(SemanticValue::Set(
                left_set.intersection(&right_set).copied().collect(),
            ))
        }
        PrivacyOperation::PrivateLookup { key, table } => {
            let found = table
                .iter()
                .find_map(|(candidate, value)| (candidate == key).then_some(*value));
            Ok(SemanticValue::OptionalScalar(found))
        }
        PrivacyOperation::AggregateSum { measurements } => {
            let mut sum = 0u64;
            for value in measurements {
                sum = sum.checked_add(*value).ok_or(PrivacyIrError::Overflow)?;
            }
            Ok(SemanticValue::Scalar(sum))
        }
    }
}

fn verify_integrity(lowered: &LoweredOperation) -> Result<(), PrivacyIrError> {
    let operation_commitment = *blake3::hash(&operation_bytes(&lowered.operation)?).as_bytes();
    if operation_commitment != lowered.operation_commitment {
        return Err(PrivacyIrError::NonCanonical);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/PRIVACY-IR/LOWERED-OPERATION/V1");
    hasher.update(&operation_commitment);
    hasher.update(&manifest_bytes(&lowered.manifest)?);
    if *hasher.finalize().as_bytes() != lowered.lowering_commitment {
        return Err(PrivacyIrError::NonCanonical);
    }
    Ok(())
}

pub fn compile(
    mut operation: PrivacyOperation,
    mut manifest: LoweringManifest,
) -> Result<LoweredOperation, PrivacyIrError> {
    match &mut operation {
        PrivacyOperation::SetIntersection { left, right } => {
            left.sort_unstable();
            left.dedup();
            right.sort_unstable();
            right.dedup();
        }
        PrivacyOperation::PrivateLookup { .. } => {}
        PrivacyOperation::AggregateSum { measurements } => measurements.sort_unstable(),
    }
    if !operation.supports(manifest.backend) {
        return Err(PrivacyIrError::UnsupportedLowering);
    }
    manifest.trust_roots.sort();
    manifest.leakage.disclosed_fields.sort();
    manifest.keys.holders.sort();
    manifest.non_guarantees.sort();
    if manifest.trust_roots.is_empty()
        || !manifest
            .trust_roots
            .iter()
            .any(|root| root.kind == manifest.backend.required_trust())
        || manifest
            .trust_roots
            .iter()
            .any(|root| root.name.is_empty() || root.commitment == [0; 32])
    {
        return Err(PrivacyIrError::HiddenTrust);
    }
    if manifest
        .trust_roots
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || manifest
            .leakage
            .disclosed_fields
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || manifest
            .keys
            .holders
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || manifest
            .non_guarantees
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(PrivacyIrError::NonCanonical);
    }
    if manifest.keys.holders.is_empty() || manifest.keys.holders.iter().any(String::is_empty) {
        return Err(PrivacyIrError::MissingKeyOwner);
    }
    if manifest.keys.permanent_global_key {
        return Err(PrivacyIrError::PermanentGlobalKey);
    }
    if manifest.non_guarantees.is_empty() || manifest.non_guarantees.iter().any(String::is_empty) {
        return Err(PrivacyIrError::MissingNonGuarantee);
    }
    if manifest.leakage.estimated_bits < operation.minimum_leakage_bits()? {
        return Err(PrivacyIrError::LeakageUnderdeclared);
    }
    if manifest.leakage.estimated_bits > manifest.leakage.budget_bits {
        return Err(PrivacyIrError::LeakageBudgetExceeded);
    }
    let operation_bytes = operation_bytes(&operation)?;
    let manifest_bytes = manifest_bytes(&manifest)?;
    let operation_commitment = *blake3::hash(&operation_bytes).as_bytes();
    let mut lowering_hasher = blake3::Hasher::new();
    lowering_hasher.update(b"NOOS/PRIVACY-IR/LOWERED-OPERATION/V1");
    lowering_hasher.update(&operation_commitment);
    lowering_hasher.update(&manifest_bytes);
    let lowered = LoweredOperation {
        operation,
        manifest,
        operation_commitment,
        lowering_commitment: *lowering_hasher.finalize().as_bytes(),
    };
    if interpret(&lowered.operation)? != execute_lowered(&lowered)? {
        return Err(PrivacyIrError::SemanticMismatch);
    }
    Ok(lowered)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivacyComposition {
    consumed: BTreeMap<Hash32, (u64, u64)>,
}

impl PrivacyComposition {
    pub fn admit(&mut self, lowering: &LoweredOperation) -> Result<(), PrivacyIrError> {
        verify_integrity(lowering)?;
        let leakage = &lowering.manifest.leakage;
        let (previous, fixed_budget) = self
            .consumed
            .get(&leakage.composition_scope)
            .copied()
            .unwrap_or((0, leakage.budget_bits));
        if fixed_budget != leakage.budget_bits {
            return Err(PrivacyIrError::LeakageBudgetExceeded);
        }
        let next = previous
            .checked_add(leakage.estimated_bits)
            .ok_or(PrivacyIrError::Overflow)?;
        if next > leakage.budget_bits {
            return Err(PrivacyIrError::LeakageBudgetExceeded);
        }
        self.consumed
            .insert(leakage.composition_scope, (next, fixed_budget));
        Ok(())
    }

    #[must_use]
    pub fn consumed_bits(&self, scope: Hash32) -> u64 {
        self.consumed
            .get(&scope)
            .map(|(consumed, _)| *consumed)
            .unwrap_or(0)
    }
}

/// Text intended for UI/RPC presentation. Trust roots and non-guarantees are never omitted.
#[must_use]
pub fn trust_summary(manifest: &LoweringManifest) -> String {
    let roots = manifest
        .trust_roots
        .iter()
        .map(|root| root.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let non_guarantees = manifest.non_guarantees.join(", ");
    format!(
        "backend={:?}; trust_roots=[{}]; leakage={}/{} bits; non_guarantees=[{}]",
        manifest.backend,
        roots,
        manifest.leakage.estimated_bits,
        manifest.leakage.budget_bits,
        non_guarantees
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    fn manifest(backend: Backend, bits: u64, scope: u8) -> LoweringManifest {
        LoweringManifest {
            backend,
            trust_roots: vec![TrustRoot {
                kind: backend.required_trust(),
                name: format!("named-{backend:?}-root"),
                commitment: [backend.tag() + 1; 32],
            }],
            leakage: LeakageManifest {
                composition_scope: [scope; 32],
                disclosed_fields: vec!["declared logical output".into()],
                estimated_bits: bits,
                budget_bits: bits * 2,
            },
            keys: KeyManifest {
                holders: vec!["workload owner".into()],
                epoch: 7,
                permanent_global_key: false,
            },
            recovery: RecoveryMode::FailClosed,
            non_guarantees: vec!["backend security is not proven by the IR".into()],
        }
    }

    fn operation_for(backend: Backend) -> (PrivacyOperation, u64) {
        match backend {
            Backend::Psi => (
                PrivacyOperation::SetIntersection {
                    left: vec![4, 2, 2, 7],
                    right: vec![9, 2, 4],
                },
                128,
            ),
            Backend::Pir => (
                PrivacyOperation::PrivateLookup {
                    key: 7,
                    table: BTreeMap::from([(7, 99), (8, 100)]),
                },
                65,
            ),
            Backend::Vdaf => (
                PrivacyOperation::AggregateSum {
                    measurements: vec![1, 2, 3],
                },
                64,
            ),
            Backend::Mpc | Backend::Tee | Backend::Fhe | Backend::Zk => (
                PrivacyOperation::AggregateSum {
                    measurements: vec![10, 20, 30],
                },
                64,
            ),
        }
    }

    #[test]
    fn every_named_backend_has_dual_semantic_agreement_and_explicit_ui_trust() {
        for backend in [
            Backend::Psi,
            Backend::Pir,
            Backend::Vdaf,
            Backend::Mpc,
            Backend::Tee,
            Backend::Fhe,
            Backend::Zk,
        ] {
            let (operation, bits) = operation_for(backend);
            let lowered = compile(operation, manifest(backend, bits, backend.tag() + 1)).unwrap();
            assert_eq!(interpret(&lowered.operation), execute_lowered(&lowered));
            let summary = trust_summary(&lowered.manifest);
            assert!(summary.contains(&format!("named-{backend:?}-root")));
            assert!(summary.contains("not proven by the IR"));
        }
    }

    #[test]
    fn hidden_tee_or_committee_trust_rejects() {
        for backend in [Backend::Tee, Backend::Mpc, Backend::Vdaf] {
            let (operation, bits) = operation_for(backend);
            let mut hidden = manifest(backend, bits, 1);
            hidden.trust_roots.clear();
            assert_eq!(compile(operation, hidden), Err(PrivacyIrError::HiddenTrust));
        }
    }

    #[test]
    fn composition_leakage_is_accounted_before_admission() {
        let operation = PrivacyOperation::AggregateSum {
            measurements: vec![1, 2],
        };
        let lowered = compile(operation.clone(), manifest(Backend::Vdaf, 64, 9)).unwrap();
        let second = compile(operation, manifest(Backend::Vdaf, 64, 9)).unwrap();
        let mut composition = PrivacyComposition::default();
        composition.admit(&lowered).unwrap();
        composition.admit(&second).unwrap();
        assert_eq!(composition.consumed_bits([9; 32]), 128);
        assert_eq!(
            composition.admit(&second),
            Err(PrivacyIrError::LeakageBudgetExceeded)
        );
        let mut expanded_manifest = manifest(Backend::Vdaf, 64, 9);
        expanded_manifest.leakage.budget_bits = 1_000;
        let expanded_budget = compile(
            PrivacyOperation::AggregateSum {
                measurements: vec![1, 2],
            },
            expanded_manifest,
        )
        .unwrap();
        assert_eq!(
            composition.admit(&expanded_budget),
            Err(PrivacyIrError::LeakageBudgetExceeded)
        );
    }

    #[test]
    fn underdeclared_leakage_global_key_and_backend_downgrade_reject() {
        let operation = PrivacyOperation::PrivateLookup {
            key: 1,
            table: BTreeMap::from([(1, 2)]),
        };
        let mut under = manifest(Backend::Pir, 64, 1);
        under.leakage.budget_bits = 128;
        assert_eq!(
            compile(operation.clone(), under),
            Err(PrivacyIrError::LeakageUnderdeclared)
        );
        let mut global = manifest(Backend::Pir, 65, 1);
        global.keys.permanent_global_key = true;
        assert_eq!(
            compile(operation.clone(), global),
            Err(PrivacyIrError::PermanentGlobalKey)
        );
        let mut duplicate_root = manifest(Backend::Pir, 65, 1);
        duplicate_root
            .trust_roots
            .push(duplicate_root.trust_roots[0].clone());
        assert_eq!(
            compile(operation.clone(), duplicate_root),
            Err(PrivacyIrError::NonCanonical)
        );
        assert_eq!(
            compile(operation, manifest(Backend::Psi, 65, 1)),
            Err(PrivacyIrError::UnsupportedLowering)
        );
    }

    #[test]
    fn operation_and_lowering_domains_prevent_shape_or_backend_ambiguity() {
        let lookup = PrivacyOperation::PrivateLookup {
            key: 1,
            table: BTreeMap::from([(1, 2)]),
        };
        let aggregate = PrivacyOperation::AggregateSum {
            measurements: vec![1, 2],
        };
        let pir = compile(lookup, manifest(Backend::Pir, 65, 2)).unwrap();
        let vdaf = compile(aggregate, manifest(Backend::Vdaf, 64, 3)).unwrap();
        assert_ne!(pir.operation_commitment, vdaf.operation_commitment);
        assert_ne!(pir.lowering_commitment, vdaf.lowering_commitment);
    }

    #[test]
    fn set_and_aggregate_semantics_have_canonical_ordering() {
        let set_a = PrivacyOperation::SetIntersection {
            left: vec![3, 1, 3, 2],
            right: vec![2, 3, 1],
        };
        let set_b = PrivacyOperation::SetIntersection {
            left: vec![1, 2, 3],
            right: vec![1, 2, 3],
        };
        let a = compile(set_a, manifest(Backend::Psi, 192, 7)).unwrap();
        let b = compile(set_b, manifest(Backend::Psi, 192, 7)).unwrap();
        assert_eq!(a.operation_commitment, b.operation_commitment);

        let sum_a = compile(
            PrivacyOperation::AggregateSum {
                measurements: vec![3, 1, 2],
            },
            manifest(Backend::Vdaf, 64, 8),
        )
        .unwrap();
        let sum_b = compile(
            PrivacyOperation::AggregateSum {
                measurements: vec![1, 2, 3],
            },
            manifest(Backend::Vdaf, 64, 8),
        )
        .unwrap();
        assert_eq!(sum_a.operation_commitment, sum_b.operation_commitment);
    }
}
