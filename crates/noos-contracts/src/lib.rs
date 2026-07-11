//! Ordinary Grain contract host. Grain remains pure; this host supplies an
//! explicit immutable context and mediates every object read/write/call.
#![forbid(unsafe_code)]

pub mod agent_object;
pub mod router;

use noos_grain::{encode_noun, eval, GrainTrap, Meter, Noun, GRAIN_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub type ObjectId = Hash32;
pub type StorageKey = Hash32;
pub const STATE_ROOT_DOMAIN: &[u8] = b"NOOS/CONTRACT/STATE/V1";
pub const MIGRATION_DOMAIN: &[u8] = b"NOOS/CONTRACT/MIGRATION/V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Access {
    Read,
    ReadWrite,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReentrancyPolicy {
    Disabled,
    AllowDifferentObject,
    Allowed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradePolicy {
    Immutable,
    DeclaredMigration,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractManifest {
    pub code_hash: Hash32,
    pub abi_root: Hash32,
    pub storage_schema_root: Hash32,
    pub max_resource_vector: [u64; 6],
    pub upgrade_policy: UpgradePolicy,
    pub reentrancy_policy: ReentrancyPolicy,
    pub allowed_call_classes: u32,
    pub compiler_id: Hash32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractContext {
    pub chain_id: Hash32,
    pub genesis_hash: Hash32,
    pub txid: Hash32,
    pub caller: ObjectId,
    pub callee: ObjectId,
    pub block_height: u64,
    pub finalized_prestate_root: Hash32,
    pub call_depth: u16,
}
impl ContractContext {
    pub fn subject(&self, state: Noun, args: Noun) -> Result<Noun, GrainTrap> {
        let identity = Noun::cell(
            Noun::atom_from_le_bytes(&self.chain_id),
            Noun::atom_from_le_bytes(&self.genesis_hash),
        )?;
        let call = Noun::cell(
            Noun::atom_from_le_bytes(&self.caller),
            Noun::atom_from_le_bytes(&self.callee),
        )?;
        let height_depth = Noun::cell(
            Noun::atom_u64(self.block_height),
            Noun::atom_u64(u64::from(self.call_depth)),
        )?;
        let envelope = Noun::cell(
            identity,
            Noun::cell(
                call,
                Noun::cell(
                    height_depth,
                    Noun::atom_from_le_bytes(&self.finalized_prestate_root),
                )?,
            )?,
        )?;
        Noun::cell(envelope, Noun::cell(state, args)?)
    }
}
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("UNDECLARED_READ")]
    UndeclaredRead,
    #[error("UNDECLARED_WRITE")]
    UndeclaredWrite,
    #[error("REENTRANCY_DENIED")]
    ReentrancyDenied,
    #[error("CALL_CLASS_DENIED")]
    CallClassDenied,
    #[error("CALL_DEPTH_EXCEEDED")]
    CallDepth,
    #[error("IMMUTABLE_CODE")]
    Immutable,
    #[error("MIGRATION_FORMULA_MISMATCH")]
    MigrationFormulaMismatch,
    #[error("MIGRATION_STATE_ROOT_MISMATCH")]
    MigrationStateRootMismatch,
    #[error("UNKNOWN_CONTRACT")]
    UnknownContract,
    #[error("GRAIN trap {0}")]
    Grain(GrainTrap),
}
impl From<GrainTrap> for ContractError {
    fn from(v: GrainTrap) -> Self {
        Self::Grain(v)
    }
}

#[derive(Clone, Debug)]
pub struct ContractRecord {
    pub manifest: ContractManifest,
    pub state: Noun,
    pub storage: BTreeMap<StorageKey, Vec<u8>>,
    pub class: u8,
}
#[derive(Default)]
pub struct ContractHost {
    contracts: BTreeMap<ObjectId, ContractRecord>,
    access: BTreeMap<ObjectId, Access>,
    stack: Vec<ObjectId>,
    max_call_depth: u16,
}
impl ContractHost {
    #[must_use]
    pub fn new(access: impl IntoIterator<Item = (ObjectId, Access)>) -> Self {
        Self {
            contracts: BTreeMap::new(),
            access: access.into_iter().collect(),
            stack: Vec::new(),
            max_call_depth: 64,
        }
    }
    pub fn install(&mut self, id: ObjectId, record: ContractRecord) {
        self.contracts.insert(id, record);
    }
    pub fn read(&self, object: ObjectId, key: StorageKey) -> Result<Option<&[u8]>, ContractError> {
        if !self.access.contains_key(&object) {
            return Err(ContractError::UndeclaredRead);
        }
        let c = self
            .contracts
            .get(&object)
            .ok_or(ContractError::UnknownContract)?;
        Ok(c.storage.get(&key).map(Vec::as_slice))
    }
    pub fn write(
        &mut self,
        object: ObjectId,
        key: StorageKey,
        value: Vec<u8>,
    ) -> Result<(), ContractError> {
        if self.access.get(&object) != Some(&Access::ReadWrite) {
            return Err(ContractError::UndeclaredWrite);
        }
        let c = self
            .contracts
            .get_mut(&object)
            .ok_or(ContractError::UnknownContract)?;
        c.storage.insert(key, value);
        Ok(())
    }
    pub fn execute_grain(
        &self,
        id: ObjectId,
        context: &ContractContext,
        formula: &Noun,
        args: Noun,
        step_limit: u64,
        arena_limit: u64,
    ) -> Result<(Noun, u64), ContractError> {
        if context.callee != id {
            return Err(ContractError::UnknownContract);
        }
        let record = self
            .contracts
            .get(&id)
            .ok_or(ContractError::UnknownContract)?;
        let subject = context.subject(record.state.clone(), args)?;
        let mut meter = Meter::new(step_limit, arena_limit);
        let value = eval(GRAIN_VERSION, subject, formula.clone(), &mut meter)?;
        Ok((value, meter.spent()))
    }
    pub fn call<T>(
        &mut self,
        caller: ObjectId,
        callee: ObjectId,
        callee_class: u8,
        f: impl FnOnce(&mut Self) -> Result<T, ContractError>,
    ) -> Result<T, ContractError> {
        let caller_record = self
            .contracts
            .get(&caller)
            .ok_or(ContractError::UnknownContract)?;
        if callee_class >= 32
            || caller_record.manifest.allowed_call_classes & (1u32 << callee_class) == 0
        {
            return Err(ContractError::CallClassDenied);
        }
        if self.stack.len() >= usize::from(self.max_call_depth) {
            return Err(ContractError::CallDepth);
        }
        let reentered = self.stack.contains(&callee);
        match caller_record.manifest.reentrancy_policy {
            ReentrancyPolicy::Disabled if reentered => return Err(ContractError::ReentrancyDenied),
            ReentrancyPolicy::AllowDifferentObject if callee == caller || reentered => {
                return Err(ContractError::ReentrancyDenied)
            }
            _ => {}
        }
        self.stack.push(callee);
        let result = f(self);
        self.stack.pop();
        result
    }
    #[allow(clippy::too_many_arguments)]
    pub fn upgrade(
        &mut self,
        id: ObjectId,
        new_code_hash: Hash32,
        migration_formula: &Noun,
        declared_formula_hash: Hash32,
        declared_new_state_root: Hash32,
        step_limit: u64,
        arena_limit: u64,
    ) -> Result<(), ContractError> {
        let formula_bytes = encode_noun(migration_formula);
        let formula_hash = domain_hash(MIGRATION_DOMAIN, &[&formula_bytes]);
        if formula_hash != declared_formula_hash {
            return Err(ContractError::MigrationFormulaMismatch);
        }
        let record = self
            .contracts
            .get_mut(&id)
            .ok_or(ContractError::UnknownContract)?;
        if record.manifest.upgrade_policy != UpgradePolicy::DeclaredMigration {
            return Err(ContractError::Immutable);
        }
        let mut meter = Meter::new(step_limit, arena_limit);
        let migrated = eval(
            GRAIN_VERSION,
            record.state.clone(),
            migration_formula.clone(),
            &mut meter,
        )?;
        let encoded = encode_noun(&migrated);
        let actual_root = domain_hash(STATE_ROOT_DOMAIN, &[&encoded]);
        if actual_root != declared_new_state_root {
            return Err(ContractError::MigrationStateRootMismatch);
        }
        record.state = migrated;
        record.manifest.code_hash = new_code_hash;
        record.manifest.storage_schema_root = declared_new_state_root;
        Ok(())
    }
    #[must_use]
    pub fn contract(&self, id: ObjectId) -> Option<&ContractRecord> {
        self.contracts.get(&id)
    }
}
#[must_use]
pub fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    fn manifest(policy: UpgradePolicy, re: ReentrancyPolicy) -> ContractManifest {
        ContractManifest {
            code_hash: [1; 32],
            abi_root: [2; 32],
            storage_schema_root: [3; 32],
            max_resource_vector: [100; 6],
            upgrade_policy: policy,
            reentrancy_policy: re,
            allowed_call_classes: 1 << 2,
            compiler_id: [4; 32],
        }
    }
    fn record(policy: UpgradePolicy, re: ReentrancyPolicy) -> ContractRecord {
        ContractRecord {
            manifest: manifest(policy, re),
            state: Noun::atom_u64(7),
            storage: BTreeMap::new(),
            class: 2,
        }
    }
    #[test]
    fn undeclared_reads_and_writes_fail_closed() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Disabled),
        );
        assert_eq!(h.read([1; 32], [2; 32]), Err(ContractError::UndeclaredRead));
        assert_eq!(
            h.write([1; 32], [2; 32], vec![1]),
            Err(ContractError::UndeclaredWrite)
        );
    }
    #[test]
    fn access_flags_are_enforced() {
        let mut h = ContractHost::new([([1; 32], Access::Read)]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Disabled),
        );
        assert_eq!(h.read([1; 32], [2; 32]).unwrap(), None);
        assert_eq!(
            h.write([1; 32], [2; 32], vec![1]),
            Err(ContractError::UndeclaredWrite)
        );
    }
    #[test]
    fn synchronous_call_and_reentrancy_policy() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Disabled),
        );
        h.install(
            [2; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Disabled),
        );
        let out = h.call([1; 32], [2; 32], 2, |h| {
            h.call([1; 32], [2; 32], 2, |_| Ok(9))
        });
        assert_eq!(out, Err(ContractError::ReentrancyDenied));
    }
    #[test]
    fn call_class_is_declared() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Allowed),
        );
        assert_eq!(
            h.call([1; 32], [2; 32], 3, |_| Ok(())),
            Err(ContractError::CallClassDenied)
        );
    }
    #[test]
    fn explicit_context_is_visible_to_grain() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Allowed),
        );
        let context = ContractContext {
            chain_id: [8; 32],
            genesis_hash: [9; 32],
            txid: [10; 32],
            caller: [0; 32],
            callee: [1; 32],
            block_height: 5,
            finalized_prestate_root: [11; 32],
            call_depth: 0,
        };
        let formula = Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1)).unwrap();
        let (v, _) = h
            .execute_grain([1; 32], &context, &formula, Noun::atom_u64(3), 100, 100)
            .unwrap();
        assert!(v.is_cell());
    }
    #[test]
    fn declared_migration_changes_code_and_state_atomically() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::DeclaredMigration, ReentrancyPolicy::Allowed),
        );
        let formula = Noun::cell(Noun::atom_u64(1), Noun::atom_u64(9)).unwrap();
        let fh = domain_hash(MIGRATION_DOMAIN, &[&encode_noun(&formula)]);
        let new_state = Noun::atom_u64(9);
        let root = domain_hash(STATE_ROOT_DOMAIN, &[&encode_noun(&new_state)]);
        h.upgrade([1; 32], [7; 32], &formula, fh, root, 100, 100)
            .unwrap();
        let c = h.contract([1; 32]).unwrap();
        assert_eq!(c.manifest.code_hash, [7; 32]);
        assert!(c.state.structural_eq(&new_state));
    }
    #[test]
    fn wrong_migration_commitment_preserves_old_record() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::DeclaredMigration, ReentrancyPolicy::Allowed),
        );
        let formula = Noun::cell(Noun::atom_u64(1), Noun::atom_u64(9)).unwrap();
        let before = h.contract([1; 32]).unwrap().manifest.clone();
        assert_eq!(
            h.upgrade([1; 32], [7; 32], &formula, [0; 32], [0; 32], 100, 100),
            Err(ContractError::MigrationFormulaMismatch)
        );
        assert_eq!(h.contract([1; 32]).unwrap().manifest, before);
    }
    #[test]
    fn immutable_contract_rejects_upgrade() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Allowed),
        );
        let f = Noun::cell(Noun::atom_u64(1), Noun::atom_u64(9)).unwrap();
        let fh = domain_hash(MIGRATION_DOMAIN, &[&encode_noun(&f)]);
        assert_eq!(
            h.upgrade([1; 32], [2; 32], &f, fh, [0; 32], 100, 100),
            Err(ContractError::Immutable)
        );
    }
    #[test]
    fn meter_exhaustion_traps_exactly_and_charges_spent_equal_to_limit() {
        let mut h = ContractHost::new([]);
        h.install(
            [1; 32],
            record(UpgradePolicy::Immutable, ReentrancyPolicy::Allowed),
        );
        let context = ContractContext {
            chain_id: [8; 32],
            genesis_hash: [9; 32],
            txid: [10; 32],
            caller: [0; 32],
            callee: [1; 32],
            block_height: 5,
            finalized_prestate_root: [11; 32],
            call_depth: 0,
        };
        // `[0 1]` charges COST_SLOT_BASE (2) up front; a 1-step budget
        // exhausts on the FIRST charge with the exact stable trap.
        let formula = Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1)).unwrap();
        let err = h
            .execute_grain([1; 32], &context, &formula, Noun::atom_u64(3), 1, 100)
            .unwrap_err();
        assert_eq!(err, ContractError::Grain(GrainTrap::MeterExhausted));

        // Meter law: exhaustion pins the reported charge to EXACTLY the
        // limit (never less, never more), so a trapped call always bills
        // spent == limit.
        let subject = context
            .subject(Noun::atom_u64(7), Noun::atom_u64(3))
            .unwrap();
        let mut meter = Meter::new(1, 100);
        assert!(matches!(
            eval(GRAIN_VERSION, subject, formula, &mut meter),
            Err(GrainTrap::MeterExhausted)
        ));
        assert_eq!(meter.spent(), 1, "spent == limit on exhaustion");
    }
}
