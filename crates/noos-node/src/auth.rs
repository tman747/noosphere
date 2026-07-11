//! Authorization and execution boundaries the node plugs into Lumen
//! (node-v1.md §4.2).
//!
//! * [`NodeAuthVerifier`] — the deterministic v1 signature law:
//!   `signature_suite = 1` is Ed25519 under the registered `D-SIG-TX`
//!   domain over the 32-byte txid; the account's `auth_descriptor` is the
//!   raw 32-byte Ed25519 public key. Unknown suites, wrong descriptor
//!   widths, and bad signatures all verify FALSE (Lumen turns that into a
//!   typed rejection). Note lock reveals fail closed: the wallet lock-tree
//!   domain row is a wallet-phase freeze (crypto-domains-v1.csv), so v1
//!   consensus cannot verify one and MUST NOT accept one.
//! * [`GrainContractEngine`] — production contract execution through the
//!   deterministic Grain v1 interpreter and ordinary-contract host. Code is
//!   resolved from an immutable registry, inputs and prior state are decoded
//!   into the explicit contract subject, and stable Grain/host traps are
//!   returned without ambient state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use noos_contracts::{
    domain_hash, Access, ContractContext, ContractError, ContractHost, ContractManifest,
    ContractRecord, ReentrancyPolicy, UpgradePolicy, STATE_ROOT_DOMAIN,
};
use noos_crypto::{verify_domain, DomainId, PublicKey, Signature};
use noos_grain::{decode_formula, decode_subject, encode_noun, Noun, ARENA_MAX_WORDS_PER_TX};
use noos_lumen::engine::{AuthVerifier, ContractEngine, EngineOutcome, EngineTrap};
use noos_lumen::Hash32;

/// Signature suite id 1: Ed25519 over `D-SIG-TX` (node-v1.md §4.2).
pub const SUITE_ED25519: u16 = 1;

/// Stable host trap codes outside the frozen Grain `1..=12` range.
pub const TRAP_UNKNOWN_CONTRACT_CODE: u32 = 0x4E0D_E001;
pub const TRAP_CONTRACT_HOST: u32 = 0x4E0D_E002;

/// Deterministic v1 verifier over noos-crypto Ed25519.
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeAuthVerifier;

impl AuthVerifier for NodeAuthVerifier {
    fn verify_signature(
        &self,
        suite: u16,
        auth_descriptor: &[u8],
        message: &Hash32,
        signature: &[u8],
    ) -> bool {
        if suite != SUITE_ED25519 {
            return false;
        }
        let Ok(key_bytes) = <[u8; 32]>::try_from(auth_descriptor) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let key = PublicKey::from_bytes(key_bytes);
        let sig = Signature::from_bytes(sig_bytes);
        verify_domain(DomainId::SigTx, &key, &[message], &sig).is_ok()
    }

    fn verify_lock_reveal(&self, _lock_root: &Hash32, _reveal: &[u8]) -> bool {
        // Wallet lock-tree domain is a wallet-phase freeze: fail closed.
        false
    }

    fn verify_evidence_ref(&self, _evidence_ref: &Hash32) -> bool {
        // Evidence lane unfrozen: fail closed.
        false
    }
}

/// Immutable production adapter from Lumen's pure execution seam to Grain.
///
/// The registry is deliberately part of the engine value rather than a
/// mutable global. Consequently execution remains a pure function of the
/// engine configuration and Lumen's execution tuple, including during
/// mempool simulation and deterministic replay.
#[derive(Debug, Default, Clone)]
pub struct GrainContractEngine {
    chain_id: Hash32,
    genesis_hash: Hash32,
    code: Arc<BTreeMap<Hash32, Vec<u8>>>,
}

impl GrainContractEngine {
    #[must_use]
    pub fn new(chain_id: Hash32, genesis_hash: Hash32, code: BTreeMap<Hash32, Vec<u8>>) -> Self {
        Self {
            chain_id,
            genesis_hash,
            code: Arc::new(code),
        }
    }

    #[must_use]
    pub fn code_hashes(&self) -> BTreeSet<Hash32> {
        self.code.keys().copied().collect()
    }
}

fn host_trap(error: ContractError) -> EngineTrap {
    let code = match error {
        ContractError::Grain(trap) => u32::from(trap.code()),
        ContractError::UnknownContract => TRAP_UNKNOWN_CONTRACT_CODE,
        _ => TRAP_CONTRACT_HOST,
    };
    EngineTrap { code }
}

impl ContractEngine for GrainContractEngine {
    fn execute(
        &self,
        code_hash: &Hash32,
        object_id: &Hash32,
        prior_state_root: &Hash32,
        input: &[u8],
        step_limit: u64,
    ) -> Result<EngineOutcome, EngineTrap> {
        let formula_bytes = self.code.get(code_hash).ok_or(EngineTrap {
            code: TRAP_UNKNOWN_CONTRACT_CODE,
        })?;
        let formula = decode_formula(formula_bytes).map_err(|trap| EngineTrap {
            code: u32::from(trap.code()),
        })?;
        let args = decode_subject(input).map_err(|trap| EngineTrap {
            code: u32::from(trap.code()),
        })?;

        let manifest = ContractManifest {
            code_hash: *code_hash,
            abi_root: [0; 32],
            storage_schema_root: *prior_state_root,
            max_resource_vector: [step_limit, 0, 0, 0, 0, 0],
            upgrade_policy: UpgradePolicy::Immutable,
            reentrancy_policy: ReentrancyPolicy::Disabled,
            allowed_call_classes: 0,
            compiler_id: [0; 32],
        };
        let mut host = ContractHost::new([(*object_id, Access::ReadWrite)]);
        host.install(
            *object_id,
            ContractRecord {
                manifest,
                state: Noun::atom_from_le_bytes(prior_state_root),
                storage: BTreeMap::new(),
                class: 0,
            },
        );
        let context = ContractContext {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            txid: domain_hash(b"NOOS/CONTRACT/INPUT/V1", &[input]),
            caller: [0; 32],
            callee: *object_id,
            block_height: 0,
            finalized_prestate_root: *prior_state_root,
            call_depth: 0,
        };
        let (value, grain_steps) = host
            .execute_grain(
                *object_id,
                &context,
                &formula,
                args,
                step_limit,
                step_limit.min(ARENA_MAX_WORDS_PER_TX),
            )
            .map_err(host_trap)?;
        let encoded = encode_noun(&value);
        let storage_words = u64::try_from(encoded.len()).unwrap_or(u64::MAX).div_ceil(8);
        Ok(EngineOutcome {
            new_state_root: domain_hash(STATE_ROOT_DOMAIN, &[&encoded]),
            grain_steps,
            storage_words,
        })
    }
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct DeferredEngine;

#[cfg(test)]
impl ContractEngine for DeferredEngine {
    fn execute(
        &self,
        _code_hash: &Hash32,
        _object_id: &Hash32,
        _prior_state_root: &Hash32,
        _input: &[u8],
        _step_limit: u64,
    ) -> Result<EngineOutcome, EngineTrap> {
        Err(EngineTrap {
            code: TRAP_UNKNOWN_CONTRACT_CODE,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use noos_grain::GrainTrap;

    #[test]
    fn grain_engine_executes_registered_code_deterministically() {
        let formula = Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1))
            .unwrap_or_else(|_| unreachable!("small noun"));
        let code_hash = [7; 32];
        let engine = GrainContractEngine::new(
            [1; 32],
            [2; 32],
            [(code_hash, encode_noun(&formula))].into_iter().collect(),
        );
        let input = encode_noun(&Noun::atom_u64(9));
        let first = engine
            .execute(&code_hash, &[3; 32], &[4; 32], &input, 10_000)
            .unwrap_or_else(|trap| panic!("unexpected trap {}", trap.code));
        let second = engine
            .execute(&code_hash, &[3; 32], &[4; 32], &input, 10_000)
            .unwrap_or_else(|trap| panic!("unexpected trap {}", trap.code));
        assert_eq!(first, second);
        assert!(first.grain_steps > 0);
        assert!(first.storage_words > 0);
    }

    #[test]
    fn grain_engine_unknown_code_has_stable_trap() {
        let trap = GrainContractEngine::default()
            .execute(&[9; 32], &[3; 32], &[4; 32], &[0], 100)
            .expect_err("unknown code must trap");
        assert_eq!(trap.code, TRAP_UNKNOWN_CONTRACT_CODE);
    }

    #[test]
    fn grain_engine_meter_exhaustion_has_exact_stable_trap() {
        // `[0 1]` charges COST_SLOT_BASE (2) up front; a 1-step budget
        // exhausts on the FIRST charge and surfaces the frozen trap code.
        let formula = Noun::cell(Noun::atom_u64(0), Noun::atom_u64(1))
            .unwrap_or_else(|_| unreachable!("small noun"));
        let code_hash = [7; 32];
        let engine = GrainContractEngine::new(
            [1; 32],
            [2; 32],
            [(code_hash, encode_noun(&formula))].into_iter().collect(),
        );
        let input = encode_noun(&Noun::atom_u64(9));
        let trap = engine
            .execute(&code_hash, &[3; 32], &[4; 32], &input, 1)
            .expect_err("meter must exhaust");
        assert_eq!(trap.code, u32::from(GrainTrap::MeterExhausted.code()));
    }
}
