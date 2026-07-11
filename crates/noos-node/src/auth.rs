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
//! * [`DeferredEngine`] — contract execution fails closed with the stable
//!   trap [`TRAP_CONTRACTS_UNWIRED`] until the Grain contract ABI phase
//!   (plan §8.4) binds `noos-grain` here. Deterministic on every node: a
//!   `CallObject` transaction settles as `Failed` with the frozen failure
//!   fee, never as divergent state.

use noos_crypto::{verify_domain, DomainId, PublicKey, Signature};
use noos_lumen::engine::{AuthVerifier, ContractEngine, EngineOutcome, EngineTrap};
use noos_lumen::Hash32;

/// Signature suite id 1: Ed25519 over `D-SIG-TX` (node-v1.md §4.2).
pub const SUITE_ED25519: u16 = 1;

/// Stable trap code: contract execution not yet wired (fails closed).
pub const TRAP_CONTRACTS_UNWIRED: u32 = 0x4E0D_E001;

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

/// Contract engine placeholder: traps deterministically (fail closed).
#[derive(Debug, Default, Clone, Copy)]
pub struct DeferredEngine;

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
            code: TRAP_CONTRACTS_UNWIRED,
        })
    }
}
