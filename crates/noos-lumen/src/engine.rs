//! Execution-boundary traits. Lumen owns the state transition; contract
//! semantics belong to noos-grain (sibling crate), signature/lock/proof
//! cryptography to noos-crypto, and WorkJob escrow to noos-work-loom. Each
//! sits behind a trait so this crate stays storage- and crypto-agnostic.

use crate::objects::TransactionWitnessesV1;
use crate::Hash32;

/// Outcome of one contract call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineOutcome {
    /// New object state root (written atomically on commit).
    pub new_state_root: Hash32,
    /// Semantic Grain steps actually charged (fee dimension G).
    pub grain_steps: u64,
    /// Persistent storage words after the call (fee dimension R input).
    pub storage_words: u64,
}

/// Deterministic trap: stable numeric code, no payload (Grain trap codes are
/// PROPOSED-G0 in schema-tables/grain.md; Lumen treats them as opaque).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineTrap {
    pub code: u32,
}

/// Contract execution boundary (arch §6.4/§6.10). Implemented by the Grain
/// interpreter crate; test stubs live in this crate's tests.
///
/// The engine MUST be a pure function of its arguments: same
/// `(code_hash, object_id, prior_state_root, input, step_limit)` tuple, same
/// outcome. It never sees ambient time, randomness, or undeclared state.
pub trait ContractEngine {
    fn execute(
        &self,
        code_hash: &Hash32,
        object_id: &Hash32,
        prior_state_root: &Hash32,
        input: &[u8],
        step_limit: u64,
    ) -> Result<EngineOutcome, EngineTrap>;
}

/// Authorization boundary: signature suites, lock-branch reveals, and proof
/// profiles verify behind this trait until noos-crypto lands (assignment
/// contract). Implementations MUST be deterministic.
pub trait AuthVerifier {
    /// Verify one account-intent signature: `suite` per SignedIntentV1,
    /// `auth_descriptor` from the account record, `message` = txid.
    fn verify_signature(
        &self,
        suite: u16,
        auth_descriptor: &[u8],
        message: &Hash32,
        signature: &[u8],
    ) -> bool;

    /// Verify one revealed lock branch + sibling path against a note's
    /// `lock_root` (balanced lock Merkle tree; wallet-side structure whose
    /// domain row is a wallet-phase freeze).
    fn verify_lock_reveal(&self, lock_root: &Hash32, reveal: &[u8]) -> bool;

    /// Verify an evidence reference's proof profile (arch §6.6 step 4).
    fn verify_evidence_ref(&self, evidence_ref: &Hash32) -> bool;

    /// Optional whole-witness structural hook (e.g. cross-checking signer
    /// scopes). The witness_root itself is checked in-crate under D-TX-WROOT;
    /// default accepts.
    fn verify_witness_extras(&self, _witnesses: &TransactionWitnessesV1) -> bool {
        true
    }
}

/// External WorkJob escrow hook (arch §6.9, plan §4.5): WorkJob value is a
/// requester→provider transfer settled by noos-work-loom, NEVER part of the
/// five-dimensional chain fee. The base v1 action set does not route through
/// this trait; it exists so the Loom crate can attach without Lumen changes.
pub trait WorkJobEscrow {
    /// Reserve escrow for a job. MUST NOT mint; funds come from the payer.
    fn reserve(&mut self, job_id: &Hash32, payer: &Hash32, amount: u128) -> Result<(), EscrowError>;
    /// Settle escrow to providers per the Loom's conserved split.
    fn settle(&mut self, job_id: &Hash32) -> Result<(), EscrowError>;
    /// Refund unspent escrow to the payer.
    fn refund(&mut self, job_id: &Hash32) -> Result<(), EscrowError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    UnknownJob,
    InsufficientFunds,
    AlreadySettled,
}
