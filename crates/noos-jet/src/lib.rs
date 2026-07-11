//! NOOSPHERE jets: certified fast paths for Grain formulas.
//!
//! Claim surface (frozen ch04 §3.3):
//! - **M-JET** — exact observational equality between a bounded Grain
//!   formula and a jet, stated over values, traps, out-of-fuel, and
//!   consensus metering, carried by a versioned [`cert::JetCert`]. Nothing
//!   here declares an uncertified nontrivial binary equivalent.
//! - **A-JET-CERT** — certificates are machine-checked *by re-derivation*:
//!   admission recomputes the semantics hash, the jet id, the certificate
//!   digest, and replays the full differential equivalence corpus. This local
//!   replay is not an independently implemented universal checker;
//!   proof-assistant-grade universal certificates remain external work.
//!
//! Architecture:
//! - [`cert`] — semantics hashes, jet ids, `JetCertV1`, equivalence records;
//! - [`jets`] — the two admitted native jets (bounded-field increment and
//!   tree equality), each mirroring the frozen Grain charge schedule;
//! - [`registry`] — the certified registry implementing
//!   [`noos_grain::JetHook`]; dispatch NEVER fires an uncertified jet and
//!   NEVER fires a certified jet on a formula whose semantics hash differs
//!   from the certified one — it declines, and pure Grain interpretation
//!   remains authoritative (the ch04 rollback);
//! - [`corpus`] — the deterministic differential corpus (seeded, no host
//!   entropy) that certification and admission both replay;
//! - [`rv32`] — the frozen RV32I integer lowering ABI (`rv32-lowering-v1`)
//!   with deterministic codegen, a closed-subset interpreter, and exact
//!   image-id hashing;
//! - [`proof`] — binding of lowered images to proof requests and the
//!   receipt-verification interface for deterministic, non-production
//!   re-execution (NOT succinct and never relabeled as a zk proof);
//! - `risc0` (feature-gated): a real RISC Zero guest, local CPU composite and
//!   succinct-recursive proving, and verification bound to an admitted jet
//!   certificate, chain/domain/profile, RV32 image, and public journal;
//! - [`architecture`]: canonical proof-profile and CPU reference commitment
//!   declarations; no GPU or cross-hardware result is inferred from them;
//! - [`vectors`] — golden fixtures for `protocol/vectors/jet/`, emitted by
//!   the `jet-vec` binary and byte-compared by the tests.

#![forbid(unsafe_code)]

pub mod architecture;
pub mod cert;
pub mod corpus;
pub mod jets;
pub mod proof;
pub mod registry;
pub mod rv32;
pub mod vectors;

#[cfg(feature = "risc0")]
pub mod risc0;

pub use cert::{semantics_hash, EquivalenceRecord, JetCert, JetId, SemanticsHash};
pub use proof::{
    input_commit, prove_local, Journal, LocalExecutionChecker, LocalReceipt, ProofError,
    ProofRequest, ReceiptVerifier,
};
pub use registry::{AdmitError, CertifyError, JetRegistry, NativeJet};
pub use rv32::{execute, lower, LowerError, Rv32Exit, Rv32Image, Rv32Trap};

#[cfg(feature = "risc0")]
pub use risc0::{
    prove_risc0_cpu, prove_risc0_succinct_cpu, risc0_method_id, Risc0Error, Risc0ProofContext,
    Risc0ProofInput, Risc0ProofRequest, Risc0Receipt, Risc0Verifier,
};

#[cfg(test)]
mod tests;
