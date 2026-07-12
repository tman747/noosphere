//! # noos-braid — Braid header DAG, fork choice, and checkpoints
//!
//! Implements plan §6.1 and §6.3-6.4 (ch01 §4.1, §4.5, §9):
//!
//! * [`BlockHeaderV1`] / [`BlockBodyV1`] — the frozen 30-field header and
//!   7-field body of `protocol/spec/schema-tables/header-body.md`, including
//!   the mandatory receipt split (`execution_receipt_root` tag 9 vs
//!   `lumen_receipts_state_root` tag 16 — omission or reorder is a
//!   decode-level rejection) and hard-zero Loom credit fields while
//!   `work_loom_credit_enabled = false`;
//! * block hash under `D-BLOCK-HEADER` and `proposal_commitment` under
//!   `D-PROPOSAL-COMMITMENT` per the ch01 §4.2 inclusion/exclusion law;
//! * [`HeaderDag`] — deterministic in-memory header store: parent/children
//!   links, height/slot indices, ancestor iteration, bounded orphan pool,
//!   the ch01 §4.2 rule-8 duplicate-ticket window (a
//!   [`noos_ground::DuplicateSet`] over post-finalized ancestors), and the
//!   local justified/finalized checkpoint pair;
//! * [`ForkScore`] — exact lexicographic fork choice
//!   `(finalized, justified, cumulative normalized G+L, inverse hash)` with
//!   saturating [`noos_ground::U256`] work accumulation; finalized
//!   checkpoints are never reverted by work;
//! * [`ReorgPlan`] — deterministic below-finality rollback/replay emission.
//!
//! Explicit non-goals (next crates): Witness Ring votes, membership,
//! slashing, and the beacon; storage; networking; block production.
//!
//! Conformance vectors live in `protocol/vectors/braid/`; the shared
//! generator is [`vector_gen`] (emitted by `bin/gen_vectors.rs`, re-verified
//! by the crate tests, so vectors can never drift from the implementation).

#![forbid(unsafe_code)]

mod body;
mod dag;
mod fork;
mod header;
mod keyless;

#[doc(hidden)]
pub mod vector_gen;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod vector_tests;

pub use body::{
    BlobDescriptorV1, BlockBodyV1, FinalityCertificateV1, GroundTicketWire,
    MAX_CONSENSUS_BLOB_DESCRIPTORS, MAX_FINALITY_CERTIFICATES, MAX_LOOM_CREDIT_CLAIMS,
    MAX_PARTICIPATION_BITMAP_BYTES, MAX_SEGREGATED_WITNESSES, MAX_SYSTEM_TRANSITIONS,
    MAX_TRANSACTIONS,
};
pub use dag::{
    AncestorIter, AncestorTicketScan, DagError, HeaderDag, InsertOutcome, OrphanHeader, ReorgPlan,
    StoredHeader, TicketTuple, DEFAULT_ORPHAN_CAPACITY,
};
pub use fork::{u256_saturating_add, ForkScore};
pub use header::{
    BlockHeaderV1, Bytes48, Bytes96, CheckpointRef, HeaderError, ResourcePriceVectorV1,
    ResourceVectorV1, EPOCH_LENGTH, TAG_GROUND_TICKET_ROOT, TAG_PROPOSER_SIGNATURE, ZERO_ROOT,
};
pub use keyless::{
    DecryptAuthorization, KeylessConsensus, KeylessError, WorkloadKeyCustody,
    MAX_KEY_COMMITTEE_MEMBERS,
};
