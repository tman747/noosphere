//! # noos-witness — the NOOSPHERE Witness Ring
//!
//! Implements `protocol/schemas/witness-v1.md` §§1–7 (ch01 §§4.6–4.10;
//! plan §§6.5–6.7):
//!
//! * [`bond`] — `WitnessBondV1` (nine frozen fields) and registration
//!   validity: distinct key material, BLS proof of possession under
//!   `D-BLS-POP`, Ed25519 self-signature under `NOOS/SIG/TX/V1` (§1.1);
//! * [`membership`] — the epoch-`e` snapshot from finalized `e-2` state
//!   (candidate list behind [`membership::CandidateSource`]): linear raw
//!   weight, top `N_max = 256` with the `NOOS/WITNESS/TIEBREAK/V1`
//!   epoch-salted tie-break, `N_tail = 32` reserve sampled without
//!   replacement under `NOOS/WITNESS/SAMPLE/V1`, the exact cap-repair loop
//!   (admit reserves → reduce proofpower → one emergency epoch → halt),
//!   the SMT `membership_root`, and declared-cluster telemetry (§2);
//! * [`vote`] — `FinalityVoteV1` and its validity law; signatures under the
//!   registered vote DST over the canonical body, fields 0–5 (§1.2);
//! * [`finality`] — exact `Q = floor(2W/3) + 1` on raw AND effective,
//!   certificate verification that recomputes both sums from the snapshot,
//!   the justified/finalized pointer state machine with the never-revert
//!   law, duplicate-certificate short-circuit on content digest, handover
//!   binding, and typed-fatal history loading (§§3, 6);
//! * [`slashing`] — the three offense classes with exact predicates;
//!   execution recheck behind [`slashing::TransitionRecheck`];
//!   unavailability alone is never slashable; removal at the next epoch
//!   boundary only (§1.4);
//! * [`beacon`] — delay-VRF commit/reveal state machine with the frozen
//!   cutoff, membership-ordered mix with committed-hash substitution, and
//!   persist-before-message via [`beacon::DurabilityBarrier`] (§4);
//! * [`liveness`] — threshold failure leaves the epoch unfinalized; the
//!   deterministic inactivity leak applies to FUTURE epochs only (§5);
//! * [`params`] — ODR-parameterized values with the valueless testnet
//!   fixture (ODR-WITNESS-002/003/005, ODR-ECON-001).
//!
//! Explicit non-goals: networking, storage internals (only the
//! [`beacon::DurabilityBarrier`] trait is defined here; `noos-store`
//! implements persistence and a composition layer adapts it), the node
//! supervisor, and proofpower economics (the code path exists behind the
//! genesis flag with a compile-time zero cap; see [`PROOFPOWER_GENESIS_CAP`]).
//!
//! Wire types owned elsewhere are reused, never re-declared:
//! `FinalityCertificateV1` and `CheckpointRef` come from `noos-braid`; the
//! snapshot tree is the `noos-lumen` SMT.
//!
//! Conformance vectors live in `protocol/vectors/witness/`; the shared
//! generator is [`vector_gen`] (emitted by `bin/gen_vectors.rs`, re-verified
//! byte-identically by the crate tests).

#![forbid(unsafe_code)]

pub mod beacon;
pub mod bond;
pub mod finality;
pub mod liveness;
pub mod membership;
pub mod params;
pub mod slashing;
pub mod vote;

mod error;

#[doc(hidden)]
pub mod vector_gen;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod vector_tests;

pub use error::WitnessError;

/// Active-set size: top `N_max` candidates by raw weight (ch01 §4.6).
pub const N_MAX: usize = 256;
/// Reserve sample size (ch01 §4.6).
pub const N_TAIL: usize = 32;
/// Hard membership ceiling; also bounds the participation bitmap at
/// 128 bytes = 1024 bits (ch01 §4.6/§4.8).
pub const N_HARD: usize = 1024;
/// Emergency continuation budget: the previous epoch set continues for
/// exactly ONE epoch when no valid weight vector exists; a second
/// consecutive failure halts finality (ch01 §4.6).
pub const EMERGENCY_CONTINUATION_EPOCHS: u64 = 1;

/// Beacon commit cutoff, as a slot offset within the 256-slot epoch
/// (witness-v1.md §4.1, PROPOSED-G0, frozen with the witness vectors and
/// `constants-v1.toml [witness] beacon_commit_cutoff_slot_offset`).
///
/// Commits for epoch `e` are accepted while `slot_in_epoch < 192` — three
/// quarters of the epoch — leaving 64 slots for the commit set to finalize
/// before reveals begin.
pub const BEACON_COMMIT_CUTOFF_SLOT_OFFSET: u64 = 192;

/// Genesis proofpower weight cap: exactly zero (precedence.md ruling d/e;
/// plan §6.8). The effective-weight code path exists behind the
/// `witness_proofpower_bonus_enabled` flag, but this cap clamps any bonus
/// to zero, so `effective weight ≡ raw weight` at genesis.
pub const PROOFPOWER_GENESIS_CAP: u128 = 0;

// Compile-time zero-cap assertion (plan §6.8: state-transition checks
// enforce the theoretical caps even while production remains zero).
const _: () = assert!(
    PROOFPOWER_GENESIS_CAP == 0,
    "genesis proofpower cap must be exactly zero"
);
