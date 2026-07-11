//! # noos-ground — Ground v1 tickets and Pulse v1 retarget
//!
//! Implements the Braid's proposal-eligibility layer (plan §6.2; ch01
//! §§4.1–4.3): the Ground challenge/ticket law under the registered
//! `D-GROUND-CHALLENGE` / `D-GROUND-TICKET` domains, exact `G(b)` work
//! accounting, the slot / median-time-past / future-drift timestamp law,
//! duplicate-ticket exclusion behind the [`DuplicateSet`] trait (the DAG
//! layer supplies the actual ancestor scan), and the deterministic Pulse
//! ASERT retarget through the frozen `exp2_q64` version-1 table.
//!
//! Explicit non-goals here: DAG storage, fork choice, the Witness Ring,
//! and block assembly. This crate exposes pure validation primitives that
//! the consensus layer composes.
//!
//! ## Exactness discipline
//!
//! No floats anywhere; all arithmetic is checked or explicitly wrapping
//! with proven bounds; iteration orders are fixed and documented. The
//! Pulse evaluation and rounding-order law is frozen in
//! `protocol/spec/pulse-exp2-v1.md` so the independent Go client can
//! reproduce every target bit-for-bit; conformance vectors live in
//! `protocol/vectors/ground/`.

mod exp2_table;
mod pulse;
mod ticket;
mod u256;

#[cfg(test)]
mod vector_tests;

pub use exp2_table::EXP2_Q64_TABLE_V1;
pub use pulse::{
    pulse_target_v1, PulseAnchor, PulseError, HALF_LIFE_SECONDS, TARGET_SPACING_SECONDS, T_MAX,
    T_MIN,
};
pub use ticket::{
    ground_challenge, ground_digest, ground_work, median_time_past_ms, slot_from_timestamp,
    validate_ticket, ChallengeInputs, DuplicateSet, GroundError, GroundTicketV1, TicketContext,
    DEVNET_MAX_FUTURE_DRIFT_MS, EXTRA_NONCE_BYTES, GROUND_PROFILE_ID_V1, MAX_SLOT_SKIP,
    MEDIAN_TIME_PAST_BLOCKS, PROPOSER_PUBKEY_BYTES, SLOT_MS, TICKET_ENCODED_BYTES,
};
pub use u256::U256;
