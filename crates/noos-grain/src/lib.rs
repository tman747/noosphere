//! Grain v1 — the NOOSPHERE deterministic consensus interpreter.
//!
//! Normative source: `protocol/schemas/grain-v1.md` (frozen semantic + cost
//! spec). This crate is the Rust reference; the independent Go `go/grainref`
//! is authored from the spec and `protocol/vectors/grain/`, never from this
//! source.
//!
//! Law recap:
//! - A noun is an unsigned atom (minimal little-endian bytes) or an ordered
//!   cell `[head tail]`.
//! - `eval(version, subject, formula, meter) -> Result<Noun, GrainTrap>` is
//!   pure and deterministic; the conformance triple is
//!   `(value-or-trap, trap_code, charge)`.
//! - Every malformed input, type violation, or resource exhaustion is a
//!   stable-coded trap (spec §5). Host panics are never Grain semantics.
//! - The meter charges BEFORE every reduction and allocation (spec §§6, 10);
//!   the arena is a cumulative allocation budget in 8-byte words.
//! - Opcode 11 hints are semantically erasable: erasing `[11 h f]` to `f`
//!   preserves the result noun, the trap, and the charge exactly.
//! - Opcode 12 is invalid in production `eval` (`UNKNOWN_OPCODE`). The
//!   lab-only jet surface is `eval_with_jets`: `[12 id f]` consults a
//!   [`JetHook`] which must reproduce the exact observational triple of
//!   `f`, or decline so `f` is interpreted (erasure-preserving, like 11).
//!
//! Decision (spec §15): Grain noun bytes are self-contained; this crate has
//! no dependencies (including `noos-codec`).

#![forbid(unsafe_code)]

use core::fmt;

mod bytes;
mod eval;
mod noun;
pub mod vectors;

pub use bytes::{decode_formula, decode_subject, encode_noun};
pub use eval::{eval, eval_with_jets, JetHook};
pub use noun::Noun;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Frozen v1 constants (spec §2)
// ---------------------------------------------------------------------------

/// The only Grain version this crate implements.
pub const GRAIN_VERSION: u32 = 1;
/// Cost/arena accounting word, in bytes.
pub const WORD_BYTES: usize = 8;
/// Maximum minimal byte length of any atom, decoded or constructed.
pub const MAX_ATOM_BYTES: usize = 65_536;
/// Maximum cell depth of any noun, decoded or constructed.
pub const MAX_CELL_DEPTH: u32 = 1_048_576;
/// Maximum encoded byte length accepted by [`decode_formula`].
pub const MAX_FORMULA_BYTES: usize = 65_536;
/// Maximum encoded byte length accepted by [`decode_subject`].
pub const MAX_SUBJECT_BYTES: usize = 1_048_576;
/// Protocol cap on the arena word limit a transaction may grant (32 MiB).
pub const ARENA_MAX_WORDS_PER_TX: u64 = 4_194_304;

// Frozen v1 cost table (spec §10), grain-steps.
pub const COST_CONS: u64 = 4;
pub const COST_SLOT_BASE: u64 = 2;
pub const COST_SLOT_STEP: u64 = 1;
pub const COST_QUOTE: u64 = 1;
pub const COST_APPLY: u64 = 4;
pub const COST_ISCELL: u64 = 2;
pub const COST_INC_BASE: u64 = 2;
pub const COST_INC_WORD: u64 = 1;
pub const COST_EQUAL_BASE: u64 = 2;
pub const COST_EQUAL_NODE: u64 = 1;
pub const COST_EQUAL_WORD: u64 = 1;
pub const COST_IF: u64 = 3;
pub const COST_COMPOSE: u64 = 3;
pub const COST_PUSH: u64 = 3;
pub const COST_ARM: u64 = 4;
pub const COST_EDIT_BASE: u64 = 4;
pub const COST_EDIT_STEP: u64 = 4;
pub const COST_HINT: u64 = 0;
/// Allocation steps == arena words for a cell.
pub const COST_CELL_ALLOC: u64 = 3;

/// Word size of an atom of minimal byte length `len` (spec §2).
#[inline]
pub fn awords(len: usize) -> u64 {
    (len as u64).div_ceil(8)
}

// ---------------------------------------------------------------------------
// GrainTrap (spec §5) — stable numeric codes, adopted from
// protocol/spec/schema-tables/grain.md (PROPOSED-G0).
// ---------------------------------------------------------------------------

/// Deterministic evaluation trap. Codes are consensus values: u16, immutable
/// for grain version 1; zero is reserved and never a trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum GrainTrap {
    /// Axis 0, or an axis walk descending into an atom / past the tree.
    InvalidAxis = 1,
    /// Formula/argument shape violation, `inc` of a cell, non-loobean `if`.
    TypeMismatch = 2,
    /// A charge exceeded the remaining step budget.
    MeterExhausted = 3,
    /// Reserved; unreachable in v1 (empty mandatory-jet set).
    MandatoryJetUnavailable = 4,
    /// Atom length or cell depth beyond the frozen structural bounds.
    NounOversized = 5,
    /// Formula head atom not in `0..=11` (in production `eval` this also
    /// covers the lab-only 12, which only `eval_with_jets` recognizes).
    UnknownOpcode = 6,
    /// `eval` called with a version other than 1.
    UnknownVersion = 7,
    /// Encoding grammar violation (spec §4.1).
    MalformedBytes = 8,
    /// `inc` result would exceed `MAX_ATOM_BYTES`.
    AtomBound = 9,
    /// An allocation exceeded the remaining arena budget.
    ArenaExhausted = 10,
    /// Encoded formula longer than `MAX_FORMULA_BYTES`.
    FormulaOversized = 11,
    /// Encoded subject longer than `MAX_SUBJECT_BYTES`.
    SubjectOversized = 12,
}

impl GrainTrap {
    /// Stable numeric trap code.
    #[inline]
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Inverse of [`GrainTrap::code`].
    pub fn from_code(code: u16) -> Option<GrainTrap> {
        Some(match code {
            1 => GrainTrap::InvalidAxis,
            2 => GrainTrap::TypeMismatch,
            3 => GrainTrap::MeterExhausted,
            4 => GrainTrap::MandatoryJetUnavailable,
            5 => GrainTrap::NounOversized,
            6 => GrainTrap::UnknownOpcode,
            7 => GrainTrap::UnknownVersion,
            8 => GrainTrap::MalformedBytes,
            9 => GrainTrap::AtomBound,
            10 => GrainTrap::ArenaExhausted,
            11 => GrainTrap::FormulaOversized,
            12 => GrainTrap::SubjectOversized,
            _ => return None,
        })
    }

    /// Stable spec name.
    pub fn name(self) -> &'static str {
        match self {
            GrainTrap::InvalidAxis => "INVALID_AXIS",
            GrainTrap::TypeMismatch => "TYPE_MISMATCH",
            GrainTrap::MeterExhausted => "METER_EXHAUSTED",
            GrainTrap::MandatoryJetUnavailable => "MANDATORY_JET_UNAVAILABLE",
            GrainTrap::NounOversized => "NOUN_OVERSIZED",
            GrainTrap::UnknownOpcode => "UNKNOWN_OPCODE",
            GrainTrap::UnknownVersion => "UNKNOWN_VERSION",
            GrainTrap::MalformedBytes => "MALFORMED_BYTES",
            GrainTrap::AtomBound => "ATOM_BOUND",
            GrainTrap::ArenaExhausted => "ARENA_EXHAUSTED",
            GrainTrap::FormulaOversized => "FORMULA_OVERSIZED",
            GrainTrap::SubjectOversized => "SUBJECT_OVERSIZED",
        }
    }
}

impl fmt::Display for GrainTrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

impl std::error::Error for GrainTrap {}

// ---------------------------------------------------------------------------
// Meter (spec §6)
// ---------------------------------------------------------------------------

/// Step meter plus cumulative arena budget. Charges happen BEFORE the work
/// they price; a failed step charge pins `spent()` to the step limit.
#[derive(Debug, Clone)]
pub struct Meter {
    step_limit: u64,
    steps: u64,
    arena_limit: u64,
    arena: u64,
}

impl Meter {
    /// `arena_limit` is in 8-byte words and is clamped to
    /// [`ARENA_MAX_WORDS_PER_TX`] (the transaction-level cap).
    pub fn new(step_limit: u64, arena_limit: u64) -> Meter {
        Meter {
            step_limit,
            steps: 0,
            arena_limit: arena_limit.min(ARENA_MAX_WORDS_PER_TX),
            arena: 0,
        }
    }

    /// Grain-steps consumed so far; the reported evaluation charge.
    #[inline]
    pub fn spent(&self) -> u64 {
        self.steps
    }

    /// Arena words consumed so far (internal accounting, not part of the
    /// conformance triple).
    #[inline]
    pub fn arena_used(&self) -> u64 {
        self.arena
    }

    /// Charge `c` steps. On exhaustion, `steps` is pinned to the limit so the
    /// reported charge of a `METER_EXHAUSTED` trap is exactly `step_limit`.
    /// Public so a [`JetHook`] can mirror the frozen charge schedule exactly;
    /// never call it outside the interpreter or a certified jet.
    #[inline]
    pub fn charge(&mut self, c: u64) -> Result<(), GrainTrap> {
        match self.steps.checked_add(c) {
            Some(n) if n <= self.step_limit => {
                self.steps = n;
                Ok(())
            }
            _ => {
                self.steps = self.step_limit;
                Err(GrainTrap::MeterExhausted)
            }
        }
    }

    /// Add `w` words to the cumulative arena. Words are never returned.
    /// Public for [`JetHook`] mirrors, like [`Meter::charge`].
    #[inline]
    pub fn arena_add(&mut self, w: u64) -> Result<(), GrainTrap> {
        match self.arena.checked_add(w) {
            Some(n) if n <= self.arena_limit => {
                self.arena = n;
                Ok(())
            }
            _ => Err(GrainTrap::ArenaExhausted),
        }
    }
}
