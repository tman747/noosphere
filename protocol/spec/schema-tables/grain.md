# Grain schema table (G0 freeze candidate)

Source: `C:/tmp/noosphere/01-architecture.md` §7 (semantic core, metering, traps,
jet registry), `C:/tmp/noosphere/06-weft-language.md` (boundary confirmations),
plan §5 (noos-grain contract). Grain meaning is the 12-opcode interpreter; a jet
may accelerate but never redefine it (ch01 invariant 12).

## Evaluation signature (ch01 §7.1)

`eval(version, subject, formula, meter) -> Result<Noun, GrainTrap>`

A noun is an unsigned atom or an ordered cell `[head tail]`; canonical atoms carry
no leading zero words. No floating point, IO, threads, wall clock, random source,
or host pointers in the semantic core (ch01 §7.2). Host panics are never Grain
semantics (ch01 §7.1).

## Opcode table — codes are source-fixed (ch01 §7.2)

| Code | Name | Meaning |
|---:|---|---|
| 0 | `slot` | Select an axis from the subject |
| 1 | `quote` | Return a literal noun |
| 2 | `apply` | Evaluate a computed subject with a computed formula |
| 3 | `is-cell` | Return `0` for a cell and `1` for an atom |
| 4 | `inc` | Increment an atom; trap on a cell or configured atom bound |
| 5 | `equal` | Structural noun equality |
| 6 | `if` | Evaluate condition, then exactly one branch |
| 7 | `compose` | Evaluate a subject-producing formula, then a formula on it |
| 8 | `push` | Evaluate a value and push it beside the old subject |
| 9 | `arm` | Select a formula from a computed core and invoke it on that core |
| 10 | `edit` | Replace the noun at an axis with a computed value |
| 11 | `hint` | Semantically erasable hint; erasure preserves result, trap, and semantic charge |

**Opcode 12 is invalid in production** (plan §5.2). The lab-only intrinsic opcode 12
(04-addendum-A, E-WEFT-01a) is eliminated by lowering to core Grain (plan §5.6); a
decoder encountering opcode ≥ 12 traps `UNKNOWN_OPCODE` — never interprets.

## GrainTrap numeric codes — PROPOSED-G0

ch01 §7.1 requires traps to be "consensus values with stable codes" but assigns no
numbers. Sequential assignment below is PROPOSED-G0 for review; once frozen, codes
are immutable (u16, declaration order).

| Code | Trap | Trigger source |
|---:|---|---|
| 1 | `INVALID_AXIS` | ch01 §7.1 (invalid axis) |
| 2 | `TYPE_MISMATCH` | ch01 §7.1 (atom/cell type mismatch) |
| 3 | `METER_EXHAUSTED` | ch01 §7.1 (exhausted meter) |
| 4 | `MANDATORY_JET_UNAVAILABLE` | ch01 §7.1; plan §5.9 (frozen trap for mandatory-jet unavailability) |
| 5 | `NOUN_OVERSIZED` | ch01 §7.1 (oversized noun) |
| 6 | `UNKNOWN_OPCODE` | plan §5.3 (unknown opcode/version) |
| 7 | `UNKNOWN_VERSION` | plan §5.3 |
| 8 | `MALFORMED_BYTES` | plan §5.3 (malformed encoding; nonminimal atom) |
| 9 | `ATOM_BOUND` | ch01 §7.2 opcode 4 (configured atom bound on `inc`) |
| 10 | `ARENA_EXHAUSTED` | ch01 §7.3 (arena-bounded memory per transaction) |
| 11 | `FORMULA_OVERSIZED` | ch01 §7.3 (formula size limit) |
| 12 | `SUBJECT_OVERSIZED` | ch01 §7.3 (subject size limit) |

Zero is reserved (never a trap). Codes 13+ require a new grain version.

## Metering and cost table (ch01 §7.3)

- Charge **before** every reduction and allocation; cost defined over semantic
  operations and noun word sizes, never host nanoseconds.
- Jets are charged the registered semantic cost function for their input sizes — a
  faster implementation cannot buy cheaper consensus execution.
- Memory arena-bounded per transaction; persistent object writes charged
  separately (fee dimension R); formula/subject size limits prevent unbounded noun
  construction ahead of metering.
- **Numeric cost-table values: UNRESOLVED_SOURCE.** ch06 §4.1b states its worked
  constants (`c_if + c_cell = 3`, widen 1, mul64 2, add 1, call 2) are
  "illustrative of the mechanism, not quotations from a frozen cost table; the real
  table is a chapter 01 §7.3 artifact and the vector suites pin it." The immutable
  per-opcode/per-word cost table must be authored, reviewed, and frozen with its
  vectors under `protocol/vectors/grain/` before G1 (ODR-GRAIN-001). Search terms
  tried: cost table, per-operation cost, grain-steps, charge constants, word size.
- Arena bound, max noun bytes, max formula bytes, max cell depth:
  UNRESOLVED_SOURCE (ODR-GRAIN-002; see constants-v1.toml [grain]).

## Serialized formula encoding (plan §3.1 codec law applied; layout PROPOSED-G0)

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `grain_version` | u16 (PROPOSED-G0) | unknown version traps before evaluation |
| 1 | `formula_noun` | canonical noun bytes, u32-length-delimited, max = max_formula_bytes (UNRESOLVED_SOURCE) | atom: minimal LE words; cell: tag+head+tail, declaration-order discriminants |

## JetEntry (ch01 §7.4; widths PROPOSED-G0)

Registry key is exactly `(grain_version, formula_hash)` (ch01 §7.4; plan §5.9).
Unknown/revoked/faulting optional jets fall back to Grain at unchanged semantic
charge; mandatory-jet unavailability traps code 4.

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `jet_id` | Hash32 (PROPOSED-G0) | |
| 1 | `grain_version` | u16 (PROPOSED-G0) | |
| 2 | `formula_hash` | Hash32 | content address of accelerated formula |
| 3 | `implementation_hash` | Hash32 | binary identity |
| 4 | `target_triple` | bounded bytes, max 64 (PROPOSED-G0) | |
| 5 | `cost_function_id` | u32 (PROPOSED-G0) | same charge as slow meaning |
| 6 | `equivalence_profile` | Hash32 (PROPOSED-G0) | |
| 7 | `certificate_root` | Hash32 | |
| 8 | `admitted_height` | u64 (PROPOSED-G0) | |
| 9 | `revoked_height` | optional u64 (PROPOSED-G0) | |

Plan §5.9 additionally binds numeric/layout mode and admission/revocation heights;
covered by fields 5–9 plus the equivalence profile.

## Cross-language conformance (plan §5.4)

Canonical outcome bytes compared across Rust `noos-grain` and independent Go
`go/grainref`: `(value-or-trap, charge)` on fixed vectors plus a sharded
deterministic 10^8-program campaign; one mismatch blocks genesis.
