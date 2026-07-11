# Grain v1 — frozen semantic and cost specification

Status: **FROZEN-V1 candidate (PROPOSED-G0)** — semantics, byte layout, trap codes,
limits, and the integer cost table below are complete and self-sufficient for an
independent reimplementation. Values invented here (not quoted from a normative
source) are individually marked PROPOSED-G0 and cite the owner decision record.
Once G0 review signs this file, every number in it is immutable for
`grain_version = 1`; any change requires `grain_version = 2` and new vectors.

Sources: `C:/tmp/noosphere/01-architecture.md` §7 (noun model, opcode table,
metering law, trap classes); `C:/tmp/noosphere/06-weft-language.md` §4.1b/§5.1
(cost-table *structure*: per-operation constants over semantic ops and noun word
sizes — its worked constants are explicitly illustrative, so the real table is
frozen HERE, resolving ODR-GRAIN-001); `protocol/spec/schema-tables/grain.md`
(trap-code assignment, adopted verbatim); plan §5.1–§5.4.

Conformance fixtures: `protocol/vectors/grain/*.json` (§14). The Rust reference
is `crates/noos-grain`; the independent Go `go/grainref` MUST be authored from
this document and the vectors alone, never from the Rust source.

---

## 1. Scope and evaluation contract

Grain is the sole consensus execution semantics. Evaluation is a pure, total
(given a finite meter), deterministic function:

```text
eval(version: u32, subject: Noun, formula: Noun, meter: &mut Meter)
    -> Result<Noun, GrainTrap>
```

- `version` MUST equal `1`; any other value traps `UNKNOWN_VERSION` (7) with
  zero charge, before any other observation of the inputs.
- There is no floating point, IO, thread, wall clock, random source, or host
  pointer anywhere in the semantics.
- Host panics and undefined behavior are never Grain semantics: every
  malformed input, resource exhaustion, or type violation is a deterministic
  trap from §5.
- The observable outcome of an evaluation is the triple
  `(value-or-trap, trap_code-if-any, charge)` where `charge = meter.spent()`
  at return. Two implementations conform iff these triples are byte/number
  identical on all inputs.

Jets: **version 1 has an empty mandatory-jet set and no jet dispatch.** Trap
code 4 (`MANDATORY_JET_UNAVAILABLE`) is reserved and unreachable in v1; it is
frozen now so the jet registry (plan §5.9) can use it without a version bump.

## 2. Terms, word size, frozen limits

A **word** is 8 bytes (u64). For an atom `a` with minimal byte length
`len(a)` (§3), its word size is

```text
awords(a) = ceil(len(a) / 8)        -- awords(0) = 0
```

Frozen v1 limits (all PROPOSED-G0, owner record ODR-GRAIN-002; chosen so that
formula ≪ subject ≪ arena, and so every limit is testable within the others):

| Constant | Value | Meaning |
|---|---:|---|
| `GRAIN_VERSION` | 1 | the only version this spec defines |
| `WORD_BYTES` | 8 | cost/arena accounting word |
| `MAX_ATOM_BYTES` | 65_536 | maximum minimal byte length of any atom, decoded or constructed |
| `MAX_CELL_DEPTH` | 1_048_576 | maximum cell depth (§3) of any noun, decoded or constructed |
| `MAX_FORMULA_BYTES` | 65_536 | maximum encoded byte length accepted by `decode_formula` |
| `MAX_SUBJECT_BYTES` | 1_048_576 | maximum encoded byte length accepted by `decode_subject` |
| `ARENA_MAX_WORDS_PER_TX` | 4_194_304 | protocol cap on the arena limit a transaction may grant (32 MiB) |

The **meter step limit** and the **arena word limit** are per-evaluation inputs
(fee-reserved by the transaction; ch01 §6.9 dimension `G`); the arena limit
MUST NOT exceed `ARENA_MAX_WORDS_PER_TX`. The step limit is any u64.

## 3. Noun model

```text
Noun  = Atom | Cell
Atom  = an unsigned integer of arbitrary size (canonical: minimal bytes, §4)
Cell  = [head tail]   -- ordered pair of nouns
```

- **Depth**: `depth(atom) = 0`; `depth([h t]) = 1 + max(depth(h), depth(t))`.
  Every noun in the system — decoded or constructed at runtime — satisfies
  `depth ≤ MAX_CELL_DEPTH`; violation traps `NOUN_OVERSIZED` (5).
- Every atom — decoded or constructed — satisfies `len ≤ MAX_ATOM_BYTES`;
  a *decoded* violation traps `NOUN_OVERSIZED` (5); the only operation that
  *grows* an atom is opcode 4 (`inc`), whose overflow of the bound traps
  `ATOM_BOUND` (9).
- Atoms are unsigned; there is no sign, no width, no float. ch01's canonical
  rule "no leading zero words" is strengthened here to **no leading zero
  byte** (minimal bytes), which implies the word rule.

## 4. Canonical byte encoding

One noun encodes to one byte string. The encoding is self-contained (it does
NOT reuse the general `noos-codec` object framing — decision recorded in §15;
the only shared law is the fixed-width little-endian `u32` length).

Grammar (exact layout, recursive, prefix form):

```text
noun  := atom | cell
atom  := 0x00  len:u32-LE  payload[len]     -- payload is the atom value,
                                            --   little-endian, minimal
cell  := 0x01  noun(head)  noun(tail)
```

- The atom `0` encodes as `00 00000000` (tag, len 0, no payload) — 5 bytes.
- A nonzero atom's payload has `payload[len-1] != 0x00` (minimality).
- A cell is tag `0x01` followed by the complete encoding of the head, then the
  complete encoding of the tail. No length prefix on cells; the grammar is
  self-delimiting.
- A decode of a top-level noun MUST consume the entire input.

Example encodings (hex):

| Noun | Bytes |
|---|---|
| `0` | `0000000000` |
| `1` | `000100000001` |
| `42` | `00010000002a` |
| `256` | `00020000000001` |
| `[0 1]` | `010000000000000100000001` |
| `[1 [2 3]]` | `01000100000001010001000000020001000000 03` (spaces cosmetic) |

### 4.1 Decode procedure and complete rejection law

`decode(bytes, max_bytes, oversize_trap) -> Result<Noun, GrainTrap>` where
`(max_bytes, oversize_trap)` is `(MAX_FORMULA_BYTES, FORMULA_OVERSIZED)` for
formulas and `(MAX_SUBJECT_BYTES, SUBJECT_OVERSIZED)` for subjects.
Decoding is **not metered** (byte fees price input size; ch01 §6.9 dim `B`)
and does not count against the arena; on a decode trap the reported evaluation
charge is `0`.

Ordered checks — the FIRST failing check names the trap:

1. `len(bytes) > max_bytes` → `FORMULA_OVERSIZED` (11) / `SUBJECT_OVERSIZED` (12).
2. Empty input → `MALFORMED_BYTES` (8).
3. Parse one noun in prefix order (iteratively; implementations MUST NOT use
   host recursion proportional to depth):
   - tag byte absent (input exhausted where a noun is required) →
     `MALFORMED_BYTES` (8);
   - tag byte not `0x00`/`0x01` → `MALFORMED_BYTES` (8);
   - atom: 4-byte length absent → `MALFORMED_BYTES` (8);
     `len > MAX_ATOM_BYTES` → `NOUN_OVERSIZED` (5) [checked BEFORE the
     remaining-input check — no allocation may precede either check];
     fewer than `len` payload bytes remain → `MALFORMED_BYTES` (8);
     `len > 0 && payload[len-1] == 0x00` → `MALFORMED_BYTES` (8);
   - cell: when a constructed cell's depth would exceed `MAX_CELL_DEPTH` →
     `NOUN_OVERSIZED` (5).
4. Trailing bytes after the complete top-level noun → `MALFORMED_BYTES` (8).

Encoding never fails; `encode(decode(b)) == b` for every accepted `b`, and
`decode(encode(n)) == n` for every valid noun `n` (within the role's size
limit).

### 4.2 Transaction embedding note (informative)

When a formula travels inside a consensus object it is wrapped by the general
codec as `grain_version:u16` + u32-length-delimited noun bytes
(`protocol/spec/schema-tables/grain.md`). That wrapper is `noos-codec` law,
not Grain law; this spec governs only the noun bytes inside it.

## 5. GrainTrap — stable numeric codes

Adopted verbatim from `protocol/spec/schema-tables/grain.md` (PROPOSED-G0
sequential assignment; u16; zero reserved, never a trap; codes 13+ require a
new grain version):

| Code | Trap | v1 triggers (exhaustive) |
|---:|---|---|
| 1 | `INVALID_AXIS` | axis `0` (ops 0/9/10); axis walk descends into an atom or runs past the tree (ops 0/9/10) |
| 2 | `TYPE_MISMATCH` | formula is an atom; opcode argument has the wrong shape (§8); `inc` of a cell; `if` condition not atom `0`/`1`; axis operand is a cell |
| 3 | `METER_EXHAUSTED` | a charge exceeds the remaining step budget (§6) |
| 4 | `MANDATORY_JET_UNAVAILABLE` | **unreachable in v1** (empty mandatory-jet set; reserved for the jet registry) |
| 5 | `NOUN_OVERSIZED` | decoded atom `len > MAX_ATOM_BYTES`; any noun (decoded or constructed) with `depth > MAX_CELL_DEPTH` |
| 6 | `UNKNOWN_OPCODE` | formula head is an atom that is not `0..=11` (this includes 12: never interpreted in production) |
| 7 | `UNKNOWN_VERSION` | `eval` called with `version != 1` |
| 8 | `MALFORMED_BYTES` | encoding grammar violations of §4.1 (bad tag, truncation, nonminimal atom, trailing bytes, empty input) |
| 9 | `ATOM_BOUND` | `inc` result would exceed `MAX_ATOM_BYTES` |
| 10 | `ARENA_EXHAUSTED` | an allocation exceeds the remaining arena budget (§6) |
| 11 | `FORMULA_OVERSIZED` | encoded formula longer than `MAX_FORMULA_BYTES` |
| 12 | `SUBJECT_OVERSIZED` | encoded subject longer than `MAX_SUBJECT_BYTES` |

A trap aborts the whole evaluation; there is no catch, no partial result.

## 6. Meter and arena

```text
Meter { step_limit: u64, steps: u64, arena_limit: u64 (words), arena: u64 (words) }
```

- **charge(c)** (steps): if `steps + c > step_limit` then set
  `steps = step_limit` and trap `METER_EXHAUSTED` (3); else `steps += c`.
  Consequence: on `METER_EXHAUSTED` the reported charge is exactly
  `step_limit`. All arithmetic is exact unsigned integer arithmetic; `steps +
  c` cannot overflow u64 in any run that respects `ARENA_MAX_WORDS_PER_TX`
  and a real fee budget, but implementations MUST use overflow-checked or
  saturating addition so overflow is impossible rather than undefined.
- **arena_add(w)** (words): if `arena + w > arena_limit` then trap
  `ARENA_EXHAUSTED` (10); else `arena += w`. The arena is a **cumulative
  allocation budget**: words are never returned when nouns die. Structural
  sharing is free — returning an existing subtree allocates nothing.
- **Allocation sequence** (frozen, applies to every runtime allocation):
  1. meter `charge(allocation cost in steps)` — may trap 3;
  2. `arena_add(words)` — may trap 10 (note: the meter charge for a failed
     arena add HAS been spent and appears in the reported charge);
  3. structural bound check — a new cell whose depth would exceed
     `MAX_CELL_DEPTH` traps `NOUN_OVERSIZED` (5); (`inc` performs its
     `ATOM_BOUND` check earlier, §9 op 4);
  4. construct.
- Allocation sizes (semantic, not host):

  | Allocation | steps = words |
  |---|---|
  | cell | 3 |
  | atom of minimal length `n` bytes | `1 + awords` where `awords = ceil(n/8)` |

- The result atoms `0` and `1` produced by opcodes 3 and 5 are canonical
  constants: producing them charges **no** allocation (steps or words).
  Quoted literals (op 1), slot results (op 0/9), and unchanged subtrees are
  shared, never copied: no allocation.
- The reported **charge** of an evaluation is `steps` at return (success or
  trap). The arena count is internal (it shapes only *which* trap fires) and
  is not part of the conformance triple.

## 7. Axis addressing

An axis is a nonzero atom. `bits(axis)` is its bit length (for minimal LE
bytes: `(len-1)*8 + 8 - clz8(payload[len-1])`). Axis semantics:

```text
/1 n         = n
/(2k) [h t]  = /k applied gives ... standard rule below
walk(axis, n):
    axis == 0        -> INVALID_AXIS (checked before any charge)
    for i in bits(axis)-2 down to 0:     -- skip the leading 1 bit
        if n is an atom -> INVALID_AXIS
        n = (bit i of axis == 0) ? head(n) : tail(n)
    return n
```

So axis 1 is the whole noun, axis 2 the head, axis 3 the tail, axis 4 the
head's head, axis 5 the head's tail, etc. Axes are arbitrary-size atoms.

**Slot cost** (used by ops 0 and 9): `COST_SLOT_BASE + (bits(axis) - 1) *
COST_SLOT_STEP`, charged in full BEFORE the walk begins; a walk that traps
`INVALID_AXIS` mid-way has already paid the full slot charge.

## 8. Formula grammar and dispatch

A formula is evaluated against a subject by `Eval(subject, formula)`:

1. If `formula` is an atom → `TYPE_MISMATCH` (2). (No charge.)
2. Let `head = head(formula)`, `arg = tail(formula)`.
3. If `head` is a **cell** → **cons composition** (§9 op-less rule).
4. Else `head` is an atom: if `len(head) > 1` or its value `> 11` →
   `UNKNOWN_OPCODE` (6). (No charge.)
5. **Shape validation** of `arg` per the opcode (table below) — traps
   `TYPE_MISMATCH` (2), or `INVALID_AXIS` (1) for a literal zero axis.
   (No charge.)
6. Charge the opcode's **dispatch cost** (§10).
7. Perform the reduction (§9), which may schedule sub-evaluations and a
   **completion step** with its own frozen charges.

Shape requirements validated at step 5 (before any charge):

| Op | `arg` must be | Extra |
|---:|---|---|
| 0 | atom | nonzero (else `INVALID_AXIS`) |
| 1 | any noun | |
| 2 | cell `[b c]` | |
| 3 | any noun (a formula) | |
| 4 | any noun (a formula) | |
| 5 | cell `[b c]` | |
| 6 | cell `[b [c d]]` (arg.tail must be a cell) | |
| 7 | cell `[b c]` | |
| 8 | cell `[b c]` | |
| 9 | cell `[b c]` | `b` atom, nonzero (else `TYPE_MISMATCH` / `INVALID_AXIS`) |
| 10 | cell `[[b c] d]` (arg.head must be a cell) | `b` atom, nonzero |
| 11 | cell `[h f]` | `h` is the hint noun (any), never evaluated |

The order of trap checks in steps 1–5 is frozen exactly as listed: e.g. a
formula `[12 5]` traps `UNKNOWN_OPCODE`, never `TYPE_MISMATCH`, even though
`5` is not a valid `[b c]` for most opcodes.

## 9. Per-opcode reduction semantics

Notation: `*[s f]` = `Eval(s, f)`; `/[x] n` = axis walk §7; charges named
from §10. Sub-evaluations run the full §8 pipeline recursively (implemented
iteratively). **Order of sub-evaluations is frozen** and observable through
the charge and through which trap fires first.

**Cons composition** — `head(formula)` is a cell:
```text
*[s [fh ft]]  =  [ *[s fh]  *[s ft] ]
```
Charge `COST_CONS` at dispatch. Evaluate `fh` fully, then `ft` fully, then
allocate the pair (allocation sequence §6, cell = 3).

**0 slot** — `*[s [0 axis]] = /[axis] s`.
Charge slot cost (§7) at dispatch; walk; result shared, no allocation.

**1 quote** — `*[s [1 b]] = b`.
Charge `COST_QUOTE`; result is `b` itself (shared), no allocation.

**2 apply** — `*[s [2 b c]] = *[ *[s b]  *[s c] ]`.
Charge `COST_APPLY` at dispatch. Evaluate `b` (new subject), then `c` (new
formula), then evaluate the new formula against the new subject (tail
position). The computed formula is validated by §8 when it is evaluated.

**3 is-cell** — `*[s [3 b]]` = `0` if `*[s b]` is a cell else `1`.
Charge `COST_ISCELL` at dispatch. Evaluate `b`; completion produces the
constant atom (no allocation, §6).

**4 inc** — `*[s [4 b]]` = `*[s b] + 1`.
No dispatch charge. Evaluate `b` → `a`. Completion, in order:
1. if `a` is a cell → `TYPE_MISMATCH` (2);
2. charge `COST_INC_BASE + awords(a) * COST_INC_WORD`;
3. compute the incremented minimal length `rlen` (LE carry; `rlen = len(a)`
   or `len(a)+1`); if `rlen > MAX_ATOM_BYTES` → `ATOM_BOUND` (9);
4. allocation sequence for an atom of `rlen` bytes (charge `1 + awords(r)`,
   arena add, construct).

**5 equal** — `*[s [5 b c]]` = `0` if `*[s b]` and `*[s c]` are structurally
identical, else `1`.
No dispatch charge. Evaluate `b` → `x`, then `c` → `y`. Completion: charge
`COST_EQUAL_BASE`, then run the frozen comparison walk:

```text
stack = [(x, y)]
while stack not empty:
    (p, q) = stack.pop()
    charge COST_EQUAL_NODE                        -- before comparing
    if p is atom and q is atom:
        if len(p) != len(q): return 1             -- no word charge
        charge awords(p) * COST_EQUAL_WORD        -- before the byte compare
        if payload(p) != payload(q): return 1
    else if p is cell and q is cell:
        stack.push((tail(p), tail(q)))
        stack.push((head(p), head(q)))            -- heads compared first
    else:
        return 1
return 0
```

Physical-identity shortcuts are FORBIDDEN from changing the charge: the
charge schedule above is the semantics, and it requires the walk. Result is
the constant atom `0`/`1` (no allocation).

**6 if** — `*[s [6 b c d]]` (formula `[6 [b [c d]]]`):
Charge `COST_IF` at dispatch. Evaluate `b` → `t`. If `t` is the atom `0`,
evaluate `c` (tail position); if the atom `1`, evaluate `d`; anything else
(a cell, or an atom ≥ 2) → `TYPE_MISMATCH` (2). Exactly one branch is ever
evaluated. This is direct semantics, not the Nock macro.

**7 compose** — `*[s [7 b c]] = *[ *[s b]  c ]`.
Charge `COST_COMPOSE` at dispatch. Evaluate `b` → `s2`; evaluate `c` against
`s2` (tail position).

**8 push** — `*[s [8 b c]] = *[ [*[s b] s]  c ]`.
Charge `COST_PUSH` at dispatch. Evaluate `b` → `v`; allocation sequence for
the cell `[v s]` (3 steps / 3 words); evaluate `c` against `[v s]` (tail
position). The new value is the HEAD; the old subject is the TAIL.

**9 arm** — `*[s [9 axis c]] = *[ core  /[axis] core ]` where
`core = *[s c]`.
Charge `COST_ARM` at dispatch. Evaluate `c` → `core`. Completion: charge the
slot cost for `axis` (§7), walk `core` (may trap `INVALID_AXIS`), obtaining
the arm formula `f`; evaluate `f` against `core` (tail position; if `f` is
an atom the inner §8 step 1 traps `TYPE_MISMATCH`).

**10 edit** — `*[s [10 [axis c] d]] = #[axis, *[s c], *[s d]]`:
replace the subtree of `t = *[s d]` at `axis` with `v = *[s c]`.
No dispatch charge (beyond shape validation). Evaluate `c` → `v`, then `d`
→ `t`. Completion, in order, with `L = bits(axis) - 1` (path length):
1. charge `COST_EDIT_BASE + L * COST_EDIT_STEP`;
2. walk `t` along the axis path (§7 bit rule); descending into an atom or
   exhausting the tree → `INVALID_AXIS` (1);
3. `arena_add(3 * L)` — may trap `ARENA_EXHAUSTED` (10);
4. rebuild the spine bottom-up: `L` new cells, each reusing the untouched
   sibling; each new cell's depth is checked (`NOUN_OVERSIZED` (5) if it
   would exceed `MAX_CELL_DEPTH`). `#[1, v, t] = v` (L = 0: no walk, no
   allocation).

(The `COST_EDIT_STEP` of 4 per level already contains the 3 allocation steps
for that level's cell plus 1 walk step; step 3 adds only the arena words —
edit is the one operation whose allocation steps are pre-charged in bulk.)

**11 hint** — `*[s [11 h f]] = *[s f]`.
Charge `COST_HINT` = **0**. The hint noun `h` is NEVER evaluated, never
charged, and has no effect on the result. **Erasability law (frozen)**:
rewriting a formula by replacing `[11 h f]` with `f` in any **formula
position** — the whole formula, both sides of a cons, the sub-formulas of
ops 2/3/4/5/6/7/8, the `c` of ops 9/10, the `f` of op 11, recursively —
preserves the result noun, the trap code (if any), and the semantic charge,
exactly. (Positions the evaluator treats as data — quoted literals under
op 1, axis atoms, hint nouns — are NOT formula positions; a rewrite there
is a different program.) This is why `COST_HINT` must be 0 and why `h`
must never be evaluated; a hint requesting a jet, trace, or provenance tag
is metadata for implementations, invisible to consensus semantics.

**Tail positions**: the final sub-evaluation of ops 2, 6, 7, 8, 9, 11 and of
cons is NOT wrapped in any additional charge or continuation beyond what is
listed. Implementations MUST NOT consume host call-stack proportional to
evaluation depth (use an explicit work stack); logical recursion is bounded
only by the meter.

## 10. Frozen v1 cost table

All values are integers in **grain-steps**, frozen for `grain_version = 1`
(PROPOSED-G0, ODR-GRAIN-001 resolved here). Structure per ch01 §7.3: costs
are over semantic operations and noun word sizes, never host time. ch06
§4.1b's worked constants were illustrative; this table supersedes them.

| Constant | Steps | Charged |
|---|---:|---|
| `COST_CONS` | 4 | dispatch |
| `COST_SLOT_BASE` | 2 | op 0: dispatch; op 9: completion |
| `COST_SLOT_STEP` (per axis bit after the leader) | 1 | with the base |
| `COST_QUOTE` | 1 | dispatch |
| `COST_APPLY` | 4 | dispatch |
| `COST_ISCELL` | 2 | dispatch |
| `COST_INC_BASE` | 2 | completion |
| `COST_INC_WORD` (per operand word) | 1 | completion |
| `COST_EQUAL_BASE` | 2 | completion |
| `COST_EQUAL_NODE` (per node pair visited) | 1 | during walk |
| `COST_EQUAL_WORD` (per word of an equal-length atom pair) | 1 | during walk |
| `COST_IF` | 3 | dispatch |
| `COST_COMPOSE` | 3 | dispatch |
| `COST_PUSH` | 3 | dispatch |
| `COST_ARM` | 4 | dispatch |
| `COST_EDIT_BASE` | 4 | completion |
| `COST_EDIT_STEP` (per path level; includes that level's 3 allocation steps + 1 walk step) | 4 | completion |
| `COST_HINT` | 0 | — (erasability law) |
| cell allocation | 3 | allocation sequence §6 |
| atom allocation (minimal length `n`) | `1 + ceil(n/8)` | allocation sequence §6 |

Arena words equal the allocation steps for the same allocation (cell 3,
atom `1 + awords`), except edit, where the completion charge pre-pays the
steps and step 3 of op 10 adds `3 * L` words.

## 11. Worked examples (normative cross-checks)

Each row is reproduced in `protocol/vectors/grain/grain-eval-v1.json`.
`s` = subject, `f` = formula; charges derived ONLY from §§6–10.

| # | s | f | Result | Charge derivation | Charge |
|---:|---|---|---|---|---:|
| 1 | `0` | `[1 42]` | `42` | quote 1 | 1 |
| 2 | `[7 8]` | `[0 2]` | `7` | slot: 2 + (bits(2)−1)=1 | 3 |
| 3 | `[7 8]` | `[3 [0 1]]` | `0` | is-cell 2 + slot(1): 2 | 4 |
| 4 | `0` | `[4 [1 41]]` | `42` | quote 1; inc 2+1; alloc 1+1 | 6 |
| 5 | `0` | `[[1 1] [1 2]]` | `[1 2]` | cons 4 + quote 1 + quote 1 + cell 3 | 9 |
| 6 | `0` | `[5 [1 5] [1 5]]` | `0` | 1+1; equal base 2 + node 1 + word 1 | 6 |
| 7 | `0` | `[6 [1 0] [1 10] [1 20]]` | `10` | if 3 + quote 1 + quote 1 | 5 |
| 8 | `99` | `[7 [1 33] [0 1]]` | `33` | compose 3 + quote 1 + slot(1) 2 | 6 |
| 9 | `99` | `[8 [1 5] [0 2]]` | `5` | push 3 + quote 1 + cell 3 + slot(2) 3 | 10 |
| 10 | `[[1 42] 0]` | `[9 2 [0 1]]` | `42` | arm 4 + slot(1) 2 + slot(2) 3 + quote 1 | 10 |
| 11 | `[7 8]` | `[10 [2 [1 9]] [0 1]]` | `[9 8]` | quote 1 + slot(1) 2 + edit 4+4·1 | 11 |
| 12 | `0` | `[11 [1 1] [1 42]]` | `42` | hint 0 + quote 1 (== erased `[1 42]`) | 1 |
| 13 | `0` | `[2 [0 1] [1 [1 99]]]` | `99` | apply 4 + slot(1) 2 + quote 1 + quote 1 | 8 |

Self-evaluation loop (meter exhaustion): `s = f = [2 [0 1] [0 1]]`. Each
cycle charges apply 4 + slot(1) 2 + slot(1) 2 = 8; with `step_limit = 1000`
the meter exhausts with reported charge exactly 1000.

## 12. Version and opcode-12 law

- `eval(version, …)` with `version != 1` → `UNKNOWN_VERSION` (7), charge 0.
- Opcode 12 (the lab-only intrinsic of 04-addendum-A / E-WEFT-01a) is
  **invalid in production**: a formula head atom `12` (or any atom > 11, or
  any multi-byte atom) traps `UNKNOWN_OPCODE` (6). It is never interpreted,
  never special-cased.
- Codes, costs, limits, and encodings in this file are immutable for
  version 1. A future version is a new frozen document plus new vectors; a
  node that does not know an active version halts rather than guesses
  (ch01 §11).

## 13. Determinism obligations on implementations

1. No host recursion proportional to noun depth or evaluation depth
   (decode, encode, equality, edit, eval, and destruction must all be
   iterative or otherwise depth-safe up to the frozen limits).
2. No hash-seeded or otherwise nondeterministic iteration anywhere.
3. Checked/exact integer arithmetic only; no floats; no wrapping that can
   change an observable value.
4. Every input — arbitrary bytes, arbitrary noun shapes, adversarial
   meter/arena limits — yields `Ok(noun)` or a §5 trap. A panic, abort, or
   host exception on any input is an implementation defect (Severity 1),
   never semantics.
5. Structural sharing is an implementation technique; it MUST NOT change
   the charge schedule (§9 op 5 note) or the arena accounting (§6: only
   fresh allocations count).

## 14. Conformance vectors

Directory: `protocol/vectors/grain/`. All files follow the repository vector
shape `{"schema", "cases":[{"name","kind","bytes",…}]}` with lowercase-hex
byte fields; `kind` is `positive` for a value outcome and `negative` for a
trap outcome. Charges include everything §6 defines; decode traps report
charge 0.

- **`grain-eval-v1.json`** — schema `noos/grain/eval-v1`. Case fields:
  `bytes` (= the formula encoding), `subject` (hex), `formula` (hex, equal
  to `bytes`), `meter_limit` (u64), `arena_limit` (u64 words), optional
  `version` (default 1), `expect`: `{"kind":"value"|"trap",
  "noun": hex|null, "trap_code": int|null, "charge": u64}`.
  Runner obligation, in order: (1) if `version != 1` expect trap 7 before
  decoding; (2) `decode_subject(subject)`; (3) `decode_formula(formula)`
  — a decode trap is the expected outcome with charge 0; (4)
  `eval(version, subject, formula, meter)`; (5) compare
  `(kind, encode(noun)-or-trap_code, meter.spent())` with `expect`.
- **`grain-noun-bytes-v1.json`** — schema `noos/grain/noun-bytes-v1`.
  Decode-only cases: `bytes`, `role` (`"formula"`|`"subject"`), `expect`:
  `{"kind":"noun"|"trap","trap_code":int|null}`. Positive obligation:
  decode succeeds AND `encode(decode(bytes)) == bytes`.
- **`grain-hint-erasure-v1.json`** — schema `noos/grain/hint-erasure-v1`.
  Pair cases: `bytes` (hinted formula), `erased_formula` (hex), `subject`,
  `meter_limit`, `arena_limit`, `expect` as in eval-v1. Runner obligation:
  evaluate BOTH formulas against the same fresh meter parameters; both
  outcomes must equal `expect` exactly (same result-or-trap, same charge).

One divergence between two implementations on any vector — or on any input
of the sharded generated campaign (plan §5.4) — blocks genesis.

## 15. Decisions recorded

1. **Codec dependency**: Grain noun bytes are **self-contained** (this spec
   §4), not built on `noos-codec` `Writer`/`Reader`. Rationale: the noun
   grammar is recursive and self-delimiting, unlike the codec's flat
   versioned-tagged objects; a Go reimplementer needs zero knowledge of the
   general codec; the only shared law (u32-LE length) is restated here.
   `crates/noos-grain` therefore has **no dependencies**.
2. **Trap codes**: schema-tables PROPOSED-G0 assignment 1–12 adopted
   unchanged (§5), including reserving 4 as v1-unreachable.
3. **Hint form**: `[11 h f]` with `h` pure data, never evaluated, cost 0 —
   the only form under which ch01 §7.2's erasability law can hold exactly
   for noun, trap, AND charge (a Nock-style evaluated dynamic clue would
   change the charge and possibly the trap under erasure).
4. **`if` is direct**, not the Nock macro: non-loobean condition traps
   `TYPE_MISMATCH` deterministically.
5. **Equality returns `0` for equal** and `if` takes `0` as the first
   branch (loobean convention, consistent with op 3's source-fixed
   `0 = cell`).
6. **Meter exhaustion pins the charge to the limit** (§6), making trap
   charges deterministic without exposing partial-charge internals.
7. **Cost magnitudes** (§10) are engineering choices frozen as PROPOSED-G0:
   dispatch costs 1–4 grain-steps proportional to reduction complexity;
   data-dependent costs linear in words with coefficient 1; allocation
   steps equal to arena words. Review may rescale them ONLY before G0
   signs; after that, a new grain version.
