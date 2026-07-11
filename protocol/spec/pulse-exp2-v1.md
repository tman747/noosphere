# Pulse v1 `exp2_q64` table and exact evaluation law

Status: frozen protocol-package artifact (resolves
`constants-v1.toml [pulse].exp2_q64_table = "UNRESOLVED_SOURCE"`).
Source law: ch01 §4.3 ("Consensus evaluates the exponent in signed Q64.64
fixed point, multiplies through the version-1 `exp2_q64` constant table
committed by `params_root`, and rounds toward negative infinity") plus the
plan §6.2 resolution. Every implementation (Rust `noos-ground`, the
independent Go client, the Python vector oracle) MUST reproduce the
procedure below bit-for-bit; the canonical edge vectors live in
`protocol/vectors/ground/pulse-retarget-v1.json`.

## 1. Interface equation

```text
T_h = clamp(T_min, T_max, floor(T_a * 2^((t - t_a - Δ(h - h_a)) / τ)))
```

* `Δ = 6 s` target spacing, `τ = 3600 s` half-life, `T_min = 1`,
  `T_max = 2^256 - 1` (constants-v1.toml `[pulse]`).
* `t` — the **parent** block's median-time-past, in integer seconds.
* Anchor `(h_a, t_a, T_a)` — height, median-time-past (seconds), and
  Ground target of the most recent **finalized checkpoint** on the branch.
  All three come from that checkpoint's already-validated headers; the
  function has no clock input, so rolling the anchor on finality is
  independent of local arrival time.
* Contract: `h > h_a` and `1 <= T_a <= T_max`; violations are caller
  errors, never consensus verdicts.

`floor(T_a * 2^x)` in the interface equation is *defined* as the exact
procedure of §3 — the per-step floors below are the normative semantics,
not an approximation of real-number arithmetic.

## 2. The table

64 entries, one per fractional exponent bit:

```text
EXP2_Q64_TABLE_V1[k] = floor(2^(2^-(k+1)) * 2^64),   k = 0..63
```

* Entry `k` is the Q64.64 encoding of `2` raised to the weight of
  fractional bit `k` (bit 0 = most significant, weight `2^-1`; bit 63 =
  least significant, weight `2^-64`).
* Every entry is a 65-bit integer in `[2^64, 2^65)`. Entry 0 is
  `floor(sqrt(2) * 2^64) = 0x16a09e667f3bcc908`; entry 63 is exactly
  `2^64` (because `2^64 * (2^(2^-64) - 1) = ln 2 + ε < 1`).
* Checked-in Rust constant: `crates/noos-ground/src/exp2_table.rs`
  (`pub const EXP2_Q64_TABLE_V1: [u128; 64]`).
* Table hash, BLAKE3-256 over the 64 entries concatenated as u128
  little-endian (1024 bytes):

  ```text
  15d783a23bcf9d9e20d1133bbc247a5c94a876705aed5281e73246f67c883999
  ```

### Derivation (exact integer arithmetic, no floats)

Generator: `tools/vector-generators/gen_exp2_table.py`
(`--check` verifies the checked-in file is byte-identical to a fresh
generation).

1. Work at precision `P = 256` fractional bits (192 guard bits).
   `s_1 = isqrt(2^(2P+1))` is exactly `floor(2^(1/2) * 2^P)`
   (`isqrt` = exact floor integer square root).
2. Iterate `s_{j+1} = isqrt(s_j << P)`. Induction: if `s_j` is within `d`
   below the real value `2^(1/2^j) * 2^P`, the square root contracts the
   error to `<= d/2` and the floor adds `< 1`, so every `s_j` lies in
   `(true - 2, true]`.
3. Truncate: `entry_{j-1} = s_j >> (P - 64)`. The generator *proves* each
   truncation unambiguous by asserting
   `(s_j >> (P-64)) == ((s_j + 4) >> (P-64))` — no Q64.64 boundary falls
   inside the error interval. A failure would abort generation (it does
   not occur at `P = 256`).
4. Independent exact cross-check for `j <= 11` (`m = 2^j <= 2048`): the
   definition is equivalent to the integer bracketing
   `c^m <= 2^(64m+1) < (c+1)^m`, verified with exact big-integer powers.
5. Fixed-value checks: `entry_0 == isqrt(2^129)`, `entry_63 == 2^64`,
   all entries in `[2^64, 2^65)` and strictly decreasing.

## 3. Exact evaluation and rounding-order law (normative)

All steps use exact integers. "floor" is rounding toward negative
infinity; for the unsigned intermediates below, truncation and floor
coincide.

1. **Exponent numerator.** `n = t - t_a - 6*(h - h_a)`, exact signed
   integer seconds (fits well inside i128 for all valid u64 inputs).
2. **Q64.64 exponent, rounded toward negative infinity.** Euclidean
   division: `q = n div_euclid 3600`, `r = n rem_euclid 3600` with
   `0 <= r < 3600`; fractional word `f = floor(r * 2^64 / 3600)`
   (`r * 2^64 < 2^76`, exact in u128). The exponent is `q + f * 2^-64`,
   which equals `floor(n * 2^64 / 3600)` in Q64.64 — this is the "signed
   Q64.64, rounded toward negative infinity" step of ch01 §4.3.
3. **Short circuits (exact equivalences, mandatory).**
   * `q >= 256` → return `T_max`. Every table entry is `>= 2^64`, so each
     fractional step is non-decreasing and the fractional product is
     `>= T_a >= 1`; shifting left by `q >= 256` reaches `>= 2^256 > T_max`.
   * `q <= -257` → return `T_min`. Every entry is `< 2^65`, so the
     fractional product is `< 2 * T_a <= 2^257`; shifting right by 257 or
     more yields 0, which clamps to `T_min = 1`.
   These are not approximations; they equal the long computation and keep
   every remaining intermediate inside 512 bits.
4. **Fractional walk, most-significant bit first.** Accumulator
   `acc = T_a` as a 512-bit unsigned integer. For `k = 0, 1, ..., 63` in
   ascending order, if bit `63 - k` of `f` is set:

   ```text
   acc = floor(acc * EXP2_Q64_TABLE_V1[k] / 2^64)
   ```

   one 512x65-bit multiply followed by a 64-bit right shift, flooring at
   **every** step. Skipped bits perform no operation. The order is part of
   consensus: applying the same set of factors in any other order may
   differ by units in the last place.
5. **Integer shift, after the fractional walk.** If `q >= 0`:
   `acc = acc << q` (`q <= 255`, cannot overflow 512 bits given step 3).
   If `q < 0`: `acc = acc >> (-q)` (floor).
6. **Clamp.** `T_h = min(max(acc, 1), 2^256 - 1)`.

Bounds recap making every step width-safe: after step 4, `acc < 2^257`;
after step 5, `acc < 2^512`; the clamp maps back into `[1, 2^256 - 1]`.

## 4. Reference implementations and vectors

* Rust: `crates/noos-ground/src/pulse.rs` (`pulse_target_v1`), over the
  crate's minimal exact u256/u512 (no floats, checked arithmetic,
  `unsafe` denied). The u256 choice rationale is documented in
  `crates/noos-ground/src/u256.rs`.
* Python oracle: `tools/vector-generators/gen_ground_vectors.py`
  (`pulse_target_v1`), arbitrary-precision integers, structurally
  independent of the Rust code.
* Vectors: `protocol/vectors/ground/pulse-retarget-v1.json` — exact
  exponents 0/±1/±2, both clamps and both short-circuit boundaries
  (`q = 255` vs `q = 256`, `q = -256` vs `q = -257`), dyadic and
  non-dyadic fractional exponents probing the floor direction, and an
  anchor-roll pair showing the retarget depends only on validated
  checkpoint fields. Each case fixes
  `{anchor_target_hex, t, t_a, h, h_a, expected_target_hex}` (big-endian
  hex) and `bytes` (expected target, 32-byte little-endian).

A Go implementation MUST implement §3 verbatim (same table, same bit
order, same per-step floors, same short circuits) and reproduce every
vector byte-for-byte before it can ship.
