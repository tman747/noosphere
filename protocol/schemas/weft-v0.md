# Weft v0 — frozen certificate schemas and the total relation checker

Status: **FROZEN-V0 candidate (PROPOSED-G0)** — the five certificate objects,
their canonical byte layouts, the content-addressing domains, the checker
relation, and the stable rejection codes below are complete and
self-sufficient for an independent reimplementation. Values invented here
(not quoted from a normative source) are individually marked PROPOSED-G0.
Once G0 review signs this file, every number in it is immutable for
`weft_schema_version = 0`; any change is `weft_schema_version = 1` with new
vectors.

Sources: `C:/tmp/noosphere/06-weft-language.md` §3.3 (v0 = schemas plus a
total checker; the SpanStatement wire example), §4.1–§4.3 (cost polynomials,
jet obligations, numeric profiles), §5.2/§5.4 (MeaningContract, certificate
lifecycle), `C:/tmp/noosphere/01-architecture.md` §7.4 (JetEntry registry
key); plan §5.5 (ship v0 first, freeze vectors, pass the false-accept gate),
§5.7 (unknown fields / uncheckable derivations reject admission), §5.8 (the
certificate-checker law), §5.9 (jet registry key). Grain semantics and the
cost table are `protocol/schemas/grain-v1.md` — this document adds **no**
execution semantics.

Reference implementation: `crates/noos-weft-check`. Conformance fixtures:
`protocol/vectors/weft/*.json` (§7). The independent Go `go/weftref` MUST be
authored from this document and the vectors alone, never from the Rust
source.

---

## 1. Scope and the two standing laws

Weft v0 is **schemas plus a checker** and nothing else:

- Five typed, versioned, content-addressed objects — `NumericProfileV0`,
  `CostCertificateV0`, `MeaningContractV0`, `JetCertificateV0`,
  `SpanStatementV0` — and a **total relation checker**: a bounded,
  deterministic validator for schema well-formedness, profile consistency,
  transcript-layout conformance, and certificate-reference integrity.
- **No parser, no inference, no elaboration.** Authors write Grain formulas
  by whatever means they like and attach v0 artifacts. The full language
  (`noos-weft-syntax` / `-check` extensions / `-compile` / `weftc`) is gated
  behind v0's false-accept gate (plan §5.5) and adds nothing to this file.
- **Raw Grain remains valid forever (frozen law).** A formula with no Weft
  artifact evaluates, pays step-metered fees, and is a first-class citizen
  indefinitely. v0 objects are *data about formulas*; the checker gates
  only the artifacts themselves. Weft can be wrong, quarantined, or
  abandoned without a state transition changing meaning — this is the
  anti-lock-in guarantee of ch06 §3.3.
- **Never trust a declared polynomial (frozen law, plan §5.8).** A cost
  certificate is checked, not believed: size variables, coefficient /
  degree / term limits, and overflow are validated with checked integer
  arithmetic; the branch combinator is `max`; and a certificate that embeds
  its formula is *executed* on its declared-size trial inputs through the
  real Grain interpreter, asserting `actual charge <= certified bound`.

**Well-formed is not well-typed.** The checker validates cross-references,
bounds, layout registration, and (for embedded formulas) trial charges. It
cannot know whether a `verifier_ref` actually implements Freivalds, whether
a trial subject truly "has" its declared sizes, or whether a jet binary
matches its slow meaning — those are what bonds, challenges, and (later)
the full language's derivations are for. The gap between "well-formed" and
"well-typed" is exactly the value `E-WEFT-08` measures.

## 2. Frozen v0 limits

All PROPOSED-G0 unless cited. Every collection maximum is enforced by the
codec *before allocation*; every checker budget makes the relation total
and bounded.

| Constant | Value | Meaning |
|---|---:|---|
| `WEFT_V0_VERSION` | 0 | the `u16` object version of every v0 object |
| `WEFT_V0_GRAIN_VERSION` | 1 | the only `grain_version` v0 certificates may cite |
| `MAX_PROFILE_NAME_BYTES` | 32 | profile name |
| `MAX_TARGET_TRIPLE_BYTES` | 64 | jet target triple |
| `MAX_TYPE_SIGNATURE_BYTES` | 4096 | opaque type signature (may be empty) |
| `MAX_SIZE_VARS` | 8 | size variables per cost certificate |
| `MAX_SIZE_VAR_NAME_BYTES` | 16 | size-variable name |
| `MAX_COST_BRANCHES` | 16 | `max`-combined branches per polynomial |
| `MAX_COST_TERMS` | 64 | terms per branch |
| `MAX_TERM_EXPONENT` | 4 | per-variable exponent in one term |
| `MAX_TERM_TOTAL_DEGREE` | 6 | sum of exponents in one term |
| `MAX_COST_COEFF` | 2^48 | term coefficient (min nonzero 1) |
| `MAX_COST_TRIALS` | 16 | evaluation trials per certificate |
| `MAX_EMBEDDED_FORMULA_BYTES` | 65_536 | == Grain `MAX_FORMULA_BYTES` |
| `MAX_TRIAL_SUBJECT_BYTES` | 65_536 | tighter than Grain's 1 MiB subject cap |
| `MAX_TRIAL_CHARGE` | 2^24 | checker step budget per trial (boundedness) |
| `MAX_TRIAL_ARENA_WORDS` | 2^20 | checker arena budget per trial (8 MiB) |
| `MAX_PROFILE_REFS` | 8 | profile references per meaning contract |
| `MAX_OBLIGATION_REFS` | 32 | obligation references per meaning contract |
| `SPAN_DIM_MAX` | 65_535 | span dimension (16-bit transcript packing, ch06 §6.1) |
| `SPAN_SOUNDNESS_MIN_BITS` | 64 | `reps * rbits >= 64` (2^-64 per span, ch06 §3.3) |
| `SPAN_MAX_REPS` | 8 | Freivalds repetitions |
| `SPAN_SHA256_FLAT_V0_RBITS` | 32 | challenge-word width of layout `SHA256_FLAT_V0` |
| `PROFILE_FORBID_REQUIRED` | 0x0F | required forbid mask (§4.1) |

The all-zero 32-byte hash is the frozen **absent-reference sentinel**
everywhere a reference field is optional; a mandatory reference field
rejects the sentinel with its own code.

## 3. Content addressing and registered domains

Every object id is BLAKE3-256 over the object's registered context string
followed by its canonical bytes:

```text
id = BLAKE3-256( context_string || canonical_object_bytes )
```

Registered rows (`protocol/spec/crypto-domains-v1.csv`, all ASSIGNED,
pending G0 review):

| domain_id | context string | id it defines |
|---|---|---|
| `D-WEFT-PROFILE` | `NOOS/WEFT/PROFILE/V0` | `profile_id` |
| `D-WEFT-COST` | `NOOS/WEFT/COST/V0` | `cost_certificate_id` |
| `D-WEFT-MEANING` | `NOOS/WEFT/MEANING/V0` | `meaning_id` |
| `D-WEFT-JETCERT` | `NOOS/WEFT/JETCERT/V0` | `jet_certificate_id` |
| `D-WEFT-SPAN` | `NOOS/WEFT/SPAN/V0` | `span_id` |
| `D-WEFT-FORMULA` | `NOOS/WEFT/FORMULA/V0` | `formula_id` |

`formula_id = H("NOOS/WEFT/FORMULA/V0" || canonical Grain noun bytes)` over
the §4 grain-v1.md encoding of the formula. The sixth row exists because
certificate-reference integrity requires the checker to *recompute* formula
ids from embedded bytes, and the registry CI law forbids any hash call site
without a registered domain (CSV law c).

Content addressing makes reference cycles unrepresentable and supersession
additive: a changed object is a *different* object (ch06 §5.2 "nothing is
upgraded in place").

## 4. Canonical object layouts

Encoding is `noos-codec` law: `u16` little-endian version (`= 0`), then per
field in declaration order a `u16` mandatory tag followed by the field's
canonical encoding; primitives fixed-width little-endian; byte strings and
lists carry a canonical `u32` length validated against BOTH the frozen
maximum and the remaining input before allocation; enum discriminants are
`u16` in declaration order and unknown discriminants reject; decoding
consumes the entire input. Unknown mandatory tags reject — there are no
optional fields in any v0 object (plan §5.7: unknown fields reject
admission).

### 4.1 NumericProfileV0

Exact quantization semantics as data (ch06 §4.3). v0 admits exactly the
measured W8A8 shape; a wider admissible set is a new schema version.

| Tag | Field | Type | Checker law |
|---:|---|---|---|
| 1 | `name` | bytes ≤ 32 | `[A-Za-z][A-Za-z0-9._-]*`, nonempty |
| 2 | `weight_bits` | u8 | == 8 |
| 3 | `activation_bits` | u8 | == 8 |
| 4 | `accum_bits` | u8 | == 32 |
| 5 | `accum_exact` | u8 | == 1 (KT-1 exact integer accumulation) |
| 6 | `requant_kind` | enum u16 | `ROUND_HALF_UP_SHIFT = 0` (the measured kt-ladder rule: `sat8((i64(acc)*i64(mult) + (1<<(shift-1))) >> shift)`); the only v0 discriminant |
| 7 | `requant_mult` | u32 | != 0 |
| 8 | `requant_shift` | u8 | 1..=31 |
| 9 | `saturate_min_twos` | u8 | == 0x80 (two's-complement −128) |
| 10 | `saturate_max_twos` | u8 | == 0x7F (127) |
| 11 | `forbid_flags` | u32 | == 0x0F: bit0 float, bit1 wrapping, bit2 zero_points, bit3 kernel_order_dependence; no unknown bits |

Note (ch06 §4.3): round-to-nearest-even at requant is a **different
consensus semantics** and therefore a different `requant_kind` in a future
version — it can never be confused with discriminant 0.

### 4.2 CostCertificateV0

A declared cost polynomial over size variables plus optional embedded
formula and trials. The polynomial value at a size assignment `s` is

```text
bound(s) = max over branches of ( sum over terms of coeff * prod_i s[i]^exp[i] )
```

— frozen branch-`max` semantics (plan §5.8: `if`/`match` arms certify as
the max of their branch polynomials). Coefficients are nonnegative by
construction, so `bound` is monotone in every variable.

| Tag | Field | Type | Checker law |
|---:|---|---|---|
| 1 | `formula_id` | 32 bytes | nonzero; must equal `H(D-WEFT-FORMULA \|\| formula_bytes)` when embedded |
| 2 | `grain_version` | u32 | == 1 |
| 3 | `size_vars` | list ≤ 8 of `SizeVarDecl` | names `[a-z][a-z0-9_]*`, unique; `max_value >= 1` |
| 4 | `branches` | list ≤ 16 of `CostBranch` | nonempty; every branch nonempty |
| 5 | `formula_bytes` | bytes ≤ 65_536 | empty = not embedded; else canonical grain-v1.md §4 formula |
| 6 | `trials` | list ≤ 16 of `CostTrial` | nonempty iff formula embedded |

Sub-structs (encoded in field order, no version/tags of their own):

```text
SizeVarDecl { name: bytes<=16, max_value: u64 }
CostTerm    { coeff: u64, exponents: bytes<=8 }   -- exponents[i] for size_vars[i]
CostBranch  { terms: list<=64 of CostTerm }
CostTrial   { sizes: list<=8 of u64, subject: bytes<=65_536 }
```

### 4.3 MeaningContractV0

Binds every representation of a computation to one Grain meaning (ch06
§5.2). v0 has no compiler: `compiler_id = 0` is the frozen "hand-authored"
sentinel; a nonzero value is reserved for `weftc` (its reproducible-build
hash) and is opaque data at v0.

| Tag | Field | Type | Checker law |
|---:|---|---|---|
| 1 | `formula_id` | 32 bytes | nonzero |
| 2 | `grain_version` | u32 | == 1 |
| 3 | `compiler_id` | 32 bytes | zero = hand-authored; opaque otherwise |
| 4 | `source_root` | 32 bytes | zero = none; opaque otherwise |
| 5 | `type_signature` | bytes ≤ 4096 | valid UTF-8; may be empty; opaque otherwise |
| 6 | `profile_ids` | list ≤ 8 of 32 bytes | no duplicates; each resolves to an admitted NumericProfileV0 |
| 7 | `cost_certificate_id` | 32 bytes | zero = none; else resolves to an admitted CostCertificateV0 whose `formula_id` equals tag 1 |
| 8 | `rv32_guest_hash` | 32 bytes | zero = no RV32IM lowering; opaque otherwise |
| 9 | `obligation_ids` | list ≤ 32 of 32 bytes | no duplicates; each resolves to an admitted JetCertificateV0 with matching `formula_id` AND `grain_version` |

### 4.4 JetCertificateV0

ch01 §7.4 `JetEntry` fused with ch06 §4.2 `EquivalenceObligation`. The
registry key remains exactly `(grain_version, formula_id)` (plan §5.9);
this object is the certificate stored under it. The `jet_certificate_id`
content address identifies the certificate *instance* (a status change is a
new instance — the lifecycle is additive).

| Tag | Field | Type | Checker law |
|---:|---|---|---|
| 1 | `grain_version` | u32 | == 1 |
| 2 | `formula_id` | 32 bytes | nonzero |
| 3 | `impl_hash` | 32 bytes | nonzero (exact binary/kernel hash) |
| 4 | `target_triple` | bytes ≤ 64 | nonempty, printable ASCII `0x21..=0x7E` |
| 5 | `profile_id` | 32 bytes | zero = none; else resolves to an admitted profile |
| 6 | `cost_certificate_id` | 32 bytes | zero = step-metered; else resolves, `formula_id` must match tag 2 (the jet charges the SAME cost as the slow meaning — speed is bought, price is not) |
| 7 | `corpus_root` | 32 bytes | nonzero (committed boundary+random test corpus) |
| 8 | `bond_micro_noos` | u64 | != 0 |
| 9 | `status` | enum u16 | `PROPOSED=0, CHALLENGEABLE=1, ADMITTED=2, QUARANTINED=3, REVOKED=4, SUPERSEDED=5` |
| 10 | `admitted_height` | u64 | see height law |
| 11 | `revoked_height` | u64 | see height law |

Height law (ch06 §5.4): `PROPOSED`/`CHALLENGEABLE` ⇒ both heights zero;
`ADMITTED`/`SUPERSEDED` ⇒ `admitted_height > 0` and `revoked_height == 0`;
`QUARANTINED`/`REVOKED` ⇒ `revoked_height > 0` and
`revoked_height >= admitted_height` (admission may never have happened —
quarantine from the challenge window keeps `admitted_height == 0`).

### 4.5 SpanStatementV0

The ch06 §3.3 wire example, frozen. All fields fixed-width; the canonical
encoding is exactly 112 bytes (`beacon_policy`'s u16 value sits at byte
offset 106, a fact the vectors' discriminant-tamper case uses).

| Tag | Field | Type | Checker law |
|---:|---|---|---|
| 1 | `profile_id` | 32 bytes | resolves to an admitted NumericProfileV0 |
| 2 | `shape_m` | u32 | 1..=65_535 |
| 3 | `shape_k` | u32 | 1..=65_535 |
| 4 | `shape_n` | u32 | 1..=65_535 |
| 5 | `transcript_layout` | enum u16 | `SHA256_FLAT_V0 = 0` (`tl:sha256-flat-v0`: `root = SHA256(A \|\| B \|\| C32 \|\| params24)`; challenge block 0 = root in place, `block_i = SHA256(root \|\| u32le(i))`) |
| 6 | `verifier_kind` | enum u16 | `GRAIN_FORMULA = 0` (verifier_ref is a D-WEFT-FORMULA id), `RV32_GUEST = 1` (guest binary hash) |
| 7 | `verifier_ref` | 32 bytes | nonzero |
| 8 | `soundness_reps` | u16 | 1..=8 |
| 9 | `soundness_rbits` | u16 | == 32 under `SHA256_FLAT_V0` |
| 10 | `beacon_policy` | enum u16 | `POST_COMMIT_REQUIRED = 0` accepted; `OFFLINE_DERIVED = 1` decodes but the checker REJECTS it (ch06 §3.3 "rejects offline-derived") |
| 11 | `journal_schema` | enum u16 | `SPAN_V0 = 0` (`js:span-v0`: `(m,k,n,quant,H(A),H(B),H(C32),H(C8),beacon,payout,root)`) |

The 16-bit dimension bound is the kt-ladder run #27 fix: 10-bit packings
alias at dimension ≥ 1024, so the schema refuses what the transcript cannot
injectively bind. Soundness policy: `reps * rbits >= 64` (the 2^-64/span
default; NEL production raises reps under its own profile, plan §10.9).

## 5. The checker relation

The checker is a pure function over `(object bytes, kind, store)` where the
**store** is the set of previously *admitted* objects keyed by content id.
Admission order is dependency order (profiles → cost certificates → jet
certificates → meaning contracts / span statements); cycles are
unrepresentable under content addressing. Every check sequence below is
frozen: the FIRST failing check names the rejection code (§6).

Totality and boundedness: all inputs are codec-bounded; the only execution
the checker performs is trial evaluation under the frozen
`MAX_TRIAL_CHARGE` / `MAX_TRIAL_ARENA_WORDS` meter, and Grain evaluation is
total given a finite meter (grain-v1.md §1). The checker never panics: any
input is either accepted or rejected with a stable code.

### 5.1 NumericProfileV0 (standalone)

1. name charset/nonempty → 20; 2. widths == (8,8,32) → 21; 3. exact
accumulation → 22; 4. requant mult/shift → 23; 5. saturation range → 24;
6. forbid mask → 25.

### 5.2 CostCertificateV0 (standalone; the certificate law)

1. `grain_version == 1` → 40.
2. `formula_id != 0` → 41.
3. Size variables valid, unique, `max_value >= 1` → 42.
4. Branches nonempty, every branch nonempty → 43.
5. Every term: exponent arity == variable count → 44; per-variable exponent
   ≤ 4 and total degree ≤ 6 → 45; `1 <= coeff <= 2^48` → 46.
6. `bound(max sizes)` evaluates without overflow and fits u64 → 47.
   (Checked u128 arithmetic; monotonicity then covers every in-range trial.)
7. If `formula_bytes` empty: trials must be empty → 51; done.
   Else: bytes decode as a canonical Grain formula → 48; recomputed
   `formula_id` matches → 49; at least one trial → 50.
8. Per trial, in order: size arity → 52; every size ≤ its variable's
   `max_value` → 53; subject decodes as a canonical Grain subject → 54;
   `bound(trial sizes) <= MAX_TRIAL_CHARGE` → 55; run
   `eval(1, subject, formula, Meter(bound, MAX_TRIAL_ARENA_WORDS))`:
   `METER_EXHAUSTED` means the actual charge exceeded the certified bound
   → 57; any other trap → 56; success means `charge <= bound` by meter
   construction.

The meter IS the bound assertion: the checker never trusts the polynomial,
it prices the execution with it. What a trial does NOT prove: that the
subject "has" the declared sizes — v0 records the author's pairing and
executes it honestly; the size-to-subject binding is a full-language
(`T-COST`) obligation and part of the §1 well-formed/well-typed gap.

### 5.3 JetCertificateV0 (store-resolved)

1. `grain_version == 1` → 80; 2. `formula_id != 0` → 81; 3. `impl_hash !=
0` → 82; 4. target triple → 83; 5. `corpus_root != 0` → 84; 6. bond → 85;
7. status/height law → 86; 8. profile resolves (when nonzero) → 87;
9. cost certificate resolves (when nonzero) → 88, with matching
`formula_id` → 89.

### 5.4 MeaningContractV0 (store-resolved)

1. `grain_version == 1` → 60; 2. `formula_id != 0` → 61; 3. type signature
UTF-8 → 62; 4. profile refs: unique → 63, resolve → 64; 5. cost ref (when
nonzero): resolves → 65, `formula_id` matches → 66; 6. obligation refs:
unique → 67, resolve → 68, `formula_id` AND `grain_version` match → 69.

### 5.5 SpanStatementV0 (store-resolved)

1. shape bounds → 100; 2. `verifier_ref != 0` → 101; 3. layout rbits law →
102; 4. soundness policy → 103; 5. beacon policy → 104; 6. profile
resolves → 105.

## 6. Stable rejection codes

u16, immutable for schema version 0; zero reserved. Codes 1–7 are the
canonical images of the codec's closed decode-error law; code 3 is
**reserved and unreachable in v0** (no v0 object carries codec atoms), the
same posture as Grain trap 4.

| Code | Class | | Code | Class |
|---:|---|---|---:|---|
| 1 | `decode_truncated` | | 50 | `cert_no_trials` |
| 2 | `decode_trailing_bytes` | | 51 | `cert_trials_without_formula` |
| 3 | `decode_nonminimal_atom` (reserved) | | 52 | `cert_trial_arity` |
| 4 | `decode_unknown_field` | | 53 | `cert_trial_size_range` |
| 5 | `decode_length_bound` | | 54 | `cert_trial_subject_invalid` |
| 6 | `decode_unknown_version` | | 55 | `cert_trial_budget_exceeded` |
| 7 | `decode_unknown_discriminant` | | 56 | `cert_trial_trapped` |
| 10 | `unknown_object_kind` | | 57 | `cert_charge_exceeds_bound` |
| 20 | `profile_name_invalid` | | 60 | `mc_grain_version` |
| 21 | `profile_width_inadmissible` | | 61 | `mc_formula_id_zero` |
| 22 | `profile_accum_not_exact` | | 62 | `mc_type_signature_invalid` |
| 23 | `profile_requant_invalid` | | 63 | `mc_profile_duplicate` |
| 24 | `profile_saturate_invalid` | | 64 | `mc_profile_unresolved` |
| 25 | `profile_forbid_invalid` | | 65 | `mc_cost_unresolved` |
| 40 | `cert_grain_version` | | 66 | `mc_cost_formula_mismatch` |
| 41 | `cert_formula_id_zero` | | 67 | `mc_obligation_duplicate` |
| 42 | `cert_size_var_invalid` | | 68 | `mc_obligation_unresolved` |
| 43 | `cert_no_branches` | | 69 | `mc_obligation_mismatch` |
| 44 | `cert_term_arity` | | 80–89 | `jet_*` (order of §5.3) |
| 45 | `cert_degree_exceeded` | | 100 | `span_shape_bound` |
| 46 | `cert_coeff_invalid` | | 101 | `span_verifier_zero` |
| 47 | `cert_bound_overflow` | | 102 | `span_rbits_layout` |
| 48 | `cert_formula_invalid` | | 103 | `span_soundness_policy` |
| 49 | `cert_formula_hash_mismatch` | | 104 | `span_beacon_policy` |
| | | | 105 | `span_profile_unresolved` |

Jet codes, explicitly: 80 `jet_grain_version`, 81 `jet_formula_id_zero`,
82 `jet_impl_hash_zero`, 83 `jet_target_invalid`, 84 `jet_corpus_zero`,
85 `jet_bond_zero`, 86 `jet_heights_inconsistent`, 87
`jet_profile_unresolved`, 88 `jet_cost_unresolved`, 89
`jet_cost_formula_mismatch`.

A truncation that lands inside a length-delimited tail collection reports
`decode_length_bound` (5), not `decode_truncated` (1): the codec validates
the declared length against the remaining input BEFORE allocation, and that
check fires first. The vectors pin this.

## 7. Conformance vectors

Directory: `protocol/vectors/weft/`. Files follow the repository vector
shape `{"schema", "description", "cases":[…]}`; every case carries `name`,
`kind` (`positive`/`negative`), `object` (a §4 kind name in
`{numeric_profile, cost_certificate, meaning_contract, jet_certificate,
span_statement}`), `bytes` (lowercase hex of the object under test),
`store` (ordered prerequisite objects, same shape), and `expect`.

Runner obligation, in order:

1. Start from an empty store; admit every `store` entry in order — each
   MUST be accepted (prerequisites are fixture data, not the case).
2. Resolve `object`; an unknown name is `unknown_object_kind` (10).
3. Decode-and-check `bytes` as `object` against the store. A `positive`
   case must accept with exactly `expect.content_id`; a `negative` case
   must reject with exactly `expect.error_code` and `expect.error_class`.

Files (83 cases total; every reachable §6 code appears in at least one
case):

- **`weft-profile-v0.json`** — schema `noos/weft/profile-v0`: profile
  admissibility plus the envelope negatives (version, tag order,
  truncation, trailing bytes, length bound, unknown discriminant).
- **`weft-cost-v0.json`** — schema `noos/weft/cost-v0`: the §5.2
  certificate law, including an accepted embedded certificate whose trials
  execute through Grain, an accepted unembedded certificate, bound
  understatement, overflow injection, budget bombs, trapped trials, and
  formula-hash tampering.
- **`weft-refs-v0.json`** — schema `noos/weft/refs-v0`: store-resolved
  reference integrity (dangling and transplanted references), the jet
  lifecycle height law, and span layout/soundness/beacon conformance.

The Rust case tables (`crates/noos-weft-check/src/vectors.rs`) are the
generation source; `cargo run -p noos-weft-check --bin gen_vectors`
re-emits the JSON, and the crate tests fail if the files on disk drift
from the tables. One divergence between two implementations on any vector
blocks the v0 freeze.

## 8. The false-accept gate (mutation battery)

`cargo test -p noos-weft-check mutation_battery_rejects_every_mutant`
executes the seeded battery: 16 deterministic seeds generate parameterized
valid bundles (varying inc-chain formula depth, bound slack, variable
maxima, bonds, span shapes, soundness reps); each seed's unmutated bundle
must fully admit (positive control), then **50 mutation classes** are
applied — field tampering, reference transplants (a cost certificate or
jet for a *different* formula), dangling references, bound understatement,
degree/coefficient inflation, overflow injection, budget bombs, trial
subject corruption, formula-byte and formula-id tampering, lifecycle
height inconsistencies, profile inadmissibility, span shape/soundness/
beacon/rbits tampering, and envelope confusion (version bump, tag swap,
truncation, trailing bytes, collection-length overflow, out-of-range
discriminants).

Gate law (plan §5.5): 100% of mutants must reject, each with a stable code
from its class's expected set. One accept is a false accept and fails the
gate — and a false accept in production freezes Weft admission. Current
frozen result: `classes=50 seeds=16 attempts=800 rejected=800
rejection_rate=100.00% false_accepts=0`.

## 9. Decisions recorded

1. **The v0 checker ships as a Rust crate**, not as a Grain formula. ch06
   §3.3 sketches "itself a Grain program"; plan §5.5 specifies "a total
   bounded Grain relation checker" for *Grain artifacts*. The relation is
   frozen here as data (ordered checks + stable codes) so a Grain-resident
   reimplementation remains possible without changing a single verdict;
   what is normative is the relation, not the host.
2. **Six domains, not five.** `D-WEFT-FORMULA` was added beyond the five
   object domains because the checker must recompute formula ids and the
   registry CI law forbids unregistered hash call sites (§3).
3. **`version: 0`** for v0 objects (the schemas are named `…V0`); the five
   objects of the full language, if it graduates, bump both.
4. **Zero-hash sentinel** for absent references instead of optional fields:
   keeps every object a fixed field sequence with no skippable regions
   (consensus objects reject unknown fields by default, codec law).
5. **Profile admissibility is exactly W8A8/i32-exact** with the measured
   round-half-up requant rule. The only measured profile is @W8A8v1
   (kt-ladder run #27); admitting unmeasured shapes at v0 would launder
   assurance. New shapes = new schema version after their own gates.
6. **Trial budget caps** (`MAX_TRIAL_CHARGE`, `MAX_TRIAL_ARENA_WORDS`) are
   checker-side, not Grain-side: they bound the checker's own work so the
   relation is total and cheap to evaluate at admission. A certificate
   whose honest trial exceeds the budget must ship smaller trials — the
   polynomial itself may still bound arbitrarily large instantiations.
7. **Jet certificates admit any lifecycle status** whose height law holds:
   the store checks internal consistency, not chain history. Enforcing
   transition legality (`QUARANTINED` never returns to `ADMITTED`, ch06
   §5.4) is registry state-machine law, layered on top of these objects.
8. **`OFFLINE_DERIVED` beacon policy decodes but never checks out**: the
   rejection must be a stable checker verdict (code 104), not a decode
   artifact, because ch06 §3.3 names "rejects offline-derived" as checker
   behavior.
