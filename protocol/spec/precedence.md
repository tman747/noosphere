# NOOSPHERE Frozen-Corpus Precedence — v1 (FROZEN)

Status: FROZEN at G0. Authority: plan §1.1, §1.5; read-only corpus `C:/tmp/noosphere/`
(chapters cited below by number). This document resolves which frozen document wins when
two of them appear to disagree, and records the five binding tension rulings. It creates
no mechanism and can promote nothing: promotion past a gate belongs exclusively to
chapter 04 and its addendum.

## 1. Authority order

Highest first. A lower tier may **narrow** a higher tier (add a constraint, record a
negative result, disable a scope) but may never widen, promote, or activate anything the
higher tier gates.

| Tier | Document(s) | Role | May it promote a mechanism? |
|---|---|---|---|
| 1 | `04-experiments-and-falsifiers.md` | **Gate and kill authority.** Universal kills (§2), ClaimRecords (§3), G0–G5 gates (§4). The only document whose rules move a mechanism toward production. | Yes — via its own preregistered gates only |
| 1a | `04-addendum-A.md` | **Binding where it records a later result.** Proposed reservations for the next unfrozen ch04 revision, "binding on this program in the interim" (addendum header). Where an addendum row records a KILL, PASS, WITHDRAWN, or partial result dated after ch04 froze, the addendum row wins over the older ch04 row it supersedes. It cannot weaken a ch04 universal kill (§2.1 applies to every addendum row unchanged, addendum header). | Only in the same sense as ch04, and never past a ch04 universal kill |
| 2 | `01-architecture.md` | **Frozen base protocol.** Object shapes, state transition, consensus rules, genesis controls, invariants. What the chain *is* when every experimental control is off. | No — it defines; ch04 gates |
| 3 | `02-mathematics.md` | **Formal boundary for experimental work.** Proof obligations, what each mechanism does and does not guarantee (e.g. the M-* "does not guarantee" table, ch02 §"mechanism boundary"). Where ch02 says a property is *not* established, no other chapter may assume it. | No |
| 4 | `03-living-model.md`, `05-neural-lane.md`, `06-weft-language.md`, `07-hearth-and-swarm.md`, `08-memetics-and-launch.md`, `09-the-identity.md`, `11-private-inference-fiber.md` | **Application / language / privacy / narrative object definitions.** They define objects, encodings, profiles, and product semantics. None of them can promote a mechanism past chapter 04, relabel an assurance class, or add consensus weight. | No |
| 5 | `10-competitive-audit.md` | **Audit, not consensus law.** Grounded competitive comparison; adds no protocol mechanism (its own header: "this file adds no protocol mechanism"). Its verdicts never satisfy a gate. | No |
| 6 | `README.md`, `papers/`, `research/`, `VERIFICATION-2026-07-11.md`, external lab roots | **Evidence and provenance.** Dated lab artifacts and compilations. Evidence feeds a ClaimRecord; it never bypasses one. | No |

Conflict algorithm:

1. If chapter 04 (or a later-dated addendum-A row) speaks to the question, it wins.
2. Otherwise, if 01 defines the base-protocol behavior, 01 wins over 02–11.
3. Otherwise, if 02 states a formal boundary ("X does not guarantee Y"), that boundary
   binds every application chapter.
4. An application chapter (tier 4) wins only inside its own object definitions, and only
   where 01/02/04 are silent.
5. Chapter 10 and tier-6 material never win a conflict; they may only supply evidence.
6. Where the corpus is genuinely silent, the approved build plan
   (`local://noosphere-full-build-plan.md`) decides; production economic values remain
   `OWNER_BLOCKED` (plan §1.7, §2.5) and are never invented.

## 2. The five tension rulings

Each ruling is frozen. Reopening one requires a new claim ID under ch04 discipline
(changing a threshold or ruling creates a new `claim_id`; addendum-A header).

### 2.1 (a) Public name vs protocol codename — MindChain / NOOSPHERE / NOOS

**Tension.** Chapters 01–09 are written under the protocol name NOOSPHERE (ch01 header:
"Protocol name: NOOSPHERE. Native asset: `NOOS`"), while the later frozen documents name
the product MindChain (ch10 header: "*Official name: MindChain. Research corpus codename:
NOOSPHERE*"; 04-addendum-A header: "*MindChain research corpus — codename NOOSPHERE*";
ch11 header carries the same formula).

**Ruling.** The public product name is **MindChain**. The internal protocol codename is
**NOOSPHERE**. Every wire-visible, machine-consumed identifier uses the neutral
`NOOS`/`noos` namespace: `NOOS/` hash domains, `NOOS-BLS-*` DSTs, `noos` address HRP,
`/noos/` libp2p protocols, `noos-*` crates, `noosd`-family binaries, `NOOS_` environment
prefix, `noos_*` metrics. UI strings say MindChain; consensus bytes never do. Frozen in
`protocol/schemas/identity-v1.md` §1 and §6.

**Citations.** ch01 header (lines 1–5); ch10 header line 3; 04-addendum-A line 3; ch11
line 3; plan Assumptions ("Public product name is `MindChain`; internal research/protocol
codename is `NOOSPHERE`").

### 2.2 (b) Raw stake controls Witness Ring safety even when effective weight is displayed

**Tension.** Chapter 01 §4.7 defines a proofpower bonus that, if enabled, "adds a bounded
multiplier to stake weight," producing an *effective* weight that telemetry, explorers,
and epoch snapshots may display. A reader could conclude effective weight is the safety
quantity.

**Ruling.** **Normalized raw stake weight is the only safety quantity.** Justification
requires the dual threshold — raw weight ≥ `Q_e^raw = floor(2*W_e^raw/3)+1` **and**
effective weight ≥ `Q_e^eff` — and "Proofpower may prioritize participation but can never
manufacture a safety quorum that lacks two-thirds stake-only support" (ch01 §4.8).
"Safety requires fewer than one third of normalized raw stake weight to violate slashable
voting rules …; the dual effective threshold cannot weaken that raw-stake quorum" (ch01
§4.10). Correlated-operator metadata and proofpower inform selection and caps only:
"finality safety rests on less than one third of normalized raw stake weight being
Byzantine, not metadata or proofpower" (ch01 §4.6). Chapter 02 §6 lists "safety without
raw stake" among the properties M-PROOFPOWER explicitly does **not** guarantee.
Displaying effective weight anywhere (UI, snapshot, certificate sums) never changes
quorum arithmetic; certificates carry **both** raw and effective sums (ch01 §4.8) and
verifiers check both, with the raw threshold load-bearing.

**Citations.** ch01 §4.6, §4.7, §4.8, §4.10; ch02 §6 (M-PROOFPOWER boundary row).

### 2.3 (c) SpanWitness is application evidence, not a base-consensus prerequisite

**Tension.** Chapter 09 §1.1 opens: "The atomic consensus object is the **committed span
witness**" and derives five products from it, one of which is "security weight … entering
the lottery as bounded Loom proposal credit and matured proofpower" (ch09 §1.2, product 2).
Read alone, that sentence makes an AI tensor witness sound like a base-consensus input.

**Ruling.** A `SpanWitness` (and every `ChunkWitness`/`TokenClaim` derived from it) is
**application evidence**: an input to Work Loom settlement, NEL receipts, disputes, and
shadow calculators. It is never a prerequisite for Ground proposal validity, Braid fork
choice, Witness Ring membership, or checkpoint finality. Chapter 01's release invariant
is explicit: "If every experimental feature is disabled, NOOSPHERE remains a
transferable-value, smart-contract, data-availability, and finality network" (ch01 §0),
and ch09's own product table caps product 2 at "both zero at genesis" (ch09 §1.2).
Chapter 04 §1 tests the base chain with `work_loom_weight_cap=0`,
`work_loom_credit_enabled=false`, and `witness_proofpower_bonus_enabled=false`. Base
consensus code therefore contains no SpanWitness type; the type lives in application
crates (`noos-work-loom`, `noos-nel`, analytics), and E-BLACKOUT scenarios prove blocks
finalize with zero witnesses in existence.

**Citations.** ch09 §1.1–§1.2; ch01 §0 (release invariant), §0.1 (property separation),
§1.2, §4.10; ch04 §1 (all-off test controls).

### 2.4 (d) Six genesis controls are authoritative, including `neural_lane_enabled = false`

**Tension.** Chapter 01 §0 lists **five** controls (`work_loom_credit_enabled`,
`work_loom_weight_cap`, `witness_proofpower_bonus_enabled`, `umbra_suite_enabled[suite_id]`,
`dream_lane_enabled`); chapter 08 §4.4 item 4 commits the same five into the genesis
ceremony. Chapter 04 §1 lists **six**, adding `neural_lane_enabled = false`.

**Ruling.** **The chapter 04 §1 six-control list is authoritative** — ch04 is the gate
authority and its list is the one the base chain is tested under. All six ship
disabled/zero at genesis on every network:

```text
work_loom_credit_enabled          = false
work_loom_weight_cap              = 0        (protocol maximum 0.10, never raisable above)
witness_proofpower_bonus_enabled  = false
umbra_suite_enabled[suite_id]     = false    (every suite)
dream_lane_enabled                = false
neural_lane_enabled               = false
```

The operational genesis registry (`protocol/spec/constants-v1.toml` `[genesis_controls]`,
`protocol/genesis/devnet-parameters.toml` `[controls]`) additionally pins
`reflex_lane_enabled = false` and `class_gate_irreversible_budget = 0` (plan §6.8,
§12.12–§12.13; addendum A.3–A.4). These extensions narrow — they can never contradict or
substitute for — the ch04 six. Turning any control off must not alter Lumen transaction
validity, Ground proposal validity, Ring quorum arithmetic, or finalized history (ch01 §0;
ch04 §1).

**Citations.** ch04 §1 (six-control list, lines 17–24); ch01 §0 (five-control list);
ch08 §4.4 commitment item 4; plan §1.5, §6.8.

### 2.5 (e) Addendum A keeps useful-work influence at S0 despite earlier activation theory

**Tension.** Chapter 01 §4.4 specifies how settled Work Loom receipts *would* add
proposal credit `L(b)` once `work_loom_credit_enabled=true`; ch01 §4.7 specifies the
proofpower bonus as [THEORY]; ch02 §6 (M-PROOFPOWER) develops the activation mathematics
with staged caps. Those texts read as an activation roadmap.

**Ruling.** **Addendum A.5 is binding: the useful-work leg stays at S0** (zero consensus
influence). `E-DEMAND-WASH-01` executed its preregistered kill on 2026-07-10: the frozen
payoff gate DW-02 failed in 206,175 / 4,723,920 comparisons (worst margin
−$10,529,559.52), so "the program therefore keeps the useful-work leg at **S0** instead
of promoting a mechanism that passed its accounting gates but failed its security
inequality" (addendum A.5). Consequences, all enforced in state transition:

- `work_loom_credit_enabled = false`, `work_loom_weight_cap = 0`,
  `witness_proofpower_bonus_enabled = false`, duplex-issuance reallocation hard-zero.
- The ch01 §4.4 credit clamp, §4.7 bonus, and ch02 §6 calculators are implemented in
  **shadow mode only** (plan §9.6, §12.11) — telemetry, never weight.
- Reactivation requires a **new claim ID** with a preregistered *absolute attack-payoff*
  experiment (not marginal wash cost), per addendum A.5 and plan §12.11; even then Loom
  fork influence rises only through explicit signed steps up to the 0.10 protocol
  maximum, and proofpower's first nonzero cap is at most 1% of Ring weight (plan §14.6).

The registry preserves `E-DEMAND-WASH-01` as `KILLED`; the kill is reproducible
(`demand_wash_activation_decision=S0`, VERIFICATION-2026-07-11 row 18) and is never
edited, only superseded by a new claim ID.

**Citations.** 04-addendum-A §A.5; ch01 §4.4, §4.7; ch02 §6; VERIFICATION-2026-07-11
row 18 and Aggregate; plan §1.5, §12.11, §14.6.

## 3. Enforcement

- `tools/gates/validate_registry.py` enforces the registry consequences of rulings (d)
  and (e): the affected rows carry `lifecycle`/`result` values (`KILLED`, `WITHDRAWN`,
  `RETIRED`) that no flattened status may erase.
- `tools/gates/check_identity.py` enforces ruling (a)'s wire boundary (no `MindChain`
  casing in consensus bytes; no historical `mind`/`ASCENT-*`/`ascent.*` identity).
- State-transition and compile-time checks enforce rulings (b), (d), (e): dual-threshold
  verification with a load-bearing raw quorum, all-off genesis controls, and hard-zero
  Loom/proofpower/duplex influence.
- This file is provenance-allowlisted for naming historical identifiers.
