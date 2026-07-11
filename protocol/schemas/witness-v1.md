# NOOSPHERE Witness Ring — v1 normative specification (PROPOSED-G0)

Status: authored by the program orchestrator from ch01 §§4.6–4.10 and plan
§§6.5–6.7; implementation target `crates/noos-witness`. Every rule below cites
its source; values the corpus names but does not number carry their ODR row
(protocol/spec/odr-ledger.md). Once G0 review signs this file, all structure is
immutable for `witness_version = 1`.

## 1. Objects

### 1.1 WitnessBond (ch01 §4.6; widths PROPOSED-G0, codec law plan §3.1)

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `validator_id` | Hash32 | stable identity, not the key |
| 1 | `consensus_bls_key` | Bytes48 | BLS12-381 G1 (min_pk, matches noos-crypto) |
| 2 | `withdrawal_key` | Bytes32 | Ed25519; MUST differ from consensus key material |
| 3 | `network_endpoints_commitment` | Hash32 | |
| 4 | `failure_domains` | bounded bytes, max 1024 | declared {operator, cloud, asn, region, client}; informative, never identity (ch01 §4.6) |
| 5 | `bonded_noos` | u128 | integer micro-NOOS; linear raw weight |
| 6 | `activation_epoch` | u64 | delay: ODR-WITNESS-004 |
| 7 | `exit_epoch` | u64 | 0 while active; delay: ODR-WITNESS-004 |
| 8 | `proofpower_account` | Hash32 | exists structurally; weight contribution is ZERO at genesis (precedence.md ruling d/e) |

Registration validity: bond locked before the `e-2` snapshot; possession proofs
for BOTH keys (BLS proof-of-possession under `NOOS-BLS-POP-…` DST; Ed25519
self-signature under `NOOS/SIG/TX/V1` context); duplicate consensus keys and
conflicting domain declarations invalid (ch01 §4.6).

### 1.2 FinalityVote (ch01 §4.8)

| # | Field | Width |
|---:|---|---|
| 0 | `chain_id` | Hash32 |
| 1 | `epoch` | u64 |
| 2 | `source` | CheckpointRef {height u64, hash Hash32} |
| 3 | `target` | CheckpointRef |
| 4 | `validator_id` | Hash32 |
| 5 | `membership_root` | Hash32 |
| 6 | `signature` | Bytes96 (BLS G2, DST `NOOS-BLS-VOTE-…` per crypto-domains-v1.csv) |

Valid iff: target is an epoch checkpoint descended from source; source already
justified in the voter's view; membership_root equals the snapshotted Ring for
`epoch`; signature verifies under the registered vote DST over the canonical
vote body (fields 0–5).

### 1.3 FinalityCertificateV1 (ch01 §4.8; schema-tables/header-body.md)

`{source, target, participation_bitmap (max 128 B ⇒ N_hard=1024 bits),
aggregate_signature Bytes96, raw_weight_sum u128, effective_weight_sum u128,
membership_root Hash32}`. Nodes MUST verify bitmap↔signer set, BOTH threshold
sums recomputed from the snapshot (never trusted from the certificate), source
ancestry, and the aggregate signature before moving justified/finalized
pointers. Duplicate certificates short-circuit after content digest (plan §6.7).

### 1.4 SlashingEvidence (ch01 §4.8; ordinary Lumen transaction)

Three offense classes, declaration-order discriminants:
0 `DoubleVote{vote_a, vote_b}` — same target epoch, distinct targets;
1 `SurroundVote{outer, inner}` — outer interval strictly surrounds inner;
2 `InvalidTransitionVote{vote, body_ref, divergence_proof}` — complete committed
body available AND deterministic re-execution yields different state or receipt
roots. Unavailability alone is NEVER slashable (ch01 §4.8 rule 3).
Evidence is chain/domain/epoch-bound and verifiable through the evidence
horizon (ODR-WITNESS-005). Penalty split: burn fraction / reporter fraction /
locked remainder — values ODR-WITNESS-002. Removal at next epoch boundary;
membership never mutates mid-epoch.

## 2. Epoch membership snapshot (ch01 §4.6; plan §6.5)

For epoch `e`, from finalized Lumen state at the `e-2` boundary ONLY
(plan §2.6 layer edge):

1. Candidates: bonds locked before the snapshot with `activation_epoch ≤ e < exit_epoch`, bonded ≥ minimum bond (mainnet value ODR-ECON-001; testnet fixture).
2. Raw weight `r_i = bonded_noos_i` (linear; splitting bonds cannot create weight).
3. Active set: top `N_max=256` by `r_i`, tie-break by ascending
   `H("NOOS/WITNESS/TIEBREAK/V1" || epoch_le || validator_id)` (domain to be
   registered as ASSIGNED row; deterministic, epoch-salted).
4. Reserve: `N_tail=32` sampled without replacement from the remainder using
   finalized epoch randomness (§4 beacon output of epoch `e-1`).
5. Cap law: no validator key may hold ≥ ⅓ of total raw OR effective weight.
   While violated: admit reserve candidates in deterministic sample order (up
   to `N_hard=1024`); then reduce proofpower bonuses before touching raw
   weight. If no valid vector exists: previous epoch set continues for exactly
   ONE emergency epoch; a second consecutive failure HALTS finality (never
   normalizes an unsafe set).
6. Declared control clusters are conservatively aggregated for selection/cap
   TELEMETRY; unknown declarations treated as correlated. Hidden beneficial
   ownership is not consensus-verifiable: external G3–G5 audit gate (plan §6.5).
7. `membership_root` = SMT root (D-SMT-LEAF/NODE domains) over
   `validator_id → (consensus_bls_key, r_i, eff_i)`; snapshot is immutable for
   the epoch.

## 3. Justification and finality (ch01 §4.8; plan §6.6)

- `W_e^raw` = Σ r_i over the snapshot; `W_e^eff` = Σ eff_i (== raw at genesis).
- Thresholds EXACT integers: `Q = floor(2*W/3) + 1`, computed separately for
  raw and effective. Never a rounded "two thirds".
- Genesis checkpoint is justified and finalized.
- Target justified ⇔ one signer set links an already-justified source to it
  with raw ≥ Q_raw AND eff ≥ Q_eff. The dual threshold can only strengthen the
  raw quorum, never substitute for it (ch01 §4.10).
- Justified source finalized ⇔ its DIRECT CHILD checkpoint is justified from it.
- Finalized checkpoints and ancestors are irreversible by any fork-choice score.

## 4. Epoch randomness — delay-VRF commit/reveal mix (ch01 §4.9; plan §6.7)

Per epoch, over the snapshot membership:

1. COMMIT phase: each eligible witness submits exactly one commitment
   `c_i = H("NOOS/BEACON/COMMIT/V1" || chain_id || epoch_le || membership_root
   || validator_id || H(reveal_i))` before the frozen cutoff slot
   (cutoff constant: PROPOSED-G0, to be frozen with vectors). Duplicate or
   post-cutoff commits reject.
2. After the commit set FINALIZES: accept only the matching delay-VRF reveal
   for each commitment. Late, alternate, or mismatched reveals reject.
3. Mix: deterministic membership-ordered fold
   `R_e = H("NOOS/BEACON/MIX/V1" || chain_id || epoch_le || membership_root ||
   bitmap || prev_finalized_certificate_digest || m_1 || … || m_n)` where
   `m_i = reveal_i` if revealed else `committed_hash_i`. A missing reveal thus
   contributes its already-committed hash and incurs the frozen penalty
   (value ODR-WITNESS-002 family) — withholding cannot select among outputs
   after seeing peers (ch01 §4.9).
4. Persistence: commit/reveal safety state persists via the noos-store
   durability barrier BEFORE any beacon message is emitted (persist-before-vote
   generalization, plan §6.7). Crash/reorg/withholding at every cutoff is a
   mandatory test matrix.
5. Consumers see `R_e` only after its carrying certificate finalizes.

## 5. Liveness degradation (ch01 §4.9)

If either threshold fails: Ground blocks continue unfinalized; clients expose
`unsafe_head` / `justified_head` / `finalized_head` separately (RPC contract,
plan §13.3); finality-gated actions pause; after the inactivity delay
(ODR-WITNESS-003) a deterministic leak reduces nonvoter weight for FUTURE
epochs only — no certificate is ever fabricated for the current epoch; recovery
requires a later certificate under a legitimately derived membership root.
No administrator signature finalizes anything.

## 6. Handover, sync, and recovery (plan §6.7)

Reconfiguration handover binds (chain_id, epoch, old membership_root, new
membership_root, finalized checkpoint) under a registered domain. Historical
validator sets are retained for certificate verification at any height.
Malformed persisted history STOPS startup (typed fatal), never resets safety
state. Duplicate certificate ingestion short-circuits on content digest.

## 7. Genesis controls (constants-v1.toml [genesis_controls])

`witness_proofpower_bonus_enabled=false`; effective weight ≡ raw weight;
the proofpower code path exists only behind the flag and a compile-time
zero-cap assertion (plan §6.8: state-transition checks enforce the theoretical
caps even while production remains zero).
