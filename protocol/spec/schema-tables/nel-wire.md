# NEL wire schema table (G0 freeze candidate)

Source: `C:/tmp/noosphere/05-neural-lane.md` §2 (normative object layouts, widths as
printed) plus the binding plan §10.2–§10.3 wire-law resolutions. Domains:
`"NOOS/NEL/<OBJECT>/V1"`, hashes 32-B domain-separated, integers fixed-width LE, no
varints, signatures Ed25519 64 B over the domain-separated body hash, quorum =
ordered pair of signatures from distinct committee members (ch05 §2.1).

Plan §10.3 field-width resolutions (normative): `t: u32`, `rng_cursor: u64`,
`dispute_id: Hash32` (never truncated), challenger key 32 B Ed25519, `round: u16`,
`position: u32`. No implicit collection length anywhere.

## ModelManifest — 240 B body (ch05 §2.2, widths src)

`model_id = H("NOOS/NEL/MANIFEST/V1" || body)`

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `architecture_hash` | 32 | layer graph, shapes, GQA config |
| 1 | `tokenizer_root` | 32 | merges, vocab, normalization pin, invalid-UTF-8 rule |
| 2 | `weight_root` | 32 | Merkle root over 4–16 MiB content-addressed shards |
| 3 | `shard_erasure_params` | 8 | `shard_size u32`, `data_shards u16`, `parity_shards u16` |
| 4 | `numeric_profile_id` | 32 | frozen N-PROFILE hash |
| 5 | `circuit_id` | 32 | all-zero until Phase C admits one |
| 6 | `reference_interpreter_hash` | 32 | referee semantics |
| 7 | `max_context` | 4 | u32; 1,024 in Phases A–B |
| 8 | `max_generation` | 4 | u32; 128 in Phases A–B |
| 9 | `activation_table_root` | 32 | exp2, SiLU, Q1.15 sin/cos, rsqrt seed LUTs |

## PromptJob (ch05 §2.3, widths src)

`job_id = H("NOOS/NEL/JOB/V1" || opening transaction)`

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `model_id` | 32 | immutable manifest reference |
| 1 | `prompt_commitment` | 32 | hash of canonical prompt token bytes |
| 2 | `prompt_blob_ref` | 32 | all-zero for P1/P2 privacy profiles |
| 3 | `privacy_profile` | 1 | u8: 0=P0_OPEN 1=P1 2=P2 3=P3 (declaration order) |
| 4 | `decoding_profile_id` | 32 | Phase B: greedy, ties → lowest token ID |
| 5 | `max_new_tokens` | 2 | u16; ≤ manifest `max_generation` |
| 6 | `fee_escrow` | 8 | u64 micro-NOOS |
| 7 | `committee_params` | 4 | `size u8 = 3`, `quorum u8 = 2`, `bond_class u16` |
| 8 | `challenge_period` | 4 | u32 blocks; ≥ 6 h protocol floor |

## TokenStateCommitment S_t (ch05 §2.4)

`S_t = H("NOOS/NEL/STATE/V1" || job_id || model_root || numeric_profile || t ||
token_history_root_t || kv_commitment_t || rng_cursor_t || trace_root_t)`

Preimage widths: `t` u32 (plan §10.3); `rng_cursor` u64 (plan §10.3; constant in
greedy Phase B); other components Hash32. `kv_commitment` binds logical KV
(recomputable — zero consensus DA bytes, N-KV-REPLAY).

## TokenClaim — naive/dispute-time form, 292 B (ch05 §2.5, widths src)

| # | Field | Bytes |
|---:|---|---:|
| 0 | `S_t` | 32 |
| 1 | `token_id` | 4 |
| 2 | `logits_commitment` | 32 |
| 3 | `S_t_plus_1` | 32 |
| 4 | `chunk_trace_root` | 32 |
| 5 | `TOPLOC_commitment` | 32 |
| 6 | quorum signatures | 128 |

## ChunkClaimV1 — exactly 1,634 B at the fixed T=32 (ch05 §2.5; plan §10.2)

Plan §10.2: `ChunkClaimV1` **always covers 32 tokens** and remains exactly 1,634 B.
A job ending on a 32-token boundary uses ordinary ChunkClaimV1 (plan §10.2).

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `S_start` | 32 | chain state before chunk |
| 1 | `S_end` | 32 | chain state after chunk |
| 2 | `chunk_trace_root` | 32 | root over 32 × 386 = 12,352 per-op commitments |
| 3 | `toploc_fingerprint` | 258 | ceil(32/32) × 258 [PAPER] |
| 4 | per-token records | 32 × 36 = 1,152 | `token_id` u32 (4) + `logits_root` (32) each |
| 5 | quorum signatures | 128 | 2-of-3 ordered pair |

Total: 32+32+32+258+1,152+128 = **1,634** (51.06 B/token).

## FinalChunkClaimV1 — 483 + 36 × token_count B (plan §10.2, normative)

Separately domain-tagged: `"NOOS/NEL/FINAL_CHUNK_CLAIM/V1"` (full chunk:
`"NOOS/NEL/CHUNK_CLAIM/V1"`) — both ASSIGNED in protocol/spec/crypto-domains-v1.csv
(IdentityFreeze registry, prefix-free verified). `token_count: u8 ∈
1..31`; 0 and 32 are **invalid** final counts. One 258-B TOPLOC fingerprint,
`token_count` 36-B records, two signatures.

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `S_start` | 32 | |
| 1 | `S_end` | 32 | |
| 2 | `chunk_trace_root` | 32 | root over token_count × 386 commitments |
| 3 | `token_count` | 1 | u8 in 1..31 |
| 4 | `toploc_fingerprint` | 258 | exactly one |
| 5 | per-token records | token_count × 36 | |
| 6 | quorum signatures | 128 | two signatures |

Fixed part: 32+32+32+1+258+128 = **483**. Canonical sizes: count 1 → **519 B**,
count 31 → **1,599 B** (plan §10.2 boundary vectors).

### Mandatory boundary vectors (plan §10.2)

| Job length | Claims |
|---:|---|
| 1 | one FinalChunkClaimV1(count=1), 519 B |
| 31 | one FinalChunkClaimV1(count=31), 1,599 B |
| 32 | one ChunkClaimV1 only |
| 33 | one ChunkClaimV1 + FinalChunkClaimV1(count=1) |
| 63 | one ChunkClaimV1 + FinalChunkClaimV1(count=31) |
| 64 | two ChunkClaimV1 only |

Wrong domain, size, count/record mismatch, duplicate position, reordered record,
extra fingerprint, truncation, or final/full substitution rejects identically in
Rust and Go (plan §10.2).

## AnchorTx (ch05 §2.8)

Permissionless; pays the D-dimension fee; `anchor_deadline_blocks` value is
UNRESOLVED_SOURCE (ODR-NEL-001, see constants-v1.toml).

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `job_id` | 32 | |
| 1 | `chunk_index` | 4 | u32 |
| 2 | claim | 1,634 or 483+36×tc | ChunkClaimV1 or FinalChunkClaimV1 |

## JobReceipt (ch05 §2.8, widths src)

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `job_id` | 32 | |
| 1 | `model_id` | 32 | |
| 2 | `prompt_commitment` | 32 | as opened |
| 3 | `token_history_root_final` | 32 | output as root; bytes retrievable from DA |
| 4 | `n_generated` | 2 | u16 |
| 5 | `finality_class` | 1 | u8 enum, declaration order: 0=SOFT 1=ANCHORED 2=ASSURED 3=ASSURED_TEE 4=PROVEN (ch05 §4.5) |
| 6 | `evidence_ptr` | 32 | per-class evidence pointer |
| 7 | `chunk_claim_refs_root` | 32 | Merkle root over anchored claim refs |
| 8 | `settlement_index` | 8 | u64 tranche-distribution record |

Class upgrades monotone SOFT → ANCHORED → ASSURED/PROVEN; a voided (slashed) chunk
is a terminal tombstone with refund semantics, never a downgrade (ch05 §4.5; plan
§10.6). SOFT cannot authorize irreversible value (plan §10.5).

## ExecutorRegistration (ch05 §2.9; widths PROPOSED-G0)

Lifecycle: REGISTERED → CONFORMANT → ELIGIBLE → (assigned) → EXITING → RELEASED.
Unbonding outlasts obligations: bond slashable until the last signed chunk's window
expires; RELEASED only with an empty live-window claim set.

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `executor_key` | 32 (PROPOSED-G0) | Ed25519 |
| 1 | `manifest_set` | Hash32 list, max 64 (PROPOSED-G0) | model_ids served |
| 2 | `declared_failure_domains` | bounded bytes, max 1024 (PROPOSED-G0) | operator, controller, cloud, ASN, region, client, hardware vendor |
| 3 | `conformance_cert_ref` | Hash32 | per manifest numeric profile |
| 4 | `bond` | u128 (PROPOSED-G0) | micro-NOOS |
| 5 | `exit_notice_height` | u64 (PROPOSED-G0) | zero while active |

## DisputeOpen (ch05 §2.6; widths per plan §10.3)

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `dispute_id` | 32 | Hash32 (plan §10.3; ch05's modeled 8-B id is superseded — no truncated dispute identifier) |
| 1 | `chunk_claim_ref` | 32 | |
| 2 | `challenger` | 32 | Ed25519 key (plan §10.3) |
| 3 | `challenger_bond` | 8 | u64 |
| 4 | `alleged_S_end` | 32 | commits challenger to a different end state pre-reveal |

## BisectMove (ch05 §2.6; widths per plan §10.3)

Forced moves; silence or missing DA within D=25 blocks loses. ch05's 200-B figure
is a [MODELED] calldata price with an 8-B dispute id; the canonical encoding below
supersedes it (plan §10.3).

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `dispute_id` | 32 | Hash32 |
| 1 | `round` | 2 | u16 (plan §10.3) |
| 2 | `position` | 4 | u32 (plan §10.3) |
| 3 | `child_commitment_left` | 32 | |
| 4 | `child_commitment_right` | 32 | |
| 5 | `signature` | 64 | Ed25519, mover |

## LeafReceipt (ch05 §2.6; envelope per plan §10.3)

Fixed canonical envelope whose proof bytes are **length-bounded by the verifier
registry**, not the old modeled 500-B estimate (plan §10.3). Verifier IDs are a
closed set: `EnvelopeV1`, `Risc0FreivaldsLeafV1`, `Risc0NonlinearLeafV1`, disabled
`SpecializedChunkV1` (plan §10.8).

| # | Field | Bytes | Notes |
|---:|---|---:|---|
| 0 | `dispute_id` | 32 | Hash32 |
| 1 | `verifier_id` | 4 (PROPOSED-G0) | u32, registry-scoped |
| 2 | `leaf_kind` | 1 (PROPOSED-G0) | u8: 0=GEMM Freivalds, 1=nonlinear direct-recompute |
| 3 | `journal_commitment` | 32 (PROPOSED-G0) | binds chain/model/profile/job/chunk/token/layer/op/span/dims/quantization/boundary/beacon/image/accept tuple (plan §10.8) |
| 4 | `proof_bytes` | u32-length-delimited, max = registry bound per verifier_id | unknown/malformed/wrong proofs reject without fallback to acceptance |

## Dispute geometry constants (ch05 §2.6, §5.2 — recorded in constants-v1.toml [nel])

386 ops/token-step; 12,352 leaves per T=32 chunk; 19 rounds / ~40 txs / ~8.1 KB at
T=32, D=25; 5-round LM-head column split; ≥6 h window; REPS=2 default (2⁻⁶⁴/span) /
REPS=4 production (2⁻¹²⁸/span), exact mod-2⁶⁴ integer Freivalds check.
