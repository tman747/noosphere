# Neural Execution Lane wire law v1

## Status and activation boundary

This document freezes NEL v1 canonical bytes. NEL is an application-settlement lane and does not reinterpret or accept any Ascent receipt, Cogitate, or verifier object. `neural_lane_enabled=false`; proposal credit, proofpower, duplex issuance, and witness bonuses are exactly zero. Code availability does not activate the lane.

First activation is limited to `P0_OPEN`, public prompt DA, registered model/profile 1 (the immutable 494,000,000-parameter test fixture), numeric profile 1 with a versioned SiLU table, greedy decoding with lowest-token-ID tie breaking, committee size 3 and quorum 2. Sampling, P1/P2/P3 privacy, other models/profiles, nonzero circuit IDs, and specialized chunk proofs reject; there is no downgrade.

All integers are fixed-width little-endian. Hashes and Ed25519 public keys are 32 bytes; signatures are 64 bytes. Decoders check total length before reading and reject trailing bytes. Signatures cover `BLAKE3-256(domain || canonical_body)`. Quorum signatures are from two distinct committee indices in strictly increasing order.

## Closed domains

| Object | Domain |
|---|---|
| ModelManifest | `NOOS/NEL/MANIFEST/V1` |
| PromptJob | `NOOS/NEL/JOB/V1` |
| TokenStateCommitment | `NOOS/NEL/STATE/V1` |
| TokenClaim | `NOOS/NEL/TOKEN_CLAIM/V1` |
| ChunkClaimV1 | `NOOS/NEL/CHUNK_CLAIM/V1` |
| FinalChunkClaimV1 | `NOOS/NEL/FINAL_CHUNK_CLAIM/V1` |
| AnchorTx | `NOOS/NEL/ANCHOR_TX/V1` |
| JobReceipt | `NOOS/NEL/JOB_RECEIPT/V1` |
| ExecutorRegistration | `NOOS/NEL/EXECUTOR_REG/V1` |
| DisputeOpen | `NOOS/NEL/DISPUTE/V1` |
| BisectMove | `NOOS/NEL/BISECT/V1` |
| LeafReceipt | `NOOS/NEL/LEAF_RECEIPT/V1` |
| EnvelopeV1 | `NOOS/NEL/ENVELOPE/V1` |

A signature or object under a sibling domain is invalid.

## Fixed objects

### ModelManifest — 240 bytes

In order: `architecture_hash[32]`, `tokenizer_root[32]`, `weight_root[32]`, `shard_size:u32`, `data_shards:u16`, `parity_shards:u16`, `numeric_profile_id[32]`, `circuit_id[32]`, `reference_interpreter_hash[32]`, `max_context:u32`, `max_generation:u32`, `activation_table_root[32]`. `model_id = H(MANIFEST domain || body)`. A manifest is immutable; any interpreter, table, tokenizer, weight, circuit, toolchain, or profile change creates a new ID. V1 activation requires `circuit_id=0`, context 1,024 and generation at most 128.

### PromptJob — 147 bytes

In order: `model_id[32]`, `prompt_commitment[32]`, `prompt_blob_ref[32]`, `privacy_profile:u8`, `decoding_profile_id[32]`, `max_new_tokens:u16`, `fee_escrow:u64`, `committee_size:u8`, `quorum:u8`, `bond_class:u16`, `challenge_period:u32`. P0 requires a nonzero public DA reference. `job_id = H(JOB domain || opening transaction)`. V1 requires size 3, quorum 2, greedy profile, and a challenge period at least the network conversion of six hours.

### TokenStateCommitment — 204-byte preimage

`job_id[32] || model_root[32] || numeric_profile[32] || t:u32 || token_history_root_t[32] || kv_commitment_t[32] || rng_cursor:u64 || trace_root_t[32]`. Its commitment is the STATE-domain hash. `t` is never truncated and `rng_cursor` is fixed `u64`.

### TokenClaim — 292 bytes

`S_t[32] || token_id:u32 || logits_commitment[32] || S_t+1[32] || chunk_trace_root[32] || TOPLOC_commitment[32] || signature_0[64] || signature_1[64]`.

### ChunkClaimV1 — exactly 1,634 bytes

T is fixed at 32. In order: `S_start[32]`, `S_end[32]`, `chunk_trace_root[32]`, exactly one `toploc_fingerprint[258]`, exactly 32 ordered records each `token_id:u32 || logits_root[32]`, and exactly two signatures. Positions are implicit consecutive values beginning at `chunk_index*32`; no collection count is encoded. Body bytes are 1,506 and signatures are 128. Any other total length rejects.

### FinalChunkClaimV1 — exactly `483 + 36*token_count` bytes

Separately tagged from a full claim. In order: `S_start[32]`, `S_end[32]`, `chunk_trace_root[32]`, `token_count:u8`, exactly one `toploc_fingerprint[258]`, exactly `token_count` ordered records each `token_id:u32 || logits_root[32]`, and two signatures. `token_count` is 1..31. Counts 0 and 32, count/length disagreement, duplicate/reordered positions, a second fingerprint, truncation, trailing bytes, or full/final substitution reject. A generation ending at a multiple of 32 uses only full claims.

Boundary law: lengths 1 and 31 use final claims of exactly 519 and 1,599 bytes; 32 uses one full claim; 33 uses one full plus a 519-byte final claim; 63 uses one full plus a 1,599-byte final claim; 64 uses two full claims.

### AnchorTx and JobReceipt

`AnchorTx = job_id[32] || chunk_index:u32 || claim_kind:u8 || canonical_claim`, with `claim_kind=0` full and `1` final. Kind and remaining job length must agree. Anchoring is permissionless but signature-authorized. Missing the class-specific `anchor_deadline_blocks` is committee timeout; never anchoring cannot defer a challenge clock.

`JobReceipt = job_id[32] || model_id[32] || prompt_commitment[32] || token_history_root_final[32] || n_generated:u16 || finality_class:u8 || evidence_ptr[32] || chunk_claim_refs_root[32] || settlement_index:u64`. Finality values are `SOFT`, `ANCHORED`, `ASSURED`, and reserved `PROVEN`; v1 moves monotonically SOFT→ANCHORED→ASSURED. SOFT cannot authorize irreversible value and is outside the bond assurance claim. An ASSURED consumer must not exceed the job-class value ceiling.

## Registries, economics, and executor lifecycle

Model, numeric, decoding, verifier, and executor registries are insert-once. Unknown and disabled IDs reject. Numeric tables are versioned; especially, replacing the SiLU table creates a new numeric-profile ID/version. The first profile is the one registered 0.5B fixture and is not a claim that the real-model activation gates passed.

Every job class freezes `value_ceiling`, `dispute_cost_reserve`, and `bond_min`; checked arithmetic enforces `bond_min >= 2*value_ceiling + dispute_cost_reserve`, including aggregate simultaneous contract exposure. Escrows fund the complete challenger game. No NEL payment mints value.

Executor registration binds `executor_key[32]`, a bounded sorted nonempty manifest set, declared failure-domain root, conformance certificate reference, bond, and `exit_notice_height`. Lifecycle is REGISTERED→CONFORMANT→ELIGIBLE→EXITING→RELEASED, with terminal tombstones. Unbonding is blocked while any signed claim has an unexpired window. False independence declarations are slashable.

## Claims, DA, and lifecycle

Each token needs byte-identical 2-of-3 claims for SOFT. Replica mismatch automatically opens a dispute at the last common state and freezes only that job. Full/final claims anchor in consensus DA. Every anchored chunk separately records availability; the challenge clock runs only while required witness data is available. ASSURED requires expiry with no open dispute and availability for every anchored chunk. Terminal records become tombstones and cannot reactivate.

An objective executor fault invalidates the dependent tail from the first bad token, refunds affected escrow, assigns a fresh committee (not the old committee, from later finalized randomness), and re-executes only that tail. Unrelated jobs and base consensus continue.

## Disputes

`DisputeOpen` carries full `dispute_id:Hash32`, `chunk_claim_ref[32]`, `challenger_key[32]`, `challenger_bond:u64`, and `alleged_S_end[32]`. No truncated identifier is accepted.

`BisectMove` carries `dispute_id[32]`, `round:u16`, `position:u32`, left and right commitments, mover key, and Ed25519 signature. Forced descent is chunk→token→layer→op→leaf. The expected mover, exact round, and exact position are state-derived. Each move resets deadline `D=25` blocks. The deadline clock is suspended while required DA is unavailable and extended by exactly the unavailable interval. Silence or failure to reveal after availability is restored loses; there is no draw.

`LeafReceipt` binds dispute, token position, layer, op, and an `EnvelopeV1`. On objective executor fault, executor slash distribution is 50% challenger, 20% watch pool, 30% burn (integer remainder goes to burn), while affected job value is refunded. Challenger fault/timeout forfeits the challenger bond under the frozen job class.

## Closed verifier envelopes

`EnvelopeV1 = verifier_id:u8 || image_id[32] || public_input_hash[32] || proof_len:u32 || proof[proof_len]`. `proof_len` must not exceed the immutable registry maximum and must equal remaining bytes. Closed IDs are 1 `EnvelopeV1`, 2 `Risc0FreivaldsLeafV1`, 3 `Risc0NonlinearLeafV1`, and 4 `SpecializedChunkV1` (disabled). Unknown, disabled, malformed, oversized, wrong-image, wrong-public-input, and invalid proof bytes reject without fallback.

The implemented v1 receipt verifier performs strict Ed25519 verification by the immutable verifier key over the ENVELOPE-domain hash of `(verifier_id, image_id, public_input_hash)`; a proof is exactly one 64-byte signature. This is a real deterministic cryptographic envelope check, not a success placeholder. RISC Zero admission remains externally blocked until its bound guest/image evidence is registered. Leaf public inputs must bind chain, model, numeric profile, job, chunk, token, layer, op, span, dimensions, quantization, boundary, post-commit beacon, image, and accept tuple.

## Freivalds profiles

Vectors contain independent uniform 32-bit coefficients. Computation is the wrapping ring modulo `2^64`; dimensions and vector lengths are exact. `StandardReps2` has REPS=2 and the exact 2^-64/span label. `ProductionReps4` has REPS=4 and the exact 2^-128/span label and is mandatory for production NEL. The cheaper profile never silently satisfies the production profile. The beacon must finalize after the challenged commitment.

## Disabled gate evidence

The implementation exposes, but does not fake-pass: E-NEL-01 at least 10^9 cross-vendor instances with two CPU implementations and AMD/NVIDIA integer kernels and zero mismatch; E-NEL-02 real 0.5B accuracy; E-NEL-03 p95 <2s and p99 <5s token latency; E-NEL-04 measured 19-round/about-40-transaction/about-8.1KB dispute under six hours; E-NEL-05 99.9% retrieval for 30 days; and at least three independent operators plus two funded challengers. Until signed activation, all gate controls remain disabled.
