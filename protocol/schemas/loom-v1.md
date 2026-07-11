# Work Loom v1

Status: application-settlement wire law. Work Loom has no consensus weight, issuance authority, or finality role. Binding negative result: `E-DEMAND-WASH-01`.

## Integer and hash law

All integers are unsigned little-endian at their stated width. `Hash32` and account identifiers are exactly 32 bytes. Collections use canonical `u32` element counts and ascending numeric IDs. Unknown enum tags, unknown or disabled registry IDs, duplicate IDs, trailing bytes, arithmetic overflow, or an out-of-bound collection reject before state mutation. Hash formulas concatenate exact fixed-width fields without separators.

Domains:

| Object | Domain |
|---|---|
| job ID | `NOOS/LOOM/JOB/V1` |
| worker commit | `NOOS/LOOM/WORKER-COMMIT/V1` |
| challenge | `NOOS/LOOM/V1` |
| receipt ID | `NOOS/LOOM/RECEIPT/V1` |
| artifact | `NOOS/TENSOR/ARTIFACT/V1` |
| challenge-bound work | `NOOS/TENSOR/WORK/V1` |
| paid delivery | `NOOS/LOOM/PAID-DELIVERY/V1` |

`H(domain, fields...) = BLAKE3-256(UTF8(domain) || fields...)`. `KH(key, domain, fields...) = BLAKE3-256-keyed(key, UTF8(domain) || fields...)`.

## Immutable registries

Registry ID zero is invalid. Every row is immutable after admission; changing source, compiler/toolchain, generated machine code, verifier, numeric profile, schema, policy, limits, or status requires a new ID. Governance may admit a new row or disable/quarantine new use; it cannot replace a row used by history.

* `WorkClass { id:u32, relation_root:Hash32, status:u8 }`
* `WorkerProfile { id:u32, source_root, compiler_toolchain_root, machine_code_root, hardware_root, status:u8 }`
* `ProofProfile { id:u32, verifier_root:Hash32, max_proof_bytes:u32, status:u8 }`
* `AvailabilityPolicy { id:u32, min_retrievers:u16, retention_blocks:u64, status:u8 }`
* `EvaluatorPolicy { id:u32, policy_root:Hash32, status:u8 }`
* `JobClass { id:u32, work_class_id:u32, relation_root, input_schema_root, output_schema_root, numeric_profile_root, allowed_worker_profiles, assurance:u8, confidentiality_flags:u8, proof_profile_id:u32, evaluator_policy_id:u32, availability_policy_id:u32, resource_bounds:ResourceVector, challenge_period:u64, minimum_worker_bond:u128, slashable:u8, status:u8 }`

`status`: 0 enabled, 1 disabled. `assurance`: 0 V0 delivery only, 1 V1 replication/statistical, 2 V2 deterministic optimistic dispute, 3 V3 succinct pinned relation. Confidentiality flags do not assert correctness. Disabled or unknown dependencies reject admission and use.

`ResourceVector = { bytes:u64, compute:u64, verification:u64, reads:u64, da_bytes:u64 }`; every measured component must be at most the job and class component.

## Objects

`WorkJob = { job_id, requester, class_id, input_root, model_or_program_root, delivery_pubkey, max_resources, fee_escrow:u128, evaluator_escrow:u128, opened_height:u64, commit_deadline:u64, submit_deadline:u64, expiry_height:u64, nonce:u64, state:u8 }`.

The ID excludes its own field:

`job_id = H(JOB, requester, class_id, input_root, model_or_program_root, opened_height, nonce)`.

Deadlines satisfy `opened < commit < submit <= expiry`. Opening atomically debits exactly `fee_escrow + evaluator_escrow` from the requester.

`WorkerCommit = { job_id, worker, implementation_profile:u32, input_root, worker_nonce_commitment, availability_plan_root, bond:u128, committed_height:u64 }`.

`worker_commit_hash = H(WORKER-COMMIT, fields in order)`. It must reference an enabled, class-allowed, non-quarantined worker profile and lock at least the class minimum bond before the commit deadline.

After this commit is finalized, derive:

`challenge = H(CHALLENGE, chain_id, job_id, worker_commit_hash, finalized_randomness_after_commit)`.

A challenge at or before `committed_height` is not finalized-after-commit and rejects.

`WorkReceipt = { receipt_id, job_id, worker_commit_hash, challenge, artifact_id, work_commit, output_commitment, encrypted_delivery_commitment, execution_evidence_root, proof_profile_id:u32, proof_bytes_or_blob_root, availability_root, resource_measurement, nullifier, worker_signature:Bytes64, correctness:u8, external_demand:u8, delivery:u8, quality_tag:u8, quality_score:u16 }`.

`receipt_id = H(RECEIPT, job_id, worker_commit_hash, challenge, artifact_id, output_commitment, encrypted_delivery_commitment, execution_evidence_root, nullifier)`. Nullifiers are globally unique.

The following fields are independent and MUST NOT imply one another:

* correctness: `UNVERIFIED`, `VERIFIED`, `REJECTED`;
* external demand telemetry: `INDEPENDENT`, `RELATED`, `SUBSIDIZED`, `UNKNOWN`;
* delivery: `COMMITTED`, `AVAILABLE`, `ACKNOWLEDGED`;
* quality: `NOT_EVALUATED` or a separately produced evaluator score.

`ArtifactID = H(ARTIFACT, canonical_tensor_descriptor, canonical_tensor_bytes)` is stable across jobs.

`WorkCommit = KH(challenge, WORK, ArtifactID, worker_profile_id:u32, trace_root)` changes with the finalized post-commit challenge. Cached content is not fresh work evidence.

`AvailabilityCertificate = { evidence_root, availability_root, retriever_count:u16, finalized_height:u64 }`. Roots must match the receipt and count must meet the immutable policy. Receipt submission never starts the dispute clock. `challenge_start` is exactly the finalized height of this valid certificate.

`PaidDeliveryCertificate = { job_id, requester_domain, worker_domain, evaluator_domain_or_zero, artifact_id, output_commitment, encrypted_delivery_commitment, delivery_ack_signature:Bytes64, payment_txid, independence_domains_root }`. Its commitment uses `PAID-DELIVERY` and the fields in order. Settlement does not require voluntary acknowledgment. Without a valid certificate, the job is not labeled externally consumed regardless of its demand telemetry.

## Lifecycle and ordering

`OPEN -> COMMITTED -> RUNNING -> SUBMITTED -> CHALLENGEABLE -> SETTLED`.

* `OPEN -> CANCELLED` only by the requester before commit.
* `OPEN -> EXPIRED` after the commit deadline.
* `COMMITTED|RUNNING -> EXPIRED` after submit deadline.
* `SUBMITTED -> EXPIRED` after expiry if availability never finalizes.
* `CHALLENGEABLE -> DISPUTED -> CHALLENGEABLE` when worker is upheld.
* `CHALLENGEABLE -> DISPUTED -> REJECTED` on objective worker fault.

Every terminal transition releases all escrow and bonds through a declared payout, refund, or burn. Terminal states never reactivate. One job's suspension, dispute, profile quarantine, expiry, or rejection does not suspend unrelated jobs.

## Escrow conservation

For every transition and asset:

`sum(liquid balances) + locked escrow + burned = genesis-funded supply`.

Opening and committing only move existing funds into locked escrow. Settlement splits requester escrow exactly among worker, verifier, evaluator, and DA provider, then unlocks worker bond. Expiry/cancellation refund all corresponding locks. Objective worker fault refunds requester escrow, returns challenger bond, and divides the worker bond according to the class dispute rule (including an explicit burn sink). Any split whose checked sum differs from the exact locked source rejects atomically. There is no mint path and useful work never changes scheduled issuance.

## Quarantine

Semantic divergence immediately quarantines the worker profile for new commits. Existing historical objects remain verifiable and existing jobs continue under their frozen class relation. Quarantine does not mutate other profiles, jobs, Ground, Braid, Lumen, or issuance.

## Shadow-only economics

Production constants are fixed false: `work_loom_credit_enabled`, `witness_proofpower_bonus_enabled`, and `duplex_issuance_enabled`. Production outputs of all calculators are exactly zero. Shadow calculators may compute counterfactual `L(b)`, proofpower, and duplex values only for experiments. Their outputs are telemetry and cannot enter a block header, fork score, Ring weight, finality threshold, balance, fee, or issuance transition. Zero jobs yields `L(b)=0`, proofpower zero, duplex zero, stake-only Ring behavior, and unchanged base issuance/finality.
