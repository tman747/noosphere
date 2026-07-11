# Umbra v1 consensus schema

Status: base object/transition implemented; every experimental suite is fail-closed and disabled.

## Canonical scalar types

All integers are unsigned little-endian. `Commitment32`, `Nullifier32`, `SuiteId`, `ProofProfileId`, and `FiberId` are distinct 32-byte types; none is implicitly interchangeable. `KeyEpoch` is `u64`. Bounded vectors use canonical `u32` count followed by elements. Hashes are 32 bytes. Unknown fields, unknown versions, trailing bytes, unsorted set-like vectors, and duplicate entries reject.

## `UmbraFiberV1`

Field order: `fiber_id:FiberId`, `suite_id:SuiteId`, `owner_policy_root:Hash32`, `ciphertext_root:Hash32`, `circuit_root:Hash32`, `lineage_root:Hash32`, `rights_root:Hash32`, `privacy_budget:u64`, `key_epoch:KeyEpoch`, `realized_head:option<Commitment32>` (`u8` 0/1 then value), `branch_set_root:Hash32`, `version:u64`.

Umbra fibers are typed Lumen objects, not a second ledger. Large ciphertext bytes are DA objects whose committed root is stored here. No network-wide decrypt or bootstrap key exists. State has a dedicated ordered commitment accumulator and one global ordered nullifier set; their roots use `NOOS/UMBRA/COMMITMENT-ACCUMULATOR/V1` and `NOOS/UMBRA/GLOBAL-NULLIFIERS/V1`.

## `EncryptedTransitionV1`

Exact field order:

1. `fiber_id:FiberId`
2. `suite_id:SuiteId`
3. `previous_version:u64`
4. `previous_ciphertext_root:Hash32`
5. `previous_circuit_root:Hash32`
6. `program_manifest_root:Hash32`
7. `ordered_input_roots:vec<Hash32>`
8. `new_ciphertext_root:Hash32`
9. `new_circuit_root:Hash32`
10. `new_lineage_root:Hash32`
11. `key_epoch:KeyEpoch`
12. `rights_root:Hash32`
13. `privacy_budget_debit:u64`
14. `read_nullifiers:strictly-increasing vec<Nullifier32>`
15. `write_commitments:strictly-increasing vec<Commitment32>`
16. `resource_vector:{bytes:u64,verification:u64,reads:u32,writes:u32}`
17. `proof_profile_id:ProofProfileId`
18. `verifier_version:u32`
19. `verifier_hash:Hash32`
20. `proof_root:Hash32`
21. `proof:bounded bytes`
22. `authorization:bounded bytes`

The complete proof public-input tuple is domain `NOOS/UMBRA/ENCRYPTED-TRANSITION/V1` followed by every field above except proof bytes, with authorization length-delimited. The verifier may not select a subset. Validation order is exactly: (1) suite activation, exact registry key, canonical bounds; (2) exact prior fiber version and roots; (3) owner/capability authorization; (4) global nullifier freshness and commitment uniqueness; (5) rights and privacy budget; (6) deterministic resources; (7) two independent verifier implementations agree on the complete tuple; (8) atomic nullifier insertion, commitment insertion, and fiber root/version replacement. Any rejection leaves all roots and fibers unchanged.

## Suite registry and lifecycle

The registry key is exactly `(suite_id, proof_profile_id, verifier_version, verifier_hash, first_key_epoch, last_key_epoch)`. Its immutable value binds schema hash, verification-key hash, parameter hash, proof/input/nullifier/commitment maxima, resource maxima and cost, activation/retirement heights, suite kind, and an optional predeclared exit relation. Overlapping keys do not create fallback lookup: the transition supplies the exact suite/profile/version/hash and its epoch must be in that key's inclusive range. Unknown, disabled, malformed, wrong-epoch, incomplete, or disagreeing proofs reject atomically.

Historical registry entries and verifier artifacts are retained after retirement. Disable rejects new writes, does not invalidate finalized history, reveal plaintext, seize an object, or create an exit. Only an exit/migration relation registered before disable may remove or migrate a fiber.

Owner keys use purpose-separated HKDF-SHA256 over owner master material, fiber ID, and epoch. Backups are encrypted and salted. Workload DKG records participant public keys, threshold and transcript root; mainnet rejects any deterministic/embedded secret fixture. Epoch rotation is sequential and binds a new DKG transcript plus migration relation. Revocation records suite, epoch, effective height and compromise-evidence root. Migration proves old/new representation, key epochs, plaintext commitment equality and rights continuity. Each suite requires two independent verifier families to agree.

## Assurance and disabled experiments

Exact accepted triples are:

- `P0_OPEN / OPEN / P0_OPEN`
- `P1_ATTESTED / TEE / ASSURED_TEE`
- `P2_SEALED_WITNESS / COMPLETE_PRIVATE_RELATION / PROVEN`
- `P3_DEEP_SEALED / BESI_SPLIT_PROTOTYPE / ASSURED_SPLIT`

No literal aliases or strength ordering exists. Substitution rejects in contracts, wallet, RPC, indexer and explorer.

P1 TEE is an experimental disabled suite and must bind model root, numeric profile, measured binary, output commitment, job/policy, vendor, firmware, expiry and revocation. P2 is an experimental disabled transparent RISC Zero profile proving the complete private inference relation: prompt, model/profile, state chain, token/output commitments, padding, nonlinear/KV/logit/decoding work. Raw GEMM proofs and output wrappers are not P2. Optional Groth16 compression has no registry entry before independent setup/provenance audit. Neither suite can emit generic `ASSURED` or launder another profile.

`MALICIOUS_3PC` is disabled pending an audited MP-SPDZ malicious honest-majority backend, frozen preprocessing ceremony, authenticated shares/MAC and sacrifice, input consistency, selective-abort blame, complete private transformer relation, restart/epoch lifecycle, independent verifier and malicious-party harness. It never falls back to BESI. `HFHE_REFRESH` is disabled and has no suite registration pending a standard-assumption reduction, concrete parameters, compact repeatable refresh, public proof, independent implementation, and mutation/performance gates. No mock, signature-only, generic, or fallback verifier exists.

## BESI conformance boundary

BESI uses two additive shares in `Z/(2^64)`, separately authenticated ephemeral X25519/HKDF-SHA256/ChaCha20Poly1305 request and response channels, context and replay binding, and public-weight raw GEMMs only. The client reconstructs physically padded output and performs mandatory exact-Z Freivalds before true-row slicing/requantization. Public bucket is 128. Nonlinear, KV, logits and token work remain client-held. Public DA accepts ciphertext commitments/transcript/output roots but never either raw activation or accumulator share. Private adjudication is Ed25519-signed over job, ordered response-ciphertext commitments, output commitment, private-proof root, exact suite, verdict, epoch and nonce; it authenticates a confidential verdict and is not permissionless witness verification. BESI remains disabled until all gates in chapter 11 section 9 pass.
