# World Wide Mind application protocol v1

Status: `EXPERIMENTAL_G0`. Every WWM execution, privacy, browser, knowledge-training, and model-activation control remains disabled until its claim-specific gate passes. This schema adds application objects; it does not change NOOSPHERE protocol identity, the frozen p2p v1 protocol list, proposal weight, finality weight, issuance, or validator hardware requirements.

Authority: `docs/world-wide-mind-architecture-and-rd-plan.md`.

## 1. Global law

- All fixed integers are little-endian.
- All hashes and public keys are exactly 32 bytes.
- All signatures are exactly 64 bytes.
- Every object begins with `version:u16 = 1`.
- Every byte string is `length:u32 || bytes`, with the object-specific maximum enforced before allocation.
- Every vector is `count:u16 || elements`, with the object-specific maximum enforced before allocation.
- Sets are encoded in strict ascending byte order without duplicates.
- Maps are encoded as strict ascending key/value pairs without duplicate keys.
- UTF-8 strings must be valid, NFC normalized, contain no NUL, and fit the object-specific byte limit.
- Decoders reject unknown enum discriminants, trailing bytes, duplicate set/map entries, noncanonical ordering, zero IDs where forbidden, and arithmetic overflow.
- IDs are `BLAKE3-256(domain || canonical_body_without_id)`. The domain bytes are literal UTF-8 and include the terminating version component shown below.
- A signature covers `NOOS/SIG/WWM/V1 || object_domain_id || object_id || canonical_body`. The closed `D-SIG-WWM` Ed25519 domain is common, while the included object-domain ID prevents every sibling-object substitution.
- Object registration is insert-once by ID. A lifecycle transition is a separate immutable object; it never mutates the registered body.
- Raw prompts, outputs, private MindLinks, browser history, cookies, route logs, secret keys, model weights, and training examples are never consensus objects.

## 2. Domain registry

| Object | ID domain |
|---|---|
| `ModelCapsuleV1` | `NOOS/WWM/MODEL-CAPSULE/V1` |
| `WeightManifestV1` | `NOOS/WWM/WEIGHT-MANIFEST/V1` |
| `ExecutorProfileV1` | `NOOS/WWM/EXECUTOR-PROFILE/V1` |
| `QueryPolicyV1` | `NOOS/WWM/QUERY-POLICY/V1` |
| `PrivateEnvelopeCommitmentV1` | `NOOS/WWM/PRIVATE-ENVELOPE/V1` |
| `MindLinkV1` | `NOOS/WWM/MINDLINK/V1` |
| `MindLinkTransitionV1` | `NOOS/WWM/MINDLINK-TRANSITION/V1` |
| `KnowledgeSnapshotV1` | `NOOS/WWM/KNOWLEDGE-SNAPSHOT/V1` |
| `RetrievalReceiptV1` | `NOOS/WWM/RETRIEVAL-RECEIPT/V1` |
| `EvaluationReportV1` | `NOOS/WWM/EVALUATION-REPORT/V1` |
| `ActivationProposalV1` | `NOOS/WWM/ACTIVATION-PROPOSAL/V1` |
| `ServingAliasTransitionV1` | `NOOS/WWM/SERVING-ALIAS/V1` |
| `RouteDescriptorV1` | `NOOS/WWM/ROUTE-DESCRIPTOR/V1` |
| `BrowserBuildManifestV1` | `NOOS/WWM/BROWSER-BUILD/V1` |
| `CapacityQuoteV1` | `NOOS/WWM/CAPACITY-QUOTE/V1` |

None of these domains may be used as a p2p protocol identifier. WWM transports run over existing transaction/blob protocols or a separately authenticated sidecar until a new protocol identity version is signed.

## 3. Bounded registries

### 3.1 Model capsules

`ModelCapsuleV1` fields, in order:

1. `version:u16 = 1`
2. `species_id[32]`
3. `revision_id[32]`
4. `parents:vec<hash32, max=8>`
5. `architecture_root[32]`
6. `weight_manifest_root[32]`
7. `tokenizer_root[32]`
8. `numeric_profile_id[32]`
9. `decoding_profiles:set<hash32, max=16>`
10. `context_policy_root[32]`
11. `reference_interpreter_root[32]`
12. `compiler_root[32]`
13. `runtime_root[32]`
14. `sbom_root[32]`
15. `conformance_suite_root[32]`
16. `independent_implementation_families:u8`
17. `license_root[32]`
18. `rights_root[32]`
19. `provenance_root[32]`
20. `evaluation_policy_root[32]`
21. `safety_policy_root[32]`
22. `privacy_profiles_bitset:u8` where bits 0..3 correspond exactly to P0..P3
23. `knowledge_policy_root[32]`
24. `tool_policy_root[32]`
25. `availability_policy_id:u32`
26. `minimum_custodians:u16`
27. `minimum_failure_domains:u16`
28. `activation_policy_root[32]`
29. `rollback_revision_id[32]`
30. `created_height:u64`
31. `expires_height:option<u64>` encoded as tag `0` or tag `1 || u64`
32. `publisher_keys:set<pubkey32, max=16>`
33. `publisher_threshold:u8`
34. `capsule_id[32]`
35. `signatures:vec<(publisher_index:u8, signature64), max=16>` with strictly increasing publisher indices

Nonzero roots are required. `parents` may be empty only for a root revision; otherwise it is strictly sorted. `decoding_profiles` and `publisher_keys` are nonempty and strictly sorted. `publisher_threshold` is in `1..=publisher_keys.len()`. `minimum_custodians >= 3`, `minimum_failure_domains >= 3`, and the latter cannot exceed the former. `independent_implementation_families >= 2` is required for execution-slashing eligibility but not for registration. Capsule registration does not activate a model.

### 3.2 Weight manifests

`WeightManifestV1` binds an ordered tensor table. Maximum tensors: 65,535. Maximum shards: 65,535. Each tensor row contains name (1..256 bytes), dimensions (1..8 positive `u32` values), dtype, quantization root, byte offset, byte length, and ordered shard span. Each shard row contains content root, byte length in 4..16 MiB for the registered NEL profile, erasure-profile ID, and reconstruction root. Tensor ranges must be nonoverlapping, increasing, and exactly cover the declared canonical weight byte length. Unknown dtypes and quantization profiles reject.

### 3.3 Executor profiles

`ExecutorProfileV1` binds operator key, payout account, control-cluster root, region (max 32 bytes), ASN, hosting root, hardware root, runtime/compiler roots, supported capsules (max 64), supported numeric/decoding/privacy profile bitsets, VRAM/RAM/storage capacities, ingress/egress limits, maximum context/output, prefill/decode concurrency, attestation policy root, capacity expiry, bond, and price schedule root. It has no proposal, finality, or issuance field.

An executor is eligible only while its profile is unexpired, bond is live, capsule is supported, availability preflight passes, and diversity constraints are satisfied. Self-reported hardware capacity is advisory until corroborated by signed receipts and probes.

### 3.4 Query policies

`QueryPolicyV1` binds a capsule, allowed knowledge snapshots (max 16), maximum prompt/attachment/context/output sizes, exact privacy profile, committee/backend rule, numeric and decoding profiles, tool-policy root, required finality class, challenge period, availability policy, fee schedule, maximum quote age, sponsor policy, refund policy, telemetry policy, and retention policy.

A policy with an unregistered or disabled privacy tuple rejects. A private policy cannot authorize public prompt DA, public retrieval, plaintext telemetry, cross-user cache, or direct-route fallback.

## 4. MindLink v1

The normative JSON interchange schema is `protocol/schemas/mindlink-v1.schema.json`. Consensus/application identity is derived from the canonical binary projection below, never from arbitrary JSON member order.

`MindLinkV1` bounds:

- title: 1..180 UTF-8 bytes;
- original text: 1..65,536 UTF-8 bytes for public/unlisted content; sealed content uses a nonzero encrypted-content root and an empty public original-text field;
- summary: 0..4,096 bytes and explicitly derived;
- language: 2..35 bytes;
- locale: 0..35 bytes;
- domain tags: at most 32, each 1..64 bytes, sorted and unique;
- source/evidence IDs: at most 64 each;
- relation edges: at most 256 total;
- authority statements: at most 16;
- predecessor/supersedes links: at most 16;
- contributor public key or blind-credential root: exactly one is nonzero;
- rights/license/cultural policy strings: at most 512 bytes each;
- challenge policy root and moderation namespace root: nonzero for public/unlisted content;
- lifecycle is one of `LOCAL_DRAFT`, `SUBMITTED`, `QUARANTINED`, `PROVENANCE_CHECKED`, `CHALLENGED`, `RETRIEVAL_ELIGIBLE`, `SNAPSHOT_CANDIDATE`, `SNAPSHOT_ACCEPTED`, `TRAINING_CANDIDATE`, `DATASET_ACCEPTED`, `REJECTED`, or `REVOKED_FUTURE_USE`.

`LOCAL_DRAFT` is never a chain object. Public visibility does not imply retrieval, training, commercial, or derivative-model permission. Revocation appends `MindLinkTransitionV1`; it never mutates or erases the original object.

Valid lifecycle transitions:

- `SUBMITTED -> QUARANTINED`
- `QUARANTINED -> PROVENANCE_CHECKED | REJECTED`
- `PROVENANCE_CHECKED -> CHALLENGED | RETRIEVAL_ELIGIBLE | REJECTED`
- `CHALLENGED -> RETRIEVAL_ELIGIBLE | REJECTED`
- `RETRIEVAL_ELIGIBLE -> SNAPSHOT_CANDIDATE | REVOKED_FUTURE_USE`
- `SNAPSHOT_CANDIDATE -> SNAPSHOT_ACCEPTED | REJECTED | REVOKED_FUTURE_USE`
- `SNAPSHOT_ACCEPTED -> TRAINING_CANDIDATE | REVOKED_FUTURE_USE`
- `TRAINING_CANDIDATE -> DATASET_ACCEPTED | REJECTED | REVOKED_FUTURE_USE`
- any nonterminal public state -> `REVOKED_FUTURE_USE`

No transition can leave `REJECTED` or `REVOKED_FUTURE_USE`.

## 5. Knowledge snapshots and retrieval

`KnowledgeSnapshotV1` contains snapshot ID, optional parent, sorted eligible MindLink IDs (max 1,000,000), sorted exclusion IDs, rights-policy root, normalization/chunking roots, optional embedding capsule/numeric profile, lexical/vector/graph/citation index roots, builder keys (max 16), builder threshold, availability certificate, challenge end height, activation height, optional retirement height, and rollback parent.

Every included MindLink must be `SNAPSHOT_ACCEPTED`, retrieval-permitted, rights-compatible, and absent from the exclusion set. Revoked IDs must appear in the first subsequent snapshot exclusion set. A snapshot cannot become active before its challenge end or before every required index has an availability certificate.

`RetrievalReceiptV1` binds job ID, snapshot ID, query commitment, retrieval policy root, ordered selected MindLink IDs (max 256), rank scores as signed fixed-point integers, citation spans, context root, builder/executor key, and signature. It proves selected context under a named procedure; it does not prove truth.

## 6. Private jobs

The only valid profile/mode/assurance tuples remain:

- `P0_OPEN / OPEN / P0_OPEN`
- `P1_ATTESTED / TEE / ASSURED_TEE`
- `P2_SEALED_WITNESS / COMPLETE_PRIVATE_RELATION / PROVEN`
- `P3_DEEP_SEALED / BESI_SPLIT_PROTOTYPE / ASSURED_SPLIT`

`PrivateEnvelopeCommitmentV1` contains job ID, chain ID, genesis hash, capsule ID, numeric profile, decoding profile, privacy profile, policy epoch, executor/backend identity root, route-policy root, quote ID, expiry, padding bucket, ciphertext root, client ephemeral public key, blinded prompt commitment, and client signature.

The encrypted envelope associated data is the canonical body through the padding bucket. A mismatch rejects before decryption. No profile downgrade exists. Missing attestation, revocation data, route, retrieval backend, or proof causes a terminal private-job error or refund—not P0 execution.

P1 receipts bind composite CPU/GPU measurement, binary/runtime/model/policy roots, vendor/firmware/revocation roots, fresh challenge, monotonic rollback counter, output ciphertext root, and expiry. They are exactly `ASSURED_TEE`; they are never NEL `ASSURED` or `PROVEN`.

## 7. Improvement and activation

`EvaluationReportV1` binds candidate revision, parent, evaluator key/control cluster, public suite root, hidden-suite commitment and reveal root, capability/safety/privacy/rights/conformance/performance metric roots, critical-failure bitset, conflict disclosure root, hardware/runtime roots, artifact root, and signature. A committed report is insert-once and cannot be deleted because it is unfavorable.

`ActivationProposalV1` contains candidate, parent, required report IDs, per-dimension hard-floor policy root, activation threshold, proposal height, challenge end, canary ceilings `[1, 5, 25, 50, 100]`, rollback triggers root, rollback parent, proposer key, evaluator-set root, activator-set root, and signatures. Proposer, trainer, evaluator, and activator control clusters must satisfy the registered separation policy.

`ServingAliasTransitionV1` changes only a serving alias pointer. It cannot mutate a revision. A forward transition requires the proposal, passed hard floors, elapsed challenge window, completed canary evidence, and activator threshold. A rollback transition may only target the proposal’s registered parent and must include a trigger report. Users may pin any available revision.

The model has no signing key or authority to change its policy, evaluator set, budget, tool permissions, activation threshold, or alias.

## 8. Browser and route objects

`RouteDescriptorV1` binds relay key, control cluster, transport (`DIRECT`, `OHTTP`, `ONION_MASQUE`, `MIX`, `REMOTE_TEE_BROWSER`), region, ASN, ingress/egress role, capacity, price root, padding policy, logging/retention roots, bond, valid epoch, and signature. Fast-private routes require non-common-control ingress/egress. Deep-private routes require a registered mix policy. A failed private route cannot become direct.

`BrowserBuildManifestV1` binds source revision, engine revision, dependency lock root, compiler/toolchain root, SBOM root, platform artifact hashes, independent builder keys/receipts, signer set and threshold, transparency root, rollout channel, expiry, minimum rollback counter, and rollback artifact. Invalid, stale, revoked, downgraded, or non-reproducible artifacts reject.

Native content security origins include scheme, publisher-key hash, and immutable content root/version. Shared path gateways never receive a native application origin. Wallet, local-vault, file, clipboard, camera, microphone, sensor, and agent capabilities are denied unless a local user-presence permission receipt explicitly grants a bounded scope.

## 9. Economics

All WWM payments are Work Loom application escrow. WWM objects cannot set issuance, Proofpower, proposal weight, or finality weight.

A capacity quote binds capsule, job bounds, model-load fee, prefill/decode unit prices, DA/evidence rate, verification rate, private-backend fee, route byte rate, storage byte-epoch rate, maximum total, expiry, worker profile, and signature. Settlement cannot exceed the signed maximum.

Objective faults may become slashable only after their zero-false-slash claim gate passes: deterministic wrong execution, equivocation, unavailable contracted evidence, model/runtime/profile substitution, quote/receipt replay, invalid attestation, false registered independence, and withheld contracted artifact. Answer quality, contested facts, and unattributable confidential-cohort underperformance are not slashable.

## 10. Activation controls

The following literals are load-bearing until signed gate promotion:

- `WWM_PUBLIC_INFERENCE_ENABLED = false`
- `WWM_P1_ENABLED = false`
- `WWM_P2_ENABLED = false`
- `WWM_P3_ENABLED = false`
- `WWM_MALICIOUS_3PC_ENABLED = false`
- `WWM_HFHE_ENABLED = false`
- `WWM_MODEL_ACTIVATION_ENABLED = false`
- `WWM_TRAINING_PROMOTION_ENABLED = false`
- `WWM_BROWSER_DEEP_ROUTE_ENABLED = false`
- `WWM_CONSENSUS_WEIGHT = 0`
- `WWM_FINALITY_WEIGHT = 0`
- `WWM_ISSUANCE = 0`

A source change alone cannot enable a control. Promotion requires an immutable claim/evidence bundle, exact revision binding, independent reproduction where required, owner authorization, and the applicable base plus WWM gate.
