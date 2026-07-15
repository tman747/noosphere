# World Wide Mind protocol identity v2

Status: **FROZEN W0 CANDIDATE / BLOCKED**. This document defines the protocol/API-v2 application contract. It does not pass G0, enable a lane, authorize valuable traffic, move model execution on chain, or authorize DNS cutover.

## 1. Version boundary and canonical codec

Protocol identity is `noos-protocol-identity-v2`; API and peer identity are v2-only. Production genesis contains no migrated WWM V1 state. A V2 decoder MUST reject V1 WWM bodies, capsules, custody records, aliases, API selectors, light-update protocol IDs, and peers before state lookup, signature verification, allocation, or model work. There is no compatibility decoder, `u32`-to-`Hash32` policy shim, old-name alias, version inference, or dual state. Historical V1 bytes remain governed only by `wwm-v1.md`.

Every body below begins with its stated little-endian fixed-width version/tag. Integers are unsigned little-endian. `Hash32`, SHA-256 values, keys, signatures, IDs, and bitmaps have fixed widths. A bounded vector is `u32 length || elements`; length and aggregate byte ceilings are checked before allocation. Maps and sets encode in the stated ascending key order. Duplicate keys/IDs, noncanonical order, integer overflow, unknown version/tag/discriminant, trailing bytes, invalid UTF-8, overlong strings, inconsistent embedded roots, and domain substitution reject the whole input. Decoders consume the entire input. `ResolutionProofV1` reuses the Lumen depth-256 sparse-Merkle proof and `D-SMT-LEAF`/`D-SMT-NODE`; it does not introduce another Merkle format.

Application model execution is always off chain. Consensus stores and validates only bounded immutable identities, policies, capability snapshots, custody/certificate records, controls, receipt/settlement commitments, and conservation state. Prompt, output, model weight, raw probe, execution trace, and full result bytes never enter consensus state.

## 2. Exact first capsule and artifact geometry

The only first-release model payload is `Bonsai-27B-Q1_0.gguf`, exactly 3,803,452,480 bytes, SHA-256 `17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0`. Codec profile is `RS-GF8-V1`, ID 1, with `k=8`, `m=4`, 12 positions, 454 stripes, 1,047,552 bytes per share, and 8,380,416 canonical source bytes per stripe. The last stripe has 7,124,032 actual bytes followed by exactly 1,256,384 zero bytes. There are 5,448 shares and each complete position is 475,588,608 bytes. A descriptor with a short final `original_bytes`, nonzero padding, a whole-artifact DA descriptor, a different hash/length/profile, or another model component rejects.

The identity graph is acyclic and ordered:

`payload bytes -> payload root and SHA-256 -> padded stripe/share/probe commitments -> position roots and manifest -> manifest root -> artifact descriptor/ID -> availability policy -> capsule -> lifecycle/alias`.

A certificate refresh changes no artifact, policy, or capsule identity. A policy change preserves payload/manifest/artifact but requires a new capsule. Every execution-affecting change requires a new execution profile and capsule; admitted jobs remain pinned.

## 3. Closed object registry

The `Domain ID` column is normative and refers only to generated entries in `protocol/spec/crypto-domains-v1.csv`; implementations MUST use generated `DomainId` values, never copied context strings.

### 3.1 Artifact and immutable model identity

| Canonical body | Version and exact ordered field set | Bound/invariant | Domain ID |
|---|---|---|---|
| `ArtifactShareCommitmentV1` | `version:u16=1, share_index:u8, share_bytes:u32, full_share_digest:Hash32, probe_root:Hash32` | index `0..11`; 1,047,552 bytes; depth-5 tree over exactly 32 ordered 32,736-byte leaves | `D-WWM-ARTIFACT-SHARE-V1` |
| `ArtifactStripeV1` | `version:u16=1, stripe_index:u32, descriptor:BlobDescriptorV1, actual_source_bytes:u32, padding_bytes:u32, share_commitments:[ArtifactShareCommitmentV1;12]` | contiguous index `0..453`; descriptor is namespace 3, original 8,380,416, shard 1,047,552, `8+4`, codec 1; actual+padding=8,380,416 | `D-WWM-ARTIFACT-STRIPE-V1` |
| `ArtifactManifestV1` | `version:u16=1, codec_profile_id:u16, source_bytes:u64, payload_root:Hash32, published_sha256:[u8;32], stripe_count:u32, stripes:Vec<ArtifactStripeV1>, position_roots:[Hash32;12]` | exactly 454 contiguous stripes; body excludes `artifact_id`; canonical body at most 1,047,552 bytes and global shard index `u32::MAX` | `D-WWM-ARTIFACT-MANIFEST-V1` |
| `ArtifactDescriptorV1` | `version:u16=1, kind:u16, media_type:BoundedUtf8<128>, source_bytes:u64, payload_root:Hash32, published_sha256:[u8;32], manifest_root:Hash32, codec_profile_id:u16, stripe_count:u32, license_root:Hash32, rights_root:Hash32, provenance_root:Hash32, publisher_key:Bytes32, published_height:u64, annotations:BoundedBytes<2048>, signer_set_root:Hash32, signatures:BoundedVec<SignatureEntry,32>` | excludes policy, certificate, capsule, and alias IDs; signatures strictly signer-ID sorted | `D-WWM-ARTIFACT-ID-V1` |
| `WeightManifestV1` | `version:u16=1, artifact_id:Hash32, gguf_version:u32, architecture:BoundedUtf8<64>, metadata_count:u32, metadata_table_root:Hash32, tensor_count:u32, tensor_table_root:Hash32, tensor_bounds_root:Hash32, dtype_quantization_root:Hash32, tokenizer_root:Hash32, special_token_root:Hash32, chat_template_root:Hash32, runtime_compatibility_root:Hash32` | no encoded-share geometry or replaceable inspector evidence | `D-WWM-WEIGHT-MANIFEST-V2-CONTRACT` |
| `WeightInspectionReceiptV1` | `version:u16=1, receipt_id:Hash32, weight_manifest_id:Hash32, artifact_id:Hash32, runtime_id:Hash32, inspector_id:Hash32, inspection_height:u64, result_root:Hash32, evidence_root:Hash32, signature:Bytes64` | append-only evidence; cannot change manifest/capsule identity | `D-WWM-WEIGHT-INSPECTION-V1` |
| `ModelCapsuleV2` | `version:u16=2, artifact_id:Hash32, payload_root:Hash32, manifest_root:Hash32, weight_manifest_root:Hash32, tokenizer_root:Hash32, chat_template_root:Hash32, runtime_id:Hash32, runtime_build_root:Hash32, sbom_root:Hash32, execution_profile_ids:BoundedVec<Hash32,8>, query_policy_id:Hash32, license_root:Hash32, rights_root:Hash32, provenance_root:Hash32, availability_policy_id:Hash32, lifecycle_policy_root:Hash32, rollback_root:Hash32, publisher_set_root:Hash32, publisher_threshold:u16, signatures:BoundedVec<SignatureEntry,32>` | execution-profile IDs strictly sorted and nonempty; V1 capsule never activates | `D-WWM-MODEL-CAPSULE-V2` |

Artifact payload, probe leaf/node, full-share, stripe, position, manifest and artifact-ID preimages use `D-WWM-ARTIFACT-PAYLOAD-V1`, `D-WWM-ARTIFACT-PROBE-LEAF-V1`, `D-WWM-ARTIFACT-PROBE-NODE-V1`, `D-WWM-ARTIFACT-SHARE-V1`, `D-WWM-ARTIFACT-STRIPE-V1`, `D-WWM-ARTIFACT-POSITION-V1`, `D-WWM-ARTIFACT-MANIFEST-V1`, and `D-WWM-ARTIFACT-ID-V1` respectively. A probe tree has exactly 32 leaves and no odd-node duplication rule.

### 3.2 Custody, availability, and capability snapshots

| Canonical body | Exact ordered field set | Bound/invariant | Domain ID |
|---|---|---|---|
| `CustodianProfileV2` | `version=2, profile_id, operator_key, beneficial_control_root, region_id, asn, provider_root, endpoint_root, software_lineage_root, capacity_bytes, staging_headroom_bytes, attestation_epoch, attestation_expiry, reviewer_id, reviewer_signature` | canonical body at most 512 bytes | `D-WWM-CUSTODIAN-PROFILE-V2` |
| `CustodianCapabilitySetV1` | `version=1, set_id, epoch, prior_set_id, entries` where entry is complete profile plus `Active|Suspended|Retired` and capability bitmap | at most 32 strictly profile-ID-sorted unique entries; each body at most 512; set at most 18,432 bytes; retired never returns | `D-WWM-CUSTODIAN-CAPSET-V1` |
| `AvailabilityPolicyV2` | `version=2, policy_id, artifact_id, manifest_root, position_count=12, data_positions=8, schedulable_min=9, assignment_root, region_min=4, region_max=3, asn_max=2, provider_max=3, challenge_period, max_probe_age, repair_deadline, evidence_retention, verifier_sample=8, verifier_threshold=5, verifier_capability_bit, reconstructor_sample=5, reconstructor_threshold=3, policy_start, policy_end` | uses `Hash32`; no V1 replica interpretation | `D-WWM-AVAILABILITY-POLICY-V2` |
| `CustodyCommitmentV2` | `version=2, commitment_id, policy_id, artifact_id, profile_id, position, position_root, bytes, obligation_start, obligation_end, set_id, set_epoch, nonce, signature` | one counted position per deduplicated profile; position `0..11` | `D-WWM-CUSTODY-COMMITMENT-V2` |
| `CustodyChallengeV2` | `version=2, challenge_id, policy_id, commitment_id, finalized_beacon, beacon_height, selected_probe_indices, issued_height, response_deadline` | indices canonical and derived only after commitment | `D-WWM-CUSTODY-CHALLENGE-V2` |
| `CustodyProbeV2` | `version=2, probe_id, challenge_id, commitment_id, profile_id, selected_leaf_digests, branch_root, result_root, observed_height, signature` | raw leaf/branches retained off chain; on-chain record is bounded commitment | `D-WWM-CUSTODY-PROBE-V2` |
| `AvailabilityCertificateV2` | `version=2, certificate_id, policy_id, artifact_id, custodian_set_id/epoch/root, executor_set_id/epoch/root, selected_verifier_ids[8], signer_ids[5], challenge/result root, assignment/diversity roots, issued_height, valid_until, signatures[5]` | selected/signers sorted and distinct; exact 5 of designated 8; `valid_until` is minimum of every policy, commitment, profile/attestation and probe horizon | `D-WWM-AVAILABILITY-CERTIFICATE-V2` |
| `ArtifactRepairOrderV1` | `version=1, order_id, artifact_id, policy_id, failed_position, replacement_profile_id, source_commitment_ids[8], source_positions[8], expected_position_root, issued_height, deadline, authority_epoch, nonce, signature` | eight distinct valid source positions; sorted pairs | `D-WWM-ARTIFACT-REPAIR-ORDER-V1` |
| `ArtifactRepairReceiptV1` | `version=1, receipt_id, order_id, replacement_commitment_id, durable_position_root, bytes_read, bytes_written, completed_height, evidence_root, signature` | becomes live only after durable verification, commitment, probes and fresh certificate | `D-WWM-ARTIFACT-REPAIR-RECEIPT-V1` |

Schedulability is closed: 9–12 live positions permits admission, exactly 8 permits emergency reconstruction/repair and completion of existing downloads only, and fewer than 8 is unavailable. Diversity caps are independently enforced after beneficial-control deduplication.

### 3.3 Execution, market, funds, jobs, and settlement

All IDs below are `Hash32`; all roots are `Hash32`; all signatures are fixed 64-byte Ed25519 unless their field explicitly names a threshold/aggregate scheme.

| Body | Exact ordered semantic fields | Canonical maximum | Domain ID |
|---|---|---:|---|
| `ExecutionProfileV1` | version, ID, capsule, tokenizer/template/runtime/build/SBOM roots, seed law, temperature, top-p, top-k, lowest-token-ID tie rule, context/output ceilings, attachment ceiling, cancellation/deadline law, evidence tier | 2,048 | `D-WWM-EXECUTION-PROFILE-V1` |
| `ExecutorProfileV1` | version, ID, operator/signing keys, beneficial-control/region/ASN/provider/software roots, attestation epoch/expiry, capability bitmap, normalized selection weight | 512 | `D-WWM-EXECUTOR-PROFILE-V2` |
| `ExecutorCapabilitySetV1` | version, set ID/epoch/prior ID, complete sorted profiles and lifecycle status | 18,432; at most 32 profiles | `D-WWM-EXECUTOR-CAPSET-V1` |
| `QueryPolicyV1` | version, ID, capsule/profile allowlists, total-context/input/output ceilings, no-attachment law, deadline, privacy/evidence/route/sponsor/refund laws | 2,048 | `D-WWM-QUERY-POLICY-V2` |
| `FeePolicyV1` | version, ID, asset, quote expiry, checked unit-price schedule, route/sponsor caps, refund and rounding laws, authority signatures | 2,048 | `D-WWM-FEE-POLICY-V1` |
| `FundProfileV1` | version, ID, five sorted liability rows, each row’s bucket, baseline liability, minimum horizon, coverage-origin height, signed coverage curve and route policy, signer set/epoch/signatures | 4,096 | `D-WWM-FUND-PROFILE-V1` |
| `FundRouteV1` | version, fund profile, bucket, payer, asset, route nonce and key preimage | 512 | `D-WWM-FUND-ROUTE-V1` |
| `FundTopUpPermitV1` | version, permit ID, payer, payer nonce, profile, bucket, amount, permit epoch, not-before/expiry, authority epoch/nonce/signature | 1,024 | `D-WWM-FUND-TOPUP-PERMIT-V1` |
| `FundMutationLockRefV1` | version, lock ID, operation `Activate|Close`, peer profile, execute-before height | 256 | `D-WWM-FUND-LOCK-REF-V1` |
| `FundMutationLockV1` | version, lock ID, operation, ordered profile IDs, two post-ref ledger roots, two permit epochs, authority epoch/nonce, expiry, `Pending|Consumed|Expired` | 1,024 | `D-WWM-FUND-LOCK-V1` |
| `WwmFundLedgerV1` | version, profile, `Staged|Current|Superseded|Closed`, exactly five sorted rows, each row’s deposited/reserved/paid/refunded/free/live-liability/funded-through/settlement-index values, topup permit epoch, optional lock ref | 4,096 | `D-WWM-FUND-LEDGER-V1` |
| `RunwayRequirementV1` | version, root, five sorted minimum baseline/horizon/free-coverage rows and evaluation height law | 1,024 | `D-WWM-RUNWAY-REQUIREMENT-V1` |
| `ServiceDirectoryV1` | version, ID, bounded region/endpoint/TLS/signing-key epochs, native/gateway/browser/update targets, not-before/expiry and authority signatures | 8,192 | `D-WWM-SERVICE-DIRECTORY-V1` |
| `WwmJobV1` | version, job ID, chain/genesis, quote and registry epochs, fresh salted/encrypted client commitment, capsule/execution/query IDs, input/output maxima, deadline, selected executor IDs, certificate ID, escrow/sponsor reservation, off-chain envelope root | 16,384 | `D-WWM-JOB-V1` |
| `WwmReceiptV1` | version, receipt/job/quote IDs, capsule/artifact/tokenizer/template/runtime/SBOM/profile IDs, token counts, final token-history/output roots, ordered signer/control-cluster IDs, evidence tier, availability/evidence horizons, anchor, metered/paid/refunded values, terminal code, signatures | 32,768 | `D-WWM-RECEIPT-V1` |
| `WwmSettlementV1` | version, settlement/receipt/job/fund-profile IDs, bucket, reserved/paid/refunded/released amounts, prior/new settlement index, ledger delta root, finalized height | 4,096 | `D-WWM-SETTLEMENT-V1` |

The genesis-only bootstrap installs exactly one threshold-signed `FundProfileV1`, one profile-keyed `Current` ledger, and registry fund epoch 0 while control is `Disabled`. The ledger has exactly five policy-bearing rows; every monetary counter, `live_liability`, settlement index, and `wwm_held_total` is zero; `topup_permit_epoch=0`; no lock exists. Production-capable policy has nonzero baseline and horizon for every row, so zero free balance derives `funded_through_height=None`. Account supply equals ledger supply plus `wwm_held_total`. No runtime action can invoke bootstrap.

Coverage cache law is deterministic checked integer arithmetic: each row derives free coverage from its immutable signed piecewise curve at `coverage_origin_height`, rounding down at each division. `live_liability=reserved`; funded-through is absent when free does not cover the first required unit. Every mutation recomputes and compares the cache. There is no shared row nonce: permits are replay-protected by `(payer, payer_nonce)` and profile permit epoch.

### 3.4 Control, alias, operational authorization, and recovery

| Body | Ordered semantic fields | Maximum | Domain ID |
|---|---|---:|---|
| `ServingAliasTransitionV1` | version, transition ID, alias, prior transition/capsule IDs, new capsule ID, expected control state, authority epoch/nonce/signature | 2,048 | `D-WWM-SERVING-ALIAS-TRANSITION-V1` |
| `RegistryEpochVectorV1` | version, vector ID, executor/custodian/fund tuple `(set/profile ID, epoch)`, prior vector ID | 512 | `D-WWM-REGISTRY-EPOCH-VECTOR-V1` |
| `CutoverSnapshotV1` | version, exact release/capsule/artifact/availability/execution/query/fee/fund/service/evidence roots, executor/custodian allowlists, epoch floors, certificate floors, five-row funding/conservation state, ledger indices/liability ceilings, exposure caps, rollback/compatibility roots | 10,240 | `D-WWM-CUTOVER-SNAPSHOT-V1` |
| `WwmAuthorizedConfigV1` | version, config/authorization/parent IDs and kind, tier, immutable release/G4/G5/capsule selectors, mutable fee/fund/service selectors, bounded capability allowlists, complete embedded runway and cutover bodies plus recomputed roots, compatibility/liability roots, signer set/epoch, activation coordinates, sorted signatures | 20,480 | `D-WWM-AUTHORIZED-CONFIG-V1` |
| `WwmControlStateV1` | version, singleton ID, `Disabled|Testnet|Canary|Production|EmergencyDisabled`, active capsule, last transition/height, direct-prior live state/config, active/latest-authorized/resolution config IDs, immutable release/ledger/capsule/artifact/availability/execution/query/runway IDs | 4,096 | `D-WWM-CONTROL-STATE-V1` |
| `WwmActivationTransitionV1` | version, transition ID, source/target, expected prior transition/config, selected config, activation height, exact G4 or G5 preimage root, authority epoch/nonce/signatures | 8,192 | `D-WWM-ACTIVATION-TRANSITION-V1` |
| `OperationalReconfigurationV1` | version/authorization ID, chain/genesis, exact tier, prior authorized/active config and control transition, finalized parent resolution height/transcript, unchanged immutable roots, change bitmap, exact old/new selectors and allowlists, target set roots/epochs/deltas, complete candidate config and changed fee/service/new-profile bodies, compatibility/liability/fee/exposure/value/certificate/funding/index/horizon floors, optional rollback-of, signer set/epoch, issued/not-before/expiry/activation heights, sorted signatures | 47,104 | `D-WWM-OPERATIONAL-RECONFIG-V1` |
| `CanaryRecoveryPreimageV1` | chain, genesis, release root, G4-start-record root, capsule, authorized config, runway, cutover, activation height | fixed | `D-WWM-CANARY-RECOVERY-PREIMAGE-V1` |
| `ProductionRecoveryPreimageV1` | chain, genesis, release root, passed G5-ledger root, capsule, authorized config, runway, cutover, activation height | fixed | `D-WWM-PRODUCTION-RECOVERY-PREIMAGE-V1` |
| `RecoveryAuthorizationV1` | version/ID, target-specific kind and preimage, emergency/direct-prior state/config/transition/heights, selected latest config and parent lineage, incident/evidence roots, signer set/epoch, issued/not-before/expiry/activation, sorted signer bitmap/signatures | 16,384 | `D-WWM-RECOVERY-AUTHORIZATION-V1` |

`resolution_config_id` equals `active_config_id` whenever an active config exists, including `EmergencyDisabled`. Authorizing a successor changes only `latest_authorized_config_id`. Only atomic `Activate`, `ApplyOperationalConfig`, or `Recover` advances active and resolution IDs. `Disabled -> Canary` is G4-only; `Canary -> Production` is signed G5-only. Recovery returns only to the direct-prior live tier and uses its target-specific preimage. Authorization/reconfiguration is nonpromoting and must be finalized and publicly retrievable for seven uninterrupted real days before apply; any body/floor change restarts the interval. Rollback is a new append-only successor, never a state rewind.

## 4. Closed action registry

The existing `ActionV1` envelope is retained. Discriminants 0–39 are historical. Exactly these 20 discriminants are appended and `ActionV1::VARIANT_COUNT` is exactly 60:

| Tag | Action | Closed payload |
|---:|---|---|
| 40 | `RegisterArtifactDescriptor` | one complete `ArtifactDescriptorV1` |
| 41 | `RegisterCustodianProfile` | tag 0 `InstallProfile`; tag 1 `TransitionCapability` |
| 42 | `RegisterAvailabilityPolicy` | one complete `AvailabilityPolicyV2` |
| 43 | `CommitCustodyPositions` | bounded sorted commitments |
| 44 | `RecordCustodyChallenge` | one `CustodyChallengeV2` |
| 45 | `RecordCustodyProbe` | one `CustodyProbeV2` |
| 46 | `IssueAvailabilityCertificate` | one `AvailabilityCertificateV2` |
| 47 | `RecordArtifactRepair` | tag 0 order; tag 1 receipt |
| 48 | `RegisterModelCapsuleV2` | one complete `ModelCapsuleV2` |
| 49 | `RegisterExecutionProfile` | one complete `ExecutionProfileV1` |
| 50 | `RegisterExecutorProfile` | tag 0 `InstallProfile`; tag 1 `TransitionCapability` |
| 51 | `RegisterFeePolicy` | one complete `FeePolicyV1` |
| 52 | `RegisterFundProfile` | tags 0–3 below |
| 53 | `RegisterQueryPolicy` | one complete `QueryPolicyV1` |
| 54 | `RegisterServiceDirectory` | one complete `ServiceDirectoryV1` |
| 55 | `OpenWwmJob` | one complete `WwmJobV1` |
| 56 | `RecordWwmReceipt` | one complete `WwmReceiptV1` |
| 57 | `SettleWwmJob` | one complete `WwmSettlementV1` |
| 58 | `TransitionServingAlias` | tag 0 only, below |
| 59 | `TransitionWwmControl` | tags 0–4 below |

Actions 41 and 50 use exactly:

- tag 0 `InstallProfile { profile, prior_set_id, authority_epoch, nonce, signature }`;
- tag 1 `TransitionCapability { profile_id, prior_set_id, prior_status, new_status, authority_epoch, nonce, signature }`.

Install requires a new ID and initial `Active`. Transitions are only `Active -> Suspended|Retired` and `Suspended -> Active|Retired`; `Retired` is terminal. Exact prior-set compare-and-swap, monotonic epoch, role authority, unused nonce, whole-input signature, and atomic set advance are mandatory.

Action 52 uses exactly:

- tag 0 `StageFundProfile { profile, prior_current_id, authority_epoch, nonce, signature }`;
- tag 1 `LockFundMutation { operation:Activate|Close, source_profile_id, other_profile_id, prior_source_permit_epoch, prior_other_permit_epoch, execute_before_height, authority_epoch, nonce, signature }`;
- tag 2 `ActivateFundProfile { profile_id, prior_current_id, lock_id, locked_current_ledger_root, locked_candidate_ledger_root, minimum_horizon, authority_epoch, nonce, signature }`;
- tag 3 `CloseFundProfile { profile_id, current_profile_id, lock_id, locked_source_ledger_root, locked_current_ledger_root, destination_route, authority_epoch, nonce, signature }`.

A lock acquisition increments both permit epochs, writes only acyclic lock refs into both ledgers, then stores a separate lock containing both post-ref roots. At most one global pending mutation lock exists. Locked ledgers reject every other write except exact completion or deterministic expiry. `Staged` accepts permitted checked top-ups, lock and close only. `Superseded` accepts permitted top-up plus settlement/release/refund for pinned obligations, never new reservations. `Closed` is immutable.

Action 58 has only tag 0:

`TransitionServingAlias { alias, prior_transition_id, prior_capsule_id, new_capsule_id, expected_control_state, authority_epoch, nonce, signature }`.

It is legal only in `Disabled|Testnet`, requires exact alias CAS, and never enables service. Once control has ever entered `Canary`, every action 58 rejects, including same-target rewrites and `EmergencyDisabled`.

Action 59 uses exactly:

- tag 0 `Activate { transition, config }`;
- tag 1 `EmergencyDisable { expected_state, expected_config, incident_root, authorization }`;
- tag 2 `AuthorizeOperationalConfig { reconfiguration }`;
- tag 3 `ApplyOperationalConfig { authorization_id, expected_active_config_id }`;
- tag 4 `Recover { recovery_authorization }`.

Every tag has its dedicated body/signature domain, exact source/target/CAS, authority epoch, replay protection, whole-input encoding, and atomic no-op on failure. Generic governance cannot enable, recover, mutate aliases, or substitute configuration.

## 5. Finalized resolution contract

`resolve_finalized_capsule(selector, freshness_bound) -> FinalizedModelResolutionV1` and `/model-resolution/<selector>` return at most 262,144 canonical bytes. The result binds chain/genesis, exact selector/freshness bound, resolution height, finalized `BlockHeaderV1`, checkpoint identity/material, terminal finality proof, and at most 17 strictly state-key-sorted duplicate-free `ResolutionProofV1` entries.

The alias path has exactly these possible leaves, in state-key order: (1) alias transition, (2) control, (3) config named by `resolution_config_id`, (4) capsule, (5) artifact descriptor, (6) availability policy, (7) current-certificate pointer, (8) certificate, (9) registry epoch vector, (10) executor capability set, (11) custodian capability set, (12) execution profile, (13) query policy, (14) fee policy, (15) fund profile, (16) ledger keyed by that exact fund profile, and (17) service directory. Each is `Absent` or `Present(bounded canonical value)` with the existing depth-256 proof to the terminal `objects_root`.

Sub-budgets are closed: proof envelopes/siblings excluding values at most 147,968; both capability sets at most 36,864; active authorized config at most 20,480; all other present values at most 20,480; terminal/checkpoint/finality/container at most 24,576. Verification order is trust anchor, complete light history, terminal finality/freshness/selector, proof to objects root, inclusion/non-inclusion, bounded decode, control/config key binding, embedded runway/cutover roots, authorization/tier/parent, sets and lifecycle, fund policy/ledger conservation and cache, object IDs/references, certificate, registry epochs, allowlists/floors, alias/control.

`resolve_authorized_config(config_id, freshness_bound) -> AuthorizedConfigResolutionV1` and `/authorized-config/<config_id>` return at most 393,216 bytes. It contains one complete parent `FinalizedModelResolutionV1` at the authorization-bound parent height and an `AUTHORIZED_NOT_ACTIVE` candidate section proved at the current terminal header. The candidate adds at most three state proofs: authorization, optional staged fund profile, optional staged ledger. Additional proof envelopes/siblings are at most 27,648; reconfiguration value at most 47,104; optional fund values combined at most 8,192. Candidate selectors never substitute into normal-resolution leaves.

## 6. Light-client update protocol

The priority protocol is exactly `/noos/sync/light-update/2`; `/noos/sync/range/1` remains headers-only. `LightUpdateRequestV1` is `version=1, chain_id, genesis_hash, start_height:u64, max_items:u16`; `1 <= max_items <= 128`, and zero rejects before work/allocation. A batch is at most 128 ordered contiguous items and verification is batch-memory-bounded.

Each `LightUpdateItemV1` is at most 262,144 canonical bytes: `BlockHeaderV1` at most 65,536; compact extracted finality certificate material at most 32,768; `LightMembershipSnapshotV1` plus handover/rotation evidence at most 155,648; item tags, lengths and wrapper at most 8,192. Full block bodies, bonds, telemetry, model bytes, and unbounded history are forbidden.

`LightMembershipSnapshotV1` fields are `version=1, epoch:u64, membership_root:Hash32, raw_total:u128, effective_total:u128, members:BoundedVec<LightMemberV1,4096>, handover_root:Hash32`; each member is `validator_id, bls_key, raw_weight, effective_weight, status, activation/retirement heights`. IDs are strictly sorted and totals recompute exactly. Every update verifies parent/source/target ancestry, justified history, membership root, raw/effective quorum, aggregate BLS signature, rotation/handover, emergency continue-or-halt law, and nonregressing height/finality.

## 7. Transaction and carrier bounds

Existing `BoundedBytes<65536>` action/call arguments remain. A transaction is accepted only when `tx_bytes.len + witness_bytes.len <= 65,532`. `TxPushV1.tx` is exactly `u32 tx_len || tx_bytes || witness_bytes`, so the prefixed carrier is at most 65,536 bytes. No nested length, action wrapper, or signature is exempt.

An operational-authorization transaction contains exactly one action 59. `OperationalReconfigurationV1 <= 47,104`; action/tag wrapper `<=2,048`; every remaining transaction/access/witness byte combined `<=16,380`; total `<=65,532`. Oversize rejects before allocation, hashing, signature work, mempool admission, relay, or state access. Unknown action 60+, unknown nested payload tag, trailing byte, mixed V1 body, and a v2 transaction announced by a v1 peer all reject.

## 8. Security and negative-vector requirements

The mandatory cross-language negative suite covers missing/wrong/self/cyclic predecessor; V1/V2 protocol/API/peer/chain/genesis substitution; old WWM bytes; every unknown object/action/payload/tag; malformed lengths and every exact bound plus one; unordered/duplicate IDs and proofs; stale CAS/epoch/nonce/parent; illegal capability resurrection; fund cache/conservation/permit/lock races; candidate substitution into normal leaves; alias mutation after G4; authorize-only live mutation; generic-governance activation; wrong recovery tier/preimage; incomplete light history; and fabricated `PASS` without complete evidence, exact authorization record, pinned external keys, and valid signatures.

Current real state is intentionally BLOCKED at G0 through G5. Evidence manifests keep `controls_enabled=false` and `promotion_effect=NONE`; only a separate exact signed G5 authorization may permit the later control and DNS ceremonies.
