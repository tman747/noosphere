# Lumen object schema table (G0 freeze candidate)

Source of field lists: `C:/tmp/noosphere/01-architecture.md` §§6.1–6.10, §11.1 (verbatim).
Codec law (plan §3.1): fixed-width little-endian fields; variable collections are
canonical u32-length-delimited with explicit maxima; explicit `version` and numeric
tags on consensus objects; enum discriminants in declaration order; trailing bytes,
nonminimal atoms, and unknown mandatory fields reject.

Legend: **Tag** = object-family numeric tag. ch01 names the objects but assigns no
numeric tags or field widths; every value marked `PROPOSED-G0` is a sequential
assignment for review, not a corpus quotation. `Hash32` = 32-byte domain-separated
BLAKE3-256. Collection maxima marked PROPOSED-G0 are engineering bounds pending the
G0 review (ch01 §9.1 requires explicit maxima but numbers none).

## Object-family tag registry (all PROPOSED-G0)

| Tag | Object | Source of shape |
|---:|---|---|
| 1 | `LumenState` | ch01 §6.1 |
| 2 | `Note` | ch01 §6.2 |
| 3 | `Account` | ch01 §6.3 |
| 4 | `Object` | ch01 §6.4 |
| 5 | `TransactionV1` | ch01 §6.5 |
| 6 | `SignedIntentV1` | ch01 §6.5 |
| 7 | `ContractManifest` | ch01 §6.10 |
| 8 | `AgentID` | ch01 §11.1 |
| 9 | `CapabilityGrant` | ch01 §11.1 |
| 10 | `Intent` | ch01 §11.1 |
| 11 | `FeeAuthorization` | ch01 §6.3 (fields named in prose) |

## 1. LumenState (ch01 §6.1)

Six roots; versioned depth-256 sparse Merkle tree (depth per plan §4.2), canonical
key derivation, domain-separated leaf/node hashes, constant empty roots.
`receipts_root` is the post-state compact settled-receipt index (ch01 §6.1; plan §4.2).

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `notes_root` | Hash32 | unspent note commitments |
| 1 | `nullifiers_root` | Hash32 | spent/claimed nullifiers |
| 2 | `accounts_root` | Hash32 | nonce, keys, balances for fees/bonds |
| 3 | `objects_root` | Hash32 | contracts, registries, jobs, agents, governance |
| 4 | `receipts_root` | Hash32 | compact settled receipt index (post-state) |
| 5 | `params_root` | Hash32 | active parameters and feature controls |

## 2. Note (ch01 §6.2)

`note_id = H("NOOS/NOTE/V1" || creating_txid || output_index || canonical_note)`.
Immutable, consumed exactly once. Amounts public.

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `asset_id` | Hash32 (PROPOSED-G0) | |
| 1 | `amount` | u128 (PROPOSED-G0) | integer micro-NOOS |
| 2 | `lock_root` | Hash32 | balanced Merkle tree of spend conditions |
| 3 | `datum_root` | Hash32 | |
| 4 | `birth_height` | u64 (PROPOSED-G0) | |
| 5 | `relative_timelock` | u32 (PROPOSED-G0) | blocks |
| 6 | `memo_commitment` | Hash32 | |

Spend-condition leaf kinds (ch01 §6.2, declaration-order discriminants): 0 signature
threshold, 1 absolute/relative height+time bounds, 2 hash preimage, 3 proof-profile
verification, 4 object-state predicate, 5 provably unspendable burn.

## 3. Account (ch01 §6.3)

An account transaction consumes exactly `nonce+1`.

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `account_id` | Hash32 (PROPOSED-G0) | |
| 1 | `auth_descriptor` | bounded bytes, max 1024 (PROPOSED-G0) | crypto-agile multi-suite |
| 2 | `nonce` | u64 (PROPOSED-G0) | |
| 3 | `liquid_balances_root` | Hash32 | |
| 4 | `bond_refs_root` | Hash32 | |
| 5 | `metadata_commitment` | Hash32 | |
| 6 | `recovery_policy_root` | Hash32 | |

## 4. Object (ch01 §6.4)

Grain-controlled persistent state; undeclared reads trap.

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `object_id` | Hash32 (PROPOSED-G0) | |
| 1 | `class_id` | u32 (PROPOSED-G0) | registry-scoped |
| 2 | `owner_or_policy_root` | Hash32 | |
| 3 | `code_hash` | Hash32 | |
| 4 | `state_root` | Hash32 | |
| 5 | `version` | u64 (PROPOSED-G0) | exact prior version checked |
| 6 | `storage_words` | u64 (PROPOSED-G0) | rent metering (fee dim R) |
| 7 | `rent_deposit` | u128 (PROPOSED-G0) | micro-NOOS |
| 8 | `flags` | u32 (PROPOSED-G0) | |

## 5. TransactionV1 (ch01 §6.5)

`txid` commits the non-witness body; `wtxid` commits body + segregated witnesses
(domains owned by IdentityFreeze, crypto-domains-v1.csv).

| # | Field | Width | Collection max | Notes |
|---:|---|---|---|---|
| 0 | `chain_id` | Hash32 | — | |
| 1 | `format_version` | u16 (PROPOSED-G0) | — | |
| 2 | `expiry_height` | u64 (PROPOSED-G0) | — | |
| 3 | `fee_payer` | Hash32 (PROPOSED-G0) | — | account_id |
| 4 | `fee_authorization` | optional `FeeAuthorization` | — | tag 11 |
| 5 | `resource_limits` | 6 × u64 = 48 (PROPOSED-G0) | — | `{bytes, grain_steps, proof_units, state_reads, state_writes, blob_bytes}` (ch01 §6.5) |
| 6 | `note_inputs[]` | Hash32 each | 256 (PROPOSED-G0) | |
| 7 | `account_inputs[]` | Hash32 each | 64 (PROPOSED-G0) | |
| 8 | `object_access_list[]` | Hash32 + u8 rw-flag each | 256 (PROPOSED-G0) | undeclared reads trap |
| 9 | `actions[]` | bounded bytes each, max 65536 (PROPOSED-G0) | 64 (PROPOSED-G0) | typed actions, declaration-order discriminants |
| 10 | `outputs[]` | `Note` each | 256 (PROPOSED-G0) | |
| 11 | `evidence_refs[]` | Hash32 each | 64 (PROPOSED-G0) | |
| 12 | `witness_root` | Hash32 | — | segregated witness program roots |

## 6. SignedIntentV1 (ch01 §6.5)

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `tx_commitment` | Hash32 | excludes segregated witness bytes, includes witness program roots |
| 1 | `signer_scope` | u8 (PROPOSED-G0) | |
| 2 | `capability_ref` | optional Hash32 | |
| 3 | `signature_suite` | u16 (PROPOSED-G0) | unknown suites invalid |
| 4 | `signature` | bounded bytes, max 96 (PROPOSED-G0) | Ed25519 = 64 B; BLS = 96 B |

## 7. ContractManifest (ch01 §6.10)

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `code_hash` | Hash32 | |
| 1 | `abi_root` | Hash32 | |
| 2 | `storage_schema_root` | Hash32 | |
| 3 | `declared_jet_set` | Hash32 list, max 64 (PROPOSED-G0) | |
| 4 | `max_resource_vector` | 6 × u64 = 48 (PROPOSED-G0) | same axes as resource_limits |
| 5 | `upgrade_policy` | u8 enum (PROPOSED-G0) | new code hash + declared migration formula |
| 6 | `allowed_call_classes` | u32 bitset (PROPOSED-G0) | reentrancy may be disabled |
| 7 | `invariant_commitments` | Hash32 list, max 32 (PROPOSED-G0) | |
| 8 | `compiler_id` | Hash32 | |

## 8. AgentID (ch01 §11.1)

| # | Field | Width |
|---:|---|---|
| 0 | `agent_id` | Hash32 (PROPOSED-G0) |
| 1 | `genesis_manifest_root` | Hash32 |
| 2 | `controller_policy_root` | Hash32 |
| 3 | `active_key_root` | Hash32 |
| 4 | `model_refs_root` | Hash32 |
| 5 | `host_refs_root` | Hash32 |
| 6 | `capability_root` | Hash32 |
| 7 | `recovery_root` | Hash32 |
| 8 | `version` | u64 (PROPOSED-G0) |

## 9. CapabilityGrant (ch01 §11.1)

Attenuable, consumable, expiring, depth-limited, revocable (ch01 §11.1).

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `grant_id` | Hash32 (PROPOSED-G0) | |
| 1 | `issuer` | Hash32 (PROPOSED-G0) | |
| 2 | `subject_agent` | Hash32 (PROPOSED-G0) | |
| 3 | `allowed_action_schema_root` | Hash32 | |
| 4 | `object_scope_root` | Hash32 | |
| 5 | `per_action_limit` | u128 (PROPOSED-G0) | micro-NOOS |
| 6 | `cumulative_budget` | u128 (PROPOSED-G0) | micro-NOOS |
| 7 | `expiry_height` | u64 (PROPOSED-G0) | |
| 8 | `delegation_depth` | u8 (PROPOSED-G0) | |
| 9 | `revocation_nonce` | u64 (PROPOSED-G0) | |

## 10. Intent (ch01 §11.1)

Model output can only propose an Intent; deterministic policy gate checks schema,
prestate, capability, budget, postcondition. Direction is a typed action field
(donation/refund confusion regression is mandatory, ch01 §11.1).

| # | Field | Width |
|---:|---|---|
| 0 | `agent_id` | Hash32 (PROPOSED-G0) |
| 1 | `action_type` | u32 (PROPOSED-G0) |
| 2 | `canonical_arguments` | bounded bytes, max 65536 (PROPOSED-G0) |
| 3 | `finalized_prestate_root` | Hash32 |
| 4 | `expected_postcondition_root` | Hash32 |
| 5 | `budget` | u128 (PROPOSED-G0) |
| 6 | `deadline` | u64 (PROPOSED-G0) |
| 7 | `capability_ref` | Hash32 |
| 8 | `nonce` | u64 (PROPOSED-G0) |

## 11. FeeAuthorization (ch01 §6.3, fields from prose)

"signed FeeAuthorization with amount, resource ceiling, expiry, and transaction
commitment." Field order PROPOSED-G0.

| # | Field | Width |
|---:|---|---|
| 0 | `amount` | u128 (PROPOSED-G0) |
| 1 | `resource_ceiling` | 6 × u64 = 48 (PROPOSED-G0) |
| 2 | `expiry_height` | u64 (PROPOSED-G0) |
| 3 | `tx_commitment` | Hash32 |
| 4 | `sponsor` | Hash32 (PROPOSED-G0) |
| 5 | `signature_suite` | u16 (PROPOSED-G0) |
| 6 | `signature` | bounded bytes, max 96 (PROPOSED-G0) |
