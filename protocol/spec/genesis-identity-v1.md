# NOOSPHERE Genesis Identity Derivation — v1 (FROZEN except OWNER_BLOCKED items)

Status: FROZEN at G0 for all structure, ordering, widths, and domains; economic field
*values* marked `OWNER_BLOCKED` in `protocol/spec/constants-v1.toml` remain unfrozen and
block mainnet (plan §1.7, §2.5).
Authority: plan §2.4; ch01 §13.2 (genesis constants); ch08 §4.4 (Quiet Week, ceremony
run-of-show, the four genesis commitments); `protocol/schemas/identity-v1.md` §4;
`protocol/spec/crypto-domains-v1.csv` rows `D-GENESIS-PARAMS`, `D-CHAIN-ID`,
`D-GENESIS-FINAL`.

## 1. The two-stage, non-circular freeze

Identity is derived in two stages so that nothing hashed at stage 1 depends on anything
produced at stage 2. Stage 1 (Quiet Week, ≥ 7 days before genesis, ch08 §4.4) freezes the
parameter manifest and derives the chain ID. Only after that freeze does the ceremony
select a **published post-freeze Bitcoin block** and complete the multi-party DKG; stage 2
then derives the final genesis hash.

```
parameter_manifest_hash = H("NOOS/GENESIS/PARAMS/V1" || canonical(GenesisParameterManifestV1))
chain_id                = H("NOOS/CHAIN/V1"          || parameter_manifest_hash)
genesis_hash            = H("NOOS/GENESIS/FINAL/V1"  || chain_id
                                                     || bitcoin_anchor      (40 bytes, §5)
                                                     || dkg_root            (32 bytes, §6)
                                                     || canonical(FinalGenesisBodyV1))
```

`H` is **BLAKE3-256** over the byte concatenation shown: the exact ASCII bytes of the
registered domain context string (no NUL terminator, no length prefix — the domain table
is closed and prefix-collision-checked by `tools/inventory/check_domains.py`), followed by
the payload bytes. The three context strings are exactly the `crypto-domains-v1.csv` rows
`D-GENESIS-PARAMS` (`NOOS/GENESIS/PARAMS/V1`), `D-CHAIN-ID` (`NOOS/CHAIN/V1`), and
`D-GENESIS-FINAL` (`NOOS/GENESIS/FINAL/V1`).

`canonical(X)` is the deterministic `noos-codec` encoding defined field-by-field in §3
and §4: fixed-width little-endian scalars in the exact declared order, bounded
collections as canonical `u32` LE length followed by elements, no optional fields, no
map/dictionary forms, trailing bytes rejected. **A JSON or TOML serialization is never
hashed** — `protocol/genesis/*-parameters.toml` files are human-readable inputs that
tooling compiles into the canonical struct; two TOML files that compile to the same
canonical bytes are the same manifest.

Non-circularity invariants:

1. `GenesisParameterManifestV1` **excludes** the Bitcoin anchor, every DKG artifact, and
   all three derived hashes (`parameter_manifest_hash`, `chain_id`, `genesis_hash`).
2. `FinalGenesisBodyV1` **excludes** `genesis_hash` (its own digest) and does not repeat
   `chain_id`, `bitcoin_anchor`, or `dkg_root` as fields — those three are bound by the
   formula prefix, exactly once each.
3. Any change to a frozen stage-1 parameter **restarts Quiet Week and creates a new
   `chain_id`** (plan §2.4). There is no in-place amendment path.

## 2. Quiet Week and ceremony sequencing

Per ch08 §4.4 run-of-show, mapped onto the formulas:

| Step | Action | Artifact |
|---|---|---|
| T−7d | Freeze and publish `GenesisParameterManifestV1` (canonical bytes + the source TOML), claim-registry root, conformance-vector root, software manifest, reference miner. Publish `parameter_manifest_hash` and derived `chain_id`. | Countdown page shows the commitment hashes and nothing else |
| T−24h | Name the Bitcoin anchor block **the moment it is mined** — it MUST have height/time strictly after the stage-1 freeze publication, giving a verifiable no-earlier-than bound (ch08 §4.4 step 2; Nockchain import). | `bitcoin_anchor` (40 bytes, §5) |
| T−24h…T+0 | Complete the multi-party DKG under `D-BLS-DKG`/`D-BLS-FELDMAN` (ceremony CSPRNGs only, plan §3.2); publish commitments, shares, and the transcript root. | `dkg_root` (32 bytes, §6) |
| T+0 | Assemble `FinalGenesisBodyV1`, derive `genesis_hash`, produce the genesis block on stream; independent parties reproduce `genesis_hash` from published inputs (plan §14.5). | Genesis block |

## 3. `GenesisParameterManifestV1` — canonical layout

All scalars little-endian. Field order is normative and exhaustive; encoders emit exactly
these fields in exactly this order, decoders reject anything else (unknown, missing,
reordered, or trailing bytes). Widths in bytes.

| # | Field | Type / width | Content |
|---|---|---|---|
| 1 | `version` | `u16` (2) | Struct version, `= 1` |
| 2 | `chain_name` | bounded UTF-8: `u32` len (4) + bytes (≤ 64) | Human label, e.g. `noos-devnet-1`; a label, never an identity input elsewhere |
| 3 | `is_test_network` | `u8` (1) | `0` mainnet, `1` test network (plan §2.5); no other value decodes |
| 4 | `asset_decimals` | `u8` (1) | `= 6` (micro-NOOS; identity-v1.md §1) |
| 5 | `slot_ms` | `u32` (4) | `6000` (constants-v1.toml `[ground]`) |
| 6 | `epoch_length` | `u32` (4) | `256` |
| 7 | `max_slot_skip` | `u32` (4) | `20` |
| 8 | `median_time_past_blocks` | `u16` (2) | `11` |
| 9 | `witness_membership_lookback_epochs` | `u16` (2) | `2` |
| 10 | `pulse_target_spacing_ms` | `u32` (4) | `6000` |
| 11 | `pulse_half_life_s` | `u32` (4) | `3600` |
| 12 | `max_future_drift_ms` | `u32` (4) | Devnet `12000`; mainnet value selected under E-WAN (`OWNER_BLOCKED`, constants-v1.toml `[ground]`) |
| 13 | `witness_n_max` | `u32` (4) | `256` |
| 14 | `witness_n_tail` | `u32` (4) | `32` |
| 15 | `witness_n_hard` | `u32` (4) | `1024` |
| 16 | `min_witness_bond_micro` | `u128` (16) | Integer micro-units. Test networks: valueless fixture; mainnet: `OWNER_BLOCKED` (constants-v1.toml `[witness]`) |
| 17 | `work_loom_credit_enabled` | `u8` (1) | `= 0` at genesis (precedence.md §2.4–§2.5) |
| 18 | `work_loom_weight_cap_permille` | `u16` (2) | `= 0` at genesis; protocol maximum `100` (0.10), unraisable ever (ch01 §12) |
| 19 | `witness_proofpower_bonus_enabled` | `u8` (1) | `= 0` at genesis |
| 20 | `umbra_suites_enabled` | bounded list: `u32` count (4) + `u16` suite IDs | `count = 0` at genesis (every suite disabled) |
| 21 | `dream_lane_enabled` | `u8` (1) | `= 0` at genesis (E-DREAM-02 KILLED) |
| 22 | `neural_lane_enabled` | `u8` (1) | `= 0` at genesis (ch04 §1 sixth control) |
| 23 | `reflex_lane_enabled` | `u8` (1) | `= 0` at genesis (Reflex v1 WITHDRAWN) |
| 24 | `class_gate_irreversible_budget` | `u64` (8) | `= 0` on every network (addendum A.4 leaves constants open) |
| 25 | `max_supply_micro` | `u128` (16) | Mainnet: `OWNER_BLOCKED` (constants-v1.toml `[emission]`); test networks: fixture |
| 26 | `emission_terminal_height` | `u64` (8) | Mainnet: `OWNER_BLOCKED` |
| 27 | `emission_table_root` | `Hash32` (32) | BLAKE3-256 root of the canonical integer per-height emission table/formula blob (ch01 §13.2); the blob itself is published beside the manifest |
| 28 | `recipient_share_ground_bp` | `u16` (2) | Basis points; the three shares MUST sum to 10000. Mainnet: `OWNER_BLOCKED` |
| 29 | `recipient_share_witness_bp` | `u16` (2) | Mainnet: `OWNER_BLOCKED` |
| 30 | `recipient_share_treasury_bp` | `u16` (2) | Mainnet: `OWNER_BLOCKED` |
| 31 | `rounding_rule_id` | `u8` (1) | Registered rule ID. Mainnet: `OWNER_BLOCKED` |
| 32 | `fee_disposition_id` | `u8` (1) | Registered disposition ID. Mainnet: `OWNER_BLOCKED` |
| 33 | `allocations_root` | `Hash32` (32) | Root of the canonical genesis allocation list (test networks: faucet fixture; mainnet: signed allocation, `OWNER_BLOCKED`) |
| 34 | `claim_registry_root` | `Hash32` (32) | Root over canonical `protocol/claims/registry.json` content — "the birth certificate lists the causes of death" (ch08 §4.4 commitment 2) |
| 35 | `conformance_vector_root` | `Hash32` (32) | Root over `protocol/vectors/` release set (ch08 §4.4 commitment 3) |
| 36 | `software_manifest_root` | `Hash32` (32) | Root over the published reference software manifest (source revision, toolchain locks, binary hashes — day-one miner parity, ch08 §4.4 Quiet Week) |

**Explicitly excluded** (normative): `bitcoin_anchor`, any DKG commitment/share/transcript
material, `parameter_manifest_hash`, `chain_id`, `genesis_hash`, timestamps, and every
post-freeze artifact. Fields 25–33 with `OWNER_BLOCKED` mainnet values are structural:
their widths and order are frozen now; a mainnet manifest cannot be encoded until the
signed `mainnet-parameters.toml` supplies the values, which is exactly the intended block.

## 4. `FinalGenesisBodyV1` — canonical layout

| # | Field | Type / width | Content |
|---|---|---|---|
| 1 | `version` | `u16` (2) | `= 1` |
| 2 | `parameter_manifest_hash` | `Hash32` (32) | Binds stage 1 (this is the *other* struct's digest; a struct may bind another struct's digest, never its own) |
| 3 | `genesis_time_ms` | `u64` (8) | Declared genesis timestamp (Unix ms); slot arithmetic origin (ch01 §4.2) |
| 4 | `dkg_suite_id` | `u16` (2) | Registered BLS suite (crypto-domains-v1.csv `D-BLS-DKG` family) |
| 5 | `dkg_group_pubkey` | bounded bytes: `u32` len (4) + bytes (≤ 192) | Ceremony threshold group public key (compressed) |
| 6 | `dkg_participant_set_root` | `Hash32` (32) | Root over the canonical ordered participant/commitment list |
| 7 | `genesis_witness_set_root` | `Hash32` (32) | Root over the canonical initial Witness Ring candidate snapshot |
| 8 | `genesis_state_roots` | 6 × `Hash32` (192) | Initial `LumenState` roots in frozen order: `notes_root`, `nullifiers_root`, `accounts_root`, `objects_root`, `receipts_root`, `params_root` (ch01 §6.1) |

**Explicitly excluded** (normative): `genesis_hash` (own digest), `chain_id`,
`bitcoin_anchor`, `dkg_root` — the latter three enter the `D-GENESIS-FINAL` preimage via
the formula prefix only, exactly once, in the order shown in §1. Raw DKG shares and any
secret material never appear in any hashed structure (plan §3.2).

## 5. `bitcoin_anchor` encoding — 40 bytes

```
bitcoin_anchor = block_height (u64 LE, 8 bytes) || block_hash (32 bytes)
```

`block_hash` is the Bitcoin block header's double-SHA256 digest in **internal byte order**
(the order the hash function emits, i.e. the display hex reversed). The anchor block MUST
be mined strictly after the stage-1 freeze publication (ch08 §4.4 step 2); verifiers check
height/time ordering against the published freeze artifact. The anchor proves the genesis
could not have been assembled earlier; it grants Bitcoin no authority over NOOSPHERE state.

## 6. `dkg_root` encoding — 32 bytes

`dkg_root` is the BLAKE3-256 root over the canonical DKG ceremony transcript (ordered
participant commitments, Feldman verification vector, complaint/resolution record, final
group public key), hashed under the registered domain row `D-DKG-TRANSCRIPT`
(`NOOS/DKG/TRANSCRIPT/V1`) in `crypto-domains-v1.csv`. Ceremony signatures and share
verification use `D-BLS-DKG` / `D-BLS-FELDMAN`. Deterministic dealer fixtures carry
`is_test_fixture = true` and cannot load on mainnet (plan §3.2;
`protocol/genesis/devnet-parameters.toml` `[dkg]`).

## 7. Binding and rejection

`chain_id`, and after the ceremony `genesis_hash`, are bound into **every** signature
preimage, proof statement, descriptor, node config, index database, wallet handshake,
release manifest (`protocol/release/manifest-template.json` fields
`identity.parameter_manifest_hash` / `identity.chain_id` / `identity.genesis_hash`), and
RPC `/api/status` response (plan §2.4, §13.3). Wrong-chain input fails **before** signing,
verification work, or any state read/write.

Historical artifacts — `mind`-HRP addresses, `ASCENT-*` DSTs, `ascent.*` domains, Ascent
chain IDs, genesis hashes, descriptors, snapshots, signatures, receipts, blocks — reject
with the stable error class `wrong_protocol_identity`, never auto-convert
(`protocol/schemas/identity-v1.md` §5; enforced by `tools/gates/check_identity.py`).

## 8. Vectors (due before Quiet Week)

Cross-language (Rust + independent Go) vectors MUST exist and agree byte-for-byte before
the stage-1 freeze (plan §2.4):

1. Positive: a complete valueless test manifest → canonical bytes → all three hashes;
   published as `protocol/vectors/genesis/params-v1-*.json` beside raw canonical-byte
   fixtures.
2. Field-order mutation: any two adjacent fields swapped → different bytes (no map form
   can mask ordering).
3. Exclusion proof: adding a `bitcoin_anchor` or `dkg_root` field to the manifest bytes →
   decoder rejects trailing/unknown bytes.
4. `bitcoin_anchor` byte order: one vector with a real historical block (height + both
   hex orders shown; internal order hashed).
5. Restart rule: a one-value parameter change → different `parameter_manifest_hash` and
   `chain_id` (no partial reuse).
6. Negative: JSON/TOML text hashed directly MUST NOT reproduce any published hash.
