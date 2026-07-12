# Lumen v1 — typed authenticated public state (freeze document)

Status: **G0 freeze candidate**. Normative sources: `C:/tmp/noosphere/01-architecture.md`
§6 (state/notes/accounts/objects/envelope/execution/fees), §11.1 (agent objects),
§13.2 (fixed issuance); build plan §4; field tables in
`protocol/spec/schema-tables/lumen-objects.md`; domain registry
`protocol/spec/crypto-domains-v1.csv`; constants `protocol/spec/constants-v1.toml`
`[lumen]`/`[fees]`. Reference implementation: `crates/noos-lumen`. Conformance
vectors: `protocol/vectors/lumen/`.

All hashes are BLAKE3-256 over `context_string || parts...` with a registered
context (identical to `noos-crypto::hash_domain`). All encodings follow the
noos-codec law: fixed-width little-endian, u32-length-delimited bounded
collections, explicit `u16` version + numeric mandatory tags, declaration-order
enum discriminants, strict whole-input decode.

## 1. State roots

```
LumenState {
  notes_root,       // unspent note commitments
  nullifiers_root,  // spent/claimed nullifiers
  accounts_root,    // account records (nonce, keys, balance roots)
  objects_root,     // contracts, registries, jobs, agents, governance
  receipts_root,    // compact settled-receipt index (POST-STATE)
  params_root       // active parameters and feature controls
}
```

**Receipt-index semantics (normative).** `receipts_root` is the post-state
compact settled-receipt index: a map `txid → ReceiptV1` covering every
transaction ever settled (applied OR failed with the failure fee). It is NOT
the ordered list of receipts emitted by the current block; that list is a
separate block-body artifact (`execution_receipt_root` in the header, plan
§6.3). Consequence: **a txid present in the settled index rejects**
(`TxAlreadySettled`), which is the replay guard for account-only transactions.

## 2. Sparse Merkle tree

Versioned depth-256 sparse Merkle tree; every root above is one instance.

- **Keys** are exactly 32 bytes. Path bit `d` (`0..256`, depth from root) is
  `(key[d/8] >> (7 - d%8)) & 1`; `0` = left. Lexicographic key order equals
  MSB-first path order.
- **Leaf hash**: `H("NOOS/SMT/LEAF/V1" || key || value)` (D-SMT-LEAF). The leaf
  binds its key: proofs cannot be transplanted between keys.
- **Node hash**: `H("NOOS/SMT/NODE/V1" || left || right)` (D-SMT-NODE).
- **Empty roots** are recursively derived constants:
  `E[0] = H("NOOS/SMT/LEAF/V1")` (context only), `E[h] = H(node_ctx || E[h-1] || E[h-1])`,
  precomputed for `h = 0..=256`. The empty tree root is `E[256]`.
- **Insertion-order independence**: the root is a pure function of the
  key→value map (tested by shuffled-insert equality).
- **Duplicate-key updates** replace the value; deleting restores the exact
  prior root.
- **Capacity**: the key space is 2^256; practical bounds come from the
  per-collection maxima below, never from the structure.

**Proof format** (`SmtProof`, version 1): `version:u16 || bitmap:[u8;32] ||
siblings: list<Hash32, max 256>`. Bit `d` of the bitmap (MSB-first) set means
the sibling at depth `d` is non-empty and carried explicitly, in root→leaf
order; a clear bit means the sibling is `E[256-d-1]`. Verification folds from
the leaf digest (inclusion: `H(leaf_ctx || key || value)`; non-inclusion:
`E[0]`) up to the root. A bitmap/sibling-count mismatch or unconsumed sibling
rejects.

## 3. Key derivation per tree (frozen)

| Tree | Key | Value (canonical bytes) |
|---|---|---|
| notes | `note_id` (§4.1) | `NoteV1` |
| nullifiers | `note_id` of the consumed note (public notes: nullifier = note id; Umbra suites register their own nullifier derivation) | `0x01` (presence marker) |
| accounts | `account_id` | `AccountV1` |
| objects | `object_id` (§4.3); AgentIDs keyed by `agent_id`, grants by `grant_id` | `ObjectV1` / `AgentIdV1` / `CapabilityGrantV1` |
| receipts | `txid` | `ReceiptV1` |
| params | ASCII name zero-padded to 32 bytes (§7.1) | `ParamRecordV1` |
| account balances (sub-tree per account, backs `AccountV1.liquid_balances_root`) | `asset_id` | amount as u128 LE (16 bytes); zero balances have NO leaf |

NOOS asset id is the zero hash `0x00…00`. Amounts are integer micro-NOOS.

## 4. Identities

### 4.1 note_id (D-NOTE-ID)

`note_id = H("NOOS/NOTE/V1" || creating_txid || output_index || canonical_note)`
with `output_index` frozen as **u32 little-endian** (4 bytes). An id derived
under any other domain (legacy chain, sibling context) never verifies
(vectors: `note_id_old_domain_rejected`, `note_id_sibling_domain_rejected`).

### 4.2 txid / wtxid / witness_root

- `txid  = H("NOOS/TX/ID/V1"  || canonical TransactionV1 body)` (D-TX-ID). The
  body includes `witness_root` and excludes segregated witness bytes.
- `wtxid = H("NOOS/TX/WID/V1" || canonical body || canonical TransactionWitnessesV1)`
  (D-TX-WID). Distinct from txid by domain and by witness coverage; witness
  malleation changes wtxid, never txid.
- `witness_root = H("NOOS/TX/WROOT/V1" || canonical lock_reveals list)`
  (D-TX-WROOT): commits the witness **programs** (revealed lock branches)
  only. Signatures are excluded, keeping txid → signature binding acyclic:
  intents sign `tx_commitment = txid`, and `SignedIntentV1.tx_commitment ≠ txid`
  rejects.
- `TransactionWitnessesV1 { intents: list<SignedIntentV1, 64>,
  lock_reveals: list<bytes<4096>, 256> }`; `intents[i]` authorizes
  `account_inputs[i]`, `lock_reveals[i]` satisfies `note_inputs[i]`.

### 4.3 object_id (D-OBJECT-ID)

`object_id = H("NOOS/OBJECT/ID/V1" || creating_txid || action_index_u32_le || class_id_u32_le)`.
Creation of an existing id fails the transaction.

### 4.4 user asset and pool identities

`asset_id = H("NOOS/ASSET/ID/V1" || creating_txid || action_index_u32_le)`.
User assets are fixed-supply and issued exactly once by their creation action;
the zero asset id remains the separately scheduled NOOS asset.

`pool_id = H("NOOS/POOL/ID/V1" || min(asset_a,asset_b) || max(asset_a,asset_b))`.
There is at most one native constant-product pool for an unordered asset pair.

## 5. Transaction envelope and typed actions

Object shapes and collection maxima are exactly the tables in
`protocol/spec/schema-tables/lumen-objects.md` (tags 1–11). The envelope's
`actions[]` are bounded byte strings (max 65,536 each, 64 per tx) whose
content is a typed `ActionV1`: `u16` discriminant in declaration order, then
the variant fields. A malformed or unknown action rejects the whole
transaction at step 1.

```
0  CallObject { object_id, input }                  — ContractEngine call
1  CreateObject { class_id, ..., rent_deposit, .. } — id per §4.3; deposit is outflow
2  DepositToAccount { account_id, asset_id, amount }
3  WithdrawFromAccount { account_id, asset_id, amount } — account must be signed
4  GovernanceParamUpdate { param_key, new_value, activation_height }
5  GovernanceRegistryUpdate { registry_key, new_value, activation_height }
6  EmergencyDisable { control_key }                 — writes DISABLED only
7  EmergencyQuarantine { object_id }                — sets FLAG_QUARANTINED
8  RegisterAgent { AgentIdV1 }
9  GrantCapability { CapabilityGrantV1 }            — issuer must be signed
10 RevokeCapability { grant_id }                    — issuer must be signed
11 SubmitIntent { IntentV1 }                        — deterministic policy gate
12 CreateAsset { issuer, symbol, name, decimals, total_supply } — fixed supply
13 CreatePool { provider, asset_a, asset_b, amount_a, amount_b, fee_bps }
14 SwapExactIn { trader, pool_id, asset_in, amount_in, min_amount_out }
15 RegisterComputeWorker { worker, capabilities, cpu_threads, memory_mb,
     gpu_memory_mb, price_per_unit, endpoint_commitment }
16 OpenComputeJob { requester, workload_kind, input_root, units, unit_size,
     max_price_per_unit, deadline_height }
17 ClaimComputeJob { worker, job_id }
18 SubmitComputeResult { worker, job_id, result_root, completed_units }
19 AcceptComputeResult { requester, job_id }
20 CancelComputeJob { requester, job_id }
```

**Closed action law (plan §4.7).** `CreateAsset` issues only a new,
domain-derived user asset once; it cannot mint NOOS or increase an existing
asset supply. The enum contains no variant that seizes user state, reverts
finalized state, forges finality, admits code outside the registry path,
exceeds caps, or activates a disabled suite. Discriminant 21+ rejects
(`unknown_discriminant`).

### 5.1 fixed-supply launch and constant-product swap

`CreateAsset` requires the issuer account signature, uppercase ASCII symbol
of 1–12 bytes, UTF-8 name of 1–64 bytes, `decimals ≤ 18`, and
`total_supply > 0`. The whole declared supply is credited atomically to the
issuer; the action cannot be repeated for its derived id.

`CreatePool` requires the provider signature, two distinct registered assets
(NOOS is intrinsically registered), nonzero reserves, and `fee_bps ≤ 1000`.
It debits the provider and stores reserves in canonical asset order.

For `SwapExactIn`, with input reserve `x`, output reserve `y`, exact input
`a`, and fee `f` basis points:

`effective = floor(a × (10000-f) / 10000)`

`amount_out = floor(y × effective / (x + effective))`.

The full input `a` enters the reserve, so the fee remains in the pool and
`x × y` is nondecreasing. Zero output, insufficient balance,
`amount_out < min_amount_out`, overflow, or an asset/pool mismatch fails
atomically.

### 5.2 self-authenticating recipients and compute escrow

A `DepositToAccount` whose recipient does not exist creates an empty
`AccountV1` with `account_id = auth_descriptor = recipient`, nonce zero, and
empty balance root before applying the deposit. The recipient is therefore an
Ed25519 verification key; later declaration as an account input still requires
the corresponding transaction signature. Existing account authentication is
never replaced by a deposit.

Compute worker capability bits are `1 = CPU` and `2 = GPU`; unknown or zero
capabilities reject. A registered worker has positive price and coherent
nonzero hardware bounds. `compute_job_id =
H("NOOS/COMPUTE/JOB/ID/V1" || creating_txid || action_index_u32_le)`.
Opening a job debits `units × max_price_per_unit` NOOS from the signed
requester into job escrow, with checked integer arithmetic and a future
deadline. Claiming binds one active signed worker whose registered price does
not exceed the maximum. Submission binds the full unit count and nonzero result
root but does not pay. The signed requester alone accepts a submitted result;
acceptance pays `units × agreed_price_per_unit`, refunds the difference, zeros
escrow, and increments worker counters atomically. The requester may cancel an
open job, or any nonterminal unfinished job after its deadline, for a complete
escrow refund.

## 6. Transaction application (normative order, arch §6.6)

Steps, exactly:

1. decode body, witnesses, and every action; reject noncanonical bytes or
   unknown mandatory fields;
2. check `chain_id`, `format_version = 1`, `height ≤ expiry_height`, declared
   resource limits ≤ per-block capacity, encoded bytes (body + witnesses)
   ≤ declared byte limit, txid not already settled;
3. resolve declared inputs against the current intermediate state: duplicate
   declarations reject; note inputs must exist, be un-nullified, and have
   `height ≥ birth_height + relative_timelock`; account inputs must exist;
   access-list objects must exist and not be quarantined; `fee_payer` must be
   a declared account input;
4. verify `witness_root`, per-input lock reveals, per-account intent
   signatures over the txid (behind `AuthVerifier` until noos-crypto lands),
   evidence-ref proof profiles, action authority (governance/emergency
   records, capability issuers), and planned output ids
   (`birth_height = current height`, no duplicates);
5. reserve the maximum fee `Fee(prices, declared_limits)` against the fee
   payer's NOOS balance; insufficient balance rejects;
6. execute actions in listed order in a bounded copy-on-write overlay keyed
   by touched entries; undeclared object access traps;
7. enforce per-asset conservation:
   `Σ note_inputs(a) + Σ withdrawals(a) = Σ outputs(a) + Σ deposits(a) + Σ rent_deposits(a=NOOS)`
   with strict equality per asset;
8. charge measured resources (≤ declared limits, else trap) at the reserved
   prices and refund the difference;
9. atomically commit: delete input notes, insert their nullifiers, increment
   every input account's nonce by exactly 1, write objects/params/balances,
   insert outputs;
10. append `ReceiptV1 { txid, status, fee_charged, resources_used }` to the
    settled index and return the ordered receipt.

**Rejection vs failure (frozen).**

- A failure in steps 1–5 is a **rejection**: the transaction is invalid,
  nothing is written, and **all six roots stay byte-identical**. Stable
  numeric reject codes live in `state::RejectReason` (1–27).
- A failure in steps 6–8 (trap, conservation, resource overrun,
  postcondition) **drops the overlay** and commits ONLY the deterministic
  failure charge: `min(failure_fee, reservation)` deducted from the fee
  payer, the fee payer's nonce +1, and the failure `ReceiptV1`
  (`status = 1000+code` for Lumen failures, `2000+trap` for Grain traps).
  `notes_root`, `nullifiers_root`, `objects_root`, `params_root` stay
  byte-identical; notes are NEVER partially consumed. The failure receipt
  settles the txid (no replay of the failed transaction).

### 6.1 StateDelta

Every commit emits a canonical ordered `StateDelta`: entries
`(tree_id, key, sub_key?, value?)` sorted by `(tree_id, key, sub_key)` with at
most one entry per slot; `value = None` deletes. Tree ids: notes 0,
nullifiers 1, accounts 2, objects 3, receipts 4, params 5, account-balances 6
(key = account, sub_key = asset). This is the exact write set the storage
adapter (`noos-store`, later phase) applies; noos-lumen performs no I/O.

### 6.2 Fee dimensions

`Fee = p_B·B + p_G·G + p_V·V + p_R·R + p_D·D`, all u128 integer micro-NOOS,
checked multiplication/addition (overflow rejects, never wraps). Mapping from
the six-axis resource vector: `B = bytes`, `G = grain_steps`,
`V = proof_units`, `R = state_writes` (v1 word-epoch approximation,
ODR-FEES-002), `D = blob_bytes`; declared `state_reads` are bounded but priced
inside `G` in v1. WorkJob escrow is SEPARATE (arch §6.9): it never enters this
formula and is reachable only through the `WorkJobEscrow` trait implemented by
noos-work-loom. v1 fee disposition is burn (fees leave the fee payer and are
credited nowhere); the production disposition is OWNER_BLOCKED
(ODR-EMISSION-006).

### 6.3 Fee controller (frozen law)

Per dimension, per block, with `target = capacity/2` (capacity ≥ 2):

- `used == target` → price unchanged;
- else `adj = floor(p · |used-target| · max_change_ppm / (target · 10^6))`,
  stepped by at least 1;
- increase clamps to `max_price`, decrease clamps to `min_price`.

Since `used ≤ capacity = 2·target`, the relative per-block change is bounded
by `max_change_ppm`. Controller coefficients, capacities, and the failure fee
are UNRESOLVED in constants-v1.toml (ODR-FEES-001/002/003): they are
`FeeParamsV1` parameters in the params tree, never code defaults;
`testnet_fixture()` provides valueless NOOS_TEST engineering values. Updated
prices persist as `FeeStateV1` under `params_root`.

## 7. Params tree and governance

### 7.1 Keys

Params keys are the ASCII name zero-padded to 32 bytes (names ≤ 32 bytes,
frozen): `noos.params.fees.v1`, `noos.params.feestate.v1`,
`noos.params.issuance.v1`, `noos.params.shares.v1`, `noos.params.gov-auth.v1`,
`noos.params.emrg-auth.v1`, prefix `noos.registry.` for registries, prefix
`noos.control.` for feature controls. Every value is a
`ParamRecordV1 { current, pending? }`.

### 7.2 Governance law (plan §4.7, arch §12)

- `GovernanceParamUpdate`/`GovernanceRegistryUpdate` require the signed
  governance-authority account, an activation height ≥ current height +
  `min_activation_delay`, and record a pending value; `activate_pending_params`
  promotes it deterministically at block start once due.
- **Feature-control keys are not governable**: writing `noos.control.*`
  through a param update rejects — activating a disabled suite requires a
  hard fork (arch §8.6). Emergency authority can only write `enabled = 0`
  (`EmergencyDisable`) or set `FLAG_QUARANTINED` (`EmergencyQuarantine`);
  quarantined objects reject calls pre-reservation. There is no enum variant
  to mint, seize, revert finalized state, forge finality, admit code, exceed
  caps, or activate a suite.
- Authority records are raw 32-byte account ids installed at genesis and
  rotated only through the delayed governance path; a missing record fails
  closed. (v1 stand-in for the bonded-vote pipeline of arch §12.1, which
  arrives with the governance product phase.)

## 8. Fixed-envelope issuance (arch §13.2)

Parameterized per-height law (`IssuanceParamsV1`): heights 1-based, era
`k = (h-1)/era_length`, `e_0 = initial_per_height`,
`e_{k+1} = floor(e_k · decay_num / decay_den)` (`num < den`), `E_h = e_k` for
`1 ≤ h ≤ terminal_height`, else 0. Validation proves
`Σ E_h ≤ max_supply` in exact closed form before any mint.

- `apply_emission(height, recipients)` is the ONLY mint entry point; it
  requires `height > last_emission_height` — **skipped/orphaned heights are
  forfeit and never recreated**.
- Split (`EmissionSharesV1`, ppm summing to exactly 10^6): witness and
  treasury shares round DOWN, the proposer takes the exact remainder — every
  split conserves `E_h` to the micro (frozen rounding rule).
- There is no useful-work mint path anywhere in the crate: Loom settlement is
  escrow (transfer), duplex reallocation is hard-zero (E-DEMAND-WASH-01).
- Production values are OWNER_BLOCKED (constants-v1.toml `[emission]`);
  `testnet_fixture()` is valueless NOOS_TEST. Conservation is tested over
  10^5 sampled heights in the unit suite and over 10^7 sequential heights in
  the ignored release test
  (`cargo test -p noos-lumen --release --lib -- --ignored issuance_conservation_10e7`);
  the full 10^7-path battery gate script arrives with tools/gates.

## 9. Conformance vectors

`protocol/vectors/lumen/` (generator: `cargo run -p noos-lumen --bin
gen_vectors`; the crate's tests re-derive and verify every case, so vectors
cannot drift from the implementation):

- `lumen-tx-v1.json` — envelope law: canonical roundtrips (full, minimal,
  no-sponsor, witnesses) and negatives (truncation ladder, trailing byte,
  unknown version, unknown mandatory tag, collection over max, invalid
  optional presence, invalid access mode) with exact noos-codec error classes.
- `lumen-ids-v1.json` — `claimed_id(32) || preimage` cases for note_id /
  txid / wtxid, including **old-domain rejection** (legacy chain note domain),
  sibling-domain rejection, wrong-index rejection, and txid-as-wtxid swap
  rejection.
- `lumen-smt-v1.json` — `expected_root(32) || u32 count || (key || u32 len ||
  value)*` cases: empty root, single leaf, adjacent-key deep split, four-leaf
  spread, wrong-value root rejection, crossed leaf/node-domain rejection.
