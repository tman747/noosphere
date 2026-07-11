# node-v1 — the noosd reference node (plan §7.5–§7.7; ch01 §3.1, §9.3, §10.5)

Normative companion to `crates/noos-node`. This document freezes what the
node ADDS on top of the frozen protocol crates: the header body-root
binding law, the import pipeline order, the store key scheme, the mempool
policy, the task topology, the operator RPC surface, and the
`NetworkEdge`/`noos-p2p` binding status. Everything cited from another
schema (`lumen-v1.md`, `witness-v1.md`, `header-body.md`,
`crypto-domains-v1.csv`) stays authoritative there.

Non-goals of this phase (later product passes): the public REST API v1
(`openapi-v1.yaml`), CUDA/Go worker processes, installers.

## 1. Scope and composition

`noosd` composes the finished crates — codec, crypto, lumen, grain,
ground, braid, witness, store, da, p2p — into the reference full node:

* one deterministic single-writer consensus core (`NodeCore`);
* a durable store behind the `StorePort` boundary;
* a bounded supervisor task topology (§7);
* a localhost bearer-token operator RPC (§8);
* header-first / snapshot / light sync behind `NetworkEdge` (§6.3).

Modes: `Full` (everything) and `Light` (headers + Ground work + finality
certificates only, ch01 §10.5). `observer` additionally disables
transaction submission as an explicit disabled feature (§8.1).

## 2. Genesis and identity

* Parameters load from `protocol/genesis/devnet-parameters.toml` and are
  CHECKED, never trusted: consensus timing values must equal the
  compile-frozen crate constants; every `is_test_fixture` item is refused
  unless `is_test_network = true` (plan §2.5 — mainnet values are
  OWNER_BLOCKED and absent by design).
* `GenesisParameterManifestV1` (fixed-width, canonical) hashes under
  `D-GENESIS-PARAMS` to the parameter manifest hash; `chain_id` derives
  under `D-CHAIN-ID`; the final genesis hash under `D-GENESIS-FINAL`
  binds chain id, the (devnet-zero) Bitcoin anchor, the DKG fixture root,
  and the canonical final body (identity-v1.md §4).
* The eight genesis controls are bit-packed in `CONTROL_NAMES` order and
  are all zero at genesis. **Control-name law:** controls live in the
  Lumen params tree at `noos.control.<name>`; `noos-lumen` freezes full
  param keys at ≤ 32 bytes and the prefix is 13 bytes, so every control
  name is ≤ 19 bytes. The frozen names (long plan aliases in comments in
  `genesis.rs`) are:
  `work_loom_credit`, `work_loom_weightcap`, `witness_proofpower`,
  `neural_lane`, `reflex_lane`, `umbra_suite`, `dream_lane`,
  `class_gate_budget`.
* `GenesisSpec.extra_accounts` pre-provisions fixture accounts
  (`account_id` = Ed25519 pubkey bytes; `auth_descriptor` = the same
  bytes). Lumen v1 has no account-creation action — deposit targets must
  already exist (lumen-v1.md §6) — so engineering networks provision
  their operator accounts at genesis. REFUSED unless
  `is_test_network = true`.

## 3. Header body-root binding law (`D-BODY-*` registry rows)

`noos-braid` freezes the header WIRE but leaves the body-derived roots
semantically open; the node binds them (import stage 3; production):

```text
tx_root                    = H(D-BODY-TX-ROOT      || canonical transactions list)
witness_root               = H(D-BODY-WITNESS-ROOT || canonical segregated_witnesses list)
execution_receipt_root     = H(D-BODY-RECEIPT-ROOT || canonical ordered ReceiptV1 list)
finality_certificate_root  = H(D-BODY-CERT-ROOT    || canonical finality_certificates list)
ground_ticket_root         = H(D-BODY-TICKET-ROOT  || canonical 76-byte ticket)
evidence_root              = ZERO_ROOT   (evidence lane unfrozen; fail closed)
```

`execution_receipt_root` (this block's ordered receipts) and
`lumen_receipts_state_root` (the post-state settled index, from the
transition) are BOTH mandatory and interchange of their values is a typed
`RootMismatch` at import stage 5 (plan §6.3).

### 3.1 System transitions

The system-transition schema table is not yet frozen: a body carrying any
entry is refused (`SystemTransitionsUnfrozen`, fail closed). Parameter
activation and emission run as implicit block-start system steps (§4).

### 3.2 The DA body form and ticket independence

ch01 §4.3 fixes `proposal_commitment` (which includes `body_da_root`)
BEFORE the Ground nonce search, so the DA-committed bytes MUST be
ticket-independent: the DA form is the canonical `BlockBodyV1` with
`ground_ticket` canonicalized to the all-zero ticket. The real ticket
travels with the header and is bound by `ground_ticket_root` — header
field 24, the ONE root excluded from the proposal commitment — plus the
ticket law itself.

**Ticket search (devnet):** the deterministic miner derives its
`extra_nonce` from the per-block challenge (which binds parent, slot, and
proposal commitment), so `(proposer, nonce, extra_nonce)` is unique per
block and never trips the ch01 §4.2 rule-8 duplicate scan even at the
trivial devnet target where `nonce = 0` always wins.

## 4. Consensus core and the import pipeline

ONE owner of ledger + DAG state: every mutation flows through `NodeCore`
methods on `&mut self`. Exact stage order:

```text
0. canonical header decode        (receipt-root interchange of the FIELD
                                   TAGS dies at decode; value interchange
                                   dies at stage 5)
1. header validation              (noos-braid structure + proposer sig)
2. ticket validation              (noos-ground eight-rule law; DAG
                                   DuplicateSet; Pulse retarget)
3. DA reconstruction              (noos-da; NotEnoughValidShards PARKS the
                                   block — pausing is NOT rejection — and
                                   feed_shards resumes it) + body/header
                                   cross-checks (§3)
4. body execution                 (Lumen normative order; system steps
                                   first: param activation, emission;
                                   header base_prices must equal the
                                   block-start controller state)
5. root comparison                (six Lumen roots + execution_receipt_
                                   root + lumen_receipts_state_root +
                                   gas_used; first mismatch is the typed
                                   RootMismatch)
6. fork choice                    (braid ForkScore: finalized, justified,
                                   cumulative work, inverse hash; reorg =
                                   rollback to the finalized anchor +
                                   replay of stored bodies)
7. finality processing            (certificates from the body; justified/
                                   finalized pointer advance; anchor
                                   refresh)
```

* A parent-unknown header enters the bounded orphan pool. A valid header
  off the executed head persists as a side chain; execution is deferred
  to fork choice.
* A stage-4/5 failure may leave the live ledger dirty; the node rebuilds
  it from the finalized anchor along the canonical path before returning
  the typed error (rejection never corrupts state).
* Reorgs below finality roll back to the finalized anchor and replay
  stored bodies deterministically; a plan across finality is
  `ReorgAcrossFinality` — finalized checkpoints are never reverted by
  work (proven in §10.2).
* Restart recovery replays the durable chain through the SAME pipeline
  (structure, ticket, execution, roots re-verified block by block);
  certificates replay afterwards in epoch order; recovered state is EXACT
  or startup fails.

### 4.4 Pulse anchor law

Ground rule 5 needs "the most recent finalized checkpoint on that
branch". The node anchors on the checkpoint NAMED BY THE PARENT HEADER
(`parent.finalized_checkpoint`): on-chain data, deterministic across
nodes and across time — header-first sync revalidates identically.

### 4.5 Weak-subjectivity checkpoints (ch01 §10.5)

A configured checkpoint is a SOCIAL INPUT: it may narrow sync candidates
but NEVER overrides local finality. A conflict with locally finalized
state — live or at restart — is the typed
`SocialCheckpointConflictsLocalFinality` and changes nothing.

## 5. Store boundary

The consensus single writer talks to storage through `StorePort`
(`InProcStore` directly over `noos_store::Store`, or the supervisor's
channel-backed `StoreClient`). Store identity is `chain_id ++
genesis_hash`; a wrong-identity open is a typed fatal.

### 5.1 Key scheme (frozen)

```text
Headers  CF:  b"h/" ++ block_hash(32)              -> canonical header ++ 76-byte ticket
Indices  CF:  b"n/" ++ height u64 BE               -> block hash (canonical chain index)
              b"c/" ++ epoch u64 BE ++ digest(32)  -> canonical FinalityCertificateV1
              b"m/head"                            -> head block hash
              b"m/final"                           -> finalized CheckpointRef (canonical)
              b"m/just"                            -> justified CheckpointRef (canonical)
Receipts CF:  txid(32)                             -> height u64 LE ++ canonical ReceiptV1
Blobs      :  body_da_root                         -> served canonical body bytes
Safety     :  kind 1 (SAFETY_KIND_WITNESS_BEACON)  -> BeaconSafetyRecordV1
              kind 2 (SAFETY_KIND_VOTE)            -> VoteSafetyRecordV1
```

Every commit is one atomic `WriteSet`; safety records are fsync-backed
WAL appends (§7.2).

## 6. Transaction and block flow

### 6.1 Mempool admission (exact order; first failing stage names the rejection)

1. size caps (`max_tx_bytes`; the declared `resource_limits.bytes`
   envelope must cover the encoding);
2. canonical decode of transaction, witnesses, and every action;
3. chain id / format version / expiry;
4. fee floor: declared maximum fee under the CURRENT base prices must
   reach the configured floor; overflow rejects;
5. settled-duplicate and pending-duplicate caches;
6. stateful checks: payer exists, payer balance covers the declared
   maximum fee, payer appears in `account_inputs`, witness alignment
   (`witness_root`, one intent per account input,
   `tx_commitment == txid`), every intent signature verifies;
7. bounded caps: per-source pending, per-payer pending (FIFO — Lumen
   transactions carry no explicit nonce; the account input consumes
   `nonce+1` implicitly, so per-payer arrival order IS the nonce order),
   then pool byte/count caps with fee-density eviction (lowest density
   leaves first; an incoming transaction that cannot beat the lowest
   resident density is refused `pool_full`).

Every rejection carries a stable snake_case code for the RPC
(`oversized`, `malformed`, `wrong_chain`, `wrong_version`, `expired`,
`fee_overflow`, `fee_below_floor`, `duplicate_pending`,
`duplicate_settled`, `unknown_payer`, `payer_not_signer`,
`insufficient_balance`, `witness_mismatch`, `signature_invalid`,
`source_limit`, `account_limit`, `pool_full`).

### 6.2 Template assembly

Deterministic: candidates ranked `(fee density desc, arrival seq asc,
txid asc)` under per-payer FIFO, filled under the body caps (count, byte
budget, five-axis resource capacity). Entries the live state rejects at
production are dropped from the pool.

### 6.3 Sync modes

* **Header-first full sync** — pull `(header, ticket)` ranges from the
  executed head, verify through the ordinary stage-1/2 law, pull bodies
  per header, execute every transition (the same seven-stage pipeline;
  nothing is trusted from a peer), then pull certificates.
* **Light sync** — headers + certificates only; the header cursor is the
  best-known DAG tip (the executed head is pinned at genesis in light
  mode).
* **Finalized snapshot sync** — assemble a store root from multiple
  `SnapshotSource`s: the file list comes from the first source that
  answers, each file from ANY source (round-robin on failure), peer paths
  are hygiene-checked (no absolute/parent components). Verification is
  entirely the store's open law — manifest hashes, per-file hashes,
  identity, proof samples — so a corrupt byte from a lying peer surfaces
  as a typed open failure, never as accepted state.

### 6.4 NetworkEdge / noos-p2p production binding

`noosd` enables the production `P2pNetworkEdge` by default. The adapter
owns a deterministic round-robin picker over handshake-complete peers and
bridges the synchronous `NetworkEdge` contract to the async `P2pHandle`.
The supervisor owns the Tokio runtime and bounded consensus/store inboxes;
transport callbacks never mutate consensus state directly.

| node abstraction                    | noos-p2p surface |
|-------------------------------------|------------------|
| `NetworkEdge::request_headers`      | `request_range` (`/noos/sync/range/1`) |
| targeted body repair                | `request_body` (`/noos/braid/body/1`) and derived shard service (`/noos/blob/shard/1`) |
| `announce_header/tx/vote`           | `announce_header` / `push_tx` / `push_vote` |
| inbound gossip                      | `P2pEvent::Inbound` decoded and sent through the bounded `ConsensusMsg` inbox |
| serving side                        | `NodeProtocolStore` round trips to the sole store task |
| finalized snapshot transport        | `/noos/sync/snapshot/1` |
| disabled Loom lane                  | `/noos/loom/receipt/1` returns the transport's explicit `FeatureDisabled` response |

`NodeProtocolStore` never opens the database. Its read-only
`ProtocolStore` implementation uses the existing cloneable `StoreClient`,
so headers, ranges and bodies are point-in-time store-task answers and
there is still exactly one durable writer. DA shards are a bounded derived
cache of already durable canonical bodies.

Peer readiness enables request selection; disconnect/rejection removes the
peer immediately. The transport owns deterministic reconnect backoff.
Every range/header response is canonically decoded, every repaired body is
re-encoded to its committed DA root, and all resulting objects enter the
ordinary import pipeline. Transaction pushes carry canonical transaction
and segregated-witness bytes together. Vote pushes enter the normal
Witness validation/quorum/certificate path.

The application protocol list remains exactly the eight frozen
`/noos/*/1` protocols. Certificates remain block/range-carried; no ninth
protocol is introduced. `NullEdge` exists only as a `cfg(test)` fixture.
`--no-network` is an explicit maintenance/test override, not the daemon
default.

## 7. Task topology and persist-before-vote

```text
noosd supervisor
├── consensus   single-writer task: HeaderDag + LumenLedger + finality
│               (NodeCore) — ALL mutations flow through its inbox
├── store       dedicated task owning noos_store::Store; consensus
│               reaches it only through the bounded StoreClient channel
├── rpc         localhost operator RPC (never shares consensus state;
│               talks over the same bounded inbox)
├── p2p/sync    async noos-p2p event loop + bounded NetworkEdge bridge
└── pool        bounded proof-check verdict pool (crate::pool): a worker
                crash is a typed verdict, never consensus corruption
```

### 7.1 Bounded inboxes

`CONSENSUS_INBOX = 1024`, `STORE_INBOX = 64` (`sync_channel`); a full
inbox applies backpressure, never unbounded growth.

### 7.2 Persist-before-vote (durable BEFORE visible)

Two safety lanes share the law:

* **Beacon** — `StoreBarrier` implements the `noos-witness`
  `DurabilityBarrier` over `StorePort::persist_safety` (kind 1); the
  beacon state machine refuses to emit before the barrier acks.
* **Votes** — `sign_and_release_vote`: (1) scan durable
  `VoteSafetyRecordV1` records and refuse a slashable conflict
  (same epoch, different target) BEFORE anything signable exists;
  (2) persist the new record (fsync-backed); (3) only then sign and
  return the vote. A failed barrier emits nothing. Restart replays the
  records, so the refusal survives process death.

### 7.3 Contained crashes

A consensus-task panic is caught; the poisoned in-memory state is
dropped and rebuilt from the durable store (the same replay as a process
restart). Persist-before-vote guarantees nothing unpersisted was ever
emitted, so a crash can lose only unacked work, never corrupt consensus
state. Restarts are counted (`noos_task_restarts_total`).

## 8. Operator RPC and chain view

### 8.1 RPC surface (localhost, bearer token; NOT the public API v1)

```text
GET  /status      chain_id, genesis_hash, and the THREE heads SEPARATELY
                  (unsafe_head / justified / finalized) — a merged
                  "latest" does not exist here (plan §13.3 law applied to
                  the operator RPC)
POST /submit_tx   {"tx":"<hex>","witnesses":"<hex>"} → txid; observer
                  mode → 409 {"error":{"code":"feature_disabled",
                  "mechanism":"node.tx_submission.observer",...}} —
                  never empty success
GET  /block/<height|hash-hex>     summary + txids; pruned → 410 "pruned"
GET  /receipt/<txid-hex>          state (MEMPOOL / settled coords) + receipt
GET  /metrics     Prometheus text, every series noos_* (unauthenticated,
                  read-only, localhost)
```

* The bind address MUST be loopback; a non-loopback bind is refused.
* Every non-metrics route requires `Authorization: Bearer <token>`
  (constant-time comparison); failures are typed 401s.
* Unsupported or disabled features return explicit `feature_disabled`
  with a mechanism id — never an empty success (plan §7.7).

### 8.2 Chain view retention

The Ascent chain-view retention pruning is a recorded INHERITED DEFECT (a
terminal object survived under small retention). The re-implementation
makes eviction a single-pass law over settlement heights:

* every per-block map is bounded by the retention window;
* a TERMINAL record (settled below the horizon) is ALWAYS evicted — the
  exact arm that failed in Ascent — and stays answerable as `Pruned`
  through bounded marker sets (never a silent `NotFound`);
* LIVE (pending) records are never evicted by retention;
* `retention_blocks = 0` keeps full presentation history (archive mode).

Independently re-proven in §10.3 (`tests/retention.rs`).

## 9. Known gaps (tracked, fail-closed)

* **G1** — public REST API v1, workers, installers: later product phases
  by plan; the operator RPC is deliberately minimal.
* **G2** — closed: production `P2pNetworkEdge`, store serving adapter,
  inbound dispatch and reconnect/shutdown are wired (§6.4).
* **G3** — beacon randomness: epoch snapshots consume the
  `DEVNET_BEACON_RANDOMNESS` fixture until the live delay-VRF beacon
  output is wired through membership; witness bonds are devnet fixtures
  from `NodeConfig`. The live bond path derives membership from finalized
  Lumen state (plan §6.5) in the Witness-Ring integration pass.

## 10. Test battery (`cargo test -p noos-node`)

* **§10.1 e2e** (`tests/e2e.rs`) — genesis → two epochs of produced
  blocks with trivial-target tickets → transfers settled → checkpoint
  justified AND finalized with a simulated witness set (raw quorum
  `floor(2W/3)+1`, direct-child finalization) → social-checkpoint
  conflict refused → restart from the store recovers the EXACT state
  (roots, heads, balances, minted supply, receipts) and RESUMES. The
  restart leg is the counter-proof for Ascent BASELINE DEFECT-3.
* **§10.2 import matrix** (`tests/import_matrix.rs`) — happy import +
  duplicate; bad ticket (root-binding mismatch AND Ground digest law);
  bad state root (typed, importer state left clean, valid block still
  imports afterwards); receipt-root value interchange; DA insufficiency
  PARKS then resumes via late shards; oversized body claim; reorg
  rollback/replay below finality (rolled-back branch's view reverts,
  replayed transfer settles); finalized checkpoint never reverted by a
  heavier conflicting branch.
* **§10.3 mempool + retention** (`tests/mempool_tests.rs`,
  `tests/retention.rs`) — every typed admission arm at its exact stage;
  fee floor with exact fee/floor values; duplicate pending vs settled;
  expiry; per-source/per-account caps; fee-density eviction incl. the
  cannot-beat-lowest refusal and the single-tx-over-cap case; per-payer
  FIFO (nonce order) in the template under capacity; terminal-eviction /
  live-preservation retention law + archive mode + restart.
* **§10.4 safety** (`tests/safety.rs`) — persist-before-vote ordering
  (record durable before the vote exists; idempotent re-release;
  slashable conflict refused, surviving restart; failed barrier emits
  NOTHING); social checkpoint law live and at restart.
* **§10.5 sync** (`tests/sync_tests.rs`) — header-first full sync to the
  exact producer state; light sync (headers + finality, zero execution);
  snapshot sync from multiple untrusted sources; corrupt source = typed
  open failure; path-escape and no-source refusals.
* **§10.6 supervisor + RPC** (`tests/rpc_supervisor.rs`) — three heads
  separate (no "latest"), bearer auth, `noos_*` metrics; submission →
  production → block/receipt lookups; observer mode 409
  `feature_disabled` + mechanism id with an untouched mempool; contained
  consensus crash recovering exact state and resuming production.
* **§10.7 CLI** (`tests/noosd_cli.rs`, integration) — `noosd --help` /
  `--version` exit 0 and document the operator surface incl. the SOCIAL
  checkpoint law; unknown flags refuse to boot.
