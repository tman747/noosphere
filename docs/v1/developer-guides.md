---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Wallet, agent, contract, and Weft developer guides

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md). Use only valueless engineering networks until signed promotion.

## Local developer network

Run the persistent three-process developer network from the repository root:

```text
python tools/e2e/local_devnet.py run
python tools/e2e/local_devnet.py status
```

The foreground `run` process owns a validator, a QUIC-peered full observer,
and the public indexer API. Durable state and generated connection metadata
live under `C:/tmp/noosphere-local-devnet` by default. `status` exits
successfully only when all three services report the expected chain and
genesis identity and the observer/indexer heads remain within their declared
lag bounds. Restarts recover validator and observer state; the local indexer
rebuilds its in-memory query view from height 1 before reporting ready.

The local runner provisions and funds one deterministic development account
and registers one deterministic Grain identity formula (`[0 1]`) at code hash
`c0c0...c0`. Its seed, verifying key, contract hash, authenticated operator
endpoint, and public API endpoint are written to `local-devnet.json`. These are
test-network fixtures. `noosd` refuses them when
`is_test_network = false`; never reuse them for valuable state.

For a three-computer engineering LAN, `tools/lan_testnet.py init` freezes one
manifest and private operator token. Computer A runs `run-validator`; computers
B and C run `run-observer` with distinct witness indices 1 and 2. Computer A
owns fixture witness 0 and block production but cannot independently reach the
3-of-4 finality quorum. Each witness persists its anti-double-vote record before
gossiping its vote. `tools/build_join_bundle.py` creates role-specific Windows
or macOS double-click invitations; they verify the parameters checksum, install
the node under the platform user-data root, configure automatic restart, join
the declared QUIC peer, and open the browser compute helper. These roles remain
test fixtures with public fixture witness keys, not production validator keys.

`noos-cli tx build --spec <json>` accepts canonical action hex and two typed
contract forms:

```json
{"type":"create_object","class_id":7,"owner_or_policy_root":"<hex32>","code_hash":"<hex32>","state_root":"<hex32>","storage_words":0,"rent_deposit":"0","flags":0}
{"type":"call_object","object_id":"<hex32>","input":"<canonical-grain-noun-hex>"}
```

Build output includes every deterministically derived `created_objects[]`
identifier. Sign with the development seed and submit through either the
authenticated node RPC or the indexer's transaction-forwarding endpoint.
Every current `call_object` action must declare its object in
`object_access_list` with `read_write` mode; the execution path always
updates the object version even when the formula returns equivalent state.

This is an execution and application-development path, not permissionless
code deployment. The running fixture exposes one registered formula. Adding
arbitrary immutable formula bytes still requires the versioned registry /
governance path and is not exposed as a local CLI command.

## Mind Market applications

With the local network running, start the loopback-only application gateway:

```text
python tools/e2e/market_gateway.py
```

Open `http://127.0.0.1:18100`. The hub links to:

- **Foundry** (`/launch/`): registers a domain-derived, fixed-supply user asset
  and seeds its unique NOOS constant-product pool.
- **Current** (`/exchange/`): quotes and submits exact-input buys and sells
  against live pool reserves.

User assets cannot mint NOOS or change scheduled issuance. `CreateAsset`
issues the declared supply exactly once to its signed issuer. `CreatePool`
moves existing signed-account balances into canonically ordered reserves.
`SwapExactIn` uses integer-floor constant-product math, retains the declared
fee in the pool, enforces `min_amount_out`, and commits reserve and trader
balance changes atomically. Failed slippage or balance checks leave the pool
unchanged and charge only the ordinary deterministic failure fee.

The gateway reads consensus-owned assets, pools, and balances through the
identity-gated indexer and signs with the deterministic local developer
account. It is a local test harness, binds only to loopback, and must never be
deployed with its fixture seed.

## World Wide Mind loopback pilot

The runnable World Wide Mind path is a **test-only local gateway**. It binds a
local model request to one live test-network chain identity, finalized
checkpoint, model capsule, policy, knowledge snapshot, and fee schedule. It
does not activate the production gateway, submit inference receipts as chain
transactions, or claim independent state quorum.

Install Ollama, pull the default local model, and start a test-network node:

```text
ollama pull qwen2.5:0.5b
```

Then launch the gateway from the repository root. Supply the public profile and
the node's status endpoint. Supply the operator-secret file only when that
status endpoint requires its bearer token:

```text
python tools/e2e/run_wwm_test_gateway.py --profile <public-profile.json> --state-url <http://node/status> [--operator-secret <operator-secret.json>]
```

Open `http://localhost:18787/query.html`, or run the complete state-pin,
quote, inference-stream, and signed-receipt smoke:

```text
python tools/e2e/wwm_gateway_smoke.py --origin http://localhost:18787
```

The launcher refuses a profile without `test_network=true`. The service
requires an explicit test-only acknowledgement, binds only to loopback, keeps
the state bearer token server-side, and labels the single-node state pin as
`TEST_SINGLE_NODE`. It accepts only the bounded `P0_OPEN` / `SOFT` request
shape, but executes exactly one local model: no executor committee match is
performed. State, stream, and receipt messages therefore disclose
`execution_mode=LOCAL_SINGLE_MODEL`, `executor_claim_count=1`, and
`soft_committee_quorum_met=false`; the browser displays `LOCAL TEST` instead of
claiming ordinary SOFT assurance. The browser sends the raw prompt to that
local model, but SQLite persists only prompt commitments, job metadata, signed
quotes, and signed receipts.

The default `OLLAMA` backend uses Ollama's native `/api/chat` contract and sets
`num_gpu=0`; this avoids the corrupt tokens observed on the local AMD path.
Opt into GPU layers only after validating that exact Ollama, model, and driver
combination with `--model-num-gpu <layers>`. A different loopback
OpenAI-compatible backend requires `--model-api OPEN_AI`, its `/v1` base URL,
and an explicit immutable `--model-digest`.

Every returned receipt states `test_only=true`,
`on_chain_receipt=false`, and
`chain_anchor_status=PINNED_FINALIZED_STATE_ONLY`. Its gateway signature proves
the receipt was produced by that local test gateway key; it does not prove
factual accuracy, independent execution, on-chain inclusion, or production
activation.

## Wallet guide

Before balance, planning, signing, or submission, compare expected chain ID, genesis hash, and API version with `/api/status`; mismatch fails before reading wallet state or signing. Use purpose-separated hardened sign/view/Umbra/agent/recovery paths. Never grant spend authority to view or agent keys. Construct canonical transaction bodies and segregated witnesses, show maximum/actual five-resource fee, expiry, effects, capability use, and change before consent. Report `MEMPOOL`, `INCLUDED`, `JUSTIFIED`, `FINALIZED`, `REVERTED`, and `REJECTED` distinctly; inclusion is not finality.

`tools/wallet_transfer.py` is the cross-device engineering-wallet path. It
derives the sender locally from a hidden prompt or permission-restricted seed
file, verifies chain and genesis identity twice, builds canonical
`WithdrawFromAccount`/`DepositToAccount` actions, signs the txid locally, posts
only transaction and witness bytes, and waits for inclusion. A first deposit to
a 32-byte Ed25519 verification key creates that empty self-authenticating
recipient account atomically; later spending still requires the corresponding
private key. Plain HTTP profiles are restricted to loopback and RFC1918 LAN
addresses. Internet profiles require HTTPS.

## Agent guide

An `AgentID` acts only through explicit, narrow, revocable `CapabilityGrant` objects. Bind grants to chain, subject, actions, object/value/resource ceilings, expiry, nonce/replay scope, and approval policy. Simulate and show postconditions before authority use. Fail closed on unknown rights, stale state, identity mismatch, exceeded limits, or non-final prerequisites. Agent output is not a signature unless a spending authority separately authorizes the exact canonical intent.

## Contract guide

Contract admission binds canonical Grain formula bytes/hash, version, manifest, declared effects/rights, resources, and certificate references. Programs must be total within declared bounds or deterministically trap. Do not depend on map iteration, wall clock, host floating point, network calls, optional jet output, or mutable external code. Tests should cover canonical/invalid encoding, resource boundary, trap rollback, capability denial, fee failure, version rejection, and slow-Grain/jet equivalence.

## Compute rental market

The application-only V0 market uses consensus-owned worker and job records.
`RegisterComputeWorker` advertises bounded CPU/GPU capability and an integer
price. `OpenComputeJob` removes the maximum payment from the signed requester
and locks it in the job. A signed worker may claim once and commit a result, but
submission never releases payment. Only the signed requester can accept a
matching submitted result; settlement pays the agreed price and refunds unused
escrow atomically. Open jobs and expired unfinished jobs can be cancelled by
the requester.

`tools/compute_market.py` opens deterministic MIX32 shards and independently
recomputes each result root before acceptance. `tools/compute_worker.py` keeps a
worker seed local, executes CPU shards, and signs claim/result transactions.
The `/apps/compute-market` browser helper uses WebGPU when available and a
bounded CPU fallback otherwise; it is suitable for a phone or laptop browser.
Browser helpers use the coordinator's explicitly custodial test-network worker
identity, so rewards accrue to that identity rather than to a browser-held
wallet. The workload is deliberately registered and deterministic: arbitrary
native code, neural-model rental, confidential inputs, production dispute
proofs, and permissionless GPU kernels are not claimed.

## Neural execution reality

The Neural Execution Lane (`noos-nel`) implements deterministic integer
inference primitives, model/token state, data-availability commitments,
chunk claims, Freivalds checks, and dispute/bisection primitives. A
fixture-only integration test composes these with Work Loom and Hearth
settlement types; the node does not dispatch NEL jobs or settle them in its
production consensus path. Exercise the implemented library path with:

```text
cargo test -p noos-nel --locked
cargo test -p noos-nel --test settlement --locked
```

NEL is disabled in the genesis feature controls
(`neural_lane_enabled = false`). It has zero consensus weight, issuance, and
ProofPower contribution. The first-activation validator checks a
494M-parameter P0_OPEN/W8A8 shape and caller-supplied manifest commitments;
the repository does not contain governed immutable production weights,
tokenizer artifacts, verifier keys, or an activation record. Executable tests
use deterministic compact models, not a hosted or decentralized production
LLM. No local-devnet model/job API is advertised while the control remains
disabled.

A production decentralized LLM path still needs governance activation,
published immutable model artifacts, GPU/accelerator kernels with
cross-implementation vectors, independent operators, live DA, adversarial
dispute evidence, and activation evidence. Do not describe the current
implementation as an operating decentralized LLM network.

## Weft guide

Weft compiles to core Grain; raw Grain remains permanently valid. V0 checks content-addressed `MeaningContract`, `NumericProfile`, `CostCertificate`, `JetCertificate`, and `SpanStatement` integrity but performs no parser/inference/elaboration. Full compiler output binds source root, formula bytes/hash, compiler identity, toolchain/target/flags/binary hash, cost derivation, size bounds, effects/rights/profile, and optional lowering manifest. Opcode 12 is invalid. Calls/control/tuples/arithmetic lower to the twelve core opcodes; slow canonical formulas define semantics before jets.

Never trust a declared polynomial: certificate verification checks variables, degree/term/coefficient limits, overflow, branch maxima, and actual charge. Optional unknown/revoked/faulting jets fall back to slow Grain with unchanged semantic charge; mandatory-jet absence traps. Rust and independent Go acceptance, diagnostics, formula bytes, noun/trap, and charge must agree before promotion.
