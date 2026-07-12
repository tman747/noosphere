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

## Wallet guide

Before balance, planning, signing, or submission, compare expected chain ID, genesis hash, and API version with `/api/status`; mismatch fails before reading wallet state or signing. Use purpose-separated hardened sign/view/Umbra/agent/recovery paths. Never grant spend authority to view or agent keys. Construct canonical transaction bodies and segregated witnesses, show maximum/actual five-resource fee, expiry, effects, capability use, and change before consent. Report `MEMPOOL`, `INCLUDED`, `JUSTIFIED`, `FINALIZED`, `REVERTED`, and `REJECTED` distinctly; inclusion is not finality.

## Agent guide

An `AgentID` acts only through explicit, narrow, revocable `CapabilityGrant` objects. Bind grants to chain, subject, actions, object/value/resource ceilings, expiry, nonce/replay scope, and approval policy. Simulate and show postconditions before authority use. Fail closed on unknown rights, stale state, identity mismatch, exceeded limits, or non-final prerequisites. Agent output is not a signature unless a spending authority separately authorizes the exact canonical intent.

## Contract guide

Contract admission binds canonical Grain formula bytes/hash, version, manifest, declared effects/rights, resources, and certificate references. Programs must be total within declared bounds or deterministically trap. Do not depend on map iteration, wall clock, host floating point, network calls, optional jet output, or mutable external code. Tests should cover canonical/invalid encoding, resource boundary, trap rollback, capability denial, fee failure, version rejection, and slow-Grain/jet equivalence.

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
