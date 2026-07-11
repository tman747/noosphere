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

## Wallet guide

Before balance, planning, signing, or submission, compare expected chain ID, genesis hash, and API version with `/api/status`; mismatch fails before reading wallet state or signing. Use purpose-separated hardened sign/view/Umbra/agent/recovery paths. Never grant spend authority to view or agent keys. Construct canonical transaction bodies and segregated witnesses, show maximum/actual five-resource fee, expiry, effects, capability use, and change before consent. Report `MEMPOOL`, `INCLUDED`, `JUSTIFIED`, `FINALIZED`, `REVERTED`, and `REJECTED` distinctly; inclusion is not finality.

## Agent guide

An `AgentID` acts only through explicit, narrow, revocable `CapabilityGrant` objects. Bind grants to chain, subject, actions, object/value/resource ceilings, expiry, nonce/replay scope, and approval policy. Simulate and show postconditions before authority use. Fail closed on unknown rights, stale state, identity mismatch, exceeded limits, or non-final prerequisites. Agent output is not a signature unless a spending authority separately authorizes the exact canonical intent.

## Contract guide

Contract admission binds canonical Grain formula bytes/hash, version, manifest, declared effects/rights, resources, and certificate references. Programs must be total within declared bounds or deterministically trap. Do not depend on map iteration, wall clock, host floating point, network calls, optional jet output, or mutable external code. Tests should cover canonical/invalid encoding, resource boundary, trap rollback, capability denial, fee failure, version rejection, and slow-Grain/jet equivalence.

## Weft guide

Weft compiles to core Grain; raw Grain remains permanently valid. V0 checks content-addressed `MeaningContract`, `NumericProfile`, `CostCertificate`, `JetCertificate`, and `SpanStatement` integrity but performs no parser/inference/elaboration. Full compiler output binds source root, formula bytes/hash, compiler identity, toolchain/target/flags/binary hash, cost derivation, size bounds, effects/rights/profile, and optional lowering manifest. Opcode 12 is invalid. Calls/control/tuples/arithmetic lower to the twelve core opcodes; slow canonical formulas define semantics before jets.

Never trust a declared polynomial: certificate verification checks variables, degree/term/coefficient limits, overflow, branch maxima, and actual charge. Optional unknown/revoked/faulting jets fall back to slow Grain with unchanged semantic charge; mandatory-jet absence traps. Rust and independent Go acceptance, diagnostics, formula bytes, noun/trap, and charge must agree before promotion.
