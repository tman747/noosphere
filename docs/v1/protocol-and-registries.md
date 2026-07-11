---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Normative protocol, glossary, and registries

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md).

## Normative protocol book

NOOSPHERE v1 orders its base system as codec/cryptography → Lumen/Grain → Ground/Braid/Witness/DA/storage/P2P → wallet/contracts/governance → optional lanes. Lumen is the atomic state transition system; Grain is the canonical bounded execution semantics; Ground supplies mandatory challenge/ticket work; Braid orders proposals and never reverts finalized checkpoints; the Witness Ring justifies and finalizes using both raw and effective thresholds. Useful work cannot replace raw-stake safety. Optional mechanisms cannot block base progress.

Consensus inputs use canonical fixed-width encodings, bounded collections, closed numeric tags and registered `NOOS/` domains. Unknown mandatory fields, versions, domains, non-canonical encodings, trailing bytes, arithmetic overflow, or wrong chain identity reject before expensive verification or state mutation. Transactions execute in a bounded overlay; a trap or failed postcondition reverts writes and charges only the frozen deterministic failure fee.

Finality thresholds are exactly `floor(2*W/3)+1` for both raw and effective epoch weight. Ground contributes to fork choice only above finalized/justified checkpoint precedence. Every signature, proof, descriptor, node config, wallet handshake, index database, and API status is chain-bound. Historical Ascent artifacts are never compatibility inputs.

## Glossary

- **MindChain** — public product name.
- **NOOSPHERE** — internal protocol codename and research provenance.
- **NOOS / micro-NOOS** — native ticker and integer base unit; six decimals. Production quantities are `OWNER_BLOCKED`.
- **Lumen** — deterministic atomic ledger transition and six-root state projection.
- **Grain** — canonical twelve-opcode bounded noun evaluator; opcode 12 is invalid.
- **Weft** — typed authoring/certificate layer compiled to Grain; raw Grain remains valid.
- **Ground** — mandatory challenge/ticket production mechanism.
- **Braid** — DAG ordering and fork-choice layer.
- **Witness Ring** — stake-selected justification/finality committee.
- **Pulse** — Ground target adjustment.
- **DA** — data availability for consensus bodies and separately governed artifacts.
- **Work Loom** — application work market; proposal credit, proofpower, and duplex issuance are zero unless separately promoted.
- **NEL** — challengeable Neural Execution Lane.
- **Umbra** — suite-specific privacy profiles; assurance is never inferred from the name alone.
- **BESI** — bounded encrypted state/inference research profile, not a generic privacy guarantee.
- **OWNER_BLOCKED** — required signed owner/external fact is unavailable and no implementation default is permitted.
- **UNKNOWN** — unavailable or semantically unverified telemetry/evidence; never equivalent to zero, pass, or healthy.

## Registries

Normative registries are versioned and closed:

- Object and schema registry: [`protocol/schemas`](../../protocol/schemas/)
- Hash/signature/KDF domains: [`protocol/spec/crypto-domains-v1.csv`](../../protocol/spec/crypto-domains-v1.csv)
- Constants: [`protocol/spec/constants-v1.toml`](../../protocol/spec/constants-v1.toml)
- Claim and negative-result registry: [`protocol/claims/registry.json`](../../protocol/claims/registry.json)
- API contract: [`protocol/api/openapi-v1.yaml`](../../protocol/api/openapi-v1.yaml)
- Telemetry contract: [`protocol/telemetry/telemetry-v1.yaml`](../../protocol/telemetry/telemetry-v1.yaml)

A registry entry does not mean enabled. Evidence label, implementation status, evidence status, lifecycle, result, enabled state, gate, and version are independent dimensions. Closed registries reject unknown entries rather than applying defaults.
