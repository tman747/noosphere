---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# MindChain / NOOSPHERE documentation bundle v1

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** Chain ID, genesis hash, production economics, ceremony records, external reviews, public-testnet duration, canary duration, and promotion signatures are unsatisfied. Nothing in this bundle is a sign-off, launch date, or evidence that a gate passed.

This versioned page set describes protocol version `v1` and API version `v1`, with release placeholder `0.0.0-preproduction`. The public product is **MindChain**; the internal protocol and provenance name is **NOOSPHERE**; wire identifiers and the native asset use **NOOS**. Every page repeats the version binding. A production bundle is valid only when its chain values equal the signed immutable release manifest and `python tools/gates/check_docs.py` passes.

## Pages

- [Normative protocol, glossary, and registries](protocol-and-registries.md)
- [Threat model, security assumptions, genesis, and economics](security-and-economics.md)
- [Governance, upgrades, emergency disable, exit, and rollback](governance-and-lifecycle.md)
- [Validator/full/light node deployment, recovery, DKG, and key operations](node-and-key-operations.md)
- [Wallet, agent, contract, and Weft developer guides](developer-guides.md)
- [Loom, NEL, Umbra, BESI, and experimental assurance disclosures](assurance-disclosures.md)
- [REST, P2P, indexer, and explorer interpretation](interfaces-and-explorer.md)
- [Build, SBOM, provenance, monitoring, incident, disaster, retention, and privacy](build-and-operations.md)
- [Domain migration, historical archive, evidence, and negative results](migration-and-evidence.md)

## Authority and reading rules

The normative machine inputs remain the versioned files under `protocol/`; documentation cannot promote a claim, change consensus, waive a gate, or replace a signed decision. `protocol/spec/precedence.md`, the source/claim registries, schemas, vectors, and signed release artifacts take precedence over explanatory prose. Disabled, killed, withdrawn, retired, partial, and unmeasured mechanisms must remain visibly so. `UNKNOWN` is never rendered as zero or healthy.

## Current blockers

The canonical ledger is [`protocol/release/promotion-blockers.json`](../../protocol/release/promotion-blockers.json). All G0–G5 verdicts are presently `BLOCKED`. DNS cutover is prohibited. The prepared cutover manifest is not authorization to change DNS, tunnels, assets, endpoints, or wallets.
