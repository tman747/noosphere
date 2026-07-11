---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# REST, P2P, indexer, and explorer interpretation

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md). Endpoint origins are not production endpoints.

## REST API v1

The normative contract is [`protocol/api/openapi-v1.yaml`](../../protocol/api/openapi-v1.yaml). Bootstrap `GET /api/status` returns exact chain/genesis/protocol/API/release identity, separate unsafe, justified, and finalized coordinates, freshness, and evidence-registry root. Core v1 reads cover blocks, transactions, notes, address balance/history, nodes, workers, objects, models, jobs/chunks, receipts, disputes, and mechanism evidence; submission is `POST /api/v1/transactions`. Hash IDs are lowercase 64-hex, quantities are base-10 strings, addresses are canonical lowercase `noos` Bech32m, pages have stable sort and opaque query-bound cursors. Disabled mechanism routes return HTTP 409 `feature_disabled` with mechanism and evidence reference, never empty success.

## P2P

Production transport is libp2p QUIC with peer identity/certificate binding, bounded frames, rate limits, duplicate caches, reconnect/backoff, targeted repair, and consensus-priority queues. The closed protocols are `/noos/braid/header/1`, `/noos/braid/body/1`, `/noos/braid/vote/1`, `/noos/lumen/tx/1`, `/noos/sync/range/1`, `/noos/sync/snapshot/1`, `/noos/blob/shard/1`, and `/noos/loom/receipt/1`. Unknown, historical, or identity-mismatched negotiation rejects.

## Indexer contract

The index database binds chain ID, genesis hash, schema/API/release version before any read or write. It ingests canonical chain events with deterministic stable ordering and preserves transaction state transitions, reorgs below finality, unsafe/justified/finalized coordinates, six Lumen roots, ordered execution receipts versus post-state receipt root, mechanism lifecycle/evidence, and `UNKNOWN` values. Failover is only to a fresh identity-matching replica; historical chain state is read-only in a separate archive.

## Explorer interpretation

“Latest” means unsafe head, not committed or finalized. A transaction is spend-safe only according to the user’s explicit policy; the explorer must not style inclusion or justification as finalization. Reverted/rejected states remain visible. Raw and effective stake are separate; raw stake controls a mandatory safety threshold. Ground work, Loom shadow credit, jobs, receipts, proofpower, and optional-lane badges do not imply finality weight. Mechanism badges independently show evidence label, implementation status, evidence status, lifecycle, result, and enabled state. Missing/stale/malformed telemetry is `UNKNOWN`. Privacy views name the exact suite and leakage/assurance class; “private” alone is prohibited.
