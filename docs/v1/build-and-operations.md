---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Build, SBOM, provenance, monitoring, incident, disaster, retention, and privacy

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md). No independent-builder or audit sign-off is claimed.

## Build, release, SBOM, and provenance

Release inputs are immutable source/spec revision, chain/genesis identity, locked compiler/toolchain/target/flags, dependency graph, schemas/vectors, and signed reproducibility policy. Two independent pinned builders produce Windows/Linux x86_64 and native Linux aarch64 artifacts. Unsigned outputs require raw byte equality. Signed installers require exact unsigned-payload manifests and deterministic containers; only predeclared signature/timestamp envelope fields may differ. Each released artifact has SHA-256, aggregate manifest entry, SPDX/CycloneDX SBOM as specified, provenance attestation, signature, schema/API/minimum-genesis metadata, builder identity, and comparison verdict. Unlisted artifacts default to raw equality; post-build normalization is invalid.

Consumers verify the aggregate signature, artifact digest, platform/architecture, embedded chain/genesis/API identity, SBOM/provenance subject digest, and updater product/channel before atomic staging. A mismatch leaves the prior install intact.

## Monitoring

The frozen telemetry registry defines `noos_*` names, types, units, labels/cardinality, freshness, recording rules, alerts, dashboards, and gate dependencies. Monitor peers, stalls, finality lag, queues, mempool, identity/freshness/replica divergence, TLS, descriptor/genesis drift, versions, raw/effective stake, operator/cloud/ASN/hardware/model/demand concentration, NEL correctness/latency/DA/disputes/diversity/backlog/exposure. Absent, stale, malformed, reset, overflowed, or semantically unknown series is `UNKNOWN`, not healthy.

## Incident response

Classify safety, liveness, key, data, privacy, supply-chain, economic, and domain incidents. Preserve clocks, raw logs, hashes, revisions, configs, telemetry, network captures, and decision/signature records without secrets. Stop the affected authority; emergency-disable/quarantine optional lanes; never forge progress or rewrite finality. Name incident commander and communications/security/operations owners, bound containment, publish user impact and exact chain/mechanism/version, track evidence custody, and require an explicit recovery/verdict. Severity-1 unresolved findings block G5.

## Disaster recovery

Maintain encrypted offline identity/config/key inventories, independently restorable verified snapshots, N/N-1 generations and WAL, release binaries/manifests/SBOM/provenance, DNS/TLS configuration, static maintenance/archive origin, and operator contacts. Drill fresh-process snapshot+tail replay, wrong-chain refusal, last-known-good software restore, signer handover/exit, and static domain rollback. Recovery never points clients to historical RPC.

## Retention and privacy

Publish retention classes separately for consensus bodies, ledger history, Work/model/evidence blobs, logs/metrics/traces, disputes, user support, and historical archives, including purpose, minimum/maximum duration, deletion authority, legal hold, replication, encryption, and public availability. Production durations and jurisdictional basis are `OWNER_BLOCKED` pending owner/counsel policy. Minimize labels and logs; prohibit secrets, mnemonics, raw DKG shares, bearer tokens, private inputs, transaction/address/job/model identifiers in metrics, and unnecessary personal data. Cryptographic deletion does not remove already-public ledger data; every privacy claim states leakage and suite limits.
