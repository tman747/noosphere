---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Domain migration, historical archive, evidence, and negative results

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md). Domain access, archive export, rehearsal, G5 verdict, and signatures are unavailable; DNS cutover is prohibited.

## Domain migration and historical-chain archive

Before reusing `mindchain.network` or `mindscan.network`, export old sites and indexed state as a dated, hashed, immutable static archive labeled **historical old chain**. Publish its inventory, chain identity, coverage/gaps, timestamp basis, software/schema, hashes, storage origins, and read-only URL. Historical balances, certificates, identities, keys, DKG material, descriptors, RPC schemas, wallet formats, and state never enter the new genesis and never serve as fallback.

Provision new chain-bound RPC/API/indexer/site/explorer origins, TLS/CSP/cache controls, synthetic probes, low-TTL DNS, wallet wrong-chain rejection, and zero candidate runtime requests to old origins. Rehearse forward and rollback without public cutover. The first-launch rollback target is signed static maintenance/archive content with wallet submission and RPC disabled; later it is a last-known-good NOOSPHERE origin set. Only exact signed G5 promotion authorizes DNS/tunnel/asset replacement. See the [prepared manifest](../../deploy/cutover/cutover-manifest-prepared.json).

## Evidence records

Every stage bundle is immutable and records schema/stage/bundle ID, exact command and cwd, source revision, toolchain/environment, fixtures and seeds, UTC start/end, exit code, raw artifact/log hashes, preregistered thresholds, measured results, verdict, exclusions/conflicts, rollback trigger/action/outcome, producer, and signatures. A missing external fact remains `OWNER_BLOCKED`; a command success alone is not a gate pass. Evidence hashes identify retained bytes, not a summary written afterward. Check with `python tools/gates/stage_evidence.py validate`.

## Claim completeness and release blocking

The claim registry records local implementation, local evidence, owner blockers, and external blockers independently. `EXTERNAL_BLOCKED` never substitutes for missing repository work. The current 136-row audit records **31 IMPLEMENTED, 31 PARTIAL, and 74 MISSING** local implementations; 36 rows also carry separate external blockers. Therefore `python tools/gates/run_claim_matrix.py --registry protocol/claims/registry.json --all-actionable --include-negative-results --require-command --require-evidence --require-rollback --fail-on-missing` must report `BLOCKED` and `LOCAL_MISSING` for the 105 local gaps. Generic disposition replay and status-echo commands are rejected. A `KILLED` or `DISABLED` outcome is executed only when its claim-specific falsifier, disabled-control check, or rollback runs and emits raw evidence.

The engineering core checks remain independent of this release-completeness decision. A local build/test gate may pass while the G5 release claim gate remains blocked; neither outcome promotes an unmeasured claim.

## Negative results

Publish all false accepts, unauthorized transitions, semantic/root/meter/formula divergence, irreproducible or weaker tests, killed/withdrawn/retired mechanisms, unsupported operations, failed performance envelopes, security findings, disputes, exclusions, conflicts, and recalibration. Link each to claim/mechanism/version, protected property/adversary, exact raw artifacts, reproducer, impact, lifecycle/result, rollback/refund/exit, and supersession. Never delete an old verdict; append superseding evidence. A failed experimental lane remains sandboxed/disabled but does not falsely block ordinary base release when its dependency graph says it is optional.

Current binding results include E-DEMAND-WASH-01 (`KILLED` for demand-based consensus influence), E-DREAM-02 (`KILLED` for authoritative payout market), Reflex v1 (`WITHDRAWN`), and universal M-HDF (`RETIRED/PARTIAL`) while any narrower surviving claim remains a separate row. Consult [`protocol/claims/registry.json`](../../protocol/claims/registry.json) for exact current records; this prose cannot change them.
