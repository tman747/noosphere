---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Governance, upgrades, emergency disable, exit, and rollback

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md).

## Governance and upgrades

Governance acts only through versioned, chain-bound parameter or registry objects after the frozen activation delay. It cannot mint, seize, revert finalized state, forge finality, admit unreviewed code, exceed caps, or activate a disabled experimental suite outside that suite’s gate. Every parameter, compiler, verifier, kernel, demand, hardware, or adversarial-cost change returns affected claims to the required earlier gate; semantic change requires a new version and vectors.

An upgrade proposal must identify old/new hashes, activation height, compatibility boundary, dependent claims, evidence bundle, operator actions, safe rollback point, and exit impact. Unknown versions reject. Nodes do not silently downgrade or interpret new mandatory fields.

## Emergency disable

Emergency authority is limited to disable or quarantine. It cannot create value, override finality, authorize irreversible work, or substitute a new mechanism. Each optional lane needs a one-checkpoint disable path. Disabling an optional worker/prover/model lane must preserve base Braid/Lumen/Grain availability. The action, reason, scope, signatures, activation, resulting state, refunds, and evidence reference must be publicly recorded.

## Exit and migration

Before canary exposure, every lane declares an owner-controlled exit/migration procedure, asset/capability scope, completion invariant, refund handling, timeout, and independent drill. Umbra exits are assurance-specific; privacy does not excuse unavailable recovery. G4 requires two independently observed exits and exposure within both per-lane and aggregate 0.1% circulating-supply caps.

## Rollback boundaries

Finalized ledger state is not rolled back by governance or work. Software rollback means restoring the previously verified binary/config and replaying canonical state; storage recovery retains verified generations and required WAL. Experimental rollback means disable/quarantine plus the registered exit/refund, not pretending a failed result passed. Domain rollback targets a last-known-good NOOSPHERE origin set or, before first launch, signed submission-disabled static maintenance/archive content—never historical RPC.

DNS cutover and rollback execution are prohibited until every v2 gate record verifies against a revision-bound external role keyring root pinned by the signed final freeze. Validators recompute typed evidence hashes, exact requirements and identity, ordered prerequisite hashes, the complete ledger root, and all required Ed25519 signatures; `PASSED` strings, file existence, embedded keys, and dummy signature objects are never authority. The prepared manifest is operational input only, not authority.
