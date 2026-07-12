# MindChain completion plan

## Goal

Move the current engineering LAN from a manually operated, fixture-backed test network to a durable public valueless testnet where ordinary Windows, macOS, and Linux users can install non-validator nodes, optionally provide bounded compute, and receive direct test-token settlement without exposing operator or wallet secrets.

## Delivery rules

- Preserve chain identity and fail closed on state divergence.
- Keep operator RPC private and exclude its token from invitations, telemetry, logs, and browser APIs.
- Keep fixture validators and fixture finality restricted to explicit test-network modes.
- Do not expose arbitrary requester code until the workload sandbox passes escape and abuse testing.
- Do not describe custodial browser helpers as independent paid workers.
- Every phase must have deterministic restart, failure, and negative-path tests before the next phase is considered complete.

## Phase 1 — consensus and indexed state

### Finality progression

1. Distinguish distributed fixture-witness mode from standalone engineering-host fixture finality.
2. Make the invitation host use standalone fixture finality so a one-host engineering network cannot advance indefinitely without justification or finalization.
3. Preserve distributed witness mode for multi-machine finality tests.
4. Detect a head beyond two epochs with finality still at genesis and restart the engineering host in its declared mode.
5. Verify finality catches up after restart and continues across subsequent epoch boundaries.
6. Add finality-stall health and dashboard incident reporting.

Acceptance:

- At height greater than two epochs, justified epoch is nonzero and finalized epoch follows the protocol lag.
- Restart preserves the exact justified/finalized checkpoints and does not double vote.
- Distributed fixture-witness tests still require independently gossiped votes.

### Indexer durability

1. Persist query state and ingest checkpoint as one versioned generation.
2. Bind each generation to indexed height, block hash, schema version, and state digest.
3. Detect cursor/state divergence and refuse readiness.
4. Support deterministic rebuild from the last validated generation or genesis.
5. Expose starting, rebuilding, catching-up, ready, and diverged states.
6. Add crash-boundary and repeated-restart equivalence tests for balances, transactions, receipts, workers, and jobs.

Acceptance:

- Reusing one indexer directory after repeated process termination returns byte-equivalent query results.
- The API never reports ready while cursor and query state disagree.

## Phase 2 — durable host and identities

### Windows host service

- Package producer, indexer, compute coordinator, dashboard, immutable manifest, and private configuration outside the repository checkout.
- Install least-privilege services with dependency ordering and bounded restart backoff.
- Add tray/status controls, protected logs, backup, restore, repair, migration, and uninstall.
- Detect sleep/resume, address changes, stale state, and port conflicts.

Acceptance: reboot returns the complete host stack to healthy state without a terminal.

### Dynamic invitation leasing

- Generate signed, expiring, checksum-bound invitations from the host UI.
- Lease each validator role to one device, reject duplicate active leases, and support revocation/replacement.
- Regenerate invitations after address or bootstrap changes without manual JSON editing.
- Produce platform-specific downloads from the signed public manifest.

### Production validator keys

- Separate validator admission from ordinary node installation.
- Add authenticated enrollment and DKG participation.
- Isolate signing keys behind hardware or remote signing.
- Persist anti-double-signing state before releasing votes.
- Add encrypted backup, rotation, emergency disable, restore, and compromise drills.
- Refuse fixture witness identities outside explicit test-network configuration.

## Phase 3 — secure remote and public network edge

### Encrypted remote onboarding

- Support an approved Tailscale/overlay bootstrap path without router port forwarding.
- Add multiple peers, reconnect, failover, and WAN/NAT/packet-loss tests.
- Keep public HTTP and operator RPC unreachable on the overlay unless explicitly permitted.

### Public edge

- Deploy at least three bootstrap nodes across distinct regions and failure domains.
- Publish stable IPv4/IPv6 QUIC addresses and signed bootstrap rotation data.
- Put public API and compute discovery behind Cloudflare TLS, rate limits, request-size controls, health checks, and DDoS protections.
- Keep operator RPC private.
- Automate deployment through scoped GitHub Actions secrets.

External prerequisites:

- `DIGITALOCEAN_ACCESS_TOKEN`
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- Public DNS zone access and deployment SSH keys

Secrets must be scoped and stored in GitHub Actions or the local secret store, never committed or pasted into issue comments.

## Phase 4 — noncustodial bounded compute

### Worker payout identity

- Create or recover a local worker wallet outside browser storage and coordinator persistence.
- Register payout address, capabilities, limits, and price on chain.
- Pay accepted work directly from escrow to the worker identity.
- Add fee onboarding, minimum payout economics, timeout, cancellation, refund, and recovery paths.

### Workload sandbox

- Keep MIX32 as the initial bounded workload.
- Add a signed, versioned workload registry.
- Enforce filesystem, network, memory, runtime, storage, GPU, temperature, battery, schedule, and bandwidth policies.
- Add deterministic metering, replication/challenge verification, disputes, penalties, and malicious requester/worker tests.
- Refuse unregistered or policy-incompatible workloads.

Acceptance:

- Requester code cannot access host secrets or escape the sandbox.
- Invalid worker output cannot release escrow.
- A WAN worker receives settlement to an independently recoverable address.

## Phase 5 — distribution, telemetry, and release evidence

### Trusted installers

- Produce organization-signed Windows installers and Apple Developer ID-notarized macOS universal packages.
- Add signed updates, downgrade protection, rollback, repair, and complete uninstall.
- Preserve explicit user choice before deleting keys or ledger data.

### Signed fleet telemetry

- Add per-node telemetry identities, signed reports, sequence numbers, replay protection, and freshness thresholds.
- Report version, architecture, sync status, peers, bootstrap path, resource capacity, and worker policy without secrets.
- Aggregate incidents and expose verified/stale/offline/unreported states to the dashboard.

### Independent release gates

- Independent protocol and cryptography audit at an exact revision.
- Public self-hosted operator evidence and signed 7-day/90-day testnet records.
- Independent reproducible builders for required platforms.
- Production 5-of-7 DKG, Quiet Week, ceremony transcript, and final identity.
- Owner hardware-key economics and release authorization.
- Completion of all remaining partial-claim evidence campaigns.

## Dependency order

Finality → indexer durability → durable host → invitation leasing → validator keys → encrypted remote connectivity → public edge → noncustodial worker payout → workload sandbox → trusted installers → signed fleet telemetry → independent release gates.

External credentials, signing certificates, governance decisions, DKG participants, and independent reviewers are hard prerequisites only for their corresponding phases; repository-controlled work proceeds without them.
