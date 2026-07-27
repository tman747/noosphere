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

`tools/operations/multi_node_fault_harness.py` emits
`noos/multi-node-network-soak-report/v2`. A passing report requires distinct
per-client NAT mappings, measured deterministic loss and latency, a complete
bootstrap outage followed by redial, an accepted direct signed bootstrap
successor with a stable PeerId and rotated address, block-equal state sync,
observer and indexer restart recovery, loopback-only operator binds, and an
observed HTTP 401 without the private bearer token.

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

## Integrated completion program

This program extends the dependency order above through the complete World Wide
Mind, native-client, application-economy, and production-promotion work. A task
state is operational:

- `ACTIVE`: code, a workflow, or a qualifying evidence collection is running.
- `READY`: repository-controlled work has an executable next action.
- `DURATION_BLOCKED`: immutable identity is frozen and real elapsed time is the
  remaining requirement.
- `OWNER_BLOCKED`: an exact signed owner decision is required.
- `EXTERNAL_BLOCKED`: independent people, organizations, hardware, credentials,
  counsel, or audits are required.

`ACTIVE` and `READY` do not imply implementation or evidence completion. A task
closes only when its listed behavior and negative paths are demonstrated at the
exact revision and the resulting immutable evidence validates.

### Track A — exact release evidence

| ID | State | Work and exit |
|---|---|---|
| `REL-01` | `ACTIVE` | Collect a continuous signed 24-hour monitor chain for the exact deployed revision. Every sample must bind release, deployment, signer, all 20 checks, prior sample, and bounded observation gaps. |
| `REL-02` | `READY` | Execute observer-first and one-witness-at-a-time restart, preserving 3-of-4 finality. Exit with pre/post coordinates, process identity, memory envelope, and no manual repair. |
| `REL-03` | `READY` | Restore the preserved prior build without deleting durable state. Exit with exact artifact hashes, rollback authorization, replay equality, and return-to-current evidence. |
| `REL-04` | `READY` | Assemble release bundle, fleet convergence, burn-in, restart, rollback, replay, and monitor ledgers into one immutable non-promoting evidence bundle. |

### Track B — finalized inference lifecycle

| ID | State | Work and exit |
|---|---|---|
| `INF-01` | `READY` | Exercise a sponsored finalized open, execution, close, and paid receipt on the live valueless testnet. |
| `INF-02` | `READY` | Exercise user cancellation and deadline timeout with deterministic close, charge, and refund outcomes. |
| `INF-03` | `READY` | Restart gateway and worker during active and terminal jobs; resume SSE without rerunning terminal work. |
| `INF-04` | `READY` | Reject bad event signatures, wrong model/key/finality proofs, duplicate submissions, and invalid settlement while preserving refunds. |
| `INF-05` | `READY` | Inspect database, cache, logs, crash artifacts, and telemetry for prompt/output canaries after success, cancellation, timeout, crash, and reboot. |
| `INF-06` | `READY` | Record p50/p95/p99 latency, completion, queue bounds, refunds, evidence bytes, and base-finality impact under declared concurrency and failures. |

### Track C — operator, challenger, and custody independence

| ID | State | Work and exit |
|---|---|---|
| `IND-01` | `READY` | Define signed enrollment binding organization, beneficial owner, control cluster, provider, region, ASN, keys, roles, capacity, expiry, and incident contact. |
| `IND-02` | `READY` | Implement successor publication, overlap, activation, stale-key rejection, revocation, and rotation evidence. |
| `IND-03` | `READY` | Reject executor and custody selections that satisfy key count but violate provider, region, beneficial-owner, software-lineage, or model-publisher diversity. |
| `IND-04` | `EXTERNAL_BLOCKED` | Run largest-provider and largest-region loss while preserving base finality, executor quorum, read quorum, and admitted reconstruction. |
| `IND-05` | `EXTERNAL_BLOCKED` | Inject corrupt, replayed, withheld, and stale model shares; prove rejection, repair, and unschedulability below threshold. |
| `IND-06` | `EXTERNAL_BLOCKED` | Enroll and fund two independently controlled challengers; demonstrate honest fault isolation and frivolous-challenge loss. |

### Track D — formal E-WWM-23 public pilot

| ID | State | Work and exit |
|---|---|---|
| `PILOT-01` | `READY` | Freeze exact revision, deployment, signer, browser cohort, authorized origins, consent version, and non-promoting policy before the clock starts. |
| `PILOT-02` | `EXTERNAL_BLOCKED` | Enroll at least 30 independently authorized origins with signed ownership, software, policy, and retention identity. |
| `PILOT-03` | `EXTERNAL_BLOCKED` | Complete the registered cross-browser, device, storage, private-mode, low-storage, and eviction matrix with at least 300 opt-in participants. |
| `PILOT-04` | `READY` | Automate consent grant, expiry, withdrawal, quota change, churn, repair, and no-hidden-work negative paths. |
| `PILOT-05` | `READY` | Automate queue saturation, key rotation, backup, restore, retention deletion, telemetry outage, and incident recovery evidence. |
| `PILOT-06` | `DURATION_BLOCKED` | Produce a validator-accepted immutable 30-day E-WWM-23 candidate bundle. Rewards, production custody, scheduling effect, and certificate effect remain disabled. |

### Track E — permissionless network and paid compute

| ID | State | Work and exit |
|---|---|---|
| `NET-01` | `READY` | Persist query state and ingest cursor as one versioned generation bound to height, hash, schema, and state digest. |
| `NET-02` | `READY` | Crash at every indexer commit boundary and prove repeated restart returns byte-equivalent balances, transactions, receipts, workers, and jobs. |
| `NET-03` | `DONE` | Signed multi-bootstrap snapshots bind stable PeerIds, chain/genesis, expiry, direct address rotation, irreversible revocation, and persisted rollback refusal. |
| `NET-04` | `DONE` | The v2 live soak covers multi-client NAT, measured WAN loss/latency, total bootstrap outage and redial, signed address rotation, block-equal state sync, process recovery, and loopback authenticated operator RPC. |
| `NET-05` | `READY` | Generate signed expiring invitations, lease each voting role once, reject duplicate leases, and support revocation and reassignment. |
| `NET-06` | `READY` | Package producer, node, indexer, gateway, dashboard, and private configuration as least-privilege auto-start services with repair and uninstall. |
| `NET-07` | `READY` | Add signed installer/update manifests, downgrade protection, rollback, repair, and data-preserving uninstall for supported desktop platforms. |
| `NET-08` | `READY` | Generate or recover a local worker payout identity outside browser and coordinator storage; settle a WAN job directly to it. |
| `NET-09` | `DONE` | Frozen signed MIX32 registry binds canonical identity, verifier, metering, limits, lifecycle, and executable fail-closed rejection vectors. |
| `NET-10` | `READY` | Enforce filesystem, network, memory, runtime, storage, GPU, temperature, battery, schedule, and bandwidth policies against malicious workloads. |
| `NET-11` | `READY` | Implement objective result verification, timeout, dispute, penalty, cancellation, and refund paths that cannot release escrow for invalid work. |

### Track F — native clients and release supply chain

| ID | State | Work and exit |
|---|---|---|
| `NATIVE-01` | `ACTIVE` | Run `noos-wallet-sdk` tests on the main Windows/macOS platform workflow and retain exact-revision results. |
| `NATIVE-02` | `ACTIVE` | Regenerate UniFFI bindings and fail CI on any uncommitted generated difference. |
| `NATIVE-03` | `READY` | Build Android on Linux and Windows and compile Swift package/iOS application on macOS from pinned toolchains. |
| `NATIVE-04` | `EXTERNAL_BLOCKED` | Record StrongBox/non-StrongBox and Secure Enclave, biometric fallback, backup exclusion, recovery, deletion, and migration behavior on physical devices. |
| `NATIVE-05` | `READY` | Emit checksums and subject manifests for SDKs, bindings, installers, Android packages, and iOS outputs. |
| `NATIVE-06` | `EXTERNAL_BLOCKED` | Obtain matching outputs from two independent builders for every supported target and record differences without normalization. |

### Track G — deterministic model assurance

| ID | State | Work and exit |
|---|---|---|
| `MODEL-01` | `READY` | Complete tokenizer, W8A8 operators, KV evolution, logits, and greedy decoding across independent CPU, AMD, and NVIDIA implementations. |
| `MODEL-02` | `EXTERNAL_BLOCKED` | Run at least one billion registered operator instances over adversarial and corpus vectors with zero unexplained mismatch. |
| `MODEL-03` | `DURATION_BLOCKED` | Run 30 real days of five-custodian retrieval, churn, correlated loss, poison, replay, repair, and reconstruction measurement. |
| `MODEL-04` | `EXTERNAL_BLOCKED` | Inject every registered deterministic execution fault with honest and frivolous challengers; prove exact settlement and no unrelated-job interruption. |
| `MODEL-05` | `EXTERNAL_BLOCKED` | Measure committed-token latency, completion, goodput, memory, and base p95 degradation under independent committee load. |

### Track H — MindLink knowledge plane

| ID | State | Work and exit |
|---|---|---|
| `MIND-01` | `READY` | Promote MindLink from local import semantics to a canonical rights, visibility, provenance, challenge, correction, and future-use revocation object. |
| `MIND-02` | `READY` | Build immutable rights-filtered knowledge snapshots with inclusion, exclusion, supersession, and rollback proofs. |
| `MIND-03` | `READY` | Build deterministic lexical/graph/vector index profiles with independent builders, tie vectors, manifests, and rebuild equality. |
| `MIND-04` | `READY` | Bind snapshot, index roots, policy, selected links, ranks, citation spans, builder, and context root in retrieval receipts. |
| `MIND-05` | `EXTERNAL_BLOCKED` | Run poisoning, Sybil, copied-source, stale-fact, invalid-rights, minority-correction, revocation, and private-draft leak campaigns. |

### Track I — governed immutable improvement

| ID | State | Work and exit |
|---|---|---|
| `IMPROVE-01` | `READY` | Commit rights-clean dataset membership, train/eval split, exclusions, canaries, recipe, code, compiler, budget, and parent roots. |
| `IMPROVE-02` | `READY` | Create insert-once adapter candidates with immutable lineage, artifacts, receipts, evaluations, and explicit rollback parent. |
| `IMPROVE-03` | `READY` | Enforce distinct proposer, trainer, evaluator, challenger, activator, and emergency authority scopes. |
| `IMPROVE-04` | `READY` | Run shadow and staged canary traffic with hard floors, automatic parent rollback, emergency expiry, and old-revision pinning. |
| `IMPROVE-05` | `EXTERNAL_BLOCKED` | Run independent poisoning, model replacement, benchmark gaming, extraction, memorization, privacy, and evaluator-capture campaigns. |

### Track J — private inference and Mind Browser

| ID | State | Work and exit |
|---|---|---|
| `PRIVATE-01` | `EXTERNAL_BLOCKED` | Verify fresh composite CPU/GPU/workload attestation, firmware policy, revocation, rollback counter, model identity, and client challenge. |
| `PRIVATE-02` | `READY` | Add encrypted private retrieval and output with blinded profile-specific receipts and local key/history control. |
| `PRIVATE-03` | `READY` | Prove prompt, context, activation, KV, logits, and output do not persist in host-visible cache, logs, crash state, or telemetry. |
| `PRIVATE-04` | `READY` | Implement fail-closed ODoH/OHTTP/onion routing with fixed buckets, control-cluster diversity, no direct fallback, and separate route disclosure. |
| `PRIVATE-05` | `READY` | Isolate native browser origins by publisher key and immutable content identity, including storage, service worker, cache, and permissions. |
| `PRIVATE-06` | `EXTERNAL_BLOCKED` | Produce reproducible threshold-signed browser builds, transparency inclusion, staged update, revocation, downgrade rejection, and rollback evidence. |
| `PRIVATE-07` | `EXTERNAL_BLOCKED` | Keep P2/P3 proof, malicious MPC, deep mix, and custom-engine assurance disabled until full relation, leakage, performance, and independent-verifier gates pass. |

### Track K — application economy

| ID | State | Work and exit |
|---|---|---|
| `APP-01` | `READY` | Bind MindScan to durable indexer truth, exact chain identity, finality labels, bounded search, restart-safe data, and live smoke evidence. |
| `APP-02` | `READY` | Freeze governance and treasury proposal, vote, execution, delay, emergency, delegation, accounting, and exit laws before UI activation. |
| `APP-03` | `READY` | Freeze unique-asset identity, ownership, transfer, royalty, listing, sale, cancellation, and marketplace conservation laws. |
| `APP-04` | `READY` | Add conservative operation-specific pricing, deviation bounds, last-good-price behavior, independent reporters, rotation, and rejected-update monitoring. |
| `APP-05` | `READY` | Implement backstop liquidation, bad-debt reserve, direct redemption, PSM inventory, separate caps, and pause-with-redemption behavior. |
| `APP-06` | `OWNER_BLOCKED` | Freeze lending and bridge targets only after oracle, liquidation, cross-chain verification, exposure, failure, and emergency designs receive independent review. |
| `APP-07` | `EXTERNAL_BLOCKED` | Run conservation, oracle divergence, liquidation cascade, thin liquidity, bad debt, bridge reconciliation, wallet review, incident, and capped-value campaigns. |

### Track L — protocol-v2 and production promotion

| ID | State | Work and exit |
|---|---|---|
| `PROMOTE-01` | `OWNER_BLOCKED` | Sign protocol/API/peer v2 identity, predecessor root, schemas, domains, bounds, authorization, rollback, and mixed-version rejection. |
| `PROMOTE-02` | `OWNER_BLOCKED` | Resolve production chain, genesis, authorities, economics, operators, origins, retention, and release constants in exact signed records. |
| `PROMOTE-03` | `READY` | Produce exact-revision protocol, cryptography, economics, operations, wallet, and browser audit handoff bundles with reproducible commands and raw vectors. |
| `PROMOTE-04` | `EXTERNAL_BLOCKED` | Complete deterministic cross-language vectors, mutation/fuzz, small-state, model/runtime, authorization, and independent reproduction. |
| `PROMOTE-05` | `EXTERNAL_BLOCKED` | Run all client pairings across two independently managed client/verifier families with restart, snapshot, proof, unknown-tag, oversize, WAN, and AI-off tests. |
| `PROMOTE-06` | `DURATION_BLOCKED` | Collect 90 public cryptographic/economic days, 30 application days, and seven uninterrupted AI-off days at the exact frozen revision. |
| `PROMOTE-07` | `OWNER_BLOCKED` | Complete parameter Quiet Week, post-freeze Bitcoin anchor, multiparty DKG, final genesis reproduction, and all-AI-off bootstrap demonstration. |
| `PROMOTE-08` | `EXTERNAL_BLOCKED` | Run a 180-day capped-value canary with one-checkpoint disable, target recovery, independent exits, WAN, blackout, and saturation drills. |
| `PROMOTE-09` | `OWNER_BLOCKED` | Collect final multiparty signatures over identical release, genesis, evidence, role, governance, and cutover bytes only after every lower gate passes. |
| `PROMOTE-10` | `READY` | Rebaseline all base and WWM claims at one exact revision; run every actionable falsifier and preserve every negative or killed result append-only. |

### Track M — external prerequisites

| ID | State | Work and exit |
|---|---|---|
| `EXT-01` | `EXTERNAL_BLOCKED` | Recruit independent executor, custodian, indexer, validator, challenger, and public-testnet operators with truthful beneficial ownership. |
| `EXT-02` | `EXTERNAL_BLOCKED` | Recruit independent builders, CPU/GPU vendors, confidential-computing hardware labs, and independent index/client implementers. |
| `EXT-03` | `EXTERNAL_BLOCKED` | Commission exact-revision protocol, consensus, network, state, cryptography, wallet, browser, privacy, and red-team reviews. |
| `EXT-04` | `EXTERNAL_BLOCKED` | Commission independent economics review and target-jurisdiction allocation, stable asset, privacy, consumer, tax, and money-transmission counsel. |
| `EXT-05` | `OWNER_BLOCKED` | Schedule immutable G0 freeze, Quiet Week, Bitcoin anchor, DKG, G2/G3 durations, G4 canary, and final G5 ceremony in dependency order. |
| `EXT-06` | `EXTERNAL_BLOCKED` | Acquire organization-backed Windows signing, Apple Developer ID/notarization, app-store, hardware-key, DNS, cloud, and release-signing credentials through protected stores. |

## Program execution order

1. Run `REL-01` while completing repository-controlled `REL-02` through
   `REL-04`, `INF-*`, `PILOT-01`, `PILOT-04`, and `PILOT-05`.
2. Stabilize `NET-01` and `NET-02`, then finish install, connectivity, worker,
   and native-release work without changing validator admission.
3. Freeze participant identity before any duration or independence campaign.
   A second key, process, VM, account, or subscription under the same
   beneficial owner never counts as independence.
4. Complete deterministic model custody and public inference evidence before
   activating knowledge retrieval.
5. Complete rights-aware MindLink and retrieval evidence before creating a
   training candidate.
6. Keep private suites, the custom browser engine, arbitrary workloads,
   material-value applications, and every production promotion disabled until
   their exact gates pass.
7. Treat external recruitment, audits, counsel, credentials, and elapsed time
   as explicit blockers. Repository code and owner-controlled CI cannot
   manufacture independent evidence.
