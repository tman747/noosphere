# G3 public-duration deployment

This directory is an operator kit, not evidence that G3 has started. The checked-in
manifest is deliberately `TEMPLATE_NOT_STARTED`; it contains placeholders and
`TEST_ONLY` key declarations. It cannot produce qualifying evidence.

Before a real public run, external operators must copy the template to an immutable
publication location and replace every placeholder with the exact G2-frozen revision,
the byte hash of its reproducible public-testnet release manifest, the testnet identity,
public HTTPS endpoints, and Ed25519 public keys whose usage is
`production-evidence`. Operators must actually be separately managed; distinct strings
in a JSON file are not proof of independence. The verifier requires three operator
observations and at least two distinct valid signatures per daily checkpoint.

At least two configured operators must sign the finalized manifest with
`sign-manifest` before the first checkpoint. Each operator deploys its own copy of
`compose.yaml` (or translates the same mounts and commands into its chosen container
service). The image references must be immutable digests. Build the verifier with an
explicit immutable base, for example
`docker build --build-arg PYTHON_BASE_IMAGE=python:<version>@sha256:<reviewed-digest>`.
TLS and public DNS terminate outside the kit because those controls differ by
provider. `telemetry_url` must expose the signed snapshot JSON through public HTTPS;
Prometheus itself should remain read-only and access-controlled.

Typical daily flow, performed separately by the configured operators:

1. Export exact lane and operator observations from public telemetry.
2. One coordinator runs `create-checkpoint`. The command takes no timestamp argument
   and records both UTC and the operating-system monotonic clock.
3. Each configured operator reviews the checkpoint and runs `sign-checkpoint` with its
   externally provisioned key. A signature proves key control, not human identity or
   organizational independence.
4. `append-checkpoint` verifies the hash chain, current-time freshness, signatures,
   revision, public endpoint binding, counters, and telemetry continuity before one
   atomic NDJSON append. Publish the unchanged ledger to at least two mirrors.
5. Run `verify --live`. It only reports `NOT_STARTED`, `IN_PROGRESS`, or
   `EVIDENCE_COMPLETE`; the last means the record met this evidence format, not that G3
   passed or that the promotion ledger may be edited.

No workflow in this repository signs checkpoints, advances clocks, fills gaps, or
changes `protocol/release/promotion-blockers.json`.
