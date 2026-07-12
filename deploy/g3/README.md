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

Every qualifying checkpoint also requires an OpenTimestamps proof confirmed in the
Bitcoin main chain. Install the reviewed dependency closure with
`python -m pip install --requirement tools/g3/requirements.lock`. The verifier pins
`opentimestamps-client==0.7.2`, Bitcoin mainnet's genesis block, a minimum of six
confirmations, a 48-hour maximum signature-to-anchor delay, and Bitcoin's two-hour
block-clock admission tolerance. A node whose validated tip is over six hours old is
rejected. Live verification must use a verifier-controlled, synchronized,
fully validating Bitcoin Core node. Its RPC URL is supplied with
`--bitcoin-rpc-url` or `G3_BITCOIN_RPC_URL`; it is not evidence content and must not be
controlled by the checkpoint submitters.
`checkpoint.schema-v2.json` documents the lifecycle envelope; the Python verifier is
the fail-closed authority for all nested telemetry, signature, receipt, and policy
constraints.

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
4. Run `stamp-checkpoint` on the threshold-signed file. It submits only an opaque
   nonce-protected commitment to public OpenTimestamps calendars and attaches the
   pending proof to a new checkpoint file. Operator signatures cover the checkpoint
   payload; the proof covers the exact checkpoint including the complete ordered
   signature set and excluding only `external_timestamp_receipt`. The checkpoint
   payload itself binds the complete finalized manifest, including its manifest
   signature set, plus the exact revision, network, and sequence.
5. After Bitcoin aggregation, run `upgrade-checkpoint`. Do not append while the proof
   is pending. Then run `append-checkpoint --bitcoin-rpc-url ...`; it verifies the
   proof against the current Bitcoin main chain and confirmation policy before one
   atomic append. A following checkpoint's `previous_checkpoint_sha256` covers the
   entire prior record, including its receipt. Publish the unchanged ledger to at
   least two separately hosted public mirrors.
6. Run `verify --live --bitcoin-rpc-url ...`. It checks every proof through the local
   Bitcoin trust root, probes telemetry, and requires both mirrors to exactly match
   the local canonical ledger. It only reports `NOT_STARTED`, `IN_PROGRESS`, or
   `EVIDENCE_COMPLETE`; the last means the record met this evidence format, not that G3
   passed or that the promotion ledger may be edited.

Offline `verify` performs strict schema, signature, hash-chain, commitment, and
OpenTimestamps proof parsing, but it cannot establish current-chain inclusion and
therefore can never return `EVIDENCE_COMPLETE`. Qualifying duration and AI-off duration
are computed only between live-verified Bitcoin block times, never from checkpoint wall
times. A checkpoint whose claimed observation/signature window diverges from its block
time is rejected, so stamping an old, preassembled ledger today cannot create historical
duration.

For this evidence protocol, the first qualifying external publication time is the
live-verified Bitcoin block time: cryptographic timestamping proves that the exact
signed bytes existed no later than that approximately timed block (subject to the
documented tolerance). It does not prove organizational independence, truthful
telemetry, or human review. Independent operator signatures and two live public
mirrors remain separate requirements; mirror publication is checked independently.

No workflow in this repository signs checkpoints, advances clocks, fills gaps, or
changes `protocol/release/promotion-blockers.json`.
