# NOOSPHERE production authorization and ceremony tooling v1

Status: executable scaffolding; every production input remains owner- or
external-blocked. This document and its tooling do not pass `GENESIS`, change a
claim state, authorize a launch, or establish that any signer is an independent
human.

The entry point is `python tools/genesis/production_authorization.py`. Every
record-writing command refuses to overwrite an existing path. Long-term
Ed25519 role keys are supplied by their owners and are never created by the
tool. Private-key JSON accepts a 32-byte seed only so operators can connect an
approved key handoff; PEM Ed25519 keys are also accepted. The public keyring is
an owner artifact based on `role-keyring.template.json`.

## Authorization sequence

1. Owners replace every placeholder in
   `mainnet-parameters.template.toml`, set `is_template=false` and
   `owner_signed=true`, choose the exact revision and DKG population, and
   publish a non-fixture role keyring. Engineering must not choose those
   values.
2. After owners set `repro-policy-v1.toml` state to `SIGNED`,
   `sign-policy` emits detached Ed25519 signatures by the release owner and
   build reviewer. `freeze-parameters` compiles the exact fixed-order
   `GenesisParameterManifestV1`, verifies the signed policy, derives
   `parameter_manifest_hash` and `chain_id`, and signs the freeze. JSON/TOML
   bytes are never used as the parameter-manifest preimage.
3. `record-publication` fetches the publicly served canonical freeze over
   HTTPS and records the live UTC observation. `verify-quiet-week` has no
   production time override: it requires at least 604800 elapsed system-clock
   seconds and a second live byte-identical HTTPS fetch. These observations do
   not prove continuous availability between them and simulated time never
   counts.
4. `sign-bitcoin-anchor` and `verify-bitcoin-anchor` validate an owner-supplied trusted Bitcoin header,
   each subsequent 80-byte header, double-SHA256 PoW, mainnet target bound,
   contiguous heights, previous-hash links, unchanged difficulty outside a
   retarget, explicit minimum chainwork, post-Quiet-Week header time, and
   post-Quiet-Week observation. A bundle that crosses a retarget is refused;
   supply a newer externally verified checkpoint instead. The validated
   bundle receives detached freeze-role signatures before later stages accept
   it.
5. The signed DKG descriptor fixes threshold and participants. Each
   `dkg-contribute` call creates only that participant's ephemeral polynomial
   through the OS CSPRNG and emits signed Feldman commitments plus a private
   state file. `dkg-share` creates a signed private packet for one recipient;
   `dkg-review-share` emits a signed receipt or a verifiable complaint. The
   transcript verifier requires every dealer/recipient pair, exact complaint
   exclusions, a surviving threshold, ordered unspliced records, the summed
   group key, and a reproducible `D-DKG-TRANSCRIPT` root.
   `dkg-finalize-share` verifies one private packet from every active dealer,
   sums the recipient's long-lived threshold share, and checks its public
   share against the aggregate Feldman vector before writing secret state.
6. `dkg-confirm-erasure` will not delete secrets or pretend deletion is
   provable. It runs only after the named private-state path is absent and the
   operator supplies the exact confirmation sentence. Its output explicitly
   remains a signed operator attestation, not proof of physical-media erasure.
7. `rebuild-final-genesis` verifies all preceding artifacts, encodes the exact
   `FinalGenesisBodyV1`, independently derives `genesis_hash`, and creates a
   signed rebuild record. The caller must supply the role key and participant
   identity; the role label alone does not prove independence.
   `freeze-final-identity` rechecks every component and rebuild record, emits
   the `chain_id`/`genesis_hash` bundle, and requires all three final roles.
   Final identity freeze and cutover records remain authorization artifacts,
   never gate verdicts.
8. `verify-cutover` requires matching hashes for the promotion ledger, release
   manifest, final identity freeze, and prepared cutover; an exact revision and
   chain/genesis identity; all seven existing gate records already `PASSED`;
   and valid signatures for release-owner, build-reviewer, operations-owner,
   and security-reviewer. With the current blocker ledger it must refuse.

Production DKG packets and polynomial state contain secrets. Operators must use
approved confidential transport, storage, backup, and erasure processes. Test
keys and synthetic headers belong only in test fixtures and are not production
signatures or evidence.
