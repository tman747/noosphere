---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Node deployment, recovery, DKG, and key operations

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md). Production descriptors, genesis, peers, signatures, and DKG participants do not yet exist.

## Deployment profiles

A validator runs `noosd` with immutable chain descriptor/genesis, consensus voting enabled, protected signing/DKG authorities, full consensus-body reconstruction, durable safety WAL, bounded RPC, and monitoring. A full node performs independent verification/reconstruction without validator keys. A light node verifies headers/finality and treats DA sampling as probabilistic; it must label social weak-subjectivity inputs. All profiles verify artifact signature/checksum/SBOM metadata and exact chain ID, genesis hash, protocol/API version before opening state. Linux uses user `noosphere`, root `/var/lib/noosphere`, and `noosd.service`; Windows uses `%ProgramData%/MindChain/NOOSPHERE`.

Deployment must fail closed on missing immutable identity, unsupported architecture, checksum/signature mismatch, truncated artifacts, or old-chain paths. RPC should be bearer-authenticated where configured, rate limited, and separated from consensus mailboxes. Optional worker processes cannot read validator keys or block the base supervisor.

## Recovery

Stop voting before ambiguous recovery. Preserve logs, WAL, safety records, descriptor, and failing snapshot. Select only a finalized chain-matching snapshot from multiple peers; verify manifest checksums, roots, proof samples, and tail replay in a fresh process. Snapshot publication uses same-filesystem staging, flush/fsync, atomic `CURRENT` replacement, and retains verified generations N and N-1 plus WAL until restart proof. Never replace live state directly or delete the last verified generation. Before resuming voting, prove no double-vote/reveal risk, correct historical validator sets, peer identity, finality, and telemetry freshness.

## DKG and key operations

Production DKG is **OWNER_BLOCKED** and occurs only after Quiet Week and Bitcoin-anchor selection. Participants use independent OS CSPRNGs; deterministic dealers, seeds, embedded shares, and historical keys are forbidden. The v2 ceremony first freezes a non-final core over commitments, reviews, complaints, exclusions, and erasure attestations. It finalizes only after at least the threshold number of distinct active participants authenticate independently recomputed aggregate public shares and valid BLS final-share possession proofs bound to the exact core. Signed `VALID` reviews without threshold possession remain incomplete. Ephemeral coefficients/nonces are erased after verification.

Backups must be encrypted, access-controlled, geographically separated, restore-tested, and inventory signing, recovery, view, agent, Umbra, DKG, and operator credentials separately. View or agent keys cannot spend. Rotation is a versioned, chain/epoch-bound handover with old/new possession proofs, activation boundary, rollback/abort conditions, and persisted safety state. Suspected signing-key compromise stops voting, preserves evidence, initiates registered handover/exit, and never restores an old key into an uncertain epoch. No documentation or evidence bundle may contain secrets, mnemonic words, raw shares, nonces, bearer tokens, or recovery material.
