---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Threat model, security assumptions, genesis, and economics

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md).

## Threat model and security assumptions

The base adversary may control network scheduling within modeled bounds, crash/restart nodes, send malformed or replayed messages, equivocate, withhold data/reveals, corrupt peers and optional workers, exploit resource asymmetries, and coordinate declared or hidden beneficial ownership. Cryptographic security assumes the registered primitives and domains remain sound, honest parties protect keys and persist safety state before messages, at least the threshold stake assumptions hold in each historical epoch, full nodes reconstruct consensus data before voting, and operators obtain correct chain-bound software and checkpoints.

Safety does not assume AI, useful work, model availability, worker honesty, privacy marketing, light-client sampling, or effective-weight display. Raw stake remains a mandatory finality threshold. Beneficial ownership cannot be fully verified by consensus; operator/cloud/ASN/hardware/demand diversity therefore remains an external G3–G5 gate. Light-client DA sampling is probabilistic opinion, not full reconstruction. Weak-subjectivity checkpoints are social inputs and never override local finality.

No software claim covers compromised hosts, stolen signing/recovery keys, malicious signed upgrades, an invalid owner decision, broken registered cryptography, or an adversary outside a published experiment envelope. `UNKNOWN` metrics and missing evidence fail closed at their dependent gates.

## Genesis disclosure

The new genesis imports no historical balance, certificate, chain ID, state, validator key, or DKG material. Identity derives in two non-circular stages: Quiet Week freezes a canonical parameter manifest and derives `chain_id`; only after at least seven published days may a post-freeze Bitcoin block be selected and a multiparty DKG completed; the final canonical body, chain ID, anchor, and DKG root derive `genesis_hash`. A frozen parameter change restarts Quiet Week and creates a new chain ID.

Current values: `parameter_manifest_hash=OWNER_BLOCKED`, `chain_id=OWNER_BLOCKED`, `bitcoin_anchor=OWNER_BLOCKED`, `dkg_root=OWNER_BLOCKED`, `genesis_hash=OWNER_BLOCKED`. These are deliberate blockers, not zero hashes.

## Economics, fees, and issuance disclosure

Engineering networks use valueless `NOOS_TEST` with `is_test_network=true`. Production allocation, maximum supply, issuance curve, minimum witness bond, treasury/community shares, rounding, terminal height, and fee disposition are deliberately absent and **OWNER_BLOCKED**. They may enter `mainnet-parameters.toml` only through exact owner approval, exhaustive cap/issuance tests, independent economic review, and required counsel. Values must not be copied from Ascent or inferred here.

The protocol fee shape is five-dimensional integer accounting: `Fee = p_B*B + p_G*G + p_V*V + p_R*R + p_D*D`, with bounded controllers, checked arithmetic, per-resource caps, and a deterministic failure fee. Exact coefficients and caps remain governed by the constants registry. Work-job escrow is separate from base issuance. Useful work never mints. Missed or orphan emission is not recreated. E-DEMAND-WASH-01 binds Loom proposal credit, proofpower, and duplex reallocation to zero absent a new preregistered successor claim that passes its attack-payoff gate; duplex never adds mint.
