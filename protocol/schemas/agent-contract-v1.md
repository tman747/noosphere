# NOOS agent and ordinary-contract host v1 (PROPOSED-G0)

Normative crates: `noos-agent-class`, `noos-contracts`, and `noos-grain`. Object field order and widths remain those frozen in `spec/schema-tables/lumen-objects.md`.

## Agent identity and capability firewall

`agent_id = BLAKE3("NOOS/AGENT/ID/V1" || genesis_manifest_root || controller_policy_root)`. Rotating model, host, or active-key roots changes the AgentID record version but not this stable ID.

A `CapabilityGrant` is accepted only when its committed ID matches all frozen fields and its subject is registered. Authorization checks, in order: known agent and grant, exact subject, revocation `(grant_id, revocation_nonce)`, action membership, object membership, per-action limit, grant and intent expiry, finalized prestate root, computed postcondition root, typed direction, nonce replay, and cumulative budget with checked arithmetic. Any failure produces no effect and consumes no grant budget or nonce.

Retrieved text, model output, and tool output inhabit `UntrustedText`. They can produce only a `Proposal<Intent>`. The effect type has a private constructor and is returned only by the deterministic firewall. `Refund` direction is `ToAgent`; `Transfer`, `Donate`, and `ContractCall` direction is `FromAgent`. Natural-language claims cannot override this field.

## Ordinary Grain contract host

Every call has explicit immutable context: chain ID, genesis hash, transaction ID, caller, callee, block height, finalized prestate root, and call depth. State and canonical arguments are explicit Grain subject fields. Grain evaluation is synchronous and deterministic.

The transaction object access list maps each ObjectID to `Read` or `ReadWrite`. A missing object traps `UNDECLARED_READ` before lookup; a write without exact `ReadWrite` traps `UNDECLARED_WRITE` before mutation. There is no fallback global-state read.

Contract manifests declare a call-class bitset and one reentrancy policy: `Disabled`, `AllowDifferentObject`, or `Allowed`. Calls are synchronous, have a maximum depth of 64, and push the callee before evaluation. Disallowed class, recursion, or depth fails before callee effects.

Code upgrades require `DeclaredMigration`, a new code hash, a Grain migration formula, its exact commitment `BLAKE3("NOOS/CONTRACT/MIGRATION/V1" || canonical_formula)`, and a declared result root `BLAKE3("NOOS/CONTRACT/STATE/V1" || canonical_migrated_state)`. Formula commitment, policy, evaluation, and result root all pass before code hash or state is changed. `Immutable` manifests reject all upgrades.
