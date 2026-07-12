---
doc_bundle: v1
protocol_version: v1
api_version: v1
release_version: 0.0.0-preproduction
chain_id: OWNER_BLOCKED
genesis_hash: OWNER_BLOCKED
status: PREPRODUCTION_OWNER_BLOCKED
---
# Loom, NEL, Umbra, BESI, and experimental assurance disclosures

> **OWNER_BLOCKED / NOT A PRODUCTION RELEASE.** See [bundle status](index.md). Implementation, evidence, lifecycle, result, and enabled state are separate; none of these mechanisms is promoted by this page.

## Work Loom

Loom may settle ordinary application work through escrow, receipts, disputes, and DA without minting or consensus influence. The current Lumen V0 compute market implements signed worker registration, exact integer escrow, claim, result commitment, requester acceptance, settlement, refund, and timeout cancellation for deterministic MIX32 shards. The requester/coordinator recomputes the result before accepting it; this is paid acknowledgement, not a general correctness proof, confidential execution, arbitrary-code sandbox, or NEL activation. At genesis and now: `work_loom_credit_enabled=false`, `work_loom_weight_cap=0`, proofpower disabled, and duplex reallocation zero. Zero jobs yields zero Loom contribution. Demand classification is descriptive telemetry only. E-DEMAND-WASH-01 is binding; proposal credit/proofpower/duplex require a new claim and preregistered absolute attack-payoff result.

## Neural Execution Lane (NEL)

NEL output is challengeable computation, not an oracle of truth. Assurance depends on exact model/profile, transcript, chunking, verifier/challenger diversity, DA, dispute coverage, bond/value relation, and enabled suite. SOFT cannot authorize irreversible value. G4 restricts NEL to the registered 0.5B profile and `bond_min ≥ 2 * value_ceiling + dispute_cost_reserve`. Latency does not imply correctness or privacy. AI blackout must leave base consensus operational.

## Umbra

“Umbra” is not a generic confidentiality claim. Every suite publishes its exact leakage, assumptions, corruption threshold, setup/key epoch, abort/blame behavior, proof coverage, performance envelope, exit, and lifecycle. Unknown or disabled suites reject. Non-base suites remain disabled by default. Hidden footprints, HFHE, and proof-carrying refresh remain experimental; only complete standard-assumption, independently implemented, compact, publicly verified results can propose a suite.

## BESI and malicious 3PC

BESI covers only its registered bounded relation and leakage profile; it is not FHE, universal private computation, or protection from compromised endpoints. The separate malicious 3PC experiment uses a pinned MP-SPDZ malicious honest-majority three-party replicated-ring profile, assumes at most one active corruption, and requires authenticated sharing/MAC checks, sacrifice, input consistency, complete transformer nonlinear/KV/logit/decoding coverage, private disputes, selective-abort/blame analysis, restart/key epochs, and independent reproduction. Unsupported operations or failed performance are recorded as negative results and leave the suite disabled; they are not relabeled BESI.

## Other experimental lanes

Reflex v1 is withdrawn; E-DREAM-02 keeps the general dream market non-authoritative and payout-free; I-PENTAGON remains shadow-only; Species/Loam global authority, training slashing, foresight, useful-work consensus credit, and proofpower remain disabled unless their exact gates pass. A failure is a valid research result: quarantine, refund/exit where defined, preserve evidence, and keep ordinary Braid/Lumen/Grain release independent.
