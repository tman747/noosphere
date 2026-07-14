# WWM route protocol v1 — experimental application profile

Status: proposed application protocol; all activation controls are disabled. This document does not amend the frozen `/noos/` identity protocol list and does not make routing part of base consensus.

## 1. Security boundary

Route privacy and compute privacy are independent. A route profile states who can observe source and destination metadata; it says nothing about who can read inference plaintext. A compute profile states who can read prompt, context, activations, KV state, logits, and output; it says nothing about network metadata.

Private route failure is terminal for that request. Implementations MUST NOT retry over direct HTTP, direct DNS, another privacy profile, or an unpinned gateway. Direct mode is valid only when selected before request construction.

A destination account can identify its logged-in user. Fast-private mode does not resist a global passive observer. Deep-private mode makes no global-observer claim until E-WWM-09 passes independently.

## 2. Canonical fields

All fixed-width integers are little-endian. Hashes and Ed25519 public keys are 32 bytes; signatures are 64 bytes. Lists carry a `u16` element count, are strictly sorted where their order has no semantic meaning, reject duplicates, and reject trailing bytes. Bounds are checked before allocation.

Signatures use:

`NOOS/SIG/WWM/V1 || object_hash_domain_registry_id || object_id || canonical_body`

under registered domain `D-SIG-WWM`.

## 3. `RouteDescriptorV1`

Identity domain: `D-WWM-ROUTE-DESCRIPTOR`.

Canonical body:

1. version `u16 = 1`;
2. operator Ed25519 key;
3. role `u8`;
4. ordered transport list (`u8` count followed by `u8` identifiers);
5. control-cluster root;
6. region `u16`;
7. ASN `u32`;
8. software-lineage root;
9. optional attestation-policy ID (`u8` presence plus 32 bytes when present);
10. logging policy `u8`;
11. retention seconds `u32`;
12. capacity requests/minute `u32`;
13. price micro-NOOS/megabyte `u64`;
14. application bond micro-NOOS `u64`;
15. valid-from epoch `u64`;
16. expiry epoch `u64`.

Roles:

| ID | Role |
|---:|---|
| 1 | ODoH proxy |
| 2 | OHTTP relay |
| 3 | onion/MASQUE ingress |
| 4 | onion/MASQUE middle |
| 5 | onion/MASQUE egress |
| 6 | registered Sphinx mix |
| 7 | confidential remote browser |

Transports:

| ID | Transport | Permitted use |
|---:|---|---|
| 1 | ODoH | DNS resolution only |
| 2 | OHTTP | discrete query, quote, status, and receipt requests |
| 3 | onion over MASQUE | general routed streams |
| 4 | registered Sphinx suite | fixed-packet deep routing |
| 5 | encrypted confidential-render stream | P1 remote browser only |

Logging policy `0` means no request metadata retention and requires retention seconds `0`. Policy `1` means bounded aggregate-only operational counters and requires a nonzero declared retention. Neither policy permits job, user, destination, circuit, packet, or stable credential identifiers in telemetry.

A remote-browser descriptor MUST carry an admitted attestation-policy ID. Every descriptor has one control cluster, region, ASN, and software lineage. Multiple keys do not manufacture diversity.

## 4. `RoutePolicyV1`

A route policy binds:

- policy ID;
- mode;
- minimum hop, region, ASN, and control-cluster counts;
- minimum application bond;
- exact power-of-two frame bucket;
- maximum circuit lifetime;
- logging requirement;
- explicit direct-fallback bit;
- optional remote-browser attestation policy.

Modes:

| Mode | Minimum construction | Direct fallback |
|---|---|---|
| Direct | one explicit local/direct path | selected mode itself |
| Fast private / discrete | independent ODoH proxy and OHTTP relay | forbidden |
| Fast private / circuit | onion ingress, one or more middle hops, and egress | forbidden |
| Deep private | at least three registered mixes in distinct control clusters | forbidden |
| Confidential remote browser | private route ending at a policy-matched P1 browser | forbidden |

Private policies with `allow_direct_fallback = true` are invalid objects, not warnings.

## 5. Circuit selection

Selection input binds finalized randomness, a fresh client nonce, policy ID, descriptor ID, and finalized registry epoch under `D-WWM-ROUTE-DESCRIPTOR`. Eligible descriptors MUST be live, policy-compatible, sufficiently bonded, within capacity, and from distinct declared control clusters. Region and ASN minima are checked after selection.

Circuit IDs commit to policy, fresh client nonce, creation epoch, and ordered descriptor IDs. Circuit IDs and packet queue IDs are local coordination metadata and MUST NOT be published as stable cross-job identifiers.

No route-selection result changes proposal weight, finality weight, issuance, transaction validity, or validator eligibility. `WWM_ROUTE_CONSENSUS_WEIGHT` is exactly zero.

## 6. Fast-private sidecars

- ODoH is used only for DNS. The proxy and target resolver MUST be independently controlled under the registered policy.
- OHTTP carries discrete, bounded request/response APIs. It is not labeled as a general web tunnel.
- General streams use an admitted onion/MASQUE suite. The circuit must change before a failed request can be retried; a retry remains within the same pinned privacy policy.
- Frames use the policy's fixed power-of-two bucket. The encrypted inner length is not emitted in route telemetry.
- DNS, WebRTC, QUIC migration, captive portal, and proxy-auth bypasses fail closed.

## 7. Deep-private sidecar

`noos-mix` accepts exact-bucket ciphertext from a separately registered Sphinx implementation. Its local scheduler provides bounded exponential delays, cover packets, loop/drop decisions, capacity bounds, and deadline expiry. Local packet IDs, queue times, and dispositions are never wire fields.

The repository primitive does not claim to implement Sphinx cryptography. A production deep route requires an independently reviewed suite that provides per-hop unlinkability and re-randomization while preserving the exact packet bucket. E-WWM-09 must test the complete live construction against global capture and active delay/drop/watermark attacks.

## 8. Lifecycle

`Proposed -> RegisteredDisabled -> LabEligible -> EvidencePassed -> Canary -> Enabled -> ExpiredOrRevoked`

This repository stops at `RegisteredDisabled`. A descriptor may expire or be revoked without changing historical receipts. A route-policy failure transitions the local circuit to `FailedClosed`; only a fresh user-selected request can create a replacement circuit.

## 9. Protocol-version boundary

Future native transports require a reviewed amendment to the frozen identity/p2p schema and new protocol strings. No implementation may advertise unregistered `/noos/route/*`, `/noos/mix/*`, or browser protocol IDs before that amendment passes G0. HTTP sidecars may be tested as application services without changing the native protocol registry.
