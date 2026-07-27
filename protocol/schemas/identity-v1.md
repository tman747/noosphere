# NOOSPHERE Protocol Identity — v1 (FROZEN except OWNER_BLOCKED items)

Status: FROZEN at G0 for all items not marked `OWNER_BLOCKED`.
Authority: plan §2.3–§2.5; `C:/tmp/noosphere/01-architecture.md` §6.2, §16.2 (read-only evidence).
Changing any frozen item after G1 creates a **new protocol version and new vectors**; it is
never a cosmetic rename.

Naming rule (global): the public product name is **MindChain**. The internal protocol
codename is **NOOSPHERE**. All wire-visible, machine-consumed identifiers use the neutral
`NOOS`/`noos` namespace. User-facing UI strings say MindChain; consensus bytes never do.

## 1. Identity table

| Facet | Frozen value |
|---|---|
| Public product name (UI strings only) | `MindChain` |
| Protocol codename | `NOOSPHERE` |
| Wire prefix / hash-domain namespace | `NOOS` (all consensus hash domains begin `NOOS/`; BLS DSTs begin `NOOS-BLS-`) |
| Native asset ticker | `NOOS` |
| Base unit | `micro-NOOS`, exactly **6 decimals** (1 NOOS = 1,000,000 micro-NOOS); all consensus amounts are integer micro-NOOS |
| Address HRP | `noos` |
| libp2p protocol namespace | `/noos/` (closed list, §3) |
| Rust crate namespace | `noos-*` (e.g. `noos-codec`, `noos-crypto`, `noos-lumen`, `noos-grain`, `noos-store`, `noos-p2p`; compiler CLI package is `noos-weftc` exposing binary `weftc`) |
| Binaries | `noosd`, `noos-cli`, `noos-workerd`, `noos-indexer` |
| Environment-variable prefix | `NOOS_` |
| Linux service user | `noosphere` |
| Linux state root | `/var/lib/noosphere` |
| Linux systemd unit | `noosd.service` |
| Windows state root | `%ProgramData%/MindChain/NOOSPHERE` |
| Prometheus metric prefix | `noos_*` |
| Test-network asset label | `NOOS_TEST` (valueless; genesis carries `is_test_network = true`) |

## 2. Address encoding

- Encoding is **BIP-350 Bech32m**. Bech32 (BIP-173 checksum constant 1) is rejected for
  all lengths; only the Bech32m checksum constant is valid.
- HRP is exactly `noos` — strict comparison, no aliases, no case folding of a non-canonical
  HRP into validity.
- **Canonical output is lowercase.** Decoders MUST reject any address containing an
  uppercase character, including all-uppercase; mixed case is rejected by Bech32m itself,
  and the all-uppercase form permitted by BIP-173 display rules is NOT accepted on any
  API, RPC, wallet, or consensus surface.
- The 5-bit → 8-bit conversion enforces **zero padding**: non-zero padding bits or an
  incomplete final group reject. Decoded payload length is checked against the frozen
  layout for its version/type **before** any allocation or interpretation.
- No checksum-error correction is ever attempted; a failed checksum is a terminal reject.

### 2.1 Version/type/payload byte layout — `OWNER_BLOCKED`

The research corpus does not fix an exact address payload layout (version byte set, type
discriminants, payload widths). Per plan §2.3, absent source authority this is
**OWNER_BLOCKED**: it enters code only through a signed owner decision record appended to
this file as `identity-v1` amendment 1, never through a codec default. Until then:

- No crate may define a default address version, type discriminant, or payload width.
- `noos-codec` address support compiles behind the layout table; a missing table is a
  build error, not a runtime fallback.

### 2.2 Address vector requirements (due with the layout amendment)

Positive vectors — for every admitted (version, type) pair:

1. Minimum-length and maximum-length payloads, canonical lowercase encoding, byte-exact.
2. Round-trip: decode(encode(payload)) == payload for every admitted length.
3. At least one vector per key-material class (sign, view where addressable, contract/object).

Negative vectors — each MUST reject with the named error class:

1. Bech32 (non-Bech32m) checksum on otherwise-valid data → `bad_checksum`.
2. Any uppercase or mixed-case input, including valid-if-lowercased → `non_canonical_case`.
3. Wrong HRP: `mind`, `noo`, `nooss`, `NOOS`, empty → `wrong_hrp`.
4. Non-zero padding bits; truncated final group → `bad_padding`.
5. Payload one byte short / one byte long for the declared version/type → `bad_length`.
6. Unknown version; unknown type under a known version → `unknown_version` / `unknown_type`.
7. Checksum valid but character outside the Bech32 charset positions → `bad_charset`.
8. Historical `mind1...` addresses (corpus of real Ascent addresses) → `wrong_protocol_identity`.

## 3. libp2p protocol identifiers (closed list)

Transport is libp2p QUIC with peer identity binding. The current
`protocol_version = 2` closed list is below; an unknown `/noos/` protocol or
any non-`/noos/` protocol string on a NOOSPHERE listener is refused at
negotiation:

```
/noos/braid/header/1
/noos/braid/body/2
/noos/braid/vote/1
/noos/lumen/tx/1
/noos/sync/range/1
/noos/sync/snapshot/1
/noos/sync/light-update/2
/noos/blob/shard/1
/noos/loom/receipt/1
```

## 4. Hash domains and cryptographic contexts

Every BLAKE3 context, Ed25519 signed-object prefix, BLS ciphersuite DST, and HKDF
salt/info string is registered in `protocol/spec/crypto-domains-v1.csv` — a **closed
table**. A cryptographic call site without a registered row fails CI; duplicate or
prefix-colliding context strings fail CI (checker: `tools/inventory/check_domains.py`).

Identity derivation (plan §2.4; `H` = BLAKE3-256 over the shown domain bytes and
canonical fixed-width encoding — a JSON/TOML map serialization is never hashed):

```
parameter_manifest_hash = H("NOOS/GENESIS/PARAMS/V1" || canonical(GenesisParameterManifestV1))
chain_id                = H("NOOS/CHAIN/V1"          || parameter_manifest_hash)
genesis_hash            = H("NOOS/GENESIS/FINAL/V1"  || chain_id || bitcoin_anchor
                                                     || dkg_root || canonical(FinalGenesisBodyV1))
```

`GenesisParameterManifestV1` explicitly excludes the later Bitcoin anchor and DKG
transcript; any frozen-parameter change restarts Quiet Week and creates a new `chain_id`.

Chain binding: `chain_id` and (post-ceremony) `genesis_hash` are bound into every
signature, proof, descriptor, node config, index database, wallet handshake, release
manifest, and RPC `/api/status` response.

Wallet key derivation uses purpose-separated hardened paths (architecture §6.2):

```
m/NOOS/1/sign/account/index
m/NOOS/1/view/account/index
m/NOOS/1/umbra/suite/account/index
m/NOOS/1/agent/account/index
m/NOOS/1/recovery/account/index
```

No view or agent authority can spend. Numeric hardened path constants are frozen in
`protocol/spec/constants-v1.toml` (G0 constants table, out of scope here).

## 5. `wrong_protocol_identity` rejection rule

NOOSPHERE is a new genesis. Nothing from the historical Ascent chain is accepted,
converted, or migrated. Every verifier, decoder, and endpoint MUST reject — with the
stable error class `wrong_protocol_identity`, never silent failure, never
auto-conversion — any artifact carrying historical identity, including:

- `mind`-HRP addresses (any case, any checksum variant);
- any BLS signature or proof produced under an `ASCENT-*` DST;
- any object hashed under an `ascent.*` or `ASCENT/` domain string;
- Ascent chain IDs, genesis hashes, descriptors, snapshots, receipts, blocks,
  finality certificates, and validator/DKG key material;
- Ascent wire protocols, RPC schemas, index databases, and wallet state roots.

The rejection fires **before** signature or proof verification work (unknown
object/domain fails first), and before any state read or write. Historical data may be
served read-only elsewhere only under an explicit old-chain label; it never enters a
NOOSPHERE code path as input. `tools/gates/check_identity.py` enforces this boundary
with an adversarial corpus of old addresses, signatures, blocks, receipts, and configs;
this document is the allowlisted provenance text that may name the old identifiers.

## 6. Public UI strings

Explorer, wallet, site, installers, and documentation display **MindChain** (e.g.
"MindChain Wallet", bundle ID `network.mindchain.noosphere.wallet`, URL scheme
`mindchain-noos://`). "NOOSPHERE" appears in public materials only as technical
provenance ("NOOSPHERE research corpus"). No machine identifier uses "MindChain" casing
on the wire.
