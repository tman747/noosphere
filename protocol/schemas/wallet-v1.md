# NOOS wallet protocol behavior v1 (PROPOSED-G0)

Normative crate: `noos-wallet`. This document resolves **ODR-WALLET-001**; it does not import any historical chain domain, root, identifier, or vector.

## Identity gate

Before balance lookup, note selection, fee planning, transaction construction, signing, or submission, the wallet compares the node `/api/status` tuple `(chain_id: Hash32, genesis_hash: Hash32, api_version: u16)` with its configured tuple. Chain or genesis mismatch returns `wrong_protocol_identity`; API mismatch returns `api_version_mismatch`. A failed comparison clears any earlier successful handshake. No signing operation is reachable while the gate is closed.

Transaction observations use four distinct values in increasing strength: `MEMPOOL`, `INCLUDED`, `JUSTIFIED`, `FINALIZED`. None is displayed or serialized as another.

## Purpose-separated derivation

The seed input is BIP-39 PBKDF2-HMAC-SHA-512 output. Authority derivation is HKDF-SHA-256 with salt `NOOS/HKDF/WALLET/SALT/V1` and info:

```
ASCII("NOOS/HKDF/WALLET/V1") || be32(path[0]) || ... || be32(path[n])
```

Every numeric component has bit 31 set. Unhardened values are:

| component | value |
|---|---:|
| namespace | `0x4e4f4f53` |
| version | 1 |
| sign | 1 |
| view | 2 |
| umbra | 3 |
| agent | 4 |
| recovery | 5 |

Paths are `namespace/version/purpose[/umbra_suite]/account/index`. Inputs must be below `2^31` before hardening. Exact outputs are frozen in `protocol/vectors/wallet/derivation-v1.json`. Only the `sign` variant can construct a `SpendingKey`; view, umbra, agent, and recovery variants have no spend conversion.

## Keystore, planning, and transport

Keystore v1 uses PBKDF2-HMAC-SHA-256 with exactly 200,000 rounds, a random 16-byte salt, AES-256-GCM with a unique random 12-byte nonce, and AAD `NOOS/WALLET/KEYSTORE/V1`. Authentication failure discloses no plaintext.

Note selection orders candidates by `(amount, note_id)`, accumulates with checked `u128`, and creates change exactly as `selected_total - amount - fee`. Fees are the checked dot product of the six resource quantities and unit prices. RPC TLS requires both the configured DNS name and an allowed SHA-256 SPKI pin.

Signatures cover `NOOS/WALLET/SIGN/V1 || chain_id || genesis_hash || api_version_le || transaction_body`.
