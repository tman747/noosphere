# NOOSPHERE Transport — p2p-v1 (PROPOSED-G0)

Status: PROPOSED at G0. Every constant in this file is `PROPOSED-G0` pending the
constants-table review (plan §1.7); the protocol ID list itself is FROZEN by
`identity-v1.md` §3. Implementation: `crates/noos-p2p`. Authority: plan §7.4;
`C:/tmp/noosphere/01-architecture.md` §10.4 (read-only evidence).

## 1. Transport law

- Transport is **libp2p QUIC** (`quic-v1` multiaddrs). Pinned stack:
  `libp2p = 0.56.0` (features `tokio`, `quic`, `ed25519`),
  `libp2p-stream = 0.4.0-alpha`, resolving to `libp2p-quic 0.13.1`,
  `libp2p-tls 0.6.2`, `quinn 0.11.11`. Changing a pin is a
  protocol-operations decision.
- Peer identity is an **Ed25519 keypair**. The libp2p TLS 1.3 handshake embeds
  the libp2p certificate extension: the connection is cryptographically bound
  to the remote's identity key and the `PeerId` derived from it (certificate
  pinning). Dialing by `PeerId` pins the expected key.
- The SAME Ed25519 key backs the chain-identity attestation (§3); the two are
  cross-checked, so a TLS identity cannot present another key's attestation.
- Every substream carries exactly one request frame and one response frame
  (§4); streams are closed after the exchange.

## 2. Protocol identifiers

Application protocols (closed list, identity-v1.md §3):

| id | shape | lane |
|---|---|---|
| `/noos/braid/header/1` | header announce (push) / header request | priority |
| `/noos/braid/body/2` | bounded body-chunk request → reassembled transfer | priority |
| `/noos/braid/vote/1` | checkpoint vote push | priority |
| `/noos/lumen/tx/1` | transaction push | normal |
| `/noos/sync/range/1` | ascending header range request | priority |
| `/noos/sync/snapshot/1` | snapshot chunk request | priority |
| `/noos/sync/light-update/2` | finalized light-update range request | priority |
| `/noos/blob/shard/1` | DA shard request → transfer | normal |
| `/noos/loom/receipt/1` | loom receipt push (lane OFF at genesis) | normal |

Session-gate protocol (transport addition, PROPOSED-G0):

| id | shape |
|---|---|
| `/noos/handshake/1` | chain-identity attestation exchange (§3) |

libp2p binds TLS identity to the *peer key* but has **no chain-identity
concept**; per plan §7.4 the required behavior is added AROUND libp2p as a
dedicated first substream rather than by switching wire stacks. The
`identity-v1.md` §3 enumerates the nine *application* protocols;
`/noos/handshake/1` is a session gate that carries no application objects.
Any other protocol string — including any unknown `/noos/…` — is refused at
libp2p negotiation because only these ten protocol IDs are registered on a
NOOSPHERE listener.

## 3. Identity-binding law (D-SIG-PEER)

Registered domain (crypto-domains-v1.csv):
`D-SIG-PEER = ED25519_PREFIX "NOOS/SIG/PEER/V1"`.

```
ChainAttestationV1 {            # noos-codec object, version 1
  1 => chain_id:          [u8; 32]
  2 => genesis_hash:      [u8; 32]
  3 => protocol_version:  u16
  4 => peer_pubkey:       [u8; 32]   # Ed25519, same key as the TLS identity
  5 => signature:         [u8; 64]   # fixed-width, not length-prefixed
}
signature = Ed25519_sign(peer_key,
    "NOOS/SIG/PEER/V1" || chain_id || genesis_hash
                       || protocol_version_le_u16 || peer_pubkey)
```

Handshake flow on `/noos/handshake/1`, before ANY application traffic
(frames bounded by `MAX_HANDSHAKE_FRAME_BYTES = 4096`):

```
dialer   -> Attest(A_dialer)
listener -> Attest(A_listener)          # accepts
         |  Reject{code}                # rejects
dialer   -> Ack                         # accepts
         |  Reject{code}                # rejects
```

`HandshakeMsgV1` is `version:u16=1` then discriminant `u16`:
`0 = Attest(ChainAttestationV1)`, `1 = Ack`, `2 = Reject{code:u16}`.

Validation order is LAW (identity-v1.md §5 precedence):

1. `chain_id`, `genesis_hash`, `protocol_version` must equal the local values,
   else reject with code **1 = `wrong_protocol_identity`** — BEFORE any
   signature work. This fires in both directions: a mismatched dialer is
   rejected by the listener, and a mismatched listener is rejected by the
   dialer.
2. `peer_pubkey` must derive the TLS-authenticated remote `PeerId`, and the
   D-SIG-PEER signature must verify strictly, else code
   **2 = `attestation_invalid`**.
3. Undecodable handshake payload: code **3 = `malformed`**.

A rejecting node fails all queued/future sends to that peer, records a
cooldown strike (§7.4), emits the rejection event, and closes the connection
after a short grace (500 ms) so the `Reject` frame outruns the QUIC close.
A session that never completes the handshake within
`HANDSHAKE_TIMEOUT_MS = 5000` is disconnected (`handshake_timeout`).
An application substream from a peer whose handshake is not complete is the
violation `stream_before_handshake` (a 3 s grace covers the final-Ack race).

## 4. Frames

- One frame = `len: u32 LE` then exactly `len` payload bytes.
- `MAX_FRAME_BYTES = 1_048_576` (1 MiB). The declaration is checked BEFORE any
  allocation or payload read; a larger declaration is the violation
  `oversize_frame` → immediate disconnect + cooldown. Honest nodes never emit
  an oversize frame: an unfittable reply is trimmed (§5.5) or refused locally.
- Handshake frames use `MAX_HANDSHAKE_FRAME_BYTES = 4096` under the same law.

### 4.1 Payload bounds (PROPOSED-G0)

| constant | value |
|---|---|
| `MAX_HEADER_BYTES` | 65_536 |
| `MAX_BODY_BYTES` | 1_047_552 (1 MiB − 1 KiB) |
| `MAX_REASSEMBLED_BODY_BYTES` | 134_217_728 (128 MiB) |
| `MAX_VOTE_BYTES` | 8_192 |
| `MAX_TX_BYTES` | 65_536 |
| `MAX_SNAPSHOT_CHUNK_BYTES` | 1_047_552 |
| `MAX_SHARD_BYTES` | 1_047_552 |
| `MAX_RECEIPT_BYTES` | 65_536 |
| `MAX_RANGE_HEADERS` | 128 |
| `RANGE_REPLY_BYTE_BUDGET` | 1_046_528 (1 MiB − 2 KiB) |

## 5. Envelopes (canonical noos-codec)

All envelopes follow the noos-codec object law: `version:u16` then tagged
fields (structs) or `u16` declaration-order discriminants (enums); collections
carry a `u32` length validated against BOTH the bound and remaining input
before allocation; trailing bytes reject; unknown versions/discriminants/tags
reject. **Every request envelope carries `chain_id`** (ch01 §10.4: every
message has chain ID, protocol version, replay domain); a mismatch is the
violation `wrong_chain_envelope` → immediate disconnect, independent of the
handshake law.

### 5.1 `/noos/braid/header/1`

```
HeaderMsgV1   = 0 Announce { chain_id, header:  bytes<=MAX_HEADER_BYTES }
              | 1 Request  { chain_id, header_hash: [u8;32] }
HeaderReplyV1 = 0 Ack | 1 Header(bytes<=MAX_HEADER_BYTES) | 2 NotFound
```

Announce is a push: fresh announces are dispatched to the embedder and
answered `Ack`; duplicates (§7.2) are answered `Ack` without dispatch.

### 5.2 `/noos/braid/body/2`

```
BodyRequestV1 (wire version 2) {
  1 => chain_id, 2 => block_hash: [u8;32],
  3 => offset: u64, 4 => max_bytes: u32
}
BodyReplyV1 (wire version 2)
  = 0 Chunk { total_bytes: u64, offset: u64, bytes<=MAX_BODY_BYTES }
  | 1 NotFound
```

This is also the **targeted repair** primitive: ask a SPECIFIC peer for a
SPECIFIC hash (`P2pHandle::request_body(peer, hash)`). The requester fetches
offset zero first, checks the declared total, allocates no more than
`MAX_REASSEMBLED_BODY_BYTES`, then fetches the remaining fixed offsets through
at most eight concurrent QUIC streams. Every non-final chunk is exactly
`MAX_BODY_BYTES`; the final chunk is exactly the remaining length. Replies must
keep `total_bytes` stable and echo their requested offsets. Missing, short,
overlapping, overlong, or inconsistent replies are `bad_reply`. The 1 MiB frame
ceiling remains unchanged.

### 5.3 Push envelopes

```
VotePushV1        { 1 => chain_id, 2 => vote:    bytes<=MAX_VOTE_BYTES }      # /noos/braid/vote/1
TxPushV1          { 1 => chain_id, 2 => tx:      bytes<=MAX_TX_BYTES }        # /noos/lumen/tx/1
LoomReceiptPushV1 { 1 => chain_id, 2 => receipt: bytes<=MAX_RECEIPT_BYTES }   # /noos/loom/receipt/1
PushReplyV1       = 0 Accepted | 1 Duplicate | 2 Rejected | 3 FeatureDisabled
```

While `work_loom_credit_enabled = false` (genesis law, plan §6.8), every
`/noos/loom/receipt/1` push is answered **`FeatureDisabled`** with no
dispatch — an explicit disabled answer, never empty success (plan §7.7).

### 5.4 `/noos/sync/range/1`

```
RangeRequestV1 { 1 => chain_id, 2 => start_height: u64, 3 => max_headers: u32 }
RangeReplyV1   { 1 => chain_id, 2 => headers: list<bytes<=MAX_HEADER_BYTES> (<=MAX_RANGE_HEADERS)>,
                 3 => more: bool(u8 in {0,1}) }
```

`max_headers` is clamped to `MAX_RANGE_HEADERS`. The reply is trimmed from the
tail until its encoding fits `RANGE_REPLY_BYTE_BUDGET`, setting `more = true`
for anything shed: a trimmed page is indistinguishable from a legitimately
short page and re-arms the requester's continuation (Ascent W7 lesson — an
oversize frame is permanently undeliverable and must never be emitted).

### 5.5 `/noos/sync/snapshot/1`

```
SnapshotChunkRequestV1 { 1 => chain_id, 2 => snapshot_root: [u8;32], 3 => chunk_index: u32 }
SnapshotReplyV1        = 0 Chunk { total_chunks: u32, chunk: bytes<=MAX_SNAPSHOT_CHUNK_BYTES }
                       | 1 NotFound
```

### 5.6 `/noos/blob/shard/1`

```
ShardRequestV1 { 1 => chain_id, 2 => content_root: [u8;32], 3 => shard_index: u32 }
ShardReplyV1   = 0 Shard(bytes<=MAX_SHARD_BYTES) | 1 NotFound
```

Sync algorithms (header-first, snapshot assembly, light sync) live in the node
layer; this file only fixes the request/response substreams they use.

## 6. Outbound scheduling

### 6.1 Lanes (consensus-over-AI)

- **Priority**: `/noos/braid/header/1`, `/noos/braid/body/2`,
  `/noos/braid/vote/1`, `/noos/sync/range/1`, `/noos/sync/snapshot/1`,
  `/noos/sync/light-update/2` (and the handshake).
- **Normal**: `/noos/lumen/tx/1`, `/noos/blob/shard/1`, `/noos/loom/receipt/1`.

Per peer, one request is in flight at a time and the priority lane drains
COMPLETELY before the normal lane sends — so consensus and sync traffic always
precedes AI/application traffic on the wire, and lane order IS wire order.
Each lane is bounded (`outbox_capacity_per_lane = 1024`, PROPOSED-G0); a full
lane refuses the send (`queue_full`) — sender backpressure, never unbounded
memory. An in-flight request interrupted by connection loss is retried once on
the next ready session, then failed.

## 7. Anti-DoS (PROPOSED-G0 constants)

### 7.1 Per-peer per-protocol token buckets

Integer milli-token buckets, `burst` capacity refilled at `per_second`:

| protocol | burst | per_second |
|---|---|---|
| braid/header | 64 | 32 |
| braid/body chunks | 32 | 32 |
| braid/vote | 128 | 64 |
| lumen/tx | 256 | 128 |
| sync/range | 8 | 4 |
| sync/snapshot | 16 | 8 |
| blob/shard | 32 | 16 |
| loom/receipt | 16 | 8 |

An inbound substream that finds an empty bucket is dropped unanswered and
records the violation `rate_limit_exceeded`.

### 7.2 Duplicate caches (replay domain `D-P2P-MSG`)

Push payloads are keyed by the registered content digest

```
digest = BLAKE3-256("NOOS/P2P/MSG/V1" || protocol_id || envelope_bytes)
```

in per-protocol LRU sets (`dup_cache_capacity = 4096` each) covering
header announces, votes, txs, and loom receipts. A duplicate is answered
(`Ack`/`Duplicate`) but NEVER dispatched twice. Local anti-replay only —
never a consensus commitment.

### 7.3 Violations, scoring, disconnect threshold

| violation | penalty | immediate disconnect |
|---|---|---|
| `oversize_frame` | 100 | yes |
| `wrong_chain_envelope` | 100 | yes |
| `handshake_timeout` | 100 | yes |
| `malformed_envelope` | 40 | no |
| `stream_before_handshake` | 40 | no |
| `rate_limit_exceeded` | 15 | no |

Per-session score accumulates; at `DISCONNECT_SCORE = 100` (or an immediate
violation) the peer is disconnected and a cooldown strike recorded. Scores
reset per session. **Peer scores affect local bandwidth and connectivity only
and are never consensus weights** (ch01 §10.4).

### 7.4 Progressive cooldowns

`COOLDOWN_BASE_MS = 30_000`, doubling per strike (`base << (strikes−1)`),
capped at `COOLDOWN_MAX_MS = 600_000`. Strikes persist across cooldowns.
Inbound connections from a cooling-down peer are closed on establishment;
no outbound dial or reconnect targets it until expiry.

## 8. Reconnect backoff (deterministic jitter)

Dialed (static) peers are redialed after connection loss with exponential
backoff: attempt `n` (0-based) draws uniformly from `[exp/2, exp]` where
`exp = min(BACKOFF_BASE_MS << n, BACKOFF_MAX_MS)`; `BACKOFF_BASE_MS = 200`,
`BACKOFF_MAX_MS = 30_000` (PROPOSED-G0). Jitter comes from a **seeded
SplitMix64 stream** (seed mixed with the peer ID), so reconnect schedules are
fully reproducible in tests and simulations; the generator is never used for
key material (plan §3.2). A completed handshake resets the attempt counter.
Rejected (wrong-chain) and cooling-down peers are not redialed.

## 9. Conformance (crates/noos-p2p tests)

Unit: frame bounds (declaration-before-allocation, boundary, truncation),
envelope round-trips and negative decodes (unknown version/discriminant,
forged length, non-canonical bool, trailing bytes), attestation
sign/verify/tamper matrix with `wrong_protocol_identity` precedence, token
bucket, LRU duplicate cache, cooldown progression, lane scheduling, backoff
determinism/envelope/reset.

Loopback (two in-process nodes over 127.0.0.1 QUIC): handshake accept with
attestation binding; wrong-chain rejection in BOTH directions with
`wrong_protocol_identity` and no protocol traffic; one canonical round trip on
each of the eight protocols (incl. `FeatureDisabled` on the loom lane);
oversize frame → violation + disconnect on the receiver; rate-limit trips →
violations + disconnect; duplicate suppression (answered `Duplicate`, single
dispatch); priority ordering under load (a vote queued after a 16-tx burst is
delivered first); unknown `/noos/` protocol refused at negotiation.
