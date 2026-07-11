# Data-availability schema table (G0 freeze candidate)

Source: `C:/tmp/noosphere/01-architecture.md` §10.1–10.2, ch04 §3.1 A-DA, ch05 §6
(NEL trace namespace), plan §7.1–§7.2.

## Consensus-body coding law (ch01 §10.1)

- Proposers Reed–Solomon encode the block body into **fixed-size shards** and
  commit a Merkle root (`body_da_root`, header field 11 in header-body.md).
- Full nodes reconstruct and verify the entire body before accepting the block.
- Witnesses MUST NOT vote a checkpoint containing an unreconstructed ancestor.
- Light-client sampling is a probabilistic availability opinion only; it never
  makes an unavailable body valid for a full node.
- Gate (ch04 A-DA): 99.99% reconstruction over 10^6 randomized in-bound loss
  trials; zero finalization before the availability certificate; failure halts at
  the last available checkpoint and AI evidence clocks do not start.

### Consensus-body shard parameters — UNRESOLVED_SOURCE / PROPOSED-G0

ch01 fixes the shape (fixed-size shards, Merkle commitment) but no numbers.
Search terms tried: shard size, fixed-size shards, data shards, parity, KiB, MiB,
Reed-Solomon rate. The 8-of-12 figure in ch04 H-SEED is Hearth content
distribution, **not** consensus DA. Proposed engineering values for review
(ODR-DA-001/002):

| Parameter | Proposed value | Status |
|---|---:|---|
| `body_shard_bytes` | 65,536 (64 KiB) | PROPOSED-G0 |
| `body_data_shards` | 16 | PROPOSED-G0 |
| `body_parity_shards` | 16 | PROPOSED-G0 (rate 1/2; reconstruct from any 16 of 32) |
| `max_block_body_bytes` | 1,048,576 (16 × 64 KiB data) | PROPOSED-G0, must co-freeze with fee capacity ODR-FEES-002 |
| `max_blob_bytes` | 262,144 per descriptor | PROPOSED-G0 |
| `max_consensus_blob_descriptors_per_block` | 64 | PROPOSED-G0 (mirrors header-body.md body field 6) |
| `p2p_max_frame_bytes` | 1,048,576 (1 MiB) | plan §7.4 (ported Ascent bound) |

## BlobDescriptor (ch01 §10.2; field list src, widths PROPOSED-G0)

Consensus blobs are fee-paid (dimension D) and retained through their declared
horizon; archival beyond it is a market. Consensus-body storage is separated from
Work Loom/model/evidence artifact storage so blobs cannot starve consensus IO
(plan §7.2).

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `namespace` | u32 (PROPOSED-G0) | registry-scoped; unknown namespace rejects |
| 1 | `content_root` | Hash32 | Merkle root over shards |
| 2 | `original_bytes` | u64 (PROPOSED-G0) | pre-coding length |
| 3 | `shard_bytes` | u32 (PROPOSED-G0) | fixed shard size for this blob |
| 4 | `data_shards` | u16 (PROPOSED-G0) | |
| 5 | `parity_shards` | u16 (PROPOSED-G0) | |
| 6 | `retention_epochs` | u32 (PROPOSED-G0) | declared horizon |
| 7 | `codec_id` | u16 (PROPOSED-G0) | registry-scoped erasure codec |
| 8 | `encryption_descriptor` | optional bounded bytes, max 256 (PROPOSED-G0) | |
| 9 | `access_policy_root` | optional Hash32 | |

Width precedent: ch05 §2.2 `shard_erasure_params` packs `shard_size u32,
data_shards u16, parity_shards u16` — the same widths are proposed here for
consistency across the DA surface.

## Shard leaf (PROPOSED-G0 layout)

| # | Field | Width | Notes |
|---:|---|---|---|
| 0 | `content_root` | Hash32 | parent descriptor binding |
| 1 | `shard_index` | u32 (PROPOSED-G0) | |
| 2 | `shard_bytes` | fixed `shard_bytes` from descriptor | zero-padded final data shard |

Merkle branch verification per ch01 §10.1 light sampling; shard requests carried on
`/noos/blob/shard/1` (ch01 §10.4; protocol IDs owned by IdentityFreeze).

## NEL trace namespace constants (ch05 §6; recorded in constants-v1.toml [nel])

| Constant | Value | Source |
|---|---:|---|
| Lean claim stream | 51.06 B/token (T=32) | ch05 §6.1 |
| Activation commit (per-layer root form) | 768 B/chunk | ch05 §6.2 |
| Full activation trace | 21,504 B/token | ch05 §6.2 |
| Full-publication ratio | 547× vs lean | ch05 §6.1 |
| Retrieval SLA | ≥ 99.9% inside deadlines, 30 days | ch05 E-NEL-05 |
| Model weight shards | 4–16 MiB content-addressed | ch05 §2.2 |

Reveal-on-dispute is a forced move: upon DisputeOpen naming a chunk, the executor
publishes that chunk's committed activation blocks to the trace namespace within
D=25 blocks, Merkle-consistent with `chunk_trace_root`, or loses by default
(ch05 §6.2, §5.2).

## Retention/lifecycle rules (ch01 §10.1–10.2; plan §7.1–7.2)

- All bytes required to validate a block before its deadline are consensus data.
- Large job/model/evidence artifacts are NOT consensus data unless a registered
  proof verifier requires them synchronously; they use the Work Loom availability
  lifecycle and cannot settle while withheld.
- Availability certificates precede every challenge clock (ch01 §1.6).
