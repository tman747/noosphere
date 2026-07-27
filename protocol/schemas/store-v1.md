# store-v1 — NOOSPHERE durable storage law

Status: NORMATIVE for `crates/noos-store` (plan §7.3).
Scope: on-disk layout, column families, protocol-WAL record format, blob
segments, snapshot/CURRENT protocol, retention, and the startup decision
tree. Consensus semantics, networking, and the node supervisor are out of
scope. The storage input contract is `noos-lumen`'s canonical ordered
`StateDelta` (lumen-v1.md); this document never reinterprets it.

## 1. Pinned backend

| Component            | Pin                                        |
|----------------------|--------------------------------------------|
| Rust crate           | `rocksdb = "=0.24.0"` (exact)              |
| Sys crate            | `librocksdb-sys 0.17.3+10.4.2`             |
| RocksDB library      | **10.4.2** (bundled, built from source)    |

Changing the pin is an operations decision that re-runs the crash matrix
and this document's review — never a routine dependency bump. Building
`librocksdb-sys` requires `bindgen` (a `libclang` on `LIBCLANG_PATH`);
`scripts/check.ps1` auto-detects it on Windows.

The engine's **internal** WAL stays enabled (batch atomicity) but is never
fsynced per write: recoverability of acknowledged commits is owned
exclusively by the protocol WAL below, which is fsynced *before* the
engine apply. Invariant: the engine's `applied_seq` never exceeds the
durable protocol-WAL end; a violation observed at startup is the typed
fatal `HistoryGap` (silent acked-write loss).

## 2. On-disk layout

```
<root>/
  CURRENT                       tiny checksummed pointer (§6)
  CURRENT.tmp                   transient flip staging (ignorable)
  live/                         live RocksDB engine — DERIVED CACHE,
                                always reconstructible from generation+WAL
  engine-logs/                  RocksDB info logs (kept out of data dirs)
  wal/wal-<firstseq:020>.log    protocol WAL segments (§4)
  segments/seg-<id:08>.seg      append-only bounded blob segments (§5)
  gen-<N:020>/                  immutable verified snapshot generation (§6)
    MANIFEST                    canonical ManifestV1 body ‖ self-checksum
    PROVEN                      fresh-process replay-proof marker (§7.4)
    engine/…                    RocksDB checkpoint files (manifest-pinned)
  tmp-gen-<N>-<seq>/            in-flight snapshot (orphans ignored)
  tmp-prove-<N>/                replay-proof scratch (orphans ignored)
```

All hashes below are BLAKE3-256 in **derive-key** mode under the listed
context strings. They are local file-integrity checksums, deliberately
outside the closed consensus domain registry (`crypto-domains-v1.csv`);
nothing here is a protocol commitment.

| Context                  | Covers                                  |
|--------------------------|------------------------------------------|
| `NOOS/STORE/WAL/V1`      | WAL record payloads                      |
| `NOOS/STORE/FILE/V1`     | manifest-pinned files, segment prefixes  |
| `NOOS/STORE/MANIFEST/V1` | manifest body (= manifest identity)      |
| `NOOS/STORE/CURRENT/V1`  | pointer body                             |
| `NOOS/STORE/SEGMENT/V1`  | blob record contents                     |
| `NOOS/STORE/SAFETY/V1`   | safety-record key derivation             |
| `NOOS/STORE/SAMPLE/V1`   | deterministic proof-sample targets       |

## 3. Column families

Closed set; numeric ids are the WAL wire discriminants.

| id | name         | contents                                              |
|----|--------------|-------------------------------------------------------|
| 0  | `state`      | authenticated state nodes: Lumen sparse-tree entries. Key = `tree:u8 ‖ key:32 ‖ (0x00 \| 0x01 ‖ sub_key:32)` — preserves the delta's canonical `(tree, key, sub_key)` order. |
| 1  | `headers`    | block headers, caller-keyed                           |
| 2  | `indices`    | secondary indices, caller-keyed                       |
| 3  | `receipts`   | execution receipts, caller-keyed                      |
| 4  | `meta`       | store + consensus-safety metadata (below)             |
| 5  | `blob_index` | `content_hash:32 → BlobLoc{segment:u32, offset:u64, len:u32}` |

Reserved `meta` keys: `applied_seq` (u64-LE), `identity` (opaque chain-id
+ genesis binding, checked on every open; mismatch is fatal),
`schema_version` (u32-LE = 1), `lumen_roots` (6×32 bytes, the six roots
of the last commit that carried them), and `s/<kind:u16-LE><payload-hash:32>`
for persist-before-vote safety records. Kind 1 is reserved for the
Witness Ring beacon adapter (`noos-witness` `DurabilityBarrier`; the
adapter lives at the composition layer so neither crate depends on the
other).

## 4. Protocol WAL

Distinct from the engine's internal WAL. Record wire form:

```
len:u32-LE ‖ checksum:32 ‖ payload:len
checksum = BLAKE3-dk("NOOS/STORE/WAL/V1", payload)
len ≤ 512 MiB
```

Payload = canonical `WalRecordV1` under noos-codec law (fixed-width LE,
u32-length collections, exact version, no trailing bytes):

```
WalRecordV1 { version:u16 = 1, seq:u64, ops: list<OpV1> (≤ 4,000,000) }
OpV1        { cf:u8 (§3), key: bytes ≤ 4096,
              tag:u8 ∈ {0 = delete, 1 ‖ value: bytes ≤ 32 MiB} }
```

Segments `wal-<firstseq:020>.log` are created lazily (the name is the
first contained seq) and rotated at the configured threshold. Sequence
numbers are contiguous (+1) across the entire retained log; the first
record of a segment must match its filename.

**Commit protocol** (single writer): blob bytes appended + fsynced first
(§5) → WAL record appended → WAL fsynced → engine `WriteBatch` applied
with `meta/applied_seq = seq` **inside the same batch** (mark applied).
The commit is acknowledged only after the engine apply returns; the WAL
fsync alone already makes it recoverable. `Store::barrier()` and
`Store::persist_safety_record()` provide the persist-before-vote
durability barrier: Ok ⇒ the record survives any subsequent crash.

**EOF rule (exact):** while scanning, an anomaly is: fewer than 36 bytes
remain for a header, `len` exceeds the bound, or the file ends before
`36 + len` bytes. An anomaly in the FINAL segment is a torn in-flight
append — the tail is truncated away and scanning ends. An anomaly in any
non-final segment is the typed fatal `WalCorrupt`. A COMPLETE record
whose checksum mismatches, or whose payload does not decode canonically,
is `WalCorrupt` **regardless of position**: records are written by a
single append and fsynced before the next append begins, so a complete
record can never be a torn write — a bad checksum there is real
corruption and startup STOPS. A truncated-away record was by construction
never acknowledged (ack requires the full append + fsync to return).

## 5. Blob segments

Append-only bounded files, physically separate from the engine so blob IO
cannot starve consensus IO. Stored record:

```
len:u32-LE ‖ content_hash:32 ‖ checksum:32 ‖ bytes:len
checksum = BLAKE3-dk("NOOS/STORE/SEGMENT/V1", bytes)
```

Default node storage accepts one compressed DA-form blob up to 128 MiB and
rotates blob segments at 256 MiB. The WAL ceiling is sized for the corresponding
atomic macroblock receipt/state/index write set; it does not relax the 32 MiB
bound on any individual value.

Location metadata lives in `blob_index` and travels through the protocol
WAL like any other write. Ordering law: segment bytes are appended and
fsynced BEFORE the WAL record referencing them exists, so a replayed
index entry always points at durable bytes. A crash in between leaves
only unreferenced tail bytes — harmless, re-appended on retry. Reads
verify both the record checksum and the requested content hash; failure
is the typed `BlobCorrupt`.

Segments are shared across generations. Each generation manifest pins,
per segment, `(id, length watermark, prefix hash)`; validation re-hashes
the pinned prefix. Retention never truncates or deletes below a retained
generation's watermark (segments are only ever removed with the
generations that pin them — currently never, as they are append-only and
content-addressed).

## 6. Snapshot generations and the CURRENT pointer

`ManifestV1` (canonical codec object): `generation:u64`, `applied_seq:u64`,
`identity: bytes ≤ 128`, `roots: 6×32`, `engine_files: list<FileEntryV1>`
(`rel_path ≤ 512` forward-slash, `size:u64`, `hash:32` under FILE ctx),
`segments: list<SegmentMarkV1>`. The `MANIFEST` file is
`body ‖ BLAKE3-dk("NOOS/STORE/MANIFEST/V1", body)`; the trailing
self-checksum equals the manifest hash the pointer pins, and makes every
manifest — including fallback candidates the pointer does not pin —
tamper-evident on its own.

`CURRENT` file (74 bytes exactly):
`CurrentPointerV1{version:u16=1, generation:u64, manifest_hash:32}` ‖
`BLAKE3-dk("NOOS/STORE/CURRENT/V1", body)`.

**Snapshot creation law (plan §7.3, exact):**

1. Write generation `N` into `tmp-gen-<N>-<seq>` in the SAME filesystem
   (RocksDB checkpoint of the live engine → `engine/`).
2. fsync every checkpoint file; write + fsync `MANIFEST`; flush the
   directory-equivalents (`engine/` and the temp dir).
3. VERIFY before adoption: open the checkpoint read-only and compare
   `applied_seq`, identity, the six Lumen roots, and `proof_samples`
   deterministic state-CF samples (seek targets
   `BLAKE3-dk("NOOS/STORE/SAMPLE/V1", gen‖i)`) against the live engine.
   Any mismatch aborts; nothing is renamed or pointed at.
4. Atomic adoption: `rename(tmp, gen-<N>)` + parent-directory flush.
   Only verified generations ever carry the final name — anything under
   `tmp-` is ignorable garbage.
5. Durable pointer replacement: write `CURRENT.tmp`, fsync it, atomic
   same-volume `std::fs::rename` onto `CURRENT`, flush the parent
   directory.

**Windows directory-flush caveat (documented per plan):** on Unix the
parent-directory flush is `fsync` on an open directory handle. Windows
has no exact equivalent in safe std; the store opens the directory with
`FILE_FLAG_BACKUP_SEMANTICS` and calls `FlushFileBuffers`
(`File::sync_all`), which flushes directory metadata on NTFS but is
treated as **best-effort**: on filesystems that reject it, durability of
the rename rests on `sync_all` of the renamed file plus the same-volume
atomic `std::fs::rename` (MoveFileEx semantics). File fsyncs on Windows
open a writable handle — `FlushFileBuffers` rejects read-only handles.

## 7. Startup decision tree

```
open(root):
 ├─ no generations AND no CURRENT
 │   ├─ create_if_missing → INIT: fresh live engine (identity, schema,
 │   │    zero roots @ seq 0) → generation 1 via §6 law → CURRENT →
 │   │    PROVEN(1). Orphan tmp/ scaffolding from an interrupted earlier
 │   │    init is discarded (nothing durable exists yet).
 │   └─ else → NotInitialized
 ├─ generations exist, CURRENT missing
 │   ├─ EXACTLY {gen 1}, no PROVEN anywhere, empty WAL  → interrupted
 │   │    first init: validate gen 1, roll the pointer forward
 │   └─ anything else → FATAL PointerMissing (never auto-adopt)
 ├─ CURRENT unreadable/checksum-fail/unparseable → FATAL PointerCorrupt
 ├─ validate pointed generation G (manifest self-checksum, pointer hash,
 │  generation number, identity, every pinned file's size+hash, segment
 │  watermark prefixes):
 │   ├─ manifest.generation ≠ G      → FATAL ConflictingPointers
 │   ├─ identity ≠ configured        → FATAL IdentityMismatch
 │   ├─ otherwise invalid → FALLBACK: highest older generation that
 │   │    fully validates; adopted only AFTER it opens and replays, then
 │   │    CURRENT is rewritten to it; the invalid generation is kept for
 │   │    forensics. No candidate → FATAL NoValidGeneration
 ├─ scan protocol WAL (§4 EOF rule; earlier corruption → FATAL WalCorrupt;
 │  seq discontinuity → FATAL HistoryGap)
 │   └─ base.applied_seq > durable WAL end → FATAL HistoryGap
 ├─ choose base engine:
 │   ├─ live engine opens, correct identity/schema, applied ≤ WAL end,
 │   │    and the tail (applied, end] is retained → use live
 │   ├─ live engine applied > WAL end → FATAL HistoryGap (acked loss)
 │   └─ else REBUILD live from the base generation (byte-copy of every
 │        manifest-pinned file) — this is the sanctioned snapshot+tail
 │        replay; missing tail → FATAL HistoryGap
 ├─ replay WAL records seq > engine.applied_seq (idempotent absolute
 │  writes; each batch re-marks applied_seq)
 ├─ PROOF (retention gate, §7.4): if the base generation lacks PROVEN,
 │  copy it to tmp-prove-<N>, replay the tail there, compare applied_seq,
 │  roots, and proof samples against the live engine; divergence →
 │  FATAL ReplayDivergence; match → write + fsync PROVEN, remove scratch
 └─ resume WAL writer / blob store; store is open
```

Fatal conditions never auto-reset, never delete data, and never fall
back past the retained previously verified generation.

### 7.4 Retention law

- Verified `N` and `N-1` plus every WAL record any retained generation
  needs are kept until a FRESH process proves snapshot+tail replay
  (`PROVEN` marker written only by `open`, or at init where generation 1
  is trivially proven).
- `prune()` removes: generations strictly older than the newest PROVEN
  generation (always keeping the current generation and its
  predecessor), orphan `tmp-` directories, and whole WAL segments whose
  entire seq range lies at or below the smallest `applied_seq` any
  retained generation reflects — never the newest segment.
- The last verified generation is never deleted (the current generation
  is unconditionally kept).

## 8. Crash-injection model (`FailpointVfs`)

Every protocol-layer durability boundary — directory create, file
create, data write/append, fsync, directory flush, rename, truncate,
file/dir removal — passes through the `Vfs` abstraction; engine apply,
checkpoint, and open calls are bracketed with explicit failpoint hooks so
they are numbered in the same global sequence. Injection at boundary `k`:
a data write persists a deterministic strict prefix (torn write);
control operations (fsync/rename/remove/flush) do nothing; afterwards
the filesystem is dead until a fresh process opens over the real one.

Model notes (deliberate, documented): an fsync that "fails" after its
data was already written may leave that data visible — recovery
therefore tolerates MORE durable data than acknowledged (an unacked
in-flight step may recover), which is exactly the property the verifier
checks: acked ⇒ present; unacked ⇒ atomically present-or-absent, in
commit order only.

`cargo test -p noos-store` runs the full matrix: the scripted workload
(init, four commits across all column families with blobs, a safety
record, two snapshots, a prune, a barrier) is numbered once, then
crashed at EVERY boundary; each crash must recover through a fresh
`Store::open` to the last durable state — or stop with a typed fatal —
and remain fully functional. Silent loss, partial batches, and adopted
partial generations all fail the property.
