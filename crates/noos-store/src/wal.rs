//! Checksummed protocol WAL — distinct from the engine's internal WAL.
//!
//! Record wire form: `len:u32-LE || checksum:32 || payload:len` where
//! `checksum = BLAKE3-derive-key("NOOS/STORE/WAL/V1", payload)`.
//!
//! Payload = canonical [`WalRecordV1`] (noos-codec law: fixed-width LE,
//! u32-length collections, exact version/tags, no trailing bytes).
//!
//! Segmentation: `wal-<first_seq:020>.log` files, rotated lazily at the
//! configured size threshold. Sequence numbers are contiguous across the
//! whole retained log.
//!
//! EOF law (plan §7.3): ONLY a truncated FINAL record is tolerated — the
//! file ends before `4 + 32 + len` bytes are available (an in-flight torn
//! append). It is truncated away on open. A COMPLETE record with a bad
//! checksum, an undecodable complete payload, or any anomaly in a
//! non-final segment is `FatalError::WalCorrupt`: startup stops.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use noos_codec::{NoosDecode, NoosEncode, Reader, Writer};

use crate::engine::Cf;
use crate::vfs::{join, Vfs, VfsFile};
use crate::{ctx_hash, FatalError, StoreError, CTX_WAL};

/// Record header: length (4) + BLAKE3 checksum (32).
pub const WAL_HEADER_LEN: u64 = 36;
/// Hard bound on a single record payload.
pub const MAX_WAL_RECORD: u32 = 64 * 1024 * 1024;
/// Bound on ops per record.
pub const MAX_OPS: u32 = 1_000_000;
/// Bound on a key.
pub const MAX_KEY: u32 = 4096;
/// Bound on a single value.
pub const MAX_VALUE: u32 = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Wire objects
// ---------------------------------------------------------------------------

/// One column-family write: `value = None` deletes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpV1 {
    pub cf: Cf,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

impl NoosEncode for OpV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u8(self.cf as u8);
        w.put_bytes(&self.key, MAX_KEY);
        match &self.value {
            None => w.put_u8(0),
            Some(v) => {
                w.put_u8(1);
                w.put_bytes(v, MAX_VALUE);
            }
        }
    }
}

impl NoosDecode for OpV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        let cf = Cf::from_u8(r.get_u8()?).ok_or(noos_codec::CodecError::UnknownDiscriminant)?;
        let key = r.get_bytes(MAX_KEY)?;
        let value = match r.get_u8()? {
            0 => None,
            1 => Some(r.get_bytes(MAX_VALUE)?),
            _ => return Err(noos_codec::CodecError::UnknownDiscriminant),
        };
        Ok(OpV1 { cf, key, value })
    }
}

/// One committed atomic batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecordV1 {
    pub seq: u64,
    pub ops: Vec<OpV1>,
}

impl NoosEncode for WalRecordV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1); // version
        w.put_u64(self.seq);
        w.put_list(&self.ops, MAX_OPS);
    }
}

impl NoosDecode for WalRecordV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        r.expect_version(&[1])?;
        let seq = r.get_u64()?;
        let ops = r.get_list(MAX_OPS)?;
        Ok(WalRecordV1 { seq, ops })
    }
}

// ---------------------------------------------------------------------------
// Segment naming
// ---------------------------------------------------------------------------

pub(crate) fn segment_name(first_seq: u64) -> String {
    format!("wal-{first_seq:020}.log")
}

pub(crate) fn parse_segment_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("wal-")?.strip_suffix(".log")?;
    if digits.len() != 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

/// Result of scanning (and, if needed, tail-truncating) the whole WAL dir.
#[derive(Debug, Default)]
pub struct WalScan {
    /// All valid records, ascending contiguous seq.
    pub records: Vec<WalRecordV1>,
    /// Bytes removed from the final segment under the EOF rule.
    pub truncated_bytes: u64,
    /// Highest seq present (0 when empty).
    pub last_seq: u64,
    /// Lowest seq present.
    pub first_seq: Option<u64>,
    /// Segment first-seqs present, ascending.
    pub segments: Vec<u64>,
}

fn wal_corrupt(segment: u64, offset: u64, reason: &str) -> StoreError {
    StoreError::Fatal(FatalError::WalCorrupt {
        segment,
        offset,
        reason: reason.to_string(),
    })
}

/// Scan every segment under `dir`. `truncate_tail` (open path) applies the
/// EOF rule to the final segment; validation-only callers pass `false` and
/// receive the same records with the torn tail ignored.
pub(crate) fn scan(
    vfs: &Arc<dyn Vfs>,
    dir: &Path,
    truncate_tail: bool,
) -> Result<WalScan, StoreError> {
    let mut out = WalScan::default();
    if !vfs.is_dir(dir) {
        return Ok(out);
    }
    let mut segs: Vec<u64> = Vec::new();
    for name in vfs
        .read_dir(dir)
        .map_err(|e| StoreError::io("read_dir", dir, e))?
    {
        if let Some(first) = parse_segment_name(&name) {
            segs.push(first);
        }
    }
    segs.sort_unstable();
    let seg_count = segs.len();

    let mut expected_next: Option<u64> = None;
    for (idx, first_seq) in segs.iter().copied().enumerate() {
        let is_last_segment = idx.checked_add(1) == Some(seg_count);
        let path = join(dir, &segment_name(first_seq));
        let bytes = vfs
            .read(&path)
            .map_err(|e| StoreError::io("read", &path, e))?;
        let mut pos: u64 = 0;
        let len_total = bytes.len() as u64;
        let mut first_in_segment = true;

        loop {
            let remaining = len_total
                .checked_sub(pos)
                .ok_or(StoreError::Arithmetic("wal pos"))?;
            if remaining == 0 {
                break;
            }
            // Header available?
            if remaining < WAL_HEADER_LEN {
                if is_last_segment {
                    out.truncated_bytes = remaining;
                    if truncate_tail {
                        vfs.truncate(&path, pos)
                            .map_err(|e| StoreError::io("truncate", &path, e))?;
                    }
                    break;
                }
                return Err(wal_corrupt(
                    first_seq,
                    pos,
                    "partial record header in non-final segment",
                ));
            }
            let at = pos as usize;
            let len_field = u32::from_le_bytes([
                bytes[at],
                bytes[at.checked_add(1).ok_or(StoreError::Arithmetic("wal idx"))?],
                bytes[at.checked_add(2).ok_or(StoreError::Arithmetic("wal idx"))?],
                bytes[at.checked_add(3).ok_or(StoreError::Arithmetic("wal idx"))?],
            ]);
            let body_needed = WAL_HEADER_LEN
                .checked_add(u64::from(len_field))
                .ok_or(StoreError::Arithmetic("wal record len"))?;
            if len_field > MAX_WAL_RECORD || remaining < body_needed {
                // Either a torn length field or a torn body. Tolerated only
                // as the FINAL record of the FINAL segment.
                if is_last_segment {
                    out.truncated_bytes = remaining;
                    if truncate_tail {
                        vfs.truncate(&path, pos)
                            .map_err(|e| StoreError::io("truncate", &path, e))?;
                    }
                    break;
                }
                return Err(wal_corrupt(
                    first_seq,
                    pos,
                    "oversized or truncated record in non-final segment",
                ));
            }
            let chk_start = at.checked_add(4).ok_or(StoreError::Arithmetic("wal idx"))?;
            let payload_start = chk_start
                .checked_add(32)
                .ok_or(StoreError::Arithmetic("wal idx"))?;
            let payload_end = payload_start
                .checked_add(len_field as usize)
                .ok_or(StoreError::Arithmetic("wal idx"))?;
            let stored_chk = &bytes[chk_start..payload_start];
            let payload = &bytes[payload_start..payload_end];
            let actual = ctx_hash(CTX_WAL, payload);
            if stored_chk != actual {
                // A COMPLETE record never tears (records are appended by a
                // single write and fsynced before the next append), so a
                // full-length checksum mismatch is real corruption — fatal
                // even at the final position.
                return Err(wal_corrupt(
                    first_seq,
                    pos,
                    "complete-record checksum mismatch",
                ));
            }
            let record = WalRecordV1::decode_canonical(payload)
                .map_err(|e| wal_corrupt(first_seq, pos, &format!("undecodable payload: {e}")))?;
            if first_in_segment {
                if record.seq != first_seq {
                    return Err(wal_corrupt(
                        first_seq,
                        pos,
                        "segment name disagrees with first record seq",
                    ));
                }
                first_in_segment = false;
            }
            if let Some(expected) = expected_next {
                if record.seq != expected {
                    return Err(StoreError::Fatal(FatalError::HistoryGap {
                        detail: format!("wal seq jump: expected {expected}, found {}", record.seq),
                    }));
                }
            }
            expected_next = record.seq.checked_add(1);
            if out.first_seq.is_none() {
                out.first_seq = Some(record.seq);
            }
            out.last_seq = record.seq;
            out.records.push(record);
            pos = pos
                .checked_add(body_needed)
                .ok_or(StoreError::Arithmetic("wal pos advance"))?;
        }
    }
    out.segments = segs;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Append side of the WAL. `append` is: encode → single write → fsync;
/// returns only after the record is durable.
pub struct WalWriter {
    vfs: Arc<dyn Vfs>,
    dir: PathBuf,
    rotate_at: u64,
    active: Option<(u64, Box<dyn VfsFile>, PathBuf)>,
    active_len: u64,
}

impl WalWriter {
    /// Resume on an already-scanned directory. `active_first_seq` is the
    /// last segment present (if any); its durable length must already have
    /// been settled by `scan` truncation.
    pub(crate) fn open(
        vfs: Arc<dyn Vfs>,
        dir: PathBuf,
        rotate_at: u64,
        last_segment: Option<u64>,
    ) -> Result<Self, StoreError> {
        let mut w = WalWriter {
            vfs,
            dir,
            rotate_at,
            active: None,
            active_len: 0,
        };
        if let Some(first_seq) = last_segment {
            let path = join(&w.dir, &segment_name(first_seq));
            let len = w
                .vfs
                .file_len(&path)
                .map_err(|e| StoreError::io("file_len", &path, e))?;
            let file = w
                .vfs
                .open_append(&path)
                .map_err(|e| StoreError::io("open_append", &path, e))?;
            w.active = Some((first_seq, file, path));
            w.active_len = len;
        }
        Ok(w)
    }

    /// Append one record durably (write boundary + fsync boundary; segment
    /// creation adds create + dir-flush boundaries).
    pub(crate) fn append(&mut self, record: &WalRecordV1) -> Result<(), StoreError> {
        let payload = record.encode_canonical();
        if payload.len() > MAX_WAL_RECORD as usize {
            return Err(StoreError::InvalidWriteSet(
                "wal record exceeds MAX_WAL_RECORD",
            ));
        }
        let rotate = match &self.active {
            None => true,
            Some(_) => self.active_len >= self.rotate_at,
        };
        if rotate {
            let path = join(&self.dir, &segment_name(record.seq));
            let file = self
                .vfs
                .open_append(&path)
                .map_err(|e| StoreError::io("open_append", &path, e))?;
            self.active = Some((record.seq, file, path));
            self.active_len = 0;
            // Make the new directory entry durable before the record is
            // considered part of history.
            self.vfs
                .sync_dir(&self.dir)
                .map_err(|e| StoreError::io("sync_dir", &self.dir, e))?;
        }
        let mut framed = Vec::with_capacity(
            payload
                .len()
                .checked_add(WAL_HEADER_LEN as usize)
                .ok_or(StoreError::Arithmetic("wal frame len"))?,
        );
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&ctx_hash(CTX_WAL, &payload));
        framed.extend_from_slice(&payload);
        let (_, file, path) = self.active.as_mut().ok_or(StoreError::InvalidWriteSet(
            "wal writer has no active segment",
        ))?;
        file.append(&framed)
            .map_err(|e| StoreError::io("wal_append", path, e))?;
        file.fsync()
            .map_err(|e| StoreError::io("wal_fsync", path, e))?;
        self.active_len = self
            .active_len
            .checked_add(framed.len() as u64)
            .ok_or(StoreError::Arithmetic("wal active len"))?;
        Ok(())
    }

    /// Durability barrier: fsync the active segment (no-op when empty).
    pub(crate) fn fsync(&mut self) -> Result<(), StoreError> {
        if let Some((_, file, path)) = self.active.as_mut() {
            file.fsync()
                .map_err(|e| StoreError::io("wal_fsync", path, e))?;
        }
        Ok(())
    }
}
