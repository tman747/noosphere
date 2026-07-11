//! Append-only versioned body/blob segments (plan §7.3).
//!
//! Blobs live in bounded segment files `segments/seg-<id:08>.seg`,
//! physically separate from the consensus engine so blob IO cannot starve
//! consensus IO. Each stored record is
//! `len:u32-LE || content_hash:32 || checksum:32 || bytes:len` with
//! `checksum = BLAKE3-derive-key("NOOS/STORE/SEGMENT/V1", bytes)`.
//!
//! Location metadata (`hash → segment/offset/len`) lives in the
//! `blob_index` column family and travels through the protocol WAL like
//! every other write. Segment bytes are appended and fsynced BEFORE the
//! WAL record referencing them exists, so a replayed index entry always
//! points at durable bytes; a crash in between leaves only unreferenced
//! (harmless, re-appendable) tail bytes.
//!
//! Segments are shared across snapshot generations: a generation manifest
//! pins, per segment, the length watermark and the BLAKE3 prefix hash it
//! depends on. Retention never truncates below a retained watermark.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use noos_codec::{NoosDecode, NoosEncode, Reader, Writer};

use crate::vfs::{join, Vfs, VfsFile};
use crate::{ctx_hash, StoreError, CTX_SEGMENT};

const RECORD_HEADER: u64 = 4 + 32 + 32;

/// Blob location stored in the `blob_index` CF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobLoc {
    pub segment: u32,
    /// Record start offset (header, not bytes).
    pub offset: u64,
    /// Content byte length.
    pub len: u32,
}

impl NoosEncode for BlobLoc {
    fn encode(&self, w: &mut Writer) {
        w.put_u32(self.segment);
        w.put_u64(self.offset);
        w.put_u32(self.len);
    }
}

impl NoosDecode for BlobLoc {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        Ok(BlobLoc {
            segment: r.get_u32()?,
            offset: r.get_u64()?,
            len: r.get_u32()?,
        })
    }
}

pub(crate) fn segment_file_name(id: u32) -> String {
    format!("seg-{id:08}.seg")
}

fn parse_segment_file_name(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("seg-")?.strip_suffix(".seg")?;
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Append side + reader of the blob segment store.
pub(crate) struct BlobStore {
    vfs: Arc<dyn Vfs>,
    dir: PathBuf,
    segment_bytes: u64,
    active_id: u32,
    active_len: u64,
    active: Option<Box<dyn VfsFile>>,
    dirty: bool,
}

impl BlobStore {
    pub fn open(vfs: Arc<dyn Vfs>, dir: PathBuf, segment_bytes: u64) -> Result<Self, StoreError> {
        let mut active_id = 0u32;
        let mut found = false;
        if vfs.is_dir(&dir) {
            for name in vfs
                .read_dir(&dir)
                .map_err(|e| StoreError::io("read_dir", &dir, e))?
            {
                if let Some(id) = parse_segment_file_name(&name) {
                    if !found || id > active_id {
                        active_id = id;
                        found = true;
                    }
                }
            }
        }
        let active_len = if found {
            let p = join(&dir, &segment_file_name(active_id));
            vfs.file_len(&p)
                .map_err(|e| StoreError::io("file_len", &p, e))?
        } else {
            0
        };
        Ok(BlobStore {
            vfs,
            dir,
            segment_bytes,
            active_id,
            active_len,
            active: None,
            dirty: false,
        })
    }

    fn active_path(&self) -> PathBuf {
        join(&self.dir, &segment_file_name(self.active_id))
    }

    /// Append one blob record (not yet fsynced; call [`Self::fsync_active`]
    /// before writing any WAL record that references the returned location).
    pub fn append(&mut self, hash: &[u8; 32], bytes: &[u8]) -> Result<BlobLoc, StoreError> {
        let record_len = RECORD_HEADER
            .checked_add(bytes.len() as u64)
            .ok_or(StoreError::Arithmetic("blob record len"))?;
        if self.active_len > 0
            && self
                .active_len
                .checked_add(record_len)
                .ok_or(StoreError::Arithmetic("blob segment len"))?
                > self.segment_bytes
        {
            // Bounded segment full: flush and rotate.
            self.fsync_active()?;
            self.active_id = self
                .active_id
                .checked_add(1)
                .ok_or(StoreError::Arithmetic("blob segment id"))?;
            self.active_len = 0;
            self.active = None;
        }
        if self.active.is_none() {
            let path = self.active_path();
            self.active_len = if self.vfs.exists(&path) {
                self.vfs
                    .file_len(&path)
                    .map_err(|e| StoreError::io("file_len", &path, e))?
            } else {
                0
            };
            let file = self
                .vfs
                .open_append(&path)
                .map_err(|e| StoreError::io("open_append", &path, e))?;
            self.active = Some(file);
            self.vfs
                .sync_dir(&self.dir)
                .map_err(|e| StoreError::io("sync_dir", &self.dir, e))?;
        }
        let offset = self.active_len;
        let mut rec = Vec::with_capacity(record_len as usize);
        rec.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        rec.extend_from_slice(hash);
        rec.extend_from_slice(&ctx_hash(CTX_SEGMENT, bytes));
        rec.extend_from_slice(bytes);
        let path = self.active_path();
        let file = self.active.as_mut().ok_or(StoreError::InvalidWriteSet(
            "blob store has no active segment",
        ))?;
        file.append(&rec)
            .map_err(|e| StoreError::io("blob_append", &path, e))?;
        self.active_len = offset
            .checked_add(record_len)
            .ok_or(StoreError::Arithmetic("blob offset"))?;
        self.dirty = true;
        Ok(BlobLoc {
            segment: self.active_id,
            offset,
            len: bytes.len() as u32,
        })
    }

    /// fsync the active segment if it has unfsynced appends.
    pub fn fsync_active(&mut self) -> Result<(), StoreError> {
        if self.dirty {
            let path = self.active_path();
            if let Some(file) = self.active.as_mut() {
                file.fsync()
                    .map_err(|e| StoreError::io("blob_fsync", &path, e))?;
            }
            self.dirty = false;
        }
        Ok(())
    }

    /// Read + verify a blob. Verifies both the record checksum and that the
    /// stored content hash matches `expect_hash`.
    pub fn read(&self, loc: &BlobLoc, expect_hash: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
        let path = join(&self.dir, &segment_file_name(loc.segment));
        let total = RECORD_HEADER
            .checked_add(u64::from(loc.len))
            .ok_or(StoreError::Arithmetic("blob read len"))?;
        let raw = self
            .vfs
            .read_at(&path, loc.offset, total as usize)
            .map_err(|e| StoreError::io("blob_read", &path, e))?;
        let corrupt = || StoreError::BlobCorrupt {
            segment: loc.segment,
            offset: loc.offset,
        };
        let len_field = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if len_field != loc.len {
            return Err(corrupt());
        }
        let stored_hash = &raw[4..36];
        let stored_chk = &raw[36..68];
        let bytes = &raw[68..];
        if stored_hash != expect_hash.as_slice() {
            return Err(corrupt());
        }
        if stored_chk != ctx_hash(CTX_SEGMENT, bytes).as_slice() {
            return Err(corrupt());
        }
        Ok(bytes.to_vec())
    }

    /// Current `(segment id, byte length)` watermarks of every segment file,
    /// ascending by id. Flushes the active segment first so watermarks are
    /// durable.
    pub fn watermarks(&mut self) -> Result<Vec<(u32, u64)>, StoreError> {
        self.fsync_active()?;
        let mut ids: Vec<u32> = Vec::new();
        if self.vfs.is_dir(&self.dir) {
            for name in self
                .vfs
                .read_dir(&self.dir)
                .map_err(|e| StoreError::io("read_dir", &self.dir, e))?
            {
                if let Some(id) = parse_segment_file_name(&name) {
                    ids.push(id);
                }
            }
        }
        ids.sort_unstable();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let p = join(&self.dir, &segment_file_name(id));
            let len = self
                .vfs
                .file_len(&p)
                .map_err(|e| StoreError::io("file_len", &p, e))?;
            out.push((id, len));
        }
        Ok(out)
    }

    /// BLAKE3 prefix hash of `segment[0..len]` under the FILE context.
    pub fn prefix_hash(
        vfs: &Arc<dyn Vfs>,
        dir: &Path,
        segment: u32,
        len: u64,
    ) -> Result<[u8; 32], StoreError> {
        let p = join(dir, &segment_file_name(segment));
        let bytes = vfs
            .read_at(&p, 0, len as usize)
            .map_err(|e| StoreError::io("segment_prefix_read", &p, e))?;
        Ok(ctx_hash(crate::CTX_FILE, &bytes))
    }
}
