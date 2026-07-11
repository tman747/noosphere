//! Snapshot-generation manifest and the tiny `CURRENT` pointer.
//!
//! Both are canonical noos-codec objects (fixed-width LE, u32-length
//! collections, exact version, no trailing bytes).
//!
//! - `MANIFEST` file = canonical [`ManifestV1`] bytes. Its identity is
//!   `manifest_hash = BLAKE3-derive-key("NOOS/STORE/MANIFEST/V1", bytes)`,
//!   pinned by the pointer.
//! - `CURRENT` file = canonical [`CurrentPointerV1`] bytes followed by a
//!   32-byte BLAKE3 checksum under `"NOOS/STORE/CURRENT/V1"`.

use noos_codec::{NoosDecode, NoosEncode, Reader, Writer};

use crate::{ctx_hash, CTX_CURRENT, CTX_MANIFEST};

pub(crate) const MAX_IDENTITY: u32 = 128;
pub(crate) const MAX_REL_PATH: u32 = 512;
pub(crate) const MAX_FILES: u32 = 100_000;
pub(crate) const MAX_SEGMENTS: u32 = 1_000_000;

/// One engine file pinned by a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntryV1 {
    /// Path relative to the generation directory, forward slashes only.
    pub rel_path: String,
    pub size: u64,
    /// BLAKE3-derive-key("NOOS/STORE/FILE/V1", contents).
    pub hash: [u8; 32],
}

impl NoosEncode for FileEntryV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_bytes(self.rel_path.as_bytes(), MAX_REL_PATH);
        w.put_u64(self.size);
        w.put_array32(&self.hash);
    }
}

impl NoosDecode for FileEntryV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        let raw = r.get_bytes(MAX_REL_PATH)?;
        let rel_path =
            String::from_utf8(raw).map_err(|_| noos_codec::CodecError::UnknownDiscriminant)?;
        Ok(FileEntryV1 {
            rel_path,
            size: r.get_u64()?,
            hash: r.get_array32()?,
        })
    }
}

/// Blob-segment watermark pinned by a generation: this generation depends
/// on exactly `segment[0..len]`, whose prefix hash is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentMarkV1 {
    pub segment: u32,
    pub len: u64,
    pub prefix_hash: [u8; 32],
}

impl NoosEncode for SegmentMarkV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u32(self.segment);
        w.put_u64(self.len);
        w.put_array32(&self.prefix_hash);
    }
}

impl NoosDecode for SegmentMarkV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        Ok(SegmentMarkV1 {
            segment: r.get_u32()?,
            len: r.get_u64()?,
            prefix_hash: r.get_array32()?,
        })
    }
}

/// Generation manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestV1 {
    pub generation: u64,
    /// Protocol-WAL sequence number this snapshot reflects.
    pub applied_seq: u64,
    /// Protocol identity binding (chain id + genesis bytes).
    pub identity: Vec<u8>,
    /// The six Lumen roots at `applied_seq` (zeroed before first commit).
    pub roots: [[u8; 32]; 6],
    /// Every engine file, sorted ascending by `rel_path`.
    pub engine_files: Vec<FileEntryV1>,
    /// Blob-segment watermarks, ascending by segment id.
    pub segments: Vec<SegmentMarkV1>,
}

impl NoosEncode for ManifestV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1); // version
        w.put_u64(self.generation);
        w.put_u64(self.applied_seq);
        w.put_bytes(&self.identity, MAX_IDENTITY);
        for r in &self.roots {
            w.put_array32(r);
        }
        w.put_list(&self.engine_files, MAX_FILES);
        w.put_list(&self.segments, MAX_SEGMENTS);
    }
}

impl NoosDecode for ManifestV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        r.expect_version(&[1])?;
        let generation = r.get_u64()?;
        let applied_seq = r.get_u64()?;
        let identity = r.get_bytes(MAX_IDENTITY)?;
        let mut roots = [[0u8; 32]; 6];
        for slot in roots.iter_mut() {
            *slot = r.get_array32()?;
        }
        Ok(ManifestV1 {
            generation,
            applied_seq,
            identity,
            roots,
            engine_files: r.get_list(MAX_FILES)?,
            segments: r.get_list(MAX_SEGMENTS)?,
        })
    }
}

impl ManifestV1 {
    /// Identity of this manifest: BLAKE3 over the canonical BODY bytes.
    /// This is exactly the trailing self-checksum of the `MANIFEST` file
    /// and the hash the `CURRENT` pointer pins.
    pub fn hash(&self) -> [u8; 32] {
        ctx_hash(CTX_MANIFEST, &self.encode_canonical())
    }

    /// File bytes: canonical body || 32-byte self-checksum. The checksum
    /// makes every manifest tamper-evident on its own, so a fallback
    /// generation (not pinned by the pointer) still cannot present
    /// corrupted metadata as valid.
    pub fn to_file_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_canonical();
        let chk = ctx_hash(CTX_MANIFEST, &out);
        out.extend_from_slice(&chk);
        out
    }

    /// Strict parse of `MANIFEST` file bytes; returns the manifest and its
    /// verified hash.
    pub fn from_file_bytes(bytes: &[u8]) -> Result<(ManifestV1, [u8; 32]), String> {
        if bytes.len() < 32 {
            return Err("manifest file shorter than its checksum".to_string());
        }
        let split = bytes
            .len()
            .checked_sub(32)
            .ok_or_else(|| "manifest length underflow".to_string())?;
        let (body, chk) = bytes.split_at(split);
        let actual = ctx_hash(CTX_MANIFEST, body);
        if chk != actual.as_slice() {
            return Err("manifest self-checksum mismatch".to_string());
        }
        let manifest =
            ManifestV1::decode_canonical(body).map_err(|e| format!("manifest decode: {e}"))?;
        Ok((manifest, actual))
    }
}

/// The tiny `CURRENT` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentPointerV1 {
    pub generation: u64,
    pub manifest_hash: [u8; 32],
}

impl NoosEncode for CurrentPointerV1 {
    fn encode(&self, w: &mut Writer) {
        w.put_u16(1); // version
        w.put_u64(self.generation);
        w.put_array32(&self.manifest_hash);
    }
}

impl NoosDecode for CurrentPointerV1 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, noos_codec::CodecError> {
        r.expect_version(&[1])?;
        Ok(CurrentPointerV1 {
            generation: r.get_u64()?,
            manifest_hash: r.get_array32()?,
        })
    }
}

impl CurrentPointerV1 {
    /// File bytes: canonical pointer || 32-byte checksum.
    pub fn to_file_bytes(&self) -> Vec<u8> {
        let body = self.encode_canonical();
        let chk = ctx_hash(CTX_CURRENT, &body);
        let mut out = body;
        out.extend_from_slice(&chk);
        out
    }

    /// Strict parse of `CURRENT` file bytes.
    pub fn from_file_bytes(bytes: &[u8]) -> Result<CurrentPointerV1, String> {
        // body = version(2) + generation(8) + hash(32) = 42; + chk(32) = 74.
        const LEN: usize = 74;
        if bytes.len() != LEN {
            return Err(format!("pointer length {} != {LEN}", bytes.len()));
        }
        let (body, chk) = bytes.split_at(42);
        if chk != ctx_hash(CTX_CURRENT, body).as_slice() {
            return Err("pointer checksum mismatch".to_string());
        }
        CurrentPointerV1::decode_canonical(body).map_err(|e| format!("pointer decode: {e}"))
    }
}
