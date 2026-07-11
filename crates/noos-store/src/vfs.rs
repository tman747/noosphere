//! File-system abstraction with crash-injection support.
//!
//! Every protocol-layer durability boundary — file create, write, append,
//! fsync, directory flush, rename, truncate, remove — goes through [`Vfs`]
//! so [`FailpointVfs`] can inject a crash at EVERY boundary (plan §7.3
//! "inject crashes at every write/fsync/rename/prune boundary"). Engine
//! (RocksDB) internal IO does not pass through here; the store brackets
//! engine apply/checkpoint calls with explicit [`Vfs::failpoint`] hooks so
//! those boundaries are numbered in the same sequence.
//!
//! Injection model (documented in `store-v1.md` §8): a failing data write
//! persists a deterministic prefix (torn write); a failing fsync, rename,
//! remove, or directory flush performs nothing; after the injected fault
//! the filesystem is "dead" — every subsequent operation fails — until the
//! process (test iteration) constructs a fresh store over [`RealVfs`].

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub(crate) const INJECTED_MSG: &str = "noos-store injected crash fault";

pub(crate) fn injected_err() -> io::Error {
    io::Error::other(INJECTED_MSG)
}

pub(crate) fn is_injected(e: &io::Error) -> bool {
    e.to_string().contains(INJECTED_MSG)
}

/// An open append-only file handle.
pub trait VfsFile: Send {
    fn append(&mut self, data: &[u8]) -> io::Result<()>;
    fn fsync(&mut self) -> io::Result<()>;
}

/// Minimal file-system surface used by the store.
pub trait Vfs: Send + Sync {
    fn create_dir_all(&self, p: &Path) -> io::Result<()>;
    /// Create/truncate + write full contents (one write boundary).
    fn write_file(&self, p: &Path, data: &[u8]) -> io::Result<()>;
    /// Open + `sync_all` an existing file.
    fn fsync_path(&self, p: &Path) -> io::Result<()>;
    /// Flush a directory-equivalent. Unix: fsync on the directory handle.
    /// Windows: `FILE_FLAG_BACKUP_SEMANTICS` + `FlushFileBuffers`,
    /// best-effort (documented caveat, store-v1.md §6).
    fn sync_dir(&self, p: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, p: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, p: &Path) -> io::Result<()>;
    fn truncate(&self, p: &Path, len: u64) -> io::Result<()>;
    /// Open (creating if absent) for append.
    fn open_append(&self, p: &Path) -> io::Result<Box<dyn VfsFile>>;
    fn read(&self, p: &Path) -> io::Result<Vec<u8>>;
    fn read_at(&self, p: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>>;
    /// Entry names (not paths), sorted ascending.
    fn read_dir(&self, p: &Path) -> io::Result<Vec<String>>;
    fn exists(&self, p: &Path) -> bool;
    fn is_dir(&self, p: &Path) -> bool;
    fn file_len(&self, p: &Path) -> io::Result<u64>;
    /// Explicit crash boundary for operations that do not pass through the
    /// Vfs (engine apply, engine checkpoint, engine open). No-op in
    /// production.
    fn failpoint(&self, _label: &'static str) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RealVfs
// ---------------------------------------------------------------------------

/// Production `std::fs` implementation.
#[derive(Debug, Default)]
pub struct RealVfs;

struct RealFile {
    file: std::fs::File,
}

impl VfsFile for RealFile {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)
    }
    fn fsync(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

impl Vfs for RealVfs {
    fn create_dir_all(&self, p: &Path) -> io::Result<()> {
        std::fs::create_dir_all(p)
    }

    fn write_file(&self, p: &Path, data: &[u8]) -> io::Result<()> {
        std::fs::write(p, data)
    }

    fn fsync_path(&self, p: &Path) -> io::Result<()> {
        // Windows `FlushFileBuffers` requires a handle with write access;
        // a read-only handle fails with ERROR_ACCESS_DENIED.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)?
            .sync_all()
    }

    #[cfg(windows)]
    fn sync_dir(&self, p: &Path) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        // Best-effort by documented caveat: FlushFileBuffers on a directory
        // handle works on NTFS; on filesystems that refuse it we rely on
        // per-file sync_all + same-volume atomic rename (store-v1.md §6).
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(p)
        {
            Ok(f) => {
                let _ = f.sync_all();
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    #[cfg(not(windows))]
    fn sync_dir(&self, p: &Path) -> io::Result<()> {
        std::fs::File::open(p)?.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove_file(&self, p: &Path) -> io::Result<()> {
        std::fs::remove_file(p)
    }

    fn remove_dir_all(&self, p: &Path) -> io::Result<()> {
        std::fs::remove_dir_all(p)
    }

    fn truncate(&self, p: &Path, len: u64) -> io::Result<()> {
        let f = std::fs::OpenOptions::new().write(true).open(p)?;
        f.set_len(len)?;
        f.sync_all()
    }

    fn open_append(&self, p: &Path) -> io::Result<Box<dyn VfsFile>> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)?;
        Ok(Box::new(RealFile { file }))
    }

    fn read(&self, p: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(p)
    }

    fn read_at(&self, p: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut f = std::fs::File::open(p)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_dir(&self, p: &Path) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(p)? {
            let entry = entry?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    fn exists(&self, p: &Path) -> bool {
        p.exists()
    }

    fn is_dir(&self, p: &Path) -> bool {
        p.is_dir()
    }

    fn file_len(&self, p: &Path) -> io::Result<u64> {
        Ok(std::fs::metadata(p)?.len())
    }
}

// ---------------------------------------------------------------------------
// Failpoints
// ---------------------------------------------------------------------------

/// Shared crash-injection state. `fail_at == 0` disables injection but the
/// counter still numbers every boundary, which is how the crash matrix
/// discovers its size.
#[derive(Debug, Default)]
pub struct Failpoints {
    fail_at: AtomicU64,
    counter: AtomicU64,
    dead: AtomicBool,
}

enum Step {
    Run,
    /// Crash at this boundary; the seed drives the deterministic torn-write
    /// prefix length for data ops.
    Crash(u64),
}

impl Failpoints {
    pub fn new() -> Arc<Self> {
        Arc::new(Failpoints::default())
    }

    /// Arm: crash at the `n`-th boundary (1-based). Resets the counter.
    pub fn arm(&self, n: u64) {
        self.counter.store(0, Ordering::SeqCst);
        self.dead.store(false, Ordering::SeqCst);
        self.fail_at.store(n, Ordering::SeqCst);
    }

    /// Total boundaries seen since the last `arm`/construction.
    pub fn boundaries_seen(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Whether the armed fault has fired.
    pub fn triggered(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn step(&self) -> io::Result<Step> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(injected_err());
        }
        let n = self
            .counter
            .fetch_add(1, Ordering::SeqCst)
            .checked_add(1)
            .ok_or_else(injected_err)?;
        let fail_at = self.fail_at.load(Ordering::SeqCst);
        if fail_at != 0 && n == fail_at {
            self.dead.store(true, Ordering::SeqCst);
            Ok(Step::Crash(n))
        } else {
            Ok(Step::Run)
        }
    }
}

/// Deterministic torn-write prefix: some strict prefix (possibly empty,
/// possibly all-but-one byte) of the attempted write survives.
fn torn_prefix(seed: u64, len: usize) -> usize {
    seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .checked_rem(len as u64)
        .unwrap_or(0) as usize
}

/// Crash-injecting wrapper over an inner [`Vfs`].
pub struct FailpointVfs {
    inner: Arc<dyn Vfs>,
    fp: Arc<Failpoints>,
}

impl FailpointVfs {
    pub fn new(inner: Arc<dyn Vfs>, fp: Arc<Failpoints>) -> Self {
        FailpointVfs { inner, fp }
    }
}

struct FailpointFile {
    inner: Box<dyn VfsFile>,
    fp: Arc<Failpoints>,
}

impl VfsFile for FailpointFile {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.append(data),
            Step::Crash(seed) => {
                let cut = torn_prefix(seed, data.len());
                let _ = self.inner.append(&data[..cut]);
                Err(injected_err())
            }
        }
    }

    fn fsync(&mut self) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.fsync(),
            Step::Crash(_) => Err(injected_err()),
        }
    }
}

impl Vfs for FailpointVfs {
    fn create_dir_all(&self, p: &Path) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.create_dir_all(p),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn write_file(&self, p: &Path, data: &[u8]) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.write_file(p, data),
            Step::Crash(seed) => {
                let cut = torn_prefix(seed, data.len());
                let _ = self.inner.write_file(p, &data[..cut]);
                Err(injected_err())
            }
        }
    }

    fn fsync_path(&self, p: &Path) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.fsync_path(p),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn sync_dir(&self, p: &Path) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.sync_dir(p),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.rename(from, to),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn remove_file(&self, p: &Path) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.remove_file(p),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn remove_dir_all(&self, p: &Path) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.remove_dir_all(p),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn truncate(&self, p: &Path, len: u64) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => self.inner.truncate(p, len),
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn open_append(&self, p: &Path) -> io::Result<Box<dyn VfsFile>> {
        // Creation of the file is a write boundary.
        match self.fp.step()? {
            Step::Run => {
                let inner = self.inner.open_append(p)?;
                Ok(Box::new(FailpointFile {
                    inner,
                    fp: Arc::clone(&self.fp),
                }))
            }
            Step::Crash(_) => Err(injected_err()),
        }
    }

    fn read(&self, p: &Path) -> io::Result<Vec<u8>> {
        if self.fp.triggered() {
            return Err(injected_err());
        }
        self.inner.read(p)
    }

    fn read_at(&self, p: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if self.fp.triggered() {
            return Err(injected_err());
        }
        self.inner.read_at(p, offset, len)
    }

    fn read_dir(&self, p: &Path) -> io::Result<Vec<String>> {
        if self.fp.triggered() {
            return Err(injected_err());
        }
        self.inner.read_dir(p)
    }

    fn exists(&self, p: &Path) -> bool {
        !self.fp.triggered() && self.inner.exists(p)
    }

    fn is_dir(&self, p: &Path) -> bool {
        !self.fp.triggered() && self.inner.is_dir(p)
    }

    fn file_len(&self, p: &Path) -> io::Result<u64> {
        if self.fp.triggered() {
            return Err(injected_err());
        }
        self.inner.file_len(p)
    }

    fn failpoint(&self, _label: &'static str) -> io::Result<()> {
        match self.fp.step()? {
            Step::Run => Ok(()),
            Step::Crash(_) => Err(injected_err()),
        }
    }
}

/// Path helper: joins with forward-slash semantics via `PathBuf`.
pub(crate) fn join(base: &Path, name: &str) -> PathBuf {
    base.join(name)
}
